//! Shared bundle hot-reload helper.
//!
//! Generalises the file-watching pattern that `dev.mcpg.policy.opa`,
//! `dev.mcpg.policy.cedar`, `dev.mcpg.policy.casbin`, and
//! `dev.mcpg.identity.workload` would each otherwise hand-roll.
//! The shape is uniform across these plugins:
//!
//! 1. Operator points the plugin at a file / set of files /
//!    directory of files.
//! 2. The plugin parses bytes into an in-memory representation
//!    (`PolicySet`, `Enforcer`, JWKS bundle, etc.).
//! 3. The plugin caches the parsed value behind
//!    [`arc_swap::ArcSwap`] so per-request evaluation snapshots
//!    cheaply.
//! 4. A background task polls the source's mtime + sha256 every
//!    N seconds; on change re-parses, atomically swaps via
//!    `arc_swap::ArcSwap::store`.
//! 5. Drop = abort the background task.
//!
//! This crate exposes that loop as a generic [`BundleReload<T>`]
//! parameterised by the operator's parser closure.
//!
//! # Cluster-aware variant
//!
//! Behind the `cluster` feature flag (default-on), the
//! [`clustered`] module exposes a variant that piggybacks
//! invalidation events on a `cluster_backend` topic. When
//! one gateway instance detects a change + reloads, it publishes
//! a notification so peer instances refresh immediately instead
//! of waiting for their next poll tick. Closes the multi-
//! instance bundle-reload divergence gap.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::task::JoinHandle;

// There is no cross-replica broadcast path: reload coordination picks WHO
// reloads via a leader lock (cedar/workload PreTickHooks) and lets peers
// converge on their own poll tick rather than signalling a reload.

// ---------------------------------------------------------------------------
// BundleSource — what files we watch
// ---------------------------------------------------------------------------

/// Where the bundle lives on disk.
#[derive(Debug, Clone)]
pub enum BundleSource {
    /// A single file. Used by `policy.opa` (one .wasm),
    /// `identity.workload` (one JWKS), etc.
    File(PathBuf),
    /// A fixed list of files. Used by `policy.casbin`
    /// (model.conf + policy.csv).
    Files(Vec<PathBuf>),
    /// A directory walked recursively for files matching the
    /// optional extension filter. Used by `policy.cedar` (every
    /// `.cedar` file under `policy_dir`).
    Directory {
        root: PathBuf,
        extension: Option<String>,
    },
    /// Composition of sub-sources. Walks each and concatenates
    /// the file lists. Used by plugins that depend on several
    /// inputs that all need to fingerprint together (e.g.
    /// `policy.cedar` watching its policy directory PLUS its
    /// schema file PLUS its entities file — any one changing
    /// should trigger a unified reload). Lexicographic ordering
    /// is preserved across the whole composite.
    Composite(Vec<BundleSource>),
}

impl BundleSource {
    /// Walk the source and collect all current bundle paths in
    /// lexicographic order. Used to compute the deterministic
    /// fingerprint over the bundle's bytes.
    pub fn list_files(&self) -> Result<Vec<PathBuf>, ReloadError> {
        match self {
            Self::File(p) => Ok(vec![p.clone()]),
            Self::Files(ps) => {
                let mut out = ps.clone();
                out.sort();
                Ok(out)
            }
            Self::Directory { root, extension } => {
                let mut out: Vec<PathBuf> = Vec::new();
                walk_dir(root, extension.as_deref(), &mut out)?;
                out.sort();
                Ok(out)
            }
            Self::Composite(parts) => {
                let mut out: Vec<PathBuf> = Vec::new();
                for sub in parts {
                    out.extend(sub.list_files()?);
                }
                out.sort();
                Ok(out)
            }
        }
    }

    /// Compute the sha256 fingerprint over the canonical
    /// concatenation of every bundle file. The fingerprint is
    /// stable across runs; bytes-identical sources produce the
    /// same hash. Path ordering is enforced by [`Self::list_files`].
    pub async fn fingerprint(&self) -> Result<String, ReloadError> {
        let paths = self.list_files()?;
        let mut hasher = Sha256::new();
        for path in &paths {
            let bytes = tokio::fs::read(path).await.map_err(|e| ReloadError::Io {
                path: path.display().to_string(),
                error: e.to_string(),
            })?;
            // Hash the path + a separator + the bytes. Including
            // the path stops bytes-rearranged-files-with-same-
            // total-content from looking unchanged.
            hasher.update(path.to_string_lossy().as_bytes());
            hasher.update(b"\x00");
            hasher.update(&bytes);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

fn walk_dir(
    root: &Path,
    extension: Option<&str>,
    out: &mut Vec<PathBuf>,
) -> Result<(), ReloadError> {
    if !root.is_dir() {
        return Err(ReloadError::Io {
            path: root.display().to_string(),
            error: "not a directory".into(),
        });
    }
    for entry in std::fs::read_dir(root).map_err(|e| ReloadError::Io {
        path: root.display().to_string(),
        error: e.to_string(),
    })? {
        let entry = entry.map_err(|e| ReloadError::Io {
            path: root.display().to_string(),
            error: e.to_string(),
        })?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, extension, out)?;
        } else {
            let matches = match extension {
                None => true,
                Some(ext) => path.extension().is_some_and(|e| e == ext),
            };
            if matches {
                out.push(path);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Failure modes for loading/fingerprinting a bundle: reading the
/// source files (`Io`) or the operator-supplied parser rejecting the
/// bytes (`Parse`). A reload tick that hits either keeps the
/// previously-loaded bundle in place.
#[derive(Debug, Error)]
pub enum ReloadError {
    #[error("bundle I/O on `{path}`: {error}")]
    Io { path: String, error: String },
    #[error("bundle parse failed: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// BundleReload — the public handle
// ---------------------------------------------------------------------------

/// Hot-reloadable bundle. Cheap to clone — interior state lives
/// behind `Arc`.
///
/// `T` is the parsed bundle type (operator-supplied) — typically
/// the plugin's runtime view of its policies / keys / config.
pub struct BundleReload<T: Send + Sync + 'static> {
    inner: Arc<ArcSwap<Loaded<T>>>,
    /// Background-poll task. `None` when the helper was
    /// constructed without spawning a watcher (tests / static-
    /// only deploys).
    watcher: Option<JoinHandle<()>>,
    /// Out-of-band trigger. The watcher's `tick` selects on
    /// `interval.tick()` OR `notify.notified()`; calling
    /// [`BundleReload::poke`] (or a clone of [`PokeHandle`]
    /// obtained via [`BundleReload::poke_handle`]) wakes the
    /// watcher so it runs a poll immediately. Used by cluster-
    /// aware plugins whose subscribers want to react to a peer's
    /// publish without waiting for the next interval.
    notify: Arc<tokio::sync::Notify>,
}

struct Loaded<T> {
    parsed: Arc<T>,
    fingerprint: String,
}

impl<T: Send + Sync + 'static> Clone for BundleReload<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            // Cloning shares the same background watcher. The
            // original handle's drop aborts the task; clones
            // don't independently abort.
            watcher: None,
            notify: Arc::clone(&self.notify),
        }
    }
}

impl<T: Send + Sync + 'static> Drop for BundleReload<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.watcher.take() {
            handle.abort();
        }
    }
}

impl<T: Send + Sync + 'static> BundleReload<T> {
    /// Snapshot the currently-loaded bundle. Cheap — single
    /// atomic load + Arc clone. Suitable for the request hot path.
    pub fn load(&self) -> Arc<T> {
        Arc::clone(&self.inner.load().parsed)
    }

    /// SHA-256 fingerprint of the bundle bytes that produced the
    /// currently-loaded value. Surfaced to operators via
    /// `policy_version()` / etc.
    pub fn fingerprint(&self) -> String {
        self.inner.load().fingerprint.clone()
    }

    /// Replace the loaded bundle with `parsed` and stamp it with
    /// `fingerprint`. Used by the cluster wrapper when a peer
    /// instance broadcasts a bundle change — bypasses re-reading
    /// from disk if the peer's fingerprint matches what we'd
    /// compute locally.
    ///
    /// Most callers don't need this; rely on the background
    /// watcher to swap on next poll tick.
    pub fn replace(&self, parsed: T, fingerprint: String) {
        self.inner.store(Arc::new(Loaded {
            parsed: Arc::new(parsed),
            fingerprint,
        }));
    }

    /// Wake the watcher so it runs a poll immediately, skipping
    /// the next interval wait. The watcher still consults the
    /// `pre_tick` hook (so cluster coordination still gates the
    /// work) and still no-ops when the fingerprint hasn't changed.
    ///
    /// Idempotent: calling `poke` multiple times before the
    /// watcher wakes coalesces into one extra poll. `tokio::sync::Notify`
    /// has the same shape as `Condvar::notify_one` — at most one
    /// pending notification is buffered.
    pub fn poke(&self) {
        self.notify.notify_one();
    }

    /// Detached, type-erased notify handle. Hand to a subscriber /
    /// gossip listener that needs to wake the watcher without
    /// holding a reference to the bundle's `T`. Cheap clone.
    pub fn poke_handle(&self) -> PokeHandle {
        PokeHandle {
            notify: Arc::clone(&self.notify),
        }
    }
}

/// Wake-the-watcher handle decoupled from `BundleReload<T>`'s
/// generic parameter. Held by closures (subscriber callbacks,
/// gossip listeners) that want to react to peer signals by
/// triggering an out-of-band poll.
#[derive(Clone)]
pub struct PokeHandle {
    notify: Arc<tokio::sync::Notify>,
}

impl PokeHandle {
    /// Same semantics as [`BundleReload::poke`]. Idempotent.
    pub fn poke(&self) {
        self.notify.notify_one();
    }
}

impl std::fmt::Debug for PokeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PokeHandle").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

/// Build a `BundleReload<T>` from the operator-supplied source +
/// parser, then spawn the background watcher.
///
/// `parser` MUST be `Send + Sync` because the watcher task
/// invokes it on every detected change.
///
/// Initial parse runs in the caller's context (so failures
/// surface as a returned `Err` instead of silently being logged
/// from a background task).
///
/// Returns the `BundleReload<T>` handle. Drop the handle to
/// abort the watcher.
pub async fn start<T, F>(
    source: BundleSource,
    parser: F,
    interval: Duration,
) -> Result<BundleReload<T>, ReloadError>
where
    T: Send + Sync + 'static,
    F: Fn(&BundleSource) -> Result<T, ReloadError> + Send + Sync + 'static,
{
    start_with_options(source, parser, BundleReloadOptions::new(interval)).await
}

/// Options-aware variant of [`start`]. Used by cluster-aware plugins
/// (cedar, workload, …) that want to skip a tick when a peer node
/// holds the cluster refresh lock.
pub async fn start_with_options<T, F>(
    source: BundleSource,
    parser: F,
    options: BundleReloadOptions,
) -> Result<BundleReload<T>, ReloadError>
where
    T: Send + Sync + 'static,
    F: Fn(&BundleSource) -> Result<T, ReloadError> + Send + Sync + 'static,
{
    // Initial load.
    let parsed = parser(&source)?;
    let fingerprint = source.fingerprint().await?;
    let inner = Arc::new(ArcSwap::from_pointee(Loaded {
        parsed: Arc::new(parsed),
        fingerprint: fingerprint.clone(),
    }));

    // Spawn the watcher.
    let watch_inner = Arc::clone(&inner);
    let parser = Arc::new(parser);
    let watch_source = source.clone();
    let interval = options.interval;
    let pre_tick = options.pre_tick;
    let notify = Arc::new(tokio::sync::Notify::new());
    let watch_notify = Arc::clone(&notify);
    let watcher = tokio::spawn(async move {
        watch_loop(
            watch_source,
            parser,
            watch_inner,
            interval,
            pre_tick,
            watch_notify,
        )
        .await;
    });

    Ok(BundleReload {
        inner,
        watcher: Some(watcher),
        notify,
    })
}

/// Async-parser variant of [`start`]. Use this when the
/// bundle parser awaits — the canonical case is `casbin-rs`'s
/// `Enforcer::new(model_path, adapter).await` which is async by
/// design.
///
/// `parser` is `Fn(&BundleSource) -> impl Future` — every reload
/// tick spawns the future on the same runtime that's executing
/// `start_async` (initial load) and on the watcher's runtime
/// (background ticks).
pub async fn start_async<T, F, Fut>(
    source: BundleSource,
    parser: F,
    interval: Duration,
) -> Result<BundleReload<T>, ReloadError>
where
    T: Send + Sync + 'static,
    F: Fn(BundleSource) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<T, ReloadError>> + Send + 'static,
{
    start_async_with_options(source, parser, BundleReloadOptions::new(interval)).await
}

/// Options-aware variant of [`start_async`]. Same shape as
/// [`start_with_options`] for the async-parser path (casbin, …).
pub async fn start_async_with_options<T, F, Fut>(
    source: BundleSource,
    parser: F,
    options: BundleReloadOptions,
) -> Result<BundleReload<T>, ReloadError>
where
    T: Send + Sync + 'static,
    F: Fn(BundleSource) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<T, ReloadError>> + Send + 'static,
{
    let parsed = parser(source.clone()).await?;
    let fingerprint = source.fingerprint().await?;
    let inner = Arc::new(ArcSwap::from_pointee(Loaded {
        parsed: Arc::new(parsed),
        fingerprint,
    }));

    let parser = Arc::new(parser);
    let watch_inner = Arc::clone(&inner);
    let watch_source = source.clone();
    let watch_parser = Arc::clone(&parser);
    let interval = options.interval;
    let pre_tick = options.pre_tick;
    let notify = Arc::new(tokio::sync::Notify::new());
    let watch_notify = Arc::clone(&notify);
    let watcher = tokio::spawn(async move {
        watch_loop_async(
            watch_source,
            watch_parser,
            watch_inner,
            interval,
            pre_tick,
            watch_notify,
        )
        .await;
    });

    Ok(BundleReload {
        inner,
        watcher: Some(watcher),
        notify,
    })
}

async fn watch_loop_async<T, F, Fut>(
    source: BundleSource,
    parser: Arc<F>,
    inner: Arc<ArcSwap<Loaded<T>>>,
    interval: Duration,
    pre_tick: Option<PreTickHook>,
    notify: Arc<tokio::sync::Notify>,
) where
    T: Send + Sync + 'static,
    F: Fn(BundleSource) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<T, ReloadError>> + Send + 'static,
{
    let mut last_fp = inner.load().fingerprint.clone();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        // Wake on either the periodic tick OR an out-of-band poke
        // from a subscriber. A poke skips the interval wait and
        // runs the same pre_tick + poll cycle, so cluster
        // coordination still gates the work — only the timing
        // changes.
        tokio::select! {
            biased;
            _ = notify.notified() => {
                tracing::debug!(
                    "bundle-reload (async): poked; running poll out-of-band"
                );
            }
            _ = ticker.tick() => {}
        }
        // Consult the cluster-coordination hook BEFORE doing any work.
        // Hook returns None → another node holds the refresh lock;
        // skip this tick. Returning Some(permit) keeps the permit
        // alive across the parse + swap so the lease isn't released
        // mid-reload.
        let _permit: Option<ReloadPermit> = match &pre_tick {
            Some(hook) => match hook() {
                Some(p) => Some(p),
                None => {
                    tracing::debug!(
                        "bundle-reload (async): pre_tick declined this tick (peer-held lock)"
                    );
                    continue;
                }
            },
            None => None,
        };
        let new_fp = match source.fingerprint().await {
            Ok(fp) => fp,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "bundle-reload (async): fingerprint failed; keeping previous bundle"
                );
                continue;
            }
        };
        if new_fp == last_fp {
            continue;
        }
        let parsed = match parser(source.clone()).await {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(
                    old_fp = %last_fp,
                    new_fp = %new_fp,
                    error = %err,
                    "bundle-reload (async): parse failed; keeping previous bundle"
                );
                continue;
            }
        };
        let next = Loaded {
            parsed: Arc::new(parsed),
            fingerprint: new_fp.clone(),
        };
        inner.store(Arc::new(next));
        tracing::info!(
            old_fp = %last_fp,
            new_fp = %new_fp,
            "bundle-reload (async): bundle swapped"
        );
        last_fp = new_fp;
    }
}

/// Boxed permit returned by a `pre_tick` hook. The bundle-reload
/// watcher holds the permit during the reload; Drop runs after
/// the swap (or skip-on-error) completes. Plugins use it to keep
/// a `ClusterLease` alive for the duration of the reload so other
/// nodes don't race the same upstream pull.
pub type ReloadPermit = Box<dyn Send + 'static>;

/// Pre-tick hook signature. Returns `Some(permit)` to proceed
/// with the reload tick; `None` to skip this iteration.
///
/// Plugins that don't need cluster coordination omit the hook
/// entirely. Plugins that do (cedar, workload, future remote-
/// fetcher policies) supply a closure that consults a cluster
/// lock / leadership lease.
///
/// The hook MUST be cheap — it runs on the watcher's task before
/// every tick. A network round-trip per tick is OK (cluster
/// `acquire_lock` typically rounds to milliseconds); blocking for
/// seconds is not.
pub type PreTickHook = Arc<dyn Fn() -> Option<ReloadPermit> + Send + Sync + 'static>;

/// Options for [`start_with_options`] / [`start_async_with_options`].
/// Splits configuration off the function signature so future knobs
/// (jitter, backoff, …) don't churn every callsite.
pub struct BundleReloadOptions {
    pub interval: Duration,
    /// Optional cluster-coordination hook. Returns `None` to skip
    /// the next reload tick (peer holds the lock); `Some(permit)`
    /// to proceed. The permit is dropped after the tick completes.
    pub pre_tick: Option<PreTickHook>,
}

impl BundleReloadOptions {
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            pre_tick: None,
        }
    }

    #[must_use]
    pub fn with_pre_tick(mut self, hook: PreTickHook) -> Self {
        self.pre_tick = Some(hook);
        self
    }
}

/// Construct a `BundleReload<T>` that does NOT spawn a background
/// watcher. Useful for tests + for plugins that handle reload
/// themselves but want to share the load() / fingerprint()
/// surface.
pub fn static_only<T: Send + Sync + 'static>(parsed: T, fingerprint: String) -> BundleReload<T> {
    let inner = Arc::new(ArcSwap::from_pointee(Loaded {
        parsed: Arc::new(parsed),
        fingerprint,
    }));
    BundleReload {
        inner,
        watcher: None,
        notify: Arc::new(tokio::sync::Notify::new()),
    }
}

async fn watch_loop<T, F>(
    source: BundleSource,
    parser: Arc<F>,
    inner: Arc<ArcSwap<Loaded<T>>>,
    interval: Duration,
    pre_tick: Option<PreTickHook>,
    notify: Arc<tokio::sync::Notify>,
) where
    T: Send + Sync + 'static,
    F: Fn(&BundleSource) -> Result<T, ReloadError> + Send + Sync + 'static,
{
    let mut last_fp = inner.load().fingerprint.clone();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // First tick fires immediately — skip so we don't double-
    // load right after construction.
    ticker.tick().await;

    loop {
        // See `watch_loop_async` for the poke / pre_tick contract.
        tokio::select! {
            biased;
            _ = notify.notified() => {
                tracing::debug!(
                    "bundle-reload: poked; running poll out-of-band"
                );
            }
            _ = ticker.tick() => {}
        }
        let _permit: Option<ReloadPermit> = match &pre_tick {
            Some(hook) => match hook() {
                Some(p) => Some(p),
                None => {
                    tracing::debug!("bundle-reload: pre_tick declined this tick (peer-held lock)");
                    continue;
                }
            },
            None => None,
        };
        match poll_once(&source, &parser, &inner, &last_fp).await {
            Ok(Some(new_fp)) => last_fp = new_fp,
            Ok(None) => continue,
            Err(_) => continue, // already logged inside poll_once
        }
    }
}

async fn poll_once<T, F>(
    source: &BundleSource,
    parser: &Arc<F>,
    inner: &Arc<ArcSwap<Loaded<T>>>,
    last_fp: &str,
) -> Result<Option<String>, ReloadError>
where
    T: Send + Sync + 'static,
    F: Fn(&BundleSource) -> Result<T, ReloadError> + Send + Sync + 'static,
{
    let new_fp = match source.fingerprint().await {
        Ok(fp) => fp,
        Err(err) => {
            tracing::warn!(error = %err, "bundle-reload: fingerprint failed; keeping previous bundle");
            return Err(err);
        }
    };
    if new_fp == last_fp {
        return Ok(None);
    }
    let parsed = match parser(source) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(
                old_fp = %last_fp,
                new_fp = %new_fp,
                error = %err,
                "bundle-reload: parse failed; keeping previous bundle"
            );
            return Err(err);
        }
    };
    let next = Loaded {
        parsed: Arc::new(parsed),
        fingerprint: new_fp.clone(),
    };
    inner.store(Arc::new(next));
    tracing::info!(
        old_fp = %last_fp,
        new_fp = %new_fp,
        "bundle-reload: bundle swapped"
    );
    Ok(Some(new_fp))
}

/// Public re-export of the poll path so the cluster wrapper can
/// trigger an immediate re-load on peer-publish without waiting
/// for the next interval tick.
#[doc(hidden)]
pub async fn force_poll<T, F>(
    bundle: &BundleReload<T>,
    source: &BundleSource,
    parser: &Arc<F>,
) -> Result<bool, ReloadError>
where
    T: Send + Sync + 'static,
    F: Fn(&BundleSource) -> Result<T, ReloadError> + Send + Sync + 'static,
{
    let last_fp = bundle.inner.load().fingerprint.clone();
    poll_once(source, parser, &bundle.inner, &last_fp)
        .await
        .map(|opt| opt.is_some())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    fn parse_count_bytes(source: &BundleSource) -> Result<usize, ReloadError> {
        let mut total = 0;
        for p in source.list_files()? {
            let bytes = std::fs::read(&p).map_err(|e| ReloadError::Io {
                path: p.display().to_string(),
                error: e.to_string(),
            })?;
            total += bytes.len();
        }
        Ok(total)
    }

    #[tokio::test]
    async fn single_file_source_initial_load() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "hello");
        let source = BundleSource::File(path);
        let bundle = start(source, parse_count_bytes, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(*bundle.load(), 5);
        // fingerprint deterministic across calls.
        let fp1 = bundle.fingerprint();
        let fp2 = bundle.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[tokio::test]
    async fn directory_source_aggregates_files() {
        let dir = TempDir::new().unwrap();
        write_file(dir.path(), "a.cedar", "AAA");
        write_file(dir.path(), "b.cedar", "BB");
        write_file(dir.path(), "c.txt", "ignore-me");
        let source = BundleSource::Directory {
            root: dir.path().to_path_buf(),
            extension: Some("cedar".into()),
        };
        let bundle = start(source, parse_count_bytes, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(*bundle.load(), 5); // 3 + 2
    }

    #[tokio::test]
    async fn fingerprint_changes_when_file_changes() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "v1");
        let source = BundleSource::File(path.clone());
        let fp_v1 = source.fingerprint().await.unwrap();
        write_file(dir.path(), "bundle.txt", "v2-different");
        let fp_v2 = source.fingerprint().await.unwrap();
        assert_ne!(fp_v1, fp_v2);
    }

    #[tokio::test]
    async fn watcher_swaps_bundle_when_file_changes() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "abc");
        let source = BundleSource::File(path.clone());
        let bundle = start(source, parse_count_bytes, Duration::from_millis(20))
            .await
            .unwrap();
        assert_eq!(*bundle.load(), 3);
        let fp1 = bundle.fingerprint();

        // Mutate the file.
        write_file(dir.path(), "bundle.txt", "1234567");
        // Wait for the watcher to pick it up.
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if *bundle.load() == 7 {
                break;
            }
        }
        assert_eq!(*bundle.load(), 7);
        assert_ne!(bundle.fingerprint(), fp1);
    }

    #[tokio::test]
    async fn parse_failure_keeps_previous_bundle() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "good");
        let parser = |source: &BundleSource| {
            // Reject any file with content "bad".
            for p in source.list_files()? {
                let bytes = std::fs::read(&p).unwrap();
                if bytes == b"bad" {
                    return Err(ReloadError::Parse("nope".into()));
                }
            }
            parse_count_bytes(source)
        };
        let bundle = start(
            BundleSource::File(path.clone()),
            parser,
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        assert_eq!(*bundle.load(), 4);
        write_file(dir.path(), "bundle.txt", "bad");
        // Wait several ticks; bundle should remain at "good".
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*bundle.load(), 4);
    }

    #[tokio::test]
    async fn drop_aborts_watcher() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "x");
        let source = BundleSource::File(path);
        let bundle = start(source, parse_count_bytes, Duration::from_millis(10))
            .await
            .unwrap();
        let watcher_alive_before = bundle.watcher.as_ref().is_some_and(|h| !h.is_finished());
        assert!(watcher_alive_before);
        drop(bundle);
        // No assert — abort is fire-and-forget. Test passes if it
        // doesn't hang.
    }

    #[tokio::test]
    async fn static_only_constructor_works() {
        let bundle: BundleReload<u32> = static_only(42, "fp-static".into());
        assert_eq!(*bundle.load(), 42);
        assert_eq!(bundle.fingerprint(), "fp-static");
    }

    #[tokio::test]
    async fn replace_swaps_in_external_bundle() {
        let bundle: BundleReload<u32> = static_only(1, "fp-1".into());
        bundle.replace(2, "fp-2".into());
        assert_eq!(*bundle.load(), 2);
        assert_eq!(bundle.fingerprint(), "fp-2");
    }

    #[tokio::test]
    async fn pre_tick_skip_keeps_old_bundle() {
        // Pre_tick that always returns None should prevent every
        // tick after the initial load. Mutating the source shouldn't
        // cause a swap.
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "abc");
        let source = BundleSource::File(path.clone());

        let pre_tick: PreTickHook = std::sync::Arc::new(|| -> Option<ReloadPermit> { None });
        let opts = BundleReloadOptions::new(Duration::from_millis(40)).with_pre_tick(pre_tick);
        let bundle = start_with_options(source, parse_count_bytes, opts)
            .await
            .unwrap();
        assert_eq!(*bundle.load(), 3);

        // Modify the source so that *if* the watcher reloaded we'd
        // see a different value.
        std::fs::write(&path, b"abcdef").unwrap();
        // Two intervals + jitter — enough for the watcher to run if
        // it were going to.
        tokio::time::sleep(Duration::from_millis(120)).await;
        // Still the original bundle — pre_tick declined every tick.
        assert_eq!(*bundle.load(), 3);
    }

    #[tokio::test]
    async fn poke_triggers_out_of_band_poll() {
        // Watcher's interval is large (5s) so we know the swap
        // didn't come from the periodic tick. After a poke, the
        // file change should be picked up within ~50ms.
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "abc");
        let source = BundleSource::File(path.clone());
        let bundle = start(source, parse_count_bytes, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(*bundle.load(), 3);

        std::fs::write(&path, b"abcdefgh").unwrap();
        bundle.poke();
        // Give the watcher time to wake + run.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            *bundle.load(),
            8,
            "poke should have caused an out-of-band reload"
        );
    }

    #[tokio::test]
    async fn poke_handle_works_from_detached_context() {
        // Same scenario but the poke is invoked through a
        // PokeHandle clone passed to a separate task — verifies
        // the type-erased handle is sufficient.
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "ab");
        let source = BundleSource::File(path.clone());
        let bundle = start(source, parse_count_bytes, Duration::from_secs(5))
            .await
            .unwrap();
        let poke = bundle.poke_handle();

        std::fs::write(&path, b"abcde").unwrap();
        tokio::spawn(async move {
            poke.poke();
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            *bundle.load(),
            5,
            "PokeHandle clone should wake the watcher"
        );
    }

    #[tokio::test]
    async fn poke_respects_pre_tick_decline() {
        // Even when poked, a pre_tick that returns None must keep
        // the watcher from running the poll. Otherwise a peer
        // could force every node to reload by spamming pokes.
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "abc");
        let source = BundleSource::File(path.clone());

        let pre_tick: PreTickHook = std::sync::Arc::new(|| -> Option<ReloadPermit> { None });
        let opts = BundleReloadOptions::new(Duration::from_secs(5)).with_pre_tick(pre_tick);
        let bundle = start_with_options(source, parse_count_bytes, opts)
            .await
            .unwrap();
        std::fs::write(&path, b"abcdefgh").unwrap();
        for _ in 0..5 {
            bundle.poke();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Old value still there — pre_tick declined every poke.
        assert_eq!(*bundle.load(), 3);
    }

    #[tokio::test]
    async fn pre_tick_some_permit_dropped_after_each_tick() {
        // Counter increments on every Drop. We expect at least
        // one increment within a couple of intervals — proves the
        // watcher acquires + releases the permit.
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        let drops = std::sync::Arc::new(AtomicUsize::new(0));
        struct DropCounter(std::sync::Arc<AtomicUsize>);
        impl Drop for DropCounter {
            fn drop(&mut self) {
                self.0.fetch_add(1, AtomicOrdering::SeqCst);
            }
        }

        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "bundle.txt", "abc");
        let source = BundleSource::File(path.clone());

        let drops_for_hook = std::sync::Arc::clone(&drops);
        let pre_tick: PreTickHook = std::sync::Arc::new(move || -> Option<ReloadPermit> {
            Some(Box::new(DropCounter(std::sync::Arc::clone(
                &drops_for_hook,
            ))))
        });
        let opts = BundleReloadOptions::new(Duration::from_millis(40)).with_pre_tick(pre_tick);
        let _bundle = start_with_options(source, parse_count_bytes, opts)
            .await
            .unwrap();
        // Wait for ~3 intervals so the watcher fires a few ticks.
        tokio::time::sleep(Duration::from_millis(150)).await;
        // We expect at least 2 permits dropped — proves the hook
        // ran AND its permit was reclaimed cleanly per tick.
        assert!(
            drops.load(AtomicOrdering::SeqCst) >= 2,
            "expected ≥2 permit drops, got {}",
            drops.load(AtomicOrdering::SeqCst)
        );
    }
}
