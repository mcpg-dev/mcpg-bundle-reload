# mcpg-bundle-reload

> Generic watch-parse-swap loop for plugins that load a bundle of files from disk and want it hot-reloaded.

This crate factors out the file-watching pattern that policy and identity
plugins would otherwise each hand-roll: point at a file, a fixed set of files,
or a directory; parse the bytes into an in-memory value with a caller-supplied
closure; keep the parsed value behind `arc_swap::ArcSwap` so the request path
snapshots it with one atomic load; poll a SHA-256 fingerprint on an interval and
atomically swap when it changes. It is deliberately a mechanism rather than a
bundle format — it knows nothing about what it parses — and it fetches nothing:
the bundle is whatever is already on the local filesystem.

## What's here
- `BundleSource` — where the bundle lives: `File(PathBuf)`, `Files(Vec<PathBuf>)`,
  `Directory { root, extension }` (walked recursively, optional extension
  filter), and `Composite(Vec<BundleSource>)` for several inputs that must
  fingerprint as one unit.
- `BundleSource::list_files()` / `BundleSource::fingerprint()` — the lexicographic
  file list, and the SHA-256 taken over each path, a NUL separator, and that
  file's bytes, so content moved between files still reads as a change.
- `start()` / `start_async()` — build a `BundleReload<T>` from a source plus a
  parser and spawn the background watcher. The initial parse runs in the
  caller's context, so a bad bundle fails the constructor instead of being
  logged from a detached task. `start_async` takes a parser returning a future,
  for parsers that are async by design.
- `start_with_options()` / `start_async_with_options()` with
  `BundleReloadOptions` — the same, with `interval` and an optional `pre_tick`
  hook split off the signature:
  `BundleReloadOptions::new(interval).with_pre_tick(hook)`.
- `BundleReload<T>` — `load()` (a cheap `Arc<T>` snapshot for the hot path),
  `fingerprint()`, `replace(parsed, fingerprint)`, `poke()` and `poke_handle()`.
  Cloning shares the loaded state; dropping the original handle aborts the
  watcher task.
- `PokeHandle` — a cloneable wake handle decoupled from `T`, for subscriber
  callbacks that want to force an out-of-band poll. Poking still runs the
  `pre_tick` hook and still no-ops when the fingerprint is unchanged; only the
  timing changes.
- `PreTickHook` / `ReloadPermit` — the cluster-coordination seam. The hook runs
  before every tick; returning `None` skips the tick (a peer holds the refresh
  lock), and the returned permit is held across the parse and swap so a lease
  cannot lapse mid-reload.
- `static_only(parsed, fingerprint)` — a `BundleReload<T>` with no watcher, for
  tests and for plugins that drive reload themselves but want the same surface.
- `ReloadError` — `Io { path, error }` and `Parse(String)`. A tick that hits
  either logs and keeps the bundle already in memory, so a broken edit on disk
  never blanks a running policy set.

## Used by
- The policy plugins `libs/plugins/security/policy-opa`,
  `libs/plugins/security/policy-cedar` and
  `libs/plugins/security/policy-casbin`, for their policy bundles.
- `libs/plugins/identity/workload`, for its key bundle.

## Build / test
```bash
cargo build -p mcpg-bundle-reload
cargo test  -p mcpg-bundle-reload
```

## Licence
Apache-2.0.

## See also
- [Policy and authorization](https://mcpg.dev/docs/security/policy) — the policy engines that consume this.
- [Writing a plugin](https://mcpg.dev/docs/plugins/plugin-authoring)
- `libs/cluster-api` — the lease primitive a `pre_tick` hook typically consults.
