# Releasing rspass

This is the manual release flow. The single source of truth for the
version is `Cargo.toml`'s `version` field; the git tag must match it.
A future `cargo-release` setup can automate these steps, but the
manual flow is what the CI release workflow is built around.

## Versioning

`MAJOR.MINOR.PATCH`, per SemVer.

- `PATCH` (0.1.0 → 0.1.1): bug fixes, backwards-compatible internals.
- `MINOR` (0.1.0 → 0.2.0): new features, backwards-compatible.
- `MAJOR` (0.1.0 → 1.0.0): breaking changes.

While in `0.x.y`, bumping `0.x → 0.(x+1)` may be breaking — the public
API is not yet considered stable.

Tag names use a `v` prefix: `v0.2.0`. The version string in
`Cargo.toml` does **not** include the `v`.

## Release steps

Assume we are releasing `0.2.0`.

1. **Bump `Cargo.toml`**

   Edit `version = "0.1.0"` → `version = "0.2.0"`.

2. **Sync `Cargo.lock`**

   ```sh
   cargo check
   ```

   This rewrites `Cargo.lock` so `rspass` shows the new version
   inside it. Skipping this step leaves `Cargo.lock` out of date and
   the next unrelated build will surprise you with a lockfile diff.

3. **Sanity check**

   ```sh
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

   The CI release workflow re-runs these, but a local pass before
   tagging avoids creating a tag that immediately fails CI.

4. **Commit**

   ```sh
   git commit -am "chore: release v0.2.0"
   ```

   Convention: a single commit that touches only `Cargo.toml` and
   `Cargo.lock`. Do not bundle feature work into a release commit.

5. **Tag**

   ```sh
   git tag -a v0.2.0 -m "v0.2.0"
   ```

   Annotated tags (`-a`) carry a tagger, date, and message; CI and
   `git describe` prefer them over lightweight tags.

6. **Push**

   ```sh
   git push origin master
   git push origin v0.2.0
   ```

   The tag push is what triggers the release workflow on GitHub.

## After pushing

- The release workflow validates that `Cargo.toml`'s version matches
  the tag (i.e. `v0.2.0` requires `version = "0.2.0"`). If they
  diverge, the run fails and no release is published.
- The workflow builds release binaries on a platform matrix and
  attaches them to a GitHub Release named after the tag.

## Recovering from mistakes

- **Pushed wrong tag**: `git tag -d v0.2.0 && git push --delete origin v0.2.0`.
  Only safe before anyone has downloaded the release. Re-tag and push
  again.
- **Forgot to bump `Cargo.toml` before tagging**: delete the tag (as
  above), bump, commit, re-tag.
- **Forgot `cargo check` and `Cargo.lock` is stale**: amend the
  release commit (`git commit --amend`) and re-tag, again only if the
  tag has not been pushed yet. Once pushed, follow the recovery flow
  with a new patch version instead.
