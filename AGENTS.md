# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

`docs/DESIGN.md` is the canonical spec. This repository has a Rust implementation in `src/`, integration tests in `tests/`, release automation in `.github/`, and public-facing docs in `README.md` / `docs/RELEASING.md`.

## Non-negotiable design decisions

The following were locked in during earlier design discussion. Do not reopen or quietly diverge from them without explicit user direction:

- **Use the `age` crate, not a subprocess.** Static-link with features `ssh` + `armor`. Never shell out to an `age` CLI binary.
- **v1 command surface is exactly** `show`, `edit`, `list` (alias `ls`), `config`, `agent {start,stop,status,list,add,remove}` with `agent ls` / `agent rm` aliases. No `init`, no clipboard, no `find` / top-level `rm` / `mv` / `cp`, no `--no-agent` / `--identity` flags, no `RSPASS_PASSPHRASE` env.
- **Agent is opt-in.** `show` / `edit` never auto-start the daemon. Only `agent start` and `agent add` may spawn it.
- **Agent decrypts inside the daemon.** Wire protocol is `decrypt(ciphertext, context)` → `plaintext`; identities never leave the daemon. `agent add` is the sole entry point.
- **No TTL, no idle eviction.** Identities stay in the agent until explicit `agent stop` / `agent rm`.
- **Recipients walk-up has override semantics.** First `.age-recipients` found walking up from `parent(<abs>.age)` to store root wins; no inheritance or layering. Directories that want the parent's recipients simply don't create a local file.
- **scrypt identities are prompted in `config.identities` order** during local fallback. Empty input = skip to next identity; Ctrl+C / EOF = exit 3. rspass never sends an empty string as a passphrase to age.
- **Path syntax is `[MOUNT/]REL/PATH`** with slash, not colon. `mounts` is a map; `""` is the optional root mount; longest component-prefix wins. Mount keys may contain `/` for multi-segment prefixes.
- **Config is YAML** at `~/.config/rspass/config.yaml` via `serde_yaml_ng` (the archived `serde_yaml` is not allowed).
- **Atomic writes**: write to `.<target>.tmp.<pid>` in the same directory as the target, `fsync`, `rename`, `fsync` parent. Never cross-filesystem rename.
- **Single binary.** The agent daemon is the same executable invoked via hidden subcommand `__agent-daemon`.
- **Unix socket security model** is `0600` permissions + `getpeereid` UID check. That is sufficient for the stated threat model — do not add session tokens, abstract namespaces, or encrypted-channel-over-socket layers.

## When docs/DESIGN.md and reality disagree

docs/DESIGN.md is canonical. If implementation reveals that a spec detail is unworkable or under-specified, **stop and raise it with the user before diverging**. Do not silently change behavior, and do not edit docs/DESIGN.md unilaterally to match shipped code.

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`). Use module scopes when helpful: `feat(config): …`, `fix(agent): …`. Subject and body always in English per the user's global preference, even when the conversation is Chinese.

## Build / test

Standard `cargo build` / `cargo test` / `cargo clippy` / `cargo fmt`. Agent integration tests must use a scratch `HOME` and `XDG_RUNTIME_DIR` (or `RSPASS_AGENT_SOCK`) so they can't clobber a running user agent.
