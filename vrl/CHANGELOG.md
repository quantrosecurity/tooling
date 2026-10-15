# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `vrl submit` — queue a CVE via the public email path, or `--internal` using a
  Google OIDC token / shared secret. `--watch` follows it immediately.
- `vrl watch` (alias `track`) — live-poll a CVE until a terminal state, with a
  pipeline timeline, elapsed time, and a `--verbose` poll log.
- `vrl show` (alias `status`) — the full write-up of one CVE: status, weakness,
  severity/EPSS, AI-XI difficulty, cost, tokens, time, verdict, remediation.
- `vrl list` (alias `feed`) — browse the live queue with status/source/order
  filters.
- `vrl stats` — per-status queue depth plus program-level economics.
- `vrl auth whoami` / `vrl auth token` — resolve and inspect internal credentials.
- `--json` on read commands; `--base-url`, `--token`, `--no-color`, `--version`.

### Notes
- Public submit against production requires a browser-obtained Cloudflare
  Turnstile token (`--turnstile-token`); a `--browser` helper to obtain it
  automatically is planned.
