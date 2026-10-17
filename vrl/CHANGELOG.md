# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `vrl submit` — queue a CVE via the public email path, `--internal` using a
  Google OIDC token / shared secret, or `--browser` to hand off to the
  website's Turnstile-protected form (the CVE id lands in the clipboard).
  `--watch` follows it immediately.
- `vrl watch` (alias `track`) — live-poll a CVE until a terminal state, with a
  pipeline timeline, elapsed time, and a `--verbose` poll log.
- `vrl show` (alias `status`) — the write-up of one CVE: status, weakness,
  severity/EPSS, and — with `--internal` — cost, tokens, AI-XI, verdict,
  remediation. Without it, the public view, named as such.
- `vrl replay <CVE>` — what happened when a processed CVE ran: every attempt,
  what the judge rejected each one for, and how it ended. `--internal` adds the
  operator's demo view (the agent's reasoning and the full verdict).
  `--list` shows coverage — replay covers corpus-harness runs only, and a CVE
  with a queue row but no trace gets an error that says exactly that (with the
  traces on file), not a bare "Not found".
- `vrl list` (alias `feed`) — browse the live queue with status/source/order
  filters; `--internal` for full records.
- `vrl stats` — per-status queue depth plus program-level economics.
- `vrl auth whoami` / `vrl auth token` — resolve and inspect internal credentials.
- `--internal` on read commands attaches the operator credential (minted via
  gcloud / google-auth) for the full record; without it the API's public
  projection is returned and rendered with an honest `public view` note.
- `--json` on read commands; `--base-url`, `--token`, `--no-color`, `--version`;
  `VRL_SUBMIT_URL` overrides the `submit --browser` form URL.

### Notes
- The API's read plane now projects records for anonymous callers (paid-feed
  data, cost/tokens, AI-XI, verdicts hidden), which is why reads are tiered:
  pass `--internal` (or set `VRL_TOKEN`) for the full record.
