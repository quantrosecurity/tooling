# vrl

A command-line client for **[Vulnerability Research Labs](https://vrl.quantrosecurity.ai)** (VRL).

Submit a CVE for processing, watch it move through the pipeline live, and read the
result — all from your terminal. `vrl` is a thin, read-mostly client over the
**public** VRL HTTP API; it ships nothing proprietary and talks only to the
documented contract.

```text
$ vrl show CVE-2024-27198
╭─ CVE-2024-27198  TeamCity authentication bypass ────────────────────────────╮
│  ✓ Submitted → ✓ Queued → ✓ Processing → ✓ Exploit generated                │
│  A working exploit was produced and verified against a live lab.            │
│                                                                             │
│            Status   Exploit generated                                       │
│           Outcome   verified                                                │
│  AI-XI difficulty   ●●●○○ (3/5)                                             │
│              Cost   $3.82                                                   │
│            Tokens   419.8k                                                  │
│           Verdict   exploit fired, negative control holds, sham clean       │
╰─────────────────────────────────────────────────────────────────────────────╯
```

## Run it from this repo (no install)

`vrl` is designed to run straight from the checkout — you point at the launcher
binary, nothing lands on your global PATH:

```bash
git clone https://github.com/quantrosecurity/tooling
cd tooling

./vrl/bin/vrl --help
./vrl/bin/vrl stats
./vrl/bin/vrl show CVE-2024-27198
```

The launcher ([`vrl/bin/vrl`](bin/vrl)) uses [`uv`](https://docs.astral.sh/uv/)
to build an isolated environment from `vrl/pyproject.toml` on first run
(`vrl/.venv`, created once; later runs are instant). If `uv` isn't present it
falls back to a plain `python3 -m venv`. Either way, nothing is installed
system-wide.

Prefer typing just `vrl`? Put the launcher on your PATH for the session:

```bash
export PATH="$PWD/vrl/bin:$PATH"
vrl stats
```

> Want a real install instead? `pipx install ./vrl` or `uv tool install ./vrl`
> also work and give you a `vrl` command. The launcher above is the no-install path.

## Quickstart

```bash
vrl submit CVE-2024-4577 --email you@example.com --name "Ada"  # queue it (public)
vrl watch  CVE-2024-4577                                        # follow it live
vrl show   CVE-2024-4577                                        # read the write-up
vrl list   --status processing                                 # see what's running
vrl stats                                                       # queue depth + economics
```

(Replace `vrl` with `./vrl/bin/vrl` if you didn't add it to your PATH.)

## Commands

| Command | What it does |
| --- | --- |
| `vrl submit <CVE>` | Queue a CVE. Public path needs `--email` (+ `--name`); `--internal` uses your own credentials. `--watch` follows it. |
| `vrl watch <CVE>` | Live-poll a CVE until it finishes. `--verbose` shows the poll log. (alias: `track`) |
| `vrl show <CVE>` | The full write-up — status, weakness, difficulty, cost, verdict. (alias: `status`) |
| `vrl list` | Browse the live queue. `--status`, `--source`, `--order`, `--limit`. (alias: `feed`) |
| `vrl stats` | Per-status queue depth and program-level economics. |
| `vrl auth whoami` | Resolve a credential and show the identity it carries. |

Add `--json` to any read command for machine-readable output, and `--version`
for the installed version. Reads (`show`, `watch`, `list`, `stats`) need **no
credentials**.

## Submitting a CVE

### Public path (anyone)

Mirrors the [website form](https://vrl.quantrosecurity.ai): you give your **name**
and **email**, and the result is emailed to you when it starts and finishes.

```bash
vrl submit CVE-2024-4577 --email you@example.com --name "Ada Lovelace"
```

The public endpoint is protected by **Cloudflare Turnstile**. A terminal can't
solve an interactive challenge, so against the production service you must pass a
browser-obtained token:

```bash
vrl submit CVE-2024-4577 -e you@example.com -n "Ada" --turnstile-token "<token>"
```

> A `--browser` helper that obtains the token for you is planned. Until then, the
> friendliest way for most people to submit is the website; this CLI shines for
> **tracking and reading results**, which need no token at all.

### Internal path (operators)

If you have access to the service's Google Cloud project, submit directly against
the privileged plane — no email, no Turnstile:

```bash
export VRL_INTERNAL_SA="<the allow-listed service account email>"
vrl submit CVE-2024-4577 --internal --watch
```

See [Authentication](#authentication).

## Authentication

Reads and the public `submit` need **no credentials**. Only the `--internal`
plane does, and `vrl` resolves a bearer token in this order:

1. `--token <value>` (an OIDC token *or* a break-glass shared secret);
2. the `VRL_TOKEN` environment variable;
3. a freshly minted **Google OIDC** identity token — in-process if the optional
   `auth` extra is installed, otherwise by shelling out to `gcloud`.

Minting impersonates the service account named by `VRL_INTERNAL_SA` (or uses the
ambient identity on a GCP workload) and sets the token's audience to the API base
URL, equivalent to:

```bash
gcloud auth print-identity-token \
  --impersonate-service-account="$VRL_INTERNAL_SA" \
  --audiences="$VRL_API_BASE" --include-email
```

Check what you'd present with `vrl auth whoami`, or print a token with
`vrl auth token`.

## Configuration

Everything has a sensible default; override via flags or environment variables.

| Env var | Flag | Default |
| --- | --- | --- |
| `VRL_API_BASE` | `--base-url` | `https://api.vrl.quantrosecurity.ai` |
| `VRL_TOKEN` | `--token` | — |
| `VRL_INTERNAL_SA` | — | — (required for off-GCP `--internal` use) |
| `VRL_OIDC_AUDIENCE` | — | the API base URL |
| `VRL_TURNSTILE_TOKEN` | `--turnstile-token` | — |

## Status lifecycle

```text
pending ──▶ processing ──▶ exploit_generated   a working, verified exploit
                        ├─▶ no_exploit          lab ran, nothing reproducible (honest negative)
                        ├─▶ failed              build/infra error before a verdict
                        ├─▶ unsupported         out of scope for the Linux/container pipeline
                        └─▶ insufficient_metadata  skipped — no version data to pin (recoverable)
```

## Development

```bash
cd vrl
uv venv && uv pip install -e '.[dev,auth]'
uv run pytest        # 54 tests, fully offline (HTTP mocked)
uv run ruff check .
```

No network and no credentials are needed to run the tests.

## License

[Apache-2.0](../LICENSE) — see the repository-root license file.
