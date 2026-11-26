# LeakHound — Secret Reconnaissance Orchestrator (v2.4.1)

`leakhound.sh` turns the single-purpose gitleaks pre-commit hook into a broader
secret-reconnaissance tool for **authorized** penetration tests, red-team
repository reconnaissance, and internal exposure audits.

It fuses **gitleaks** (fast pattern/history scanner) with **trufflehog**
(entropy + provider-aware, with optional live verification), normalizes both into
one schema, triages by severity, dedupes, **corroborates findings across engines**,
**probes live web roots for exposed `.git`/`.env`/backups**, **crawls for
JS/JSON/config assets** (with anchored-regex asset matching), splits out **LIVE
(verified) credentials**, maps findings to **tunable SARIF rules**, and emits
JSON / CSV / **SARIF** / Markdown.

> Only scan assets you are authorised to test. Verify ownership or written
> permission (bug bounty scope / engagement letter) before scanning anything.

## Requirements
- `gitleaks` (v8.19+; tested on 8.30.1)
- `trufflehog` (v3.x; tested on 3.99.2)
- `jq`, `python3`, `git`
- `curl` (web mode)
- `gitdumper` (optional — required for `web … --dump` history recovery)
- `katana` (optional — deeper crawl; falls back to robots/sitemap/link harvest.
  `gospider` is a secondary fallback, see Known limitations)
- `shellcheck` (optional — only for the CI lint job / local linting; the shipped
  script and the regression suite are clean at `-S warning`)

## Install
```bash
chmod +x leakhound.sh
# optional: sudo install -m0755 leakhound.sh /usr/local/bin/leakhound
```

## Commands
```text
leakhound.sh repo  <path|url>   scan a git repository's FULL HISTORY (local path or remote URL)
leakhound.sh dir   <path>       scan a directory / filesystem tree
leakhound.sh list  <file>       scan every target listed in a file (one per line)
leakhound.sh web   <url>        probe a web root for exposed .git/.env/backups/configs
                                (--crawl) harvest robots.txt/sitemap/links (+katana) and
                                scan discovered JS/JSON/config assets
                                (--dump)  additionally recover the .git repo + download
                                exposed files, then scan recovered history + contents
```

### Options
| Flag | Meaning |
|------|---------|
| `-e, --engines` | `gitleaks` (default) \| `trufflehog` \| `both` (run in parallel) |
| `-o, --outdir` | output directory (default `./leakhound-out`) |
| `-f, --format` | any of `json,csv,sarif,md` (default `json,csv,md`) |
| `-s, --severity` | minimum severity to report: `low`\|`medium`\|`high`\|`critical` |
| `-c, --config` | config file passed to the engine(s) |
| `-b, --baseline` | gitleaks baseline report — suppress already-known findings (CI-friendly) |
| `--fail-on` | exit non-zero if findings at/above `critical`\|`high`\|`medium`\|`any`\|`verified`\|`exposure` |
| `--verify` | **NETWORK:** actively validate credentials via provider APIs (trufflehog) |
| `--verify-allowlist` | with `--verify`, restrict trufflehog to these detector(s); names/IDs/ranges; repeatable |
| `--show-secrets` | write raw secret values (default: redacted) |
| `--dump` | web mode: recover `.git` and download exposed files, then scan them |
| `--crawl` | web mode: harvest robots/sitemap/links (+katana) and scan found assets |
| `--crawl-depth` | katana crawl depth (default `2`) |
| `--asset-ext` | crawl: strict extension allowlist for downloads (e.g. `js,map,json`) |
| `--asset-always` | crawl: always-include exceptions (extension or name substring); repeatable |
| `--asset-glob` | treat each `--asset-always` entry as an **anchored regex** (full-match) against the filename, e.g. `id_.*` or `\.env\..*` |
| `--sarif-rule-map` | JSON file mapping a rule name to `{id,level,name,helpUri}` overrides for the SARIF output |
| `--history-only` | with `dir`/`list`, scan git **history** (repo mode) instead of the working tree |
| `--excludepaths` | comma-separated regex; skip matching paths/URLs **and** tell katana they are out of scope |
| `-H, --header` | extra HTTP header, repeatable (auth tokens/cookies) |
| `--cookie` | Cookie header value |
| `--proxy` | route web requests through a proxy (e.g. Burp: `http://127.0.0.1:8080`) |
| `--delay` | sleep N seconds between web requests (rate courtesy) |
| `-A, --user-agent` | override User-Agent |
| `--keep-clones` | keep cloned mirrors |
| `--timeout` | per-engine timeout (seconds) |
| `-q, --quiet` | suppress progress output |
| `-V, --version`, `-h, --help` | |

## Examples
```bash
# Local repo, full history, default engine
./leakhound.sh repo ./myapp

# Remote repo (clones a full mirror, then scans history)
./leakhound.sh repo https://github.com/org/repo.git

# Filesystem tree, both engines, fail the job if anything HIGH+ is found
./leakhound.sh dir /srv/www --engines both --fail-on high

# Probe in-scope web host for exposed .git/.env; recover + scan on hit
./leakhound.sh web https://target.example.com --dump --crawl -e both -f json,sarif

# SPA secret harvest: ONLY JS bundles + source maps, PLUS any id_rsa/.htpasswd
./leakhound.sh web https://app.example.com --crawl \
  --asset-ext js,map,json --asset-always 'id_rsa,.htpasswd'

# Same, but treat the exceptions as ANCHORED regexes (only exact "id_rsa",
# plus any ".env.*" file such as .env.local / .env.backup)
./leakhound.sh web https://app.example.com --crawl --asset-ext js,map,json \
  --asset-glob --asset-always 'id_rsa' --asset-always '\.env\..*'

# Scan only committed history of a working directory (ignore the live checkout)
./leakhound.sh dir /srv/app --history-only -e both -f json,sarif

# CI: emit SARIF with per-rule id/level/name/helpUri overrides
./leakhound.sh repo ./myapp -f sarif --sarif-rule-map rules.json

# Authenticated web recon, skipping out-of-scope paths, via Burp
./leakhound.sh web https://app.example.com --crawl \
  -H "Authorization: Bearer $TOKEN" \
  --excludepaths '/logout,/admin,/signout' \
  --proxy http://127.0.0.1:8080 --delay 0.5

# Batch several targets, only CRITICAL, JSON out
./leakhound.sh list targets.txt -e both -s critical -f json -o ./report

# CI gate: ignore what we've already triaged
./leakhound.sh repo ./myapp -e gitleaks -b baseline.json --fail-on high

# Validate creds, but ONLY against Slack + GitHub (nothing else leaves the host)
./leakhound.sh repo ./myapp --engines trufflehog --verify --verify-allowlist Slack,github
```

## Output
Written to `--outdir`:
- `findings.json` — normalized, deduped, severity-sorted findings (canonical output)
- `findings.csv` — spreadsheet-friendly
- `findings.sarif` — **SARIF 2.1.0**, for GitHub code scanning / IDE / CI ingest
- `report.md` — prioritized human-readable report
- `verified.json` + `live-credentials.md` — **only when `--verify` returns live creds**
- `gitleaks.json` / `trufflehog.json` — raw engine evidence (preserved; the gitleaks
  file is an NDJSON accumulator so multi-stage scans do not clobber earlier results)

### Normalized schema
```json
{
  "engine": "gitleaks",
  "rule": "private-key",
  "description": "...",
  "file": "config.py",
  "line": 1,
  "commit": "<sha>",
  "author": "Dev",
  "date": "2026-10-12T06:20:28Z",
  "secret": "[REDACTED]",
  "verified": false,
  "corroborated": false,
  "severity": "critical"
}
```
Web-exposure findings add `"exposure": true` (and are never counted as live creds).

### Reading the results
- **`corroborated: true`** — the same file/commit/line was flagged by *both*
  engines. Highest-confidence hits; prioritise these.
- **`exposure: true`** — a live web resource (e.g. `/.git/HEAD`, `/.env`) was
  actually served (HTTP 200 + content marker). These are confirmed disclosures.
- **`verified: true`** — trufflehog independently authenticated the credential
  against the provider API (`--verify`). Treat as compromised; rotate now.

### SARIF rule mapping (`--sarif-rule-map`)
`findings.sarif` is SARIF 2.1.0 (driver `LeakHound`, version tracks the script).
By default each finding's SARIF `ruleId` is its engine rule name and `level` is
derived from severity (`critical`/`high`→`error`, `medium`→`warning`, `low`→`note`).
`--sarif-rule-map FILE` lets you override that per rule so the SARIF lines up
with your own rule catalogue / code-scanning policy:
```json
{
  "private-key": {
    "id": "LH-KEY-001",
    "level": "note",
    "name": "Leaked Private Key",
    "helpUri": "https://example.org/rules/LH-KEY-001"
  }
}
```
`id` replaces the `ruleId`/rule entry id, `level` overrides the SARIF result
level, `name` sets the rule's display name / short description, and `helpUri`
adds the rule help link. Rules without an entry keep their defaults, and a
missing/broken map file is ignored with a warning (fail-safe). Keys are matched
exactly against the engine rule name (see Known limitations).

### History-only (`--history-only`)
With `dir`/`list`, targets are normally scanned as a **working tree**. `--history-only`
re-routes each local target through **repo mode**, so only committed history is
scanned — the live checkout (including untracked files) is ignored. This is the
right mode for "a secret was committed and then deleted": the working tree looks
clean while the secret survives in history. Non-git paths are warned and yield an
empty history scan.

## Web mode in detail
1. **Static probes** — a curated path list for `.git/`, `.env*`, config backups,
   VCS metadata, archives, and high-value files (`/.aws/credentials`,
   `/.ssh/id_rsa`, `/appsettings.json`, `/web.config`, `/actuator/env`, …). A hit
   requires HTTP 200 **and** a content marker, so plain 200 soft-404s are filtered.
2. **`--crawl`** — reads `robots.txt` (Sitemap/Disallow/Allow), `sitemap.xml`
   (`<loc>` URLs), and homepage `href`/`src`/`action` links; if `katana` is present
   it also crawls to `--crawl-depth` (same registered domain).
3. **Asset selection** — crawled paths that return 200 and are ≤2 MB are downloaded
   and scanned. Which ones is controlled by, in priority order:
   - **`--asset-always LIST`** — *always include*: each entry is an **extension or a
     filename (basename) substring**, matched **case-insensitively**. Matches pass
     even in strict mode. Repeatable
     (`--asset-always id_rsa --asset-always .htpasswd`, so `ID_RSA`/`.HTPASSWD` also
     match). Use it to guarantee high-value extensionless files (SSH keys,
     `htpasswd`, `.npmrc`, …) are never filtered out. Matching is against the
     **filename only**, so a *directory* named `id_rsa` no longer drags in every
     file beneath it.
     - **`--asset-glob`** switches these entries from *substring* to **anchored
       regex** matching against the filename (whole-name match, case-insensitive).
       This avoids over-matching: `--asset-always id_rsa` with `--asset-glob`
       matches exactly `id_rsa` (not `id_rsa_backup`), while `id_.*` matches both,
       and `\.env\..*` matches `.env.local`/`.env.backup`. The startup banner tags
       the list `[anchored-regex]` so the active mode is explicit.
   - **`--asset-ext LIST`** — *strict*: only these extensions pass
     (e.g. `js,map,json`). Best for focused SPA bundle / source-map harvesting.
   - **default (neither flag)** — a broad text/source set (`.js/.json/.map/.xml/`
     `.yml/.env/.config/.txt/.php/.sql/.pem/.key/…`) **plus** any sensitive-named
     file (contains *env/config/secret/credential/password/token*, or `id_rsa`/
     `htpasswd`, etc.) regardless of extension.
   Sensitive-named assets that are downloaded are also reported directly as
   `crawl-sensitive-asset` exposures.
4. **`--dump`** — on a `.git` hit, `gitdumper` recovers the repo and LeakHound scans
   the recovered **history**; other exposed files are downloaded and scanned too.
5. **Scope control** — `--excludepaths` filters the probes, the download step, **and
   is forwarded to katana as out-of-scope regexes** so the crawler does not fetch
   paths you have excluded.

## Severity triage
Rule/detector names are mapped heuristically:
- **critical** — private keys, SSH/RSA/PGP, AWS/GCP/Azure/Stripe/Slack/Heroku/OpenAI,
  GitHub/GitLab/JWT, DB connection strings, Docker/K8s/Vault/NPM/PyPI, and any
  confirmed `exposed-git`/`exposed-env`/`exposed-aws-creds`/`exposed-gcp-creds`
- **high** — generic API keys, access/client tokens, passwords, OAuth/bearer, backups,
  and `crawl-sensitive-asset`
- **low** — `.DS_Store`, API-doc/OIDC listings and other path-disclosure noise

## Safety model
- **Redaction is enforced by LeakHound itself**, not merely delegated to the
  engines. `secret` is written as `[REDACTED]` by default; `--show-secrets` is the
  only way to get raw values (and it warns). This matters because trufflehog's own
  `Redacted` field still leaks a prefix of high-value secrets such as private keys.
- **Verification is opt-in and can be scoped.** With `--verify`, secrets are
  submitted to provider APIs — network traffic attributable to you. Add
  **`--verify-allowlist Slack,github`** to restrict trufflehog to those detectors
  only, so **no verification traffic can reach any provider you did not name**.
  Without the allowlist, verification covers every detector trufflehog runs.
- **Web mode probes live targets** — the tool prints a scope reminder and only
  issues read-only `GET` requests. `--crawl`/`--delay`/`--asset-ext`/`--asset-always`/
  `--asset-glob` bound and pace it; `--excludepaths` keeps you inside scope.
- **Scope control is explicit** — pass `--excludepaths` for any path you must not
  touch; it is honoured by probes, downloads, and katana.
- **No exfiltration.** Nothing leaves the host except opt-in verification calls.
- **Exit codes:** `0` success, `1` `--fail-on` triggered, `2` usage/target error.

## Notes from validation
**v2.0.0** — local lab (git repo with a private key + `.env` in history, exposed
over HTTP with `.git/` and `.env` accessible):
- Web mode detected 4 exposures, recovered the repo, and surfaced findings from
  **both** the recovered history *and* the downloaded `.env` (previously one stage
  overwrote the other).
- `id_rsa` was flagged by gitleaks **and** trufflehog at the same location and
  marked `corroborated: true`.
- `--baseline` suppressed all known findings; without it they reappear.
- `list` mode kept findings from every target.
- No raw secret material was present in any emitted report in default (redacted) mode.

**v2.1.0** — crawl lab (site with `robots.txt` + `sitemap.xml`, homepage links to a
JS bundle and a JSON config carrying secrets, plus an out-of-scope `/admin` path):
- `--crawl` harvested robots + sitemap, ran katana, and surfaced the private key
  (gitleaks **and** trufflehog, `corroborated`) and the AWS key.
- `--excludepaths '/admin'` produced **0** requests to `/admin` — verified against
  the server access log, and katana was confirmed to skip it too (before the `-cos`
  fix, katana fetched `/admin/panel.html` despite the exclusion).
- `-H 'X-Test: leakhound'` was confirmed, from a header-logging server, to be sent
  on every request alongside the custom User-Agent.

**v2.2.0** — asset filter + verification guard:
- `--asset-ext json` downloaded/scanned **only** the JSON config; `--asset-ext
  js,map` downloaded **only** the JS bundle; default (no flag) took the JS + JSON +
  text assets.
- `--verify` alone detected `PrivateKey`; adding `--verify-allowlist Slack` filtered
  it out (**0 findings**); `--verify-allowlist` without `--verify` warns it is a no-op.

**v2.3.0** — always-include exceptions + allowlist accumulation:
- `--asset-ext json` (strict) alone downloaded **only** `app-config.json`.
  Adding `--asset-always 'id_rsa,.htpasswd'` **also** pulled in the extensionless
  `/.ssh/id_rsa` (containing a private key) and flagged it — the exception overrides
  strict mode as intended.
- Repeating `--asset-always htpasswd --asset-always id_rsa` accumulated correctly to
  `{htpasswd,id_rsa}` (an earlier comma-placement bug that produced
  `{SlackPrivateKey}` was found and fixed by this test).
- Repeating `--verify-allowlist Slack --verify-allowlist PrivateKey` accumulated to
  `{Slack,PrivateKey}` and the PrivateKey detector ran. An unknown detector name
  yielded 0 findings without error (safe fail-closed behaviour).

**v2.4.1** — asset-match correctness fix (patch).
- **`--asset-always` / `--asset-glob` matching is now against the filename
  (basename) and is case-insensitive**, consistent with how `--asset-ext` already
  compares lower-cased extensions. Before: entries were lower-cased at parse time
  but matched case-sensitively against the *whole path*, so a pattern could never
  hit an upper-case name (`ID_RSA`, `.ENV.LOCAL`) and a *directory* name could
  spuriously match. The default sensitive-name fallback (`…env/config/id_rsa…`) is
  also now case-insensitive. Verified by an extracted-function truth table (below).
- No CLI or output-schema changes; SARIF driver version now reports `2.4.1`.

**v2.4.1 (tooling)** — regression suite + CI/commit-gate integration:
- ShellCheck is clean at `-S warning` for **both** `leakhound.sh` and
  `tests/leakhound-regression.sh` (ShellCheck 0.11.0). Fixes: removed an unused
  `C_CYA`, dropped a `*htpasswd*` case subsumed by `*passwd*` (SC2221/SC2222),
  used `read -r p _` where the second field was unused, and added targeted
  `shellcheck disable` directives to the suite for deliberately-unused fixture
  globals plus `|| exit` on `cd` (SC2164).
- The dependency-free suite passes **47/0/0** against `leakhound.sh` v2.4.1.
- The CI workflow's two new jobs were proven in an isolated fixture before
  delivery: the `upload-sarif` command emitted a valid, non-empty SARIF 2.1.0
  document (driver `LeakHound` 2.4.1, ≥1 result + rule), and the
  `.pre-commit-hooks.yaml` command line (`dir . --engines gitleaks --format sarif
  --fail-on high --quiet`) blocked a working-tree private key and passed on a
  clean tree (an isolated end-to-end check, not a live GitHub run — the actual
  `upload-sarif` step needs GitHub's `security-events` permission and was not
  executed here).
- **Dedup fix (redacted-mode over-collapse).** Findings are now deduped on
  `(rule, file, commit, line, secret)`. Previously the key omitted `line` and used
  the secret field — which in default (redacted) mode is the literal
  `[REDACTED]` for every finding — so two *distinct* secrets matching the *same*
  rule in the same file/commit collapsed into a single finding and silently
  under-reported. Reproduced and re-verified: a file with two distinct RSA keys
  now yields **2** `private-key` findings in both default and `--show-secrets`
  modes (before the fix: 1 vs 2).

**v2.4.0** — anchored asset globs, SARIF rule mapping, history-only. Lab: a repo
with an RSA key **committed then deleted** (key present in history, absent from the
working tree) plus a local web root serving `id_rsa`, `id_rsa_backup`, `.env.backup`,
`data.txt`:
- **`--history-only`**: `dir <repo>` found **0** (key is gone from the working tree);
  `dir <repo> --history-only` found **1** `private-key` (from history). `repo` mode
  with both engines marked the key `corroborated: true` (gitleaks `private-key` +
  trufflehog `PrivateKey`). In `list` mode the same flag re-routed the git path and
  warned that the non-git path yields an empty history scan.
- **`--asset-glob`**: with `--asset-ext txt --asset-always id_rsa`, substring mode
  downloaded **3** assets (incl. `id_rsa_backup`); adding `--asset-glob` downloaded
  **2** — the anchored match no longer over-matches `id_rsa_backup`. A direct
  function-level truth table confirmed `id_.*` matches both while `\.env\..*` matches
  `.env.backup` but not `my.env.backup`.
- **`--sarif-rule-map`**: mapping `private-key → {id:LH-KEY-001, level:note, name,
  helpUri}` produced a SARIF whose rule id/name/helpUri and result level were all
  overridden (default was `error`), while the unmapped trufflehog `PrivateKey` rule
  kept its defaults; `findings.sarif` reports driver version `2.4.1`.

## Testing & CI
A dependency-free regression suite lives at [`tests/leakhound-regression.sh`](tests/leakhound-regression.sh).
It emits TAP-style output and exits non-zero on the first failing assertion set, so
it drops straight into any CI runner.

```bash
# from the repo root (expects ./leakhound.sh next to tests/)
bash tests/leakhound-regression.sh

# point at a script elsewhere, or run on a machine without gitleaks
tests/leakhound-regression.sh   # honors LEAKHOUND=/path/to/leakhound.sh
LH_SKIP_E2E=1 bash tests/leakhound-regression.sh   # unit tests only, 3 e2e skipped
```

What it covers:
- **Unit truth tables** for `asset_wanted()` and `path_excluded()` — the real
  functions are extracted from the shipped `leakhound.sh` with `awk` at runtime, so
  the suite can never drift from a hand-copied replica. Covers substring vs. anchored
  glob matching, case-insensitivity, strict `--asset-ext` precedence, filename
  narrowing, and the default whole-path sensitive-name fallback.
- **CLI contract** — `bash -n`, `--version`/`--help`, documented flags, `2.4.1` string,
  and exit-code `2` for bad command / missing file.
- **End-to-end — gitleaks** (self-skips without `gitleaks`) — a throwaway git repo
  commits then deletes an RSA key to prove `--history-only` finds it while the
  working-tree scan does not; plus the `--fail-on critical` gate (exit 1) and
  `--sarif-rule-map` ruleId/level override.
- **End-to-end — trufflehog** (self-skips without `trufflehog`) — a second fixture
  proves trufflehog detects the key in history (exercising the local-path → `file://`
  URI normalization) and that `-e both` marks the finding **corroborated** across
  both engines.

Design choices: the *suite itself* needs no `bats`/`shellcheck` dependency (works
on a bare image); e2e fixtures and outputs are written under a private `mktemp -d`
that is removed on exit; every assertion is plain `sh`, so wrapping with `bats -c`
is optional. (The CI adds a separate ShellCheck job for the *shipped* script —
see below.)

### CI wiring

A ready-to-use GitHub Actions workflow is committed at
[`.github/workflows/leakhound-regression.yml`](.github/workflows/leakhound-regression.yml).
It runs **five** jobs:

1. `shellcheck` — lints `leakhound.sh` and `tests/leakhound-regression.sh` at
   `-S warning` (fails the build on any warning-or-worse).
2. `unit-and-cli` — the fast gate (`LH_SKIP_E2E=1`, no engines needed).
3. `full` — a pinned gitleaks is installed so the e2e group runs.
4. `trufflehog-e2e` — pinned gitleaks + trufflehog, exercising the local-path
   `file://` normalization and the cross-engine corroboration assertion.
5. `upload-sarif` — self-scans the repo (gitleaks engine) and uploads
   `findings.sarif` to **GitHub code scanning** via
   `github/codeql-action/upload-sarif@v3`, so LeakHound hits appear in the
   Security → Code scanning tab. This job needs `permissions: security-events: write`
   (plus `actions: read` for **private** repos) and `fetch-depth: 0` (full history);
   it deliberately has no `--fail-on`, so it only feeds the dashboard while the
   suite jobs own pass/fail gating. It also skips **fork** PRs
   (`if: github.event_name != 'pull_request' || …head.repo.full_name == github.repository`),
   because a fork PR receives a read-only `GITHUB_TOKEN` and the upload would fail.

```yaml
name: leakhound-regression
on:
  push:
    branches: ["**"]
  pull_request:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: shellcheck -S warning leakhound.sh
      - run: shellcheck -S warning tests/leakhound-regression.sh
  unit-and-cli:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y jq
      - env: { LH_SKIP_E2E: "1" }
        run: bash tests/leakhound-regression.sh
  full:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y jq
      - env: { GITLEAKS_VERSION: "8.30.1" }
        run: |
          curl -sSfL \
            "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
            | sudo tar -xz -C /usr/local/bin gitleaks
      - run: bash tests/leakhound-regression.sh
  trufflehog-e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y jq
      - env: { GITLEAKS_VERSION: "8.30.1" }
        run: |
          curl -sSfL \
            "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
            | sudo tar -xz -C /usr/local/bin gitleaks
      - env: { TRUFFLEHOG_VERSION: "v3.99.2" }
        run: |
          curl -sSfL \
            https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
            | sudo sh -s -- -b /usr/local/bin "${TRUFFLEHOG_VERSION}"
      - run: bash tests/leakhound-regression.sh
  upload-sarif:
    runs-on: ubuntu-latest
    # skip fork PRs (read-only token) -- run on push/dispatch + same-repo PRs
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    permissions: { contents: read, actions: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: sudo apt-get update && sudo apt-get install -y jq
      - env: { GITLEAKS_VERSION: "8.30.1" }
        run: |
          curl -sSfL \
            "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
            | sudo tar -xz -C /usr/local/bin gitleaks
      - run: |
          bash leakhound.sh dir . --engines gitleaks --format sarif --outdir lh-sarif
          test -s lh-sarif/findings.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: lh-sarif/findings.sarif, category: leakhound }
```

Notes for other runners:
- The committed workflow pins `gitleaks` to `8.30.1` and `trufflehog` to `v3.99.2`
  for reproducibility; bump those env values when you want newer engines.
- Suite requirements are just `bash`, `git`, and `jq`; add `gitleaks` (and optionally
  `trufflehog`) to exercise the e2e group, or set `LH_SKIP_E2E=1` to get a pure
  unit/CLI gate on a minimal image. The `shellcheck` job additionally needs
  `shellcheck` (preinstalled on `ubuntu-latest`).
- No network access is needed for the unit groups; the e2e group is fully offline
  (a local `git init` repo), so it is safe in a sandboxed runner.
- Run it from the repo root, or set `LEAKHOUND=/abs/path/leakhound.sh`.
- The `upload-sarif` job writes `findings.sarif` with
  `leakhound.sh dir . --engines gitleaks --format sarif` and ingests it with
  `github/codeql-action/upload-sarif`. GitHub requires `security-events: write`
  for that step (and `actions: read` for private repos); without them the upload
  fails with a permissions error. Public repos get code scanning free; **private/
  internal repos need GitHub Code Security enabled**, otherwise the upload returns
  `403: GitHub Code Security or GitHub Advanced Security is not enabled`. Fork-PR
  runs are skipped (read-only token).
- ShellCheck is pinned only by the runner image; the script is gated at
  `-S warning` and is clean against ShellCheck 0.11.0.

### Pre-commit hook

Two integration paths are committed so LeakHound can gate commits locally, not
just in CI:

- **`.pre-commit-hooks.yaml`** — makes LeakHound consumable by the
  [`pre-commit`](https://pre-commit.com) framework (`language: script`, so the
  hook repo is cloned and `leakhound.sh` is run directly — no extra runtime).
  Downstream repos add:
  ```yaml
  repos:
    - repo: <url-of-this-leakhound-repo>
      rev: v2.4.1
      hooks:
        - id: leakhound
  ```
  The hook runs `leakhound.sh dir . --engines gitleaks --format sarif
  --fail-on high --quiet` (`pass_filenames: false`, `always_run: true`), so a
  `high`+ secret in the working tree blocks the commit while a SARIF report is
  left on disk.
- **`.pre-commit-config.yaml.example`** — a copy-paste config showing both the
  remote-repo form and a `language: system` form for a `leakhound.sh` you already
  keep in the repo.

`setup-gitleaks-hook.sh` (repo root) remains the dependency-free alternative: it
installs a raw `git` `pre-commit` hook that shells out to `gitleaks git --staged`,
chains to any pre-existing hook, and needs no `pre-commit` framework at all. Use it
when you want a single-binary staged scan; use `pre-commit` when you already run
that framework for other linters.

## Known limitations
- trufflehog's `git` source requires a **URI**: LeakHound normalizes local paths to
  `file://…` automatically, but be aware a bare `trufflehog git /path` returns
  nothing (observed on v3.99.2).
- **`--verify-allowlist` also narrows *detection*, not just verification.** It maps
  to trufflehog's `--include-detectors`, so detectors outside the list do not run.
  That makes it a strong safety control, but you will not *see* findings from other
  detectors in that same run — do a non-verifying pass too for full coverage.
- **Detector NAMES are confirmed working; numeric IDs / ranges are passthrough
  only.** trufflehog documents that `--include-detectors` accepts "Protobuf name or
  IDs … as well as ranges", and LeakHound passes the value through verbatim, but a
  positive test with a numeric/range value (`0-10000`) returned 0 findings in this
  environment, so treat ID/range forms as unverified and prefer names.
- Web probes use HTTP 200 + a content marker; a soft-404 SPA that returns 200 with
  marker-like content could over-report entries whose marker is a catch-all (e.g.
  `/.hg`, `/backup.tar.gz`). Treat those as leads and eyeball the URL.
- **`--excludepaths` only extends to katana, not gospider.** If katana is absent and
  the tool falls back to gospider, LeakHound warns that excluded paths may still be
  crawled. Install katana for scoped crawling.
- `--crawl` downloads up to 500 crawled paths and skips files >2 MB; `--crawl-depth`
  only affects the katana stage, not the robots/sitemap/link harvest (single pass).
- **`--sarif-rule-map` keys are matched exactly (case-sensitive) against the engine
  rule name**, and engines name the same class differently (gitleaks `private-key`
  vs trufflehog `PrivateKey`). Map each engine's spelling you care about; unmatched
  rules silently keep their defaults.
- **`--asset-glob` entries are anchored full-match regexes**, so a bare `id_rsa`
  matches only `id_rsa`. Use `id_.*` for prefixes and escape dots (`\.env\..*`); an
  invalid regex simply does not match. Both `--asset-glob` and substring
  `--asset-always` matching are **case-insensitive** and evaluated against the
  filename only (see the v2.4.1 changelog entry).
- **`--history-only` requires git.** Non-git paths are converted to a (empty) history
  scan with a warning; untracked and modified-but-uncommitted files are never seen.
- Severity mapping is keyword-based and will over/under-rate some rules; tune it in
  the `normalize()` step for your environment.
- Dedup is keyed on `(rule, file, commit, line, secret)`. In the rare case of the
  *same* secret value appearing on the *same* line under the *same* rule, the two
  are collapsed by design. Cross-engine hits are never deduped (engines name the
  same class differently), which is what preserves the `corroborated` signal.
- The SARIF driver's `informationUri` is emitted **only** when you set the
  `LEAKHOUND_INFO_URI` environment variable (e.g.
  `LEAKHOUND_INFO_URI=https://github.com/you/leakhound ./leakhound.sh …`).
  Left unset, the field is omitted (it is optional in SARIF 2.1.0) rather than
  pointing at an unrelated project.
- trufflehog line numbers are provider/metadata dependent and may be absent.
- Remote scanning clones a full mirror; large repos take time/space.
- gitleaks' upstream integrity story remains checksum-only (no signing); this tool
  does not alter that.
