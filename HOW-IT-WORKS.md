# UserSpice Security Scanner

A local, Docker-based security scanning stack built for UserSpice PHP projects. Runs seven tools — static analysis, PHP taint tracking, PHP code quality, dependency CVEs, secrets detection, runtime HTTP scanning, and header validation — from a single command or web UI.

## Setup

```bash
git clone <this-repo> /var/www/html/codetest
cd /var/www/html/codetest
./setup.sh
```

The setup script checks prerequisites, asks where your projects live, and creates `scanner.conf` (gitignored) with your local settings. It optionally pulls the Docker images (~4GB total).

### Requirements

- **Linux** or WSL2
- **Docker** — all scanners run in containers, nothing installed on your host
- **jq** — processes scan results (`sudo apt-get install jq`)
- **bash 4+** — runs the scan scripts
- **PHP 8.0+** — powers the web UI (optional — CLI works without it)
- **Apache/Nginx** — serves the web UI (optional)

### Web UI Setup

After running `./setup.sh`, the web UI is available at `http://localhost/codetest/ui/`. If the web server user (usually `www-data`) needs to trigger scans from the UI:

```bash
sudo usermod -aG docker www-data
sudo systemctl restart apache2
```

## Quick Start

**Most users will use the web UI for everything.** After running `./setup.sh`, open `http://localhost/codetest/ui/` in your browser. From there you can:

- Browse your projects and kick off scans with one click
- Configure ZAP URL, scan profile, and login credentials in a simple form
- View reports with findings grouped by tool, rule, or file
- Click any finding to see the actual source code with the flagged line highlighted
- Compare scans with delta analysis (new vs resolved findings)
- View finding trends over time with severity breakdowns
- Read these docs right in the UI via the **Docs** button

**No terminal needed for day-to-day use.**

### CLI Reference

For automated testing, custom scripts, or CI/CD integration, the full CLI is available:

```bash
./scan.sh myproject                                        # Static scan
./scan.sh myproject --url http://localhost/myproject/       # Static + ZAP + headers
./scan.sh myproject --url http://localhost/myproject/ \
    --zap-user testuser --zap-pass password                # Authenticated ZAP crawl
./scan.sh myproject --zap-profile quick --url http://...   # Passive-only ZAP scan (~3 min, safe for any env)
./scan.sh myproject --zap-profile deep --url http://...    # Full active scan + Ajax spider (up to ~60 min, local only)
./scan.sh myproject --only semgrep                         # Single tool
./scan.sh myproject --skip psalm,zap                       # Skip specific tools
./scan.sh myproject --include phpstan                       # Include opt-in tools (PHPStan)
./scan.sh myproject --pull                                 # Update Docker images first
./scan.sh myproject --init                                 # Create per-project overrides
./scan.sh myproject --prune 5                              # Keep 5 most recent reports
./scan.sh myproject --threshold high                       # Exit 1 if any high+ findings (CI gate)
./scan.sh myproject --sarif                                # Output SARIF 2.1.0 for GitHub
./scan.sh myproject --diff                                 # Scan only changed files (vs HEAD~1)
./scan.sh myproject --diff main                            # Scan only files changed since main
./scan.sh --check-updates                                  # Check for newer Docker images
./scan.sh --latest myproject                               # Path to most recent report
./scan.sh --list-reports myproject                         # List all reports
```

## What Each Tool Does

| Tool | What it catches | Config |
|------|----------------|--------|
| **Semgrep** | SQL injection, XSS, command injection, insecure crypto, framework bypass patterns, DOM XSS in JS | [Custom rules](shared/semgrep/userspice-rules.yml) + community registry |
| **Psalm** | PHP taint analysis — traces user input through code to dangerous sinks (SQL, HTML, shell, file, SSRF) | [UserSpice stubs](shared/psalm/userspice-stubs.php) teach it which framework functions are safe |
| **Trivy** | CVEs in Composer/npm dependencies, misconfigurations, embedded secrets | [Ignore file](shared/trivy/.trivyignore) |
| **Gitleaks** | Hardcoded API keys, passwords, tokens, credentials | [Allowlist](shared/gitleaks/.gitleaks.toml) |
| **ZAP** | Runtime HTTP vulnerabilities — missing headers, cookies, XSS, info leaks, CSRF gaps | [Rules config](shared/zap/rules.tsv) for suppressing noise |
| **PHPStan** | PHP code quality — type errors, logic bugs, dead code, undefined variables. Complements Psalm's security focus with broader type-level analysis | [Generated neon config](lib/phpstan.sh) with UserSpice-aware suppressions |
| **Headers** | Security response headers — HSTS, CSP, X-Frame-Options, Permissions-Policy, server exposure | Automatic when `--url` is provided |

## How Semgrep Works

Semgrep runs in two passes:

1. **Custom UserSpice rules** — framework-aware patterns that know `DB::query()` is parameterized, `Input::get()` sanitizes, `safeReturn()` escapes HTML, etc. These fire on code that *bypasses* the framework. Runs with `--metrics off` (no telemetry).
2. **Community registry rules** — hundreds of generic PHP/JS security patterns (OWASP Top 10). The generic `unlink-use` rule is excluded since we replace it with a framework-aware variant that only fires when `unlink()` receives user input.

Results are merged and deduplicated. Suppressions are applied later as part of the unified suppression system.

### Inline Suppressions

For code that's been reviewed and is safe, use inline comments instead of suppression entries:

```php
// Semgrep: nosemgrep: rule-name — reason
$token = $_POST['csrf']; // nosemgrep: userspice-direct-superglobal-access

// Psalm: @psalm-taint-escape context
/** @psalm-taint-escape html */ $val = (string)$_GET['msg'];
```

These travel with the code and never break when lines shift.

## Suppressions

The file [shared/suppressions.json](shared/suppressions.json) and per-project `overrides/<project>/suppressions.json` hold cross-tool suppressions applied after the summary is generated. Each entry includes:

- `tool` — which scanner (semgrep, psalm, phpstan, trivy, gitleaks, zap)
- `rule` — the rule ID
- `file` — relative path
- `content_hash` — MD5 of the source line (for exact matching)
- `scope` — matching granularity:
  - **exact** — matches on `tool + rule + file + content_hash` (falls back to `tool + rule + file + line`)
  - **file** — suppresses all findings of that rule in that file
  - **rule** — suppresses all findings of that rule everywhere
  - **glob** — `file` is treated as a glob pattern (e.g. `users/admin.php`, `users/admin_*.php`, `usersc/plugins/*/views/*.php`). Pre-expanded against the project's file list at suppression time for O(1) matching.
- `reason` — why this finding is suppressed

**Matching uses `content_hash`**, not line numbers. This means suppression entries survive code being added above them — the hash matches the actual code content, not its position. Falls back to `tool + rule + file + line` for entries without a content hash.

Suppressions can be managed from the web UI (suppress/unsuppress buttons) or by editing the JSON files directly. Project-level suppressions override shared ones. The shared file ships with the scanner and includes ~85 reviewed framework-level entries.

Suppressions should stay small. If a category of findings repeats, fix it in rules/stubs/scoping instead of adding more suppression entries.

## Owner Classification

Every finding is tagged with an owner:

| Owner | Meaning | Action |
|-------|---------|--------|
| **project** | Your code outside the UserSpice framework | Fix it |
| **userspice-core** | Files in `users/` that ship with UserSpice | Report upstream, don't patch locally |
| **userspice-customizable** | Files in `usersc/` — shipped with UserSpice but you can modify | Your call |
| **dependency** | Trivy CVE in a Composer/npm package | Update the package |

## Severity Normalization

Every finding has a `normalized_severity` field mapped to a unified scale: `critical`, `high`, `medium`, `low`, `info`. The summary includes a `severity_summary` with counts at each level.

| Tool | Original | Normalized |
|------|----------|------------|
| Semgrep | ERROR | high |
| Semgrep | WARNING | medium |
| Semgrep | INFO | info |
| Psalm | error | high |
| Psalm | info | info |
| Trivy | CRITICAL / HIGH / MEDIUM / LOW | critical / high / medium / low |
| Gitleaks | (all) | high |
| ZAP | riskcode 3 / 2 / 1 / 0 | high / medium / low / info |
| PHPStan | error | medium |
| PHPStan | warning | low |

## Tool Status

Each scan records per-tool status (`success`, `failed`, or `skipped`) in `tool-status.json` and in the summary under `meta.tool_status`. When a tool fails, remaining tools still run. The web UI shows status badges on each stat box, and delta analysis skips failed tools to avoid counting missing findings as "resolved."

## CI/CD Threshold Gates

Use `--threshold <level>` to fail the scan (exit code 1) if any findings meet or exceed the given severity. Levels: `critical`, `high`, `medium`, `low`.

```bash
./scan.sh myproject --threshold high    # Fail if any critical or high findings
./scan.sh myproject --threshold medium  # Fail if any medium+ findings
```

This uses `normalized_severity` from the summary. Designed for CI pipelines where you want to gate merges on security findings.

## SARIF Export

Use `--sarif` to output findings in SARIF 2.1.0 format for GitHub Code Scanning:

```bash
./scan.sh myproject --sarif
# Produces: reports/myproject/<timestamp>/results.sarif
```

Each tool becomes a SARIF `run`. PHPStan (code quality) is excluded from SARIF output. Upload to GitHub with:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/myproject/latest/results.sarif
```

## Incremental Scanning

Use `--diff [ref]` to scan only files changed since a git ref (default: `HEAD~1`):

```bash
./scan.sh myproject --diff              # Changed since last commit
./scan.sh myproject --diff main         # Changed since main branch
```

Semgrep uses `--include` to scan only changed files. Psalm and PHPStan run on the full project for type resolution, then results are post-filtered to changed files. Trivy scans lock files (not affected by diff). Gitleaks is not affected.

**Limitation:** Psalm's cross-file taint analysis may miss flows where the source is in an unchanged file but the sink was modified.

## Delta Analysis

Each scan compares against the most recent previous scan for the same project:

- **New findings** — appeared since last scan (red)
- **Resolved findings** — gone since last scan (green)

Visible in the web UI and in `delta.json` in the report directory.

## Trends

The web UI includes a **Trends** view (accessible from any project page) that charts finding counts over time. It shows:

- Total findings per scan with per-tool breakdowns
- Severity trends (critical, high, medium) over time
- Clickable data points that link to individual reports

Data comes from historical `summary.json` files (up to 50 most recent scans).

## ZAP (DAST)

ZAP scans your running application over HTTP. Requires `--url`.

### Profiles

| Profile | Spider | Active scan | Wall time | Safe for |
|---------|--------|-------------|-----------|----------|
| **quick** | 2 min | **none** (passive only, via `zap-baseline.py`) | ~3 min | Any environment, including production |
| **standard** | 5 min | capped at 10 min | up to ~15 min | Local / staging only |
| **deep** | 15 min + Ajax spider | capped at 45 min | up to ~60 min | Local only |

**Quick** just observes responses as ZAP crawls — it checks for missing security headers, insecure cookies, info leaks, and framework fingerprints. It sends no attack payloads, so it's the only profile safe to run against a real environment. It's actually more useful against staging/production than local because it sees real TLS/CDN/nginx header config.

**Standard** and **Deep** run ZAP's active scanner — tens of thousands of attack probes (SQLi, RCE, path traversal, XSS, XXE, SSTI, etc.). Against a real environment these can pollute databases with garbage rows, create test accounts via `join.php`, trip WAFs and fail2ban, spam logs, and get you banned from your own host. **Always run them against a local copy.**

The active scanner in `standard` and `deep` is time-capped via `ascan.maxScanDurationInMins` in a ZAP hook — without this cap it runs until it's finished every plugin against every URL, which can take hours. The spider duration (`-m` flag) is separate and bounds the crawl phase.

The web UI warns before starting `standard` or `deep` against a non-local URL and requires typing `I UNDERSTAND` to proceed. Local is detected via hostname: `localhost`, `127.0.0.1`, `::1`, `host.docker.internal`, `*.local`, `*.localhost`, `*.test`, or RFC1918 private ranges.

### Live Progress

ZAP scans can be slow and previously looked locked up. The scanner now backgrounds the ZAP container with `--cidfile`, waits for a hook to write ZAP's dynamic API port to `.zap-port`, and polls the ZAP API via `docker exec` every 5 seconds. It prints compact status lines like:

```
ZAP [2m15s] spider 47% | ascan 12% · 8,421 reqs · 3 alerts | 9,103 msgs
ZAP [2m20s] spider done | ascan 15% · 10,882 reqs · 3 alerts | 11,560 msgs
ZAP [2m25s] spider done | ascan 18% · 13,118 reqs · 4 alerts | pscan queue: 42 | 13,800 msgs
```

If the port isn't discovered yet, it prints `ZAP [Xs] starting up...` so the scan never goes silent.

### Spider Seed URL Fix

`zap-full-scan.py` (the upstream wrapper script) strips the path from the target URL and resets it to the host root before calling the spider — so `http://host/myproject/` becomes `http://host/`, and the spider crawls the webroot instead of the actual target. [lib/zap.sh](lib/zap.sh) works around this by defining `zap_spider`, `zap_ajax_spider`, and `zap_active_scan` pre-hooks that re-inject the full seed URL via the return-value mechanism in `zap_common.py`. Without this, the spider would only find 2-4 URLs on any path-based target.

### Authenticated Scanning

Pass `--zap-user` and `--zap-pass` to let ZAP crawl pages behind login. The scanner bootstraps a UserSpice session (GET login page, extract CSRF token, POST credentials) and injects the session cookie into ZAP via the `replacer` add-on (matching on the `Cookie` request header). Use a **non-admin test account**. Use `--zap-login` to specify a custom login path if the app doesn't use the default.

```bash
./scan.sh myproject --url http://localhost/myproject/ --zap-user testuser --zap-pass testpass
./scan.sh myproject --url http://localhost/myproject/ --zap-user testuser --zap-pass testpass --zap-login users/login.php
```

The web UI has username/password fields in the scan modal for this.

### ZAP Noise Suppression

The file [shared/zap/rules.tsv](shared/zap/rules.tsv) controls which ZAP alerts to suppress. Format:

```
# alert_id	IGNORE|WARN|FAIL	description
10054	IGNORE	Cookie without SameSite Attribute (fixed in framework)
2	IGNORE	Private IP Disclosure (Docker internal IPs)
```

Ignored alerts are filtered out of the summary and the web UI.

### Important: Force-SSL

If your app forces HTTPS redirect, ZAP can't follow it on localhost (no SSL cert). **Disable force-SSL in UserSpice settings** before running ZAP scans locally.

## HTTP Security Headers

When `--url` is provided, the scanner checks response headers:

| Header | Level |
|--------|-------|
| X-Content-Type-Options | Required |
| X-Frame-Options | Required |
| Referrer-Policy | Required |
| Strict-Transport-Security | Required on HTTPS / Recommended on HTTP |
| Content-Security-Policy | Recommended |
| Permissions-Policy | Recommended |
| X-XSS-Protection | Recommended |
| X-Powered-By | Should NOT be present |
| Server | Should NOT be present |

## Shared vs Project Overrides

```
shared/                          # Ships — applies to ALL UserSpice projects
├── semgrep/
│   ├── userspice-rules.yml      # Custom rules
│   └── .semgrepignore           # Path exclusions
├── psalm/
│   ├── userspice-stubs.php      # Taint annotations for framework functions
│   └── userspice-baseline.xml   # Psalm suppression baseline
├── trivy/
│   └── .trivyignore             # Accepted CVEs
├── gitleaks/
│   └── .gitleaks.toml           # Secret allowlists
├── suppressions.json             # Unified suppression entries (all tools, framework-level)
└── zap/
    └── rules.tsv                # ZAP alert suppressions

overrides/<project>/             # Gitignored — per-project (takes precedence)
├── suppressions.json            # Per-project suppression entries
└── (same structure as shared/)
```

Run `./scan.sh myproject --init` to scaffold the overrides directory for a project.

## Web UI

The web UI at `http://localhost/codetest/ui/` provides:

- **Dashboard** — all discoverable projects with live filter, scan counts, latest findings
- **Scan trigger** — modal with URL, ZAP profile, and authentication fields; runs scan in background with live console output
- **Report browser** — scan history table with Type badges (Static / Full / Full+Auth / Deep), per-tool finding counts, delta indicators
- **Report detail** — stat boxes (including PHPStan when present), delta summary, ownership breakdown, header check results, tabbed findings browser with lazy-loaded source code snippets
- **Suppression management** — suppress/unsuppress findings from the UI with scope and reason; view all suppressions per project
- **ZAP tab** — alert summaries with link to full ZAP HTML report
- **Setup detection** — shows setup instructions if `scanner.conf` is missing or Docker isn't configured

## What Ships vs What Doesn't

**Ships (tracked in git):**
- `setup.sh` — interactive setup script
- `scan.sh`, `lib/` — scanner engine
- `shared/` — framework-level configs, rules, stubs, suppressions
- `ui/` — web interface
- `ci/` — CI/CD templates
- `HOW-IT-WORKS.md`

**Does NOT ship (gitignored):**
- `scanner.conf` — your local configuration (created by setup.sh)
- `reports/` — scan output
- `overrides/` — your per-project customizations

The scanner never writes files into target project directories. All generated config (Psalm XML, stubs, classmap autoloader) stays in the report directory.

## Pre-Scan Discovery

Before tools run, the scanner checks the project for:
- `composer.lock` / `package-lock.json` locations (Trivy needs these for CVE scanning)
- Whether `vendor/autoload.php` exists (Psalm uses it; otherwise generates a classmap autoloader that maps all PHP classes)
- UserSpice directory structure (`users/`, `usersc/`)
- PHP and JS file counts

## Report Pruning

Reports accumulate in `reports/<project>/`. To manage disk:

```bash
./scan.sh myproject --prune 5    # Keep 5 most recent, delete older
./scan.sh myproject --prune 1    # Keep only the latest
```

## CI/CD Templates

The `ci/` directory contains ready-to-use templates:

- [ci/github-actions.yml](ci/github-actions.yml) — GitHub Actions with S1 (lint) and S2 (scan) gates on PR, S3 (full + ZAP) on tag push
- [ci/gitlab-ci.yml](ci/gitlab-ci.yml) — GitLab CI with lint and scan stages

## Key Files

| File | Purpose |
|------|---------|
| [setup.sh](setup.sh) | Interactive setup — checks prerequisites, creates scanner.conf |
| [scan.sh](scan.sh) | Main entry point |
| [lib/common.sh](lib/common.sh) | Docker image versions, shared helpers, loads scanner.conf |
| [lib/semgrep.sh](lib/semgrep.sh) | Two-pass semgrep runner + content-hash baseline filtering |
| [lib/psalm.sh](lib/psalm.sh) | Psalm taint analysis + classmap autoloader generator |
| [lib/trivy.sh](lib/trivy.sh) | Trivy dependency/config/secret scanner |
| [lib/gitleaks.sh](lib/gitleaks.sh) | Secrets detection |
| [lib/zap.sh](lib/zap.sh) | ZAP DAST — auth bootstrap, profiles, rules config |
| [lib/headers.sh](lib/headers.sh) | HTTP security header validation |
| [lib/summary.sh](lib/summary.sh) | Merges all tool outputs into summary.json |
| [lib/delta.sh](lib/delta.sh) | New/resolved findings vs previous scan |
| [lib/owners.sh](lib/owners.sh) | Owner classification (project vs framework vs dependency) |
| [lib/prescan.sh](lib/prescan.sh) | Project structure discovery |
| [lib/phpstan.sh](lib/phpstan.sh) | PHPStan code quality analysis + config generation |
| [lib/suppressions.sh](lib/suppressions.sh) | Unified suppression filtering |
| [lib/sarif.sh](lib/sarif.sh) | SARIF 2.1.0 export for GitHub Code Scanning |
| [lib/prune.sh](lib/prune.sh) | Report lifecycle management |
| [lib/classmap.sh](lib/classmap.sh) | PHP classmap autoloader generator for Psalm |
| [lib/init-overrides.sh](lib/init-overrides.sh) | Scaffold per-project overrides |
| [shared/semgrep/userspice-rules.yml](shared/semgrep/userspice-rules.yml) | Custom UserSpice-aware semgrep rules |
| [shared/psalm/userspice-stubs.php](shared/psalm/userspice-stubs.php) | Psalm taint annotations for framework |
| [shared/gitleaks/.gitleaks.toml](shared/gitleaks/.gitleaks.toml) | Gitleaks allowlists |
| [shared/suppressions.json](shared/suppressions.json) | Unified suppression entries (all tools, framework-level) |
| [shared/zap/rules.tsv](shared/zap/rules.tsv) | ZAP alert suppressions |
| [ci/github-actions.yml](ci/github-actions.yml) | GitHub Actions CI template |
| [ci/gitlab-ci.yml](ci/gitlab-ci.yml) | GitLab CI template |

## Docker Images

Pinned in [lib/common.sh](lib/common.sh):

```
returntocorp/semgrep:1.156.0
ghcr.io/psalm/psalm-github-actions  (pinned by SHA256 digest)
aquasec/trivy:0.69.3
zricethezav/gitleaks:v8.30.1
ghcr.io/phpstan/phpstan             (pinned by SHA256 digest)
ghcr.io/zaproxy/zaproxy:stable
```

### Keeping Images Up to Date

Docker images are pinned for reproducibility, but **they do not auto-update**. Stale images mean stale CVE databases, rule sets, and bug fixes.

#### Quick check

```bash
./scan.sh --check-updates
```

This queries Docker Hub for the three tag-pinned images (Semgrep, Trivy, Gitleaks) and compares against what's in `lib/common.sh`. SHA-pinned images (Psalm, PHPStan) and floating-tag images (ZAP) are noted separately.

#### Update workflow

1. **Edit versions** in `lib/common.sh`:
   - For tag-pinned images (Semgrep, Trivy, Gitleaks): change the version tag.
   - For SHA-pinned images (Psalm, PHPStan): pull the latest and grab the new digest:
     ```bash
     docker pull ghcr.io/phpstan/phpstan:latest
     docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/phpstan/phpstan:latest
     # Copy the ghcr.io/phpstan/phpstan@sha256:... value into lib/common.sh
     ```
   - ZAP uses `:stable` (floating tag) — it updates automatically on pull with no version change.

2. **Pull** — `./scan.sh <project> --pull` downloads the new images.

3. **Test** — Run a scan against a known project and compare findings against a previous report. The delta analysis will show new vs resolved findings. Watch for:
   - Unexpected new findings (new rules added upstream)
   - Findings that disappeared (rules removed or refined)
   - Suppression count changes (orphaned suppressions are harmless)
   - Any tool failures from output format changes

## Design Principles

1. **Framework truths belong in rules/stubs/scoping, not suppressions.** If UserSpice legitimately does something, teach the tools about it rather than suppressing the finding.
2. **Suppressions should stay small.** Each entry has a documented reason. If a category of findings repeats, fix the rule.
3. **Content-hash matching over line numbers.** Suppression entries survive code shifts because they match on what the code says, not where it sits.
4. **Never pollute target projects.** All generated config stays in the report directory. No files written to the scanned project.
5. **Shared knowledge, local customization.** Framework-level rules ship with the scanner. Per-project overrides are gitignored.
