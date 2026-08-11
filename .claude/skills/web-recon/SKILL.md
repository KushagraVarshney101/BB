---
name: web-recon
description: >
  Black-box web bug-bounty pipeline for WILDCARD targets, run from a Docker toolbox.
  Use when the chosen lane is live web assets: picking a paying program with *.domain
  wildcards, enumerating subdomains, resolving and probing for live hosts, crawling and
  mining parameters, then scanning for XSS, SQLi, SSRF, open redirect, CORS, LFI/traversal,
  subdomain takeover, exposed files and JS secrets. Complements bb-recon (program screening)
  and bug-hunter (source audit / Module A-D), which remain the primary lane.
---

# web-recon — wildcard web testing pipeline

> **Source code is the first priority.** White-box beats black-box: it gives root cause,
> exact file:line, and a far stronger report. Reach for `bug-hunter` (Modules A–D) whenever the
> target puts source in scope. Use this skill when the lane is deliberately **live web surface** —
> the program's value is in `*.domain` wildcards, or source is unavailable/already swept.

The wildcard-only selection criteria below apply **to web target picking only**. They are not a
statement that source targets rank lower — they exist because a wildcard is what makes *web*
recon worth running: one accepted wildcard gives an unbounded host surface instead of a single asset.

## Non-negotiable gates (run these BEFORE any traffic)

Four failures this project has already paid for. Do not skip them.

1. **Program open?** Confirm it is *currently accepting submissions*. A dead intake wastes
   the whole effort. → `python program_details.py <name>`, and read the live page.
2. **Class eligible?** Read the ineligible list. Open redirect / self-XSS / blind SSRF /
   low-impact CSRF are commonly excluded *without a demonstrated chain*. Verified-real ≠ payable.
3. **Scope, default-deny.** Every host goes through `scope_check.py`. The pipeline enforces
   this in `00_scope_guard.sh` and **fails closed** if the resolver is missing.
4. **Triager-reproducible?** Before writing a report, confirm the triager can reach the
   vulnerable state themselves on the in-scope host. Seeded/DB-injected state = do not submit.

Also: keep the identifying header (`X-Bug-Bounty: ...`), keep the rate limit sane, and never
run `BB_DEEP=1` (ffuf + sqlmap) on a program whose policy forbids automated/intrusive scanning.

## Build once

```bash
cd BB/recon
docker compose build          # ~10 min, installs the full toolchain
```

## 1. Pick a target

```bash
python recon/pick_targets.py --noise --top 20
```

Selects programs that are **paying + open + have wildcard assets**, excludes repos/mobile/CIDR,
and (with `--noise`) ranks by H1 reports-received-90d so low-duplicate-risk programs come first.
Prefer: many roots, low noise, no gate in MEMORY.md.

Get bare domains to feed the pipeline:

```bash
python recon/pick_targets.py --roots --top 5
```

## 2. Run the pipeline

```bash
cd BB/recon
docker compose run --rm recon recon.sh example.com          # all phases
docker compose run --rm recon recon.sh example.com crawl    # one phase
docker compose run --rm -e BB_DEEP=1 recon recon.sh example.com params   # + dirbust/sqlmap
```

Phases (each resumable — rerunning skips completed output):

| # | Phase | Tools | Output |
|---|-------|-------|--------|
| 1 | `subs` | subfinder, assetfinder, gau | `raw/subs.txt` (scope-gated) |
| 2 | `resolve` | dnsx | `raw/resolved.txt`, `raw/cnames.txt` |
| 3 | `probe` | httpx | `http/live.txt`, `http/summary.tsv` |
| 4 | `ports` | naabu | `http/ports.txt` |
| 5 | `crawl` | katana (headless+JS), gau, waybackurls | `crawl/urls.txt`, `crawl/js.txt` |
| 6 | `params` | uro, gf, ffuf* | `crawl/params.txt`, `crawl/gf_*.txt` |
| 7 | `scan` | nuclei (+takeover, +param templates) | `scan/*.jsonl` |
| 8 | `vulns` | dalfox, kxss, qsreplace, curl, sqlmap* | `vulns/*`, `loot/*` |

`*` = deep mode only.

## 3. What it actually looks for

Do not stop at XSS — the pipeline covers, and you should triage, all of:

- **XSS** — `gf xss` → `kxss` (reflection) → `dalfox` (verification)
- **SQLi** — `gf sqli` → nuclei tags → sqlmap (deep)
- **SSRF** — `gf ssrf` + nuclei; pair with `interactsh-client` for OOB
- **Open redirect** — `gf redirect` → `qsreplace` → follow `Location` (scheme-relative `//host` too)
- **CORS** — origin-reflection **with** `credentials: true` (reflection alone is noise)
- **LFI / traversal** — `gf lfi` + nuclei traversal tags
- **Subdomain takeover** — dangling CNAMEs → nuclei `-tags takeover`
- **Exposed files** — `.git/config`, `.env`, backups, `actuator/env`, swagger, `.DS_Store`
- **JS secrets** — API keys, bearer tokens, AKIA/ghp_/xox/AIza patterns
- **CVEs / misconfig / default creds** — nuclei full template set
- **IDOR candidates** — `gf idor` output feeds `idor_harness.py` (see bug-hunter Module A)

## 4. Triage the output — do not report raw scanner hits

```
out/<domain>/scan/nuclei.jsonl        # start here, filter by severity
out/<domain>/vulns/*.txt              # per-class confirmed-ish hits
out/<domain>/loot/js_secrets.txt      # triage every key: does it call a privileged backend?
```

Before anything becomes a report:
1. **Reproduce by hand** — a scanner hit is a lead, not a finding.
2. **Name the attacker** — who sends what input, and what do they gain? No attacker, no report.
3. **Check the class is eligible** and, if it is a P4/P5 primitive (open redirect, CORS,
   exposure), **chain it** to P2/P1 impact per bug-hunter Module C, or drop it.
4. **Dupe-screen** — corpus grep + disclosed reports before building anything.

## Tuning

| Env | Default | Meaning |
|-----|---------|---------|
| `BB_RATE` | 20 | requests/sec ceiling |
| `BB_CONC` | 25 | concurrency |
| `BB_HEADER` | `X-Bug-Bounty: h1-cybrix` | identifying header |
| `BB_SEVERITY` | all | nuclei severities |
| `BB_DEEP` | 0 | 1 = ffuf dirbust + sqlmap |

API keys (`CHAOS_KEY`, `GITHUB_TOKEN`, `SHODAN_API_KEY`, `SECURITYTRAILS_KEY`) materially improve
subdomain coverage — export them on the host and compose passes them through.

## Related

- `bb-recon` — program/scope screening, `program_details.py`, `h1_noise.py`
- `bug-hunter` — source audit Modules A–D, `idor_harness.py`, P5→P1 chaining table
- MEMORY.md gates: verify-program-open-first, eligibility-gate-check-vrt-first,
  poc-must-be-triager-reproducible, pick-programs-by-noise
