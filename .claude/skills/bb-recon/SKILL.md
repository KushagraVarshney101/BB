---
name: bb-recon
description: >
  Pull a bug-bounty program's details — scope, payouts, and the gates that kill
  reports — from HackerOne, Bugcrowd, YesWeHack, and Intigriti, then hand the
  in-scope assets to the `bug-hunter` skill. Use when starting on a target, when
  you need a program's in/out-of-scope asset list, its bounty range, or whether
  it requires 2FA/TAC/is managed, or to find which programs expose source code or
  wildcards to hunt. Backed by local cached dumps (884 programs) with a live
  refresh path; feeds scope_check.py and h1_noise.py.
---

# bb-recon

Answers one question fast: **"What is this program, what's in scope, and is it worth
my time?"** — then points `bug-hunter` at the assets. It does NOT hunt bugs; it decides
*where* to.

The engine is `program_details.py` (repo root), a unifier over four cached dumps in the
bounty-targets-data schema:

| Platform | Cache file | Count |
|----------|-----------|-------|
| HackerOne | `hackerone_data.json` | 448 |
| Bugcrowd | `bugcrowd_data.json` | 241 |
| YesWeHack | `yeswehack_data.json` | 63 |
| Intigriti | `intigriti_data.json` | 132 |

## Core usage

```bash
python program_details.py <term>                    # search all 4 platforms by name/handle
python program_details.py gitlab --platform hackerone
python program_details.py mattermost --assets       # full in/out-of-scope asset lists
python program_details.py stripe --json             # machine-readable, for piping
python program_details.py --list intigriti          # every program handle on a platform
```

Default output per match shows: url, payout range, **gates**, in/out-of-scope counts, and
auto-extracts **WILDCARDS** (broadest surface) and **SOURCE/REPO** assets (what
`bug-hunter` Module A/B need). `--assets` dumps every asset with `max_severity`/tier.

## The recon → hunt flow

1. **Identify + screen the program**
   ```bash
   python program_details.py <target>
   ```
   Read the `gates` line first — it's the go/no-go:
   - HackerOne: `offers_bounties:false` → not paid, skip. `managed:true` = HackerOne triages
     (stricter). `response_%` low / `avg_days_to_bounty` huge = slow program.
   - Bugcrowd: `safe_harbor`, `max_payout`, `allows_disclosure`.
   - YesWeHack: `public`/`disabled`, `min-max` bounty.
   - Intigriti: `tac_required:true` or `2fa_required:true` = onboarding friction before you
     can even submit; `status` must be `open`.
   Then cross-check the program-level gates memory: some ban AI-assisted reports or need a
   rep floor ([[check-program-gates-before-hunting]]).

2. **Screen the noise** (duplicate risk) — the second gate that kills findings:
   ```bash
   python h1_noise.py <handle>        # reports_received_last_90_days (H1 only)
   ```
   High-noise program → a real bug is a closed duplicate. This is the single most
   report-saving check ([[pick-programs-by-noise]]).

3. **Pick the surface**
   - **Source in scope** (the `SOURCE / REPO` block, `asset_type SOURCE_CODE` / github repos)
     → clone it and run `bug-hunter` Module A (Java/Node IDOR + mass assignment) or Module B
     (mobile). White-box is the highest-EV path.
   - **Wildcards** (`*.target.com`) → broadest live surface; subdomain-enum then Module C
     chaining on whatever leaks.
   - **A single web/API host** → Module C recon, or Module D to see what's already been paid.

4. **Confirm each asset is actually payable before touching it**
   ```bash
   python scope_check.py <host>       # default-deny resolver against scope.json
   ```
   `program_details.py` shows the *program's advertised* scope; `scope_check.py` is your
   *own* curated allow/deny (paid vs unpaid vs excluded). Trust the latter for go-live.

5. **Mine prior art** — hand the handle to `bug-hunter` Module D
   (`corpus/reports/` grep + H1 GraphQL disclosed feed) to find the classes that already
   paid on this program and the sibling assets the fixes missed.

## Refreshing the cache

The dumps are snapshots. To refresh, pull the public bounty-targets-data feed (raw JSON,
one file per platform) and overwrite the four `*_data.json` files:

```
https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json
https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json
https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json
https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json
```

Fetch with WebFetch (or `curl`), write to the repo root, then re-run any query. The schema
matches what `program_details.py` already parses. (Federacy is also present as
`federacy_data.json` if a fifth platform is ever needed — add it to `FILES` in the script.)

For **live, per-program** detail beyond the dump (fresh disclosed reports, live scope
changes), the H1 GraphQL endpoint is unauthenticated — see `h1_noise.py` for the client and
`bug-hunter` Module D for the queries.

## What this skill deliberately does NOT do

- It doesn't judge in-scope-ness for go-live — that's `scope_check.py` / `scope.json`.
- It doesn't hunt — that's `bug-hunter`.
- It doesn't rank by payout alone — a high `max_payout` in a 4,000-report/90d program is a
  trap. Always pair payout with the noise screen.

Related: [[bb-scope-json]], [[bb-skill-suite]], [[h1-graphql-noise-oracle]],
[[pick-programs-by-noise]], [[check-program-gates-before-hunting]].
