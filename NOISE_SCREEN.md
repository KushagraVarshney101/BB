# Duplicate / Noise Screen

Enhances, does not replace, the three-part dupe screen already defined across the
skills (`bug-hunter`'s two gates + `web-recon`'s step 4). Each original check stays
intact; this file adds the pieces that were missing (multi-platform coverage,
program-freshness proxy, and an offline substitute for the disclosed-report
corpus, which doesn't exist in this repo).

## The original three checks (kept as-is)

1. **H1 noise oracle** (`h1_noise.py`) — `reports_received_last_90_days` per
   handle. High volume → a real bug is a likely closed duplicate.
2. **Unmerged-hardening-PR crowd screen** (`bug-hunter` gate #1) — grep a
   repo's open PRs for security-shaped titles. Swarming PRs → other
   researchers are already reading those files, move on.
3. **Disclosed-report corpus grep** (`bug-hunter` Module D0 / `web-recon`
   step 4) — `grep -rliE ... corpus/reports/` before building anything.

## What's added here

### A. Multi-platform noise proxy (H1's oracle is H1-only)

`h1_noise.py` only works for HackerOne. For YesWeHack and Intigriti there is
no equivalent public disclosed-report-count API in the bounty-targets-data
schema. Static proxies, weakest signal first:

- **Platform-level base rate.** YesWeHack and Intigriti each have materially
  smaller registered-researcher pools than HackerOne industry-wide. This is
  not a per-program signal — it does not tell you *this* program is quiet,
  only that the platform's overall hunter density is lower. Use it to break
  ties, never as the primary signal.
- **`tacRequired` / `twoFactorRequired` (Intigriti)** — onboarding friction
  measurably reduces casual participation. `ripencc` has both `false`, so
  this doesn't apply here; note it when it does.
- **Managed vs. self-managed (`managed_program` / `managed`)** — a
  platform-managed program gets more platform-side promotion → more eyes.
  Unmanaged is a weak signal toward less traffic, easily wrong for famous
  brands (do not use alone).

None of these substitute for the real oracle. **Run `h1_noise.py` for real
the moment there's open egress**, before sinking more time into a program
picked on static proxies alone.

### B. Program-freshness proxy (no `created_at` field exists in any dump)

The bounty-targets-data schema carries no join-date field on any platform,
and HackerOne's `id` field is zeroed out in the public snapshot (verified —
every record has `id: 0`), so it can't be used as a proxy either. Given
that, freshness is inferred from what *is* present, in order of reliability:

1. **`average_time_to_bounty_awarded: null`** (H1) — no bounty has been
   recorded as awarded in this stats snapshot. Weak alone (also true for
   programs that are simply strict, or for well-known projects where the
   stat just wasn't backfilled — confirmed by checking `discourse`, which
   shows `null` here despite a long paid-bounty history). Use only in
   combination with (2).
2. **Small in-scope asset count + narrow, specific repo list** (all
   platforms) — a program with a handful of named repos, not a blanket
   "all our GitHub orgs," reads as a smaller, more recently-scoped effort
   rather than a mature, heavily-groomed target.
3. **Not a globally recognized consumer/developer brand.** This is the
   strongest practical signal available without live data: generalist
   hunters gravitate to names they recognize (Node.js, WordPress,
   DigitalOcean, NVIDIA, Discourse all showed up in the static candidate
   list and were deliberately passed over for this reason — see the
   selection writeup in the PR description / commit message).

`ripencc` (RIPE NCC) was selected on (2) + (3): seven specifically-named
source repos, Tier-1-tagged, and a specialized internet-infrastructure
nonprofit rather than a name most generalist web bounty hunters gravitate to.

### C. Offline substitute for the missing disclosed-report corpus

`corpus/reports/` (12,361 H1 report bodies) referenced by Module D0 does not
exist in this repo and re-fetching it requires the same blocked
`hackerone.com` GraphQL endpoint as `h1_noise.py`. Until it's available,
substitute the **target's own issue/PR history** as the dupe-and-fix-history
signal — it's a narrower window (this repo only, not the whole disclosed
corpus) but it's real, present data instead of an absent one:

```bash
# Already-reported security issues (closed as fixed = don't re-find the same bug;
# still open = someone beat you to the report, don't duplicate it)
grep -rliE 'security|vulnerab|CVE-|IDOR|injection|traversal|SSRF|XSS|auth.*bypass' \
  <(gh api repos/RIPE-NCC/whois/issues --paginate --jq '.[] | .title + " " + .body' 2>&1 || true)

# Merged security-shaped commits/PRs (same intent as bug-hunter gate #1, applied
# to *merged* history too, not just open PRs — shows what's already been fixed
# so effort isn't spent re-finding a patched bug)
git -C <clone> log --all --oneline -i --grep='fix.*inject\|IDOR\|traversal\|auth.*bypass\|CVE-'
```

This is strictly weaker than the real corpus (no cross-program pattern
mining, no payout data) — treat it as a floor, not a replacement, and swap
back to Module D0's corpus grep the moment `corpus/reports/` exists.

## Applied to this pass (RIPE NCC / `ripencc` / `whois`)

- H1 noise oracle: N/A, this is an Intigriti program.
- Unmerged-hardening-PR screen: run against `RIPE-NCC/whois`'s open PRs
  before treating any file as high-value (see the review notes).
- Corpus grep: unavailable: substituted with the repo's own issue/PR history
  per (C) above.
- Freshness/noise proxy: per (B)/(A) above — `ripencc` is unmanaged-neutral
  (Intigriti doesn't expose a managed flag the same way H1 does), no TAC/2FA
  friction, small named-repo scope, non-mainstream brand.
