---
name: bug-hunter
description: >
  Offensive source-code-audit and recon workflows for triaged bug-bounty
  payouts — NOT OWASP theory. Use when hunting IDOR / mass-assignment in
  Java-Spring or Node source (Module A), auditing an Android/iOS app for
  hardcoded secrets, deep-link hijack, or WebView bugs (Module B), chaining
  a P5 info-leak up to P2/P1 (Module C), or mining the HackerOne/Bugcrowd
  disclosed feed for a target's attack surface (Module D). Each module gives
  the exact grep/CodeQL/jadx/adb command, the code pattern to match, the HTTP
  payload, and why it pays.
---

# bug-hunter

A field manual, not a textbook. Every entry is derived from patterns in *validated,
paid* H1/Bugcrowd reports and from this workspace's own scar tissue (see the
"House rules" below). If a section would only restate "what is XSS," it was cut.

## Before you audit ANY target — the two gates that kill duplicates

These override enthusiasm. Both are learned from real findings that died with no reward.

1. **Screen the crowd, not the advisories.** Do not pick a repo *because* it has fresh
   security patches — that is a signal other researchers are already reading those files.
   The true crowd metric is **unmerged hardening PRs**:
   ```bash
   gh api "repos/{owner}/{repo}/pulls?state=open&per_page=100" \
     --jq '.[] | .title' \
     | grep -iE 'valid|sanitiz|escape|traversal|inject|ssrf|xss|verify|digest|symlink|reject|harden|overflow|bounds|unsafe|secret|redact|spoof' \
     | grep -viE 'bump|dependabot'
   ```
   If that surface is swarming, move on. (Ref: `NEXT_SESSION.md`, four dupes from patch-adjacent hunting.)

2. **Screen the program's noise before reading code.** A real bug in a 4,000-report/90d
   program is a closed duplicate. Pull `reports_received_last_90_days` first:
   ```bash
   python h1_noise.py <program-handle>     # H1 GraphQL noise oracle, already in this repo
   ```
   And read the policy page for scope/exclusions *before* choosing a bug class — an
   out-of-scope class is wasted work (cost a full Matomo SSRF report once).

3. **Name the attacker before you invest.** Write one line: *who* sends *what input* to
   gain *what*. No threat actor → no report. A client-side SDK/CLI with no remote attacker
   is not a finding no matter how "wrong" the code looks.

## Modules — read the reference file for the one you need

| Module | When | File |
|--------|------|------|
| **A — Web source review** | You have Java/Spring or Node source and want IDOR / mass-assignment that URL-fuzzing misses | `references/module-a-web-source-review.md` |
| **B — Mobile** | You have an APK/IPA — secrets, deep-link hijack, exported components, WebView | `references/module-b-mobile.md` |
| **C — Chaining** | You have a P5 (path disclosure, dir listing, verbose error) and want to escalate to P2/P1 | `references/module-c-chaining.md` |
| **D — Disclosed-report recon** | Starting on a target; mine the disclosed feed for its real attack surface | `references/module-d-disclosed-recon.md` |

Each reference entry uses one shape:
**The Prompt** (the question to ask the target) →
**The Tool** (exact command) →
**The Payload/Pattern** (the code/HTTP to look for or send) →
**The Bounty Mindset** (why a triager pays it).

## House rules (this workspace)

- Local labs already exist: GitLab-EE Docker, Matomo 5.12 on :8090, Next.js on :8095. Use them for live PoCs.
- Disclosed corpus: `corpus/reports/{id}.json` (12,361 H1 reports, full bodies) — grep it, don't guess.
- Scope resolver: `python scope_check.py <asset>` and `scope.json`.
- A finding without a reproducible PoC against a real instance is a lead, not a report.
