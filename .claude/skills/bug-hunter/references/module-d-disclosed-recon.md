# Module D — Extracting Attack Surface from Disclosed Reports

Disclosed reports are the cheapest EV in bug bounty: someone already found, proved, and got
paid for a bug class on a program, and the program *told you* what it was. Your job is to
mine that for (a) the same class on a sibling asset, and (b) the recon patterns the paid
report used. This workspace already has the corpus and tooling — use it before scraping.

---

## D0. You already have a local corpus — query it first

**The Prompt:** "Has anyone been paid on this program / for this bug class, and what did the
report actually do?"

**The Tool:**
```bash
# 12,361 disclosed H1 reports, full bodies, offline:
grep -rliE '\$[0-9],?[0-9]{3}|RCE|SSRF|account takeover|IDOR' corpus/reports/ | head
# Pull one report body:
python -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('title')); print(d.get('vulnerability_information',''))" corpus/reports/12345.json
# Program noise + payout screen (do this before committing):
python h1_noise.py <program-handle>
```

**The Bounty Mindset:** Local grep is instant and unauthenticated; the live feed is for
*fresh* reports since your corpus snapshot. Start local.

---

## D1. Monitor the live disclosed feed for a target + keywords

**The Prompt:** "What got disclosed on my target (or my target's tech) in the last N days,
filtered to the money classes?"

**The Tool — H1 GraphQL (unauthenticated, the same oracle as `h1_noise.py`):**
```bash
# Latest disclosed reports for one program handle, newest first:
curl -s https://hackerone.com/graphql -H 'Content-Type: application/json' -d '{
  "query":"query($h:String!){ team(handle:$h){ reports(first:50, order_by:{field:disclosed_at,direction:DESC}){ edges{ node{ title severity_rating disclosed_at bounty:awarded_amount url } } } } }",
  "variables":{"h":"<program-handle>"}
}' | python -m json.tool
```
```bash
# Global hacktivity search by keyword (target name, tech, or class):
curl -s 'https://hackerone.com/graphql' -H 'Content-Type: application/json' -d '{
  "query":"query($q:String!){ search(query:$q, first:25){ nodes{ ... on HacktivityDocument{ title url substate cve_ids severity_rating total_awarded_amount latest_disclosable_activity_at } } } }",
  "variables":{"q":"<keyword>"}
}' | python -m json.tool
```
Bugcrowd (Crowdstream, public): scrape `https://bugcrowd.com/crowdstream` filtered by
program; this workspace also has `bugcrowd_data.json` cached.

**The Payload/Pattern — the keyword sets that map to money:**
- Impact: `RCE`, `SSRF`, `account takeover`, `IDOR`, `SQL injection`, `auth bypass`, `SSTI`.
- Data: `PII`, `sensitive data`, `internal`, `source code`, `credentials`.
- Payout floor: regex the awarded amount `\$[2-9],[0-9]{3}|\$[0-9]{2},` to skip the $50 noise.

**The Bounty Mindset:** A recently-disclosed RCE on your target's tech stack is a live crowd
signal *and* a variant map — but per the house rule, a fresh disclosure means **others are
reading those files now**. Treat it as "hunt the *sibling* asset," not "re-report the same file."

---

## D2. Turn a disclosed report into new attack surface (the extraction)

**The Prompt:** "This paid report attacked endpoint/param/feature X on asset A — where else
does the same code path live?"

**The Tool / method:**
1. Read the report's **repro steps** — pull the exact endpoint, param, header, and payload.
2. **Map siblings**: the same feature on other subdomains, other API versions (`/v1`→`/v2`),
   mobile API vs web API, the same OSS component in a different product.
   ```bash
   # If the program is source-in-scope, grep for the vulnerable pattern the report described:
   grep -rnE '<the-vulnerable-call-or-param>' ./target-src/
   ```
3. **Check the fix**: if the patch is public (linked CVE/commit), diff it — incomplete fixes
   and the *variant they missed* are the highest-EV follow-ups.
4. **Reuse the recon technique**, not just the bug: if the report found the endpoint in a JS
   bundle or an old mobile build, do that on the current target.

**The Payload/Pattern — the "same class, new asset" moves that pay:**
- IDOR on `/api/v1/x` → try `/api/v2/x`, `/internal/x`, the GraphQL equivalent (Module A5).
- SSRF via `url=` on one feature → find every other `url=/webhook=/callback=` in the app.
- A disclosed hardcoded-secret in an old APK → decompile the *current* APK (Module B1).

**The Bounty Mindset:** "Known-good class on a surface the fix didn't cover" is the
highest-survival report type — the program already agreed the class is valid and payable, so
triage is about *scope*, not *validity*. That is the easiest argument you'll ever win.

---

## D3. Build a standing monitor (optional)

**The Tool:** wrap D1 in a cron/loop that diffs today's feed against yesterday's and alerts
on new disclosures matching your target+keyword set.
```bash
# sketch: pull, hash, diff
python - <<'PY'
# reuse h1_noise.py's GraphQL client; store seen report ids in seen.json;
# print only new ones whose severity in {critical,high} or bounty >= $1000
PY
```
Feed new hits straight into D2.

**The Bounty Mindset:** Being first to the *variant* of a fresh disclosure — before the crowd
finishes reading the same patch — is where the timing edge actually is.

---

## The one caveat (house rule)

Disclosed-report mining is also how *everyone else* finds targets, so the same discipline
applies: run the **noise screen** (`h1_noise.py`) and the **open-PR crowd screen** before
committing. The winning play from D2 is the *sibling asset the fix didn't reach* — not a
re-report of the disclosed file, which is a guaranteed duplicate.
