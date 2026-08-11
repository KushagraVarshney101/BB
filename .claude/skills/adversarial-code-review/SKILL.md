---
name: adversarial-code-review
description: Perform an adversarial, source-code-only security review of a codebase — think and act like an attacker hunting for exploitable weaknesses, not a compliance checklist reviewer. Use this whenever the user points Claude at a repo, codebase, service, diff, or PR and asks for a security review, vulnerability assessment, code audit, threat model from source, pre-launch security pass, "find the bugs," "is this safe to ship," or asks to check code for a specific vuln class (XSS, SSRF, IDOR, auth bypass, injection, deserialization, prompt injection, etc). Also use when the user asks to re-review changed code against a previous review, to build or extend a local codebase knowledge base for security work, or to run variant analysis on a known bug. Stack-agnostic — adapts to whatever language and framework it finds. This is NOT a linter or style-guide skill.
---

# Adversarial Code Review

## What this skill is

A methodology for reviewing a codebase the way an attacker would, not the way a
compliance checklist would. The question is never "did this follow policy" — it
is **"if I were hostile and had this source code, what would I do with it, and
does the code stop me."**

This file is the **orchestrator**: phases, triage, budget, dispatch. The factual
knowledge lives in `references/`, one vulnerability class per file, loaded only
when reachable.

The purpose is defensive: find bugs so they get fixed. Findings document the
*path* and the *fix*, not a weaponized exploit.

## Read this first

Two ideas drive every design decision below. Internalize them before running any
phase.

**1. Exhaustiveness comes from determinism, not from reasoning.** No model, at
any reasoning budget, reliably enumerates every instance of anything across a
large repo. So split the work:

| Must be exhaustive → mechanize it | Needs judgment → spend model budget here |
|---|---|
| Enumerating files, routes, sinks | Is this input actually attacker-controlled |
| Finding every instance of a pattern | Is this control bypassable |
| Tracking what has been reviewed | Do these two lows chain into a critical |
| Variant sweeps after a confirmed bug | Is this really a trust boundary |
| Dedup, staleness, export | Does this violate a domain invariant |

Anything expressible as a script becomes a script. Model tokens spent on
enumeration are tokens not spent on the two judgments that actually find bugs.
This is also what makes the skill work on cheaper models — the tasks they are
bad at have been removed from their plate.

**2. Beat the default, don't just grep.** Modern frameworks are largely
secure-by-default: auto-escaping templates, parameterized ORMs, CSRF middleware,
strict CSP. Grepping for classic bad patterns in such a codebase yields almost
nothing, because the real bugs live in the *escapes* from the safe default.
Establish what "safe by default" means for this specific stack in Phase 0, then
hunt exceptions: raw queries, `dangerouslySetInnerHTML`-class escapes,
suppression annotations, disabled middleware, hand-rolled crypto, explicit
trust markers, `# nosec`/`# noqa` comments.

## Review state lives on disk

Never hold the review in context. Scaffold a `.review/` directory in the repo
and treat it as the source of truth. Context holds only the current unit of
work plus `STACK.md` and `DOMAIN.md`.

```
.review/
  STACK.md          # Phase 0 output — ~2KB, the only file always in context
  DOMAIN.md         # Phase 2 output — business logic, invariants, ownership
  ASSUMPTIONS.md    # named trust assumptions, each a candidate finding
  sources.jsonl     # untrusted entry points
  sinks.jsonl       # dangerous operations
  paths.jsonl       # source→sink candidates + status
  coverage.jsonl    # (file × class) ledger — the "did we miss anything" answer
  leads.jsonl       # mid-process hunches, deferred
  findings.jsonl    # claimed / confirmed / ruled-out, tagged by discovery technique
  verdicts.jsonl    # independent verification verdicts (Phase 6.5)
  misses.jsonl      # bugs found later by someone/something else
  patterns/         # semgrep / ast-grep rules generated during this review
  report.md
```

Scaffold and query it with `scripts/review.py` (stdlib Python, no installs):

```bash
python scripts/review.py init                              # create .review/ skeleton
python scripts/review.py cover --files-from files.txt --classes injection,access-control
python scripts/review.py add --to paths --json '{...}'     # append a record (auto-ids, auto file_sha)
python scripts/review.py mark --file F --class C --status reviewed --depth full --pass both
python scripts/review.py status                            # what's left; refuses to bless an undrained review
python scripts/review.py query --from paths --where status=unverified
python scripts/review.py stale                             # anchors whose file changed since recording
python scripts/review.py scope --files-from changed.txt    # diff-mode scoping
python scripts/review.py sarif -o out.sarif                # export findings
python scripts/review.py db                                # promote to SQLite when you need joins
```

`status` is the phase gate: it reports which ledgers are still undrained and
names the phase responsible for each. Run it before claiming a review is done.

Full schemas and field semantics: `references/artifacts.md`. Read it before
writing any record.

**Anchors, not line numbers.** Line numbers drift on the next commit. Record
locations as `path::symbolName` plus the file's SHA at review time. Staleness
detection then becomes a script instead of a judgment call.

---

## Phase 0 — Recon: what am I actually looking at

Establish, and write to `STACK.md`:

- Languages, frameworks, package managers, build and deploy config
- Repo layout: monolith vs services, where entrypoints live
- Dependency manifests — what is imported determines which sink knowledge loads
- **Safe defaults already in force**: authz middleware, ORM, templating engine
  and its escaping behavior, CSP, secret manager, input validation layer

Keep `STACK.md` under ~2KB. It is the only file that stays in context all the
way through, so every line has to earn its place.

## Phase 1 — Attack surface map

Enumerate **every** point where untrusted data enters. This is the most-skipped
step and where most blind spots originate. Not just HTTP routes:

- Web routes, API endpoints, GraphQL resolvers
- Webhooks, queue and event consumers, scheduled jobs reading external state
- File uploads, imports, deserialization entry points
- CLI args, environment variables, config pulled from external sources
- Inter-service calls — is this service trusting another service's output?
- LLM and agent tool-call boundaries — model output and tool results are
  untrusted input, same as a web request
- Anything reachable pre-authentication

A source is untrusted if it **crosses a trust boundary**, not merely if it is a
web request. Write each to `sources.jsonl` with `pre_auth` and `trust_boundary`
set. Enumerate mechanically — route decorators, handler registrations, consumer
registrations — then have the model classify. Every later phase is scoped by
this list, so an omission here is invisible for the rest of the review.

## Phase 2 — Adversary threat model and domain model

Two outputs, both on disk.

**`ASSUMPTIONS.md`** — every time the review leans on "this is internal only,"
"already authenticated upstream," "validated by the gateway," record it as a
named assumption with a confidence level and who could confirm it. These are
exactly where the most damaging real breaches happen (confused deputy across a
boundary everyone assumed safe), and they are the easiest thing to silently
inherit. Writing them down converts an invisible blind spot into a reviewable
finding. **They ship in the report** — see Phase 7.

**`DOMAIN.md`** — the business-logic mental model. This is what separates a good
review from a fast one, and it is the thing checklists cannot do at all. Build:

- **Ownership graph** — which entities belong to which principal. Every IDOR
  falls out of this mechanically.
- **State machines** — `draft → paid → shipped`. Can a state be skipped?
  Re-entered? Reached by two paths where only one validates?
- **Invariant table** — "balance never negative," "refund ≤ original charge,"
  "role raised only by admin." Write them as assertions.
- **Role × capability matrix** — the empty cells are the interesting ones.
- **Irreversible actions** — money out, email sent, key rotated, data deleted.

The payoff: **a business-logic vulnerability is a reachable state that violates
an invariant.** Once invariants are written down, hunting them is tractable.
Without the table, "check the business logic" is unfalsifiable advice.

Template and worked method: `references/domain-model.md`.

Then, for each (adversary, crown jewel) pair, work backwards toward Phase 1
entry points. That backward pass produces the Phase 4 priority order — never
review files top to bottom.

## Phase 3 — Triage and budget

**Reachability filter.** Load only the `references/<class>.md` heads that can
apply, based on the Phase 0 stack profile and Phase 1 surface:

- No HTML rendering anywhere → skip XSS entirely
- No IaC or pipeline config in this repo → skip the CI/CD head
- No LLM or agent code → skip the AI/agentic head
- File upload plus any deserialization → load that head, do not skip it for
  being less fashionable

Reachability is the **only** valid reason to skip a class. Never skip one for
being unglamorous.

**Budget.** Triage silently loading everything is how reviews run out of budget
before reaching the interesting part. Load at most 3 class heads at full depth;
the rest at summary depth. Record the ranking and its reason in `STACK.md`.

**Hot set.** Designate the 5–10% of files touching money, authn/authz, PII,
crypto, or admin functions. Hot set gets full source→sink tracing at maximum
reasoning. Everything else gets a mechanical sink sweep. Uniform depth across a
whole repo is a budget bug, not thoroughness.

Priority within the hot set:

```
priority ≈ crown_jewel_value × adversary_population × reachability ÷ control_depth
```

`adversary_population` deserves more weight than it usually gets:
anonymous-internet-reachable beats authenticated-low-priv beats insider by
orders of magnitude in real risk.

## Phase 4 — Per-class deep dive

Run each triaged class through the uniform per-class template, pulling from its
`references/<class>.md`. Template definition: `references/class-template.md`.

Two mechanics make this survive a weaker model:

**Narrow the unit of work.** "Review this repo" fails. "In this one file, list
every call to any name in this 40-item sink list, and for each state whether the
argument traces to an entry in `sources.jsonl`" is near-mechanical
classification and works fine. Fan out per file or per route, merge structured
output into `paths.jsonl`, then spend the expensive model only on the reduced
candidate set. See `references/harness.md`.

**Two passes with opposite framings.** Pass A goes forward from sources; Pass B
goes backward from sinks. They miss different things. Anything found by only one
pass goes into a review queue — the disagreement is itself signal.

Mark each (file × class) cell in `coverage.jsonl` as `reviewed` or
`skipped:<reason>` as you go. Unmarked cells are visible gaps, which turns "did
we miss something" from an anxiety into a query.

### Recording leads without derailing

When you notice something off your current path, **append one line to
`leads.jsonl` and keep going. Do not investigate now.** Chasing the hunch loses
the trace; ignoring it loses the hunch. Deferring costs one line:

```json
{"id":"L-014","anchor":"api/orders.py::refund","hunch":"refund amount re-read from request, not from stored charge","class_guess":"logic/invariant","why_not_now":"mid-IDOR-trace on /users","confidence":"med","status":"open","triage":null}
```

`triage: null` is the manual-review column — a human can sort these later
without re-reading the code.

## Phase 4.5 — Lead drain

Before chain analysis, work `leads.jsonl` down: every `open` lead becomes
`promoted` (now a path or finding), `dismissed:<reason>`, or `deferred:<owner>`.

Leads earn their own phase because they are disproportionately the "weird but
not obviously bad" observations that turn out to be one link in a chain. Drained
too early they are noise; never drained they are silent misses.

## Phase 5 — Chain and variant analysis

Two things checklists structurally cannot do, because they review one class at a
time. This lives at the orchestrator level — inside a class file it gets
silently skipped.

**Chaining.** Revisit every low/medium finding and ask explicitly: does this
become critical combined with anything else in this review? Info leak +
predictable token + missing rate limit = account takeover. Query
`findings.jsonl` for all low/medium rather than relying on recall.

**Variant analysis — mechanize this.** The moment one real bug is confirmed,
write an `ast-grep` or Semgrep pattern for it into `.review/patterns/` and sweep
the whole repo. Never ask the model to "look for similar ones" — it will find
three of the five. One XSS via an unsanitized template variable usually means
there are five.

More broadly: the source and sink inventories built in Phase 1 and 4 are exactly
the inputs a Semgrep taint rule needs. The model decides *what* counts as a
source and a sink for this stack; Semgrep then finds *every* instance
mechanically. This is the single biggest lever for not missing things.

## Phase 6 — Evidence assembly (the finder's job)

Before anything reaches verification, drain `paths.jsonl` from `unverified` to a
terminal state, and make every surviving claim **falsifiable by someone else**:

- Trace the full source → sink path. "This function looks dangerous" is not a
  finding.
- For every control that appears to block the path, explicitly try to show it
  bypassable, or mark the path `blocked` and say why.
- Assemble the **evidence contract** for each finding — source proof, sink
  proof, hops, controls encountered, reachability proof, impact proof,
  preconditions. Schema in `references/verification.md`.

Note what the contract demands: `controls_encountered: []` is a *claim*, not an
omission. Findings that quietly skip the middleware they walked past are the
most common false-positive shape, and requiring the empty list to be stated
makes it checkable in one grep.

`unverified` reaching zero is the phase exit condition — a countable state, not
a feeling.

## Phase 6.5 — Independent verification

**The reviewer who found a bug is the worst possible verifier of it.** They are
anchored on the path they already traced, and every ambiguity resolves toward
"yes, this is real." Self-verification catches typos, not false positives.

So verification is a separate role with an inverted burden of proof: **the
verifier's job is to refute, and the default verdict is *not proven*.** Spawn it
fresh — subagent, separate session, or clean context. Prompts:
`agents/verifier.md`. Method: `references/verification.md`.

```
Stage 0   mechanical prefilter (script)      → free rejections, no model cost
Stage 1   verifier reconstructs path BLIND   → no anchoring on finder's reasoning
Stage 2   verifier attacks the finder's claim → confirmed / refuted / disputed
Stage 3   batch checks over the survivors     → root-cause merge, contradictions
```

```bash
python scripts/review.py verify --queue        # Stage 0; emits only what survives
python scripts/review.py verdict --json '{...}' # record a verdict
python scripts/review.py fp-stats               # FP rate by technique, class, reason
```

Five verdicts, not two: `confirmed`, `refuted` (with one closed-vocabulary
reason), `underspecified` (returned once, not rejected), `latent` (real defect,
currently unreachable — **do not delete these**, they go live the moment someone
registers the route), and `disputed` (escalate to a human after one rebuttal
round; never silently resolve).

Two things this phase must do that are easy to drop:

- **Verify severity separately from existence.** A real finding rated critical
  when it is medium damages credibility nearly as much as a false positive, and
  is far more common. Check adversary population, actual crown-jewel reach, and
  irreversibility independently of whether the path is real.
- **Steelman before refuting.** Without it, verifiers latch onto the weakest
  phrasing in the write-up and declare victory. If the steelman is stronger than
  the original claim, that is itself the finding.

A report with three real bugs and seven false positives is worse than one with
three real bugs, because the reader must now re-verify all ten — and typically
stops after the second FP.

## Phase 7 — Report

Structure, severity rubric, and the vulnerable-vs-fixed pairing:
`references/report.md`.

Three things the report must contain that reviews usually omit:

1. **The assumption ledger**, as a first-class section: "this review is valid
   only if these N assumptions hold," each tagged with who can confirm it.
   Expect roughly half to come back false — those are findings.
2. **Considered and ruled out** — everything refuted in Phase 6.5, each with
   its taxonomy reason and citation. This is where verification earns its keep:
   it demonstrates rigor and stops the same dead end being re-walked next cycle.
   Only `confirmed` findings enter the main findings list; `latent` ones go in a
   separate section with their reachability precondition stated.
3. **Coverage statement** — what was reviewed, what was skipped, and why,
   straight from `coverage.jsonl`. Honest scope beats implied completeness.

Export findings to **SARIF** (`scripts/review.py sarif`) alongside the prose.
Semgrep, CodeQL, GitHub code scanning, and most IDEs consume it, so the review
lands in existing tooling instead of a markdown file nobody reopens.

## Phase 8 — Retro

The rule that stops this becoming a diary: **the retro's output is a diff to a
reference file, not prose.** Hit a sanitizer bypass missing from the catalogue?
The deliverable is the new catalogue entry. Missed a whole category of entry
point? The deliverable is a new Phase 1 bullet.

Two ledgers make the methodology improvable on evidence:

- **`findings.jsonl`** tags each finding with the technique that found it —
  grep pattern, negative-space check, chain analysis, invariant violation, lead
  drain. After a few reviews you get a hit rate per technique and can reorder
  the methodology on data rather than intuition.
- **`misses.jsonl`** records bugs found later — in prod, by another reviewer, by
  a tool run afterward. This is the only real signal for improving coverage. It
  is also the ledger everyone skips, because it is unflattering.

Verification calibration (`review.py fp-stats`) closes the loop on both. FP rate
by `found_by` tells you which techniques generate junk; refutation-reason
distribution points at fixable upstream problems — heavy `control_missed` means
the finder is not reading middleware before tracing, heavy
`source_not_attacker_controlled` means Phase 1 is over-marking sources. Both are
cheaper to fix upstream than to verify harder downstream.

The metric that matters most and that nobody tracks: **verifier
false-refutation rate** — anything in `misses.jsonl` that this pipeline
previously refuted. A verifier optimizing purely for a low FP count will start
refuting real bugs, and only this number catches it.

---

## Diff mode (PR / incremental review)

Full reviews do not scale to every PR. Given a baseline `.review/` from a prior
full pass, an incremental review is scoped to changed symbols that:

1. appear in an existing `paths.jsonl` entry, or
2. introduce a new source or sink, or
3. remove or weaken a control on an existing path, or
4. touch a file in the hot set, or
5. modify anything referenced in `DOMAIN.md` invariants

Everything else is untouched and stays untouched. Run `scripts/review.py stale`
first to catch anchors whose files moved under the baseline. Procedure:
`references/harness.md`.

This is the highest-ROI mode for day-to-day use, and it only exists because the
baseline was written to disk in a queryable form.

## Vulnerabilities of omission

Missing code is treated as seriously as bad code, and it is what checklists
structurally cannot find. But greps *can* find absence, if written to look for a
gap inside a known shape:

- Route handler with no authz decorator
- Model query method with no ownership filter
- Raw query constructed outside the ORM
- State transition with no precondition check
- Mutating endpoint with no CSRF token check under a cookie-auth scheme
- Tool-call handler with no argument schema validation

Write these as negative patterns into `.review/patterns/` like any other rule.

## Stack-agnostic dispatch

Nothing in Phases 1–8 hardcodes a language. The mechanism:

1. Phase 0 produces the stack profile.
2. Each `references/<class>.md` organizes its source→sink inventory and bypass
   catalogue as lookup tables **keyed by framework**, not as one fixed list.
3. When a class file has no entry for a detected framework, research the current
   best-known sinks and bypasses for that framework/class pair before
   proceeding — do not silently fall back to a generic pattern that may not
   apply to this stack.

This keeps the core reasoning permanently reusable while the factual knowledge
underneath extends per class and per stack independently.

## Class heads (build one at a time, in rough priority order)

1. `injection.md` — SQL/NoSQL/command/template/path
2. `access-control.md` — IDOR, privesc, missing or forgeable authz
3. `xss-and-sanitizers.md` — reflected/stored/DOM, sanitizer and escape bypass
4. `business-logic.md` — invariant violation, state-machine abuse, race/TOCTOU
5. `oauth-sso-session.md`
6. `ssrf.md` — including blind
7. `csrf-cors-clickjacking.md` — the same-origin trust cluster, reviewed together
8. `deserialization.md`
9. `prototype-pollution.md`
10. `secrets-and-supply-chain.md` — git history, lockfile integrity, postinstall
11. `cicd-and-iac.md` — pipeline injection, `pull_request_target`-class bugs
12. `ai-llm-agentic.md` — prompt injection, MCP trust boundaries, tool-call
    argument validation

Each is built and researched independently against
`references/class-template.md`. This backbone does not change when one is added
— it just gains another head to dispatch to in Phase 3.

## Validating the methodology itself

Points about "not missing things" are unfalsifiable without a test set. Keep a
fixture corpus of small repos with planted bugs, plus two or three clean repos
to measure false-positive rate, and re-run after every methodology change. This
is also the only honest way to answer "does this still work on a cheaper model."
Use the `skill-creator` skill to wire up the eval loop.

## Reference files

| File | Read when |
|---|---|
| `references/artifacts.md` | Before writing any `.review/` record — schemas, anchors, statuses |
| `references/domain-model.md` | Phase 2 — DOMAIN.md template, invariant elicitation |
| `references/harness.md` | Phase 4 fan-out, Semgrep generation, diff mode |
| `references/class-template.md` | Phase 4, and whenever building a new class head |
| `references/verification.md` | Phase 6.5 — evidence contract, FP taxonomy, verdicts, calibration |
| `agents/verifier.md` | Phase 6.5 — drop-in prompts for the independent verifier |
| `references/report.md` | Phase 7 — report structure and severity rubric |
