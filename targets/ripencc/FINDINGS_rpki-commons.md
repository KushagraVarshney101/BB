# Static Review — RIPE NCC `rpki-commons` + `rpki-core` (Intigriti `ripencc`, Tier 1)

Source-only, no live traffic (same egress constraint as the `whois` pass).
`rpki-commons` cloned with full history (1,570 commits); `rpki-core`
shallow-cloned (722 Java files) for cross-reference only, not yet reviewed
in its own right — see coverage note at the end.

## Confirmed (already fixed upstream — documented for the record)

### Lenient ROA prefix parsing allowed a partially-malformed ROA to validate as fully valid
**File:** `src/main/java/net/ripe/rpki/commons/crypto/cms/roa/RoaCmsParser.java`
**Status:** Fixed by RIPE NCC in commit `d3566fac` ("Invalidate ROA when one
of its prefixes fails to parse from ASN1"), merged via `strict-roa-prefix-parsing`,
July 2026 — predates this review.

Before the fix, `parseRoaIpAddressFamilySequence` caught
`IllegalArgumentException` per-prefix, silently dropped any prefix that
failed to parse, and still marked the overall ROA as successfully parsed
(with just the parseable prefixes). RIPE's own commit message asserts "this
change has no effect on security." Independently evaluated that claim
rather than taking it at face value:

- **Locally, for RIPE's own systems, the claim holds** — a ROA silently
  losing a malformed prefix narrows what it authorizes rather than
  broadening it (RFC 6482 route-origin authorization becoming stricter is
  not a privilege escalation in RIPE's own validator).
- **The ecosystem-wide angle isn't addressed by that framing.** RPKI's
  security model depends on *all* relying parties reaching the same
  validity verdict for the same published object — parser leniency
  differences between implementations are a documented real category of
  RPKI robustness issues (this is why RFC 6482-adjacent strict-parsing
  pushes happen across the RP ecosystem periodically). Whether RIPE's
  previously-lenient behavior actually diverged from other relying-party
  implementations for any real-world malformed ROA wasn't verified here —
  that requires cross-implementation testing, out of scope for a
  single-repo static review. Documented as a caveat on RIPE's "no security
  effect" framing, not as a counter-finding — I don't have evidence it was
  ever exploited, only that the stated rationale doesn't cover the
  ecosystem-consistency angle.

**Variant sweep (this review):** grepped every `catch (IllegalArgumentException`
in `src/main/java` (10 files) and read each. `ManifestCmsParser`,
`AspaCmsParser`, `X509ResourceCertificateParser`, and `X509CertificateParser`
all already propagate a structural parse failure to
`validationResult.error(...)`/`rejectIfTrue`/`rejectIfNull` — i.e., they fail
the *whole* object, the correct behavior. The ROA parser was the outlier,
not the norm; the fix brought it in line with the codebase's own
established convention. No other live instance of the "drop the bad
element and keep going" pattern exists in this codebase's crypto/x509
parsers. (The other two hits — `DateTimeConverter`'s two-format retry and
`X509CertificateParser`'s EC-point decode, which already correctly calls
`rejectIfNull` right after — are unrelated/already-correct and not part of
this class.)

## Investigated in depth, ruled out (no finding — confirmed unreachable in production)

### RFC 3779 resource-containment check can be downgraded to warning-only
**Files:** `validation/objectvalidators/X509ResourceCertificateParentChildLooseValidator.java`,
`ResourceValidatorFactory.java`, `ValidationOptions.java`

This is the single most security-critical invariant in the whole RPKI trust
model: a child certificate must never claim IP/AS resources its issuer
didn't actually delegate to it ("overclaiming"). The strict validator
(`X509ResourceCertificateParentChildValidator`) correctly calls
`result.rejectIfFalse(overclaiming.isEmpty(), RESOURCE_RANGE, ...)` —
overclaiming fails validation. Its sibling, `...ParentChildLooseValidator`,
calls `result.warnIfFalse(...)` for the *identical* condition instead of
`rejectIfFalse`.

Confirmed via `ValidationResult.java` that this distinction is real, not
cosmetic: `warnIfFalse` routes to `warn(...)`, `rejectIfFalse` routes to
`error(...)`, and `hasFailures()` only inspects the `error` bucket — a
certificate validated only through the loose path would be treated as
**fully valid** by any caller checking `hasFailures()`, resources
overclaimed or not.

Traced reachability before treating this as a finding:
`ResourceValidatorFactory` only ever constructs the loose validator when
`options.isAllowOverclaimParentChild()` is true, and that field **defaults
to `false`** (`ValidationOptions.java`). Grepped both `rpki-commons` and
`rpki-core` in full (main + test source) for `AllowOverclaim` — **zero
call sites anywhere set it to `true`**. RIPE's own certification-authority
service never exercises this path; it exists in the shared library, gated
behind an opt-in flag, presumably for external consumers of `rpki-commons`
who want lenient/diagnostic validation (the `context.addOverclaiming(...)`
tracking call reads as built for exactly that: "tell me what would have
been rejected" tooling, not production gatekeeping).

**Conclusion:** not exploitable against RIPE's own systems as shipped in
these two repos. Worth flagging to RIPE anyway (not as a bounty
submission) — a security-critical validator with a same-signature warn-only
sibling, reachable via a boolean flag with no call site currently guarding
who can set it, is exactly the kind of landmine that becomes live the
moment a future feature (e.g. a legacy-resource migration tool, or a
third-party fork) flips that flag without fully appreciating what it
disables. Same shape as the `isAllowedAndValid` finding in the `whois`
pass — noted there too.

## Coverage

- `rpki-commons`: full crypto/cms parser sweep (ROA, Manifest, ASPA, X509
  cert/CRL) for the lenient-parse pattern; RFC3779 resource-containment
  validator pair fully traced end-to-end including every call site in both
  repos. Not covered this pass: provisioning-protocol XML
  (de)serialization (`provisioning/identity/*`, `provisioning/payload/*`),
  RRDP/RSYNC transport code, manifest freshness/staleness logic beyond
  what surfaced incidentally.
- `rpki-core`: only cross-referenced (grepped for `AllowOverclaim` usage,
  722 Java files not otherwise read). **Not yet reviewed in its own
  right** — this is the actual certification-authority service (cert
  issuance, resource delegation workflow, publication) and is a natural
  next target: it's where a resource-delegation logic bug would most
  directly translate to "a customer's CA issues a cert for IP space it
  doesn't hold," independent of the shared-library validators covered here.
- Not started: `rpki-monitoring`, `rpki-publication-server`, `rpki-ta-0`,
  `rsyncit` (all Tier 2, source-in-scope on the same program).
- Not started: `whois-update`'s core authz handler chain (flagged in
  `FINDINGS_whois.md` as the top follow-up item from that pass).

## Next steps

1. `rpki-core` proper: cert issuance/resource-delegation workflow,
   publication-point handling, key-rollover logic.
2. `whois-update` `Authenticator` chain (carried over from the `whois`
   pass).
3. Tier-2 repos (`rpki-monitoring`, `rpki-publication-server`, `rpki-ta-0`,
   `rsyncit`) — not yet started, lower priority given Tier-1 repos aren't
   exhausted either.
