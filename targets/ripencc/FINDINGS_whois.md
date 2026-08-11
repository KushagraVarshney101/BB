# Static Review — RIPE NCC `whois` (Intigriti `ripencc`, Tier 1)

Source-only review per `bug-hunter` Module A + `adversarial-code-review`
methodology (skill used as-is, unmodified). No live traffic sent — this
environment's egress policy blocks `*.ripe.net` (see `NOISE_SCREEN.md`).
Repo: `github.com/RIPE-NCC/whois`, cloned with full history (5,455 commits)
for the crowd/dupe screen.

## Coverage

- Crowd/dupe screen: git log security-shaped-commit-message grep (offline
  substitute per `NOISE_SCREEN.md` §C — GitHub PR history is empty; RIPE
  develops on internal GitLab, GitHub is a mirror, confirmed via
  `.gitlab-ci.yml` + `.gitlab/CODEOWNERS` presence and zero non-mirrored
  `refs/pull/*`).
- Deep dive: `whois-commons/common/sso/AuthServiceClient.java` (fixed
  traversal + full variant sweep), `whois-rdap` link-builder pattern-match,
  `whois-commons/common/override/OverrideCredentialValidator.java` +
  `whois-commons/common/rpsl/transform/FilterAuthFunction.java` (full call
  graph, every production caller traced).
- Not yet reviewed this pass: `whois-update`'s core RPSL update/authz
  handler chain beyond the entry points already traced (large, mature,
  30-year-old subsystem — flagged for a dedicated follow-up pass, not
  skipped for being uninteresting); `whois-nrtm`/`whois-nrtm4`;
  `whois-scheduler`; `whois-smtp`. Sibling in-scope repos `rpki-commons`,
  `rpki-core`, `rpki-monitoring`, `rpki-publication-server`, `rpki-ta-0`,
  `rsyncit` not yet started (next in this session).

## Confirmed (already fixed upstream — documented for the record, not reportable)

### Path traversal in `AuthServiceClient` outbound calls
**File:** `whois-commons/src/main/java/net/ripe/db/whois/common/sso/AuthServiceClient.java`
**Status:** Fixed by RIPE NCC in commit `f029f652a` ("Fix path traversal
issue in auth services"), June 2026 — predates this review.

Four methods (`validateToken`, `getUserInfoByEmail`, `getMemberContacts`,
`getUuid`) built a JAX-RS `WebTarget` by appending caller-influenced strings
(email, username, uuid) directly via `.path(rawInput)`, with no validation.
JAX-RS `.path()` treats `/` as a literal path separator rather than
percent-encoding it, so a value like `../../<something>` escaped the
intended path prefix on the internal auth/SSO backend. The fix adds
`validateTarget()`: build the target, `.normalize()` the resulting URI, and
reject if the normalized path no longer starts with the expected prefix —
a standard canonicalize-then-check-prefix defense that closes the class
correctly for this call shape.

**Variant sweep (this review, not upstream):** grepped every
`client.target(...)` construction site in the repo (10 files) and every
`.path(<variable>)` call with a non-constant argument. Two other patterns
matched the same shape and were individually traced:

- `ApiKeyAuthServiceClient.validateApiKeyWithRetry` — path is a hardcoded
  `VALIDATE_PATH` constant; the caller-supplied `apiKeyId` is only used for
  logging/cache-key, never appended to the path. Not vulnerable.
- `RdapObjectMapper.buildRirSearchUri` — builds a *response* link (embedded
  in RDAP JSON output, not an outbound request) from `objectType`,
  `relationType` (both derived from a fixed enum) and `handle`
  (`rpslObject.getKey().toString()`). Traced `handle`'s origin: it's the
  RPSL object's primary key, which is syntax-constrained by RPSL attribute
  validation per object type (AS-number, IP-range, or domain-label syntax —
  none permit `/` or `..`). Not reachable with traversal-shaped input.
- `RsngAuthoritativeResourceWorker.getRsngDelegations(url)` and
  `whois-client/RestClientTarget` (`source`/`pkey` args) — both take
  hardcoded-literal or SDK-caller-supplied values, not attacker input at
  the whois server boundary. Not vulnerable.

**Conclusion:** the fix is complete; no live sibling instance of this bug
class exists in the current tree.

## Investigated in depth, ruled out (no finding)

### Override-credential password check appears skippable in `isAllowedAndValid`
`OverrideCredentialValidator.isAllowedAndValid()` checks trusted-IP-or-SSO-
username-match plus object-type permission, but **never checks the
override password** — unlike its sibling `isValidOverride()` /
`getValidOverrideUser()`, which do. Its only production caller is
`FilterAuthFunction.isOverrideAuthenticated()`, reached from
`RpslResponseDecorator.filterAuth()`, which decides whether a queried
mntner object's `auth:` attribute (containing the MD5/CRYPT password hash)
is returned in the clear or redacted as `TYPE # Filtered`.

Traced every path that can populate the `User overrideUser` field flowing
into that decision:
- REST search (`WhoisSearchService`) and REST lookup (`WhoisRestService`) —
  both call `overrideCredentialValidator.getValidOverrideUser(override)`,
  which **does** check the password before returning a non-null `User`.
- Legacy port43 protocol (`QueryDecoder` → `Query.parse(msg, Origin.LEGACY,
  trusted)`) — this 3-arg overload never sets `overrideUser`; the field
  stays `null`. The legacy protocol has no `-V`/override syntax at all
  (confirmed: zero references to any override flag constant in `Query.java`).
- RDAP (`RdapLookupService`/`RdapRelationService`/`RdapController`) — all
  three call the credential-free `Query.parse(String)` overload; `overrideUser`
  stays null. (These three *do* set `NO_FILTERING`, which affects a
  different function — email-address redaction, not auth-hash redaction —
  and is very likely intentional: RDAP's spec expects unredacted contact
  data unlike legacy WHOIS's anti-scraping email obfuscation. Flagged as
  "probably intentional," not reported, given no evidence otherwise.)

**Conclusion:** every real path that reaches the password-hash disclosure
decision already password-validates the override credential *before*
`isAllowedAndValid` runs. The missing check inside `isAllowedAndValid`
itself is dead weight, not a live bypass — but it is a landmine for the
next person who adds a new caller and reasonably assumes the method's name
means what it says. **Worth a hygiene PR upstream** (make
`isAllowedAndValid` actually validate the password itself, or rename it to
make the precondition explicit) even though it is not currently
exploitable — noting it here per the "vulnerabilities of omission" spirit,
not as a bounty submission.

### Spring Security filter chain is `permitAll` on every path
`SecurityConfig.securityFilterChain` sets `.requestMatchers("/**").permitAll()`
plus `.anyRequest().permitAll()` and disables CSRF — landed as part of the
very recent "Migrate to Spring Security and OIDC Support" commit
(`530e574b1`, top of history at review time). Initially read as a large red
flag. Traced where the identity these filters establish
(`AuthenticationUtils.getOauthSession()`/`getOidcSession()`) is actually
consumed: every call site feeds it into `InternalUpdatePerformer.initContext()`
alongside the legacy SSO cookie and client certs, which is then handled by
`whois-update`'s `Authenticator`/maintainer-password authorization chain —
a much older, more mature subsystem that is the *real* per-object
authorization gate, independent of the URL-level filter chain. This is a
consistent, apparently-intentional design (Spring Security here does
authentication/identity-establishment only; RPSL-level maintainer
authorization is a separate, orthogonal layer) rather than an oversight —
but **not fully verified**: the `whois-update` handler chain itself wasn't
audited end-to-end this pass. Flagged as the top candidate for the next
session, specifically: does *every* mutating path that accepts an
OAuth/OIDC-sourced identity correctly bind it to maintainer ownership
before acting, with no code path that treats "a valid Spring-Security
session exists" as sufficient on its own.

## Next steps (this program, follow-up passes)

1. `whois-update`'s `Authenticator` + handler chain, full trace — the
   actual maintainer-authorization core, not yet exhaustively covered.
2. `rpki-commons` / `rpki-core` (Tier 1, untouched) — X.509 IP-address
   extension parsing is a classic memory-safety/parsing-bug surface even
   in Java (integer overflow in extension length fields, malformed ASN.1).
3. `rpki-publication-server`, `rpki-ta-0`, `rsyncit`, `rpki-monitoring`
   (Tier 2) — not started.
