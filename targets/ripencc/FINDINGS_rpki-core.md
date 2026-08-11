# Static Review — RIPE NCC `rpki-core` (Intigriti `ripencc`, Tier 1)

Source-only, no live traffic. Repo cloned with full history (137 commits —
this GitHub mirror is a curated/partial export of RIPE's actual production
CA service; the program's own scope description says as much: "we strive
to publish as many components as possible... some elements are not
included because of our threat model"). Crowd screen: thin recent history,
no useful security-shaped commit-message signal this pass (two generic
merge markers only).

## Finding — no per-CA authorization check in the REST API; trust boundary rests entirely on network isolation + a shared static key

**Confidence: code-level facts below are directly verified by reading the
source. Real-world exploitability depends on one infrastructure fact this
review cannot verify from a static-only, no-network-access pass — see
"Load-bearing assumption" below. Reporting this as a named, evidenced
finding per that uncertainty, not as a confirmed critical bug and not
silently dropped either.**

### What the code does

`rpki-core` exposes a REST API (`/api/**`, `/prod/ca/**`) for CA-scoped
operations — ROA configuration (`CaRoaConfigurationService`), ASPA
configuration (`CaAspaConfigurationService`), resource management
(`ResourceService`), publisher-repository management
(`PublisherRepositoriesService`), etc. Every such service extends
`AbstractCaRestService`, which resolves the target CA purely by name from
the URL (`getCa(type, CaName.parse(pathParam))`) with **no check that the
caller is permitted to act on that specific CA**.

Authentication for this whole API surface is a single shared secret:
`ApiKeySecurity` (a Spring Security `AuthorizationManager`) checks the
`ncc-internal-api-key` header against a `Properties` file loaded at
startup — `granted = apikey != null && apiKeys.containsKey(apikey)`. That
is the *entire* check `SecurityConfig.java` wires up for `/api/**`:

```java
.requestMatchers("/api/monitoring/**").permitAll()
.requestMatchers("/api/public/**").permitAll()
.anyRequest().access(apiKeySecurity)   // ← the only gate on everything else
```

Separately, `AbstractCaRestService` reads a `user-id` cookie (an arbitrary
client-supplied UUID, no signature, no server-side session lookup) and
wraps it in a `RunAsUser`. Traced every consumer of that identity
(`RunAsUserHolder.get()`, 3 call sites total in the whole main source
tree): one (`CaRoaConfigurationService.java:300`) uses it only to attribute
a change in an audit-log entry; the other two are in the *web UI's*
authentication strategy, an entirely separate code path from the REST API.
**`RunAsUser`/`user-id` is never compared against which member actually
owns the target CA, anywhere in `rest`, `domain`, `core`, or `services`.**
Confirmed by grepping the whole main source tree for
`ROLE_CA_OPERATOR`/`@PreAuthorize`/`hasRole`/`hasAuthority`/any
ownership-check method name — zero hits outside the UI's own,
separately-gated `SecurityFilterChain`.

Net effect, read purely from the code: **anyone who can present a valid
`ncc-internal-api-key` can set the `user-id` cookie to any UUID and act on
any CA by name** — read or mutate ROA/ASPA configuration, resource
assignments, publisher repositories — for any RIPE member's certificate
authority, not just the one the "acting user" actually manages. Given that
ROAs are literally how BGP route-origin authorization is expressed in
RPKI, cross-member ROA mutation is about as high-impact as a bug in this
codebase can get — it would let one member author a route-origin
authorization for IP space belonging to a different member.

### Load-bearing assumption (unverified — this is what determines real risk)

The code contains **zero defense-in-depth** for this path — no per-object
ownership check exists anywhere between the API key gate and the mutation.
Its entire security therefore rests on one fact this review cannot check:
**that the `/api/**` surface is not reachable by anything except RIPE's own
already-authenticated member-portal backend**, which is presumably the
actual place per-user CA-ownership gets validated before it ever calls
into rpki-core with a `caName` + `user-id` pair. This is a completely
standard, often-correct microservice pattern (BFF does authz, internal
service trusts the BFF) — the finding is not "this is definitely broken,"
it's "there is no second line of defense if that one assumption is ever
wrong": a network misconfiguration, an SSRF from any other RIPE-internal
service that can reach this port, or a leaked/guessed `ncc-internal-api-key`
(the file shipped in `src/main/resources/test-api-keys.properties` is
explicitly marked test-only/not-a-secret, so that specific file isn't the
risk — but it does confirm the mechanism is "one flat static key," a much
smaller attack surface to protect than per-request signed tokens would be)
would each independently be sufficient to reach full cross-member CA
takeover, with nothing else standing in the way.

**Who could confirm this:** RIPE NCC's own infrastructure/network team —
whether `/api/**` on this service is genuinely unreachable except from the
portal backend (private VPC/no public ingress/mTLS-only internal mesh,
etc.). Not confirmable from this repo alone, and not confirmable from this
sandbox regardless (no live network egress here even if the endpoint were
public — see `NOISE_SCREEN.md`).

**Update from the `rpki-publication-server` pass (`FINDINGS_rpki-publication-server.md`):**
traced `rpki-core`'s outbound side too. `PublishingServerClient.publish(url,
xml, clientId)` uses a single shared client to push published content to
`rpki-publication-server`'s namespace named by whatever `clientId` string
it's given — that server enforces no independent check on which `clientId`
its one trusted caller (`rpki-core`) is allowed to act as. So this isn't
just "an attacker can rewrite another member's ROA row in a database" — if
a ROA/config mutation through the vulnerable REST path triggers the normal
republish flow (not separately confirmed this pass, but it is the entire
point of that config existing), the forged content propagates all the way
to the live, globally-fetched RPKI repository other networks' routers make
trust decisions from. That's the actual ceiling on this finding's impact,
not "internal database state."

### Why this wasn't over-claimed as a P1 and submitted

Per `bug-hunter`'s own house rule ("name the attacker before you invest")
and the `adversarial-code-review` evidence-contract discipline: a finding
needs a stated, real attacker who can reach the vulnerable state. Here the
code-level mechanism is fully proven, but the reachability precondition
(external or cross-service network access to `/api/**`) is unverified —
this is exactly the `latent` verdict category from that methodology's
verification phase: *a real defect, currently unreachable as far as this
review can establish, that goes live the moment the network assumption
doesn't hold.* Documenting it here rather than as a bounty submission until
someone can confirm reachability — if you have access to check whether
this port/path is internet- or cross-service-reachable in RIPE's actual
deployment, that single fact converts this from a note into a P1 report.

## Finding 2 — unauthenticated PII/business-relationship oracle at `/api/public/gdpr/investigate`

**Higher confidence than Finding 1** — this one requires no API key at all,
by explicit design in `SecurityConfig.java`, so there is no "maybe a key
gates it" ambiguity; the only open question is whether `/api/public/**`
is served to the internet at all, and the path segment's own name argues
that it's *more* likely to be internet-facing than the general `/api/**`
surface, not less.

**File:** `src/main/java/net/ripe/rpki/rest/service/GdprService.java`

`POST /api/public/gdpr/investigate` takes a JSON body `{id: UUID, emails:
[String]}` and, for each email, returns:

- which certificate authorities (RIPE members) that email address is
  registered for ROA-alert notifications on (`"Subscribed '<email>' for
  alerts for the CA(s) <names>"`) — i.e., **which member organization an
  email address belongs to**;
- every `commandType` in the internal audit log that mentions the email
  (or the `id` UUID), with an occurrence count;
- an overall `partOfRegistry` boolean.

No authentication, no rate limiting, no restriction to querying your own
address — `emails` is a list, so this is a batch oracle: feed it a
candidate list and learn, for each one, whether it's a RIPE NCC portal
user and which CA(s)/member it's tied to. This is a standard, commonly
payable broken-access-control class (unauthenticated PII/business-
relationship enumeration) if the endpoint is actually internet-reachable.

**Signal that this is unintended exposure, not intended design:** the
method's own Swagger annotation reads *"Endpoint called by Controlroom"* —
Controlroom being (by every contextual signal in this codebase) an
internal RIPE NCC admin/ops tool. That is close to a developer admission
that this was built for internal, tool-to-tool use, and its placement
under `/api/public/**` (rather than the API-key-gated `/api/**` root,
where the rest of the CA-management surface lives) looks like an
oversight in path choice rather than an intentional "self-service GDPR
lookup for the public" feature — a genuine self-service design would
scope a caller to their own single, pre-verified email, not accept an
arbitrary batch.

**Compare:** the other two endpoints actually under `/api/public/**`
(`SystemStatusService` — health/status, `RoaPrefixesService`/`AspaService`/
`PublishedObjectsService` under `/api/monitoring/**` — RPKI's own
published data, public by the protocol's design) are all genuinely
public-appropriate. `GdprService` is the one outlier that returns
cross-referenced personal/business data on that path.

**Not yet confirmed:** actual internet reachability (same caveat as
Finding 1) — flagging here rather than submitting, for the same reason.
If you can confirm `/api/public/**` is served externally, this is likely
the stronger and more directly reportable of the two findings in this
file, since it needs no key/cookie manipulation at all to reach — just an
HTTP POST.

## Coverage

- Reviewed: `AbstractCaRestService`, `ApiKeySecurity`, `SpringAuthInterceptor`,
  `SecurityConfig` (rest/security package in full), `RunAsUser`/
  `RunAsUserHolder` and every consumer of the latter repo-wide.
- Not reviewed this pass: the actual ROA/ASPA/resource mutation business
  logic inside `CaRoaConfigurationService`/`CaAspaConfigurationService`/
  `ResourceService` beyond confirming they inherit the same
  no-ownership-check base class; `/api/public/**` and `/api/monitoring/**`
  (both explicitly `permitAll()` — worth a quick pass to confirm nothing
  sensitive lives there, not yet done); `offline`, `hsm`, `bgpris`,
  `publication` packages; the provisioning (`/updown`) protocol endpoint,
  which `SecurityConfig` also sets fully `permitAll()` for a different
  reason (it's the RFC 6492 up-down protocol, authenticated by its own
  CMS-signature scheme rather than Spring Security — plausible by design,
  not verified this pass).

## Next steps

1. **Highest priority: get the network-reachability question answered.**
   Everything else in this file is secondary to that one fact.
2. `/api/public/**` and `/api/monitoring/**` — confirm nothing sensitive
   is exposed under the explicit `permitAll()`.
3. `/updown` provisioning endpoint's own CMS-based auth, to confirm it's
   not relying on the same "trust the network boundary" assumption without
   its own cryptographic gate.
4. Carry over from prior passes: `whois-update`'s authz chain; three
   Tier-2 RIPE repos (`rpki-monitoring`, `rpki-publication-server`,
   `rpki-ta-0`, `rsyncit`) not yet started.
