# Static Review — RIPE NCC `rpki-publication-server` (Intigriti `ripencc`, Tier 2)

Source-only, no live traffic. Scala/Pekko-HTTP service. Shallow clone
(single commit — no crowd/dupe-screen history available this pass).

## Finding — publish/withdraw/list namespace (`clientId`) is a bare query
## parameter, never bound to the authenticated mTLS client identity — but
## this is very likely a *second confirmation* of the rpki-core gap, not an
## independently new external attack surface

**File:** `src/main/scala/net/ripe/rpki/publicationserver/PublicationService.scala`
(request routing) + `.../util/SSLHelper.scala` (TLS setup).

The publication endpoint (`POST /`) reads which publisher's namespace to
act on — publish, withdraw, or list objects — from a plain URL query
parameter: `parameter("clientId") { clientId => ... processRequest(request,
ClientId(clientId)) }`. The server does require a client certificate at the
TLS layer (`engine.setNeedClientAuth(true)` in `SSLHelper`), but **nothing
in the main source tree reads the negotiated peer certificate's identity
and cross-checks it against the `clientId` parameter.** Grepped the whole
repo for any certificate-subject/CN-to-clientId binding logic
(`PeerCertificate`, `X500`, `getSubjectDN`, `CN=`) — the only hit is
`SSLHelper.scala` itself, which only configures *that a* client cert is
required, not *whose*.

Read in isolation, this looks like a severe bug: whoever holds *any*
trusted client certificate could publish or withdraw objects under *any*
other publisher's `clientId` — for a system whose entire purpose is being
the authoritative source relying parties worldwide fetch RPKI objects
from, that's as high-impact as this program gets.

### Why this most likely isn't independently exploitable by an external party

Traced the only caller of this endpoint found across both repos this
session: `rpki-core`'s `PublishingServerClient.publish(url, xml, clientId)`
(`src/main/java/net/ripe/rpki/publication/server/PublishingServerClient.java`)
uses a single injected, singleton `WebClient` (`@Qualifier("publishingClient")`)
for *every* publish call regardless of which CA/`clientId` it concerns.
That reads as: in RIPE's hosted-CA model, `rpki-core` holds the one mTLS
client identity this truststore trusts, and it self-selects the `clientId`
per request — end users/members are not expected to hold their own
publication-server client certificates at all. If that's accurate (not
independently confirmed — inferred from the calling code's shape, same
caveat as everything else in this pass), an external attacker has no path
to a trusted client certificate in the first place, and this finding
collapses into "the same trust-boundary question as `rpki-core` Finding 1,"
not a second independent hole.

### Why it's still worth recording, and why it *raises* the severity of `rpki-core` Finding 1

If `rpki-core`'s missing per-CA authorization (`FINDINGS_rpki-core.md`,
Finding 1) is ever exploited, this is the mechanism that turns it from "an
attacker can rewrite another member's ROA config in a database" into "an
attacker's forged content becomes the live, globally-fetched RPKI
repository data other people's routers make trust decisions from" — because
`rpki-core`, using its own always-trusted client identity, will faithfully
publish whatever `clientId`/content it's told to, exactly as `rpki-publication-server`
is designed to expect from its one trusted caller. The two repos'
findings aren't separate bugs so much as two ends of the same chain:
rpki-core is the only party this server checks, and rpki-core doesn't
check who's asking it to act on which CA's behalf.

## Coverage

- Reviewed: request routing/auth (`PublicationService.scala`), TLS setup
  (`SSLHelper.scala`), the `clientId` parameter's full path from HTTP
  request to `objectStore.applyChanges`/`.list`.
- Not reviewed: `PgStore.scala` (object storage/DB layer), `RRDPService`/
  `Rrdp.scala`/`RrdpRepositoryWriter.scala` (the actual RRDP snapshot/delta
  generation relying parties fetch), `MessageParser`/`PublicationMessageParser`
  (RFC 8181 XML parsing — a natural next target given this session's other
  finding about strict-vs-lenient parsing in `rpki-commons`'s ROA parser).
- No commit history available this pass (shallow clone) — crowd/dupe
  screen not run for this repo.

## Next steps

1. Confirm (infrastructure-side, not source-reviewable) that
   `rpki-publication-server`'s truststore genuinely contains only
   `rpki-core`'s certificate and no per-member/per-publisher certs — this
   is the fact that determines whether this file's finding is "already
   covered by rpki-core Finding 1" or an independent new hole.
2. `PublicationMessageParser.scala` — check for the same
   lenient-vs-strict-on-malformed-input class already found once in this
   program (`rpki-commons`'s ROA parser fix).
3. `RRDPService`/`Rrdp.scala` — snapshot/delta generation correctness;
   this is what relying parties actually fetch, so a bug here has direct
   ecosystem-wide reach independent of the auth questions above.
