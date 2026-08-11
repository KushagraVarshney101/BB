# Static Review — remaining `ripencc` Tier-2 repos: `rpki-ta-0`, `rsyncit`, `rpki-monitoring`

Lighter-touch pass than `whois`/`rpki-commons`/`rpki-core`/
`rpki-publication-server` — structural review plus one concrete thread
followed on `rpki-ta-0` given its outsized importance (it's the actual
trust-anchor signing tool). No live traffic; no history-based crowd screen
available (all three shallow-cloned).

## `rpki-ta-0` — worth a procedural-controls question, not a software finding

This is a standalone, manually-operated CLI signing tool (`Main.java` +
`ProgramOptions.java`), built for use with an HSM (the changelog mentions
"FIPS 140-[23] level 3 mode"), matching the standard real-world pattern for
RPKI trust-anchor key material: kept offline/air-gapped, run as a manual
signing ceremony rather than a network service. `TA.processRequestXml`
reads a `TrustAnchorRequest` XML file (produced elsewhere — presumably
exported from `rpki-core` and carried across the air gap) and, for a
`SigningRequest`, calls `signAllResourcesCertificate`, which builds an
"all resources" CA certificate using **the request's own subject DN and
public key** (`builder.withSubjectDN(request.getSubjectDN())`,
`builder.withPublicKey(new EncodedPublicKey(request.getEncodedSubjectPublicKey()))`)
— only the resource scope itself (`ALL_RESOURCES_SET`) is hardcoded, not
attacker-influenceable via the request.

Read purely as code, this is unremarkable — it's exactly what a TA-signing
tool is supposed to do: sign whatever key/subject a properly-formed
request specifies, scoped to the resources the TA actually holds. It's
**not** independently a software vulnerability. It is, however, the
concrete mechanism by which a compromise upstream (the `rpki-core`
authorization gap in `FINDINGS_rpki-core.md`, if that assumption turns out
to be wrong) could theoretically escalate all the way to "attacker's own
keypair receives an all-resources CA certificate signed by RIPE's trust
anchor" — the most severe object in the entire hierarchy — *if* the
request-transfer and signing-ceremony process has no independent human
review of request contents before signing. That's a procedural/physical
control, not something this review can verify from source. Not reported
as a finding; recorded because it's the thing that would make an eventual
confirmation of the `rpki-core` assumption catastrophic rather than merely
severe, and it's worth RIPE's own team double-checking that the signing
ceremony includes a genuine content review step rather than blind
"process whatever file arrived" automation.

## `rsyncit` — structural pass only

An RRDP→rsync bridge: fetches already-published RRDP content and
re-serves it over rsync (`RrdpFetcher`, `RrdpFetchJob`, `RsyncWriter`).
Read-only republishing of data that's already gone through
`rpki-publication-server`'s authority checks — not itself an
authorization boundary for who can publish what. Lower priority given
the Tier-1 repos' authorization surface wasn't exhausted either; not
deep-dived this pass.

## `rpki-monitoring` — structural pass only

A read-only collector/analysis service (`CollectorUpdateMetrics`,
`CertificateAnalysisService`, `ExpiryMonitorHooks`) — monitors the RPKI
repository's own health/expiry, doesn't mutate CA state. Same reasoning
as `rsyncit`: lower-priority given it's not an authorization boundary;
not deep-dived.

## Session-wide coverage summary (all 7 in-scope repos touched this pass)

| Repo | Depth | Outcome |
|---|---|---|
| `whois` | Deep | 1 already-fixed vuln + full variant sweep; 2 threads ruled out with full evidence |
| `rpki-commons` | Deep | 1 already-fixed vuln + full variant sweep; 1 severe-looking path confirmed unreachable in production |
| `rpki-core` | Deep | 2 live candidate findings, both gated on one unverified network-reachability fact |
| `rpki-publication-server` | Deep | Traces/connects to `rpki-core` Finding 1, raises its real-world ceiling |
| `rpki-ta-0` | Light | Procedural-controls note, not a software finding |
| `rsyncit` | Structural only | No auth-boundary surface identified; not deep-dived |
| `rpki-monitoring` | Structural only | No auth-boundary surface identified; not deep-dived |

Not covered this session: `whois-update`'s core `Authenticator`/maintainer-
authz chain (flagged in `FINDINGS_whois.md` as the top follow-up from that
pass — still open); `rpki-publication-server`'s `PublicationMessageParser`/
`RRDPService` (flagged in that file); a full deep-dive of `rsyncit`/
`rpki-monitoring` if a reason to prioritize them emerges.

## The one action that unblocks everything in `rpki-core`/`rpki-publication-server`

Every open finding in this program funnels back to a single unverified
fact: **is `rpki-core`'s `/api/**`/`/api/public/**` REST surface reachable
by anything other than RIPE's own authenticated portal backend?** This
review has no way to check that from a source-only pass with no live
network egress. Confirming it one way or the other is worth more than any
further static analysis in this program right now.
