# ExpressVPN `lightway` — fragment reassembly: overlap-check bypass + unbounded state retention

**Program:** ExpressVPN Bug Bounty (YesWeHack, `expressvpn-bug-bounty-program`,
public, €50–2500). `https://github.com/expressvpn/lightway` is explicitly
listed in-scope.

> Note: the repo's `SECURITY.adoc` points at Bugcrowd, but the live
> YesWeHack program lists this repo as an in-scope asset and is `public:
> true, disabled: false`. Worth confirming which intake ExpressVPN wants
> before submitting — the YWH program is the one that appears in the
> current bounty-targets-data snapshot.

**File:** `lightway-core/src/connection/fragment_map.rs`
**Reachability:** post-authentication (`handle_outside_data_fragment` requires
`State::Online`), i.e. any client that can complete a normal VPN session.
Both client and server run the same reassembly code.

**Status: VERIFIED BY EXECUTION.** Unlike a read-only argument, these were
run as tests against unmodified upstream logic (`cargo test -p lightway-core`).
PoCs are in `poc/fragment_map_poc.rs` and apply cleanly to the crate's
existing `#[cfg(test)]` module.

**Upstream commit reviewed:** `c40df64dabf424fa3d036a2a139d548b63400397`
(2026-08-11, `main`).

## Bottom line before the detail

- **Finding 1 (overlap-check bypass) is the report.** It is a genuine,
  novel, execution-verified break of an invariant the module explicitly
  implements and tests for. Nothing in the repo's history addresses it.
  Realistically **low severity** (P4-ish): it corrupts reassembly state and
  silently drops a legitimate packet; I could not escalate it to data
  injection or memory unsafety, and I say so explicitly below.
- **Finding 2 (resource retention) is largely already known to ExpressVPN**
  — see the dupe-screen box on it. Do not submit it standalone.

---

## Finding 1 — Overlapping-fragment check can be bypassed (state corruption)

### The defect

`FragmentedPacket::update()` walks the sorted fragment list and, for each
index, first tests the incoming fragment for overlap against **only that
one entry**:

```rust
for idx in 0..self.fragments.len() {
    let curr = &mut self.fragments[idx];

    // Check for overlap — against `curr` ONLY
    if frag.end_offset() > curr.start && frag.start_offset() < curr.end() {
        return Err(FragmentMapError::Overlapping);
    };
    ...
    } else if frag.end_offset() == curr.start || curr.end() == frag.start_offset() {
        curr.add_wire_frag(frag)?;   // ← extends `curr` FORWARD, unbounded
        // merge with idx+1 only if it exactly closes the gap
        if idx < self.fragments.len() - 1
            && self.fragments[idx].end() == self.fragments[idx + 1].start
        { ... }
        return Ok(());
    }
}
```

When the incoming fragment is *contiguous immediately after* `fragments[idx]`,
`add_wire_frag` extends that fragment forward by the new fragment's full
length. That new extent is **never re-checked against `fragments[idx+1]`**.
The only post-merge test is for an *exact* gap closure (`==`); an
overshoot past the next fragment's start silently passes.

So a fragment that is contiguous-after A and *overlapping* B is accepted,
even though rejecting overlaps is an explicit, tested invariant of this
module (`FragmentMapError::Overlapping`, with five dedicated test cases).

### Verified PoC

Three wire-representable fragments (offsets are 8-byte aligned as the wire
format requires; lengths fit `u16`):

| # | offset | len | more_fragments |
|---|--------|-----|----------------|
| A | 0      | 8   | true           |
| B | 16     | 8   | true           |
| C | 8      | 16  | true           |

C is contiguous after A (`A.end() == 8 == C.start`) and overlaps B
(`C` spans 8..24, `B` spans 16..24).

Actual output from `cargo test`:

```
update() returned: None
resulting state:   32: { 0..24 = AAAAAAAACCCCCCCCCCCCCCCC, 16..24 = BBBBBBBB }
```

`update()` returns `Ok` — the overlapping fragment is accepted — and the
fragment list now holds two entries whose ranges overlap (`0..24` and
`16..24`). The reported total (`32`) also double-counts B's 8 bytes against
a real span of 24, so `Fragment::size` accounting is inflated.

### Consequence: the packet is permanently wedged

`try_complete()` requires `fragments.len() == 1`. Once the list is
corrupted, the orphaned entry can never be merged away — merging requires
`fragments[idx].end() == fragments[idx+1].start`, and the corrupted
fragment's end has already overshot past that point and only ever grows.
Sending the legitimate final fragment does not help:

```
after final frag: 40: { 0..32 = AAAAAAAACCCCCCCCCCCCCCCC DDDDDDDD., 16..24 = BBBBBBBB }
try_complete -> false
```

The entry is complete-looking (`0..32`, `is_last` set) yet can never be
delivered, and is retained until LRU eviction — which, per Finding 2, has
no time bound.

### What this is *not*

Being precise so severity isn't overstated: I could not reach a state where
a *corrupted* fragment reaches `fragments.len() == 1` and completes.
Therefore this does **not** yield a reassembled packet containing
attacker-chosen overlapping data (the classic fragment-overlap
IDS/firewall-evasion primitive), and there is no memory-safety impact —
`try_complete` uses `frag.size` only as a `BytesMut::with_capacity` hint
and then `extend`s the actual data. The realistic impact is state
corruption → permanent wedge → resource retention, which is Finding 2.

---

## Finding 2 — No reassembly timeout and no per-packet fragment limit

> ### ⚠️ DUPE SCREEN RESULT: mostly already known — do NOT lead with this
>
> `git log` on this file turns up commit `edac39e` (May 2026, ticket
> `CVPN-1597-reduce-fragment-map-size`):
>
> > *"Previously max size was 65536 (uint16), which can take up to 8GB of
> > memory per connection, assuming maximum fragment size. Reduced to 4096."*
>
> ExpressVPN has **already identified, quantified and deliberately
> mitigated** the memory-exhaustion issue. The ~1.28 GB measured below is
> precisely the residual they accepted when they chose 4096. Submitting
> this as a new memory-DoS finding would almost certainly be closed as
> known/duplicate, and would signal the history wasn't read.
>
> Two aspects are arguably *not* covered by that commit, but both are
> adjacent to a known issue and carry high duplicate risk:
> - Their stated reasoning is entirely about **memory**; the **O(N²) CPU**
>   cost of insertion appears unconsidered.
> - There is still no **time-based expiry** — the bound is purely LRU
>   capacity, so retention is unbounded in *time* even if bounded in size.
>
> Recommendation: fold these in as a hardening note attached to Finding 1,
> not as a standalone report.

### The defect

`FragmentMap` is an `LruCache<u16, FragmentedPacket>` with
`DEFAULT_MAX_ENTRIES = 4096`. That caps the number of concurrent
*fragment ids*, and it is the **only** bound:

- No time-based expiry of incomplete reassemblies. Entries are freed only
  when a 4097th distinct id forces LRU eviction. (For comparison, IP
  fragment reassembly has had a mandatory reassembly timeout since RFC 791
  §3.2 — 15 seconds — precisely to bound this.)
- No cap on the number of `Fragment` entries within one packet.
- No cap on total bytes buffered per packet or per connection.

Because the wire format's fragment offset is 13 bits shifted left by 3
(8-byte aligned, max `0xfff8`), an attacker can place 8-byte fragments at
offsets 0, 16, 32, … — every one non-contiguous, so every one allocates a
separate `Fragment` that is never coalesced and never freed.

Insertion is also a linear scan of the existing list, so building N
fragments costs O(N²) comparisons when offsets arrive in ascending order.

### Verified measurements

From the executed test (`poc_unbounded_fragment_retention`):

```
size_of::<Fragment>()            = 48
fragments retained for ONE id    = 4096
attacker wire bytes for ONE id   = 61440 (15B per DataFrag frame)
struct bytes retained ONE id     = 320 KiB
insert wall time ONE id          = 16.603794ms       [RELEASE build]
                                 (273.584204ms debug — do not quote that one)
--- scaled to the 4096-id LRU capacity ---
total fragments retained         = 16777216
total struct bytes retained      = 1280 MiB
total attacker bytes to get there= 240 MiB
```

Two amplifications, per connection:

- **Memory:** ~240 MB of attacker traffic pins ~1.28 GB of `Fragment`
  structs that are never reclaimed. This is a floor — it counts only the
  structs. Each retained `Bytes` is a slice of the connection's receive
  buffer (`commit_and_split_to`), so the underlying allocation stays alive
  while any fragment references it, adding more. **But see the dupe-screen
  box: this specific figure is the residual ExpressVPN knowingly accepted.**
- **CPU:** the O(N²) insert cost — 16.6 ms per id in a release build, so
  ~68 s of single-core CPU to fill all 4096 ids. Against ~240 MB of
  traffic (~2 s at 1 Gbps) that is roughly a **30×** compute amplification.
  Real, but modest, and it is the one part of Finding 2 their commit
  message does not appear to have reasoned about.

`max_fragment_map_entries` is builder-configurable
(`with_fragment_map_entries`), but the default is what ships, and raising
or lowering it only trades the id cap against the per-id cap — neither
bounds total bytes or adds expiry.

### Note on scope

Resource-exhaustion issues are excluded by some programs. The framing that
matters here is that Finding 1 is a **bypass of an explicit security check
the code implements and tests for**, not a traffic flood; Finding 2 is the
missing-bound that turns it into retained state. If ExpressVPN's YWH policy
excludes DoS outright, Finding 1 still stands on its own as a correctness
/security-invariant break. I could not read the program's exclusion list
from this environment (no egress to yeswehack.com) — **check the policy
before submitting**.

---

## Suggested fixes

**Finding 1** — after `add_wire_frag` extends `curr` forward, re-check the
new extent against `fragments[idx + 1]` and reject if
`self.fragments[idx].end() > self.fragments[idx + 1].start`. (Changing the
merge condition from `==` to `>=` would silently accept the overlap rather
than reject it, so the explicit check is the safer fix.)

**Finding 2** — add (a) a reassembly deadline per `FragmentedPacket`,
dropping entries older than a small timeout, (b) a cap on
`fragments.len()` per packet, and (c) a cap on total buffered bytes per
connection. Any one of these alone bounds the impact; (a) matches the
long-standing IP-reassembly precedent.

## Why the existing fuzzers did not catch this

`lightway-core/fuzz/fuzz_targets/` contains `fuzz_parse_frame.rs` and
`fuzz_parse_header.rs` — both single-shot parsers over one buffer.
Reassembly is **stateful across packets**: the bug needs a specific
three-fragment *sequence*, which a single-input fuzz target cannot
construct. A stateful harness driving `FragmentedPacket::update()` with a
sequence of `(offset, len, more_fragments)` tuples, asserting the
list stays sorted and non-overlapping after every operation, would find
Finding 1 immediately. That harness is worth suggesting to them regardless
of these findings' outcome.
