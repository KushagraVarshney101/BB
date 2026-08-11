# Module A — Web Source Review: IDOR & Mass Assignment (Java/Spring, Node)

Goal: **IDOR** (object-level authz missing on a path that reaches another
tenant's data) and **mass assignment** (a request binds fields the client
should never control — role, ownership, price, `verified`). Both are the
classic "URL fuzzing can't find this, but ten minutes of source reading can"
bug classes — they require no unusual input, just the *absence* of a check.

Static first (grep the sink patterns below, read the surrounding method),
then confirm dynamically against a real instance if one is reachable.

---

## A1. IDOR — missing ownership check on a fetch/update/delete path

**The Prompt:** "Which endpoints take an ID and return/modify a row, and does
the code verify the caller *owns* that row, or only that the row *exists*?"

**The Tool — Spring:**
```bash
# Every handler that binds a path/query id straight into a repository call
grep -rnE '@(Get|Post|Put|Delete|Patch)Mapping.*\{[a-zA-Z]+Id\}' --include=*.java .
# Then, for each match, look at the method body for a repository/service call
# taking that same id with NOTHING upstream checking it against the
# authenticated principal:
grep -rnE '\.findById\(|\.getById\(|repository\.(find|get|delete)' --include=*.java .
```
**The Tool — Node (Express/Nest/etc.):**
```bash
grep -rnE "router\.(get|post|put|patch|delete)\(.*:(\w*[Ii]d)" --include=*.js --include=*.ts .
grep -rnE '\.findById\(|\.findOne\(\{|Model\.(find|update|delete)' --include=*.js --include=*.ts .
```

**The Payload/Pattern (vulnerable — Spring):**
```java
@GetMapping("/api/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) {
    return orderRepository.findById(orderId).orElseThrow();   // no ownership check
}
```
**The fix that should be present and its absence is the finding:**
```java
Order o = orderRepository.findById(orderId).orElseThrow();
if (!o.getOwnerId().equals(currentUser().getId())) throw new AccessDeniedException();
```
Look specifically for handlers where the *only* gate is `@PreAuthorize`/
`@Secured` checking a **role** (`hasRole('USER')`) rather than **ownership**
of the specific object — role-only checks are exactly what makes IDOR
invisible to a permissions matrix review. A role check answers "can this
principal type touch this endpoint," never "does this principal own this
row" — the two are orthogonal and only the second one stops IDOR.

**The Bounty Mindset:** IDOR on a numeric/sequential ID is trivially
provable (increment by one, show the other tenant's data) and triagers pay
it fast. IDOR on a UUID still counts if the UUID is discoverable (leaked in
another response, in a URL, in an export) — don't dismiss non-sequential IDs
without checking for a leak path first.

---

## A2. Mass assignment — the request binds fields it shouldn't

**The Prompt:** "Does any endpoint deserialize the request body straight
into a persistence entity (or into a DTO promoted straight to one) without
an explicit allow-list, letting the client set fields the UI never exposes?"

**The Tool — Spring:**
```bash
# @RequestBody bound directly to an @Entity (not a narrow DTO) is the tell
grep -rnE '@RequestBody\s+\w+' --include=*.java . | grep -v DTO
# Confirm the target class is a JPA entity, not a request-scoped DTO:
grep -rlE '@Entity' --include=*.java . | xargs -I{} basename {} .java
# Cross-reference: any @RequestBody type name that also appears in the @Entity list above
```
**The Tool — Node:**
```bash
# Spread/assign of req.body straight onto a model, with no field allow-list
grep -rnE '(Object\.assign\(.*req\.body|new \w+\(req\.body\)|\.update\(req\.body\)|\{\s*\.\.\.req\.body)' --include=*.js --include=*.ts .
```

**The Payload/Pattern (vulnerable):**
```java
@PostMapping("/api/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User update) {   // User is the @Entity
    User existing = userRepository.findById(id).orElseThrow();
    BeanUtils.copyProperties(update, existing, "id");   // copies EVERY field, including "role", "verified", "balance"
    return userRepository.save(existing);
}
```
```js
// Node/Mongoose equivalent
app.patch('/api/users/:id', (req, res) => {
  User.findByIdAndUpdate(req.params.id, req.body, (e, u) => res.json(u));  // req.body could contain {role:"admin"}
});
```
**Fields to specifically hunt for in the request schema that turn this from
Informative into a real finding:** `role`, `isAdmin`, `verified`,
`emailVerified`, `balance`, `price`, `discount`, `ownerId`, `tenantId`,
`status` on any state machine. A mass-assignment bug that only lets you
rename yourself is Informative; one that lets you set `role: "admin"` or
`ownerId` to someone else's account is P1.

**The Bounty Mindset:** Prove it by sending the extra field and observing
the state actually changed server-side (re-fetch the object, don't trust the
echoed response). "The DTO looks unsafe" is not a finding — "I set
`role=admin` on my own account via this endpoint and the server persisted
it" is.

---

## A3. GraphQL equivalent — no per-field or per-resolver authz

**The Prompt:** "Does a resolver that returns/mutates a specific object
check ownership, or does it trust the ID argument the same way a REST path
param can't be trusted?"

**The Tool:**
```bash
grep -rnE '@(QueryMapping|MutationMapping|SchemaMapping)' --include=*.java .   # Spring GraphQL
grep -rnE 'resolvers\s*=|Query:\s*\{|Mutation:\s*\{' --include=*.js --include=*.ts .
```
Same check as A1, just applied per-resolver instead of per-route: does the
resolver body verify the requesting principal owns the object identified by
the argument, or only that an object with that ID exists?

**The Bounty Mindset:** GraphQL IDOR is systematically under-reported
because generalist scanners don't crawl the schema — a manual pass here is
disproportionately high-EV per hour spent versus REST.

---

## A4. Broken object-level authz via nested/indirect references

**The Prompt:** "Does an endpoint accept a *parent* ID the caller owns, but
then trust a *child* ID from the same request body without re-checking that
the child actually belongs to that parent?"

**The Tool:** read every handler that takes two related IDs (e.g.
`orgId` + `memberId`, `orderId` + `lineItemId`) and check whether the code
verifies `child.parentId == parentId`, or just does `child = repo.find(childId)`
and trusts the URL's `parentId` for the authz decision while never using it
to filter the actual query.

**The Payload/Pattern (vulnerable):**
```java
@DeleteMapping("/api/orgs/{orgId}/members/{memberId}")
public void removeMember(@PathVariable Long orgId, @PathVariable Long memberId) {
    // orgId is checked against the caller's org membership — but memberId
    // is looked up globally, not scoped to orgId, so any org admin can
    // delete a member of ANY org by passing their own orgId + a foreign memberId.
    checkCallerIsAdminOf(orgId);
    memberRepository.deleteById(memberId);
}
```

**The Bounty Mindset:** This is the IDOR variant that survives a naive
"does every endpoint have an authz check" audit, because there *is* a check
— it's just checking the wrong ID. It is also exactly the kind of bug
`bug-hunter` Module C's escalation table describes turning a P5 into a P1:
an endpoint that looks protected on first read is often protected against
the wrong axis.

---

## House rule for this module

Every A1–A4 candidate needs a **negative-space confirmation** before it's a
lead: grep for the fix shape (`.getOwnerId().equals(`, `@PreAuthorize`
referencing the *specific* object, an explicit DTO allow-list) in the same
file. If the fix pattern is present elsewhere in the method and you just
didn't see it on first read, it's not a finding — re-read before writing it
up. `adversarial-code-review`'s evidence-contract discipline (Phase 6 of
that skill) applies here directly: trace the full source → sink path, and
state explicitly which controls you checked and ruled out, not just which
ones you didn't see.
