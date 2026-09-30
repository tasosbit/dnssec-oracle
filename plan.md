# DNSSEC oracle on Algorand — plan

## Context

Goal: a smart contract on Algorand that lets anyone prove, with no trusted
relayer, that a TXT record exists at a DNS name, by verifying the DNSSEC
signature chain from the DNS root down to the TXT RRset on-chain.

- Greenfield: `/home/bit/code/dnssec-oracle` is empty.
- RSA verification and MBR accounting are **out of scope**. They come from
  `@d13co/puya-ts-utils/rsa` and `@d13co/puya-ts-utils/mbrManager`; the
  prover computes hints with `@d13co/puya-ts-utils/rsaHint`
  (`rsaMontgomeryHint(modulus)`). Source: `/home/bit/code/puya-ts-utils`,
  v0.3.0, not on npm yet, so linked locally. Taken at face value: Wycheproof
  PKCS#1 v1.5 vectors pass, and a hostile hint can only fail.
- Target: MainNet consensus v42 / AVM v13. The local Algorand skills describe
  AVM 12 and are stale; `/home/bit/Docs/draftvim/avm13-opus.md` is the reference.
- Stack: Algorand TypeScript (PuyaTs ≥ 1.3.1) + AlgoKit, in **D13 style**:
  layered contract, generated error codes, reader/writer SDK, op-up by the SDK,
  e2e tests through the SDK.

## Decisions taken

| Topic         | Decision                                                       |
|---------------|----------------------------------------------------------------|
| Root anchors  | Box storage. Admin uploads the initial anchor set once, after creation. |
| Rollover      | RFC 5011, permissionless (second pass, see "Root anchors: rollover"). First pass: fixed anchors, a KSK roll meant a redeploy. |
| Results       | Stored attestations in boxes, readable on- and off-chain.      |
| RSA size      | Modulus 1024 to 2048 bits.                                     |
| Box rent      | `MbrManager` prepaid credits.                                  |
| TLDs          | No whitelist: any TLD whose keys pass the key rules. Consumers pick the names they trust. Target TLDs for testing: `com`, `io`, `finance`, `co`. |
| Contract code | No update, no delete.                                          |
| RSA host      | Inside the contract (see "Cost").                              |

## Time-sensitive: do this first

The root KSK rolls on **2026-10-11**. Rollover test data cannot be recreated
afterwards, and the second pass needs it. First task, before any code: a daily
cron capturing `. DNSKEY` with its RRSIGs, kept running until the revocation
has been seen.

| When               | What the capture will contain                       |
|--------------------|-----------------------------------------------------|
| Before 2026-10-11  | signed by KSK-2017 (20326), carrying KSK-2024       |
| After 2026-10-11   | signed by KSK-2024 (38696)                          |
| About 2027-01-11   | KSK-2017 with the REVOKE flag, self-signed          |

Also capture a full chain for one name under each target TLD.

The first-pass anchor is **KSK-2017 (20326)**, for live testing now. It
stops signing the root DNSKEY RRset on 2026-10-11, so `proveRoot` fails from
then on and the deployment winds down as its root cache expires. That
deployment is for testing only.

A second-pass deployment made before 2026-10-11 anchors **both** KSK-2017 and
KSK-2024, as IANA's trust anchor file does: anchoring KSK-2017 alone and
letting RFC 5011 add KSK-2024 would leave its 30-day hold-down running past
the roll. From 2026-10-11, KSK-2024 alone does.

## What a proof is

For `_tag.example.com TXT`, 6 signatures and 2 digests:

| # | RRset                  | Signed by        | Links to next via           |
|---|------------------------|------------------|-----------------------------|
| 1 | `. DNSKEY`             | root KSK         | KSK is an anchor            |
| 2 | `com. DS`              | root ZSK         | digest of com KSK           |
| 3 | `com. DNSKEY`          | com KSK          | contains com ZSK            |
| 4 | `example.com. DS`      | com ZSK          | digest of example.com KSK   |
| 5 | `example.com. DNSKEY`  | example.com KSK  | contains example.com ZSK    |
| 6 | `_tag.example.com TXT` | example.com ZSK  | the result                  |

Live key material for the target TLDs (2026-09-28):

| Zone    | Algorithm      | KSK      | ZSK              |
|---------|----------------|----------|------------------|
| root    | 8 RSA/SHA-256  | RSA-2048 | RSA-2048         |
| com     | 13 ECDSA P-256 | P-256    | P-256            |
| io      | 8 RSA/SHA-256  | RSA-2048 | RSA-1024         |
| finance | 8 RSA/SHA-256  | RSA-2048 | RSA-1024         |
| co      | 8 RSA/SHA-256  | RSA-2048 | RSA-1280 + 1024  |

All DS records use SHA-256. All RSA exponents are 65537. Nothing exceeds the
2048-bit cap.

## Design

One contract. Every proving method performs **exactly one** signature
verification. Rows 1–3 are cached, so they are paid once per signing period
and shared by every domain under that TLD.

### Contract layering (D13)

```
Contract → MbrManager (puya-ts-utils) → BaseContract (increaseBudget) → DnssecOracle
```

The library's `MbrManager` extends `Contract` directly, so `BaseContract` sits
above it rather than below. Each layer owns one concern.

- `BaseContract.increaseBudget(itxns)`: the contract never sizes its own
  budget and never calls `ensureBudget`. The SDK probes by simulation and
  prepends this call when short.
- `MbrManager`: every method that creates or deletes boxes snapshots
  `minBalance` at the start and settles the difference against credits at
  the end. `depositCredits`, `withdrawCredits` and `logCredits` come with it.
- Errors: `loggedAssert(cond, errX)` with codes in `errors.algo.ts`, e.g.
  `export const errAnchor = 'ANC' // Signing key is not an anchor`.
  `generate-errors.ts` must also read the library's codes (`CRD`, `RCV`,
  `AMT`), which are documented with a JSDoc comment above the constant, not a
  trailing one.
- The RSA library uses plain `assert` with messages. The contract pre-checks
  what it can (lengths, exponent, size bounds) with `loggedAssert` first, so
  the usual failures surface as codes.

### Lifecycle: two-step creation

1. **Create**, `@baremethod({ onCreate: 'require' })`: `admin = sender`;
   enable `ForeignBoxReads` with `app_params_set`. No anchor: boxes cannot be
   written yet, the app account is not funded.
2. **Anchor**, one group from the admin: fund the app's base MBR,
   `depositCredits`, `addAnchors(dnskeys)`.

`addAnchors` requires sender = `admin` and `anchorCount = 0`. It applies the
DNSKEY and RSA/ECDSA checks below plus flags exactly 257 to each key, rejects
duplicates, writes each box `a ‖ sha256(alg ‖ pubkey)` as Valid and sets
`anchorCount` to the number of keys. After that only RFC 5011 rollover
changes the anchor set; the admin has no say in it. Until it runs, every
proof fails.

No update or delete methods: this overrides the D13 default of creator-gated
ones, per "Decisions taken".

### The one input format

Every proving method takes one `signedData` argument: exactly the bytes that
get hashed (RRSIG RDATA without the signature, then the RRset). Alongside it:
the signature, the Montgomery hint for RSA, a key index and, for child
methods, a `parent` argument.

- Parsed from offset 0; the cursor must land exactly on the end.
- Owner name, type and signer name come **only** from these bytes.
- Box keys are derived from the parsed names, never from arguments.
- RRs are reached by index, walking from the start. No prover-supplied offsets.
- `parent` is the RRset bytes of an earlier proof: the signer's DNSKEY RRset
  (`proveDs`, `proveTxt`) or the owner's DS RRset (`proveDnskey`). Its cache
  box is located from names parsed out of `signedData`, and `sha256(parent)`
  must equal the stored hash. It is parsed by the same rules. The cache holds
  hashes only, so this is how a child method gets the parent key or digest.

This closes boundary-shifting: a tenant of a shared zone embedding a fake RR
for a sibling name inside their own TXT value.

Hard limit: `sha256` takes one value of at most 4,096 bytes and cannot stream,
so signed data or a parent RRset above that size is unprovable. Documented,
not worked around. The contract needs no check: v42 caps each app argument at
4,096 bytes, so oversized data never reaches it. The SDK's prover refuses it
before sending.

Wire rules: a label length byte must be below `0x40`, which rejects
compression pointers and extended label types.

### State

| Where  | Key                          | Value                                                     |
|--------|------------------------------|-----------------------------------------------------------|
| Global | `admin`                      | address                                                   |
| Global | `anchorCount`                | uint64, 0 until `addAnchors`, then the initial count      |
| Global | `rollInception`              | uint64, inception of the newest root RRset a rollover step used |
| Global | `lastEpoch`                  | uint64, the last epoch handed out (see "Epochs")          |
| Global | `rootEpoch`                  | uint64, the anchor set's epoch, fresh at each revocation of a trusted key |
| Box    | `a` ‖ `sha256(alg ‖ pubkey)` | anchor: `state`, `since` (uint64 each), RFC 5011          |
| Box    | `r` ‖ `sha256(name ‖ type)`  | cache: `sha256(RRset)`, `inception`, `expiry`, `weakestKeyBits`, `epoch`, `parentEpoch` |
| Box    | `t` ‖ `sha256(name)`         | attestation: header, then `uint16 rdlen ‖ rdata` per RR   |
| Box    | `c` ‖ address                | MbrManager credits, uint64                                |

Attestation header: `inception`, `expiration`, `weakestKeyBits`, `parentEpoch`, `payer`.

- `c` is reserved by `MbrManager` (33-byte keys), which is why the cache
  uses `r`. All prefixes are disjoint.
- Anchors are looked up by hash, so they need no enumeration. They are keyed
  by public key because the REVOKE flag changes both key tag and DS digest,
  which matters once rollover lands. `pubkey` is the DNSKEY public key field
  only; flags, protocol and key tag are not hashed.
- Names are wire format, lowercase, labels ≤ 63 bytes, name ≤ 255. In box
  keys, `name` includes the terminating zero byte and `type` is uint16
  big-endian.
- `expiry` and `expiration` are both
  `min(this RRSIG's expiration, expiry of the entry it was verified against)`.
- `weakestKeyBits` describes the path this proof took. P-256 counts as 3072.
- The attestation box layout is the public API. A reference reader ships with
  the project; consumers must walk RRs from the header, never substring-match.

### Methods

| Method        | Verifies                                                  | Signer must be        |
|---------------|-----------------------------------------------------------|-----------------------|
| `addAnchors`  | nothing: admin-supplied, once (see "Lifecycle")           | sender is `admin`     |
| `proveRoot`   | root DNSKEY RRset under a Valid or Missing anchor         | owner, and owner = root |
| `revokeRoot`  | root DNSKEY RRset under the anchor it revokes (flags 385) | owner, and owner = root |
| `updateAnchor` | nothing: applies the RFC 5011 event the cached root RRset implies for one key | |
| `proveDs`     | DS RRset under a key in the parent's cached DNSKEY RRset  | a proper ancestor of owner |
| `proveDnskey` | DNSKEY RRset under one of its own keys matching the cached DS | equal to owner    |
| `proveTxt`    | TXT RRset under a key in a cached DNSKEY RRset            | owner or an ancestor  |
| `prune`       | see "Box rent"                                            |                       |
| `setAdmin`    | sender is `admin`                                         |                       |
| `logAttestations(names)` | `@readonly`: logs each attestation box, empty line if missing; stale ones too (walk the chain) |  |
| inherited     | `increaseBudget`, `depositCredits`, `withdrawCredits`, `logCredits` |             |

- Proving methods and `prune` are permissionless, but a sender that creates
  boxes needs credits.
- `proveDs`, `proveDnskey` and `proveTxt` reject the root as owner (`ROT`):
  only `proveRoot` writes the root DNSKEY entry.
- Ancestry is tested label by label.
- Newest inception wins, for caches and attestations alike. Ties replace,
  except that a cache entry at the same inception is replaced only if its
  expiry and `weakestKeyBits` get no worse (`WRS`): a second signature cannot
  shorten or weaken it, and a re-proof after its parent is refreshed still
  extends it.
- A TXT proof replaces the whole RDATA set, so a removed record disappears as
  soon as anyone submits the newer RRset.
- `setAdmin` to the zero address renounces the role permanently. Doing it
  before `addAnchors` bricks the contract.

### Key and signature checks

Applied to the **indexed** key or DS only. Other records in the RRset are
skipped, so a revoked key, an unknown algorithm or a SHA-1 DS sitting
alongside does not block a proof.

| Item    | Checks                                                                   |
|---------|--------------------------------------------------------------------------|
| DNSKEY  | Zone flag set, REVOKE clear, protocol 3, algorithm = RRSIG algorithm, 8 or 13 |
| DS      | digest type 2, 36 bytes; key tag, algorithm and digest match the DNSKEY  |
| RSA     | exponent exactly 65537; modulus first byte non-zero; **1024 to 2048 bits** by real length; signature length = modulus length; Montgomery hint required |
| ECDSA   | key and signature exactly 64 bytes; if `s > n/2` then `s = n − s`, left-padded to 32 bytes |
| RRSIG   | type covered = RRset type; class IN; one owner for all RRs; labels field = owner's label count; no `*` label; `inception ≤ now ≤ expiration` |
| TXT     | per RR, character-string lengths sum to `rdlen`                          |

Not checked, because the signature already binds the bytes: RR ordering and
duplicates.

The 2048-bit cap bounds the worst-case cost to one RSA-2048 check (92k
opcodes), which fits one group's op-up pool with room to spare. RSA-3072 would
need 189k, right at the 190k pool limit.

Deployment assumptions, not DNSSEC rules: exponent 65537, DS digest type 2,
RSA 1024 to 2048 bits. A zone moving off any of them silently stops proving,
so the capture cron also alerts on changes to these values.

### Root anchors: rollover (RFC 5011)

Second pass. The first-pass contract cannot be updated, so this ships as a new
deployment. Each anchor box holds an RFC 5011 state and `since`, the block
time it was entered. No box means Start (or Removed).

`updateAnchor(rrset, keyHash)` takes the root DNSKEY RRset as cached (hash
match, unexpired, like `parent`) and one key's `sha256(alg ‖ pubkey)`. The key
is *present* if the RRset holds it without REVOKE. One event applies:

| State   | Present | Event   | Becomes                                     |
|---------|---------|---------|---------------------------------------------|
| none    | yes     | Add     | AddPend; flags 257 and a key `checkKey` takes |
| AddPend | yes     | Promote | Valid, 30 days after Add (`HLD` before)     |
| AddPend | no      | Reset   | box deleted                                 |
| Valid   | no      | Miss    | Missing, still trusted                      |
| Missing | yes     | Return  | Valid                                       |
| Revoked | either  | Retire  | box deleted, 30 days after Revoke           |

Anything else fails with `ROL`. `revokeRoot` is the seventh event: the root
DNSKEY RRset signed by an anchor (any state but Revoked) that the RRset holds
with flags 385. Only the key can revoke itself, and for good.

- `proveRoot` accepts Valid and Missing anchors only.
- No hold-down timer checks DNS continuously: it counts on-chain time from the
  Add call, and a key's absence counts only once someone sends Reset or Miss.
  Watchers (trust point 11) run `maintainAnchors` daily.
- Anti-replay: `updateAnchor` requires the cached RRset's inception to be at
  least `rollInception`, then raises it. An older RRset still in its validity
  window, proven again after the newer cache entry expired and was pruned,
  cannot undo a step.
- Revocation needs no inception rule: replaying it changes nothing.
- The hold-down is 30 days, RFC 5011's minimum; the root DNSKEY TTL is 2 days.
- Anchor boxes created by Add are paid from the sender's credits; Reset and
  Retire refund the sender, as a cache prune does.
- Revoking a Valid or Missing anchor gives `rootEpoch` a fresh epoch, which
  stales the root DNSKEY entry and everything below it (see "Epochs"). An
  AddPend key never proved anything, so its revocation stales nothing; else a
  thief could Add keys under a stolen anchor and, once revoked, revoke them one
  by one to re-stale the contract each time. A stale root entry cannot drive
  `updateAnchor` (`STL`). Without this, a compromised key's forged root RRset,
  and every DS, DNSKEY and TXT proven below it, would outlive the revocation by
  their attacker-chosen validity, and could still promote the attacker's key.
  A real rollover's revocation costs one early re-proof of the cache, which
  the root's ~21-day signatures force anyway, and of every attestation, each
  by whoever wants it usable.

### Epochs: a change above stales everything below

DNSSEC withdraws a key by publishing a key set without it: a TLD dropping a
compromised ZSK, a domain changing hands (new DS), a root revocation. Any of
these must stale what the old keys signed, at every level.

- `lastEpoch` is a counter; a fresh epoch is `++lastEpoch`, so each value
  names exactly one box generation. It starts at 1, as does `rootEpoch`, and
  0 is never an epoch.
- A cache entry holds `epoch`, its own generation, and `parentEpoch`, the
  epoch of the entry it was verified against (`rootEpoch` for the root DNSKEY
  RRset). An attestation holds `parentEpoch`: its signer's DNSKEY entry.
- An entry keeps its epoch only when its hash and its parent epoch are both
  unchanged: a re-signed, identical RRset stales nothing. A new RRset, a new
  parent generation, or a box re-created after a prune gets a fresh epoch.
- Epochs only grow, and `rootEpoch` is minted at the revocation, so a box
  whose epoch is below `rootEpoch` (for an attestation, whose `parentEpoch`
  is) predates the last revocation. Such a box fails as a parent (`STL`,
  which also keeps a forged root from driving `updateAnchor`), anyone may
  prune it, and any proof replaces it whatever its inception (a forged one
  may be newer than any real RRSIG).
- Otherwise "newest inception wins" holds, across parent generations too: a
  routine change above must not let a withdrawn but still-signed RRset or TXT
  roll back in. Across generations a tie re-links without the `WRS` rule.
- The contract checks one level only, plus the revocation test above: a
  parent must exist, be unexpired, not predate the revocation and match the
  hash. Every write reads its parent box's current generation, so a stale
  chain exists only below a box that really changed. Consumers walk the whole
  chain (below). Staleness from a routine change is not prunable early; a
  newer proof replaces the box.
- Residual, below the root: after a TLD key compromise and re-key, forged
  entries off the real path still serve as parents until they expire. What is
  proven under them fails the walk, and the inception rule keeps them from
  displacing newer real proofs; a forged one with a recent inception can hold
  a box until the zone's next signature is newer.
- Cost: any change to an RRset above stales everything below it, a
  pre-published key included. The root's DNSKEY RRset changes a few times a
  quarter (ZSK rolls), so every attestation needs re-proving about that often,
  within what `maxAge` asks anyway. `ponytail:` stale on key removal only if
  that churn bites; it needs the old RRset passed in for a subset check.

Captured on 2026-09-28: the RRset signed by KSK-2017 and holding KSK-2024
drives Add in the emulator. Post-roll captures (2026-10-11 on) and the
revocation (about 2027-01-11) are to be replayed once the cron has them.

### Box rent

All box MBR runs through `MbrManager` credits. Refunds are credit entries, not
payments, so a closed account can never block a write.

| Box          | Who pays                   | Who can prune, and when                          | Refund credited to |
|--------------|----------------------------|--------------------------------------------------|--------------------|
| Anchor       | admin (initial), Add sender | Reset and Retire, by anyone (see "Root anchors") | the caller         |
| Cache        | first prover               | anyone, once expired or predating a revocation   | the pruner         |
| Attestation  | each prover                | `payer` once expired; anyone 30 days after, or once it predates a revocation | `payer` |

- Cache boxes are fixed size, so replacing one moves no credit.
- Replacing an attestation deletes the old box and credits the old `payer`
  with `settleMbrCredits(payer, before)`, then creates the new one and charges
  the sender with `manageMbrCredits`.
- If `payer` has no credit box any more (they withdrew), the refund stays
  with the app instead of failing, since `settleMbrCredits` would assert.
  `ponytail:` stranded dust, add a sweep if it ever adds up.
- A pruner must hold a credit box to receive the refund.
- The 30-day grace keeps an expired attestation readable. It is not a
  freshness guarantee: once pruned, an older RRset still inside its window
  can be proven again. Consumers bound that with a maximum age on
  `inception` (below).

### Reading attestations

- On-chain: the contract enables `ForeignBoxReads` on itself at creation with
  `app_params_set` (AVM v13). Consumers read the `t` box directly with the
  reference reader, from an oracle app ID they pin (the example consumer
  stores it at create). Fallback, only if PuyaTs 1.3.1 does not expose
  `app_params_set`: consumers call `logAttestations` as an inner call.
- The reader's `attestationUsable` walks the chain: the attestation's
  `parentEpoch` must equal the signer's DNSKEY entry's `epoch`, its
  `parentEpoch` the zone's DS entry's `epoch`, and so on up to the root DNSKEY
  entry, whose `parentEpoch` must equal `rootEpoch`. The caller passes the
  zones from the signer up to the TLD. That is safe, because each epoch
  names one box generation: a wrong or shortened list fails. The transaction
  needs box references for the attestation, each zone's DNSKEY and DS, and
  the root DNSKEY: 6 for `_tag.example.com`, which fits beside the oracle app
  in one transaction's 8. Longer chains spread them over the group. The SDK
  mirrors the walk off-chain (`chainLive`), and `attestationZones` finds the
  zones from the name by matching epochs; the CLI's `get` reports it.
- Off-chain, SDK: point lookups simulate `logAttestations` (batched,
  `@chunked`); listing every attestation or cache uses the algod
  `scanBoxes` prefix scan. An e2e test asserts both return the same bytes.

### Cost

Library figures, with hint, taken at face value:

| Check       | Opcodes | In-contract fee, approx. |
|-------------|---------|--------------------------|
| RSA-2048    | 92k     | 0.13 Algo                |
| RSA-1280    | 53k     | 0.08 Algo                |
| RSA-1024    | 29k     | 0.04 Algo                |
| ECDSA P-256 | 2.5k    | 0.004 Algo               |

One app call gets 700 opcodes. The rest comes from `increaseBudget` inner
calls, pooled across the group: at most 16 top-level plus 256 inner calls,
190,400 opcodes. The SDK's executor simulates the group, and if it is short
rebuilds it with `increaseBudget(n)` first (about 135 for RSA-2048), paid
through `extraFee`. `increaseBudgetBaseCost` / `increaseBudgetIncrementCost`
are measured on LocalNet and pinned in the SDK constants.

- Refreshing root + one RSA TLD: three RSA-2048 checks, about 0.4 Algo, once
  per signing period (roughly two weeks).
- A `.com` domain on Cloudflare or Route 53: three ECDSA checks, about 0.01 Algo.

Fees are usage-based in v42: the SDK simulates every group to price it.

`ponytail:` RSA runs inside the contract. A LogicSig host could be much
cheaper (the 1/20th figure is unverified under v42 usage fees; Phase 0
measures it) but adds a second program and binding checks between the two.
Move only if proof volume makes fees matter; it means a redeploy.

### SDK (D13)

- `DnssecOracleReaderSDK`: no signer, simulate-only. Anchors, caches,
  attestations (decoded by the reference layout), credits.
- `DnssecOracleSDK extends` the reader: a pure, `builder`-aware maker per
  method, turned into an executor with automatic op-up probing. Proof flows
  that need reads first (which parents are stale, is the credit enough) are
  `@wrapErrors` methods that call the executors, parents before children.
- `prover/`: plain TypeScript, untrusted. Queries DNS with the DO bit, builds
  canonical signed data and Montgomery hints (`rsaMontgomeryHint`), feeds
  the makers.

## Trust points

Ordered from unavoidable to self-inflicted.

| # | Who or what | What they can do |
|---|-------------|------------------|
| 1 | **DNS root** (ICANN/IANA, root zone maintainer) | Forge any name. Inherent to DNSSEC. |
| 2 | **TLD registry** | Publish a DS for any name under it, or sign records below a zone cut directly. Full takeover of that name. |
| 3 | **Intermediate zones, registrar, registrant account** | Anyone who can change a DS on the path controls everything below it. |
| 4 | **DNS operator of the domain** | Holds the zone keys; can sign any TXT. Cloudflare uses **one key pair for all customer zones**. |
| 5 | **Weakest key in the chain** | `io`, `finance` and `co` sign with 1024-bit RSA. Factoring that key forges any name under the TLD. `weakestKeyBits` lets a consumer refuse such proofs. Where one name is provable along paths of different strength (`co`'s 1280 and 1024-bit ZSKs, or any size change mid-roll), a forger can also overwrite the stronger attestation with a weaker one: denial of service to consumers that refuse weak proofs. |
| 6 | **Admin, at deploy** | Uploads the initial anchors. A false anchor forges everything. Checkable once: consumers pin the app ID and compare the anchor boxes to IANA's trust anchor file. Afterwards only RFC 5011 changes them, and any Valid anchor can bring in a new key after 30 days. |
| 7 | **Admin, after deploy** | Nothing: `addAnchors` runs once and there is no TLD whitelist. A registry can only forge names under its own TLD, so which TLDs to trust is each consumer's choice, made by the names it accepts. |
| 8 | **Algorand consensus and AVM** | The only clock is the block timestamp, bounded to +25 s per block but not to wall-clock time. Proposers stalling it extend the life of expired signatures. |
| 9 | **Verification code** | The RSA and MBR libraries, the wire parser, the Puya compiler, the rule list. A bug equals a forged root key, and the contract cannot be patched. Largest avoidable risk. |
| 10 | **Consumer code** | Must pin the oracle app ID, parse the attestation box by its layout, and walk its chain (`attestationUsable`). Reading from an app the caller names, or a substring match, is a forgery at the consumer; skipping the walk accepts proofs from withdrawn keys. |
| 11 | **Watchers, for liveness and rollover** | Someone must submit the root RRset at least every 21 days or every proof below stalls. The same cron (`maintainAnchors`) sends revocations and Reset within 30 days, or a key added under a compromised anchor gets promoted. Cheap, permissionless. |
| — | **Relayer** | **Not trusted for integrity.** Freshness depends on everyone who can submit, below. |

### What an attestation does not mean

- **That the record exists now.** It was signed and is inside its validity
  window: about 3 hours on Route 53, 2 days on Cloudflare, up to weeks
  elsewhere. Anyone can submit any still-valid RRset when nothing newer is
  stored. Consumers must set a maximum age on **`inception`**.
- **That a name has no records.** No NSEC/NSEC3. A TXT set deleted entirely
  can only age out.
- **Current ownership.** After a transfer or lapse, the previous owner's keys
  stay usable until the new owner's DS is proven: that stales everything
  signed by the old keys (see "Epochs"). Until then, up to the old DS
  signature's expiry (about 7 days for `.com`), the old owner can pick
  inception = now to outrank the new owner.
- **Resolver semantics.** No CNAME following, no wildcards.

Advice for consumers: put the app ID, the Algorand address and a nonce inside
the TXT value, so a record proven for one purpose cannot be reused for another.

### End of life

The contract fails closed and must be redeployed when: the root moves to an
algorithm the AVM lacks or to RSA above 2048 bits (Add rejects such a key, so
it never becomes an anchor), every anchor is revoked or retired without a
successor promoted, nobody submits the root for longer than its signatures
last, or in 2106 when DNSSEC's 32-bit timestamps wrap. The first pass also
failed at a root KSK roll (with KSK-2017, 2026-10-11).

## Open in `puya-ts-utils`

- Publish 0.3.0 to npm. Until then the workspace links it locally.

Program size: the RSA code adds about 1.45 KB (`verifyRsaSha256`). An app
gets 2 KB per page with up to 3 extra pages, 8 KB in all. Plan on extra
pages; Phase 0 measures the full contract.

## Project layout

pnpm workspace, D13 monorepo:

```
projects/dnssec-oracle/                    contract, unit + e2e tests
  smart_contracts/base/base.algo.ts        BaseContract (increaseBudget) + EmptyContract
  smart_contracts/dnssec_oracle/contract.algo.ts   state, methods
  smart_contracts/dnssec_oracle/errors.algo.ts     error codes
  smart_contracts/dnssec_oracle/wire.algo.ts       signed-data parser, name rules
  smart_contracts/dnssec_oracle/reader.algo.ts     reference attestation reader
  tests/fixtures/                          captured chains
  tests/helpers.ts                         sendMutated
projects/dnssec-oracle-sdk/                e2e tests import it via "link:../dnssec-oracle-sdk"
  scripts/generate-errors.ts               own layers + puya-ts-utils MbrManager codes
  src/generated/                           DnssecOracleClient.ts, errors.ts
  src/sdkReader.ts, src/sdk.ts
  src/prover/                              off-chain proof builder
  src/util/                                txnExecutor, increaseBudget, wrapErrors, chunked
  src/constants.ts                         AVM limits + measured op costs
scripts/capture-root.sh                    the daily capture
```

Build chain: contract `build` → SDK `prebuild` copies the client and
regenerates errors → SDK build → contract e2e tests.

## Build order

| Phase | Work | Proves |
|-------|------|--------|
| 0 | Start daily capture. Scaffold the D13 monorepo, link `puya-ts-utils`. Spike on LocalNet: `app_params_set` at creation, a foreign box read, RSA-2048 opcode cost and program size in app mode with the SDK's op-up probe, `increaseBudget` base and increment cost, simulated fee of one RSA and one ECDSA `proveTxt`. Confirm the emulator can pin `latestTimestamp`. `generate-errors` picks up the library codes. | The assumptions the design rests on |
| 1 | Signed-data parser and name rules, as pure functions | Boundary shift, trailing bytes, `ample` vs `example`, `co` vs `co.com`, pointer and extended labels, RRsets holding revoked or unknown keys |
| 2 | Crypto wrappers, two-step creation with `addAnchors`, `proveRoot` | High-S, `s` with a leading zero, zero-padded modulus, wrong exponent, wrong lengths, RSA-1023 and RSA-2049 rejected; `addAnchors` by non-admin, twice, with duplicates, with flags 256 or 385; proofs before any anchor |
| 3 | `proveDs`, `proveDnskey`, `proveTxt` | Full chain under each TLD; one negative per rule; `parent` hash mismatch or wrong zone; expiry capping; inception order and ties; self-signed DS rejected |
| 4 | Credits and `prune` | Proof without credits (`CRD`); replace refunds the old payer's credits; payer who withdrew; pruner without a credit box; grace period |
| 5 | Admin | Non-admin rejected; hand-over; renounce |
| 6 | SDK prover and reads, then a TestNet soak across a real root ZSK roll | End to end before MainNet; simulate and algod reads agree |

Second pass: root rollover (`updateAnchor`, `revokeRoot`, SDK `maintainAnchors`,
CLI `maintain-anchors`). Proves: every event and its hold-down in the emulator
with a pinned clock; AddPend and Revoked not trusted; revocation self-signed
only, RSA-2048 included; replay of an older RRset (`OLD`); Add only for usable
KSKs in the cached RRset; Add from the captured 2026-09-28 root. On LocalNet
through the SDK: Add, Reset, revocation, credits. Still to do: replay the
post-roll and revocation captures when the cron has them.

## Verification

- LocalNet cannot move block time backwards (dev-mode offset only moves it
  forward), and captured signatures expire. So: past captures run in the
  `algorand-typescript-testing` emulator with `latestTimestamp` pinned inside
  the fixture's window. LocalNet runs chains captured the same day and
  synthetic roots signed at test time.
- E2E tests go through the SDK. Negative cases start from the real maker and
  mutate its group with `sendMutated`, asserting on the transformed error
  (`Error ANC: ...`).
- Each phase's "Proves" column is its test list.
- A second contract reads an attestation box directly using the reference reader.
- SDK constants that mirror on-chain behaviour (op-up costs, limits) are
  pinned by LocalNet tests. Every method is simulated; opcode cost and fee
  recorded.
