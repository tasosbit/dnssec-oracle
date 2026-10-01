# Architecture

How the DNSSEC oracle is built, what each part checks, where it departs from the DNSSEC
RFCs, and what it cannot do. The trust model and the design decisions behind it are in
[plan.md](./plan.md). Usage is covered in the [README](../README.md).

## Overview

```
            DNS (any resolver, untrusted)
                      │  RRsets + RRSIGs, DO bit, over TCP
                      ▼
  ┌──────────────── prover (SDK, off-chain, untrusted) ─────────────────┐
  │ canonical signed data · key/DS selection · Montgomery hints · op-up │
  └─────────────────────────────────┬───────────────────────────────────┘
                                    │ one app call group per signature
                                    ▼
  ┌──────────────── DnssecOracle (AVM 13, immutable) ───────────────────┐
  │ parse signed data · check keys · verify signature · link to parent  │
  │                                                                     │
  │  a‖… anchors (RFC 5011)   r‖… cache: hash of root/DS/DNSKEY RRsets  │
  │  t‖… attestations: TXT RDATA + header      c‖… box-rent credits     │
  └─────────────────────────────────┬───────────────────────────────────┘
                                    │ ForeignBoxReads / simulate
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
         consumer contracts                  off-chain readers
         (reader.algo.ts)                    (SDK, CLI)
```

Everything off-chain is untrusted. The prover only chooses which bytes to send, and the
contract re-derives every name, key and link from those bytes.

## Components

| Path | Role |
|------|------|
| `projects/dnssec-oracle/smart_contracts/dnssec_oracle/contract.algo.ts` | The oracle: state, proving methods, RFC 5011, rent |
| `.../dnssec_oracle/wire.algo.ts` | Signed-data parser, name rules, key tag |
| `.../dnssec_oracle/reader.algo.ts` | Reference reader for consumers: attestation layout and chain walk |
| `.../dnssec_oracle/errors.algo.ts` | Three-letter error codes, logged by `loggedAssert` |
| `.../base/base.algo.ts` | `BaseContract.increaseBudget`: op-up through no-op inner app calls |
| `.../consumer/contract.algo.ts` | Example consumer that reads attestation boxes directly |
| `projects/dnssec-oracle-sdk/src/prover/` | DNS client, canonical form, chain builder, root anchors |
| `projects/dnssec-oracle-sdk/src/sdkReader.ts`, `sdk.ts` | Reader (simulate-only) and writer SDK, proof orchestration, `maintainAnchors` |
| `projects/cli/` | Operator CLI over the SDK |

The contract is layered as `Contract → MbrManager → BaseContract → DnssecOracle`.
`MbrManager` (from `@d13co/puya-ts-utils`) settles box rent against prepaid credits.
`BaseContract` adds `increaseBudget`. RSA verification is `verifyRsaSha256` from the same
library.

## A proof

For `_tag.example.com TXT`, a full chain is six signatures and two digest checks. Each row
is one app call group:

| # | Method        | RRset                  | Signed by        | Linked to the row above by          |
|---|---------------|------------------------|------------------|-------------------------------------|
| 1 | `proveRoot`   | `. DNSKEY`             | root KSK         | the signing key is a trusted anchor |
| 2 | `proveDs`     | `com. DS`              | root ZSK         | the key is in row 1's RRset         |
| 3 | `proveDnskey` | `com. DNSKEY`          | com KSK          | row 2 holds a DS digest of the key  |
| 4 | `proveDs`     | `example.com. DS`      | com ZSK          | the key is in row 3's RRset         |
| 5 | `proveDnskey` | `example.com. DNSKEY`  | example.com KSK  | row 4 holds a DS digest of the key  |
| 6 | `proveTxt`    | `_tag.example.com TXT` | example.com ZSK  | the key is in row 5's RRset         |

Rows 1–5 are cached and shared. A second name under `example.com` needs only row 6 while
the cache is fresh. `proveChain` in the SDK reads the cache and skips fresh steps.

### Input format

Every proving method takes `signedData`: exactly the bytes the zone signed, that is the
RRSIG RDATA without the signature, followed by the canonical RRset. Alongside it come the
signature, a Montgomery hint for RSA, a key index and, for child steps, `parent`.

- `signedData` is parsed from offset 0 and the cursor must land exactly on its end.
- The owner name, type, signer name, validity window and algorithm come only from these
  bytes. Box keys are derived from the parsed names, never from arguments.
- RRs are reached by index, walking from the first one. The prover supplies no offsets.
- `parent` is the RRset bytes of an earlier step: the signer's DNSKEY RRset for `proveDs`
  and `proveTxt`, or the owner's DS RRset for `proveDnskey`. Its cache box is located from
  names in `signedData`, and `sha256(parent)` must equal the stored hash. The cache holds
  hashes only, so this is how a child step reaches its parent's keys or digests.

The result is that a record cannot shift its boundaries. A tenant of a shared zone cannot
embed a fake RR for a sibling name inside its own TXT value, because every RR is re-walked
from the start and must share the first RR's owner.

## State

| Where  | Key                          | Value |
|--------|------------------------------|-------|
| Global | `admin`                      | address; only used by `addAnchors` and `setAdmin` |
| Global | `anchorCount`                | 0 until `addAnchors`, which runs once |
| Global | `rollInception`              | inception of the newest root RRset an RFC 5011 step used |
| Global | `lastEpoch`                  | the last epoch handed out |
| Global | `rootEpoch`                  | epoch of the anchor set; fresh at each revocation of a trusted key |
| Box    | `a ‖ sha256(alg ‖ pubkey)`   | anchor: `state`, `since` |
| Box    | `r ‖ sha256(name ‖ type)`    | cache: `hash`, `inception`, `expiry`, `weakestKeyBits`, `epoch`, `parentEpoch` (72 bytes) |
| Box    | `t ‖ sha256(name)`           | attestation: 64-byte header, then `uint16 rdlen ‖ rdata` per TXT RR |
| Box    | `c ‖ address`                | `MbrManager` credits |

Names are in wire format, lowercase, with the terminating zero byte. The attestation
layout is the public API and is documented byte by byte in `reader.algo.ts`.

- `expiry` (cache) and `expiration` (attestation) are both `min(this RRSIG's
  expiration, the parent entry's expiry)`. An entry never outlives the chain above it.
- `weakestKeyBits` is the minimum over the path. P-256 counts as 3072.
- Anchors are keyed by algorithm and public key only, so setting the REVOKE flag (which
  changes the key tag and the DS digest) still finds the same box.

## Methods

| Method          | Verifies                                                    | Signer must be |
|-----------------|-------------------------------------------------------------|----------------|
| `addAnchors`    | nothing; admin-supplied DNSKEYs with flags exactly 257, once | sender is `admin` |
| `proveRoot`     | root DNSKEY RRset under one of its own keys that is a Valid or Missing anchor | owner, and owner is the root |
| `proveDs`       | DS RRset under a key in an ancestor's cached DNSKEY RRset   | a proper ancestor of the owner |
| `proveDnskey`   | DNSKEY RRset under one of its own keys that matches a cached DS | the owner |
| `proveTxt`      | TXT RRset under a key in a cached DNSKEY RRset              | the owner or an ancestor |
| `updateAnchor`  | applies the one RFC 5011 event the cached root RRset implies for a key | – |
| `revokeRoot`    | root DNSKEY RRset under the anchor it revokes (flags 385)   | owner, and owner is the root |
| `prune`         | deletes an expired or pre-revocation box (see [Box rent](#box-rent)) | – |
| `setAdmin`      | sender is `admin`; the zero address renounces               | – |
| `logAttestations`, `logCaches` | read-only: log raw boxes for simulate reads  | – |
| inherited       | `increaseBudget`, `depositCredits`, `withdrawCredits`, `logCredits` | – |

Every proving method performs exactly one signature verification, and all of them are
permissionless. A sender that creates boxes needs credits.

Replacement rules:

- **Newest inception wins**, for caches and attestations alike (`OLD`).
- **Ties:** a cache entry at the same inception is replaced only if its expiry and
  `weakestKeyBits` get no worse (`WRS`).
- **TXT:** a proof replaces the whole RDATA set, so a removed record disappears as soon
  as anyone submits the newer RRset.
- **Revocations:** a box from before the last trusted-key revocation is replaced whatever
  its inception, because a forged one may carry any inception.

### Key and signature checks

These apply to the **indexed** key or DS only. Other records in the RRset are skipped, so
a revoked key, an unknown algorithm or a SHA-1 DS published alongside does not block a
proof.

| Item   | Checks |
|--------|--------|
| DNSKEY | zone flag set, REVOKE clear, protocol 3, algorithm 8 or 13 and equal to the RRSIG's |
| DS     | digest type 2 with 32 bytes; key tag, algorithm and `sha256(owner ‖ DNSKEY RDATA)` match the key |
| RSA    | exponent exactly 65537 (`03 010001`); modulus first byte non-zero; **1024 to 2048 bits** by real length; signature length equals modulus length; hint required |
| ECDSA  | key and signature 64 bytes each; high-S normalized to `n − s`, because the AVM rejects high-S |
| RRSIG  | type covered equals the method's type; class IN; one owner for every RR; labels field equals the owner's label count; no `*` label; `inception ≤ now ≤ expiration` |
| TXT    | per RR, the character-string lengths sum to `rdlen` |
| Names  | every label length byte below `0x40` (no compression pointers or extended labels); name at most 255 bytes |

## Epochs: a change above stales everything below

DNSSEC withdraws a key by publishing a key set without it. That happens when a TLD drops a
ZSK, a domain changes hands (new DS), or the root revokes a KSK. Anything signed by the
old keys has to become unusable, at every level below.

- `lastEpoch` is a counter, and each value names exactly one box generation.
- A cache entry stores its own `epoch` and its `parentEpoch`, which is the epoch of the
  entry it was verified against (`rootEpoch` for the root DNSKEY entry). An attestation
  stores the epoch of its signer's DNSKEY entry.
- An entry keeps its epoch only if both its hash and its parent epoch are unchanged. A
  re-signed, identical RRset stales nothing.
- The contract checks one level per write: the parent must exist, be unexpired, match
  the hash and not predate the last revocation (`STL`). Consumers walk the whole chain
  with `attestationChainLive`, comparing each link's epoch up to `rootEpoch`. They pass
  the zone list, which is safe because only the real ancestors' epochs match.
- Revoking a Valid or Missing root anchor mints a new `rootEpoch`. That stales the root
  entry and everything below it, so nothing a compromised key may have forged survives
  the revocation. Such boxes become prunable at once.

## Root anchors: RFC 5011

| State   | Key present in the cached root RRset | Event   | Becomes |
|---------|--------------------------------------|---------|---------|
| none    | yes                                  | Add     | AddPend (flags 257, key passes `checkKey`) |
| AddPend | yes                                  | Promote | Valid, 30 days after Add (`HLD` before) |
| AddPend | no                                   | Reset   | box deleted |
| Valid   | no                                   | Miss    | Missing, still trusted |
| Missing | yes                                  | Return  | Valid |
| Revoked | either                               | Retire  | box deleted, 30 days after Revoke |
| any but Revoked | with flags 385, self-signed  | Revoke (`revokeRoot`) | Revoked |

- `proveRoot` accepts Valid and Missing anchors only.
- `updateAnchor` needs the cached root RRset's inception to be at least `rollInception`,
  then raises it. An older RRset that is still valid, re-proven after a prune, cannot
  undo a step.
- Revoking an AddPend key does not mint a new `rootEpoch`, because such a key never
  proved anything.
- Hold-downs count on-chain time from the call that entered the state. Watchers run
  `maintainAnchors` daily (see [RFC compliance](#rfc-compliance-and-divergence)).
- To check the anchors against IANA's trust anchor file, or any zone's keys and DS against
  what the oracle has cached, see the README's
  [Verifying anchors and zone keys](../README.md#verifying-anchors-and-zone-keys).

## Box rent

All box MBR runs through `MbrManager` credits. Refunds are credit entries, never payments,
so a closed account cannot block a write.

| Box         | Paid by                     | Prunable                                                     | Refund to |
|-------------|-----------------------------|--------------------------------------------------------------|-----------|
| Anchor      | admin (initial), Add sender | Reset and Retire, by anyone                                  | the caller |
| Cache       | first prover                | by anyone, once expired or predating a revocation            | the pruner |
| Attestation | each prover                 | by `payer` once expired; by anyone 30 days later, or once it predates a revocation | `payer` |

If a payer withdrew their credit box, their refund stays with the app.

## Reading attestations

- **On-chain.** The contract enables `ForeignBoxReads` on itself at creation
  (`app_params_set`, AVM 13), so any app can read `t` boxes directly. Consumers must pin
  the oracle's app ID, parse the box by its layout (never substring-match), and call
  `attestationUsable(oracle, value, maxAge, minKeyBits, zones)`. For `_tag.example.com`
  the transaction needs 6 box references: the attestation, each zone's DNSKEY and DS, and
  the root DNSKEY.
- **Off-chain.** The SDK reads point lookups by simulating `logAttestations`/`logCaches`,
  and lists boxes with algod's prefix scan. `chainLive` and `attestationZones` mirror the
  on-chain walk.

## Cost

One app call gets 700 opcodes. `increaseBudget(n)` buys 700 more per no-op inner call,
and the pool is shared across the group: 16 top-level and 256 inner calls give at most
**190,400 opcodes per group**. The SDK simulates each group and, if the budget falls
short, rebuilds it with `increaseBudget` first. `increaseBudget` costs 21 opcodes plus 21
per inner call.

Library figures for one verification, with hint:

| Check       | Opcodes | Fee, approx. |
|-------------|---------|--------------|
| RSA-2048    | 92k     | 0.13 Algo    |
| RSA-1280    | 53k     | 0.08 Algo    |
| RSA-1024    | 29k     | 0.04 Algo    |
| ECDSA P-256 | 2.5k    | 0.004 Algo   |

On LocalNet (consensus v42), group usage stayed at the 1,000,000 baseline, so each fee is
the transaction count at the minimum fee. Refreshing the root and one RSA TLD takes three
RSA-2048 checks, about 0.4 Algo, once per signing period. A `.com` domain on an ECDSA DNS
provider costs about 0.01 Algo for its three remaining steps. The approval program was
6,017 bytes at e4e451b: two extra pages, 127 bytes short of needing a third (AVM 13 allows
16 KB). Other Phase 0 measurements are in the [README](../README.md#phase-0-results).

## Limitations

### RSA keys above 2048 bits

`checkKey` rejects RSA moduli above 2048 bits (`MOD`). The cap bounds the most expensive
step to one RSA-2048 check, about 92k opcodes, which fits one group's 190,400-opcode
op-up pool with room to spare. Cost grows roughly with the square of the modulus size:
RSA-3072 needs about 189k, right at the pool limit, and RSA-4096 would be roughly four
times RSA-2048 (extrapolated, not measured). Neither fits reliably in one group.

**Not implemented: verification spanning several groups.** RSA with exponent 65537 is 16
modular squarings and one multiplication, so the work splits cleanly. One group would run
part of the exponentiation and store the intermediate value in a box keyed by the sender
and `sha256(signedData ‖ signature)`. Later groups would continue from it, and the last
would compare the result with the PKCS#1 v1.5 encoding of the digest and mark it verified,
for the proving method to consume. This is feasible, and nothing else in the design
depends on the cap. It was left out for simplicity, because it would need:

- a step-wise RSA API in `puya-ts-utils`, whose `verifyRsaSha256` runs in one go today;
- extra methods, a scratch box with its own rent and cleanup, and rules for abandoned or
  replayed partial verifications;
- more audited surface in a contract that cannot be patched.

Impact as of 2026-09-28: 19 of 1,351 signed TLDs publish an RSA key above 2048 bits (`ar`,
`bg`, `bj`, `firmdale`, `gdn`, `gy`, `ht`, `kw`, `lv`, `ly`, `mr`, `na`, `pl`, `rw`, `uy`,
`ve`, `zm` and two IDN TLDs). A TLD is only blocked if every key that links its DS to its
DNSKEY RRset is above the cap. If the root ever moves to a key above 2048 bits, `updateAnchor`
cannot Add it and the deployment winds down. The capture cron alerts when a target zone
moves off these assumptions.

### RRsets over 4,096 bytes

`sha256` hashes one byte value and cannot stream, and an AVM byte value holds at most
4,096 bytes. Three values are subject to this limit:

- **`signedData`:** the RRSIG header plus the canonical RRset, with the owner name
  repeated in every RR. The prover refuses anything larger before sending it.
- **`parent`:** a cached RRset handed back in, always smaller than its own signed data.
- **The attestation:** a 64-byte header plus `uint16 rdlen ‖ rdata` per TXT RR, written
  as one value (`BIG` if it would not fit).

On the 2026-09-28 snapshot of every signed TLD, nothing on the DS/DNSKEY path came close.
The largest TLD DNSKEY RRset was 1,962 bytes, and every key in every TLD could double
without one crossing the limit ([research](../research/sha256-limit/README.md)). The limit
bites at a zone apex, where TXT sets collect SPF and site-verification tokens:
one measured apex was already at 2,844 bytes (69%) and apex sets only grow. A TXT RRset is
all-or-nothing: the oracle can only prove the whole set, so one large set blocks every
record in it.

**If you control the zone, publish the oracle's records at a dedicated subdomain** such as
`_algorand.example.com`, never at the apex. The RRset then holds only your records, and a
short owner name leaves the most room: about 4,030 bytes of TXT RDATA at
`_algorand.example.com`, or some 44 records of one 58-character Algorand address each.
The subdomain needs no delegation: it is signed by the same zone keys, so the chain is no
longer.

If the name belongs to someone else and its TXT set is too large, it cannot be proven.
The fix is a dedicated name on their side.

### Other limits

| Limit | Cause | Consequence |
|-------|-------|-------------|
| RSA below 1024 bits rejected | deliberate floor | weak zones unprovable; `weakestKeyBits` lets consumers set a higher floor |
| Exponent 65537 only | deployment assumption; keeps the RSA code path single | a zone using another exponent is unprovable |
| Algorithms 8 and 13 only | AVM has P-256 natively; RSA comes from a library | 36 of 1,351 TLDs also use 7, 10, 14 or 15; names signed only with those are unprovable |
| DS digest type 2 only | deployment assumption | a delegation with only SHA-1 or SHA-384 DS is unprovable (2 TLDs on 2026-09-28) |
| 4,096 bytes of signed data, `parent` and attestation | `sha256` takes one value and cannot stream; an AVM byte value holds at most 4,096 bytes | see [RRsets over 4,096 bytes](#rrsets-over-4096-bytes) |
| TXT only, positive answers only | no NSEC/NSEC3 | cannot prove absence; a deleted record only ages out |
| No CNAME, DNAME or wildcards | labels field must equal the owner's label count, `*` rejected | names answered through these are unprovable |
| Freshness is the signature, not now | DNSSEC signatures are valid for hours to weeks | consumers must bound `inception` with `maxAge` |
| Liveness needs watchers | no on-chain timer can fetch DNS | the root entry must be re-proven before its signature expires, and RFC 5011 events sent within 30 days |
| Block-timestamp clock | the only clock on-chain | proposers stalling time extend expired signatures |
| Timestamps wrap in 2106 | 32-bit RRSIG times compared as plain integers | end of life |
| Immutable | no update method, by design | any change of rules is a redeployment and a new app ID for consumers |

## RFC compliance and divergence

The oracle is a validator for one narrow question: was this TXT RRset validly signed under
the root? It implements the validation path of the DNSSEC RFCs, but it is not a
resolver, so it diverges wherever a resolver's job (lookups, caching by TTL, denial of
existence) does not apply. It also diverges where the AVM forces a narrower choice.

### Followed

| Requirement | RFC | How |
|-------------|-----|-----|
| Signature over RRSIG RDATA (minus signature) ‖ canonical RRset | 4034 §3.1.8.1 | `signedData` is exactly that, hashed whole |
| Canonical names: uncompressed, lowercase | 4034 §6.2 | compression pointers rejected (`WIR`); case is enforced by the signature, since only the canonical form verifies |
| RRSIG and RRset share owner, class and type covered | 4035 §5.3.1 | `walkRRset` and `parseSignedData` (`OWN`, `CLS`, `TYP`) |
| Validity window | 4035 §5.3.1 | `inception ≤ now ≤ expiration` against block time (`TIM`) |
| RRSIG algorithm equals the DNSKEY's | 4035 §5.3.1 | `ALG` |
| Zone key flag set, protocol 3 | 4034 §2.1.1–2.1.2 | `KFL`, `PRO` |
| SEP flag is advisory | 4034 §2.1.1 | any zone key that matches a DS may sign the DNSKEY RRset (anchors are the exception: exactly 257) |
| DS links parent to child: key tag, algorithm, digest of owner ‖ RDATA | 4034 §5.1.4, App. B; 4509 | `checkDs` |
| A DNSKEY RRset is trusted when a key matching a trusted DS signs it | 4035 §5.2 | `proveDnskey` |
| Any one valid path suffices; unknown algorithms alongside are ignored | 4035 §5.3.1; 6840 §5.11 | only the indexed key or DS is checked |
| RSA/SHA-256 keys and PKCS#1 v1.5 signatures | 3110 §2; 5702 | `checkKey`, `verifyRsaSha256` |
| ECDSA P-256 key `x ‖ y`, signature `r ‖ s` | 6605 §4 | 64-byte checks; low-S normalization yields an equivalent signature |
| Label below 64 bytes, name at most 255 | 1035 §2.3.4 | `readName` |
| RFC 5011 states, 30-day add and remove hold-downs, Missing still trusted, revoked keys never validate, revocation self-signed | 5011 §2, §4 | `updateAnchor`, `revokeRoot`; root DNSKEY TTL is 2 days, so 30 days is the hold-down |
| Anchors keyed independently of the REVOKE bit | 5011 §2.1 (key tag changes when revoked) | keyed by `sha256(alg ‖ pubkey)` |
| Initial anchors from IANA's trust anchor file | 7958 | KSK-2017 (20326) and KSK-2024 (38696) in `prover/anchors.ts` |

### Diverges

| Topic | RFC | Oracle | Why / effect |
|-------|-----|--------|--------------|
| Algorithm support | 8624 §3.1 lists 5, 7, 8 and 13 as MUST-validate, 14 and 15 as RECOMMENDED | 8 and 13 only | SHA-1 algorithms are being retired; 14 and 15 are not implemented. Unsupported zones fail closed (unprovable) instead of being treated as insecure |
| DS digest types | 8624 §3.3: SHA-1 and SHA-256 MUST, SHA-384 RECOMMENDED | SHA-256 only | deployment assumption; a SHA-1 DS published alongside is ignored, not an error |
| RSA key size and exponent | 3110 and 5702 allow any exponent and 512–4096-bit moduli | 65537 only; 1024–2048 bits | opcode budget per group (see [above](#rsa-keys-above-2048-bits)) and a single code path |
| Wildcards | 4035 §5.3.1 allows labels < owner labels; 4035 §5.3.4, 4592 | labels must equal the owner's count; `*` labels rejected (`LBL`, `WLD`) | wildcard proofs need NSEC/NSEC3 to rule out a closer match, which the oracle does not do |
| Signer name | 4035 §5.3.1: the signer is the zone containing the RRset | `proveDs`: any proper ancestor; `proveTxt`: the owner or any ancestor whose DNSKEY is cached | the oracle has no zone cut knowledge (no NS/SOA). An ancestor zone could sign data below a delegation that a resolver would ignore. It could take the name over anyway by publishing a DS (plan.md trust point 2), so the trust boundary does not move |
| Authenticated denial | 4035 §5.4; 5155 (NSEC3) | none | cannot prove absence, insecure delegations or NODATA; unsigned zones are simply unprovable |
| CNAME, DNAME | 1034 §3.6.2; 6672 | not followed; the prover refuses CNAME answers | a name must hold its TXT RRset directly |
| Time arithmetic | 4034 §3.1.5: serial number arithmetic (1982) | plain unsigned comparison | identical until 2106, then the contract stops working |
| Clock | 4035 §5.3.1: the validator's current time | block timestamp | trust in consensus time (plan.md trust point 8) |
| TTLs and Original TTL | 4035 §5.3.3: RR TTLs reset to Original TTL; a cache honours TTLs | RR TTLs not checked; the signature binds whatever was signed. Cache life is the chain's earliest RRSIG expiration, not the TTL | an oracle records proofs, not lookups. Consumers' `maxAge` stands in for TTL-based freshness |
| RRSIG key tag field | 4035 §5.3.1 uses it to select the key | ignored; the key comes by index and must verify | a wrong tag cannot make a bad signature verify |
| Canonical RR order, duplicates | 4034 §6.3 | not checked | the signature binds the order that was signed |
| Class | any class | IN only (`CLS`) | – |
| RFC 5011 active refresh | 5011 §2.3: the resolver queries the trust point periodically, and a key must be seen throughout the hold-down | permissionless watchers submit the root RRset. Hold-downs count on-chain time from the Add call, and a key's absence counts only once someone submits it (Reset, Miss) | the chain cannot query DNS. A key that vanishes and returns between two watcher runs is not reset. Daily `maintainAnchors` keeps the gap small |
| RFC 5011 anchor set changes | 5011 §4 | additionally, revoking a trusted anchor mints a new `rootEpoch` and stales every cached box and attestation below it | goes beyond the RFC: anything a compromised key may have forged stops being usable at once |
| Initial anchor flags | 4034 §2.1.1 allows any zone key as an anchor | exactly 257 (zone + SEP), checked like a signing key | anchors must be able to prove the root |
