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
| Root anchors  | Box storage. Admin uploads the first anchor after creation, only while there is none. |
| Rollover      | **Not in the first pass.** Anchors are fixed once set; a root KSK roll means a redeploy. |
| Results       | Stored attestations in boxes, readable on- and off-chain.      |
| RSA size      | Modulus 1024 to 2048 bits.                                     |
| Box rent      | `MbrManager` prepaid credits.                                  |
| Whitelist     | `com`, `io`, `finance`, `co`. Admin can add and remove.        |
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

Also capture a full chain for one name under each whitelisted TLD.

The first-pass anchor is **KSK-2017 (20326)**, for live testing now. It
stops signing the root DNSKEY RRset on 2026-10-11, so `proveRoot` fails from
then on and the deployment winds down as its root cache expires. That
deployment is for testing only; a lasting one needs KSK-2024 or rollover.

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

Live key material for the whitelist (2026-09-28):

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
   `depositCredits`, `addAnchor(dnskeyRdata)`.

`addAnchor` requires sender = `admin` and `anchorCount = 0`. It applies the
DNSKEY and RSA/ECDSA checks below plus flags exactly 257, writes box
`a ‖ sha256(alg ‖ pubkey)` and sets `anchorCount = 1`. After that no method
can add, change or remove an anchor. Until it runs, every proof fails.

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
not worked around; rejected before hashing.

Wire rules: a label length byte must be below `0x40`, which rejects
compression pointers and extended label types.

### State

| Where  | Key                          | Value                                                     |
|--------|------------------------------|-----------------------------------------------------------|
| Global | `admin`                      | address                                                   |
| Global | `anchorCount`                | uint64, 0 until `addAnchor`                               |
| Box    | `a` ‖ `sha256(alg ‖ pubkey)` | empty (anchor)                                            |
| Box    | `w` ‖ TLD label              | empty (whitelist)                                         |
| Box    | `r` ‖ `sha256(name ‖ type)`  | cache: `sha256(RRset)`, `inception`, `expiry`, `weakestKeyBits` |
| Box    | `t` ‖ `sha256(name)`         | attestation: header, then `uint16 rdlen ‖ rdata` per RR   |
| Box    | `c` ‖ address                | MbrManager credits, uint64                                |

Attestation header: `inception`, `expiration`, `weakestKeyBits`, `payer`.

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
| `addAnchor`   | nothing: admin-supplied, once (see "Lifecycle")           | sender is `admin`     |
| `proveRoot`   | root DNSKEY RRset under an anchor                         | owner, and owner = root |
| `proveDs`     | DS RRset under a key in the parent's cached DNSKEY RRset  | a proper ancestor of owner |
| `proveDnskey` | DNSKEY RRset under one of its own keys matching the cached DS | equal to owner    |
| `proveTxt`    | TXT RRset under a key in a cached DNSKEY RRset            | owner or an ancestor  |
| `prune`       | see "Box rent"                                            |                       |
| `addTld` / `removeTld` / `setAdmin` | sender is `admin`                   |                       |
| `logAttestations(names)` | `@readonly`: logs each attestation box, empty line if missing |            |
| inherited     | `increaseBudget`, `depositCredits`, `withdrawCredits`, `logCredits` |             |

- Proving methods and `prune` are permissionless, but a sender that creates
  boxes needs credits.
- The whitelist is checked in `proveDs`, `proveDnskey` and `proveTxt`
  against the owner's rightmost label. `proveRoot` is exempt: the root has no
  labels.
- Ancestry is tested label by label.
- Newest inception wins, for caches and attestations alike. Ties replace.
- A TXT proof replaces the whole RDATA set, so a removed record disappears as
  soon as anyone submits the newer RRset.
- `setAdmin` to the zero address renounces the role permanently. Doing it
  before `addAnchor` bricks the contract.

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

### Root anchors: first pass

No rollover and no revocation. The anchor set is whatever `addAnchor` wrote.
When the root KSK next rolls, or the root moves to ECDSA, the contract stops
proving and is redeployed. The rollover design (Add, Promote, Reset, Miss,
Return, Retire, Revoke) is deferred to a second pass and will need its own
contract, since this one cannot be updated.

### Box rent

All box MBR runs through `MbrManager` credits. Refunds are credit entries, not
payments, so a closed account can never block a write.

| Box          | Who pays                   | Who can prune, and when                          | Refund credited to |
|--------------|----------------------------|--------------------------------------------------|--------------------|
| Anchor, whitelist | admin                 | whitelist: `removeTld`; anchor: never            | admin              |
| Cache        | first prover               | anyone, once expired                             | the pruner         |
| Attestation  | each prover                | `payer` once expired; anyone 30 days after; anyone if the TLD is unlisted | `payer` |

- Cache boxes are fixed size, so replacing one moves no credit.
- Replacing an attestation deletes the old box and credits the old `payer`
  with `settleMbrCredits(payer, before)`, then creates the new one and charges
  the sender with `manageMbrCredits`.
- If `payer` has no credit box any more (they withdrew), the refund stays
  with the app instead of failing, since `settleMbrCredits` would assert.
  `ponytail:` stranded dust, add a sweep if it ever adds up.
- A pruner must hold a credit box to receive the refund.
- The 30-day grace keeps the newest-inception mark alive for short-lived
  signatures such as Route 53's.

### Reading attestations

- On-chain: the contract enables `ForeignBoxReads` on itself at creation with
  `app_params_set` (AVM v13). Consumers read the `t` box directly with the
  reference reader. Fallback, only if PuyaTs 1.3.1 does not expose
  `app_params_set`: consumers call `logAttestations` as an inner call.
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
| 6 | **Admin, at deploy** | Uploads the only anchor. A false anchor forges everything. Checkable once: consumers pin the app ID and compare the anchor box to IANA's trust anchor file. Fixed afterwards. |
| 7 | **Whitelist admin** | Add a TLD: extends trust to that registry, for names under it only. Remove a TLD: blocks proofs and lets its attestations be pruned. **Cannot forge** under existing TLDs, cannot touch anchors or code. |
| 8 | **Algorand consensus and AVM** | The only clock is the block timestamp, bounded to +25 s per block but not to wall-clock time. Proposers stalling it extend the life of expired signatures. |
| 9 | **Verification code** | The RSA and MBR libraries, the wire parser, the Puya compiler, the rule list. A bug equals a forged root key, and the contract cannot be patched. Largest avoidable risk. |
| 10 | **Consumer code** | Must parse the attestation box by its layout. A substring match is a forgery at the consumer. |
| 11 | **Watchers, for liveness** | Someone must submit the root RRset at least every 21 days or every proof below stalls. Cheap, permissionless, should be a cron job. |
| — | **Relayer** | **Not trusted for integrity.** Freshness depends on everyone who can submit, below. |

### What an attestation does not mean

- **That the record exists now.** It was signed and is inside its validity
  window: about 3 hours on Route 53, 2 days on Cloudflare, up to weeks
  elsewhere. Anyone can submit any still-valid RRset when nothing newer is
  stored. Consumers must set a maximum age on **`inception`**.
- **That a name has no records.** No NSEC/NSEC3. A TXT set deleted entirely
  can only age out.
- **Current ownership.** After a transfer or lapse, the previous owner's keys
  stay usable until the DS signature expires, up to about 7 days for `.com`,
  and they can pick inception = now to outrank the new owner.
- **Resolver semantics.** No CNAME following, no wildcards.

Advice for consumers: put the app ID, the Algorand address and a nonce inside
the TXT value, so a record proven for one purpose cannot be reused for another.

### End of life

The contract fails closed and must be redeployed when: the root KSK rolls
(no rollover in the first pass; with the KSK-2017 anchor that is
2026-10-11), the root moves to an algorithm the AVM lacks or to RSA above
2048 bits, or in 2106 when DNSSEC's 32-bit timestamps wrap.

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
| 2 | Crypto wrappers, two-step creation with `addAnchor`, `proveRoot` | High-S, `s` with a leading zero, zero-padded modulus, wrong exponent, wrong lengths, RSA-1023 and RSA-2049 rejected; `addAnchor` by non-admin, twice, with flags 256 or 385; proofs before any anchor |
| 3 | `proveDs`, `proveDnskey`, `proveTxt` | Full chain under each TLD; one negative per rule; `parent` hash mismatch or wrong zone; expiry capping; inception order and ties; self-signed DS rejected |
| 4 | Credits and `prune` | Proof without credits (`CRD`); replace refunds the old payer's credits; payer who withdrew; pruner without a credit box; grace period; unlisted TLD |
| 5 | Whitelist admin | Non-admin rejected; removal blocks proofs; renounce |
| 6 | SDK prover and reads, then a TestNet soak across a real root ZSK roll | End to end before MainNet; simulate and algod reads agree |

Second pass, not scheduled: root rollover and `revokeRoot`, tested against the
captures.

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
