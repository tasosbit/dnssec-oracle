# DNSSEC oracle on Algorand — plan

## Context

Goal: a smart contract on Algorand that lets anyone prove, with no trusted
relayer, that a TXT record exists at a DNS name, by verifying the DNSSEC
signature chain from the DNS root down to the TXT RRset on-chain.

- Greenfield: `/home/bit/code/dnssec-oracle` is empty.
- RSA verification is **out of scope**. It comes from
  `@d13co/puya-ts-utils/rsa` (`/home/bit/code/puya-ts-utils`, work currently
  unstaged). Taken at face value; this project only adds TODOs there.
- Target: MainNet consensus v42 / AVM v13. The local Algorand skills describe
  AVM 12 and are stale; `/home/bit/Docs/draftvim/avm13-opus.md` is the reference.
- Stack per `AGENTS.md`: Algorand TypeScript (PuyaTs ≥ 1.3.1) + AlgoKit.

## Decisions taken

| Topic         | Decision                                                       |
|---------------|----------------------------------------------------------------|
| Root anchors  | Roll on-chain, RFC 5011 style. No admin involvement.           |
| Results       | Stored attestations in boxes, readable on- and off-chain.      |
| RSA minimum   | 1024-bit modulus.                                              |
| Whitelist     | `com`, `io`, `finance`, `co`. Admin can add and remove.        |
| Contract code | No update, no delete.                                          |
| RSA host      | Inside the contract (see "Cost").                              |

## Time-sensitive: do this first

The root KSK rolls on **2026-10-11**. Rollover test data cannot be recreated
afterwards. First task, before any code: a daily cron capturing
`. DNSKEY` with its RRSIGs, kept running until the revocation has been seen.

| When               | What the capture will contain                       |
|--------------------|-----------------------------------------------------|
| Before 2026-10-11  | signed by KSK-2017 (20326), carrying KSK-2024       |
| After 2026-10-11   | signed by KSK-2024 (38696)                          |
| About 2027-01-11   | KSK-2017 with the REVOKE flag, self-signed          |

Also capture a full chain for one name under each whitelisted TLD.

## What a proof is

For `_tag.example.com TXT`, 6 signatures and 2 digests:

| # | RRset                  | Signed by        | Links to next via           |
|---|------------------------|------------------|-----------------------------|
| 1 | `. DNSKEY`             | root KSK         | KSK is an active anchor     |
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

All DS records use SHA-256. All RSA exponents are 65537.

## Design

One contract. Every proving method performs **exactly one** signature
verification. Rows 1–3 are cached, so they are paid once per signing period
and shared by every domain under that TLD.

### The one input format

Every proving method takes a single `signedData` argument: exactly the bytes
that get hashed (RRSIG RDATA without the signature, then the RRset).

- Parsed from offset 0; the cursor must land exactly on the end.
- Owner name, type and signer name come **only** from these bytes.
- Box keys are derived from the parsed names, never from arguments.
- RRs are reached by index, walking from the start. No prover-supplied offsets.

This closes boundary-shifting: a tenant of a shared zone embedding a fake RR
for a sibling name inside their own TXT value.

Hard limit: `sha256` takes one value of at most 4,096 bytes and cannot stream,
so signed data above that size is unprovable. Documented, not worked around.

### State

| Where        | Key                          | Value                                                     |
|--------------|------------------------------|-----------------------------------------------------------|
| Global       | `admin`                      | address                                                   |
| Global       | `a0` … `a15`                 | anchor: `sha256(alg ‖ pubkey)`, `status`, `firstSeen`     |
| Box          | `w` ‖ TLD label              | empty (whitelist)                                         |
| Box          | `c` ‖ `sha256(name ‖ type)`  | cache: `sha256(RRset)`, `inception`, `expiry`, `weakestKeyBits` |
| Box          | `t` ‖ `sha256(name)`         | attestation: header, then `uint16 rdlen ‖ rdata` per RR   |

Attestation header: `inception`, `expiration`, `weakestKeyBits`, `payer`.

- Anchors live in global state because boxes cannot be written during
  creation (the app account is not funded yet) and cannot be enumerated.
  Revoked anchors stay as tombstones.
- Anchors are keyed by public key because the REVOKE flag changes both key
  tag and DS digest.
- Names are wire format, lowercase, labels ≤ 63 bytes, name ≤ 255.
- `expiry` and `expiration` are both
  `min(this RRSIG's expiration, expiry of the entry it was verified against)`.
- `weakestKeyBits` describes the path this proof took. P-256 counts as 3072.
- The attestation box layout is the public API. A reference reader ships with
  the project; consumers must walk RRs from the header, never substring-match.

### Methods

| Method        | Verifies                                                  | Signer must be        |
|---------------|-----------------------------------------------------------|-----------------------|
| `proveRoot`   | root DNSKEY RRset under an active anchor; drives rollover | owner, and owner = root |
| `proveDs`     | DS RRset under a key in the parent's cached DNSKEY RRset  | a proper ancestor of owner |
| `proveDnskey` | DNSKEY RRset under one of its own keys matching the cached DS | equal to owner    |
| `proveTxt`    | TXT RRset under a key in a cached DNSKEY RRset            | owner or an ancestor  |
| `revokeRoot`  | root DNSKEY RRset under an anchor carrying the REVOKE flag | that key itself      |
| `prune`       | see "Box rent"                                            |                       |
| `addTld` / `removeTld` / `setAdmin` | sender is `admin`                   |                       |

- Proving methods, `revokeRoot` and `prune` are permissionless.
- The whitelist is checked in every proving method against the owner's
  rightmost label.
- Ancestry is tested label by label.
- Newest inception wins, for caches and attestations alike. Ties replace.
- A TXT proof replaces the whole RDATA set, so a removed record disappears as
  soon as anyone submits the newer RRset.
- `setAdmin` to the zero address renounces the role permanently.

### Key and signature checks

Applied to the **indexed** key or DS only. Other records in the RRset are
skipped, so a revoked key, an unknown algorithm or a SHA-1 DS sitting
alongside does not block a proof.

| Item    | Checks                                                                   |
|---------|--------------------------------------------------------------------------|
| DNSKEY  | Zone flag set, REVOKE clear, protocol 3, algorithm = RRSIG algorithm, 8 or 13 |
| DS      | digest type 2, 36 bytes; key tag, algorithm and digest match the DNSKEY  |
| RSA     | exponent exactly 65537; modulus first byte non-zero; ≥ 1024 bits by real length; signature length = modulus length; Montgomery hint required |
| ECDSA   | key and signature exactly 64 bytes; if `s > n/2` then `s = n − s`, left-padded to 32 bytes |
| RRSIG   | type covered = RRset type; class IN; one owner for all RRs; labels field = owner's label count; no `*` label; `inception ≤ now ≤ expiration` |
| TXT     | per RR, character-string lengths sum to `rdlen`                          |

Not checked, because the signature already binds the bytes: RR ordering and
duplicates.

### Root rollover

Transitions run on **any** valid root RRset, not only the newest. Gating them
on inception would let a stolen key, signing with inception = now, shut out
the real operator for good. Only the root *cache write* is newest-wins.

| Step     | Trigger                                                           | Result             |
|----------|-------------------------------------------------------------------|--------------------|
| Add      | key with flags exactly 257, not an anchor, in `proveRoot`         | `pending`, `firstSeen = now` |
| Promote  | pending key seen again, `now ≥ firstSeen + 30 days`               | `active`           |
| Reset    | pending key absent from the RRset                                 | slot cleared       |
| Revoke   | `revokeRoot`: anchor with REVOKE set, RRset verifies under it     | `revoked`, forever |

- Initial anchors are creation arguments: whatever IANA's trust anchor file
  lists as valid on deploy day. Before about 2027-01-11 that is both KSK-2017
  and KSK-2024.
- A keyless attacker replaying an old RRset can delay a promotion by at most
  one RRSIG lifetime, about 21 days. ICANN pre-publishes for far longer.
- A proposed (not approved) root move to ECDSA would double-sign from 2028
  and drop RSA in 2030. Add and Promote already cover it.

### Box rent

| Box          | Who pays            | Who can prune, and when                          | Rent goes to |
|--------------|---------------------|--------------------------------------------------|--------------|
| Cache        | first prover        | anyone, once expired                             | the pruner   |
| Attestation  | each prover         | `payer` once expired; anyone 30 days after; anyone if the TLD is unlisted | `payer` |

- Cache boxes are fixed size, so replacing one moves no money.
- Attestation refunds are guarded: if `payer` holds under 100,000 µAlgo the
  refund stays with the app. An unguarded refund to a closed account would
  fail and block every later write to that name.
- The 30-day grace keeps the newest-inception mark alive for short-lived
  signatures such as Route 53's.

### Reading attestations

The contract enables `ForeignBoxReads` on itself at creation with
`app_params_set` (AVM v13). Consumers read the box directly.

Fallback, only if PuyaTs 1.3.1 does not expose `app_params_set`: one readonly
`getTxt(name)` method.

### Cost

Library figures, with hint, taken at face value:

| Check       | Opcodes | In-contract fee, approx. |
|-------------|---------|--------------------------|
| RSA-2048    | 92k     | 0.13 Algo                |
| RSA-1280    | 53k     | 0.08 Algo                |
| RSA-1024    | 29k     | 0.04 Algo                |
| ECDSA P-256 | 2.5k    | 0.004 Algo               |

A group can supply 190,400 opcodes, so every single check fits.

- Refreshing root + one RSA TLD: three RSA-2048 checks, about 0.4 Algo, once
  per signing period (roughly two weeks).
- A `.com` domain on Cloudflare or Route 53: three ECDSA checks, about 0.01 Algo.

Fees are usage-based in v42: the prover simulates every group to price it.

`ponytail:` RSA runs inside the contract. A LogicSig host would cost about
1/20th in fees but adds a second program and binding checks between the two.
Move only if proof volume makes fees matter; it means a redeploy.

### Off-chain prover

Plain TypeScript, untrusted. Queries DNS with the DO bit, builds canonical
signed data, computes Montgomery hints, refreshes parents before children,
then submits `proveTxt`.

## Trust points

Ordered from unavoidable to self-inflicted.

| # | Who or what | What they can do |
|---|-------------|------------------|
| 1 | **DNS root** (ICANN/IANA, root zone maintainer) | Forge any name. Inherent to DNSSEC. |
| 2 | **TLD registry** | Publish a DS for any name under it, or sign records below a zone cut directly. Full takeover of that name. |
| 3 | **Intermediate zones, registrar, registrant account** | Anyone who can change a DS on the path controls everything below it. |
| 4 | **DNS operator of the domain** | Holds the zone keys; can sign any TXT. Cloudflare uses **one key pair for all customer zones**. |
| 5 | **Weakest key in the chain** | `io`, `finance` and `co` sign with 1024-bit RSA; every name under them is at most that strong. Chosen, not inherited. `weakestKeyBits` lets a consumer refuse such proofs, but a forger with a factored key can still overwrite a strong attestation with a weak one: denial of service, not forgery. |
| 6 | **Whitelist admin** | Add a TLD: extends trust to that registry, for names under it only. Remove a TLD: blocks proofs and lets its attestations be pruned. **Cannot forge** under existing TLDs, cannot touch anchors or code. |
| 7 | **Deployer** | Anchors are creation arguments. Consumers must pin the app ID and check the anchors once. |
| 8 | **Algorand consensus and AVM** | The only clock is the block timestamp, bounded to +25 s per block but not to wall-clock time. Proposers stalling it extend the life of expired signatures. |
| 9 | **Verification code** | The RSA library, the wire parser, the Puya compiler, the rule list. A bug equals a forged root key, and the contract cannot be patched. Largest avoidable risk. |
| 10 | **Consumer code** | Must parse the attestation box by its layout. A substring match is a forgery at the consumer. |
| 11 | **Watchers, for liveness** | Someone must submit the root RRset at least every 21 days, twice 30 days apart during a rollover, and must submit revocations. If nobody does, the oracle stops permanently. Cheap, permissionless, should be a cron job. |
| 12 | **Watchers, for rollover safety** | A stolen root key can nominate its successor using only the ability to submit. The defence is any one watcher submitting the real RRset within the 30-day hold-down. |
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

The contract fails closed and must be redeployed when: all anchors are
revoked, the root moves to an algorithm the AVM lacks, all 16 anchor slots
are used, or in 2106 when DNSSEC's 32-bit timestamps wrap.

## TODOs to add in `puya-ts-utils`

Comments only, at the top of `projects/puya-ts-utils/src/rsa.algo.ts`, tagged
`TODO(dnssec-oracle)`. No code changes, nothing staged or committed there.
Each is added only if a look at the repo at that point shows it is missing:

- Commit and publish a version that exports `./rsa`.
- Export the off-chain Montgomery hint helper (the README has it as a snippet).
- State the compiled size the RSA code adds to a contract (16 KB app limit).
- Negative tests from Wycheproof RSA PKCS#1 v1.5 vectors.
- A statement that a hostile `hint` can only fail, never cause a false accept.

## Project layout

- `smart_contracts/dnssec_oracle/contract.algo.ts` — state, methods, rollover
- `smart_contracts/dnssec_oracle/wire.algo.ts` — signed-data parser, name rules
- `smart_contracts/dnssec_oracle/reader.algo.ts` — reference attestation reader
- `prover/` — off-chain proof builder
- `tests/fixtures/` — captured chains
- `scripts/capture-root.sh` — the daily capture

## Build order

| Phase | Work | Proves |
|-------|------|--------|
| 0 | Start daily capture. Scaffold with AlgoKit, link the RSA library, add the TODOs. Spike on LocalNet: `app_params_set` at creation, a foreign box read, RSA-2048 opcode cost and program size in app mode. | The three assumptions the design rests on |
| 1 | Signed-data parser and name rules, as pure functions | Boundary shift, trailing bytes, `ample` vs `example`, pointer labels, RRsets holding revoked or unknown keys |
| 2 | Crypto wrappers, `proveRoot` with fixed anchors | High-S, `s` with a leading zero, zero-padded modulus, wrong exponent, wrong lengths |
| 3 | `proveDs`, `proveDnskey`, `proveTxt` | Full chain under each TLD; one negative per rule; expiry capping; inception order and ties; self-signed DS rejected |
| 4 | Box rent and `prune` | Closed payer on replace and prune; grace period; unlisted TLD |
| 5 | Rollover and `revokeRoot`, with synthetic root keys, then the real captures | Add, promote, reset, revoke; flags 385 never added; inception flooding cannot block revoke; slots full |
| 6 | Whitelist admin | Non-admin rejected; removal blocks proofs; renounce |
| 7 | Prover, then a TestNet soak across a real root ZSK roll | End to end before MainNet |

## Verification

- LocalNet with block time pinned inside each fixture's validity window.
- Each phase's "Proves" column is its test list.
- A second contract reads an attestation box directly using the reference reader.
- Simulate every method; record opcode cost and fee.
