# DNSSEC oracle on Algorand

> [!WARNING]
> **Experimental and unaudited.** Neither the contract nor the RSA and box-rent libraries it
> depends on have had a security audit. The contract cannot be updated, so a bug cannot be
> patched: it takes a redeployment. Do not rely on it for anything of value.

Proves on-chain, with no trusted relayer, that a TXT record exists at a DNS name. The
contract verifies the DNSSEC signature chain from the root trust anchor down to the TXT
RRset, one signature per call, and stores the result in a box that any Algorand app can read
directly.

- **Trustless submission.** Anyone can submit a proof. The submitter is not trusted: the
  contract parses every byte it hashes and checks every signature itself (RSA/SHA-256 and
  ECDSA P-256).
- **Shared cache.** Root, DS and DNSKEY RRsets are cached as hashes, so a TLD's keys are
  paid for once per signing period and reused by every name below it.
- **Root key rollover on-chain.** Anchors follow RFC 5011: anyone can apply Add, Promote,
  Miss, Return, Reset, Retire and self-signed revocation. The admin uploads the initial
  anchors once and has no say in them after that.
- **Immutable.** No update or delete methods. A rule change means a new deployment.

Architecture, RFC compliance and the full list of limitations:
[docs/architecture.md](./docs/architecture.md). Design history and trust model:
[docs/plan.md](./docs/plan.md).

## What an attestation says

The box `t ‖ sha256(name)` holds the TXT RDATA set as signed, plus a header:

| Field            | Meaning                                                              |
|------------------|----------------------------------------------------------------------|
| `inception`      | when the zone signed this RRset (the TXT RRSIG's inception)           |
| `expiration`     | the earliest RRSIG expiration on the chain, root included            |
| `weakestKeyBits` | the weakest key on the chain (P-256 counts as 3072)                  |
| `parentEpoch`    | links the attestation to the cache entries above it, for the chain walk |
| `payer`          | who paid the box rent                                                |

It means *this RRset was validly signed at `inception`*, not that the record still exists
now. The consumer decides how old is too old (`maxAge`) and how weak is too weak
(`minKeyBits`), and walks the chain to check that no key above has been replaced since.
The reference reader `smart_contracts/dnssec_oracle/reader.algo.ts` does all three in
`attestationUsable`. Contracts that would rather not carry it call the oracle's
`hasRecord`, which does the same and matches the record (one inner call).
Both ship in the SDK package (`dnssec-oracle-sdk/reader`, and `dnssec-oracle-sdk/contract`
to type the call); see its [README](projects/dnssec-oracle-sdk/README.md#on-chain-consumers).

## Usage models

### Prove once

The consumer checks the attestation once and records its own fact, with an expiry of its
own choosing. After that it no longer reads the oracle, and the attestation can expire and
be pruned.

```ts
// consumer contract, sketch: the TXT text holds the claimant's address and this app's ID
public claim(name: bytes, text: bytes, zones: bytes[]): void {
  const [value, exists] = readAttestation(ORACLE, name)            // ORACLE: pinned app ID
  assert(exists && attestationUsable(ORACLE, value, 3600, 2048, zones))
  assert(attestationHasRecord(value, txtRdata(text)))
  this.claims(name).value = { text, until: Global.latestTimestamp + 365 * 86_400 }
}
```

- Cost: one chain proof, at claim time. Nobody has to keep anything fresh afterwards.
- `maxAge` here only bounds how stale the proof may be *at claim time*. Keep it short,
  but longer than the zone's re-signing interval, or there may be no signature recent
  enough to submit.
- The consumer does not see later changes until its own expiry: a removed record, a
  domain transfer (new DS) or a root key revocation. Choose the expiry with that in
  mind, or let the owner re-claim to extend it.
- Suits registrations, one-time ownership checks and allowlists that are reviewed
  periodically anyway.

### Continuous attestations

The consumer reads the oracle box on every use, as the example `AttestationConsumer.hasTxt`
does, so the data must stay proven the whole time it is relied on.

```bash
# from cron, more often than the consumer's maxAge
dnssec-oracle prove _algorand.example.com
```

```ts
await sdk.proveTxt('_algorand.example.com') // fresh cache steps are skipped; op-up is automatic
```

- Someone (the name owner, the consumer's operator or any keeper) must re-prove before
  the attestation fails any of the following:
  - **`maxAge` on `inception`.** Consumers reject anything signed longer ago than this,
    so it must be longer than the zone's re-signing interval: Cloudflare signs on the
    fly, while other zones re-sign weekly.
  - **`expiration`.** The earliest RRSIG expiration on the chain, often a root signature,
    which lasts two to three weeks.
  - **The chain walk.** Any new RRset above the name (a root or TLD ZSK roll, a new DS)
    stales everything below it, a few times a quarter at the root alone. `proveTxt`
    re-proves the stale links first.
- Cost: each refresh pays for the TXT step, plus any cache steps that expired or changed
  since the last refresh, which every name under the same TLD shares. The figures are
  under [Phase 0 results](#phase-0-results). Box rent is unchanged: replacing an
  attestation refunds the old payer and charges the new one.
- Suits access control, payments routed by DNS name and anything else that must stop
  trusting a record soon after it is withdrawn. Removal still takes up to `maxAge` to
  take effect: the oracle cannot prove that a record is absent.

Both models need the root DNSKEY entry kept fresh. `dnssec-oracle maintain-anchors`
(daily, see [Root KSK rollover](#root-ksk-rollover)) does that as well as the RFC 5011
work.

## Limitations

Summary only. The reasons behind each one are in
[docs/architecture.md](./docs/architecture.md#limitations).

- **RSA keys of 1024 to 2048 bits, exponent 65537.** The 2048-bit cap keeps one RSA
  check (about 92k opcodes) inside a single transaction group's op-up pool (190,400).
  Larger keys could be verified over several groups, carrying the modular exponentiation
  forward in a box between them. That option has not been implemented, to keep the
  contract simple. On 2026-09-28, 19 of 1,351 signed TLDs published an RSA key above
  2048 bits (`pl`, `ar` and `lv` among them). Names under such a TLD are provable only
  while its DS links to a key of 2048 bits or fewer.
- **Algorithms 8 (RSA/SHA-256) and 13 (ECDSA P-256/SHA-256) only; DS digest type 2
  (SHA-256) only.** 36 TLDs also use other algorithms.
- **4,096 bytes per signed RRset and per attestation.** `sha256` cannot stream, and an
  AVM byte value holds at most 4,096 bytes. A TXT RRset whose signed data or attestation
  is larger cannot be proven. Apex TXT sets (SPF, verification tokens) are where this
  bites: one measured apex is already at 2,844 bytes.
  - **Tip:** if you control the zone, put the records the oracle should prove at a
    dedicated subdomain such as `_algorand.example.com`, never at the apex. The RRset
    then holds only your records: about 4,000 bytes of RDATA, or some 44 records of one
    Algorand address each. See [research/sha256-limit](./research/sha256-limit/README.md).
- **TXT, positive answers only.** No NSEC/NSEC3, so the oracle cannot prove that a record
  or a name does not exist. No CNAME or DNAME following, and no wildcards.
- **The record existed, not that it still exists.** Freshness is the consumer's `maxAge`.
- **Liveness depends on watchers.** Someone has to re-prove the root DNSKEY RRset before
  its signature expires (about every three weeks), and send RFC 5011 events within 30 days
  of a change.
- **The clock is the block timestamp.** DNSSEC's 32-bit times wrap in 2106.
- **Fixed code.** A new root algorithm, a root key above 2048 bits or a bug all need a
  redeployment, and consumers then have to pin the new app ID.

## Layout

```
projects/dnssec-oracle/          contract (PuyaTs, AVM 13), unit + e2e tests
  smart_contracts/base/          BaseContract: increaseBudget, above puya-ts-utils' MbrManager
  smart_contracts/dnssec_oracle/ contract, errors, wire parser, reference attestation reader
  smart_contracts/consumer/      example consumer: direct box reads, or hasRecord by call
  tests/                         emulator (*.algo.spec.ts) and LocalNet (*.e2e.spec.ts) suites
projects/dnssec-oracle-sdk/      reader/writer SDK and the off-chain prover
  src/prover/                    DNS over TCP, canonical signed data, chain building
projects/cli/                    `dnssec-oracle` operator CLI over the SDK (yargs, bun executables)
research/sha256-limit/           RRset sizes across every signed TLD vs the 4,096-byte limit
scripts/capture-root.sh          daily capture for rollover test data (cron)
captures/<date>/                 dig.txt (presentation) and chains.json (wire)
docs/architecture.md             architecture, RFC compliance, limitations
docs/plan.md                     design plan, decisions and trust model
```

## Build and test

```bash
pnpm install
algokit localnet start
algokit project run build   # contract → client + errors copied into the SDK → SDK
algokit project run test    # emulator suites, then LocalNet e2e through the SDK
```

Rebuild the SDK after every contract change: the e2e tests import its `dist`.

`@d13co/puya-ts-utils` ships its contract subroutines as TypeScript source; vitest
inlines the package so the emulator can run it.

## Deploy and prove

```ts
const sdk = new DnssecOracleSDK({ algorand, appId, writerAccount })
await sdk.depositCredits({ amount: 1_000_000 }) // box rent
await sdk.proveTxt('_algorand.example.com')     // skips fresh cached steps, op-up is automatic
// undefined unless current, unexpired, signed within maxAge and no key weaker than minKeyBits
const verified = await sdk.getVerifiedAttestation('_algorand.example.com', { maxAge: 86_400, minKeyBits: 2048 })
```

Attestation getters say whether they validate. `getVerifiedAttestation` applies the same
checks as the on-chain `attestationUsable`: the chain is current, the attestation is
unexpired, it was signed within `maxAge` and no key is weaker than `minKeyBits`.
`getRawAttestation(s)` and `listRawAttestations` return box contents as stored, stale,
expired and weak entries included. Use them to inspect boxes, not to trust them. The cache
getters (`getRawCache(s)`, `listRawCaches`) are raw in the same way.

Deploying takes two steps, both from the admin: `DnssecOracleSDK.create(...)`, then
`sdk.setup({ anchors: ROOT_ANCHORS })`. `setup` funds the app, deposits the admin's credits
and uploads the anchors (KSK-2017 and KSK-2024) in one group. Any TLD can be proven.
Consumers choose which names, and therefore which registries, they trust. The CLI wraps
all of this: [projects/cli/README.md](./projects/cli/README.md).

## Root KSK rollover

`updateAnchor` applies RFC 5011's Add, Promote (after a 30-day hold-down), Reset, Miss,
Return and Retire from the cached root DNSKEY RRset. `revokeRoot` takes an anchor's
self-signed revocation. Both are permissionless. Run the watcher daily:

```ts
await sdk.maintainAnchors() // revocations, then the root proof, then every event it implies
```

or `dnssec-oracle maintain-anchors`.

## Verifying anchors and zone keys

The oracle is only as trustworthy as its root anchors, and a consumer that pins an app ID
should check them once. `dnssec-oracle keys <zone>` shows what DNS serves for a zone
alongside what the oracle holds, at any level. The dig commands below are the
independent check. They are bash, and `dnssec-dsfromkey` comes with BIND's tools
(`bind9-utils` on Debian and Ubuntu).

### Root anchors against IANA

```bash
dnssec-oracle anchors   # each anchor's id, sha256(alg ‖ pubkey), and RFC 5011 state
dnssec-oracle keys .    # root DNSKEYs: role, key tag, size, anchor state, the same id
```

```
. DNSKEY: cache matches DNS; inception 2026-09-19T00:00:00.000Z, expiry 2026-10-10T00:00:00.000Z, epoch 2
  ZSK 8763, RSA-2048 (alg 8): usable by the oracle; not an anchor, id 7830bac1…
  ZSK 57780, RSA-2048 (alg 8): usable by the oracle; not an anchor, id a51d365c…
  KSK 20326, RSA-2048 (alg 8): usable by the oracle; anchor Valid since 2026-09-30T22:54:52.000Z, id bcd10e3a…
  KSK 38696, RSA-2048 (alg 8): usable by the oracle; anchor Valid since 2026-09-30T22:54:52.000Z, id 093b9779…
```

Ids are shortened here; the command prints all 64 hex digits. The same ids from dig, and
the root KSKs' DS digests compared with IANA's trust anchor
file:

```bash
# anchor ids: sha256 of the algorithm byte and the public key, for each root KSK
dig +noall +answer . DNSKEY | awk '$5 == 257 || $5 == 385 { key = ""; for (i = 8; i <= NF; i++) key = key $i; print $7, key }' |
  while read alg key; do { printf '%02x' "$alg" | xxd -r -p; echo "$key" | base64 -d; } | sha256sum; done

# key tag and DS digest of each root KSK, then IANA's list
dig +noall +answer . DNSKEY | dnssec-dsfromkey -a SHA-256 -f - .
curl -s https://data.iana.org/root-anchors/root-anchors.xml | grep -E 'KeyTag|Digest>'
```

Every Valid or AddPend anchor in `dnssec-oracle anchors` should match a key that `keys .`
lists with the same id, and that key's tag and digest from `dnssec-dsfromkey` should
appear in `root-anchors.xml`. A Missing anchor is still trusted but has left the root
DNSKEY RRset, so neither `keys .` nor dig lists it: check that one by hand, by finding
the key in IANA's file or an older capture and computing its id. The file also lists
retired keys (19036, KSK-2010), which the oracle does not anchor.

### Any zone: KSK, ZSK and DS

```bash
dnssec-oracle keys com
dnssec-oracle keys example.com --resolver 9.9.9.9
```

```
com. DNSKEY: cache matches DNS; inception 2026-09-24T13:57:35.000Z, expiry 2026-10-09T14:02:35.000Z, epoch 4
  ZSK 41446, P-256 (alg 13): usable by the oracle; no DS
  KSK 19718, P-256 (alg 13): usable by the oracle; DS matches
com. DS: cache matches DNS; inception 2026-09-30T19:00:00.000Z, expiry 2026-10-10T00:00:00.000Z, epoch 3
  DS 19718, alg 13, digest type 2: vouches for KSK 19718
```

- **Cache line.** `cache matches DNS` means the oracle's entry is exactly the RRset DNS
  serves now. `differs` means it holds another one: an older one, which the next proof
  replaces, or a newer one than this resolver serves. `not cached` means nobody has proven
  it yet. `(stale: …)` marks an entry the oracle or a consumer's chain walk would refuse,
  even if it matches: one from before a root key revocation, or a DNSKEY entry no longer
  linked to the zone's current DS entry. When DNS serves no such RRset, serves it
  unsigned or answers with a CNAME, the line says so instead.
- **Key lines.** Each key's role, tag and size, and why the oracle would refuse it, if it
  would (`RSA-4096 is outside 1024 to 2048 bits` for `pl`'s KSK). `DS matches` marks the
  keys that the parent's DS vouches for. ZSKs normally show `no DS`.
- **DS lines.** The key each DS vouches for. Digest types other than 2 are listed as
  ignored.

dig shows the same records, and validates them locally:

```bash
dig +multi +noall +answer com DNSKEY | grep 'key id'       # role, algorithm and tag of each key
dig +noall +answer com DS                                  # the DS records in the parent zone
dig +noall +answer com DNSKEY | dnssec-dsfromkey -a SHA-256 -f - com   # the DS each KSK should have
delv com DNSKEY                                            # "; fully validated" from the root down
```

One check needs the CLI: comparing with the oracle's cache. The oracle stores only
`sha256` of the canonical wire-format RRset, which dig cannot reproduce. Replay a capture
with `--captured captures/<date>/chains.json` to see the keys as they were on that date.
Its key and DS lines are exact, but cache lines only mean something live: they compare
today's cache with the capture, and judge expiry at the capture's time.

## Daily capture

The capture runs from the user crontab at 03:17 local time and logs to `captures/cron.log`.
Keep it running until KSK-2017 is seen revoked, around 2027-01-11. Each run writes the root
DNSKEY RRset straight from a root server, plus a full chain for one name under each of
`com`, `io`, `finance` and `co`. It writes `alerts.txt` (exit code 2) when a zone moves off
the contract's deployment assumptions, or when a key other than 20326 signs the root DNSKEY
RRset.

## Phase 0 results

Measured on LocalNet (algod 5.0.0, consensus v42), 2026-09-28, recorded in 6b1fb81 unless
marked:

| Proof step                     | Opcodes | Fee, µAlgo |
|--------------------------------|---------|------------|
| root DNSKEY, RSA-2048 KSK      | 89,082  | 132,000    |
| TLD DS, RSA-2048 root ZSK      | 92,187  | 136,000    |
| TLD DNSKEY, RSA-2048 KSK       | 94,571  | 140,000    |
| domain DS, RSA-1024 TLD ZSK    | 30,289  | 45,000     |
| any step signed by P-256       | 3.8k–4.7k | 6,000–7,000 |

- `app_params_set(ForeignBoxReads)` works inside the creation call, and a second contract
  reads attestation boxes directly (the `logAttestations` fallback was not needed on-chain;
  the SDK uses it, and `logCaches`, for simulated point reads). Contracts that would rather
  not carry the reader call `hasRecord` instead: the oracle walks the chain and matches the
  record, and returns a boolean (an app call logs at most 1024 bytes, so not the box).
- Group usage stayed at 1,000,000 for every proof group: fees are the transaction count
  (outer calls plus op-up inner calls) at the minimum fee, nothing extra.
- `increaseBudget` costs 21 opcodes, plus 21 per inner call: pinned in the SDK constants.
- Approval program: 6,393 bytes with `hasRecord` (2026-10-01), three extra pages.
  AVM 13 allows 16 KB.
- The emulator (`algorand-typescript-testing` 1.2.0) pins `latestTimestamp`, but has no
  `app_params_set` and misdecodes struct reads through `.maybe()`; the tests and the
  contract work around both.
- All five captured chains prove on LocalNet the same day under the real KSK-2017 anchor,
  and replay in the emulator at their capture time.
