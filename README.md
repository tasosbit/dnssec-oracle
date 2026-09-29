# DNSSEC oracle on Algorand

Proves on-chain, with no trusted relayer, that a TXT record exists at a DNS name: the
contract verifies the DNSSEC chain from the root down, one signature per call. Design and
trust model: [plan.md](./plan.md).

## Layout

```
projects/dnssec-oracle/          contract (PuyaTs, AVM 13), unit + e2e tests
  smart_contracts/base/          BaseContract: increaseBudget, above puya-ts-utils' MbrManager
  smart_contracts/dnssec_oracle/ contract, errors, wire parser, reference attestation reader
  smart_contracts/consumer/      example consumer reading attestation boxes directly
  tests/                         emulator (*.algo.spec.ts) and LocalNet (*.e2e.spec.ts) suites
projects/dnssec-oracle-sdk/      reader/writer SDK and the off-chain prover
  src/prover/                    DNS over TCP, canonical signed data, chain building
projects/cli/                    `dnssec-oracle` operator CLI over the SDK (yargs, bun executables)
scripts/capture-root.sh          daily capture for rollover test data (cron)
captures/<date>/                 dig.txt (presentation) and chains.json (wire)
```

## Build and test

```bash
pnpm install
algokit localnet start
algokit project run build   # contract → client + errors copied into the SDK → SDK
algokit project run test    # emulator suites, then LocalNet e2e through the SDK
```

Rebuild the SDK after every contract change: the e2e tests import its `dist`.

`@d13co/puya-ts-utils` is pinned to the v0.3.0 commit (`8f453eb`) of the local repository
until it is on npm. It ships TypeScript source only, so the SDK's `prebuild` copies
`rsaHint.ts` in beside the generated client, and vitest inlines the package so the
emulator can run it.

## Proving a name

```ts
const sdk = new DnssecOracleSDK({ algorand, appId, writerAccount })
await sdk.depositCredits({ amount: 1_000_000 }) // box rent
await sdk.proveTxt('_algorand.example.com')     // skips fresh cached steps, op-up is automatic
const attestation = await sdk.getAttestation('_algorand.example.com')
```

Deploying is two steps from the admin: `DnssecOracleSDK.create(...)`, then
`sdk.setup({ anchor: ROOT_KSK_2017, tlds: ['com', 'io', 'finance', 'co'] })`, which funds
the app, deposits the admin's credits, uploads the anchor and whitelists in one group.

## Daily capture

Installed in the user crontab at 03:17 local time, logging to `captures/cron.log`. Keep it
running until KSK-2017 is seen revoked, about 2027-01-11. Each run writes the root DNSKEY
RRset straight from a root server and a full chain for one name per whitelisted TLD, and
writes `alerts.txt` (exit code 2) when a zone moves off the contract's deployment
assumptions or the root DNSKEY RRset is signed by a key other than 20326.

## Phase 0 results

Measured on LocalNet (algod 5.0.0, consensus v42), 2026-09-28:

| Proof step                     | Opcodes | Fee, µAlgo |
|--------------------------------|---------|------------|
| root DNSKEY, RSA-2048 KSK      | 89,082  | 132,000    |
| TLD DS, RSA-2048 root ZSK      | 92,187  | 136,000    |
| TLD DNSKEY, RSA-2048 KSK       | 94,571  | 140,000    |
| domain DS, RSA-1024 TLD ZSK    | 30,289  | 45,000     |
| any step signed by P-256       | 3.8k–4.7k | 6,000–7,000 |

- `app_params_set(ForeignBoxReads)` works inside the creation call, and a second contract
  reads attestation boxes directly (the `logAttestations` fallback was not needed on-chain;
  the SDK uses it for simulated point reads).
- Group usage stayed at 1,000,000 for every proof group: fees are the transaction count
  (outer calls plus op-up inner calls) at the minimum fee, nothing extra.
- `increaseBudget` costs 21 opcodes, plus 21 per inner call: pinned in the SDK constants.
- Approval program: 5,089 bytes, two extra pages. AVM 13 allows 16 KB.
- The emulator (`algorand-typescript-testing` 1.2.0) pins `latestTimestamp`, but has no
  `app_params_set` and misdecodes struct reads through `.maybe()`; the tests and the
  contract work around both.
- All five captured chains prove on LocalNet the same day under the real KSK-2017 anchor,
  and replay in the emulator at their capture time.
