# @d13co/dnssec-oracle-sdk

TypeScript SDK and prover for the DNSSEC oracle on Algorand: the typed client
(`DnssecOracleClient`), the prover that builds and submits chain proofs, and readers for
the oracle's boxes. See the [project README](../../README.md) for what the oracle attests.

## On-chain consumers

The package also ships the oracle's Algorand TypeScript sources, for consumer contracts
compiled with puya-ts:

| Import                              | What                                                         |
|-------------------------------------|--------------------------------------------------------------|
| `@d13co/dnssec-oracle-sdk/contract` | the `DnssecOracle` contract class, to type ABI calls into it |
| `@d13co/dnssec-oracle-sdk/reader`   | the reference reader: `readAttestation`, `attestationUsable`, `attestationHasRecord`, `txtRdata` |

Call `hasRecord` by inner call, typed from the contract class:

```ts
import { assert } from '@algorandfoundation/algorand-typescript'
import { abiCall } from '@algorandfoundation/algorand-typescript/arc4'
import type { DnssecOracle } from '@d13co/dnssec-oracle-sdk/contract'
import { txtRdata } from '@d13co/dnssec-oracle-sdk/reader'

// this.oracle: the oracle app, pinned at create
assert(text.length <= 255, 'text over 255 bytes') // txtRdata writes a one-byte length
const ok = abiCall<typeof DnssecOracle.prototype.hasRecord>({
  appId: this.oracle.value,
  args: [name, txtRdata(text), maxAge, minKeyBits, zones],
}).returnValue
```

Or read the attestation boxes directly through the reader, with no inner call. Both are in
the example consumer, `projects/dnssec-oracle/smart_contracts/consumer/contract.algo.ts`.

- Use `import type`: puya-ts takes the method signature from it and emits only your
  contract's artifacts.
- Pin the oracle's app ID at create. An app the caller names could hold forged boxes or
  return anything.
- The outer transaction carries the box references: the attestation, each zone's DNSKEY
  and DS, and the root DNSKEY (see `hasRecord`).
- Compile with `--target-avm-version 13`: the reader uses `app_box_get`.
- Needs `@algorandfoundation/algorand-typescript` 1.3 or later in 1.x (an optional peer
  dependency).
- Type-check with `moduleResolution` `node` or `bundler`, as AlgoKit templates do. Under
  `node16`/`nodenext`, algorand-typescript's own types do not resolve, with or without this
  package.
