// ── Opcode budget ───────────────────────────────────────────────────

/** Opcode budget per app call and per op-up inner call. */
export const APP_CALL_BUDGET = 700
/** Inner transactions one group can issue: 16 per app call. */
export const MAX_OP_UP_ITXNS = 256
/** Minimum transaction fee (µAlgo). */
export const MIN_TXN_FEE_MICROALGOS = 1000

// sync with the "increaseBudget opcode cost" test in projects/dnssec-oracle/tests/contract.e2e.spec.ts
export const increaseBudgetBaseCost = 21
export const increaseBudgetIncrementCost = 21

// ── Box MBR ─────────────────────────────────────────────────────────

export const BOX_MBR_BASE_MICROALGOS = 2500
export const BOX_MBR_PER_BYTE_MICROALGOS = 400
const boxMbr = (keyLength: number, valueLength: number) =>
  BOX_MBR_BASE_MICROALGOS + BOX_MBR_PER_BYTE_MICROALGOS * (keyLength + valueLength)

/** Attestation header: inception, expiration, weakestKeyBits (uint64 each), payer (32). */
export const ATTESTATION_HEADER_BYTES = 56
/** Cache value: sha256(RRset), inception, expiry, weakestKeyBits. */
export const CACHE_VALUE_BYTES = 56

/** MbrManager credit box: 'c' ‖ address, uint64. */
export const CREDIT_BOX_MBR_MICROALGOS = boxMbr(33, 8)
/** A cache box, paid by the first prover of an RRset. */
export const CACHE_BOX_MBR_MICROALGOS = boxMbr(33, CACHE_VALUE_BYTES)
/** The anchor box, empty value. */
export const ANCHOR_BOX_MBR_MICROALGOS = boxMbr(33, 0)
/** A whitelist box: 'w' ‖ label, empty value. */
export const tldBoxMbrMicroAlgos = (label: string) => boxMbr(1 + new TextEncoder().encode(label).length, 0)
/** An attestation box, given the summed TXT RDATA lengths and RR count. */
export const attestationBoxMbrMicroAlgos = (rdataBytes: number, records: number) =>
  boxMbr(33, ATTESTATION_HEADER_BYTES + rdataBytes + 2 * records)

// ── Contract rules mirrored off-chain ───────────────────────────────

/** Past expiry, an attestation's payer has this long before anyone may prune it. */
export const PRUNE_GRACE_SECONDS = 30 * 24 * 60 * 60
/** A proven cache entry closer than this to expiry is refreshed by proveChain. */
export const DEFAULT_REFRESH_MARGIN_SECONDS = 60 * 60
/** Largest value the AVM holds: signed data, parents and attestations must fit. */
export const MAX_VALUE_BYTES = 4096
