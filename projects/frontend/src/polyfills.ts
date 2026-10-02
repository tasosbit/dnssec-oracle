import { Buffer } from 'buffer'

// the SDK hex-encodes with Buffer, at import time too (prover/anchors.ts)
globalThis.Buffer ??= Buffer
// Defly's WalletConnect v1 client reads Node's `global`
;(globalThis as { global?: typeof globalThis }).global ??= globalThis
