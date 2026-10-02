import { Buffer } from 'buffer'

// the SDK hex-encodes with Buffer, at import time too (prover/anchors.ts)
globalThis.Buffer ??= Buffer
