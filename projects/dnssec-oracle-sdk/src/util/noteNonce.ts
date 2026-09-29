/**
 * Random note fragment to keep otherwise-identical transactions from colliding into one
 * duplicate txn ID — the node rejects a byte-identical txn as already-in-ledger while the
 * earlier one is inside its validity window.
 */
export const noteNonce = () => Math.floor(Math.random() * 100_000_000)
