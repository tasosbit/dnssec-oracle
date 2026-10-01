import { Address, encodeAddress } from 'algosdk'
import { concat, parseDnskey, RRType, sha256, txtStrings, u16 } from './prover/wire.js'
import { ATTESTATION_HEADER_BYTES } from './constants.js'

const prefix = (p: string) => new TextEncoder().encode(p)

/** An anchor's box key: `sha256(alg ‖ pubkey)`, so the REVOKE flag does not move it. */
export const anchorHash = (dnskeyRdata: Uint8Array) => {
  const key = parseDnskey(dnskeyRdata)
  return sha256(concat(new Uint8Array([key.algorithm]), key.publicKey))
}

/** Box names, as the contract derives them. `name` is wire format, lowercase. */
export const boxNames = {
  anchor: (dnskeyRdata: Uint8Array) => concat(prefix('a'), anchorHash(dnskeyRdata)),
  anchorByHash: (keyHash: Uint8Array) => concat(prefix('a'), keyHash),
  cache: (name: Uint8Array, type: number) => concat(prefix('r'), sha256(concat(name, u16(type)))),
  attestation: (name: Uint8Array) => concat(prefix('t'), sha256(name)),
  credit: (account: string | Address) => concat(prefix('c'), Address.fromString(account.toString()).publicKey),
  /** The cache boxes an attestation's chain walk reads: see chainLinks. */
  chain: (zones: Uint8Array[]) => chainLinks(zones).map(([name, type]) => boxNames.cache(name, type)),
}

/**
 * The cache entries above an attestation, child first: each zone's DNSKEY then DS, from the
 * signer's zone up to the TLD, then the root DNSKEY. `zones` is wire format.
 */
export const chainLinks = (zones: Uint8Array[]): [Uint8Array, number][] => [
  ...zones.flatMap((zone): [Uint8Array, number][] => [
    [zone, RRType.DNSKEY],
    [zone, RRType.DS],
  ]),
  [new Uint8Array([0]), RRType.DNSKEY],
]

/** RFC 5011 anchor states, as the contract numbers them. No box: Start, or Removed. */
export enum AnchorState {
  AddPend = 1,
  Valid = 2,
  Missing = 3,
  Revoked = 4,
}

export interface AnchorEntry {
  state: AnchorState
  /** When the state was entered, block time. */
  since: number
}

/** Whether proveRoot accepts signatures by this anchor. */
export const isTrusted = (anchor?: AnchorEntry) =>
  anchor?.state === AnchorState.Valid || anchor?.state === AnchorState.Missing

export interface CacheEntry {
  /** sha256 of the proven RRset. */
  hash: Uint8Array
  inception: number
  /** min(this RRSIG's expiration, the parent entry's expiry) */
  expiry: number
  weakestKeyBits: number
  /** This entry's generation: fresh whenever its hash or its parent's epoch changes. */
  epoch: number
  /** The epoch of the entry it was verified against, or the contract's rootEpoch for the root. */
  parentEpoch: number
}

export interface Attestation {
  inception: number
  expiration: number
  weakestKeyBits: number
  /** The signer's DNSKEY cache entry epoch when proven: see DnssecOracleReaderSDK.attestationChainLive. */
  parentEpoch: number
  payer: string
  /** TXT RDATA, one per RR, in stored (canonical) order. */
  records: Uint8Array[]
  /** Each record's character-strings, joined: the text most consumers want. */
  texts: string[]
}

const view = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength)
const u64 = (b: Uint8Array, at: number) => Number(view(b).getBigUint64(at))

export function decodeAnchor(value: Uint8Array): AnchorEntry {
  return { state: u64(value, 0), since: u64(value, 8) }
}

export function decodeCache(value: Uint8Array): CacheEntry {
  return {
    hash: value.slice(0, 32),
    inception: u64(value, 32),
    expiry: u64(value, 40),
    weakestKeyBits: u64(value, 48),
    epoch: u64(value, 56),
    parentEpoch: u64(value, 64),
  }
}

/**
 * Off-chain reference reader for an attestation box: the header, then records walked by
 * length from offset 64. Never substring-match the raw value.
 */
export function decodeAttestation(value: Uint8Array): Attestation {
  const records: Uint8Array[] = []
  for (let at = ATTESTATION_HEADER_BYTES; at < value.length; ) {
    const length = (value[at] << 8) | value[at + 1]
    records.push(value.slice(at + 2, at + 2 + length))
    at += 2 + length
  }
  return {
    inception: u64(value, 0),
    expiration: u64(value, 8),
    weakestKeyBits: u64(value, 16),
    parentEpoch: u64(value, 24),
    payer: encodeAddress(value.slice(32, 64)),
    records,
    texts: records.map((r) => txtStrings(r).join('')),
  }
}
