import { Address, encodeAddress } from 'algosdk'
import { concat, parseDnskey, sha256, txtStrings, u16 } from './prover/wire.js'
import { ATTESTATION_HEADER_BYTES } from './constants.js'

const prefix = (p: string) => new TextEncoder().encode(p)

/** Box names, as the contract derives them. `name` is wire format, lowercase. */
export const boxNames = {
  anchor: (dnskeyRdata: Uint8Array) => {
    const key = parseDnskey(dnskeyRdata)
    return concat(prefix('a'), sha256(concat(new Uint8Array([key.algorithm]), key.publicKey)))
  },
  tld: (label: string) => concat(prefix('w'), new TextEncoder().encode(label.toLowerCase())),
  cache: (name: Uint8Array, type: number) => concat(prefix('r'), sha256(concat(name, u16(type)))),
  attestation: (name: Uint8Array) => concat(prefix('t'), sha256(name)),
  credit: (account: string | Address) => concat(prefix('c'), Address.fromString(account.toString()).publicKey),
}

export interface CacheEntry {
  /** sha256 of the proven RRset. */
  hash: Uint8Array
  inception: number
  /** min(this RRSIG's expiration, the parent entry's expiry) */
  expiry: number
  weakestKeyBits: number
}

export interface Attestation {
  inception: number
  expiration: number
  weakestKeyBits: number
  payer: string
  /** TXT RDATA, one per RR, in stored (canonical) order. */
  records: Uint8Array[]
  /** Each record's character-strings, joined: the text most consumers want. */
  texts: string[]
}

const view = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength)
const u64 = (b: Uint8Array, at: number) => Number(view(b).getBigUint64(at))

export function decodeCache(value: Uint8Array): CacheEntry {
  return { hash: value.slice(0, 32), inception: u64(value, 32), expiry: u64(value, 40), weakestKeyBits: u64(value, 48) }
}

/**
 * Off-chain reference reader for an attestation box: the header, then records walked by
 * length from offset 56. Never substring-match the raw value.
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
    payer: encodeAddress(value.slice(24, 56)),
    records,
    texts: records.map((r) => txtStrings(r).join('')),
  }
}
