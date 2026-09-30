import { createHash } from 'node:crypto'

/** RR types the oracle deals with. */
export const RRType = { CNAME: 5, TXT: 16, OPT: 41, DS: 43, RRSIG: 46, DNSKEY: 48 } as const
export const CLASS_IN = 1

/** DNSKEY flags: Zone Key, REVOKE, Secure Entry Point. */
export const DNSKEY_ZONE = 0x0100
export const DNSKEY_REVOKE = 0x0080
export const DNSKEY_SEP = 0x0001

/** A resource record with its RDATA kept raw. `owner` is wire format, lowercase. */
export interface RR {
  owner: Uint8Array
  type: number
  class: number
  ttl: number
  rdata: Uint8Array
}

export interface Rrsig {
  typeCovered: number
  algorithm: number
  labels: number
  originalTtl: number
  expiration: number
  inception: number
  keyTag: number
  signer: Uint8Array
  signature: Uint8Array
  /** The RDATA without the signature: the head of the signed data. */
  header: Uint8Array
}

export interface Dnskey {
  flags: number
  protocol: number
  algorithm: number
  publicKey: Uint8Array
}

export interface Ds {
  keyTag: number
  algorithm: number
  digestType: number
  digest: Uint8Array
}

export const sha256 = (data: Uint8Array) => new Uint8Array(createHash('sha256').update(data).digest())

export const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export const u16 = (n: number) => new Uint8Array([n >> 8, n & 0xff])
export const u32 = (n: number) => new Uint8Array([n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
export const readU16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1]
export const readU32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0

export const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex')
export const fromHex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'))
export const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i])

/** `example.com`, `example.com.` or `.` to lowercase wire format. */
export function nameToWire(name: string): Uint8Array {
  const labels = name
    .toLowerCase()
    .split('.')
    .filter((l) => l !== '')
  const parts = labels.map((l) => {
    const bytes = new TextEncoder().encode(l)
    if (bytes.length > 63) throw new Error(`label over 63 bytes: ${l}`)
    return concat(new Uint8Array([bytes.length]), bytes)
  })
  const wire = concat(...parts, new Uint8Array([0]))
  if (wire.length > 255) throw new Error(`name over 255 bytes: ${name}`)
  return wire
}

/** Wire format to presentation, with the trailing dot. */
export function nameFromWire(wire: Uint8Array): string {
  const labels: string[] = []
  for (let at = 0; wire[at] !== 0; at += 1 + wire[at]) {
    labels.push(new TextDecoder().decode(wire.slice(at + 1, at + 1 + wire[at])))
  }
  return labels.join('.') + '.'
}

/** Lowercase an uncompressed wire-format name (ASCII only, as DNS canonical form does). */
export function lowercaseName(wire: Uint8Array): Uint8Array {
  const out = wire.slice()
  for (let at = 0; out[at] !== 0; at += 1 + out[at]) {
    for (let i = at + 1; i <= at + out[at]; i++) if (out[i] >= 0x41 && out[i] <= 0x5a) out[i] |= 0x20
  }
  return out
}

/** Length of the uncompressed name starting at `at`. */
export function nameLength(b: Uint8Array, at: number): number {
  let end = at
  while (b[end] !== 0) {
    if (b[end] >= 0x40) throw new Error('compressed or extended label in a name')
    end += 1 + b[end]
  }
  return end + 1 - at
}

export function labelCount(wire: Uint8Array): number {
  let n = 0
  for (let at = 0; wire[at] !== 0; at += 1 + wire[at]) n++
  return n
}

/** The label boundaries of `wire`, root last: `a.b.` → [`a.b.`, `b.`, `.`]. */
export function ancestors(wire: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []
  let at = 0
  for (; wire[at] !== 0; at += 1 + wire[at]) out.push(wire.slice(at))
  out.push(wire.slice(at))
  return out
}

export function parseRrsig(rdata: Uint8Array): Rrsig {
  const signerLength = nameLength(rdata, 18)
  const headerLength = 18 + signerLength
  return {
    typeCovered: readU16(rdata, 0),
    algorithm: rdata[2],
    labels: rdata[3],
    originalTtl: readU32(rdata, 4),
    expiration: readU32(rdata, 8),
    inception: readU32(rdata, 12),
    keyTag: readU16(rdata, 16),
    signer: lowercaseName(rdata.slice(18, headerLength)),
    signature: rdata.slice(headerLength),
    header: concat(rdata.slice(0, 18), lowercaseName(rdata.slice(18, headerLength))),
  }
}

export function parseDnskey(rdata: Uint8Array): Dnskey {
  return { flags: readU16(rdata, 0), protocol: rdata[2], algorithm: rdata[3], publicKey: rdata.slice(4) }
}

export function parseDs(rdata: Uint8Array): Ds {
  return { keyTag: readU16(rdata, 0), algorithm: rdata[2], digestType: rdata[3], digest: rdata.slice(4) }
}

/** RFC 3110: `[exponent, modulus]` of an RSA DNSKEY public key field. */
export function rsaKeyParts(publicKey: Uint8Array): { exponent: Uint8Array; modulus: Uint8Array } {
  let offset = 1
  let exponentLength = publicKey[0]
  if (exponentLength === 0) {
    exponentLength = readU16(publicKey, 1)
    offset = 3
  }
  return {
    exponent: publicKey.slice(offset, offset + exponentLength),
    modulus: publicKey.slice(offset + exponentLength),
  }
}

/** Bit length of a big-endian unsigned integer. */
export function bitLength(b: Uint8Array): number {
  let i = 0
  while (i < b.length && b[i] === 0) i++
  return i === b.length ? 0 : 8 * (b.length - i - 1) + (32 - Math.clz32(b[i]))
}

/** RFC 4034 appendix B. */
export function keyTag(dnskeyRdata: Uint8Array): number {
  let acc = 0
  for (let i = 0; i < dnskeyRdata.length; i++) acc += i & 1 ? dnskeyRdata[i] : dnskeyRdata[i] << 8
  acc += (acc >> 16) & 0xffff
  return acc & 0xffff
}

/** DS digest type 2: SHA-256 of owner name ‖ DNSKEY RDATA. */
export const dsDigest = (owner: Uint8Array, dnskeyRdata: Uint8Array) => sha256(concat(owner, dnskeyRdata))

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]
  return a.length - b.length
}

/**
 * RFC 4034 §6.3: an RRset in canonical form, as it is signed. Every RR shares one owner,
 * type and class; TTLs are the RRSIG's original TTL; RDATA sorts as unsigned bytes and
 * duplicates collapse.
 */
export function canonicalRRset(rrs: RR[], originalTtl: number): Uint8Array {
  if (rrs.length === 0) throw new Error('empty RRset')
  const rdatas = [...new Map(sortedRdata(rrs).map((r) => [toHex(r), r])).values()]
  const { owner, type } = rrs[0]
  const head = concat(lowercaseName(owner), u16(type), u16(CLASS_IN), u32(originalTtl))
  return concat(...rdatas.map((r) => concat(head, u16(r.length), r)))
}

/** RDATA of `rrs` in canonical order, deduplicated: the order RR indexes refer to. */
export function sortedRdata(rrs: RR[]): Uint8Array[] {
  const unique = [...new Map(rrs.map((r) => [toHex(r.rdata), r.rdata])).values()]
  return unique.sort(compareBytes)
}

/** Walk a canonical RRset and return each RR's RDATA, in order. */
export function rdataOf(rrset: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []
  for (let at = 0; at < rrset.length; ) {
    at += nameLength(rrset, at) + 8
    const length = readU16(rrset, at)
    out.push(rrset.slice(at + 2, at + 2 + length))
    at += 2 + length
  }
  return out
}

/** TXT RDATA as its character-strings. */
export function txtStrings(rdata: Uint8Array): string[] {
  const out: string[] = []
  for (let at = 0; at < rdata.length; at += 1 + rdata[at]) {
    out.push(new TextDecoder().decode(rdata.slice(at + 1, at + 1 + rdata[at])))
  }
  return out
}

/** One TXT RDATA holding `text`, split into 255-byte character-strings. */
export function txtRdata(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text)
  const parts: Uint8Array[] = []
  for (let at = 0; at === 0 || at < bytes.length; at += 255) {
    const chunk = bytes.slice(at, at + 255)
    parts.push(concat(new Uint8Array([chunk.length]), chunk))
  }
  return concat(...parts)
}
