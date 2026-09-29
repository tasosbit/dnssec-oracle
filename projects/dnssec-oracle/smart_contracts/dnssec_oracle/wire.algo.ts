import { Bytes, bytes, loggedAssert, op, uint64 } from '@algorandfoundation/algorand-typescript'
import {
  errClass,
  errIndex,
  errLabels,
  errOwner,
  errTime,
  errTxt,
  errType,
  errWildcard,
  errWire,
} from './errors.algo'

export const TYPE_TXT: uint64 = 16
export const TYPE_DS: uint64 = 43
export const TYPE_DNSKEY: uint64 = 48
const CLASS_IN: uint64 = 1

/** Fixed part of RRSIG RDATA, before the signer name. */
const RRSIG_FIXED: uint64 = 18

/**
 * A parsed `signedData`: RRSIG RDATA without the signature, then the RRset it covers.
 * Everything a method needs about names comes from here, never from arguments.
 */
export type SignedData = Readonly<{
  algorithm: uint64
  inception: uint64
  expiration: uint64
  signer: bytes
  owner: bytes
  ownerLabels: uint64
  /** The RRset: what the cache hashes, and what a child method gets as `parent`. */
  rrset: bytes
  /** RDATA of the RR at the requested index. */
  indexed: bytes
  /** For TXT: `uint16 rdlen ‖ rdata` per RR, the attestation body. Empty otherwise. */
  records: bytes
}>

/**
 * Read the uncompressed name at `at`: `[offset after it, label count]`.
 *
 * A label length byte must be below 0x40, which rejects compression pointers and the
 * extended label types. A `*` label is rejected anywhere: no wildcards. A name is at
 * most 255 bytes. Reading past the end fails the program.
 */
export function readName(data: bytes, at: uint64): readonly [uint64, uint64] {
  let pos = at
  let labels: uint64 = 0
  let length = op.getByte(data, pos)
  while (length !== 0) {
    loggedAssert(length < 0x40, errWire)
    loggedAssert(length !== 1 || op.getByte(data, pos + 1) !== 0x2a, errWildcard)
    pos += length + 1
    labels++
    length = op.getByte(data, pos)
  }
  const end: uint64 = pos + 1
  loggedAssert(end - at <= 255, errWire)
  return [end, labels]
}

/** Assert `name` is exactly one valid name, and return its label count. */
export function checkName(name: bytes): uint64 {
  const [end, labels] = readName(name, 0)
  loggedAssert(end === name.length, errWire)
  return labels
}

/**
 * Walk the RRset `data[start:]` from its first RR to the end: `[owner, owner label count,
 * RDATA of RR #index, TXT records]`. Every RR must share the first RR's owner, have type
 * `rrtype` and class IN, and the cursor must land exactly on the end.
 *
 * With `txt`, each RDATA must be well-formed character-strings, and the records come back
 * as `uint16 rdlen ‖ rdata` per RR.
 */
export function walkRRset(
  data: bytes,
  start: uint64,
  rrtype: uint64,
  index: uint64,
  txt: boolean,
): readonly [bytes, uint64, bytes, bytes] {
  const [ownerEnd, ownerLabels] = readName(data, start)
  const owner = op.extract(data, start, ownerEnd - start)
  let at = start
  let i: uint64 = 0
  let indexed = Bytes()
  let found = false
  let records = Bytes()
  while (at < data.length) {
    const [nameEnd] = readName(data, at)
    loggedAssert(op.extract(data, at, nameEnd - at) === owner, errOwner)
    loggedAssert(op.extractUint16(data, nameEnd) === rrtype, errType)
    loggedAssert(op.extractUint16(data, nameEnd + 2) === CLASS_IN, errClass)
    // TTL at nameEnd + 4 is not checked: the signature binds it
    const rdlength = op.extractUint16(data, nameEnd + 8)
    const rdataStart: uint64 = nameEnd + 10
    loggedAssert(rdataStart + rdlength <= data.length, errWire)
    if (i === index) {
      indexed = op.extract(data, rdataStart, rdlength)
      found = true
    }
    if (txt) {
      checkTxt(op.extract(data, rdataStart, rdlength))
      records = records.concat(op.extract(data, nameEnd + 8, rdlength + 2))
    }
    at = rdataStart + rdlength
    i++
  }
  loggedAssert(found, errIndex)
  return [owner, ownerLabels, indexed, records]
}

/** TXT RDATA: one or more character-strings whose lengths sum to the RDATA length. */
export function checkTxt(rdata: bytes): void {
  let at: uint64 = 0
  while (at < rdata.length) {
    at += op.getByte(rdata, at) + 1
  }
  loggedAssert(rdata.length > 0 && at === rdata.length, errTxt)
}

/**
 * Parse `data` as RRSIG RDATA without the signature, followed by the RRset it covers.
 * Checks what needs no key: type covered, labels, validity window at `now`, and the RRset
 * rules of `walkRRset`.
 */
export function parseSignedData(data: bytes, rrtype: uint64, index: uint64, now: uint64): SignedData {
  loggedAssert(op.extractUint16(data, 0) === rrtype, errType)
  const labels = op.getByte(data, 3)
  const expiration = op.extractUint32(data, 8)
  const inception = op.extractUint32(data, 12)
  loggedAssert(inception <= now && now <= expiration, errTime)
  const [signerEnd] = readName(data, RRSIG_FIXED)
  const [owner, ownerLabels, indexed, records] = walkRRset(data, signerEnd, rrtype, index, rrtype === TYPE_TXT)
  loggedAssert(labels === ownerLabels, errLabels)
  return {
    algorithm: op.getByte(data, 2),
    inception: inception,
    expiration: expiration,
    signer: op.extract(data, RRSIG_FIXED, signerEnd - RRSIG_FIXED),
    owner: owner,
    ownerLabels: ownerLabels,
    rrset: op.extract(data, signerEnd, data.length - signerEnd),
    indexed: indexed,
    records: records,
  }
}

/**
 * Whether `ancestor` is `name` or one of its ancestors, label by label: `example.com`
 * is not an ancestor of `ample.com`'s sibling `xample.com`. With `proper`, `name` itself
 * does not count. Both must be valid names.
 */
export function isAncestor(ancestor: bytes, name: bytes, proper: boolean): boolean {
  let at: uint64 = 0
  if (proper) {
    if (name.length === 1) return false
    at = op.getByte(name, 0) + 1
  }
  // only one label boundary leaves a suffix of the ancestor's length
  while (name.length - at > ancestor.length) {
    at += op.getByte(name, at) + 1
  }
  return name.length - at === ancestor.length && op.extract(name, at, ancestor.length) === ancestor
}

/** The rightmost label of a non-root name, without its length byte: the TLD. */
export function tldOf(name: bytes): bytes {
  let at: uint64 = 0
  let length = op.getByte(name, 0)
  while (at + length + 2 < name.length) {
    at += length + 1
    length = op.getByte(name, at)
  }
  return op.extract(name, at + 1, length)
}

/** Box key part for an RRset: `name ‖ uint16 type`. */
export function nameType(name: bytes, rrtype: uint64): bytes {
  return name.concat(op.extract(op.itob(rrtype), 6, 2))
}

/** RFC 4034 appendix B key tag of DNSKEY RDATA. */
export function keyTag(rdata: bytes): uint64 {
  let acc: uint64 = 0
  let i: uint64 = 0
  for (; i + 1 < rdata.length; i += 2) {
    acc += op.extractUint16(rdata, i)
  }
  if (i < rdata.length) acc += op.getByte(rdata, i) << 8
  acc += (acc >> 16) & 0xffff
  return acc & 0xffff
}
