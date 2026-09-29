import { Account, Application, Bytes, bytes, Global, op, uint64 } from '@algorandfoundation/algorand-typescript'
import { tldOf } from './wire.algo'

/*
 * Reference reader for attestation boxes, for contracts that consume the oracle. The
 * oracle enables ForeignBoxReads on itself, so any app can read these boxes directly.
 * Pin the oracle's app ID: never read from an app the caller names, or any app with a
 * forged `t` box passes.
 *
 * Box `t ‖ sha256(name)`, where `name` is the owner in wire format, lowercase, with its
 * terminating zero byte. The layout is the public API:
 *
 *   offset  size  field
 *   0       8     inception       uint64, the TXT RRSIG's inception
 *   8       8     expiration      uint64, min over the chain of RRSIG expirations
 *   16      8     weakestKeyBits  uint64, weakest key on the path; P-256 counts as 3072
 *   24      32    payer           who paid the box rent
 *   56      ...   records         per TXT RR: uint16 rdlen ‖ rdata
 *
 * Each rdata is one or more character-strings (length byte ‖ bytes). Walk the records from
 * offset 56: never substring-match the value, or a record's contents can pass for another.
 */

export const ATTESTATION_HEADER: uint64 = 56

/** The attestation value for `name`, and whether it exists. */
export function readAttestation(oracle: Application, name: bytes): readonly [bytes, boolean] {
  return op.AppBox.get(oracle, Bytes('t').concat(op.sha256(name)))
}

/**
 * Whether `name`'s TLD is still whitelisted, from box `w ‖ TLD label`. After `removeTld` an
 * attestation stays readable until someone prunes it: check this too.
 */
export function tldListed(oracle: Application, name: bytes): boolean {
  const [, exists] = op.AppBox.length(oracle, Bytes('w').concat(tldOf(name)))
  return exists
}

export function attestationInception(value: bytes): uint64 {
  return op.extractUint64(value, 0)
}

export function attestationExpiration(value: bytes): uint64 {
  return op.extractUint64(value, 8)
}

export function attestationWeakestKeyBits(value: bytes): uint64 {
  return op.extractUint64(value, 16)
}

export function attestationPayer(value: bytes): Account {
  return Account(op.extract(value, 24, 32))
}

/**
 * Whether the attestation is usable now: not expired, signed at most `maxAge` seconds ago,
 * and no key on its path weaker than `minKeyBits`. An attestation says a record was
 * signed, not that it still exists: `maxAge` is the consumer's bound on that gap.
 */
export function attestationUsable(value: bytes, maxAge: uint64, minKeyBits: uint64): boolean {
  const now = Global.latestTimestamp
  return (
    now <= attestationExpiration(value) &&
    now <= attestationInception(value) + maxAge &&
    attestationWeakestKeyBits(value) >= minKeyBits
  )
}

/** Whether one of the attestation's TXT records has exactly this RDATA. */
export function attestationHasRecord(value: bytes, rdata: bytes): boolean {
  let at = ATTESTATION_HEADER
  while (at < value.length) {
    const length = op.extractUint16(value, at)
    if (length === rdata.length && op.extract(value, at + 2, length) === rdata) return true
    at += length + 2
  }
  return false
}

/** TXT RDATA holding `text` as a single character-string: up to 255 bytes. */
export function txtRdata(text: bytes): bytes {
  return op.extract(op.itob(text.length), 7, 1).concat(text)
}
