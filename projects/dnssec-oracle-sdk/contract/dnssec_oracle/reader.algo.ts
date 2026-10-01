import { Account, Application, Bytes, bytes, Global, op, uint64 } from '@algorandfoundation/algorand-typescript'
import { nameType, TYPE_DNSKEY, TYPE_DS } from './wire.algo'

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
 *   24      8     parentEpoch     uint64, epoch of the signer's DNSKEY cache entry when proven
 *   32      32    payer           who paid the box rent
 *   64      ...   records         per TXT RR: uint16 rdlen ‖ rdata
 *
 * Epochs. Cache box `r ‖ sha256(name ‖ uint16 type)` holds hash (0, 32 bytes), inception
 * (32), expiry (40), weakestKeyBits (48), epoch (56) and parentEpoch (64). An entry's epoch
 * changes whenever its RRset or its parent's epoch does, and the root DNSKEY entry's parent
 * is the oracle's `rootEpoch` global, which changes when a trusted root key is revoked. So a
 * new key set or DS anywhere above an attestation breaks one link of its chain.
 * attestationUsable walks the chain: pass the zones from the signer up to the TLD, and put
 * the attestation box, each zone's DNSKEY and DS box and the root DNSKEY box in the box
 * references (6 for `_tag.example.com`); a long chain can spread them over the group.
 *
 * Each rdata is one or more character-strings (length byte ‖ bytes). Walk the records from
 * offset 64: never substring-match the value, or a record's contents can pass for another.
 */

export const ATTESTATION_HEADER: uint64 = 64

/** The attestation value for `name`, and whether it exists. */
export function readAttestation(oracle: Application, name: bytes): readonly [bytes, boolean] {
  return op.AppBox.get(oracle, Bytes('t').concat(op.sha256(name)))
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

export function attestationParentEpoch(value: bytes): uint64 {
  return op.extractUint64(value, 24)
}

export function attestationPayer(value: bytes): Account {
  return Account(op.extract(value, 32, 32))
}

/** The oracle's current `rootEpoch`. */
export function oracleRootEpoch(oracle: Application): uint64 {
  const [epoch] = op.AppGlobal.getExUint64(oracle, Bytes('rootEpoch'))
  return epoch
}

const ROOT = Bytes.fromHex('00')
const CACHE_EPOCH: uint64 = 56

/** The parent epoch of the `name ‖ rrtype` cache entry if its epoch is `epoch`, else 0: never an epoch. */
function linkUp(oracle: Application, name: bytes, rrtype: uint64, epoch: uint64): uint64 {
  const [entry, exists] = op.AppBox.get(oracle, Bytes('r').concat(op.sha256(nameType(name, rrtype))))
  return exists && op.extractUint64(entry, CACHE_EPOCH) === epoch ? op.extractUint64(entry, CACHE_EPOCH + 8) : 0
}

/**
 * Whether no ancestor has changed since the attestation was proven: each link's epoch matches
 * its parent's current one, up to the oracle's `rootEpoch`. `zones` runs from the signer's zone
 * up to the TLD, the root implied. Caller-supplied is safe: each epoch names one box
 * generation, so only the real ancestors match, and a short or wrong list fails.
 */
export function attestationChainLive(oracle: Application, value: bytes, zones: bytes[]): boolean {
  let epoch = attestationParentEpoch(value)
  for (const zone of zones) {
    // the zone's keys, then the DS in its parent that vouches for them
    epoch = linkUp(oracle, zone, TYPE_DNSKEY, epoch)
    epoch = linkUp(oracle, zone, TYPE_DS, epoch)
  }
  return linkUp(oracle, ROOT, TYPE_DNSKEY, epoch) === oracleRootEpoch(oracle)
}

/**
 * Whether `oracle`'s attestation is usable now: its chain current (see attestationChainLive),
 * not expired, signed at most `maxAge` seconds ago, and no key on its path weaker than
 * `minKeyBits`. An attestation says a record was signed, not that it still exists: `maxAge`
 * is the consumer's bound on that gap.
 */
export function attestationUsable(
  oracle: Application,
  value: bytes,
  maxAge: uint64,
  minKeyBits: uint64,
  zones: bytes[],
): boolean {
  const now = Global.latestTimestamp
  return (
    now <= attestationExpiration(value) &&
    now <= attestationInception(value) + maxAge &&
    attestationWeakestKeyBits(value) >= minKeyBits &&
    attestationChainLive(oracle, value, zones)
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
