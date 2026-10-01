import { createPublicKey, verify } from 'node:crypto'
import { rsaMontgomeryHint } from '@d13co/puya-ts-utils/rsaHint'
import { MAX_VALUE_BYTES } from '../constants.js'
import { parseResponse, Resolver } from './dns.js'
import {
  ancestors,
  bitLength,
  bytesEqual,
  canonicalRRset,
  concat,
  DNSKEY_REVOKE,
  DNSKEY_ZONE,
  dsDigest,
  keyTag,
  nameFromWire,
  nameToWire,
  parseDnskey,
  parseDs,
  parseRrsig,
  rdataOf,
  rsaKeyParts,
  Rrsig,
  RRType,
  sortedRdata,
  toHex,
} from './wire.js'

/** P-256 counts as this many RSA bits in `weakestKeyBits`. Keep in sync with the contract. */
export const ECDSA_P256_KEY_BITS = 3072

interface StepBase {
  /** Owner name, wire format. */
  owner: Uint8Array
  /** RR type proven. */
  type: number
  signedData: Uint8Array
  signature: Uint8Array
  /** Montgomery hint for RSA keys, empty for ECDSA. */
  hint: Uint8Array
  /** Index of the signing key in its DNSKEY RRset. */
  keyIndex: number
  /** Canonical RRset: what the cache hashes, and a child step's `parent`. */
  rrset: Uint8Array
  inception: number
  expiration: number
  keyBits: number
}

export type ProofStep =
  | (StepBase & { kind: 'root' })
  | (StepBase & { kind: 'ds'; parent: Uint8Array })
  | (StepBase & { kind: 'dnskey'; parent: Uint8Array; dsIndex: number })
  | (StepBase & { kind: 'txt'; parent: Uint8Array })

export interface ChainOptions {
  /**
   * Root trust anchors as DNSKEY RDATA, or a predicate over root DNSKEYs (see
   * `DnssecOracleReaderSDK.trustedAnchors`); the root RRSIG must come from one of them.
   */
  anchors: Uint8Array[] | ((dnskeyRdata: Uint8Array) => boolean)
  /** Unix seconds the signatures must be valid at. Defaults to now. */
  now?: number
}

/** Why a key cannot sign for the oracle, or undefined if it can. Mirrors the contract's checks. */
export function keyProblem(dnskeyRdata: Uint8Array, algorithm: number): string | undefined {
  const key = parseDnskey(dnskeyRdata)
  if (!(key.flags & DNSKEY_ZONE)) return 'zone flag clear'
  if (key.flags & DNSKEY_REVOKE) return 'revoked'
  if (key.protocol !== 3) return 'protocol is not 3'
  if (key.algorithm !== algorithm) return 'algorithm differs from the RRSIG'
  if (key.algorithm === 13) return key.publicKey.length === 64 ? undefined : 'P-256 key is not 64 bytes'
  if (key.algorithm !== 8) return `algorithm ${key.algorithm} unsupported`
  const { exponent, modulus } = rsaKeyParts(key.publicKey)
  if (key.publicKey[0] !== 3 || toHex(exponent) !== '010001') return 'RSA exponent is not 65537 in the 1-byte length form'
  if (modulus[0] === 0) return 'RSA modulus has a leading zero'
  const bits = bitLength(modulus)
  if (bits < 1024 || bits > 2048) return `RSA-${bits} is outside 1024 to 2048 bits`
  return undefined
}

export function keyBits(dnskeyRdata: Uint8Array): number {
  const key = parseDnskey(dnskeyRdata)
  return key.algorithm === 13 ? ECDSA_P256_KEY_BITS : bitLength(rsaKeyParts(key.publicKey).modulus)
}

export function montgomeryHint(dnskeyRdata: Uint8Array): Uint8Array {
  const key = parseDnskey(dnskeyRdata)
  return key.algorithm === 8 ? rsaMontgomeryHint(rsaKeyParts(key.publicKey).modulus) : new Uint8Array(0)
}

const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url')

/** Verify a DNSSEC signature locally: algorithm 8 or 13. */
export function verifySignature(dnskeyRdata: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  const key = parseDnskey(dnskeyRdata)
  try {
    if (key.algorithm === 8) {
      const { exponent, modulus } = rsaKeyParts(key.publicKey)
      const pub = createPublicKey({ key: { kty: 'RSA', n: b64url(modulus), e: b64url(exponent) }, format: 'jwk' })
      return verify('sha256', data, pub, signature)
    }
    if (key.algorithm === 13) {
      const [x, y] = [key.publicKey.slice(0, 32), key.publicKey.slice(32)]
      const pub = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64url(x), y: b64url(y) }, format: 'jwk' })
      return verify('sha256', data, { key: pub, dsaEncoding: 'ieee-p1363' }, signature)
    }
  } catch {
    return false
  }
  return false
}

/** An RRset and its RRSIGs valid at `now`, newest first. */
async function fetchSigned(resolver: Resolver, owner: Uint8Array, type: number, now: number) {
  const { rcode, answers } = parseResponse(await resolver(owner, type))
  const label = `${nameFromWire(owner)} ${type}`
  if (rcode !== 0) throw new Error(`${label}: DNS rcode ${rcode}`)
  const own = answers.filter((rr) => bytesEqual(rr.owner, owner))
  if (own.some((rr) => rr.type === RRType.CNAME)) throw new Error(`${label}: CNAME, which the oracle does not follow`)
  const rrs = own.filter((rr) => rr.type === type)
  if (rrs.length === 0) throw new Error(`${label}: no records`)
  const sigs = own
    .filter((rr) => rr.type === RRType.RRSIG)
    .map((rr) => parseRrsig(rr.rdata))
    .filter((s) => s.typeCovered === type && s.inception <= now && now <= s.expiration)
    // newest first: an older one can fail OLD against what is stored
    .sort((a, b) => b.inception - a.inception)
  if (sigs.length === 0) throw new Error(`${label}: no RRSIG valid at ${now}`)
  return { rrs, sigs }
}

/** The newest RRSIG that a key in `keys` both may make and did make. */
function pick(sigs: Rrsig[], rrs: Parameters<typeof canonicalRRset>[0], keys: Uint8Array[], allowed: (k: Uint8Array) => boolean) {
  const problems: string[] = []
  for (const sig of sigs) {
    const rrset = canonicalRRset(rrs, sig.originalTtl)
    const signedData = concat(sig.header, rrset)
    for (const [keyIndex, key] of keys.entries()) {
      if (keyTag(key) !== sig.keyTag || !allowed(key)) continue
      const problem = keyProblem(key, sig.algorithm)
      if (problem) {
        problems.push(`key ${sig.keyTag}: ${problem}`)
      } else if (verifySignature(key, signedData, sig.signature)) {
        return { sig, rrset, signedData, keyIndex, key }
      }
    }
  }
  throw new Error(`no usable signature${problems.length ? ` (${problems.join('; ')})` : ''}`)
}

function stepOf(p: ReturnType<typeof pick>, owner: Uint8Array, type: number, parentBits = Infinity) {
  if (p.signedData.length > MAX_VALUE_BYTES) {
    const size = p.signedData.length
    throw new Error(`${nameFromWire(owner)} ${type}: signed data is ${size} bytes, over the ${MAX_VALUE_BYTES}-byte argument limit`)
  }
  return {
    owner,
    type,
    signedData: p.signedData,
    signature: p.sig.signature,
    hint: montgomeryHint(p.key),
    keyIndex: p.keyIndex,
    rrset: p.rrset,
    inception: p.sig.inception,
    expiration: p.sig.expiration,
    keyBits: Math.min(keyBits(p.key), parentBits),
  }
}

/**
 * Build every proof step for `name TXT`, root first: `. DNSKEY`, then `DS` and `DNSKEY`
 * for each zone down to the signer, then the TXT. The oracle caches all but the last,
 * so `DnssecOracleSDK.proveChain` skips steps whose cache is still fresh.
 *
 * Untrusted: every choice made here is checked again on-chain.
 */
export async function buildTxtChain(name: string, resolver: Resolver, options: ChainOptions): Promise<ProofStep[]> {
  const now = options.now ?? Math.floor(Date.now() / 1000)
  const zones = new Map<string, ProofStep[]>()
  const owner = nameToWire(name)

  const fetch = (owner: Uint8Array, type: number) => fetchSigned(resolver, owner, type, now)

  /** Steps proving `zone DNSKEY`, ancestors first; the last one's RRset holds the zone's keys. */
  async function dnskeySteps(zone: Uint8Array): Promise<ProofStep[]> {
    const cached = zones.get(toHex(zone))
    if (cached) return cached
    const { rrs, sigs } = await fetch(zone, RRType.DNSKEY)
    const keys = sortedRdata(rrs)
    let steps: ProofStep[]
    if (zone.length === 1) {
      const { anchors } = options
      const isAnchor =
        typeof anchors === 'function'
          ? anchors
          : (k: Uint8Array) => anchors.some((a) => bytesEqual(parseDnskey(a).publicKey, parseDnskey(k).publicKey))
      steps = [{ kind: 'root', ...stepOf(pick(sigs, rrs, keys, isAnchor), zone, RRType.DNSKEY) }]
    } else {
      const ds = await fetch(zone, RRType.DS)
      const dsSig = ds.sigs.find((s) => ancestors(zone).slice(1).some((a) => bytesEqual(a, s.signer)))
      if (!dsSig) throw new Error(`${nameFromWire(zone)} DS: not signed by an ancestor`)
      const above = await dnskeySteps(dsSig.signer)
      const signerStep = above[above.length - 1]
      const dsPick = pick(
        ds.sigs.filter((s) => bytesEqual(s.signer, dsSig.signer)),
        ds.rrs,
        rdataOf(signerStep.rrset),
        () => true,
      )
      const dsStep: ProofStep = {
        kind: 'ds',
        ...stepOf(dsPick, zone, RRType.DS, signerStep.keyBits),
        parent: signerStep.rrset,
      }
      const dsRecords = rdataOf(dsStep.rrset).map(parseDs)
      const dsIndexOf = (k: Uint8Array) =>
        dsRecords.findIndex(
          (d) =>
            d.digestType === 2 &&
            d.keyTag === keyTag(k) &&
            d.algorithm === parseDnskey(k).algorithm &&
            bytesEqual(d.digest, dsDigest(zone, k)),
        )
      const own = pick(
        sigs.filter((s) => bytesEqual(s.signer, zone)),
        rrs,
        keys,
        (k) => dsIndexOf(k) >= 0,
      )
      const dnskeyStep: ProofStep = {
        kind: 'dnskey',
        ...stepOf(own, zone, RRType.DNSKEY, dsStep.keyBits),
        parent: dsStep.rrset,
        dsIndex: dsIndexOf(own.key),
      }
      steps = [...above, dsStep, dnskeyStep]
    }
    zones.set(toHex(zone), steps)
    return steps
  }

  const txt = await fetch(owner, RRType.TXT)
  const errors: string[] = []
  for (const signer of new Set(txt.sigs.map((s) => toHex(s.signer)))) {
    const sigs = txt.sigs.filter((s) => toHex(s.signer) === signer)
    try {
      const above = await dnskeySteps(sigs[0].signer)
      const signerStep = above[above.length - 1]
      const p = pick(sigs, txt.rrs, rdataOf(signerStep.rrset), () => true)
      return [
        ...above,
        { kind: 'txt', ...stepOf(p, owner, RRType.TXT, signerStep.keyBits), parent: signerStep.rrset },
      ]
    } catch (e) {
      errors.push((e as Error).message)
    }
  }
  throw new Error(`${name} TXT: ${errors.join('; ')}`)
}

/**
 * Every root DNSKEY step DNS offers: one per RRSIG that verifies under a key of the RRset,
 * newest first, revoked keys included. The rollover watcher (`maintainAnchors`) picks the
 * root proof and the revocations from these.
 */
export async function buildRootSteps(resolver: Resolver, { now = Math.floor(Date.now() / 1000) } = {}): Promise<ProofStep[]> {
  const root = new Uint8Array([0])
  const { rrs, sigs } = await fetchSigned(resolver, root, RRType.DNSKEY, now)
  const keys = sortedRdata(rrs)
  const steps: ProofStep[] = []
  for (const sig of sigs) {
    const rrset = canonicalRRset(rrs, sig.originalTtl)
    const signedData = concat(sig.header, rrset)
    for (const [keyIndex, key] of keys.entries()) {
      if (keyTag(key) === sig.keyTag && verifySignature(key, signedData, sig.signature)) {
        steps.push({ kind: 'root', ...stepOf({ sig, rrset, signedData, keyIndex, key }, root, RRType.DNSKEY) })
      }
    }
  }
  return steps
}
