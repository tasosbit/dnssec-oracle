import { AlgorandClient } from '@algorandfoundation/algokit-utils'
import {
  ancestors,
  anchorHash,
  APP_SPEC,
  Attestation,
  buildQuery,
  buildTxtChain,
  bytesEqual,
  CacheEntry,
  chainLinks,
  concat,
  DnssecOracleReaderSDK,
  keyBits,
  nameFromWire,
  nameLength,
  nameToWire,
  parseDnskey,
  parseResponse,
  parseRrsig,
  ProofStep,
  rdataOf,
  readU16,
  Resolver,
  ROOT_KSK_2017,
  ROOT_KSK_2024,
  Rrsig,
  RRType,
  sha256,
  toHex,
  u16,
} from '@d13co/dnssec-oracle-sdk'
import { ABIMethod } from 'algosdk'

export type Network = 'testnet' | 'localnet'
export const DEFAULT_APP_ID: Record<Network, string> = { testnet: '772959888', localnet: '' }

export function makeSdk(network: Network, appId: string) {
  const algorand = network === 'testnet' ? AlgorandClient.testNet() : AlgorandClient.defaultLocalNet()
  return new DnssecOracleReaderSDK({ algorand, appId: BigInt(appId) })
}

export const DOH_RESOLVERS = {
  Cloudflare: 'https://cloudflare-dns.com/dns-query',
  Google: 'https://dns.google/dns-query',
  Quad9: 'https://dns.quad9.net/dns-query',
}

/** RFC 8484 DNS over HTTPS in wire format: the same messages the SDK's TCP resolver exchanges. */
export const dohResolver =
  (url: string): Resolver =>
  async (name, type) => {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
      body: buildQuery(name, type) as Uint8Array<ArrayBuffer>,
    })
    if (!res.ok) throw new Error(`DoH ${url}: HTTP ${res.status}`)
    return new Uint8Array(await res.arrayBuffer())
  }

export const typeName = (type: number) =>
  Object.entries(RRType).find(([, t]) => t === type)?.[0] ?? `TYPE${type}`

export function keyRole(flags: number) {
  const role = ({ 256: 'ZSK', 257: 'KSK' } as Record<number, string>)[flags & ~0x80] ?? `flags ${flags}`
  return flags & 0x80 ? `${role} (revoked)` : role
}

export function keySize(rdata: Uint8Array) {
  const { algorithm } = parseDnskey(rdata)
  if (algorithm === 13) return 'ECDSA P-256'
  return [5, 7, 8, 10].includes(algorithm) ? `RSA-${keyBits(rdata)}` : `algorithm ${algorithm}`
}

// ── Names ────────────────────────────────────────────────────────

/**
 * Box keys hold only hashes, so names come from the proof transactions themselves: each
 * proving method's first argument is the signed data, whose RRset names its owner. Returns
 * `sha256(owner ‖ type)` (cache) and `sha256(owner)` (attestation) hex, to a label.
 */
export async function provenNames(sdk: DnssecOracleReaderSDK): Promise<Map<string, string>> {
  const selectors = new Set(
    APP_SPEC.methods.filter((m) => m.args[0]?.name === 'signedData').map((m) => toHex(new ABIMethod(m).getSelector())),
  )
  const labels = new Map<string, string>()
  let next = ''
  // ponytail: scans every app call, up to 20k; an index of names off-chain if this grows
  for (let page = 0; page < 20; page++) {
    const res = await sdk.algorand.client.indexer
      .searchForTransactions()
      .applicationID(sdk.appId)
      .limit(1000)
      .nextToken(next)
      .do()
    for (const txn of res.transactions) {
      const args = txn.applicationTransaction?.applicationArgs
      if (!args || args.length < 2 || !selectors.has(toHex(args[0]))) continue
      try {
        const signedData = args[1].slice(2) // ABI byte[]: uint16 length, then the bytes
        const type = readU16(signedData, 0)
        const at = 18 + nameLength(signedData, 18) // after the RRSIG fields and signer name
        const owner = signedData.slice(at, at + nameLength(signedData, at))
        labels.set(toHex(sha256(concat(owner, u16(type)))), `${nameFromWire(owner)} ${typeName(type)}`)
        if (type === RRType.TXT) labels.set(toHex(sha256(owner)), nameFromWire(owner))
      } catch {
        // a failed or malformed submission: nothing to label
      }
    }
    if (!res.nextToken) break
    next = res.nextToken
  }
  return labels
}

/** Anchor ids (`sha256(alg ‖ pubkey)` hex) to a description, from IANA's keys and the live root key set. */
export async function anchorLabels(resolver: Resolver): Promise<Map<string, string>> {
  const labels = new Map([
    [toHex(anchorHash(ROOT_KSK_2017)), 'KSK-2017 (tag 20326)'],
    [toHex(anchorHash(ROOT_KSK_2024)), 'KSK-2024 (tag 38696)'],
  ])
  const { answers } = parseResponse(await resolver(new Uint8Array([0]), RRType.DNSKEY))
  for (const rr of answers.filter((rr) => rr.type === RRType.DNSKEY)) {
    const id = toHex(anchorHash(rr.rdata))
    const live = `${keyRole(parseDnskey(rr.rdata).flags)}, ${keySize(rr.rdata)}, in the root key set now`
    labels.set(id, labels.has(id) ? `${labels.get(id)} · ${live}` : live)
  }
  return labels
}

// ── Oracle against live DNS ──────────────────────────────────────

export interface Row {
  step: ProofStep
  /** The DNSKEY that signed this step. */
  key: Uint8Array
  sig: Rrsig
  liveHash: Uint8Array
  /** The oracle's side: a cache entry, or the attestation for the TXT step. */
  entry?: CacheEntry | Attestation
  /** The oracle holds exactly this RRset. */
  same: boolean
  /** The oracle's entry was proven under the entry above it as it stands now (epochs match). */
  linked: boolean
}

/** What the oracle holds for a name: the attestation, its verdict, and every cache entry above it. */
export interface OracleSide {
  now: number
  rootEpoch: bigint
  raw?: Attestation
  verified?: { attestation: Attestation; zones: Uint8Array[] }
  /** Why the raw attestation is not usable, when it is not. */
  reasons: string[]
  /** Cache entries of every ancestor's DNSKEY and DS, by cacheKey. */
  caches: Map<string, CacheEntry>
}

export interface Comparison extends OracleSide {
  name: string
  rows?: Row[]
}

const cacheKey = (owner: Uint8Array, type: number) => `${toHex(owner)} ${type}`

export async function oracleSide(
  sdk: DnssecOracleReaderSDK,
  name: string,
  { maxAge, minKeyBits }: { maxAge: number; minKeyBits: number },
): Promise<OracleSide> {
  const now = Math.floor(Date.now() / 1000)
  // every link a chain for this name could use, whichever zone signs it
  const links = chainLinks(ancestors(nameToWire(name)).slice(0, -1))
  const [raw, verified, { rootEpoch }, entries] = await Promise.all([
    sdk.getRawAttestation(name),
    sdk.getVerifiedAttestation(name, { maxAge, minKeyBits, now }),
    sdk.getState(),
    sdk.getRawCaches(links),
  ])
  const caches = new Map<string, CacheEntry>()
  links.forEach(([owner, type], i) => entries[i] && caches.set(cacheKey(owner, type), entries[i]))
  const reasons: string[] = []
  if (raw && !verified) {
    if (now > raw.expiration) reasons.push('expired: a signature on its chain has run out')
    if (now > raw.inception + maxAge) reasons.push(`signed longer ago than maxAge (${duration(maxAge)})`)
    if (raw.weakestKeyBits < minKeyBits) reasons.push(`a key on its chain is weaker than ${minKeyBits} bits`)
    if (!reasons.length) reasons.push('stale: a key set above it changed since it was proven, so it must be proven again')
  }
  return { now, rootEpoch, raw, verified, reasons, caches }
}

/** The chain for `name TXT` from live DNS, every signature verified here, under the oracle's own anchors. */
export async function liveChain(sdk: DnssecOracleReaderSDK, name: string, resolver: Resolver): Promise<ProofStep[]> {
  return buildTxtChain(name, resolver, { anchors: await sdk.trustedAnchors() })
}

/** Each live step next to the oracle's entry for the same record set. */
export function compareRows(steps: ProofStep[], { raw, caches, rootEpoch }: OracleSide): Row[] {
  const entries = steps.map((s) => (s.kind === 'txt' ? raw : caches.get(cacheKey(s.owner, s.type))))
  return steps.map((step, i) => {
    const entry = entries[i]
    const liveHash = sha256(step.rrset)
    const same =
      !!entry &&
      (step.kind === 'txt'
        ? sameSet((entry as Attestation).records, rdataOf(step.rrset))
        : bytesEqual((entry as CacheEntry).hash, liveHash))
    // the step above is always this one's parent: the signer's DNSKEY, or the zone's DS
    const linked =
      !!entry && (step.kind === 'root' ? BigInt(entry.parentEpoch) === rootEpoch : entry.parentEpoch === (entries[i - 1] as CacheEntry | undefined)?.epoch)
    return { step, entry, same, linked, liveHash, key: signingKey(step), sig: rrsigOf(step) }
  })
}

const sameSet = (a: Uint8Array[], b: Uint8Array[]) =>
  a.map(toHex).sort().join() === b.map(toHex).sort().join()

const signingKey = (step: ProofStep) =>
  rdataOf(step.kind === 'root' || step.kind === 'dnskey' ? step.rrset : step.parent)[step.keyIndex]

/** The RRSIG fields: signed data minus the RRset it covers. */
const rrsigOf = (step: ProofStep) => parseRrsig(step.signedData.slice(0, step.signedData.length - step.rrset.length))

// ── Formatting ───────────────────────────────────────────────────

export function duration(seconds: number) {
  const s = Math.abs(seconds)
  if (s < 3600) return `${Math.round(s / 60)}m`
  if (s < 86400 * 2) return `${Math.round(s / 3600)}h`
  return `${Math.round(s / 86400)}d`
}

export const isoTime = (t: number) => new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
export const relTime = (t: number, now = Date.now() / 1000) => (t > now ? `in ${duration(t - now)}` : `${duration(now - t)} ago`)
