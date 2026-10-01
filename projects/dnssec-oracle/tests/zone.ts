import { generateKeyPairSync, KeyObject, sign } from 'node:crypto'
import {
  canonicalRRset,
  captureKey,
  CLASS_IN,
  concat,
  dsDigest,
  keyTag,
  labelCount,
  nameToWire,
  Resolver,
  RR,
  RRType,
  u16,
  u32,
} from '@d13co/dnssec-oracle-sdk'

/*
 * A synthetic DNSSEC world for tests: keys generated and RRsets signed at test time, so
 * signatures are valid on LocalNet now, served through a Resolver as real DNS messages.
 */

export interface TestKey {
  rdata: Uint8Array
  privateKey: KeyObject
  algorithm: number
}

const fromB64url = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'))

export function rsaKey({ bits = 2048, flags = 257, exponent = 65537 } = {}): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: bits, publicExponent: exponent })
  const jwk = publicKey.export({ format: 'jwk' })
  const e = fromB64url(jwk.e!)
  const n = fromB64url(jwk.n!)
  const field = concat(new Uint8Array([e.length]), e, n)
  return { rdata: dnskeyRdata(flags, 8, field), privateKey, algorithm: 8 }
}

export function ecKey({ flags = 257 } = {}): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const jwk = publicKey.export({ format: 'jwk' })
  return { rdata: dnskeyRdata(flags, 13, concat(fromB64url(jwk.x!), fromB64url(jwk.y!))), privateKey, algorithm: 13 }
}

export const dnskeyRdata = (flags: number, algorithm: number, publicKey: Uint8Array) =>
  concat(u16(flags), new Uint8Array([3, algorithm]), publicKey)

/** The same key with other flags: e.g. 385 to revoke it. */
export const withFlags = (key: TestKey, flags: number): TestKey => ({
  ...key,
  rdata: concat(u16(flags), key.rdata.slice(2)),
})

/** DS RDATA for `key` at `owner`, digest type 2. */
export const dsRdata = (owner: Uint8Array, key: Uint8Array) =>
  concat(u16(keyTag(key)), new Uint8Array([key[3], 2]), dsDigest(owner, key))

export interface SignOptions {
  signer: Uint8Array
  inception: number
  expiration: number
  ttl?: number
  /** Override the RRSIG labels field. */
  labels?: number
  /** Override the RRSIG algorithm field. */
  algorithm?: number
}

export function rawSign(key: TestKey, data: Uint8Array): Uint8Array {
  return new Uint8Array(
    key.algorithm === 13
      ? sign('sha256', data, { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
      : sign('sha256', data, key.privateKey),
  )
}

/** Sign an RRset: the RRSIG RDATA, and the pieces a proof step takes. */
export function signRRset(key: TestKey, owner: Uint8Array, type: number, rdatas: Uint8Array[], o: SignOptions) {
  const ttl = o.ttl ?? 3600
  const header = concat(
    u16(type),
    new Uint8Array([o.algorithm ?? key.algorithm, o.labels ?? labelCount(owner)]),
    u32(ttl),
    u32(o.expiration),
    u32(o.inception),
    u16(keyTag(key.rdata)),
    o.signer,
  )
  const rrset = canonicalRRset(
    rdatas.map((rdata) => ({ owner, type, class: CLASS_IN, ttl, rdata })),
    ttl,
  )
  const signedData = concat(header, rrset)
  const signature = rawSign(key, signedData)
  return { rrsig: concat(header, signature), signedData, signature, rrset }
}

export interface Zone {
  name: Uint8Array
  ksk: TestKey
  zsk: TestKey
}

export type Alg = 'rsa' | 'rsa1024' | 'ecdsa'
const makeKey = (alg: Alg, flags: number) =>
  alg === 'ecdsa' ? ecKey({ flags }) : rsaKey({ bits: alg === 'rsa1024' ? 1024 : 2048, flags })

export function makeZone(name: string, ksk: Alg, zsk: Alg = ksk): Zone {
  return { name: nameToWire(name), ksk: makeKey(ksk, 257), zsk: makeKey(zsk, 256) }
}

/** RRsets with their RRSIGs, served as DNS responses. */
export class World {
  readonly now = Math.floor(Date.now() / 1000)
  /** A window around now that tolerates a LocalNet whose last block is a while old. */
  inception = this.now - 2 * 3600
  expiration = this.now + 2 * 86400
  private answers = new Map<string, RR[]>()

  constructor(public root: Zone) {
    this.publishKeys(root)
  }

  /**
   * Publish `rdatas` at `owner`, signed by `key` of `signer`, or by each of several keys.
   * Replaces what was there. Returns the first key's signature.
   */
  publish(
    owner: Uint8Array,
    type: number,
    rdatas: Uint8Array[],
    key: TestKey | TestKey[],
    signer: Uint8Array,
    o: Partial<SignOptions> = {},
  ) {
    const signed = [key].flat().map((k) =>
      signRRset(k, owner, type, rdatas, { signer, inception: this.inception, expiration: this.expiration, ...o }),
    )
    const ttl = o.ttl ?? 3600
    this.answers.set(captureKey(owner, type), [
      ...rdatas.map((rdata) => ({ owner, type, class: CLASS_IN, ttl, rdata })),
      ...signed.map((s) => ({ owner, type: RRType.RRSIG, class: CLASS_IN, ttl, rdata: s.rrsig })),
    ])
    return signed[0]
  }

  /** A zone's DNSKEY RRset, signed by its KSK. */
  publishKeys(zone: Zone, extra: Uint8Array[] = []) {
    return this.publish(zone.name, RRType.DNSKEY, [zone.ksk.rdata, zone.zsk.rdata, ...extra], zone.ksk, zone.name)
  }

  /** Delegate `child` from `parent`: DS signed by the parent's ZSK, then the child's keys. */
  delegate(parent: Zone, child: Zone) {
    this.publish(child.name, RRType.DS, [dsRdata(child.name, child.ksk.rdata)], parent.zsk, parent.name)
    this.publishKeys(child)
  }

  txt(zone: Zone, owner: string, texts: Uint8Array[], o: Partial<SignOptions> = {}) {
    return this.publish(nameToWire(owner), RRType.TXT, texts, zone.zsk, zone.name, o)
  }

  resolver: Resolver = async (name, type) => {
    const answers = this.answers.get(captureKey(name, type)) ?? []
    const header = concat(u16(0), u16(0x8180), u16(0), u16(answers.length), u16(0), u16(0))
    return concat(header, ...answers.map((rr) => concat(rr.owner, u16(rr.type), u16(rr.class), u32(rr.ttl), u16(rr.rdata.length), rr.rdata)))
  }
}

/**
 * root (RSA-2048 by default) → com (P-256) → example.com (P-256), and root → io (RSA-2048
 * KSK, RSA-1024 ZSK) → example.io (P-256), with `_tag.example.<tld>` TXT under each.
 * A P-256 root keeps tests that do not need RSA-2048 cheap.
 */
export function standardWorld({ rootAlg = 'rsa' as Alg } = {}) {
  const root = makeZone('.', rootAlg)
  const world = new World(root)
  const com = makeZone('com', 'ecdsa')
  const io = makeZone('io', 'rsa', 'rsa1024')
  const exampleCom = makeZone('example.com', 'ecdsa')
  const exampleIo = makeZone('example.io', 'ecdsa')
  world.delegate(root, com)
  world.delegate(root, io)
  world.delegate(com, exampleCom)
  world.delegate(io, exampleIo)
  world.txt(exampleCom, '_tag.example.com', [txt('hello com')])
  world.txt(exampleIo, '_tag.example.io', [txt('hello io')])
  return { world, root, com, io, exampleCom, exampleIo }
}

/** TXT RDATA with one character-string. */
export const txt = (text: string) => {
  const bytes = new TextEncoder().encode(text)
  return concat(new Uint8Array([bytes.length]), bytes)
}
