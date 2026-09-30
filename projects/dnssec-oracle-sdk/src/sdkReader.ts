import { AlgorandClient } from '@algorandfoundation/algokit-utils'
import { encodeAddress, getApplicationAddress, makeEmptyTransactionSigner } from 'algosdk'
import {
  anchorHash,
  AnchorEntry,
  Attestation,
  boxNames,
  CacheEntry,
  chainLinks,
  decodeAnchor,
  decodeAttestation,
  decodeCache,
  isTrusted,
} from './boxes.js'
import { APP_SPEC, DnssecOracleClient, DnssecOracleComposer } from './generated/DnssecOracleClient.js'
import { ancestors, concat, nameToWire, sha256, toHex, u16 } from './prover/wire.js'
import { ReaderConstructorArgs } from './types.js'
import { chunk } from './util/chunk.js'
import { chunked } from './util/chunked.js'
import { SIMULATE_PARAMS } from './util/increaseBudget.js'
import { scanBoxes } from './util/scanBoxes.js'
import { errorTransformer, wrapErrors } from './util/wrapErrors.js'

/**
 * Names per logAttestations call and per simulate group. Simulate supplies the box
 * references (allowUnnamedResources), up to 8 per transaction across a 16-transaction group.
 */
const NAMES_PER_CALL = 8
const NAMES_PER_GROUP = 128
/** Accounts per logCredits call and group: the same resource math, one credit box each. */
const ACCOUNTS_PER_CALL = 8
const ACCOUNTS_PER_GROUP = 128
/** Cache keys per logCaches call and group: the same resource math, one cache box each. */
const KEYS_PER_CALL = 8
const KEYS_PER_GROUP = 128

/** A name as wire bytes, or in presentation form (`example.com`). */
export type NameLike = string | Uint8Array
const toWire = (name: NameLike) => (typeof name === 'string' ? nameToWire(name) : name)

export class DnssecOracleReaderSDK {
  static APP_SPEC = APP_SPEC

  public algorand: AlgorandClient
  public appId: bigint
  public readClient: DnssecOracleClient
  public debug?: boolean
  /** Concurrent simulate groups for chunked batch reads. */
  public concurrency = 2

  constructor({ algorand, appId, readerAccount, debug }: ReaderConstructorArgs) {
    this.algorand = algorand
    algorand.registerErrorTransformer(errorTransformer)
    this.appId = BigInt(appId)
    this.debug = debug
    this.readClient = new DnssecOracleClient({
      algorand,
      appId: this.appId,
      // the app's own address exists wherever the app does, so simulated reads work
      // with no configuration: the app account keeps some fee slack for this
      defaultSender: readerAccount ?? getApplicationAddress(this.appId).toString(),
      defaultSigner: makeEmptyTransactionSigner(),
    })
  }

  /**
   * Global state: admin, initial anchor count, the newest root inception a rollover step
   * used, and the anchor set's epoch, fresh at each revocation of a trusted key.
   */
  @wrapErrors()
  async getState(): Promise<{ admin: string; anchorCount: bigint; rollInception: bigint; rootEpoch: bigint }> {
    const { admin, anchorCount, rollInception, rootEpoch } = await this.readClient.state.global.getAll()
    return {
      admin: admin ?? '',
      anchorCount: anchorCount ?? 0n,
      rollInception: rollInception ?? 0n,
      rootEpoch: rootEpoch ?? 0n,
    }
  }

  /**
   * The attestation for `name`, through the contract's logAttestations logger, or undefined.
   * Stale ones included: check chainLive.
   */
  @wrapErrors()
  async getAttestation(name: NameLike): Promise<Attestation | undefined> {
    const [attestation] = await this.getAttestations([name])
    return attestation
  }

  /** Batch getAttestation, index-aligned with the input. */
  @wrapErrors()
  async getAttestations(names: NameLike[]): Promise<(Attestation | undefined)[]> {
    const raw = await this._logAttestationsChunked(names.map(toWire))
    return raw.map((value) => value && decodeAttestation(value))
  }

  /** Raw attestation box values through the logger: undefined where there is none. */
  @chunked(NAMES_PER_GROUP)
  async _logAttestationsChunked(names: Uint8Array[]): Promise<(Uint8Array | undefined)[]> {
    if (names.length === 0) return []
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let builder: DnssecOracleComposer<any> = this.readClient.newGroup()
    for (const call of chunk(names, NAMES_PER_CALL)) {
      builder = builder.logAttestations({ args: { names: call } })
    }
    const { confirmations } = await builder.simulate(SIMULATE_PARAMS)
    const logs = confirmations.flatMap((c: { logs?: Uint8Array[] }) => c.logs ?? [])
    // one line per name; an empty line means no attestation
    return logs.map((log) => (log.length === 0 ? undefined : new Uint8Array(log)))
  }

  /**
   * Every attestation, by the algod prefix scan, keyed by `sha256(name)` hex: box names
   * hold only the hash, so names are for the caller to match. Stale ones included: check
   * chainLive.
   */
  @wrapErrors()
  async listAttestations(): Promise<Map<string, Attestation>> {
    const boxes = await this.scanRaw('t')
    return new Map([...boxes].map(([hash, value]) => [hash, decodeAttestation(value)]))
  }

  /** Raw values under a box prefix, keyed by the rest of the name, hex. */
  @wrapErrors()
  async scanRaw(prefix: string): Promise<Map<string, Uint8Array>> {
    const boxes = await scanBoxes(this.algorand.client.algod, this.appId, new TextEncoder().encode(prefix))
    return new Map(boxes.map(({ name, value }) => [toHex(name.slice(prefix.length)), value]))
  }

  /**
   * Whether no ancestor of `attestation` has changed since it was proven: the off-chain twin
   * of reader.algo.ts's attestationChainLive. `zones` runs from the signer's zone up to the TLD.
   */
  @wrapErrors()
  async chainLive(attestation: Attestation, zones: NameLike[]): Promise<boolean> {
    const [entries, { rootEpoch }] = await Promise.all([
      this.getCaches(chainLinks(zones.map(toWire))),
      this.getState(),
    ])
    let epoch = attestation.parentEpoch
    for (const entry of entries) {
      if (entry?.epoch !== epoch) return false
      epoch = entry.parentEpoch
    }
    return BigInt(epoch) === rootEpoch
  }

  /**
   * The zones `name`'s attestation chains through, signer first, found by matching epochs up
   * the name's ancestors: what chainLive and a consumer's hasTxt take. Undefined if its chain
   * is not current.
   */
  @wrapErrors()
  async attestationZones(name: NameLike, attestation: Attestation): Promise<Uint8Array[] | undefined> {
    const all = ancestors(toWire(name))
    // every ancestor's DNSKEY then DS, the root's DNSKEY last, in one read: entries[2i] is
    // all[i]'s DNSKEY, entries[2i + 1] its DS
    const [entries, { rootEpoch }] = await Promise.all([this.getCaches(chainLinks(all.slice(0, -1))), this.getState()])
    const zones: Uint8Array[] = []
    let epoch = attestation.parentEpoch
    // the same walk as chainLive, in one pass: each box is read once
    for (const [i, zone] of all.entries()) {
      const keys = entries[2 * i]
      // epochs are unique: only the zone that signed the link below matches
      if (keys?.epoch !== epoch) continue
      if (zone.length === 1) return BigInt(keys.parentEpoch) === rootEpoch ? zones : undefined
      const ds = entries[2 * i + 1]
      if (ds?.epoch !== keys.parentEpoch) return undefined
      zones.push(zone)
      epoch = ds.parentEpoch
    }
    return undefined
  }

  /** The cache entry for `name type`, or undefined. */
  @wrapErrors()
  async getCache(name: NameLike, type: number): Promise<CacheEntry | undefined> {
    const [entry] = await this.getCaches([[name, type]])
    return entry
  }

  /** Batch getCache, index-aligned with the input, through the contract's logCaches logger. */
  @wrapErrors()
  async getCaches(links: [NameLike, number][]): Promise<(CacheEntry | undefined)[]> {
    const raw = await this._logCachesChunked(links.map(([name, type]) => concat(toWire(name), u16(type))))
    return raw.map((value) => value && decodeCache(value))
  }

  /** Raw cache box values through the logger, by `name ‖ uint16 type`: undefined where there is none. */
  @chunked(KEYS_PER_GROUP)
  async _logCachesChunked(keys: Uint8Array[]): Promise<(Uint8Array | undefined)[]> {
    if (keys.length === 0) return []
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let builder: DnssecOracleComposer<any> = this.readClient.newGroup()
    for (const call of chunk(keys, KEYS_PER_CALL)) {
      builder = builder.logCaches({ args: { keys: call } })
    }
    const { confirmations } = await builder.simulate(SIMULATE_PARAMS)
    const logs = confirmations.flatMap((c: { logs?: Uint8Array[] }) => c.logs ?? [])
    return logs.map((log) => (log.length === 0 ? undefined : new Uint8Array(log)))
  }

  /** Every cache entry, keyed by `sha256(name ‖ type)` hex. */
  @wrapErrors()
  async listCaches(): Promise<Map<string, CacheEntry>> {
    const boxes = await this.scanRaw('r')
    return new Map([...boxes].map(([hash, value]) => [hash, decodeCache(value)]))
  }

  /** The anchor entry for `dnskeyRdata`'s public key, whatever its flags, or undefined. */
  @wrapErrors()
  async getAnchor(dnskeyRdata: Uint8Array): Promise<AnchorEntry | undefined> {
    const value = await this.getBox(boxNames.anchor(dnskeyRdata))
    return value && decodeAnchor(value)
  }

  /** Every anchor entry, keyed by `sha256(alg ‖ pubkey)` hex (see anchorHash). */
  @wrapErrors()
  async listAnchors(): Promise<Map<string, AnchorEntry>> {
    const boxes = await this.scanRaw('a')
    return new Map([...boxes].map(([hash, value]) => [hash, decodeAnchor(value)]))
  }

  /** A predicate for the prover: whether a root DNSKEY is a Valid or Missing anchor now. */
  @wrapErrors()
  async trustedAnchors(): Promise<(dnskeyRdata: Uint8Array) => boolean> {
    const anchors = await this.listAnchors()
    return (dnskeyRdata) => isTrusted(anchors.get(toHex(anchorHash(dnskeyRdata))))
  }

  /** MBR credit balance (µAlgo), or undefined without a credit box. */
  @wrapErrors()
  async getCredits(account: string): Promise<bigint | undefined> {
    const [credit] = await this._logCreditsChunked([account])
    return credit
  }

  /** Every credit balance, by the algod prefix scan. */
  @wrapErrors()
  async listCredits(): Promise<Map<string, bigint>> {
    const boxes = await this.scanRaw('c')
    return new Map(
      [...boxes].map(([key, value]) => [encodeAddress(Buffer.from(key, 'hex')), Buffer.from(value).readBigUInt64BE()]),
    )
  }

  @chunked(ACCOUNTS_PER_GROUP)
  async _logCreditsChunked(accounts: string[]): Promise<(bigint | undefined)[]> {
    if (accounts.length === 0) return []
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let builder: DnssecOracleComposer<any> = this.readClient.newGroup()
    for (const call of chunk(accounts, ACCOUNTS_PER_CALL)) {
      builder = builder.logCredits({ args: { accounts: call } })
    }
    const { confirmations } = await builder.simulate(SIMULATE_PARAMS)
    const logs = confirmations.flatMap((c: { logs?: Uint8Array[] }) => c.logs ?? [])
    return logs.map((l) => (l.length === 0 ? undefined : Buffer.from(l).readBigUInt64BE()))
  }

  /** One box by name, straight from algod, or undefined. */
  protected async getBox(name: Uint8Array): Promise<Uint8Array | undefined> {
    try {
      return await this.algorand.app.getBoxValue(this.appId, name)
    } catch (e) {
      if (e instanceof Error && /box not found/i.test(e.message)) return undefined
      throw e
    }
  }
}

/** sha256(name) hex: the key listAttestations uses. */
export const attestationKey = (name: NameLike) => toHex(sha256(toWire(name)))
