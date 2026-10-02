import { AlgorandClient, microAlgo } from '@algorandfoundation/algokit-utils'
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
import { MAX_VALUE_BYTES, MIN_TXN_FEE_MICROALGOS } from './constants.js'
import { APP_SPEC, DnssecOracleClient, DnssecOracleComposer } from './generated/DnssecOracleClient.js'
import { ancestors, concat, nameToWire, sha256, toHex, u16 } from './prover/wire.js'
import { ReaderConstructorArgs } from './types.js'
import { chunked, deduped } from './util/chunked.js'
import { SIMULATE_PARAMS } from './util/increaseBudget.js'
import { scanBoxes } from './util/scanBoxes.js'
import { errorTransformer, wrapErrors } from './util/wrapErrors.js'

/**
 * Simulate supplies the box references (allowUnnamedResources) and lends one call the whole
 * group's: 8 per transaction slot, filled or not, so 128 boxes per group. A group is then as
 * few calls as the argument and logs allow (packCalls).
 */
const NAMES_PER_GROUP = 128
const KEYS_PER_GROUP = 128
/** Accounts per logCredits group, and so per call: an address[] argument, 2 + 32n bytes, within 4 KB. */
const ACCOUNTS_PER_GROUP = 127
/** Simulate's log ceiling per transaction (allowMoreLogging), over 4 KB attestations: 16 per call. */
const NAMES_PER_CALL = 65_536 / MAX_VALUE_BYTES

/**
 * A logger call's extra fee, given its array argument's size: one min fee covers v42's
 * surcharge on arguments past 2 KB (the 4-byte selector included), ~0.2 min fee at 4 KB.
 * None below that, so a reader account near its minimum balance can still read small batches.
 * Simulated, never paid.
 */
const loggerExtraFee = (argBytes: number) => (4 + argBytes > 2048 ? microAlgo(MIN_TXN_FEE_MICROALGOS) : undefined)
/** A byte[][] argument's ABI size: a 2-byte count, then a 2-byte offset and 2-byte length per item. */
const arrayBytes = (items: Uint8Array[]) => items.reduce((n, item) => n + 4 + item.length, 2)

/**
 * Split `items` into byte[][] logger calls: at most `perCall` each, each argument
 * (arrayBytes) within 4 KB.
 * @internal
 */
export function packCalls(items: Uint8Array[], perCall: number): Uint8Array[][] {
  const calls: Uint8Array[][] = []
  let call: Uint8Array[] = []
  let size = 2
  for (const item of items) {
    if (call.length === perCall || (call.length > 0 && size + 4 + item.length > MAX_VALUE_BYTES)) {
      calls.push(call)
      call = []
      size = 2
    }
    call.push(item)
    size += 4 + item.length
  }
  if (call.length > 0) calls.push(call)
  return calls
}

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
   * Unvalidated: stale, expired or weak ones included. getVerifiedAttestation checks them.
   */
  @wrapErrors()
  async getRawAttestation(name: NameLike): Promise<Attestation | undefined> {
    const [attestation] = await this.getRawAttestations([name])
    return attestation
  }

  /** Batch getRawAttestation, index-aligned with the input. */
  @wrapErrors()
  async getRawAttestations(names: NameLike[]): Promise<(Attestation | undefined)[]> {
    const raw = await this._logAttestationsChunked(names.map(toWire))
    return raw.map((value) => value && decodeAttestation(value))
  }

  /**
   * The attestation for `name` and the zones its chain runs through, if usable now: the
   * off-chain twin of reader.algo.ts's attestationUsable. Undefined if missing, stale, expired,
   * signed more than `maxAge` seconds ago, or with a key on its path weaker than `minKeyBits`.
   * `now` defaults to the wall clock; on-chain it is the latest block's timestamp, which lags
   * (on an idle dev LocalNet, arbitrarily). Pass that for exact parity near a boundary.
   */
  @wrapErrors()
  async getVerifiedAttestation(
    name: NameLike,
    { maxAge, minKeyBits, now = Math.floor(Date.now() / 1000) }: { maxAge: number; minKeyBits: number; now?: number },
  ): Promise<{ attestation: Attestation; zones: Uint8Array[] } | undefined> {
    const attestation = await this.getRawAttestation(name)
    if (!attestation) return undefined
    const { expiration, inception, weakestKeyBits } = attestation
    if (now > expiration || now > inception + maxAge || weakestKeyBits < minKeyBits) return undefined
    const zones = await this.attestationZones(name, attestation)
    return zones && { attestation, zones }
  }

  /** Raw attestation box values through the logger: undefined where there is none. */
  @deduped()
  @chunked(NAMES_PER_GROUP)
  async _logAttestationsChunked(names: Uint8Array[]): Promise<(Uint8Array | undefined)[]> {
    if (names.length === 0) return []
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let builder: DnssecOracleComposer<any> = this.readClient.newGroup()
    for (const call of packCalls(names, NAMES_PER_CALL)) {
      builder = builder.logAttestations({ args: { names: call }, extraFee: loggerExtraFee(arrayBytes(call)) })
    }
    const { confirmations } = await builder.simulate(SIMULATE_PARAMS)
    const logs = confirmations.flatMap((c: { logs?: Uint8Array[] }) => c.logs ?? [])
    // one line per name; an empty line means no attestation
    return logs.map((log) => (log.length === 0 ? undefined : new Uint8Array(log)))
  }

  /**
   * Every attestation, by the algod prefix scan, keyed by `sha256(name)` hex: box names
   * hold only the hash, so names are for the caller to match. Stale ones included: check
   * attestationChainLive.
   */
  @wrapErrors()
  async listRawAttestations(): Promise<Map<string, Attestation>> {
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
  async attestationChainLive(attestation: Attestation, zones: NameLike[]): Promise<boolean> {
    const [entries, { rootEpoch }] = await Promise.all([
      this.getRawCaches(chainLinks(zones.map(toWire))),
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
   * the name's ancestors: what attestationChainLive and a consumer's hasTxt take. Undefined if its chain
   * is not current.
   */
  @wrapErrors()
  async attestationZones(name: NameLike, attestation: Attestation): Promise<Uint8Array[] | undefined> {
    const all = ancestors(toWire(name))
    // every ancestor's DNSKEY then DS, the root's DNSKEY last, in one read: entries[2i] is
    // all[i]'s DNSKEY, entries[2i + 1] its DS
    const [entries, { rootEpoch }] = await Promise.all([this.getRawCaches(chainLinks(all.slice(0, -1))), this.getState()])
    const zones: Uint8Array[] = []
    let epoch = attestation.parentEpoch
    // the same walk as attestationChainLive, in one pass: each box is read once
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

  /** The cache entry for `name type`, or undefined. Unvalidated: stale or expired ones included. */
  @wrapErrors()
  async getRawCache(name: NameLike, type: number): Promise<CacheEntry | undefined> {
    const [entry] = await this.getRawCaches([[name, type]])
    return entry
  }

  /** Batch getRawCache, index-aligned with the input, through the contract's logCaches logger. */
  @wrapErrors()
  async getRawCaches(links: [NameLike, number][]): Promise<(CacheEntry | undefined)[]> {
    const raw = await this._logCachesChunked(links.map(([name, type]) => concat(toWire(name), u16(type))))
    return raw.map((value) => value && decodeCache(value))
  }

  /** Raw cache box values through the logger, by `name ‖ uint16 type`: undefined where there is none. */
  @deduped()
  @chunked(KEYS_PER_GROUP)
  async _logCachesChunked(keys: Uint8Array[]): Promise<(Uint8Array | undefined)[]> {
    if (keys.length === 0) return []
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let builder: DnssecOracleComposer<any> = this.readClient.newGroup()
    for (const call of packCalls(keys, KEYS_PER_GROUP)) {
      builder = builder.logCaches({ args: { keys: call }, extraFee: loggerExtraFee(arrayBytes(call)) })
    }
    const { confirmations } = await builder.simulate(SIMULATE_PARAMS)
    const logs = confirmations.flatMap((c: { logs?: Uint8Array[] }) => c.logs ?? [])
    return logs.map((log) => (log.length === 0 ? undefined : new Uint8Array(log)))
  }

  /** Every cache entry, keyed by `sha256(name ‖ type)` hex. */
  @wrapErrors()
  async listRawCaches(): Promise<Map<string, CacheEntry>> {
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

  @deduped()
  @chunked(ACCOUNTS_PER_GROUP)
  async _logCreditsChunked(accounts: string[]): Promise<(bigint | undefined)[]> {
    if (accounts.length === 0) return []
    const { confirmations } = await this.readClient
      .newGroup()
      .logCredits({ args: { accounts }, extraFee: loggerExtraFee(2 + 32 * accounts.length) })
      .simulate(SIMULATE_PARAMS)
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

/** sha256(name) hex: the key listRawAttestations uses. */
export const attestationKey = (name: NameLike) => toHex(sha256(toWire(name)))
