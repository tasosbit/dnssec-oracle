import { AlgorandClient, microAlgo } from '@algorandfoundation/algokit-utils'
import { TransactionSigner } from 'algosdk'
import { AnchorEntry, anchorHash, AnchorState, boxNames, isTrusted } from './boxes.js'
import {
  ANCHOR_BOX_MBR_MICROALGOS,
  CREDIT_BOX_MBR_MICROALGOS,
  DEFAULT_REFRESH_MARGIN_SECONDS,
  HOLD_DOWN_SECONDS,
  MIN_TXN_FEE_MICROALGOS,
} from './constants.js'
import { DnssecOracleClient, DnssecOracleComposer, DnssecOracleFactory } from './generated/DnssecOracleClient.js'
import { buildRootSteps, buildTxtChain, keyProblem, ProofStep } from './prover/chain.js'
import { Resolver, tcpResolver } from './prover/dns.js'
import {
  bytesEqual,
  DNSKEY_REVOKE,
  fromHex,
  keyTag,
  nameFromWire,
  nameToWire,
  parseDnskey,
  rdataOf,
  RRType,
  sha256,
  toHex,
} from './prover/wire.js'
import { DnssecOracleReaderSDK, NameLike } from './sdkReader.js'
import { ConstructorArgs, SenderWithSigner } from './types.js'
import { noteNonce } from './util/noteNonce.js'
import { createTxnExecutor } from './util/txnExecutor.js'
import { wrapErrors, wrapErrorsInternal } from './util/wrapErrors.js'

// the composer's tuple type grows per chained call, so a builder handed between makers is widened
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type BuilderArgs = { builder?: DnssecOracleComposer<any> }

export interface ProveChainResult {
  /** Steps sent, in order. */
  proven: ProofStep[]
  /** Steps skipped because the cache already held the same RRset, fresh. */
  cached: ProofStep[]
  txIds: string[]
}

export interface ProveTxtOptions {
  /** DNS source; defaults to 1.1.1.1 over TCP. */
  resolver?: Resolver
  /** Root trust anchors the chain may start from; defaults to the app's Valid and Missing anchors. */
  anchors?: Uint8Array[] | ((dnskeyRdata: Uint8Array) => boolean)
  /** Refresh cache entries this close to expiry, in seconds. */
  refreshMarginSeconds?: number
}

/** An RFC 5011 event, as `updateAnchor` or `revokeRoot` applies it. */
export type AnchorEvent = 'Add' | 'Promote' | 'Reset' | 'Miss' | 'Return' | 'Retire' | 'Revoke'

export interface MaintainAnchorsResult {
  /** Events sent, in order, with the key's anchorHash hex and key tag (undefined once the key left the RRset). */
  events: { event: AnchorEvent; keyHash: string; keyTag?: number }[]
  txIds: string[]
}

/**
 * The event `updateAnchor` would apply, mirroring the contract, or undefined for none.
 * @param key The key as the root DNSKEY RRset holds it, or undefined if it does not
 */
export function anchorEvent(anchor: AnchorEntry | undefined, key: Uint8Array | undefined, now: number): AnchorEvent | undefined {
  const flags = key && parseDnskey(key).flags
  const present = flags !== undefined && !(flags & DNSKEY_REVOKE)
  if (!anchor) return flags === 257 && !keyProblem(key!, parseDnskey(key!).algorithm) ? 'Add' : undefined
  switch (anchor.state) {
    case AnchorState.AddPend:
      return !present ? 'Reset' : now >= anchor.since + HOLD_DOWN_SECONDS ? 'Promote' : undefined
    case AnchorState.Valid:
      return present ? undefined : 'Miss'
    case AnchorState.Missing:
      return present ? 'Return' : undefined
    case AnchorState.Revoked:
      return now >= anchor.since + HOLD_DOWN_SECONDS ? 'Retire' : undefined
  }
}

export class DnssecOracleSDK extends DnssecOracleReaderSDK {
  public writerAccount?: SenderWithSigner
  public writeClient?: DnssecOracleClient

  constructor({ writerAccount, ...rest }: ConstructorArgs) {
    super(rest)
    if (writerAccount) {
      this.writerAccount = writerAccount
      this.writeClient = new DnssecOracleClient({
        algorand: this.algorand,
        appId: this.appId,
        defaultSender: writerAccount.sender,
        defaultSigner: toSigner(writerAccount.signer),
      })
    }
  }

  /**
   * Step one of the two-step creation: create the app with `admin` as sender. Step two is
   * `setup`, from the same admin.
   */
  static async create({
    algorand,
    admin,
    debug,
  }: {
    algorand: AlgorandClient
    admin: SenderWithSigner
    debug?: boolean
  }): Promise<DnssecOracleSDK> {
    const factory = algorand.client.getTypedAppFactory(DnssecOracleFactory, {
      defaultSender: admin.sender,
      defaultSigner: toSigner(admin.signer),
    })
    const { appClient } = await factory.send.create.bare()
    return new DnssecOracleSDK({ algorand, appId: appClient.appId, writerAccount: admin, debug })
  }

  private makeTxnExecutor = createTxnExecutor(
    this,
    () => this.writeClient!.newGroup(),
    wrapErrorsInternal,
    () => this.writerAccount,
    () => this.algorand.client.algod,
  )

  private get writer() {
    if (!this.writerAccount || !this.writeClient) throw new Error('DnssecOracleSDK needs a writerAccount to write')
    const { sender, signer } = this.writerAccount
    return { sender, signer: toSigner(signer) }
  }

  // ── Setup and admin ─────────────────────────────────────────────

  /**
   * Maker for step two of creation, one group from the admin: fund the app account's
   * base MBR and fee slack, deposit the admin's credits, upload the anchors.
   */
  private async makeSetupTxns({
    anchors,
    fund = 200_000,
    credits,
    builder,
  }: { anchors: Uint8Array[]; fund?: number; credits?: number } & BuilderArgs) {
    const { sender, signer } = this.writer
    const appAddress = this.writeClient!.appAddress.toString()
    const needed = CREDIT_BOX_MBR_MICROALGOS + anchors.length * ANCHOR_BOX_MBR_MICROALGOS
    const pay = (amount: number) =>
      this.algorand.createTransaction.payment({ sender, receiver: appAddress, amount: microAlgo(amount), note: `${noteNonce()}` })
    let group = (builder ?? this.writeClient!.newGroup()).addTransaction(await pay(fund), signer)
    group = await this.makeDepositCreditsTxns({ amount: credits ?? needed, builder: group })
    return this.makeAddAnchorsTxns({ anchors, builder: group })
  }

  /** Step two of creation. See makeSetupTxns. */
  setup = this.makeTxnExecutor({ maker: this.makeSetupTxns })

  private makeAddAnchorsTxns({ anchors, builder }: { anchors: Uint8Array[] } & BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).addAnchors({
      args: { dnskeys: anchors },
      boxReferences: [...anchors.map(boxNames.anchor), boxNames.credit(sender)],
      sender,
      signer,
    })
  }

  /** Upload the initial root anchors (DNSKEY RDATA), all Valid. Admin only, once. */
  addAnchors = this.makeTxnExecutor({ maker: this.makeAddAnchorsTxns })

  private makeSetAdminTxns({ admin, builder }: { admin: string } & BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).setAdmin({ args: { newAdmin: admin }, sender, signer })
  }

  /** Hand over the admin role; the zero address renounces it. Admin only. */
  setAdmin = this.makeTxnExecutor({ maker: this.makeSetAdminTxns })

  // ── Credits ─────────────────────────────────────────────────────

  private async makeDepositCreditsTxns({
    amount,
    creditor,
    builder,
  }: { amount: number | bigint; creditor?: string } & BuilderArgs) {
    const { sender, signer } = this.writer
    const creditorAddress = creditor ?? sender.toString()
    const payTxn = await this.algorand.createTransaction.payment({
      sender,
      // a string, not an Address: the consumer may bring its own algosdk instance
      receiver: this.writeClient!.appAddress.toString(),
      amount: microAlgo(Number(amount)),
    })
    return (builder ?? this.writeClient!.newGroup()).depositCredits({
      args: { creditor: creditorAddress, txn: { txn: payTxn, signer } },
      boxReferences: [boxNames.credit(creditorAddress)],
      sender,
      signer,
    })
  }

  /**
   * Deposit MBR credits (µAlgo), which box rent is drawn from. A first deposit pays for the
   * creditor's own credit box (CREDIT_BOX_MBR_MICROALGOS) out of the amount.
   */
  depositCredits = this.makeTxnExecutor({ maker: this.makeDepositCreditsTxns })

  private makeWithdrawCreditsTxns({ builder }: BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).withdrawCredits({
      args: {},
      boxReferences: [boxNames.credit(sender)],
      extraFee: microAlgo(MIN_TXN_FEE_MICROALGOS), // the inner refund payment
      sender,
      signer,
    })
  }

  /** Withdraw all credits, the credit box's own MBR included. */
  withdrawCredits = this.makeTxnExecutor({ maker: this.makeWithdrawCreditsTxns })

  // ── Proofs ──────────────────────────────────────────────────────

  /**
   * Maker for one proof step. Declares the boxes the method is known to touch; algokit's
   * resource population adds the rest (a replaced attestation's payer, and box I/O quota
   * for large attestations).
   */
  private makeProveTxns({ step, builder }: { step: ProofStep } & BuilderArgs) {
    const { sender, signer } = this.writer
    const group = builder ?? this.writeClient!.newGroup()
    const credit = boxNames.credit(sender)
    const base = { signedData: step.signedData, signature: step.signature, hint: step.hint, keyIndex: step.keyIndex }
    const common = { sender, signer, note: `${noteNonce()}` }
    switch (step.kind) {
      case 'root': {
        const key = rdataOf(step.rrset)[step.keyIndex]
        return group.proveRoot({
          args: base,
          boxReferences: [boxNames.anchor(key), boxNames.cache(step.owner, RRType.DNSKEY), credit],
          ...common,
        })
      }
      case 'ds':
        return group.proveDs({
          args: { ...base, parent: step.parent },
          boxReferences: [
            boxNames.cache(signerOf(step), RRType.DNSKEY),
            boxNames.cache(step.owner, RRType.DS),
            credit,
          ],
          ...common,
        })
      case 'dnskey':
        return group.proveDnskey({
          args: { ...base, dsIndex: step.dsIndex, parent: step.parent },
          boxReferences: [
            boxNames.cache(step.owner, RRType.DS),
            boxNames.cache(step.owner, RRType.DNSKEY),
            credit,
          ],
          ...common,
        })
      case 'txt':
        return group.proveTxt({
          args: { ...base, parent: step.parent },
          boxReferences: [
            boxNames.cache(signerOf(step), RRType.DNSKEY),
            boxNames.attestation(step.owner),
            credit,
          ],
          ...common,
        })
    }
  }

  /** Send one proof step, with op-up as needed. */
  proveStep = this.makeTxnExecutor({ maker: this.makeProveTxns })

  /**
   * Prove a chain from buildTxtChain, parents before children. Cache steps whose RRset is
   * already stored, fresh and proven under the parent's current entry are skipped; an expired
   * entry with a newer inception is pruned first. One from before the last revocation is
   * simply overwritten. The TXT step is always sent.
   */
  @wrapErrors()
  async proveChain(
    steps: ProofStep[],
    { refreshMarginSeconds = DEFAULT_REFRESH_MARGIN_SECONDS }: { refreshMarginSeconds?: number } = {},
  ): Promise<ProveChainResult> {
    const result: ProveChainResult = { proven: [], cached: [], txIds: [] }
    const now = Math.floor(Date.now() / 1000)
    const rootEpoch = Number((await this.getState()).rootEpoch)
    for (const step of steps) {
      if (step.kind !== 'txt') {
        const found = await this.getCache(step.owner, step.type)
        // parents come first, so this reads the parent's entry as this step will see it
        const live = found && found.parentEpoch === (await this.parentEpoch(step))
        if (live && bytesEqual(found.hash, sha256(step.rrset)) && found.expiry > now + refreshMarginSeconds) {
          result.cached.push(step)
          continue
        }
        // the contract overwrites an entry from before the last revocation whatever its inception
        const cached = found && found.epoch >= rootEpoch ? found : undefined
        if (cached && cached.inception > step.inception) {
          // expired: anyone may prune it, and the older RRset, still valid, proves into a fresh box
          if (cached.expiry < now) {
            result.txIds.push(...(await this.prune({ name: step.owner, type: step.type })).txIds)
          } else {
            throw new Error(
              `${nameFromWire(step.owner)} ${step.type}: the cache holds a newer RRset (inception ` +
                `${cached.inception} > ${step.inception}); rebuild the chain from fresh DNS data`,
            )
          }
        }
      }
      const sent = await this.proveStep({ step })
      if (this.debug) console.log(`proved ${step.kind} ${nameFromWire(step.owner)}`, sent.txIds)
      result.proven.push(step)
      result.txIds.push(...sent.txIds)
    }
    return result
  }

  /** The current epoch of the entry a cache step is verified against; 0 if none. */
  private async parentEpoch(step: ProofStep): Promise<number> {
    if (step.kind === 'root') return Number((await this.getState()).rootEpoch)
    const parent =
      step.kind === 'ds'
        ? await this.getCache(signerOf(step), RRType.DNSKEY)
        : await this.getCache(step.owner, RRType.DS)
    return parent?.epoch ?? 0
  }

  /** Build `name TXT`'s chain from DNS and prove it: see buildTxtChain and proveChain. */
  @wrapErrors()
  async proveTxt(name: string, options: ProveTxtOptions = {}): Promise<ProveChainResult> {
    const steps = await buildTxtChain(name, options.resolver ?? tcpResolver(), {
      anchors: options.anchors ?? (await this.trustedAnchors()),
    })
    return this.proveChain(steps, options)
  }

  // ── Root rollover (RFC 5011) ────────────────────────────────────

  private makeUpdateAnchorTxns({ rrset, keyHash, builder }: { rrset: Uint8Array; keyHash: Uint8Array } & BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).updateAnchor({
      args: { rrset, keyHash },
      boxReferences: [
        boxNames.anchorByHash(keyHash),
        boxNames.cache(new Uint8Array([0]), RRType.DNSKEY),
        boxNames.credit(sender),
      ],
      sender,
      signer,
      note: `${noteNonce()}`,
    })
  }

  /** Apply the RFC 5011 event the cached root DNSKEY RRset `rrset` implies for one key (see anchorEvent). */
  updateAnchor = this.makeTxnExecutor({ maker: this.makeUpdateAnchorTxns })

  private makeRevokeRootTxns({ step, builder }: { step: ProofStep } & BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).revokeRoot({
      args: { signedData: step.signedData, signature: step.signature, hint: step.hint, keyIndex: step.keyIndex },
      boxReferences: [boxNames.anchor(rdataOf(step.rrset)[step.keyIndex])],
      sender,
      signer,
      note: `${noteNonce()}`,
    })
  }

  /** Revoke an anchor with a root step (from buildRootSteps) signed by the anchor itself, flags 385. */
  revokeRoot = this.makeTxnExecutor({ maker: this.makeRevokeRootTxns })

  /**
   * The rollover watcher; run it daily. From the root DNSKEY RRset in DNS: send every
   * self-signed revocation of an anchor, prove the RRset under a trusted anchor unless the
   * cache holds it, then send every event it implies for the keys in it and the anchors
   * stored (see anchorEvent). Adds are paid from the sender's credits, deletions refunded
   * to them.
   */
  @wrapErrors()
  async maintainAnchors({
    resolver = tcpResolver(),
    now = Math.floor(Date.now() / 1000),
  }: { resolver?: Resolver; now?: number } = {}): Promise<MaintainAnchorsResult> {
    const result: MaintainAnchorsResult = { events: [], txIds: [] }
    const anchors = await this.listAnchors()
    const steps = await buildRootSteps(resolver, { now })
    const keyOf = (step: ProofStep) => rdataOf(step.rrset)[step.keyIndex]

    for (const step of steps) {
      const key = keyOf(step)
      const hash = toHex(anchorHash(key))
      const anchor = anchors.get(hash)
      if (parseDnskey(key).flags !== 385 || !anchor || anchor.state === AnchorState.Revoked) continue
      result.txIds.push(...(await this.revokeRoot({ step })).txIds)
      result.events.push({ event: 'Revoke', keyHash: hash, keyTag: keyTag(key) })
      anchors.set(hash, { state: AnchorState.Revoked, since: now })
    }

    const trusted = steps.find((step) => {
      const key = keyOf(step)
      return isTrusted(anchors.get(toHex(anchorHash(key)))) && !keyProblem(key, parseDnskey(key).algorithm)
    })
    if (!trusted) throw new Error('root DNSKEY: no signature by a trusted anchor')
    result.txIds.push(...(await this.proveChain([trusted])).txIds)

    const inRRset = new Map(rdataOf(trusted.rrset).map((key) => [toHex(anchorHash(key)), key]))
    for (const hash of new Set([...anchors.keys(), ...inRRset.keys()])) {
      const key = inRRset.get(hash)
      const event = anchorEvent(anchors.get(hash), key, now)
      if (!event) continue
      result.txIds.push(...(await this.updateAnchor({ rrset: trusted.rrset, keyHash: fromHex(hash) })).txIds)
      result.events.push({ event, keyHash: hash, keyTag: key && keyTag(key) })
    }
    return result
  }

  // ── Rent ────────────────────────────────────────────────────────

  private makePruneTxns({ name, type, builder }: { name: NameLike; type: number } & BuilderArgs) {
    const { sender, signer } = this.writer
    const wire = typeof name === 'string' ? nameToWire(name) : name
    const box = type === RRType.TXT ? boxNames.attestation(wire) : boxNames.cache(wire, type)
    return (builder ?? this.writeClient!.newGroup()).prune({
      args: { name: wire, rrtype: type },
      boxReferences: [box, boxNames.credit(sender)],
      sender,
      signer,
    })
  }

  /** Delete an expired attestation (type 16) or cache entry (any other type). */
  prune = this.makeTxnExecutor({ maker: this.makePruneTxns })
}

/** The signer name of a step's RRSIG: right after the 18 fixed bytes. */
function signerOf(step: ProofStep): Uint8Array {
  return step.signedData.slice(18, step.signedData.length - step.rrset.length)
}

function toSigner(signer: SenderWithSigner['signer']): TransactionSigner {
  return typeof signer === 'function' ? signer : signer.signer
}
