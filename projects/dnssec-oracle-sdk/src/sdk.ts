import { AlgorandClient, microAlgo } from '@algorandfoundation/algokit-utils'
import { TransactionSigner } from 'algosdk'
import { boxNames } from './boxes.js'
import {
  ANCHOR_BOX_MBR_MICROALGOS,
  CREDIT_BOX_MBR_MICROALGOS,
  DEFAULT_REFRESH_MARGIN_SECONDS,
  MIN_TXN_FEE_MICROALGOS,
  tldBoxMbrMicroAlgos,
} from './constants.js'
import { DnssecOracleClient, DnssecOracleComposer, DnssecOracleFactory } from './generated/DnssecOracleClient.js'
import { ROOT_ANCHORS } from './prover/anchors.js'
import { buildTxtChain, ProofStep } from './prover/chain.js'
import { Resolver, tcpResolver } from './prover/dns.js'
import { bytesEqual, nameFromWire, nameToWire, rdataOf, RRType, sha256, tldOf } from './prover/wire.js'
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
  /** Root trust anchors the chain may start from; defaults to KSK-2017 and KSK-2024. */
  anchors?: Uint8Array[]
  /** Refresh cache entries this close to expiry, in seconds. */
  refreshMarginSeconds?: number
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
   * base MBR and fee slack, deposit the admin's credits, upload the anchor, whitelist TLDs.
   */
  private async makeSetupTxns({
    anchor,
    tlds,
    fund = 200_000,
    credits,
    builder,
  }: { anchor: Uint8Array; tlds: string[]; fund?: number; credits?: number } & BuilderArgs) {
    const { sender, signer } = this.writer
    const appAddress = this.writeClient!.appAddress.toString()
    const needed =
      CREDIT_BOX_MBR_MICROALGOS + ANCHOR_BOX_MBR_MICROALGOS + tlds.reduce((n, t) => n + tldBoxMbrMicroAlgos(t), 0)
    const pay = (amount: number) =>
      this.algorand.createTransaction.payment({ sender, receiver: appAddress, amount: microAlgo(amount), note: `${noteNonce()}` })
    let group = (builder ?? this.writeClient!.newGroup()).addTransaction(await pay(fund), signer)
    group = await this.makeDepositCreditsTxns({ amount: credits ?? needed, builder: group })
    group = this.makeAddAnchorTxns({ anchor, builder: group })
    for (const label of tlds) group = this.makeAddTldTxns({ label, builder: group })
    return group
  }

  /** Step two of creation. See makeSetupTxns. */
  setup = this.makeTxnExecutor({ maker: this.makeSetupTxns })

  private makeAddAnchorTxns({ anchor, builder }: { anchor: Uint8Array } & BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).addAnchor({
      args: { dnskeyRdata: anchor },
      boxReferences: [boxNames.anchor(anchor), boxNames.credit(sender)],
      sender,
      signer,
    })
  }

  /** Upload the one root anchor (DNSKEY RDATA). Admin only, once. */
  addAnchor = this.makeTxnExecutor({ maker: this.makeAddAnchorTxns })

  private makeAddTldTxns({ label, builder }: { label: string } & BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).addTld({
      args: { label: new TextEncoder().encode(label.toLowerCase()) },
      boxReferences: [boxNames.tld(label), boxNames.credit(sender)],
      sender,
      signer,
    })
  }

  /** Whitelist a TLD, lowercased. Admin only. */
  addTld = this.makeTxnExecutor({ maker: this.makeAddTldTxns })

  private makeRemoveTldTxns({ label, builder }: { label: string } & BuilderArgs) {
    const { sender, signer } = this.writer
    return (builder ?? this.writeClient!.newGroup()).removeTld({
      args: { label: new TextEncoder().encode(label.toLowerCase()) },
      boxReferences: [boxNames.tld(label), boxNames.credit(sender)],
      sender,
      signer,
    })
  }

  /** Remove a TLD from the whitelist. Admin only. */
  removeTld = this.makeTxnExecutor({ maker: this.makeRemoveTldTxns })

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
            ...tldBox(step.owner),
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
            ...tldBox(step.owner),
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
            ...tldBox(step.owner),
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
   * already stored and fresh are skipped; an expired entry with a newer inception is pruned
   * first. The TXT step is always sent.
   */
  @wrapErrors()
  async proveChain(
    steps: ProofStep[],
    { refreshMarginSeconds = DEFAULT_REFRESH_MARGIN_SECONDS }: { refreshMarginSeconds?: number } = {},
  ): Promise<ProveChainResult> {
    const result: ProveChainResult = { proven: [], cached: [], txIds: [] }
    const now = Math.floor(Date.now() / 1000)
    for (const step of steps) {
      if (step.kind !== 'txt') {
        const cached = await this.getCache(step.owner, step.type)
        if (cached && bytesEqual(cached.hash, sha256(step.rrset)) && cached.expiry > now + refreshMarginSeconds) {
          result.cached.push(step)
          continue
        }
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

  /** Build `name TXT`'s chain from DNS and prove it: see buildTxtChain and proveChain. */
  @wrapErrors()
  async proveTxt(name: string, options: ProveTxtOptions = {}): Promise<ProveChainResult> {
    const steps = await buildTxtChain(name, options.resolver ?? tcpResolver(), {
      anchors: options.anchors ?? ROOT_ANCHORS,
    })
    return this.proveChain(steps, options)
  }

  // ── Rent ────────────────────────────────────────────────────────

  private makePruneTxns({ name, type, builder }: { name: NameLike; type: number } & BuilderArgs) {
    const { sender, signer } = this.writer
    const wire = typeof name === 'string' ? nameToWire(name) : name
    const box = type === RRType.TXT ? boxNames.attestation(wire) : boxNames.cache(wire, type)
    return (builder ?? this.writeClient!.newGroup()).prune({
      args: { name: wire, rrtype: type },
      boxReferences: [box, ...(type === RRType.TXT ? tldBox(wire) : []), boxNames.credit(sender)],
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

/** The owner's whitelist box; none for the root, which the contract rejects itself. */
const tldBox = (owner: Uint8Array) => (owner.length > 1 ? [boxNames.tld(new TextDecoder().decode(tldOf(owner)))] : [])

function toSigner(signer: SenderWithSigner['signer']): TransactionSigner {
  return typeof signer === 'function' ? signer : signer.signer
}
