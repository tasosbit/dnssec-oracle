import { AlgorandClient, microAlgo } from '@algorandfoundation/algokit-utils'
import { BoxReference } from '@algorandfoundation/algokit-utils/types/app-manager'
import { Transaction, TransactionSigner } from 'algosdk'
import { AnchorEntry, anchorHash, AnchorState, Attestation, boxNames, isTrusted } from './boxes.js'
import {
  ANCHOR_BOX_MBR_MICROALGOS,
  APP_CALL_BUDGET,
  attestationBoxMbrMicroAlgos,
  CACHE_BOX_MBR_MICROALGOS,
  CREDIT_BOX_MBR_MICROALGOS,
  DEFAULT_REFRESH_MARGIN_SECONDS,
  HOLD_DOWN_SECONDS,
  increaseBudgetBaseCost,
  increaseBudgetIncrementCost,
  MAX_OP_UP_ITXNS,
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
import { simulateUnsigned } from './util/increaseBudget.js'
import { noteNonce } from './util/noteNonce.js'
import { createTxnExecutor } from './util/txnExecutor.js'
import { errorTransformer, wrapErrors, wrapErrorsInternal } from './util/wrapErrors.js'

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

/** One call of a chain plan: a proof step, or the prune that clears the way for it. */
export interface PlanItem {
  action: 'prove' | 'prune'
  step: ProofStep
}

/** A group of a chain plan: an `increaseBudget` call, then its items in chain order. */
export interface PlannedGroup {
  items: (PlanItem & { opcodes: number })[]
  /** Unsigned and grouped, all from the writer. */
  transactions: Transaction[]
  /** Opcodes the items use together, as simulated. */
  opcodes: number
  /** No-op inner calls the `increaseBudget` call makes, 700 opcodes each. */
  opUps: number
  /** µAlgo, the whole group. */
  fee: number
}

export interface ChainPlan {
  /** Steps skipped because the cache already holds the same RRset, fresh. */
  cached: ProofStep[]
  groups: PlannedGroup[]
  /**
   * µAlgo of credits the first group deposits for the sender, ahead of its proofs: what new
   * boxes draw beyond the sender's credits (and its credit box's own MBR, without one). 0 if
   * they cover it.
   */
  deposit: number
  /** Steps one simulation could not reach: plan the chain again once `groups` confirm. */
  remaining: ProofStep[]
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
   * What proving a chain from buildTxtChain takes, parents before children. Cache steps whose
   * RRset is already stored, fresh and proven under the parent's entry as the run leaves it are
   * skipped; an expired entry with a newer inception is pruned first. One from before the last
   * revocation is simply overwritten. The TXT step is always sent.
   */
  private async triage(steps: ProofStep[], refreshMarginSeconds: number) {
    const now = Math.floor(Date.now() / 1000)
    const rootEpoch = Number((await this.getState()).rootEpoch)
    const entries = await this.getRawCaches(steps.map((s) => [s.owner, s.type]))
    // each entry's epoch once the run is done; NaN for a new one, which nothing cached matches
    const epochs = new Map<string, number>()
    const cached: ProofStep[] = []
    const items: PlanItem[] = []
    // credits the items draw, net of refunds to the sender: the most at any point is the rent
    let charge = 0
    let rent = 0
    const draw = (micro: number) => (rent = Math.max(rent, (charge += micro)))
    for (const [i, step] of steps.entries()) {
      if (step.kind === 'txt') {
        items.push({ action: 'prove', step })
        // the old box's rent goes back to its payer, which only helps if that is the sender
        const old = await this.getRawAttestation(step.owner)
        draw(
          attestationMbr({ records: rdataOf(step.rrset) }) -
            (old?.payer === this.writer.sender.toString() ? attestationMbr(old) : 0),
        )
        continue
      }
      const found = entries[i]
      const parentEpoch = step.kind === 'root' ? rootEpoch : (epochs.get(parentKey(step)) ?? (await this.parentEpoch(step)))
      const same = !!found && bytesEqual(found.hash, sha256(step.rrset))
      if (same && found.parentEpoch === parentEpoch && found.expiry > now + refreshMarginSeconds) {
        cached.push(step)
        epochs.set(cacheKey(step.owner, step.type), found.epoch)
        continue
      }
      // the contract overwrites an entry from before the last revocation whatever its inception
      let current = found && found.epoch >= rootEpoch ? found : undefined
      if (current && current.inception > step.inception) {
        // expired: anyone may prune it, and the older RRset, still valid, proves into a fresh box
        if (current.expiry >= now) {
          throw new Error(
            `${nameFromWire(step.owner)} ${step.type}: the cache holds a newer RRset (inception ` +
              `${current.inception} > ${step.inception}); rebuild the chain from fresh DNS data`,
          )
        }
        items.push({ action: 'prune', step })
        current = undefined
      }
      items.push({ action: 'prove', step })
      // a new box; a pruned one refunds the sender first, so its proof draws nothing net
      if (!found) draw(CACHE_BOX_MBR_MICROALGOS)
      // writeCache keeps the epoch only for the same RRset under the same parent generation
      epochs.set(cacheKey(step.owner, step.type), current && same && current.parentEpoch === parentEpoch ? current.epoch : NaN)
    }
    return { cached, items, rent }
  }

  /** The current epoch of the entry a cache step is verified against; 0 if none. */
  private async parentEpoch(step: ProofStep): Promise<number> {
    if (step.kind === 'root') return Number((await this.getState()).rootEpoch)
    const parent =
      step.kind === 'ds'
        ? await this.getRawCache(signerOf(step), RRType.DNSKEY)
        : await this.getRawCache(step.owner, RRType.DS)
    return parent?.epoch ?? 0
  }

  /**
   * Prove a chain from buildTxtChain, one group per call, each simulated as it goes: see
   * triage for what is skipped. planChain sends fewer groups, all signed at once.
   */
  @wrapErrors()
  async proveChain(
    steps: ProofStep[],
    { refreshMarginSeconds = DEFAULT_REFRESH_MARGIN_SECONDS }: { refreshMarginSeconds?: number } = {},
  ): Promise<ProveChainResult> {
    const { cached, items } = await this.triage(steps, refreshMarginSeconds)
    const result: ProveChainResult = { proven: [], cached, txIds: [] }
    for (const { action, step } of items) {
      if (action === 'prune') {
        result.txIds.push(...(await this.prune({ name: step.owner, type: step.type })).txIds)
        continue
      }
      const sent = await this.proveStep({ step })
      if (this.debug) console.log(`proved ${step.kind} ${nameFromWire(step.owner)}`, sent.txIds)
      result.proven.push(step)
      result.txIds.push(...sent.txIds)
    }
    return result
  }

  /**
   * Plan a chain from buildTxtChain as unsigned groups, to sign all at once and send in order.
   * The calls triage keeps run in one simulated group behind a maximal op-up, which measures
   * each against the state the calls before it leave (algod simulates one group at a time,
   * and a group cannot see another still pending). Then they are packed, in order, into as
   * few groups as one group's budget allows: 700 opcodes per app call, 16 calls and 256 op-up
   * inner calls, 190,400 at most. An RSA-2048 check (about 92k) takes a group to itself;
   * P-256 checks (about 2.5k) share one.
   *
   * Each group must confirm, or at least reach the pool, before the next is sent: every call
   * checks the cache entry a call before it writes. A sender needs the fees, the credits for
   * new boxes (the first group deposits any shortfall: `deposit`), and about 0.5 Algo
   * spendable for the measuring simulation.
   */
  @wrapErrors()
  async planChain(
    steps: ProofStep[],
    { refreshMarginSeconds = DEFAULT_REFRESH_MARGIN_SECONDS }: { refreshMarginSeconds?: number } = {},
  ): Promise<ChainPlan> {
    const { cached, items: all, rent } = await this.triage(steps, refreshMarginSeconds)
    const { sender } = this.writer
    const credits = await this.getCredits(sender.toString())
    // refunds to the sender land only in a credit box: without one, deposit first to open it,
    // even when refunds would cover the rent
    const deposit = credits === undefined ? rent + CREDIT_BOX_MBR_MICROALGOS : Math.max(0, rent - Number(credits))
    // the deposit's payment and call, behind the op-up and ahead of the first group's items
    const depositTxns = deposit ? 2 : 0
    const withDeposit = async (builder: NonNullable<BuilderArgs['builder']>) =>
      deposit ? this.makeDepositCreditsTxns({ amount: deposit, builder }) : builder

    const measured = all.slice(0, MAX_GROUP_SIZE - 1 - depositTxns)
    let builder = await withDeposit(this.makeOpUp({ itxns: MAX_OP_UP_ITXNS }))
    for (const item of measured) builder = await this.makeItemTxns(item, builder)
    const { group, txns } = await simulateUnsigned(builder, this.algorand.client.algod, 2 * MAX_OP_UP_ITXNS * MIN_TXN_FEE_MICROALGOS)

    // a call that ran out of budget (the simulation's, not a real group's) waits for the next plan
    // the group: the op-up at 0, the deposit's transactions, then the items
    const failedTxn = group.failedAt?.length ? Number(group.failedAt[0]) : undefined
    const failedAt = failedTxn === undefined ? undefined : failedTxn - 1 - depositTxns
    if (failedAt !== undefined && (failedAt < 1 || !/budget exceeded/.test(group.failureMessage ?? ''))) {
      const failed = measured[failedAt]
      const error = await errorTransformer(new Error(group.failureMessage))
      error.message = `${failed ? `${failed.action} ${nameFromWire(failed.step.owner)} ${failed.step.type}` : failedTxn === 0 ? 'increaseBudget' : 'deposit'}: ${error.message}`
      throw error
    }
    const items = measured.slice(0, failedAt).map((item, i) => ({
      ...item,
      opcodes: Number(group.txnResults[i + 1 + depositTxns].appBudgetConsumed ?? 0),
      bytes: txns[i + 1 + depositTxns].toByte().length,
    }))
    // fee usage beyond the op-up, its inner calls and the deposit (one unit each), shared out by size
    const usage = Math.max(0, Number(group.groupUsage ?? 0) / 1_000_000 - 1 - MAX_OP_UP_ITXNS - depositTxns)
    const bytes = items.reduce((n, item) => n + item.bytes, 0)

    // ponytail: greedy, in order; optimal for contiguous runs under one capacity
    const runs: (typeof items)[] = []
    for (const item of items) {
      const run = runs.at(-1)
      const room = MAX_GROUP_SIZE - 1 - (runs.length === 1 ? depositTxns : 0)
      if (run && run.length < room && opUpsFor([...run, item]) <= MAX_OP_UP_ITXNS) run.push(item)
      else runs.push([item])
    }

    const groups: PlannedGroup[] = []
    for (const [g, run] of runs.entries()) {
      const opUps = opUpsFor(run)
      const units = 1 + opUps + (usage * run.reduce((n, item) => n + item.bytes, 0)) / bytes
      const shortfall = Math.max(0, Math.ceil(units * MIN_TXN_FEE_MICROALGOS) - (1 + run.length + opUps) * MIN_TXN_FEE_MICROALGOS)
      const txt = run.find((item) => item.step.kind === 'txt')
      const opUp = this.makeOpUp({
        itxns: opUps,
        extraFee: opUps * MIN_TXN_FEE_MICROALGOS + shortfall,
        boxReferences: txt && (await this.txtBoxes(txt.step, sender.toString())),
      })
      let groupBuilder = g === 0 ? await withDeposit(opUp) : opUp
      for (const item of run) groupBuilder = await this.makeItemTxns(item, groupBuilder)
      const transactions = (await (await groupBuilder.composer()).build()).transactions.map((t) => t.txn)
      groups.push({
        items: run.map(({ action, step, opcodes }) => ({ action, step, opcodes })),
        transactions,
        opcodes: run.reduce((n, item) => n + item.opcodes, 0),
        opUps,
        fee: transactions.reduce((n, t) => n + Number(t.fee), 0),
      })
    }
    const remaining = all.slice(items.length).flatMap(({ action, step }) => (action === 'prove' ? [step] : []))
    return { cached, groups, deposit, remaining }
  }

  private makeOpUp({ itxns, extraFee = itxns * MIN_TXN_FEE_MICROALGOS, boxReferences }: { itxns: number; extraFee?: number; boxReferences?: BoxReference[] }) {
    const { sender, signer } = this.writer
    return this.writeClient!.newGroup().increaseBudget({
      args: { itxns },
      extraFee: microAlgo(extraFee),
      boxReferences,
      note: `${noteNonce()}`,
      sender,
      signer,
    })
  }

  private async makeItemTxns({ action, step }: PlanItem, builder: BuilderArgs['builder']) {
    return action === 'prune'
      ? this.makePruneTxns({ name: step.owner, type: step.type, builder })
      : this.makeProveTxns({ step, builder })
  }

  /**
   * The box references a TXT step needs beyond its own: the replaced attestation's payer, whose
   * credits get the refund, and empty ones for box I/O quota, 1 KB each, since the old and the
   * new attestation may each come near 4 KB. Placed on the op-up call: references are shared
   * across a group. send() gets these from algokit's resource population, which simulates the
   * group alone and so cannot run a planned group whose parent is still pending.
   */
  private async txtBoxes(step: ProofStep, sender: string): Promise<BoxReference[]> {
    const payer = (await this.getRawAttestation(step.owner))?.payer
    const refs = payer && payer !== sender ? [{ appId: 0n, name: boxNames.credit(payer) }] : []
    while (refs.length < MAX_APP_REFERENCES) refs.push({ appId: 0n, name: new Uint8Array() })
    return refs
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

  private makePruneManyTxns({ targets, builder }: { targets: { name: NameLike; type: number }[] } & BuilderArgs) {
    return targets.reduce((b, t) => this.makePruneTxns({ ...t, builder: b }), builder ?? this.writeClient!.newGroup())
  }

  /** `prune` several boxes in one group: at most 16. */
  pruneMany = this.makeTxnExecutor({ maker: this.makePruneManyTxns })
}

/** Transactions in a group, and references (boxes included) one app call may carry. */
const MAX_GROUP_SIZE = 16
const MAX_APP_REFERENCES = 8

const cacheKey = (owner: Uint8Array, type: number) => `${toHex(owner)} ${type}`

/** The cache entry a non-root step is proven under. */
function parentKey(step: ProofStep): string {
  return step.kind === 'dnskey' ? cacheKey(step.owner, RRType.DS) : cacheKey(signerOf(step), RRType.DNSKEY)
}

/**
 * The op-up inner calls a group of these calls needs, behind one `increaseBudget` call: the
 * same sum probeOpUp does, over the calls' simulated opcodes.
 */
function opUpsFor(run: { opcodes: number }[]): number {
  const opcodes = run.reduce((n, item) => n + item.opcodes, 0)
  const own = APP_CALL_BUDGET * (run.length + 1) - increaseBudgetBaseCost
  return Math.max(0, Math.ceil((opcodes - own) / (APP_CALL_BUDGET - increaseBudgetIncrementCost)))
}

const attestationMbr = ({ records }: Pick<Attestation, 'records'>) =>
  attestationBoxMbrMicroAlgos(records.reduce((n, r) => n + r.length, 0), records.length)

/** The signer name of a step's RRSIG: right after the 18 fixed bytes. */
function signerOf(step: ProofStep): Uint8Array {
  return step.signedData.slice(18, step.signedData.length - step.rrset.length)
}

function toSigner(signer: SenderWithSigner['signer']): TransactionSigner {
  return typeof signer === 'function' ? signer : signer.signer
}
