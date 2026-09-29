import { microAlgo } from '@algorandfoundation/algokit-utils'
import { TransactionSignerAccount } from '@algorandfoundation/algokit-utils/types/account'
import { TransactionComposer } from '@algorandfoundation/algokit-utils/types/composer'
import { Algodv2, makeEmptyTransactionSigner, modelsv2, TransactionSigner } from 'algosdk'
import { APP_CALL_BUDGET, increaseBudgetBaseCost, increaseBudgetIncrementCost, MIN_TXN_FEE_MICROALGOS } from '../constants.js'
import { noteNonce } from './noteNonce.js'

/** Shared simulate options for every readonly / probing path. */
export const SIMULATE_PARAMS = {
  allowMoreLogging: true,
  allowUnnamedResources: true,
  // simulate's maximum: a probe must never run out before the group does (it can use 190,400)
  extraOpcodeBudget: 320_000,
  fixSigners: true,
  allowEmptySignatures: true,
}

const simulateRequest = new modelsv2.SimulateRequest({
  txnGroups: [],
  ...SIMULATE_PARAMS,
})

/**
 * Probe a transaction group's opcode budget and fee, and return what an `increaseBudget`
 * call prepended to it must carry: `itxns` op-up inner transactions to cover the budget
 * shortfall, and `extraFee` for those plus any usage fee the group owes beyond its own
 * fees. Undefined when the group fits its own budget and pays its own usage.
 *
 * `itxns` 0 is not undefined: a deficit smaller than one inner call is covered by the
 * op-up transaction's own app-call budget, so the caller still prepends the call.
 *
 * The count assumes the op-up call will be PREPENDED to the probed group: it credits
 * that extra outer app call's own budget, minus what increaseBudget itself costs. The op-up
 * call and its inner calls are small, so each adds one fee unit of usage, which its own
 * fee and `itxns × 1000` cover.
 *
 * Fees: under v42 a group owes `groupUsage` millionths of the minimum fee, which is more
 * than one per transaction once transactions are large (a 4 KB argument owes about 2.2).
 *
 * The probe replaces every signer with an empty one, so a group signed by a logic
 * signature simulates without the program running — its fee rules cannot fail the
 * probe, and the fee forced onto txn 0 below cannot violate them.
 */
export async function probeOpUp(
  builder: { composer(): Promise<TransactionComposer> },
  algod: Algodv2,
): Promise<{ itxns: number; extraFee: number } | undefined> {
  // maxFee/coverAppCallInnerTransactionFees does not work with builder.simulate() #algokit
  // increase first txn's fee so the probe does not fail because of fees
  // (need to clone the atc to make txns mutable)
  const atc = (await (await builder.composer()).build()).atc.clone()
  // @ts-expect-error private and readonly
  const ownFees = atc.transactions.reduce((n, t) => n + Number(t.txn.fee), 0)
  // @ts-expect-error private and readonly
  atc.transactions[0].txn.fee = 256_000n // 256x min fee

  // replace signers with empty signers for simulation so end users are not prompted to sign
  // @ts-expect-error private and readonly
  atc.transactions = atc.transactions.map((t) => {
    t.signer = makeEmptyTransactionSigner()
    return t
  })

  const {
    simulateResponse: {
      txnGroups: [{ txnResults, appBudgetConsumed = 0, groupUsage = 0 }],
    },
  } = await atc.simulate(algod, simulateRequest)

  // intentionally doing op-up even if the probe reports a failure: returning early
  // would let out-of-budget errors obscure the actual failure on send

  const usageShortfall = Math.max(0, Math.ceil((Number(groupUsage) * MIN_TXN_FEE_MICROALGOS) / 1_000_000) - ownFees)

  // existing budget: count OUTER app calls (inner-call budget is added at call time
  // and cannot be fully relied upon here)
  const numAppCalls = txnResults.filter(({ txnResult }) => txnResult?.txn.txn.type === 'appl').length

  let existingBudget = APP_CALL_BUDGET * numAppCalls

  // budget and fee are OK, returning
  if (appBudgetConsumed <= existingBudget && usageShortfall === 0) return

  existingBudget += APP_CALL_BUDGET - increaseBudgetBaseCost // the op-up call's own 700 minus its base cost
  const itxnBudgetNeeded = appBudgetConsumed - existingBudget // budget to create in itxns

  const itxns = Math.max(0, Math.ceil(itxnBudgetNeeded / (APP_CALL_BUDGET - increaseBudgetIncrementCost)))
  return { itxns, extraFee: itxns * MIN_TXN_FEE_MICROALGOS + usageShortfall }
}

/**
 * Probe a transaction group's opcode budget and fee, and if either is short, return a new
 * builder with an `increaseBudget` call prepended, sized and priced to the measurement.
 * Returns undefined when the group fits its own budget and pays its own usage.
 */
export async function getIncreaseBudgetBuilder<
  T extends { composer(): Promise<TransactionComposer>; increaseBudget(args: never): T },
>(
  builder: T,
  newBuilderFactory: () => T,
  sender: string,
  signer: TransactionSigner | TransactionSignerAccount,
  algod: Algodv2,
): Promise<T | undefined> {
  const opUp = await probeOpUp(builder, algod)
  if (opUp === undefined) return

  const increaseBudgetArgs = {
    args: { itxns: opUp.itxns },
    extraFee: microAlgo(opUp.extraFee),
    maxFee: microAlgo(MIN_TXN_FEE_MICROALGOS + opUp.extraFee),
    note: noteNonce().toString(),
    sender,
    signer,
  }

  return newBuilderFactory().increaseBudget(increaseBudgetArgs as never)
}
