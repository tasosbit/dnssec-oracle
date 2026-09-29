import { SendParams } from '@algorandfoundation/algokit-utils/types/transaction'
import { Algodv2 } from 'algosdk'
import { SenderWithSigner, SendResult } from '../types.js'
import { getIncreaseBudgetBuilder } from './increaseBudget.js'

/**
 * Execute a transaction group with automatic budget increase: run the maker on a fresh
 * group, probe the opcode budget, and if an op-up is needed re-run the same maker on a
 * builder that already starts with an `increaseBudget` call.
 */
export async function executeTxns<T extends { builder?: unknown }>({
  txnBuilder,
  txnBuilderArgs,
  emptyGroupBuilder,
  sendParams,
  writerAccount,
  algod,
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  txnBuilder: (args: T) => Promise<any> | any
  txnBuilderArgs: T
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  emptyGroupBuilder: () => any
  sendParams?: SendParams
  writerAccount: SenderWithSigner
  algod: Algodv2
}): Promise<SendResult> {
  let builder = await txnBuilder(txnBuilderArgs)
  const increasedBudgetBuilder = await getIncreaseBudgetBuilder(
    builder,
    emptyGroupBuilder,
    writerAccount.sender.toString(),
    typeof writerAccount.signer === 'function' ? writerAccount.signer : writerAccount.signer.signer,
    algod,
  )
  if (increasedBudgetBuilder) builder = await txnBuilder({ ...txnBuilderArgs, builder: increasedBudgetBuilder })
  return builder.send(sendParams)
}

/**
 * Create a txn-executor factory bound to a specific SDK instance. Each write method is a
 * pure "maker" (appends its calls to `args.builder ?? newGroup()`); the returned executor
 * wraps it with the budget probe, error transformation, and an optional result transform.
 */
export function createTxnExecutor(
  sdkInstance: object,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  emptyGroupBuilder: () => any,
  wrapErrorsFn: <U>(p: Promise<U> | (() => Promise<U>)) => Promise<U>,
  getWriterAccount: () => SenderWithSigner | undefined,
  getAlgod: () => Algodv2,
) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return <T extends (...args: any) => any, R = SendResult>({
    maker,
    returnTransformer,
    sendParams,
  }: {
    maker: T
    returnTransformer?: (result: SendResult) => R
    sendParams?: SendParams
  }) => {
    return async (args: Omit<Parameters<T>[0], 'builder'>): Promise<R> => {
      const writerAccount = getWriterAccount()
      if (!writerAccount) {
        throw new Error(`writerAccount not set on the SDK instance`)
      }
      const result = await wrapErrorsFn(
        executeTxns({
          txnBuilder: (args) => maker.bind(sdkInstance)(args),
          txnBuilderArgs: args,
          emptyGroupBuilder,
          sendParams,
          writerAccount,
          algod: getAlgod(),
        }),
      )
      if (returnTransformer) {
        return returnTransformer(result)
      }
      return result as R
    }
  }
}
