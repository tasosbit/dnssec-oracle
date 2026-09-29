import type { AlgorandClient } from '@algorandfoundation/algokit-utils'
import type { TransactionComposer } from '@algorandfoundation/algokit-utils/types/composer'
import type { TransactionWithSigner } from 'algosdk'

/**
 * Build a maker's group, let `mutate` tamper with it, and send it. `txns` is the live
 * array: mutate fields, splice transactions in or out, or swap signers. Fees are not
 * recomputed, so set them yourself when the mutation changes what the group owes.
 */
export async function sendMutated(
  sdk: { algorand: AlgorandClient },
  builder: { composer(): Promise<TransactionComposer> },
  mutate: (txns: TransactionWithSigner[]) => void | Promise<void> = () => {},
) {
  // clone(): fresh ATC with group ids cleared; addAtc re-groups on send
  const atc = (await (await builder.composer()).build()).atc.clone()
  // @ts-expect-error private
  await mutate(atc.transactions)
  return sdk.algorand.newGroup().addAtc(atc).send()
}
