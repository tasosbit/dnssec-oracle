import { AlgorandClient } from '@algorandfoundation/algokit-utils'
import { TransactionSignerAccount } from '@algorandfoundation/algokit-utils/types/account'
import {
  SendAtomicTransactionComposerResults,
  SendSingleTransactionResult,
} from '@algorandfoundation/algokit-utils/types/transaction'
import { Address, TransactionSigner } from 'algosdk'

/** An account that can sign write transactions. */
export type SenderWithSigner = {
  sender: string | Address
  signer: TransactionSigner | TransactionSignerAccount
}

export type ReaderConstructorArgs = {
  algorand: AlgorandClient
  appId: number | bigint
  /** Sender for simulated reads; defaults to the app's own address. */
  readerAccount?: string | Address
  debug?: boolean
}

export type ConstructorArgs = ReaderConstructorArgs & {
  writerAccount?: SenderWithSigner
}

export type SendResult = SendSingleTransactionResult | SendAtomicTransactionComposerResults
