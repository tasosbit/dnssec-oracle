import { AlgorandClient, Config } from '@algorandfoundation/algokit-utils'
import { nullLogger } from '@algorandfoundation/algokit-utils/types/logging'
import { Address, Algodv2, makeBasicAccountTransactionSigner, mnemonicToSecretKey } from 'algosdk'
import { DnssecOracleSDK, SenderWithSigner } from 'dnssec-oracle-sdk'

export interface ClientArgs {
  algodHost: string
  algodPort: number
  algodToken: string
  appId?: string
  mnemonic?: string
  address?: string
  debug?: boolean
}

const scheme = (port: number) => (port === 443 ? 'https' : 'http')

export function createAlgorandClient({ algodHost, algodPort, algodToken, debug }: ClientArgs): AlgorandClient {
  // algokit logs every group and dumps raw simulate traces: keep them for --debug
  if (!debug) Config.configure({ logger: nullLogger })
  const algod = new Algodv2(algodToken, `${scheme(algodPort)}://${algodHost}:${algodPort}`, algodPort)
  return AlgorandClient.fromClients({ algod })
}

/** Signer from a mnemonic; `address` overrides the sender for a rekeyed account. */
export function createWriterAccount(mnemonic?: string, address?: string): SenderWithSigner | undefined {
  if (!mnemonic) return undefined
  let account
  try {
    account = mnemonicToSecretKey(mnemonic)
  } catch (error) {
    throw new Error(`Invalid mnemonic: ${(error as Error).message}`)
  }
  const sender = address ? Address.fromString(address).toString() : account.addr.toString()
  return { sender, signer: makeBasicAccountTransactionSigner(account) }
}

export function requireWriter(argv: ClientArgs): SenderWithSigner {
  const writer = createWriterAccount(argv.mnemonic, argv.address)
  if (!writer) throw new Error('This command signs transactions: set MNEMONIC or pass --mnemonic')
  return writer
}

export function makeSdk(argv: ClientArgs, { write = false } = {}): DnssecOracleSDK {
  if (!argv.appId) throw new Error('Set APP_ID or pass --app-id')
  return new DnssecOracleSDK({
    algorand: createAlgorandClient(argv),
    appId: BigInt(argv.appId),
    writerAccount: write ? requireWriter(argv) : undefined,
    debug: argv.debug,
  })
}

/** "1.5" → 1_500_000n µAlgo, exactly: no float on the way. */
export function parseAlgo(amount: string): bigint {
  const match = /^(\d+)(?:\.(\d{1,6}))?$/.exec(amount.trim())
  if (!match) throw new Error(`Invalid ALGO amount "${amount}": use a non-negative number with at most 6 decimals`)
  return BigInt(match[1]) * 1_000_000n + BigInt((match[2] ?? '').padEnd(6, '0'))
}

export function formatAlgo(microAlgo: bigint): string {
  return `${microAlgo / 1_000_000n}.${(microAlgo % 1_000_000n).toString().padStart(6, '0')}`
}

export const isoTime = (seconds: number) => new Date(seconds * 1000).toISOString()
