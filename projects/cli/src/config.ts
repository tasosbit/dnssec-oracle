import dotenv from 'dotenv'

// Load .env, or .env.{ENV} when ENV is set
const envFile = process.env.ENV ? `.env.${process.env.ENV}` : '.env'
dotenv.config({ path: envFile })

export interface Config {
  algodHost: string
  algodPort: number
  algodToken: string
  appId?: string
  mnemonic?: string
  address?: string
  debug?: boolean
}

// LocalNet defaults: point ALGOD_* at a real node for testnet/mainnet
export function getConfig(): Config {
  return {
    algodHost: process.env.ALGOD_HOST || 'localhost',
    algodPort: parseInt(process.env.ALGOD_PORT || '4001'),
    algodToken: process.env.ALGOD_TOKEN ?? 'a'.repeat(64),
    appId: process.env.APP_ID || undefined,
    mnemonic: process.env.MNEMONIC || undefined,
    address: process.env.ADDRESS || undefined,
    debug: process.env.DEBUG === 'true',
  }
}
