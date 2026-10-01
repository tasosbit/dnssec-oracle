#!/usr/bin/env node

import yargs, { Argv } from 'yargs'
import { hideBin } from 'yargs/helpers'
import { getConfig } from './config'
import {
  handleAnchors,
  handleCaches,
  handleCreate,
  handleDeploy,
  handleCredits,
  handleDepositCredits,
  handleGet,
  handleKeys,
  handleList,
  handleMaintainAnchors,
  handleProve,
  handlePrune,
  handleSetAdmin,
  handleSetup,
  handleState,
  handleWithdrawCredits,
} from './commands'

// Every handler shares one error path: message to stderr, exit 1
const run = (handler: (argv: any) => Promise<void>) => async (argv: any) => {
  try {
    await handler(argv)
  } catch (error) {
    console.error('Error:', (error as Error).message)
    if (argv.debug) console.error(error)
    process.exit(1)
  }
}

const config = getConfig()

// shared by deploy and setup
const setupOptions = (y: Argv) =>
  y
    .option('anchors', { type: 'string', demandOption: true, description: 'Root KSK trust anchors: 2017, 2024 or 2017,2024' })
    .option('fund', { type: 'number', description: 'µAlgo sent to the app account (SDK default: 200000)' })
    .option('credits', { type: 'string', description: 'ALGO of credits to deposit (default: the exact rent needed)' })

yargs(hideBin(process.argv))
  .scriptName('dnssec-oracle')
  .option('algod-host', { type: 'string', default: config.algodHost, description: 'Algorand node host' })
  .option('algod-port', { type: 'number', default: config.algodPort, description: 'Algorand node port (443 → https)' })
  .option('algod-token', {
    type: 'string',
    default: config.algodToken,
    // never render secrets: --help output ends up in screenshots and bug reports
    defaultDescription: process.env.ALGOD_TOKEN ? '(set via ALGOD_TOKEN)' : '(LocalNet token)',
    description: 'Algorand node token',
  })
  .option('app-id', { type: 'string', default: config.appId, description: 'Oracle application ID' })
  .option('mnemonic', {
    type: 'string',
    default: config.mnemonic,
    defaultDescription: config.mnemonic ? '(set via MNEMONIC)' : undefined,
    description: 'Mnemonic of the signing account',
  })
  .option('address', {
    type: 'string',
    default: config.address,
    description: 'Sender address, when the mnemonic signs for a rekeyed account',
  })
  .option('debug', { type: 'boolean', default: config.debug, description: 'Verbose SDK output and stack traces' })

  // reads
  .command('state', 'Show admin, initial anchor count and rollover inception', {}, run(handleState))
  .command('anchors', 'List root anchors and their RFC 5011 states', {}, run(handleAnchors))
  .command(
    'get <names..>',
    'Show the TXT attestations for one or more names',
    (y) => y.positional('names', { type: 'string', array: true, demandOption: true }),
    run(handleGet),
  )
  .command('list', 'List every attestation box', {}, run(handleList))
  .command('caches', 'List every cached DNSKEY/DS entry', {}, run(handleCaches))
  .command(
    'keys <zone>',
    "Compare a zone's DNSKEY and DS RRsets in DNS with the oracle: cache, KSK/ZSK, DS links, root anchors",
    (y) =>
      y
        .positional('zone', { type: 'string', demandOption: true, description: 'Zone name, e.g. ., com or example.com' })
        .option('resolver', { type: 'string', default: '1.1.1.1', description: 'DNS server, queried over TCP' })
        .option('captured', { type: 'string', description: 'Read a captures/<date>/chains.json instead of querying DNS' }),
    run(handleKeys),
  )
  .command(
    'credits [account]',
    "Show an account's MBR credits, or every account's",
    (y) => y.positional('account', { type: 'string', description: 'Account address' }),
    run(handleCredits),
  )

  // setup and admin
  .command(
    'deploy',
    'Create the oracle app and set it up in one go (create + setup)',
    setupOptions,
    run(handleDeploy),
  )
  .command('create', 'Create the oracle app, with the signer as admin (step 1 of 2)', {}, run(handleCreate))
  .command(
    'setup',
    'Fund the app, deposit credits, add the root anchors (step 2 of 2, admin)',
    setupOptions,
    run(handleSetup),
  )
  .command(
    'set-admin <admin>',
    'Hand over the admin role; the zero address renounces it (admin)',
    (y) =>
      y
        .positional('admin', { type: 'string', demandOption: true })
        .option('yes', { type: 'boolean', default: false, description: 'Confirm renouncing to the zero address' }),
    run(handleSetAdmin),
  )

  // credits
  .command(
    'deposit-credits <amount>',
    'Deposit MBR credits, in ALGO',
    (y) =>
      y
        .positional('amount', { type: 'string', demandOption: true })
        .option('creditor', { type: 'string', description: 'Account credited (default: the signer)' }),
    run(handleDepositCredits),
  )
  .command('withdraw-credits', "Withdraw all of the signer's credits", {}, run(handleWithdrawCredits))

  // proofs
  .command(
    'prove <name>',
    "Prove a name's TXT RRset, refreshing any stale DNSKEY/DS cache entries on the way",
    (y) =>
      y
        .positional('name', { type: 'string', demandOption: true })
        .option('resolver', { type: 'string', default: '1.1.1.1', description: 'DNS server, queried over TCP' })
        .option('captured', { type: 'string', description: 'Replay a captures/<date>/chains.json instead of querying DNS' })
        .option('refresh-margin', { type: 'number', description: 'Re-prove cache entries this close to expiry, seconds (SDK default: 3600)' }),
    run(handleProve),
  )
  .command(
    'maintain-anchors',
    'Root KSK rollover watcher (RFC 5011): revoke, prove the root, add/promote/retire anchors. Run daily',
    (y) => y.option('resolver', { type: 'string', default: '1.1.1.1', description: 'DNS server, queried over TCP' }),
    run(handleMaintainAnchors),
  )
  .command(
    'prune <name>',
    'Delete an expired attestation (type 16) or cache entry (DNSKEY 48, DS 43)',
    (y) =>
      y
        .positional('name', { type: 'string', demandOption: true })
        .option('type', { type: 'number', default: 16, description: 'RR type' }),
    run(handlePrune),
  )
  .demandCommand(1, 'Specify a command')
  .strict()
  .help()
  .parse()
