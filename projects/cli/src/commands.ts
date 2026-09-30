import { readFileSync } from 'fs'
import { ALGORAND_ZERO_ADDRESS_STRING } from 'algosdk'
import {
  AnchorState,
  Attestation,
  DnssecOracleSDK,
  ROOT_KSK_2017,
  ROOT_KSK_2024,
  capturedResolver,
  nameFromWire,
  tcpResolver,
} from 'dnssec-oracle-sdk'
import { ClientArgs, createAlgorandClient, formatAlgo, isoTime, makeSdk, parseAlgo, requireWriter } from './utils'

// yargs argv: the global ClientArgs plus each command's own options
type Argv = ClientArgs & Record<string, any>

const ANCHORS: Record<string, Uint8Array> = { '2017': ROOT_KSK_2017, '2024': ROOT_KSK_2024 }

function printAttestation(a: Attestation, indent = '  ') {
  for (const text of a.texts) console.log(`${indent}text: ${text}`)
  console.log(`${indent}inception: ${isoTime(a.inception)}  expiration: ${isoTime(a.expiration)}`)
  console.log(`${indent}weakestKeyBits: ${a.weakestKeyBits}  parentEpoch: ${a.parentEpoch}  payer: ${a.payer}`)
}

const printTxIds = (txIds: string[]) => txIds.forEach((id) => console.log(`Transaction ID: ${id}`))

// ── Reads ─────────────────────────────────────────────────────────

export async function handleState(argv: Argv) {
  const { admin, anchorCount, rollInception, rootEpoch } = await makeSdk(argv).getState()
  console.log(`admin: ${admin}`)
  console.log(`anchorCount: ${anchorCount}`)
  console.log(`rollInception: ${rollInception ? isoTime(Number(rollInception)) : 'none'}`)
  console.log(`rootEpoch: ${rootEpoch}`)
}

export async function handleAnchors(argv: Argv) {
  for (const [hash, a] of await makeSdk(argv).listAnchors()) {
    console.log(`${hash} ${AnchorState[a.state]} since ${isoTime(a.since)}`)
  }
}

export async function handleGet(argv: Argv) {
  const names: string[] = argv.names
  const sdk = makeSdk(argv)
  const attestations = await sdk.getAttestations(names)
  for (const [i, name] of names.entries()) {
    const a = attestations[i]
    if (!a) {
      console.log(`${name} N/A`)
      continue
    }
    console.log(name)
    printAttestation(a)
    const zones = await sdk.attestationZones(name, a)
    const path = zones && [...zones.map((z) => nameFromWire(z)), '.'].join(' → ')
    console.log(path ? `  chain: live, ${path}` : '  chain: STALE, a key set above changed: prove it again')
  }
}

export async function handleList(argv: Argv) {
  const sdk = makeSdk(argv)
  const { rootEpoch } = await sdk.getState()
  for (const [key, a] of await sdk.listAttestations()) {
    console.log(`${key} (sha256 of wire name)`)
    printAttestation(a)
    // without the name the zones are unknown: only a revocation is visible here; `get` walks the chain
    if (BigInt(a.parentEpoch) < rootEpoch) console.log('  chain: STALE, predates a root key revocation')
  }
}

export async function handleCaches(argv: Argv) {
  for (const [key, c] of await makeSdk(argv).listCaches()) {
    console.log(`${key} inception=${isoTime(c.inception)} expiry=${isoTime(c.expiry)} weakestKeyBits=${c.weakestKeyBits} epoch=${c.epoch} parentEpoch=${c.parentEpoch}`)
  }
}

export async function handleCredits(argv: Argv) {
  const sdk = makeSdk(argv)
  if (argv.account) {
    const credit = await sdk.getCredits(argv.account)
    return console.log(`${argv.account} ${credit === undefined ? 'N/A' : `${formatAlgo(credit)} ALGO`}`)
  }
  for (const [account, credit] of await sdk.listCredits()) console.log(`${account} ${formatAlgo(credit)} ALGO`)
}

// ── Writes ────────────────────────────────────────────────────────

async function createApp(argv: Argv): Promise<DnssecOracleSDK> {
  const sdk = await DnssecOracleSDK.create({
    algorand: createAlgorandClient(argv),
    admin: requireWriter(argv),
    debug: argv.debug,
  })
  console.log(`App ID: ${sdk.appId}`)
  return sdk
}

async function setupApp(sdk: DnssecOracleSDK, argv: Argv) {
  const anchors: string[] = String(argv.anchors).split(',').map((a) => a.trim())
  const unknown = anchors.filter((a) => !ANCHORS[a])
  if (unknown.length) throw new Error(`Unknown anchor ${unknown.join(', ')}: use 2017 and/or 2024`)
  const { txIds } = await sdk.setup({
    anchors: anchors.map((a) => ANCHORS[a]),
    fund: argv.fund,
    credits: argv.credits === undefined ? undefined : Number(parseAlgo(argv.credits)),
  })
  console.log(`Set up with anchors ${anchors.map((a) => `KSK-${a}`).join(', ')}`)
  printTxIds(txIds)
}

export async function handleCreate(argv: Argv) {
  const sdk = await createApp(argv)
  console.log(`Next: APP_ID=${sdk.appId} dnssec-oracle setup --anchors 2017,2024`)
}

export async function handleSetup(argv: Argv) {
  await setupApp(makeSdk(argv, { write: true }), argv)
}

/** create + setup. If setup fails, the app exists: finish it with `setup` rather than deploying again. */
export async function handleDeploy(argv: Argv) {
  const sdk = await createApp(argv)
  try {
    await setupApp(sdk, argv)
  } catch (error) {
    throw new Error(
      `${(error as Error).message}\nApp ${sdk.appId} was created but not set up: retry with APP_ID=${sdk.appId} dnssec-oracle setup ...`,
    )
  }
}


export async function handleSetAdmin(argv: Argv) {
  if (argv.admin === ALGORAND_ZERO_ADDRESS_STRING && !argv.yes) {
    throw new Error('The zero address renounces the admin role for good: pass --yes to confirm')
  }
  printTxIds((await makeSdk(argv, { write: true }).setAdmin({ admin: argv.admin })).txIds)
}

export async function handleDepositCredits(argv: Argv) {
  const amount = parseAlgo(String(argv.amount))
  printTxIds((await makeSdk(argv, { write: true }).depositCredits({ amount, creditor: argv.creditor })).txIds)
}

export async function handleWithdrawCredits(argv: Argv) {
  printTxIds((await makeSdk(argv, { write: true }).withdrawCredits({})).txIds)
}

export async function handleProve(argv: Argv) {
  const resolver = argv.captured
    ? capturedResolver(JSON.parse(readFileSync(argv.captured, 'utf8')).responses)
    : tcpResolver(argv.resolver)
  const { proven, cached, txIds } = await makeSdk(argv, { write: true }).proveTxt(argv.name, {
    resolver,
    refreshMarginSeconds: argv.refreshMargin,
  })
  for (const step of cached) console.log(`cached  ${step.kind} ${nameFromWire(step.owner)}`)
  for (const step of proven) console.log(`proven  ${step.kind} ${nameFromWire(step.owner)}`)
  printTxIds(txIds)
}

export async function handlePrune(argv: Argv) {
  printTxIds((await makeSdk(argv, { write: true }).prune({ name: argv.name, type: argv.type })).txIds)
}

export async function handleMaintainAnchors(argv: Argv) {
  const { events, txIds } = await makeSdk(argv, { write: true }).maintainAnchors({ resolver: tcpResolver(argv.resolver) })
  for (const e of events) console.log(`${e.event} ${e.keyTag ?? ''} ${e.keyHash}`)
  if (events.length === 0) console.log('No rollover events')
  printTxIds(txIds)
}
