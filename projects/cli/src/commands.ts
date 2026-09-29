import { readFileSync } from 'fs'
import { ALGORAND_ZERO_ADDRESS_STRING } from 'algosdk'
import {
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
  console.log(`${indent}weakestKeyBits: ${a.weakestKeyBits}  payer: ${a.payer}`)
}

const printTxIds = (txIds: string[]) => txIds.forEach((id) => console.log(`Transaction ID: ${id}`))

// ── Reads ─────────────────────────────────────────────────────────

export async function handleState(argv: Argv) {
  const { admin, anchorCount } = await makeSdk(argv).getState()
  console.log(`admin: ${admin}`)
  console.log(`anchorCount: ${anchorCount}`)
}

export async function handleGet(argv: Argv) {
  const names: string[] = argv.names
  const attestations = await makeSdk(argv).getAttestations(names)
  names.forEach((name, i) => {
    const a = attestations[i]
    if (!a) return console.log(`${name} N/A`)
    console.log(name)
    printAttestation(a)
  })
}

export async function handleList(argv: Argv) {
  for (const [key, a] of await makeSdk(argv).listAttestations()) {
    console.log(`${key} (sha256 of wire name)`)
    printAttestation(a)
  }
}

export async function handleCaches(argv: Argv) {
  for (const [key, c] of await makeSdk(argv).listCaches()) {
    console.log(`${key} inception=${isoTime(c.inception)} expiry=${isoTime(c.expiry)} weakestKeyBits=${c.weakestKeyBits}`)
  }
}

export async function handleTlds(argv: Argv) {
  for (const tld of await makeSdk(argv).getTlds()) console.log(tld)
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
  const tlds = String(argv.tlds).split(',').map((t) => t.trim()).filter(Boolean)
  const { txIds } = await sdk.setup({
    anchor: ANCHORS[argv.anchor],
    tlds,
    fund: argv.fund,
    credits: argv.credits === undefined ? undefined : Number(parseAlgo(argv.credits)),
  })
  console.log(`Set up with anchor KSK-${argv.anchor} and TLDs: ${tlds.join(', ')}`)
  printTxIds(txIds)
}

export async function handleCreate(argv: Argv) {
  const sdk = await createApp(argv)
  console.log(`Next: APP_ID=${sdk.appId} dnssec-oracle setup --anchor 2017 --tlds <tld,...>`)
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

export async function handleAddTld(argv: Argv) {
  printTxIds((await makeSdk(argv, { write: true }).addTld({ label: argv.label })).txIds)
}

export async function handleRemoveTld(argv: Argv) {
  printTxIds((await makeSdk(argv, { write: true }).removeTld({ label: argv.label })).txIds)
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
