import { readFileSync } from 'fs'
import { ALGORAND_ZERO_ADDRESS_STRING } from 'algosdk'
import {
  AnchorEntry,
  AnchorState,
  Attestation,
  CacheEntry,
  DnssecOracleSDK,
  Ds,
  ROOT_KSK_2017,
  ROOT_KSK_2024,
  Resolver,
  RRType,
  anchorHash,
  ancestors,
  bytesEqual,
  canonicalRRset,
  capturedResolver,
  dsDigest,
  keyBits,
  keyProblem,
  keyTag,
  nameFromWire,
  nameToWire,
  parseDnskey,
  parseDs,
  parseResponse,
  parseRrsig,
  sha256,
  tcpResolver,
  toHex,
} from '@d13co/dnssec-oracle-sdk'
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

/** Live DNS over TCP, or a captures/<date>/chains.json replay. */
const resolverOf = (argv: Argv): Resolver =>
  argv.captured ? capturedResolver(JSON.parse(readFileSync(argv.captured, 'utf8')).responses) : tcpResolver(argv.resolver)

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
  const attestations = await sdk.getRawAttestations(names)
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
  for (const [key, a] of await sdk.listRawAttestations()) {
    console.log(`${key} (sha256 of wire name)`)
    printAttestation(a)
    // without the name the zones are unknown: only a revocation is visible here; `get` walks the chain
    if (BigInt(a.parentEpoch) < rootEpoch) console.log('  chain: STALE, predates a root key revocation')
  }
}

export async function handleCaches(argv: Argv) {
  for (const [key, c] of await makeSdk(argv).listRawCaches()) {
    console.log(`${key} inception=${isoTime(c.inception)} expiry=${isoTime(c.expiry)} weakestKeyBits=${c.weakestKeyBits} epoch=${c.epoch} parentEpoch=${c.parentEpoch}`)
  }
}

/** What `zoneKeysReport` reads from the oracle. Injected, so tests can run it on a capture. */
export interface KeyLookups {
  cache(zone: Uint8Array, type: number): Promise<CacheEntry | undefined>
  anchor(dnskeyRdata: Uint8Array): Promise<AnchorEntry | undefined>
  rootEpoch(): Promise<number>
}

const typeName = (type: number) => (type === RRType.DS ? 'DS' : 'DNSKEY')

/**
 * `zone type` from DNS, and the hash the oracle would cache for it under each RRSIG's original
 * TTL. `problem` says why there is nothing to compare: the oracle could not prove it either.
 */
async function fetchZoneRRset(resolver: Resolver, zone: Uint8Array, type: number) {
  const { rcode, answers } = parseResponse(await resolver(zone, type))
  if (rcode !== 0) throw new Error(`${nameFromWire(zone)} ${typeName(type)}: DNS rcode ${rcode}`)
  const own = answers.filter((rr) => bytesEqual(rr.owner, zone))
  const rrs = own.filter((rr) => rr.type === type)
  const ttls = new Set(
    own
      .filter((rr) => rr.type === RRType.RRSIG)
      .map((rr) => parseRrsig(rr.rdata))
      .filter((s) => s.typeCovered === type)
      .map((s) => s.originalTtl),
  )
  let problem: string | undefined
  if (own.some((rr) => rr.type === RRType.CNAME)) problem = 'DNS serves a CNAME, which the oracle does not follow'
  else if (rrs.length === 0) problem = `DNS serves no ${typeName(type)}`
  else if (ttls.size === 0) problem = `DNS serves the ${typeName(type)} RRset unsigned`
  const hashes = problem ? [] : [...ttls].map((ttl) => sha256(canonicalRRset(rrs, ttl)))
  return { rdatas: rrs.map((rr) => rr.rdata), hashes, problem }
}

/**
 * The cache entry against DNS: the oracle stores only `sha256(canonical RRset)`. `stale` names
 * why the oracle would refuse the entry as a parent even when it matches.
 */
function cacheStatus(
  entry: CacheEntry | undefined,
  rrset: { hashes: Uint8Array[]; problem?: string },
  now: number,
  stale?: string,
): string {
  const verdict = rrset.problem ?? (entry && rrset.hashes.some((h) => bytesEqual(h, entry.hash)) ? 'cache matches DNS' : 'cache differs from DNS')
  if (!entry) return rrset.problem ? `${rrset.problem}; not cached` : 'not cached'
  const expired = entry.expiry < now ? ' (expired)' : ''
  const notes = stale ? ` (stale: ${stale})` : ''
  return `${verdict}; inception ${isoTime(entry.inception)}, expiry ${isoTime(entry.expiry)}${expired}, epoch ${entry.epoch}${notes}`
}

function keyRole(flags: number): string {
  const roles: Record<number, string> = { 256: 'ZSK', 257: 'KSK' }
  const role = roles[flags & ~0x80] ?? `flags ${flags}`
  return flags & 0x80 ? `${role} REVOKED` : role
}

function keySize(rdata: Uint8Array): string {
  const { algorithm } = parseDnskey(rdata)
  if (algorithm === 13) return 'P-256 (alg 13)'
  return [5, 7, 8, 10].includes(algorithm) ? `RSA-${keyBits(rdata)} (alg ${algorithm})` : `alg ${algorithm}`
}

/**
 * A zone's DNSKEY and DS RRsets as DNS serves them, next to what the oracle holds: whether each
 * cache entry is the RRset DNS serves and still usable, both as a parent and by consumers whose
 * walk runs through it to the root; each key's role, size and whether the oracle accepts it; which DS vouches for which key, and for the root each key's
 * anchor state.
 */
export async function zoneKeysReport(
  zoneName: string,
  resolver: Resolver,
  lookups: KeyLookups,
  now = Math.floor(Date.now() / 1000),
): Promise<string[]> {
  const zone = nameToWire(zoneName)
  const root = zone.length === 1
  const name = nameFromWire(zone)
  const rootEpoch = await lookups.rootEpoch()
  const dnskey = await fetchZoneRRset(resolver, zone, RRType.DNSKEY)
  const ds = root ? undefined : await fetchZoneRRset(resolver, zone, RRType.DS)
  const dsRecords = (ds?.rdatas ?? []).map(parseDs)
  const dnskeyEntry = await lookups.cache(zone, RRType.DNSKEY)
  const dsEntry = root ? undefined : await lookups.cache(zone, RRType.DS)
  // the contract's checkDs: digest type 2, then key tag, algorithm and sha256(owner ‖ RDATA)
  const vouches = (d: Ds, rdata: Uint8Array) =>
    d.digestType === 2 && d.keyTag === keyTag(rdata) && d.algorithm === parseDnskey(rdata).algorithm && bytesEqual(d.digest, dsDigest(zone, rdata))
  // the contract refuses a parent from before the last revocation; consumers' walk (attestationChainLive)
  // also needs every link up to the root current: DNSKEY to its DS, DS to the parent's DNSKEY, root to rootEpoch
  const staleness = async (entry: CacheEntry | undefined, type: number): Promise<string | undefined> => {
    if (!entry) return undefined
    if (entry.epoch < rootEpoch) return 'predates a root key revocation'
    let [at, atType, atEntry, where] = [zone, type, entry, '']
    while (at.length > 1 || atType !== RRType.DNSKEY) {
      const [up, upType] = atType === RRType.DNSKEY ? [at, RRType.DS] : [ancestors(at)[1], RRType.DNSKEY]
      const parent = await lookups.cache(up, upType)
      const label = `${nameFromWire(up)} ${typeName(upType)} entry`
      if (!parent) return `${where}no ${label} above it`
      if (atEntry.parentEpoch !== parent.epoch) return `${where}proven under an older ${label}`
      ;[at, atType, atEntry, where] = [up, upType, parent, `${label}: `]
    }
    if (atEntry.parentEpoch !== rootEpoch) return `${where}proven under an older anchor set`
  }

  const lines = [`${name} DNSKEY: ${cacheStatus(dnskeyEntry, dnskey, now, await staleness(dnskeyEntry, RRType.DNSKEY))}`]
  for (const rdata of dnskey.rdatas) {
    const key = parseDnskey(rdata)
    const usable = keyProblem(rdata, key.algorithm) ?? 'usable by the oracle'
    let link: string
    if (root) {
      const anchor = await lookups.anchor(rdata)
      const state = anchor ? `anchor ${AnchorState[anchor.state]} since ${isoTime(anchor.since)}` : 'not an anchor'
      link = `${state}, id ${toHex(anchorHash(rdata))}`
    } else {
      link = dsRecords.some((d) => vouches(d, rdata)) ? 'DS matches' : 'no DS'
    }
    lines.push(`  ${keyRole(key.flags)} ${keyTag(rdata)}, ${keySize(rdata)}: ${usable}; ${link}`)
  }

  if (!ds) return lines
  lines.push(`${name} DS: ${cacheStatus(dsEntry, ds, now, await staleness(dsEntry, RRType.DS))}`)
  for (const d of dsRecords) {
    const head = `  DS ${d.keyTag}, alg ${d.algorithm}, digest type ${d.digestType}`
    if (d.digestType !== 2) {
      lines.push(`${head}: ignored by the oracle (SHA-256 only)`)
      continue
    }
    const key = dnskey.rdatas.find((k) => vouches(d, k))
    lines.push(`${head}: ${key ? `vouches for ${keyRole(parseDnskey(key).flags)} ${d.keyTag}` : 'matches no key in the DNSKEY RRset'}`)
  }
  return lines
}

export async function handleKeys(argv: Argv) {
  const sdk = makeSdk(argv)
  const lookups: KeyLookups = {
    cache: (zone, type) => sdk.getRawCache(zone, type),
    anchor: (rdata) => sdk.getAnchor(rdata),
    rootEpoch: async () => Number((await sdk.getState()).rootEpoch),
  }
  // a capture is judged at its own time, not the wall clock's
  const now = argv.captured ? JSON.parse(readFileSync(argv.captured, 'utf8')).capturedAt : undefined
  for (const line of await zoneKeysReport(argv.zone, resolverOf(argv), lookups, now)) console.log(line)
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
  const { proven, cached, txIds } = await makeSdk(argv, { write: true }).proveTxt(argv.name, {
    resolver: resolverOf(argv),
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
