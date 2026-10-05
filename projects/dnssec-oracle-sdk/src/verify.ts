import { Arc56Contract } from '@algorandfoundation/algokit-utils/types/app-arc56'
import { anchorHash, AnchorEntry, AnchorState, isTrusted } from './boxes.js'
import { HOLD_DOWN_SECONDS } from './constants.js'
import { COMPILER_INFO } from './generated/buildInfo.js'
import { IANA_DIGESTS, ROOT_ANCHORS } from './prover/anchors.js'
import { bytesEqual, concat, dsDigest, keyTag, sha256, toHex, u16 } from './prover/wire.js'

/**
 * Deployment verification: the checks that turn "we pin app id N" into "app id N runs this
 * contract, anchored to IANA's root keys, with nobody able to change either". The initial
 * anchors are loaded once by the admin (`addAnchors`), so the anchor boxes, not the program,
 * show which keys they were, and the admin should be renounced. `evaluateDeployment` is
 * pure: the reader SDK gathers `DeploymentFacts` and the CLI prints the result.
 */

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'skip'
export type CheckName = 'program' | 'rebuild' | 'actions' | 'anchors' | 'admin' | 'rootKeys'

export interface Check {
  name: CheckName
  status: CheckStatus
  message: string
  details?: Record<string, unknown>
}

/** `ok` is false when any check failed; warnings and skips do not clear it. */
export interface VerificationResult {
  ok: boolean
  checks: Check[]
}

/** The AVM version the contract is built for (`algokit compile ts --target-avm-version`). */
export const TARGET_AVM_VERSION = 13
export const IANA_ROOT_ANCHORS_URL = 'https://data.iana.org/root-anchors/root-anchors.xml'
/** algosdk's zero address: `setAdmin` to it renounces the role. */
export const ZERO_ADDRESS = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'

export interface VerifyOptions {
  /**
   * Root KSK DNSKEY RDATA accepted besides ROOT_ANCHORS, for a synthetic root (LocalNet).
   * An anchor from one of these passes but is reported as caller-supplied, not IANA's.
   */
  knownAnchors?: Uint8Array[]
  /**
   * The build the on-chain programs must match; defaults to the published APP_SPEC.
   */
  spec?: Arc56Contract
  /** Fetch root-anchors.xml and check the pinned digests, and the anchor set, against it. */
  iana?: boolean
  /**
   * Compile the contract sources shipped with the SDK and compare the on-chain programs to
   * that output too. `true` finds `contract/` and `puya-ts` on its own; pass paths otherwise.
   */
  rebuild?: boolean | { contractDir?: string; puyaTs?: string }
  /** Wall clock in seconds; defaults to now. */
  now?: number
  /** Injected for tests; defaults to the global fetch. */
  fetch?: typeof globalThis.fetch
}

/** One `<KeyDigest>` of IANA's root-anchors.xml. */
export interface IanaAnchor {
  id: string
  keyTag: number
  algorithm: number
  digestType: number
  /** Lowercase hex. */
  digest: string
  validFrom: string
  validUntil?: string
  /** Base64 DNSKEY public key; IANA lists it for current keys. */
  publicKey?: string
  flags?: number
}

export type RebuildOutput = { approval: Uint8Array; clear: Uint8Array; compilerVersion: string } | { skipped: string }

/** What `evaluateDeployment` judges. The reader SDK's `verifyDeployment` gathers it. */
export interface DeploymentFacts {
  appId: bigint
  /** On-chain programs. */
  approval: Uint8Array
  clear: Uint8Array
  globals: { admin: string; anchorCount: bigint; rootEpoch: bigint; rollInception: bigint }
  /** Anchor boxes, keyed by `sha256(alg ‖ pubkey)` hex. */
  anchors: Map<string, AnchorEntry>
  spec: Arc56Contract
  /** Present when a rebuild was asked for. */
  rebuilt?: RebuildOutput
  /** Present when the live IANA file was asked for. */
  iana?: { anchors: IanaAnchor[] } | { skipped: string }
}

const fromBase64 = (b64: string) => new Uint8Array(Buffer.from(b64, 'base64'))
const ROOT = new Uint8Array([0])
const DNSKEY_PROTOCOL = 3

/** DNSKEY RDATA for an IANA entry that lists its public key, or undefined. */
export function ianaDnskey(anchor: IanaAnchor): Uint8Array | undefined {
  if (anchor.publicKey === undefined || anchor.flags === undefined) return undefined
  return concat(u16(anchor.flags), new Uint8Array([DNSKEY_PROTOCOL, anchor.algorithm]), fromBase64(anchor.publicKey))
}

/** Entries valid at `now` (seconds): no `validUntil`, or one still ahead. */
export const currentIanaAnchors = (anchors: IanaAnchor[], now: number) =>
  anchors.filter((a) => a.validUntil === undefined || Date.parse(a.validUntil) / 1000 > now)

/** Parse root-anchors.xml. No XML library: the file is small, flat and IANA's. */
export function parseRootAnchorsXml(xml: string): IanaAnchor[] {
  const text = (block: string, tag: string) => block.match(new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`))?.[1]
  const attr = (open: string, name: string) => open.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1]
  const out: IanaAnchor[] = []
  for (const m of xml.matchAll(/<KeyDigest\b([^>]*)>([\s\S]*?)<\/KeyDigest>/g)) {
    const [, open, body] = m
    const digest = text(body, 'Digest')
    const tag = text(body, 'KeyTag')
    const algorithm = text(body, 'Algorithm')
    const digestType = text(body, 'DigestType')
    if (!digest || !tag || !algorithm || !digestType) throw new Error('root-anchors.xml: incomplete KeyDigest')
    const flags = text(body, 'Flags')
    out.push({
      id: attr(open, 'id') ?? '',
      keyTag: Number(tag),
      algorithm: Number(algorithm),
      digestType: Number(digestType),
      digest: digest.toLowerCase(),
      validFrom: attr(open, 'validFrom') ?? '',
      validUntil: attr(open, 'validUntil'),
      publicKey: text(body, 'PublicKey'),
      flags: flags === undefined ? undefined : Number(flags),
    })
  }
  if (out.length === 0) throw new Error('root-anchors.xml: no KeyDigest entries')
  return out
}

const sha256Hex = (b: Uint8Array) => toHex(sha256(b))
/** `puya 5.10.1`: from the spec when the generator kept it, else the build info generated beside the client. */
export const compilerVersionOf = (spec: Arc56Contract) => {
  const info = spec.compilerInfo ?? COMPILER_INFO
  const v = info.compilerVersion
  return `${info.compiler} ${v.major}.${v.minor}.${v.patch}`
}

const FORBIDDEN_ACTIONS = ['UpdateApplication', 'DeleteApplication']

const stateName = (state: AnchorState) => AnchorState[state] ?? `state ${state}`

/** Where a known root key came from, for the anchors check's messages. */
type KnownSource = 'IANA (pinned)' | 'IANA (live)' | 'caller'

export function evaluateDeployment(facts: DeploymentFacts, opts: VerifyOptions = {}): VerificationResult {
  const now = opts.now ?? Math.floor(Date.now() / 1000)
  const checks: Check[] = []

  // ── program: the deployed bytes are the bundled build ────────────
  const expected = { approval: fromBase64(facts.spec.byteCode?.approval ?? ''), clear: fromBase64(facts.spec.byteCode?.clear ?? '') }
  const onChain = { approval: sha256Hex(facts.approval), clear: sha256Hex(facts.clear) }
  const bundled = { approval: sha256Hex(expected.approval), clear: sha256Hex(expected.clear) }
  const programMatches = bytesEqual(facts.approval, expected.approval) && bytesEqual(facts.clear, expected.clear)
  checks.push({
    name: 'program',
    status: programMatches ? 'pass' : 'fail',
    message: programMatches
      ? `approval and clear programs match APP_SPEC (${compilerVersionOf(facts.spec)}), approval sha256 ${onChain.approval.slice(0, 16)}…`
      : `on-chain programs differ from APP_SPEC: approval ${onChain.approval.slice(0, 16)}… vs ${bundled.approval.slice(0, 16)}…` +
        (bytesEqual(facts.clear, expected.clear) ? '' : ', clear differs too'),
    details: { onChain, bundled, compiler: compilerVersionOf(facts.spec) },
  })

  // ── rebuild: the same, against a fresh compile of the shipped sources ──
  if (facts.rebuilt) {
    if ('skipped' in facts.rebuilt) {
      checks.push({ name: 'rebuild', status: 'skip', message: facts.rebuilt.skipped })
    } else {
      const { approval, clear, compilerVersion } = facts.rebuilt
      const same = bytesEqual(facts.approval, approval) && bytesEqual(facts.clear, clear)
      const sameCompiler = compilerVersion === compilerVersionOf(facts.spec)
      checks.push({
        name: 'rebuild',
        status: same ? 'pass' : sameCompiler ? 'fail' : 'warn',
        message: same
          ? `rebuilt programs (${compilerVersion}) match the chain`
          : sameCompiler
            ? `rebuilt programs (${compilerVersion}) differ from the chain: sources and deployment disagree`
            : `rebuilt programs differ from the chain, but the compiler differs too (${compilerVersion} here, ${compilerVersionOf(facts.spec)} in APP_SPEC): rebuild with the pinned toolchain`,
        details: { rebuilt: { approval: sha256Hex(approval), clear: sha256Hex(clear) }, onChain, compilerVersion },
      })
    }
  }

  // ── actions: nothing in the spec can update or delete the app ────
  const forbidden: string[] = []
  const bare = facts.spec.bareActions ?? { create: [], call: [] }
  for (const action of [...bare.create, ...bare.call]) {
    if (FORBIDDEN_ACTIONS.includes(action)) forbidden.push(`bare ${action}`)
  }
  for (const method of facts.spec.methods) {
    for (const action of [...method.actions.create, ...method.actions.call]) {
      if (FORBIDDEN_ACTIONS.includes(action)) forbidden.push(`${method.name} ${action}`)
    }
  }
  checks.push({
    name: 'actions',
    status: forbidden.length === 0 ? 'pass' : 'fail',
    message:
      forbidden.length === 0
        ? `no UpdateApplication or DeleteApplication action in the ARC-56 spec (${facts.spec.methods.length} methods, bare create ${bare.create.join('/') || 'none'})`
        : `the spec allows ${forbidden.join(', ')}`,
    details: { forbidden },
  })

  // ── anchors: every anchor box is a known root KSK, and IANA agrees ──
  const known = new Map<string, { rdata: Uint8Array; source: KnownSource; digest: string }>()
  const addKnown = (rdata: Uint8Array, source: KnownSource) => {
    const hash = toHex(anchorHash(rdata))
    if (!known.has(hash)) known.set(hash, { rdata, source, digest: toHex(dsDigest(ROOT, rdata)) })
  }
  for (const rdata of ROOT_ANCHORS) addKnown(rdata, 'IANA (pinned)')
  const liveIana = facts.iana && !('skipped' in facts.iana) ? currentIanaAnchors(facts.iana.anchors, now) : undefined
  for (const anchor of liveIana ?? []) {
    const rdata = ianaDnskey(anchor)
    if (rdata) addKnown(rdata, 'IANA (live)')
  }
  for (const rdata of opts.knownAnchors ?? []) addKnown(rdata, 'caller')

  const anchorRows: Record<string, unknown>[] = []
  const unknown: string[] = []
  const described: string[] = []
  let trusted = 0
  for (const [hash, entry] of facts.anchors) {
    const key = known.get(hash)
    if (isTrusted(entry)) trusted++
    if (!key) {
      unknown.push(hash)
      anchorRows.push({ hash, state: stateName(entry.state), since: entry.since, source: 'unknown' })
      continue
    }
    const tag = keyTag(key.rdata)
    const inPinned = IANA_DIGESTS.includes(key.digest)
    anchorRows.push({ hash, state: stateName(entry.state), since: entry.since, keyTag: tag, source: key.source, digest: key.digest, pinned: inPinned })
    described.push(`tag ${tag} ${stateName(entry.state)} (${inPinned ? 'IANA' : key.source})`)
  }

  const anchorProblems: string[] = []
  const anchorWarnings: string[] = []
  if (facts.globals.anchorCount === 0n) anchorProblems.push('anchorCount is 0: addAnchors has not run')
  if (facts.anchors.size === 0) anchorProblems.push('no anchor boxes')
  for (const hash of unknown) anchorProblems.push(`anchor ${hash} is not derivable from any known root KSK`)
  if (facts.anchors.size > 0 && trusted === 0) anchorProblems.push('no anchor is Valid or Missing: nothing can prove the root')
  if (liveIana) {
    const liveDigests = new Set(liveIana.map((a) => a.digest))
    for (const digest of IANA_DIGESTS) {
      if (!liveDigests.has(digest)) anchorProblems.push(`pinned digest ${digest.slice(0, 16)}… is not in IANA's current trust anchor file`)
    }
    for (const anchor of liveIana) {
      if (!IANA_DIGESTS.includes(anchor.digest)) anchorWarnings.push(`IANA lists key tag ${anchor.keyTag}, which the SDK does not pin: update prover/anchors.ts`)
      const rdata = ianaDnskey(anchor)
      if (rdata && !facts.anchors.has(toHex(anchorHash(rdata)))) anchorWarnings.push(`IANA key tag ${anchor.keyTag} is not an anchor of this oracle`)
    }
  } else if (facts.iana && 'skipped' in facts.iana) {
    anchorWarnings.push(`IANA file not checked: ${facts.iana.skipped}`)
  }
  checks.push({
    name: 'anchors',
    status: anchorProblems.length > 0 ? 'fail' : anchorWarnings.length > 0 ? 'warn' : 'pass',
    message: [
      ...anchorProblems,
      ...anchorWarnings,
      ...(anchorProblems.length === 0
        ? [`${described.join(', ')}${liveIana ? '; IANA file agrees' : ''}`]
        : []),
    ].join('; '),
    details: { anchorCount: facts.globals.anchorCount, anchors: anchorRows, iana: liveIana ? 'live' : 'pinned' },
  })

  // ── admin: renounced, so nobody holds a role over the contract ───
  const renounced = facts.globals.admin === ZERO_ADDRESS
  checks.push({
    name: 'admin',
    status: renounced ? 'pass' : 'warn',
    message: renounced
      ? 'renounced (zero address)'
      : `${facts.globals.admin} still holds the admin role: it can only hand the role on (addAnchors already ran: ${facts.globals.anchorCount > 0n}), but renounce it with set-admin`,
    details: { admin: facts.globals.admin },
  })

  // ── rootKeys: RFC 5011 state, so a stuck AddPend is visible ──────
  const stuck: string[] = []
  for (const [hash, entry] of facts.anchors) {
    if (entry.state === AnchorState.AddPend && now >= entry.since + HOLD_DOWN_SECONDS) {
      stuck.push(`${hash.slice(0, 16)}… AddPend since ${new Date(entry.since * 1000).toISOString()} with its hold-down over: no watcher ran updateAnchor`)
    }
  }
  const states = [...facts.anchors.values()].reduce<Record<string, number>>((acc, e) => {
    const name = stateName(e.state)
    acc[name] = (acc[name] ?? 0) + 1
    return acc
  }, {})
  checks.push({
    name: 'rootKeys',
    status: stuck.length > 0 ? 'warn' : 'pass',
    message:
      (stuck.length > 0 ? stuck.join('; ') + '; ' : '') +
      `rootEpoch ${facts.globals.rootEpoch}, rollInception ${
        facts.globals.rollInception === 0n ? 'none' : new Date(Number(facts.globals.rollInception) * 1000).toISOString()
      }, anchors ${
        Object.entries(states)
          .map(([k, v]) => `${v} ${k}`)
          .join(', ') || 'none'
      }`,
    details: { rootEpoch: facts.globals.rootEpoch, rollInception: facts.globals.rollInception, states },
  })

  return { ok: checks.every((c) => c.status !== 'fail'), checks }
}
