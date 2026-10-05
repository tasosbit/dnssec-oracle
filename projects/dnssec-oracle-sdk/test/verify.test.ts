import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { Arc56Contract } from '@algorandfoundation/algokit-utils/types/app-arc56'
import { AnchorEntry, AnchorState, anchorHash } from '../src/boxes'
import { HOLD_DOWN_SECONDS } from '../src/constants'
import { APP_SPEC } from '../src/generated/DnssecOracleClient'
import { IANA_DIGESTS, ROOT_KSK_2017, ROOT_KSK_2024 } from '../src/prover/anchors'
import { concat, dsDigest, toHex, u16 } from '../src/prover/wire'
import {
  Check,
  CheckName,
  compilerVersionOf,
  currentIanaAnchors,
  DeploymentFacts,
  evaluateDeployment,
  ianaDnskey,
  parseRootAnchorsXml,
  ZERO_ADDRESS,
} from '../src/verify'

const xml = readFileSync(join(__dirname, 'fixtures/root-anchors.xml'), 'utf8')
const now = 1_790_000_000 // 2026-09-21

/** A root KSK nobody published: flags 257, RSA-SHA256, an arbitrary 32-byte key field. */
const UNKNOWN_KSK = concat(u16(257), new Uint8Array([3, 8]), new Uint8Array(32).fill(7))

const valid = (since = now - 10 * 86_400): AnchorEntry => ({ state: AnchorState.Valid, since })
const anchorsOf = (entries: [Uint8Array, AnchorEntry][]) => new Map(entries.map(([key, entry]) => [toHex(anchorHash(key)), entry]))

const decode = (b64: string) => new Uint8Array(Buffer.from(b64, 'base64'))

const facts = (over: Partial<DeploymentFacts> = {}): DeploymentFacts => ({
  appId: 1001n,
  approval: decode(APP_SPEC.byteCode!.approval),
  clear: decode(APP_SPEC.byteCode!.clear),
  globals: { admin: ZERO_ADDRESS, anchorCount: 2n, rootEpoch: 1n, rollInception: 0n },
  anchors: anchorsOf([
    [ROOT_KSK_2017, valid()],
    [ROOT_KSK_2024, valid()],
  ]),
  spec: APP_SPEC,
  ...over,
})

const check = (checks: Check[], name: CheckName) => {
  const found = checks.find((c) => c.name === name)
  if (!found) throw new Error(`no ${name} check`)
  return found
}

describe('evaluateDeployment', () => {
  it('passes a deployment that is the bundled build, IANA-anchored', () => {
    const result = evaluateDeployment(facts(), { now })
    expect(result.ok).toBe(true)
    for (const name of ['program', 'actions', 'anchors', 'admin', 'rootKeys'] as const) {
      expect(check(result.checks, name).status, name).toBe('pass')
    }
    expect(result.checks.find((c) => c.name === 'rebuild')).toBeUndefined()
    expect(check(result.checks, 'program').message).toMatch(/match APP_SPEC \(puya \d+\.\d+\.\d+\)/)
    expect(check(result.checks, 'anchors').message).toMatch(/^tag 20326 Valid \(IANA\), tag 38696 Valid \(IANA\)$/)
    expect(result.checks.map((c) => c.name)).toEqual(['program', 'actions', 'anchors', 'admin', 'rootKeys'])
  })

  describe('admin', () => {
    it('passes when renounced, warns naming a live admin', () => {
      expect(check(evaluateDeployment(facts(), { now }).checks, 'admin')).toMatchObject({ status: 'pass', message: 'renounced (zero address)' })
      const admin = 'GD64YIY3TWGDMCNPP553DZPPR6LDUSFQOIJVFDPPXWEG3FVOJCCDBBHU5A'
      const result = evaluateDeployment(facts({ globals: { ...facts().globals, admin } }), { now })
      expect(check(result.checks, 'admin').status).toBe('warn')
      expect(check(result.checks, 'admin').message).toContain(admin)
      expect(result.ok).toBe(true)
    })
  })

  it('accepts another build as the expected program when told so', () => {
    const approval = decode(APP_SPEC.byteCode!.approval)
    approval[approval.length - 1] ^= 1
    const spec: Arc56Contract = { ...APP_SPEC, byteCode: { approval: Buffer.from(approval).toString('base64'), clear: APP_SPEC.byteCode!.clear } }
    expect(check(evaluateDeployment(facts({ approval }), { now }).checks, 'program').status).toBe('fail')
    expect(check(evaluateDeployment(facts({ approval, spec }), { now }).checks, 'program').status).toBe('pass')
  })

  describe('program', () => {
    it('fails on one flipped byte in the approval program', () => {
      const approval = decode(APP_SPEC.byteCode!.approval)
      approval[approval.length - 1] ^= 1
      const result = evaluateDeployment(facts({ approval }), { now })
      expect(result.ok).toBe(false)
      expect(check(result.checks, 'program').status).toBe('fail')
      expect(check(result.checks, 'program').message).toMatch(/differ from APP_SPEC/)
      expect(check(result.checks, 'program').message).not.toMatch(/clear differs too/)
    })

    it('fails on a different clear program and says so', () => {
      const clear = decode(APP_SPEC.byteCode!.clear)
      clear[0] ^= 1
      const result = evaluateDeployment(facts({ clear }), { now })
      expect(check(result.checks, 'program').status).toBe('fail')
      expect(check(result.checks, 'program').message).toMatch(/clear differs too/)
    })
  })

  describe('rebuild', () => {
    const chain = { approval: decode(APP_SPEC.byteCode!.approval), clear: decode(APP_SPEC.byteCode!.clear) }
    const specCompiler = compilerVersionOf(APP_SPEC)

    it('passes when the rebuilt bytes match the chain', () => {
      const result = evaluateDeployment(facts({ rebuilt: { ...chain, compilerVersion: specCompiler } }), { now })
      expect(check(result.checks, 'rebuild').status).toBe('pass')
    })

    it('fails on a mismatch with the same compiler, warns with another', () => {
      const approval = new Uint8Array(chain.approval)
      approval[5] ^= 0xff
      const same = evaluateDeployment(facts({ rebuilt: { approval, clear: chain.clear, compilerVersion: specCompiler } }), { now })
      expect(check(same.checks, 'rebuild').status).toBe('fail')
      expect(same.ok).toBe(false)
      const other = evaluateDeployment(facts({ rebuilt: { approval, clear: chain.clear, compilerVersion: 'puya 9.0.0' } }), { now })
      expect(check(other.checks, 'rebuild').status).toBe('warn')
      expect(check(other.checks, 'rebuild').message).toMatch(/pinned toolchain/)
      expect(other.ok).toBe(true)
    })

    it('skips with the reason when no compiler ran', () => {
      const result = evaluateDeployment(facts({ rebuilt: { skipped: 'puya-ts not found' } }), { now })
      expect(check(result.checks, 'rebuild')).toMatchObject({ status: 'skip', message: 'puya-ts not found' })
    })
  })

  describe('actions', () => {
    it('fails when a bare call may update the app', () => {
      const spec: Arc56Contract = { ...APP_SPEC, bareActions: { create: ['NoOp'], call: ['UpdateApplication'] } }
      const result = evaluateDeployment(facts({ spec }), { now })
      expect(check(result.checks, 'actions')).toMatchObject({ status: 'fail', message: 'the spec allows bare UpdateApplication' })
      expect(result.ok).toBe(false)
    })

    it('fails when a method may delete the app', () => {
      const [first, ...rest] = APP_SPEC.methods
      const spec: Arc56Contract = { ...APP_SPEC, methods: [{ ...first, actions: { create: [], call: ['NoOp', 'DeleteApplication'] } }, ...rest] }
      const result = evaluateDeployment(facts({ spec }), { now })
      expect(check(result.checks, 'actions').message).toBe(`the spec allows ${first.name} DeleteApplication`)
    })
  })

  describe('anchors', () => {
    it('fails on an anchor from a key nobody knows, naming its hash', () => {
      const anchors = anchorsOf([
        [ROOT_KSK_2017, valid()],
        [ROOT_KSK_2024, valid()],
        [UNKNOWN_KSK, valid()],
      ])
      const result = evaluateDeployment(facts({ anchors, globals: { ...facts().globals, anchorCount: 3n } }), { now })
      expect(result.ok).toBe(false)
      expect(check(result.checks, 'anchors').status).toBe('fail')
      expect(check(result.checks, 'anchors').message).toContain(`anchor ${toHex(anchorHash(UNKNOWN_KSK))} is not derivable from any known root KSK`)
    })

    it('accepts a caller-supplied key, reported as such', () => {
      const anchors = anchorsOf([[UNKNOWN_KSK, valid()]])
      const result = evaluateDeployment(facts({ anchors, globals: { ...facts().globals, anchorCount: 1n } }), { now, knownAnchors: [UNKNOWN_KSK] })
      expect(check(result.checks, 'anchors').status).toBe('pass')
      expect(check(result.checks, 'anchors').message).toMatch(/^tag \d+ Valid \(caller\)$/)
    })

    it('fails when addAnchors never ran', () => {
      const result = evaluateDeployment(facts({ anchors: new Map(), globals: { ...facts().globals, anchorCount: 0n } }), { now })
      expect(check(result.checks, 'anchors').status).toBe('fail')
      expect(check(result.checks, 'anchors').message).toMatch(/anchorCount is 0: addAnchors has not run/)
    })

    it('fails when no anchor can prove the root any more', () => {
      const anchors = anchorsOf([
        [ROOT_KSK_2017, { state: AnchorState.Revoked, since: now - 1 }],
        [ROOT_KSK_2024, { state: AnchorState.AddPend, since: now - 1 }],
      ])
      const result = evaluateDeployment(facts({ anchors }), { now })
      expect(check(result.checks, 'anchors').message).toMatch(/no anchor is Valid or Missing/)
    })

    it('agrees with the live IANA file, and fails when a pinned digest left it', () => {
      const live = evaluateDeployment(facts({ iana: { anchors: parseRootAnchorsXml(xml) } }), { now })
      expect(check(live.checks, 'anchors').status).toBe('pass')
      expect(check(live.checks, 'anchors').message).toMatch(/IANA file agrees$/)

      const without2024 = parseRootAnchorsXml(xml).filter((a) => a.keyTag !== 38696)
      const stale = evaluateDeployment(facts({ iana: { anchors: without2024 } }), { now })
      expect(check(stale.checks, 'anchors').status).toBe('fail')
      expect(check(stale.checks, 'anchors').message).toMatch(/pinned digest 683d2d0acb8c9b71… is not in IANA's current trust anchor file/)
    })

    it('warns when IANA lists a key the SDK does not pin or the oracle does not anchor', () => {
      const extra = { ...parseRootAnchorsXml(xml)[2], keyTag: 11111, digest: 'ab'.repeat(32), publicKey: undefined }
      const result = evaluateDeployment(facts({ iana: { anchors: [...parseRootAnchorsXml(xml), extra] } }), { now })
      expect(check(result.checks, 'anchors').status).toBe('warn')
      expect(check(result.checks, 'anchors').message).toMatch(/IANA lists key tag 11111, which the SDK does not pin/)

      const missing = evaluateDeployment(facts({ anchors: anchorsOf([[ROOT_KSK_2017, valid()]]), iana: { anchors: parseRootAnchorsXml(xml) } }), { now })
      expect(check(missing.checks, 'anchors').status).toBe('warn')
      expect(check(missing.checks, 'anchors').message).toMatch(/IANA key tag 38696 is not an anchor of this oracle/)
    })

    it('warns, not fails, when the IANA fetch was skipped', () => {
      const result = evaluateDeployment(facts({ iana: { skipped: 'offline' } }), { now })
      expect(check(result.checks, 'anchors')).toMatchObject({ status: 'warn' })
      expect(check(result.checks, 'anchors').message).toMatch(/IANA file not checked: offline/)
      expect(result.ok).toBe(true)
    })
  })

  describe('rootKeys', () => {
    it('reports the epoch and states, and warns about an AddPend past its hold-down', () => {
      const fresh = anchorsOf([
        [ROOT_KSK_2017, valid()],
        [ROOT_KSK_2024, { state: AnchorState.AddPend, since: now - 86_400 }],
      ])
      const pending = evaluateDeployment(facts({ anchors: fresh, globals: { ...facts().globals, rootEpoch: 3n, rollInception: BigInt(now - 86_400) } }), { now })
      expect(check(pending.checks, 'rootKeys').status).toBe('pass')
      expect(check(pending.checks, 'rootKeys').message).toMatch(/rootEpoch 3, rollInception 2026-09-20T.*, anchors 1 Valid, 1 AddPend/)

      const stuck = anchorsOf([
        [ROOT_KSK_2017, valid()],
        [ROOT_KSK_2024, { state: AnchorState.AddPend, since: now - HOLD_DOWN_SECONDS }],
      ])
      const result = evaluateDeployment(facts({ anchors: stuck }), { now })
      expect(check(result.checks, 'rootKeys').status).toBe('warn')
      expect(check(result.checks, 'rootKeys').message).toMatch(/hold-down over: no watcher ran updateAnchor/)
    })
  })
})

describe('parseRootAnchorsXml', () => {
  it('reads IANA\'s file: the retired KSK-2010 and the two pinned keys', () => {
    const anchors = parseRootAnchorsXml(xml)
    expect(anchors.map((a) => a.keyTag)).toEqual([19036, 20326, 38696])
    expect(anchors[0].validUntil).toBe('2019-01-11T00:00:00+00:00')
    expect(anchors[0].publicKey).toBeUndefined()
    expect(anchors.slice(1).map((a) => a.digest)).toEqual([...IANA_DIGESTS])
    expect(currentIanaAnchors(anchors, now).map((a) => a.keyTag)).toEqual([20326, 38696])
  })

  it('rebuilds the DNSKEY RDATA from the listed public key, matching the pinned anchors', () => {
    const [, k2017, k2024] = parseRootAnchorsXml(xml)
    expect(ianaDnskey(k2017)).toEqual(ROOT_KSK_2017)
    expect(ianaDnskey(k2024)).toEqual(ROOT_KSK_2024)
    expect(toHex(dsDigest(new Uint8Array([0]), ianaDnskey(k2024)!))).toBe(k2024.digest)
  })

  it('rejects a file without entries or with an incomplete one', () => {
    expect(() => parseRootAnchorsXml('<TrustAnchor></TrustAnchor>')).toThrow(/no KeyDigest/)
    expect(() => parseRootAnchorsXml('<KeyDigest id="x"><KeyTag>1</KeyTag></KeyDigest>')).toThrow(/incomplete/)
  })
})
