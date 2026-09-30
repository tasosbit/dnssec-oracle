import { Bytes, bytes } from '@algorandfoundation/algorand-typescript'
import { TestExecutionContext } from '@algorandfoundation/algorand-typescript-testing'
import {
  anchorHash,
  AnchorState,
  buildRootSteps,
  capturedResolver,
  chainLinks,
  concat,
  HOLD_DOWN_SECONDS,
  montgomeryHint,
  nameToWire,
  rdataOf,
  ROOT_KSK_2017,
  ROOT_KSK_2024,
  RRType,
  sha256,
  toHex,
  u16,
} from 'dnssec-oracle-sdk'
import { afterEach, describe, expect, test } from 'vitest'
import { DnssecOracle } from '../smart_contracts/dnssec_oracle/contract.algo'
import { attestationParentEpoch } from '../smart_contracts/dnssec_oracle/reader.algo'
import fixture from './fixtures/2026-09-28.json'
import { dsRdata, ecKey, rsaKey, signRRset, TestKey, txt, withFlags } from './zone'

/*
 * RFC 5011 rollover in the emulator: its 30-day hold-downs need a clock LocalNet cannot
 * move back. Root keys are P-256 to keep the runs fast; the captured test uses the real root.
 */

const ctx = new TestExecutionContext()
afterEach(() => ctx.reset())

const code = (c: string) => new RegExp(`ERR:${c}\\b`)
const B = (x: Uint8Array) => Bytes(x)
const DAY = 86400
const T0 = 1_800_000_000
const ROOT = new Uint8Array([0])
const NO_HINT = B(new Uint8Array())

const at = (latestTimestamp: number) => ctx.ledger.patchGlobalData({ latestTimestamp })
const hash = (k: TestKey | Uint8Array) => Bytes(anchorHash(k instanceof Uint8Array ? k : k.rdata)) as bytes<32>

function deploy(anchors: (TestKey | Uint8Array)[], now = T0) {
  const contract = ctx.contract.create(DnssecOracle)
  // the emulator lacks AVM 13's app_params_set: initialise what createApplication would
  contract.admin.value = ctx.defaultSender
  contract.anchorCount.value = 0
  contract.rollInception.value = 0
  contract.lastEpoch.value = 1
  contract.rootEpoch.value = 1
  at(now)
  contract.addAnchors(anchors.map((k) => B(k instanceof Uint8Array ? k : k.rdata)))
  return contract
}

/** The anchor's state, 0 without a box, and when it was entered. */
function anchor(contract: DnssecOracle, k: TestKey | Uint8Array) {
  const box = contract.anchors(hash(k))
  return box.exists ? { state: Number(box.value.state), since: Number(box.value.since) } : { state: 0, since: 0 }
}

const zsk = ecKey({ flags: 256 })

/** The root DNSKEY RRset of `keys` plus a ZSK, signed by `signer` with inception `t`. */
function rootSet(signer: TestKey, keys: TestKey[], t: number, validFor = 10 * DAY) {
  const signed = signRRset(signer, ROOT, RRType.DNSKEY, [...keys.map((k) => k.rdata), zsk.rdata], {
    signer: ROOT,
    inception: t,
    expiration: t + validFor,
  })
  const keyIndex = rdataOf(signed.rrset).findIndex((r) => toHex(r) === toHex(signer.rdata))
  return { ...signed, keyIndex }
}

type Signed = ReturnType<typeof rootSet>
const proveRoot = (c: DnssecOracle, s: Signed) => c.proveRoot(B(s.signedData), B(s.signature), NO_HINT, s.keyIndex)
const revokeRoot = (c: DnssecOracle, s: Signed) => c.revokeRoot(B(s.signedData), B(s.signature), NO_HINT, s.keyIndex)
const update = (c: DnssecOracle, s: Signed, k: TestKey) => c.updateAnchor(B(s.rrset), hash(k))

describe('root rollover (RFC 5011)', () => {
  test('addAnchors: once, no duplicates, all Valid', () => {
    const [k0, k1, k2] = [ecKey(), ecKey(), ecKey()]
    // the emulator does not roll back a failed call: k0's box would survive it
    expect(() => deploy([k0, k0])).toThrow(code('AST'))
    const contract = deploy([k1, k2])
    expect(anchor(contract, k1)).toEqual({ state: AnchorState.Valid, since: T0 })
    expect(anchor(contract, k2).state).toBe(AnchorState.Valid)
    expect(() => contract.addAnchors([B(ecKey().rdata)])).toThrow(code('AST'))
  })

  test('Add, hold-down, Promote: the new key then proves the root', () => {
    const [k1, k2] = [ecKey(), ecKey()]
    const contract = deploy([k1])
    at(T0 + DAY)
    const withK2 = rootSet(k1, [k1, k2], T0)
    proveRoot(contract, withK2)
    update(contract, withK2, k2)
    expect(anchor(contract, k2)).toEqual({ state: AnchorState.AddPend, since: T0 + DAY })
    expect(contract.rollInception.value).toEqual(T0)

    // AddPend is not trusted
    expect(() => proveRoot(contract, rootSet(k2, [k1, k2], T0 + DAY))).toThrow(code('ANC'))
    expect(() => update(contract, withK2, k2)).toThrow(code('HLD'))

    const promoteAt = T0 + DAY + HOLD_DOWN_SECONDS
    at(promoteAt - 1)
    const later = rootSet(k1, [k1, k2], promoteAt - DAY)
    proveRoot(contract, later)
    expect(() => update(contract, later, k2)).toThrow(code('HLD'))
    at(promoteAt)
    update(contract, later, k2)
    expect(anchor(contract, k2)).toEqual({ state: AnchorState.Valid, since: promoteAt })
    proveRoot(contract, rootSet(k2, [k1, k2], promoteAt))

    // nothing left to do for either key
    const current = rootSet(k2, [k1, k2], promoteAt)
    expect(() => update(contract, current, k2)).toThrow(code('ROL'))
    expect(() => update(contract, current, k1)).toThrow(code('ROL'))
  })

  test('Add takes only usable KSKs that are in the cached RRset', () => {
    const k1 = ecKey()
    const contract = deploy([k1])
    const [zone, weakExponent, absent] = [ecKey({ flags: 256 }), rsaKey({ bits: 1024, exponent: 3 }), ecKey()]
    at(T0 + DAY)
    const set = rootSet(k1, [k1, zone, weakExponent], T0)
    proveRoot(contract, set)
    expect(() => update(contract, set, zone)).toThrow(code('ROL'))
    expect(() => update(contract, set, weakExponent)).toThrow(code('EXP'))
    expect(() => update(contract, set, absent)).toThrow(code('ROL'))
    // the RRset must be the cached one
    expect(() => update(contract, rootSet(k1, [k1, absent], T0), absent)).toThrow(code('PAR'))
  })

  test('Reset, Miss and Return', () => {
    const [k1, k2, k3] = [ecKey(), ecKey(), ecKey()]
    const contract = deploy([k1, k2])
    at(T0 + DAY)
    const withK3 = rootSet(k1, [k1, k2, k3], T0)
    proveRoot(contract, withK3)
    update(contract, withK3, k3)
    expect(anchor(contract, k3).state).toBe(AnchorState.AddPend)

    // k3 and k2 leave
    const onlyK1 = rootSet(k1, [k1], T0 + DAY)
    proveRoot(contract, onlyK1)
    update(contract, onlyK1, k3)
    expect(anchor(contract, k3).state).toBe(0)
    expect(() => update(contract, onlyK1, k3)).toThrow(code('ROL'))
    update(contract, onlyK1, k2)
    expect(anchor(contract, k2)).toEqual({ state: AnchorState.Missing, since: T0 + DAY })
    expect(() => update(contract, onlyK1, k2)).toThrow(code('ROL'))

    // a Missing anchor is still trusted, and comes back
    at(T0 + 2 * DAY)
    const back = rootSet(k2, [k1, k2], T0 + 2 * DAY)
    proveRoot(contract, back)
    update(contract, back, k2)
    expect(anchor(contract, k2)).toEqual({ state: AnchorState.Valid, since: T0 + 2 * DAY })
  })

  test('Revoke, then Retire 30 days later', () => {
    const [k1, k2] = [ecKey(), ecKey()]
    const k1r = withFlags(k1, 385)
    const contract = deploy([k1, k2])
    at(T0 + DAY)
    const revocation = rootSet(k1r, [k1r, k2], T0 + DAY)
    revokeRoot(contract, revocation)
    expect(anchor(contract, k1)).toEqual({ state: AnchorState.Revoked, since: T0 + DAY })
    expect(() => revokeRoot(contract, revocation)).toThrow(code('ANC'))
    // an RRset from before the revocation, still valid, no longer proves
    expect(() => proveRoot(contract, rootSet(k1, [k1, k2], T0))).toThrow(code('ANC'))

    const retireAt = T0 + DAY + HOLD_DOWN_SECONDS
    at(retireAt - 1)
    const current = rootSet(k2, [k1r, k2], retireAt - DAY)
    proveRoot(contract, current)
    expect(() => update(contract, current, k1)).toThrow(code('HLD'))
    at(retireAt)
    update(contract, current, k1)
    expect(anchor(contract, k1).state).toBe(0)
    // still in the RRset, but revoked: not added back
    expect(() => update(contract, current, k1)).toThrow(code('ROL'))
  })

  test('revoking an AddPend key stales nothing: it never proved anything', () => {
    const [k1, k2] = [ecKey(), ecKey()]
    const k2r = withFlags(k2, 385)
    const contract = deploy([k1])
    at(T0 + DAY)
    const withK2 = rootSet(k1, [k1, k2], T0)
    proveRoot(contract, withK2)
    update(contract, withK2, k2)
    expect(anchor(contract, k2).state).toBe(AnchorState.AddPend)
    revokeRoot(contract, rootSet(k2r, [k1, k2r], T0 + DAY))
    expect(anchor(contract, k2)).toEqual({ state: AnchorState.Revoked, since: T0 + DAY })
    expect(contract.rootEpoch.value).toEqual(1)
  })

  test('revokeRoot: self-signed, flags 385, by an anchor', () => {
    const [k1, k2, k3] = [ecKey(), ecKey(), ecKey()]
    const [k1r, k3r] = [withFlags(k1, 385), withFlags(k3, 385)]
    const contract = deploy([k1, k2])
    at(T0 + DAY)
    expect(() => revokeRoot(contract, rootSet(k1, [k1, k2], T0))).toThrow(code('RVK'))
    expect(() => revokeRoot(contract, rootSet(k3r, [k1, k2, k3r], T0))).toThrow(code('ANC'))
    // k2 signs, but the data names k1r as the signer
    const forged = rootSet(k2, [k1r, k2], T0)
    const k1rIndex = rdataOf(forged.rrset).findIndex((r) => toHex(r) === toHex(k1r.rdata))
    expect(() => revokeRoot(contract, { ...forged, keyIndex: k1rIndex })).toThrow(code('SIG'))
    // a revoked key cannot prove the root either
    expect(() => proveRoot(contract, rootSet(k1r, [k1r, k2], T0))).toThrow(code('KFL'))
  })

  test('an RSA-2048 anchor, like the real root KSK, revokes itself', () => {
    const [k1, k2] = [rsaKey(), ecKey()]
    const k1r = withFlags(k1, 385)
    const contract = deploy([k1, k2])
    at(T0 + DAY)
    const s = rootSet(k1r, [k1r, k2], T0)
    contract.revokeRoot(B(s.signedData), B(s.signature), B(montgomeryHint(k1r.rdata)), s.keyIndex)
    expect(anchor(contract, k1).state).toBe(AnchorState.Revoked)
  })

  test('a revocation stales everything a compromised key proved', () => {
    const [k1, k2, rogue, com] = [ecKey(), ecKey(), ecKey(), ecKey()]
    const k1r = withFlags(k1, 385)
    const contract = deploy([k1, k2])
    const t = T0 + DAY
    at(t)
    // k1's thief signs a root RRset adding their key, valid for years, and a chain below it
    const forged = rootSet(k1, [k1, rogue], t, 3650 * DAY)
    const o = { inception: t, expiration: t + 3650 * DAY }
    const comName = nameToWire('com')
    const zskIndex = rdataOf(forged.rrset).findIndex((r) => toHex(r) === toHex(zsk.rdata))
    const ds = signRRset(zsk, comName, RRType.DS, [dsRdata(comName, com.rdata)], { signer: ROOT, ...o })
    const keys = signRRset(com, comName, RRType.DNSKEY, [com.rdata], { signer: comName, ...o })
    const txtName = nameToWire('_tag.com')
    const tag = signRRset(com, txtName, RRType.TXT, [txt('forged')], { signer: comName, ...o })
    const proveDs = (parent: Uint8Array) =>
      contract.proveDs(B(ds.signedData), B(ds.signature), NO_HINT, zskIndex, B(parent))
    const proveTag = () => contract.proveTxt(B(tag.signedData), B(tag.signature), NO_HINT, 0, B(keys.rrset))
    proveRoot(contract, forged)
    update(contract, forged, rogue)
    proveDs(forged.rrset)
    contract.proveDnskey(B(keys.signedData), B(keys.signature), NO_HINT, 0, 0, B(ds.rrset))
    proveTag()
    expect(anchor(contract, rogue).state).toBe(AnchorState.AddPend)
    const live = () => chainLive(contract, txtName, [comName])
    expect(live()).toBe(true)

    at(t + DAY)
    revokeRoot(contract, rootSet(k1r, [k1r, k2], t + DAY))
    expect(contract.rootEpoch.value).not.toEqual(1)
    // nothing chains from the forged root any more: the rollover refuses it, consumers too
    expect(() => update(contract, forged, rogue)).toThrow(code('STL'))
    expect(live()).toBe(false)
    expect(() => proveDs(forged.rrset)).toThrow(code('STL'))
    expect(() => proveTag()).toThrow(code('STL'))
    // anyone prunes what predates the revocation, unexpired and not their own
    const stranger = ctx.any.account()
    const appId = ctx.ledger.getApplicationForContract(contract)
    ctx.txn
      .createScope([ctx.any.txn.applicationCall({ appId, sender: stranger })])
      .execute(() => contract.prune(B(txtName), RRType.TXT))
    expect(contract.attestations(Bytes(sha256(txtName)) as bytes<32>).exists).toBe(false)

    // k2 overwrites the forged root entry with an older RRset, which then drives nothing
    // until a newer one arrives: rollInception is the forged inception
    const older = rootSet(k2, [k1r, k2], T0, 10 * DAY)
    proveRoot(contract, older)
    expect(() => update(contract, older, rogue)).toThrow(code('OLD'))
    const current = rootSet(k2, [k1r, k2], t + DAY)
    proveRoot(contract, current)
    // Reset: the rogue key never reaches Valid
    update(contract, current, rogue)
    expect(anchor(contract, rogue).state).toBe(0)
  })

  test('a replayed older RRset cannot undo a step', () => {
    const [k1, k2] = [ecKey(), ecKey()]
    const contract = deploy([k1])
    const old = rootSet(k1, [k1, k2], T0, 40 * DAY)
    const newer = rootSet(k1, [k1], T0 + DAY, 4 * DAY)
    at(T0 + 2 * DAY)
    proveRoot(contract, old)
    update(contract, old, k2)
    proveRoot(contract, newer)
    update(contract, newer, k2)
    expect(anchor(contract, k2).state).toBe(0)

    // the newer RRset expires, its cache is pruned, and the older one proves again
    at(T0 + 6 * DAY)
    contract.prune(B(ROOT), RRType.DNSKEY)
    proveRoot(contract, old)
    expect(() => update(contract, old, k2)).toThrow(code('OLD'))
  })
})

/**
 * reader.algo.ts's attestationChainLive over the contract's own boxes: the emulator lacks
 * AVM 13's foreign box reads, so the reader itself runs in the LocalNet consumer test.
 */
function chainLive(contract: DnssecOracle, owner: Uint8Array, zones: Uint8Array[]) {
  let epoch = attestationParentEpoch(contract.attestations(Bytes(sha256(owner)) as bytes<32>).value)
  for (const [name, type] of chainLinks(zones)) {
    const box = contract.caches(Bytes(sha256(concat(name, u16(type)))) as bytes<32>)
    if (!box.exists || box.value.epoch !== epoch) return false
    epoch = box.value.parentEpoch
  }
  return epoch === contract.rootEpoch.value
}

describe('epochs: a change above stales everything below', () => {
  const k1 = ecKey()
  const com = ecKey()
  const comName = nameToWire('com')
  const tagName = nameToWire('_tag.com')
  const root = rootSet(k1, [k1], T0, 90 * DAY)
  const zskIndex = rdataOf(root.rrset).findIndex((r) => toHex(r) === toHex(zsk.rdata))
  const o = (t: number) => ({ inception: t, expiration: t + 30 * DAY })
  // outlives com's keys, so they can expire and be pruned under it
  const ds = signRRset(zsk, comName, RRType.DS, [dsRdata(comName, com.rdata)], {
    signer: ROOT,
    inception: T0,
    expiration: T0 + 60 * DAY,
  })
  /** com's DNSKEY RRset: its KSK plus `extra` keys, self-signed at `t`. */
  const comKeys = (t: number, extra: TestKey[] = []) =>
    signRRset(com, comName, RRType.DNSKEY, [com.rdata, ...extra.map((k) => k.rdata)], { signer: comName, ...o(t) })
  const tag = (t: number, text = 'hi') => signRRset(com, tagName, RRType.TXT, [txt(text)], { signer: comName, ...o(t) })

  type S = ReturnType<typeof comKeys>
  // the RRset is in canonical order: find com's KSK in it
  const comIndex = (keys: S) => rdataOf(keys.rrset).findIndex((r) => toHex(r) === toHex(com.rdata))
  const proveKeys = (c: DnssecOracle, s: S, parent = ds) =>
    c.proveDnskey(B(s.signedData), B(s.signature), NO_HINT, comIndex(s), 0, B(parent.rrset))
  const proveTag = (c: DnssecOracle, s: S, keys: S) =>
    c.proveTxt(B(s.signedData), B(s.signature), NO_HINT, comIndex(keys), B(keys.rrset))
  const epochOf = (c: DnssecOracle, name: Uint8Array, type: number) =>
    c.caches(Bytes(sha256(concat(name, u16(type)))) as bytes<32>).value.epoch

  function setup() {
    const contract = deploy([k1])
    at(T0 + DAY)
    proveRoot(contract, root)
    contract.proveDs(B(ds.signedData), B(ds.signature), NO_HINT, zskIndex, B(root.rrset))
    const keys = comKeys(T0)
    proveKeys(contract, keys)
    proveTag(contract, tag(T0), keys)
    expect(chainLive(contract, tagName, [comName])).toBe(true)
    return { contract, keys }
  }

  test('the same RRset, signed again, keeps its epoch: nothing below goes stale', () => {
    const { contract } = setup()
    const before = epochOf(contract, comName, RRType.DNSKEY)
    proveKeys(contract, comKeys(T0 + 1))
    expect(epochOf(contract, comName, RRType.DNSKEY)).toEqual(before)
    expect(chainLive(contract, tagName, [comName])).toBe(true)
  })

  test('a new key set stales what was proven under the old one, until proven again', () => {
    const { contract } = setup()
    const newer = comKeys(T0 + 1, [ecKey({ flags: 256 })])
    proveKeys(contract, newer)
    expect(chainLive(contract, tagName, [comName])).toBe(false)
    proveTag(contract, tag(T0 + 1), newer)
    expect(chainLive(contract, tagName, [comName])).toBe(true)
  })

  test('only the real ancestors match: a wrong or short zone list fails', () => {
    const { contract } = setup()
    expect(chainLive(contract, tagName, [])).toBe(false)
    expect(chainLive(contract, tagName, [nameToWire('org')])).toBe(false)
    expect(chainLive(contract, tagName, [comName, comName])).toBe(false)
  })

  test('no rollback across a change above: an older TXT stays out once the keys change', () => {
    const { contract, keys } = setup()
    proveTag(contract, tag(T0 + 2, 'current'), keys)
    const newer = comKeys(T0 + 1, [ecKey({ flags: 256 })])
    proveKeys(contract, newer)
    // the older record, still validly signed, cannot slip in while the stored one is stale
    expect(() => proveTag(contract, tag(T0 + 1, 'withdrawn'), newer)).toThrow(code('OLD'))
    proveTag(contract, tag(T0 + 2, 'current'), newer)
    expect(chainLive(contract, tagName, [comName])).toBe(true)
  })

  test('no rollback across a change above: a withdrawn key set stays out once the DS changes', () => {
    const { contract } = setup()
    const newer = comKeys(T0 + 1, [ecKey({ flags: 256 })])
    proveKeys(contract, newer)
    const ds2 = signRRset(zsk, comName, RRType.DS, [dsRdata(comName, com.rdata), dsRdata(comName, ecKey().rdata)], {
      signer: ROOT,
      inception: T0 + 1,
      expiration: T0 + 60 * DAY,
    })
    contract.proveDs(B(ds2.signedData), B(ds2.signature), NO_HINT, zskIndex, B(root.rrset))
    expect(() => proveKeys(contract, comKeys(T0), ds2)).toThrow(code('OLD'))
    // the same signature re-links under the new DS
    proveKeys(contract, newer, ds2)
    proveTag(contract, tag(T0 + 1), newer)
    expect(chainLive(contract, tagName, [comName])).toBe(true)
  })

  test('a pruned entry comes back with a fresh epoch', () => {
    const { contract, keys } = setup()
    const before = epochOf(contract, comName, RRType.DNSKEY)
    at(T0 + 31 * DAY)
    contract.prune(B(comName), RRType.DNSKEY)
    const again = signRRset(com, comName, RRType.DNSKEY, [com.rdata], {
      signer: comName,
      inception: T0 + 30 * DAY,
      expiration: T0 + 35 * DAY,
    })
    proveKeys(contract, again)
    expect(toHex(again.rrset)).toBe(toHex(keys.rrset))
    expect(epochOf(contract, comName, RRType.DNSKEY)).not.toEqual(before)
  })
})

describe('root rollover, captured 2026-09-28', () => {
  const steps = () => buildRootSteps(capturedResolver(fixture.responses), { now: fixture.capturedAt })

  test('KSK-2017 signs, and KSK-2024 enters AddPend from its RRset', async () => {
    const contract = deploy([ROOT_KSK_2017], fixture.capturedAt)
    const [step, ...others] = await steps()
    expect(others).toEqual([])
    contract.proveRoot(B(step.signedData), B(step.signature), B(step.hint), step.keyIndex)
    contract.updateAnchor(B(step.rrset), hash(ROOT_KSK_2024))
    expect(anchor(contract, ROOT_KSK_2024)).toEqual({ state: AnchorState.AddPend, since: fixture.capturedAt })
    // not revoked, so no revocation
    expect(() => contract.revokeRoot(B(step.signedData), B(step.signature), B(step.hint), step.keyIndex)).toThrow(
      code('RVK'),
    )
  })

  test('with both KSKs as initial anchors, nothing is pending', async () => {
    const contract = deploy([ROOT_KSK_2017, ROOT_KSK_2024], fixture.capturedAt)
    const [step] = await steps()
    contract.proveRoot(B(step.signedData), B(step.signature), B(step.hint), step.keyIndex)
    expect(() => contract.updateAnchor(B(step.rrset), hash(ROOT_KSK_2024))).toThrow(code('ROL'))
    expect(anchor(contract, ROOT_KSK_2024).state).toBe(AnchorState.Valid)
  })
})
