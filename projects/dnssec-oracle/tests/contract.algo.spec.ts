import { Account, Bytes, bytes } from '@algorandfoundation/algorand-typescript'
import { TestExecutionContext } from '@algorandfoundation/algorand-typescript-testing'
import {
  buildTxtChain,
  capturedResolver,
  decodeAttestation,
  nameToWire,
  parseResponse,
  PRUNE_GRACE_SECONDS,
  ProofStep,
  ROOT_KSK_2017,
  RRType,
  sha256,
  txtStrings,
  u16,
} from 'dnssec-oracle-sdk'
import { encodeAddress } from 'algosdk'
import { afterEach, describe, expect, test } from 'vitest'
import { DnssecOracle } from '../smart_contracts/dnssec_oracle/contract.algo'
import fixture from './fixtures/2026-09-28.json'

/*
 * Captured chains replayed in the emulator with the clock pinned inside their validity
 * windows: LocalNet cannot move block time backwards, and captured signatures expire.
 */

const ctx = new TestExecutionContext()
afterEach(() => ctx.reset())

const code = (c: string) => new RegExp(`ERR:${c}\\b`)
const B = (x: Uint8Array) => Bytes(x)
/** A box key: sha256 of `data`. */
const key = (data: Uint8Array) => Bytes(sha256(data)) as bytes<32>
/** The emulator's bytes carry their Uint8Array; the type does not say so. */
const u8 = (x: bytes) => (x as unknown as { asUint8Array(): Uint8Array }).asUint8Array()

const chainOf = (name: string) =>
  buildTxtChain(name, capturedResolver(fixture.responses), { anchors: [ROOT_KSK_2017], now: fixture.capturedAt })

function deploy() {
  const contract = ctx.contract.create(DnssecOracle)
  // the emulator lacks AVM 13's app_params_set: initialise what createApplication would
  contract.admin.value = ctx.defaultSender
  contract.anchorCount.value = 0
  contract.rollInception.value = 0
  contract.lastEpoch.value = 1
  contract.rootEpoch.value = 1
  at(fixture.capturedAt)
  contract.addAnchors([B(ROOT_KSK_2017)])
  return contract
}

const at = (latestTimestamp: number) => ctx.ledger.patchGlobalData({ latestTimestamp })

/** Run `fn` as an app call from `sender`. */
function as<T>(contract: DnssecOracle, sender: Account, fn: () => T): T {
  const appId = ctx.ledger.getApplicationForContract(contract)
  return ctx.txn.createScope([ctx.any.txn.applicationCall({ appId, sender })]).execute(fn)
}

function prove(contract: DnssecOracle, step: ProofStep) {
  const [d, s, h] = [B(step.signedData), B(step.signature), B(step.hint)]
  switch (step.kind) {
    case 'root':
      return contract.proveRoot(d, s, h, step.keyIndex)
    case 'ds':
      return contract.proveDs(d, s, h, step.keyIndex, B(step.parent))
    case 'dnskey':
      return contract.proveDnskey(d, s, h, step.keyIndex, step.dsIndex, B(step.parent))
    case 'txt':
      return contract.proveTxt(d, s, h, step.keyIndex, B(step.parent))
  }
}

const cache = (contract: DnssecOracle, name: string, type: number) =>
  contract.caches(key(new Uint8Array([...nameToWire(name), ...u16(type)]))).value

const attestation = (contract: DnssecOracle, name: string) =>
  decodeAttestation(u8(contract.attestations(key(nameToWire(name))).value))

/** The TXT strings DNS returned, joined per record, sorted like the attestation. */
function dnsTexts(name: string) {
  const key = `${Buffer.from(nameToWire(name)).toString('hex')} ${RRType.TXT}`
  const { answers } = parseResponse(Buffer.from((fixture.responses as Record<string, string>)[key], 'hex'))
  return answers.filter((rr) => rr.type === RRType.TXT).map((rr) => txtStrings(rr.rdata).join(''))
}

describe('captured chains, 2026-09-28', () => {
  test.each([
    ['_dmarc.publicnode.com', 2048], // root RSA-2048, then P-256 all the way
    ['_dmarc.nodely.io', 1024], // io signs with an RSA-1024 ZSK
    ['_dmarc.folks.finance', 1024],
    ['_dmarc.mercury.co', 1280], // co signs with RSA-1280
    ['llamanodes.com', 1024], // an apex TXT, signed by the zone's own RSA-1024 ZSK
  ])('proves %s from the real root anchor', async (name, weakest) => {
    const contract = deploy()
    const steps = await chainOf(name)
    for (const step of steps) prove(contract, step)
    const a = attestation(contract, name)
    expect(a.texts.sort()).toEqual(dnsTexts(name).sort())
    expect(a.weakestKeyBits).toBe(weakest)
    expect(a.inception).toBe(steps.at(-1)!.inception)
    expect(a.expiration).toBe(Math.min(...steps.map((s) => s.expiration)))
    expect(a.payer).toBe(encodeAddress(u8(ctx.defaultSender.bytes)))
  })

  test('a child entry expires with its parent', async () => {
    const contract = deploy()
    const [root, comDs] = await chainOf('_dmarc.publicnode.com')
    expect(comDs.expiration).toBeGreaterThan(root.expiration)
    prove(contract, root)
    prove(contract, comDs)
    expect(cache(contract, 'com', RRType.DS).expiry).toEqual(root.expiration)
  })

  test('a stale parent cannot be used, even with a child signature still valid', async () => {
    const contract = deploy()
    const [root, comDs] = await chainOf('_dmarc.publicnode.com')
    prove(contract, root)
    at(root.expiration + 1)
    expect(comDs.inception).toBeLessThanOrEqual(root.expiration + 1)
    expect(() => prove(contract, comDs)).toThrow(code('stale'))
    at(root.expiration)
    prove(contract, comDs)
  })

  test('an attestation: its payer may prune once expired, anyone else 30 days later', async () => {
    const contract = deploy()
    const steps = await chainOf('_dmarc.publicnode.com')
    for (const step of steps) prove(contract, step)
    const name = B(nameToWire('_dmarc.publicnode.com'))
    const { expiration } = attestation(contract, '_dmarc.publicnode.com')
    const payer = ctx.defaultSender
    const other = ctx.any.account()

    at(expiration)
    expect(() => as(contract, payer, () => contract.prune(name, RRType.TXT))).toThrow(code('prune'))
    at(expiration + 1)
    expect(() => as(contract, other, () => contract.prune(name, RRType.TXT))).toThrow(code('prune'))
    at(expiration + PRUNE_GRACE_SECONDS)
    expect(() => as(contract, other, () => contract.prune(name, RRType.TXT))).toThrow(code('prune'))
    at(expiration + PRUNE_GRACE_SECONDS + 1)
    as(contract, other, () => contract.prune(name, RRType.TXT))
    expect(contract.attestations(key(nameToWire('_dmarc.publicnode.com'))).exists).toBe(false)
  })

  test('a cache entry: anyone may prune once expired', async () => {
    const contract = deploy()
    const [root] = await chainOf('_dmarc.publicnode.com')
    prove(contract, root)
    const rootName = B(new Uint8Array([0]))
    at(root.expiration)
    expect(() => contract.prune(rootName, RRType.DNSKEY)).toThrow(code('prune'))
    at(root.expiration + 1)
    contract.prune(rootName, RRType.DNSKEY)
    expect(() => contract.prune(rootName, RRType.DNSKEY)).toThrow(code('missing'))
    expect(() => contract.prune(B(new Uint8Array([0xc0, 0])), RRType.DNSKEY)).toThrow(code('wireFormat'))
  })
})
