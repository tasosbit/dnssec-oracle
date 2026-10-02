import { Config, microAlgo } from '@algorandfoundation/algokit-utils'
import { algorandFixture } from '@algorandfoundation/algokit-utils/testing'
import { Address, TransactionSigner } from 'algosdk'
import {
  ANCHOR_BOX_MBR_MICROALGOS,
  anchorHash,
  AnchorState,
  attestationBoxMbrMicroAlgos,
  attestationKey,
  boxNames,
  buildTxtChain,
  CACHE_BOX_MBR_MICROALGOS,
  CREDIT_BOX_MBR_MICROALGOS,
  capturedResolver,
  concat,
  DnssecOracleSDK,
  increaseBudgetBaseCost,
  increaseBudgetIncrementCost,
  keyProblem,
  keyTag,
  labelCount,
  nameFromWire,
  nameToWire,
  ProofStep,
  rdataOf,
  ROOT_KSK_2017,
  RRType,
  sha256,
  SIMULATE_PARAMS,
  toHex,
  u16,
  u32,
} from '@d13co/dnssec-oracle-sdk'
import { randomBytes } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { AttestationConsumerFactory } from '../smart_contracts/artifacts/consumer/AttestationConsumerClient'
import { sendMutated } from './helpers'
import { Alg, dnskeyRdata, dsRdata, ecKey, rawSign, rsaKey, standardWorld, TestKey, txt, withFlags } from './zone'

const P256_N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')

/** The transformed error: `Error CODE: message`. */
const code = (c: string) => new RegExp(`Error ${c}:`)

/** TXT RDATA of `length` bytes, in 255-byte strings. */
const bigRdata = (length: number) => {
  const full = Math.ceil(length / 255) - 1
  return concat(...Array.from({ length: full }, () => txt('x'.repeat(254))), txt('x'.repeat(length - full * 255 - 1)))
}

const indexOf = (rrset: Uint8Array, rdata: Uint8Array) => rdataOf(rrset).findIndex((r) => toHex(r) === toHex(rdata))

/** A step by kind, and owner when several share a kind. */
function find<K extends ProofStep['kind']>(steps: ProofStep[], kind: K, owner?: string) {
  const step = steps.find((s) => s.kind === kind && (!owner || toHex(s.owner) === toHex(nameToWire(owner))))
  if (!step) throw new Error(`no ${kind} step${owner ? ` for ${owner}` : ''}`)
  return step as Extract<ProofStep, { kind: K }>
}

describe('DnssecOracle e2e', () => {
  const localnet = algorandFixture({ testAccountFunding: (1000).algo() })
  beforeAll(() => Config.configure({ populateAppCallResources: true }))
  beforeEach(localnet.newScope, 30_000)

  const accountSigner = (a: { addr: Address; signer: TransactionSigner }) => ({ sender: a.addr, signer: a.signer })

  /** Create, then (unless `anchor` is false) fund, deposit and anchor in one group. */
  const deploy = async ({
    rootAlg = 'ecdsa' as Alg,
    credits = 5_000_000,
    anchor = true,
    extraAnchors = [] as Uint8Array[],
  } = {}) => {
    // the world signs from two hours back
    await waitPast(Math.floor(Date.now() / 1000) - 3600)
    const w = standardWorld({ rootAlg })
    const { testAccount } = localnet.context
    const sdk = await DnssecOracleSDK.create({ algorand: localnet.algorand, admin: accountSigner(testAccount) })
    if (anchor) await sdk.setup({ anchors: [w.root.ksk.rdata, ...extraAnchors], credits })
    const anchors = [w.root.ksk.rdata]
    const chain = (name: string) => buildTxtChain(name, w.world.resolver, { anchors })
    const prove = (name: string) => sdk.proveTxt(name, { resolver: w.world.resolver, anchors })
    return { sdk, ...w, anchors, chain, prove }
  }

  /** Another prover on the same app, with `credits` deposited unless 0. */
  const otherSdk = async (sdk: DnssecOracleSDK, credits = 2_000_000) => {
    const account = await localnet.context.generateAccount({ initialFunds: (100).algo() })
    const other = new DnssecOracleSDK({ algorand: sdk.algorand, appId: sdk.appId, writerAccount: accountSigner(account) })
    if (credits) await other.depositCredits({ amount: credits })
    return { other, account }
  }

  /**
   * An example consumer pinned to `sdk`'s app, asking whether `_tag.example.com` holds `text`,
   * both by reading the boxes itself and by calling the oracle's hasRecord: the two must
   * agree. Box references: the attestation and its chain walk, 6 boxes.
   */
  const consumerAsk = async (sdk: DnssecOracleSDK) => {
    const { testAccount } = localnet.context
    const factory = localnet.algorand.client.getTypedAppFactory(AttestationConsumerFactory, { defaultSender: testAccount })
    // the consumer pins the oracle at create: callers cannot point it at an app of their own
    const { appClient: consumer } = await factory.send.create.createApplication({ args: { oracle: sdk.appId } })
    return async (text: string, { maxAge = 86_400 * 3, minKeyBits = 2048, zones = ['example.com', 'com'], owner = '_tag.example.com' } = {}) => {
      const name = nameToWire(owner)
      const wireZones = zones.map((z) => nameToWire(z))
      const boxes = [boxNames.attestation(name), ...boxNames.chain(wireZones)]
      const params = {
        args: { name, text: new TextEncoder().encode(text), maxAge, minKeyBits, zones: wireZones },
        appReferences: [sdk.appId],
        boxReferences: boxes.map((box) => ({ appId: sdk.appId, name: box })),
        note: `${Math.random()}`,
      }
      const { return: direct } = await consumer.send.hasTxt(params)
      const { return: byCall } = await consumer.send.hasTxtByCall({ ...params, extraFee: microAlgo(1000) })
      expect(byCall).toBe(direct)
      return direct
    }
  }

  /** The oracle's hasRecord, called directly: `name` signed by its parent zone, under `com`. */
  const hasRecord = async (sdk: DnssecOracleSDK, owner: string, rdata: Uint8Array, zones = ['example.com', 'com']) => {
    const name = nameToWire(owner)
    const wireZones = zones.map((z) => nameToWire(z))
    const { return: ok } = await sdk.writeClient!.send.hasRecord({
      args: { name, rdata, maxAge: 86_400 * 3, minKeyBits: 0, zones: wireZones },
      boxReferences: [boxNames.attestation(name), ...boxNames.chain(wireZones)],
      note: `${Math.random()}`,
    })
    return ok
  }

  /** App balance that is neither locked by boxes nor owed to anyone as credit. */
  const unowned = async (sdk: DnssecOracleSDK) => {
    const info = await sdk.algorand.account.getInformation(sdk.writeClient!.appAddress)
    const credits = [...(await sdk.listCredits()).values()].reduce((a, b) => a + b, 0n)
    return info.balance.microAlgo - info.minBalance.microAlgo - credits
  }

  /** Wait until LocalNet's latest block is past `ts`: dev mode makes a block per transaction. */
  const waitPast = async (ts: number) => {
    const { algod } = localnet.algorand.client
    const { testAccount } = localnet.context
    for (;;) {
      await localnet.algorand.send.payment({
        sender: testAccount,
        receiver: testAccount,
        amount: microAlgo(0),
        note: `${Math.random()}`,
      })
      const { lastRound } = await algod.status().do()
      const { block } = await algod.block(lastRound).do()
      if (Number(block.header.timestamp) > ts) return
      // a block steps at most 25 s past its parent: a LocalNet left idle catches up block by block
      if (Number(block.header.timestamp) < Date.now() / 1000 - 30) continue
      await new Promise((r) => setTimeout(r, 1000))
    }
  }

  // ── Phase 0: the assumptions the design rests on ─────────────────

  describe('phase 0: measurements', () => {
    test('increaseBudget opcode cost matches the SDK constants', async () => {
      const { sdk } = await deploy()
      const consumed = async (itxns: number) => {
        const { simulateResponse } = await sdk
          .writeClient!.newGroup()
          .increaseBudget({ args: { itxns }, extraFee: microAlgo(itxns * 1000), note: `${Math.random()}` })
          .simulate(SIMULATE_PARAMS)
        return simulateResponse.txnGroups[0].appBudgetConsumed ?? 0
      }
      const [zero, one, two] = [await consumed(0), await consumed(1), await consumed(2)]
      // keep in sync with increaseBudgetBaseCost / increaseBudgetIncrementCost in the SDK's constants.ts
      expect(zero).toBe(increaseBudgetBaseCost)
      expect(one - zero).toBe(increaseBudgetIncrementCost)
      expect(two - one).toBe(increaseBudgetIncrementCost)
    })

    test('opcode cost, fee and program size per proof kind', async () => {
      const { sdk, chain } = await deploy({ rootAlg: 'rsa' })
      const rows: Record<string, unknown>[] = []
      for (const name of ['_tag.example.com', '_tag.example.io']) {
        for (const step of await chain(name)) {
          const cached = await sdk.getRawCache(step.owner, step.type)
          if (cached && step.kind !== 'txt') continue
          const { simulateResponse } = await sdk['makeProveTxns']({ step }).simulate(SIMULATE_PARAMS)
          const group = simulateResponse.txnGroups[0]
          const sent = await sdk.proveStep({ step })
          const fee = sent.transactions.reduce((n, t) => n + Number(t.fee), 0)
          rows.push({
            step: `${step.kind} ${new TextDecoder().decode(step.owner.slice(1, 1 + step.owner[0])) || '.'}`,
            keyBits: step.keyBits,
            opcodes: group.appBudgetConsumed,
            groupTxns: sent.transactions.length,
            feeMicroAlgo: fee,
            groupUsage: Number(group.groupUsage ?? 0),
          })
        }
      }
      console.table(rows)
      const root = rows[0] as { opcodes: number; feeMicroAlgo: number }
      // RSA-2048 fits one group's pool with room to spare: 700 × (16 + 256)
      expect(root.opcodes).toBeGreaterThan(80_000)
      expect(root.opcodes).toBeLessThan(120_000)
      expect(root.feeMicroAlgo).toBeLessThan(150_000)

      const app = await sdk.algorand.app.getById(sdk.appId)
      console.log(`approval ${app.approvalProgram.length} B, extra pages ${app.extraProgramPages}`)
      expect(app.approvalProgram.length).toBeLessThanOrEqual(8 * 2048)
    })
  })

  describe('phase 0: lifecycle and reads', () => {
    test('create enables ForeignBoxReads: another contract reads the attestation box through the reference reader', async () => {
      const { sdk, prove, chain, world, exampleCom } = await deploy()
      await prove('_tag.example.com')
      const ask = await consumerAsk(sdk)
      expect(await ask('hello com')).toBe(true)
      expect(await ask('hello com', { owner: '_none.example.com' })).toBe(false) // no attestation
      expect(await ask('hello')).toBe(false) // a substring is not a record
      expect(await ask('hello com', { maxAge: 60 })).toBe(false) // signed too long ago
      expect(await ask('hello com', { minKeyBits: 4096 })).toBe(false) // weaker than asked: P-256 counts as 3072
      // the chain walk takes only the real ancestors
      expect(await ask('hello com', { zones: ['com'] })).toBe(false)
      expect(await ask('hello com', { zones: ['example.com', 'io'] })).toBe(false)

      // example.com publishes a new key set: what its old one signed is stale, until proven again
      world.publishKeys(exampleCom, [ecKey({ flags: 256 }).rdata])
      await sdk.proveStep({ step: find(await chain('_tag.example.com'), 'dnskey', 'example.com') })
      const [stale] = await sdk.getRawAttestations(['_tag.example.com'])
      expect(await sdk.attestationChainLive(stale!, ['example.com', 'com'])).toBe(false)
      expect(await sdk.attestationZones('_tag.example.com', stale!)).toBeUndefined()
      const policy = { maxAge: 86_400 * 3, minKeyBits: 2048 }
      expect(await sdk.getVerifiedAttestation('_tag.example.com', policy)).toBeUndefined()
      expect(await ask('hello com')).toBe(false)
      await prove('_tag.example.com')
      const [fresh] = await sdk.getRawAttestations(['_tag.example.com'])
      expect(await sdk.attestationChainLive(fresh!, ['example.com', 'com'])).toBe(true)
      const zones = await sdk.attestationZones('_tag.example.com', fresh!)
      expect(zones?.map((z) => nameFromWire(z))).toEqual(['example.com.', 'com.'])
      const verified = await sdk.getVerifiedAttestation('_tag.example.com', policy)
      expect(verified?.zones.map((z) => nameFromWire(z))).toEqual(['example.com.', 'com.'])
      expect(verified?.attestation).toEqual(fresh)
      // boundaries are inclusive, as on-chain: usable at expiration and at inception + maxAge
      const { inception, expiration } = fresh!
      const at = (now: number, maxAge: number) => sdk.getVerifiedAttestation('_tag.example.com', { ...policy, maxAge, now })
      expect(await at(expiration, expiration - inception)).toBeDefined()
      expect(await at(expiration + 1, expiration - inception + 1)).toBeUndefined() // expired
      expect(await at(inception + 10, 10)).toBeDefined()
      expect(await at(inception + 11, 10)).toBeUndefined() // signed too long ago
      // the same policy checks as the consumer's ask above
      expect(await sdk.getVerifiedAttestation('_tag.example.com', { ...policy, maxAge: 60 })).toBeUndefined()
      expect(await sdk.getVerifiedAttestation('_tag.example.com', { ...policy, minKeyBits: 4096 })).toBeUndefined()
      expect(await ask('hello com')).toBe(true)
    })

    test('setup charges exactly the MBR constants the SDK mirrors', async () => {
      const { sdk } = await deploy({ credits: 1_000_000 })
      const needed = CREDIT_BOX_MBR_MICROALGOS + ANCHOR_BOX_MBR_MICROALGOS
      expect(await sdk.getCredits(localnet.context.testAccount.toString())).toBe(BigInt(1_000_000 - needed))
    })

    test('simulated and algod box reads agree', async () => {
      const { sdk, prove } = await deploy()
      await prove('_tag.example.com')
      await prove('_tag.example.io')
      const names = ['_tag.example.com', '_tag.example.io', '_missing.example.com']
      const viaSimulate = await sdk._logAttestationsChunked(names.map((n) => nameToWire(n)))
      const viaAlgod = await sdk.scanRaw('t')
      expect(viaSimulate[2]).toBeUndefined()
      for (const [i, name] of names.slice(0, 2).entries()) {
        expect(toHex(viaSimulate[i]!)).toBe(toHex(viaAlgod.get(attestationKey(name))!))
      }
      expect(viaAlgod.size).toBe(2)
      expect((await sdk.listRawAttestations()).get(attestationKey('_tag.example.io'))?.texts).toEqual(['hello io'])

      const admin = localnet.context.testAccount.toString()
      expect(await sdk.getCredits(admin)).toBe((await sdk.listCredits()).get(admin))
      // root, then DS and DNSKEY for com, io, example.com, example.io
      const caches = await sdk.listRawCaches()
      expect(caches.size).toBe(9)
      const links: [string, number][] = [
        ['.', RRType.DNSKEY],
        ['com', RRType.DS],
        ['example.io', RRType.DNSKEY],
        ['missing.com', RRType.DNSKEY],
      ]
      const viaLogger = await sdk.getRawCaches(links)
      expect(viaLogger[3]).toBeUndefined()
      for (const [i, [name, type]] of links.slice(0, 3).entries()) {
        expect(viaLogger[i]).toEqual(caches.get(toHex(sha256(concat(nameToWire(name), u16(type))))))
      }
      expect(await sdk.getState()).toEqual({ admin, anchorCount: 1n, rollInception: 0n, rootEpoch: 1n })
    })

    test('loggers read a full simulate group in as few calls as fit', async () => {
      const { sdk, prove } = await deploy()
      await prove('_tag.example.com')
      // the simulate requests sent during `read`, each as its transactions' fees
      const simulate = vi.spyOn(sdk.algorand.client.algod, 'simulateTransactions')
      const groups = async (read: () => Promise<unknown>) => {
        simulate.mockClear()
        await read()
        return simulate.mock.calls.map(([request]) => request.txnGroups[0].txns.map((stxn) => Number(stxn.txn.fee)))
      }
      try {
        // 128 boxes, one group's references, all in one call while the keys fit one 4 KB argument
        // (~3 KB here, past the free 2 KB: the extra fee)
        const keys = Array.from({ length: 128 }, (_, i) => concat(nameToWire(`_${i}.example.com`), u16(RRType.DNSKEY)))
        keys[100] = concat(nameToWire('com'), u16(RRType.DS))
        let caches: unknown[] = []
        expect(await groups(async () => (caches = await sdk._logCachesChunked(keys)))).toEqual([[2000]])
        expect(caches.filter(Boolean)).toHaveLength(1)
        expect(caches[100]).toBeDefined()
        // ~250-byte keys: 16 to a 4 KB argument, each past the free 2 KB and paying for it
        const long = (i: number) => nameToWire(`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(50)}.${i}`)
        const longKeys = keys.map((key, i) => (i === 100 ? key : concat(long(i), u16(RRType.DNSKEY))))
        let longCaches: unknown[] = []
        expect(await groups(async () => (longCaches = await sdk._logCachesChunked(longKeys)))).toEqual([
          Array(8).fill(2000),
        ])
        expect(longCaches).toEqual(caches)

        // attestations log up to 4 KB each: 16 per call under simulate's 64 KB per transaction
        const names = Array.from({ length: 128 }, (_, i) => nameToWire(`_${i}.example.com`))
        names[127] = nameToWire('_tag.example.com')
        let attestations: (Uint8Array | undefined)[] = []
        expect(await groups(async () => (attestations = await sdk._logAttestationsChunked(names)))).toEqual([
          Array(8).fill(1000),
        ])
        expect(attestations.slice(0, 127).every((a) => a === undefined)).toBe(true)
        expect(attestations[127]).toBeDefined()

        // credits: 127 addresses, 4066 bytes, in one call; checked against algod's box scan
        const admin = localnet.context.testAccount.toString()
        const accounts = Array.from({ length: 127 }, (_, i) => (i === 64 ? admin : new Address(randomBytes(32)).toString()))
        let credits: (bigint | undefined)[] = []
        expect(await groups(async () => (credits = await sdk._logCreditsChunked(accounts)))).toEqual([[2000]])
        expect(credits[64]).toBe((await sdk.listCredits()).get(admin))
        expect(credits.filter((c) => c !== undefined)).toHaveLength(1)

        // repeats are simulated once, across chunks too, and expanded back in order: 300 names, 3 distinct, one call
        const repeated = Array.from({ length: 300 }, (_, i) => names[[127, 0, 126][i % 3]])
        let expanded: (Uint8Array | undefined)[] = []
        expect(await groups(async () => (expanded = await sdk._logAttestationsChunked(repeated)))).toEqual([[1000]])
        expect(expanded).toEqual(repeated.map((_, i) => [attestations[127], undefined, undefined][i % 3]))
      } finally {
        simulate.mockRestore()
      }
    })
  })

  // ── Phase 2: crypto, anchors, proveRoot ──────────────────────────

  describe('phase 2: anchors', () => {
    const unanchored = async () => {
      const d = await deploy({ anchor: false })
      await d.sdk.algorand.send.payment({
        sender: localnet.context.testAccount,
        receiver: d.sdk.writeClient!.appAddress,
        amount: (0.2).algo(),
      })
      await d.sdk.depositCredits({ amount: 1_000_000 })
      return d
    }

    test('proofs fail before any anchor', async () => {
      const { sdk, chain } = await unanchored()
      const [root] = await chain('_tag.example.com')
      await expect(sdk.proveStep({ step: root })).rejects.toThrow(code('anchor'))
    })

    test('addAnchors: admin only, once, KSK flags only', async () => {
      const { sdk, root } = await unanchored()
      const { account } = await otherSdk(sdk)
      await expect(
        sendMutated(sdk, sdk['makeAddAnchorsTxns']({ anchors: [root.ksk.rdata] }), ([call]) => {
          // @ts-expect-error readonly
          call.txn.sender = account.addr
          call.signer = account.signer
        }),
      ).rejects.toThrow(code('admin'))
      await expect(sdk.addAnchors({ anchors: [withFlags(root.ksk, 256).rdata] })).rejects.toThrow(code('anchorFlags'))
      await expect(sdk.addAnchors({ anchors: [root.ksk.rdata, withFlags(root.ksk, 385).rdata] })).rejects.toThrow(
        code('anchorFlags'),
      )
      await expect(sdk.addAnchors({ anchors: [root.ksk.rdata, root.ksk.rdata] })).rejects.toThrow(code('anchorSet'))
      const second = ecKey()
      await sdk.addAnchors({ anchors: [root.ksk.rdata, second.rdata] })
      expect((await sdk.getAnchor(root.ksk.rdata))?.state).toBe(AnchorState.Valid)
      expect((await sdk.getAnchor(second.rdata))?.state).toBe(AnchorState.Valid)
      expect((await sdk.getState()).anchorCount).toBe(2n)
      await expect(sdk.addAnchors({ anchors: [ecKey().rdata] })).rejects.toThrow(code('anchorSet'))
    })

    test('the anchor is keyed by public key: a REVOKE flag does not move it', async () => {
      const { sdk, root } = await deploy()
      expect((await sdk.getAnchor(withFlags(root.ksk, 385).rdata))?.state).toBe(AnchorState.Valid)
      expect(await sdk.getAnchor(ecKey().rdata)).toBeUndefined()
    })
  })

  describe('phase 2: RSA key and signature checks', () => {
    const fakeModulus = (bytes: number, top: number) => {
      const m = new Uint8Array(randomBytes(bytes))
      m[0] = top
      m[bytes - 1] |= 1
      return m
    }
    const rsaRdata = (field: Uint8Array) => dnskeyRdata(257, 8, field)
    const e65537 = new Uint8Array([3, 1, 0, 1])

    test.each([
      ['RSA-1023', () => rsaRdata(concat(e65537, fakeModulus(128, 0x7f))), 'modulus'],
      ['RSA-2049', () => rsaRdata(concat(e65537, fakeModulus(257, 0x01))), 'modulus'],
      ['a zero-padded modulus', () => rsaRdata(concat(e65537, new Uint8Array([0]), fakeModulus(256, 0x80))), 'modulus'],
      ['exponent 3', () => rsaRdata(concat(new Uint8Array([1, 3]), fakeModulus(256, 0x80))), 'exponent'],
      ['65537 in the 3-byte length form', () => rsaRdata(concat(new Uint8Array([0, 0, 3, 1, 0, 1]), fakeModulus(256, 0x80))), 'exponent'],
      ['a revoked key', () => withFlags(rsaKey({ bits: 1024 }), 385).rdata, 'keyFlags'],
      ['a key without the zone flag', () => withFlags(rsaKey({ bits: 1024 }), 1).rdata, 'keyFlags'],
      ['protocol 2', () => concat(u16(257), new Uint8Array([2, 8]), fakeModulus(64, 0x80)), 'protocol'],
      ['an unknown algorithm', () => dnskeyRdata(257, 15, fakeModulus(32, 0x80)), 'algorithm'],
    ])('rejects %s at the key index; the same RRset still proves under its KSK', async (_, key, err) => {
      const { sdk, world, root, chain } = await deploy({ rootAlg: 'rsa' })
      const bad = key()
      expect(keyProblem(bad, 8)).toBeDefined() // the SDK agrees
      world.publishKeys(root, [bad])
      const step = find(await chain('_tag.example.com'), 'root')
      await expect(sdk.proveStep({ step: { ...step, keyIndex: indexOf(step.rrset, bad) } })).rejects.toThrow(code(err))
      await sdk.proveStep({ step })
    })

    test('rejects wrong signature lengths, a missing hint, a bad hint and a bad signature', async () => {
      const { sdk, chain } = await deploy({ rootAlg: 'rsa' })
      const step = find(await chain('_tag.example.com'), 'root')
      await expect(sdk.proveStep({ step: { ...step, signature: step.signature.slice(1) } })).rejects.toThrow(code('sigLength'))
      await expect(sdk.proveStep({ step: { ...step, hint: new Uint8Array() } })).rejects.toThrow(code('rsaHint'))
      // puya-ts-utils' own RSA codes
      const badHint = step.hint.slice()
      badHint[10] ^= 1
      await expect(sdk.proveStep({ step: { ...step, hint: badHint } })).rejects.toThrow(code('BADHINT'))
      await expect(sdk.proveStep({ step: { ...step, hint: step.hint.slice(0, 1) } })).rejects.toThrow(code('HINTLEN'))
      const badSig = step.signature.slice()
      badSig[100] ^= 1
      await expect(sdk.proveStep({ step: { ...step, signature: badSig } })).rejects.toThrow(code('signature'))
      await sdk.proveStep({ step })
    })
  })

  describe('phase 2: ECDSA checks', () => {
    const withS = (signature: Uint8Array, s: bigint) =>
      concat(signature.slice(0, 32), new Uint8Array(Buffer.from(s.toString(16).padStart(64, '0'), 'hex')))

    test('accepts a high-S signature, normalised on-chain', async () => {
      const { sdk, chain } = await deploy()
      const step = find(await chain('_tag.example.com'), 'root')
      const s = BigInt('0x' + toHex(step.signature.slice(32)))
      const high = s > P256_N / 2n ? s : P256_N - s
      await sdk.proveStep({ step: { ...step, signature: withS(step.signature, high) } })
    })

    test('accepts an s with a leading zero byte', async () => {
      const { sdk, chain, root } = await deploy()
      const step = find(await chain('_tag.example.com'), 'root')
      let signature: Uint8Array
      do signature = rawSign(root.ksk, step.signedData)
      while (signature[32] !== 0)
      await sdk.proveStep({ step: { ...step, signature } })
    })

    test('rejects a 63-byte key, a 63-byte signature and a bad signature', async () => {
      const { sdk, world, root, chain } = await deploy()
      const short = dnskeyRdata(257, 13, new Uint8Array(randomBytes(63)))
      world.publishKeys(root, [short])
      const step = find(await chain('_tag.example.com'), 'root')
      await expect(sdk.proveStep({ step: { ...step, keyIndex: indexOf(step.rrset, short) } })).rejects.toThrow(code('ecKey'))
      await expect(sdk.proveStep({ step: { ...step, signature: step.signature.slice(1) } })).rejects.toThrow(code('sigLength'))
      const bad = step.signature.slice()
      bad[5] ^= 1
      await expect(sdk.proveStep({ step: { ...step, signature: bad } })).rejects.toThrow(code('signature'))
    })

    test('rejects s = 0, s = n and s > n', async () => {
      const { sdk, chain } = await deploy()
      const step = find(await chain('_tag.example.com'), 'root')
      await expect(sdk.proveStep({ step: { ...step, signature: withS(step.signature, 0n) } })).rejects.toThrow(code('signature'))
      // normalised to n - n = 0
      await expect(sdk.proveStep({ step: { ...step, signature: withS(step.signature, P256_N) } })).rejects.toThrow(code('signature'))
      // n - s underflows: the AVM fails, with no error code
      await expect(sdk.proveStep({ step: { ...step, signature: withS(step.signature, P256_N + 1n) } })).rejects.toThrow()
      await sdk.proveStep({ step })
    })

    test('rejects a root key that is not the anchor', async () => {
      const { sdk, world, root } = await deploy()
      const imposter = ecKey()
      world.root = { ...root, ksk: imposter }
      world.publish(root.name, RRType.DNSKEY, [imposter.rdata, root.zsk.rdata], imposter, root.name)
      const step = (await buildTxtChain('_tag.example.com', world.resolver, { anchors: [imposter.rdata] }))[0]
      await expect(sdk.proveStep({ step })).rejects.toThrow(code('anchor'))
    })
  })

  // ── Phase 3: the chain ───────────────────────────────────────────

  describe('phase 3: chain rules', () => {
    test('a child entry expires with its earliest parent; weakest key bits carry down', async () => {
      const { sdk, world, root, com, chain } = await deploy({ rootAlg: 'rsa' })
      const early = world.expiration - 1000
      world.publish(com.name, RRType.DS, [dsRdata(com.name, com.ksk.rdata)], root.zsk, root.name, { expiration: early })
      await sdk.proveChain(await chain('_tag.example.com'))
      expect((await sdk.getRawCache('com', RRType.DS))?.expiry).toBe(early)
      expect((await sdk.getRawCache('example.com', RRType.DNSKEY))?.expiry).toBe(early)
      const attestation = await sdk.getRawAttestation('_tag.example.com')
      expect(attestation?.expiration).toBe(early)
      expect(attestation?.inception).toBe(world.inception)
      expect(attestation?.weakestKeyBits).toBe(2048)
    })

    test('newest inception wins; ties replace', async () => {
      const { sdk, world, exampleCom, chain } = await deploy()
      const old = find(await chain('_tag.example.com'), 'txt')
      await sdk.proveChain(await chain('_tag.example.com'))

      world.txt(exampleCom, '_tag.example.com', [txt('newer')], { inception: world.inception + 10 })
      await sdk.proveChain(await chain('_tag.example.com'))
      expect((await sdk.getRawAttestation('_tag.example.com'))?.texts).toEqual(['newer'])
      await expect(sdk.proveStep({ step: old })).rejects.toThrow(code('old'))

      // the same RRset again: replaces, and the payer becomes the new sender
      const { other, account } = await otherSdk(sdk)
      await other.proveStep({ step: find(await chain('_tag.example.com'), 'txt') })
      expect((await sdk.getRawAttestation('_tag.example.com'))?.payer).toBe(account.toString())

      // caches too
      const olderRoot = find(await chain('_tag.example.com'), 'root')
      world.inception += 20
      world.publishKeys(world.root)
      await sdk.proveStep({ step: find(await chain('_tag.example.com'), 'root') })
      await expect(sdk.proveStep({ step: olderRoot })).rejects.toThrow(code('old'))

      // a cache tie replaces only if expiry and key bits get no worse
      const keys = [world.root.ksk.rdata, world.root.zsk.rdata]
      world.publish(world.root.name, RRType.DNSKEY, keys, world.root.ksk, world.root.name, { expiration: world.expiration - 1000 })
      await expect(sdk.proveStep({ step: find(await chain('_tag.example.com'), 'root') })).rejects.toThrow(code('worse'))
      world.publish(world.root.name, RRType.DNSKEY, keys, world.root.ksk, world.root.name, { expiration: world.expiration + 1000 })
      await sdk.proveStep({ step: find(await chain('_tag.example.com'), 'root') })
      expect((await sdk.getRawCache('.', RRType.DNSKEY))?.expiry).toBe(world.expiration + 1000)
    })

    test('a TXT RRset replaces the whole stored set', async () => {
      const { sdk, world, exampleCom, prove } = await deploy()
      world.txt(exampleCom, '_tag.example.com', [txt('a'), txt('b'), txt('c')])
      await prove('_tag.example.com')
      expect((await sdk.getRawAttestation('_tag.example.com'))?.texts).toEqual(['a', 'b', 'c'])
      world.txt(exampleCom, '_tag.example.com', [txt('b')], { inception: world.inception + 1 })
      await prove('_tag.example.com')
      expect((await sdk.getRawAttestation('_tag.example.com'))?.texts).toEqual(['b'])
    })

    test('signer rules: self-signed DS, foreign-signed DNSKEY and TXT, and root owners', async () => {
      const { sdk, world, com, exampleCom, chain } = await deploy()
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps)
      const comKeys = find(steps, 'dnskey', 'com')
      const exampleKeys = find(steps, 'dnskey', 'example.com')

      // a DS signed by the zone itself
      const selfDs = world.publish(exampleCom.name, RRType.DS, [dsRdata(exampleCom.name, exampleCom.ksk.rdata)], exampleCom.zsk, exampleCom.name)
      const dsStep = find(steps, 'ds', 'example.com')
      await expect(
        sdk.proveStep({
          step: { ...dsStep, signedData: selfDs.signedData, signature: selfDs.signature, keyIndex: indexOf(exampleKeys.rrset, exampleCom.zsk.rdata), parent: exampleKeys.rrset },
        }),
      ).rejects.toThrow(code('signer'))

      // a zone's DNSKEY RRset signed by its parent
      const foreign = world.publish(exampleCom.name, RRType.DNSKEY, [exampleCom.ksk.rdata, exampleCom.zsk.rdata], com.zsk, com.name)
      await expect(sdk.proveStep({ step: { ...exampleKeys, signedData: foreign.signedData, signature: foreign.signature } })).rejects.toThrow(code('signer'))

      // a TXT signed by a zone that is not an ancestor of it
      const sideways = world.publish(nameToWire('_tag.example.io'), RRType.TXT, [txt('x')], exampleCom.zsk, exampleCom.name)
      const txtStep = find(steps, 'txt')
      await expect(sdk.proveStep({ step: { ...txtStep, signedData: sideways.signedData, signature: sideways.signature } })).rejects.toThrow(code('signer'))

      // proveRoot for a zone that is not the root
      await expect(sdk.proveStep({ step: { ...comKeys, kind: 'root' } })).rejects.toThrow(code('signer'))

      // a TXT at the root
      const rootTxt = world.publish(new Uint8Array([0]), RRType.TXT, [txt('x')], world.root.zsk, world.root.name)
      const rootKeys = find(steps, 'root')
      await expect(
        sdk.proveStep({
          step: { kind: 'txt', ...rootTxt, owner: new Uint8Array([0]), type: RRType.TXT, hint: new Uint8Array(), keyIndex: indexOf(rootKeys.rrset, world.root.zsk.rdata), inception: 0, expiration: 0, keyBits: 0, parent: rootKeys.rrset },
        }),
      ).rejects.toThrow(code('rootOwner'))
    })

    test('parent rules: not cached, hash mismatch, another zone', async () => {
      const { sdk, chain } = await deploy()
      const com = await chain('_tag.example.com')
      const io = await chain('_tag.example.io')
      await expect(sdk.proveStep({ step: find(com, 'ds', 'com') })).rejects.toThrow(code('parent'))
      await sdk.proveChain(io)
      await sdk.proveStep({ step: find(com, 'root') })

      const ds = find(com, 'ds', 'com')
      const tampered = ds.parent.slice()
      tampered[tampered.length - 1] ^= 1
      await expect(sdk.proveStep({ step: { ...ds, parent: tampered } })).rejects.toThrow(code('parent'))

      await sdk.proveChain(com.slice(0, 5))
      const txtStep = find(com, 'txt')
      await expect(sdk.proveStep({ step: { ...txtStep, parent: find(io, 'dnskey', 'example.io').rrset } })).rejects.toThrow(code('parent'))
    })

    test('DS rules: digest type and match', async () => {
      const { sdk, world, root, com, chain } = await deploy()
      const sha1 = concat(dsRdata(com.name, com.ksk.rdata).slice(0, 3), new Uint8Array([1]), new Uint8Array(randomBytes(20)))
      const otherKey = dsRdata(com.name, ecKey().rdata)
      world.publish(com.name, RRType.DS, [dsRdata(com.name, com.ksk.rdata), sha1, otherKey], root.zsk, root.name)
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps.slice(0, 2))
      const keys = find(steps, 'dnskey', 'com')
      await expect(sdk.proveStep({ step: { ...keys, dsIndex: indexOf(keys.parent, sha1) } })).rejects.toThrow(code('dsDigest'))
      await expect(sdk.proveStep({ step: { ...keys, dsIndex: indexOf(keys.parent, otherKey) } })).rejects.toThrow(code('dsMatch'))
      await expect(sdk.proveStep({ step: { ...keys, dsIndex: 3 } })).rejects.toThrow(code('index'))
      await sdk.proveStep({ step: keys })
    })

    test('parse rules through a real maker: type, labels, wildcard, TXT strings, validity window', async () => {
      const { sdk, world, exampleCom, chain } = await deploy()
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps.slice(0, 5))
      const txtStep = find(steps, 'txt')
      const withSigned = (s: { signedData: Uint8Array; signature: Uint8Array }) => ({ ...txtStep, signedData: s.signedData, signature: s.signature })
      const owner = nameToWire('_tag.example.com')

      const mislabeled = world.publish(owner, RRType.TXT, [txt('x')], exampleCom.zsk, exampleCom.name, { labels: 2 })
      await expect(sdk.proveStep({ step: withSigned(mislabeled) })).rejects.toThrow(code('labels'))
      const wild = world.publish(nameToWire('*.example.com'), RRType.TXT, [txt('x')], exampleCom.zsk, exampleCom.name)
      await expect(sdk.proveStep({ step: withSigned(wild) })).rejects.toThrow(code('wildcard'))
      const broken = world.publish(owner, RRType.TXT, [new Uint8Array([5, 0x61, 0x62])], exampleCom.zsk, exampleCom.name)
      await expect(sdk.proveStep({ step: withSigned(broken) })).rejects.toThrow(code('txt'))
      const future = world.publish(owner, RRType.TXT, [txt('x')], exampleCom.zsk, exampleCom.name, { inception: world.now + 3600 })
      await expect(sdk.proveStep({ step: withSigned(future) })).rejects.toThrow(code('sigTime'))
      const expired = world.publish(owner, RRType.TXT, [txt('x')], exampleCom.zsk, exampleCom.name, { expiration: world.now - 7200 })
      await expect(sdk.proveStep({ step: withSigned(expired) })).rejects.toThrow(code('sigTime'))
      // a DNSKEY RRset handed to proveTxt
      await expect(sdk.proveStep({ step: { ...find(steps, 'dnskey', 'example.com'), kind: 'txt', parent: txtStep.parent } })).rejects.toThrow(code('rrType'))
      await expect(sdk.proveStep({ step: { ...txtStep, keyIndex: 2 } })).rejects.toThrow(code('index'))
      await sdk.proveStep({ step: txtStep })
    })

    test('proveDnskey: the signing key must be the one the DS matches', async () => {
      const { sdk, world, exampleCom, chain } = await deploy()
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps.slice(0, 4))
      const keys = find(steps, 'dnskey', 'example.com')
      const ksk = indexOf(keys.rrset, exampleCom.ksk.rdata)
      const zsk = indexOf(keys.rrset, exampleCom.zsk.rdata)
      // the key set signed by the ZSK, which has no DS
      const byZsk = world.publish(exampleCom.name, RRType.DNSKEY, [exampleCom.ksk.rdata, exampleCom.zsk.rdata], exampleCom.zsk, exampleCom.name)
      const signed = { signedData: byZsk.signedData, signature: byZsk.signature }
      await expect(sdk.proveStep({ step: { ...keys, ...signed, keyIndex: zsk } })).rejects.toThrow(code('dsMatch'))
      // ...claimed to be the KSK's signature
      await expect(sdk.proveStep({ step: { ...keys, ...signed, keyIndex: ksk } })).rejects.toThrow(code('signature'))
      // the KSK's signature, pointed at the ZSK
      await expect(sdk.proveStep({ step: { ...keys, keyIndex: zsk } })).rejects.toThrow(code('dsMatch'))
      await sdk.proveStep({ step: keys })
    })

    test("an RRSIG algorithm that is not the key's", async () => {
      const { sdk, world, exampleCom, chain } = await deploy()
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps.slice(0, 4))
      const keys = find(steps, 'dnskey', 'example.com')
      const asRsa = world.publish(exampleCom.name, RRType.DNSKEY, [exampleCom.ksk.rdata, exampleCom.zsk.rdata], exampleCom.ksk, exampleCom.name, { algorithm: 8 })
      await expect(sdk.proveStep({ step: { ...keys, signedData: asRsa.signedData, signature: asRsa.signature } })).rejects.toThrow(code('algorithm'))
      await sdk.proveStep({ step: keys })
      const txtStep = find(steps, 'txt')
      const txtAsRsa = world.txt(exampleCom, '_tag.example.com', [txt('x')], { algorithm: 8 })
      await expect(sdk.proveStep({ step: { ...txtStep, signedData: txtAsRsa.signedData, signature: txtAsRsa.signature } })).rejects.toThrow(code('algorithm'))
    })

    test('a revoked or non-zone key in a cached DNSKEY RRset cannot sign a DS or a TXT', async () => {
      const { sdk, world, com, exampleCom, chain } = await deploy()
      const revoked = withFlags(ecKey({ flags: 256 }), 384)
      const nonZone = withFlags(ecKey({ flags: 256 }), 0)
      world.publishKeys(com, [revoked.rdata, nonZone.rdata])
      world.publishKeys(exampleCom, [revoked.rdata, nonZone.rdata])
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps.slice(0, 3))
      const ds = find(steps, 'ds', 'example.com')
      for (const key of [revoked, nonZone]) {
        const bad = world.publish(exampleCom.name, RRType.DS, [dsRdata(exampleCom.name, exampleCom.ksk.rdata)], key, com.name)
        await expect(
          sdk.proveStep({ step: { ...ds, signedData: bad.signedData, signature: bad.signature, keyIndex: indexOf(ds.parent, key.rdata) } }),
        ).rejects.toThrow(code('keyFlags'))
      }
      await sdk.proveChain(steps.slice(3, 5))
      const txtStep = find(steps, 'txt')
      for (const key of [revoked, nonZone]) {
        const bad = world.publish(nameToWire('_tag.example.com'), RRType.TXT, [txt('x')], key, exampleCom.name)
        await expect(
          sdk.proveStep({ step: { ...txtStep, signedData: bad.signedData, signature: bad.signature, keyIndex: indexOf(txtStep.parent, key.rdata) } }),
        ).rejects.toThrow(code('keyFlags'))
      }
      await sdk.proveStep({ step: txtStep })
    })

    test('a DS RRset handed in as the signer DNSKEY RRset', async () => {
      const { sdk, chain } = await deploy()
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps.slice(0, 5))
      const comDs = find(steps, 'ds', 'com').rrset
      const exampleDs = find(steps, 'ds', 'example.com')
      await expect(sdk.proveStep({ step: { ...exampleDs, parent: comDs } })).rejects.toThrow(code('parent'))
      await expect(sdk.proveStep({ step: { ...find(steps, 'txt'), parent: exampleDs.rrset } })).rejects.toThrow(code('parent'))
    })

    test('a DS signed by a sibling zone', async () => {
      const { sdk, world, io, exampleCom, exampleIo, chain } = await deploy()
      const steps = await chain('_tag.example.com')
      const ioSteps = await chain('_tag.example.io')
      await sdk.proveChain(ioSteps)
      await sdk.proveChain(steps.slice(0, 3))
      const ds = find(steps, 'ds', 'example.com')
      const record = [dsRdata(exampleCom.name, exampleCom.ksk.rdata)]
      // everything else valid: the signer's keys cached, the signature good
      for (const [signer, key, keys] of [
        [io, io.zsk, find(ioSteps, 'dnskey', 'io')],
        [exampleIo, exampleIo.zsk, find(ioSteps, 'dnskey', 'example.io')],
      ] as const) {
        const bad = world.publish(exampleCom.name, RRType.DS, record, key, signer.name)
        await expect(
          sdk.proveStep({ step: { ...ds, signedData: bad.signedData, signature: bad.signature, keyIndex: indexOf(keys.rrset, key.rdata), parent: keys.rrset } }),
        ).rejects.toThrow(code('signer'))
      }
    })

    test('mixed case: an owner lands in its own box, a signer is not an ancestor', async () => {
      const { sdk, world, exampleCom, chain } = await deploy()
      const steps = await chain('_tag.example.com')
      await sdk.proveChain(steps.slice(0, 5))
      const txtStep = find(steps, 'txt')
      const lower = nameToWire('_tag.example.com')
      const signer = nameToWire('example.com')
      const mixedOwner = lower.slice()
      mixedOwner[2] = 0x54 // _Tag
      const mixedSigner = signer.slice()
      mixedSigner[1] = 0x45 // Example

      // signRRset lowercases the owner, as real signers do: build these by hand
      const signedTxt = (owner: Uint8Array, signerName: Uint8Array) => {
        const rdata = txt('x')
        const header = concat(u16(RRType.TXT), new Uint8Array([13, labelCount(owner)]), u32(3600), u32(world.expiration), u32(world.inception), u16(keyTag(exampleCom.zsk.rdata)), signerName)
        const signedData = concat(header, owner, u16(RRType.TXT), u16(1), u32(3600), u16(rdata.length), rdata)
        return { ...txtStep, owner, signedData, signature: rawSign(exampleCom.zsk, signedData) }
      }

      await expect(sdk.proveStep({ step: signedTxt(lower, mixedSigner) })).rejects.toThrow(code('signer'))
      // accepted, but under its own bytes: the lowercase name is still unattested
      await sdk.proveStep({ step: signedTxt(mixedOwner, signer) })
      expect(await sdk.getRawAttestation('_tag.example.com')).toBeUndefined()
      expect((await sdk.scanRaw('t')).has(attestationKey(mixedOwner))).toBe(true)
    })

    test('an attestation over 4096 bytes', async () => {
      const { sdk, world, exampleCom, chain } = await deploy()
      await sdk.proveChain((await chain('_tag.example.com')).slice(0, 5))
      // stored: 64 header + 2 rdlen + RDATA. Signed data is 54 + RDATA at the apex, and an
      // argument caps at 4096 bytes: only names this short can reach the limit at all.
      // A group this large owes a usage fee over one per transaction: proveStep prices it
      const send = async () => sdk.proveStep({ step: find(await chain('example.com'), 'txt') })
      world.txt(exampleCom, 'example.com', [bigRdata(4031)])
      await expect(send()).rejects.toThrow(code('tooBig'))
      world.txt(exampleCom, 'example.com', [bigRdata(4030)])
      await send()
      expect((await sdk.scanRaw('t')).get(attestationKey('example.com'))?.length).toBe(4096)
      // hasRecord answers at any size: returning the box would log past an app call's 1024 bytes
      expect(await hasRecord(sdk, 'example.com', txt('hi'))).toBe(false)
      // a second record costs more signed bytes than stored ones: two top out at 4085.
      // The match sorts last (0xff > 0xfe), so the walk crosses the whole box
      const last = txt('y'.repeat(255))
      world.txt(exampleCom, 'example.com', [bigRdata(3761), last])
      await send()
      expect((await sdk.scanRaw('t')).get(attestationKey('example.com'))?.length).toBe(4085)
      expect(await hasRecord(sdk, 'example.com', last)).toBe(true)
    })

  })

  // ── Phase 3/6: a real chain, captured the same day ───────────────

  test('proves live captured chains under the real root anchor, where still valid', async (ctx) => {
    const dir = join(__dirname, '../../../captures')
    const latest = readdirSync(dir).filter((d) => /^\d{4}-\d\d-\d\d$/.test(d)).sort().at(-1)
    if (!latest) return ctx.skip()
    const capture = JSON.parse(readFileSync(join(dir, latest, 'chains.json'), 'utf8'))
    const valid: { name: string; steps: ProofStep[] }[] = []
    for (const name of capture.names as string[]) {
      try {
        const steps = await buildTxtChain(name, capturedResolver(capture.responses), { anchors: [ROOT_KSK_2017] })
        // leave a margin for LocalNet's clock
        if (Math.min(...steps.map((s) => s.expiration)) > Date.now() / 1000 + 300) valid.push({ name, steps })
      } catch {
        // expired since the capture
      }
    }
    if (valid.length === 0) return ctx.skip()

    const { testAccount } = localnet.context
    const sdk = await DnssecOracleSDK.create({ algorand: localnet.algorand, admin: accountSigner(testAccount) })
    await sdk.setup({ anchors: [ROOT_KSK_2017], credits: 5_000_000 })
    for (const { name, steps } of valid) {
      await sdk.proveChain(steps)
      const attestation = await sdk.getRawAttestation(name)
      expect(attestation?.texts.length).toBeGreaterThan(0)
      console.log(`${name}: ${attestation?.texts[0].slice(0, 60)}… weakest ${attestation?.weakestKeyBits} bits`)
    }
  })

  // ── Second pass: root rollover (RFC 5011) ───────────────────────
  // Hold-downs need a 30-day clock: Promote and Retire run in rollover.algo.spec.ts.

  describe('second pass: root rollover', () => {
    const rootKeys = (w: Awaited<ReturnType<typeof deploy>>, keys: Uint8Array[], signers: TestKey[], inceptionDelta = 0) =>
      w.world.publish(w.root.name, RRType.DNSKEY, keys, signers, w.root.name, { inception: w.world.inception + inceptionDelta })

    test('maintainAnchors: Add a new KSK, then Reset it when it leaves, credits round-trip', async () => {
      const d = await deploy()
      const { sdk, root, world } = d
      const admin = localnet.context.testAccount.toString()
      const next = ecKey()
      rootKeys(d, [root.ksk.rdata, root.zsk.rdata, next.rdata], [root.ksk])
      const before = await sdk.getCredits(admin)

      const added = await sdk.maintainAnchors({ resolver: world.resolver })
      expect(added.events).toEqual([{ event: 'Add', keyHash: toHex(anchorHash(next.rdata)), keyTag: keyTag(next.rdata) }])
      expect((await sdk.getAnchor(next.rdata))?.state).toBe(AnchorState.AddPend)
      // the root's cache box, then the new anchor's
      const rootCache = BigInt(CACHE_BOX_MBR_MICROALGOS)
      expect(await sdk.getCredits(admin)).toBe(before! - rootCache - BigInt(ANCHOR_BOX_MBR_MICROALGOS))
      // an AddPend key does not sign for the root
      expect((await sdk.trustedAnchors())(next.rdata)).toBe(false)
      // nothing more to do until the hold-down passes
      expect((await sdk.maintainAnchors({ resolver: world.resolver })).events).toEqual([])

      rootKeys(d, [root.ksk.rdata, root.zsk.rdata], [root.ksk], 60)
      const reset = await sdk.maintainAnchors({ resolver: world.resolver })
      expect(reset.events.map((e) => e.event)).toEqual(['Reset'])
      expect(await sdk.getAnchor(next.rdata)).toBeUndefined()
      expect(await sdk.getCredits(admin)).toBe(before! - rootCache)
      expect((await sdk.getState()).rollInception).toBe(BigInt(world.inception + 60))
    })

    test('maintainAnchors: a self-signed revocation stales what came before, then proofs go on under the other anchor', async () => {
      const second = ecKey()
      const d = await deploy({ extraAnchors: [second.rdata] })
      const { sdk, root, world, prove } = d
      await prove('_tag.example.com')
      const consumer = await consumerAsk(sdk)
      const ask = () => consumer('hello com')
      const live = async () => sdk.attestationChainLive((await sdk.getRawAttestation('_tag.example.com'))!, ['example.com', 'com'])
      expect(await ask()).toBe(true)
      const { rootEpoch } = await sdk.getState()

      const revoked = withFlags(root.ksk, 385)
      const signed = rootKeys(d, [revoked.rdata, second.rdata, root.zsk.rdata], [revoked, second])
      const { events } = await sdk.maintainAnchors({ resolver: world.resolver })
      expect(events.map((e) => [e.event, e.keyTag])).toEqual([['Revoke', keyTag(revoked.rdata)]])
      expect((await sdk.getAnchor(root.ksk.rdata))?.state).toBe(AnchorState.Revoked)
      expect(toHex((await sdk.getRawCache('.', RRType.DNSKEY))!.hash)).toBe(toHex(sha256(signed.rrset)))
      expect((await sdk.getState()).rootEpoch).not.toBe(rootEpoch)

      // proven before the revocation: stale to the SDK's reader and to consumers
      expect(await live()).toBe(false)
      expect(await ask()).toBe(false)

      // the SDK's default anchors are now read from the app: the revoked KSK is not among them.
      // Every stale cache entry is proven again, over its newer-or-equal inception
      const { proven } = await sdk.proveTxt('_tag.example.com', { resolver: world.resolver })
      expect(proven.map((s) => s.kind)).toEqual(['ds', 'dnskey', 'ds', 'dnskey', 'txt'])
      expect(await live()).toBe(true)
      expect(await ask()).toBe(true)
      expect((await sdk.maintainAnchors({ resolver: world.resolver })).events).toEqual([])
    })

    test('updateAnchor needs the cached root RRset and a key with an event', async () => {
      const d = await deploy()
      const { sdk, root, chain } = d
      const rootStep = find(await chain('_tag.example.com'), 'root')
      await sdk.proveStep({ step: rootStep })
      const stranger = ecKey()
      await expect(sdk.updateAnchor({ rrset: rootStep.rrset, keyHash: anchorHash(stranger.rdata) })).rejects.toThrow(code('rollover'))
      await expect(sdk.updateAnchor({ rrset: rootStep.rrset, keyHash: anchorHash(root.ksk.rdata) })).rejects.toThrow(code('rollover'))
      const tampered = rootStep.rrset.slice()
      tampered[tampered.length - 1] ^= 1
      await expect(sdk.updateAnchor({ rrset: tampered, keyHash: anchorHash(root.ksk.rdata) })).rejects.toThrow(code('parent'))
    })
  })

  // ── Phase 4: credits and prune ───────────────────────────────────

  describe('phase 4: credits and prune', () => {
    test('a sender without credits cannot create boxes', async () => {
      const { sdk, chain } = await deploy()
      const { other } = await otherSdk(sdk, 0)
      await expect(other.proveStep({ step: find(await chain('_tag.example.com'), 'root') })).rejects.toThrow(code('crd'))
    })

    test('replacing an attestation refunds the old payer; a payer who withdrew leaves it with the app', async () => {
      const { sdk, world, exampleCom, chain, prove } = await deploy()
      await prove('_tag.example.com')
      const payer = localnet.context.testAccount.toString()
      const { other, account } = await otherSdk(sdk)
      const mbr = attestationBoxMbrMicroAlgos(txt('hello com').length, 1)

      const before = await sdk.getCredits(payer)
      const otherBefore = await other.getCredits(account.toString())
      world.txt(exampleCom, '_tag.example.com', [txt('hello moo')], { inception: world.inception + 1 })
      await other.proveStep({ step: find(await chain('_tag.example.com'), 'txt') })
      expect(await sdk.getCredits(payer)).toBe(before! + BigInt(mbr))
      expect(await other.getCredits(account.toString())).toBe(otherBefore! - BigInt(mbr))

      // the payer is now `other`; they withdraw, and the next replacement still goes through
      await other.withdrawCredits({})
      expect(await other.getCredits(account.toString())).toBeUndefined()
      const stranded = await unowned(sdk)
      world.txt(exampleCom, '_tag.example.com', [txt('hello baa')], { inception: world.inception + 2 })
      await sdk.proveStep({ step: find(await chain('_tag.example.com'), 'txt') })
      expect(await other.getCredits(account.toString())).toBeUndefined()
      // the refund had nowhere to go: the app now holds that much that no credit accounts for
      expect((await unowned(sdk)) - stranded).toBe(BigInt(mbr))
    })

    test('expired boxes: prune rules and refunds, and a stale parent', async () => {
      const { sdk, world, com, exampleCom, chain } = await deploy()
      // a delegation and a TXT that expire in seconds
      const soon = Math.floor(Date.now() / 1000) + 15
      const short = { name: nameToWire('short.com'), ksk: ecKey(), zsk: ecKey({ flags: 256 }) }
      world.publish(short.name, RRType.DS, [dsRdata(short.name, short.ksk.rdata)], com.zsk, com.name, { expiration: soon })
      world.publishKeys(short)
      world.txt(short, 'x.short.com', [txt('x')])
      world.txt(exampleCom, '_tag.example.com', [txt('brief')], { expiration: soon })
      await sdk.proveChain(await chain('_tag.example.com'))
      const shortSteps = await chain('x.short.com')
      await sdk.proveStep({ step: find(shortSteps, 'ds', 'short.com') })
      const shortKeys = find(shortSteps, 'dnskey', 'short.com')

      // not yet expired
      await expect(sdk.prune({ name: 'short.com', type: RRType.DS })).rejects.toThrow(code('prune'))
      await waitPast(soon)

      // a stale parent
      await expect(sdk.proveStep({ step: shortKeys })).rejects.toThrow(code('stale'))

      // cache: anyone once expired, refund to the pruner, who needs a credit box
      const { other: noBox } = await otherSdk(sdk, 0)
      await expect(noBox.prune({ name: 'short.com', type: RRType.DS })).rejects.toThrow(code('rcv'))
      const { other, account } = await otherSdk(sdk)
      const before = await other.getCredits(account.toString())
      await other.prune({ name: 'short.com', type: RRType.DS })
      expect(await other.getCredits(account.toString())).toBe(before! + BigInt(CACHE_BOX_MBR_MICROALGOS))
      expect(await sdk.getRawCache('short.com', RRType.DS)).toBeUndefined()

      // attestation: only the payer, until 30 days past expiry; refund to the payer
      await expect(other.prune({ name: '_tag.example.com', type: RRType.TXT })).rejects.toThrow(code('prune'))
      const payer = localnet.context.testAccount.toString()
      const payerBefore = await sdk.getCredits(payer)
      await sdk.prune({ name: '_tag.example.com', type: RRType.TXT })
      expect(await sdk.getCredits(payer)).toBe(payerBefore! + BigInt(attestationBoxMbrMicroAlgos(txt('brief').length, 1)))
      expect(await sdk.getRawAttestation('_tag.example.com')).toBeUndefined()
      await expect(sdk.prune({ name: '_tag.example.com', type: RRType.TXT })).rejects.toThrow(code('missing'))
    })

  })

  // ── Phase 5: admin ───────────────────────────────────────────────

  describe('phase 5: admin', () => {
    test('the admin role can be handed over and renounced', async () => {
      const { sdk } = await deploy()
      const { other, account } = await otherSdk(sdk)
      const admin = localnet.context.testAccount.toString()
      await expect(other.setAdmin({ admin: account.toString() })).rejects.toThrow(code('admin'))
      await sdk.setAdmin({ admin: account.toString() })
      await expect(sdk.setAdmin({ admin })).rejects.toThrow(code('admin'))
      await other.setAdmin({ admin: Address.zeroAddress().toString() })
      await expect(other.setAdmin({ admin: account.toString() })).rejects.toThrow(code('admin'))
      expect((await sdk.getState()).admin).toBe(Address.zeroAddress().toString())
    })
  })

})
