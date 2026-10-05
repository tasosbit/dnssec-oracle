import { generateAccount, secretKeyToMnemonic } from 'algosdk'
import { describe, expect, it } from 'vitest'
import {
  CACHE_BOX_MBR_MICROALGOS,
  CREDIT_BOX_MBR_MICROALGOS,
  ProofStep,
  attestationBoxMbrMicroAlgos,
  boxNames,
  nameToWire,
} from '@d13co/dnssec-oracle-sdk'
import { consumerReferencesReport, proveDeposit, proveMbrEstimate } from '../src/commands'
import { createWriterAccount, formatAlgo, parseAlgo } from '../src/utils'

describe('parseAlgo', () => {
  it('converts exactly, with no float rounding', () => {
    expect(parseAlgo('1')).toBe(1_000_000n)
    expect(parseAlgo('1.5')).toBe(1_500_000n)
    expect(parseAlgo('0.000001')).toBe(1n)
    expect(parseAlgo('4.35')).toBe(4_350_000n) // 4.35 * 1e6 = 4349999.999… as a float
    expect(parseAlgo(' 2 ')).toBe(2_000_000n)
  })

  it('rejects what is not a non-negative amount with at most 6 decimals', () => {
    for (const bad of ['', '-1', '1.0000001', 'abc', '1e6', '.5', '1.', '0x10']) {
      expect(() => parseAlgo(bad), bad).toThrow(/Invalid ALGO amount/)
    }
  })

  it('round-trips through formatAlgo', () => {
    expect(formatAlgo(parseAlgo('12.0345'))).toBe('12.034500')
    expect(formatAlgo(0n)).toBe('0.000000')
  })
})

describe('createWriterAccount', () => {
  const account = generateAccount()
  const mnemonic = secretKeyToMnemonic(account.sk)

  it('returns undefined without a mnemonic', () => {
    expect(createWriterAccount(undefined)).toBeUndefined()
  })

  it("signs as the mnemonic's own address by default", () => {
    const writer = createWriterAccount(mnemonic)!
    expect(writer.sender).toBe(account.addr.toString())
    expect(typeof writer.signer).toBe('function')
  })

  it('uses the given address as sender for a rekeyed account', () => {
    const other = generateAccount().addr.toString()
    expect(createWriterAccount(mnemonic, other)!.sender).toBe(other)
  })

  it('rejects a bad mnemonic and a bad address', () => {
    expect(() => createWriterAccount('not a mnemonic')).toThrow(/Invalid mnemonic/)
    expect(() => createWriterAccount(mnemonic, 'nope')).toThrow()
  })
})

describe('prove auto-credits', () => {
  const step = (kind: string, rrset = new Uint8Array()) => ({ kind, rrset }) as unknown as ProofStep
  // one TXT RR: root owner (1), type/class/TTL (8), RDLENGTH 4, RDATA "\x03abc"
  const txt = step('txt', new Uint8Array([0, 0, 16, 0, 1, 0, 0, 0, 60, 0, 4, 3, 97, 98, 99]))
  const attestation = BigInt(attestationBoxMbrMicroAlgos(4, 1))

  it('charges a cache box only where none exists, plus the attestation', () => {
    const steps = [step('root'), step('ds'), step('dnskey'), txt]
    expect(proveMbrEstimate(steps, [true, false, false])).toBe(2n * BigInt(CACHE_BOX_MBR_MICROALGOS) + attestation)
    expect(proveMbrEstimate(steps, [true, true, true])).toBe(attestation)
  })

  it('pads 10%, adds a new credit box, nets out credits held', () => {
    expect(proveDeposit(1000n, undefined)).toBe(1100n + BigInt(CREDIT_BOX_MBR_MICROALGOS))
    expect(proveDeposit(1001n, 0n)).toBe(1102n) // rounds up
    expect(proveDeposit(1000n, 600n)).toBe(500n)
    expect(proveDeposit(1000n, 5000n)).toBe(0n)
  })
})

describe('get --refs', () => {
  const b64 = (box: Uint8Array) => Buffer.from(box).toString('base64')

  it('prints the zones and 2 × zones + 2 box names, the attestation first', () => {
    const zones = ['example.com', 'com'].map((z) => nameToWire(z))
    const lines = consumerReferencesReport('_tag.example.com', zones)
    expect(lines[0]).toBe('  zones: example.com. com.')
    expect(lines[1]).toBe('  boxes (6):')
    expect(lines.slice(2)).toEqual([boxNames.attestation(nameToWire('_tag.example.com')), ...boxNames.chain(zones)].map((b) => `    ${b64(b)}`))
  })

  it('warns when a delegated chain needs more references than one transaction holds', () => {
    const zones = ['sub.example.com', 'example.com', 'com'].map((z) => nameToWire(z))
    const lines = consumerReferencesReport('_tag.sub.example.com', zones)
    expect(lines[0]).toBe('  zones: sub.example.com. example.com. com.')
    expect(lines[1]).toBe('  boxes (8):')
    expect(lines).toHaveLength(2 + 8 + 1)
    expect(lines.at(-1)).toMatch(/spread the boxes over the group/)
  })
})
