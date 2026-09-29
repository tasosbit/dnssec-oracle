import { generateAccount, secretKeyToMnemonic } from 'algosdk'
import { describe, expect, it } from 'vitest'
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
