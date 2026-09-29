import { Bytes, bytes } from '@algorandfoundation/algorand-typescript'
import { TestExecutionContext } from '@algorandfoundation/algorand-typescript-testing'
import {
  canonicalRRset,
  CLASS_IN,
  concat,
  keyTag as sdkKeyTag,
  nameToWire,
  ROOT_KSK_2017,
  ROOT_KSK_2024,
  RRType,
  u16,
  u32,
} from 'dnssec-oracle-sdk'
import { afterEach, describe, expect, test } from 'vitest'
import {
  checkName,
  isAncestor,
  keyTag,
  parseSignedData,
  readName,
  tldOf,
  walkRRset,
} from '../smart_contracts/dnssec_oracle/wire.algo'
import { txt } from './zone'

const ctx = new TestExecutionContext()
afterEach(() => ctx.reset())
/** loggedAssert logs, and logging needs a transaction. */
const inTxn = <T>(fn: () => T) => ctx.txn.createScope([ctx.any.txn.applicationCall()]).execute(fn)

const b = (x: Uint8Array | string) => Bytes(typeof x === 'string' ? nameToWire(x) : x)
const hex = (x: bytes) => Buffer.from((x as unknown as { asUint8Array(): Uint8Array }).asUint8Array()).toString('hex')
const code = (c: string) => new RegExp(`ERR:${c}\\b`)

/** One RR in wire format, TTL 3600. */
const rr = (owner: Uint8Array, type: number, rdata: Uint8Array, cls = CLASS_IN) =>
  concat(owner, u16(type), u16(cls), u32(3600), u16(rdata.length), rdata)

/** RRSIG RDATA without the signature, over `rrset`. */
const header = (type: number, labels: number, signer: string, inception = 1000, expiration = 2000) =>
  concat(u16(type), new Uint8Array([13, labels]), u32(3600), u32(expiration), u32(inception), u16(1), nameToWire(signer))

describe('names', () => {
  test('reads a name: end offset and label count', () => {
    const [end, labels] = readName(b('_tag.example.com'), 0)
    expect(end).toEqual(18)
    expect(labels).toEqual(3)
    expect(readName(b('.'), 0)).toEqual([1, 0])
  })

  test.each([
    ['a compression pointer', [0xc0, 0x0c]],
    ['an extended label 0x40', [0x40, 0x00]],
    ['an extended label 0x80', [0x80, 0x00]],
    ['a 64-byte label', [64, ...new Array(64).fill(0x61), 0]],
  ])('rejects %s', (_, wire) => {
    expect(() => inTxn(() => readName(Bytes(new Uint8Array(wire)), 0))).toThrow(code('WIR'))
  })

  test('rejects names over 255 bytes, and accepts 255', () => {
    const label = [63, ...new Array(63).fill(0x61)]
    const long = new Uint8Array([...label, ...label, ...label, ...label, 0]) // 257 bytes
    expect(() => inTxn(() => readName(Bytes(long), 0))).toThrow(code('WIR'))
    const max = new Uint8Array([...label, ...label, ...label, 61, ...new Array(61).fill(0x61), 0]) // 255 bytes
    expect(readName(Bytes(max), 0)[0]).toEqual(255)
  })

  test('rejects a wildcard label anywhere, but not a label merely starting with *', () => {
    expect(() => inTxn(() => readName(b('*.example.com'), 0))).toThrow(code('WLD'))
    expect(() => inTxn(() => readName(b('a.*.com'), 0))).toThrow(code('WLD'))
    expect(readName(b('*a.example.com'), 0)[1]).toEqual(3)
  })

  test('checkName rejects trailing bytes', () => {
    expect(checkName(b('example.com'))).toEqual(2)
    expect(() => inTxn(() => checkName(Bytes(concat(nameToWire('example.com'), new Uint8Array([0])))))).toThrow(code('WIR'))
  })

  test('ancestry is label by label: ample is not an ancestor of example', () => {
    expect(isAncestor(b('ample.com'), b('example.com'), false)).toBe(false)
    expect(isAncestor(b('le.com'), b('example.com'), true)).toBe(false)
    expect(isAncestor(b('example.com'), b('x.example.com'), true)).toBe(true)
    expect(isAncestor(b('example.com'), b('example.com'), false)).toBe(true)
    expect(isAncestor(b('example.com'), b('example.com'), true)).toBe(false)
    expect(isAncestor(b('.'), b('example.com'), true)).toBe(true)
    expect(isAncestor(b('.'), b('.'), true)).toBe(false)
    expect(isAncestor(b('.'), b('.'), false)).toBe(true)
    expect(isAncestor(b('x.example.com'), b('example.com'), false)).toBe(false)
  })

  test('co is not co.com: the TLD is the rightmost label', () => {
    expect(hex(tldOf(b('co.com')))).toBe(Buffer.from('com').toString('hex'))
    expect(hex(tldOf(b('x.co')))).toBe(Buffer.from('co').toString('hex'))
    expect(hex(tldOf(b('com')))).toBe(Buffer.from('com').toString('hex'))
    expect(isAncestor(b('co'), b('co.com'), true)).toBe(false)
    expect(isAncestor(b('com'), b('co.com'), true)).toBe(true)
  })

  test('key tags agree with the SDK and the root KSKs', () => {
    expect(keyTag(Bytes(ROOT_KSK_2017))).toEqual(20326)
    expect(keyTag(Bytes(ROOT_KSK_2024))).toEqual(38696)
    const odd = new Uint8Array([1, 1, 3, 13, 9, 8, 7])
    expect(keyTag(Bytes(odd))).toEqual(sdkKeyTag(odd))
  })
})

describe('RRsets', () => {
  const owner = nameToWire('_tag.example.com')

  test('walks to the indexed RR and builds TXT records', () => {
    const rrset = canonicalRRset(
      [txt('b'), txt('a')].map((rdata) => ({ owner, type: RRType.TXT, class: CLASS_IN, ttl: 1, rdata })),
      3600,
    )
    const [o, labels, indexed, records] = walkRRset(Bytes(rrset), 0, RRType.TXT, 1, true)
    expect(hex(o)).toBe(Buffer.from(owner).toString('hex'))
    expect(labels).toEqual(3)
    expect(hex(indexed)).toBe(Buffer.from(txt('b')).toString('hex'))
    expect(hex(records)).toBe('0002' + '0161' + '0002' + '0162')
    expect(() => inTxn(() => walkRRset(Bytes(rrset), 0, RRType.TXT, 2, true))).toThrow(code('IDX'))
  })

  test('boundary shift: a fake RR inside a TXT value stays RDATA', () => {
    // a tenant's TXT value that is, byte for byte, an RR for a sibling name
    const fake = rr(nameToWire('victim.example.com'), RRType.TXT, txt('forged'))
    const value = concat(new Uint8Array([fake.length]), fake)
    const data = rr(owner, RRType.TXT, value)
    const [o, , indexed, records] = walkRRset(Bytes(data), 0, RRType.TXT, 0, true)
    expect(hex(o)).toBe(Buffer.from(owner).toString('hex'))
    expect(hex(indexed)).toBe(Buffer.from(value).toString('hex'))
    expect(hex(records)).toBe(Buffer.from(concat(u16(value.length), value)).toString('hex'))
    expect(() => inTxn(() => walkRRset(Bytes(data), 0, RRType.TXT, 1, true))).toThrow(code('IDX'))
  })

  test('rejects trailing bytes and RDATA past the end', () => {
    const data = rr(owner, RRType.TXT, txt('x'))
    expect(() => inTxn(() => walkRRset(Bytes(concat(data, new Uint8Array([0]))), 0, RRType.TXT, 0, true))).toThrow(code('OWN'))
    expect(() => inTxn(() => walkRRset(Bytes(concat(data, new Uint8Array([1, 0x61]))), 0, RRType.TXT, 0, true))).toThrow()
    const short = data.slice(0, data.length - 1)
    expect(() => inTxn(() => walkRRset(Bytes(short), 0, RRType.TXT, 0, true))).toThrow(code('WIR'))
  })

  test('one owner, one type, class IN', () => {
    const one = rr(owner, RRType.TXT, txt('x'))
    const other = rr(nameToWire('_tag.example.org'), RRType.TXT, txt('y'))
    expect(() => inTxn(() => walkRRset(Bytes(concat(one, other)), 0, RRType.TXT, 0, true))).toThrow(code('OWN'))
    expect(() => inTxn(() => walkRRset(Bytes(one), 0, RRType.DS, 0, false))).toThrow(code('TYP'))
    expect(() => inTxn(() => walkRRset(Bytes(rr(owner, RRType.TXT, txt('x'), 3)), 0, RRType.TXT, 0, true))).toThrow(code('CLS'))
  })

  test('TXT character-strings must sum to the RDATA length', () => {
    for (const bad of [new Uint8Array([]), new Uint8Array([2, 0x61]), new Uint8Array([1, 0x61, 5])]) {
      expect(() => inTxn(() => walkRRset(Bytes(rr(owner, RRType.TXT, bad)), 0, RRType.TXT, 0, true))).toThrow(code('TXT'))
    }
    // not checked for other types
    walkRRset(Bytes(rr(owner, RRType.DS, new Uint8Array([2, 0x61]))), 0, RRType.DS, 0, false)
  })
})

describe('signed data', () => {
  const owner = nameToWire('_tag.example.com')
  const rrset = rr(owner, RRType.TXT, txt('hello'))

  test('parses names only from the bytes', () => {
    const s = parseSignedData(Bytes(concat(header(RRType.TXT, 3, 'example.com'), rrset)), RRType.TXT, 0, 1500)
    expect(hex(s.signer)).toBe(Buffer.from(nameToWire('example.com')).toString('hex'))
    expect(hex(s.owner)).toBe(Buffer.from(owner).toString('hex'))
    expect(hex(s.rrset)).toBe(Buffer.from(rrset).toString('hex'))
    expect(s.inception).toEqual(1000)
    expect(s.expiration).toEqual(2000)
    expect(s.algorithm).toEqual(13)
  })

  test.each([
    ['type covered', () => concat(header(RRType.DS, 3, 'example.com'), rrset), 1500, 'TYP'],
    ['labels', () => concat(header(RRType.TXT, 2, 'example.com'), rrset), 1500, 'LBL'],
    ['not yet valid', () => concat(header(RRType.TXT, 3, 'example.com'), rrset), 999, 'TIM'],
    ['expired', () => concat(header(RRType.TXT, 3, 'example.com'), rrset), 2001, 'TIM'],
    ['a pointer in the signer name', () => concat(header(RRType.TXT, 3, 'com').slice(0, 18), new Uint8Array([0xc0, 0x0c]), rrset), 1500, 'WIR'],
  ])('rejects a wrong %s', (_, data, now, err) => {
    expect(() => inTxn(() => parseSignedData(Bytes(data()), RRType.TXT, 0, now))).toThrow(code(err))
  })

  test('accepts the edges of the validity window', () => {
    const data = Bytes(concat(header(RRType.TXT, 3, 'example.com'), rrset))
    parseSignedData(data, RRType.TXT, 0, 1000)
    parseSignedData(data, RRType.TXT, 0, 2000)
  })
})
