import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import {
  AnchorState,
  CacheEntry,
  RR,
  ROOT_KSK_2017,
  RRType,
  Resolver,
  anchorHash,
  buildRootSteps,
  capturedResolver,
  nameToWire,
  parseDnskey,
  parseResponse,
  rdataOf,
  sha256,
  toHex,
} from 'dnssec-oracle-sdk'
import { KeyLookups, zoneKeysReport } from '../src/commands'

const capture = JSON.parse(readFileSync(join(__dirname, '../../../captures/2026-09-28/chains.json'), 'utf8'))
const resolver = capturedResolver(capture.responses)
const now: number = capture.capturedAt

const entry = (hash: Uint8Array, epoch = 2, parentEpoch = 1): CacheEntry => ({
  hash,
  inception: now - 1,
  expiry: now + 1,
  weakestKeyBits: 2048,
  epoch,
  parentEpoch,
})
const empty: KeyLookups = { cache: async () => undefined, anchor: async () => undefined, rootEpoch: async () => 1 }
const keyLines = (lines: string[]) => lines.filter((l) => /^ {2}(KSK|ZSK|flags)/.test(l))

/** The capture, with `edit` applied in place to the RDATA of the first RR in `name type`'s answer that `pick` selects. */
function patched(name: string, type: number, pick: (rr: RR) => boolean, edit: (rdata: Uint8Array) => void): Resolver {
  return async (n, t) => {
    const msg = await resolver(n, t)
    if (toHex(n) !== toHex(nameToWire(name)) || t !== type) return msg
    const rr = parseResponse(msg).answers.find((a) => a.type === type && pick(a))!
    const out = Buffer.from(msg)
    const rdata = rr.rdata.slice()
    edit(rdata)
    out.set(rdata, out.indexOf(Buffer.from(rr.rdata)))
    return new Uint8Array(out)
  }
}

describe('zoneKeysReport', () => {
  it('matches the root cache hash the prover would submit, and shows anchor states and ids', async () => {
    const [step] = await buildRootSteps(resolver, { now })
    const kskHash = toHex(anchorHash(ROOT_KSK_2017))
    const lines = await zoneKeysReport('.', resolver, {
      ...empty,
      cache: async () => entry(sha256(step.rrset)),
      anchor: async (rdata) => (toHex(anchorHash(rdata)) === kskHash ? { state: AnchorState.Valid, since: now } : undefined),
    }, now)
    expect(lines[0]).toMatch(/^\. DNSKEY: cache matches DNS; .*epoch 2$/)
    expect(keyLines(lines)).toHaveLength(rdataOf(step.rrset).length)
    expect(lines.find((l) => l.includes('KSK 20326'))).toMatch(
      new RegExp(`RSA-2048 \\(alg 8\\): usable by the oracle; anchor Valid since .*, id ${kskHash}$`),
    )
    const zsks = lines.filter((l) => l.startsWith('  ZSK'))
    expect(zsks.length).toBeGreaterThan(0)
    for (const zsk of zsks) expect(zsk).toMatch(/; not an anchor, id [0-9a-f]{64}$/)
  })

  it('flags a cache entry that is not the RRset DNS serves, or that the oracle would refuse', async () => {
    const [step] = await buildRootSteps(resolver, { now })
    const [differs] = await zoneKeysReport('.', resolver, { ...empty, cache: async () => entry(new Uint8Array(32)) }, now)
    expect(differs).toMatch(/cache differs from DNS/)
    const [none] = await zoneKeysReport('.', resolver, empty, now)
    expect(none).toBe('. DNSKEY: not cached')
    const revoked = { ...empty, cache: async () => entry(sha256(step.rrset)), rootEpoch: async () => 3 }
    const [stale] = await zoneKeysReport('.', resolver, revoked, now)
    expect(stale).toMatch(/cache matches DNS; .*\(stale: predates a root key revocation\)$/)
  })

  it('links a TLD KSK to its DS, and checks the DNSKEY entry is linked to the DS entry', async () => {
    const lines = await zoneKeysReport('com', resolver, empty, now)
    expect(lines).toContain('com. DS: not cached')
    expect(keyLines(lines).filter((l) => l.startsWith('  KSK'))).toEqual([expect.stringMatching(/P-256 \(alg 13\): usable by the oracle; DS matches$/)])
    for (const zsk of keyLines(lines).filter((l) => l.startsWith('  ZSK'))) expect(zsk).toMatch(/; no DS$/)
    expect(lines.filter((l) => l.startsWith('  DS'))).toEqual([expect.stringMatching(/digest type 2: vouches for KSK \d+$/)])

    const relinked = { ...empty, cache: async (_: Uint8Array, type: number) => entry(new Uint8Array(32), type === RRType.DS ? 7 : 8, 5) }
    expect((await zoneKeysReport('com', resolver, relinked, now))[0]).toMatch(/\(stale: proven under an older com\. DS entry\)$/)
    const orphan = { ...empty, cache: async (_: Uint8Array, type: number) => (type === RRType.DS ? undefined : entry(new Uint8Array(32))) }
    expect((await zoneKeysReport('com', resolver, orphan, now))[0]).toMatch(/\(stale: no com\. DS entry above it\)$/)
  })

  it('walks every link up to the root, as a consumer does', async () => {
    // epochs by entry: . DNSKEY 2 under rootEpoch 1, com. DS 3 under 2, com. DNSKEY 4 under 3
    const chain = (overrides: Record<string, Partial<CacheEntry> | null> = {}): KeyLookups => ({
      ...empty,
      cache: async (zone, type) => {
        const id = `${zone.length === 1 ? '.' : 'com.'} ${type === RRType.DS ? 'DS' : 'DNSKEY'}`
        const [epoch, parentEpoch] = ({ '. DNSKEY': [2, 1], 'com. DS': [3, 2], 'com. DNSKEY': [4, 3] } as Record<string, number[]>)[id]
        return overrides[id] === null ? undefined : { ...entry(new Uint8Array(32), epoch, parentEpoch), ...overrides[id] }
      },
    })
    const stale = async (lookups: KeyLookups) => (await zoneKeysReport('com', resolver, lookups, now)).filter((l) => /^com\. (DNSKEY|DS):/.test(l))
    for (const line of await stale(chain())) expect(line).not.toMatch(/stale/)

    const reroot = await stale(chain({ '. DNSKEY': { epoch: 9 } }))
    expect(reroot[0]).toMatch(/\(stale: com\. DS entry: proven under an older \. DNSKEY entry\)$/)
    expect(reroot[1]).toMatch(/^com\. DS: .*\(stale: proven under an older \. DNSKEY entry\)$/)
    const unrooted = await stale(chain({ '. DNSKEY': null }))
    expect(unrooted[1]).toMatch(/\(stale: no \. DNSKEY entry above it\)$/)
    const reanchored = await stale(chain({ '. DNSKEY': { parentEpoch: 7 } }))
    expect(reanchored[0]).toMatch(/\(stale: \. DNSKEY entry: proven under an older anchor set\)$/)
  })

  it('does not link a DS whose digest is wrong, and ignores digest types other than 2', async () => {
    const wrongDigest = patched('com', RRType.DS, () => true, (rdata) => (rdata[rdata.length - 1] ^= 1))
    const lines = await zoneKeysReport('com', wrongDigest, empty, now)
    expect(lines.find((l) => l.startsWith('  KSK'))).toMatch(/; no DS$/)
    expect(lines.find((l) => l.startsWith('  DS'))).toMatch(/: matches no key in the DNSKEY RRset$/)

    const sha384 = patched('com', RRType.DS, () => true, (rdata) => (rdata[3] = 4))
    const ignored = await zoneKeysReport('com', sha384, empty, now)
    expect(ignored.find((l) => l.startsWith('  DS'))).toMatch(/digest type 4: ignored by the oracle \(SHA-256 only\)$/)
    expect(ignored.find((l) => l.startsWith('  KSK'))).toMatch(/; no DS$/)
  })

  it('labels a revoked key, which the oracle refuses and its DS no longer matches', async () => {
    const revoke = patched('com', RRType.DNSKEY, (rr) => parseDnskey(rr.rdata).flags === 257, (rdata) => (rdata[1] |= 0x80))
    const lines = await zoneKeysReport('com', revoke, empty, now)
    expect(lines.find((l) => l.includes('REVOKED'))).toMatch(/^ {2}KSK REVOKED \d+, P-256 \(alg 13\): revoked; no DS$/)
  })

  it('says why there is nothing to compare when DNS serves no DNSKEY', async () => {
    // com's DS answer handed back for its DNSKEY query: no DNSKEY RRs at all
    const noKeys: Resolver = (n, t) => resolver(n, t === RRType.DNSKEY ? RRType.DS : t)
    const lines = await zoneKeysReport('com', noKeys, empty, now)
    expect(lines[0]).toBe('com. DNSKEY: DNS serves no DNSKEY; not cached')
    expect(keyLines(lines)).toHaveLength(0)
  })
})
