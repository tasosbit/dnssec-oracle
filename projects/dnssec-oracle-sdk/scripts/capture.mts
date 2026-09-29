/**
 * Capture DNS responses in wire format, for the prover and the test fixtures.
 *
 * Usage: tsx scripts/capture.mts <out dir> <name>...
 *
 * Writes <out dir>/chains.json: `responses` keyed by "<name wire hex> <type>" (see
 * capturedResolver), and per name either the built chain or the error. Deployment
 * assumptions that changed go to <out dir>/alerts.txt and stderr, and the exit code is 2.
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { ROOT_ANCHORS } from '../src/prover/anchors.js'
import { buildTxtChain, keyProblem } from '../src/prover/chain.js'
import { parseResponse, recordingResolver, tcpResolver } from '../src/prover/dns.js'
import { nameFromWire, parseDnskey, parseDs, parseRrsig, RRType } from '../src/prover/wire.js'

const [outDir, ...names] = process.argv.slice(2)
if (!outDir || names.length === 0) {
  console.error('Usage: tsx scripts/capture.mts <out dir> <name>...')
  process.exit(1)
}
mkdirSync(outDir, { recursive: true })

const responses: Record<string, string> = {}
const alerts: string[] = []
const capturedAt = Math.floor(Date.now() / 1000)

// the root straight from a root server, then everything else through a resolver
const rootResolver = recordingResolver(tcpResolver('198.41.0.4', { recursion: false }), responses)
await rootResolver(new Uint8Array([0]), RRType.DNSKEY)
const resolver = recordingResolver(tcpResolver('1.1.1.1'), responses)
const rootAware = (name: Uint8Array, type: number) =>
  name.length === 1 && type === RRType.DNSKEY ? rootResolver(name, type) : resolver(name, type)

const chains: Record<string, unknown> = {}
for (const name of names) {
  try {
    const steps = await buildTxtChain(name, rootAware, { anchors: ROOT_ANCHORS, now: capturedAt })
    chains[name] = steps.map((s) => ({
      kind: s.kind,
      owner: nameFromWire(s.owner),
      keyIndex: s.keyIndex,
      keyBits: s.keyBits,
      inception: s.inception,
      expiration: s.expiration,
    }))
  } catch (e) {
    chains[name] = { error: (e as Error).message }
    alerts.push(`${name}: chain failed: ${(e as Error).message}`)
  }
}

// Assumptions the contract makes that DNSSEC does not: alert when a zone moves off them.
for (const hex of Object.values(responses)) {
  const { answers } = parseResponse(Buffer.from(hex, 'hex'))
  for (const rr of answers) {
    const where = `${nameFromWire(rr.owner)} ${rr.type}`
    if (rr.type === RRType.DNSKEY) {
      const key = parseDnskey(rr.rdata)
      const problem = keyProblem(rr.rdata, key.algorithm)
      // revoked keys are expected during a roll; anything else is a change worth a look
      if (problem && problem !== 'revoked') alerts.push(`${where}: key flags ${key.flags}: ${problem}`)
      if (rr.owner.length === 1 && problem === 'revoked') alerts.push(`${where}: root key REVOKED (flags ${key.flags})`)
    }
    if (rr.type === RRType.DS && parseDs(rr.rdata).digestType !== 2) {
      alerts.push(`${where}: DS digest type ${parseDs(rr.rdata).digestType}`)
    }
    if (rr.type === RRType.RRSIG && rr.owner.length === 1 && parseRrsig(rr.rdata).typeCovered === RRType.DNSKEY) {
      const sig = parseRrsig(rr.rdata)
      if (sig.keyTag !== 20326) alerts.push(`${where}: root DNSKEY RRset signed by key ${sig.keyTag}, not 20326`)
    }
  }
}

writeFileSync(join(outDir, 'chains.json'), JSON.stringify({ capturedAt, names, chains, responses }, null, 1) + '\n')
if (alerts.length) {
  writeFileSync(join(outDir, 'alerts.txt'), alerts.join('\n') + '\n')
  console.error(alerts.join('\n'))
  process.exit(2)
}
console.log(`captured ${Object.keys(responses).length} responses for ${names.length} names into ${outDir}`)
