import { readFileSync } from 'node:fs'
import { buildTxtChain, capturedResolver, rdataOf, ROOT_ANCHORS, verifySignature } from '@d13co/dnssec-oracle-sdk'
import { expect, test } from 'vitest'
import * as crypto from 'node:crypto'
import { Buffer as BufferPolyfill } from 'buffer/'

// run the SDK on the browser's Buffer polyfill too, not node's
globalThis.Buffer = BufferPolyfill as unknown as typeof Buffer

// vite.config.ts aliases node:crypto to the shim, so the SDK runs on it here as in the browser
const fixture = JSON.parse(readFileSync(new URL('../../../dnssec-oracle/tests/fixtures/2026-09-28.json', import.meta.url), 'utf8'))

test('node:crypto is the shim', () => {
  // node's own createPublicKey would reject this half a JWK
  expect(crypto.createPublicKey({ key: { kty: 'RSA', n: '', e: '' }, format: 'jwk' })).toEqual({ kty: 'RSA', n: '', e: '' })
})

test('captured chains build and verify on the shim, and tampering fails', async () => {
  const algorithms = new Set<number>()
  for (const name of fixture.names) {
    const steps = await buildTxtChain(name, capturedResolver(fixture.responses), { anchors: ROOT_ANCHORS, now: fixture.capturedAt })
    for (const step of steps) {
      const key = rdataOf(step.kind === 'root' || step.kind === 'dnskey' ? step.rrset : step.parent)[step.keyIndex]
      algorithms.add(key[3])
      expect(verifySignature(key, step.signedData, step.signature)).toBe(true)
      const tampered = step.signedData.slice()
      tampered[tampered.length - 1] ^= 1
      expect(verifySignature(key, tampered, step.signature)).toBe(false)
    }
  }
  expect([...algorithms].sort((a, b) => a - b)).toEqual([8, 13])
})
