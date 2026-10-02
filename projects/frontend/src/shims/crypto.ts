/**
 * Browser stand-in for the node:crypto calls the SDK makes: sha256 (prover/wire.ts) and the
 * RSA/SHA-256 and ECDSA P-256 checks in prover/chain.ts's verifySignature, which hands over
 * JWKs. Synchronous like node:crypto, so WebCrypto is out.
 */
import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'

type Jwk = { kty: 'RSA'; n: string; e: string } | { kty: 'EC'; crv: string; x: string; y: string }

export function createHash(algorithm: string) {
  if (algorithm !== 'sha256') throw new Error(`createHash: ${algorithm} unsupported`)
  const hash = sha256.create()
  const api = {
    update: (data: Uint8Array) => (hash.update(data), api),
    digest: () => hash.digest(),
  }
  return api
}

export function createPublicKey({ key }: { key: Jwk; format: 'jwk' }): Jwk {
  return key
}

export function verify(algorithm: string, data: Uint8Array, key: Jwk | { key: Jwk }, signature: Uint8Array): boolean {
  if (algorithm !== 'sha256') throw new Error(`verify: ${algorithm} unsupported`)
  const jwk = 'kty' in key ? key : key.key
  if (jwk.kty === 'RSA') return rsaVerify(b64url(jwk.n), b64url(jwk.e), data, signature)
  if (jwk.crv !== 'P-256') throw new Error(`verify: curve ${jwk.crv} unsupported`)
  const point = new Uint8Array([4, ...b64url(jwk.x), ...b64url(jwk.y)])
  // DNSSEC signatures may be high-S: noble rejects those by default
  return p256.verify(signature, data, point, { lowS: false })
}

const b64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const big = (b: Uint8Array) => BigInt('0x' + (hex(b) || '0'))

/** RFC 8017 §9.2: DigestInfo prefix for SHA-256. */
const SHA256_DIGEST_INFO = '3031300d060960864801650304020105000420'

/** RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2.2). */
function rsaVerify(modulus: Uint8Array, exponent: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
  const n = big(modulus)
  const k = Math.ceil(n.toString(16).length / 2)
  const s = big(signature)
  if (signature.length !== k || s >= n || k < 3 + 51 + 8) return false
  let m = 1n
  for (let base = s, e = big(exponent); e > 0n; e >>= 1n, base = (base * base) % n) if (e & 1n) m = (m * base) % n
  const expected = '0001' + 'ff'.repeat(k - 3 - 51) + '00' + SHA256_DIGEST_INFO + hex(sha256(data))
  return m.toString(16).padStart(2 * k, '0') === expected
}
