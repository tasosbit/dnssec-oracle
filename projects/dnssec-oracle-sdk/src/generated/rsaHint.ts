/**
 * Off chain: the Montgomery hint `rsaStart` and the verify functions take for
 * `modulus`. That is `R² mod n` left-padded to `k` limbs, then `⌊R / n⌋`, with
 * `R = 2^(512·k)` and `k` the modulus length in 64-byte limbs, rounded up.
 *
 * It depends only on the key, so compute it once per key.
 */
export function rsaMontgomeryHint(modulus: Uint8Array): Uint8Array {
  const width = Math.ceil(modulus.length / 64) * 64
  const n = BigInt('0x' + toHex(modulus))
  const r = 1n << BigInt(8 * width)
  const rSquared = fromHex(((r * r) % n).toString(16).padStart(2 * width, '0'))
  const quotient = (r / n).toString(16)
  return new Uint8Array([...rSquared, ...fromHex(quotient.padStart(quotient.length + (quotient.length % 2), '0'))])
}

const toHex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

const fromHex = (hex: string) => Uint8Array.from(hex.match(/../g) ?? [], (b) => parseInt(b, 16))
