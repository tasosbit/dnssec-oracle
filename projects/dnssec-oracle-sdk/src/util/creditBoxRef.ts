import { Address } from 'algosdk'

/** The MbrManager userCredits box name for an account: 'c' + 32-byte public key. */
export function creditBoxRef(account: string | Address | Uint8Array): Uint8Array {
  const publicKey = account instanceof Uint8Array ? account : Address.fromString(account.toString()).publicKey
  const ref = new Uint8Array(1 + publicKey.length)
  ref[0] = 0x63 // 'c'
  ref.set(publicKey, 1)
  return ref
}
