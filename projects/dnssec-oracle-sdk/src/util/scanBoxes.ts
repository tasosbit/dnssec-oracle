import { Algodv2 } from 'algosdk'

/** Every box under `prefix`, values included, consistent at one round. */
export async function scanBoxes(algod: Algodv2, appId: bigint, prefix: Uint8Array, limit = 1000) {
  const out: { name: Uint8Array; value: Uint8Array }[] = []
  let next: string | undefined
  let round: number | undefined
  do {
    let q = algod.getApplicationBoxes(appId).include('values').limit(limit).next(next)
    if (prefix.length) q = q.prefix(prefix)
    if (round !== undefined) q = q.round(round)
    const page = await q.do()
    round ??= page.round
    for (const { name, value } of page.boxes) {
      if (value === undefined) throw new Error('algod did not return box values (node too old?)')
      out.push({ name, value })
    }
    next = page.nextToken
  } while (next)
  return out
}
