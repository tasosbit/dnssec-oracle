import { concat, dsDigest, fromHex, toHex, u16 } from './wire.js'

const dnskey = (flags: number, publicKeyBase64: string) =>
  concat(u16(flags), new Uint8Array([3, 8]), new Uint8Array(Buffer.from(publicKeyBase64, 'base64')))

/** Root KSK-2017, key tag 20326: the first-pass anchor. Stops signing the root DNSKEY RRset on 2026-10-11. */
export const ROOT_KSK_2017 = dnskey(
  257,
  'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=',
)

/** Root KSK-2024, key tag 38696: signs the root DNSKEY RRset from 2026-10-11. */
export const ROOT_KSK_2024 = dnskey(
  257,
  'AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=',
)

/**
 * SHA-256 DS digests (hex, lowercase) of the current root KSKs, from
 * https://data.iana.org/root-anchors/root-anchors.xml, checked against the keys above at
 * import. The verifier compares anchor boxes to this list; `verify --iana` compares the list
 * to the live file.
 */
export const IANA_DIGESTS: readonly string[] = [
  'e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d', // KSK-2017, tag 20326
  '683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16', // KSK-2024, tag 38696
]

export const ROOT_ANCHORS = [ROOT_KSK_2017, ROOT_KSK_2024]

for (const [i, key] of ROOT_ANCHORS.entries()) {
  if (toHex(dsDigest(fromHex('00'), key)) !== IANA_DIGESTS[i]) {
    throw new Error(`root anchor does not match IANA digest ${IANA_DIGESTS[i]}`)
  }
}
