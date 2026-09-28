# `rsa_verify` — AVM opcode design

Status: proposal, 2026-09-28. Opcode design only: no implementation plan.

## Goal

A native RSA signature verification opcode for the AVM, general enough for the
common PKI uses of RSA, and sufficient for the DNSSEC oracle in `plan.md`.

Today RSA-2048 verification in TEAL costs about 92k opcodes, needs a
prover-supplied Montgomery hint, and needs a group padded with about 130 OpUp
calls.

## Specification

```
rsa_verify S
Stack: ..., A: []byte, B: []byte, C: []byte, D: uint64 → ..., bool

  A = message digest (not the message)
  B = signature, big-endian
  C = modulus n, big-endian
  D = public exponent e
```

Argument order follows `ecdsa_verify` and `ed25519verify_bare`: data,
signature, key.

### Field `S`: scheme and hash

| Field             | Digest length | Used by                                                          |
|-------------------|---------------|------------------------------------------------------------------|
| `PKCS1v15_SHA256` | 32            | DNSSEC alg 8, X.509 sha256WithRSA, JWT RS256, WebAuthn -257, DKIM |
| `PKCS1v15_SHA512` | 64            | DNSSEC alg 10, X.509 sha512WithRSA, JWT RS512                    |

Deferred to v2, not part of this proposal:

| Field             | Digest length | Used by                                                          |
|-------------------|---------------|------------------------------------------------------------------|
| `PSS_SHA256`      | 32            | JWT PS256, WebAuthn -37, TLS 1.3, X.509 RSASSA-PSS               |
| `PSS_SHA512`      | 64            | JWT PS512                                                        |

- **PKCS#1 v1.5:** the opcode builds the DigestInfo prefix itself; the
  contract passes only the raw digest. Only the DigestInfo form with NULL
  parameters is accepted.
- **PSS (v2):** MGF1 uses the same hash as the digest. Salt length is fixed
  to the hash length, as TLS 1.3 and JOSE require. Open for v2: with a
  64-byte salt, `PSS_SHA512` cannot verify under a modulus below 1034 bits,
  so it needs its own floor.

### Outcomes

Wrong lengths fail the program. Bad values return 0. This matches
`ecdsa_verify`, which fails on a wrong data length and returns false for a
public key that is not on the curve.

| Condition                                         | Outcome  |
|---------------------------------------------------|----------|
| `len(A)` ≠ digest size of `S`                     | fail     |
| `len(C)` > 512                                    | fail     |
| `len(B)` ≠ `len(C)`                               | fail     |
| `C[0]` = 0, or `bitlen(n)` < 1024                 | return 0 |
| `n` even                                          | return 0 |
| `e` even, `e` < 3, or `e` > 65537                 | return 0 |
| signature value ≥ `n`                             | return 0 |
| padding or digest mismatch                        | return 0 |
| otherwise                                         | return 1 |

The opcode never strips or adds leading zeros. A contract holding a shorter
signature left-pads it to the modulus length.

Returning 0 rather than failing lets a contract try more than one key. DNSSEC
key tags collide, so this is a real case.

### Cost

By modulus size bracket, each benchmarked at the most expensive allowed
exponent:

| Bracket, bits | 1024 | 1025–2048 | 2049–3072 | 3073–4096 |
|---------------|------|-----------|-----------|-----------|

The cost does not depend on the value of `e`. Brackets need a small new cost
function: verification time is far from linear in modulus size, so the
existing linear `costByLength` would overcharge RSA-2048 by about 8x.

## Design choices

| Choice | Reason |
|--------|--------|
| Digest in, not message | Matches `ecdsa_verify`. The contract picks the hash opcode. Message size limits are the hash opcode's concern. |
| Raw `n` and `e`, no key format | DNSKEY (RFC 3110), JWK and X.509 SubjectPublicKeyInfo are unpacked by the contract. No ASN.1 parsing in consensus code. |
| Standard padding only, no raw modexp | Hand-written padding checks are where RSA verifiers break (Bleichenbacher 2006, BERserk). |
| Size bound in bits | A byte-length bound admits 1017 to 1023-bit moduli. |
| 1024 to 4096 bits | 1024 is the smallest key DNSSEC still uses (`io`, `finance`, `co` ZSKs). 4096 covers root CAs. A 512-byte modulus fits the 4,096-byte AVM value limit. |
| `e` ≤ 65537 | Covers 3, 17 and 65537. Keeps the gap between the charged worst case and the common case small. |
| Every case listed in the spec | The opcode's behaviour must not be "whatever the library does". See below. |

### Why the spec cannot defer to `crypto/rsa`

Observed behaviour of `rsa.VerifyPKCS1v15` with a valid signature:

| Input            | Go 1.23.4          | Go 1.25.3 (repo toolchain) |
|------------------|--------------------|----------------------------|
| 512-bit key      | accepts            | rejects                    |
| 1017-bit key     | accepts            | rejects                    |
| 1023-bit key     | accepts            | rejects                    |
| 1024-bit key     | accepts            | accepts                    |
| even `e`         | verification error | key error                  |
| even `n`         | verification error | key error                  |
| signature ≥ `n`  | verification error | verification error         |
| signature with an extra leading zero byte | verification error | verification error |

The minimum key size is also switchable at run time with
`GODEBUG=rsa1024min=0`. None of this may influence consensus.

## Measurements

Laptop figures (AMD Ryzen 7 5700U), PKCS#1 v1.5 with SHA-256. Estimates only:
not the repository's cost calibration procedure. PSS was within 10% of v1.5.

| Modulus | e = 3  | e = 65537 | e = 2³¹−1 | Go version |
|---------|--------|-----------|-----------|------------|
| 1024    | 5 µs   | 10 µs     | 24 µs     | 1.25.3     |
| 2048    | 15 µs  | 29 µs     | 72 µs     | 1.25.3     |
| 3072    | 72 µs  | 166 µs    | 409 µs    | 1.23.4     |
| 4096    | 122 µs | 270 µs    | 683 µs    | 1.25.3     |

Reference points on the same machine:

| Opcode               | Cost | Time  |
|----------------------|------|-------|
| `ed25519verify_bare` | 1900 | 51 µs |
| `ecdsa_verify` P-256 | 2500 | 64 µs |

That is about 38 cost units per µs, which puts RSA-2048 at e = 65537 near
1,100 and RSA-4096 near 10,000.

Not measured: the most expensive exponent under the `e` ≤ 65537 rule (65535).

## Effect on the DNSSEC oracle

- No Montgomery hint and no OpUp-padded group.
- The RSA library no longer counts against the 16 KB program limit.
- RSASHA512 (DNSSEC alg 10) becomes available.
- The RSA arithmetic moves from contract code into the node. Trust point #9
  in `plan.md` still covers the wire parser and the rule list.
- The exponent and modulus rules in `plan.md` ("Key and signature checks")
  stay in the contract: they are stricter than the opcode's.

Every key on the whitelist is 1024 to 2048 bits with e = 65537 and SHA-256, so
all of it is covered.

## Left out

| Item | Add when |
|------|----------|
| PSS fields (v2) | A contract needs JWT PS256/PS512, WebAuthn -37 or RSASSA-PSS certificates. DNSSEC has no PSS algorithm. |
| SHA-384 fields | The AVM gets a `sha384` opcode. Without one the fields cannot be used. |
| SHA-1 fields | DNSSEC alg 5 and 7 or legacy documents are needed. |
| Other PSS salt lengths | A real format needs one. Many e-passports do. |
| Raw modexp | A non-standard padding such as ISO 9796-2 is needed. |
| Moduli above 4096 bits | Never seen in the target formats. |
| `e` above 65537 | A real key needs it. DNSSEC permits it; no whitelisted zone uses it. |
