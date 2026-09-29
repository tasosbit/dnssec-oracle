# Review findings

Independent review of the first implementation, 2026-09-29, with follow-up by running the
negative tests it asked for. All findings are resolved as of 2026-09-29; each notes how.

No way was found to get a cache entry or attestation for data DNS did not sign. The
findings are about rent and prune rules, the reference consumer, and the SDK.

Tests named below are in `tests/contract.e2e.spec.ts` and run on LocalNet.

## 1. Resolved: the plan claimed the grace keeps the newest-inception mark alive

The plan said the 30-day grace "keeps the newest-inception mark alive". Its own rules
contradicted that:
- The payer may prune the moment an attestation expires.
- Ties replace, so anyone can become the payer by proving the current RRset again.

After such a prune, an older RRset whose RRSIG is still valid can be proven again. This
needs the older signature to outlive the newer attestation's expiry, which usually means
that expiry was capped by the chain above it.

That is ordinary DNSSEC replay inside a validity window, which the plan already accepts
("Anyone can submit any still-valid RRset when nothing newer is stored"). The replayed
record keeps its older inception, so a consumer's `maxAge` bounds it.

- Resolution: the claim was dropped from `plan.md`. The grace now only keeps an expired
  attestation readable. The code is unchanged.

## 2. Resolved (medium): the reference consumer does not pin the oracle

`consumer/contract.algo.ts` `hasTxt(oracle, …)` and `reader.algo.ts` `readAttestation`
read `t‖sha256(name)` from whatever app the caller passes. An attacker's app with a forged
`t` box and ForeignBoxReads makes `hasTxt` return true. Plan trust point #6 has consumers pin
the app ID, and the example does not.

`attestationUsable` also does not check the whitelist: after `removeTld`, attestations stay
usable until someone prunes them.

- Resolution: `AttestationConsumer` takes the oracle at create (global state `oracle`), and
  `hasTxt` no longer takes one. `reader.algo.ts` gains `tldListed(oracle, name)`, which
  `hasTxt` checks. The ForeignBoxReads test now also shows a de-listed attestation reads
  as unusable.

## 3. Resolved (medium): the SDK under-pays the fee of a large proof

The SDK's op-up sets a flat 1,000 µAlgo per transaction. Under consensus v42, a large group
owes a usage fee on top. A TXT step of about 4 KB reports `groupUsage` 10,231,000 in
simulate, against 1,000,000 for small groups, and `proveStep` comes up 232 µAlgo short. Any
name with a large TXT RRset fails through the SDK. The Phase 0 conclusion that fees are
just the transaction count holds only for small groups.

- Measured on LocalNet: a group owes `ceil(groupUsage × minFee / 10⁶)`, and the op-up call
  and each of its inner calls add exactly one unit, so no margin or second simulate is needed.
- Resolution: `probeOpUp` (was `probeOpUpItxns`) returns `{ itxns, extraFee }`: the inner
  calls, plus what the probed group's usage fee exceeds its own fees. The op-up call carries
  it, with `maxFee` to match. A group that fits its budget but under-pays still gets an
  `increaseBudget(0)` to carry the fee. The 4096-byte test now proves through `proveStep`.

## 4. Resolved (low): `removeTld` fails when the admin has no credit box

The refund goes through `manageMbrCredits`, which asserts that the sender has a credit box.
After `withdrawCredits`, or with a new admin who never deposited, an emergency de-listing
fails with RCV until they deposit.

- Resolution: the refund is skipped when there is no box, as `deleteAttestation` does. Covered
  in `removing a TLD blocks its proofs and refunds the admin`.

## 5. Resolved (low): ties replace cache entries too

`writeCache` lets anyone overwrite a cache entry at equal inception. When two valid
signatures share an inception (multiple signers or ZSKs, or `co`'s 1280- and 1024-bit keys),
the replacement can lower `expiry` or `weakestKeyBits`. Plan trust point #5 covers the
bits, but not the expiry-shortening denial of service. Plausible, not reproduced with real
data.

- Fix: on a tie, replace only if expiry and bits do not get worse. Not "only if the hash
  changes": re-proving the same RRset at the same inception is how a cache entry picks up a
  longer expiry after its parent is refreshed (`proveChain` does this).
- It heals itself: anyone can re-prove the better signature.
- Resolution: `writeCache` asserts, on a tie, that expiry and bits do not get worse (new code
  `WRS`). Covered in `newest inception wins; ties replace`. Attestations keep plain ties, as
  plan trust point #5 describes.

## 6. Resolved (low): the SDK accepts an RSA key the contract rejects

`prover/chain.ts` `keyProblem` accepts 65537 in the 3-byte exponent-length form. The
contract requires the `03 010001` prefix and fails with EXP, so the SDK builds proofs that
fail on-chain.

- Resolution: `keyProblem` requires `publicKey[0] === 3`. The RSA key tests now assert that
  `keyProblem` rejects every key the contract does.

## 7. Resolved (low): names are never checked for case

- **Owners:** the contract never checks that names are lowercase. This is not exploitable:
  a mixed-case owner lands in its own box and the lowercase name stays unattested, and a
  mixed-case signer is not an ancestor (SGN). Both are covered by
  `test('mixed case: …')`.
- **TLD labels:** `addTld` accepts any bytes. The SDK sends the label unchanged but
  `boxNames.tld` lowercases it, so `addTld({ label: 'COM' })` gets the wrong box reference,
  and if it goes through it creates a whitelist entry that matches nothing.
- Resolution: both. `addTld` rejects 0x41–0x5A (TLD), and the SDK makers for `addTld` and
  `removeTld` lowercase the label. Covered by `TLD labels must be lowercase; …`.

## 8. Resolved (nit): the 4096-byte limit

The plan says anything over 4096 bytes is "rejected before hashing"; the contract does not
check that. It doesn't need to, though: v42 caps each app argument at 4096 bytes, so
oversized signed data never reaches it.

The same cap means the `BIG` error only fires for short names. Signed data is 54 bytes plus
the RDATA for an apex TXT at `example.com`, against 58 bytes plus the RDATA as stored, and
`_tag.example.com` cannot reach the limit at all. This is covered by
`test('an attestation over 4096 bytes')`.

The SDK exports `MAX_VALUE_BYTES` but never checks against it.

- Resolution: `plan.md` now says the argument cap does the job. `buildTxtChain` throws on
  signed data over `MAX_VALUE_BYTES` instead of sending a group algod will refuse.

## 9. Resolved (nit): the probe has little budget headroom

`SIMULATE_PARAMS.extraOpcodeBudget` is 130,013, only about 35k above the largest measured
step (94.6k). If a step ever outgrows the probe, the op-up is under-sized.

- Resolution: raised to 320,000, simulate's maximum, above the 190,400 a group can ever use.

## 10. Resolved (nit): prover choices

- `buildTxtChain`'s `pick` takes the first valid RRSIG, not the one with the newest
  inception, so the TXT step can hit OLD when signatures have different inceptions. Cache
  steps whose RRset is unchanged are skipped, so they don't. Resolution: `fetch` sorts
  RRSIGs newest first, so `pick` takes the newest usable one.
- `proveChain` throws on an expired cache with a newer inception instead of pruning it,
  which anyone may do. Resolution: it prunes the entry, then proves. It still throws while
  the newer entry is unexpired.
- The contract's `proveTxt` accepts any ancestor as signer, not only the closest enclosing
  zone, so data under a delegation that is signed by the parent is accepted. This is a
  contract rule, not a prover choice, and within plan trust point #2 ("sign records below a
  zone cut directly"). Accepted: no change.

## Checked and sound

- **Parent binding:**
  - The cache box is found from the signer or owner parsed out of the signed data, and
    `sha256(parent)` must equal the stored hash.
  - `keyIndex` and `dsIndex` pick the exact bytes that `checkKey`, `checkDs` and `verify`
    use.
  - A DS RRset passed as `parent` fails with PAR.
- **DS:** type 2 only, length 36, and key tag, algorithm and digest over `owner‖dnskey`
  must all match.
  - A key other than the one the DS matches fails with DSM.
  - A KSK claim with a ZSK signature fails with SIG.
- **Parser:**
  - Parsing starts at offset 0 and must end exactly at the end of the data.
  - All RRs share one owner, one type and class IN.
  - Pointers, extended labels and a `*` label anywhere are rejected.
  - The labels field must equal the owner's label count, and names are capped at 255
    bytes.
  - The boundary-shift attack is closed.
- **Names:**
  - `isAncestor` compares label by label, so `ample`/`example` and `co`/`co.com` are
    handled correctly.
  - A sibling or cousin zone cannot sign a DS (SGN).
- **Time:**
  - Expiry takes the minimum down the chain, and a stale parent is rejected.
  - The validity window is inclusive.
- **Crypto:**
  - **ECDSA:**
    - Low-S is normalized, s = 0 and s = n fail with SIG, and s > n fails because the
      subtraction underflows (no error code).
    - An RRSIG algorithm that differs from the key's fails with ALG.
  - **RSA:**
    - The exponent must be 65537 in the 1-byte form.
    - The modulus must be 1024 to 2048 bits by its real length, with no leading zero.
    - The signature must be the same length as the modulus, and a hint is required.
  - **Key flags:** a revoked or non-zone key fails with KFL on every path, including
    through `parent` in `proveDs` and `proveTxt`.
- **Box keys:** the `a`/`w`/`r`/`t`/`c` prefixes are disjoint, and `name‖u16 type` is
  unambiguous.
- **Contract controls:**
  - Inner-transaction fees are 0 in both `increaseBudget` and `withdrawCredits`.
  - The router accepts NoOp only (no update or delete).
  - ForeignBoxReads is set at create.
- **Rent:**
  - Replacing an attestation refunds the old payer and charges the sender.
  - A payer who withdrew is skipped.
  - No path pays out more than the credits.
