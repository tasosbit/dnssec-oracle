import {
  Account,
  BigUint,
  BoxMap,
  bytes,
  Bytes,
  Global,
  GlobalState,
  log,
  loggedAssert,
  op,
  readonly,
  Txn,
  uint64,
} from '@algorandfoundation/algorand-typescript'
import { baremethod } from '@algorandfoundation/algorand-typescript/arc4'
import { verifyRsaSha256 } from '@d13co/puya-ts-utils/rsa'
import { BaseContract } from '../base/base.algo'
import {
  errAdmin,
  errAlgorithm,
  errAnchor,
  errAnchorFlags,
  errAnchorSet,
  errDsDigest,
  errDsMatch,
  errEcKey,
  errExponent,
  errHint,
  errKeyFlags,
  errListed,
  errMissing,
  errModulus,
  errOld,
  errParent,
  errProtocol,
  errPrune,
  errRoot,
  errSigLength,
  errSignature,
  errSigner,
  errStale,
  errTld,
  errTldExists,
  errTooBig,
  errWorse,
} from './errors.algo'
import { ATTESTATION_HEADER } from './reader.algo'
import {
  checkName,
  isAncestor,
  keyTag,
  nameType,
  parseSignedData,
  SignedData,
  tldOf,
  TYPE_DNSKEY,
  TYPE_DS,
  TYPE_TXT,
  walkRRset,
} from './wire.algo'

const ALG_RSASHA256: uint64 = 8
const ALG_ECDSAP256SHA256: uint64 = 13
const FLAG_ZONE: uint64 = 0x0100
const FLAG_REVOKE: uint64 = 0x0080
/** Anchors are KSKs: Zone and Secure Entry Point, nothing else. */
const ANCHOR_FLAGS: uint64 = 257
const RSA_MIN_BITS: uint64 = 1024
const RSA_MAX_BITS: uint64 = 2048
/** P-256 counts as this many RSA bits in `weakestKeyBits`. Keep in sync with the SDK's ECDSA_P256_KEY_BITS. */
const ECDSA_P256_KEY_BITS: uint64 = 3072
/** How long past expiry an attestation is kept for anyone but its payer. */
const PRUNE_GRACE_SECONDS: uint64 = 30 * 24 * 60 * 60
/** Largest byte value the AVM holds, and so the largest attestation. */
const MAX_VALUE: uint64 = 4096

/** P-256 group order, and half of it for low-S normalization. */
const P256_N = BigUint(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n)
const P256_HALF_N = BigUint(0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n)

/** The root's owner name. */
const ROOT = Bytes.fromHex('00')

/** Cache entry for a proven RRset, keyed by `sha256(name ‖ type)`. Fixed size. */
export type CacheEntry = Readonly<{
  hash: bytes<32>
  inception: uint64
  /** min(this RRSIG's expiration, expiry of the entry it was verified against) */
  expiry: uint64
  weakestKeyBits: uint64
}>

/**
 * Proves that a TXT RRset exists at a DNS name by verifying the DNSSEC chain from the root
 * down, one signature per call. Root, DS and DNSKEY RRsets are cached as hashes and shared
 * by every name below them; TXT RRsets are stored as attestations.
 *
 * No update or delete: the code is fixed once created.
 */
export class DnssecOracle extends BaseContract {
  admin = GlobalState<Account>({ key: 'admin' })
  anchorCount = GlobalState<uint64>({ key: 'anchorCount' })

  /** `a ‖ sha256(alg ‖ pubkey)`: root trust anchors, empty value. */
  anchors = BoxMap<bytes<32>, bytes>({ keyPrefix: 'a' })
  /** `w ‖ TLD label`: whitelisted TLDs, empty value. */
  whitelist = BoxMap<bytes, bytes>({ keyPrefix: 'w' })
  /** `r ‖ sha256(name ‖ type)`: proven root DNSKEY, DS and DNSKEY RRsets. */
  caches = BoxMap<bytes<32>, CacheEntry>({ keyPrefix: 'r' })
  /** `t ‖ sha256(name)`: header, then `uint16 rdlen ‖ rdata` per TXT RR. See reader.algo.ts. */
  attestations = BoxMap<bytes<32>, bytes>({ keyPrefix: 't' })

  /**
   * Step one of two: the app account is not funded yet, so no boxes. The admin then funds
   * it, deposits credits and calls `addAnchor`, in one group.
   */
  @baremethod({ onCreate: 'require' })
  public createApplication(): void {
    this.admin.value = Txn.sender
    this.anchorCount.value = 0
    // consumers read attestation boxes directly
    op.AppParamsSet.appForeignBoxReads(true)
  }

  // ── Admin ───────────────────────────────────────────────────────

  private onlyAdmin(): void {
    loggedAssert(Txn.sender === this.admin.value, errAdmin)
  }

  /**
   * Upload the one root trust anchor, as DNSKEY RDATA. Once only: no method can add,
   * change or remove an anchor afterwards. Box rent comes from the admin's credits.
   */
  public addAnchor(dnskeyRdata: bytes): void {
    this.onlyAdmin()
    loggedAssert(this.anchorCount.value === 0, errAnchorSet)
    loggedAssert(op.extractUint16(dnskeyRdata, 0) === ANCHOR_FLAGS, errAnchorFlags)
    const algorithm = op.getByte(dnskeyRdata, 3)
    const [publicKey] = checkKey(dnskeyRdata, algorithm)
    const mbrBefore = Global.currentApplicationAddress.minBalance
    this.anchors(anchorKey(algorithm, publicKey)).value = Bytes()
    this.anchorCount.value = 1
    this.manageMbrCredits(mbrBefore)
  }

  /** Whitelist a TLD, e.g. `com`, lowercase. Box rent comes from the admin's credits. */
  public addTld(label: bytes): void {
    this.onlyAdmin()
    loggedAssert(label.length > 0 && label.length < 64, errTld)
    // owners are matched byte for byte: an uppercase label would whitelist nothing
    for (let i: uint64 = 0; i < label.length; i++) {
      const c = op.getByte(label, i)
      loggedAssert(c < 0x41 || c > 0x5a, errTld)
    }
    loggedAssert(!this.whitelist(label).exists, errTldExists)
    const mbrBefore = Global.currentApplicationAddress.minBalance
    this.whitelist(label).value = Bytes()
    this.manageMbrCredits(mbrBefore)
  }

  /**
   * Remove a TLD: blocks its proofs and lets its attestations be pruned. Refund to the
   * admin's credits, or to the app if they have no credit box, so de-listing never waits
   * on a deposit.
   */
  public removeTld(label: bytes): void {
    this.onlyAdmin()
    loggedAssert(this.whitelist(label).exists, errMissing)
    const mbrBefore = Global.currentApplicationAddress.minBalance
    this.whitelist(label).delete()
    if (this.userCredits(Txn.sender).exists) this.manageMbrCredits(mbrBefore)
  }

  /** Hand over the admin role. The zero address renounces it for good. */
  public setAdmin(newAdmin: Account): void {
    this.onlyAdmin()
    this.admin.value = newAdmin
  }

  // ── Proofs ──────────────────────────────────────────────────────

  /**
   * Prove the root DNSKEY RRset, signed by one of its own keys that is an anchor.
   * @param signedData RRSIG RDATA without the signature, then the RRset
   * @param signature RRSIG signature
   * @param hint Montgomery hint for RSA keys, empty for ECDSA
   * @param keyIndex Index of the signing key in the RRset
   */
  public proveRoot(signedData: bytes, signature: bytes, hint: bytes, keyIndex: uint64): void {
    const mbrBefore = Global.currentApplicationAddress.minBalance
    const s = parseSignedData(signedData, TYPE_DNSKEY, keyIndex, Global.latestTimestamp)
    loggedAssert(s.owner === ROOT && s.signer === ROOT, errSigner)
    const [publicKey, bits] = checkKey(s.indexed, s.algorithm)
    loggedAssert(this.anchors(anchorKey(s.algorithm, publicKey)).exists, errAnchor)
    verify(signedData, signature, hint, s.algorithm, publicKey)
    this.writeCache(s, TYPE_DNSKEY, s.expiration, bits)
    this.manageMbrCredits(mbrBefore)
  }

  /**
   * Prove a DS RRset, signed by a key in a proper ancestor's cached DNSKEY RRset.
   * @param keyIndex Index of the signing key in `parent`
   * @param parent The signer's DNSKEY RRset, as cached
   */
  public proveDs(signedData: bytes, signature: bytes, hint: bytes, keyIndex: uint64, parent: bytes): void {
    const mbrBefore = Global.currentApplicationAddress.minBalance
    const s = parseSignedData(signedData, TYPE_DS, 0, Global.latestTimestamp)
    loggedAssert(isAncestor(s.signer, s.owner, true), errSigner)
    this.checkListed(s.owner)
    const cached = this.parentEntry(s.signer, TYPE_DNSKEY, parent)
    const [, , key] = walkRRset(parent, 0, TYPE_DNSKEY, keyIndex, false)
    const [publicKey, bits] = checkKey(key, s.algorithm)
    verify(signedData, signature, hint, s.algorithm, publicKey)
    this.writeCache(s, TYPE_DS, min(s.expiration, cached.expiry), min(bits, cached.weakestKeyBits))
    this.manageMbrCredits(mbrBefore)
  }

  /**
   * Prove a zone's DNSKEY RRset, signed by one of its own keys that matches its cached DS.
   * @param keyIndex Index of the signing key in `signedData`'s RRset
   * @param dsIndex Index of the matching DS in `parent`
   * @param parent The zone's DS RRset, as cached
   */
  public proveDnskey(
    signedData: bytes,
    signature: bytes,
    hint: bytes,
    keyIndex: uint64,
    dsIndex: uint64,
    parent: bytes,
  ): void {
    const mbrBefore = Global.currentApplicationAddress.minBalance
    const s = parseSignedData(signedData, TYPE_DNSKEY, keyIndex, Global.latestTimestamp)
    loggedAssert(s.signer === s.owner, errSigner)
    this.checkListed(s.owner)
    const cached = this.parentEntry(s.owner, TYPE_DS, parent)
    const [, , ds] = walkRRset(parent, 0, TYPE_DS, dsIndex, false)
    checkDs(ds, s.owner, s.indexed)
    const [publicKey, bits] = checkKey(s.indexed, s.algorithm)
    verify(signedData, signature, hint, s.algorithm, publicKey)
    this.writeCache(s, TYPE_DNSKEY, min(s.expiration, cached.expiry), min(bits, cached.weakestKeyBits))
    this.manageMbrCredits(mbrBefore)
  }

  /**
   * Prove a TXT RRset, signed by a key in the cached DNSKEY RRset of its owner or an
   * ancestor, and store it as the owner's attestation. Replaces the whole stored RDATA set.
   * @param keyIndex Index of the signing key in `parent`
   * @param parent The signer's DNSKEY RRset, as cached
   */
  public proveTxt(signedData: bytes, signature: bytes, hint: bytes, keyIndex: uint64, parent: bytes): void {
    const s = parseSignedData(signedData, TYPE_TXT, 0, Global.latestTimestamp)
    loggedAssert(isAncestor(s.signer, s.owner, false), errSigner)
    this.checkListed(s.owner)
    const cached = this.parentEntry(s.signer, TYPE_DNSKEY, parent)
    const [, , key] = walkRRset(parent, 0, TYPE_DNSKEY, keyIndex, false)
    const [publicKey, bits] = checkKey(key, s.algorithm)
    verify(signedData, signature, hint, s.algorithm, publicKey)

    loggedAssert(ATTESTATION_HEADER + s.records.length <= MAX_VALUE, errTooBig)
    const box = this.attestations(op.sha256(s.owner))
    if (box.exists) {
      loggedAssert(s.inception >= op.extractUint64(box.extract(0, 8), 0), errOld)
      this.deleteAttestation(s.owner)
    }
    const mbrBefore = Global.currentApplicationAddress.minBalance
    box.value = op
      .itob(s.inception)
      .concat(op.itob(min(s.expiration, cached.expiry)))
      .concat(op.itob(min(bits, cached.weakestKeyBits)))
      .concat(Txn.sender.bytes)
      .concat(s.records)
    this.manageMbrCredits(mbrBefore)
  }

  // ── Rent ────────────────────────────────────────────────────────

  /**
   * Delete an expired box. `rrtype` 16 names an attestation: its payer may prune it once
   * expired, anyone 30 days after, or anyone at all once its TLD is unlisted; the refund
   * goes to the payer. Any other type names a cache entry, which anyone may prune once
   * expired, for a refund to their own credits.
   */
  public prune(name: bytes, rrtype: uint64): void {
    checkName(name)
    const now = Global.latestTimestamp
    if (rrtype === TYPE_TXT) {
      const box = this.attestations(op.sha256(name))
      loggedAssert(box.exists, errMissing)
      const expiration = op.extractUint64(box.extract(8, 8), 0)
      const payer = Account(box.extract(24, 32))
      loggedAssert(
        (Txn.sender === payer && now > expiration) ||
          now > expiration + PRUNE_GRACE_SECONDS ||
          !this.whitelist(tldOf(name)).exists,
        errPrune,
      )
      this.deleteAttestation(name)
    } else {
      const box = this.caches(op.sha256(nameType(name, rrtype)))
      loggedAssert(box.exists, errMissing)
      loggedAssert(now > box.value.expiry, errPrune)
      const mbrBefore = Global.currentApplicationAddress.minBalance
      box.delete()
      this.manageMbrCredits(mbrBefore)
    }
  }

  // ── Reads ───────────────────────────────────────────────────────

  /** Log each name's attestation box, in input order; an empty line if there is none. */
  @readonly
  public logAttestations(names: bytes[]): void {
    for (const name of names) {
      const [value, exists] = this.attestations(op.sha256(name)).maybe()
      log(exists ? value : Bytes())
    }
  }

  // ── Internals ───────────────────────────────────────────────────

  /** The owner's TLD must be whitelisted; the root has none. */
  private checkListed(owner: bytes): void {
    loggedAssert(owner.length > 1, errRoot)
    loggedAssert(this.whitelist(tldOf(owner)).exists, errListed)
  }

  /** The cache entry `parent` must match: present, unexpired, same hash. */
  private parentEntry(name: bytes, rrtype: uint64, parent: bytes): CacheEntry {
    // not .maybe(): algorand-typescript-testing 1.2.0 misdecodes a struct read that way
    const box = this.caches(op.sha256(nameType(name, rrtype)))
    loggedAssert(box.exists, errParent)
    const entry = box.value
    loggedAssert(Global.latestTimestamp <= entry.expiry, errStale)
    loggedAssert(op.sha256(parent) === entry.hash, errParent)
    return entry
  }

  /**
   * Newest inception wins. A tie replaces only if expiry and key bits get no worse, so a
   * second signature at the same inception cannot shorten or weaken the entry, while a
   * re-proof after its parent was refreshed still extends it. Fixed size, so a replacement
   * moves no credit.
   */
  private writeCache(s: SignedData, rrtype: uint64, expiry: uint64, weakestKeyBits: uint64): void {
    const box = this.caches(op.sha256(nameType(s.owner, rrtype)))
    if (box.exists) {
      const old = box.value
      loggedAssert(s.inception >= old.inception, errOld)
      loggedAssert(
        s.inception > old.inception || (expiry >= old.expiry && weakestKeyBits >= old.weakestKeyBits),
        errWorse,
      )
    }
    box.value = { hash: op.sha256(s.rrset), inception: s.inception, expiry: expiry, weakestKeyBits: weakestKeyBits }
  }

  /**
   * Delete an attestation and refund its payer. A payer who withdrew has no credit box to
   * refund into, and settling would assert: the refund stays with the app instead.
   * ponytail: stranded dust, add a sweep if it ever adds up.
   */
  private deleteAttestation(name: bytes): void {
    const box = this.attestations(op.sha256(name))
    const payer = Account(box.extract(24, 32))
    const mbrBefore = Global.currentApplicationAddress.minBalance
    box.delete()
    if (this.userCredits(payer).exists) this.settleMbrCredits(payer, mbrBefore)
  }
}

function min(a: uint64, b: uint64): uint64 {
  return a < b ? a : b
}

/** Anchor box key: the public key field and algorithm only, so the REVOKE flag does not move it. */
function anchorKey(algorithm: uint64, publicKey: bytes): bytes<32> {
  return op.sha256(op.extract(op.itob(algorithm), 7, 1).concat(publicKey))
}

/**
 * Check a DNSKEY for signing `algorithm` signatures: `[public key, strength in bits]`.
 * Zone flag set, REVOKE clear, protocol 3, algorithm 8 or 13 and equal to the RRSIG's.
 * RSA: exponent exactly 65537 in the one-byte length form, 1024 to 2048-bit modulus
 * without a leading zero. ECDSA: a 64-byte P-256 point.
 */
function checkKey(rdata: bytes, algorithm: uint64): readonly [bytes, uint64] {
  const flags = op.extractUint16(rdata, 0)
  loggedAssert((flags & FLAG_ZONE) !== 0 && (flags & FLAG_REVOKE) === 0, errKeyFlags)
  loggedAssert(op.getByte(rdata, 2) === 3, errProtocol)
  loggedAssert(op.getByte(rdata, 3) === algorithm, errAlgorithm)
  const publicKey = op.extract(rdata, 4, rdata.length - 4)
  if (algorithm === ALG_ECDSAP256SHA256) {
    loggedAssert(publicKey.length === 64, errEcKey)
    return [publicKey, ECDSA_P256_KEY_BITS]
  }
  loggedAssert(algorithm === ALG_RSASHA256, errAlgorithm)
  loggedAssert(publicKey.length > 4 && op.extract(publicKey, 0, 4) === Bytes.fromHex('03010001'), errExponent)
  const first = op.getByte(publicKey, 4)
  const bits: uint64 = (publicKey.length - 5) * 8 + op.bitLength(first)
  loggedAssert(first !== 0 && bits >= RSA_MIN_BITS && bits <= RSA_MAX_BITS, errModulus)
  return [publicKey, bits]
}

/** Verify `signature` over `signedData` with a key `checkKey` accepted. */
function verify(signedData: bytes, signature: bytes, hint: bytes, algorithm: uint64, publicKey: bytes): void {
  const digest = op.sha256(signedData)
  if (algorithm === ALG_ECDSAP256SHA256) {
    loggedAssert(signature.length === 64, errSigLength)
    let s = BigUint(op.extract(signature, 32, 32))
    if (s > P256_HALF_N) s = P256_N - s
    const low = op.bzero(32).bitwiseOr(Bytes(s))
    const valid = op.ecdsaVerify(
      op.Ecdsa.Secp256r1,
      digest,
      op.extract(signature, 0, 32),
      low,
      op.extract(publicKey, 0, 32),
      op.extract(publicKey, 32, 32),
    )
    loggedAssert(valid, errSignature)
    return
  }
  const modulus = op.extract(publicKey, 4, publicKey.length - 4)
  loggedAssert(signature.length === modulus.length, errSigLength)
  loggedAssert(hint.length > 0, errHint)
  loggedAssert(verifyRsaSha256(digest, signature, modulus, op.extract(publicKey, 1, 3), hint), errSignature)
}

/** DS digest type 2 over `owner ‖ dnskey`, with matching key tag and algorithm. */
function checkDs(ds: bytes, owner: bytes, dnskey: bytes): void {
  loggedAssert(ds.length === 36 && op.getByte(ds, 3) === 2, errDsDigest)
  loggedAssert(
    op.extractUint16(ds, 0) === keyTag(dnskey) &&
      op.getByte(ds, 2) === op.getByte(dnskey, 3) &&
      op.extract(ds, 4, 32) === op.sha256(owner.concat(dnskey)),
    errDsMatch,
  )
}
