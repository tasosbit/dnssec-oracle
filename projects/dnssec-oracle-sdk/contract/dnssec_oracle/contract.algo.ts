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
  errHoldDown,
  errKeyFlags,
  errMissing,
  errModulus,
  errOld,
  errParent,
  errProtocol,
  errPrune,
  errRevoke,
  errRoll,
  errRoot,
  errSigLength,
  errSignature,
  errSigner,
  errStale,
  errTooBig,
  errWorse,
} from './errors.algo'
import {
  ATTESTATION_HEADER,
  attestationExpiration,
  attestationHasRecord,
  attestationInception,
  attestationParentEpoch,
  attestationPayer,
  attestationUsable,
  readAttestation,
} from './reader.algo'
import {
  checkName,
  isAncestor,
  keyTag,
  nameType,
  parseSignedData,
  SignedData,
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
/** An anchor revoking itself: ANCHOR_FLAGS plus REVOKE. */
const REVOKED_FLAGS: uint64 = 385
/** RFC 5011 anchor states. A key with no box is in Start, or Removed. */
const ANCHOR_ADDPEND: uint64 = 1
const ANCHOR_VALID: uint64 = 2
const ANCHOR_MISSING: uint64 = 3
const ANCHOR_REVOKED: uint64 = 4
/** RFC 5011 add and remove hold-down. */
const HOLD_DOWN_SECONDS: uint64 = 30 * 24 * 60 * 60
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

/** Root trust anchor, keyed by `sha256(alg ‖ pubkey)`: RFC 5011 state and when it was entered. */
export type AnchorEntry = Readonly<{
  state: uint64
  since: uint64
}>

/** Cache entry for a proven RRset, keyed by `sha256(name ‖ type)`. Fixed size. */
export type CacheEntry = Readonly<{
  hash: bytes<32>
  inception: uint64
  /** min(this RRSIG's expiration, expiry of the entry it was verified against) */
  expiry: uint64
  weakestKeyBits: uint64
  /** This entry's generation: fresh whenever its hash or its parent's epoch changes. */
  epoch: uint64
  /** The epoch of the entry it was verified against, or `rootEpoch` for the root DNSKEY RRset. */
  parentEpoch: uint64
}>

/**
 * Proves that a TXT RRset exists at a DNS name by verifying the DNSSEC chain from the root
 * down, one signature per call. Root, DS and DNSKEY RRsets are cached as hashes and shared
 * by every name below them; TXT RRsets are stored as attestations. Root anchors roll over
 * by RFC 5011: `updateAnchor` and `revokeRoot`.
 *
 * No update or delete: the code is fixed once created.
 */
export class DnssecOracle extends BaseContract {
  admin = GlobalState<Account>({ key: 'admin' })
  /** Initial anchors uploaded: 0 until `addAnchors`, which runs once. */
  anchorCount = GlobalState<uint64>({ key: 'anchorCount' })
  /** Inception of the newest root DNSKEY RRset a rollover step used: no step may use an older one. */
  rollInception = GlobalState<uint64>({ key: 'rollInception' })
  /** The last epoch handed out. Each value names one box generation; 0 is never an epoch. */
  lastEpoch = GlobalState<uint64>({ key: 'lastEpoch' })
  /**
   * The anchor set's epoch: fresh at each revocation of a trusted key, which stales the root
   * DNSKEY entry and so everything that chains from it. Epochs only grow, so a box whose epoch
   * is below it predates the last revocation.
   */
  rootEpoch = GlobalState<uint64>({ key: 'rootEpoch' })

  /** `a ‖ sha256(alg ‖ pubkey)`: root trust anchors and rollover candidates. */
  anchors = BoxMap<bytes<32>, AnchorEntry>({ keyPrefix: 'a' })
  /** `r ‖ sha256(name ‖ type)`: proven root DNSKEY, DS and DNSKEY RRsets. */
  caches = BoxMap<bytes<32>, CacheEntry>({ keyPrefix: 'r' })
  /** `t ‖ sha256(name)`: header, then `uint16 rdlen ‖ rdata` per TXT RR. See reader.algo.ts. */
  attestations = BoxMap<bytes<32>, bytes>({ keyPrefix: 't' })

  /**
   * Step one of two: the app account is not funded yet, so no boxes. The admin then funds
   * it, deposits credits and calls `addAnchors`, in one group.
   */
  @baremethod({ onCreate: 'require' })
  public createApplication(): void {
    this.admin.value = Txn.sender
    this.anchorCount.value = 0
    this.rollInception.value = 0
    this.lastEpoch.value = 1
    this.rootEpoch.value = 1
    // consumers read attestation boxes directly
    op.AppParamsSet.appForeignBoxReads(true)
  }

  // ── Admin ───────────────────────────────────────────────────────

  private onlyAdmin(): void {
    loggedAssert(Txn.sender === this.admin.value, errAdmin)
  }

  /**
   * Upload the initial root trust anchors, as DNSKEY RDATA, all Valid. Once only: after
   * this the anchor set changes only by RFC 5011 rollover. Box rent comes from the admin's
   * credits.
   */
  public addAnchors(dnskeys: bytes[]): void {
    this.onlyAdmin()
    // once only: afterwards the admin has no say over anchors
    loggedAssert(this.anchorCount.value === 0, errAnchorSet)
    const mbrBefore = Global.currentApplicationAddress.minBalance
    for (const rdata of dnskeys) {
      // KSKs only: Zone and SEP set, REVOKE clear
      loggedAssert(op.extractUint16(rdata, 0) === ANCHOR_FLAGS, errAnchorFlags)
      // the checks a signing key gets, so every anchor can actually prove the root
      const algorithm = op.getByte(rdata, 3)
      const [publicKey] = checkKey(rdata, algorithm)
      const box = this.anchors(anchorKey(algorithm, publicKey))
      // a duplicate would be counted twice in anchorCount
      loggedAssert(!box.exists, errAnchorSet)
      box.value = { state: ANCHOR_VALID, since: Global.latestTimestamp }
    }
    this.anchorCount.value = dnskeys.length
    // the admin pays for the anchor boxes
    this.manageMbrCredits(mbrBefore)
  }

  /** Hand over the admin role. The zero address renounces it for good. */
  public setAdmin(newAdmin: Account): void {
    this.onlyAdmin()
    this.admin.value = newAdmin
  }

  // ── Proofs ──────────────────────────────────────────────────────

  /**
   * Prove the root DNSKEY RRset, signed by one of its own keys that is a Valid or Missing anchor.
   * @param signedData RRSIG RDATA without the signature, then the RRset
   * @param signature RRSIG signature
   * @param hint Montgomery hint for RSA keys, empty for ECDSA
   * @param keyIndex Index of the signing key in the RRset
   */
  public proveRoot(signedData: bytes, signature: bytes, hint: bytes, keyIndex: uint64): void {
    const mbrBefore = Global.currentApplicationAddress.minBalance
    // the signing key sits in the RRset it signs, at keyIndex
    const s = parseSignedData(signedData, TYPE_DNSKEY, keyIndex, Global.latestTimestamp)
    loggedAssert(s.owner === ROOT && s.signer === ROOT, errSigner)
    const [publicKey, bits] = checkKey(s.indexed, s.algorithm)
    // AddPend keys are not trusted yet and Revoked ones never again; Missing still are
    const anchor = this.anchors(anchorKey(s.algorithm, publicKey))
    loggedAssert(
      anchor.exists && (anchor.value.state === ANCHOR_VALID || anchor.value.state === ANCHOR_MISSING),
      errAnchor,
    )
    verify(signedData, signature, hint, s.algorithm, publicKey)
    // the top of the chain: expiry and strength are this signature's own
    this.writeCache(s, TYPE_DNSKEY, s.expiration, bits, this.rootEpoch.value)
    // the first prover pays for the cache box; a replacement is the same size
    this.manageMbrCredits(mbrBefore)
  }

  /**
   * Prove a DS RRset, signed by a key in a proper ancestor's cached DNSKEY RRset.
   * @param keyIndex Index of the signing key in `parent`
   * @param parent The signer's DNSKEY RRset, as cached
   */
  public proveDs(signedData: bytes, signature: bytes, hint: bytes, keyIndex: uint64, parent: bytes): void {
    const mbrBefore = Global.currentApplicationAddress.minBalance
    // the signing key is not in a DS RRset: index 0 only has to exist
    const s = parseSignedData(signedData, TYPE_DS, 0, Global.latestTimestamp)
    // a DS lives in the parent zone: signed by a proper ancestor, never the zone itself
    loggedAssert(isAncestor(s.signer, s.owner, true), errSigner)
    loggedAssert(s.owner.length > 1, errRoot)
    // the signer's DNSKEY RRset, handed back in and matched against its cached hash
    const cached = this.parentEntry(s.signer, TYPE_DNSKEY, parent)
    const [, , key] = walkRRset(parent, 0, TYPE_DNSKEY, keyIndex, false)
    const [publicKey, bits] = checkKey(key, s.algorithm)
    verify(signedData, signature, hint, s.algorithm, publicKey)
    // an entry never outlives or outranks the chain above it
    this.writeCache(s, TYPE_DS, min(s.expiration, cached.expiry), min(bits, cached.weakestKeyBits), cached.epoch)
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
    // self-signed: the signing key sits in the RRset it signs, at keyIndex
    const s = parseSignedData(signedData, TYPE_DNSKEY, keyIndex, Global.latestTimestamp)
    loggedAssert(s.signer === s.owner, errSigner)
    // the root's DNSKEY RRset goes through proveRoot
    loggedAssert(s.owner.length > 1, errRoot)
    // the link to the parent zone: a DS in the zone's cached DS RRset digests the signing key
    const cached = this.parentEntry(s.owner, TYPE_DS, parent)
    const [, , ds] = walkRRset(parent, 0, TYPE_DS, dsIndex, false)
    checkDs(ds, s.owner, s.indexed)
    const [publicKey, bits] = checkKey(s.indexed, s.algorithm)
    verify(signedData, signature, hint, s.algorithm, publicKey)
    this.writeCache(s, TYPE_DNSKEY, min(s.expiration, cached.expiry), min(bits, cached.weakestKeyBits), cached.epoch)
    this.manageMbrCredits(mbrBefore)
  }

  /**
   * Prove a TXT RRset, signed by a key in the cached DNSKEY RRset of its owner or an
   * ancestor, and store it as the owner's attestation. Replaces the whole stored RDATA set.
   * @param keyIndex Index of the signing key in `parent`
   * @param parent The signer's DNSKEY RRset, as cached
   */
  public proveTxt(signedData: bytes, signature: bytes, hint: bytes, keyIndex: uint64, parent: bytes): void {
    // parsing also checks each TXT RDATA and collects the records to store
    const s = parseSignedData(signedData, TYPE_TXT, 0, Global.latestTimestamp)
    // the owner's zone or any zone above it (plan trust point 2)
    loggedAssert(isAncestor(s.signer, s.owner, false), errSigner)
    loggedAssert(s.owner.length > 1, errRoot)
    const cached = this.parentEntry(s.signer, TYPE_DNSKEY, parent)
    const [, , key] = walkRRset(parent, 0, TYPE_DNSKEY, keyIndex, false)
    const [publicKey, bits] = checkKey(key, s.algorithm)
    verify(signedData, signature, hint, s.algorithm, publicKey)

    loggedAssert(ATTESTATION_HEADER + s.records.length <= MAX_VALUE, errTooBig)
    // newest inception wins, ties replace; the old box's rent goes back to its payer
    const box = this.attestations(op.sha256(s.owner))
    if (box.exists) {
      // one from before the last revocation is replaced whatever its inception: a forged one
      // may be the newer. Otherwise no rollback, even across a change above.
      const old = box.value
      if (attestationParentEpoch(old) >= this.rootEpoch.value) {
        loggedAssert(s.inception >= attestationInception(old), errOld)
      }
      this.deleteAttestation(s.owner)
    }
    // header (see reader.algo.ts), then the records; the sender pays and becomes the payer
    const mbrBefore = Global.currentApplicationAddress.minBalance
    box.value = op
      .itob(s.inception)
      .concat(op.itob(min(s.expiration, cached.expiry)))
      .concat(op.itob(min(bits, cached.weakestKeyBits)))
      .concat(op.itob(cached.epoch))
      .concat(Txn.sender.bytes)
      .concat(s.records)
    this.manageMbrCredits(mbrBefore)
  }

  // ── Root rollover (RFC 5011) ────────────────────────────────────

  /**
   * Apply the one RFC 5011 event that the cached root DNSKEY RRset implies for one key.
   * The key is present if the RRset holds it without REVOKE:
   *
   * | State   | Present | Event   | Becomes                                   |
   * |---------|---------|---------|-------------------------------------------|
   * | none    | yes     | Add     | AddPend; flags 257 and a usable key only  |
   * | AddPend | yes     | Promote | Valid, 30 days after Add                  |
   * | AddPend | no      | Reset   | box deleted                               |
   * | Valid   | no      | Miss    | Missing, still trusted                    |
   * | Missing | yes     | Return  | Valid                                     |
   * | Revoked | either  | Retire  | box deleted, 30 days after Revoke         |
   *
   * Anything else fails with `rollover`. A new box is paid from the sender's credits, a deleted
   * one refunded to them.
   * @param rrset The root DNSKEY RRset, as cached
   * @param keyHash `sha256(alg ‖ pubkey)` of the key: its anchor box key
   */
  public updateAnchor(rrset: bytes, keyHash: bytes<32>): void {
    const mbrBefore = Global.currentApplicationAddress.minBalance
    // no signature here: the cached root RRset was verified under a trusted anchor when proven
    // parentEntry refuses a root entry from before the last revocation: its key may have forged it
    const cached = this.parentEntry(ROOT, TYPE_DNSKEY, rrset)
    // an older RRset, still valid and proven again after a prune, must not undo a step
    loggedAssert(cached.inception >= this.rollInception.value, errOld)
    this.rollInception.value = cached.inception
    // by hash, not index, so a key that has left the RRset can be named too
    const [key, found] = findKey(rrset, keyHash)
    // a key listed with REVOKE counts as absent: revoking takes revokeRoot's self-signature
    const present = found && (op.extractUint16(key, 0) & FLAG_REVOKE) === 0
    const now = Global.latestTimestamp
    const box = this.anchors(keyHash)
    if (!box.exists) {
      // Add: a usable KSK starts its hold-down
      loggedAssert(present && op.extractUint16(key, 0) === ANCHOR_FLAGS, errRoll)
      checkKey(key, op.getByte(key, 3))
      box.value = { state: ANCHOR_ADDPEND, since: now }
    } else {
      const anchor = box.value
      if (anchor.state === ANCHOR_REVOKED) {
        // Retire, whether the RRset still lists the key or not
        loggedAssert(now >= anchor.since + HOLD_DOWN_SECONDS, errHoldDown)
        box.delete()
      } else if (anchor.state === ANCHOR_ADDPEND && !present) {
        // Reset: gone before its hold-down ended; a return starts it over
        box.delete()
      } else if (anchor.state === ANCHOR_ADDPEND) {
        // Promote
        loggedAssert(now >= anchor.since + HOLD_DOWN_SECONDS, errHoldDown)
        box.value = { state: ANCHOR_VALID, since: now }
      } else {
        // Miss (Valid and absent) or Return (Missing and present)
        loggedAssert(present === (anchor.state === ANCHOR_MISSING), errRoll)
        box.value = { state: present ? ANCHOR_VALID : ANCHOR_MISSING, since: now }
      }
    }
    // charges the sender for an Add, refunds them for a Reset or Retire
    this.manageMbrCredits(mbrBefore)
  }

  /**
   * RFC 5011 revocation: the root DNSKEY RRset, signed by an anchor key in any state but
   * Revoked, which the RRset holds with flags 385. Only the key itself can revoke itself,
   * and for good: it can no longer prove the root, and `updateAnchor` retires it 30 days
   * later. Revoking a Valid or Missing key gives `rootEpoch` a fresh epoch, which stales the
   * root entry and everything below it; an AddPend key never proved anything, so its
   * revocation does not. No inception rule: a replayed revocation changes nothing.
   * @param keyIndex Index of the revoked, signing key in the RRset
   */
  public revokeRoot(signedData: bytes, signature: bytes, hint: bytes, keyIndex: uint64): void {
    // the revoking key signs the RRset that lists it, at keyIndex
    const s = parseSignedData(signedData, TYPE_DNSKEY, keyIndex, Global.latestTimestamp)
    loggedAssert(s.owner === ROOT && s.signer === ROOT, errSigner)
    loggedAssert(op.extractUint16(s.indexed, 0) === REVOKED_FLAGS, errRevoke)
    // checkKey rejects REVOKE: check the key as it was before
    const [publicKey] = checkKey(op.replace(s.indexed, 0, Bytes.fromHex('0101')), s.algorithm)
    // the box is keyed without flags, so the revoked form finds the anchor; AddPend counts
    const box = this.anchors(anchorKey(s.algorithm, publicKey))
    loggedAssert(box.exists && box.value.state !== ANCHOR_REVOKED, errAnchor)
    verify(signedData, signature, hint, s.algorithm, publicKey)
    const trusted = box.value.state !== ANCHOR_ADDPEND
    // `since` starts the 30 days to Retire; same box size, so no rent moves
    box.value = { state: ANCHOR_REVOKED, since: Global.latestTimestamp }
    // a trusted key may have signed a forged root RRset: stale everything that could chain from it
    if (trusted) this.rootEpoch.value = this.nextEpoch()
  }

  // ── Rent ────────────────────────────────────────────────────────

  /**
   * Delete an expired box, or one from before the last revocation. `rrtype` 16 names an
   * attestation: its payer may prune it once expired, anyone 30 days after or once it predates
   * the revocation; the refund goes to the payer. Any other type names a cache entry, which
   * anyone may prune once expired or predating it, for a refund to their own credits. Staleness
   * from a routine change above is not prunable early: a newer proof replaces the box.
   */
  public prune(name: bytes, rrtype: uint64): void {
    // box keys are only ever derived from valid names
    checkName(name)
    const now = Global.latestTimestamp
    if (rrtype === TYPE_TXT) {
      const box = this.attestations(op.sha256(name))
      loggedAssert(box.exists, errMissing)
      const value = box.value
      const expiration = attestationExpiration(value)
      loggedAssert(
        (Txn.sender === attestationPayer(value) && now > expiration) ||
          now > expiration + PRUNE_GRACE_SECONDS ||
          attestationParentEpoch(value) < this.rootEpoch.value,
        errPrune,
      )
      // the refund goes to the payer, not the pruner
      this.deleteAttestation(name)
    } else {
      // a cache entry: anyone, once expired, refunded to the pruner
      const box = this.caches(op.sha256(nameType(name, rrtype)))
      loggedAssert(box.exists, errMissing)
      const entry = box.value
      loggedAssert(now > entry.expiry || entry.epoch < this.rootEpoch.value, errPrune)
      const mbrBefore = Global.currentApplicationAddress.minBalance
      box.delete()
      this.manageMbrCredits(mbrBefore)
    }
  }

  // ── Reads ───────────────────────────────────────────────────────

  /**
   * Log each name's attestation box, in input order; an empty line if there is none. Stale
   * ones included: whether the chain above is current takes a walk (reader.algo.ts). For
   * simulate with more logging allowed: an app call logs at most 1024 bytes on-chain.
   */
  @readonly
  public logAttestations(names: bytes[]): void {
    for (const name of names) {
      const [value, exists] = this.attestations(op.sha256(name)).maybe()
      log(exists ? value : Bytes())
    }
  }

  /**
   * Whether `name` has a usable attestation (attestationUsable in reader.algo.ts) holding a
   * TXT record with exactly this `rdata`. For contracts calling in: box references as for a
   * direct read (the attestation, each zone's DNSKEY and DS, the root DNSKEY). A boolean, not
   * the box: an app call logs at most 1024 bytes, and attestations run to 4096.
   */
  @readonly
  public hasRecord(name: bytes, rdata: bytes, maxAge: uint64, minKeyBits: uint64, zones: bytes[]): boolean {
    const self = Global.currentApplicationId
    const [value, exists] = readAttestation(self, name)
    return exists && attestationUsable(self, value, maxAge, minKeyBits, zones) && attestationHasRecord(value, rdata)
  }

  /**
   * Log each cache entry, in input order, as its raw box value; an empty line if there is
   * none. `keys` are `name ‖ uint16 type`. Expired and stale ones included.
   */
  @readonly
  public logCaches(keys: bytes[]): void {
    for (const key of keys) {
      // raw, not box.value: algorand-typescript-testing 1.2.0 misdecodes a struct .maybe()
      const [value, exists] = op.Box.get(this.caches.keyPrefix.concat(op.sha256(key)))
      log(exists ? value : Bytes())
    }
  }

  // ── Internals ───────────────────────────────────────────────────

  /**
   * The cache entry `parent` must match: present, unexpired, not from before the last
   * revocation, same hash. Staleness from a routine change further up is not checked: a proof
   * under such a parent is stale too, and consumers walk the chain.
   */
  private parentEntry(name: bytes, rrtype: uint64, parent: bytes): CacheEntry {
    // not .maybe(): algorand-typescript-testing 1.2.0 misdecodes a struct read that way
    const box = this.caches(op.sha256(nameType(name, rrtype)))
    loggedAssert(box.exists, errParent)
    const entry = box.value
    loggedAssert(Global.latestTimestamp <= entry.expiry && entry.epoch >= this.rootEpoch.value, errStale)
    loggedAssert(op.sha256(parent) === entry.hash, errParent)
    return entry
  }

  /**
   * Newest inception wins. A tie replaces only if expiry and key bits get no worse, so a
   * second signature at the same inception cannot shorten or weaken the entry, while a
   * re-proof after its parent was refreshed still extends it. Across a change of parent
   * generation only the inception rule holds, so a tie can re-link. An entry from before the
   * last revocation is replaced whatever its inception: a forged one may be newer than any
   * real RRSIG. The epoch stays only if hash and parent epoch do, so any change here stales
   * everything below. Fixed size, so a replacement moves no credit.
   */
  private writeCache(s: SignedData, rrtype: uint64, expiry: uint64, weakestKeyBits: uint64, parentEpoch: uint64): void {
    const box = this.caches(op.sha256(nameType(s.owner, rrtype)))
    const hash = op.sha256(s.rrset)
    let epoch: uint64 = 0
    if (box.exists && box.value.epoch >= this.rootEpoch.value) {
      const old = box.value
      // no rollback to a withdrawn RRset, even after a change above
      loggedAssert(s.inception >= old.inception, errOld)
      if (old.parentEpoch === parentEpoch) {
        if (old.hash === hash) epoch = old.epoch
        loggedAssert(
          s.inception > old.inception || (expiry >= old.expiry && weakestKeyBits >= old.weakestKeyBits),
          errWorse,
        )
      }
    }
    if (epoch === 0) epoch = this.nextEpoch()
    box.value = { hash, inception: s.inception, expiry, weakestKeyBits, epoch, parentEpoch }
  }

  private nextEpoch(): uint64 {
    this.lastEpoch.value += 1
    return this.lastEpoch.value
  }

  /**
   * Delete an attestation and refund its payer. A payer who withdrew has no credit box to
   * refund into, and settling would assert: the refund stays with the app instead.
   * ponytail: stranded dust, add a sweep if it ever adds up.
   */
  private deleteAttestation(name: bytes): void {
    const box = this.attestations(op.sha256(name))
    const payer = attestationPayer(box.value)
    const mbrBefore = Global.currentApplicationAddress.minBalance
    box.delete()
    if (this.userCredits(payer).exists) this.settleMbrCredits(payer, mbrBefore)
  }
}

function min(a: uint64, b: uint64): uint64 {
  return a < b ? a : b
}

/**
 * The DNSKEY in a cached root DNSKEY RRset whose anchor box key is `keyHash`: `[rdata,
 * found]`. The RRset was parsed when it was proven, so each RR is the one-byte root name,
 * 10 fixed bytes, then the RDATA.
 */
function findKey(rrset: bytes, keyHash: bytes<32>): readonly [bytes, boolean] {
  let at: uint64 = 0
  while (at < rrset.length) {
    // owner (1), type (2), class (2), TTL (4), then RDLENGTH
    const rdlength = op.extractUint16(rrset, at + 9)
    const rdata = op.extract(rrset, at + 11, rdlength)
    // DNSKEY RDATA: flags (2), protocol (1), algorithm (1), public key
    if (anchorKey(op.getByte(rdata, 3), op.extract(rdata, 4, rdlength - 4)) === keyHash) return [rdata, true]
    at += 11 + rdlength
  }
  return [Bytes(), false]
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
  // RFC 3110 public key: exponent length (1 byte), exponent, modulus. Only `03 010001` passes.
  loggedAssert(publicKey.length > 4 && op.extract(publicKey, 0, 4) === Bytes.fromHex('03010001'), errExponent)
  // real modulus size: the first byte's significant bits, plus 8 per byte after it
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
    // signature is r ‖ s. The AVM rejects high-S; DNSSEC signers may produce either, and
    // n − s is an equally valid signature. s > n underflows and fails the program.
    let s = BigUint(op.extract(signature, 32, 32))
    if (s > P256_HALF_N) s = P256_N - s
    // Bytes(s) drops leading zeros: left-pad back to 32 bytes
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
  // after the `03 010001` prefix checkKey enforced
  const modulus = op.extract(publicKey, 4, publicKey.length - 4)
  loggedAssert(signature.length === modulus.length, errSigLength)
  // the hint makes the modular exponentiation affordable; a wrong one can only fail
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
