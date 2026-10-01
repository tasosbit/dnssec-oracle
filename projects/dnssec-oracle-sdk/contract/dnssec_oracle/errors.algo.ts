// Error codes. The trailing comment is the message: scripts/generate-errors.ts in the SDK parses it.

// Access and lifecycle
export const errAdmin = 'admin' // Sender is not the admin
export const errAnchorSet = 'anchorSet' // Anchors are already set, or one is listed twice
export const errAnchor = 'anchor' // Key is not an anchor, or not in a state this call accepts
export const errAnchorFlags = 'anchorFlags' // Anchor flags must be exactly 257

// Root rollover (RFC 5011)
export const errRoll = 'rollover' // No rollover event applies to this key now
export const errHoldDown = 'holdDown' // The 30-day hold-down has not passed
export const errRevoke = 'revoke' // Revoking key's flags must be exactly 385

// Wire format
export const errWire = 'wireFormat' // Malformed wire data: label, name length or cursor
export const errIndex = 'index' // RR index past the end of the RRset
export const errOwner = 'owner' // RRs in one RRset have different owners
export const errType = 'rrType' // RR type differs from the RRSIG type covered, or the method
export const errClass = 'class' // RR class is not IN
export const errLabels = 'labels' // RRSIG labels field differs from the owner's label count
export const errWildcard = 'wildcard' // Wildcard label in a name
export const errTxt = 'txt' // TXT RDATA character-strings do not sum to its length
export const errTooBig = 'tooBig' // Attestation would exceed 4096 bytes

// Chain rules
export const errSigner = 'signer' // Signer name has the wrong relation to the owner
export const errRoot = 'rootOwner' // Owner must not be the root here
export const errTime = 'sigTime' // RRSIG is not valid now
export const errParent = 'parent' // Parent RRset is not cached, or its hash differs
export const errStale = 'stale' // Parent cache entry has expired, or predates a revocation
export const errOld = 'old' // A newer inception is already stored
export const errWorse = 'worse' // Same inception as stored, but a shorter expiry or weaker key

// Keys and signatures
export const errKeyFlags = 'keyFlags' // DNSKEY zone flag clear or REVOKE set
export const errProtocol = 'protocol' // DNSKEY protocol is not 3
export const errAlgorithm = 'algorithm' // Algorithm unsupported or differs from the RRSIG
export const errExponent = 'exponent' // RSA exponent is not 65537
export const errModulus = 'modulus' // RSA modulus is not 1024 to 2048 bits or has a leading zero
export const errSigLength = 'sigLength' // Signature length is wrong for the key
export const errHint = 'rsaHint' // Montgomery hint required for RSA
export const errEcKey = 'ecKey' // ECDSA key is not 64 bytes
export const errSignature = 'signature' // Signature does not verify
export const errDsDigest = 'dsDigest' // DS digest type is not 2 or not 32 bytes
export const errDsMatch = 'dsMatch' // DS key tag, algorithm or digest does not match the DNSKEY

// Rent
export const errMissing = 'missing' // Box does not exist
export const errPrune = 'prune' // Not prunable yet
