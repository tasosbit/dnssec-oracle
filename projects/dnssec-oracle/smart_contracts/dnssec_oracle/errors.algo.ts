// Error codes. The trailing comment is the message: scripts/generate-errors.ts in the SDK parses it.

// Access and lifecycle
export const errAdmin = 'ADM' // Sender is not the admin
export const errAnchorSet = 'AST' // An anchor is already set
export const errAnchor = 'ANC' // Signing key is not an anchor
export const errAnchorFlags = 'AFL' // Anchor flags must be exactly 257

// Wire format
export const errWire = 'WIR' // Malformed wire data: label, name length or cursor
export const errIndex = 'IDX' // RR index past the end of the RRset
export const errOwner = 'OWN' // RRs in one RRset have different owners
export const errType = 'TYP' // RR type differs from the RRSIG type covered, or the method
export const errClass = 'CLS' // RR class is not IN
export const errLabels = 'LBL' // RRSIG labels field differs from the owner's label count
export const errWildcard = 'WLD' // Wildcard label in a name
export const errTxt = 'TXT' // TXT RDATA character-strings do not sum to its length
export const errTooBig = 'BIG' // Attestation would exceed 4096 bytes

// Chain rules
export const errSigner = 'SGN' // Signer name has the wrong relation to the owner
export const errRoot = 'ROT' // Owner must not be the root here
export const errTime = 'TIM' // RRSIG is not valid now
export const errListed = 'WLS' // TLD is not whitelisted
export const errParent = 'PAR' // Parent RRset is not cached, or its hash differs
export const errStale = 'STL' // Parent cache entry has expired
export const errOld = 'OLD' // A newer inception is already stored
export const errWorse = 'WRS' // Same inception as stored, but a shorter expiry or weaker key

// Keys and signatures
export const errKeyFlags = 'KFL' // DNSKEY zone flag clear or REVOKE set
export const errProtocol = 'PRO' // DNSKEY protocol is not 3
export const errAlgorithm = 'ALG' // Algorithm unsupported or differs from the RRSIG
export const errExponent = 'EXP' // RSA exponent is not 65537
export const errModulus = 'MOD' // RSA modulus is not 1024 to 2048 bits or has a leading zero
export const errSigLength = 'SLN' // Signature length is wrong for the key
export const errHint = 'HNT' // Montgomery hint required for RSA
export const errEcKey = 'ECK' // ECDSA key is not 64 bytes
export const errSignature = 'SIG' // Signature does not verify
export const errDsDigest = 'DSD' // DS digest type is not 2 or not 32 bytes
export const errDsMatch = 'DSM' // DS key tag, algorithm or digest does not match the DNSKEY

// Admin and rent
export const errTld = 'TLD' // TLD label must be 1 to 63 bytes, lowercase
export const errTldExists = 'TLX' // TLD already whitelisted
export const errMissing = 'MIS' // Box does not exist
export const errPrune = 'PRN' // Not prunable yet
