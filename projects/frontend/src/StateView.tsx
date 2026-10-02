import { AnchorEntry, anchorHash, AnchorState, keyTag, toHex } from '@d13co/dnssec-oracle-sdk'
import { useQuery } from '@tanstack/react-query'
import { ALGORAND_ZERO_ADDRESS_STRING } from 'algosdk'
import { useState } from 'react'
import { IANA_ANCHORS, isoTime, isRevoked, keyRole, keySize, rootDsDigest } from './oracle'
import { anchorProofQuery, namesQuery, Oracle, rootKeysQuery, stateQuery } from './queries'
import { Badge, Clamp, Hash, Load, Section, Time } from './ui'

const ANCHOR_STATES: Record<AnchorState, string> = {
  [AnchorState.AddPend]: 'seen in the root key set; trusted once its 30-day hold-down ends',
  [AnchorState.Valid]: 'trusted to sign the root key set',
  [AnchorState.Missing]: 'gone from the root key set, but still trusted',
  [AnchorState.Revoked]: 'revoked by its own signature; never trusted again, deleted after 30 days',
}

/** Zone order: `.` first, then each zone (its DS, then DNSKEY) followed by the names below it. */
const zoneOrder = (label: string) => {
  const [name, type] = label.split(' ')
  return `${name.split('.').reverse().join('.')} ${type === 'DS' ? 0 : 1}`
}

export function StateView({ oracle, onVerify }: { oracle: Oracle; onVerify: (name: string) => void }) {
  const core = useQuery(stateQuery(oracle))
  const boxes = core.data ? [...core.data[2].keys(), ...core.data[3].keys()] : []
  // labels are best-effort: without them, boxes show as hashes
  const names = useQuery({ ...namesQuery(oracle, boxes), enabled: !!core.data })
  const anchorNames = useQuery(rootKeysQuery())
  const label = (hash: string) => names.data?.get(hash)
  const now = Date.now() / 1000

  return (
    <Load query={core}>
      {([state, anchors, caches, attestations, credits]) => (
        <>
          <Section
            title="Global state"
            about="The contract's few global values. Everything else lives in boxes, below."
          >
            <dl className="fields">
              <dt>admin</dt>
              <dd>
                <code>{state.admin}</code>
                {state.admin === ALGORAND_ZERO_ADDRESS_STRING && <Badge ok>renounced</Badge>}
                <p>
                  May upload the initial anchors (once) and hand the role on. It has no say over anchors after that,
                  and the contract has no update method. The zero address means the role was renounced.
                </p>
              </dd>
              <dt>anchorCount</dt>
              <dd>
                <code>{String(state.anchorCount)}</code>
                <p>How many initial root anchors the admin uploaded. Zero until setup; the upload runs only once.</p>
              </dd>
              <dt>rollInception</dt>
              <dd>
                {state.rollInception ? <Time t={Number(state.rollInception)} /> : <code>none</code>}
                <p>
                  The signing time of the newest root key set an RFC 5011 rollover step has used. A rollover step
                  needs a key set at least this new, so an older one, still valid, cannot undo it.
                </p>
              </dd>
              <dt>rootEpoch</dt>
              <dd>
                <code>{String(state.rootEpoch)}</code>
                <p>
                  The generation of the anchor set. Revoking a trusted root key mints a new one, which makes every
                  cached entry and attestation proven before it unusable at once.
                </p>
              </dd>
            </dl>
          </Section>

          <Section
            title={`Root trust anchors (${anchors.size})`}
            about={
              <>
                The root keys (KSKs) the oracle trusts to sign the root zone's key set: the start of every chain.
                Each is keyed by <code>sha256(algorithm ‖ public key)</code>. Anyone may apply rollover events under
                RFC 5011, from the root key set as DNS serves it; check these against{' '}
                <a href="https://data.iana.org/root-anchors/root-anchors.xml">IANA's trust anchors</a>.
              </>
            }
          >
            <table>
              <thead>
                <tr>
                  <th>Key</th>
                  <th>State</th>
                  <th>Since</th>
                </tr>
              </thead>
              <tbody>
                {[...anchors].map(([id, a]) => (
                  <AnchorRow key={id} id={id} anchor={a} label={anchorNames.data?.get(id)} />
                ))}
              </tbody>
            </table>
          </Section>

          <Section
            title={`Attestations (${attestations.size})`}
            about={
              <>
                Proven TXT record sets: the oracle's output, which other apps read. An attestation says the record set
                was validly signed at its signing time, not that it still exists: consumers choose how old is too old
                (<code>maxAge</code>) and how weak a key is too weak (<code>minKeyBits</code>), and check that no key
                above it has changed since. Verify one to run those checks and compare it with live DNS.
              </>
            }
          >
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Records</th>
                  <th>Signed</th>
                  <th>Expires</th>
                  <th title="The weakest key on its chain; P-256 counts as 3072">Weakest key</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {[...attestations]
                  .sort(([a], [b]) => zoneOrder(label(a) ?? '~').localeCompare(zoneOrder(label(b) ?? '~')))
                  .map(([hash, a]) => {
                    const name = label(hash)
                    return (
                      <tr key={hash}>
                        <td>{name ? <strong>{name}</strong> : <Hash hex={hash} />}</td>
                        <td>
                          <Clamp>
                            <ul className="records">
                              {a.texts.map((t, i) => (
                                <li key={i}>
                                  <code>{t}</code>
                                </li>
                              ))}
                            </ul>
                          </Clamp>
                        </td>
                        <td>
                          <Time t={a.inception} />
                        </td>
                        <td>
                          <Time t={a.expiration} /> {a.expiration < now && <Badge ok={false}>expired</Badge>}
                        </td>
                        <td>{a.weakestKeyBits} bits</td>
                        <td>{name && <button onClick={() => onVerify(name)}>Verify</button>}</td>
                      </tr>
                    )
                  })}
              </tbody>
            </table>
          </Section>

          <Section
            title={`Cached key sets (${caches.size})`}
            about={
              <>
                Every link proven above the attestations: the root's keys, each zone's DS (the parent vouching for
                the zone's key) and DNSKEY (the zone's keys). The oracle stores only <code>sha256</code> of each
                record set, so a later proof hands the records back and the hash checks them. Shared: a TLD's keys
                are proven once per signing period and reused by every name below it. Each entry has an{' '}
                <em>epoch</em> and records its parent's: when a key set changes, everything proven under the old one
                stops matching and is stale.
              </>
            }
          >
            <table>
              <thead>
                <tr>
                  <th>Record set</th>
                  <th>Signed</th>
                  <th title="The earliest signature expiration on its path to the root">Expires</th>
                  <th>Weakest key</th>
                  <th title="This entry's epoch ← the epoch of the entry it was proven under">Epoch ← parent</th>
                </tr>
              </thead>
              <tbody>
                {[...caches]
                  .sort(([a], [b]) => zoneOrder(label(a) ?? '~').localeCompare(zoneOrder(label(b) ?? '~')))
                  .map(([hash, c]) => (
                    <tr key={hash}>
                      <td>{label(hash) ? <strong>{label(hash)}</strong> : <Hash hex={hash} />}</td>
                      <td>
                        <Time t={c.inception} />
                      </td>
                      <td>
                        <Time t={c.expiry} /> {c.expiry < now && <Badge ok={false}>expired</Badge>}
                      </td>
                      <td>{c.weakestKeyBits} bits</td>
                      <td>
                        <code>
                          {c.epoch} ← {c.parentEpoch}
                        </code>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </Section>

          <Section
            title={`Box rent credits (${credits.size})`}
            about="Prepaid box storage deposits, per account. A prover pays rent for the boxes it creates out of its credits; pruning an expired box, or replacing someone else's attestation, refunds the payer's credits."
          >
            <table>
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Credits</th>
                </tr>
              </thead>
              <tbody>
                {[...credits].map(([account, amount]) => (
                  <tr key={account}>
                    <td>
                      <code>{account}</code>
                    </td>
                    <td>{(Number(amount) / 1e6).toFixed(6)} ALGO</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
          <p className="muted">Read at {isoTime(Math.floor(core.dataUpdatedAt / 1000))}.</p>
        </>
      )}
    </Load>
  )
}

/** An anchor and its proof toggle: the open state lives here, so a toggle re-renders this row, not the whole view. */
function AnchorRow({ id, anchor, label }: { id: string; anchor: AnchorEntry; label?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <tr>
        <td>
          {label ?? 'not in the root key set now'}
          <br />
          <Hash hex={id} />
          <br />
          <button className="more" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
            {open ? '▾ Hide the proof' : '▸ Prove it is a real root key'}
          </button>
        </td>
        <td>
          <Badge ok={anchor.state === AnchorState.Valid || anchor.state === AnchorState.Missing}>
            {AnchorState[anchor.state]}
          </Badge>
          <p className="muted">{ANCHOR_STATES[anchor.state as AnchorState]}</p>
        </td>
        <td>
          <Time t={anchor.since} />
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={3}>
            <AnchorProof id={id} anchor={anchor} />
          </td>
        </tr>
      )}
    </>
  )
}

/** Step by step, why an anchor id is one of IANA's root keys, checked in the browser. */
function AnchorProof({ id, anchor }: { id: string; anchor: AnchorEntry }) {
  const proof = useQuery(anchorProofQuery(id))
  return (
    <Load query={proof}>
      {({ iana, ianaKeys, live }) => {
        const algorithm = iana?.rdata[3]
        const computed = iana && toHex(anchorHash(iana.rdata))
        const digest = iana && rootDsDigest(iana.rdata)
        const tag = iana && keyTag(iana.rdata)
        const liveOk =
          anchor.state === AnchorState.Missing
            ? !live
            : anchor.state === AnchorState.Revoked
              ? !live || isRevoked(live.flags)
              : !!live && !isRevoked(live.flags)
        return (
          <ol className="chain proof">
            <li>
              <strong>The oracle trusts this id.</strong> Its anchor box <code>a ‖ id</code> holds only the state,{' '}
              {AnchorState[anchor.state]} since <Time t={anchor.since} />: the key itself is known by{' '}
              <code>sha256(algorithm ‖ public key)</code>, so a key matches only if it hashes to <Hash hex={id} />.
            </li>
            <li>
              <strong>IANA publishes the root keys.</strong> Fetched just now over HTTPS from{' '}
              <a href={IANA_ANCHORS}>root-anchors.xml</a>, the root zone's trust anchor file ({ianaKeys} keys with a
              public key).{' '}
              {iana ? (
                <>
                  Its entry for key tag <strong>{iana.tag}</strong>: algorithm {iana.algorithm}, flags{' '}
                  {(iana.rdata[0] << 8) | iana.rdata[1]}, valid from {iana.validFrom.slice(0, 10)}
                  {iana.validUntil && ` until ${iana.validUntil.slice(0, 10)}`}, {keySize(iana.rdata)}. Public key:
                  <Clamp>
                    <code>{btoa(String.fromCharCode(...iana.rdata.slice(4)))}</code>
                  </Clamp>
                </>
              ) : (
                <Badge ok={false}>No key in IANA's file hashes to this id: it is not a published root key</Badge>
              )}
            </li>
            {iana && (
              <>
                <li>
                  <strong>That key hashes to the anchor id.</strong> Computed in your browser:{' '}
                  <code>sha256({algorithm} ‖ public key)</code> = <Hash hex={computed!} />{' '}
                  <Badge ok={computed === id}>{computed === id ? 'equals the anchor id' : 'differs'}</Badge>
                </li>
                <li>
                  <strong>IANA's digest vouches for the same key.</strong> The file's authoritative field is the DS
                  digest, <code>sha256(root name ‖ DNSKEY RDATA)</code>, over flags, protocol 3, algorithm and public
                  key: <Hash hex={digest!} /> <Badge ok={digest === iana.digest}>
                    {digest === iana.digest ? "equals IANA's Digest" : "differs from IANA's Digest"}
                  </Badge>{' '}
                  Its key tag, computed the same way: {tag} <Badge ok={tag === iana.tag}>
                    {tag === iana.tag ? 'as listed' : `IANA lists ${iana.tag}`}
                  </Badge>
                </li>
              </>
            )}
            <li>
              <strong>The root zone serves it now.</strong> The root DNSKEY RRset, from Cloudflare over DNS over HTTPS:{' '}
              {live
                ? `a ${keyRole(live.flags)}, key tag ${live.tag}${isRevoked(live.flags) ? ' (the REVOKE flag changes the tag)' : ''}.`
                : 'it is not there.'}{' '}
              <Badge ok={liveOk}>
                {liveOk
                  ? `consistent with ${AnchorState[anchor.state]}`
                  : `${AnchorState[anchor.state]} lags DNS: the next maintain-anchors run catches up`}
              </Badge>
            </li>
          </ol>
        )
      }}
    </Load>
  )
}
