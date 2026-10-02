import { AnchorState } from '@d13co/dnssec-oracle-sdk'
import { useQuery } from '@tanstack/react-query'
import { ALGORAND_ZERO_ADDRESS_STRING } from 'algosdk'
import { isoTime } from './oracle'
import { namesQuery, Oracle, rootKeysQuery, stateQuery } from './queries'
import { Badge, Hash, Load, Section, Time } from './ui'

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
  const boxes = core.data ? core.data[2].size + core.data[3].size : 0
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
                  <tr key={id}>
                    <td>
                      {anchorNames.data?.get(id) ?? 'not in the root key set now'}
                      <br />
                      <Hash hex={id} />
                    </td>
                    <td>
                      <Badge ok={a.state === AnchorState.Valid || a.state === AnchorState.Missing}>
                        {AnchorState[a.state]}
                      </Badge>
                      <p className="muted">{ANCHOR_STATES[a.state as AnchorState]}</p>
                    </td>
                    <td>
                      <Time t={a.since} />
                    </td>
                  </tr>
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
                          <ul className="records">
                            {a.texts.map((t, i) => (
                              <li key={i}>
                                <code>{t}</code>
                              </li>
                            ))}
                          </ul>
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
