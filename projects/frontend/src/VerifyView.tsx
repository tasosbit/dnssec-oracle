import {
  Attestation,
  CacheEntry,
  keyTag,
  nameFromWire,
  parseDnskey,
  parseDs,
  rdataOf,
  RRType,
  toHex,
  txtStrings,
} from '@d13co/dnssec-oracle-sdk'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { FormEvent, useState } from 'react'
import { compareRows, Comparison, DOH_RESOLVERS, duration, keyRole, keySize, Row, typeName } from './oracle'
import { liveChainQuery, Oracle, oracleSideQuery } from './queries'
import { Badge, Hash, Load, Section, Time } from './ui'

const MAX_AGES = [3600, 86_400, 7 * 86_400, 30 * 86_400]
const KEY_BITS = [1024, 2048]

export function VerifyView({ oracle, name, onName }: { oracle: Oracle; name: string; onName: (n: string) => void }) {
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState(name)
  const [maxAge, setMaxAge] = useState(7 * 86_400)
  const [minKeyBits, setMinKeyBits] = useState(1024)
  const [resolver, setResolver] = useState<keyof typeof DOH_RESOLVERS>('Cloudflare')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const next = draft.trim()
    // pressing Verify again on the same name means: check now, not from cache
    for (const q of [oracleSideQuery(oracle, next, maxAge, minKeyBits), liveChainQuery(oracle, next, resolver)]) {
      queryClient.invalidateQueries({ queryKey: q.queryKey })
    }
    onName(next)
  }

  return (
    <>
      <Section
        title="Verify a name"
        about={
          <>
            Reads the name's attestation with <code>getVerifiedAttestation</code>, the SDK's twin of the check consumer
            contracts run on-chain. Then fetches the same chain of trust from live DNS over HTTPS, verifies every
            signature in your browser, and lays the two side by side.
          </>
        }
      >
        <form className="verify" onSubmit={submit}>
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="_algorand.example.com"
            autoFocus
            spellCheck={false}
          />
          <label title="Consumers reject attestations signed longer ago than this">
            maxAge
            <select value={maxAge} onChange={(e) => setMaxAge(Number(e.target.value))}>
              {MAX_AGES.map((s) => (
                <option key={s} value={s}>
                  {duration(s)}
                </option>
              ))}
            </select>
          </label>
          <label title="Consumers reject chains with a key weaker than this; P-256 counts as 3072">
            minKeyBits
            <select value={minKeyBits} onChange={(e) => setMinKeyBits(Number(e.target.value))}>
              {KEY_BITS.map((b) => (
                <option key={b}>{b}</option>
              ))}
            </select>
          </label>
          <label>
            DoH
            <select value={resolver} onChange={(e) => setResolver(e.target.value as keyof typeof DOH_RESOLVERS)}>
              {Object.keys(DOH_RESOLVERS).map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
          </label>
          <button type="submit">Verify</button>
        </form>
      </Section>
      {name && <Result {...{ oracle, name, maxAge, minKeyBits, resolver }} />}
    </>
  )
}

function Result(props: {
  oracle: Oracle
  name: string
  maxAge: number
  minKeyBits: number
  resolver: keyof typeof DOH_RESOLVERS
}) {
  const { oracle, name, maxAge, minKeyBits, resolver } = props
  const side = useQuery(oracleSideQuery(oracle, name, maxAge, minKeyBits))
  const chain = useQuery(liveChainQuery(oracle, name, resolver))
  return (
    <Load query={side}>
      {(o) => {
        const c: Comparison = { ...o, name, rows: chain.data && compareRows(chain.data, o) }
        return (
          <>
            <Verdict c={c} maxAge={maxAge} minKeyBits={minKeyBits} />
            {chain.isPending && <p className="muted">Fetching the chain from live DNS and checking its signatures…</p>}
            {chain.error && (
              <p className="error">
                Live DNS: {chain.error.message}. The oracle could not prove this chain from DNS as served now either.
              </p>
            )}
            {c.rows && <RecordCompare c={c} />}
            {c.rows && <Chain c={c} />}
          </>
        )
      }}
    </Load>
  )
}

function Verdict({ c, maxAge, minKeyBits }: { c: Comparison; maxAge: number; minKeyBits: number }) {
  if (c.verified) {
    const zones = [...c.verified.zones.map((z) => nameFromWire(z)), '.'].join(' → ')
    return (
      <div className="verdict ok">
        <strong>Verified.</strong> A consumer checking with maxAge {duration(maxAge)} and minKeyBits {minKeyBits}{' '}
        accepts this attestation now. Its chain runs {zones}, and every link is current.
      </div>
    )
  }
  if (c.raw) {
    return (
      <div className="verdict bad">
        <strong>Stored, but not usable</strong> with maxAge {duration(maxAge)} and minKeyBits {minKeyBits}:
        <ul>
          {c.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
        Anyone can prove it again: <code>dnssec-oracle prove {c.name}</code>
      </div>
    )
  }
  return (
    <div className="verdict bad">
      <strong>No attestation</strong> for {c.name}. Anyone can prove one: <code>dnssec-oracle prove {c.name}</code>
    </div>
  )
}

const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`

const texts = (records: Uint8Array[]) => records.map((r) => txtStrings(r).join(''))

function RecordCompare({ c }: { c: Comparison }) {
  const rows = c.rows!
  const txt = rows[rows.length - 1]
  const live = rdataOf(txt.step.rrset)
  const liveExpiration = Math.min(...rows.map((r) => r.step.expiration))
  const a = c.raw
  return (
    <Section
      title="The record: oracle and live DNS"
      about="What the oracle stored when the record set was proven, next to what DNS serves now. The two differ when the record changed since, or when a newer signature has not been proven yet."
    >
      <table className="compare">
        <thead>
          <tr>
            <th />
            <th>Oracle</th>
            <th>Live DNS</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th>
              Records <Badge ok={txt.same}>{txt.same ? 'same' : 'differ'}</Badge>
            </th>
            <td>{a ? <TextList items={a.texts} other={texts(live)} /> : '—'}</td>
            <td>
              <TextList items={texts(live)} other={a?.texts} />
            </td>
          </tr>
          <tr>
            <th title="The TXT signature's inception">Signed</th>
            <td>{a ? <Time t={a.inception} /> : '—'}</td>
            <td>
              <Time t={txt.step.inception} />
            </td>
          </tr>
          <tr>
            <th title="The earliest signature expiration on the chain, root included">Chain expires</th>
            <td>{a ? <Time t={a.expiration} /> : '—'}</td>
            <td>
              <Time t={liveExpiration} />
            </td>
          </tr>
          <tr>
            <th title="P-256 counts as 3072 bits">Weakest key</th>
            <td>{a ? `${a.weakestKeyBits} bits` : '—'}</td>
            <td>{txt.step.keyBits} bits</td>
          </tr>
          <tr>
            <th title="Who paid the box rent, refunded when the box is replaced or pruned">Payer</th>
            <td>{a ? <code>{a.payer}</code> : '—'}</td>
            <td />
          </tr>
        </tbody>
      </table>
    </Section>
  )
}

function TextList({ items, other }: { items: string[]; other?: string[] }) {
  return (
    <ul className="records">
      {items.map((t, i) => (
        <li key={i} className={other && !other.includes(t) ? 'only' : ''} title={other && !other.includes(t) ? 'only on this side' : ''}>
          <code>{t}</code>
        </li>
      ))}
    </ul>
  )
}

function Chain({ c }: { c: Comparison }) {
  return (
    <Section
      title="Chain of trust"
      about={
        <>
          From the root down to the record, each link one signature. On the left, what the oracle cached when the link
          was proven; on the right, the link as DNS serves it now, its signature verified here. The oracle compares{' '}
          <code>sha256</code> of the canonical record set, so <em>same</em> means it holds exactly these records, even if
          proven under an older signature. <em>Linked</em> means the entry was proven under the entry above it as it
          stands now: a consumer's chain walk passes through it.
        </>
      }
    >
      <ol className="chain">
        {c.rows!.map((row, i) => (
          <Link key={i} row={row} c={c} />
        ))}
      </ol>
    </Section>
  )
}

function explain({ step, sig }: Row) {
  const owner = nameFromWire(step.owner)
  const signer = nameFromWire(sig.signer)
  switch (step.kind) {
    case 'root':
      return "The root zone's keys, signed by a root key the oracle holds as a trust anchor."
    case 'ds':
      return `${signer} vouches for ${owner}'s key: a DS record holds a digest of it, signed by ${signer}'s zone key.`
    case 'dnskey':
      return `${owner}'s keys, signed by the key its DS vouches for.`
    case 'txt':
      return `The record set itself, signed by ${signer}'s zone key.`
  }
}

function Link({ row, c }: { row: Row; c: Comparison }) {
  const { step, sig, key, entry, same, linked } = row
  const isTxt = step.kind === 'txt'
  const cache = isTxt ? undefined : (entry as CacheEntry | undefined)
  const att = isTxt ? (entry as Attestation | undefined) : undefined
  const keyInfo = parseDnskey(key)
  return (
    <li>
      <div className="link-head">
        <h3>
          {nameFromWire(step.owner)} {typeName(step.type)}
        </h3>
        {entry ? (
          <>
            <Badge ok={same} title={same ? 'The oracle holds exactly this record set' : 'The oracle holds another version'}>
              {same ? 'same' : 'differs'}
            </Badge>
            <Badge
              ok={linked}
              title={
                step.kind === 'root'
                  ? 'Proven under the current anchor set (rootEpoch)'
                  : 'Proven under the entry above as it stands now'
              }
            >
              {linked ? 'linked' : 'stale link'}
            </Badge>
          </>
        ) : (
          <Badge ok={false}>{isTxt ? 'not attested' : 'not cached'}</Badge>
        )}
      </div>
      <p className="about">{explain(row)}</p>
      <div className="sides">
        <div>
          <h4>Oracle</h4>
          {cache ? (
            <dl className="kv">
              <dt>hash</dt>
              <dd>
                <Hash hex={toHex(cache.hash)} />
              </dd>
              <dt>signed</dt>
              <dd>
                <Time t={cache.inception} />
              </dd>
              <dt>expires</dt>
              <dd>
                <Time t={cache.expiry} />
              </dd>
              <dt>weakest key</dt>
              <dd>{cache.weakestKeyBits} bits</dd>
              <dt>epoch ← parent</dt>
              <dd>
                <code>
                  {cache.epoch} ← {cache.parentEpoch}
                </code>
                {step.kind === 'root' && <span className="muted"> (rootEpoch {String(c.rootEpoch)})</span>}
              </dd>
            </dl>
          ) : att ? (
            <dl className="kv">
              <dt>signed</dt>
              <dd>
                <Time t={att.inception} />
              </dd>
              <dt>parent epoch</dt>
              <dd>
                <code>{att.parentEpoch}</code>
              </dd>
            </dl>
          ) : (
            <p className="muted">Nothing stored.</p>
          )}
        </div>
        <div>
          <h4>Live DNS</h4>
          <dl className="kv">
            <dt>hash</dt>
            <dd>
              <Hash hex={toHex(row.liveHash)} />
            </dd>
            <dt>signature</dt>
            <dd>
              <Time t={sig.inception} /> to <Time t={sig.expiration} />
            </dd>
            <dt>signed by</dt>
            <dd>
              {nameFromWire(sig.signer)} {keyRole(keyInfo.flags)} {keyTag(key)}, {keySize(key)}{' '}
              <Badge ok title="Verified in this browser">
                verified
              </Badge>
            </dd>
          </dl>
          <details>
            <summary>{plural(rdataOf(step.rrset).length, 'record')}</summary>
            <Records type={step.type} rrset={step.rrset} signer={key} />
          </details>
        </div>
      </div>
    </li>
  )
}

function Records({ type, rrset, signer }: { type: number; rrset: Uint8Array; signer: Uint8Array }) {
  const rdatas = rdataOf(rrset)
  return (
    <ul className="records">
      {rdatas.map((r, i) => {
        if (type === RRType.DNSKEY) {
          const k = parseDnskey(r)
          const signs = toHex(r) === toHex(signer)
          return (
            <li key={i}>
              {keyRole(k.flags)} {keyTag(r)}, {keySize(r)}
              {signs && <Badge ok>signed this set</Badge>}
            </li>
          )
        }
        if (type === RRType.DS) {
          const d = parseDs(r)
          return (
            <li key={i}>
              DS for key {d.keyTag}, algorithm {d.algorithm}, digest type {d.digestType}
              {d.digestType !== 2 && <span className="muted"> (ignored: the oracle reads SHA-256 only)</span>}{' '}
              <Hash hex={toHex(d.digest)} />
            </li>
          )
        }
        return (
          <li key={i}>
            <code>{txtStrings(r).join('')}</code>
          </li>
        )
      })}
    </ul>
  )
}
