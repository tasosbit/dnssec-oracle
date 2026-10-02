import { ReactNode } from 'react'
import { isoTime, relTime } from './oracle'

/** Loading and error states of a query, then `children` with its data. */
export function Load<T>({ query, children }: { query: { data?: T; error: Error | null }; children: (data: T) => ReactNode }) {
  if (query.error) return <p className="error">{query.error.message}</p>
  if (query.data === undefined) return <p className="muted">Loading…</p>
  return <>{children(query.data)}</>
}

export function Section({ title, about, children }: { title: string; about: ReactNode; children: ReactNode }) {
  return (
    <section>
      <h2>{title}</h2>
      <p className="about">{about}</p>
      {children}
    </section>
  )
}

export const Time = ({ t }: { t: number }) => (
  <span title={isoTime(t)}>
    {isoTime(t)} <span className="muted">({relTime(t)})</span>
  </span>
)

export const Hash = ({ hex }: { hex: string }) => (
  <code className="hash" title={hex}>
    {hex.slice(0, 10)}…{hex.slice(-6)}
  </code>
)

export const Badge = ({ ok, children, title }: { ok: boolean | undefined; children: ReactNode; title?: string }) => (
  <span className={`badge ${ok === undefined ? 'neutral' : ok ? 'ok' : 'bad'}`} title={title}>
    {children}
  </span>
)
