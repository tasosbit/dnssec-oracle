import { ReactNode, useLayoutEffect, useRef, useState } from 'react'
import { toast } from 'sonner'
import { isoTime, relTime } from './oracle'
import { humanError, toastError } from './toasts'

/** Loading and error states of a query, then `children` with its data. */
export function Load<T>({ query, children }: { query: { data?: T; error: Error | null }; children: (data: T) => ReactNode }) {
  if (query.error) return <ErrorText>{query.error.message}</ErrorText>
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

/** A failed read, in place of what it would show; a toast is for failed actions. */
export const ErrorText = ({ children }: { children: string }) => (
  <p className="error">
    {humanError(children)}
    <button
      className="copy"
      onClick={() => navigator.clipboard.writeText(children).then(() => toast.success('Copied'), toastError)}
    >
      Copy
    </button>
  </p>
)

/** At most five lines of `children`, and a toggle for the rest when there is more. */
export function Clamp({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(false)
  const [overflows, setOverflows] = useState(false)
  useLayoutEffect(() => {
    const el = ref.current!
    const check = () => setOverflows(el.scrollHeight > el.clientHeight + 1)
    const observer = new ResizeObserver(check)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
  return (
    <>
      <div ref={ref} className={open ? undefined : overflows ? 'clamp fade' : 'clamp'}>
        {children}
      </div>
      {(open || overflows) && (
        <button className="more" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? 'Show less' : 'Show more'}
        </button>
      )}
    </>
  )
}
