import { toast } from 'sonner'

/**
 * A node error a person can act on, in plain words; anything else unchanged. `overspend`: the
 * sender lacks the ALGO for the fees, or for a payment (a credit deposit) when there is one.
 */
export function humanError(message: string) {
  const overspend = message.match(/overspend \(account (\w+)/)
  if (!overspend) return message
  const [, account] = overspend
  const balance = message.match(/MicroAlgos:([\d.]+)A\b/)?.[1]
  return (
    `Not enough ALGO: ${account.slice(0, 6)}…${account.slice(-4)}${balance ? ` holds ${Number(balance)} ALGO, which` : ''} cannot ` +
    'cover the fees (and any credit deposit). Fund the account and try again; on TestNet, free ALGO comes from ' +
    'lora.algokit.io/testnet/fund or testnet-dispenser.algorand.tech.'
  )
}

/** An error toast that stays until closed, with a button copying its message. */
export function toastError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error)
  // the raw message stays one click away, for bug reports
  toast.error(humanError(message), {
    duration: Infinity,
    action: {
      label: 'Copy',
      onClick: (e) => {
        e.preventDefault() // keep the toast open
        navigator.clipboard.writeText(message).then(
          () => toast.success('Copied'),
          () => toast.error('Could not copy: the clipboard is unavailable'),
        )
      },
    },
  })
}
