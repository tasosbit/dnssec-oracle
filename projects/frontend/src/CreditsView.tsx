import {
  CACHE_BOX_MBR_MICROALGOS,
  CREDIT_BOX_MBR_MICROALGOS,
  DnssecOracleSDK,
  SendResult,
} from '@d13co/dnssec-oracle-sdk'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useWallet } from '@txnlab/use-wallet-react'
import { WalletButton } from '@txnlab/use-wallet-ui-react'
import { algosToMicroalgos } from 'algosdk'
import { FormEvent, useMemo, useState } from 'react'
import { toast } from 'sonner'
import { creditsQuery, Oracle } from './queries'
import { Load, Section } from './ui'

const algo = (micro: number | bigint) => `${(Number(micro) / 1e6).toFixed(6)} ALGO`

export function CreditsView({ oracle }: { oracle: Oracle }) {
  const { activeAddress } = useWallet()
  return (
    <>
      {activeAddress ? (
        <Credits oracle={oracle} account={activeAddress} />
      ) : (
        <Section title="Wallet" about="Connect an account to deposit or withdraw its credits. Reading the oracle needs no wallet.">
          <WalletButton />
        </Section>
      )}
    </>
  )
}

/** The oracle's SDK writing as the active wallet account. */
export function useWriter(oracle: Oracle, account: string) {
  const { transactionSigner } = useWallet()
  return useMemo(
    () =>
      new DnssecOracleSDK({
        algorand: oracle.sdk.algorand,
        appId: oracle.sdk.appId,
        writerAccount: { sender: account, signer: transactionSigner },
      }),
    [oracle, account, transactionSigner],
  )
}

function Credits({ oracle, account }: { oracle: Oracle; account: string }) {
  const credits = useQuery(creditsQuery(oracle, account))
  const writer = useWriter(oracle, account)
  const queryClient = useQueryClient()
  // errors toast from the query client's MutationCache
  const sent = (what: string) => (result: SendResult) => {
    toast.success(what, {
      description: <TxLinks txIds={result.txIds} network={oracle.network} />,
    })
    return Promise.all(
      ['state', 'credits'].map((q) =>
        queryClient.invalidateQueries({
          queryKey: ['oracle', oracle.network, oracle.appId, q],
        }),
      ),
    )
  }
  const deposit = useMutation({
    mutationFn: ({ amount, creditor }: { amount: bigint; creditor?: string }) =>
      writer.depositCredits({ amount, creditor }),
    onSuccess: sent('Deposit confirmed'),
  })
  const withdraw = useMutation({
    mutationFn: () => writer.withdrawCredits({}),
    onSuccess: sent('Withdrawal confirmed'),
  })
  const [amount, setAmount] = useState('1')
  const [creditor, setCreditor] = useState('')

  const submit = (e: FormEvent) => {
    e.preventDefault()
    deposit.mutate({
      amount: BigInt(algosToMicroalgos(Number(amount))),
      creditor: creditor.trim() || undefined,
    })
  }

  return (
    <Section
      title="Box rent credits"
      about={
        <>
          The oracle stores what it proves in boxes, and every box locks a minimum balance (MBR) in the app. Provers
          prepay that rent as credits: each new box draws its MBR from the prover's credits (a cache entry{' '}
          {algo(CACHE_BOX_MBR_MICROALGOS)}, an attestation a little more for its records), and deleting a box returns
          it. Credits are a deposit, not a fee: withdraw them whenever you like.
        </>
      }
    >
      <Load query={credits}>
        {(balance) => (
          <>
            <dl className="fields">
              <dt>Your credits</dt>
              <dd>
                <code>{balance === null ? 'none' : algo(balance)}</code>
                <p>
                  {balance === null ? (
                    `No credit box yet. The first deposit creates one, and pays its own MBR (${algo(CREDIT_BOX_MBR_MICROALGOS)}) out of the amount.`
                  ) : (
                    <>
                      Held in the app for <span title={account}>{account.slice(0, 6)}…{account.slice(-4)}</span>.
                      <br />
                      Its credit box locks {algo(CREDIT_BOX_MBR_MICROALGOS)} more, returned on withdrawal.
                    </>
                  )}
                </p>
              </dd>
            </dl>

            <h3 className="sub">Deposit</h3>
            <form className="credits" onSubmit={submit}>
              <label>
                Amount (ALGO)
                <input
                  type="number"
                  min="0.000001"
                  step="0.000001"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  required
                />
              </label>
              <label className="grow">
                For account (optional)
                <input value={creditor} onChange={(e) => setCreditor(e.target.value)} placeholder={account} />
              </label>
              <button type="submit" disabled={deposit.isPending}>
                {deposit.isPending ? 'Sign in your wallet…' : 'Deposit'}
              </button>
            </form>
            <p className="muted">Anyone may fund another account's credits.</p>

            <h3 className="sub">Withdraw</h3>
            <p className="muted">
              Withdraws all of your credits at once and deletes your credit box, returning its MBR too
              {balance !== null && <>: {algo(balance + BigInt(CREDIT_BOX_MBR_MICROALGOS))} in all</>}.
            </p>
            <button disabled={balance === null || withdraw.isPending} onClick={() => withdraw.mutate()}>
              {withdraw.isPending ? 'Sign in your wallet…' : 'Withdraw all'}
            </button>
          </>
        )}
      </Load>
    </Section>
  )
}

export const TxLinks = ({ txIds, network }: { txIds: string[]; network: string }) => (
  <>
    {txIds.map((id) => (
      <a key={id} href={`https://lora.algokit.io/${network}/transaction/${id}`} target="_blank" rel="noreferrer">
        <code>{id.slice(0, 10)}…</code>{' '}
      </a>
    ))}
  </>
)
