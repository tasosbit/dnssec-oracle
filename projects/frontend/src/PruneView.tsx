import {
  Attestation,
  attestationBoxMbrMicroAlgos,
  CACHE_BOX_MBR_MICROALGOS,
  CacheEntry,
  DnssecOracleSDK,
  PRUNE_GRACE_SECONDS,
  RRType,
} from '@d13co/dnssec-oracle-sdk'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useWallet } from '@txnlab/use-wallet-react'
import { WalletButton } from '@txnlab/use-wallet-ui-react'
import { toast } from 'sonner'
import { TxLinks } from './CreditsView'
import { relTime } from './oracle'
import { creditsQuery, namesQuery, Oracle, stateQuery } from './queries'
import { Hash, Load, Section, Time } from './ui'

const algo = (micro: number) => `${(micro / 1e6).toFixed(6)} ALGO`
const short = (address: string) => `${address.slice(0, 6)}…${address.slice(-4)}`
/** Prunes per group: one app call each. */
const GROUP = 16

type Target = { name: string; type: number }

interface Candidate {
  hash: string
  label?: string
  /** What prune takes: unknown without the box's name. */
  target?: Target
  why: string
  refund: number
  /** Who the rent goes back to: the pruner (undefined) or the attestation's payer. */
  payer?: string
  /** The payer has no credit box: the rent stays with the app. */
  stranded?: boolean
  /** When anyone may prune it, if the connected account may not yet. */
  from?: number
}

/**
 * What the contract's prune accepts now: a cache entry once expired or proven under an old root
 * epoch; an attestation likewise, but only its payer until 30 days past expiry.
 */
function candidates(
  [{ rootEpoch }, , caches, attestations, creditBoxes]: [
    { rootEpoch: bigint },
    unknown,
    Map<string, CacheEntry>,
    Map<string, Attestation>,
    Map<string, bigint>,
  ],
  label: (hash: string) => string | undefined,
  account: string | null,
  now: number,
): Candidate[] {
  const out: Candidate[] = []
  for (const [hash, c] of caches) {
    const stale = BigInt(c.epoch) < rootEpoch
    if (!stale && now <= c.expiry) continue
    const l = label(hash)
    const [name, type] = l?.split(' ') ?? []
    out.push({
      hash,
      label: l,
      target: l ? { name, type: RRType[type as keyof typeof RRType] } : undefined,
      why: stale ? 'proven under a root anchor since revoked' : `expired ${relTime(c.expiry, now)}`,
      refund: CACHE_BOX_MBR_MICROALGOS,
    })
  }
  for (const [hash, a] of attestations) {
    const stale = BigInt(a.parentEpoch) < rootEpoch
    if (!stale && now <= a.expiration) continue
    const l = label(hash)
    const open = stale || a.payer === account || now > a.expiration + PRUNE_GRACE_SECONDS
    out.push({
      hash,
      label: l,
      target: l ? { name: l, type: RRType.TXT } : undefined,
      why: stale ? 'proven under a root anchor since revoked' : `expired ${relTime(a.expiration, now)}`,
      refund: attestationBoxMbrMicroAlgos(
        a.records.reduce((n, r) => n + r.length, 0),
        a.records.length,
      ),
      payer: a.payer,
      stranded: !creditBoxes.has(a.payer),
      from: open ? undefined : a.expiration + PRUNE_GRACE_SECONDS,
    })
  }
  return out
}

export function PruneView({ oracle }: { oracle: Oracle }) {
  const { activeAddress } = useWallet()
  const core = useQuery(stateQuery(oracle))
  const boxes = core.data ? core.data[2].size + core.data[3].size : 0
  const names = useQuery({ ...namesQuery(oracle, boxes), enabled: !!core.data })
  // ponytail: the contract judges by the last block's time, a few seconds behind; a minute's margin
  // keeps a just-expired box out of a group it would sink. Read the block time if LocalNet dev mode matters
  const now = Date.now() / 1000 - 60

  return (
    <>
      <Section
        title="Prune expired boxes"
        about={
          <>
            Boxes whose signatures have run out, or that were proven under a root key since revoked, are no use to
            anyone, but still lock their rent. Anyone may delete an expired cache entry, and its rent goes into their
            credits. An expired attestation is its payer's to delete for 30 days, then anyone's; its rent goes back
            to the payer's credits, or stays with the app if the payer has withdrawn and has no credit box.
          </>
        }
      >
        {!activeAddress && <WalletButton />}
      </Section>
      <Load query={core}>
        {(data) => (
          <Prunable
            oracle={oracle}
            account={activeAddress}
            list={candidates(data, (h) => names.data?.get(h), activeAddress, now)}
            labelling={names.isPending}
          />
        )}
      </Load>
    </>
  )
}

function Prunable({
  oracle,
  account,
  list,
  labelling,
}: {
  oracle: Oracle
  account: string | null
  list: Candidate[]
  labelling: boolean
}) {
  const queryClient = useQueryClient()
  const { transactionSigner } = useWallet()
  const credits = useQuery({ ...creditsQuery(oracle, account ?? ''), enabled: !!account })
  // a cache refund goes into the pruner's credits, so it needs a credit box
  const noCreditBox = credits.data === null
  const usable = (c: Candidate) => !!account && !!c.target && !c.from && !(noCreditBox && !c.payer)
  const ready = list.filter(usable)

  const prune = useMutation({
    // not useWriter: there may be no account to write as
    mutationFn: (targets: Target[]) =>
      new DnssecOracleSDK({
        algorand: oracle.sdk.algorand,
        appId: oracle.sdk.appId,
        writerAccount: { sender: account!, signer: transactionSigner },
      }).pruneMany({ targets }),
    onSuccess: (result, targets) => {
      toast.success(`Pruned ${targets.length} box${targets.length === 1 ? '' : 'es'}`, {
        description: <TxLinks txIds={result.txIds} network={oracle.network} />,
      })
      return queryClient.invalidateQueries({ queryKey: ['oracle', oracle.network, oracle.appId] })
    },
  })

  if (!list.length) return <p className="muted">Nothing to prune: every box is current.</p>
  return (
    <Section
      title={`Expired boxes (${list.length})`}
      about={
        <>
          {labelling && 'Looking up names… '}
          {noCreditBox && 'Pruning a cache entry pays its rent into your credits: deposit on the Credits tab first. '}
          {ready.length > GROUP && `One group prunes at most ${GROUP}; prune again for the rest.`}
        </>
      }
    >
      {ready.length > 0 && (
        <p>
          <button
            type="submit"
            disabled={prune.isPending}
            onClick={() => prune.mutate(ready.slice(0, GROUP).map((c) => c.target!))}
          >
            {prune.isPending ? 'Sign in your wallet…' : `Prune ${Math.min(ready.length, GROUP)} in one group`}
          </button>
        </p>
      )}
      <table>
        <thead>
          <tr>
            <th>Box</th>
            <th>Why</th>
            <th>Rent back</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {list.map((c) => (
            <tr key={c.hash}>
              <td>{c.label ? <strong>{c.label}</strong> : <Hash hex={c.hash} />}</td>
              <td>{c.why}</td>
              <td>
                {algo(c.refund)}{' '}
                <span className="muted">
                  to{' '}
                  {c.stranded ? (
                    <>the app: payer {c.payer && <span title={c.payer}>{short(c.payer)}</span>} has no credit box</>
                  ) : !c.payer ? (
                    account ? (
                      'you'
                    ) : (
                      'the pruner'
                    )
                  ) : c.payer === account ? (
                    'you (payer)'
                  ) : (
                    <span title={c.payer}>{short(c.payer)}</span>
                  )}
                </span>
              </td>
              <td>
                {usable(c) ? (
                  <button disabled={prune.isPending} onClick={() => prune.mutate([c.target!])}>
                    Prune
                  </button>
                ) : c.from ? (
                  <span className="muted">
                    the payer's until <Time t={c.from} />
                  </span>
                ) : !c.target ? (
                  <span className="muted">name unknown</span>
                ) : (
                  <span className="muted">{account ? 'needs a credit box' : 'connect a wallet'}</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Section>
  )
}
