import { CACHE_BOX_MBR_MICROALGOS, ChainPlan, nameFromWire, PlannedGroup } from '@d13co/dnssec-oracle-sdk'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useWallet } from '@txnlab/use-wallet-react'
import { WalletButton } from '@txnlab/use-wallet-ui-react'
import { Algodv2, waitForConfirmation } from 'algosdk'
import { FormEvent, useState } from 'react'
import { toast } from 'sonner'
import { TxLinks, useWriter } from './CreditsView'
import { DOH_RESOLVERS, explainStep, keySize, signingKey, typeName } from './oracle'
import { creditsQuery, liveChainQuery, Oracle, planQuery } from './queries'
import { Badge, ErrorText, Load, Section } from './ui'

type Resolver = keyof typeof DOH_RESOLVERS

const algo = (micro: number | bigint) => `${(Number(micro) / 1e6).toFixed(6)} ALGO`
const n = (x: number) => x.toLocaleString('en')
const plural = (k: number, noun: string) => `${k} ${noun}${k === 1 ? '' : 's'}`

export function ProveView({
  oracle,
  name,
  onName,
  onVerify,
}: {
  oracle: Oracle
  name: string
  onName: (n: string) => void
  onVerify: (n: string) => void
}) {
  const { activeAddress } = useWallet()
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState(name)
  const [resolver, setResolver] = useState<Resolver>('Cloudflare')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const next = draft.trim()
    // planning again on the same name means: from DNS and the chain as they are now
    queryClient.invalidateQueries({
      queryKey: liveChainQuery(oracle, next, resolver).queryKey,
    })
    onName(next)
  }

  return (
    <>
      <Section
        title="Prove a TXT record"
        about={
          <>
            Fetches the record's chain of trust from live DNS and checks every signature in your browser. Then works out
            which proofs the oracle still needs and bundles them into as few transaction groups as possible, for your
            wallet to sign at once.
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
          <label>
            DoH
            <select value={resolver} onChange={(e) => setResolver(e.target.value as Resolver)}>
              {Object.keys(DOH_RESOLVERS).map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
          </label>
          <button type="submit">Plan</button>
        </form>
      </Section>
      {!activeAddress ? (
        <Section
          title="Wallet"
          about="Proving sends transactions: connect the account that pays the fees and box rent."
        >
          <WalletButton />
        </Section>
      ) : (
        name && <Plan {...{ oracle, name, resolver, onVerify }} account={activeAddress} />
      )}
    </>
  )
}

function Plan({
  oracle,
  name,
  resolver,
  account,
  onVerify,
}: {
  oracle: Oracle
  name: string
  resolver: Resolver
  account: string
  onVerify: (n: string) => void
}) {
  const chain = useQuery(liveChainQuery(oracle, name, resolver))
  const writer = useWriter(oracle, account)
  const plan = useQuery({
    ...planQuery(oracle, writer, account, {
      name,
      steps: chain.data ?? [],
      at: chain.dataUpdatedAt,
    }),
    enabled: !!chain.data,
  })
  const credits = useQuery(creditsQuery(oracle, account))

  if (chain.error) return <ErrorText>{`Live DNS: ${chain.error.message}`}</ErrorText>
  if (chain.isPending) return <p className="muted">Fetching the chain from live DNS and checking its signatures…</p>
  return (
    <Load query={plan}>
      {(p) => (
        <>
          <Overview plan={p} steps={chain.data.length} credits={credits.data} />
          {p.groups.map((g, i) => (
            <GroupCard key={i} group={g} index={i} before={p.groups[i - 1]} deposit={i === 0 ? p.deposit : 0} />
          ))}
          <Submit {...{ oracle, name, plan: p, onVerify }} />
        </>
      )}
    </Load>
  )
}

function Overview({ plan, steps, credits }: { plan: ChainPlan; steps: number; credits?: bigint | null }) {
  const calls = plan.groups.flatMap((g) => g.items)
  const prunes = calls.filter((c) => c.action === 'prune').length
  const txns = plan.groups.reduce((k, g) => k + g.transactions.length, 0)
  const fee = plan.groups.reduce((k, g) => k + g.fee, 0)
  return (
    <Section
      title={`${plural(plan.groups.length, 'group')} to sign`}
      about={
        <>
          Each link of the chain is a signature the oracle checks on-chain, and each check builds on the one above it,
          so they run in order. A transaction group can only do so much computation: a large RSA key fills most of a
          group on its own, while elliptic-curve keys are cheap and several share one.
        </>
      }
    >
      <dl className="fields">
        <dt>chain</dt>
        <dd>
          <code>{plural(steps, 'link')}</code>
          <p>
            {plan.cached.length
              ? `${plural(plan.cached.length, 'link')} already proven, fresh and linked to the entry above: skipped (${plan.cached
                  .map((s) => `${nameFromWire(s.owner)} ${typeName(s.type)}`)
                  .join(', ')}). `
              : 'Nothing above it is cached yet: every link is proven. '}
            The TXT record is always proven again.
          </p>
        </dd>
        <dt>calls</dt>
        <dd>
          <code>{plural(calls.length, 'call')}</code>
          <p>
            {calls.length - prunes} proofs
            {prunes ? `, and ${plural(prunes, 'prune')} of expired entries in the way` : ''}, packed in order into{' '}
            {plural(plan.groups.length, 'group')}, {txns} transactions in all.
          </p>
        </dd>
        <dt>fees</dt>
        <dd>
          <code>{algo(fee)}</code>
          <p>Network fees, including the extra computation the signature checks need.</p>
        </dd>
        <dt>box rent</dt>
        <dd>
          <code>{plan.deposit ? `deposit ${algo(plan.deposit)}` : 'covered by your credits'}</code>
          <p>
            Storing what you prove locks a small amount from your credits: {algo(CACHE_BOX_MBR_MICROALGOS)} per new
            link, a little more for the TXT record. You hold{' '}
            {credits === undefined ? '…' : credits === null ? 'no credits' : algo(credits)}
            {plan.deposit
              ? ', not enough: the first group tops them up. Credits stay yours; withdraw them on the Credits tab.'
              : '.'}
          </p>
        </dd>
      </dl>
      {plan.remaining.length > 0 && (
        <p className="verdict bad">
          {plural(plan.remaining.length, 'more step')} could not be planned at once. Send these groups first, then plan
          again for the rest.
        </p>
      )}
    </Section>
  )
}

/** Why this group starts here: the first call would not fit in the group before, or the chain starts. */
function boundary(before?: PlannedGroup) {
  if (!before) return undefined
  return before.transactions.length >= 16
    ? 'The group before holds as many transactions as a group can. '
    : 'Too much computation to join the group before. '
}

function GroupCard({
  group,
  index,
  before,
  deposit,
}: {
  group: PlannedGroup
  index: number
  before?: PlannedGroup
  deposit: number
}) {
  return (
    <Section
      title={`Group ${index + 1}: ${plural(group.transactions.length, 'transaction')}`}
      about={
        <>
          {boundary(before)}
          {deposit > 0 && <>It first tops up your credits by {algo(deposit)}. </>}
          Fee {algo(group.fee)}.
        </>
      }
    >
      <ol className="chain">
        {group.items.map(({ action, step, opcodes }, i) => (
          <li key={i}>
            <div className="link-head">
              <h3>
                {action === 'prune' ? 'prune ' : 'prove '}
                {nameFromWire(step.owner)} {typeName(step.type)}
              </h3>
              <Badge ok>{n(opcodes)} opcodes</Badge>
            </div>
            <p className="about">
              {action === 'prune'
                ? 'The cache holds a newer record set that has expired, which blocks this older one, still valid. Anyone may prune it; its rent goes into your credits.'
                : `${explainStep(step)} Checked with ${keySize(signingKey(step))}.`}
            </p>
          </li>
        ))}
      </ol>
    </Section>
  )
}

type Progress = { sent?: bigint; confirmed?: bigint }[]

function Submit({
  oracle,
  name,
  plan,
  onVerify,
}: {
  oracle: Oracle
  name: string
  plan: ChainPlan
  onVerify: (n: string) => void
}) {
  const { signTransactions } = useWallet()
  const queryClient = useQueryClient()
  const [progress, setProgress] = useState<Progress>([])
  const send = useMutation({
    mutationFn: async (plan: ChainPlan) => {
      setProgress([])
      const flat = await signTransactions(plan.groups.map((g) => g.transactions))
      if (flat.some((b) => !b)) throw new Error('The wallet left some transactions unsigned')
      let at = 0
      const groups = plan.groups.map((g) => flat.slice(at, (at += g.transactions.length)) as Uint8Array[])
      const update = (i: number, step: Progress[number]) =>
        setProgress((p) => Object.assign([...p], { [i]: { ...p[i], ...step } }))
      return sendPaced(oracle.sdk.algorand.client.algod, groups, update)
    },
    onSuccess: (_, plan) => {
      // each group's last transaction: its proof of the TXT record, or the link it proves
      const txIds = plan.groups.map((g) => g.transactions.at(-1)!.txID())
      const left = plan.remaining.length
      toast.success(left ? `${name}: ${plural(left, 'more step')} to go, sign the next plan` : `${name} proven`, {
        description: <TxLinks txIds={txIds} network={oracle.network} />,
        // a partial plan stops short of the TXT record: nothing to verify yet
        action: left ? undefined : { label: 'Verify', onClick: () => onVerify(name) },
      })
    },
    // the plan, state, credits and verification all moved, also when a later group failed after
    // earlier ones landed: a stale plan would resend them
    onSettled: () =>
      queryClient.invalidateQueries({
        queryKey: ['oracle', oracle.network, oracle.appId],
      }),
  })
  const count = plan.groups.length
  const sent = send.variables // the plan sent last: the one shown refreshes once it lands
  return (
    <Section
      title="Sign and send"
      about="One wallet prompt signs every group. They go out one block apart, each without waiting for the one before to confirm."
    >
      <button disabled={send.isPending} onClick={() => send.mutate(plan)}>
        {send.isPending
          ? progress.length
            ? 'Sending…'
            : 'Sign in your wallet…'
          : `Sign ${plural(count, 'group')} in one prompt and send`}
      </button>
      {sent && progress.length > 0 && (
        <ol className="progress">
          {sent.groups.map((_, i) => (
            <li key={i}>
              Group {i + 1}:{' '}
              {progress[i]?.confirmed
                ? `sent in round ${progress[i].sent}, confirmed in round ${progress[i].confirmed}`
                : progress[i]?.sent
                  ? `sent in round ${progress[i].sent}, confirming…`
                  : send.isPending
                    ? 'waiting for the next round'
                    : 'not sent'}
            </li>
          ))}
        </ol>
      )}
    </Section>
  )
}

/**
 * Send signed groups in order, each once a round has passed since the one before, without
 * waiting for its confirmation; then wait for all. On a dev-mode LocalNet a sent group makes
 * its own block, so there is no wait.
 */
async function sendPaced(algod: Algodv2, groups: Uint8Array[][], update: (i: number, p: Progress[number]) => void) {
  const confirmations: Promise<unknown>[] = []
  let sentAt = -1n
  try {
    for (const [i, group] of groups.entries()) {
      let { lastRound } = await algod.status().do()
      if (lastRound <= sentAt) ({ lastRound } = await algod.statusAfterBlock(sentAt).do())
      const { txid } = await algod.sendRawTransaction(group).do()
      sentAt = lastRound
      update(i, { sent: lastRound })
      confirmations.push(waitForConfirmation(algod, txid, 20).then((r) => update(i, { confirmed: r.confirmedRound })))
    }
  } catch (e) {
    await Promise.allSettled(confirmations)
    throw new Error(`Group ${confirmations.length + 1} of ${groups.length} was rejected: ${(e as Error).message}`)
  }
  await Promise.all(confirmations)
}
