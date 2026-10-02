import { DnssecOracleReaderSDK, DnssecOracleSDK, ProofStep } from '@d13co/dnssec-oracle-sdk'
import { keepPreviousData, MutationCache, QueryClient, queryOptions } from '@tanstack/react-query'
import { toastError } from './toasts'
import { anchorLabels, anchorProof, anchorSources, DOH_RESOLVERS, dohResolver, liveChain, Network, oracleSide, provenNames } from './oracle'

/**
 * In memory only: nothing is persisted, a reload starts cold. Failed queries show in place;
 * failed actions (mutations) raise a toast.
 */
export const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1 } },
  mutationCache: new MutationCache({ onError: toastError }),
})

/** The oracle an SDK reads, as query key material: the SDK instance itself does not serialize. */
export interface Oracle {
  sdk: DnssecOracleReaderSDK
  network: Network
  appId: string
}

type Resolver = keyof typeof DOH_RESOLVERS

const MINUTE = 60_000

/**
 * On-chain reads. Blocks come every few seconds but the oracle changes only when someone
 * proves, prunes or deposits, so 30s spares re-simulating on every tab switch while a proof
 * just sent from the CLI still shows up soon. Window focus refetches once stale.
 */
const ON_CHAIN = 30_000

export const stateQuery = ({ sdk, network, appId }: Oracle) =>
  queryOptions({
    queryKey: ['oracle', network, appId, 'state'],
    queryFn: () =>
      Promise.all([sdk.getState(), sdk.listAnchors(), sdk.listRawCaches(), sdk.listRawAttestations(), sdk.listCredits()]),
    staleTime: ON_CHAIN,
  })

// ponytail: the count and an XOR of each key's first 32 bits; swapping one box for another
// changes it bar a 2^-32 collision. The sorted keys themselves, if that ever matters
const boxSet = (keys: string[]) => [keys.length, keys.reduce((x, k) => x ^ parseInt(k.slice(0, 8), 16), 0)]

/**
 * Names from the proof transactions: an indexer scan of every app call, the most expensive
 * read here. The key carries which boxes exist, so a new box triggers a rescan, even when a
 * prune since the last poll keeps the count. Otherwise 10 minutes, no focus refetch, and the
 * previous labels stay up meanwhile.
 */
export const namesQuery = ({ sdk, network, appId }: Oracle, boxKeys: string[]) =>
  queryOptions({
    queryKey: ['oracle', network, appId, 'names', boxSet(boxKeys)],
    queryFn: () => provenNames(sdk),
    staleTime: 10 * MINUTE,
    refetchOnWindowFocus: false,
    placeholderData: keepPreviousData,
  })

/**
 * The root DNSKEY RRset, to label anchors. Its TTL is two days and its keys change only at
 * a rollover, months apart: an hour is plenty.
 */
export const rootKeysQuery = (resolver: Resolver = 'Cloudflare') =>
  queryOptions({
    queryKey: ['dns', resolver, 'root-keys'],
    queryFn: () => anchorLabels(dohResolver(DOH_RESOLVERS[resolver])),
    staleTime: 60 * MINUTE,
  })

/** An account's ALGO balance in µAlgo: refetched on window focus, so funding in another tab shows on return. */
export const balanceQuery = ({ sdk, network }: Oracle, account: string) =>
  queryOptions({
    queryKey: ['account', network, account, 'balance'],
    queryFn: async () => (await sdk.algorand.client.algod.accountInformation(account).do()).amount,
    staleTime: ON_CHAIN,
  })

/** An anchor's key traced to IANA's file and live DNS: both change rarely, and one fetch serves every anchor. */
export const anchorProofQuery = (id: string, resolver: Resolver = 'Cloudflare') =>
  queryOptions({
    queryKey: ['dns', resolver, 'anchor-sources'],
    queryFn: () => anchorSources(dohResolver(DOH_RESOLVERS[resolver])),
    select: (sources) => anchorProof(id, sources),
    staleTime: 60 * MINUTE,
  })

/** The oracle's side of a verification: on-chain, so as fresh as the state view. */
export const oracleSideQuery = ({ sdk, network, appId }: Oracle, name: string, maxAge: number, minKeyBits: number) =>
  queryOptions({
    queryKey: ['oracle', network, appId, 'verify', name, maxAge, minKeyBits],
    queryFn: () => oracleSide(sdk, name, { maxAge, minKeyBits }),
    staleTime: ON_CHAIN,
  })

/**
 * The live chain: a DoH query per link and every signature checked in the browser, the
 * slowest work here. Five minutes matches common TXT TTLs (resolvers would serve the same
 * answer anyway), and signatures stay valid for days. Independent of maxAge and minKeyBits,
 * so changing those reuses it. Failures are DNS facts (no records, no usable signature), not
 * flakes: no retry.
 */
export const liveChainQuery = ({ sdk, network, appId }: Oracle, name: string, resolver: Resolver) =>
  queryOptions({
    // the oracle's anchors pick the root signature, hence the oracle in the key
    queryKey: ['dns', resolver, 'chain', name, network, appId],
    queryFn: () => liveChain(sdk, name, dohResolver(DOH_RESOLVERS[resolver])),
    staleTime: 5 * MINUTE,
    retry: false,
  })

/** One account's credits: on-chain, and a deposit or withdrawal invalidates it. */
export const creditsQuery = ({ sdk, network, appId }: Oracle, account: string) =>
  queryOptions({
    queryKey: ['oracle', network, appId, 'credits', account],
    queryFn: async () => (await sdk.getCredits(account)) ?? null, // null: no credit box (undefined means loading)
    staleTime: ON_CHAIN,
  })

/**
 * A proof plan: which steps of a live chain the oracle still needs, simulated and packed into
 * groups. It holds transactions valid for 200 rounds (about 10 minutes; see makeSdk), so it is
 * replanned every 5 minutes, and the state it reads changes with every proof: as fresh as the
 * state view. Keyed by the chain it plans.
 */
export const planQuery = (
  { network, appId }: Oracle,
  writer: DnssecOracleSDK,
  account: string,
  chain: { name: string; steps: ProofStep[]; at: number },
) =>
  queryOptions({
    queryKey: ['oracle', network, appId, 'plan', account, chain.name, chain.at],
    queryFn: () => writer.planChain(chain.steps),
    staleTime: ON_CHAIN,
    refetchInterval: 5 * MINUTE,
    retry: false,
  })
