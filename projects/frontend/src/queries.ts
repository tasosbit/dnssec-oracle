import { DnssecOracleReaderSDK } from '@d13co/dnssec-oracle-sdk'
import { keepPreviousData, QueryClient, queryOptions } from '@tanstack/react-query'
import { anchorLabels, DOH_RESOLVERS, dohResolver, liveChain, Network, oracleSide, provenNames } from './oracle'

/** In memory only: nothing is persisted, a reload starts cold. */
export const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1 } } })

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

/**
 * Names from the proof transactions: an indexer scan of every app call, the most expensive
 * read here. Names only accumulate, so the key carries the box count and a new box triggers a
 * rescan. Otherwise 10 minutes, no focus refetch, and the previous labels stay up meanwhile.
 */
export const namesQuery = ({ sdk, network, appId }: Oracle, boxes: number) =>
  queryOptions({
    queryKey: ['oracle', network, appId, 'names', boxes],
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
