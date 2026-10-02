import { useQuery } from '@tanstack/react-query'
import { useNetwork, useWallet } from '@txnlab/use-wallet-react'
import { WalletButton } from '@txnlab/use-wallet-ui-react'
import { useEffect, useMemo, useState } from 'react'
import { CreditsView } from './CreditsView'
import { DevView } from './DevView'
import { DEFAULT_APP_ID, makeSdk, Network } from './oracle'
import { ProveView } from './ProveView'
import { PruneView } from './PruneView'
import { balanceQuery, Oracle } from './queries'
import { StateView } from './StateView'
import { VerifyView } from './VerifyView'

const TABS = { state: 'Oracle state', prove: 'Prove record', verify: 'Verify attestations', prune: 'Prune', credits: 'Credits', dev: 'SDK / CLI' }
type Tab = keyof typeof TABS

export function App() {
  const params = new URLSearchParams(location.search)
  const [network, setNetwork] = useState<Network>(params.get('network') === 'localnet' ? 'localnet' : 'testnet')
  const [appId, setAppId] = useState(params.get('app') ?? DEFAULT_APP_ID[network])
  const [tab, setTab] = useState<Tab>(Object.hasOwn(TABS, params.get('tab') ?? '') ? (params.get('tab') as Tab) : 'state')
  const [name, setName] = useState(params.get('name') ?? '')

  // shareable: the URL carries the view
  useEffect(() => {
    const q = new URLSearchParams({ network, app: appId, tab, ...((tab === 'verify' || tab === 'prove') && name ? { name } : {}) })
    history.replaceState(null, '', `?${q}`)
  }, [network, appId, tab, name])

  // wallets sign for the network the app reads; switching disconnects those that lack it (KMD)
  const { activeNetwork, setActiveNetwork } = useNetwork()
  useEffect(() => {
    if (activeNetwork !== network) setActiveNetwork(network)
  }, [network, activeNetwork, setActiveNetwork])

  const oracle = useMemo(
    () => (/^\d+$/.test(appId) ? { sdk: makeSdk(network, appId), network, appId } : undefined),
    [network, appId],
  )
  const verify = (n: string) => {
    setName(n)
    setTab('verify')
  }
  const prove = (n: string) => {
    setName(n)
    setTab('prove')
  }

  return (
    <>
      <header>
        <div className="bar">
          <h1>DNSSEC Oracle Explorer</h1>
          <div className="controls">
            <label>
              Network
              <select
                value={network}
                onChange={(e) => {
                  const n = e.target.value as Network
                  setNetwork(n)
                  setAppId(DEFAULT_APP_ID[n])
                }}
              >
                <option value="testnet">TestNet</option>
                <option value="localnet">LocalNet</option>
              </select>
            </label>
            <label>
              App ID
              {/* committed on blur or Enter: per keystroke, every digit prefix would be read as an app */}
              <input
                key={appId} // a network switch resets it
                defaultValue={appId}
                onBlur={(e) => setAppId(e.target.value.trim())}
                onKeyDown={(e) => e.key === 'Enter' && e.currentTarget.blur()}
                placeholder="app ID"
                size={12}
              />
            </label>
            <WalletButton />
          </div>
        </div>
      </header>
      <div className="intro">
        {oracle?.network === 'testnet' && <FundBanner oracle={oracle} />}
        <p>
          An Algorand app that verifies DNSSEC signature chains from the root down to a TXT record, and stores the result
          for other apps to read. Nobody is trusted to relay DNS: the contract checks every signature itself.
        </p>
        <nav>
          {Object.entries(TABS).map(([t, label]) => (
            <button key={t} className={tab === t ? 'active' : ''} onClick={() => setTab(t as Tab)}>
              {label}
            </button>
          ))}
        </nav>
      </div>
      <main>
        {!oracle ? (
          <p className="error">Enter the oracle's app ID.</p>
        ) : tab === 'state' ? (
          <StateView oracle={oracle} onVerify={verify} />
        ) : tab === 'prove' ? (
          <ProveView oracle={oracle} name={name} onName={setName} onVerify={verify} />
        ) : tab === 'prune' ? (
          <PruneView oracle={oracle} />
        ) : tab === 'verify' ? (
          <VerifyView oracle={oracle} name={name} onName={setName} onProve={prove} />
        ) : tab === 'credits' ? (
          <CreditsView oracle={oracle} />
        ) : (
          <DevView oracle={oracle} />
        )}
      </main>
      <footer>
        Experimental and unaudited. Limits: RSA keys up to 2048 bits, TXT record sets up to 4 KB.{' '}
        <a href="https://github.com/tasosbit/dnssec-oracle">Source and docs</a>
      </footer>
    </>
  )
}

/** A connected TestNet account with no ALGO can sign nothing: point it at the dispensers. */
function FundBanner({ oracle }: { oracle: Oracle }) {
  const { activeAddress } = useWallet()
  const balance = useQuery({
    ...balanceQuery(oracle, activeAddress ?? ''),
    enabled: !!activeAddress,
    // poll while empty: funding happens in another tab or on another device
    refetchInterval: (q) => (q.state.data === 0n ? 5000 : false),
    refetchOnWindowFocus: 'always',
  })
  if (balance.data !== 0n) return null
  return (
    <p className="warn">
      Your account has no TestNet ALGO, which every transaction here needs for fees. Get some free from{' '}
      <a href="https://lora.algokit.io/testnet/fund">Lora's dispenser</a> (sign in with an email account) or the{' '}
      <a href="https://testnet-dispenser.algorand.tech/">Algorand TestNet dispenser</a> (paste the address, solve a
      captcha).
    </p>
  )
}
