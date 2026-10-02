import { useEffect, useMemo, useState } from 'react'
import { DEFAULT_APP_ID, makeSdk, Network } from './oracle'
import { StateView } from './StateView'
import { VerifyView } from './VerifyView'

type Tab = 'state' | 'verify'

export function App() {
  const params = new URLSearchParams(location.search)
  const [network, setNetwork] = useState<Network>(params.get('network') === 'localnet' ? 'localnet' : 'testnet')
  const [appId, setAppId] = useState(params.get('app') ?? DEFAULT_APP_ID[network])
  const [tab, setTab] = useState<Tab>(params.get('tab') === 'verify' ? 'verify' : 'state')
  const [name, setName] = useState(params.get('name') ?? '')

  // shareable: the URL carries the view
  useEffect(() => {
    const q = new URLSearchParams({ network, app: appId, tab, ...(tab === 'verify' && name ? { name } : {}) })
    history.replaceState(null, '', `?${q}`)
  }, [network, appId, tab, name])

  const oracle = useMemo(
    () => (/^\d+$/.test(appId) ? { sdk: makeSdk(network, appId), network, appId } : undefined),
    [network, appId],
  )
  const verify = (n: string) => {
    setName(n)
    setTab('verify')
  }

  return (
    <>
      <header>
        <div className="brand">
          <h1>DNSSEC Oracle Explorer</h1>
          <p>
            An Algorand app that verifies DNSSEC signature chains from the root down to a TXT record, and stores the
            result for other apps to read. Nobody is trusted to relay DNS: the contract checks every signature itself.
          </p>
        </div>
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
            <input value={appId} onChange={(e) => setAppId(e.target.value.trim())} placeholder="app ID" size={12} />
          </label>
        </div>
        <nav>
          <button className={tab === 'state' ? 'active' : ''} onClick={() => setTab('state')}>
            Oracle state
          </button>
          <button className={tab === 'verify' ? 'active' : ''} onClick={() => setTab('verify')}>
            Verify a name
          </button>
        </nav>
      </header>
      <main>
        {!oracle ? (
          <p className="error">Enter the oracle's app ID.</p>
        ) : tab === 'state' ? (
          <StateView oracle={oracle} onVerify={verify} />
        ) : (
          <VerifyView oracle={oracle} name={name} onName={setName} />
        )}
      </main>
      <footer>
        Experimental and unaudited. <a href="https://github.com/tasosbit/dnssec-oracle">Source and docs</a>
      </footer>
    </>
  )
}
