import './polyfills'
import { QueryClientProvider } from '@tanstack/react-query'
import { WalletManager, WalletProvider } from '@txnlab/use-wallet-react'
import { WalletUIProvider } from '@txnlab/use-wallet-ui-react'
import '@txnlab/use-wallet-ui-react/dist/style.css'
import { defly } from '@txnlab/use-wallet-defly'
import { kmd } from '@txnlab/use-wallet-kmd'
import { lute } from '@txnlab/use-wallet-lute'
import { pera } from '@txnlab/use-wallet-pera'
import { createRoot } from 'react-dom/client'
import { Toaster } from 'sonner'
import { App } from './App'
import { queryClient } from './queries'
import './styles.css'

// KMD is LocalNet only (the adapter says so); App keeps the manager's network on the app's
const wallets = new WalletManager({
  wallets: [pera(), defly(), lute({ siteName: 'DNSSEC Oracle Explorer' }), kmd()],
  defaultNetwork: new URLSearchParams(location.search).get('network') === 'localnet' ? 'localnet' : 'testnet',
})

createRoot(document.getElementById('root')!).render(
  <QueryClientProvider client={queryClient}>
    <WalletProvider manager={wallets}>
      <WalletUIProvider theme="system">
        <App />
        <Toaster theme="system" richColors closeButton />
      </WalletUIProvider>
    </WalletProvider>
  </QueryClientProvider>,
)
