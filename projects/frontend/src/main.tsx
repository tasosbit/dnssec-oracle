import './polyfills'
import { QueryClientProvider } from '@tanstack/react-query'
import { WalletId, WalletManager, WalletProvider } from '@txnlab/use-wallet-react'
import { WalletUIProvider } from '@txnlab/use-wallet-ui-react'
import '@txnlab/use-wallet-ui-react/dist/style.css'
import { createRoot } from 'react-dom/client'
import { Toaster } from 'sonner'
import { App } from './App'
import { queryClient } from './queries'
import './styles.css'

// KMD is LocalNet's (it talks to 127.0.0.1:4002); App keeps the manager's network on the app's
const wallets = new WalletManager({
  wallets: [
    WalletId.PERA,
    WalletId.DEFLY,
    { id: WalletId.LUTE, options: { siteName: 'DNSSEC Oracle Explorer' } },
    WalletId.KMD,
  ],
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
