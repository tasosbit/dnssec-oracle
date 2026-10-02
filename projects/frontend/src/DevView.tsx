import { DEFAULT_APP_ID } from './oracle'
import { Oracle } from './queries'
import { Section } from './ui'

const REPO = 'https://github.com/tasosbit/dnssec-oracle/tree/main/projects'

export function DevView({ oracle }: { oracle: Oracle }) {
  const { network, appId } = oracle
  // -n testnet presets the default testnet app
  const cli =
    network === 'testnet'
      ? `-n testnet${appId === DEFAULT_APP_ID.testnet ? '' : ` --app-id ${appId}`}`
      : `--app-id ${appId}`
  const client = network === 'testnet' ? 'AlgorandClient.testNet()' : 'AlgorandClient.defaultLocalNet()'
  return (
    <>
      <Section
        title="CLI"
        about={
          <>
            <code>@d13co/dnssec-oracle</code> reads the oracle, proves records and manages credits from a terminal.
            Reads need no account. Writes sign locally with the 25-word mnemonic in <code>MNEMONIC</code> (from the
            environment or a <code>.env</code> file), which never leaves your machine.{' '}
            <a href={`${REPO}/cli#readme`}>Full reference</a>
          </>
        }
      >
        <p className="warn">
          <strong>Never use a mnemonic that controls MainNet funds.</strong> The oracle and its tools are experimental
          and unaudited, and a mnemonic in a file or a shell is one leak from an emptied account. Make a throwaway
          TestNet account and fund it from a <a href="https://lora.algokit.io/testnet/fund">dispenser</a>.
        </p>
        <pre>
          <code>{`(umask 077; touch .env)    # readable only by you; then put MNEMONIC="word1 … word25" in it with an editor
npx @d13co/dnssec-oracle ${cli} get example.com      # read an attestation
npx @d13co/dnssec-oracle ${cli} prove example.com    # prove it from live DNS
npx @d13co/dnssec-oracle ${cli} credits <address>
npx @d13co/dnssec-oracle --help`}</code>
        </pre>
      </Section>
      <Section
        title="SDK"
        about={
          <>
            <code>@d13co/dnssec-oracle-sdk</code> is the TypeScript client this explorer runs on: read, prove and prune
            from your own app, plus the reader contracts import to check attestations on-chain.{' '}
            <a href={`${REPO}/dnssec-oracle-sdk#readme`}>Full reference</a>
          </>
        }
      >
        <pre>
          <code>{`npm install @d13co/dnssec-oracle-sdk @algorandfoundation/algokit-utils`}</code>
        </pre>
        <pre>
          <code>{`import { AlgorandClient } from '@algorandfoundation/algokit-utils'
import { DnssecOracleSDK } from '@d13co/dnssec-oracle-sdk'

const sdk = new DnssecOracleSDK({
  algorand: ${client},
  appId: ${appId}n,
  writerAccount: { sender, signer }, // or DnssecOracleReaderSDK to only read
})

// the attestation, if usable now: unexpired, signed within maxAge, no key under minKeyBits
const verified = await sdk.getVerifiedAttestation('example.com', { maxAge: 86_400, minKeyBits: 2048 })

await sdk.depositCredits({ amount: 1_000_000n }) // box rent, in µAlgo; withdraw any time
await sdk.proveTxt('example.com')`}</code>
        </pre>
      </Section>
    </>
  )
}
