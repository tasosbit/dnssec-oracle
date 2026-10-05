# @d13co/dnssec-oracle

Command-line operator for the DNSSEC oracle: deploy, admin, credits, proofs and reads, as a thin layer over `@d13co/dnssec-oracle-sdk`.

## Quick start

Try it on TestNet with npx. `-n testnet` presets a public node and the deployed oracle (app 772959888), and read commands need no account:

```sh
npx @d13co/dnssec-oracle -n testnet --help
npx @d13co/dnssec-oracle -n testnet state      # oracle state
npx @d13co/dnssec-oracle -n testnet anchors    # root trust anchors
npx @d13co/dnssec-oracle -n testnet list       # every attestation
npx @d13co/dnssec-oracle -n testnet verify     # is the pinned app this contract, anchored to IANA, admin renounced?
```

Write commands such as `prove` need a signer. Put its mnemonic in a `.env` in the directory you run from:

```sh
echo 'MNEMONIC="word1 word2 ... word25"' > .env && chmod 600 .env
npx @d13co/dnssec-oracle -n testnet prove _dmarc.nodely.io
```

> [!WARNING]
> **Use a throwaway TestNet account, never a real mnemonic.** Create a fresh one (`algokit goal account new`, or any wallet) and fund it from the [TestNet dispenser](https://lora.algokit.io/testnet/fund) or the [other TestNet dispenser](https://testnet-dispenser.algorand.tech/). Don't reuse a mnemonic that holds MainNet funds: the same words sign on every network. See [Signing with a mnemonic](#signing-with-a-mnemonic).

The examples below write `dnssec-oracle`; with npx that is `npx @d13co/dnssec-oracle`.

### From a checkout

```sh
pnpm install && algokit project run build   # from the repo root: contract → SDK → CLI
cd projects/cli
cp env.example .env                          # LocalNet by default; set MNEMONIC
node dist/index.js --help
```

Or run it straight from the GitHub repo, no checkout (npm builds a bundle on first run):

```sh
npx github:tasosbit/dnssec-oracle --help
```

## Build from source

```sh
pnpm run build:ts                      # dist/index.js
pnpm run build:executables             # every bun target → dist-exe/standalone/
pnpm run build:executables linux-x64   # one target
```

## Commands

### Deploy

```sh
dnssec-oracle deploy --anchors 2017,2024
```

`deploy` runs the two steps below one after the other from the same admin account. If setup fails, the app is already created: finish it with `APP_ID=<id> dnssec-oracle setup ...` instead of deploying again.

```sh
dnssec-oracle create                                   # prints the App ID
dnssec-oracle setup --anchors 2017,2024
```

`setup` funds the app, deposits exactly the credits the anchor boxes need, and adds the anchors, all in one group. Until the root KSK roll of 2026-10-11 completes, set up with both 2017 and 2024; after it, 2024 alone does. Every later box (caches, attestations) is paid from the sender's credits: `prove` deposits them itself, or run `deposit-credits` first and pass `--no-auto-credits`.

### Prove

```sh
dnssec-oracle prove _dmarc.nodely.io                         # live DNS, 1.1.1.1 over TCP
dnssec-oracle prove _dmarc.nodely.io --resolver 9.9.9.9
dnssec-oracle prove _dmarc.nodely.io --captured ../../captures/2026-09-29/chains.json
```

This proves the root, then the DS and DNSKEY for each zone, then the TXT. Cache entries already stored and more than `--refresh-margin` seconds (default 3600) from expiry are skipped. Running any `prove` from cron keeps the root DNSKEY entry fresh (docs/plan.md trust point 11).

By default `prove` estimates the box rent the chain needs (a cache box per entry not yet stored, plus the attestation), pads it by 10%, nets out credits already held, and asks before depositing the difference. Once proven it withdraws all of the signer's credits; if proving fails they stay deposited, for a retry or `withdraw-credits`. Withdrawing deletes the credit box, and a deleted attestation refunds its payer only into one: if your attestation may be replaced by someone else or pruned (by you included), keep a deposit, or the refund stays in the app. `--no-auto-credits` skips all of this and draws on credits already held.

If the name already has an attestation, `prove` shows it and asks before re-proving. From cron, pass `--no-auto-credits --reprove` so it never prompts.

### Root rollover

```sh
dnssec-oracle maintain-anchors      # daily from cron: RFC 5011 events for the root KSKs
```

Revokes anchors that sign their own revocation, proves the current root DNSKEY RRset, then applies every event it implies: Add a new KSK (AddPend), Promote it after 30 days, Reset or Miss a key that left, Return one that came back, Retire a revoked one after 30 days. New anchor boxes are paid from the signer's credits and deleted ones refunded to them.

### Read

```sh
dnssec-oracle state                 # admin, anchorCount, rollInception
dnssec-oracle anchors               # root anchors: AddPend, Valid, Missing or Revoked
dnssec-oracle get <name>...         # attestations: TXT text, validity, key strength, payer
dnssec-oracle list                  # every attestation, by sha256(wire name)
dnssec-oracle caches                # every DNSKEY/DS cache entry
dnssec-oracle keys <zone>           # a zone's DNSKEY/DS in DNS vs the oracle: cache, KSK/ZSK, DS links, anchors
dnssec-oracle credits [address]
```

`keys` takes `--resolver` and `--captured` like `prove`. To check its output against IANA's trust anchors and plain dig, see [Verifying anchors and zone keys](../../README.md#verifying-anchors-and-zone-keys).

### Admin

```sh
dnssec-oracle set-admin <address>   # the zero address renounces; needs --yes
```

### Verify a deployment

```sh
dnssec-oracle verify                                   # algod only
dnssec-oracle verify --iana --rebuild                  # plus IANA's live file and a fresh compile
```

```
✔ program   approval and clear programs match APP_SPEC (puya 5.10.1), approval sha256 8df1cea61bd6a82a…
✔ rebuild   rebuilt programs (puya 5.10.1) match the chain
✔ actions   no UpdateApplication or DeleteApplication action in the ARC-56 spec (16 methods, bare create NoOp)
✔ anchors   tag 38696 Valid (IANA), tag 20326 Valid (IANA); IANA file agrees
✔ admin     renounced (zero address)
✔ rootKeys  rootEpoch 1, rollInception none, anchors 2 Valid
verified
```

One line per check, `✔` pass, `!` warn, `✖` fail, `-` skip, then a verdict; the exit code is 1 when
any check fails. What each check settles:

| Check | Passes when |
|---|---|
| `program` | The on-chain approval and clear programs are byte-for-byte the bytecode bundled in the SDK (`APP_SPEC.byteCode`), which CI ties to the contract source. |
| `rebuild` | With `--rebuild`: a fresh `puya-ts` compile of the sources shipped in the SDK package (`contract/`) matches the chain too. Skips when no `puya-ts` is found (the repo's contract project has one); warns rather than fails when the local compiler version differs from the one that built the bundle. |
| `actions` | The ARC-56 spec declares no `UpdateApplication` or `DeleteApplication` action, bare or on a method: the program cannot be replaced or removed. |
| `anchors` | `addAnchors` ran, every anchor box is `sha256(alg ‖ pubkey)` of a known root KSK (the SDK's pinned KSK-2017/2024, `--known-anchor`, or with `--iana` a key listed in IANA's file), and at least one anchor is Valid or Missing. The admin chose the initial set, so this is the check that it chose IANA's. With `--iana`, also that every pinned digest is still in `root-anchors.xml`; a key IANA lists that the SDK does not pin, or that the oracle does not anchor, is a warning. |
| `admin` | The `admin` global is the zero address: renounced. A live admin warns: it can only hand the role on, since `addAnchors` runs once. |
| `rootKeys` | Informational: `rootEpoch`, `rollInception` and the RFC 5011 state of each anchor. Warns about an AddPend whose 30-day hold-down has passed without a Promote or Reset: nobody is running `maintain-anchors`. |

On LocalNet the root is synthetic: `--known-anchor <base64>` names its KSK's DNSKEY RDATA so `anchors` can pass.

### Credits and rent

```sh
dnssec-oracle deposit-credits 2 [--creditor <address>]
dnssec-oracle withdraw-credits
dnssec-oracle prune <name> [--type 16]   # 16: expired attestation; 48/43: expired DNSKEY/DS cache entry
```

## Signing with a mnemonic

Read commands need no account. Write commands (`prove`, `deposit-credits`, `prune`, `deploy` and the rest) sign with the 25-word Algorand mnemonic in `MNEMONIC` or `--mnemonic`. The CLI derives the private key in memory, signs each transaction locally and sends only the signed transactions; it never stores the mnemonic or sends it anywhere. For a rekeyed account, `MNEMONIC` is the signing key's and `ADDRESS` the account it signs for.

Prefer `.env` (or `.env.testnet` with `ENV=testnet`) to `--mnemonic`, which leaves the words in your shell history and the process list. Keep that file out of git and readable only by you (`chmod 600 .env`).

> [!WARNING]
> **Never use a mnemonic that controls MainNet funds.** This CLI and the oracle are experimental and unaudited, and a mnemonic in a `.env` file or a shell is one leak away from an emptied account. Create a throwaway account for TestNet or LocalNet (`algokit goal account new`, or any wallet), fund it from a [TestNet dispenser](https://lora.algokit.io/testnet/fund), and use only that one here. The same mnemonic signs on every network.

## Configuration

| Variable | Flag | Default | Description |
|---|---|---|---|
| `ALGOD_HOST` | `--algod-host` | `localhost` | Algorand node host |
| `ALGOD_PORT` | `--algod-port` | `4001` | Port; `443` means https |
| `ALGOD_TOKEN` | `--algod-token` | LocalNet token | Node token |
| `APP_ID` | `--app-id` | | Oracle app ID (all commands but `create`) |
| `MNEMONIC` | `--mnemonic` | | Signer, for write commands |
| `ADDRESS` | `--address` | | Sender, when `MNEMONIC` signs for a rekeyed account |
| `DEBUG` | `--debug` | `false` | algokit logs, SDK tracing, stack traces |

Settings are read from `.env`, or from `.env.$ENV` when `ENV` is set (e.g. `ENV=testnet` → `.env.testnet`). Flags override the environment. `-n testnet` (`--network`) presets the Nodely testnet node and app 772959888 over the environment; other flags still override it, and `MNEMONIC`/`ADDRESS` still come from the environment.

LocalNet's block clock can lag the wall clock. When it does, proofs from live DNS fail with `sigTime` (RRSIG is not valid now), because their signatures look like they come from the future. Replay a capture with `--captured` instead.
