# @d13co/dnssec-oracle

Command-line operator for the DNSSEC oracle: deploy, admin, credits, proofs and reads, as a thin layer over `@d13co/dnssec-oracle-sdk`.

## Quick start

```sh
pnpm install && algokit project run build   # from the repo root: contract → SDK → CLI
cd projects/cli
cp env.example .env                          # LocalNet by default; set MNEMONIC
node dist/index.js --help
```

Or run it straight from the repo, no checkout (npm builds a bundle on first run):

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

### Credits and rent

```sh
dnssec-oracle deposit-credits 2 [--creditor <address>]
dnssec-oracle withdraw-credits
dnssec-oracle prune <name> [--type 16]   # 16: expired attestation; 48/43: expired DNSKEY/DS cache entry
```

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
