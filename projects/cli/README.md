# dnssec-oracle-cli

Command-line operator for the DNSSEC oracle: deploy, admin, credits, proofs and reads, as a thin layer over `dnssec-oracle-sdk`.

## Quick start

```sh
pnpm install && algokit project run build   # from the repo root: contract → SDK → CLI
cd projects/cli
cp env.example .env                          # LocalNet by default; set MNEMONIC
node dist/index.js --help
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

`setup` funds the app, deposits exactly the credits the anchor boxes need, and adds the anchors, all in one group. Until the root KSK roll of 2026-10-11 completes, set up with both 2017 and 2024; after it, 2024 alone does. Every later box (caches, attestations) is paid from the sender's credits, so run `deposit-credits` before proving.

### Prove

```sh
dnssec-oracle prove _dmarc.nodely.io                         # live DNS, 1.1.1.1 over TCP
dnssec-oracle prove _dmarc.nodely.io --resolver 9.9.9.9
dnssec-oracle prove _dmarc.nodely.io --captured ../../captures/2026-09-29/chains.json
```

This proves the root, then the DS and DNSKEY for each zone, then the TXT. Cache entries already stored and more than `--refresh-margin` seconds (default 3600) from expiry are skipped. Running any `prove` from cron keeps the root DNSKEY entry fresh (docs/plan.md trust point 11).

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
dnssec-oracle credits [address]
```

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

Settings are read from `.env`, or from `.env.$ENV` when `ENV` is set (e.g. `ENV=testnet` → `.env.testnet`). Flags override the environment.

LocalNet's block clock can lag the wall clock. When it does, proofs from live DNS fail with `TIM` (RRSIG is not valid now), because their signatures look like they come from the future. Replay a capture with `--captured` instead.
