# Ethereum RPC providers: DNSSEC status

Checked 2026-09-28 via 1.1.1.1. "Signed" = DS in parent + `delv` reports `fully validated`.
Top 10 is a judgement of market share / mindshare, not an authoritative ranking.

## Top 10

| # | Provider | Apex | RPC host | Apex | RPC host | Alg |
|---|---|---|---|---|---|---|
| 1 | Infura | `infura.io` | `mainnet.infura.io` | ❌ | ❌ | – |
| 2 | Alchemy | `alchemy.com` | `eth-mainnet.g.alchemy.com` | ❌ | ❌ | – |
| 3 | QuickNode | `quicknode.com` | `*.quiknode.pro` | ❌ | ❌ | – |
| 4 | Ankr | `ankr.com` | `rpc.ankr.com` | ❌ | ❌ | – |
| 5 | **Chainstack** | `chainstack.com` | `ethereum-mainnet.core.chainstack.com` | ✅ | ✅ | 13 |
| 6 | dRPC | `drpc.org` | `eth.drpc.org` | ❌ | ❌ | – |
| 7 | **PublicNode** | `publicnode.com` | `ethereum-rpc.publicnode.com` | ✅ | ✅ | 13 |
| 8 | LlamaNodes | `llamanodes.com` | `eth.llamarpc.com` | ✅ | ❌ | 8 (2048 KSK / 1024 ZSK) |
| 9 | GetBlock | `getblock.io` | `go.getblock.io` | ❌ | ❌ | – |
| 10 | Tenderly | `tenderly.co` | `mainnet.gateway.tenderly.co` | ❌ | ❌ | – |

Parent companies: `consensys.io` (Infura) ✅ alg 13; `allnodes.com` (PublicNode) ✅ alg 13.

## Next tier

| Provider | RPC host | Signed | Notes |
|---|---|---|---|
| Flashbots | `rpc.flashbots.net` | ✅ 13 | |
| Blast API | `eth-mainnet.public.blastapi.io` | ✅ 13 | |
| Cloudflare | `cloudflare-eth.com` | ✅ 13 | gateway dead: every call returns "Cannot fulfill request" |
| BlockPI | `ethereum.blockpi.network` | ❌ | |
| NOWNodes | `eth.nownodes.io` | ❌ | |
| 1RPC | `1rpc.io` | ❌ | |
| MEV Blocker | `rpc.mevblocker.io` | ❌ | |
| Moralis | `*.moralis-nodes.com` | ❌ | |

## Apex TXT signed-blob size (signed zones)

RRSIG rdata + canonical RRset; must be ≤ 4096 B to hash on-chain.

| Apex | Records | Blob |
|---|---|---|
| `consensys.io` | 32 | ~2.8 KB |
| `chainstack.com` | 15 | ~1.5 KB |
| `allnodes.com` | 6 | ~620 B |
| `blastapi.io` | 5 | ~440 B |
| `flashbots.net` | 3 | ~340 B |
| `publicnode.com` | 2 | ~170 B |
| `llamanodes.com` | 1 | ~160 B |

## Takeaways

- Only 2/10 (Chainstack, PublicNode) sign their own RPC domain; both are alg 13 on Cloudflare DNS.
- Signed providers under `.com`/`.net` need no RSA below the root. `.io` adds one RSA-1024 ZSK verify (~29k).
- Apex TXT sets fit today but can grow past 4 KB; require a dedicated `_name.<domain>` TXT.

## Reproduce

```sh
dig +short DS <domain> @1.1.1.1      # empty = unsigned
delv @1.1.1.1 <host> A               # "; fully validated" vs "; unsigned answer"
```
