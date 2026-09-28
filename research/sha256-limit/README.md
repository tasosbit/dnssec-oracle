# Is the 4,096-byte `sha256` limit a practical concern?

Measured 2026-09-28 via 1.1.1.1 (TCP, DO bit). Question raised by `plan.md`,
"The one input format":

> Hard limit: `sha256` takes one value of at most 4,096 bytes and cannot
> stream, so signed data or a parent RRset above that size is unprovable.

**No.** Nothing on any measured chain exceeds 48% of the limit, provided TXT
records live in a dedicated subdomain such as `_algorand.example.com`. Apex
TXT is the only RRset that gets close, and the subdomain rule keeps it off
the path.

Size = signed data = RRSIG RDATA without the signature (18 B + signer name)
followed by the canonical RRset (owner + 10 B + RDATA per RR). A `parent`
RRset is the same bytes minus the RRSIG header, so it is always smaller.

## Results

| Proof row | Sample | Median | Max | Largest case |
|---|---|---|---|---|
| `. DNSKEY` | root | – | 1,119 B | 4 × RSA-2048; both KSKs already published |
| TLD `DS` | all 1,351 signed TLDs | 72 B | 199 B | `versicherung`, 3 DS |
| TLD `DNSKEY` | all 1,351 signed TLDs | 578 B | 1,962 B | `xn--mgbayh7gpa`, 3 × RSA-4096 KSK + RSA-2048 ZSK |
| Domain `DS` | 42 signed domains | 82 B | 139 B | `paypal.com`, 2 DS |
| Domain `DNSKEY` | 44 signed domains | 228 B | 908 B | `arin.net`, 2 × RSA-2048 + 2 × RSA-1024 |
| Subdomain `TXT` | 40 (`_dmarc.*`, one DKIM) | 159 B | 486 B | `google._domainkey.consensys.io`, 2048-bit DKIM key |
| Apex `TXT` | 7 signed provider apexes | – | 2,844 B | `consensys.io`, 32 records |

TLD `DNSKEY` distribution: 488 above 1,024 B, 1 above 1,536 B, 0 above 2,048 B.

### Whitelisted TLDs

| TLD | `DNSKEY` | Keys | `DS` |
|---|---|---|---|
| `com` | 189 B | 2 × P-256 | 70 B |
| `io` | 1,028 B | 2 × RSA-2048, 3 × RSA-1024 | 69 B |
| `finance` | 1,058 B | 2 × RSA-2048, 3 × RSA-1024 | 74 B |
| `co` | 910 B | 2 × RSA-2048, RSA-1280, RSA-1024 | 69 B |

Other mainstream TLDs (`net`, `org`, `xyz`, `dev`, `app`, `ai`, `info`, `me`,
`network`, `uk`, `de`, `eu`, …) range from 186 B to 1,076 B. Full list in
`tlds-summary.txt`.

### Provider domains from `rpc-providers.md`

| Domain | `DS` | `DNSKEY` | `_dmarc` TXT | Apex TXT |
|---|---|---|---|---|
| `chainstack.com` | 85 B | 222 B | 144 B | 1,489 B |
| `publicnode.com` | 85 B | 222 B | 199 B | 167 B |
| `llamanodes.com` | 85 B | 486 B | – | 157 B |
| `consensys.io` | 82 B | 216 B | 271 B | 2,844 B |
| `allnodes.com` | 83 B | 216 B | 181 B | 621 B |
| `flashbots.net` | 84 B | 219 B | 273 B | 339 B |
| `blastapi.io` | 81 B | 213 B | 139 B | 437 B |
| `cloudflare-eth.com` | 89 B | 234 B | – | – |

## Headroom

- **Rollovers.** Doubling every key in every TLD at once still leaves all
  1,351 under the limit; the largest reaches 3,890 B. This is a projection
  from one day's snapshot, not an observed rollover.
- **Breaking point.** About 14 RSA-2048 keys or 7 RSA-4096 keys in one
  `DNSKEY` RRset. No measured zone has more than 6 keys.
- **`_algorand.example.com` capacity.** About 4,030 B of TXT RDATA, roughly
  44 separate records each holding a 58-character address.
- **Wildcards.** No `_algorand.*` or `_dmarc.*` lookup returned a
  wildcard-synthesised answer.

## Where the limit does bite

Apex TXT: `consensys.io` is at 69% of the limit and apex sets only grow (SPF,
verification tokens). Covered by requiring a dedicated `_name.<domain>` TXT.

## Caveats

- One-day snapshot.
- TLD coverage is complete; the domain sample is hand-picked (`names.txt`),
  not exhaustive. A self-hosted zone with many large RSA keys could exist,
  but would need about 4× the largest one seen.
- `_dmarc` and DKIM stand in for `_algorand`, which no sampled domain
  publishes yet.
- Sizes only. Algorithms the contract rejects (5, 7, 10, 14, 15) are a
  separate question.

## Files

| File | What |
|---|---|
| `measure.py` | Queries and sizing |
| `summarize.py` | Distribution and projections from `tlds.json` |
| `names.txt` | Input: `name type` per line |
| `tlds.json` | Raw: `DS` and `DNSKEY` per signed TLD |
| `tlds-summary.txt` | Output of `summarize.py` |
| `domains.txt` | Output of `measure.py names` |

## Reproduce

```sh
uv run --with dnspython python measure.py tlds tlds.json
uv run --with dnspython python measure.py names < names.txt > domains.txt
python3 summarize.py tlds.json > tlds-summary.txt
```
