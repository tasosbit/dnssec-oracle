#!/usr/bin/env bash
# Daily DNSSEC capture, for rollover test data that cannot be recreated later.
#
# Keep it running until KSK-2017 (20326) has been seen with the REVOKE flag,
# about 2027-01-11. The root KSK rolls on 2026-10-11.
#
# Writes captures/<UTC date>/:
#   dig.txt      presentation format, from dig alone: the fallback if node breaks
#   chains.json  wire format for the prover and the test fixtures
#   alerts.txt   only when a deployment assumption changed (see capture.mts)
#
# Install: crontab -e, then
#   17 3 * * * /home/bit/code/dnssec-oracle/scripts/capture-root.sh >> /home/bit/code/dnssec-oracle/captures/cron.log 2>&1
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DAY="$(date -u +%F)"
OUT="$ROOT/captures/$DAY"
mkdir -p "$OUT"
# cron starts with a bare PATH
export PATH="$HOME/.nvm/versions/node/v22.19.0/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

# One name per target TLD.
NAMES=(_dmarc.publicnode.com _dmarc.nodely.io _dmarc.folks.finance _dmarc.mercury.co)

{
  echo "; captured $(date -u +%FT%TZ)"
  # the root straight from a root server, so no resolver sits in between
  dig @a.root-servers.net . DNSKEY +dnssec +norec +tcp +multi
  for name in "${NAMES[@]}"; do
    labels=(${name//./ })
    # every zone on the path, root excluded: com, publicnode.com, ...
    for ((i = ${#labels[@]} - 1; i >= 0; i--)); do
      zone="$(IFS=.; echo "${labels[*]:i}")"
      dig @1.1.1.1 "$zone" DS +dnssec +tcp +multi
      dig @1.1.1.1 "$zone" DNSKEY +dnssec +tcp +multi
    done
    dig @1.1.1.1 "$name" TXT +dnssec +tcp +multi
  done
} > "$OUT/dig.txt" 2>&1
dig_status=$?

pnpm --dir "$ROOT/projects/dnssec-oracle-sdk" exec tsx scripts/capture.mts "$OUT" "${NAMES[@]}"
node_status=$?

echo "$(date -u +%FT%TZ) dig=$dig_status node=$node_status $OUT"
[ -s "$OUT/alerts.txt" ] && { echo "ALERT:"; cat "$OUT/alerts.txt"; } >&2
exit $((dig_status || node_status))
