"""Summarize tlds.json (from `measure.py tlds`) against the 4096-byte limit."""
import sys, json, collections

d = json.load(open(sys.argv[1]))
k, ds = d["dnskey"], d["ds"]
sizes = sorted(v["size"] for v in k.values())
n = len(sizes)
print("DNSKEY signed data, all", n, "signed TLDs")
print(" min/median/p95/p99/max:", sizes[0], sizes[n // 2], sizes[int(n * .95)],
      sizes[int(n * .99)], sizes[-1])
for b in (512, 1024, 1536, 2048, 3072, 4096):
    print(f"  > {b}: {sum(s > b for s in sizes)}")
print("top 15:")
for t, v in sorted(k.items(), key=lambda x: -x[1]["size"])[:15]:
    print(f"  {t:28} {v['size']:5}  n={v['n']} alg={v['algs']} "
          f"keys={[(f, l) for f, a, l in v['keys']]}")

dsz = sorted(v["size"] for v in ds.values())
print("DS signed data: median/max", dsz[len(dsz) // 2], dsz[-1],
      "max n", max(v["n"] for v in ds.values()))
for t, v in sorted(ds.items(), key=lambda x: -x[1]["size"])[:5]:
    print(f"  {t:28} {v['size']:5} n={v['n']} digests={v['digests']}")

main = ("com net org io co finance xyz dev app ai info biz me network tech cloud fi pro "
        "exchange money fund capital foundation art gg tv cc us uk de eu ch nl fr ca au "
        "jp in br sg").split()
print("mainstream:")
for t in main:
    v, s = k.get(t + "."), ds.get(t + ".")
    if not v:
        print(f"  {t:12} unsigned / not delegated")
        continue
    print(f"  {t:12} DNSKEY {v['size']:5} n={v['n']} alg={v['algs']} "
          f"keys={[(f, l) for f, a, l in v['keys']]}  DS {s['size']} n={s['n']}")

# projection: every key doubled at once (double-signature roll of KSK and ZSK together)
hdr = lambda t: 18 + len(t) + 1
worst = {t: hdr(t) + 2 * (v["size"] - hdr(t)) for t, v in k.items()}
print("TLDs over 4096 if every key were doubled:", sum(s > 4096 for s in worst.values()),
      "; largest", max(worst.values()))
print("algs:", dict(collections.Counter(tuple(v["algs"]) for v in k.values())))
