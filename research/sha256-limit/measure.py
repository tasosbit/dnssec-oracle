"""Measure DNSSEC signed-data sizes against the 4096-byte sha256 limit.

signed data = RRSIG rdata without signature (18 + signer name) + canonical RRset
"""
import sys, json, urllib.request, concurrent.futures as cf
import dns.message, dns.query, dns.name, dns.rdatatype, dns.zone, dns.flags

RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
LIMIT = 4096


def ask(name, rdtype):
    q = dns.message.make_query(name, rdtype, want_dnssec=True)
    q.flags |= dns.flags.CD
    last = None
    for r in RESOLVERS:
        for _ in range(2):
            try:
                return dns.query.tcp(q, r, timeout=6)
            except Exception as e:  # noqa
                last = e
    raise last


def rrset_bytes(rrset):
    owner = len(rrset.name.to_wire())
    return sum(owner + 10 + len(rd.to_wire()) for rd in rrset)


def measure(name, rdtype):
    """-> dict or None. size is the largest signed data over all RRSIGs."""
    name = dns.name.from_text(name)
    rdt = dns.rdatatype.from_text(rdtype)
    resp = ask(name, rdt)
    rrset = resp.find_rrset(resp.answer, name, 1, rdt) if any(
        r.rdtype == rdt and r.name == name for r in resp.answer) else None
    if rrset is None:
        return None
    sigs = [r for r in resp.answer if r.rdtype == dns.rdatatype.RRSIG and r.name == name
            and r.covers == rdt]
    body = rrset_bytes(rrset)
    out = {"name": str(name), "type": rdtype, "n": len(rrset), "rrset": body,
           "signed": bool(sigs)}
    if sigs:
        sig = sigs[0]
        out["signers"] = sorted({str(s.signer) for s in sig})
        out["algs"] = sorted({int(s.algorithm) for s in sig})
        out["wild"] = any(s.labels < len(name.labels) - 1 for s in sig)
        out["size"] = max(18 + len(s.signer.to_wire()) for s in sig) + body
    else:
        out["size"] = 18 + 1 + body
    if rdt == dns.rdatatype.DNSKEY:
        out["keys"] = sorted(
            (int(k.flags), int(k.algorithm), len(k.to_wire())) for k in rrset)
    return out


def tlds():
    txt = urllib.request.urlopen("https://www.internic.net/domain/root.zone", timeout=60).read().decode()
    z = dns.zone.from_text(txt, origin=".", relativize=False, check_origin=False)
    ds = {}
    for name, node in z.nodes.items():
        if len(name.labels) != 2:
            continue
        rds = node.get_rdataset(1, dns.rdatatype.DS)
        if rds:
            owner = len(name.to_wire())
            ds[str(name)] = {"n": len(rds),
                             "size": 18 + 1 + sum(owner + 10 + len(r.to_wire()) for r in rds),
                             "digests": sorted({int(r.digest_type) for r in rds})}
    rootkeys = z.nodes[dns.name.root].get_rdataset(1, dns.rdatatype.DNSKEY)
    return ds, rootkeys


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "tlds":
        ds, _ = tlds()
        res, errs = {}, {}

        def one(t):
            try:
                return t, measure(t, "DNSKEY"), None
            except Exception as e:  # noqa
                return t, None, repr(e)
        with cf.ThreadPoolExecutor(24) as ex:
            for t, m, e in ex.map(one, sorted(ds)):
                if m:
                    res[t] = m
                else:
                    errs[t] = e
        json.dump({"ds": ds, "dnskey": res, "errs": errs}, open(sys.argv[2], "w"))
        print(len(ds), "signed TLDs;", len(res), "DNSKEY measured;", len(errs), "failed")
    else:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            name, rdtype = line.split()
            try:
                m = measure(name, rdtype)
            except Exception as e:  # noqa
                print(f"{name:45} {rdtype:7} ERROR {e!r}")
                continue
            if not m:
                print(f"{name:45} {rdtype:7} -")
                continue
            extra = " ".join(f"{f}/{a}/{l}B" for f, a, l in m.get("keys", []))
            print(f"{name:45} {rdtype:7} n={m['n']:<3} size={m['size']:<5} "
                  f"{'signed' if m['signed'] else 'UNSIGNED'} {'WILDCARD ' if m.get('wild') else ''}"
                  f"{','.join(m.get('signers', []))} alg={m.get('algs', '')} {extra}")
