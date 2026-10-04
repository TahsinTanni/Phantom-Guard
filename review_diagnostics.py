"""
Reviewer diagnostics for Phantom Guard — reproduces every number in
reports/phantom_guard_review.md from data/frozen/incidents_snapshot.jsonl.

Run from the project_p0_edited folder:  python review_diagnostics.py
"""
from __future__ import annotations
import json, os, re, sys, collections, statistics as st
from pathlib import Path
HERE = Path(__file__).resolve().parent; os.chdir(HERE); sys.path.insert(0, str(HERE))
from scipy.stats import fisher_exact, mannwhitneyu
from src.labeling.malware_labeler import label_batch
from src.data.naming_grammar import classify_naming_grammar
from src.statistics.h1_pilot_analysis import (attach_grammar_labels, build_contingency_table,
    build_campaign_signature, collapse_to_campaign_level)

recs = [json.loads(l) for l in open("data/frozen/incidents_snapshot.jsonl", encoding="utf-8") if l.strip()]
j = attach_grammar_labels(label_batch(recs))
c = collapse_to_campaign_level(j)

def fisher(rs):
    t = build_contingency_table(rs); o, p = fisher_exact(t.as_2x2()); return t.as_2x2(), o, p

def H(s): print("\n" + "=" * 70 + f"\n{s}\n" + "=" * 70)

H("A. Sample size, honestly")
print("records", len(recs), "| unique (ecosystem, package)", len({(r['ecosystem'], r['package_name']) for r in recs}), "| campaigns", len(c))
print("published_at by month:", dict(sorted(collections.Counter((r.get('published_at') or '')[:7] for r in recs).items())))
print("campaign group sizes:", dict(sorted(collections.Counter(g['_member_count'] for g in c).items())))
for g in sorted(c, key=lambda x: -x["_member_count"])[:2]:
    print(f"  size={g['_member_count']} eco={g['ecosystem']} e.g. {g['_member_package_names'][:4]}  sig={build_campaign_signature(g)[1][:90]!r}")

H("B. IV: what drives the grammar flag, and base rate on famous legit names")
tok = collections.Counter()
for g in c:
    gm = g["grammar_match"]; tok.update(gm["matched_compound_suffixes"] + gm["matched_compound_prefixes"] + gm["matched_trend_suffixes"])
print("tokens (campaign level):", tok.most_common(12))
print("pattern_type:", dict(collections.Counter(g["grammar_match"]["matched_pattern_type"] for g in c)))
legit = ("requests numpy pandas boto3 flask django pytest click pyyaml urllib3 pyjwt pyopenssl python-dateutil "
         "google-api-python-client azure-core aws-cdk-lib react vue express lodash axios typescript eslint webpack jest "
         "react-dom next vite tailwindcss prettier @types/node @aws-sdk/client-s3 @azure/core-http openai-cli langchain-core ai pytorch-lightning").split()
fl = [n for n in legit if classify_naming_grammar(n).is_grammar_flagged]
print(f"flagged {len(fl)}/{len(legit)} popular legit names:", fl)

H("C. DV: GHSA vs OSV text disagreement, and its effect on H1")
by = collections.defaultdict(dict)
for r in j: by[(r["ecosystem"], r["package_name"])][r["source"]] = r
both = [v for v in by.values() if "ghsa" in v and "osv" in v]
agree = collections.Counter((v["ghsa"]["malware_label"]["malware_payload_present_candidate"],
                             v["osv"]["malware_label"]["malware_payload_present_candidate"]) for v in both)
print(f"packages with both texts: {len(both)}/{len(by)}  (ghsa_pos, osv_pos) counts: {dict(agree)}")
print("median description length ghsa/osv:", st.median(len(v['ghsa']['description']) for v in both), "/", st.median(len(v['osv']['description']) for v in both))
for label, pick in [("any-source (current 5.6)", None), ("GHSA text only", "ghsa"), ("OSV text only", "osv")]:
    rs = c if pick is None else collapse_to_campaign_level([v.get(pick) or v.get("osv" if pick == "ghsa" else "ghsa") for v in by.values()])
    t, o, p = fisher(rs); print(f"  {label:26s} table={t} OR={o:.3f} p={p:.3f}")
    if pick == "ghsa":
        for eco in ("npm", "pypi"):
            t, o, p = fisher([g for g in rs if g["ecosystem"] == eco]); print(f"      {eco}: table={t} OR={o:.3f} p={p:.3f}")
dis = [k for k, v in by.items() if v["osv"]["malware_label"]["malware_payload_present_candidate"] and not v["ghsa"]["malware_label"]["malware_payload_present_candidate"]]
print("OSV-only positives (hand-inspect these):", [k[1] for k in dis])

H("D. Reporter as confounder")
def reporter(r):
    d = r.get("description") or ""
    m = re.match(r"\s*##\s*Source:\s*([^\s(]+)", d)
    if m: return m.group(1)
    if "should be considered fully compromised" in d: return "<ghsa-boilerplate>"
    return "other"
tab = collections.defaultdict(lambda: [0, 0, 0, 0])
for g in c:
    f = g["grammar_match"]["is_grammar_flagged"]; o = g["malware_label"]["malware_payload_present_candidate"]
    tab[reporter(g)][0 if (f and o) else 1 if f else 2 if o else 3] += 1
print("campaign-level [flag&pos, flag&neg, noflag&pos, noflag&neg]:")
for k, v in sorted(tab.items(), key=lambda kv: -sum(kv[1])):
    n = sum(v); print(f"  {k:20s} n={n:3d} {v}  flag-rate={(v[0]+v[1])/n:.2f}  DV-rate={(v[0]+v[2])/n:.2f}")
bp = collections.defaultdict(lambda: [0, 0])
for r in j: bp[r["grammar_match"]["is_grammar_flagged"]][0 if "should be considered fully compromised" in (r.get("description") or "") else 1] += 1
for f, (b, nb) in bp.items(): print(f"  boilerplate when flagged={f}: {b}/{b+nb} = {b/(b+nb):.1%}")

H("E. Sensitivity rows")
def cats_of(g): return set().union(*(set(mm["malware_label"]["matched_categories"]) for m in g.get("_members", [g]) for mm in m.get("_members", [m]))) if "_members" in g else set(g["malware_label"]["matched_categories"])
# NOTE: upstream collapse_to_campaign_level() does not keep members; this script re-derives categories at name level.
name_level = {}
for r in j: name_level.setdefault((r["ecosystem"], r["package_name"]), set()).update(r["malware_label"]["matched_categories"])
def table_excluding(ex):
    a = b = cc = d = 0
    for g in c:
        cats = set().union(*(name_level[(g["ecosystem"], n)] for n in g["_member_package_names"])) - ({ex} if ex else set())
        f = g["grammar_match"]["is_grammar_flagged"]; o = bool(cats)
        if f and o: a += 1
        elif f: b += 1
        elif o: cc += 1
        else: d += 1
    return [[a, b], [cc, d]]
for ex in (None, "brand_impersonation_narrative", "remote_backdoor_access"):
    t = table_excluding(ex); o, p = fisher_exact(t); print(f"  exclude {str(ex):32s} table={t} OR={o:.3f} p={p:.3f}")
sc = {True: [], False: []}
for g in c:
    sc[g["grammar_match"]["is_grammar_flagged"]].append(len(set().union(*(name_level[(g["ecosystem"], n)] for n in g["_member_package_names"]))))
print(f"  ordinal DV (#categories): flagged mean={st.mean(sc[True]):.2f} vs not={st.mean(sc[False]):.2f}, Mann-Whitney p={mannwhitneyu(sc[True], sc[False]).pvalue:.3f}")
