"""Changes exact values written as strings: "old", 'old', \\"old\\", \\'old\\'.

For the values that are not names of anything and that the compiler cannot follow: codes and
verdicts sent to the page, actions, confirmation tokens, routes. Only the WHOLE string: a value
inside a longer text stays. Only src/main (Java and pages), never the language files: there the
same words are the text the user reads. In the tests an Italian code and its Italian text are
often the same string, so the tests are listed (--tests) and decided by hand.

Map: one line per value, old<TAB>new (there are spaces and apostrophes).
Usage: python3 tools/literal_values.py <root> <map.txt> [--dry] [--tests]"""
import re, sys, glob, collections
root, mapfile = sys.argv[1], sys.argv[2]
dry, tests = "--dry" in sys.argv, "--tests" in sys.argv
mp = dict(l.rstrip("\n").split("\t") for l in open(mapfile, encoding="utf-8") if "\t" in l and not l.startswith("#"))
alt = "|".join(sorted(map(re.escape, mp), key=len, reverse=True))
# the same quote (with or without a backslash) before and after, and nothing else in between
rx = re.compile(r"""(\\?)(["'])(""" + alt + r""")\1\2""")
counts = collections.Counter()
if tests:
    for f in sorted(glob.glob(f"{root}/tests/**/*.java", recursive=True) + glob.glob(f"{root}/tests/*.js")):
        for n, l in enumerate(open(f, encoding="utf-8"), 1):
            for m in rx.finditer(l): print(f"{f[len(root)+1:]}:{n}: {m.group(3)!r} :: {l.strip()[:140]}")
    sys.exit(0)
files = glob.glob(f"{root}/src/main/java/**/*.java", recursive=True) + glob.glob(f"{root}/src/main/resources/pages/*")
for f in sorted(files):
    t = open(f, encoding="utf-8").read()
    def r(m):
        counts[(f.split("/")[-1], m.group(3))] += 1
        return m.group(1) + m.group(2) + mp[m.group(3)] + m.group(1) + m.group(2)
    t2 = rx.sub(r, t)
    if t2 != t and not dry: open(f, "w", encoding="utf-8").write(t2)
by = collections.Counter()
for (f, v), c in counts.items(): by[v] += c
for v in mp: print(f"  {by[v]:3}  {v!r} -> {mp[v]!r}   {', '.join(f'{f}:{c}' for (f, w), c in sorted(counts.items()) if w == v)}")
missing = [v for v in mp if not by[v]]
print(f"valori: {len(mp)}, cambiati: {sum(by.values())}{' (a secco)' if dry else ''}; mai trovati: {missing}")
