"""Cambia valori esatti scritti come stringhe: "vecchio", 'vecchio', \\"vecchio\\", \\'vecchio\\'.

Per i valori che non sono nomi di niente e che il compilatore non puo' seguire: codici e verdetti
mandati alla pagina, azioni, gettoni di conferma, rotte. Solo la stringa INTERA: un valore dentro
un testo piu' lungo resta. Solo src/main (Java e pagine), mai i file di lingua: li' le stesse parole
sono il testo che l'utente legge. Nelle prove un codice italiano e il suo testo italiano sono
spesso la stessa stringa, quindi le prove si elencano (--tests) e si decidono a mano.

Mappa: una riga per valore, vecchio<TAB>nuovo (ci sono spazi e apostrofi).
Uso: python3 tools/literal_values.py <radice> <mappa.txt> [--dry] [--tests]
"""
import re, sys, glob, collections
root, mapfile = sys.argv[1], sys.argv[2]
dry, tests = "--dry" in sys.argv, "--tests" in sys.argv
mp = dict(l.rstrip("\n").split("\t") for l in open(mapfile, encoding="utf-8") if "\t" in l and not l.startswith("#"))
alt = "|".join(sorted(map(re.escape, mp), key=len, reverse=True))
# la stessa virgoletta (con o senza barra) prima e dopo, e nient'altro in mezzo
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
