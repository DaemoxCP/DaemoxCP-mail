"""Id del DOM, classi CSS e altri nomi col trattino: a parola intera, mai dentro un nome piu' lungo.

Un id attraversa quattro parti (markup, JavaScript, CSS, prove da browser) e nessun compilatore lo
segue. I nomi della mappa sono distintivi (camelCase o col trattino), quindi si cambiano ovunque
compaiano come parola intera: il confine e' tutto cio' che non e' lettera, cifra, _ o -. Un nome che
finisce col trattino ('filtro-') e' un prefisso: vale anche seguito da ' o ` o $ (id costruiti).
Mai i file di lingua. Le parole comuni (pacchetti, aggiornamenti) non vanno in mappa: compaiono
anche nei testi e nei nomi di file, e si cambiano a mano solo dove sono id.

Uso: python3 tools/dom_names.py <radice> <mappa.txt> [--dry]
"""
import re, sys, glob, collections
root, mapfile = sys.argv[1], sys.argv[2]
dry = "--dry" in sys.argv
mp = dict(l.split() for l in open(mapfile, encoding="utf-8") if l.strip() and not l.startswith("#"))
alt = "|".join(sorted(map(re.escape, mp), key=len, reverse=True))
rx = re.compile(r"(?<![A-Za-z0-9_\-])(" + alt + r")(?![A-Za-z0-9_\-])")
files = glob.glob(f"{root}/src/main/java/**/*.java", recursive=True) + glob.glob(f"{root}/src/main/resources/pages/*") \
      + glob.glob(f"{root}/tests/**/*.java", recursive=True) + glob.glob(f"{root}/tests/*.js")
counts = collections.Counter()
for f in sorted(files):
    t = open(f, encoding="utf-8").read()
    def r(m):
        counts[m.group(1)] += 1
        return mp[m.group(1)]
    t2 = rx.sub(r, t)
    # un prefisso col trattino davanti a ' " ` $ : la lookahead sopra lo esclude se segue una lettera
    if t2 != t and not dry: open(f, "w", encoding="utf-8").write(t2)
for k in mp: print(f"  {counts[k]:3} {k} -> {mp[k]}")
print("mai trovati:", [k for k in mp if not counts[k]])
