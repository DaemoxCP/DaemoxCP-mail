"""DOM ids, CSS classes and other hyphenated names: as a whole word, never inside a longer name.

An id crosses four parts (markup, JavaScript, CSS, browser tests) and no compiler follows
it. The names in the map are distinctive (camelCase or hyphenated), so they are changed wherever
they appear as a whole word: the boundary is anything that is not a letter, a digit, _ or -. A name
that ends with a hyphen ('filtro-') is a prefix: it also holds when followed by ' or ` or $ (built ids).
Never the language files. The common words (pacchetti, aggiornamenti) do not go in the map: they
also appear in the texts and in file names, and are changed by hand only where they are ids.

Usage: python3 tools/dom_names.py <root> <map.txt> [--dry]"""
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
    # a hyphenated prefix before ' " ` $ : the lookahead above excludes it if a letter follows
    if t2 != t and not dry: open(f, "w", encoding="utf-8").write(t2)
for k in mp: print(f"  {counts[k]:3} {k} -> {mp[k]}")
print("mai trovati:", [k for k in mp if not counts[k]])
