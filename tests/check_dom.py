#!/usr/bin/env python3
"""Lo spazio dei nomi del DOM attraversa QUATTRO superfici, non tre:
   pages/*.js, pages/*.html, il JavaScript dentro i .java, e tests/*.js.
Le prove da browser sono CONSUMATRICI: cercano id e selettori che l'applicazione
deve creare, ma non ne creano nessuno. Non guardarle ha fatto passare 35
riferimenti morti quando la famiglia "ramo" e' diventata "branch".

Verifica sull'unione:
  - ogni funzione chiamata da un attributo on* e' dichiarata da qualche parte
  - ogni id cercato dall'applicazione e' creato da qualche parte
  - ogni id/selettore cercato dalle PROVE e' creato dall'applicazione

Tre cose che vanno sapute, o la rete urla a vuoto:
  - passwordField("X") genera id X, XErr, XShow, XCopy via %1$s
  - gli id costruiti ('ver-' + k) danno un PREFISSO, non un id
  - nelle prove, un selettore con .count() === 0 asserisce che NON c'e'
"""
import re, sys, glob, os

# La radice e' il primo argomento che NON e' un'opzione. Prima era argv[1] qualunque fosse,
# quindi "check_dom.py --quiet" prendeva "--quiet" per una cartella: i glob non trovavano
# niente, la rete stampava zero problemi e usciva ZERO. Un controllo che non puo' fallire e'
# peggio di nessun controllo, e questo non poteva nemmeno accorgersene.
folders = [a for a in sys.argv[1:] if not a.startswith("-")]
root = folders[0] if folders else "."
quiet = "--quiet" in sys.argv

def read_sources(pats, rec=False):
    out = []
    for p in pats:
        for f in sorted(glob.glob(os.path.join(root, p), recursive=rec)):
            try: out.append((f, open(f, encoding='utf-8', errors='replace').read()))
            except Exception: pass
    return out

app  = read_sources(['src/main/resources/pages/*.js', 'src/main/resources/pages/*.html'])
app += read_sources(['src/main/java/**/*.java'], rec=True)
test_sources = read_sources(['tests/*.js'])
A = "\n".join(s for _, s in app)

# ---- handler chiamati da on* ----
# tutto il VALORE dell'attributo, poi ogni chiamata dentro: onkeyup="if(...)loadLogs()"
# ne contiene due, e la vecchia rete vedeva solo "if", che e' una parola chiave.
ATTR = re.compile(r'on(?:click|change|input|submit|keyup|focus|blur)\s*=\s*\\{0,2}(["\'])((?:(?!\1)[^\\]|\\.)*)\1')
KW = {'if','else','for','while','do','switch','case','return','typeof','instanceof',
      'new','delete','void','function','this','try','catch','finally','throw','await','in','of'}
GLOBAL_NAMES = {'Number','String','Boolean','Array','Object','JSON','Math','Date','parseInt',
           'parseFloat','encodeURIComponent','decodeURIComponent','alert','confirm','prompt',
           'setTimeout','setInterval','getElementById','querySelector','querySelectorAll'}
calls = set()
for m in ATTR.finditer(A):
    v = m.group(2)
    for c in re.finditer(r'([A-Za-z_$][\w$]*)\s*\(', v):
        if c.group(1) in KW: continue
        if c.start() and v[c.start()-1] == '.': continue   # chiamata di metodo, non funzione
        if c.group(1) in GLOBAL_NAMES: continue
        calls.add(c.group(1))
calls = sorted(calls)
def declared(n):
    e = re.escape(n)
    return re.search(r'function\s+'+e+r'\b|(?:const|let|var)\s+'+e+r'\b'
                     r'|\b'+e+r'\s*=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$])'
                     r'|\b'+e+r'\s*:\s*(?:async\s*)?(?:function\b|\()', A)
orphans = [c for c in calls if not declared(c)]

# ---- id creati dall'applicazione ----
created  = set(re.findall(r'id\s*=\s*\\{0,2}["\']([A-Za-z0-9_$-]+)', A))
created |= set(re.findall(r"\.id\s*=\s*\\{0,2}['\"]([A-Za-z0-9_$-]+)", A))
# passwordField("X") -> X, XErr, XShow, XCopy
for m in re.finditer(r'passwordField\(\s*"([A-Za-z0-9_-]+)"', A):
    b = m.group(1); created |= {b, b+"Err", b+"Show", b+"Copy"}
# prefissi costruiti: 'ver-' + k, 'pk-det-' + i
prefixes = set(re.findall(r"""['"]([A-Za-z0-9_-]*-)['"]\s*\+""", A))
# id scritti con un segnaposto di String.format: id="%s-status", id="%1$s"
patterns = []
wildcard = []
for lit in set(re.findall(r'id\s*=\s*\\{0,2}["\']([A-Za-z0-9_$%-]*%[0-9$]*s[A-Za-z0-9_$-]*)', A)):
    fixed = re.sub(r'%[0-9]*\$?s', '', lit).strip('-_')
    if not fixed:
        wildcard.append(lit)   # id="%s" da solo assolverebbe QUALUNQUE id: scartato
        continue
    patterns.append(re.compile("^" + re.sub(r'%[0-9]*\$?s', '[A-Za-z0-9_-]+', re.escape(lit).replace('\\%','%').replace('\\$','$')) + "$"))

def resolved(i):
    if i in created: return True
    if any(i.startswith(p) for p in prefixes if p): return True
    return any(r.match(i) for r in patterns)

# ---- id cercati dall'applicazione ----
g = re.compile(r"getElementById\(\s*\\{0,2}['\"]([A-Za-z0-9_$-]+)\\{0,2}['\"]?(\s*\+)?")
sought = sorted(set(m.group(1) for m in g.finditer(A) if not m.group(2)))
missing = [i for i in sought if not resolved(i)]

# ---- id/selettori cercati dalle prove (consumatrici) ----
NEG = re.compile(r"\.count\(\)\s*===\s*0")
SEL = re.compile(r"""getElementById\(['"]([A-Za-z0-9_-]+)['"]\)|['"`]#([A-Za-z0-9_-]+)""")
from_tests, negatives = {}, set()
for f, s in test_sources:
    for line in s.splitlines():
        neg = bool(NEG.search(line))
        for m in SEL.finditer(line):
            i = m.group(1) or m.group(2)
            if line[m.end():m.end()+6].lstrip().startswith("+"): continue  # prefisso, non id
            if neg: negatives.add(i)
            else: from_tests.setdefault(i, set()).add(os.path.basename(f))
dead = {i: v for i, v in from_tests.items() if not resolved(i)}

# ---- le ancore dei collegamenti ----
# Un collegamento a una scheda porta il suo id dopo il cancelletto: href="/updates#branch",
# a.href = '/updates#branch', data-bs-target="#hetznerGuide". Se l'id cambia e l'ancora no, il
# collegamento apre la pagina e non porta piu' alla scheda, senza errori. Misurato il 29/10/2026:
# la Home mandava a /updates#ramo da quando la scheda si chiama branch.
ANCHOR = re.compile(r"""(?:href|data-bs-target)\s*=\s*\\{0,2}["'][^"'#\s]*#([A-Za-z][A-Za-z0-9_-]*)\\{0,2}["']"""
                    r"""|\.href\s*=\s*\\{0,2}['"][^'"#\s]*#([A-Za-z][A-Za-z0-9_-]*)\\{0,2}['"]""")
anchors = sorted(set(m.group(1) or m.group(2) for m in ANCHOR.finditer(A)))
broken_anchors = [i for i in anchors if not resolved(i)]

# Zero file non e' "zero problemi": e' "non ho guardato niente". Si dice e si esce male,
# altrimenti una radice sbagliata passa per una rete verde.
if not app or not test_sources:
    print(f"  NIENTE DA CONTROLLARE in {root!r}: file applicazione {len(app)}, file di prova {len(test_sources)}.")
    print("  La radice e' sbagliata, o i file non ci sono: in nessuno dei due casi questa e' una rete verde.")
    sys.exit(2)

print(f"  file applicazione: {len(app)}   file di prova: {len(test_sources)}")
print(f"  funzioni chiamate da on*: {len(calls)}   senza dichiarazione: {len(orphans)}")
for o in orphans[:10]: print(f"    orfana: {o}")
print(f"  id cercati dall'applicazione: {len(sought)}   mai creati: {len(missing)}")
for m in missing[:10]: print(f"    mai creato: {m}")
print(f"  ancore dei collegamenti: {len(anchors)}   verso id mai creati: {len(broken_anchors)}")
for i in broken_anchors[:10]: print(f"    ancora morta: #{i}")
print(f"  id/selettori cercati dalle PROVE: {len(from_tests)}   mai creati: {len(dead)}")
for i in sorted(dead): print(f"    MORTO NELLE PROVE: {i:<22} {', '.join(sorted(dead[i]))}")
if not quiet:
    print(f"  (prefissi costruiti noti: {len(prefixes)}; schemi di format: {len(patterns)}; "
          f"jolly scartati: {wildcard}; selettori asseriti ASSENTI, esclusi: {len(negatives)})")
sys.exit(1 if (orphans or missing or dead or broken_anchors) else 0)
