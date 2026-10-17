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
  - campoPassword("X") genera id X, XErr, XMostra, XCopia via %1$s
  - gli id costruiti ('ver-' + k) danno un PREFISSO, non un id
  - nelle prove, un selettore con .count() === 0 asserisce che NON c'e'
"""
import re, sys, glob, os

root = sys.argv[1] if len(sys.argv) > 1 else "."
quiet = "--quiet" in sys.argv

def leggi(pats, rec=False):
    out = []
    for p in pats:
        for f in sorted(glob.glob(os.path.join(root, p), recursive=rec)):
            try: out.append((f, open(f, encoding='utf-8', errors='replace').read()))
            except Exception: pass
    return out

app  = leggi(['src/main/resources/pages/*.js', 'src/main/resources/pages/*.html'])
app += leggi(['src/main/java/**/*.java'], rec=True)
prove = leggi(['tests/*.js'])
A = "\n".join(s for _, s in app)

# ---- handler chiamati da on* ----
# tutto il VALORE dell'attributo, poi ogni chiamata dentro: onkeyup="if(...)loadLogs()"
# ne contiene due, e la vecchia rete vedeva solo "if", che e' una parola chiave.
ATTR = re.compile(r'on(?:click|change|input|submit|keyup|focus|blur)\s*=\s*\\{0,2}(["\'])((?:(?!\1)[^\\]|\\.)*)\1')
KW = {'if','else','for','while','do','switch','case','return','typeof','instanceof',
      'new','delete','void','function','this','try','catch','finally','throw','await','in','of'}
GLOBALI = {'Number','String','Boolean','Array','Object','JSON','Math','Date','parseInt',
           'parseFloat','encodeURIComponent','decodeURIComponent','alert','confirm','prompt',
           'setTimeout','setInterval','getElementById','querySelector','querySelectorAll'}
chiamate = set()
for m in ATTR.finditer(A):
    v = m.group(2)
    for c in re.finditer(r'([A-Za-z_$][\w$]*)\s*\(', v):
        if c.group(1) in KW: continue
        if c.start() and v[c.start()-1] == '.': continue   # chiamata di metodo, non funzione
        if c.group(1) in GLOBALI: continue
        chiamate.add(c.group(1))
chiamate = sorted(chiamate)
def dichiarata(n):
    e = re.escape(n)
    return re.search(r'function\s+'+e+r'\b|(?:const|let|var)\s+'+e+r'\b'
                     r'|\b'+e+r'\s*=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$])'
                     r'|\b'+e+r'\s*:\s*(?:async\s*)?(?:function\b|\()', A)
orfane = [c for c in chiamate if not dichiarata(c)]

# ---- id creati dall'applicazione ----
creati  = set(re.findall(r'id\s*=\s*\\{0,2}["\']([A-Za-z0-9_$-]+)', A))
creati |= set(re.findall(r"\.id\s*=\s*\\{0,2}['\"]([A-Za-z0-9_$-]+)", A))
# campoPassword("X") -> X, XErr, XMostra, XCopia
for m in re.finditer(r'campoPassword\(\s*"([A-Za-z0-9_-]+)"', A):
    b = m.group(1); creati |= {b, b+"Err", b+"Mostra", b+"Copia"}
# prefissi costruiti: 'ver-' + k, 'pk-det-' + i
prefissi = set(re.findall(r"""['"]([A-Za-z0-9_-]*-)['"]\s*\+""", A))
# id scritti con un segnaposto di String.format: id="%s-status", id="%1$s"
schemi = []
jolly = []
for lit in set(re.findall(r'id\s*=\s*\\{0,2}["\']([A-Za-z0-9_$%-]*%[0-9$]*s[A-Za-z0-9_$-]*)', A)):
    fisso = re.sub(r'%[0-9]*\$?s', '', lit).strip('-_')
    if not fisso:
        jolly.append(lit)   # id="%s" da solo assolverebbe QUALUNQUE id: scartato
        continue
    schemi.append(re.compile("^" + re.sub(r'%[0-9]*\$?s', '[A-Za-z0-9_-]+', re.escape(lit).replace('\\%','%').replace('\\$','$')) + "$"))

def risolto(i):
    if i in creati: return True
    if any(i.startswith(p) for p in prefissi if p): return True
    return any(r.match(i) for r in schemi)

# ---- id cercati dall'applicazione ----
g = re.compile(r"getElementById\(\s*\\{0,2}['\"]([A-Za-z0-9_$-]+)\\{0,2}['\"]?(\s*\+)?")
cercati = sorted(set(m.group(1) for m in g.finditer(A) if not m.group(2)))
mancanti = [i for i in cercati if not risolto(i)]

# ---- id/selettori cercati dalle prove (consumatrici) ----
NEG = re.compile(r"\.count\(\)\s*===\s*0")
SEL = re.compile(r"""getElementById\(['"]([A-Za-z0-9_-]+)['"]\)|['"`]#([A-Za-z0-9_-]+)""")
da_prove, negativi = {}, set()
for f, s in prove:
    for line in s.splitlines():
        neg = bool(NEG.search(line))
        for m in SEL.finditer(line):
            i = m.group(1) or m.group(2)
            if line[m.end():m.end()+6].lstrip().startswith("+"): continue  # prefisso, non id
            if neg: negativi.add(i)
            else: da_prove.setdefault(i, set()).add(os.path.basename(f))
morti = {i: v for i, v in da_prove.items() if not risolto(i)}

print(f"  file applicazione: {len(app)}   file di prova: {len(prove)}")
print(f"  funzioni chiamate da on*: {len(chiamate)}   senza dichiarazione: {len(orfane)}")
for o in orfane[:10]: print(f"    orfana: {o}")
print(f"  id cercati dall'applicazione: {len(cercati)}   mai creati: {len(mancanti)}")
for m in mancanti[:10]: print(f"    mai creato: {m}")
print(f"  id/selettori cercati dalle PROVE: {len(da_prove)}   mai creati: {len(morti)}")
for i in sorted(morti): print(f"    MORTO NELLE PROVE: {i:<22} {', '.join(sorted(morti[i]))}")
if not quiet:
    print(f"  (prefissi costruiti noti: {len(prefissi)}; schemi di format: {len(schemi)}; "
          f"jolly scartati: {jolly}; selettori asseriti ASSENTI, esclusi: {len(negativi)})")
sys.exit(1 if (orfane or mancanti or morti) else 0)
