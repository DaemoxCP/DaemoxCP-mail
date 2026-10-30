"""Rinomina nomi Python con il tokenizer, e verifica con l'albero sintattico (r26).

Si cambiano i token NAME col nome nella mappa, tranne quelli dopo un punto (attributi di altri
oggetti: re.compile resta re.compile). Dentro le f-string i nomi sono token anche loro (Python
3.12+), quindi vengono presi; il testo delle stringhe no. Poi la verifica, che e' la parte che
conta: l'albero del file dopo dev'essere quello di prima con i nomi passati dalla mappa, nodo per
nodo; e nessun nome nuovo puo' esistere gia' nel file (catturerebbe l'altro in silenzio).

Uso: python3 tools/py_rename.py <mappa.txt> <file.py>... [--dry]
"""
import ast, io, sys, tokenize, keyword
args = [a for a in sys.argv[1:] if not a.startswith("--")]
dry = "--dry" in sys.argv
mp = dict(l.split() for l in open(args[0], encoding="utf-8") if l.strip() and not l.startswith("#"))
problems = 0

def rename(src):
    toks, out, prev = list(tokenize.generate_tokens(io.StringIO(src).readline)), [], None
    edits = []
    for t in toks:
        if t.type == tokenize.NAME and t.string in mp and not (prev and prev.type == tokenize.OP and prev.string == "."):
            edits.append((t.start, t.end, mp[t.string]))
        if t.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT):
            prev = t
    lines = src.splitlines(keepends=True)
    for (sr, sc), (er, ec), new in reversed(edits):
        assert sr == er
        l = lines[sr - 1]; lines[sr - 1] = l[:sc] + new + l[ec:]
    return "".join(lines), len(edits)

class Mapped(ast.NodeTransformer):
    def visit_Name(self, n): n.id = mp.get(n.id, n.id); return n
    def visit_arg(self, n): n.arg = mp.get(n.arg, n.arg); self.generic_visit(n); return n
    def visit_keyword(self, n):
        if n.arg: n.arg = mp.get(n.arg, n.arg)
        self.generic_visit(n); return n
    def visit_FunctionDef(self, n): n.name = mp.get(n.name, n.name); self.generic_visit(n); return n
    def visit_ClassDef(self, n): n.name = mp.get(n.name, n.name); self.generic_visit(n); return n

for f in args[1:]:
    src = open(f, encoding="utf-8").read()
    # i nomi che si possono catturare: variabili, argomenti, funzioni, classi, import. Non gli
    # attributi (m.end() non e' una variabile end) ne' gli argomenti per nome di altre funzioni.
    tree = ast.parse(src)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} \
          | {n.arg for n in ast.walk(tree) if isinstance(n, ast.arg)} \
          | {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.ClassDef))} \
          | {(a.asname or a.name).split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    caught = sorted(v for k, v in mp.items() if k in names and v in names and v not in mp)
    for v in caught:
        print(f"NON TORNA {f}: il nome nuovo {v} c'e' gia'"); problems += 1
    new, n = rename(src)
    before = ast.dump(Mapped().visit(ast.parse(src)), include_attributes=False)
    after = ast.dump(ast.parse(new), include_attributes=False)
    if before != after:
        i = next(i for i in range(min(len(before), len(after))) if before[i] != after[i])
        print(f"NON TORNA {f}: albero diverso: ...{before[i-80:i+60]}... / ...{after[i-80:i+60]}..."); problems += 1
    left = sorted({t.string for t in tokenize.generate_tokens(io.StringIO(new).readline) if t.type == tokenize.NAME} & set(mp))
    print(f"{f}: {n} nomi cambiati" + (f"; restano (dopo un punto?): {left}" if left else ""))
    if not dry and not problems: open(f, "w", encoding="utf-8").write(new)
print("VERIFICA FALLITA" if problems else "VERIFICA: stesso albero a meno della mappa, nessuna cattura")
sys.exit(1 if problems else 0)
