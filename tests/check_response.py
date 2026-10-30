#!/usr/bin/env python3
"""I nomi dei campi della RISPOSTA attraversano due parti: il server li mette in un JSON, il
JavaScript della pagina li legge con un punto. Rinominato su un lato solo, la lettura
restituisce undefined e la funzione muore in silenzio.

E' il difetto che il 17 ottobre 2026 ha reso morto "Esegui ora" nella pagina Cron:
CronManagement mandava exitCode e output, la pagina leggeva e.codice ed e.uscita, e
"undefined === 0" e' falso, quindi ogni lavoro riuscito veniva dichiarato in errore. Compilava,
nessun avviso. Il compagno di questa rete e' tests/check_api.py, che fa la stessa cosa
nell'altro senso (i parametri che la pagina MANDA e la rotta legge).

Come funziona:
  1. dalle rotte: case "azione" -> quali metodi del server costruiscono la risposta;
  2. dal server: le chiavi che quei metodi mettono, piu' quelle dei metodi che chiamano
     (un livello, perche' una risposta e' fatta di oggetti annidati);
  3. dalla pagina: nella funzione che chiama updApi('azione'), i campi letti dalla
     variabile che riceve la risposta.
Si segnala un campo letto che nessuno mette.

L'approssimazione e' VOLUTA e sta tutta da un lato: l'insieme delle chiavi del server e'
piu' largo del vero (si prendono anche quelle dei metodi chiamati). Cosi' la rete non urla
per gli oggetti annidati, e resta vera quando dice "questa chiave non la mette nessuno".

Si lancia dalla radice del progetto:  python3 tests/check_response.py
Gira sul Mac: legge dei file del repository e non tocca il sistema.
"""
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
PAGE = os.path.join(root, "src/main/java/org/mail_panel/content/MailPanelContent.java")
ROUTES = os.path.join(root, "src/main/java/org/mail_panel/webserver/SSLMailServer.java")
# Tutte le classi del progetto fuori dalla pagina: le rotte chiamano anche Autoconfig, AppleProfile,
# PeriodicReport, AutoDns. Con le sole cinque classi di prima, un'azione di quelle risultava
# "non verificabile" o, peggio, attribuita a un metodo omonimo di un'altra rotta.
import glob as _g
SERVER = sorted(os.path.relpath(f, root) for f in _g.glob(os.path.join(root, "src/main/java/org/mail_panel/**/*.java"), recursive=True)
                if "/content/" not in f)
CLASSES = sorted({os.path.splitext(os.path.basename(f))[0] for f in SERVER}, key=len, reverse=True)

# La busta che ogni risposta ha, messa dai percorsi comuni e non dal metodo dell'azione.
ENVELOPE = {"success", "error", "jobId", "async", "job", "warning"}

page = open(PAGE, encoding="utf-8", errors="replace").read()
# E le pagine scritte come file a parte (vedi check_api.py: lo stesso buco).
import glob as _glob
for _f in sorted(_glob.glob(os.path.join(root, "src/main/resources/pages/*.js"))):
    page += "\n" + open(_f, encoding="utf-8", errors="replace").read()
routes = open(ROUTES, encoding="utf-8", errors="replace").read()
server = {}
for rel in SERVER:
    p = os.path.join(root, rel)
    if os.path.exists(p):
        server[os.path.basename(p)] = open(p, encoding="utf-8", errors="replace").read()


def method_body(text, name):
    """I corpi di un metodo e dei suoi overload, bilanciando le graffe dalla firma. '' se non c'e'."""
    bodies = []
    for m in re.finditer(r"\b(?:JSONObject|JSONArray|String|boolean|int|long)\s+" + re.escape(name) + r"\s*\(", text):
        i = text.find("{", m.end())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(text[i:j + 1])
                    break
            j += 1
    return "\n".join(bodies)


def keys_of(name, depth=1, seen=None):
    """Le chiavi che il metodo mette, piu' quelle dei metodi che chiama (un livello)."""
    seen = seen or set()
    if name in seen or depth < 0:
        return set()
    seen.add(name)
    outside = set()
    for text in server.values():
        body = method_body(text, name)
        if not body:
            continue
        outside |= set(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', body))
        if depth > 0:
            for called in set(re.findall(r"\b([a-z][A-Za-z0-9_]*)\s*\(", body)):
                outside |= keys_of(called, depth - 1, seen)
    return outside


# --- 1. azione -> metodi del server ---
CASE = re.compile(r'case\s+"([a-z0-9_]+)"\s*->')
cases = [(m.group(1), m.start()) for m in CASE.finditer(routes)]
methods = {}
in_block = {}
for n, (action, start) in enumerate(cases):
    end = cases[n + 1][1] if n + 1 < len(cases) else len(routes)
    block = routes[start:end]
    # la risposta puo' essere costruita nella rotta stessa: response.put("chiave", ...)
    in_block.setdefault(action, set()).update(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', block))
    methods.setdefault(action, set()).update(
        re.findall(r"\b(?:" + "|".join(CLASSES) + r")\.([a-zA-Z_][A-Za-z0-9_]*)\s*\(", block)
        # e i metodi chiamati su un'istanza (autoDns.create(...)): conta solo se il metodo esiste
        # in una classe del progetto, cioe' se chiavi_di trova il suo corpo
        + [n for n in re.findall(r"\b[a-z][A-Za-z0-9_]*\.([a-z][A-Za-z0-9_]*)\s*\(", block)
           if n not in ("put", "opt", "optString", "optInt", "optLong", "optBoolean", "optJSONArray", "optJSONObject",
                        "getString", "getInt", "getBoolean", "has", "equals", "length", "isEmpty", "trim", "toString")])

# --- 2. la pagina: funzione che chiama updApi('azione') -> campi letti ---
FUNCTION = re.compile(r"(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
starts = [(m.group(1), m.start()) for m in FUNCTION.finditer(page)]
read_fields = {}
for n, (fn_name, start) in enumerate(starts):
    end = starts[n + 1][1] if n + 1 < len(starts) else len(page)
    body = page[start:end]
    for m in re.finditer(r"(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*await\s+[a-zA-Z]+Api\(\s*'([a-z0-9_]+)'", body):
        var, action = m.group(1), m.group(2)
        fields = set(re.findall(r"\b" + re.escape(var) + r"\.([A-Za-z_][A-Za-z0-9_]*)", body))
        read_fields.setdefault(action, set()).update(fields)

print(f"  azioni con una risposta letta dalla pagina: {len(read_fields)}")
failures = []
for action in sorted(read_fields):
    if action not in methods or not methods[action]:
        # Nessun metodo riconosciuto: la risposta e' costruita nella rotta stessa. Non si
        # puo' dire niente, e si dice che non si puo'.
        print(f"    --  {action}: risposta costruita nella rotta, non verificabile qui")
        continue
    available = set(ENVELOPE) | in_block.get(action, set())
    for method in methods[action]:
        available |= keys_of(method)
    for k in sorted(read_fields[action] - available):
        failures.append(f'la pagina legge "{k}" dalla risposta di "{action}", che nessuno mette '
                      f"(metodi: {', '.join(sorted(methods[action]))})")

# --- 2. e i FINTI delle prove non devono mandare nomi che il server non manda ---
#
# Era il terzo lato dello stesso nome, e il piu' insidioso: i finti di
# packages-browser-test.js, english-pages-browser-test.js e pkg-branch-browser-test.js
# mandavano "spiegazione" mentre il server manda "explanation", quindi le prove erano VERDI
# contro una pagina morta. Dodici letture di "spiegazione", tre di "descrizione", due di
# "problemi", quattro di "motivo", due di "uscita": ventitre' campi che in produzione erano
# undefined, e nessuna prova poteva dirlo perche' le prove si parlavano da sole.
#
# Si guarda dentro gli oggetti passati a json(route, ...) e nelle costanti MAIUSCOLE che i
# finti usano come risposta: quelle sono la forma della risposta, e devono essere la forma
# vera.
import glob

# Risposte che il server NON costruisce con .put(...), quindi il vocabolario non le vede.
# Ognuna misurata il 23/10/2026: i firewall e la rotazione DKIM le compongono altrove.
OUT_OF_VOCABULARY = {
    "panel_bl_cidrs", "panel_wl_cidrs", "panel_geo_bl", "panel_geo_wl",
    "last_rotation_at_ms", "next_rotation_at_ms", "live_state_all", "strength_label",
}

vocabulary = set()
for f in glob.glob(os.path.join(root, "src/main/java/**/*.java"), recursive=True):
    vocabulary |= set(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', open(f, encoding="utf-8", errors="replace").read()))
actions = set(re.findall(r'case\s+"([a-z0-9_]+)"\s*->', routes))


def object_text(t, i):
    while i < len(t) and t[i] in " \t\r\n":
        i += 1
    if i >= len(t) or t[i] != "{":
        return ""
    depth, j = 0, i
    while j < len(t):
        if t[j] == "{":
            depth += 1
        elif t[j] == "}":
            depth -= 1
            if depth == 0:
                return t[i:j + 1]
        j += 1
    return ""


fakes = {}
for f in sorted(glob.glob(os.path.join(root, "tests/*.js"))):
    t = open(f, encoding="utf-8", errors="replace").read()
    blocks = [object_text(t, m.end()) for m in re.finditer(r"json\(\s*route\s*,", t)]
    blocks += [object_text(t, m.end()) for m in re.finditer(r"^const\s+[A-Z][A-Z0-9_]*\s*=\s*", t, re.M)]
    for b in blocks:
        for k in set(re.findall(r"[{,]\s*([a-z][A-Za-z0-9_]*)\s*:", b)):
            if k in vocabulary or k in actions or k in OUT_OF_VOCABULARY:
                continue
            fakes.setdefault(k, set()).add(os.path.basename(f))
print(f"  nomi che i finti mandano e il server no: {len(fakes)}")
for k, files in sorted(fakes.items()):
    failures.append(f'un finto manda "{k}", che il server non mette da nessuna parte: '
                  f"{', '.join(sorted(files))}")

print(f"  campi letti e mai messi: {len(failures)}")
if failures:
    print()
    for g in failures:
        print(f"    NO  {g}")
    print(f"\n{len(failures)} GUASTI")
    sys.exit(1)
print("\nTUTTO OK")
