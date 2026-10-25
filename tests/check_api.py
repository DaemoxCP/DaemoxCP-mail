#!/usr/bin/env python3
"""I nomi dei parametri dell'API attraversano DUE parti: il JavaScript della pagina li
manda, la rotta in SSLMailServer li legge. Rinominato su un lato solo, il parametro arriva
e nessuno lo guarda — e la funzione muore in silenzio, senza un errore, senza un avviso,
senza che il compilatore possa dire niente (sono stringhe dentro un JSON).

E' lo stesso difetto che il 17 ottobre 2026 ha reso morto "Esegui ora" nella pagina Cron
(e.codice contro exitCode), e lo stesso rischio che ha tenuto fuori dalla revisione la
firma dell'aggiornamento dei non protetti: passare una firma dalla pagina all'API vuol dire
scrivere lo stesso nome in due file lontani.

Qui si confrontano i due elenchi:
  - dalla pagina:  updApi('azione', { chiave: ..., chiave2: ... })
  - dalla rotta:   case "azione" -> ... req.optString("chiave") ...

Si segnalano:
  1. una chiave che la pagina manda e che il server NON legge da nessuna parte: morta.
     E' il difetto che conta, e il server non puo' accorgersene.
  2. un'azione che la pagina chiama e che nessuna rotta gestisce.
  3. (avviso) una chiave letta in un'altra azione: non e' detto che sia un guasto —
     alcune rotte leggono i parametri in metodi condivisi — ma vale una guardata.

Si lancia dalla radice del progetto:  python3 tests/check_api.py
Gira sul Mac: legge due file del repository e non tocca il sistema.
"""
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
PAGE = os.path.join(root, "src/main/java/org/mail_panel/content/MailPanelContent.java")
ROUTES = os.path.join(root, "src/main/java/org/mail_panel/webserver/SSLMailServer.java")

page = open(PAGE, encoding="utf-8", errors="replace").read()
# Anche le pagine scritte come file a parte (Home, DNS, rapporti, standard): chiamano le stesse
# rotte con le loro funzioni (autoDnsApi, repApi, stsApi...). Prima la rete guardava solo
# MailPanelContent, e una rotta rinominata chiamata da standards-watch.js non la vedeva.
import glob as _glob
for _f in sorted(_glob.glob(os.path.join(root, "src/main/resources/pages/*.js"))):
    page += "\n" + open(_f, encoding="utf-8", errors="replace").read()
routes = open(ROUTES, encoding="utf-8", errors="replace").read()


def object_after(text, i):
    """Il { ... } che comincia a i, bilanciando le graffe. '' se non comincia con una graffa."""
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    if i >= len(text) or text[i] != "{":
        return ""
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return ""


# --- la pagina: azione -> chiavi mandate ---
CALL = re.compile(r"\b[a-zA-Z]+Api\(\s*'([a-z0-9_]+)'\s*(,)?")
KEY = re.compile(r"[{,]\s*([A-Za-z_][A-Za-z0-9_]*)\s*:")
sent = {}
for m in CALL.finditer(page):
    action = m.group(1)
    keys = sent.setdefault(action, set())
    if not m.group(2):
        continue
    obj = object_after(page, m.end())
    for k in KEY.findall(obj):
        keys.add(k)
# Le chiamate con il nome dell'azione calcolato non si possono attribuire: si contano e si dicono.
non_literal = len(re.findall(r"\b[a-zA-Z]+Api\(\s*[^'\s)]", page))

# --- le rotte: azione -> chiavi lette, piu' tutte le chiavi lette nel file ---
CASE = re.compile(r'case\s+"([a-z0-9_]+)"\s*->')
READING = re.compile(r'(?:req|json|body|request)\.(?:opt|get)[A-Za-z]*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"')
cases = [(m.group(1), m.start()) for m in CASE.finditer(routes)]
reads = {}
for n, (action, start) in enumerate(cases):
    end = cases[n + 1][1] if n + 1 < len(cases) else len(routes)
    reads.setdefault(action, set()).update(READING.findall(routes[start:end]))
reads_anywhere = set(READING.findall(routes))

print(f"  chiamate updApi con azione letterale: {len(sent)} azioni distinte"
      f"   (con nome calcolato, non attribuibili: {non_literal})")
print(f"  rotte case \"...\": {len(reads)} azioni distinte")

failures, warnings = [], []

for action in sorted(sent):
    if action not in reads:
        failures.append(f'la pagina chiama "{action}" e nessuna rotta la gestisce')
        continue
    for k in sorted(sent[action]):
        if k in reads[action]:
            continue
        if k in reads_anywhere:
            warnings.append(f'"{action}" manda "{k}", che il server legge ma in un\'altra azione')
        else:
            failures.append(f'"{action}" manda "{k}" e il server NON lo legge da nessuna parte')

print(f"  chiavi mandate e mai lette, o azioni senza rotta: {len(failures)}")
print(f"  chiavi lette in un'altra azione (avviso): {len(warnings)}")
for a in warnings:
    print(f"    --  {a}")
if failures:
    print()
    for g in failures:
        print(f"    NO  {g}")
    print(f"\n{len(failures)} GUASTI")
    sys.exit(1)
print("\nTUTTO OK")
