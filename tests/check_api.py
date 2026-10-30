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

radice = sys.argv[1] if len(sys.argv) > 1 else "."
PAGINA = os.path.join(radice, "src/main/java/org/mail_panel/content/MailPanelContent.java")
ROTTE = os.path.join(radice, "src/main/java/org/mail_panel/webserver/SSLMailServer.java")

pagina = open(PAGINA, encoding="utf-8", errors="replace").read()
# Anche le pagine scritte come file a parte (Home, DNS, rapporti, standard): chiamano le stesse
# rotte con le loro funzioni (autoDnsApi, repApi, stsApi...). Prima la rete guardava solo
# MailPanelContent, e una rotta rinominata chiamata da standards-watch.js non la vedeva.
import glob as _glob
for _f in sorted(_glob.glob(os.path.join(radice, "src/main/resources/pages/*.js"))):
    pagina += "\n" + open(_f, encoding="utf-8", errors="replace").read()
rotte = open(ROTTE, encoding="utf-8", errors="replace").read()


def oggetto_dopo(testo, i):
    """Il { ... } che comincia a i, bilanciando le graffe. '' se non comincia con una graffa."""
    while i < len(testo) and testo[i] in " \t\r\n":
        i += 1
    if i >= len(testo) or testo[i] != "{":
        return ""
    liv, j = 0, i
    while j < len(testo):
        if testo[j] == "{":
            liv += 1
        elif testo[j] == "}":
            liv -= 1
            if liv == 0:
                return testo[i:j + 1]
        j += 1
    return ""


# --- la pagina: azione -> chiavi mandate ---
CHIAMATA = re.compile(r"\b[a-zA-Z]+Api\(\s*'([a-z0-9_]+)'\s*(,)?")
CHIAVE = re.compile(r"[{,]\s*([A-Za-z_][A-Za-z0-9_]*)\s*:")
mandate = {}
for m in CHIAMATA.finditer(pagina):
    azione = m.group(1)
    chiavi = mandate.setdefault(azione, set())
    if not m.group(2):
        continue
    obj = oggetto_dopo(pagina, m.end())
    for k in CHIAVE.findall(obj):
        chiavi.add(k)
# Le chiamate con il nome dell'azione calcolato non si possono attribuire: si contano e si dicono.
non_letterali = len(re.findall(r"\b[a-zA-Z]+Api\(\s*[^'\s)]", pagina))

# --- le rotte: azione -> chiavi lette, piu' tutte le chiavi lette nel file ---
CASO = re.compile(r'case\s+"([a-z0-9_]+)"\s*->')
LETTURA = re.compile(r'(?:req|json|body|request)\.(?:opt|get)[A-Za-z]*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"')
casi = [(m.group(1), m.start()) for m in CASO.finditer(rotte)]
lette = {}
for n, (azione, inizio) in enumerate(casi):
    fine = casi[n + 1][1] if n + 1 < len(casi) else len(rotte)
    lette.setdefault(azione, set()).update(LETTURA.findall(rotte[inizio:fine]))
lette_dovunque = set(LETTURA.findall(rotte))

print(f"  chiamate updApi con azione letterale: {len(mandate)} azioni distinte"
      f"   (con nome calcolato, non attribuibili: {non_letterali})")
print(f"  rotte case \"...\": {len(lette)} azioni distinte")

guasti, avvisi = [], []

for azione in sorted(mandate):
    if azione not in lette:
        guasti.append(f'la pagina chiama "{azione}" e nessuna rotta la gestisce')
        continue
    for k in sorted(mandate[azione]):
        if k in lette[azione]:
            continue
        if k in lette_dovunque:
            avvisi.append(f'"{azione}" manda "{k}", che il server legge ma in un\'altra azione')
        else:
            guasti.append(f'"{azione}" manda "{k}" e il server NON lo legge da nessuna parte')

print(f"  chiavi mandate e mai lette, o azioni senza rotta: {len(guasti)}")
print(f"  chiavi lette in un'altra azione (avviso): {len(avvisi)}")
for a in avvisi:
    print(f"    --  {a}")
if guasti:
    print()
    for g in guasti:
        print(f"    NO  {g}")
    print(f"\n{len(guasti)} GUASTI")
    sys.exit(1)
print("\nTUTTO OK")
