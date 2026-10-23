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

radice = sys.argv[1] if len(sys.argv) > 1 else "."
PAGINA = os.path.join(radice, "src/main/java/org/mail_panel/content/MailPanelContent.java")
ROTTE = os.path.join(radice, "src/main/java/org/mail_panel/webserver/SSLMailServer.java")
SERVER = [
    "src/main/java/org/mail_panel/system/UpdateManager.java",
    "src/main/java/org/mail_panel/system/PackagePlan.java",
    "src/main/java/org/mail_panel/system/PkgBranch.java",
    "src/main/java/org/mail_panel/system/PkgCatalog.java",
    "src/main/java/org/mail_panel/system/SoftwareVersions.java",
]

# La busta che ogni risposta ha, messa dai percorsi comuni e non dal metodo dell'azione.
BUSTA = {"success", "error", "jobId", "async", "job", "warning"}

pagina = open(PAGINA, encoding="utf-8", errors="replace").read()
rotte = open(ROTTE, encoding="utf-8", errors="replace").read()
server = {}
for rel in SERVER:
    p = os.path.join(radice, rel)
    if os.path.exists(p):
        server[os.path.basename(p)] = open(p, encoding="utf-8", errors="replace").read()


def corpo_metodo(testo, nome):
    """Il corpo di un metodo, bilanciando le graffe dalla sua firma. '' se non c'e'."""
    m = re.search(r"\b(?:JSONObject|JSONArray|String|boolean|int|long)\s+" + re.escape(nome) + r"\s*\(", testo)
    if not m:
        return ""
    i = testo.find("{", m.end())
    if i < 0:
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


def chiavi_di(nome, profondita=1, visti=None):
    """Le chiavi che il metodo mette, piu' quelle dei metodi che chiama (un livello)."""
    visti = visti or set()
    if nome in visti or profondita < 0:
        return set()
    visti.add(nome)
    fuori = set()
    for testo in server.values():
        corpo = corpo_metodo(testo, nome)
        if not corpo:
            continue
        fuori |= set(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', corpo))
        if profondita > 0:
            for chiamato in set(re.findall(r"\b([a-z][A-Za-z0-9_]*)\s*\(", corpo)):
                fuori |= chiavi_di(chiamato, profondita - 1, visti)
    return fuori


# --- 1. azione -> metodi del server ---
CASO = re.compile(r'case\s+"([a-z0-9_]+)"\s*->')
casi = [(m.group(1), m.start()) for m in CASO.finditer(rotte)]
metodi = {}
for n, (azione, inizio) in enumerate(casi):
    fine = casi[n + 1][1] if n + 1 < len(casi) else len(rotte)
    blocco = rotte[inizio:fine]
    metodi.setdefault(azione, set()).update(
        re.findall(r"\b(?:UpdateManager|PackagePlan|PkgBranch|PkgCatalog|SoftwareVersions)\.([a-zA-Z_][A-Za-z0-9_]*)\s*\(", blocco))

# --- 2. la pagina: funzione che chiama updApi('azione') -> campi letti ---
FUNZIONE = re.compile(r"(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
inizi = [(m.group(1), m.start()) for m in FUNZIONE.finditer(pagina)]
letti = {}
for n, (nomeFn, inizio) in enumerate(inizi):
    fine = inizi[n + 1][1] if n + 1 < len(inizi) else len(pagina)
    corpo = pagina[inizio:fine]
    for m in re.finditer(r"(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*await\s+updApi\(\s*'([a-z0-9_]+)'", corpo):
        var, azione = m.group(1), m.group(2)
        campi = set(re.findall(r"\b" + re.escape(var) + r"\.([A-Za-z_][A-Za-z0-9_]*)", corpo))
        letti.setdefault(azione, set()).update(campi)

print(f"  azioni con una risposta letta dalla pagina: {len(letti)}")
guasti = []
for azione in sorted(letti):
    if azione not in metodi or not metodi[azione]:
        # Nessun metodo riconosciuto: la risposta e' costruita nella rotta stessa. Non si
        # puo' dire niente, e si dice che non si puo'.
        print(f"    --  {azione}: risposta costruita nella rotta, non verificabile qui")
        continue
    disponibili = set(BUSTA)
    for me in metodi[azione]:
        disponibili |= chiavi_di(me)
    for k in sorted(letti[azione] - disponibili):
        guasti.append(f'la pagina legge "{k}" dalla risposta di "{azione}", che nessuno mette '
                      f"(metodi: {', '.join(sorted(metodi[azione]))})")

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
FUORI_DAL_VOCABOLARIO = {
    "panel_bl_cidrs", "panel_wl_cidrs", "panel_geo_bl", "panel_geo_wl",
    "last_rotation_at_ms", "next_rotation_at_ms", "live_state_all", "strength_label",
}

vocabolario = set()
for f in glob.glob(os.path.join(radice, "src/main/java/**/*.java"), recursive=True):
    vocabolario |= set(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', open(f, encoding="utf-8", errors="replace").read()))
azioni = set(re.findall(r'case\s+"([a-z0-9_]+)"\s*->', rotte))


def oggetto(t, i):
    while i < len(t) and t[i] in " \t\r\n":
        i += 1
    if i >= len(t) or t[i] != "{":
        return ""
    liv, j = 0, i
    while j < len(t):
        if t[j] == "{":
            liv += 1
        elif t[j] == "}":
            liv -= 1
            if liv == 0:
                return t[i:j + 1]
        j += 1
    return ""


finti = {}
for f in sorted(glob.glob(os.path.join(radice, "tests/*.js"))):
    t = open(f, encoding="utf-8", errors="replace").read()
    blocchi = [oggetto(t, m.end()) for m in re.finditer(r"json\(\s*route\s*,", t)]
    blocchi += [oggetto(t, m.end()) for m in re.finditer(r"^const\s+[A-Z][A-Z0-9_]*\s*=\s*", t, re.M)]
    for b in blocchi:
        for k in set(re.findall(r"[{,]\s*([a-z][A-Za-z0-9_]*)\s*:", b)):
            if k in vocabolario or k in azioni or k in FUORI_DAL_VOCABOLARIO:
                continue
            finti.setdefault(k, set()).add(os.path.basename(f))
print(f"  nomi che i finti mandano e il server no: {len(finti)}")
for k, files in sorted(finti.items()):
    guasti.append(f'un finto manda "{k}", che il server non mette da nessuna parte: '
                  f"{', '.join(sorted(files))}")

print(f"  campi letti e mai messi: {len(guasti)}")
if guasti:
    print()
    for g in guasti:
        print(f"    NO  {g}")
    print(f"\n{len(guasti)} GUASTI")
    sys.exit(1)
print("\nTUTTO OK")
