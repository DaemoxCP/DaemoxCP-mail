#!/usr/bin/env python3
"""I file di lingua sono testo, e dentro si sono infilati dei nomi del CODICE.

Una rinomina r26 fatta a testo (bloccati -> lockedPackages, sbloccati ->
unlockedPackages, eseguibile -> runnable, misurato -> measured, haConflitti ->
hasConflicts) ha colpito anche src/main/resources/lang/it.json, e nessuno se n'e'
accorto: il pannello scriveva in pagina "Verranno unlockedPackages postfix-mysql" e
"Il piano non e' runnable". Il compilatore non vede dentro un JSON, e nessuna prova
leggeva quei testi. Trentotto occorrenze, trovate per caso guardando l'uscita di un
aggiornamento guidato.

Quattro controlli, tre generali e uno esplicito:

  1. le due lingue hanno le STESSE chiavi. Una chiave aggiunta su un lato solo
     e' una riga che in un'altra lingua non esiste.
  2. i segnaposto {cosi} combaciano chiave per chiave. E' lo stesso difetto di r26
     ("un nome che viaggia fra due parti"): rinominato su un lato, l'interpolazione
     non sostituisce piu' niente e il testo mostra la graffa all'utente.
  3. nessun token camelCase nei testi, fuori dai segnaposto, tranne una whitelist
     corta e motivata. E' la parte generale: i nomi del codice sono quasi sempre
     camelCase, quindi questa prende anche quelli che verranno.
  4. in it.json, nessuna parola da una lista esplicita di nomi inglesi del codice
     che ci sono finiti davvero. Questa NON e' una rete generale — e' una lista, e
     il suo limite va detto: non c'e' nessun dizionario qui, quindi una parola
     inglese minuscola nuova non la prende nessuno. La lista cresce quando se ne
     trova una.

Si lancia dalla radice del progetto:  python3 tests/check_lang.py
Gira sul Mac: legge due file del repository e non tocca il sistema.
"""
import json
import re
import sys
import os

radice = sys.argv[1] if len(sys.argv) > 1 else "."
IT = os.path.join(radice, "src/main/resources/lang/it.json")
EN = os.path.join(radice, "src/main/resources/lang/en.json")

# camelCase legittimi, misurati il 23/10/2026. Ognuno ha un motivo:
#  - nomi di prodotto scritti come li scrive chi li fa
#  - segnaposto scritti a mano nei testi, dove NN sta per un numero di versione
#  - direttive di configurazione di fail2ban, citate perche' l'utente le ritrova nel file
CAMEL_AMMESSI = {
    "iPhone", "iPad", "macOS", "iOS",
    "phpNN", "mysqlNN", "py3NN",
    "maxRetry", "findTime", "banTime",
    "nAtteso", "nTrovato", "nAttendi", "nExpected", "nFound", "nWait",
}

# Nomi del codice che in un testo italiano non ci vanno mai. Accanto, la parola che
# il testo deve usare: serve a chi corregge, e dice che non e' un divieto astratto.
INGLESI_VIETATI_IN_ITALIANO = {
    "runnable": "eseguibile",
    "measured": "misurato",
    "lockedPackages": "bloccati",
    "unlockedPackages": "sbloccati",
    "hasConflicts": "conflitti",
}

CAMEL = re.compile(r"\b[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b")
SEGNAPOSTO = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def testo_senza_segnaposto(v):
    """Il testo come lo legge una persona: i {segnaposto} non sono testo."""
    return SEGNAPOSTO.sub(" ", v)


def carica(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


it, en = carica(IT), carica(EN)
guasti = []

# --- 1. le stesse chiavi ---
solo_it, solo_en = sorted(set(it) - set(en)), sorted(set(en) - set(it))
print(f"  chiavi: it {len(it)}, en {len(en)}")
for k in solo_it[:10]:
    guasti.append(f"chiave solo in it.json: {k}")
for k in solo_en[:10]:
    guasti.append(f"chiave solo in en.json: {k}")

# --- 2. i segnaposto combaciano ---
diversi = 0
for k in sorted(set(it) & set(en)):
    a, b = it[k], en[k]
    if not isinstance(a, str) or not isinstance(b, str):
        continue
    pa, pb = set(SEGNAPOSTO.findall(a)), set(SEGNAPOSTO.findall(b))
    if pa != pb:
        diversi += 1
        guasti.append(f"segnaposto diversi su {k}: solo it {sorted(pa - pb)}, solo en {sorted(pb - pa)}")
print(f"  chiavi con segnaposto diversi fra le due lingue: {diversi}")

# --- 3. camelCase nei testi ---
camel = {}
for nome, d in (("it", it), ("en", en)):
    for k, v in d.items():
        if not isinstance(v, str):
            continue
        for tok in CAMEL.findall(testo_senza_segnaposto(v)):
            if tok in CAMEL_AMMESSI:
                continue
            camel.setdefault((nome, tok), []).append(k)
print(f"  token camelCase non ammessi nei testi: {len(camel)}")
for (nome, tok), chiavi in sorted(camel.items()):
    guasti.append(f"camelCase in {nome}.json: {tok} ({len(chiavi)} chiavi, es. {chiavi[0]})")

# --- 4. parole inglesi del codice nei testi italiani ---
inglesi = {}
for k, v in it.items():
    if not isinstance(v, str):
        continue
    testo = testo_senza_segnaposto(v)
    for parola, invece in INGLESI_VIETATI_IN_ITALIANO.items():
        if re.search(r"\b" + re.escape(parola) + r"\b", testo):
            inglesi.setdefault(parola, []).append(k)
print(f"  parole inglesi del codice nei testi italiani: {len(inglesi)}")
for parola, chiavi in sorted(inglesi.items()):
    guasti.append(f'in it.json c\'e\' "{parola}" (si dice "{INGLESI_VIETATI_IN_ITALIANO[parola]}"): '
                  f"{len(chiavi)} chiavi, es. {chiavi[0]}")

# --- 5. e nemmeno le prove da browser devono ASPETTARSI il testo rotto ---
#
# Il testo rotto aveva un consumatore: tests/packages-browser-test.js cercava
# "3 lockedPackages" nella pagina, quindi la prova sarebbe diventata rossa correggendo
# l'italiano — o, peggio, sarebbe rimasta verde su un testo sbagliato. Un nome che viaggia
# fra due parti si cambia su tutte le parti nello stesso passaggio (r26), e le prove sono
# una di quelle parti.
# Solo dentro le STRINGHE: in quei file "measured: true" e "unlockedPackages: ['nginx']"
# sono chiavi JSON del server simulato — cioe' i nomi veri del contratto, che li' ci vanno.
# Guardando tutto il file, la rete li segnalava: due falsi positivi, visti e tolti.
import glob
LETTERALE = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*\"""" + '"' + r"""|`(?:[^`\\]|\\.)*`""")
prove = {}
for f in sorted(glob.glob(os.path.join(radice, "tests/*.js"))):
    contenuto = open(f, encoding="utf-8", errors="replace").read()
    stringhe = " ".join(LETTERALE.findall(contenuto))
    for parola in INGLESI_VIETATI_IN_ITALIANO:
        if re.search(r"\b" + re.escape(parola) + r"\b", stringhe):
            prove.setdefault(parola, []).append(os.path.basename(f))
print(f"  parole del codice attese dalle prove da browser: {len(prove)}")
for parola, files in sorted(prove.items()):
    guasti.append(f'una prova si aspetta "{parola}" nel testo (si dice '
                  f'"{INGLESI_VIETATI_IN_ITALIANO[parola]}"): {", ".join(files)}')

# --- 6. i segnaposto che il TESTO chiede devono essere quelli che il CODICE passa ---
#
# Terzo lato ancora: `I18n.tr("chiave", Map.of("reason", ...))` contro un testo che dice
# {motivo}. L'interpolazione non sostituisce niente e l'utente legge la graffa. Misurato il
# 23/10/2026 eseguendo la manutenzione completa sulla VM: nel log compariva
# «dovecot -> TRATTENUTO: {motivo}». Sette chiavi, tutte dalla stessa rinomina a meta'
# (motivo -> reason, uscita -> output) con i file di lingua rimasti indietro. Il controllo 2
# non le vedeva: it.json e en.json dicevano {motivo} TUTTI E DUE, quindi fra loro combaciavano.
#
# Il parser dei siti di chiamata prende le stringhe vicine alla chiave, quindi l'insieme dei
# nomi passati e' piu' largo del vero: l'approssimazione sta dalla parte che NON inventa
# guasti, e ogni segnaposto segnalato qui non e' passato da nessuna parte.
import glob

siti = {}
for f in glob.glob(os.path.join(radice, "src/main/java/**/*.java"), recursive=True):
    t = open(f, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r'I18n\.tr\(\s*"([A-Za-z0-9_.]+)"\s*,', t):
        coda = t[m.end():m.end() + 1500]
        fine = coda.find(");")
        if fine > 0:
            coda = coda[:fine]
        siti.setdefault(m.group(1), set()).update(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*,', coda))

senza = 0
for chiave, passati in sorted(siti.items()):
    if chiave not in it:
        continue
    attesi = set(SEGNAPOSTO.findall(it[chiave])) | set(SEGNAPOSTO.findall(en.get(chiave, "")))
    mancanti = sorted(attesi - passati)
    if mancanti:
        senza += 1
        guasti.append(f'il testo di {chiave} chiede {mancanti} e il codice non li passa '
                      f"(passa {sorted(passati)[:6]}): l'utente leggerebbe la graffa")
print(f"  testi che chiedono un segnaposto che il codice non passa: {senza}")

# --- 7. e lo stesso nel JavaScript: t('chiave', { nome: ... }) ---
#
# Il controllo 6 guarda i Map.of del Java. La pagina passa i segnaposto con un oggetto, e una
# rinomina delle chiavi JSON fatta a testo li cambierebbe come se fossero chiavi della risposta:
# t('ad.reportsToFwd', { address: ... }) con il testo che chiede {indirizzo}. Si guardano le
# chiavi di primo livello dell'oggetto, e devono stare fra i segnaposto del testo (tn ha anche n).
CHIAMATA_JS = re.compile(r"""\b(t|tn|tNodes)\(\s*\\?['"]([A-Za-z0-9_.\-]+)\\?['"]\s*,\s*(?:[^,{}()'"]+,\s*)?\{""")
sorgenti_js = glob.glob(os.path.join(radice, "src/main/resources/pages/*.js")) + \
              glob.glob(os.path.join(radice, "src/main/java/**/*.java"), recursive=True)
chiamate_js, js_diversi = 0, 0
for f in sorgenti_js:
    testo = open(f, encoding="utf-8", errors="replace").read()
    for m in CHIAMATA_JS.finditer(testo):
        funzione, chiave = m.group(1), m.group(2)
        i, prof = m.end() - 1, 0
        while i < len(testo):
            if testo[i] == "{": prof += 1
            elif testo[i] == "}":
                prof -= 1
                if prof == 0: break
            i += 1
        piatto = re.sub(r"\([^()]*\)|\[[^\[\]]*\]|\{[^{}]*\}", "", testo[m.end():i])
        passati = set(re.findall(r"(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?::|(?=,|$))", piatto))
        chiamate_js += 1
        if chiave not in it or not isinstance(it[chiave], str):
            continue
        chiesti = set(SEGNAPOSTO.findall(it[chiave])) | ({"n"} if funzione == "tn" else set())
        for nome in sorted(passati - chiesti):
            js_diversi += 1
            guasti.append(f"{os.path.basename(f)}: {funzione}('{chiave}') passa {{{nome}}}, il testo chiede {sorted(chiesti)}")
print(f"  chiamate del JavaScript con segnaposto: {chiamate_js}, con nomi che il testo non chiede: {js_diversi}")

# --- 8. ogni chiave che il codice usa esiste ---
#
# Il contrario del controllo 1: una chiave rinominata nel file di lingua e non nel codice (o il
# contrario) fa comparire in pagina il NOME della chiave, senza errori. Si cercano le chiavi
# letterali di I18n.tr, t/tn/tNodes, {{t:...}} e data-i18n, e devono esistere (per tn bastano
# chiave.one e chiave.other). Quelle costruite con un prefisso + valore non si possono
# controllare qui, e si contano. Nel Java le righe di commento non contano: un commento puo'
# citare {{t:chiave}} come esempio.
USI = [
    re.compile(r"""\bI18n\.tr(?:In)?\(\s*(?:[^,()"]+,\s*)?"([A-Za-z][\w.\-]*)\""""),
    re.compile(r"""\b(?:t|tn|tNodes)\(\s*\\?['"]([A-Za-z][\w.\-]*)\\?['"]"""),
    re.compile(r"""\{\{t:([A-Za-z][\w.\-]*)\}\}"""),
    re.compile(r"""data-i18n(?:-[a-z]+)?=\\?["']([A-Za-z][\w.\-]*)\\?["']"""),
]
COSTRUITE = [
    re.compile(r"""\bI18n\.tr(?:In)?\(\s*(?:[^,()"]+,\s*)?"([A-Za-z][\w.\-]*\.)"\s*\+"""),
    re.compile(r"""\b(?:t|tn|tNodes)\(\s*\\?['"]([A-Za-z][\w.\-]*\.)\\?['"]\s*\+"""),
]
usate, costruite = {}, set()
for f in glob.glob(os.path.join(radice, "src/main/java/**/*.java"), recursive=True) + \
         glob.glob(os.path.join(radice, "src/main/resources/pages/*")):
    testo = open(f, encoding="utf-8", errors="replace").read()
    if f.endswith(".java"):
        testo = "\n".join(r for r in testo.split("\n") if not r.lstrip().startswith(("*", "//", "/*")))
    for rx in USI:
        for k in rx.findall(testo): usate.setdefault(k, os.path.basename(f))
    for rx in COSTRUITE:
        costruite |= set(rx.findall(testo))
assenti = sorted(k for k in usate if k not in it and not (k + ".one" in it and k + ".other" in it)
                 and not k.endswith(".") and not any(k.startswith(p) for p in costruite))
print(f"  chiavi usate dal codice: {len(usate)}, che i file di lingua non hanno: {len(assenti)}"
      f"   (costruite con un prefisso, non controllabili: {len(costruite)})")
for k in assenti[:20]:
    guasti.append(f"il codice usa la chiave {k}, che non c'e' nei file di lingua ({usate[k]})")

if guasti:
    print()
    for g in guasti:
        print(f"    NO  {g}")
    print(f"\n{len(guasti)} GUASTI")
    sys.exit(1)
print("\nTUTTO OK")
