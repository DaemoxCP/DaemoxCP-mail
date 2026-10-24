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

# --- 8. le tabelle codice -> testo leggono codici che qualcuno produce ---
#
# La pagina traduce un codice del server con una tabella: ({ consistent: t('up.eConsistent'),
# absent: t('up.eMissing') })[v] || v. Se il codice cambia nel server e non nella tabella, la
# pagina mostra il codice grezzo al posto del testo, senza errori. Misurato il 24/10/2026: la
# rinomina dei codici aveva cambiato "coerente" -> "consistent" nel server e lasciato la tabella
# con coerente, quindi un italiano leggeva «consistent». Una tabella e' un oggetto letterale con
# almeno due voci, tutte del tipo  chiave: t('...'). Ogni chiave deve comparire come stringa
# letterale altrove nel codice (Java o JavaScript, fuori dalle tabelle stesse), oppure come
# costante di enum (name() la manda fuori col suo nome).
def code_tables(text):
    """Le tabelle (inizio, fine, chiavi) in un testo, cercate a mano: niente parser qui."""
    out = []
    entry = re.compile(r"""\s*(?:'([^'\n]+)'|"([^"\n]+)"|([A-Za-z_$][\w$]*))\s*:\s*t\(\s*\\?'[\w.\-]+\\?'\s*\)\s*(,|\})""")
    for m in re.finditer(r"\{", text):
        keys, i = [], m.end()
        while True:
            e = entry.match(text, i)
            if not e: break
            keys.append(next(g for g in e.groups()[:3] if g is not None))
            i = e.end()
            if e.group(4) == "}":
                if len(keys) >= 2 and is_lookup(text, m.start(), i): out.append((m.start(), i, keys))
                break
    return out
def is_lookup(text, start, end):
    """Usata con [codice]: ({...})[v], oppure const NOME = {...} e poi NOME[...]. Un oggetto
    { title: t(...), desc: t(...) } e' una scheda di testi, non una tabella, e non conta."""
    if re.match(r"\s*\)?\s*\[", text[end:end + 20]): return True
    name = re.search(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$", text[max(0, start - 80):start])
    return bool(name and re.search(r"(?<![\w$.])" + re.escape(name.group(1)) + r"\s*\[", text[end:]))
def java_without_comments(src):
    """Il Java senza commenti, letto carattere per carattere: una regex /\\*.*?\\*/ prende per
    commento anche "/usr/local/*" dentro una stringa, e si mangia il codice fino al primo */."""
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith('"""', i):
            j = src.find('"""', i + 3)
            while j > 0 and src[j - 1] == "\\": j = src.find('"""', j + 1)
            j = n if j < 0 else j + 3
            out.append(src[i:j]); i = j
        elif src[i] in "\"'":
            q, j = src[i], i + 1
            while j < n and src[j] != q and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1]); i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i); i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2); i = n if j < 0 else j + 2
            out.append(" ")
        else:
            out.append(src[i]); i += 1
    return "".join(out)
code_files = glob.glob(os.path.join(radice, "src/main/java/**/*.java"), recursive=True) + \
             glob.glob(os.path.join(radice, "src/main/resources/pages/*"))
tables, produced, enum_names = [], set(), set()
for f in code_files:
    text = open(f, encoding="utf-8", errors="replace").read()
    found = code_tables(text)
    for a, b, keys in found:
        tables.append((os.path.basename(f), text.count("\n", 0, a) + 1, keys))
    for a, b, keys in reversed(found):
        text = text[:a] + " " * (b - a) + text[b:]
    if f.endswith(".java"):
        text = java_without_comments(text)
        for body in re.findall(r"\benum\s+\w+[^{]*\{([^;}]*)", text):
            enum_names |= set(re.findall(r"\b([A-Z][A-Z0-9_]*)\b", body))
    produced |= set(re.findall(r'"((?:\\.|[^"\\\n])*)"', text))
    produced |= set(re.findall(r"'((?:\\.|[^'\\\n])*)'", text))
def is_produced(k):
    # una chiave composta come "postfix:stop" (servizio + azione) si guarda per parti
    return all(p in produced or p in enum_names for p in k.split(":"))
orphans = [(f, line, k) for f, line, keys in tables for k in keys if not is_produced(k)]
print(f"  tabelle codice -> testo: {len(tables)}, con {sum(len(k) for _, _, k in tables)} codici;"
      f" codici che nessuno produce: {len(orphans)}")
for f, line, k in orphans[:20]:
    guasti.append(f"la tabella in {f}:{line} traduce il codice \"{k}\", che il codice non produce da nessuna parte")

if guasti:
    print()
    for g in guasti:
        print(f"    NO  {g}")
    print(f"\n{len(guasti)} GUASTI")
    sys.exit(1)
print("\nTUTTO OK")
