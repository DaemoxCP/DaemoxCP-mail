"""Rinomina le chiavi JSON italiane in tutte le parti che le usano, nello stesso passo.

Una chiave JSON e' una stringa: nessun compilatore la risolve, quindi la rinomina si fa solo
nei contesti in cui la stringa e' certamente una chiave, e il resto si elenca per una revisione
a mano. Le garanzie vere vengono dopo, dalle reti che confrontano chi scrive e chi legge
(check_response.py, check_api.py) e dalle prove da browser.

Contesti in cui si cambia:
  Java    primo argomento letterale di put/accumulate/append/opt*/get*/has/remove/isNull;
          dentro le stringhe Java, il JavaScript che ci sta scritto (regole qui sotto).
  JS      .chiave e ?.chiave non seguite da "(";  ['chiave'] e ["chiave"];
          chiave di un oggetto letterale preceduta da "{" o "," e seguita da ":".
Si elencano senza cambiarle: le stringhe sciolte 'chiave' nel JavaScript e le proprieta'
abbreviate { chiave } / , chiave } / { chiave, .

Uso: python3 jsonkeys.py <radice> <mappa.txt> [--dry]
"""
import re
import sys
import glob
import collections

root, mapfile = sys.argv[1], sys.argv[2]
dry = "--dry" in sys.argv
mp = dict(l.split() for l in open(mapfile, encoding="utf-8") if l.strip())
alt = "|".join(sorted(map(re.escape, mp), key=len, reverse=True))
counts = collections.Counter()
review = []

JAVA_CALL = re.compile(r'(\.(?:put|accumulate|append|opt\w*|get(?:String|Int|Long|Boolean|Double|Float|Number|BigDecimal|BigInteger|JSONArray|JSONObject|Enum)?|has|remove|isNull)\(\s*)"(' + alt + r')"')
JS_PROP = re.compile(r'((?:\?\.|(?<![\w$])\.|(?<=[\w$\])"\'])\.))(' + alt + r')\b(?![\w-]|\s*\()')
JS_BRACKET = re.compile(r"(\[\s*)(['\"])(" + alt + r")\2(\s*\])")
JS_OBJKEY = re.compile(r"([{,]\s*)(" + alt + r")(\s*:)(?!:)")
JS_QUOTED_OBJKEY = re.compile(r"([{,]\s*)(['\"])(" + alt + r")\2(\s*:)")
JS_LOOSE = re.compile(r"(?<![\w$\[])(['\"])(" + alt + r")\1(?!\s*[\]:])")
JS_SHORT = re.compile(r"[{,]\s*(" + alt + r")\s*(?=[,}])")


import json as _json
I18N_KEYS = set(_json.load(open(f"{root}/src/main/resources/lang/it.json", encoding="utf-8")))
# Le chiavi di traduzione citate nel codice ('pkgs.m.nome', {{t:acc.nome}}) hanno punti dentro:
# .nome li' non e' una proprieta'. Si mascherano prima delle regole e si rimettono dopo.
MASKABLE = re.compile(r"""(\\?['"])([A-Za-z][\w-]*(?:\.[\w-]+)+)\1|\{\{t:[^}]+\}\}""")


def mask(text):
    saved = []
    def m(mo):
        whole = mo.group(0)
        if mo.group(2) is None or mo.group(2) in I18N_KEYS or any(mo.group(2).startswith(k + ".") for k in ()):
            saved.append(whole)
            return f"\x00{len(saved) - 1}\x00"
        return whole
    return MASKABLE.sub(m, text), saved


def unmask(text, saved):
    return re.sub(r"\x00(\d+)\x00", lambda mo: saved[int(mo.group(1))], text)


def js_rename(text, where):
    """Le regole del JavaScript su un pezzo di testo. Restituisce il testo nuovo."""
    text, saved = mask(text)
    text = _js_rename(text, where)
    return unmask(text, saved)


def _js_rename(text, where):
    def r_prop(m):
        counts["js ." + where] += 1
        return m.group(1) + mp[m.group(2)]
    text = JS_PROP.sub(r_prop, text)
    def r_br(m):
        counts["js [] " + where] += 1
        return m.group(1) + m.group(2) + mp[m.group(3)] + m.group(2) + m.group(4)
    text = JS_BRACKET.sub(r_br, text)
    def r_qobj(m):
        counts["js {'k':} " + where] += 1
        return m.group(1) + m.group(2) + mp[m.group(3)] + m.group(2) + m.group(4)
    text = JS_QUOTED_OBJKEY.sub(r_qobj, text)
    protected = i18n_object_ranges(text)
    def r_obj(m):
        if any(a <= m.start(2) < b for a, b in protected):
            counts["js {k:} lasciata, segnaposto di t()"] += 1
            return m.group(0)
        counts["js {k:} " + where] += 1
        return m.group(1) + mp[m.group(2)] + m.group(3)
    text = JS_OBJKEY.sub(r_obj, text)
    return text


I18N_CALL = re.compile(r"""\b(?:t|tn|tNodes)\(\s*\\?['"][^'"]+\\?['"]\s*,\s*(?:[^,{}()'"]+,\s*)?\{""")


def i18n_object_ranges(text):
    """Gli oggetti dei segnaposto: dall'apertura della graffa alla sua chiusura."""
    out = []
    for m in I18N_CALL.finditer(text):
        i, depth = m.end() - 1, 0
        while i < len(text):
            if text[i] == "{": depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0: break
            i += 1
        out.append((m.end() - 1, i))
    return out


def note_review(text, path, offset_line=0):
    for m in JS_LOOSE.finditer(text):
        review.append((path, text.count("\n", 0, m.start()) + 1 + offset_line, "stringa sciolta", m.group(0)))
    for m in JS_SHORT.finditer(text):
        review.append((path, text.count("\n", 0, m.start()) + 1 + offset_line, "abbreviata", m.group(0).strip()))


def string_ranges(t):
    """Le stringhe di un sorgente Java (anche i text block), come intervalli."""
    out, i, n = [], 0, len(t)
    while i < n:
        if t.startswith('"""', i):
            j = t.find('"""', i + 3)
            j = n if j < 0 else j + 3
            out.append((i, j)); i = j
        elif t[i] == '"':
            j = i + 1
            while j < n and t[j] != '"' and t[j] != "\n":
                j += 2 if t[j] == "\\" else 1
            out.append((i, j + 1)); i = j + 1
        elif t[i] == "'":
            j = i + 1
            while j < n and t[j] != "'" and t[j] != "\n":
                j += 2 if t[j] == "\\" else 1
            i = j + 1
        elif t.startswith("//", i):
            j = t.find("\n", i); i = n if j < 0 else j
        elif t.startswith("/*", i):
            j = t.find("*/", i + 2); i = n if j < 0 else j + 2
        else:
            i += 1
    return out


changed = 0
for path in sorted(glob.glob(f"{root}/src/main/java/**/*.java", recursive=True) + glob.glob(f"{root}/tests/**/*.java", recursive=True)):
    t = open(path, encoding="utf-8").read()
    rel = path[len(root) + 1:]
    # 1. le chiamate dell'API JSON
    def r_call(m):
        counts["java call"] += 1
        return m.group(1) + '"' + mp[m.group(2)] + '"'
    t2 = JAVA_CALL.sub(r_call, t)
    # 2. il JavaScript scritto dentro le stringhe Java (pagine, card, script inline)
    parts, last = [], 0
    for a, b in string_ranges(t2):
        seg = t2[a:b]
        # una stringa che e' solo una chiave usata come argomento e' gia' passata dal punto 1;
        # le altre si trattano come JavaScript solo se ne hanno l'aria
        if re.search(r"[{}();=]|\.\w", seg) and len(seg) > 6:
            new = js_rename(seg, "in java")
            if new != seg:
                note_review(new, rel, t2.count("\n", 0, a))
            seg = new
        parts.append(t2[last:a]); parts.append(seg); last = b
    parts.append(t2[last:])
    t3 = "".join(parts)
    if t3 != t:
        changed += 1
        if not dry:
            open(path, "w", encoding="utf-8").write(t3)

for path in sorted(glob.glob(f"{root}/src/main/resources/pages/*.js") + glob.glob(f"{root}/src/main/resources/pages/*.html") + glob.glob(f"{root}/tests/*.js")):
    t = open(path, encoding="utf-8").read()
    rel = path[len(root) + 1:]
    t2 = js_rename(t, "file js")
    note_review(t2, rel)
    if t2 != t:
        changed += 1
        if not dry:
            open(path, "w", encoding="utf-8").write(t2)

print(f"file cambiati: {changed}{' (prova a secco)' if dry else ''}")
for k, v in sorted(counts.items()):
    print(f"  {k}: {v}")
print(f"da guardare a mano: {len(review)}")
with open(f"{root}/../jsonkeys-review.txt", "w", encoding="utf-8") as f:
    for r in review:
        f.write(f"{r[0]}:{r[1]}\t{r[2]}\t{r[3]}\n")
