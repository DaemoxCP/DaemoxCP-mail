"""Translation keys and placeholders: language files, code that uses the keys, JavaScript.

  - the language files: the keys renamed, and the {placeholders} renamed inside the texts; if in
    the same text two placeholders end up with the same name, it stops;
  - the keys quoted in the code: exact strings in quotes, {{t:key}}, data-i18n;
  - the placeholders in the JavaScript: the keys of the objects passed to t()/tn()/tNodes(), and
    the shorthand properties { nome } (which become { name: nome }).
The Java of the placeholders (Map.of inside I18n.tr) is done by PlaceholderRename.java, with the compiler.

Usage: python3 i18n_rename.py <root> <keys.json> <placeholders.txt> [--dry]"""
import re, sys, json, glob, os, collections
root, keyfile, phfile = sys.argv[1], sys.argv[2], sys.argv[3]
dry = "--dry" in sys.argv
keys = json.load(open(keyfile, encoding="utf-8"))
ph = dict(l.split() for l in open(phfile, encoding="utf-8") if l.strip())
counts = collections.Counter()
problems = []

# 1. language files
PH = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
for lang in ("it", "en"):
    p = os.path.join(root, f"src/main/resources/lang/{lang}.json")
    d = json.load(open(p, encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
    out = collections.OrderedDict()
    for k, v in d.items():
        nk = keys.get(k, k)
        if nk != k: counts[f"chiavi {lang}"] += 1
        if isinstance(v, str):
            names = PH.findall(v)
            finals = [ph.get(n, n) for n in names]
            if len(set(finals)) < len(set(names)):
                problems.append(f"{lang}:{k}: due segnaposto sullo stesso nome {names}")
            def r(m):
                n = m.group(1)
                if n in ph: counts[f"segnaposto {lang}"] += 1; return "{" + ph[n] + "}"
                return m.group(0)
            v = PH.sub(r, v)
        if nk in out: problems.append(f"{lang}: chiave doppia {nk}")
        out[nk] = v
    if not dry:
        with open(p, "w", encoding="utf-8") as f:
            f.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")

# 2. the keys quoted in the code
alt = "|".join(sorted(map(re.escape, keys), key=len, reverse=True))
QK = re.compile(r"""(\\?['"])(""" + alt + r""")(\\?['"])""")
TK = re.compile(r"""\{\{t:(""" + alt + r""")\}\}""")
# 3. the placeholders in the objects of t()/tn()/tNodes()
I18N_CALL = re.compile(r"""\b(?:t|tn|tNodes)\(\s*\\?['"][^'"]+\\?['"]\s*,\s*(?:[^,{}()'"]+,\s*)?\{""")
phalt = "|".join(sorted(map(re.escape, ph), key=len, reverse=True))
OBJKEY = re.compile(r"([{,]\s*)(" + phalt + r")(\s*:)(?!:)")
SHORT = re.compile(r"([{,]\s*)(" + phalt + r")(\s*(?=[,}]))")

def js_placeholders(text, where):
    out, last = [], 0
    for m in I18N_CALL.finditer(text):
        i, depth = m.end() - 1, 0
        while i < len(text):
            if text[i] == "{": depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0: break
            i += 1
        obj = text[m.end() - 1:i + 1]
        # only the first level: the objects nested inside the values stay
        def r_key(mm):
            counts["segnaposto js " + where] += 1
            return mm.group(1) + ph[mm.group(2)] + mm.group(3)
        def r_short(mm):
            counts["segnaposto js abbreviati " + where] += 1
            return mm.group(1) + ph[mm.group(2)] + ": " + mm.group(2) + mm.group(3)
        new = OBJKEY.sub(r_key, obj)
        new = SHORT.sub(r_short, new)
        out.append(text[last:m.end() - 1]); out.append(new); last = i + 1
    out.append(text[last:])
    return "".join(out)

files = glob.glob(os.path.join(root, "src/main/java/**/*.java"), recursive=True) + glob.glob(os.path.join(root, "tests/**/*.java"), recursive=True) \
      + glob.glob(os.path.join(root, "src/main/resources/pages/*")) + glob.glob(os.path.join(root, "tests/*.js")) + glob.glob(os.path.join(root, "tests/*.py"))
changed = 0
for f in sorted(files):
    t = open(f, encoding="utf-8", errors="replace").read()
    def r_q(m):
        if m.group(1).lstrip("\\") != m.group(3).lstrip("\\"): return m.group(0)
        counts["chiavi nel codice"] += 1
        return m.group(1) + keys[m.group(2)] + m.group(3)
    # with an empty key map the alternation is empty and would match the empty string
    t2 = QK.sub(r_q, t) if keys else t
    t2 = t2 if not keys else TK.sub(lambda m: (counts.update(["chiavi {{t:}}"]) or "{{t:" + keys[m.group(1)] + "}}"), t2)
    if f.endswith((".js", ".html")) or f.endswith(".java"):
        t2 = js_placeholders(t2, "pagine" if not f.endswith(".java") else "nel java")
    if t2 != t:
        changed += 1
        if not dry: open(f, "w", encoding="utf-8").write(t2)
print(f"file di codice cambiati: {changed}{' (a secco)' if dry else ''}")
for k, v in sorted(counts.items()): print(f"  {k}: {v}")
for p in problems: print("  PROBLEMA", p)
sys.exit(1 if problems else 0)
