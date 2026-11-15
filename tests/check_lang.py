#!/usr/bin/env python3
"""The language files are text, and names of the CODE slipped into them.

An r26 rename made on the text (bloccati -> lockedPackages, sbloccati -> unlockedPackages,
eseguibile -> runnable, misurato -> measured, haConflitti -> hasConflicts) also hit
src/main/resources/lang/it.json, and nobody noticed: the panel wrote on the page "Verranno
unlockedPackages postfix-mysql" and "Il piano non e' runnable". The compiler does not see inside
a JSON, and no test read those texts. Thirty-eight occurrences, found by chance looking at the
output of a guided update.

Four checks, three general and one explicit:

  1. the two languages have the SAME keys. A key added on one side only is a line that does not
     exist in the other language.
  2. the {placeholders} match key by key. It is the same defect as r26 ("a name that travels
     between two parts"): renamed on one side, the interpolation no longer replaces anything and
     the text shows the brace to the user.
  3. no camelCase token in the texts, outside the placeholders, except a short and motivated
     whitelist. It is the general part: the code's names are almost always camelCase, so this
     catches the future ones too.
  4. in it.json, no word from an explicit list of English code names that really ended up
     there. This is NOT a general net — it is a list, and its limit must be said: there is no
     dictionary here, so a new lowercase English word is caught by nobody. The list grows when
     one is found.

Run from the project root:  python3 tests/check_lang.py
It runs on the Mac: it reads two files of the repository and does not touch the system.
"""
import json
import re
import sys
import os

root = sys.argv[1] if len(sys.argv) > 1 else "."
IT = os.path.join(root, "src/main/resources/lang/it.json")
EN = os.path.join(root, "src/main/resources/lang/en.json")

# Legitimate camelCase, measured on 23/10/2026. Each has a reason:
#  - product names written as their makers write them
#  - placeholders written by hand in the texts, where NN stands for a version number
#  - fail2ban configuration directives, quoted because the user finds them in the file
ALLOWED_CAMEL = {
    "iPhone", "iPad", "macOS", "iOS",
    "phpNN", "mysqlNN", "py3NN",
    "maxRetry", "findTime", "banTime",
    "nAtteso", "nTrovato", "nAttendi", "nExpected", "nFound", "nWait",
}

# Code names that never belong in an Italian text. Next to each, the Italian word the text must
# use: it helps whoever fixes it, and says it is not an abstract ban.
ENGLISH_BANNED_IN_ITALIAN = {
    "runnable": "eseguibile",
    "measured": "misurato",
    "lockedPackages": "bloccati",
    "unlockedPackages": "sbloccati",
    "hasConflicts": "conflitti",
}

CAMEL = re.compile(r"\b[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b")
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def text_without_placeholders(v):
    """The text as a person reads it: the {placeholders} are not text."""
    return PLACEHOLDER.sub(" ", v)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


it, en = load(IT), load(EN)
failures = []

# --- 1. the same keys ---
only_it, only_en = sorted(set(it) - set(en)), sorted(set(en) - set(it))
print(f"  keys: it {len(it)}, en {len(en)}")
for k in only_it[:10]:
    failures.append(f"key only in it.json: {k}")
for k in only_en[:10]:
    failures.append(f"key only in en.json: {k}")

# --- 2. the placeholders match ---
different = 0
for k in sorted(set(it) & set(en)):
    a, b = it[k], en[k]
    if not isinstance(a, str) or not isinstance(b, str):
        continue
    pa, pb = set(PLACEHOLDER.findall(a)), set(PLACEHOLDER.findall(b))
    if pa != pb:
        different += 1
        failures.append(f"different placeholders on {k}: only it {sorted(pa - pb)}, only en {sorted(pb - pa)}")
print(f"  keys with different placeholders between the two languages: {different}")

# --- 3. camelCase in the texts ---
camel = {}
for label, d in (("it", it), ("en", en)):
    for k, v in d.items():
        if not isinstance(v, str):
            continue
        for tok in CAMEL.findall(text_without_placeholders(v)):
            if tok in ALLOWED_CAMEL:
                continue
            camel.setdefault((label, tok), []).append(k)
print(f"  camelCase tokens not allowed in the texts: {len(camel)}")
for (label, tok), key_list in sorted(camel.items()):
    failures.append(f"camelCase in {label}.json: {tok} ({len(key_list)} keys, e.g. {key_list[0]})")

# --- 4. English code words in the Italian texts ---
english = {}
for k, v in it.items():
    if not isinstance(v, str):
        continue
    source_text = text_without_placeholders(v)
    for word, instead in ENGLISH_BANNED_IN_ITALIAN.items():
        if re.search(r"\b" + re.escape(word) + r"\b", source_text):
            english.setdefault(word, []).append(k)
print(f"  English code words in the Italian texts: {len(english)}")
for word, key_list in sorted(english.items()):
    failures.append(f'it.json has "{word}" (the word is "{ENGLISH_BANNED_IN_ITALIAN[word]}"): '
                  f"{len(key_list)} keys, e.g. {key_list[0]}")

# --- 5. and the browser tests must not EXPECT the broken text either ---
#
# The broken text had a consumer: tests/packages-browser-test.js looked for "3 lockedPackages" in
# the page, so the test would have turned red when the Italian was fixed — or, worse, it would
# have stayed green on a wrong text. A name that travels between two parts is changed on all the
# parts in the same pass (r26), and the tests are one of those parts.
# Only inside the STRINGS: in those files "measured: true" and "unlockedPackages: ['nginx']" are
# JSON keys of the simulated server — that is the real names of the contract, which belong there.
# Looking at the whole file, the net reported them: two false positives, seen and removed.
import glob
LITERAL = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*\"""" + '"' + r"""|`(?:[^`\\]|\\.)*`""")
# Only the camelCase names (lockedPackages, hasConflicts): they are never text, in either language. A real English word
# of the list ("measured", "runnable") is the right text in the many tests that run the pages in English
# (english-pages-browser-test.js expects "not measured" in a reply of fail2ban), and that it is not in the Italian text
# is check 4's job: with it.json clean, a test expecting it in Italian turns red, it does not stay green.
test_sources = {}
for f in sorted(glob.glob(os.path.join(root, "tests/*.js"))):
    content = open(f, encoding="utf-8", errors="replace").read()
    strings = " ".join(LITERAL.findall(content))
    for word in ENGLISH_BANNED_IN_ITALIAN:
        if not CAMEL.fullmatch(word):
            continue
        if re.search(r"\b" + re.escape(word) + r"\b", strings):
            test_sources.setdefault(word, []).append(os.path.basename(f))
print(f"  code words expected by the browser tests: {len(test_sources)}")
for word, files in sorted(test_sources.items()):
    failures.append(f'a test expects "{word}" in the text (the word is '
                  f'"{ENGLISH_BANNED_IN_ITALIAN[word]}"): {", ".join(files)}')

# --- 6. the placeholders the TEXT asks for must be those the CODE passes ---
#
# A third side again: `I18n.tr("key", Map.of("reason", ...))` against a text saying {motivo}.
# The interpolation replaces nothing and the user reads the brace. Measured on 23/10/2026 running
# the full maintenance on the VM: the log showed "dovecot -> TRATTENUTO: {motivo}". Seven keys,
# all from the same half-done rename (motivo -> reason, uscita -> output) with the language files
# left behind. Check 2 did not see them: it.json and en.json BOTH said {motivo}, so they matched
# each other.
#
# The call-site parser takes the strings near the key, so the set of names passed is wider than
# the truth: the approximation is on the side that does NOT make up faults, and every placeholder
# reported here is passed from nowhere.
import glob

# A text that a generated shell script prints goes through echo() of UpdateManager, which turns every {NAME} in
# capitals into the shell variable "$NAME" (server.um.jvs.wrongUser: {USER_NOW}, {LISTENER_USER}, read by sockstat while
# the script runs). Those are filled by the script, not by the Map: they are passed only if EVERY call of the key
# is inside echo( ... ).
SHELL_VARIABLE = re.compile(r"[A-Z_]{1,20}")
sites, shell_only = {}, {}
for f in glob.glob(os.path.join(root, "src/main/java/**/*.java"), recursive=True):
    t = open(f, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r'I18n\.tr\(\s*"([A-Za-z0-9_.]+)"\s*,', t):
        tail = t[m.end():m.end() + 1500]
        stop = tail.find(");")
        if stop > 0:
            tail = tail[:stop]
        sites.setdefault(m.group(1), set()).update(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*,', tail))
        in_echo = re.search(r"\becho\(\s*$", t[max(0, m.start() - 20):m.start()]) is not None
        shell_only[m.group(1)] = shell_only.get(m.group(1), True) and in_echo

without = 0
for key, passed in sorted(sites.items()):
    if key not in it:
        continue
    expected = set(PLACEHOLDER.findall(it[key])) | set(PLACEHOLDER.findall(en.get(key, "")))
    missing = sorted(x for x in expected - passed if not (shell_only.get(key) and SHELL_VARIABLE.fullmatch(x)))
    if missing:
        without += 1
        failures.append(f'the text of {key} asks for {missing} and the code does not pass them '
                      f"(it passes {sorted(passed)[:6]}): the user would read the brace")
print(f"  texts asking for a placeholder the code does not pass: {without}")

# --- 7. and the same in the JavaScript: t('key', { name: ... }) ---
#
# Check 6 looks at the Java Map.of. The page passes the placeholders with an object, and a rename
# of the JSON keys made on the text would change them as if they were keys of the response:
# t('ad.reportsToFwd', { address: ... }) with the text asking for {indirizzo}. The object's
# top-level keys are looked at, and they must be among the text's placeholders (tn also has n).
JS_CALL = re.compile(r"""\b(t|tn|tNodes)\(\s*\\?['"]([A-Za-z0-9_.\-]+)\\?['"]\s*,\s*(?:[^,{}()'"]+,\s*)?\{""")
js_sources = glob.glob(os.path.join(root, "src/main/resources/pages/*.js")) + \
              glob.glob(os.path.join(root, "src/main/java/**/*.java"), recursive=True)
js_calls, js_different = 0, 0
for f in js_sources:
    source_text = open(f, encoding="utf-8", errors="replace").read()
    for m in JS_CALL.finditer(source_text):
        function, key = m.group(1), m.group(2)
        i, depth = m.end() - 1, 0
        while i < len(source_text):
            if source_text[i] == "{": depth += 1
            elif source_text[i] == "}":
                depth -= 1
                if depth == 0: break
            i += 1
        flat = re.sub(r"\([^()]*\)|\[[^\[\]]*\]|\{[^{}]*\}", "", source_text[m.end():i])
        passed = set(re.findall(r"(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?::|(?=,|$))", flat))
        js_calls += 1
        if key not in it or not isinstance(it[key], str):
            continue
        requested = set(PLACEHOLDER.findall(it[key])) | ({"n"} if function == "tn" else set())
        for label in sorted(passed - requested):
            js_different += 1
            failures.append(f"{os.path.basename(f)}: {function}('{key}') passes {{{label}}}, the text asks for {sorted(requested)}")
print(f"  JavaScript calls with placeholders: {js_calls}, with names the text does not ask for: {js_different}")

# --- 8. every key the code uses exists ---
#
# The opposite of check 1: a key renamed in the language file and not in the code (or the other
# way round) makes the key's NAME appear on the page, without errors. The literal keys of
# I18n.tr, t/tn/tNodes, {{t:...}} and data-i18n are looked for, and they must exist (for tn,
# key.one and key.other are enough). Those built with a prefix + value cannot be checked here,
# and they are counted. In the Java the comment lines do not count: a comment can quote
# {{t:key}} as an example.
USES = [
    re.compile(r"""\bI18n\.tr(?:In)?\(\s*(?:[^,()"]+,\s*)?"([A-Za-z][\w.\-]*)\""""),
    re.compile(r"""\b(?:t|tn|tNodes)\(\s*\\?['"]([A-Za-z][\w.\-]*)\\?['"]"""),
    re.compile(r"""\{\{t:([A-Za-z][\w.\-]*)\}\}"""),
    re.compile(r"""data-i18n(?:-[a-z]+)?=\\?["']([A-Za-z][\w.\-]*)\\?["']"""),
]
BUILT = [
    re.compile(r"""\bI18n\.tr(?:In)?\(\s*(?:[^,()"]+,\s*)?"([A-Za-z][\w.\-]*\.)"\s*\+"""),
    re.compile(r"""\b(?:t|tn|tNodes)\(\s*\\?['"]([A-Za-z][\w.\-]*\.)\\?['"]\s*\+"""),
]
used, built = {}, set()
for f in glob.glob(os.path.join(root, "src/main/java/**/*.java"), recursive=True) + \
         glob.glob(os.path.join(root, "src/main/resources/pages/*")):
    source_text = open(f, encoding="utf-8", errors="replace").read()
    if f.endswith(".java"):
        source_text = "\n".join(r for r in source_text.split("\n") if not r.lstrip().startswith(("*", "//", "/*")))
    for rx in USES:
        for k in rx.findall(source_text): used.setdefault(k, os.path.basename(f))
    for rx in BUILT:
        built |= set(rx.findall(source_text))
absent = sorted(k for k in used if k not in it and not (k + ".one" in it and k + ".other" in it)
                 and not k.endswith(".") and not any(k.startswith(p) for p in built))
print(f"  keys used by the code: {len(used)}, which the language files do not have: {len(absent)}"
      f"   (built with a prefix, not checkable: {len(built)})")
for k in absent[:20]:
    failures.append(f"the code uses the key {k}, which is not in the language files ({used[k]})")
# --- 9. the code -> text tables read codes somebody produces ---
#
# The page translates a server code with a table: ({ consistent: t('up.eConsistent'),
# absent: t('up.eMissing') })[v] || v. If the code changes in the server and not in the table, the
# page shows the raw code instead of the text, without errors. Measured on 24/10/2026: the rename
# of the codes had changed "coerente" -> "consistent" in the server and left the table with
# coerente, so an Italian read "consistent". A table is an object literal with at least two
# entries, all of the kind  key: t('...'). Every key must appear as a string literal elsewhere in
# the code (Java or JavaScript, outside the tables themselves), or as an enum constant (name()
# sends it out with its name).
def code_tables(text):
    """The tables (start, end, keys) in a text, searched by hand: no parser here."""
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
    """Used with [code]: ({...})[v], or const NAME = {...} and then NAME[...]. An object
    { title: t(...), desc: t(...) } is a card of texts, not a table, and does not count."""
    if re.match(r"\s*\)?\s*\[", text[end:end + 20]): return True
    name = re.search(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$", text[max(0, start - 80):start])
    return bool(name and re.search(r"(?<![\w$.])" + re.escape(name.group(1)) + r"\s*\[", text[end:]))
def java_without_comments(src):
    """The Java without comments, read character by character: a regex /\\*.*?\\*/ takes for a
    comment also "/usr/local/*" inside a string, and eats the code up to the first */."""
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
code_files = glob.glob(os.path.join(root, "src/main/java/**/*.java"), recursive=True) + \
             glob.glob(os.path.join(root, "src/main/resources/pages/*"))
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
    # a composite key like "postfix:stop" (service + action) is looked at by parts
    return all(p in produced or p in enum_names for p in k.split(":"))
orphans = [(f, line, k) for f, line, keys in tables for k in keys if not is_produced(k)]
print(f"  code -> text tables: {len(tables)}, with {sum(len(k) for _, _, k in tables)} codes;"
      f" codes nobody produces: {len(orphans)}")
for f, line, k in orphans[:20]:
    failures.append(f"the table in {f}:{line} translates the code \"{k}\", which the code produces nowhere")

if failures:
    print()
    for g in failures:
        print(f"    NO  {g}")
    print(f"\n{len(failures)} FAULTS")
    sys.exit(1)
print("\nALL OK")
