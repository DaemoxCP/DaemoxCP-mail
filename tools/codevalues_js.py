"""The status codes in the JavaScript (pages, JavaScript inside the Java strings, fakes of the tests)."""
import re, sys, glob, collections
root, mapfile = sys.argv[1], sys.argv[2]
dry = "--dry" in sys.argv
mp = dict(l.split() for l in open(mapfile, encoding="utf-8") if l.strip() and not l.startswith("#"))
alt = "|".join(sorted(map(re.escape, mp), key=len, reverse=True))
Q = r"""(\\?['"])"""
V = r"(" + alt + r")"
PATS_ALL = [
    re.compile(r"((?:===|!==|==|!=)\s*)" + Q + V + r"\2"),
    re.compile(Q + V + r"\1(\s*(?:===|!==|==|!=))"),
    re.compile(r"([{,]\s*[\w$]+\s*:\s*)" + Q + V + r"\2(?=\s*[,}\n])"),
]
PATS_PAGE = [
    re.compile(r"((?:\?|:|\breturn|\bcase)\s*)" + Q + V + r"\2"),
    re.compile(r"(\bvalue=)" + Q + V + r"\2"),
    re.compile(r"([\[,]\s*)" + Q + V + r"\2(?=\s*[,\]])"),
]
counts = collections.Counter()
def apply(text, pats, where):
    for p in pats:
        def r(m):
            g = m.groups()
            counts[where] += 1
            if p.pattern.startswith(Q):
                return g[0] + mp[g[1]] + g[0] + g[2]
            return g[0] + g[1] + mp[g[2]] + g[1]
        text = p.sub(r, text)
    return text
def string_ranges(t):
    out, i, n = [], 0, len(t)
    while i < n:
        if t.startswith('"""', i):
            j = t.find('"""', i + 3); j = n if j < 0 else j + 3; out.append((i, j)); i = j
        elif t[i] == '"':
            j = i + 1
            while j < n and t[j] != '"' and t[j] != "\n": j += 2 if t[j] == "\\" else 1
            out.append((i, j + 1)); i = j + 1
        elif t[i] == "'":
            j = i + 1
            while j < n and t[j] != "'" and t[j] != "\n": j += 2 if t[j] == "\\" else 1
            i = j + 1
        elif t.startswith("//", i):
            j = t.find("\n", i); i = n if j < 0 else j
        elif t.startswith("/*", i):
            j = t.find("*/", i + 2); i = n if j < 0 else j + 2
        else: i += 1
    return out
changed = 0
for f in sorted(glob.glob(f"{root}/src/main/resources/pages/*") + glob.glob(f"{root}/tests/*.js")):
    t = open(f, encoding="utf-8").read()
    page = "/pages/" in f
    t2 = apply(t, PATS_ALL + (PATS_PAGE if page else []), "pages" if page else "prove")
    if t2 != t:
        changed += 1
        if not dry: open(f, "w", encoding="utf-8").write(t2)
for f in sorted(glob.glob(f"{root}/src/main/java/**/*.java", recursive=True)):
    if f.endswith("PathMigration.java"): continue
    t = open(f, encoding="utf-8").read()
    parts, last = [], 0
    for a, b in string_ranges(t):
        seg = t[a:b]
        # only the Java strings that contain JavaScript (a string that is only a code has
        # already gone through ValueRename)
        if len(seg) > 12 and re.search(r"===|!==|\breturn\b|=>|function|\bcase\b|value=", seg):
            seg = apply(seg, PATS_ALL + PATS_PAGE, "javascript in the java")
        parts.append(t[last:a]); parts.append(seg); last = b
    parts.append(t[last:]); t2 = "".join(parts)
    if t2 != t:
        changed += 1
        if not dry: open(f, "w", encoding="utf-8").write(t2)
print(f"files changed: {changed}{' (dry run)' if dry else ''}", dict(counts))
