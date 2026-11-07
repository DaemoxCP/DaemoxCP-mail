#!/usr/bin/env python3
"""The DOM namespace crosses FOUR surfaces, not three:
   pages/*.js, pages/*.html, the JavaScript inside the .java files, and tests/*.js.
The browser tests are CONSUMERS: they look for ids and selectors the application must create,
but they create none. Not looking at them let 35 dead references through when the "ramo"
family became "branch".

It checks on the union:
  - every function called from an on* attribute is declared somewhere
  - every id the application looks for is created somewhere
  - every id/selector the TESTS look for is created by the application

Three things to know, or the net shouts for nothing:
  - passwordField("X") generates ids X, XErr, XShow, XCopy via %1$s
  - the built ids ('ver-' + k) give a PREFIX, not an id
  - in the tests, a selector with .count() === 0 asserts that it is NOT there
"""
import re, sys, glob, os

# The root is the first argument that is NOT an option. Before it was argv[1] whatever it was,
# so "check_dom.py --quiet" took "--quiet" for a folder: the globs found nothing, the net printed
# zero problems and exited ZERO. A check that cannot fail is worse than no check, and this one
# could not even notice.
folders = [a for a in sys.argv[1:] if not a.startswith("-")]
root = folders[0] if folders else "."
quiet = "--quiet" in sys.argv

def read_sources(pats, rec=False):
    out = []
    for p in pats:
        for f in sorted(glob.glob(os.path.join(root, p), recursive=rec)):
            try: out.append((f, open(f, encoding='utf-8', errors='replace').read()))
            except Exception: pass
    return out

app  = read_sources(['src/main/resources/pages/*.js', 'src/main/resources/pages/*.html'])
app += read_sources(['src/main/java/**/*.java'], rec=True)
test_sources = read_sources(['tests/*.js'])
A = "\n".join(s for _, s in app)

# ---- handlers called from on* ----
# the whole VALUE of the attribute, then every call inside: onkeyup="if(...)loadLogs()"
# contains two, and the old net saw only "if", which is a keyword.
ATTR = re.compile(r'on(?:click|change|input|submit|keyup|focus|blur)\s*=\s*\\{0,2}(["\'])((?:(?!\1)[^\\]|\\.)*)\1')
KW = {'if','else','for','while','do','switch','case','return','typeof','instanceof',
      'new','delete','void','function','this','try','catch','finally','throw','await','in','of'}
GLOBAL_NAMES = {'Number','String','Boolean','Array','Object','JSON','Math','Date','parseInt',
           'parseFloat','encodeURIComponent','decodeURIComponent','alert','confirm','prompt',
           'setTimeout','setInterval','getElementById','querySelector','querySelectorAll'}
calls = set()
for m in ATTR.finditer(A):
    v = m.group(2)
    for c in re.finditer(r'([A-Za-z_$][\w$]*)\s*\(', v):
        if c.group(1) in KW: continue
        if c.start() and v[c.start()-1] == '.': continue   # a method call, not a function
        if c.group(1) in GLOBAL_NAMES: continue
        calls.add(c.group(1))
calls = sorted(calls)
def declared(n):
    e = re.escape(n)
    return re.search(r'function\s+'+e+r'\b|(?:const|let|var)\s+'+e+r'\b'
                     r'|\b'+e+r'\s*=\s*(?:async\s*)?(?:function\b|\(|[A-Za-z_$])'
                     r'|\b'+e+r'\s*:\s*(?:async\s*)?(?:function\b|\()', A)
orphans = [c for c in calls if not declared(c)]

# ---- ids created by the application ----
created  = set(re.findall(r'id\s*=\s*\\{0,2}["\']([A-Za-z0-9_$-]+)', A))
created |= set(re.findall(r"\.id\s*=\s*\\{0,2}['\"]([A-Za-z0-9_$-]+)", A))
# passwordField("X") -> X, XErr, XShow, XCopy
for m in re.finditer(r'passwordField\(\s*"([A-Za-z0-9_-]+)"', A):
    b = m.group(1); created |= {b, b+"Err", b+"Show", b+"Copy"}
# built prefixes: 'ver-' + k, 'pk-det-' + i
prefixes = set(re.findall(r"""['"]([A-Za-z0-9_-]*-)['"]\s*\+""", A))
# ids written with a String.format placeholder: id="%s-status", id="%1$s"
patterns = []
wildcard = []
for lit in set(re.findall(r'id\s*=\s*\\{0,2}["\']([A-Za-z0-9_$%-]*%[0-9$]*s[A-Za-z0-9_$-]*)', A)):
    fixed = re.sub(r'%[0-9]*\$?s', '', lit).strip('-_')
    if not fixed:
        wildcard.append(lit)   # id="%s" alone would absolve ANY id: discarded
        continue
    patterns.append(re.compile("^" + re.sub(r'%[0-9]*\$?s', '[A-Za-z0-9_-]+', re.escape(lit).replace('\\%','%').replace('\\$','$')) + "$"))

def resolved(i):
    if i in created: return True
    if any(i.startswith(p) for p in prefixes if p): return True
    return any(r.match(i) for r in patterns)

# ---- ids the application looks for ----
g = re.compile(r"getElementById\(\s*\\{0,2}['\"]([A-Za-z0-9_$-]+)\\{0,2}['\"]?(\s*\+)?")
sought = sorted(set(m.group(1) for m in g.finditer(A) if not m.group(2)))
missing = [i for i in sought if not resolved(i)]

# ---- ids/selectors the tests look for (consumers) ----
NEG = re.compile(r"\.count\(\)\s*===\s*0")
SEL = re.compile(r"""getElementById\(['"]([A-Za-z0-9_-]+)['"]\)|['"`]#([A-Za-z0-9_-]+)""")
from_tests, negatives = {}, set()
for f, s in test_sources:
    for line in s.splitlines():
        neg = bool(NEG.search(line))
        for m in SEL.finditer(line):
            i = m.group(1) or m.group(2)
            if line[m.end():m.end()+6].lstrip().startswith("+"): continue  # a prefix, not an id
            if neg: negatives.add(i)
            else: from_tests.setdefault(i, set()).add(os.path.basename(f))
dead = {i: v for i, v in from_tests.items() if not resolved(i)}

# ---- the links' anchors ----
# A link to a card carries its id after the hash: href="/updates#branch",
# a.href = '/updates#branch', data-bs-target="#hetznerGuide". If the id changes and the anchor
# does not, the link opens the page and no longer leads to the card, without errors. Measured on
# 29/10/2026: Home sent to /updates#ramo since the card has been called branch.
ANCHOR = re.compile(r"""(?:href|data-bs-target)\s*=\s*\\{0,2}["'][^"'#\s]*#([A-Za-z][A-Za-z0-9_-]*)\\{0,2}["']"""
                    r"""|\.href\s*=\s*\\{0,2}['"][^'"#\s]*#([A-Za-z][A-Za-z0-9_-]*)\\{0,2}['"]""")
anchors = sorted(set(m.group(1) or m.group(2) for m in ANCHOR.finditer(A)))
broken_anchors = [i for i in anchors if not resolved(i)]

# Zero files is not "zero problems": it is "I looked at nothing". It is said and it exits badly,
# otherwise a wrong root passes for a green net.
if not app or not test_sources:
    print(f"  NOTHING TO CHECK in {root!r}: application files {len(app)}, test files {len(test_sources)}.")
    print("  The root is wrong, or the files are not there: in neither case is this a green net.")
    sys.exit(2)

print(f"  application files: {len(app)}   test files: {len(test_sources)}")
print(f"  functions called from on*: {len(calls)}   without a declaration: {len(orphans)}")
for o in orphans[:10]: print(f"    orphan: {o}")
print(f"  ids the application looks for: {len(sought)}   never created: {len(missing)}")
for m in missing[:10]: print(f"    never created: {m}")
print(f"  links' anchors: {len(anchors)}   towards ids never created: {len(broken_anchors)}")
for i in broken_anchors[:10]: print(f"    dead anchor: #{i}")
print(f"  ids/selectors the TESTS look for: {len(from_tests)}   never created: {len(dead)}")
for i in sorted(dead): print(f"    DEAD IN THE TESTS: {i:<22} {', '.join(sorted(dead[i]))}")
if not quiet:
    print(f"  (known built prefixes: {len(prefixes)}; format patterns: {len(patterns)}; "
          f"discarded wildcards: {wildcard}; selectors asserted ABSENT, excluded: {len(negatives)})")
sys.exit(1 if (orphans or missing or dead or broken_anchors) else 0)
