#!/usr/bin/env python3
"""The names of the API parameters cross TWO parts: the page's JavaScript sends them, the route
in SSLMailServer reads them. Renamed on one side only, the parameter arrives and nobody looks at
it — and the function dies silently, without an error, without a warning, without the compiler
being able to say anything (they are strings inside a JSON).

It is the same defect that on 17 October 2026 killed "Run now" in the Cron page (e.codice
against exitCode), and the same risk that kept out of the review the signature of the update of
the unprotected packages: passing a signature from the page to the API means writing the same
name in two distant files.

Here the two lists are compared:
  - from the page:   updApi('action', { key: ..., key2: ... })
  - from the route:  case "action" -> ... req.optString("key") ...

Reported:
  1. a key the page sends and the server does NOT read anywhere: dead.
     It is the defect that matters, and the server cannot notice it.
  2. an action the page calls and no route handles.
  3. (warning) a key read in another action: not necessarily a fault — some routes read the
     parameters in shared methods — but worth a look.

Run from the project root:  python3 tests/check_api.py
It runs on the Mac: it reads two files of the repository and does not touch the system.
"""
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
PAGE = os.path.join(root, "src/main/java/org/mail_panel/content/MailPanelContent.java")
ROUTES = os.path.join(root, "src/main/java/org/mail_panel/webserver/SSLMailServer.java")

page = open(PAGE, encoding="utf-8", errors="replace").read()
# Also the pages written as separate files (Home, DNS, reports, standards): they call the same
# routes with their own functions (autoDnsApi, repApi, stsApi...). Before, the net looked only at
# MailPanelContent, and it did not see a renamed route called by standards-watch.js.
import glob as _glob
for _f in sorted(_glob.glob(os.path.join(root, "src/main/resources/pages/*.js"))):
    page += "\n" + open(_f, encoding="utf-8", errors="replace").read()
routes = open(ROUTES, encoding="utf-8", errors="replace").read()


def object_after(text, i):
    """The { ... } starting at i, balancing the braces. '' if it does not start with a brace."""
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


# --- the page: action -> keys sent ---
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
# The calls with a computed action name cannot be attributed: they are counted and reported.
non_literal = len(re.findall(r"\b[a-zA-Z]+Api\(\s*[^'\s)]", page))

# --- the routes: action -> keys read, plus all the keys read in the file ---
CASE = re.compile(r'case\s+"([a-z0-9_]+)"\s*->')
READING = re.compile(r'(?:req|json|body|request)\.(?:opt|get)[A-Za-z]*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"')
cases = [(m.group(1), m.start()) for m in CASE.finditer(routes)]
reads = {}
for n, (action, start) in enumerate(cases):
    end = cases[n + 1][1] if n + 1 < len(cases) else len(routes)
    reads.setdefault(action, set()).update(READING.findall(routes[start:end]))
reads_anywhere = set(READING.findall(routes))

print(f"  updApi calls with a literal action: {len(sent)} distinct actions"
      f"   (with a computed name, not attributable: {non_literal})")
print(f"  case \"...\" routes: {len(reads)} distinct actions")

failures, warnings = [], []

for action in sorted(sent):
    if action not in reads:
        failures.append(f'the page calls "{action}" and no route handles it')
        continue
    for k in sorted(sent[action]):
        if k in reads[action]:
            continue
        if k in reads_anywhere:
            warnings.append(f'"{action}" sends "{k}", which the server reads but in another action')
        else:
            failures.append(f'"{action}" sends "{k}" and the server does NOT read it anywhere')

print(f"  keys sent and never read, or actions without a route: {len(failures)}")
print(f"  keys read in another action (warning): {len(warnings)}")
for a in warnings:
    print(f"    --  {a}")
if failures:
    print()
    for g in failures:
        print(f"    NO  {g}")
    print(f"\n{len(failures)} FAULTS")
    sys.exit(1)
print("\nALL OK")
