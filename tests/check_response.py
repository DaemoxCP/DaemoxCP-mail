#!/usr/bin/env python3
"""The names of the RESPONSE fields cross two parts: the server puts them in a JSON, the page's
JavaScript reads them with a dot. Renamed on one side only, the read returns undefined and the
function dies silently.

It is the defect that on 17 October 2026 killed "Run now" in the Cron page: CronManagement sent
exitCode and output, the page read e.codice and e.uscita, and "undefined === 0" is false, so every
successful job was declared in error. It compiled, no warning. This net's companion is
tests/check_api.py, which does the same thing the other way round (the parameters the page SENDS
and the route reads).

How it works:
  1. from the routes: case "action" -> which server methods build the response;
  2. from the server: the keys those methods put, plus those of the methods they call (one
     level, because a response is made of nested objects);
  3. from the page: in the function that calls updApi('action'), the fields read from the
     variable that receives the response.
A field read that nobody puts is reported.

The approximation is ON PURPOSE and all on one side: the set of the server's keys is wider than
the truth (the keys of the called methods are taken too). So the net does not shout for nested
objects, and stays true when it says "nobody puts this key".

Run from the project root:  python3 tests/check_response.py
It runs on the Mac: it reads files of the repository and does not touch the system.
"""
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
PAGE = os.path.join(root, "src/main/java/org/daemoxcp/mail/content/MailPanelContent.java")
ROUTES = os.path.join(root, "src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java")
# All the project's classes outside the page: the routes also call Autoconfig, AppleProfile,
# PeriodicReport, AutoDns. With only the five classes of before, an action of those showed as
# "not verifiable" or, worse, attributed to a same-named method of another route.
import glob as _g
SERVER = sorted(os.path.relpath(f, root) for f in _g.glob(os.path.join(root, "src/main/java/org/daemoxcp/mail/**/*.java"), recursive=True)
                if "/content/" not in f)
CLASSES = sorted({os.path.splitext(os.path.basename(f))[0] for f in SERVER}, key=len, reverse=True)

# The envelope every response has, put by the common paths and not by the action's method.
ENVELOPE = {"success", "error", "jobId", "async", "job", "warning"}

page = open(PAGE, encoding="utf-8", errors="replace").read()
# And the pages written as separate files (see check_api.py: the same hole).
import glob as _glob
for _f in sorted(_glob.glob(os.path.join(root, "src/main/resources/pages/*.js"))):
    page += "\n" + open(_f, encoding="utf-8", errors="replace").read()
routes = open(ROUTES, encoding="utf-8", errors="replace").read()
server = {}
for rel in SERVER:
    p = os.path.join(root, rel)
    if os.path.exists(p):
        server[os.path.basename(p)] = open(p, encoding="utf-8", errors="replace").read()


def method_body(text, name):
    """The bodies of a method and its overloads, balancing the braces from the signature. '' if it is not there."""
    bodies = []
    for m in re.finditer(r"\b(?:JSONObject|JSONArray|String|boolean|int|long)\s+" + re.escape(name) + r"\s*\(", text):
        i = text.find("{", m.end())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append(text[i:j + 1])
                    break
            j += 1
    return "\n".join(bodies)


def keys_of(name, depth=1, seen=None):
    """The keys the method puts, plus those of the methods it calls (one level)."""
    seen = seen or set()
    if name in seen or depth < 0:
        return set()
    seen.add(name)
    outside = set()
    for text in server.values():
        body = method_body(text, name)
        if not body:
            continue
        outside |= set(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', body))
        if depth > 0:
            for called in set(re.findall(r"\b([a-z][A-Za-z0-9_]*)\s*\(", body)):
                outside |= keys_of(called, depth - 1, seen)
    return outside


# --- 1. action -> server methods ---
CASE = re.compile(r'case\s+"([a-z0-9_]+)"\s*->')
cases = [(m.group(1), m.start()) for m in CASE.finditer(routes)]
methods = {}
in_block = {}
for n, (action, start) in enumerate(cases):
    end = cases[n + 1][1] if n + 1 < len(cases) else len(routes)
    block = routes[start:end]
    # the response can be built in the route itself: response.put("key", ...)
    in_block.setdefault(action, set()).update(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', block))
    methods.setdefault(action, set()).update(
        re.findall(r"\b(?:" + "|".join(CLASSES) + r")\.([a-zA-Z_][A-Za-z0-9_]*)\s*\(", block)
        # and the methods called on an instance (autoDns.create(...)): it counts only if the method
        # exists in a class of the project, that is if keys_of finds its body
        + [n for n in re.findall(r"\b[a-z][A-Za-z0-9_]*\.([a-z][A-Za-z0-9_]*)\s*\(", block)
           if n not in ("put", "opt", "optString", "optInt", "optLong", "optBoolean", "optJSONArray", "optJSONObject",
                        "getString", "getInt", "getBoolean", "has", "equals", "length", "isEmpty", "trim", "toString")])

# --- 2. the page: function that calls updApi('action') -> fields read ---
FUNCTION = re.compile(r"(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
starts = [(m.group(1), m.start()) for m in FUNCTION.finditer(page)]
read_fields = {}
for n, (fn_name, start) in enumerate(starts):
    end = starts[n + 1][1] if n + 1 < len(starts) else len(page)
    body = page[start:end]
    for m in re.finditer(r"(?:const|let|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*await\s+[a-zA-Z]+Api\(\s*'([a-z0-9_]+)'", body):
        var, action = m.group(1), m.group(2)
        # The reads of this binding: up to the next binding of the same name (const r = ..., r = ..., an arrow r => ...).
        # Before, the whole function counted, and «Aggiorna tutto» was reported for r.checks and r.services: in the
        # same function a second "const r" takes the answer of package_preflight / java_preflight (an action computed
        # here, so not seen), which does put them (reperto 230).
        again = re.compile(r"(?<![.\w$])" + re.escape(var) + r"\s*=(?!=)").search(body, m.end())
        segment = body[m.end():again.start() if again else len(body)]
        fields = set(re.findall(r"(?<![.\w$])" + re.escape(var) + r"\.([A-Za-z_][A-Za-z0-9_]*)", segment))
        read_fields.setdefault(action, set()).update(fields)

print(f"  actions with a response read by the page: {len(read_fields)}")
failures = []
for action in sorted(read_fields):
    if action not in methods or not methods[action]:
        # No method recognised: the response is built in the route itself. Nothing can be said,
        # and it says that nothing can.
        print(f"    --  {action}: response built in the route, not verifiable here")
        continue
    available = set(ENVELOPE) | in_block.get(action, set())
    for method in methods[action]:
        available |= keys_of(method)
    for k in sorted(read_fields[action] - available):
        failures.append(f'the page reads "{k}" from the response of "{action}", which nobody puts '
                      f"(methods: {', '.join(sorted(methods[action]))})")

# --- 2. and the tests' FAKES must not send names the server does not send ---
#
# It was the third side of the same name, and the most insidious: the fakes of
# packages-browser-test.js, english-pages-browser-test.js and pkg-branch-browser-test.js sent
# "spiegazione" while the server sends "explanation", so the tests were GREEN against a dead
# page. Twelve reads of "spiegazione", three of "descrizione", two of "problemi", four of
# "motivo", two of "uscita": twenty-three fields that in production were undefined, and no test
# could say so because the tests were talking to themselves.
#
# It looks inside the objects passed to json(route, ...) and in the UPPERCASE constants the fakes
# use as a response: those are the shape of the response, and must be the real shape.
import glob

# Responses the server does NOT build with .put(...), so the vocabulary does not see them.
# Each measured on 23/10/2026: the firewalls and the DKIM rotation compose them elsewhere.
OUT_OF_VOCABULARY = {
    "panel_bl_cidrs", "panel_wl_cidrs", "panel_geo_bl", "panel_geo_wl",
    "last_rotation_at_ms", "next_rotation_at_ms", "live_state_all", "strength_label",
}

vocabulary = set()
for f in glob.glob(os.path.join(root, "src/main/java/**/*.java"), recursive=True):
    vocabulary |= set(re.findall(r'\.put\("([A-Za-z_][A-Za-z0-9_]*)"', open(f, encoding="utf-8", errors="replace").read()))
actions = set(re.findall(r'case\s+"([a-z0-9_]+)"\s*->', routes))


def object_text(t, i):
    while i < len(t) and t[i] in " \t\r\n":
        i += 1
    if i >= len(t) or t[i] != "{":
        return ""
    depth, j = 0, i
    while j < len(t):
        if t[j] == "{":
            depth += 1
        elif t[j] == "}":
            depth -= 1
            if depth == 0:
                return t[i:j + 1]
        j += 1
    return ""


fakes = {}
for f in sorted(glob.glob(os.path.join(root, "tests/*.js"))):
    t = open(f, encoding="utf-8", errors="replace").read()
    blocks = [object_text(t, m.end()) for m in re.finditer(r"json\(\s*route\s*,", t)]
    blocks += [object_text(t, m.end()) for m in re.finditer(r"^const\s+[A-Z][A-Z0-9_]*\s*=\s*", t, re.M)]
    for b in blocks:
        for k in set(re.findall(r"[{,]\s*([a-z][A-Za-z0-9_]*)\s*:", b)):
            if k in vocabulary or k in actions or k in OUT_OF_VOCABULARY:
                continue
            fakes.setdefault(k, set()).add(os.path.basename(f))
print(f"  names the fakes send and the server does not: {len(fakes)}")
for k, files in sorted(fakes.items()):
    failures.append(f'a fake sends "{k}", which the server puts nowhere: '
                  f"{', '.join(sorted(files))}")

print(f"  fields read and never put: {len(failures)}")
if failures:
    print()
    for g in failures:
        print(f"    NO  {g}")
    print(f"\n{len(failures)} FAULTS")
    sys.exit(1)
print("\nALL OK")
