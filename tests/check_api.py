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

The second part does the same for the plain calls, route by route (reperto 224):
  - from the page:   fetch('/api/route?key=' + ..., { body: JSON.stringify({ action: 'x', key: ... }) })
  - from the route:  context("/api/route", ..., this::handler), and in that handler (and in the
                     methods it hands the JSON to) extractParamFromQuery(..., "key"), case "x",
                     "x".equals(action), and req.optString("key") on its JSONObjects.
The first part could not see them: the Sieve dialogs of the Mailboxes page sent conditions and
actions as JSON text (JSON.stringify inside JSON.stringify) to a route that reads them with
optJSONArray, which gives null for a text; asked GET /api/sieve?id= of a route that knew only
mailbox_id; sent id where the route reads filter_id and rule_id. No filter could be created,
edited or deleted, and no forward deleted. Reported there:
  4. a key of the query or of the body the handler of that route does NOT read: dead;
  5. an action the handler of that route does not know;
  6. a key sent as text (JSON.stringify, a string) that the route reads as an array or object;
  7. (warning) a key the handler reads, but in another action.
Calls whose route, body or action are computed cannot be attributed: they are counted.

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


# ---------- second part: the plain fetch calls, route by route ----------

def skip_java_literal(text, i):
    """i is on a quote, a text block or a comment of Java: the index just after it (else i)."""
    if text.startswith('"""', i):
        j = text.find('"""', i + 3)
        return len(text) if j < 0 else j + 3
    if text[i] in "\"'":
        q, j = text[i], i + 1
        while j < len(text) and text[j] != q:
            j += 2 if text[j] == "\\" else 1
        return j + 1
    if text.startswith("//", i):
        j = text.find("\n", i)
        return len(text) if j < 0 else j
    if text.startswith("/*", i):
        j = text.find("*/", i + 2)
        return len(text) if j < 0 else j + 2
    return i


def java_block(text, i):
    """The { ... } of Java starting at the brace at i, skipping strings, characters and comments."""
    depth, j = 0, i
    while j < len(text):
        k = skip_java_literal(text, j)
        if k != j:
            j = k
            continue
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return text[i:]


def skip_js_literal(text, i):
    """i is on a quote of JavaScript ('...', "...", `...` with ${...} inside): the index after it."""
    q, j = text[i], i + 1
    while j < len(text):
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == q:
            return j + 1
        if q == "`" and text.startswith("${", j):
            j = js_close(text, j + 1) + 1
            continue
        j += 1
    return j


def js_close(text, i):
    """i is on an opening bracket of JavaScript: the index of the one that closes it."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack, j = [], i
    while j < len(text):
        c = text[j]
        if c in "'\"`":
            j = skip_js_literal(text, j)
            continue
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")}]":
            if not stack or stack.pop() != c:
                return j
            if not stack:
                return j
        j += 1
    return len(text) - 1


def js_split(text):
    """The pieces of text separated by commas at the outermost level."""
    parts, depth, start, j = [], 0, 0, 0
    while j < len(text):
        c = text[j]
        if c in "'\"`":
            j = skip_js_literal(text, j)
            continue
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:j])
            start = j + 1
        j += 1
    parts.append(text[start:])
    return [x.strip() for x in parts if x.strip()]


def js_object(text):
    """The members of an object literal: {key: value text}; None if it is not one (or has a ...spread)."""
    text = text.strip()
    if not text.startswith("{") or js_close(text, 0) != len(text) - 1:
        return None
    members = {}
    for part in js_split(text[1:-1]):
        if part.startswith("..."):
            return None
        m = re.match(r"""(?:([A-Za-z_$][\w$]*)|'([^']*)'|"([^"]*)")\s*:\s*(.*)$""", part, re.S)
        if m:
            members[m.group(1) or m.group(2) or m.group(3)] = m.group(4).strip()
        elif re.fullmatch(r"[A-Za-z_$][\w$]*", part):
            members[part] = part
        else:
            return None
    return members


def literal_actions(value):
    """The actions an action: value can be: 'x', or c ? 'x' : 'y'. Empty if computed."""
    value = value.strip()
    m = re.fullmatch(r"'([a-z0-9_]+)'|" + r'"([a-z0-9_]+)"', value)
    if m:
        return {m.group(1) or m.group(2)}
    m = re.fullmatch(r"[^?]+\?\s*'([a-z0-9_]+)'\s*:\s*'([a-z0-9_]+)'", value, re.S)
    if m:
        return {m.group(1), m.group(2)}
    return set()


def sent_as_text(value):
    """A value that reaches the server as a string, whatever it holds: JSON.stringify(...), or a
    single string literal ('...', "...", `...`)."""
    value = value.strip()
    if value.startswith("JSON.stringify("):
        return True
    return value[:1] in "'\"`" and skip_js_literal(value, 0) == len(value)


# The page's calls.
calls, unattributed = [], 0
for m in re.finditer(r"\bfetch\(", page):
    open_paren = m.end() - 1
    args = js_split(page[open_paren + 1:js_close(page, open_paren)])
    if not args:
        continue
    url = args[0]
    first = re.match(r"""\s*(['"`])(/api/[^'"`?$]*)""", url)
    if not first:
        unattributed += 1
        continue
    route = first.group(2)
    query = set()
    for lit in re.findall(r"""'[^']*'|"[^"]*"|`[^`]*`""", url):
        query.update(re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_]*)=", lit))
    body = None
    options = js_object(args[1]) if len(args) > 1 else None
    if len(args) > 1 and options is None:
        unattributed += 1
    if options and "body" in options:
        b = options["body"]
        if b.startswith("JSON.stringify(") and b.endswith(")"):
            body = js_object(b[len("JSON.stringify("):-1])
        if body is None:
            unattributed += 1
    line = page.count("\n", 0, m.start()) + 1
    calls.append((route, query, body, line))

# The routes: their handlers in SSLMailServer, and the methods that take a JSONObject.
handlers = {}
for m in re.finditer(r'context\(\s*"(/[^"]*)"', routes):
    nxt = routes.find("context(", m.end())
    seg = routes[m.end():nxt if nxt > 0 else len(routes)]
    h = re.search(r"\b(\w+)::(\w+)\s*\)", seg)
    if h:
        handlers[m.group(1)] = (h.group(1), h.group(2))
methods = {}
for m in re.finditer(r"(?:private|public|protected|static)[\w<>\[\], ?]*\s(\w+)\(([^)]*)\)\s*(?:throws [\w., ]+)?\{", routes):
    methods.setdefault(m.group(1), []).append((m.group(2), java_block(routes, m.end() - 1)))


def handler_text(name):
    """The handler's code, then the methods it hands a JSONObject to (transitively): one piece each."""
    seen, todo, parts = set(), [name], []
    while todo:
        n = todo.pop()
        if n in seen:
            continue
        seen.add(n)
        for params, code in methods.get(n, []):
            if n != name and "JSONObject" not in params:
                continue
            parts.append(params + " " + code)
            todo.extend(re.findall(r"\b(\w+)\(", code))
    return parts


def route_facts(pieces):
    code = "\n".join(pieces)
    """What a handler reads: query keys, actions, body keys per action (and before any), structured keys."""
    # The body is read from its JSONObjects (JSONObject req = ..., a parameter JSONObject req) or
    # straight from new JSONObject(body).
    receivers = set(re.findall(r"\bJSONObject\s+(\w+)\s*[=,)]", code))
    source = r"new\s+JSONObject\([^()]*\)"
    if receivers:
        source += r"|\b(?:%s)" % "|".join(sorted(receivers))
    body_read = re.compile(r"(?:%s)\.(opt|get)([A-Za-z]*)\(\s*\"([A-Za-z_][A-Za-z0-9_]*)\"" % source)
    marker = re.compile(r'case\s+"([a-z0-9_]+)"(?:\s*,\s*"[a-z0-9_]+")*\s*->|"([a-z0-9_]+)"\.equals\(\s*action\s*\)'
                        r'|\baction\.equals\(\s*"([a-z0-9_]+)"\s*\)')
    actions, shared, per_action, everywhere, structured = set(), set(), {}, set(), set()
    # Piece by piece: a read belongs to the last action named before it in its own piece; before any (or in a
    # method the handler calls, whose action the handler chose) it is shared.
    for piece in pieces:
        marks = [(m.start(), set(re.findall(r'"([a-z0-9_]+)"', m.group(0)))) for m in marker.finditer(piece)]
        for _, a in marks:
            actions |= a
        for r in body_read.finditer(piece):
            key = r.group(3)
            everywhere.add(key)
            if r.group(2) in ("JSONArray", "JSONObject"):
                structured.add(key)
            before = [a for pos, a in marks if pos < r.start()]
            if before:
                for a in before[-1]:
                    per_action.setdefault(a, set()).add(key)
            else:
                shared.add(key)
    # The three ways the routes read their query: extractParamFromQuery(q, "key"), queryParameter(raw, "key"),
    # extractIdFromQuery(q) for "id".
    query_read = set(re.findall(r'(?:extractParamFromQuery|queryParameter)\([^;]*?,\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)', code))
    if re.search(r"\bextractIdFromQuery\(", code):
        query_read.add("id")
    return {"actions": actions, "shared": shared, "per_action": per_action, "everywhere": everywhere,
            "structured": structured, "query": query_read}


facts, elsewhere, fetch_failures, fetch_warnings, checked = {}, set(), [], [], 0
for route, query, body, line in calls:
    where = f"line {line}: {route}"
    if route not in handlers:
        fetch_failures.append(f"{where}: no route of SSLMailServer has this path")
        continue
    owner, name = handlers[route]
    if owner != "this":
        elsewhere.add(route)
        continue
    if name not in facts:
        facts[name] = route_facts(handler_text(name))
    f = facts[name]
    checked += 1
    for k in sorted(query):
        if k not in f["query"]:
            fetch_failures.append(f'{where}: the query sends "{k}" and the route does NOT read it')
    if not body:
        continue
    sent_actions = literal_actions(body["action"]) if "action" in body else set()
    for a in sorted(sent_actions):
        if f["actions"] and a not in f["actions"]:
            fetch_failures.append(f'{where}: the page sends the action "{a}", which the route does not know')
    for k, v in sorted(body.items()):
        if k in ("action", "csrf_token"):
            continue
        if k not in f["everywhere"]:
            fetch_failures.append(f'{where}: sends "{k}" and the route does NOT read it')
            continue
        if k in f["structured"] and sent_as_text(v):
            fetch_failures.append(f'{where}: sends "{k}" as text ({v[:40]}), the route reads it as an array or object')
        for a in sorted(sent_actions):
            if k not in f["shared"] and k not in f["per_action"].get(a, set()):
                fetch_warnings.append(f'{where}: "{a}" sends "{k}", which the route reads but in another action')

print()
print(f"  fetch calls to /api/: {len(calls)}, checked against their route: {checked}"
      f"   (route served by another class: {len(elsewhere)}; route, options or body computed: {unattributed})")
print(f"  fetch keys or actions the route does not read, or text for an array: {len(fetch_failures)}")
print(f"  fetch keys read in another action (warning): {len(fetch_warnings)}")
warnings += fetch_warnings
failures += fetch_failures

print()
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
