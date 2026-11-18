#!/bin/sh
# Generates every page of the panel and checks its JavaScript with a real parser, then the
# structure of the HTML (at the end).
#
# It finds the class of error the Java compiler does NOT see: inside a text block the
# backslash-n sequence is a Java escape, it becomes a real newline and breaks the JavaScript
# string. The browser stops there and the whole page is left without scripts — every spinner
# turns and it looks as if the calls never finish, while they never started.
#
# To be run from the project root, BEFORE handing over a jar.
set -e

# The jar is BUILT AGAIN before looking at it.
#
# Without this line, if the build fails the check runs on the OLD jar and announces "all valid"
# while the source is broken. It happened on 03/09/2026: the green message came from a jar twenty
# minutes old. A check that measures something other than what it seems to measure is worse than
# no check.
#
# With a folder as argument it checks the pages already generated there by PageGenerator (on the test VM, where
# the Java programs run: run.sh of the series writes them in pages-panel), without building anything:
#   sh tests/check-pages.sh <folder with the pages, assets/ and i18n/>
# Only the temporary folder made here is removed at the end: a folder given as argument is someone else's, and until
# 08/11/2026 it was deleted too (reperto 196).
OWN_DIR=
if [ -n "${1:-}" ]; then
    DIR=$1
    [ -d "$DIR/assets" ] || { echo "$DIR has no assets/: not a folder written by PageGenerator"; exit 2; }
else
    mvn -o -q package -DskipTests
    DIR=$(mktemp -d)
    OWN_DIR=$DIR
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.content.PageGenerator "$DIR" >/dev/null
fi
python3 - "$DIR" <<'PY'
import io, re, glob, sys
for f in sorted(glob.glob(sys.argv[1] + "/*.html")):
    s = io.open(f, encoding="utf-8").read()
    js = "\n;\n".join(p for p in re.findall(r"<script\b[^>]*>(.*?)</script>", s, re.S) if p.strip())
    io.open(f[:-5] + ".js", "w", encoding="utf-8").write(js)
PY
ko=0; tot=0
for f in "$DIR"/*.js; do
    tot=$((tot+1)); n=$(basename "$f" .js)
    if node --check "$f" 2>/dev/null; then
        printf "  OK       %s\n" "$n"
    else
        printf "  ERROR    %s\n" "$n"; node --check "$f" 2>&1 | sed -n '2,4p' | sed 's/^/           /'
        ko=$((ko+1))
    fi
done
# The script files. Since the strict CSP (no inline script) the JavaScript of every page is in the files the page
# loads, /assets/*.js and /i18n/*.js: what the loop above extracts from the pages is empty, and it answered "valid"
# on every page while /account and /settings did not load their script at all (reperto 191). A file that does not
# parse is named with the pages that load it.
assets=0
for f in $(find "$DIR/assets" "$DIR/i18n" -name '*.js' 2>/dev/null | sort); do
    assets=$((assets+1)); rel=${f#$DIR}
    if node --check "$f" 2>/dev/null; then
        printf "  OK       %s\n" "$rel"
    else
        printf "  ERROR    %s, loaded by: %s\n" "$rel" "$(grep -l "src=\"${rel}" "$DIR"/*.html | xargs -n1 basename | tr '\n' ' ')"
        node --check "$f" 2>&1 | sed -n '2,4p' | cut -c1-200 | sed 's/^/           /'
        ko=$((ko+1))
    fi
done
if [ "$assets" -eq 0 ]; then echo "  ERROR    no script file under $DIR/assets: the pages load nothing I can check"; ko=$((ko+1)); fi
tot=$((tot+assets))
# No browser dialog: confirmations are the panel's window (panelAsk, panelConfirm) and messages its notices (panelSay),
# reperto 198. A call to alert(), confirm() or prompt() in a page's script is a fault, named with the file and the
# line; window.confirm inside panelAsk (its fallback when a page has no window) is not a call of this kind.
dialogs=$(python3 - "$DIR" <<'PY'
import glob, re, sys
call = re.compile(r'(?<![A-Za-z0-9_.$])(alert|confirm|prompt)\s*\(')
for f in sorted(glob.glob(sys.argv[1] + '/assets/*.js')):
    for i, line in enumerate(open(f, encoding='utf-8'), 1):
        code = re.sub(r'//.*$', '', line)
        code = re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", "''", code)
        for m in call.finditer(code):
            print('/assets/' + f.rsplit('/', 1)[1] + ':' + str(i) + ': ' + m.group(1) + '(')
PY
)
if [ -n "$dialogs" ]; then
    echo "$dialogs" | sed 's/^/  ERROR    browser dialog in /'
    ko=$((ko+$(echo "$dialogs" | wc -l)))
else
    echo "  OK       no browser dialog (alert, confirm, prompt) in the scripts"
fi
# The structure: every element opened must be closed, and the footer sits directly in <body>.
#
# The JavaScript check above does not see it, and the browser does not report it either: it
# repairs broken HTML silently, in its own way. On 26/09/2026 the /firewall page did not close its
# container, and the footer ended up inside the 1200px box instead of across the whole page.
if python3 - "$DIR" <<'PY'
import sys, glob, os
from html.parser import HTMLParser

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}

class Structure(HTMLParser):
    # script and style: HTMLParser passes their content as text, the tags inside JS strings do not count.
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.troubles = [], []
    def handle_starttag(self, tag, attrs):
        if tag == "footer" and [t for t, _ in self.stack] != ["html", "body"]:
            self.troubles.append("footer inside " + " > ".join(e for _, e in self.stack))
        if tag not in VOID:
            a = dict(attrs)
            name = tag + ("." + a["class"].split()[0] if a.get("class") else "") + ("#" + a["id"] if a.get("id") else "")
            self.stack.append((tag, "%s (line %d)" % (name, self.getpos()[0])))
    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                if i != len(self.stack) - 1:
                    self.troubles.append("</%s> at line %d also closes %s"
                                         % (tag, self.getpos()[0], ", ".join(e for _, e in self.stack[i + 1:])))
                del self.stack[i:]
                return
        self.troubles.append("</%s> at line %d without an opening" % (tag, self.getpos()[0]))

broken = 0
pages = sorted(glob.glob(sys.argv[1] + "/*.html"))
for f in pages:
    p = Structure()
    p.feed(open(f, encoding="utf-8").read())
    p.close()
    troubles = p.troubles + (["still open: " + ", ".join(e for _, e in p.stack)] if p.stack else [])
    if troubles:
        broken += 1
        print("  STRUCTURE %s" % os.path.basename(f)[:-5])
        for g in troubles[:5]:
            print("           " + g)
print()
print("STRUCTURE IN PLACE IN ALL %d PAGES" % len(pages) if broken == 0
      else "%d PAGES OF %d WITH A BROKEN STRUCTURE" % (broken, len(pages)))
sys.exit(1 if broken else 0)
PY
then brokenStructure=0; else brokenStructure=1; fi

[ -n "$OWN_DIR" ] && rm -rf "$OWN_DIR"
echo
if [ "$ko" -eq 0 ]; then echo "ALL $tot PAGES AND SCRIPT FILES HAVE VALID JAVASCRIPT"; else echo "$ko PAGES OR SCRIPT FILES OF $tot WITH BROKEN JAVASCRIPT"; fi
if [ "$ko" -ne 0 ] || [ "$brokenStructure" -ne 0 ]; then exit 1; fi
