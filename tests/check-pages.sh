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
mvn -o -q package -DskipTests

DIR=$(mktemp -d)
javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java
java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator "$DIR" >/dev/null
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

rm -rf "$DIR"
echo
if [ "$ko" -eq 0 ]; then echo "ALL $tot PAGES HAVE VALID JAVASCRIPT"; else echo "$ko PAGES OF $tot WITH BROKEN JAVASCRIPT"; fi
if [ "$ko" -ne 0 ] || [ "$brokenStructure" -ne 0 ]; then exit 1; fi
