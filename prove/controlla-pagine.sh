#!/bin/sh
# Genera tutte le pagine del pannello e ne controlla il JavaScript con un parser vero,
# poi la struttura dell'HTML (in fondo).
#
# Trova la classe di errore che il compilatore Java NON vede: dentro un text block la
# sequenza barra-n e' un escape Java, diventa un a capo vero e spezza la stringa
# JavaScript. Il browser si ferma li' e l'intera pagina resta senza script — tutti gli
# indicatori girano e sembra che le chiamate non finiscano, mentre non sono partite.
#
# Da eseguire dalla radice del progetto, PRIMA di consegnare un jar.
set -e

# Si RICOSTRUISCE il jar prima di guardarlo.
#
# Senza questa riga, se la compilazione fallisce il controllo gira sul jar VECCHIO e
# annuncia "tutte valide" mentre il sorgente e' rotto. E' successo il 03/09/2026: il
# messaggio verde arrivava da un jar di venti minuti prima. Un controllo che misura una
# cosa diversa da quella che sembra misurare e' peggio di nessun controllo.
mvn -o -q package -DskipTests

DIR=$(mktemp -d)
javac -cp target/freebsd-mail-panel-1.0.jar -d prove prove/org/mail_panel/content/GeneraPagine.java
java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.GeneraPagine "$DIR" >/dev/null
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
        printf "  ERRORE   %s\n" "$n"; node --check "$f" 2>&1 | sed -n '2,4p' | sed 's/^/           /'
        ko=$((ko+1))
    fi
done
# La struttura: ogni elemento aperto va chiuso, e il footer sta direttamente nel <body>.
#
# Il controllo del JavaScript qui sopra non la vede, e nemmeno il browser la segnala: l'HTML
# rotto lo ripara in silenzio, a modo suo. Il 26/09/2026 la pagina /firewall non chiudeva il
# suo contenitore, e il footer finiva dentro il riquadro largo 1200px invece che a tutta pagina.
if python3 - "$DIR" <<'PY'
import sys, glob, os
from html.parser import HTMLParser

VUOTI = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}

class Struttura(HTMLParser):
    # script e style: HTMLParser ne passa il contenuto come testo, i tag dentro le stringhe JS non contano.
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pila, self.guai = [], []
    def handle_starttag(self, tag, attrs):
        if tag == "footer" and [t for t, _ in self.pila] != ["html", "body"]:
            self.guai.append("footer dentro " + " > ".join(e for _, e in self.pila))
        if tag not in VUOTI:
            a = dict(attrs)
            nome = tag + ("." + a["class"].split()[0] if a.get("class") else "") + ("#" + a["id"] if a.get("id") else "")
            self.pila.append((tag, "%s (riga %d)" % (nome, self.getpos()[0])))
    def handle_endtag(self, tag):
        for i in range(len(self.pila) - 1, -1, -1):
            if self.pila[i][0] == tag:
                if i != len(self.pila) - 1:
                    self.guai.append("</%s> alla riga %d chiude anche %s"
                                     % (tag, self.getpos()[0], ", ".join(e for _, e in self.pila[i + 1:])))
                del self.pila[i:]
                return
        self.guai.append("</%s> alla riga %d senza apertura" % (tag, self.getpos()[0]))

rotte = 0
pagine = sorted(glob.glob(sys.argv[1] + "/*.html"))
for f in pagine:
    p = Struttura()
    p.feed(open(f, encoding="utf-8").read())
    p.close()
    guai = p.guai + (["restano aperti: " + ", ".join(e for _, e in p.pila)] if p.pila else [])
    if guai:
        rotte += 1
        print("  STRUTTURA %s" % os.path.basename(f)[:-5])
        for g in guai[:5]:
            print("           " + g)
print()
print("STRUTTURA A POSTO IN TUTTE LE %d PAGINE" % len(pagine) if rotte == 0
      else "%d PAGINE SU %d CON LA STRUTTURA ROTTA" % (rotte, len(pagine)))
sys.exit(1 if rotte else 0)
PY
then strutturaRotta=0; else strutturaRotta=1; fi

rm -rf "$DIR"
echo
if [ "$ko" -eq 0 ]; then echo "TUTTE LE $tot PAGINE HANNO JAVASCRIPT VALIDO"; else echo "$ko PAGINE SU $tot CON JAVASCRIPT ROTTO"; fi
if [ "$ko" -ne 0 ] || [ "$strutturaRotta" -ne 0 ]; then exit 1; fi
