#!/bin/sh
# Genera tutte le pagine del pannello e ne controlla il JavaScript con un parser vero.
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
rm -rf "$DIR"
echo
if [ "$ko" -eq 0 ]; then echo "TUTTE LE $tot PAGINE HANNO JAVASCRIPT VALIDO"; else echo "$ko PAGINE SU $tot CON JAVASCRIPT ROTTO"; exit 1; fi
