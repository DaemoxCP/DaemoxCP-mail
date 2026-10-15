#!/bin/sh
# Prova la simulazione su COPIA del database di pkg, contro un pkg finto.
#
# Il punto da dimostrare non si vede leggendo il codice: che lo sblocco avvenga nella copia e
# non nel database vero, che le dipendenze protette nominate da pkg vengano aggiunte, e che la
# copia sparisca alla fine. Sul server non si prova giocando con i lock veri; qui un pkg finto
# risponde solo ai comandi che PackagePlan usa e tiene i "lock" come file in $FINTO_DB/locked.
#
# Da eseguire dalla radice del progetto, DOPO aver costruito il jar e compilato le prove.
set -e
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/db/locked"
touch "$TMP/db/locked/kafka" "$TMP/db/locked/openjdk21" "$TMP/db/locked/nginx"
cat > "$TMP/bin/pkg" <<'FINTO'
#!/bin/sh
DB="$FINTO_DB"
if [ "$1" = "config" ]; then echo "$FINTO_DB"; exit 0; fi
if [ "$1" = "-o" ]; then DB="${2#PKG_DBDIR=}"; shift 2; fi
case "$1" in
  query)  [ "$3" = "pkg" ] && echo "2.1.0"; exit 0 ;;
  rquery) [ "$4" = "pkg" ] && echo "2.2.0"; exit 0 ;;
  version)
    if [ "$2" = "-t" ]; then
      if [ "$3" = "$4" ]; then echo "="; exit 0; fi
      basso=$(printf '%s\n%s\n' "$3" "$4" | sort -V | head -1)
      if [ "$basso" = "$3" ]; then echo "<"; else echo ">"; fi
      exit 0
    fi ;;
  unlock) rm -f "$DB/locked/$3"; exit 0 ;;
  upgrade)
    shift 3
    for p in "$@"; do
      case "$p" in
        kafka)
          if [ -f "$DB/locked/openjdk21" ]; then
            printf 'Installed packages LOCKED:\n\tPackage openjdk21-21.0.8+9.1 is locked and may not be upgraded to version 21.0.9+10.1\n\n'
            printf 'Installed packages to be UPGRADED:\n\tkafka: 4.3.0 -> 4.3.1\n\nNumber of packages to be upgraded: 1\n'
          else
            printf 'Installed packages to be UPGRADED:\n\tkafka: 4.3.0 -> 4.3.1\n\topenjdk21: 21.0.8+9.1 -> 21.0.9+10.1\n\nNumber of packages to be upgraded: 2\n'
          fi ;;
        nginx) echo "Your packages are up to date." ;;
      esac
    done
    exit 0 ;;
esac
echo "pkg finto: comando non previsto: $*" >&2
exit 1
FINTO
chmod +x "$TMP/bin/pkg"
FINTO_DB="$TMP/db" PATH="$TMP/bin:$PATH" \
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackagePlanTest simulazione
