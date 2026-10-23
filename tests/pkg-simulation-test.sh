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
# Il caso del gemello di famiglia: mysql84-client protetto, e postfix-mysql da aggiornare.
touch "$TMP/db/locked/mysql84-client" "$TMP/db/locked/mysql84-server" "$TMP/db/locked/postfix-mysql"
cat > "$TMP/bin/pkg" <<'FINTO'
#!/bin/sh
DB="$FINTO_DB"
if [ "$1" = "config" ]; then echo "$FINTO_DB"; exit 0; fi
if [ "$1" = "-o" ]; then DB="${2#PKG_DBDIR=}"; shift 2; fi
case "$1" in
  query)
    case "$2" in
      %v) case "$3" in
            pkg) echo "2.1.0" ;;
            mysql84-client) echo "${V_INST:-8.4.11_1}" ;;
          esac ;;
      # L'elenco degli installati, per il riconoscimento del gemello di famiglia.
      %n) echo "kafka"; echo "openjdk21"; echo "nginx"; echo "postfix-mysql"
          echo "mysql84-client"; echo "mysql84-server"; echo "python312" ;;
    esac
    exit 0 ;;
  rquery)
    case "$4" in
      pkg) echo "2.2.0" ;;
      mysql84-client) echo "${V_CAT:-8.4.11_1}" ;;
    esac
    exit 0 ;;
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
        postfix-mysql)
          # Per pkg un pacchetto protetto e' "non disponibile": se mysql84-client e'
          # protetto, cerca un altro fornitore della stessa libreria e propone
          # mysql97-client. Sbloccato, torna a usare quello che c'e'.
          if [ "${MYSQL97:-se-protetto}" = "sempre" ] || [ -f "$DB/locked/mysql84-client" ]; then
            printf 'Installed packages to be UPGRADED:\n\tpostfix-mysql: 3.11.7_1,1 -> 3.11.7_3,1\n\n'
            printf 'New packages to be INSTALLED:\n\tmysql97-client: 9.7.2\n\n'
            printf 'Number of packages to be upgraded: 1\nNumber of packages to be installed: 1\n'
          else
            printf 'Installed packages to be UPGRADED:\n\tpostfix-mysql: 3.11.7_1,1 -> 3.11.7_3,1\n\nNumber of packages to be upgraded: 1\n'
          fi ;;
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

# Il gemello di famiglia, due casi che hanno bisogno di un pkg finto diverso. Ogni lancio
# riparte da uno stato pulito dei lock: il primo sblocca mysql84-client nella COPIA, non qui,
# ma il terzo lo vuole davvero non protetto.
touch "$TMP/db/locked/mysql84-client"
echo
echo "--- il gemello protetto, ma col catalogo piu' recente ---"
FINTO_DB="$TMP/db" PATH="$TMP/bin:$PATH" V_CAT="8.4.12" \
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackagePlanTest famiglia-catalogo-nuovo

echo
echo "--- il gemello installato ma NON protetto: conflitto vero ---"
rm -f "$TMP/db/locked/mysql84-client"
FINTO_DB="$TMP/db" PATH="$TMP/bin:$PATH" MYSQL97="sempre" \
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackagePlanTest famiglia-conflitto-vero
