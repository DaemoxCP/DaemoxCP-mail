#!/bin/sh
# Tests the simulation on a COPY of pkg's database, against a fake pkg.
#
# What must be shown cannot be seen by reading the code: that the unlock happens in the copy and
# not in the real database, that the protected dependencies pkg names get added, and that the copy
# vanishes at the end. On the server it is not tested by playing with the real locks; here a fake
# pkg answers only the commands PackagePlan uses and keeps the "locks" as files in $FAKE_DB/locked.
#
# To be run from the project root, AFTER building the jar and compiling the tests.
set -e
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/db/locked"
touch "$TMP/db/locked/kafka" "$TMP/db/locked/openjdk21" "$TMP/db/locked/nginx"
# The family-twin case: mysql84-client protected, and postfix-mysql to upgrade.
touch "$TMP/db/locked/mysql84-client" "$TMP/db/locked/mysql84-server" "$TMP/db/locked/postfix-mysql"
cat > "$TMP/bin/pkg" <<'FAKE'
#!/bin/sh
DB="$FAKE_DB"
if [ "$1" = "config" ]; then echo "$FAKE_DB"; exit 0; fi
if [ "$1" = "-o" ]; then DB="${2#PKG_DBDIR=}"; shift 2; fi
case "$1" in
  query)
    case "$2" in
      %v) case "$3" in
            pkg) echo "2.1.0" ;;
            mysql84-client) echo "${V_INST:-8.4.11_1}" ;;
          esac ;;
      # The list of installed packages, to recognise the family twin.
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
      low=$(printf '%s\n%s\n' "$3" "$4" | sort -V | head -1)
      if [ "$low" = "$3" ]; then echo "<"; else echo ">"; fi
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
          # For pkg a protected package is "unavailable": if mysql84-client is protected, it
          # looks for another provider of the same library and proposes mysql97-client.
          # Unlocked, it goes back to using the one that is there.
          if [ "${MYSQL97:-if-locked}" = "always" ] || [ -f "$DB/locked/mysql84-client" ]; then
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
echo "fake pkg: unexpected command: $*" >&2
exit 1
FAKE
chmod +x "$TMP/bin/pkg"
FAKE_DB="$TMP/db" PATH="$TMP/bin:$PATH" \
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PackagePlanTest simulation

# The family twin, two cases that need a different fake pkg. Every run starts again from a clean
# state of the locks: the first unlocks mysql84-client in the COPY, not here, but the third
# really wants it unprotected.
touch "$TMP/db/locked/mysql84-client"
echo
echo "--- the protected twin, but with a newer catalog ---"
FAKE_DB="$TMP/db" PATH="$TMP/bin:$PATH" V_CAT="8.4.12" \
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PackagePlanTest family-new-catalog

echo
echo "--- the twin installed but NOT protected: a real conflict ---"
rm -f "$TMP/db/locked/mysql84-client"
FAKE_DB="$TMP/db" PATH="$TMP/bin:$PATH" MYSQL97="always" \
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PackagePlanTest family-real-conflict
