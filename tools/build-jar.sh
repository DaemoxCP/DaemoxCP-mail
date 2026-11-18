#!/bin/sh
# Costruisce il jar del pannello col numero di build e il commit dentro, e ne stampa l'impronta.
#
# Maven da solo non sa leggere git: senza questo script il jar dice "build non registrata" nella
# dashboard (reperto 183). Il numero di build e' il numero di commit del ramo (git rev-list
# --count), quindi cresce a ogni commit; il commit e' quello intero. Se nei sorgenti ci sono
# modifiche non salvate in un commit, il jar lo dice: quel commit non basta a rifarlo.
#
# Uso, dalla radice del progetto (le opzioni in piu' vanno a Maven, per esempio -o):
#   tools/build-jar.sh -o
set -eu
cd "$(dirname "$0")/.."

commit=$(git rev-parse HEAD)
build=$(git rev-list --count HEAD)
modified=false
if [ -n "$(git status --porcelain -- src pom.xml)" ]; then
    modified=true
fi

# Il plugin shade riscrive dependency-reduced-pom.xml, che e' nel repository: lo si rimette
# com'era, qualunque cosa ci fosse.
saved=$(mktemp)
cp dependency-reduced-pom.xml "$saved"
status=0
mvn -B -q package -DskipTests -Dpanel.build="$build" -Dpanel.commit="$commit" -Dpanel.modified="$modified" "$@" || status=$?
cp "$saved" dependency-reduced-pom.xml
rm -f "$saved"
[ "$status" -eq 0 ] || exit "$status"

echo "build $build, commit $commit$([ "$modified" = true ] && echo ' (con modifiche non salvate in un commit)')"
if command -v sha256 >/dev/null 2>&1; then
    sha256 -q target/daemoxcp-mail.jar
else
    shasum -a 256 target/daemoxcp-mail.jar | cut -d' ' -f1
fi
