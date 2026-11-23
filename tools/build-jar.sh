#!/bin/sh
# Builds the jar of the panel with the build number and the commit inside, and prints its fingerprint.
#
# Maven alone cannot read git: without this script the jar says `build non registrata` ("build not
# recorded") in the dashboard (finding 183). The build number is the number of commits of the branch
# (git rev-list --count), so it grows with every commit; the commit is the full one. If the sources
# have changes not saved in a commit, the jar says so: that commit is not enough to rebuild it.
#
# Usage, from the project root (the extra options go to Maven, for example -o):
#   tools/build-jar.sh -o
set -eu
cd "$(dirname "$0")/.."

commit=$(git rev-parse HEAD)
build=$(git rev-list --count HEAD)
modified=false
if [ -n "$(git status --porcelain -- src pom.xml)" ]; then
    modified=true
fi

# The shade plugin rewrites dependency-reduced-pom.xml, which is in the repository: it is put back
# as it was, whatever was there.
saved=$(mktemp)
cp dependency-reduced-pom.xml "$saved"
status=0
mvn -B -q package -DskipTests -Dpanel.build="$build" -Dpanel.commit="$commit" -Dpanel.modified="$modified" "$@" || status=$?
cp "$saved" dependency-reduced-pom.xml
rm -f "$saved"
[ "$status" -eq 0 ] || exit "$status"

echo "build $build, commit $commit$([ "$modified" = true ] && echo ' (with changes not saved in a commit)')"
if command -v sha256 >/dev/null 2>&1; then
    sha256 -q target/daemoxcp-mail.jar
else
    shasum -a 256 target/daemoxcp-mail.jar | cut -d' ' -f1
fi
