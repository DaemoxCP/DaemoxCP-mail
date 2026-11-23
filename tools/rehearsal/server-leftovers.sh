#!/bin/sh
# What the production mail server has in addition to the test bench, seen read-only on 2026-11-05
# (findings, point 135), redone on the test bench after RehearsalOldSetup and acme.sh as root:
#   - two certificates in /root/.acme.sh, requested with the DNS challenge (dns_cf for Cloudflare, dns by
#     hand), not with --standalone;
#   - the files with the Italian names that PathMigration renames: riavvio.log, ssl-precedente/,
#     sistema/salto.json (a FINISHED release jump, as on the server) with its inventory folder;
#     and installazione-completata, which nobody renames.
# The contents are fake but of the same shape: keys and fields as on the server, no real data.
# Usage, as root on the VM, with the old panel running: server-leftovers.sh
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
H=/root/.acme.sh
D=/var/db/mailpanel
[ -d "$H/mail.rehearsal.test_ecc" ] || { echo "manca $H/mail.rehearsal.test_ecc: prima acme.sh da root (README)"; exit 1; }

# The first certificate with the Cloudflare DNS challenge, the second with the manual one.
sed -i '' "s/^Le_Webroot=.*/Le_Webroot='dns_cf'/" "$H/mail.rehearsal.test_ecc/mail.rehearsal.test.conf"
N=mail.second.test
C=$H/${N}_ecc
mkdir -p "$C"
openssl ecparam -name prime256v1 -genkey -noout -out "$C/$N.key" 2>/dev/null
chmod 600 "$C/$N.key"
openssl req -new -key "$C/$N.key" -subj "/CN=$N" -out "$C/$N.csr" 2>/dev/null
openssl x509 -req -in "$C/$N.csr" -signkey "$C/$N.key" -days 90 -out "$C/$N.cer" 2>/dev/null
cp "$C/$N.cer" "$C/ca.cer"
cat "$C/$N.cer" "$C/ca.cer" > "$C/fullchain.cer"
cp "$H/mail.rehearsal.test_ecc/mail.rehearsal.test.csr.conf" "$C/$N.csr.conf"
sed -e "s/mail\.rehearsal\.test/$N/g" -e "s/^Le_Webroot=.*/Le_Webroot='dns'/" \
    "$H/mail.rehearsal.test_ecc/mail.rehearsal.test.conf" > "$C/$N.conf"
"$H/acme.sh" --home "$H" --list

# The Italian names of /var/db/mailpanel, with owners and permissions as on the server.
printf '2026-10-12T02:41:57Z riavvio chiesto dal pannello\n2026-10-12T02:42:30Z il pannello e'"'"' ripartito\n' > "$D/riavvio.log"
chmod 600 "$D/riavvio.log"
printf 'installazione completata il 2026-09-01T14:18:00Z\n' > "$D/installazione-completata"
chmod 644 "$D/installazione-completata"
mkdir -p "$D/ssl-precedente"
cp /usr/local/etc/ssl/mail/fullchain.pem "$D/ssl-precedente/fullchain.pem"
cp /usr/local/etc/ssl/mail/fullchain.pem "$D/ssl-precedente/ca.pem"
cp /usr/local/etc/ssl/mail/privkey.pem "$D/ssl-precedente/privkey.pem"
chmod 644 "$D/ssl-precedente/fullchain.pem" "$D/ssl-precedente/ca.pem"
chmod 600 "$D/ssl-precedente/privkey.pem"
mkdir -p "$D/sistema/20260831-190102"
cat > "$D/sistema/salto.json" <<'EOF'
{
  "fase": "finito",
  "passi": [
    {"giro": 1, "codice": 0, "chiede": "ancora"},
    {"giro": 2, "codice": 0, "chiede": "finished"}
  ],
  "kernel": "15.1-RELEASE-p3",
  "userland": "15.1-RELEASE-p3"
}
EOF
chmod 644 "$D/sistema/salto.json"
freebsd-version -k > "$D/sistema/20260831-190102/versione.txt"
for s in postfix dovecot nginx; do echo "$s attivo"; done > "$D/sistema/20260831-190102/servizi.txt"
pkg query '%n-%v' | head -20 > "$D/sistema/20260831-190102/pacchetti.txt"
ls -la "$D" "$D/sistema"
