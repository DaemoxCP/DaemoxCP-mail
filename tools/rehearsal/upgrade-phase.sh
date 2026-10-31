#!/bin/sh
# Un passaggio di versione come lo farebbe il committente: fermo il pannello, cambio il jar,
# lo riavvio con lo script di avvio che c'e'. Poi un secondo riavvio, per vedere cosa resta.
# Uso: upgrade-phase.sh JAR ETICHETTA DOMINIO
JAR="$1"; LABEL="$2"; DOMAIN="$3"; OUT=/root/rehearsal/$LABEL
mkdir -p "$OUT"
wait_panel() {
    i=0; while [ $i -lt 180 ] && [ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:2096/)" = "000" ]; do sleep 2; i=$((i+2)); done
    sleep 30   # le migrazioni all'avvio, nginx e fail2ban ricaricati
}
service mailpanel stop
cp -p "$JAR" /home/panel/freebsd-mail-panel-1.0.jar
sha256 -q /home/panel/freebsd-mail-panel-1.0.jar > "$OUT/jar.sha256"
service mailpanel start
wait_panel
/root/rehearsal/check-state.sh "$DOMAIN" > "$OUT/first-start.txt" 2>&1
service mailpanel restart
wait_panel
/root/rehearsal/check-state.sh "$DOMAIN" > "$OUT/second-start.txt" 2>&1
grep -h "RcScriptRepair\|PublicSurfaceRename\|PathMigration\|LocalMta\|Renamed\|Both " /var/db/mailpanel/*.log 2>/dev/null | tail -30 > "$OUT/migrations.txt"
echo FINE > "$OUT/done"
