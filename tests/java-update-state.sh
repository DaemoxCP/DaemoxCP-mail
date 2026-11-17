#!/bin/sh
# What the Java update touches, on the TEST VM: the panel's processes, the service's pidfile, the port and who holds
# it, the JVM and its protection, the package jobs, the services. Read only. Used by everything-browser-test.js
# (copied to /root/signed on the VM).
echo "service: $(service mailpanel status 2>&1)"
echo "pidfile: $(cat /var/run/mailpanel.pid 2>/dev/null || echo none)"
ps -axww -o pid= -o ppid= -o user= -o command= | grep -E '[j]ava -jar|daemon: mailpanel' | cut -c1-200
echo "port 2096: $(sockstat -46l -p 2096 | tail -n +2 | awk '{print $1, $2, $3, $5, $6}' | sort -u | tr '\n' ';')"
echo "root.sock: $(sockstat -u | grep -c root.sock) entries"
echo "openjdk25: $(pkg query '%v' openjdk25), repo $(pkg rquery -U '%v' openjdk25 2>/dev/null), locked: $(pkg lock -l | grep -c openjdk25)"
echo "java -version: $(/usr/local/openjdk25/bin/java -version 2>&1 | head -1)"
for f in package-job-running.json package-job-interrupted.json; do printf '%s: ' $f; [ -e /var/db/daemoxcp-mail/$f ] && echo PRESENT || echo absent; done
printf 'list of unlocked packages: '; ls /var/db/daemoxcp-mail-maintenance-locks 2>/dev/null && echo PRESENT || echo absent
echo "panel /index: $(curl -sk -m 15 -o /dev/null -w '%{http_code}' https://127.0.0.1:2096/index)"
for s in dovecot postfix rspamd mysql-server nginx php_fpm redis fail2ban; do service $s status 2>&1 | head -1; done
