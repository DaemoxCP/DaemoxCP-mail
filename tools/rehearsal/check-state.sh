#!/bin/sh
# Lo stato di un server di posta col pannello, per confrontare prima e dopo un passaggio di versione.
# Uso: check-state.sh DOMINIO
DOMAIN="$1"
echo "== file del pannello in /var/db/mailpanel"
ls -1 /var/db/mailpanel | grep -vE "^(config-before-update|jdk|mysql84|nginx|python|roundcube|dovecot-config-.*)$"
echo "== i log del pannello"
ls -l /var/db/mailpanel/*.log* 2>/dev/null | awk '{print $5, $NF}'
echo "== lo script di avvio"
grep -n "mailpanel_log:=" /usr/local/etc/rc.d/mailpanel; stat -f "%Sp %Su:%Sg" /usr/local/etc/rc.d/mailpanel; sh -n /usr/local/etc/rc.d/mailpanel && echo "sh -n: ok"
echo "== il processo che daemon fa scrivere"
pgrep -lf "daemon: mailpanel" | cut -c1-120; ps -axo user,command | grep "[j]ava -jar" | cut -c1-120
echo "== nginx: la superficie pubblica"
ls -1 /usr/local/etc/nginx/conf.d; grep -h "alias\|access_log" /usr/local/etc/nginx/conf.d/*.conf; nginx -t 2>&1 | tail -1
printf "mta-sts.txt sulla 443: "; curl -sk --resolve "mta-sts.${DOMAIN}:443:127.0.0.1" -o /tmp/mta-sts.out -w "%{http_code}" "https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt"; echo " $(head -1 /tmp/mta-sts.out 2>/dev/null)"; rm -f /tmp/mta-sts.out
ls -l /var/db/mailpanel/*/mta-sts.txt 2>/dev/null | awk '{print $NF}'
echo "== fail2ban e pf"
fail2ban-client status 2>/dev/null | tail -1; ls -1 /usr/local/etc/fail2ban/jail.d /usr/local/etc/fail2ban/filter.d 2>/dev/null | grep -i "mailpanel"; pfctl -s Anchors 2>/dev/null | tr "\n" " "; echo
echo "== Postfix come MTA locale"
for p in myorigin smtp_generic_maps; do printf "%s = %s\n" "$p" "$(postconf -h $p)"; done
grep -c "^sendmail.*/usr/local/sbin/sendmail" /usr/local/etc/mail/mailer.conf 2>/dev/null || echo "mailer.conf di Postfix: assente"
echo "== servizi"
printf "mysqld: %s\n" "$(pgrep -q mysqld && echo su || echo GIU)"
for s in postfix dovecot nginx php_fpm redis rspamd clamav_clamd fail2ban mailpanel; do printf "%s:%s " "$s" "$(service $s status >/dev/null 2>&1 && echo su || echo GIU)"; done; echo
printf "pannello sulla 2096: "; curl -sk -o /dev/null -w "%{http_code}\n" https://127.0.0.1:2096/
echo "== una casella: accesso e consegna"
read box pass < /root/rehearsal/mailboxes
timeout -f 20 doveadm auth test "$box" "$pass" 2>&1 | head -1
token="rehearsal-$(date +%s)"
printf "Subject: %s\n\nprova\n" "$token" | timeout -f 20 /usr/local/sbin/sendmail "$box"
i=0; while [ $i -lt 30 ] && ! timeout -f 5 doveadm search -u "$box" mailbox INBOX subject "$token" 2>/dev/null | grep -q .; do sleep 1; i=$((i+1)); done
timeout -f 5 doveadm search -u "$box" mailbox INBOX subject "$token" 2>/dev/null | grep -q . && echo "consegnata in ${i}s" || echo "NON consegnata"
echo "== pacchetti protetti"
pkg lock -l 2>/dev/null | sed 1d | wc -l | tr -d " "
