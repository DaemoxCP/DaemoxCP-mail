#!/bin/sh
# Lo stato di un server di posta col pannello, per confrontare prima e dopo un passaggio di versione.
# Uso: check-state.sh DOMINIO
DOMAIN="$1"
# I nomi del pannello: quelli di DaemoxCP Mail (17/11/2026) o quelli di prima, come li trova.
D=/var/db/daemoxcp-mail; [ -d "$D" ] || D=/var/db/mailpanel
SVC=daemoxcp_mail; [ -f /usr/local/etc/rc.d/$SVC ] || SVC=mailpanel
SSO=daemoxcp_mail_sso; [ -d /usr/local/www/roundcube/plugins/$SSO ] || SSO=mailpanel_sso
echo "== panel files in $D"
ls -1 "$D" | grep -vE "^(config-before-update|jdk|mysql84|nginx|python|roundcube|dovecot-config-.*)$"
echo "== the panel's logs"
ls -l "$D"/*.log* 2>/dev/null | awk '{print $5, $NF}'
echo "== the startup script"
grep -n "${SVC}_log:=" /usr/local/etc/rc.d/$SVC; stat -f "%Sp %Su:%Sg" /usr/local/etc/rc.d/$SVC; sh -n /usr/local/etc/rc.d/$SVC && echo "sh -n: ok"
echo "== the process daemon writes"
pgrep -lf "daemon: $SVC|daemon: mailpanel" | cut -c1-120; ps -axo user,command | grep "[j]ava -jar" | cut -c1-120
echo "== nginx: the public surface"
ls -1 /usr/local/etc/nginx/conf.d; grep -h "alias\|access_log" /usr/local/etc/nginx/conf.d/*.conf; nginx -t 2>&1 | tail -1
printf "mta-sts.txt on 443: "; curl -sk --resolve "mta-sts.${DOMAIN}:443:127.0.0.1" -o /tmp/mta-sts.out -w "%{http_code}" "https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt"; echo " $(head -1 /tmp/mta-sts.out 2>/dev/null)"; rm -f /tmp/mta-sts.out
ls -l "$D"/*/mta-sts.txt 2>/dev/null | awk '{print $NF}'
echo "== fail2ban and pf"
fail2ban-client status 2>/dev/null | tail -1; ls -1 /usr/local/etc/fail2ban/jail.d /usr/local/etc/fail2ban/filter.d 2>/dev/null | grep -i -E "mailpanel|daemoxcp"; pfctl -s Anchors 2>/dev/null | tr "\n" " "; echo
echo "== Postfix as the local MTA"
for p in myorigin smtp_generic_maps; do printf "%s = %s\n" "$p" "$(postconf -h $p)"; done
grep -c "^sendmail.*/usr/local/sbin/sendmail" /usr/local/etc/mail/mailer.conf 2>/dev/null || echo "Postfix mailer.conf: missing"
echo "== services"
printf "mysqld: %s\n" "$(pgrep -q mysqld && echo up || echo DOWN)"
for s in postfix dovecot nginx php_fpm redis rspamd clamav_clamd fail2ban $SVC; do printf "%s:%s " "$s" "$(service $s status >/dev/null 2>&1 && echo up || echo DOWN)"; done; echo
printf "panel on 2096: "; curl -sk -o /dev/null -w "%{http_code}\n" https://127.0.0.1:2096/
echo "== a mailbox: login and delivery"
read box pass < /root/rehearsal/mailboxes
timeout -f 20 doveadm auth test "$box" "$pass" 2>&1 | head -1
token="rehearsal-$(date +%s)"
printf "Subject: %s\n\ntest\n" "$token" | timeout -f 20 /usr/local/sbin/sendmail "$box"
i=0; while [ $i -lt 30 ] && ! timeout -f 5 doveadm search -u "$box" mailbox INBOX subject "$token" 2>/dev/null | grep -q .; do sleep 1; i=$((i+1)); done
timeout -f 5 doveadm search -u "$box" mailbox INBOX subject "$token" 2>/dev/null | grep -q . && echo "delivered in ${i}s" || echo "NOT delivered"
echo "== the services' users"
ps -axww -o user= -o command= | awk '/php-fpm: pool|nginx: (master|worker)|php-fpm: master/ {print $1, $2, $3, $4}' | sort | uniq -c
ls -1 /usr/local/etc/php-fpm.d/; grep -h "^\[\|^user\|^listen" /usr/local/etc/php-fpm.d/*.conf 2>/dev/null | tr "\n" " "; echo
grep -h "fastcgi_pass" /usr/local/etc/nginx/nginx.conf /usr/local/etc/nginx/conf.d/*.conf 2>/dev/null | sort | uniq -c
for f in /usr/local/www/roundcube/config/config.inc.php /usr/local/www/roundcube/plugins/$SSO/config.inc.php \
         /usr/local/www/roundcube/temp /usr/local/www/roundcube/logs $D/php_sessions /var/log/php_errors.log \
         $D/roundcube_sso.key; do
    [ -e "$f" ] && stat -f "%Sp %Su:%Sg %N" "$f"
done
grep -h "www:www\|roundcube:roundcube" /usr/local/etc/newsyslog.conf.d/php-errors.conf /usr/local/etc/newsyslog.conf.d/roundcube.conf 2>/dev/null
printf "webmail: "; n=$(awk '/server_name/ && !/_;/ {gsub(";","",$2); print $2; exit}' /usr/local/etc/nginx/nginx.conf)
p=$(awk '/listen/ && !/default_server/ {print $2; exit}' /usr/local/etc/nginx/nginx.conf)
curl -sk -m 15 --resolve "$n:$p:127.0.0.1" "https://$n:$p/" | grep -c rcmloginuser
printf "acme.sh: "; [ -d /root/.acme.sh ] && echo "/root/.acme.sh present" || echo "/root/.acme.sh missing"
[ -d /var/db/acme ] && stat -f "%Sp %Su:%Sg %N" /var/db/acme /var/db/acme/certs 2>/dev/null; ls -1 /var/db/acme/certs 2>/dev/null
crontab -l -u root 2>/dev/null | grep -c acme.sh
echo "== locked packages"
pkg lock -l 2>/dev/null | sed 1d | wc -l | tr -d " "
