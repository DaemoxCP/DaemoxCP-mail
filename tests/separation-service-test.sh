#!/bin/sh
# The separated panel as a service, on the test machine.
#
# Run as root on the VM, with the panel installed as a service (rc.d daemoxcp_mail) from the jar to test,
# and the compiled tests copied to a folder the user daemoxcp_mail can read:
#   sh tests/separation-service-test.sh /home/panel /var/tmp/sep-tests
# With the panel's own name set (option 2 of the menu): HOST=panel.example.com sh tests/separation-service-test.sh ...
#
# It restarts the panel several times. With the separation on it checks who runs what (ps), who listens
# (sockstat), the permissions of every file the two parts share, what daemoxcp_mail can and cannot read or
# write, a sign-in with a one-time console code and the API through the web part, and requests forged on
# the root socket. Then it plants faults, each put back right after:
#   - the user daemoxcp_mail with another comment: the panel stays as before (root on the port);
#   - the jar unreadable by daemoxcp_mail: the same;
#   - the web part killed every time it starts: after the wait the panel serves everything as root;
#   - the root part killed with -9: the next start stops the web part left behind.
# And a second start with nothing to do must be quiet: no DONE, no WARNING.
#
# Exit code: 0 if every check passed.
set -u
PANEL=${1:?panel folder}
TESTS=${2:?compiled tests folder, readable by daemoxcp_mail}
JAR=$PANEL/daemoxcp-mail.jar
JAVA=/usr/local/openjdk25/bin/java
LOG=/var/db/daemoxcp-mail/panel.log
RUN=/var/run/daemoxcp-mail
PORT=2096
# A panel with its own name answers only to that name (HostCheck: 421 to any other Host): give it as HOST, for example
# HOST=panel.example.com, and every request still goes to 127.0.0.1, with that name.
HOST=${HOST:-127.0.0.1}
BASE=https://$HOST:$PORT
curl() { command curl --resolve "$HOST:$PORT:127.0.0.1" "$@"; }
UA="separation-service-test"
fail=0

check() { if [ "$2" = 0 ]; then echo "  OK     $1"; else echo "  FAILED $1"; fail=$((fail + 1)); fi; }
is() { [ "$1" = "$2" ]; echo $?; }
has() { case "$1" in *"$2"*) echo 0 ;; *) echo 1 ;; esac; }
mode() { stat -f '%Sp %Su:%Sg' "$1" 2>/dev/null; }
as_web() { /usr/sbin/chroot -u daemoxcp_mail -g daemoxcp_mail -G daemoxcp_mail / "$@"; }
mark() { stat -f %z "$LOG"; }
since() { tail -c +$(($1 + 1)) "$LOG"; }

# Waits for the end of a start: "separated", "legacy" or "timeout".
wait_start() {
    i=0
    while [ $i -lt 240 ]; do
        s=$(since "$1")
        case "$s" in *"Panel web part started as daemoxcp_mail"*)
            case "$s" in *"DaemoxCP Mail root part ready"*) echo separated; return ;; esac ;; esac
        case "$s" in *"DaemoxCP Mail server started on port"*) echo legacy; return ;; esac
        sleep 1
        i=$((i + 1))
    done
    echo timeout
}

restart() {
    m=$(mark)
    service daemoxcp_mail stop >/dev/null 2>&1
    service daemoxcp_mail start >/dev/null 2>&1
    STATE=$(wait_start "$m")
    SEGMENT=$(since "$m")
}

# Signs in with a one-time console code; leaves the cookies in $JAR_COOKIES and the CSRF token in $CSRF.
login() {
    JAR_COOKIES=$(mktemp /var/tmp/sep-cookies.XXXXXX)
    code=$(cd "$PANEL" && "$JAVA" -jar "$JAR" --lang en --access-code 2>/dev/null | sed -n 's/.*One-time access code for [^:]*: \([0-9]\{4\} [0-9]\{4\}\).*/\1/p' | head -1)
    pre=$(curl -sk -A "$UA" -c "$JAR_COOKIES" -b "$JAR_COOKIES" "$BASE/index" | sed -n 's/.*id="csrf_token" value="\([^"]*\)".*/\1/p' | head -1)
    LOGIN=$(curl -sk -A "$UA" -c "$JAR_COOKIES" -b "$JAR_COOKIES" -H 'Content-Type: application/json' \
        -d "{\"action\":\"console_verify\",\"code\":\"$code\",\"csrf_token\":\"$pre\"}" "$BASE/api/login")
    CSRF=$(curl -sk -A "$UA" -c "$JAR_COOKIES" -b "$JAR_COOKIES" "$BASE/home" | sed -n 's/.*id="csrf_token" value="\([^"]*\)".*/\1/p' | head -1)
}

get() { curl -sk -A "$UA" -b "$JAR_COOKIES" -o /var/tmp/sep-body -w '%{http_code}' "$BASE$1"; }
# The confirmation the root part writes after a passkey or an email code, put
# straight into MySQL as its root for the newest session: a test signed in with a console code has neither.
confirm_session() {
    f=$(mktemp /var/tmp/sep-root.XXXXXX); chmod 600 "$f"
    printf '[client]\nuser=root\npassword="%s"\n' "$(sed -n 's/^mysql_root_password=//p' /usr/local/etc/daemoxcp-mail/root-secrets.properties | sed 's/\\\(.\)/\1/g')" > "$f"
    db=$(/usr/local/bin/mysql --defaults-extra-file="$f" -N -e "SELECT DISTINCT routine_schema FROM information_schema.routines WHERE routine_name = 'check_session'")
    /usr/local/bin/mysql --defaults-extra-file="$f" -N -e "UPDATE $db.panel_sessions SET reauth_at = UTC_TIMESTAMP() ORDER BY created_at DESC LIMIT 1"
    rm -f "$f"
}
post() { curl -sk -A "$UA" -b "$JAR_COOKIES" -H 'Content-Type: application/json' ${3:+-H "X-CSRF-Token: $3"} -d "$2" -o /var/tmp/sep-body -w '%{http_code}' "$BASE$1"; }
del() { curl -sk -A "$UA" -b "$JAR_COOKIES" -H "X-CSRF-Token: $CSRF" -X DELETE -o /var/tmp/sep-body -w '%{http_code}' "$BASE$1"; }
probe_root() { "$JAVA" -cp "$TESTS:$JAR" org.daemoxcp.mail.webserver.RootSocketProbe "$@"; }
probe_web() { as_web "$JAVA" -cp "$TESTS:$JAR" org.daemoxcp.mail.webserver.RootSocketProbe "$@"; }

echo "== 1. Separated =="
restart
check "the panel started separated ($STATE)" "$(is "$STATE" separated)"
WARN=$(printf '%s' "$SEGMENT" | grep 'WARNING' | head -3)
check "the start said nothing alarming ($WARN)" "$(is "$WARN" "")"
ROOT_PID=$(cat /var/run/daemoxcp_mail.pid)
WEB_PID=$(cat $RUN/web/web.pid 2>/dev/null)
SUP_PID=$(cat $RUN/web/web-supervisor.pid 2>/dev/null)
check "the root part runs as root ($ROOT_PID)" "$(is "$(ps -o user= -p "$ROOT_PID" | tr -d ' ')" root)"
check "the web part runs as daemoxcp_mail ($WEB_PID: $(ps -o user= -o command= -p "$WEB_PID"))" \
    "$(has "$(ps -o user= -o command= -p "$WEB_PID")" "daemoxcp_mail")"
check "  and it is java --web-part" "$(has "$(ps -o command= -p "$WEB_PID")" "--web-part")"
check "its supervisor is daemon(8) ($(ps -o user= -o command= -p "$SUP_PID"))" \
    "$(has "$(ps -o user= -o command= -p "$SUP_PID")" "daemon: daemoxcp-mail-web[")"
check "  and it runs as daemoxcp_mail, not root" "$(is "$(ps -o user= -p "$SUP_PID" | tr -d ' ')" daemoxcp_mail)"
LISTEN=$(sockstat -46l -p $PORT | awk 'NR > 1 { print $1, $3 }' | sort -u)
check "only the web part listens on $PORT ($LISTEN)" "$(is "$LISTEN" "daemoxcp_mail $WEB_PID")"
ROOT_LISTEN=$(sockstat -46l | awk -v p="$ROOT_PID" '$3 == p')
check "the root part listens on no network port ($ROOT_LISTEN)" "$(is "$ROOT_LISTEN" "")"

echo
echo "== 2. Files =="
check "$RUN: $(mode $RUN)" "$(is "$(mode $RUN)" "drwxr-x--- root:daemoxcp_mail")"
check "the socket: $(mode $RUN/root.sock)" "$(is "$(mode $RUN/root.sock)" "srw-rw---- root:daemoxcp_mail")"
check "the web part's run folder is its own: $(mode $RUN/web)" "$(is "$(mode $RUN/web)" "drwxr-x--- daemoxcp_mail:daemoxcp_mail")"
check "the pid files are the supervisor's, daemoxcp_mail's: $(mode $RUN/web/web.pid)" "$(has "$(mode $RUN/web/web.pid)" "daemoxcp_mail:")"
check "no pidfile left in root's folder" "$(is "$(ls $RUN/web.pid $RUN/web-supervisor.pid 2>/dev/null)" "")"
E=/usr/local/etc/daemoxcp-mail
check "$E: $(mode $E)" "$(is "$(mode $E)" "drwxr-x--- root:daemoxcp_mail")"
check "panel-secrets.properties: $(mode $E/panel-secrets.properties)" "$(is "$(mode $E/panel-secrets.properties)" "-rw-r----- root:daemoxcp_mail")"
# The asymmetric vault: the old symmetric key is root's only, the private key
# in root's file, the public one in the web part's.
[ -e $E/master.key ] && check "master.key, only for the copies of before: $(mode $E/master.key)" "$(is "$(mode $E/master.key)" "-rw------- root:wheel")"
check "the vault's private key only in root's file" "$(is "$(grep -c '^vault_private_key=' $E/root-secrets.properties)$(grep -c '^vault_private_key' $E/panel-secrets.properties)" 10)"
check "the vault's public key in the web part's file" "$(is "$(grep -c '^vault_public_key=' $E/panel-secrets.properties)" 1)"
check "root-secrets.properties: $(mode $E/root-secrets.properties)" "$(is "$(mode $E/root-secrets.properties)" "-rw------- root:wheel")"
OTHERS=$(find $E -type f ! -name panel-secrets.properties -perm +077)
check "nothing else in $E is open to the group ($OTHERS)" "$(is "$OTHERS" "")"
check "$PANEL/database: $(mode $PANEL/database)" "$(is "$(mode $PANEL/database)" "drwxr-x--- root:daemoxcp_mail")"
check "daemoxcp-mail.db: $(mode $PANEL/database/daemoxcp-mail.db)" "$(is "$(mode $PANEL/database/daemoxcp-mail.db)" "-rw-r----- root:daemoxcp_mail")"
check "the audit log: $(mode /var/log/daemoxcp-mail-auth.log)" "$(is "$(mode /var/log/daemoxcp-mail-auth.log)" "-rw-r----- daemoxcp_mail:wheel")"
check "newsyslog recreates it as daemoxcp_mail" "$(has "$(cat /usr/local/etc/newsyslog.conf.d/daemoxcp-mail-auth.conf)" "daemoxcp_mail:wheel")"
check "the web part's log, its supervisor's: $(mode /var/db/daemoxcp-mail/panel-web.log)" "$(is "$(mode /var/db/daemoxcp-mail/panel-web.log)" "-rw------- daemoxcp_mail:wheel")"
A=$PANEL/admin
check "the pages: $(mode $A)" "$(is "$(mode $A)" "drwxr-x--- root:daemoxcp_mail")"
check "their scripts: $(mode $A/assets/open)" "$(is "$(mode $A/assets/open)" "drwxr-x--- root:daemoxcp_mail")"
UNREADABLE=$(find $A -type f ! -perm -040 | head -3)
check "every page file is readable by the group ($UNREADABLE)" "$(is "$UNREADABLE" "")"
NOT_GROUP=$(find $A ! -group daemoxcp_mail | head -3)
check "every page file is in the group daemoxcp_mail ($NOT_GROUP)" "$(is "$NOT_GROUP" "")"
as_web /bin/test -r $E/panel-secrets.properties; check "daemoxcp_mail reads its secrets" $?
as_web /bin/test -r $PANEL/database/daemoxcp-mail.db; check "daemoxcp_mail reads SQLite" $?
as_web /bin/test -w /var/log/daemoxcp-mail-auth.log; check "daemoxcp_mail writes the audit log" $?
for f in $E/root-secrets.properties $E/master.key $E/firewall.json /var/db/daemoxcp-mail/roundcube_sso.key /var/db/daemoxcp-mail/dovecot_master.key; do
    as_web /bin/test -r "$f"; r=$?
    check "daemoxcp_mail cannot read $f" "$(is $r 1)"
done
for f in $E/panel-secrets.properties $E/master.key $E $PANEL/database/daemoxcp-mail.db $PANEL/database $RUN $JAR; do
    as_web /bin/test -w "$f"; r=$?
    check "daemoxcp_mail cannot write $f" "$(is $r 1)"
done
# unix(4): connecting to a socket needs write permission on it; the folder, root's, keeps it from being replaced.
as_web /bin/test -w $RUN/root.sock; check "daemoxcp_mail can write the root socket, to connect to it (unix(4))" $?

echo
echo "== 3. Sign-in and the API through the web part =="
WEBLOG=/var/db/daemoxcp-mail/panel-web.log
WM3=$(stat -f %z $WEBLOG)
login
check "signed in with a console code ($LOGIN)" "$(has "$LOGIN" '"success":true')"
check "the page has a CSRF token" "$(is "$([ -n "$CSRF" ] && echo y)" y)"
c=$(get "/api/panel_info?action=uptime"); check "GET /api/panel_info: $c" "$(is "$c" 200)"
c=$(get "/api/domains"); check "GET /api/domains: $c" "$(is "$c" 200)"
c=$(get "/api/admins"); check "GET /api/admins: $c" "$(is "$c" 200)"
c=$(get "/api/account"); check "GET /api/account (root part): $c" "$(is "$c" 200)"
c=$(get "/home"); check "GET /home (web part): $c" "$(is "$c" 200)"
ASSET=$(curl -sk -A "$UA" "$BASE/index" | grep -o '/assets/open/[0-9a-f]*\.js' | head -1)
c=$(get "$ASSET"); check "a script of the sign-in page ($ASSET): $c" "$(is "$c" 200)"
PASSET=$(curl -sk -A "$UA" -b "$JAR_COOKIES" "$BASE/home" | grep -o '/assets/[0-9a-f]*\.js' | head -1)
c=$(get "$PASSET"); check "a script of a signed-in page ($PASSET): $c" "$(is "$c" 200)"
c=$(post "/api/updates" '{"action":"service_users"}' "$CSRF"); B=$(cat /var/tmp/sep-body)
check "POST service_users with the CSRF token: $c" "$(is "$c" 200)"
# Each user of a service is an object of its "roles", with the processes ps shows: the panel's are --web and --web-part,
# and only the panel runs as daemoxcp_mail.
check "  the panel runs as daemoxcp_mail ($(printf '%s' "$B" | grep -o '"user":"daemoxcp_mail"' | head -1))" "$(has "$B" '"user":"daemoxcp_mail"')"
check "  root for the part that manages the machine (--web)" "$(has "$B" '"--web"')"
check "  and the page does not say it runs entirely as root" "$(is "$(has "$B" panelLegacy)" 1)"
c=$(post "/api/updates" '{"action":"service_users"}' ""); check "the same without the CSRF token: 403 ($c)" "$(is "$c" 403)"

echo
echo "== 3b. What the web part serves by itself =="
WM=$(stat -f %z $WEBLOG)
D=sep-test-$$.example
c=$(post "/api/domains" "{\"domain\":\"$D\",\"description\":\"separation test\"}" "$CSRF"); DID=$(sed -n 's/.*"id":\([0-9]*\).*/\1/p' /var/tmp/sep-body)
check "add a test domain: $c (id $DID)" "$(is "$c" 200)"
c=$(post "/api/mailboxes" "{\"email\":\"probe@$D\",\"password\":\"Sep-Test-Password-2026x\",\"name\":\"Probe\",\"quota_mb\":10}" "$CSRF"); MID=$(sed -n 's/.*"id":\([0-9]*\).*/\1/p' /var/tmp/sep-body)
check "add a test mailbox: $c (id $MID, $(cut -c1-120 /var/tmp/sep-body))" "$(is "$c" 200)"
# The Maildir is the mailbox's folder itself (mail_path = /var/vmail/<domain>/<user>, since 20/11/2026).
[ -d "/var/vmail/$D/probe/cur" ] && [ -d "/var/vmail/$D/probe/new" ] && [ -d "/var/vmail/$D/probe/tmp" ]; r=$?
check "the root part made its mail folders (the mail-folders operation)" $r
check "  owned by vmail ($(stat -f %Su /var/vmail/$D/probe 2>/dev/null))" "$(is "$(stat -f %Su /var/vmail/$D/probe 2>/dev/null)" vmail)"
c=$(post "/api/mailbox-password" "{\"id\":$MID}" "$CSRF"); B=$(cat /var/tmp/sep-body)
check "Show password asks a recent confirmation first: $c, needs_reauth" "$(is "$c$(has "$B" '"needs_reauth":true')" 4030)"
confirm_session
c=$(post "/api/mailbox-password" "{\"id\":$MID}" "$CSRF"); B=$(cat /var/tmp/sep-body)
check "  confirmed: the password comes back from the vault, read by the root part ($c)" "$(has "$B" "Sep-Test-Password-2026x")"
c=$(post "/api/mailboxes" "{\"action\":\"reveal_password\",\"id\":$MID}" "$CSRF"); B=$(cat /var/tmp/sep-body)
check "  the web part has no reveal of its own any more ($c $(printf '%s' "$B" | cut -c1-80))" "$(is "$(has "$B" "Sep-Test-Password-2026x")" 1)"
c=$(post "/api/webmail" "{\"mailbox_id\":$MID}" "$CSRF"); check "POST /api/webmail, a sign-in token for the webmail: $c" "$(is "$c" 200)"
# The webmail's two routes: the web part checks who calls (loopback and the webmail's key), the root serves them.
# The key as Roundcube sends it: base64url without padding.
WKEY=$(sed -n 's/^webmail_key=//p' $E/panel-secrets.properties | sed 's/\\//g' | tr '+/' '-_' | tr -d '=')
webmail() { curl -sk -H "X-DaemoxCP-Key: $1" --data-urlencode "user=probe@$D" --data-urlencode "$3" ${4:+--data-urlencode "$4"} -o /var/tmp/sep-body -w '%{http_code}' "$BASE$2"; }
c=$(webmail "$WKEY" /api/internal/mailbox-vault "pass=Sep-Test-Password-2026x"); check "the webmail's copy route, through the root: $c $(cat /var/tmp/sep-body)" "$(is "$c" 200)"
c=$(webmail "not-the-key-$$" /api/internal/mailbox-vault "pass=Sep-Test-Password-2026x"); check "  without the webmail's key: 404 from the web part ($c)" "$(is "$c" 404)"
c=$(webmail "$WKEY" /api/internal/mailbox-password "curpass=wrong-$$" "newpass=Sep-Test-Password-2026y"); check "the webmail's password change with a wrong current password: 403 ($c)" "$(is "$c" 403)"
c=$(webmail "$WKEY" /api/internal/mailbox-password "curpass=Sep-Test-Password-2026x" "newpass=Sep-Test-Password-2026y"); check "  with the right one: $c $(cat /var/tmp/sep-body)" "$(is "$c" 200)"
c=$(post "/api/mailbox-password" "{\"id\":$MID}" "$CSRF"); B=$(cat /var/tmp/sep-body)
check "  the root wrote the hash and the copy: Show password gives the new one ($c)" "$(has "$B" "Sep-Test-Password-2026y")"
for p in /api/domains /api/mailboxes "/api/statistics?days=7" /api/mailconfig /api/theme; do
    c=$(get "$p"); check "GET $p: $c" "$(is "$c" 200)"
done
c=$(post "/api/apple-profile" '{"action":"status"}' "$CSRF"); check "POST /api/apple-profile status: $c" "$(is "$c" 200)"
c=$(post "/api/theme" '{"theme":"dark"}' "$CSRF"); check "POST /api/theme dark (the web part writes the theme): $c" "$(is "$c" 200)"
c=$(post "/api/theme" '{"theme":"auto"}' "$CSRF"); check "  and back to auto: $c" "$(is "$c" 200)"
c=$(post "/api/language" '{"language":"en"}' "$CSRF"); check "POST /api/language en (the web part writes the language): $c" "$(is "$c" 200)"
c=$(del "/api/mailboxes?id=$MID"); check "remove the test mailbox: $c" "$(is "$c" 200)"
c=$(del "/api/domains?id=$DID"); check "remove the test domain: $c" "$(is "$c" 200)"
rm -rf "/var/vmail/$D"
PROBLEMS=$(tail -c +$((WM + 1)) $WEBLOG | grep -E "Permission denied|AccessDenied|Exception|SEVERE|refused" | head -3)
check "nothing went wrong in the web part ($PROBLEMS)" "$(is "$PROBLEMS" "")"
c=$(curl -sk -A "$UA" -b "$JAR_COOKIES" -c "$JAR_COOKIES" -H "X-CSRF-Token: $CSRF" -X POST -o /dev/null -w '%{http_code}' "$BASE/api/logout")
check "sign out through the web part: $c" "$(is "$c" 200)"
c=$(get "/api/domains"); check "  the root removed the session: the same cookie gets 401 ($c)" "$(is "$c" 401)"
SQLREF=$(tail -c +$((WM3 + 1)) $WEBLOG | grep "outside the panel's catalog" | head -3)
check "the web part ran only statements of its list, from the sign-in to the sign-out ($SQLREF)" "$(is "$SQLREF" "")"

echo
echo "== 3c. The web part's MySQL user =="
check "the web part entered MySQL as daemoxcp_mail_web ($(grep 'Web part: MySQL as' $WEBLOG | tail -1))" "$(has "$(grep 'Web part: MySQL as' $WEBLOG | tail -1)" "as daemoxcp_mail_web, only")"
check "its password is in its secrets file" "$(is "$(grep -c '^mysql_web_password=' $E/panel-secrets.properties)" 1)"
check "the panel user's password is not there any more" "$(is "$(grep -c '^mysql_password' $E/panel-secrets.properties)" 0)"
check "  it is in root's file" "$(is "$(grep -c '^mysql_password=' $E/root-secrets.properties)" 1)"
MYOPT=$(mktemp /var/tmp/sep-my.XXXXXX)
printf '[client]\nuser=daemoxcp_mail_web\npassword=%s\nhost=127.0.0.1\nport=3306\n' "$(sed -n 's/^mysql_web_password=//p' $E/panel-secrets.properties)" > "$MYOPT"
chown daemoxcp_mail "$MYOPT"; chmod 600 "$MYOPT"
my() { as_web /usr/local/bin/mysql --defaults-extra-file="$MYOPT" -N -e "$1" 2>&1; }
DB=$(my "SELECT DISTINCT routine_schema FROM information_schema.routines WHERE routine_name = 'has_admin'")
check "daemoxcp_mail, with its own MySQL user, sees the procedures of the panel's database ($DB)" "$(is "$([ -n "$DB" ] && echo y)" y)"
R=$(my "CALL $DB.has_admin(NULL)"); check "  a public procedure answers ($R)" "$(is "$R" 1)"
R=$(my "CALL $DB.list_domains(NULL)"); check "  a procedure bound to a session, without one: refused ($R)" "$(has "$R" "ERROR 1644")"
R=$(my "SELECT COUNT(*) FROM $DB.panel_admin"); check "  a SELECT on the administrators: refused ($R)" "$(has "$R" "ERROR 1142")"
R=$(my "SELECT COUNT(*) FROM $DB.mailboxes"); check "  a SELECT on the mailboxes: refused ($R)" "$(has "$R" "ERROR 1142")"
R=$(my "INSERT INTO $DB.panel_sessions (token_hash) VALUES ('x')"); check "  writing a session: refused ($R)" "$(has "$R" "ERROR 1142")"
R=$(my "CALL $DB.web_session_admin(NULL, '', @a)"); check "  the procedures' own helper: refused ($R)" "$(has "$R" "ERROR 1370")"
rm -f "$MYOPT"

echo
echo "== 3d. Postfix's and Dovecot's own MySQL users (MailDbUsers) =="
PF=/usr/local/etc/postfix
# Dovecot 2.4 keeps its MySQL settings in auth-sql.conf.ext ("user = ..."); 2.3 in dovecot-sql.conf ("user=..." in connect).
DSQL=/usr/local/etc/dovecot/conf.d/auth-sql.conf.ext
[ -f $DSQL ] || DSQL=/usr/local/etc/dovecot/dovecot-sql.conf
dsql_user() { grep -oE 'user ?= ?[A-Za-z0-9_]+' $DSQL | head -1 | tr -d ' '; }
unescape() { sed 's/\\\(.\)/\1/g'; }
PANELPW=$(sed -n 's/^mysql_password=//p' $E/root-secrets.properties | unescape)
check "the panel's MySQL password is known to the test" "$(is "$([ -n "$PANELPW" ] && echo y)" y)"
for m in mysql-virtual-domains.cf mysql-virtual-mailboxes.cf mysql-virtual-aliases.cf; do
    check "$m enters as daemoxcp_mail_postfix ($(grep '^user' $PF/$m))" "$(is "$(grep '^user' $PF/$m)" "user = daemoxcp_mail_postfix")"
    check "  the panel's password is not in it" "$(is "$(grep -cF -- "$PANELPW" $PF/$m)" 0)"
    check "  still root:postfix 0640 ($(mode $PF/$m))" "$(is "$(mode $PF/$m)" "-rw-r----- root:postfix")"
    R=$(/usr/local/sbin/postmap -q daemoxcp-mail-probe@invalid mysql:$PF/$m 2>&1; echo "exit $?")
    check "  postmap -q asks MySQL without an error ($R)" "$(is "$R" "exit 1")"
done
check "$(basename $DSQL) enters as daemoxcp_mail_dovecot ($(dsql_user))" "$(is "$(dsql_user)" "user=daemoxcp_mail_dovecot")"
check "  the panel's password is not in it" "$(is "$(grep -cF -- "$PANELPW" $DSQL)" 0)"
check "  still root:dovecot 0600 ($(mode $DSQL))" "$(is "$(mode $DSQL)" "-rw------- root:dovecot")"
R=$(/usr/local/bin/doveadm auth lookup daemoxcp-mail-auth-probe@invalid >/dev/null 2>&1; echo $?)
check "doveadm auth lookup answers (exit $R, 67 = no such user)" "$(is "$R" 67)"
ROOTOPT=$(mktemp /var/tmp/sep-root.XXXXXX); chmod 600 "$ROOTOPT"
printf '[client]\nuser=root\npassword="%s"\n' "$(sed -n 's/^mysql_root_password=//p' $E/root-secrets.properties | unescape)" > "$ROOTOPT"
asroot() { /usr/local/bin/mysql --defaults-extra-file="$ROOTOPT" -N -e "$1" 2>&1; }
R=$(asroot "SELECT COUNT(*) FROM information_schema.processlist WHERE user = 'daemoxcp_mail_dovecot'")
check "MySQL sees Dovecot's connection as daemoxcp_mail_dovecot ($R)" "$(is "$([ "$R" -ge 1 ] 2>/dev/null && echo y)" y)"
MDB=$(sed -n 's/.*dbname *= *\([A-Za-z0-9_]*\).*/\1/p' $DSQL | head -1)
BOX=$(asroot "SELECT email FROM $MDB.mailboxes WHERE active = 1 AND receive_enabled = 1 LIMIT 1")
if [ -n "$BOX" ]; then
    R=$(/usr/local/sbin/postmap -q "$BOX" mysql:$PF/mysql-virtual-mailboxes.cf 2>&1)
    check "a real mailbox: Postfix finds where to deliver it ($R)" "$(is "$R" "${BOX#*@}/${BOX%@*}/")"
fi
for u in daemoxcp_mail_postfix daemoxcp_mail_dovecot; do
    O=$(mktemp /var/tmp/sep-my.XXXXXX); chmod 600 "$O"
    printf '[client]\nuser=%s\npassword=%s\nhost=127.0.0.1\nport=3306\n' "$u" \
        "$(sed -n "s/^${u#daemoxcp_mail_}_db_password=//p" $E/root-secrets.properties | unescape)" > "$O"
    asuser() { /usr/local/bin/mysql --defaults-extra-file="$O" -N -e "$1" 2>&1; }
    R=$(asuser "SELECT COUNT(*) FROM $MDB.panel_admin"); check "$u: the administrators refused ($R)" "$(has "$R" "ERROR 1142")"
    R=$(asuser "UPDATE $MDB.mailboxes SET active = active"); check "$u: writing the mailboxes refused ($R)" "$(has "$R" "ERROR 1142")"
    if [ $u = daemoxcp_mail_postfix ]; then
        R=$(asuser "SELECT password FROM $MDB.mailboxes LIMIT 1"); check "$u: the password hashes refused ($R)" "$(has "$R" "ERROR 1143")"
        R=$(asuser "SELECT dkim_private_key FROM $MDB.domains LIMIT 1"); check "$u: the DKIM keys refused ($R)" "$(has "$R" "ERROR 1143")"
    else
        R=$(asuser "SELECT destination FROM $MDB.aliases LIMIT 1"); check "$u: the aliases refused ($R)" "$(has "$R" "ERROR 1142")"
        R=$(asuser "SELECT password_encrypted FROM $MDB.mailboxes LIMIT 1"); check "$u: the vault copies refused ($R)" "$(has "$R" "ERROR 1143")"
    fi
    rm -f "$O"
done
rm -f "$ROOTOPT"

echo
echo "== 4. The root socket =="
S=$RUN/root.sock
R=$(probe_root "$S" /api/logs GET /api/logs 1 1); check "root's own client gets no answer ($R)" "$(has "$R" "NO ANSWER")"
R=$(probe_web "$S" /api/logs GET /api/logs 1 999999999); check "daemoxcp_mail with a session that does not exist: 401 ($R)" "$(has "$R" "401 ")"
R=$(probe_web "$S" /api/account GET /api/account 1 999999999); check "daemoxcp_mail asking the account API without a live session: 401 ($R)" "$(has "$R" "401 ")"
R=$(probe_web "$S" /op/session-key POST /op/session-key 0 0 | sed 's/"key":"[^"]*"/"key":"(not shown)"/')
check "daemoxcp_mail asking the session key: 200 ($R)" "$(has "$R" '200 {"success":true,"key":')"
R=$(probe_web "$S" /op/session-key POST /op/session-key 1 999999999); check "  the session key with an administrator: 404 ($R)" "$(has "$R" "404 ")"
R=$(probe_root "$S" /op/session-key POST /op/session-key 0 0); check "  root's own client asking the session key gets no answer ($R)" "$(has "$R" "NO ANSWER")"
R=$(probe_web "$S" /api/admins GET /api/admins 0 0); check "daemoxcp_mail without an administrator on a signed-in route: 400 ($R)" "$(has "$R" "400 ")"
R=$(probe_web "$S" /api/login POST /api/login 1 1 '{"action":"console_verify"}'); check "daemoxcp_mail asking a public route: 404 ($R)" "$(has "$R" "404 ")"
rm -f "$JAR_COOKIES" /var/tmp/sep-body

echo
echo "== 5. A second start is quiet =="
restart
check "separated again ($STATE)" "$(is "$STATE" separated)"
DONE=$(printf '%s' "$SEGMENT" | grep -E 'DONE|WARNING' | head -5)
check "no DONE, no WARNING ($DONE)" "$(is "$DONE" "")"

echo
echo "== 6. Planted: the user daemoxcp_mail is someone else's =="
service daemoxcp_mail stop >/dev/null 2>&1
GECOS_BEFORE=$(pw usershow daemoxcp_mail | cut -d: -f8)
pw usermod daemoxcp_mail -c "Someone else"
m=$(mark); service daemoxcp_mail start >/dev/null 2>&1; STATE=$(wait_start "$m"); SEGMENT=$(since "$m")
check "the panel serves everything as root ($STATE)" "$(is "$STATE" legacy)"
check "  and says why" "$(has "$SEGMENT" "is not the panel's: comment")"
check "  root listens on $PORT" "$(is "$(sockstat -46l -p $PORT | awk 'NR > 1 { print $1 }' | sort -u)" root)"
c=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/index"); check "  the panel answers ($c)" "$(is "$c" 200)"
service daemoxcp_mail stop >/dev/null 2>&1
pw usermod daemoxcp_mail -c "$GECOS_BEFORE"

echo
echo "== 7. Planted: the jar unreadable by daemoxcp_mail =="
chmod 600 "$JAR"
m=$(mark); service daemoxcp_mail start >/dev/null 2>&1; STATE=$(wait_start "$m"); SEGMENT=$(since "$m")
check "the panel serves everything as root ($STATE)" "$(is "$STATE" legacy)"
check "  and says why" "$(has "$SEGMENT" "cannot read $PANEL/")"
service daemoxcp_mail stop >/dev/null 2>&1
chmod 644 "$JAR"

echo
echo "== 8. Planted: the web part killed every time it starts =="
m=$(mark)
service daemoxcp_mail start >/dev/null 2>&1
( end=$(($(date +%s) + 150)); while [ "$(date +%s)" -lt "$end" ]; do pkill -u daemoxcp_mail -f -- '--web-part'; sleep 0.5; done ) &
KILLER=$!
STATE=$(wait_start "$m"); SEGMENT=$(since "$m")
kill $KILLER 2>/dev/null
check "after the wait the panel serves everything as root ($STATE)" "$(is "$STATE" legacy)"
check "  and says why" "$(has "$SEGMENT" "did not answer")"
check "  no supervisor left" "$(is "$(pgrep -f 'daemon: daemoxcp-mail-web')" "")"
c=$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/index"); check "  the panel answers ($c)" "$(is "$c" 200)"

echo
echo "== 9. Planted: the root part killed with -9 =="
restart
check "separated ($STATE)" "$(is "$STATE" separated)"
OLD_WEB=$(cat $RUN/web/web.pid)
kill -9 "$(cat /var/run/daemoxcp_mail.pid)"
sleep 2
check "the web part is still there, alone ($OLD_WEB)" "$(has "$(ps -o command= -p "$OLD_WEB")" "--web-part")"
m=$(mark); service daemoxcp_mail start >/dev/null 2>&1; STATE=$(wait_start "$m"); SEGMENT=$(since "$m")
check "the next start stops it and separates again ($STATE)" "$(is "$STATE" separated)"
check "  it said so" "$(has "$SEGMENT" "a web part of a previous start was still running")"
check "  the old web part is gone" "$(is "$(ps -o pid= -p "$OLD_WEB" | tr -d ' ')" "")"

echo
echo "== 10. Stop =="
service daemoxcp_mail stop >/dev/null 2>&1
sleep 2
check "no web part left" "$(is "$(pgrep -f -- '--web-part')" "")"
check "no supervisor left" "$(is "$(pgrep -f 'daemon: daemoxcp-mail-web')" "")"
check "the socket is gone" "$(is "$(ls $RUN/root.sock 2>/dev/null)" "")"
service daemoxcp_mail start >/dev/null 2>&1

echo
if [ $fail = 0 ]; then echo "ALL OK"; else echo "$fail CHECKS FAILED"; fi
exit $fail
