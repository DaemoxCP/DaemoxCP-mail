package org.daemoxcp.mail.system;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The check of the users that run the services (ServiceUsers.examine) on ps outputs written here: the VM's
 * before the migration (nginx and the www pool with the same user), the one after, and a fault
 * planted for every warning, with the cases that must NOT warn (the Postfix and Dovecot processes
 * that run as root by design). It calls nothing: it runs anywhere.
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.ServiceUsersTest
 */
public class ServiceUsersTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** ps -axww -o user= -o pid= -o ppid= -o command= on the VM, on 31/10/2026, before the migration. */
    static final String BEFORE = """
            root    12174     1 /usr/local/bin/python3.12 /usr/local/bin/fail2ban-server --async -b -s /var/run/fail2ban/fail2ban.sock
            unbound 19144     1 /usr/sbin/local-unbound -c /var/unbound/unbound.conf
            mysql   26927 67863 /usr/local/libexec/mysqld --basedir=/usr/local --datadir=/var/db/mysql
            root    32645     1 php-fpm: master process (/usr/local/etc/php-fpm.conf) (php-fpm)
            www     33079 32645 php-fpm: pool www (php-fpm)
            www     34440 32645 php-fpm: pool www (php-fpm)
            root    36807     1 nginx: master process /usr/local/sbin/nginx
            www     37741 36807 nginx: worker process (nginx)
            redis   40133     1 redis-server: /usr/local/bin/redis-server 127.0.0.1:6379 (redis-server)
            clamav  43258     1 /usr/local/sbin/clamd
            root    56502     1 rspamd: main process (rspamd-4.1.0)
            rspamd  56567 56502 rspamd: rspamd_proxy process (127.0.0.1:11332) (rspamd-4.1.0)
            clamav  57292     1 /usr/local/bin/freshclam --daemon -p /var/run/clamav/freshclam.pid
            root    59971     1 /usr/local/sbin/dovecot -c /usr/local/etc/dovecot/dovecot.conf
            dovecot 61342 59971 dovecot/anvil
            root    62962 59971 dovecot/log
            root    64752 59971 dovecot/config
            root    64913     1 /usr/local/libexec/postfix/master -w
            postfix 64955 64913 pickup -l -t unix -u
            postfix 65038 64913 qmgr -l -t unix -u
            mysql   67863     1 /bin/sh /usr/local/bin/mysqld_safe --basedir=/usr/local --user=mysql
            root    70001     1 /usr/local/openjdk25/bin/java -jar /home/panel/daemoxcp-mail-1.0.jar --web
            root    72566 72455 sshd-session: root@notty (sshd-session)
            """;
    static final String AFTER = BEFORE.replace("www     33079 32645 php-fpm: pool www", "roundcube 33079 32645 php-fpm: pool roundcube")
            .replace("www     34440 32645 php-fpm: pool www", "roundcube 34440 32645 php-fpm: pool roundcube")
            .replace("root    56502     1 rspamd: main process", "rspamd  56502     1 rspamd: main process")
            // Since 23/11/2026 php-fpm's master runs as roundcube too (PhpFpmMaster).
            .replace("root    32645     1 php-fpm: master process", "roundcube 32645     1 php-fpm: master process");
    static final Map<Path, String> POOL_BEFORE = Map.of(Path.of("/usr/local/etc/php-fpm.d/www.conf"), "[www]\nuser = www\nlisten = /var/run/php-fpm.sock\n");
    static final Map<Path, String> POOL_AFTER = Map.of(Path.of("/usr/local/etc/php-fpm.d/roundcube.conf"), RoundcubeUser.poolConf(null),
            Path.of("/usr/local/etc/php-fpm.d/www.conf"), RoundcubeUser.wwwPlaceholder());

    static ServiceUsers.Findings ex(String ps, Map<Path, String> pools, String crontab, boolean acmeRoot) {
        return ServiceUsers.examine(ServiceUsers.processes(ps), pools, crontab, acmeRoot, Map.of());
    }

    static String codes(ServiceUsers.Findings f) {
        return f.problems().stream().map(p -> p.code() + ":" + p.service()).collect(Collectors.joining(" "));
    }

    public static void main(String[] args) {
        OUT.println("== Before: nginx and Roundcube with the same user");
        ServiceUsers.Findings f = ex(BEFORE, POOL_BEFORE, "", false);
        f.problems().forEach(p -> OUT.println("     " + p.logText()));
        check("www shared between nginx and the www pool", f.problems().stream().anyMatch(p -> "shared".equals(p.code()) && "www".equals(p.user())
                && p.detail().contains("nginx") && p.detail().contains("php-fpm pool www")));
        check("the www pool configured with nginx's user", f.problems().stream().anyMatch(p -> "poolShared".equals(p.code()) && "www".equals(p.service())));
        // Since 07/11/2026 rspamd's main process does not need root either (RspamdUser): on the
        // 31/10 picture it is the only root warning.
        check("the only root warning is rspamd's main process (" + codes(f) + ")", f.problems().stream()
                .filter(p -> "root".equals(p.code())).map(ServiceUsers.Problem::service).toList().equals(List.of("rspamd")));
        check("the users read: mysql, redis, clamav, rspamd, unbound, postfix, dovecot",
                f.services().get("mysql").users.equals(java.util.Set.of("mysql")) && f.services().get("clamav").users.equals(java.util.Set.of("clamav"))
                && f.services().get("postfix").users.containsAll(List.of("root", "postfix")) && f.services().get("unbound").users.equals(java.util.Set.of("unbound")));

        OUT.println("\n== After: Roundcube with its own user");
        f = ex(AFTER, POOL_AFTER, "", false);
        check("no warning (" + codes(f) + ")", f.problems().isEmpty());
        check("the roundcube pool runs as roundcube", f.services().get("php-fpm pool roundcube").users.equals(java.util.Set.of("roundcube")));
        check("the pools read from the files, www without a pool", f.pools().size() == 1 && "roundcube".equals(f.pools().get(0)[1]));
        check("php-fpm's master runs as roundcube, with its pool: one program, not a shared user",
                f.services().get("php-fpm").users.equals(java.util.Set.of("roundcube")) && !f.services().get("php-fpm").neededRoot);

        OUT.println("\n== php-fpm's master: root only with other pools (23/11/2026)");
        String rootMaster = AFTER.replace("roundcube 32645     1 php-fpm: master process", "root    32645     1 php-fpm: master process");
        f = ex(rootMaster, POOL_AFTER, "", false);
        check("master as root with Roundcube's pool alone: root warning (" + codes(f) + ")", codes(f).equals("root:php-fpm"));
        Map<Path, String> twoPools = new java.util.TreeMap<>(POOL_AFTER);
        twoPools.put(Path.of("/usr/local/etc/php-fpm.d/shop.conf"), "[shop]\nuser = shop\nlisten = /var/run/shop.sock\n");
        f = ex(rootMaster, twoPools, "", false);
        check("master as root with a pool added by hand: needed, no warning (" + codes(f) + ")",
                f.problems().isEmpty() && f.services().get("php-fpm").neededRoot);
        f = ex(AFTER.replace("redis   40133", "roundcube 40133"), POOL_AFTER, "", false);
        check("redis with roundcube's user: still a shared user, the master aside (" + codes(f) + ")",
                codes(f).equals("shared:php-fpm pool roundcube, redis"));

        OUT.println("\n== The planted faults: each its own warning");
        f = ex(AFTER.replace("mysql   26927", "root    26927"), POOL_AFTER, "", false);
        check("mysqld as root: root warning on mysql (" + codes(f) + ")", codes(f).equals("root:mysql"));
        f = ex(AFTER.replace("postfix 64955 64913 pickup", "root    64955 64913 pickup"), POOL_AFTER, "", false);
        check("Postfix's pickup as root: warning (" + codes(f) + ")", codes(f).equals("root:postfix"));
        f = ex(AFTER + "root    64999 64913 local -t unix\n", POOL_AFTER, "", false);
        check("Postfix's local as root: no warning, that is how it is built (" + codes(f) + ")", f.problems().isEmpty());
        // Measured on 07/11/2026: Dovecot 2.3 runs auth-worker as root by default, and it only looks
        // passwords up in MySQL. As the internal user it is right; as root it is a warning.
        f = ex(AFTER + "dovecot 65001 59971 dovecot/auth\ndovecot 65002 59971 dovecot/auth -w\n", POOL_AFTER, "", false);
        check("Dovecot's auth and auth-worker as dovecot: no warning (" + codes(f) + ")", f.problems().isEmpty());
        f = ex(AFTER + "dovecot 65001 59971 dovecot/auth\nroot    65002 59971 dovecot/auth -w\n", POOL_AFTER, "", false);
        check("Dovecot's auth-worker as root: warning (" + codes(f) + ")", codes(f).equals("root:dovecot"));
        f = ex(AFTER + "root    65001 59971 dovecot/auth\n", POOL_AFTER, "", false);
        check("Dovecot's auth as root: warning (" + codes(f) + ")", codes(f).equals("root:dovecot"));
        // Dovecot 2.4 runs anvil as root by design (measured on 09/11/2026, finding 213): there it is needed, on 2.3 not.
        String anvilRoot = AFTER.replace("dovecot 61342 59971 dovecot/anvil", "root    61342 59971 dovecot/anvil");
        f = ex(anvilRoot, POOL_AFTER, "", false);
        check("Dovecot 2.3's anvil as root: warning (" + codes(f) + ")", codes(f).equals("root:dovecot"));
        f = ServiceUsers.examine(ServiceUsers.processes(anvilRoot), POOL_AFTER, "", false, Map.of(), true);
        check("Dovecot 2.4's anvil as root: needed, no warning (" + codes(f) + ")", f.problems().isEmpty() && f.services().get("dovecot").neededRoot);
        f = ServiceUsers.examine(ServiceUsers.processes(AFTER + "dovecot 65001 59971 dovecot/auth\nroot    65002 59971 dovecot/auth -w\n"),
                POOL_AFTER, "", false, Map.of(), true);
        check("  on 2.4 too, auth-worker as root is still a warning (" + codes(f) + ")", codes(f).equals("root:dovecot"));
        f = ex(AFTER.replace("rspamd  56502     1 rspamd: main process", "root    56502     1 rspamd: main process"), POOL_AFTER, "", false);
        check("rspamd's main process as root: warning (" + codes(f) + ")", codes(f).equals("root:rspamd"));
        OUT.println("\n== Why root, said on the page");
        for (ServiceUsers.Rule r : ServiceUsers.RULES)
            if (r.rootNeeded() && !r.service().contains("$1"))
                check(r.service() + " keeps root by design: the page says why", ServiceUsers.ROOT_WHY.containsKey(r.service()));
        for (String k : ServiceUsers.ROOT_WHY.values()) {
            String key = "server.su.rootWhy." + k;
            check("  " + key + " in both languages", !org.daemoxcp.mail.i18n.I18n.t("it", key).equals(key)
                    && !org.daemoxcp.mail.i18n.I18n.t("en", key).equals(key));
        }
        f = ex(AFTER + "root    65003 59971 dovecot/imap\n", POOL_AFTER, "", false);
        check("a Dovecot imap as root: warning (" + codes(f) + ")", codes(f).equals("root:dovecot"));
        f = ex(AFTER.replace("www     37741 36807 nginx: worker", "root    37741 36807 nginx: worker"), POOL_AFTER, "", false);
        check("an nginx worker as root: warning (" + codes(f) + ")", codes(f).contains("root:nginx"));
        f = ex(AFTER.replace("redis   40133", "clamav  40133"), POOL_AFTER, "", false);
        check("redis with clamav's user: shared user warning (" + codes(f) + ")", codes(f).equals("shared:clamav, redis"));
        f = ex(AFTER, Map.of(Path.of("/x/root.conf"), "[evil]\nuser = root\nlisten = /tmp/e.sock\n"), "", false);
        check("a pool configured as root, even without processes (" + codes(f) + ")", codes(f).equals("poolRoot:evil"));
        f = ex(AFTER, POOL_AFTER, "25 0 * * * \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" > /dev/null\n", false);
        check("acme.sh in root's cron (" + codes(f) + ")", codes(f).equals("acmeRoot:acme.sh"));
        f = ex(AFTER, POOL_AFTER, "", true);
        check("acme.sh still in /root (" + codes(f) + ")", codes(f).equals("acmeRoot:acme.sh"));
        f = ex(AFTER, POOL_AFTER, "# 25 0 * * * acme.sh --cron\n", false);
        check("a comment in the cron is not a warning", f.problems().isEmpty());

        OUT.println("\n== What every user of a service does (reperto 228)");
        // A separated panel, Dovecot with its four users, Postfix's daemons: as on the VM after the upgrades.
        String full = AFTER.replace("root    70001     1 /usr/local/openjdk25/bin/java -jar /home/panel/daemoxcp-mail-1.0.jar --web",
                        "root    70001     1 /usr/local/openjdk25/bin/java -jar /home/panel/daemoxcp-mail-1.0.jar --web\n"
                        + "daemoxcp_mail 70002 70001 /usr/local/openjdk25/bin/java -jar /home/panel/daemoxcp-mail-1.0.jar --web-part")
                + "dovecot 65001 59971 dovecot/auth\ndovecot 65002 59971 dovecot/auth -w\n"
                + "dovenull 65010 59971 dovecot/imap-login\nvmail 65011 59971 dovecot/imap\nroot    65012 59971 dovecot/lmtp\n"
                + "postfix 65020 64913 smtpd -n smtp -t inet -u -o stress=\nroot    65021 64913 local -t unix\n";
        f = ex(full, POOL_AFTER, "", false);
        check("still no warning (" + codes(f) + ")", f.problems().isEmpty());
        Map<String, java.util.Set<String>> dovecot = f.services().get("dovecot").roles;
        check("Dovecot: root runs master, log, config, lmtp (" + dovecot.get("root") + ")",
                dovecot.get("root").equals(new java.util.LinkedHashSet<>(List.of("master", "log", "config", "lmtp"))));
        check("Dovecot: dovecot runs anvil, auth, auth-worker (" + dovecot.get("dovecot") + ")",
                dovecot.get("dovecot").equals(new java.util.LinkedHashSet<>(List.of("anvil", "auth", "auth-worker"))));
        check("Dovecot: dovenull runs imap-login, vmail runs imap", dovecot.get("dovenull").equals(java.util.Set.of("imap-login"))
                && dovecot.get("vmail").equals(java.util.Set.of("imap")));
        Map<String, java.util.Set<String>> postfix = f.services().get("postfix").roles;
        check("Postfix: root runs master and local, postfix pickup, qmgr, smtpd (" + postfix + ")",
                postfix.get("root").equals(java.util.Set.of("master", "local"))
                        && postfix.get("postfix").equals(java.util.Set.of("pickup", "qmgr", "smtpd")));
        Map<String, java.util.Set<String>> panel = f.services().get("daemoxcp-mail").roles;
        // Technical names, as ps shows them (the option each java runs with), not words: words belong to the language
        // files, and "root part" in English was shown on the Italian page.
        check("the panel: --web as root, --web-part as daemoxcp_mail (" + panel + ")", panel.get("root").equals(java.util.Set.of("--web"))
                && panel.get("daemoxcp_mail").equals(java.util.Set.of("--web-part")));
        check("  the panel from the menu, without --web: java", ServiceUsers.processName("daemoxcp-mail",
                "/usr/local/openjdk25/bin/java -jar /home/panel/daemoxcp-mail-1.0.jar").equals("java"));
        check("  the jar with the name it had before the rename (until the restart) is still the panel",
                java.util.regex.Pattern.compile(ServiceUsers.JAR).matcher("java -jar /home/panel/freebsd-mail-panel-1.0.jar --web").find()
                && !java.util.regex.Pattern.compile(ServiceUsers.JAR).matcher("java -jar /home/panel/other-1.0.jar --web").find());
        // The panel's two daemon(8) supervisors (23/11/2026): the rc script's, root like the root part it runs; the web
        // part's, as daemoxcp_mail. The page shows them, so a supervisor left as root no longer goes unseen.
        String supervised = full + "root    69990     1 daemon: daemoxcp_mail[70001] (daemon)\n"
                + "daemoxcp_mail 70003     1 daemon: daemoxcp-mail-web[70002] (daemon)\n";
        ServiceUsers.Findings sup = ex(supervised, POOL_AFTER, "", false);
        Map<String, java.util.Set<String>> supRoles = sup.services().get("daemoxcp-mail").roles;
        check("the supervisors are the panel's, with no warning (" + codes(sup) + "): " + supRoles, sup.problems().isEmpty()
                && supRoles.get("root").equals(java.util.Set.of("--web", "daemon"))
                && supRoles.get("daemoxcp_mail").equals(java.util.Set.of("--web-part", "daemon")));
        sup = ex(full + "root    70003     1 daemon: daemoxcp-mail-web[70002] (daemon)\n", POOL_AFTER, "", false);
        check("  the web part's supervisor as root: warning (" + codes(sup) + ")", codes(sup).equals("root:daemoxcp-mail"));
        sup = ex(full + "root    70004     1 daemon: other-service[70005] (daemon)\n", POOL_AFTER, "", false);
        check("  a daemon(8) of something else is not the panel's (" + sup.services().get("daemoxcp-mail").roles + ")",
                !sup.services().get("daemoxcp-mail").roles.get("root").contains("daemon"));
        check("mysql: mysqld and mysqld_safe, not sh (" + f.services().get("mysql").roles + ")",
                f.services().get("mysql").roles.get("mysql").equals(java.util.Set.of("mysqld", "mysqld_safe")));
        check("fail2ban: fail2ban-server, not python3.12; redis: redis-server; unbound: local-unbound",
                f.services().get("fail2ban").roles.get("root").equals(java.util.Set.of("fail2ban-server"))
                        && f.services().get("redis").roles.get("redis").equals(java.util.Set.of("redis-server"))
                        && f.services().get("unbound").roles.get("unbound").equals(java.util.Set.of("local-unbound")));
        check("nginx: master and worker; rspamd: main and rspamd_proxy; php-fpm: master; the pool: pool",
                f.services().get("nginx").roles.get("root").equals(java.util.Set.of("master"))
                        && f.services().get("nginx").roles.get("www").equals(java.util.Set.of("worker"))
                        && f.services().get("rspamd").roles.get("rspamd").equals(java.util.Set.of("main", "rspamd_proxy"))
                        && f.services().get("php-fpm").roles.get("roundcube").equals(java.util.Set.of("master"))
                        && f.services().get("php-fpm pool roundcube").roles.get("roundcube").equals(java.util.Set.of("pool")));
        org.json.JSONArray roles = ServiceUsers.roles(f.services().get("dovecot"));
        check("on the page root comes first, then the others as ps listed them (" + roles + ")",
                roles.length() == 4 && "root".equals(roles.getJSONObject(0).getString("user"))
                        && "dovecot".equals(roles.getJSONObject(1).getString("user")));
        ServiceUsers.addOnDemand(f, true);
        check("sievec is listed although no process of it runs (it compiles the rules when they are saved)",
                f.services().get("sievec") != null && f.services().get("sievec").roles.get("sievec").equals(java.util.Set.of("sievec")));
        ServiceUsers.Findings none = ex(full, POOL_AFTER, "", false);
        ServiceUsers.addOnDemand(none, false);
        check("without the user sievec, no line for it", none.services().get("sievec") == null);
        // Every user the panel installs has a sentence on what it is for, in both languages.
        for (ServiceUsers.Service sv : f.services().values())
            for (String user : sv.roles.keySet()) {
                String key = ServiceUsers.purposeKey(sv.name, user);
                check("  " + sv.name + " / " + user + ": " + key + " in both languages", !org.daemoxcp.mail.i18n.I18n.t("it", key).equals(key)
                        && !org.daemoxcp.mail.i18n.I18n.t("en", key).equals(key)
                        && !org.daemoxcp.mail.i18n.I18n.t("it", key).equals(org.daemoxcp.mail.i18n.I18n.t("en", key)));
            }
        // And the page gets it: in roles() every user of every service carries its sentence, the one of the language files.
        // Without this the keys above could all exist while the answer to the page had none (measured: with the line that
        // puts "purpose" taken out, every check of this test was still green).
        StringBuilder withoutSentence = new StringBuilder();
        for (ServiceUsers.Service sv : f.services().values()) {
            org.json.JSONArray rs = ServiceUsers.roles(sv);
            for (int i = 0; i < rs.length(); i++) {
                org.json.JSONObject r = rs.getJSONObject(i);
                String expected = org.daemoxcp.mail.i18n.I18n.tr(ServiceUsers.purposeKey(sv.name, r.getString("user")));
                if (!expected.equals(r.optString("purpose", null))) withoutSentence.append(sv.name).append('/').append(r.getString("user")).append(' ');
            }
        }
        check("the page gets the sentence of every user in roles() (" + withoutSentence.toString().trim() + ")", withoutSentence.length() == 0);
        check("the keys of the acme user and of the pools", ServiceUsers.purposeKey("acme.sh", "acme").equals("server.su.purpose.acme.acme")
                && ServiceUsers.purposeKey("php-fpm pool www", "www").equals("server.su.purpose.pool.www.www")
                && ServiceUsers.purposeKey("daemoxcp-mail", "daemoxcp_mail").equals("server.su.purpose.daemoxcpMail.daemoxcp_mail"));
        check("a user the panel does not know gets no sentence, only its processes",
                ServiceUsers.roles(ex(AFTER.replace("clamav  43258", "nobody  43258"), POOL_AFTER, "", false).services().get("clamav"))
                        .toString().contains("\"user\":\"nobody\"")
                        && !ServiceUsers.roles(ex(AFTER.replace("clamav  43258", "nobody  43258"), POOL_AFTER, "", false).services().get("clamav"))
                        .getJSONObject(0).has("purpose"));

        OUT.println("\n== The ps output");
        check("one line per process, with the fields", ServiceUsers.processes(BEFORE).size() == BEFORE.strip().split("\n").length
                && ServiceUsers.processes("www 1 2 php-fpm: pool www (php-fpm)").get(0).ppid() == 2);
        check("the users of every pool", ServiceUsers.poolUsers(AFTER).equals(Map.of("roundcube", java.util.Set.of("roundcube"))));

        OUT.println();
        OUT.println(failed == 0 ? "ALL OK" : "FAILED: " + failed);
        if (failed > 0) System.exit(1);
    }
}
