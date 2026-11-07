package org.mail_panel.system;

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
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ServiceUsersTest
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
            root    70001     1 /usr/local/openjdk25/bin/java -jar /home/panel/freebsd-mail-panel-1.0.jar --web
            root    72566 72455 sshd-session: root@notty (sshd-session)
            """;
    static final String AFTER = BEFORE.replace("www     33079 32645 php-fpm: pool www", "roundcube 33079 32645 php-fpm: pool roundcube")
            .replace("www     34440 32645 php-fpm: pool www", "roundcube 34440 32645 php-fpm: pool roundcube")
            .replace("root    56502     1 rspamd: main process", "rspamd  56502     1 rspamd: main process");
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
        f = ex(AFTER.replace("rspamd  56502     1 rspamd: main process", "root    56502     1 rspamd: main process"), POOL_AFTER, "", false);
        check("rspamd's main process as root: warning (" + codes(f) + ")", codes(f).equals("root:rspamd"));
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

        OUT.println("\n== The ps output");
        check("one line per process, with the fields", ServiceUsers.processes(BEFORE).size() == BEFORE.strip().split("\n").length
                && ServiceUsers.processes("www 1 2 php-fpm: pool www (php-fpm)").get(0).ppid() == 2);
        check("the users of every pool", ServiceUsers.poolUsers(AFTER).equals(Map.of("roundcube", java.util.Set.of("roundcube"))));

        OUT.println();
        OUT.println(failed == 0 ? "ALL OK" : "FAILED: " + failed);
        if (failed > 0) System.exit(1);
    }
}
