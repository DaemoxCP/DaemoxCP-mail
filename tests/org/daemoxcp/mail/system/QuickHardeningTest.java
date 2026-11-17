package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Three hardenings done at startup, measured on 07/11/2026 on the real server:
 *  - MysqlListen: the X protocol port 33060 on every address (and, on the VM, 3306 too);
 *  - SyslogNetwork: syslogd on UDP 514, FreeBSD's default "-s";
 *  - VmailPermissions: folders 0755 and mail files 0644 inside /var/vmail.
 *
 * Part 1 is pure (the my.cnf edit, the syslogd decision). Part 2, with -De2e.vm=yes, as root on the
 * FreeBSD VM, runs each repair on the real system and puts back what it found: MySQL with the mail
 * lookups checked before and after, syslogd with a real message through logger, /var/vmail on a copy in
 * /var/tmp. Each one has a planted fault: a my.cnf that mysqld refuses, an address chosen by hand that
 * the check after the restart must see, syslogd still listening, a folder vmail cannot enter.
 *
 * Usage (on the VM):
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.QuickHardeningTest
 */
public class QuickHardeningTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The real server's my.cnf, 07/11/2026 (the package's sample), the parts that matter. */
    static final String SAMPLE = """
            [client]
            port                            = 3306
            socket                          = /tmp/mysql.sock

            [mysql]
            prompt                          = \\u@\\h [\\d]>\\_
            no_auto_rehash

            [mysqld]
            user                            = mysql
            port                            = 3306
            socket                          = /tmp/mysql.sock
            bind-address                    = 127.0.0.1
            basedir                         = /usr/local
            innodb_buffer_pool_size         = 1G

            [mysqldump]
            max_allowed_packet              = 256M
            quote_names
            quick
            """;

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. my.cnf ==");
        String h = MysqlListen.harden(SAMPLE);
        check("the sample: only mysqlx = OFF is added", h != null && h.contains("mysqlx                          = OFF")
                && h.split("bind-address", -1).length == 2);
        check("  inside [mysqld], after its last option and before [mysqldump]", h != null
                && h.indexOf("mysqlx ") > h.indexOf("innodb_buffer_pool_size") && h.indexOf("mysqlx ") < h.indexOf("[mysqldump]"));
        check("  and nothing else changes", h != null && h.replace(MysqlListen.COMMENT + "\n", "")
                .replace("mysqlx                          = OFF\n", "").equals(SAMPLE));
        check("the second time: nothing to add", MysqlListen.harden(h) == null);
        check("no my.cnf: a minimal one, not the sample", MysqlListen.harden(null)
                .equals("[mysqld]\n" + MysqlListen.COMMENT + "\nbind-address = 127.0.0.1\nmysqlx = OFF\n"));
        check("mysqlx_bind_address written by someone: their choice, nothing added",
                MysqlListen.harden(SAMPLE.replace("basedir", "mysqlx_bind_address = 10.0.0.1\nbasedir")) == null);
        check("loose_mysqlx = 0 counts too", MysqlListen.harden(SAMPLE.replace("basedir", "loose_mysqlx = 0\nbasedir")) == null);
        String noBind = MysqlListen.harden(SAMPLE.replace("bind-address                    = 127.0.0.1\n", ""));
        check("without bind-address: both lines", noBind != null && noBind.contains("bind-address                    = 127.0.0.1")
                && noBind.contains("mysqlx                          = OFF"));
        check("a bind-address only in [client] does not count",
                MysqlListen.harden("[client]\nbind-address = 127.0.0.1\n[mysqld]\nport = 3306\n").contains("[mysqld]\nport = 3306\n"
                        + MysqlListen.COMMENT + "\nbind-address"));
        check("a commented bind-address does not count",
                MysqlListen.harden("[mysqld]\n# bind-address = 127.0.0.1\nport = 3306\n").contains("bind-address                    = 127.0.0.1"));
        check("no [mysqld] at all: the section is added at the end",
                MysqlListen.harden("[client]\nport = 3306\n").endsWith("\n[mysqld]\n" + MysqlListen.COMMENT
                        + "\nbind-address                    = 127.0.0.1\nmysqlx                          = OFF\n"));

        System.out.println("\n== 2. syslogd ==");
        check("FreeBSD's default -s: apply", SyslogNetwork.decide("-s", List.of()).action() == SyslogNetwork.Action.APPLY);
        check("-ss: nothing", SyslogNetwork.decide("-ss", List.of()).action() == SyslogNetwork.Action.NOTHING);
        check("-s -s: nothing", SyslogNetwork.decide("-s -s", List.of()).action() == SyslogNetwork.Action.NOTHING);
        check("other flags chosen by someone: left alone",
                SyslogNetwork.decide("-s -a 192.0.2.0/24", List.of()).action() == SyslogNetwork.Action.LEFT_ALONE);
        check("logs sent to another machine: left alone",
                SyslogNetwork.decide("-s", List.of("*.*\t\t\t\t\t\t@loghost")).action() == SyslogNetwork.Action.LEFT_ALONE);
        check("the commented @loghost of FreeBSD's syslog.conf: apply",
                SyslogNetwork.decide("-s", List.of("#*.*\t\t\t\t\t\t@loghost")).action() == SyslogNetwork.Action.APPLY);

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 3 skipped: it restarts MySQL and syslogd, turned on with -De2e.vm=yes on the VM)");
            finish();
            return;
        }
        endToEnd();
        finish();
    }

    static void finish() {
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static List<String> logged = new ArrayList<>();

    static Handler capture(Class<?> c) {
        Handler h = new Handler() {
            @Override public void publish(LogRecord r) { logged.add(r.getLevel() + ": " + r.getMessage()); }
            @Override public void flush() {}
            @Override public void close() {}
        };
        Logger.getLogger(c.getName()).addHandler(h);
        return h;
    }

    static List<String> mysqlListeners() {
        List<String> out = new ArrayList<>();
        for (String l : Shell.run(Duration.ofSeconds(15), "sockstat", "-46l").outputTrim().split("\n")) {
            String[] f = l.trim().split("\\s+");
            if (f.length >= 6 && f[1].startsWith("mysqld")) out.add(f[5]);
        }
        return out;
    }

    static void endToEnd() throws Exception {
        capture(MysqlListen.class);
        capture(SyslogNetwork.class);
        capture(VmailPermissions.class);

        System.out.println("\n== 3. MySQL on the VM ==");
        Path cnf = MysqlListen.myCnf;
        String found = Files.exists(cnf) ? Files.readString(cnf) : null;
        System.out.println("    my.cnf at the start: " + (found == null ? "absent" : found.length() + " bytes")
                + ", MySQL listens on " + mysqlListeners());
        String lookups = MysqlListen.lookups();
        System.out.println("    mail lookups at the start: " + lookups);
        try {
            logged.clear();
            MysqlListen.ensureAtBoot();
            System.out.println("    log: " + logged);
            List<String> now = mysqlListeners();
            check("the repair: DONE", logged.size() == 1 && logged.get(0).startsWith("INFO: [MysqlListen] DONE: "));
            check("MySQL listens only on 127.0.0.1 and not on 33060 (" + now + ")", !now.isEmpty()
                    && now.stream().allMatch(a -> a.startsWith("127.0.0.1:") && !a.endsWith(":33060")));
            check("the mail lookups answer as before (" + MysqlListen.lookups() + ")", MysqlListen.lookups().equals(lookups));
            logged.clear();
            MysqlListen.ensureAtBoot();
            check("the second time: nothing", logged.isEmpty());

            // Fault 1: a my.cnf that mysqld refuses. The repair must not restart anything.
            Files.writeString(cnf, "[mysqld]\nthis-option-does-not-exist = 1\n");
            logged.clear();
            boolean ok = MysqlListen.apply(Files.readString(cnf), MysqlListen.harden(Files.readString(cnf)));
            check("a my.cnf mysqld refuses: rolled back before any restart (" + logged + ")", !ok
                    && logged.stream().anyMatch(l -> l.startsWith("WARNING: [MysqlListen] ROLLED_BACK: mysqld --validate-config")));
            check("  and the file is the one it found", Files.readString(cnf).equals("[mysqld]\nthis-option-does-not-exist = 1\n"));

            // Fault 2: an address chosen by hand that is not local: the check after the restart sees it.
            String chosen = "[mysqld]\nbind-address = 0.0.0.0\n";
            Files.writeString(cnf, chosen);
            Shell.run(Duration.ofSeconds(180), "service", "mysql-server", "restart");
            MysqlListen.waitForMysql();
            logged.clear();
            ok = MysqlListen.apply(chosen, MysqlListen.harden(chosen));
            check("bind-address = 0.0.0.0 chosen by hand: the check after the restart sees it, rolled back (" + logged + ")",
                    !ok && logged.stream().anyMatch(l -> l.contains("ROLLED_BACK: MySQL still listens on")));
            check("  and my.cnf is the one chosen by hand", Files.readString(cnf).equals(chosen));
        } finally {
            if (found == null) Files.deleteIfExists(cnf); else Files.writeString(cnf, found);
            Shell.run(Duration.ofSeconds(180), "service", "mysql-server", "restart");
            System.out.println("    MySQL put back as found: " + (MysqlListen.waitForMysql() ? "answers" : "DOES NOT ANSWER")
                    + ", listens on " + mysqlListeners());
        }

        System.out.println("\n== 4. syslogd on the VM ==");
        String flags = Shell.run(Duration.ofSeconds(10), "sysrc", "-n", "syslogd_flags").outputTrim();
        boolean inRc = Shell.run(Duration.ofSeconds(10), "sh", "-c", "grep -q '^[[:space:]]*syslogd_flags=' /etc/rc.conf").success();
        System.out.println("    syslogd_flags at the start: '" + flags + "'" + (inRc ? " (in rc.conf)" : " (FreeBSD's default)"));
        try {
            logged.clear();
            SyslogNetwork.ensureAtBoot();
            System.out.println("    log: " + logged);
            check("the repair: DONE", logged.size() == 1 && logged.get(0).startsWith("INFO: [SyslogNetwork] DONE: "));
            check("syslogd has no network socket", Shell.run(Duration.ofSeconds(15), "sh", "-c", "sockstat -46l | grep -c syslogd")
                    .outputTrim().equals("0"));
            logged.clear();
            SyslogNetwork.ensureAtBoot();
            check("the second time: nothing", logged.isEmpty());
            // Fault: syslogd listening again; the check must say so.
            Shell.run(Duration.ofSeconds(10), "sysrc", "syslogd_flags=-s");
            Shell.run(Duration.ofSeconds(30), "service", "syslogd", "restart");
            String problem = SyslogNetwork.verify();
            check("syslogd listening again: the check sees it (" + problem + ")", problem != null && problem.contains("network socket"));
        } finally {
            if (inRc) Shell.run(Duration.ofSeconds(10), "sysrc", "syslogd_flags=" + flags);
            else Shell.run(Duration.ofSeconds(10), "sysrc", "-x", "syslogd_flags");
            Shell.run(Duration.ofSeconds(30), "service", "syslogd", "restart");
            System.out.println("    syslogd put back: flags '" + Shell.run(Duration.ofSeconds(10), "sysrc", "-n", "syslogd_flags").outputTrim() + "'");
        }

        System.out.println("\n== 6. rspamd on the VM ==");
        String to = System.getProperty("test.mailbox", "");
        boolean rcSet = Shell.run(Duration.ofSeconds(10), "sh", "-c", "sysrc -n rspamd_user >/dev/null 2>&1").success();
        System.out.println("    main process as '" + RspamdUser.mainUser() + "', rspamd_user " + (rcSet ? "set" : "not set")
                + ", a scan says '" + RspamdUser.scan() + "'");
        try {
            logged.clear();
            capture(RspamdUser.class);
            RspamdUser.ensureAtBoot();
            System.out.println("    log: " + logged);
            check("the repair: DONE", logged.size() == 1 && logged.get(0).startsWith("INFO: [RspamdUser] DONE: "));
            List<String> users = RspamdUser.processes().stream().map(p -> p[0]).distinct().toList();
            check("every rspamd process, the main one too, as rspamd (" + users + ")", users.equals(List.of("rspamd")));
            check("a real scan answers (" + RspamdUser.scan() + ")", RspamdUser.scan() != null);
            if (!to.isEmpty()) {
                String d = delivery(to);
                check("a real message through Postfix and rspamd's milter is delivered (" + d + ")", d == null);
            } else System.out.println("    (no -Dtest.mailbox: real delivery not tried)");
            logged.clear();
            RspamdUser.ensureAtBoot();
            check("the second time: nothing", logged.isEmpty());
            // Fault: back to root (stop as the user, then without the setting), and the check must say so.
            RspamdUser.stop();
            Shell.run(Duration.ofSeconds(10), "sysrc", "-x", "rspamd_user");
            Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
            String problem = RspamdUser.verify();
            check("the main process as root again: the check sees it (" + problem + ")", problem != null && problem.contains("root"));
        } finally {
            RspamdUser.stop();
            if (!rcSet) Shell.run(Duration.ofSeconds(10), "sysrc", "-x", "rspamd_user");
            Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
            Thread.sleep(3000);
            System.out.println("    rspamd put back: main process as '" + RspamdUser.mainUser() + "', a scan says '" + RspamdUser.scan() + "'");
        }

        System.out.println("\n== 5. /var/vmail, on a copy ==");
        Path root = Files.createTempDirectory(Path.of("/var/tmp"), "vmail-test");
        Path saved = VmailPermissions.root;
        VmailPermissions.root = root;
        try {
            Path mailbox = Files.createDirectories(root.resolve("example.test/alice/cur"));
            Files.writeString(mailbox.resolve("1.mail"), "From: x\n\nhello\n");
            Files.writeString(root.resolve("example.test/alice/dovecot.index"), "x");
            Files.writeString(root.resolve("example.test/root-owned.txt"), "x");
            Shell.runShell(Duration.ofSeconds(30), "chown -R vmail:vmail " + root + "/example.test && chown root:wheel "
                    + root + "/example.test/root-owned.txt && chmod -R 755 " + root + "/example.test && chmod 644 "
                    + mailbox.resolve("1.mail") + " " + root + "/example.test/alice/dovecot.index " + root + "/example.test/root-owned.txt && chown vmail:vmail " + root + " && chmod 770 " + root);
            logged.clear();
            VmailPermissions.ensureAtBoot();
            System.out.println("    log: " + logged);
            check("the repair: DONE", logged.size() == 1 && logged.get(0).startsWith("INFO: [VmailPermissions] DONE: "));
            check("  folders 0700 and files 0600", mode(root.resolve("example.test")).equals("drwx------")
                    && mode(mailbox).equals("drwx------") && mode(mailbox.resolve("1.mail")).equals("-rw-------"));
            check("  a file not owned by vmail left as it is, and counted",
                    mode(root.resolve("example.test/root-owned.txt")).equals("-rw-r--r--") && logged.get(0).contains("1 entries not owned by vmail"));
            logged.clear();
            VmailPermissions.ensureAtBoot();
            check("the second time: nothing", logged.isEmpty());
            Shell.run(Duration.ofSeconds(10), "chmod", "000", root.resolve("example.test/alice").toString());
            String problem = VmailPermissions.unreadableByVmail();
            check("a mailbox vmail cannot enter: the check sees it (" + problem + ")", problem != null && problem.contains("alice"));
        } finally {
            VmailPermissions.root = saved;
            Shell.run(Duration.ofSeconds(30), "rm", "-rf", root.toString());
        }
    }

    /** A real message through Postfix (and rspamd's milter) to the VM's test mailbox: delivered, no milter error. */
    static String delivery(String to) throws Exception {
        String id = "rspamd-probe-" + java.util.UUID.randomUUID() + "@daemoxcp-mail.invalid";
        Path m = Files.createTempFile(Path.of("/var/tmp"), "probe-", ".eml");
        Files.writeString(m, "From: root@localhost\nTo: " + to + "\nSubject: daemoxcp-mail rspamd probe\nMessage-ID: <" + id
                + ">\n\nThis message checks that Postfix and rspamd still deliver.\n");
        Shell.runShell(Duration.ofSeconds(30), "/usr/local/sbin/sendmail -t < " + m);
        Files.deleteIfExists(m);
        java.util.regex.Pattern queued = java.util.regex.Pattern.compile("postfix/cleanup\\[\\d+\\]: ([0-9A-Za-z]+): message-id=<" + java.util.regex.Pattern.quote(id) + ">");
        String qid = null;
        for (int i = 0; i < 40; i++) {
            Thread.sleep(1000);
            String log = Shell.run(Duration.ofSeconds(10), "tail", "-n", "400", "/var/log/maillog").output();
            if (qid == null) {
                java.util.regex.Matcher q = queued.matcher(log);
                if (q.find()) qid = q.group(1); else continue;
            }
            for (String l : log.split("\n")) {
                if (!l.contains(qid + ":")) continue;
                if (l.contains("milter-reject") || l.contains("milter") && l.contains("error")) return "milter: " + l;
                if (l.contains("status=sent")) return null;
                if (l.contains("status=bounced") || l.contains("status=deferred")) return "not delivered: " + l;
            }
        }
        return "the message " + id + (qid == null ? " never reached cleanup" : " (" + qid + ") was not delivered") + " within 40 seconds";
    }

    static String mode(Path p) {
        return Shell.run(Duration.ofSeconds(10), "stat", "-f", "%Sp", p.toString()).outputTrim();
    }
}
