package org.mail_panel.security;

import org.mail_panel.database.MailDatabase;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The root part does not trust the names it reads from MySQL.
 * With the separated panel MySQL is written by the web part too, which has the panel's MySQL user: a
 * broken-into web part could write a domain like "x; command" or a mailbox like "..", and wait for the
 * root part to put it in a shell script or a path. Names are planted here straight into MySQL, past the
 * checks of the pages, as that web part would:
 *
 *  1. SafeNames: domains, local parts, addresses, DKIM selectors and paths under a folder, with the
 *     shapes that must pass and the ones that must not (shell characters, slashes, "..", a leading dot);
 *  2. DKIM key files: a domain or selector that is not one is refused, a good one stays in the key folder;
 *  3. Sieve (as root on the VM, -De2e.vm=yes): a mailbox ".." or a domain with ".." is refused, and no
 *     file is written;
 *  4. with the test MySQL: the mail configuration script leaves out a planted domain with a command in
 *     its name and a planted mailbox "..", says so, keeps the good ones between quotes, creates cur, new
 *     and tmp one by one (FreeBSD's /bin/sh does not expand {cur,new,tmp}), and sh -n accepts it;
 *  5. with the test MySQL, as root on the VM: the DNS challenge check of a certificate with a planted
 *     record name that carries a command does not run it (before, it went to /bin/sh -c as root).
 *
 * Usage (on the VM):
 *   java -De2e.vm=yes -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=... \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.RootDistrustsDataTest
 */
public class RootDistrustsDataTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. SafeNames ==");
        for (String d : new String[]{"example.com", "mail.example.co.uk", "xn--80ak6aa92e.com", "a-b.c1.org"})
            check("domain " + d + " passes", SafeNames.domain(d));
        for (String d : new String[]{"x; touch /tmp/a", "a/b.com", "../etc", ".example.com", "example.com.", "-a.com",
                "a..b.com", "a b.com", "a'b.com", "a$(id).com", "localhost", "", "é.com"})
            check("domain '" + d + "' refused", !SafeNames.domain(d));
        for (String u : new String[]{"john", "john.doe", "a+b", "info_2", "x-y"})
            check("local part " + u + " passes", SafeNames.localPart(u));
        for (String u : new String[]{"..", ".", ".hidden", "a..b", "a/b", "a;b", "a b", "a'b", "trailing.", ""})
            check("local part '" + u + "' refused", !SafeNames.localPart(u));
        check("an address passes", SafeNames.address("john.doe@example.com"));
        for (String a : new String[]{"..@example.com", "a@b@example.com", "a@../etc", "a@", "@example.com"})
            check("address '" + a + "' refused", !SafeNames.address(a));
        check("selectors mail, r20261107, r20261107-2 pass", SafeNames.selector("mail") && SafeNames.selector("r20261107")
                && SafeNames.selector("r20261107-2"));
        check("selector with a quote or a slash refused", !SafeNames.selector("mail\";") && !SafeNames.selector("a/b"));
        Path base = Path.of("/var/mail/sieve");
        check("under(): a good path stays under the folder", SafeNames.under(base, "example.com", "john").equals(base.resolve("example.com/john")));
        for (String[] bad : new String[][]{{".."}, {"a", ".."}, {"a/../.."}, {""}})
            check("under(): " + String.join("|", bad) + " refused", refused(() -> SafeNames.under(base, bad)));

        System.out.println("\n== 2. DKIM key files ==");
        check("a good domain and selector: a file in the key folder",
                DkimManager.keyFile("example.com", "mail").toString().equals("/usr/local/etc/mail/dkim/example.com.mail.key"));
        check("domain ../etc refused", refused(() -> DkimManager.keyFile("../etc", "mail")));
        check("selector ../../x refused", refused(() -> DkimManager.keyFile("example.com", "../../x")));
        check("selector with a quote refused (it goes in rspamd's configuration)", refused(() -> DkimManager.keyFile("example.com", "a\"b")));

        boolean e2e = "yes".equals(System.getProperty("e2e.vm")) && "root".equals(System.getProperty("user.name"));
        if (e2e) {
            System.out.println("\n== 3. Sieve, as root ==");
            org.mail_panel.integration.SieveGenerator sieve = new org.mail_panel.integration.SieveGenerator();
            Path escaped = Path.of("/var/mail/sieve/evil-test.example/.dovecot.sieve");
            Path outside = Path.of("/var/mail/.dovecot.sieve");
            boolean beforeA = Files.exists(escaped), beforeB = Files.exists(outside);
            check("mailbox '..' refused", !sieve.saveSieveScript("..@evil-test.example", "keep;"));
            check("domain with '..' refused", !sieve.saveSieveScript("x@../../tmp", "keep;"));
            check("  and no file written outside a mailbox folder", Files.exists(escaped) == beforeA && Files.exists(outside) == beforeB);
            check("reading '..' gives nothing", sieve.getSieveScript("..@evil-test.example") == null);
        } else {
            System.out.println("\n  (part 3 skipped: it writes under /var/mail as root, turned on with -De2e.vm=yes on the VM)");
        }

        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("\n  (parts 4 and 5 skipped: they need the test MySQL, -Dmysql.port=...)");
        } else {
            Path dir = Files.createTempDirectory("root-distrust");
            System.setProperty("mailpanel.secrets.dir", dir.resolve("secrets").toString());
            System.setProperty("mailpanel.vault.key", dir.resolve("master.key").toString());
            MailDatabase db = new MailDatabase();
            db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
            db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_test"));
            check("connected to the test MySQL", db.connect());
            db.createSchema();
            org.mail_panel.Main.mailDatabase = db;

            System.out.println("\n== 4. The mail configuration script ==");
            String marker = "/tmp/root-distrust-regen-" + ProcessHandle.current().pid();
            int good = db.addDomain("good-test.example", "test");
            int evil = db.addDomain("evil.example;touch " + marker, "planted");
            db.addMailbox(good, "john@good-test.example", "Test-Password-123", "John", 0);
            db.addMailbox(good, "..@good-test.example", "Test-Password-123", "Planted", 0);
            String script = new org.mail_panel.scripts.ConfigRegeneratorScript(db).getScriptContent();
            check("the planted domain with a command is not in the script", !script.contains("touch"));
            check("the planted mailbox '..' is not in the script", !script.contains("/good-test.example/../"));
            check("the script says both were skipped", script.contains("a domain with an invalid name was skipped")
                    && script.contains("a mailbox with an invalid name was skipped"));
            check("the good domain is there, between quotes", script.contains("mkdir -p '/var/vmail/good-test.example'"));
            check("its mailbox: cur, new and tmp one by one", script.contains("'/var/vmail/good-test.example/john/Maildir/cur' '/var/vmail/good-test.example/john/Maildir/new' '/var/vmail/good-test.example/john/Maildir/tmp'")
                    && !script.contains("{cur,new,tmp}"));
            Path f = dir.resolve("regen.sh");
            Files.writeString(f, script);
            check("sh -n accepts the script", org.mail_panel.util.Shell.run("sh", "-n", f.toString()).success());

            if (e2e) {
                System.out.println("\n== 5. The certificate's DNS challenge, as root ==");
                String acmeMarker = "/tmp/root-distrust-acme-" + ProcessHandle.current().pid();
                db.setSetting("dns_challenge_hostname", "mail.good-test.example");
                db.setSetting("dns_challenge_domain", "x; touch " + acmeMarker + " #");
                db.setSetting("dns_challenge_value", "planted-value");
                AcmeManager.CertificateResult r = new AcmeManager(db).verifyDnsAndIssue("mail.good-test.example");
                check("the check fails, as the record is not there (" + (r == null ? "null" : r.message) + ")", r != null && !r.success);
                check("and the command in the planted record name did not run", !Files.exists(Path.of(acmeMarker)));
                Files.deleteIfExists(Path.of(acmeMarker));
            }
            db.deleteDomain(evil);
            db.deleteDomain(good);
            org.mail_panel.util.Shell.run("rm", "-rf", dir.toString());
            Files.deleteIfExists(Path.of(marker));
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static boolean refused(Runnable r) {
        try {
            r.run();
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }
}
