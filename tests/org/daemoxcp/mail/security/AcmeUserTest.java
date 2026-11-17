package org.daemoxcp.mail.security;

import org.daemoxcp.mail.util.Shell;

import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * acme.sh with its own user (AcmeUser): the pieces of the migration from /root/.acme.sh, the
 * migration in temporary folders with fake pkg, cron and acme.sh and a fault planted for every
 * step, the HTTP challenge's port 80, and running as acme.
 *
 * <p>Running as acme is real: a fake script, run by {@link AcmeUser#run} with a Layout that names
 * it, says which user it runs as, which HOME it sees and which variables it gets; then real acme.sh
 * (--version). The acme user is needed, that is the security/acme.sh package: without it, that part
 * is skipped saying so. It must be run as root on the FreeBSD VM.
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.security.AcmeUserTest
 */
public class AcmeUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** account.conf as the installation with curl writes it, plus what dns_cf and --set-default-ca add. */
    static final String OLD_ACCOUNT = """
            #LOG_FILE="/root/.acme.sh/acme.sh.log"
            #LOG_LEVEL=1
            ACCOUNT_EMAIL='postmaster@test.local'
            AUTO_UPGRADE='1'
            UPGRADE_HASH='0123abcd'
            USER_PATH='/sbin:/bin:/usr/sbin:/usr/bin:/root/bin'
            SAVED_CF_Token='planted-token'
            SAVED_CF_Account_ID='abc'
            DEFAULT_ACME_SERVER='https://acme-v02.api.letsencrypt.org/directory'
            LOG_FILE='/root/.acme.sh/acme.sh.log'
            """;
    static final String PKG_ACCOUNT = """
            NSUPDATE_SERVER="mydns.example.org"
            DEFAULT_DNS_SLEEP="10"
            CERT_HOME="/var/db/acme/certs"
            LOG_FILE='/var/log/acme.sh.log'
            """;
    /** Root's cron with the line acme.sh installed in {@code home} used to write. */
    static String crontab(String home) {
        return "SHELL=/bin/sh\n# root's cron\n15 3 * * * /usr/local/sbin/backup.sh\n"
            + "25 0 * * * \"" + home + "\"/acme.sh --cron --home \"" + home + "\" > /dev/null\n";
    }
    static final String CRONTAB = crontab("/root/.acme.sh");

    /** A /root/.acme.sh as the old installation leaves it, with two certificates. */
    static final class Bench {
        final Path root, oldHome, moved, home, certHome, backup;
        final AcmeUser.Places at;
        Bench() throws Exception {
            root = Files.createTempDirectory(Path.of("/var/tmp"), "acmeuser-");
            oldHome = root.resolve("root/.acme.sh");
            moved = root.resolve("root/.acme.sh.moved-to-var-db-acme");
            home = root.resolve("var/db/acme/.acme.sh");
            certHome = root.resolve("var/db/acme/certs");
            backup = root.resolve("backup");
            at = new AcmeUser.Places(oldHome, moved, home, certHome, backup);
            Files.createDirectories(oldHome.resolve("dnsapi"));
            Files.writeString(oldHome.resolve("acme.sh"), "#!/bin/sh\necho old\n");
            Files.writeString(oldHome.resolve("dnsapi/dns_cf.sh"), "# dns_cf\n");
            Files.writeString(oldHome.resolve("account.conf"), OLD_ACCOUNT);
            Files.createDirectories(oldHome.resolve("ca/acme-v02.api.letsencrypt.org/directory"));
            Path key = oldHome.resolve("ca/acme-v02.api.letsencrypt.org/directory/account.key");
            Files.writeString(key, "-----BEGIN EC PRIVATE KEY-----\nplanted\n");
            Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-------"));
            cert("mail.test.local_ecc", "mail.test.local", "no");
            cert("webmail.test.local", "webmail.test.local", "dns_cf");
            Files.createDirectories(home);
            Files.writeString(home.resolve("account.conf"), PKG_ACCOUNT);
            Files.createDirectories(certHome);
        }
        void cert(String dir, String name, String webroot) throws Exception {
            Path d = Files.createDirectories(oldHome.resolve(dir));
            Files.writeString(d.resolve(name + ".conf"), "Le_Domain='" + name + "'\nLe_Alt='no'\nLe_Webroot='" + webroot
                    + "'\nLe_API='https://acme-v02.api.letsencrypt.org/directory'\nLe_NextRenewTime='1800000000'\n");
            Files.writeString(d.resolve(name + ".cer"), "-----BEGIN CERTIFICATE-----\n" + name + "\n");
            Files.writeString(d.resolve(name + ".key"), "-----BEGIN EC PRIVATE KEY-----\n" + name + "\n");
            Files.setPosixFilePermissions(d.resolve(name + ".key"), PosixFilePermissions.fromString("rw-------"));
        }
        void clean() throws Exception {
            try (Stream<Path> s = Files.walk(root)) {
                for (Path p : s.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            }
        }
    }

    static Map<String, String> photo(Path root) throws Exception {
        Map<String, String> m = new TreeMap<>();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : s.toList()) {
                if (p.startsWith(root.resolve("backup"))) continue;
                m.put(root.relativize(p).toString(), Files.isDirectory(p) ? "dir" : HexFormat.of().formatHex(sha.digest(Files.readAllBytes(p)))
                        + " " + PosixFilePermissions.toString(Files.getPosixFilePermissions(p)));
            }
        }
        return m;
    }

    /** Fake pkg, cron and acme.sh: --list says the certificates it finds in the new folder, like the real one. */
    static final class Fake implements AcmeUser.Services {
        final Bench b;
        boolean installed = true, installWorks = true, crontabUnreadable, crontabWriteFails, listForgets;
        String crontab;
        int installs, crontabWrites;
        final List<Path> given = new ArrayList<>();
        Fake(Bench b) { this.b = b; crontab = crontab(b.oldHome.toString()); }
        @Override public boolean packageInstalled() { return installed; }
        @Override public Shell.Result installPackage() {
            installs++;
            if (installWorks) installed = true;
            return new Shell.Result(installWorks ? 0 : 1, installWorks ? "" : "pkg: No packages available to install matching 'security/acme.sh'", false, List.of());
        }
        @Override public String rootCrontab() { return crontabUnreadable ? null : crontab; }
        @Override public boolean writeRootCrontab(String c) {
            crontabWrites++;
            if (crontabWriteFails && crontabWrites == 1) return false;
            crontab = c;
            return true;
        }
        @Override public void giveToAcme(Path p) { given.add(p); }
        @Override public String list() {
            StringBuilder s = new StringBuilder("Main_Domain KeyLength SAN_Domains Profile CA Created Renew\n");
            try (Stream<Path> st = Files.list(b.certHome)) {
                for (Path d : st.sorted().toList()) {
                    String n = d.getFileName().toString().replaceFirst("_ecc$", "");
                    if (listForgets && n.startsWith("webmail")) continue;
                    if (Files.exists(d.resolve(n + ".conf"))) s.append(n).append(" \"ec-256\" no LetsEncrypt.org\n");
                }
            } catch (Exception e) { return null; }
            return s.toString();
        }
    }

    static void plantedFault(String what, java.util.function.Consumer<Fake> plant, AcmeUser.Outcome expected) throws Exception {
        OUT.println("\n-- planted fault: " + what);
        Bench b = new Bench();
        try {
            Map<String, String> before = photo(b.root);
            Fake f = new Fake(b);
            plant.accept(f);
            AcmeUser.Report r = AcmeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("outcome " + expected, r.outcome() == expected);
            check("it does not say EXCEPT", !r.detail().contains("EXCEPT"));
            check("every file as it was, /root/.acme.sh included", before.equals(photo(b.root)));
            check("root's cron as it was", crontab(b.oldHome.toString()).equals(f.crontab));
        } finally { b.clean(); }
    }

    static String get(int port, String path, String method) throws Exception {
        HttpURLConnection c = (HttpURLConnection) URI.create("http://127.0.0.1:" + port + path).toURL().openConnection();
        c.setRequestMethod(method);
        int code = c.getResponseCode();
        String body = code == 200 && !"HEAD".equals(method) ? new String(c.getInputStream().readAllBytes(), StandardCharsets.UTF_8) : "";
        return code + " " + body;
    }

    public static void main(String[] args) throws Exception {
        if (!"root".equals(System.getProperty("user.name")) || !System.getProperty("os.name").contains("FreeBSD")) {
            OUT.println("This test runs programs as acme: it must be run as root on the FreeBSD VM.");
            System.exit(2);
        }

        OUT.println("== The pieces");
        String merged = AcmeUser.mergedAccount(PKG_ACCOUNT, OLD_ACCOUNT, "/root/.acme.sh");
        check("account.conf: the package's CERT_HOME and LOG_FILE", merged.contains("CERT_HOME=\"/var/db/acme/certs\"")
                && merged.contains("LOG_FILE='/var/log/acme.sh.log'") && !merged.contains("/root/.acme.sh/acme.sh.log'"));
        check("account.conf: the old email, token and CA", merged.contains("ACCOUNT_EMAIL='postmaster@test.local'")
                && merged.contains("SAVED_CF_Token='planted-token'") && merged.contains("DEFAULT_ACME_SERVER="));
        check("account.conf: no root USER_PATH, no self-update", !merged.contains("USER_PATH") && !merged.contains("AUTO_UPGRADE"));
        check("Le_Webroot='no' (standalone) becomes the challenge folder",
                AcmeUser.withoutStandalone("Le_Domain='a'\nLe_Webroot='no'\n").contains("Le_Webroot='" + AcmeUser.WEBROOT + "'"));
        check("dns_cf stays dns_cf", AcmeUser.withoutStandalone("Le_Webroot='dns_cf'\n").equals("Le_Webroot='dns_cf'\n"));
        String cron = AcmeUser.withoutAcmeCron(CRONTAB, "/root/.acme.sh");
        check("the cron without the acme.sh line, the rest untouched", !cron.contains("acme.sh") && cron.contains("backup.sh") && cron.endsWith("\n")
                && cron.startsWith("SHELL=/bin/sh\n# root's cron\n"));
        check("a cron with only the acme.sh line stays empty", AcmeUser.withoutAcmeCron(
                "25 0 * * * \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" > /dev/null\n", "/root/.acme.sh").isEmpty());
        check("a comment quoting acme.sh stays", AcmeUser.withoutAcmeCron("# /root/.acme.sh --cron\n", "/root/.acme.sh").equals("# /root/.acme.sh --cron\n"));
        check("a cron without acme.sh does not change", AcmeUser.withoutAcmeCron("1 1 * * * x\n", "/root/.acme.sh").equals("1 1 * * * x\n"));

        OUT.println("\n== The migration that succeeds");
        Bench b = new Bench();
        try {
            Fake f = new Fake(b);
            f.installed = false;
            AcmeUser.Report r = AcmeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("DONE", r.outcome() == AcmeUser.Outcome.DONE);
            check("the package installed once", f.installs == 1);
            check("the two certificates in the new folder", Files.exists(b.certHome.resolve("mail.test.local_ecc/mail.test.local.key"))
                    && Files.exists(b.certHome.resolve("webmail.test.local/webmail.test.local.cer")));
            check("the keys stay 600", PosixFilePermissions.toString(Files.getPosixFilePermissions(
                    b.certHome.resolve("mail.test.local_ecc/mail.test.local.key"))).equals("rw-------"));
            check("the account (ca/) in the new home", Files.exists(b.home.resolve("ca/acme-v02.api.letsencrypt.org/directory/account.key")));
            check("the certificate requested with --standalone now uses the challenge folder",
                    Files.readString(b.certHome.resolve("mail.test.local_ecc/mail.test.local.conf")).contains("Le_Webroot='" + AcmeUser.WEBROOT + "'"));
            check("the one through Cloudflare stays dns_cf", Files.readString(b.certHome.resolve("webmail.test.local/webmail.test.local.conf")).contains("Le_Webroot='dns_cf'"));
            check("account.conf merged", Files.readString(b.home.resolve("account.conf")).contains("SAVED_CF_Token='planted-token'")
                    && Files.readString(b.home.resolve("account.conf")).contains("CERT_HOME=\"/var/db/acme/certs\""));
            check("the program and dnsapi are not copied (the package provides them)", !Files.exists(b.home.resolve("acme.sh")) && !Files.exists(b.home.resolve("dnsapi")));
            check("everything copied is given to acme", f.given.contains(b.home.resolve("ca")) && f.given.contains(b.home.resolve("account.conf"))
                    && f.given.contains(b.certHome.resolve("mail.test.local_ecc")));
            check("root's cron no longer runs acme.sh, the rest is there", !f.crontab.contains("acme.sh") && f.crontab.contains("backup.sh"));
            check("/root/.acme.sh changed name, with everything inside", !Files.exists(b.oldHome) && Files.exists(b.moved.resolve("account.conf")));
            check("the copy of the old cron in the backup folder", Files.exists(b.backup));
            r = AcmeUser.migrate(b.at, f);
            check("the second time: NOTHING (" + r.outcome() + ")", r.outcome() == AcmeUser.Outcome.NOTHING);
        } finally { b.clean(); }

        OUT.println("\n== The planted faults: every failed step puts everything back, and acme.sh stays as root");
        plantedFault("the package does not install", f -> { f.installed = false; f.installWorks = false; }, AcmeUser.Outcome.NOT_YET);
        plantedFault("acme.sh, as acme, does not see one of the certificates", f -> f.listForgets = true, AcmeUser.Outcome.ROLLED_BACK);
        plantedFault("root's cron cannot be read", f -> f.crontabUnreadable = true, AcmeUser.Outcome.ROLLED_BACK);
        plantedFault("root's cron cannot be rewritten", f -> f.crontabWriteFails = true, AcmeUser.Outcome.ROLLED_BACK);

        OUT.println("\n-- planted fault: /root/.acme.sh does not move (chflags schg), with the cron already rewritten");
        Bench m = new Bench();
        try {
            Map<String, String> before = photo(m.root);
            check("chflags schg planted", Shell.run("chflags", "schg", m.oldHome.toString()).success());
            Fake f = new Fake(m);
            AcmeUser.Report r = AcmeUser.migrate(m.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            Shell.run("chflags", "noschg", m.oldHome.toString());
            check("ROLLED_BACK, without EXCEPT", r.outcome() == AcmeUser.Outcome.ROLLED_BACK && !r.detail().contains("EXCEPT"));
            check("root's cron put back as it was (rewritten twice)", crontab(m.oldHome.toString()).equals(f.crontab) && f.crontabWrites == 2);
            check("every file as it was", before.equals(photo(m.root)));
        } finally { Shell.run("chflags", "-R", "noschg", m.root.toString()); m.clean(); }

        OUT.println("\n-- refusal: a certificate is already in the new folder");
        Bench c = new Bench();
        try {
            Files.createDirectories(c.certHome.resolve("webmail.test.local"));
            Map<String, String> before = photo(c.root);
            Fake f = new Fake(c);
            AcmeUser.Report r = AcmeUser.migrate(c.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("BOTH_PLACES, nothing changed", r.outcome() == AcmeUser.Outcome.BOTH_PLACES && before.equals(photo(c.root))
                    && crontab(c.oldHome.toString()).equals(f.crontab));
        } finally { c.clean(); }

        OUT.println("\n== The HTTP challenge's port");
        Path dir = Files.createTempDirectory(Path.of("/var/tmp"), "acme-challenge-");
        Path secret = Files.writeString(dir.resolveSibling(dir.getFileName() + "-secret"), "secret\n");
        try {
            Files.writeString(dir.resolve("tok3n_-A"), "tok3n_-A.thumbprint");
            Files.createSymbolicLink(dir.resolve("linked"), secret);
            int port = 18000 + (int) (ProcessHandle.current().pid() % 1000);
            try (AcmeUser.Challenge ch = AcmeUser.Challenge.open(port, dir)) {
                check("the token can be read", get(port, "/.well-known/acme-challenge/tok3n_-A", "GET").equals("200 tok3n_-A.thumbprint"));
                check("HEAD risponde 200", get(port, "/.well-known/acme-challenge/tok3n_-A", "HEAD").startsWith("200"));
                check("a token that is not there: 404", get(port, "/.well-known/acme-challenge/nope", "GET").startsWith("404"));
                check("leaving the folder: 404", get(port, "/.well-known/acme-challenge/..%2F" + secret.getFileName(), "GET").startsWith("404")
                        && get(port, "/.well-known/acme-challenge/../" + secret.getFileName(), "GET").startsWith("404"));
                check("a link in the folder is not followed: 404", get(port, "/.well-known/acme-challenge/linked", "GET").startsWith("404"));
                check("another path: 404", get(port, "/index.html", "GET").startsWith("404"));
                check("POST: 404", get(port, "/.well-known/acme-challenge/tok3n_-A", "POST").startsWith("404"));
            }
            boolean closed;
            try { get(port, "/.well-known/acme-challenge/tok3n_-A", "GET"); closed = false; } catch (java.io.IOException e) { closed = true; }
            check("at the end of the try the port is closed", closed);
            try (AcmeUser.Challenge one = AcmeUser.Challenge.open(port, dir)) {
                boolean busy;
                try (AcmeUser.Challenge two = AcmeUser.Challenge.open(port, dir)) { busy = false; } catch (java.net.BindException e) { busy = true; }
                check("port busy: BindException, which AcmeManager puts into words", busy);
            }
        } finally {
            Files.deleteIfExists(dir.resolve("linked"));
            Files.deleteIfExists(dir.resolve("tok3n_-A"));
            Files.deleteIfExists(dir);
            Files.deleteIfExists(secret);
        }

        OUT.println("\n== As acme, for real");
        if (!AcmeUser.userExists() || !Files.isRegularFile(Path.of(AcmeUser.SCRIPT))) {
            OUT.println("  SKIPPED: the acme user or " + AcmeUser.SCRIPT + " is missing (pkg install " + AcmeUser.PACKAGE + ")");
        } else {
            Path probe = Files.createTempDirectory(Path.of("/var/tmp"), "acme-run-");
            Path script = probe.resolve("fake-acme.sh");
            Files.writeString(script, "#!/bin/sh\necho \"user=$(id -un) home=$HOME pwd=$(pwd)\"\necho \"token=$CF_Token\"\n"
                    + "echo \"ssh=${SSH_CONNECTION:-none}\"\necho \"args=$*\"\n");
            Files.setPosixFilePermissions(probe, PosixFilePermissions.fromString("rwxr-xr-x"));
            Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwxr-xr-x"));
            try {
                String out = AcmeUser.run(new AcmeUser.Layout(script.toString(), AcmeUser.HOME, AcmeUser.CERT_HOME, true),
                        "--list", Map.of("CF_Token", "planted-cf"));
                OUT.println("     " + out.trim().replace("\n", " | "));
                check("it runs as acme, with acme's home", out.contains("user=acme home=/var/db/acme pwd=/var/db/acme"));
                check("it gets the Cloudflare token", out.contains("token=planted-cf"));
                // Started via ssh, the JVM has SSH_CONNECTION: if it reached acme.sh, the environment would not be empty.
                if (System.getenv("SSH_CONNECTION") == null) OUT.println("  SKIPPED: without SSH_CONNECTION it cannot be seen whether the environment passes");
                else check("and not the environment of whoever starts it (SSH_CONNECTION)", out.contains("ssh=none"));
                check("with --home and --cert-home in front", out.contains("args=--home " + AcmeUser.HOME + " --cert-home " + AcmeUser.CERT_HOME + " --list"));
                String legacy = AcmeUser.run(new AcmeUser.Layout(script.toString(), "/root/.acme.sh", "/root/.acme.sh", false), "--list", null);
                check("before the migration: as root, as before", legacy.contains("user=root home=/root"));
                String v = AcmeUser.run(new AcmeUser.Layout(AcmeUser.SCRIPT, AcmeUser.HOME, AcmeUser.CERT_HOME, true), "--version", null);
                OUT.println("     " + v.trim().replace("\n", " | "));
                check("real acme.sh, as acme: it answers with its version", v.contains("v3."));
            } finally {
                Files.deleteIfExists(script);
                Files.deleteIfExists(probe);
            }
        }

        OUT.println();
        OUT.println(failed == 0 ? "ALL OK" : "FAILED: " + failed);
        if (failed > 0) System.exit(1);
    }
}
