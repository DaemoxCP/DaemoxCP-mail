package org.mail_panel.security;

import org.mail_panel.util.Shell;

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
 * acme.sh col suo utente (AcmeUser): i pezzi della migrazione da /root/.acme.sh, la migrazione in
 * cartelle temporanee con pkg, cron e acme.sh finti e un guasto piantato per ogni passo, la porta
 * 80 della sfida HTTP, e l'esecuzione come acme.
 *
 * <p>L'esecuzione come acme e' vera: uno script finto, eseguito da {@link AcmeUser#run} con un
 * Layout che lo nomina, dice con quale utente gira, che HOME vede e quali variabili riceve; poi
 * acme.sh vero (--version). Serve l'utente acme, cioe' il pacchetto security/acme.sh: senza, la
 * parte si salta dicendolo. Va lanciata da root sulla VM FreeBSD.
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.security.AcmeUserTest
 */
public class AcmeUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** account.conf come lo scrive l'installazione con curl, piu' quello che aggiungono dns_cf e --set-default-ca. */
    static final String OLD_ACCOUNT = """
            #LOG_FILE="/root/.acme.sh/acme.sh.log"
            #LOG_LEVEL=1
            ACCOUNT_EMAIL='postmaster@prova.local'
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
    /** Il cron di root con la riga che si scriveva acme.sh installato in {@code home}. */
    static String crontab(String home) {
        return "SHELL=/bin/sh\n# il cron di root\n15 3 * * * /usr/local/sbin/backup.sh\n"
            + "25 0 * * * \"" + home + "\"/acme.sh --cron --home \"" + home + "\" > /dev/null\n";
    }
    static final String CRONTAB = crontab("/root/.acme.sh");

    /** Un /root/.acme.sh come lo lascia l'installazione di prima, con due certificati. */
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
            Files.writeString(oldHome.resolve("acme.sh"), "#!/bin/sh\necho vecchio\n");
            Files.writeString(oldHome.resolve("dnsapi/dns_cf.sh"), "# dns_cf\n");
            Files.writeString(oldHome.resolve("account.conf"), OLD_ACCOUNT);
            Files.createDirectories(oldHome.resolve("ca/acme-v02.api.letsencrypt.org/directory"));
            Path key = oldHome.resolve("ca/acme-v02.api.letsencrypt.org/directory/account.key");
            Files.writeString(key, "-----BEGIN EC PRIVATE KEY-----\nplanted\n");
            Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-------"));
            cert("mail.prova.local_ecc", "mail.prova.local", "no");
            cert("webmail.prova.local", "webmail.prova.local", "dns_cf");
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

    /** pkg, cron e acme.sh finti: --list dice i certificati che trova nella cartella nuova, come quello vero. */
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
        OUT.println("\n-- guasto piantato: " + what);
        Bench b = new Bench();
        try {
            Map<String, String> before = photo(b.root);
            Fake f = new Fake(b);
            plant.accept(f);
            AcmeUser.Report r = AcmeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("esito " + expected, r.outcome() == expected);
            check("non dice EXCEPT", !r.detail().contains("EXCEPT"));
            check("ogni file com'era, /root/.acme.sh compreso", before.equals(photo(b.root)));
            check("il cron di root com'era", crontab(b.oldHome.toString()).equals(f.crontab));
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
            OUT.println("Questa prova esegue programmi come acme: va lanciata da root sulla VM FreeBSD.");
            System.exit(2);
        }

        OUT.println("== I pezzi");
        String merged = AcmeUser.mergedAccount(PKG_ACCOUNT, OLD_ACCOUNT, "/root/.acme.sh");
        check("account.conf: CERT_HOME e LOG_FILE del pacchetto", merged.contains("CERT_HOME=\"/var/db/acme/certs\"")
                && merged.contains("LOG_FILE='/var/log/acme.sh.log'") && !merged.contains("/root/.acme.sh/acme.sh.log'"));
        check("account.conf: email, token e CA di prima", merged.contains("ACCOUNT_EMAIL='postmaster@prova.local'")
                && merged.contains("SAVED_CF_Token='planted-token'") && merged.contains("DEFAULT_ACME_SERVER="));
        check("account.conf: niente USER_PATH di root, niente aggiornamento da se'", !merged.contains("USER_PATH") && !merged.contains("AUTO_UPGRADE"));
        check("Le_Webroot='no' (standalone) diventa la cartella delle sfide",
                AcmeUser.withoutStandalone("Le_Domain='a'\nLe_Webroot='no'\n").contains("Le_Webroot='" + AcmeUser.WEBROOT + "'"));
        check("dns_cf resta dns_cf", AcmeUser.withoutStandalone("Le_Webroot='dns_cf'\n").equals("Le_Webroot='dns_cf'\n"));
        String cron = AcmeUser.withoutAcmeCron(CRONTAB, "/root/.acme.sh");
        check("il cron senza la riga di acme.sh, col resto intatto", !cron.contains("acme.sh") && cron.contains("backup.sh") && cron.endsWith("\n")
                && cron.startsWith("SHELL=/bin/sh\n# il cron di root\n"));
        check("un cron con la sola riga di acme.sh resta vuoto", AcmeUser.withoutAcmeCron(
                "25 0 * * * \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" > /dev/null\n", "/root/.acme.sh").isEmpty());
        check("un commento che cita acme.sh resta", AcmeUser.withoutAcmeCron("# /root/.acme.sh --cron\n", "/root/.acme.sh").equals("# /root/.acme.sh --cron\n"));
        check("un cron senza acme.sh non cambia", AcmeUser.withoutAcmeCron("1 1 * * * x\n", "/root/.acme.sh").equals("1 1 * * * x\n"));

        OUT.println("\n== La migrazione che riesce");
        Bench b = new Bench();
        try {
            Fake f = new Fake(b);
            f.installed = false;
            AcmeUser.Report r = AcmeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("DONE", r.outcome() == AcmeUser.Outcome.DONE);
            check("il pacchetto installato una volta", f.installs == 1);
            check("i due certificati nella cartella nuova", Files.exists(b.certHome.resolve("mail.prova.local_ecc/mail.prova.local.key"))
                    && Files.exists(b.certHome.resolve("webmail.prova.local/webmail.prova.local.cer")));
            check("le chiavi restano 600", PosixFilePermissions.toString(Files.getPosixFilePermissions(
                    b.certHome.resolve("mail.prova.local_ecc/mail.prova.local.key"))).equals("rw-------"));
            check("l'account (ca/) nella casa nuova", Files.exists(b.home.resolve("ca/acme-v02.api.letsencrypt.org/directory/account.key")));
            check("il certificato chiesto con --standalone ora usa la cartella delle sfide",
                    Files.readString(b.certHome.resolve("mail.prova.local_ecc/mail.prova.local.conf")).contains("Le_Webroot='" + AcmeUser.WEBROOT + "'"));
            check("quello via Cloudflare resta dns_cf", Files.readString(b.certHome.resolve("webmail.prova.local/webmail.prova.local.conf")).contains("Le_Webroot='dns_cf'"));
            check("account.conf unito", Files.readString(b.home.resolve("account.conf")).contains("SAVED_CF_Token='planted-token'")
                    && Files.readString(b.home.resolve("account.conf")).contains("CERT_HOME=\"/var/db/acme/certs\""));
            check("il programma e dnsapi non si copiano (li da' il pacchetto)", !Files.exists(b.home.resolve("acme.sh")) && !Files.exists(b.home.resolve("dnsapi")));
            check("tutto quello che si e' copiato e' dato ad acme", f.given.contains(b.home.resolve("ca")) && f.given.contains(b.home.resolve("account.conf"))
                    && f.given.contains(b.certHome.resolve("mail.prova.local_ecc")));
            check("il cron di root non esegue piu' acme.sh, il resto c'e'", !f.crontab.contains("acme.sh") && f.crontab.contains("backup.sh"));
            check("/root/.acme.sh ha cambiato nome, con dentro tutto", !Files.exists(b.oldHome) && Files.exists(b.moved.resolve("account.conf")));
            check("la copia del cron di prima nella cartella di backup", Files.exists(b.backup));
            r = AcmeUser.migrate(b.at, f);
            check("la seconda volta: NOTHING (" + r.outcome() + ")", r.outcome() == AcmeUser.Outcome.NOTHING);
        } finally { b.clean(); }

        OUT.println("\n== I guasti piantati: ogni passo fallito rimette tutto, e acme.sh resta da root");
        plantedFault("il pacchetto non si installa", f -> { f.installed = false; f.installWorks = false; }, AcmeUser.Outcome.NOT_YET);
        plantedFault("acme.sh, come acme, non vede uno dei certificati", f -> f.listForgets = true, AcmeUser.Outcome.ROLLED_BACK);
        plantedFault("il cron di root non si legge", f -> f.crontabUnreadable = true, AcmeUser.Outcome.ROLLED_BACK);
        plantedFault("il cron di root non si riscrive", f -> f.crontabWriteFails = true, AcmeUser.Outcome.ROLLED_BACK);

        OUT.println("\n-- guasto piantato: /root/.acme.sh non si sposta (chflags schg), col cron gia' riscritto");
        Bench m = new Bench();
        try {
            Map<String, String> before = photo(m.root);
            check("chflags schg piantato", Shell.run("chflags", "schg", m.oldHome.toString()).success());
            Fake f = new Fake(m);
            AcmeUser.Report r = AcmeUser.migrate(m.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            Shell.run("chflags", "noschg", m.oldHome.toString());
            check("ROLLED_BACK, senza EXCEPT", r.outcome() == AcmeUser.Outcome.ROLLED_BACK && !r.detail().contains("EXCEPT"));
            check("il cron di root rimesso com'era (riscritto due volte)", crontab(m.oldHome.toString()).equals(f.crontab) && f.crontabWrites == 2);
            check("ogni file com'era", before.equals(photo(m.root)));
        } finally { Shell.run("chflags", "-R", "noschg", m.root.toString()); m.clean(); }

        OUT.println("\n-- rifiuto: un certificato c'e' gia' nella cartella nuova");
        Bench c = new Bench();
        try {
            Files.createDirectories(c.certHome.resolve("webmail.prova.local"));
            Map<String, String> before = photo(c.root);
            Fake f = new Fake(c);
            AcmeUser.Report r = AcmeUser.migrate(c.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("BOTH_PLACES, niente cambiato", r.outcome() == AcmeUser.Outcome.BOTH_PLACES && before.equals(photo(c.root))
                    && crontab(c.oldHome.toString()).equals(f.crontab));
        } finally { c.clean(); }

        OUT.println("\n== La porta della sfida HTTP");
        Path dir = Files.createTempDirectory(Path.of("/var/tmp"), "acme-challenge-");
        Path secret = Files.writeString(dir.resolveSibling(dir.getFileName() + "-secret"), "segreto\n");
        try {
            Files.writeString(dir.resolve("tok3n_-A"), "tok3n_-A.thumbprint");
            Files.createSymbolicLink(dir.resolve("linked"), secret);
            int port = 18000 + (int) (ProcessHandle.current().pid() % 1000);
            try (AcmeUser.Challenge ch = AcmeUser.Challenge.open(port, dir)) {
                check("il gettone si legge", get(port, "/.well-known/acme-challenge/tok3n_-A", "GET").equals("200 tok3n_-A.thumbprint"));
                check("HEAD risponde 200", get(port, "/.well-known/acme-challenge/tok3n_-A", "HEAD").startsWith("200"));
                check("un gettone che non c'e': 404", get(port, "/.well-known/acme-challenge/nope", "GET").startsWith("404"));
                check("uscire dalla cartella: 404", get(port, "/.well-known/acme-challenge/..%2F" + secret.getFileName(), "GET").startsWith("404")
                        && get(port, "/.well-known/acme-challenge/../" + secret.getFileName(), "GET").startsWith("404"));
                check("un link nella cartella non si segue: 404", get(port, "/.well-known/acme-challenge/linked", "GET").startsWith("404"));
                check("un altro percorso: 404", get(port, "/index.html", "GET").startsWith("404"));
                check("POST: 404", get(port, "/.well-known/acme-challenge/tok3n_-A", "POST").startsWith("404"));
            }
            boolean closed;
            try { get(port, "/.well-known/acme-challenge/tok3n_-A", "GET"); closed = false; } catch (java.io.IOException e) { closed = true; }
            check("alla fine del try la porta e' chiusa", closed);
            try (AcmeUser.Challenge one = AcmeUser.Challenge.open(port, dir)) {
                boolean busy;
                try (AcmeUser.Challenge two = AcmeUser.Challenge.open(port, dir)) { busy = false; } catch (java.net.BindException e) { busy = true; }
                check("porta occupata: BindException, che AcmeManager dice a parole", busy);
            }
        } finally {
            Files.deleteIfExists(dir.resolve("linked"));
            Files.deleteIfExists(dir.resolve("tok3n_-A"));
            Files.deleteIfExists(dir);
            Files.deleteIfExists(secret);
        }

        OUT.println("\n== Come acme, davvero");
        if (!AcmeUser.userExists() || !Files.isRegularFile(Path.of(AcmeUser.SCRIPT))) {
            OUT.println("  SALTATA: manca l'utente acme o " + AcmeUser.SCRIPT + " (pkg install " + AcmeUser.PACKAGE + ")");
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
                check("gira come acme, con la casa di acme", out.contains("user=acme home=/var/db/acme pwd=/var/db/acme"));
                check("riceve il token di Cloudflare", out.contains("token=planted-cf"));
                // Lanciata via ssh, la JVM ha SSH_CONNECTION: se arrivasse ad acme.sh, l'ambiente non sarebbe vuoto.
                if (System.getenv("SSH_CONNECTION") == null) OUT.println("  SALTATA: senza SSH_CONNECTION non si vede se l'ambiente passa");
                else check("e non l'ambiente di chi lo lancia (SSH_CONNECTION)", out.contains("ssh=none"));
                check("con --home e --cert-home davanti", out.contains("args=--home " + AcmeUser.HOME + " --cert-home " + AcmeUser.CERT_HOME + " --list"));
                String legacy = AcmeUser.run(new AcmeUser.Layout(script.toString(), "/root/.acme.sh", "/root/.acme.sh", false), "--list", null);
                check("prima della migrazione: da root, come prima", legacy.contains("user=root home=/root"));
                String v = AcmeUser.run(new AcmeUser.Layout(AcmeUser.SCRIPT, AcmeUser.HOME, AcmeUser.CERT_HOME, true), "--version", null);
                OUT.println("     " + v.trim().replace("\n", " | "));
                check("acme.sh vero, come acme: risponde con la sua versione", v.contains("v3."));
            } finally {
                Files.deleteIfExists(script);
                Files.deleteIfExists(probe);
            }
        }

        OUT.println();
        OUT.println(failed == 0 ? "TUTTO OK" : "FALLITE: " + failed);
        if (failed > 0) System.exit(1);
    }
}
