package org.mail_panel.scripts;

import java.io.File;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Postfix come MTA locale: la posta che nasce sulla macchina (cron, periodic, mail(1), il mail()
 * di PHP) deve passare da Postfix e restare su questa macchina, non uscire da dma.
 *
 * Il difetto, misurato sulla VM FreeBSD 15.1 il 23/10/2026: nessuno dei tre script che
 * installano Postfix scriveva /usr/local/etc/mail/mailer.conf, quindi mailwrapper(8) usava
 * quello del sistema base e passava tutto a dma. E correggere SOLO mailer.conf non bastava:
 * con myorigin = $mydomain "root" diventava root@<nome del server>, che non e' locale, e Postfix
 * lo rimbalzava a se stesso. Vedi LocalMtaScript e il commento accanto a myorigin in
 * FullMailServerScript.
 *
 * Quello che si prova qui:
 *  - che tutti e tre gli script contengano il pezzo, e DOPO l'installazione del pacchetto: prima
 *    il file di Postfix da copiare non c'e' e il pezzo, giustamente, non fa niente;
 *  - che il loro main.cf, letto da postconf e non guardato come testo, dia myorigin = localhost e
 *    un mydestination che non contiene il nome del server;
 *  - il pezzo eseguito davvero, in una cartella finta al posto di /usr/local/etc/mail,
 *    /etc/periodic.conf, /var/spool/dma e del newaliases di Postfix: senza Postfix non scrive
 *    niente, con Postfix scrive e costruisce il database degli alias, ripetuto non tocca
 *    mailer.conf, un mailer.conf diverso lo mette da parte, la coda di dma la dice.
 *
 * Si lancia sulla VM, dove postconf e sysrc ci sono:
 *   javac -cp &lt;dir&gt;/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/scripts/LocalMtaTest.java
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.scripts.LocalMtaTest
 */
public class LocalMtaTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        for (String command : List.of("postconf", "sysrc")) {
            if (!onPath(command)) {
                check(command + " c'e' (questa prova va lanciata sulla VM, non sul Mac)", false);
                OUT.println("\n" + failed + " CONTROLLI FALLITI");
                System.exit(1);
            }
        }
        Path home = Files.createTempDirectory("local-mta");

        Map<String, String> scripts = Map.of(
                "FullMailServerScript", new FullMailServerScript().getScriptContent(),
                "PostfixScript", new PostfixScript().getScriptContent(),
                "FullMailStackScript", new FullMailStackScript().getScriptContent());
        for (String name : List.of("FullMailServerScript", "PostfixScript", "FullMailStackScript")) {
            String script = scripts.get(name);
            OUT.println("\n== " + name + " ==");
            int pkg = script.indexOf("pkg install -y postfix-mysql");
            int activation = script.indexOf(LocalMtaScript.SHELL);
            check("contiene il pezzo LocalMtaScript, intero", activation >= 0);
            check("e lo esegue dopo pkg install -y postfix-mysql", pkg >= 0 && activation > pkg);

            Path dir = home.resolve(name);
            Files.createDirectories(dir);
            Run written = writeMainCf(script, dir);
            check("il blocco di main.cf si estrae e si scrive (" + written.out.trim() + ")",
                    written.code == 0 && Files.isRegularFile(dir.resolve("main.cf")));
            String myorigin = postconf(dir, "myorigin");
            String mydestination = postconf(dir, "mydestination");
            String localTransport = postconf(dir, "local_transport");
            OUT.println("  myorigin = " + myorigin + " | mydestination = " + mydestination
                    + " | local_transport = " + localTransport);
            check("myorigin = localhost: root e postmaster restano su questa macchina",
                    "localhost".equals(myorigin));
            check("mydestination e' localhost, non il nome del server (che da Internet "
                    + "renderebbe raggiungibili gli account di sistema)", "localhost".equals(mydestination));
            check("la consegna locale non e' spenta (con local_transport = error: la posta di "
                    + "sistema rimbalzerebbe)", !localTransport.startsWith("error"));
            String restrictions = postconf(dir, "smtpd_recipient_restrictions");
            if (!restrictions.isEmpty())
                check("con le restrizioni scritte, root@localhost resta fuori da Internet "
                        + "(reject_non_fqdn_recipient)", restrictions.contains("reject_non_fqdn_recipient"));
        }
        check("l'installazione completa verifica anche mailer.conf alla fine",
                scripts.get("FullMailServerScript").contains("sendmail(8) does NOT hand over to Postfix"));

        OUT.println("\n== Il pezzo eseguito in una cartella finta ==");
        Path fake = home.resolve("system");
        Path mailDir = fake.resolve("usr-local-etc-mail");
        Path mailerConf = mailDir.resolve("mailer.conf");
        Path shared = fake.resolve("share/mailer.conf.postfix");
        Path sendmail = fake.resolve("sbin/sendmail");
        Path periodic = fake.resolve("periodic.conf");
        Path dmaSpool = fake.resolve("spool-dma");
        // Il newaliases finto conta le chiamate: quello vero scriverebbe /etc/aliases.db.
        Path newaliases = fake.resolve("bin/newaliases");
        Path newaliasesCalls = fake.resolve("newaliases-calls");
        Files.createDirectories(dmaSpool);
        Files.createDirectories(shared.getParent());
        Files.createDirectories(sendmail.getParent());
        Files.createDirectories(newaliases.getParent());
        Files.writeString(newaliases, "#!/bin/sh\necho called >> '" + newaliasesCalls + "'\n");
        newaliases.toFile().setExecutable(true);

        // Si sostituiscono i percorsi veri, e si controlla che la sostituzione sia AVVENUTA:
        // un percorso rimasto vero vorrebbe dire scrivere sul sistema della VM.
        String piece = LocalMtaScript.SHELL;
        Map<String, Path> replacements = new java.util.LinkedHashMap<>();
        replacements.put("/usr/local/share/postfix/mailer.conf.postfix", shared);
        replacements.put("/usr/local/etc/mail", mailDir);
        replacements.put("/usr/local/sbin/sendmail", sendmail);
        replacements.put("/usr/local/bin/newaliases", newaliases);
        replacements.put("/etc/periodic.conf", periodic);
        replacements.put("/var/spool/dma", dmaSpool);
        for (Map.Entry<String, Path> r : replacements.entrySet()) {
            check("il pezzo nomina " + r.getKey(), piece.contains(r.getKey()));
            piece = piece.replace(r.getKey(), r.getValue().toString());
        }
        check("dopo la sostituzione non nomina piu' nessun percorso del sistema",
                !piece.contains("/usr/local/") && !piece.contains("/etc/periodic") && !piece.contains("/var/spool"));
        Path pieceFile = home.resolve("local-mta.sh");
        Files.writeString(pieceFile, piece, StandardCharsets.UTF_8);

        OUT.println("\n-- 1. Postfix non c'e' --");
        Run r1 = sh(pieceFile);
        check("dice che sendmail passa ancora a dma", r1.out.contains("ERROR") && r1.out.contains("dma"));
        check("e non scrive mailer.conf", !Files.exists(mailerConf));
        check("e non chiama newaliases", newaliasesCallCount(newaliasesCalls) == 0);

        OUT.println("\n-- 2. c'e' il file di Postfix ma non il suo sendmail --");
        Path real = Path.of("/usr/local/share/postfix/mailer.conf.postfix");
        String postfixMailer = Files.isRegularFile(real) ? Files.readString(real)
                : "sendmail\t/usr/local/sbin/sendmail\nsend-mail\t/usr/local/sbin/sendmail\n"
                + "mailq\t\t/usr/local/sbin/sendmail\nnewaliases\t/usr/local/sbin/sendmail\n";
        Files.writeString(shared, postfixMailer);
        Run r2 = sh(pieceFile);
        check("non scrive mailer.conf: punterebbe a un programma che non c'e'",
                !Files.exists(mailerConf) && r2.out.contains("ERROR"));
        check("e non chiama newaliases", newaliasesCallCount(newaliasesCalls) == 0);

        OUT.println("\n-- 3. Postfix c'e', e nella coda di dma e' rimasto un messaggio --");
        Files.writeString(sendmail, "#!/bin/sh\nexit 0\n");
        sendmail.toFile().setExecutable(true);
        Files.writeString(dmaSpool.resolve("Q1a2b3.4c5d6e7f8000"), "");
        Files.writeString(dmaSpool.resolve("M1a2b3.4c5d6e7f8000"), "");
        Files.writeString(dmaSpool.resolve("flush"), "");
        Run r3 = sh(pieceFile);
        check("scrive mailer.conf, identico a quello del pacchetto",
                Files.isRegularFile(mailerConf) && Files.readString(mailerConf).equals(postfixMailer));
        check("e lo dice", r3.out.contains("hands over to Postfix"));
        check("costruisce il database degli alias, una volta (senza, la consegna locale resta in "
                + "coda con \"alias database unavailable\")", newaliasesCallCount(newaliasesCalls) == 1);
        for (String v : List.of("daily_clean_hoststat_enable", "daily_status_mail_rejects_enable",
                "daily_status_include_submit_mailq", "daily_submit_queuerun"))
            check("periodic.conf: " + v + " = NO", "NO".equals(sysrc(periodic, v)));
        check("avvisa del messaggio rimasto nella coda di dma (uno: M e flush non sono messaggi)",
                r3.out.contains("WARNING: 1 message"));

        OUT.println("\n-- 4. di nuovo, uguale --");
        Files.delete(dmaSpool.resolve("Q1a2b3.4c5d6e7f8000"));
        Files.delete(dmaSpool.resolve("M1a2b3.4c5d6e7f8000"));
        BasicFileAttributes before = Files.readAttributes(mailerConf, BasicFileAttributes.class);
        byte[] periodicBefore = Files.readAllBytes(periodic);
        Thread.sleep(1100);
        Run r4 = sh(pieceFile);
        BasicFileAttributes after = Files.readAttributes(mailerConf, BasicFileAttributes.class);
        check("mailer.conf non riscritto (stesso file, stessa ora)",
                before.fileKey().equals(after.fileKey()) && before.lastModifiedTime().equals(after.lastModifiedTime()));
        check("periodic.conf identico, nessuna voce doppia",
                java.util.Arrays.equals(periodicBefore, Files.readAllBytes(periodic)));
        check("nessuna copia di riserva", backups(mailDir).isEmpty());
        check("e nessun avviso sulla coda di dma, ora vuota", !r4.out.contains("WARNING"));

        OUT.println("\n-- 5. un mailer.conf diverso c'era gia' (quello di base, cioe' dma) --");
        String base = "sendmail\t/usr/libexec/dma\nmailq\t\t/usr/libexec/dma\nnewaliases\t/usr/libexec/dma\n";
        Files.writeString(mailerConf, base);
        sh(pieceFile);
        List<Path> copies = backups(mailDir);
        check("mailer.conf torna quello di Postfix", Files.readString(mailerConf).equals(postfixMailer));
        check("quello di prima resta accanto, una copia sola",
                copies.size() == 1 && Files.readString(copies.get(0)).equals(base));
        check("con data e ora UTC nel nome (" + (copies.isEmpty() ? "-" : copies.get(0).getFileName()) + ")",
                copies.size() == 1 && copies.get(0).getFileName().toString()
                        .matches("mailer\\.conf\\.before-postfix\\.\\d{8}T\\d{6}Z"));

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }

    record Run(int code, String out) {}

    static Run sh(Path file, String... env) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", file.toString());
        for (int i = 0; i + 1 < env.length; i += 2) pb.environment().put(env[i], env[i + 1]);
        pb.redirectErrorStream(true);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return new Run(p.waitFor(), out);
    }

    static final Pattern MAIN_CF = Pattern.compile(
            "^[ \\t]*cat > /usr/local/etc/postfix/main\\.cf << '?([A-Z_]+)'?\\n(.*?)\\n\\1\\n",
            Pattern.MULTILINE | Pattern.DOTALL);

    /**
     * Il blocco che scrive main.cf, eseguito con sh in una cartella di prova. Con sh e non
     * copiato a mano: nell'installazione completa l'heredoc non e' fra apici, e il nome del
     * server ce lo mette la shell.
     */
    static Run writeMainCf(String script, Path dir) throws Exception {
        Matcher m = MAIN_CF.matcher(script);
        if (!m.find()) return new Run(1, "nessun blocco main.cf");
        String block = m.group().replaceFirst("/usr/local/etc/postfix/main\\.cf",
                Matcher.quoteReplacement(dir.resolve("main.cf").toString()));
        Path file = dir.resolve("write-main-cf.sh");
        Files.writeString(file, block, StandardCharsets.UTF_8);
        // postconf -c vuole anche master.cf accanto, se no avvisa: qui conta solo main.cf.
        Files.writeString(dir.resolve("master.cf"), "");
        Run r = sh(file, "MAIL_HOSTNAME", "mail.example.org");
        return new Run(r.code, "heredoc " + m.group(1) + ", " + m.group(2).split("\n").length + " righe");
    }

    /**
     * Il valore che Postfix legge, dallo standard output soltanto: gli avvisi di postconf vanno
     * sullo standard error, e mescolati al valore lo rendevano irriconoscibile (era successo con
     * "warning: open .../master.cf", che writeMainCf adesso evita).
     */
    static String postconf(Path dir, String parameter) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("postconf", "-c", dir.toString(), "-h", parameter);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        p.waitFor();
        return out;
    }

    static String sysrc(Path file, String variable) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sysrc", "-f", file.toString(), "-n", variable);
        pb.redirectErrorStream(true);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        p.waitFor();
        return out;
    }

    /** Quante volte il newaliases finto e' stato chiamato: una riga per chiamata. */
    static long newaliasesCallCount(Path calls) throws Exception {
        if (!Files.exists(calls)) return 0;
        try (var lines = Files.lines(calls)) {
            return lines.filter(l -> l.equals("called")).count();
        }
    }

    static List<Path> backups(Path mailDir) throws Exception {
        if (!Files.isDirectory(mailDir)) return List.of();
        try (var s = Files.list(mailDir)) {
            return s.filter(p -> p.getFileName().toString().startsWith("mailer.conf.")).sorted().toList();
        }
    }

    static boolean onPath(String command) {
        String path = System.getenv("PATH");
        if (path == null) return false;
        for (String dir : path.split(":"))
            if (Files.isExecutable(Path.of(dir, command))) return true;
        return false;
    }
}
