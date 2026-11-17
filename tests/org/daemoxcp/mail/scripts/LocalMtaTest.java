package org.daemoxcp.mail.scripts;

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
 * Postfix as the local MTA: the mail born on the machine (cron, periodic, mail(1), PHP's mail())
 * must go through Postfix and stay on this machine, not leave through dma.
 *
 * The defect, measured on the FreeBSD 15.1 VM on 23/10/2026: none of the three scripts installing
 * Postfix wrote /usr/local/etc/mail/mailer.conf, so mailwrapper(8) used the base system's and passed
 * everything to dma. And fixing ONLY mailer.conf was not enough: with myorigin = $mydomain "root"
 * became root@<server name>, which is not local, and Postfix bounced it to itself. See
 * LocalMtaScript and the comment next to myorigin in
 * FullMailServerScript.
 *
 * What is tested here:
 *  - that all three scripts contain the piece, and AFTER the package installation: before it the
 *    Postfix file to copy is not there and the piece, rightly, does nothing;
 *  - that their main.cf, read by postconf and not looked at as text, gives myorigin = localhost and
 *    a mydestination that does not contain the server's name;
 *  - the piece really run, in a fake folder in place of /usr/local/etc/mail, /etc/periodic.conf,
 *    /var/spool/dma and Postfix's newaliases: without Postfix it writes nothing, with Postfix it
 *    writes and builds the aliases database, repeated it does not touch mailer.conf, a different
 *    mailer.conf is set aside, dma's queue is reported.
 *
 * It runs on the VM, where postconf and sysrc are:
 *   javac -cp &lt;dir&gt;/freebsd-mail-panel-1.0.jar -d tests tests/org/daemoxcp/mail/scripts/LocalMtaTest.java
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.scripts.LocalMtaTest
 */
public class LocalMtaTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        for (String command : List.of("postconf", "postmap", "sysrc")) {
            if (!onPath(command)) {
                check(command + " is there (this test must be run on the VM, not on the Mac)", false);
                OUT.println("\n" + failed + " CHECKS FAILED");
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
            // The package is installed with "pkg install -y" or, in the full installation, with
            // install_packages (PackageInstall), which checks that pkg did not remove it.
            int pkg = Math.max(script.indexOf("pkg install -y postfix-mysql"),
                    script.indexOf("install_packages postfix-mysql"));
            int activation = script.indexOf(LocalMtaScript.SHELL);
            check("it contains the LocalMtaScript piece, whole", activation >= 0);
            check("and it runs it after installing postfix-mysql", pkg >= 0 && activation > pkg);

            Path dir = home.resolve(name);
            Files.createDirectories(dir);
            Run written = writeMainCf(script, dir);
            check("the main.cf block is extracted and written (" + written.out.trim() + ")",
                    written.code == 0 && Files.isRegularFile(dir.resolve("main.cf")));
            String myorigin = postconf(dir, "myorigin");
            String mydestination = postconf(dir, "mydestination");
            String localTransport = postconf(dir, "local_transport");
            OUT.println("  myorigin = " + myorigin + " | mydestination = " + mydestination
                    + " | local_transport = " + localTransport);
            check("myorigin = localhost: root and postmaster stay on this machine",
                    "localhost".equals(myorigin));
            check("mydestination is localhost, not the server's name (which from the Internet "
                    + "would make the system accounts reachable)", "localhost".equals(mydestination));
            check("local delivery is not off (with local_transport = error: system mail "
                    + "would bounce)", !localTransport.startsWith("error"));
            String restrictions = postconf(dir, "smtpd_recipient_restrictions");
            check("root@localhost stays out of the Internet (reject_non_fqdn_recipient among the "
                    + "restrictions)", restrictions.contains("reject_non_fqdn_recipient"));

            // System mail leaving the machine: other people's servers refuse root@localhost. The map's
            // text is not looked at: postmap is made to read it, with the value Postfix gets by
            // expanding $myhostname.
            String hostname = postconf(dir, "-x", "myhostname");
            String genericMaps = postconf(dir, "-x", "smtp_generic_maps");
            // postmap -q looks for the exact key: the rule "@domain applies to every user" is applied
            // by Postfix when it rewrites, and that effect is measured on the VM with a fake SMTP.
            String rewritten = genericMaps.isEmpty() ? "" : postmap(genericMaps, "@localhost");
            OUT.println("  smtp_generic_maps = " + genericMaps + " | @localhost -> " + rewritten);
            check("outgoing @localhost becomes @" + hostname + " (smtp_generic_maps, read by postmap)",
                    !hostname.isEmpty() && ("@" + hostname).equals(rewritten));
            check("and only outgoing: myorigin stays localhost, local delivery does not change",
                    "localhost".equals(myorigin));

            // The relay: only this machine sends without authenticating.
            String compatibility = postconf(dir, "compatibility_level");
            String mynetworks = postconf(dir, "-x", "mynetworks");
            String relay = postconf(dir, "-x", "smtpd_relay_restrictions");
            OUT.println("  compatibility_level = " + compatibility + " | mynetworks = " + mynetworks);
            check("compatibility_level written (at level 0 mynetworks_style is subnet: the server's "
                    + "whole network becomes trusted)", !compatibility.isEmpty() && !"0".equals(compatibility));
            check("mynetworks is only this machine", "127.0.0.0/8 [::1]/128".equals(mynetworks));
            check("the relay restrictions are there, and they reject destinations that are not ours",
                    relay.contains("unauth_destination"));
        }
        check("the full installation also checks mailer.conf at the end",
                scripts.get("FullMailServerScript").contains("sendmail(8) does NOT hand over to Postfix"));

        // The full installation's colours: sh is made to run their definitions and the byte that
        // comes out is looked at. With the strings in quotes /bin/sh's echo printed "\033[1;33m"
        // spelled out.
        String colors = between(scripts.get("FullMailServerScript"), "\nRED=", "\nNC=");
        String ncLine = colors == null ? "" : scripts.get("FullMailServerScript")
                .substring(scripts.get("FullMailServerScript").indexOf("\nNC=") + 1).split("\n", 2)[0];
        Path colorFile = home.resolve("colors.sh");
        Files.writeString(colorFile, "RED=" + colors + "\n" + ncLine + "\necho \"${GREEN}x${NC}\"\n");
        Run colorRun = sh(colorFile);
        check("the installation's colours come out as real sequences (ESC), not as a written \\033",
                colors != null && colorRun.out.startsWith("\u001b[0;32mx\u001b[0m")
                        && !colorRun.out.contains("\\033"));

        OUT.println("\n== The piece run in a fake folder ==");
        Path fake = home.resolve("system");
        Path mailDir = fake.resolve("usr-local-etc-mail");
        Path mailerConf = mailDir.resolve("mailer.conf");
        Path shared = fake.resolve("share/mailer.conf.postfix");
        Path sendmail = fake.resolve("sbin/sendmail");
        Path periodic = fake.resolve("periodic.conf");
        Path dmaSpool = fake.resolve("spool-dma");
        // The fake newaliases counts the calls: the real one would write /etc/aliases.db.
        Path newaliases = fake.resolve("bin/newaliases");
        Path newaliasesCalls = fake.resolve("newaliases-calls");
        Files.createDirectories(dmaSpool);
        Files.createDirectories(shared.getParent());
        Files.createDirectories(sendmail.getParent());
        Files.createDirectories(newaliases.getParent());
        Files.writeString(newaliases, "#!/bin/sh\necho called >> '" + newaliasesCalls + "'\n");
        newaliases.toFile().setExecutable(true);

        // The real paths are replaced, and it is checked that the replacement HAPPENED: a path left
        // real would mean writing on the VM's system.
        String piece = LocalMtaScript.SHELL;
        Map<String, Path> replacements = new java.util.LinkedHashMap<>();
        replacements.put("/usr/local/share/postfix/mailer.conf.postfix", shared);
        replacements.put("/usr/local/etc/mail", mailDir);
        replacements.put("/usr/local/sbin/sendmail", sendmail);
        replacements.put("/usr/local/bin/newaliases", newaliases);
        replacements.put("/etc/periodic.conf", periodic);
        replacements.put("/var/spool/dma", dmaSpool);
        for (Map.Entry<String, Path> r : replacements.entrySet()) {
            check("the piece names " + r.getKey(), piece.contains(r.getKey()));
            piece = piece.replace(r.getKey(), r.getValue().toString());
        }
        check("after the replacement it no longer names any system path",
                !piece.contains("/usr/local/") && !piece.contains("/etc/periodic") && !piece.contains("/var/spool"));
        Path pieceFile = home.resolve("local-mta.sh");
        Files.writeString(pieceFile, piece, StandardCharsets.UTF_8);

        OUT.println("\n-- 1. Postfix is not there --");
        Run r1 = sh(pieceFile);
        check("it says sendmail still hands over to dma", r1.out.contains("ERROR") && r1.out.contains("dma"));
        check("and it does not write mailer.conf", !Files.exists(mailerConf));
        check("and it does not call newaliases", newaliasesCallCount(newaliasesCalls) == 0);

        OUT.println("\n-- 2. Postfix's file is there but not its sendmail --");
        Path real = Path.of("/usr/local/share/postfix/mailer.conf.postfix");
        String postfixMailer = Files.isRegularFile(real) ? Files.readString(real)
                : "sendmail\t/usr/local/sbin/sendmail\nsend-mail\t/usr/local/sbin/sendmail\n"
                + "mailq\t\t/usr/local/sbin/sendmail\nnewaliases\t/usr/local/sbin/sendmail\n";
        Files.writeString(shared, postfixMailer);
        Run r2 = sh(pieceFile);
        check("it does not write mailer.conf: it would point to a program that is not there",
                !Files.exists(mailerConf) && r2.out.contains("ERROR"));
        check("and it does not call newaliases", newaliasesCallCount(newaliasesCalls) == 0);

        OUT.println("\n-- 3. Postfix is there, and a message was left in dma's queue --");
        Files.writeString(sendmail, "#!/bin/sh\nexit 0\n");
        sendmail.toFile().setExecutable(true);
        Files.writeString(dmaSpool.resolve("Q1a2b3.4c5d6e7f8000"), "");
        Files.writeString(dmaSpool.resolve("M1a2b3.4c5d6e7f8000"), "");
        Files.writeString(dmaSpool.resolve("flush"), "");
        Run r3 = sh(pieceFile);
        check("it writes mailer.conf, identical to the package's",
                Files.isRegularFile(mailerConf) && Files.readString(mailerConf).equals(postfixMailer));
        check("and it says so", r3.out.contains("hands over to Postfix"));
        check("it builds the aliases database, once (without it, local delivery stays in the "
                + "queue with \"alias database unavailable\")", newaliasesCallCount(newaliasesCalls) == 1);
        for (String v : List.of("daily_clean_hoststat_enable", "daily_status_mail_rejects_enable",
                "daily_status_include_submit_mailq", "daily_submit_queuerun"))
            check("periodic.conf: " + v + " = NO", "NO".equals(sysrc(periodic, v)));
        check("it warns about the message left in dma's queue (one: M and flush are not messages)",
                r3.out.contains("WARNING: 1 message"));

        OUT.println("\n-- 4. again, the same --");
        Files.delete(dmaSpool.resolve("Q1a2b3.4c5d6e7f8000"));
        Files.delete(dmaSpool.resolve("M1a2b3.4c5d6e7f8000"));
        BasicFileAttributes before = Files.readAttributes(mailerConf, BasicFileAttributes.class);
        byte[] periodicBefore = Files.readAllBytes(periodic);
        Thread.sleep(1100);
        Run r4 = sh(pieceFile);
        BasicFileAttributes after = Files.readAttributes(mailerConf, BasicFileAttributes.class);
        check("mailer.conf not rewritten (same file, same time)",
                before.fileKey().equals(after.fileKey()) && before.lastModifiedTime().equals(after.lastModifiedTime()));
        check("periodic.conf identical, no duplicated entry",
                java.util.Arrays.equals(periodicBefore, Files.readAllBytes(periodic)));
        check("no backup copy", backups(mailDir).isEmpty());
        check("and no warning about dma's queue, now empty", !r4.out.contains("WARNING"));

        OUT.println("\n-- 5. a different mailer.conf was already there (the base one, that is dma) --");
        String base = "sendmail\t/usr/libexec/dma\nmailq\t\t/usr/libexec/dma\nnewaliases\t/usr/libexec/dma\n";
        Files.writeString(mailerConf, base);
        sh(pieceFile);
        List<Path> copies = backups(mailDir);
        check("mailer.conf goes back to Postfix's", Files.readString(mailerConf).equals(postfixMailer));
        check("the old one stays next to it, a single copy",
                copies.size() == 1 && Files.readString(copies.get(0)).equals(base));
        check("with UTC date and time in the name (" + (copies.isEmpty() ? "-" : copies.get(0).getFileName()) + ")",
                copies.size() == 1 && copies.get(0).getFileName().toString()
                        .matches("mailer\\.conf\\.before-postfix\\.\\d{8}T\\d{6}Z"));

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
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
     * The block that writes main.cf, run with sh in a test folder. With sh and not copied by hand: in
     * the full installation the heredoc is not quoted, and the shell puts the server's name in it.
     */
    static Run writeMainCf(String script, Path dir) throws Exception {
        Matcher m = MAIN_CF.matcher(script);
        if (!m.find()) return new Run(1, "no main.cf block");
        String block = m.group().replaceFirst("/usr/local/etc/postfix/main\\.cf",
                Matcher.quoteReplacement(dir.resolve("main.cf").toString()));
        Path file = dir.resolve("write-main-cf.sh");
        Files.writeString(file, block, StandardCharsets.UTF_8);
        // postconf -c also wants master.cf next to it, otherwise it warns: only main.cf counts here.
        Files.writeString(dir.resolve("master.cf"), "");
        Run r = sh(file, "MAIL_HOSTNAME", "mail.example.org");
        return new Run(r.code, "heredoc " + m.group(1) + ", " + m.group(2).split("\n").length + " lines");
    }

    /**
     * The value Postfix reads, from standard output only: postconf's warnings go to standard error,
     * and mixed with the value they made it unrecognisable (it had happened with "warning: open
     * .../master.cf", which writeMainCf now avoids).
     */
    static String postconf(Path dir, String... args) throws Exception {
        List<String> cmd = new java.util.ArrayList<>(List.of("postconf", "-c", dir.toString(), "-h"));
        cmd.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        p.waitFor();
        return out;
    }

    /** A key looked for in a Postfix table, as postmap -q looks for it. */
    static String postmap(String table, String key) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("postmap", "-q", key, table);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        p.waitFor();
        return out;
    }

    static String between(String text, String start, String end) {
        int a = text.indexOf(start);
        if (a < 0) return null;
        int b = text.indexOf(end, a + start.length());
        return b < 0 ? null : text.substring(a + start.length(), b);
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

    /** How many times the fake newaliases was called: one line per call. */
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
