package org.daemoxcp.mail.system;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.daemoxcp.mail.util.Shell;

/**
 * Rspamd learns from the users (SpamLearning, SpamLearner): a message moved or copied into Junk is spam, one moved out
 * of it is ham, unless it goes to Trash. Before 20/11/2026 Rspamd learned only from rspamc run by hand.
 *  1. the decision: only Dovecot 2.4 with the panel's Junk; missing configuration or parts: apply; a configuration of
 *     the same name written by hand: left alone;
 *  2. the configuration, the two Sieve scripts and the program Dovecot pipes to (it only leaves the message in the
 *     spool, as vmail, and always exits 0);
 *  3. a round of the root part on a throwaway spool with a fake Rspamd: whole messages are learned and deleted, oldest
 *     first; messages still being written (a leading dot) wait; empty, too big and week-old ones are dropped unread; a
 *     link is removed without reading what it points to; a 400 drops the message; Rspamd not answering stops the round
 *     and keeps the messages;
 *  4. the webmail's spam button (markasjunk) in the panel's block, once; the order at boot;
 *  5. with -De2e.vm=yes, as root on the VM: the configuration in place and compiled, the program writes as vmail; then
 *     real IMAP moves for the first mailbox (doveadm exec imap): INBOX -> Junk leaves a spam message in the spool and
 *     Rspamd's «learned» counter grows once the root part's round (called here, as the panel does every minute) hands it
 *     over; Junk -> INBOX leaves a ham message; Junk -> Trash leaves nothing; the spool ends empty and the test messages
 *     are expunged. NB: the VM's Bayes learns the test message (a new one each run).
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SpamLearningTest
 */
public class SpamLearningTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        String conf = SpamLearning.confContent();

        System.out.println("== 1. The decision");
        check("Dovecot 2.3: nothing", SpamLearning.decide(false, true, null, false) == SpamLearning.Action.NOTHING);
        check("no Junk of the panel: nothing", SpamLearning.decide(true, false, null, false) == SpamLearning.Action.NOTHING);
        check("missing: apply", SpamLearning.decide(true, true, null, false) == SpamLearning.Action.APPLY);
        check("in place, parts current: nothing", SpamLearning.decide(true, true, conf, true) == SpamLearning.Action.NOTHING);
        check("in place, a part missing or old: apply", SpamLearning.decide(true, true, conf, false) == SpamLearning.Action.APPLY);
        check("an older configuration of the panel: apply", SpamLearning.decide(true, true, "# " + PanelMarker.WRITTEN + ".\nold\n", true) == SpamLearning.Action.APPLY);
        check("written by hand: left alone", SpamLearning.decide(true, true, "mailbox Junk {\n}\n", true) == SpamLearning.Action.LEFT_ALONE);

        System.out.println("\n== 2. The configuration, the scripts, the program");
        check("the IMAP plugin", conf.contains("protocol imap {\n  mail_plugins {\n    imap_sieve = yes\n  }\n}\n"));
        check("the Sieve plugins", conf.contains("sieve_plugins {\n  sieve_imapsieve = yes\n  sieve_extprograms = yes\n}\n"));
        check("pipe only for global scripts", conf.contains("sieve_global_extensions {\n  vnd.dovecot.pipe = yes\n}\n"));
        check("the programs' folder", conf.contains("sieve_pipe_bin_dir = " + SpamLearning.PIPE_DIR + "\n"));
        check("into Junk: the spam script, on copy (MOVE included)", conf.contains("mailbox Junk {\n  sieve_script learn_spam {\n    type = before\n    cause = copy\n    path = /usr/local/etc/dovecot/sieve/learn-spam.sieve\n"));
        check("out of Junk: the ham script", conf.contains("imapsieve_from Junk {\n  sieve_script learn_ham {\n    type = before\n    cause = copy\n    path = /usr/local/etc/dovecot/sieve/learn-ham.sieve\n"));
        check("spam script: pipe a copy as spam", SpamLearning.spamScript().contains("pipe :copy \"daemoxcp-learn\" [\"spam\"];"));
        String ham = SpamLearning.hamScript();
        check("ham script: not when it goes to Trash, then pipe as ham", ham.indexOf("if string \"${mailbox}\" \"Trash\" { stop; }")
                < ham.indexOf("pipe :copy \"daemoxcp-learn\" [\"ham\"];") && ham.contains("environment :matches \"imap.mailbox\" \"*\""));
        String program = SpamLearning.programContent();
        check("program: only spam and ham are kept, check only tries to write", program.contains("  spam|ham) ;;\n")
                && program.contains("  check) t=$(mktemp \"/var/spool/daemoxcp-learn/spam/.check.XXXXXXXX\") && rm -f \"$t\" && echo ok; exit 0 ;;\n")
                && program.contains("  *) cat > /dev/null; exit 0 ;;\n"));
        check("program: a dotted name while writing, at most the limit, all the input read, always 0",
                program.contains("tmp=$(mktemp \"$dir/.in.XXXXXXXX\")") && program.contains("head -c " + SpamLearning.MAX_BYTES + " > \"$tmp\"\ncat > /dev/null\n")
                && program.contains("mv \"$tmp\" \"$dir/$(date +%s).${tmp##*.in.}\"") && program.endsWith("exit 0\n"));
        check("sievec gets the plugins and the extensions", SpamLearning.SIEVEC_OPTIONS.equals(List.of("-P", "sieve_imapsieve", "-P", "sieve_extprograms",
                "-x", "+vnd.dovecot.pipe +imapsieve")));

        System.out.println("\n== 3. A round of the root part, with a fake Rspamd");
        rounds();

        System.out.println("\n== 4. The webmail's button and the order at boot");
        String config = "<?php\n$config['plugins'] = ['archive', 'zipdownload'];\n", key = "TestKey_0123456789-abcdefgh";
        String block = org.daemoxcp.mail.integration.WebmailPasswordConfig.apply(config, 2096, key);
        check("markasjunk in the panel's block", block.contains("!in_array('markasjunk', $config['plugins'], true)) { $config['plugins'][] = 'markasjunk'; }"));
        String again = org.daemoxcp.mail.integration.WebmailPasswordConfig.apply(block, 2096, key);
        check("  once, also when the block is written again", again.split(Pattern.quote("$config['plugins'][] = 'markasjunk';"), -1).length == 2);
        String server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"));
        int folders = server.indexOf("SpecialFolders.ensureAtBoot();"), learning = server.indexOf("SpamLearning.ensureAtBoot();"),
                controller = server.indexOf("RspamdController.ensureAtBoot();"), learner = server.indexOf("SpamLearner.start();");
        check("SpamLearning after SpecialFolders (the Junk)", folders > 0 && learning > folders);
        check("the learner after RspamdController (the password)", controller > 0 && learner > controller);

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 5 skipped: it moves messages on the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            live();
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void rounds() throws Exception {
        Path spool = Files.createTempDirectory("spam-learning-");
        Path outside = Files.createTempFile("spam-learning-secret-", ".txt");
        try {
            Path spam = Files.createDirectories(spool.resolve("spam")), hamDir = Files.createDirectories(spool.resolve("ham"));
            Files.writeString(spam.resolve("1700000002.bbbbbbbb"), "Subject: second\n\nspam two\n");
            Files.writeString(spam.resolve("1700000001.aaaaaaaa"), "Subject: first\n\nspam one\n");
            Files.writeString(spam.resolve(".in.cccccccc"), "Subject: still being written\n");
            Files.writeString(spam.resolve("1700000003.empty000"), "");
            Files.write(spam.resolve("1700000004.big00000"), new byte[(int) SpamLearning.MAX_BYTES + 1]);
            Path old = Files.writeString(spam.resolve("1700000005.old00000"), "Subject: old\n\nold\n");
            Files.setLastModifiedTime(old, FileTime.from(Instant.now().minus(Duration.ofDays(8))));
            Files.writeString(outside, "root's secret");
            Files.createSymbolicLink(spam.resolve("1700000006.link0000"), outside);
            Files.writeString(hamDir.resolve("1700000007.dddddddd"), "Subject: ham\n\nham\n");

            List<String> seen = new ArrayList<>();
            SpamLearner.Round r = SpamLearner.round(spool, (kind, msg) -> { seen.add(kind + ":" + new String(msg)); return 204; }, Instant.now());
            check("learned the two spam and the ham (" + r.learned() + ")", r.learned() == 3 && !r.stopped());
            check("oldest first, ham after spam", seen.size() == 3 && seen.get(0).contains("spam one") && seen.get(1).contains("spam two")
                    && seen.get(2).startsWith("ham:"));
            check("learned ones deleted", !Files.exists(spam.resolve("1700000001.aaaaaaaa")) && !Files.exists(hamDir.resolve("1700000007.dddddddd")));
            check("the one being written waits", Files.exists(spam.resolve(".in.cccccccc")));
            check("empty, too big, old and the link dropped (" + r.dropped() + ")", r.dropped() == 4
                    && !Files.exists(spam.resolve("1700000003.empty000")) && !Files.exists(spam.resolve("1700000004.big00000"))
                    && !Files.exists(spam.resolve("1700000005.old00000"))
                    && !Files.exists(spam.resolve("1700000006.link0000"), java.nio.file.LinkOption.NOFOLLOW_LINKS));
            check("the link's target never read and still there", seen.stream().noneMatch(s -> s.contains("secret"))
                    && Files.readString(outside).equals("root's secret"));

            Files.writeString(spam.resolve("1700000010.eeeeeeee"), "Subject: a\n\na\n");
            Files.writeString(spam.resolve("1700000011.ffffffff"), "Subject: b\n\nb\n");
            SpamLearner.Round down = SpamLearner.round(spool, (kind, msg) -> -1, Instant.now());
            check("Rspamd not answering: the round stops, the messages stay", down.stopped() && down.lastStatus() == -1
                    && Files.exists(spam.resolve("1700000010.eeeeeeee")) && Files.exists(spam.resolve("1700000011.ffffffff")));
            SpamLearner.Round refused = SpamLearner.round(spool, (kind, msg) -> 400, Instant.now());
            check("a 400: dropped, not retried", refused.dropped() == 2 && !Files.exists(spam.resolve("1700000010.eeeeeeee")));
            Files.writeString(spam.resolve("1700000012.gggggggg"), "Subject: c\n\nc\n");
            SpamLearner.Round wrong = SpamLearner.round(spool, (kind, msg) -> 401, Instant.now());
            check("a 401 (wrong password): kept for the next round", wrong.stopped() && Files.exists(spam.resolve("1700000012.gggggggg")));
        } finally {
            try (Stream<Path> s = Files.walk(spool)) {
                for (Path p : s.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            }
            Files.deleteIfExists(outside);
        }
    }

    // ===================== 5. On the VM =====================

    static final String SUBJECT = "learn-e2e-" + System.nanoTime();

    static void live() throws Exception {
        System.out.println("\n== 5. Live, on the VM");
        Path conf = SpamLearning.conf();
        check("the configuration is the panel's", Files.isRegularFile(conf) && SpamLearning.confContent().equals(Files.readString(conf)));
        check("the scripts are compiled", Files.isRegularFile(Path.of("/usr/local/etc/dovecot/sieve/learn-spam.svbin"))
                && Files.isRegularFile(Path.of("/usr/local/etc/dovecot/sieve/learn-ham.svbin")));
        check("the parts are the panel's", SpamLearning.partsCurrent());
        check("the program writes as vmail", sh("su -m vmail -c '" + SpamLearning.PIPE_DIR + "/daemoxcp-learn check'").trim().equals("ok"));
        String user = null;
        for (String u : sh("doveadm user '*'").trim().split("\\s+")) if (u.contains("@")) { user = u; break; }
        if (user == null) { check("a mailbox to try with", false); return; }
        String password = org.daemoxcp.mail.security.PanelSecrets.reread(org.daemoxcp.mail.security.PanelSecrets.RSPAMD_CONTROLLER_PASSWORD);
        if (password == null) { check("the controller password in the root secrets", false); return; }
        try {
            StringBuilder words = new StringBuilder();
            for (int i = 0; i < 60; i++) words.append("word").append(i).append(Long.toString(System.nanoTime() % 100000, 36)).append(' ');
            sh("printf 'From: <someone@example.org>\\nTo: <" + user + ">\\nSubject: " + SUBJECT + "\\nMessage-ID: <" + SUBJECT
                    + "@e2e.test>\\n\\n" + words + "\\n' | doveadm save -u " + user + " -m INBOX");
            long before = learned(password);

            move(user, "INBOX", "Junk");
            check("INBOX -> Junk: a spam message in the spool", waitFor(() -> count("spam") == 1));
            SpamLearner.Round r = SpamLearner.round(Path.of(SpamLearning.SPOOL), SpamLearner.rspamd(password), Instant.now());
            long after = learned(password);
            check("  handed to Rspamd and deleted (round learned " + r.learned() + ", Rspamd learned " + before + " -> " + after + ")",
                    count("spam") == 0 && after > before);

            move(user, "Junk", "INBOX");
            check("Junk -> INBOX: a ham message in the spool", waitFor(() -> count("ham") == 1));
            SpamLearner.Round h = SpamLearner.round(Path.of(SpamLearning.SPOOL), SpamLearner.rspamd(password), Instant.now());
            check("  handed to Rspamd and deleted (round learned " + h.learned() + ")", count("ham") == 0 && !h.stopped());

            move(user, "INBOX", "Junk");
            waitFor(() -> count("spam") == 1);
            SpamLearner.round(Path.of(SpamLearning.SPOOL), SpamLearner.rspamd(password), Instant.now());
            move(user, "Junk", "Trash");
            Thread.sleep(3000);
            check("Junk -> Trash: nothing in the spool", count("ham") == 0 && count("spam") == 0);
            String log = sh("tail -n 200 /var/log/maillog | grep -i -e 'sieve' | grep -i -e error -e fail | tail -3");
            check("no Sieve error in the mail log" + (log.isBlank() ? "" : " (" + log.trim() + ")"), log.isBlank());
        } finally {
            sh("doveadm expunge -u " + user + " mailbox '*' header Subject " + SUBJECT);
            check("the test messages expunged", sh("doveadm search -u " + user + " mailbox '*' header Subject " + SUBJECT).isBlank());
        }
    }

    interface Condition { boolean ok() throws Exception; }

    static boolean waitFor(Condition c) throws Exception {
        for (int i = 0; i < 50; i++) {
            if (c.ok()) return true;
            Thread.sleep(200);
        }
        return c.ok();
    }

    static int count(String kind) throws Exception {
        return SpamLearner.waiting(Path.of(SpamLearning.SPOOL, kind)).size();
    }

    /** A real IMAP MOVE of the test message, in a preauthenticated session for the mailbox. */
    static void move(String user, String from, String to) {
        String uid = sh("printf 'a SELECT " + from + "\\r\\nb UID SEARCH HEADER Subject " + SUBJECT + "\\r\\nz LOGOUT\\r\\n' | doveadm exec imap -u " + user)
                .lines().filter(l -> l.startsWith("* SEARCH ")).map(l -> l.substring(9).trim().split(" ")[0]).findFirst().orElse("");
        if (uid.isEmpty()) { check("the test message is in " + from, false); return; }
        String out = sh("printf 'a SELECT " + from + "\\r\\nb UID MOVE " + uid + " " + to + "\\r\\nz LOGOUT\\r\\n' | doveadm exec imap -u " + user);
        if (!out.contains("b OK")) check("IMAP MOVE " + from + " -> " + to, false);
    }

    private static final Pattern LEARNED = Pattern.compile("\"learned\"\\s*:\\s*(\\d+)");

    /** Rspamd's «learned» counter, from the controller with the password. */
    static long learned(String password) throws Exception {
        HttpRequest r = HttpRequest.newBuilder(URI.create(SpamLearner.CONTROLLER + "stat")).header("Password", password)
                .timeout(Duration.ofSeconds(20)).GET().build();
        String body = HttpClient.newHttpClient().send(r, HttpResponse.BodyHandlers.ofString()).body();
        Matcher m = LEARNED.matcher(body);
        return m.find() ? Long.parseLong(m.group(1)) : -1;
    }

    static String sh(String command) {
        return Shell.run(Duration.ofSeconds(90), "sh", "-c", command).output();
    }
}
