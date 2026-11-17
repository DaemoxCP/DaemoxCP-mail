package org.daemoxcp.mail.integration;

import org.daemoxcp.mail.database.MailDatabase;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The panel's Sieve rules do what they say: no keep forced at the end of the script (reperto 216).
 *
 * Until 09/11/2026 SieveGenerator ended every script with "# Default action" and an explicit "keep;". The message then
 * always stayed in INBOX: a "move" filter left it in the folder AND in INBOX (measured on the VM: doveadm search gave
 * INBOX 1, Junk 1), a forward without a copy kept one, "delete" deleted nothing. The implicit keep (RFC 5228, 2.10.2)
 * already keeps the message when no rule takes it away.
 *
 *  1. The scripts the generator writes, rule by rule: no top-level keep, the action as Sieve means it (fileinto,
 *     redirect, redirect :copy, fileinto :copy, discard), a script without rules is just the require line.
 *  2. With -De2e.vm=yes, on the VM: every one of those scripts compiles with the real sievec.
 *
 *   java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.integration.SieveGeneratorTest
 */
public class SieveGeneratorTest {

    private static int failures = 0;

    /** The three things the generator reads from the database, given by hand. */
    public static final class Rules extends MailDatabase {
        AutoResponder autoResponder;
        final List<ForwardingRule> forwards = new ArrayList<>();
        final List<SieveFilter> filters = new ArrayList<>();

        @Override public AutoResponder getAutoResponder(int mailboxId) { return autoResponder; }
        @Override public List<ForwardingRule> getForwardingRules(int mailboxId) { return forwards; }
        @Override public List<SieveFilter> getSieveFilters(int mailboxId) { return filters; }

        public Rules filter(String token, String type, String value) {
            SieveFilter f = new SieveFilter();
            f.name = type + " " + token;
            f.enabled = true;
            f.conditions = "[{\"field\":\"subject\",\"operator\":\"contains\",\"value\":\"" + token + "\"}]";
            f.actions = "[{\"type\":\"" + type + "\",\"value\":\"" + value + "\"}]";
            filters.add(f);
            return this;
        }

        public Rules forward(String destination, boolean keepCopy) {
            ForwardingRule r = new ForwardingRule();
            r.destination = destination;
            r.keepCopy = keepCopy;
            r.enabled = true;
            forwards.add(r);
            return this;
        }

        public Rules away(String subject, String body) {
            AutoResponder a = new AutoResponder();
            a.enabled = true;
            a.subject = subject;
            a.body = body;
            a.intervalHours = 24;
            autoResponder = a;
            return this;
        }
    }

    public static void main(String[] args) throws Exception {
        SieveGenerator generator = new SieveGenerator();
        List<String[]> generated = new ArrayList<>();

        System.out.println("== 1. What the generator writes ==");
        String none = generator.generateSieveScript(1, new Rules());
        generated.add(new String[]{"no rules", none});
        check("no rules: just the require line, the implicit keep does the rest", none.equals(SieveGenerator.REQUIRE));

        String move = generator.generateSieveScript(1, new Rules().filter("spam", "move", "Junk"));
        generated.add(new String[]{"move", move});
        print(move);
        check("move: fileinto :create without :copy (a missing folder is created, reperto 229)", move.contains("  fileinto :create \"Junk\";\n"));
        check("the require line asks for mailbox (fileinto :create), the one of before did not",
                SieveGenerator.REQUIRE.contains("\"mailbox\"") && !SieveGenerator.REQUIRE_BEFORE_MAILBOX.contains("\"mailbox\"")
                        && SieveGenerator.REQUIRE.replace(", \"mailbox\"", "").equals(SieveGenerator.REQUIRE_BEFORE_MAILBOX));
        check("  and no keep anywhere, so the message leaves INBOX", !move.contains("keep"));

        String copy = generator.generateSieveScript(1, new Rules().filter("work", "copy", "Work"));
        generated.add(new String[]{"copy", copy});
        check("copy: fileinto :copy :create, the implicit keep stays", copy.contains("  fileinto :copy :create \"Work\";\n") && !hasTopLevelKeep(copy));

        String delete = generator.generateSieveScript(1, new Rules().filter("junk", "delete", ""));
        generated.add(new String[]{"delete", delete});
        check("delete: discard, and no keep that would undo it", delete.contains("  discard;\n") && !delete.contains("keep"));

        String forward = generator.generateSieveScript(1, new Rules().forward("bob@example.test", false));
        generated.add(new String[]{"forward without a copy", forward});
        print(forward);
        check("forward without a copy: redirect without :copy", forward.contains("redirect \"bob@example.test\";\n"));
        check("  and no keep anywhere, so no copy stays", !forward.contains("keep"));

        String forwardCopy = generator.generateSieveScript(1, new Rules().forward("bob@example.test", true));
        generated.add(new String[]{"forward with a copy", forwardCopy});
        check("forward with a copy: redirect :copy, the implicit keep stays",
                forwardCopy.contains("redirect :copy \"bob@example.test\";\n") && !hasTopLevelKeep(forwardCopy));

        String filterForward = generator.generateSieveScript(1, new Rules().filter("boss", "forward", "carol@example.test"));
        generated.add(new String[]{"filter forward", filterForward});
        check("a filter's forward: redirect without :copy, no keep",
                filterForward.contains("  redirect \"carol@example.test\";\n") && !filterForward.contains("keep"));

        String away = generator.generateSieveScript(1, new Rules().away("Away", "Back on Monday"));
        generated.add(new String[]{"autoresponder", away});
        check("autoresponder: vacation, and the message stays through the implicit keep",
                away.contains("vacation :days 1") && !hasTopLevelKeep(away));

        String all = generator.generateSieveScript(1, new Rules().away("Away", "Back").forward("bob@example.test", true)
                .filter("spam", "move", "Junk").filter("news", "mark_read", "").filter("x", "reject", "No thanks"));
        generated.add(new String[]{"everything together", all});
        check("everything together: still no top-level keep", !hasTopLevelKeep(all) && all.startsWith(SieveGenerator.REQUIRE));
        check("  the script ends with the last rule, not with the old default action",
                !all.contains("# Default action") && all.endsWith("}\n\n"));

        System.out.println("\n== 2. sievec accepts every script ==");
        boolean e2e = "yes".equals(System.getProperty("e2e.vm"));
        Path sievec = Path.of("/usr/local/bin/sievec");
        if (e2e && Files.isExecutable(sievec)) {
            Path dir = Files.createTempDirectory(Path.of("/var/tmp"), "sieve-generator-test");
            try {
                int n = 0;
                for (String[] g : generated) {
                    Path f = dir.resolve("s" + (n++) + ".sieve");
                    Files.writeString(f, g[1]);
                    Process p = new ProcessBuilder(sievec.toString(), f.toString()).redirectErrorStream(true).start();
                    String out = new String(p.getInputStream().readAllBytes()).trim();
                    int code = p.waitFor();
                    check("sievec: " + g[0] + (code == 0 ? "" : " -> " + out), code == 0);
                }
            } finally {
                new ProcessBuilder("rm", "-rf", dir.toString()).start().waitFor();
            }
        } else {
            System.out.println("  (skipped: needs sievec, turned on with -De2e.vm=yes on the VM)");
        }

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    /** A keep at the top level of the script (not inside a rule's braces), as the old generator wrote it. */
    static boolean hasTopLevelKeep(String script) {
        return script.lines().anyMatch(l -> l.equals("keep;"));
    }

    static void print(String script) {
        System.out.println(script.stripTrailing().replaceAll("(?m)^", "    | "));
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
