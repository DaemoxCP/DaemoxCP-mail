package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The SMTP VRFY command off (PostfixVrfy). Measured on the VM on 20/11/2026, on port 25 without authentication:
 * «VRFY an-existing-mailbox» answered 252, «VRFY a-missing-one» 550 User unknown: anyone could list the mailboxes.
 *  1. the decision: anything but yes (the default no, empty) needs it; yes does not;
 *  2. the answer: only 502 (the command is off) counts as refused; 252 and 550 do not;
 *  3. the installer writes it in main.cf, and the panel's start runs the repair;
 *  4. with -De2e.vm=yes, on the VM with Postfix running: a real VRFY on port 25 gets 502.
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixVrfyTest
 */
public class PostfixVrfyTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("== 1. The decision");
        check("no (Postfix's default): needed", PostfixVrfy.needed("no"));
        check("empty or unreadable: needed", PostfixVrfy.needed("") && PostfixVrfy.needed(null));
        check("yes: nothing to do", !PostfixVrfy.needed("yes") && !PostfixVrfy.needed(" YES "));

        System.out.println("\n== 2. The answer");
        check("502 5.5.1 VRFY command is disabled: refused", PostfixVrfy.refused("502 5.5.1 VRFY command is disabled"));
        check("252 (the mailbox exists) is not", !PostfixVrfy.refused("252 2.0.0 carol@example.test"));
        check("550 User unknown is not", !PostfixVrfy.refused("550 5.1.1 <x@example.test>: Recipient address rejected: User unknown"));
        check("no answer is not", !PostfixVrfy.refused(null) && !PostfixVrfy.refused(""));

        System.out.println("\n== 3. Where it is written");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("the installer's main.cf has disable_vrfy_command = yes", installer.contains("\ndisable_vrfy_command = yes\n"));
        check("the panel's start runs the repair", Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"))
                .contains("org.daemoxcp.mail.system.PostfixVrfy.ensureAtBoot();"));

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 4 skipped: it talks to port 25 of the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            System.out.println("\n== 4. A real VRFY on port 25");
            String reply = PostfixVrfy.probe();
            check("Postfix answers 502 (" + reply + ")", PostfixVrfy.refused(reply));
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
