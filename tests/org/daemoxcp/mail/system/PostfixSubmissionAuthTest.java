package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * SMTP AUTH only on the sending ports 587 and 465, not on port 25 (PostfixSubmissionAuth). Measured on the VM on
 * 20/11/2026: main.cf turned AUTH on for every port, so port 25 offered it after STARTTLS; the webmail, the client
 * profiles and the settings page all use 587 or 465.
 *  1. the decision: main.cf already no: nothing; master.cf not turning AUTH on for both 587 and 465: left as it is
 *     (the clients would stop sending); otherwise: apply;
 *  2. reading the answer to EHLO: «250-AUTH PLAIN LOGIN» and «250 AUTH=...» offer it, a list without AUTH does not;
 *  3. the installer: no in main.cf, yes for submission and smtps in master.cf; the panel's start runs the repair;
 *  4. with -De2e.vm=yes on the VM: port 25 does not offer AUTH after STARTTLS, port 587 does.
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixSubmissionAuthTest
 */
public class PostfixSubmissionAuthTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("== 1. The decision");
        check("main.cf already no: nothing", PostfixSubmissionAuth.decide("no", "yes", "yes") == PostfixSubmissionAuth.Action.NOTHING);
        check("yes, and master.cf turns it on for 587 and 465: apply",
                PostfixSubmissionAuth.decide("yes", "yes", "yes") == PostfixSubmissionAuth.Action.APPLY);
        check("465 without its own AUTH: left as it is", PostfixSubmissionAuth.decide("yes", "yes", "")
                == PostfixSubmissionAuth.Action.MASTER_NOT_READY);
        check("587 without its own AUTH: left as it is", PostfixSubmissionAuth.decide("yes", "no", "yes")
                == PostfixSubmissionAuth.Action.MASTER_NOT_READY);

        System.out.println("\n== 2. Reading the answer to EHLO");
        String with = "250-mail.example.test\n250-PIPELINING\n250-SIZE 52428800\n250-AUTH PLAIN LOGIN\n250-AUTH=PLAIN LOGIN\n250 CHUNKING\n";
        String without = "250-mail.example.test\n250-PIPELINING\n250-SIZE 52428800\n250-ENHANCEDSTATUSCODES\n250 CHUNKING\n";
        check("250-AUTH PLAIN LOGIN offers it", PostfixSubmissionAuth.offersAuth(with));
        check("250 AUTH=PLAIN as the last line offers it", PostfixSubmissionAuth.offersAuth("250-x\n250 AUTH=PLAIN\n"));
        check("a list without AUTH does not", !PostfixSubmissionAuth.offersAuth(without) && !PostfixSubmissionAuth.offersAuth(null));
        check("a word containing AUTH elsewhere does not", !PostfixSubmissionAuth.offersAuth("250-XAUTHORITY\n250 OK\n"));

        System.out.println("\n== 3. Where it is written");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("main.cf: smtpd_sasl_auth_enable = no", installer.contains("\nsmtpd_sasl_auth_enable = no\n")
                && !installer.contains("\nsmtpd_sasl_auth_enable = yes\n"));
        int sub = installer.indexOf("\nsubmission inet"), smtps = installer.indexOf("\nsmtps     inet");
        check("master.cf turns it on for submission and smtps",
                sub > 0 && installer.indexOf("-o smtpd_sasl_auth_enable=yes", sub) > sub
                && smtps > 0 && installer.indexOf("-o smtpd_sasl_auth_enable=yes", smtps) > smtps);
        check("the panel's start runs the repair", Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"))
                .contains("org.daemoxcp.mail.system.PostfixSubmissionAuth.ensureAtBoot();"));

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 4 skipped: it talks to ports 25 and 587 of the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            System.out.println("\n== 4. Live, with STARTTLS");
            check("port 25 does not offer AUTH", !PostfixSubmissionAuth.offersAuth(PostfixSubmissionAuth.ehlo(25)));
            check("port 587 offers AUTH", PostfixSubmissionAuth.offersAuth(PostfixSubmissionAuth.ehlo(587)));
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
