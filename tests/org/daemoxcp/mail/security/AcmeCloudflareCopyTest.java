package org.daemoxcp.mail.security;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;

/**
 * The clear copy of the Cloudflare token that acme.sh keeps in its account.conf (SAVED_CF_Token, SAVED_CF_Account_ID),
 * removed: the panel passes the token at every run, and acme.sh never runs on its own (seen on the real server on
 * 17/11/2026, after the token in the database had been encrypted).
 *  1. only the SAVED_CF_ lines go; every other line stays byte for byte, with owner, group and permissions; no file
 *     left beside it; a second run has nothing to do;
 *  2. an account.conf that is a symbolic link, or a file with two names: left as it is (and its target untouched);
 *     no account.conf: nothing to do;
 *  3. the panel's code: after every acme.sh run that was given CF_Token, and at boot after AcmeUser.
 * As root on the TEST VM (owner nobody, in a temporary folder):
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.AcmeCloudflareCopyTest
 */
public class AcmeCloudflareCopyTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String KEEP = "ACCOUNT_EMAIL='postmaster@example.org'\nLOG_FILE=\"/var/log/acme.sh.log\"\nCERT_HOME='/var/db/acme/certs'\n";
    static final String CONF = "ACCOUNT_EMAIL='postmaster@example.org'\nSAVED_CF_Token='AbCdEf0123456789-AbCdEf0123456789_xyz12'\n"
            + "LOG_FILE=\"/var/log/acme.sh.log\"\nSAVED_CF_Account_ID='0123456789abcdef0123456789abcdef'\nCERT_HOME='/var/db/acme/certs'\n";

    static String attrs(Path p) {
        return Shell.run(Duration.ofSeconds(10), "stat", "-f", "%Su:%Sg %Lp", p.toString()).outputTrim();
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory(Path.of("/var/tmp"), "acme-cloudflare-copy-test");
        try {
            System.out.println("== 1. The copies removed, the rest as it was");
            Path conf = dir.resolve("account.conf");
            Files.writeString(conf, CONF);
            Shell.run(Duration.ofSeconds(10), "chown", "nobody:nobody", conf.toString());
            Files.setPosixFilePermissions(conf, PosixFilePermissions.fromString("rw-r-----"));
            AcmeCloudflareCopy.Report r = AcmeCloudflareCopy.forget(conf);
            System.out.println("    -> " + r.outcome() + ": " + r.detail());
            check("DONE, naming the two keys and never their values", r.outcome() == AcmeCloudflareCopy.Outcome.DONE
                    && r.detail().contains("SAVED_CF_Token") && r.detail().contains("SAVED_CF_Account_ID") && !r.detail().contains("AbCdEf"));
            check("every other line stays byte for byte", Files.readString(conf).equals(KEEP));
            check("owner, group and permissions as before (nobody:nobody 640): " + attrs(conf), attrs(conf).equals("nobody:nobody 640"));
            check("no file left beside it", Files.list(dir).count() == 1);
            check("a second run: nothing to do", AcmeCloudflareCopy.forget(conf).outcome() == AcmeCloudflareCopy.Outcome.NOTHING);

            System.out.println("\n== 2. What is left alone");
            Path target = dir.resolve("elsewhere.conf");
            Files.writeString(target, CONF);
            Path linked = dir.resolve("linked");
            Files.createDirectories(linked);
            Files.createSymbolicLink(linked.resolve("account.conf"), target);
            r = AcmeCloudflareCopy.forget(linked.resolve("account.conf"));
            check("an account.conf that is a link: LEFT, its target untouched", r.outcome() == AcmeCloudflareCopy.Outcome.LEFT
                    && Files.readString(target).equals(CONF));
            Path twoNames = dir.resolve("two-names");
            Files.createDirectories(twoNames);
            Files.createLink(twoNames.resolve("account.conf"), target);
            r = AcmeCloudflareCopy.forget(twoNames.resolve("account.conf"));
            check("an account.conf with two names: LEFT, the other name untouched", r.outcome() == AcmeCloudflareCopy.Outcome.LEFT
                    && Files.readString(target).equals(CONF));
            check("no account.conf: nothing to do", AcmeCloudflareCopy.forget(dir.resolve("missing/account.conf")).outcome()
                    == AcmeCloudflareCopy.Outcome.NOTHING);

            System.out.println("\n== 3. The panel's code");
            String manager = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/security/AcmeManager.java"));
            int run = manager.indexOf("return AcmeUser.run(l, args, env);");
            int after = manager.indexOf("if (env != null && env.containsKey(\"CF_Token\")) AcmeCloudflareCopy.afterRun(l);");
            check("after every acme.sh run given CF_Token, in a finally", run > 0 && after > run
                    && manager.substring(run, after).contains("} finally {"));
            int boot = manager.indexOf("AcmeUser.ensureAtBoot();");
            check("at boot, right after AcmeUser", boot > 0 && manager.indexOf("AcmeCloudflareCopy.ensureAtBoot();") > boot);
        } finally {
            Shell.run(Duration.ofSeconds(30), "rm", "-rf", dir.toString());
        }
        System.out.println("\n" + (failed == 0 ? "ALL OK" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
