package org.mail_panel.system;

import org.mail_panel.database.MailDatabase;
import org.mail_panel.i18n.I18n;
import org.mail_panel.security.CloudflareManager;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;

/**
 * "Set up everything" on a server installed from scratch (reperto 250, found following the installation guide on a
 * clean VM):
 *  1. the MTA-STS policy is written readable by nginx (folder 0755, file 0644) even when the panel runs with umask
 *     077, as the service does: before, they were born 0700 and 0600 and nginx answered 403;
 *  2. the servers where it was already written that way are repaired at boot; links are never followed: a link in
 *     place of the folder or of the file is left as it is and said;
 *  3. before touching anything, a Cloudflare account that sees the domain's zone: the domain's own, or the only
 *     account of the panel that sees it (then assigned); no account, none that sees it, or several: refused, with
 *     what to do.
 * Run it with the service's umask, as root on the TEST VM:
 *   sh -c 'umask 077; java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SetUpEverythingTest'
 */
public class SetUpEverythingTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String perms(Path p) throws Exception {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS));
    }

    static MailDatabase.CloudflareAccount account(int id, String label) {
        MailDatabase.CloudflareAccount a = new MailDatabase.CloudflareAccount();
        a.id = id;
        a.label = label;
        a.apiToken = "token-" + id;
        return a;
    }

    static CloudflareManager.ZoneLookup sees(String zone) { return new CloudflareManager.ZoneLookup(true, "id-" + zone, zone, null); }

    static CloudflareManager.ZoneLookup blind(String error) { return new CloudflareManager.ZoneLookup(false, null, null, error); }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("public-policy-test");
        try {
            System.out.println("== 1. Writing the policy");
            Path dir = root.resolve("public"), file = dir.resolve("mta-sts.txt");
            PublicPolicyAccess.write(dir, file, "version: STSv1\nmode: testing\n");
            check("a new folder, under the service's umask: 0755 (" + perms(dir) + ")", perms(dir).equals("rwxr-xr-x"));
            check("the policy: 0644 (" + perms(file) + ")", perms(file).equals("rw-r--r--"));
            check("the policy's text", Files.readString(file).equals("version: STSv1\nmode: testing\n"));
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            PublicPolicyAccess.write(dir, file, "version: STSv1\nmode: enforce\n");
            check("written again over 0700 and 0600: 0755 and 0644, new text", perms(dir).equals("rwxr-xr-x")
                    && perms(file).equals("rw-r--r--") && Files.readString(file).contains("enforce"));
            check("nothing left beside it", Files.list(dir).count() == 1);
            Path outside = root.resolve("outside.txt");
            Files.writeString(outside, "not to be touched");
            Files.setPosixFilePermissions(outside, PosixFilePermissions.fromString("rw-------"));
            Files.createSymbolicLink(dir.resolve(".mta-sts.txt.new"), outside);
            PublicPolicyAccess.write(dir, file, "version: STSv1\nmode: testing\n");
            check("a link planted where the new file is written: removed, its target untouched",
                    Files.readString(outside).equals("not to be touched") && perms(outside).equals("rw-------")
                    && Files.readString(file).contains("testing") && Files.list(dir).count() == 1);
            Path realDir = root.resolve("real-dir"), linkedDir = root.resolve("linked-dir");
            Files.createDirectory(realDir);
            Files.setPosixFilePermissions(realDir, PosixFilePermissions.fromString("rwx------"));
            Files.createSymbolicLink(linkedDir, realDir);
            boolean refused;
            try { PublicPolicyAccess.write(linkedDir, linkedDir.resolve("mta-sts.txt"), "x"); refused = false; }
            catch (java.io.IOException e) { refused = true; }
            check("a link in place of the folder: refused, its target untouched", refused
                    && perms(realDir).equals("rwx------") && Files.list(realDir).count() == 0);

            System.out.println("\n== 2. Repaired at boot");
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
            PublicPolicyAccess.Report r = PublicPolicyAccess.repair(dir, file);
            check("0700 and 0600: DONE (" + r.detail() + ")", r.outcome() == PublicPolicyAccess.Outcome.DONE
                    && perms(dir).equals("rwxr-xr-x") && perms(file).equals("rw-r--r--"));
            check("a second start: nothing to do", PublicPolicyAccess.repair(dir, file).outcome() == PublicPolicyAccess.Outcome.NOTHING);
            check("no folder: nothing to do", PublicPolicyAccess.repair(root.resolve("missing"), root.resolve("missing/x")).outcome()
                    == PublicPolicyAccess.Outcome.NOTHING);
            r = PublicPolicyAccess.repair(linkedDir, linkedDir.resolve("mta-sts.txt"));
            check("a link in place of the folder: LEFT, its target untouched (" + r.detail() + ")",
                    r.outcome() == PublicPolicyAccess.Outcome.LEFT && perms(realDir).equals("rwx------"));
            Files.delete(file);
            Files.createSymbolicLink(file, outside);
            r = PublicPolicyAccess.repair(dir, file);
            check("a link in place of the policy: LEFT, its target still 0600", r.outcome() == PublicPolicyAccess.Outcome.LEFT
                    && perms(outside).equals("rw-------"));
        } finally {
            try (var w = Files.walk(root)) { w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }

        System.out.println("\n== 3. The Cloudflare account, before touching anything");
        MailDatabase.CloudflareAccount mine = account(1, "Main"), other = account(2, "Other");
        DomainSetup.CloudflareChoice c = DomainSetup.choose("example.org", mine, List.of(mine, other), a -> sees("example.org"));
        check("the domain's own account sees the zone: ready, nothing assigned", c.ready() && c.assigned() == null);
        c = DomainSetup.choose("example.org", mine, List.of(mine), a -> blind("no zone"));
        check("its own account does not see the zone: refused, saying which account",
                !c.ready() && c.error().equals(I18n.tr("server.cfgdom.cfZoneNotSeen", Map.of("a", "Main", "d", "example.org", "e", "no zone"))));
        c = DomainSetup.choose("example.org", null, List.of(), a -> sees("example.org"));
        check("no account in the panel: refused", !c.ready()
                && c.error().equals(I18n.tr("server.cfgdom.cfNone", Map.of("d", "example.org"))));
        c = DomainSetup.choose("example.org", null, List.of(mine, other), a -> a.id == 2 ? sees("example.org") : blind("not here"));
        check("only one account of two sees the zone: ready, and that one assigned", c.ready() && c.assigned() == other);
        c = DomainSetup.choose("example.org", null, List.of(mine, other), a -> blind("not here"));
        check("no account sees the zone: refused, listing them", !c.ready()
                && c.error().equals(I18n.tr("server.cfgdom.cfNoneSees", Map.of("d", "example.org", "list", "Main, Other"))));
        c = DomainSetup.choose("example.org", null, List.of(mine, other), a -> sees("example.org"));
        check("two accounts see the zone: refused, the choice is the administrator's", !c.ready() && c.assigned() == null
                && c.error().equals(I18n.tr("server.cfgdom.cfSeveral", Map.of("d", "example.org", "list", "Main, Other"))));
        c = DomainSetup.choose("example.org", null, List.of(mine), a -> null);
        check("Cloudflare does not answer: refused", !c.ready());

        System.out.println("\n" + (failed == 0 ? "ALL OK" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
