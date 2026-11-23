package org.daemoxcp.mail.system;

import org.json.JSONObject;

import java.time.Instant;

/**
 * The decisions behind installing FreeBSD patches from the panel (finding 185), with no system
 * underneath: the freebsd-update outputs are the ones seen on the test VM and on the real server.
 *
 *  1. target: the version from the tag file ("...|15.1-RELEASE|6|..." -> 15.1-RELEASE-p6).
 *  2. freebsd-update outputs: nothing to fetch, nothing to install, reboot then install again.
 *  3. rebootState: needed (installed kernel differs from the running one), advised (patches
 *     installed after the last boot), none (and what was done before the last boot).
 *  4. installConfig: the system configuration with CreateBootEnv no, exactly once.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.OsPatchTest
 */
public class OsPatchTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) {
        System.out.println("== 1. target ==");
        check("p6 from the real server's tag", OsPatch.target("freebsd-update|arm64|15.1-RELEASE|6|3b46c9fe530b8e80e7cc977d7619a523ace29a3ec12a38238635fb1d6fb1fa3c|1806537600")
                .equals("15.1-RELEASE-p6"));
        check("patch level 0 is the release itself", OsPatch.target("freebsd-update|amd64|14.3-RELEASE|0|abc|1806537600").equals("14.3-RELEASE"));
        check("a tag of another shape: empty", OsPatch.target("something else").isEmpty() && OsPatch.target(null).isEmpty()
                && OsPatch.target("freebsd-update|arm64|15.1-RELEASE|x|abc|1").isEmpty());

        System.out.println("\n== 2. freebsd-update outputs ==");
        check("nothing to fetch", OsPatch.nothingToFetch("src component not installed, skipped\nNo updates needed to update system to 15.1-RELEASE-p6.")
                && !OsPatch.nothingToFetch("The following files will be updated as part of updating to\n15.1-RELEASE-p6:"));
        check("nothing to install", OsPatch.nothingToInstall("src component not installed, skipped\nNo updates are available to install.")
                && !OsPatch.nothingToInstall("There are updates available to install."));
        check("reboot then install again (release upgrade)", OsPatch.asksRebootFirst(
                "Installing updates...\nKernel updates have been installed.  Please reboot and run\n'/usr/sbin/freebsd-update install' again to finish installing updates."));
        check("an ordinary patch does not ask for it", !OsPatch.asksRebootFirst("Creating snapshot of existing boot environment... done.\nInstalling updates... done."));

        System.out.println("\n== 3. rebootState ==");
        Instant boot = Instant.parse("2026-11-07T16:00:00Z");
        long before = boot.getEpochSecond() - 3600, after = boot.getEpochSecond() + 600;
        check("installed kernel differs from the running one: needed",
                OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE", after, boot, "15.1-RELEASE-p6").getString("state").equals("needed"));
        check("  even without patches from the panel (an update done by hand)",
                OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE-p3", 0, boot, "").getString("state").equals("needed"));
        check("patches installed after the boot, right kernel: advised",
                OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE-p6", after, boot, "15.1-RELEASE-p6").getString("state").equals("advised"));
        JSONObject done = OsPatch.rebootState("15.1-RELEASE-p6", "15.1-RELEASE-p6", before, boot, "15.1-RELEASE-p6");
        check("patches installed before the boot: none, and it says what was done", done.getString("state").equals("none")
                && done.optString("done").equals("15.1-RELEASE-p6"));
        check("nothing ever installed: none", OsPatch.rebootState("15.1-RELEASE", "15.1-RELEASE", 0, boot, "").getString("state").equals("none")
                && !OsPatch.rebootState("15.1-RELEASE", "15.1-RELEASE", 0, boot, "").has("done"));
        check("unreadable versions: no restart is made up", OsPatch.rebootState("", "15.1-RELEASE", 0, null, "").getString("state").equals("none"));

        System.out.println("\n== 4. installConfig ==");
        String system = "KeyPrint 800651ef4b4c71c27e60786d7b487188970f4b4169cc055784e21eb71d410cc5\nServerName update.FreeBSD.org\n"
                + "Components src world kernel\n# CreateBootEnv yes\nCreateBootEnv yes\n";
        String conf = OsPatch.installConfig(system);
        check("keeps the key, the server and the components", conf.contains("KeyPrint 800651ef") && conf.contains("ServerName update.FreeBSD.org")
                && conf.contains("Components src world kernel"));
        check("CreateBootEnv no, exactly once (freebsd-update refuses duplicates)",
                conf.lines().filter(l -> l.trim().startsWith("CreateBootEnv")).toList().equals(java.util.List.of("CreateBootEnv no")));
        check("the old comment stays", conf.contains("# CreateBootEnv yes"));

        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
