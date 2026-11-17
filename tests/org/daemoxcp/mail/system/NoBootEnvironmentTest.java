package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;

/**
 * A system WITHOUT boot environments (UFS, or ZFS without bectl): reinstalling and going back do not
 * break and say so (reperto 172). It is simulated with a fake bectl first in the PATH that always
 * fails (Shell puts the inherited PATH before the system folders), in a child process.
 *  - the reinstall's way back is not created and that is said, without stopping anything;
 *  - the space check is not done (there is nothing to keep occupied);
 *  - after the installation nothing is touched;
 *  - going back: no way back, and any name is refused;
 *  - the boot environments card says there are none.
 * Usage: java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.NoBootEnvironmentTest
 */
public class NoBootEnvironmentTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(); return; }
        Path d = Files.createTempDirectory("no-bectl");
        int code;
        try {
            Path fake = d.resolve("bectl");
            Files.writeString(fake, "#!/bin/sh\necho \"bectl: libbe_init(\\\"\\\") failed.\" >&2\nexit 1\n");
            Files.setPosixFilePermissions(fake, PosixFilePermissions.fromString("rwxr-xr-x"));
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            ProcessBuilder pb = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    NoBootEnvironmentTest.class.getName(), "child").inheritIO();
            pb.environment().put("PATH", d + ":" + System.getenv("PATH"));
            code = pb.start().waitFor();
        } finally {
            // System.exit used to be inside the try: the finally did not run and the folder stayed in /tmp.
            Files.deleteIfExists(d.resolve("bectl"));
            Files.deleteIfExists(d);
        }
        System.exit(code);
    }

    static void child() {
        I18n.setCurrent("en");
        List<String> log = new ArrayList<>();
        PackageWayBack.Prepared p;
        try {
            p = PackageWayBack.beforeInstallation(log::add);
        } catch (IllegalStateException e) {
            // The NB1 fault (reperto 172) ended up here: an exception instead of the check.
            check("the way back is not created, without exceptions: " + e.getMessage(), false);
            p = new PackageWayBack.Prepared("", "");
        }
        check("the way back is not created, without exceptions", p.name().isEmpty());
        check("and it says so", String.join("\n", log).contains("no ZFS boot environments"));
        log.clear();
        check("the space check stops nothing", PackageWayBack.reinstallSpace(log::add) == null && log.isEmpty());
        PackageWayBack.afterInstallation(log::add, p, true);
        check("after the installation nothing is touched", log.isEmpty());
        check("going back: no way back", ReinstallReturn.latest().isEmpty());
        JSONObject r = ReinstallReturn.goBack("reinstall-before-2026-11-06-120000", log::add);
        check("and any name is refused", !r.optBoolean("success") && r.optString("error").contains("not there any more"));
        JSONObject be = UpdateManager.bootEnvironments();
        check("the card says there are no boot environments", !be.optBoolean("success") && !be.optString("error").isEmpty());
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
