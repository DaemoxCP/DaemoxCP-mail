package org.daemoxcp.mail.system;

import java.util.List;

/**
 * The services restarted after updating a package.
 *
 * Measured on latest on 24/10/2026: guided update of clamav 1.5.4_1,1 -> 1.5.4_2,1, "clamav in
 * service", but only clamd restarted. freshclam, which comes from the same package and loads the
 * same libclamav, was still running the old program: started at 10:48, package updated at 14:58,
 * and procstat no longer found its executable. The package -> service table gave a single service
 * per package.
 *
 * The direct part of the table asks pkg nothing, so this test runs anywhere.
 */
public class RestartServicesTest {

    private static int failures = 0;

    public static void main(String[] args) {
        List<String> clamav = UpdateManager.servicesToRestart("clamav");
        check("clamav: clamd restarts " + clamav, clamav.contains("clamav_clamd"));
        check("clamav: and freshclam too", clamav.contains("clamav_freshclam"));
        check("clamav: once each", clamav.stream().distinct().count() == clamav.size());
        check("nginx: only nginx " + UpdateManager.servicesToRestart("nginx"),
                UpdateManager.servicesToRestart("nginx").contains("nginx")
                && !UpdateManager.servicesToRestart("nginx").contains("clamav_freshclam"));
        check("a package that runs nothing: no direct service",
                !UpdateManager.servicesToRestart("xorgproto").contains("clamav_clamd"));
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
