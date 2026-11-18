package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;

/**
 * For the on-screen menu tests: creates a reinstallation's way back (as the reinstallation creates
 * it, PackageWayBack.beforeInstallation) and prints its name. Only on a test clone.
 *   java -De2e.vm=yes -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.MakeReinstallWayBack
 */
public class MakeReinstallWayBack {
    public static void main(String[] args) {
        // A driver, not a test: it changes the machine. Without -De2e.vm=yes it stops, like the E2E tests, so that running
        // every class that has a main (the suite on the VM) never goes back, reinstalls or creates a boot environment.
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: a driver that changes the machine: it needs -De2e.vm=yes (a test clone on the FreeBSD VM, as root).");
            return;
        }
        I18n.setCurrent("en");
        PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(line -> { });
        System.out.println(p.name());
        System.exit(p.name().isEmpty() ? 1 : 0);
    }
}
