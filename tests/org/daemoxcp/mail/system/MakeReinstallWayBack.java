package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;

/**
 * For the on-screen menu tests: creates a reinstallation's way back (as the reinstallation creates
 * it, PackageWayBack.beforeInstallation) and prints its name. Only on a test clone.
 *   java -cp "tests:daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.MakeReinstallWayBack
 */
public class MakeReinstallWayBack {
    public static void main(String[] args) {
        I18n.setCurrent("en");
        PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(line -> { });
        System.out.println(p.name());
        System.exit(p.name().isEmpty() ? 1 : 0);
    }
}
