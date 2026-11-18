package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

/**
 * The driver of menu item 6 (ReinstallReturn.goBack on the most recent reinstallation way back),
 * without the confirmation window and without rebooting: whoever runs it reboots. Like
 * MenuReinstall, only on a test clone.
 *   java -De2e.vm=yes -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.MenuGoBack
 */
public class MenuGoBack {
    public static void main(String[] args) {
        // A driver, not a test: it changes the machine. Without -De2e.vm=yes it stops, like the E2E tests, so that running
        // every class that has a main (the suite on the VM) never goes back, reinstalls or creates a boot environment.
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: a driver that changes the machine: it needs -De2e.vm=yes (a test clone on the FreeBSD VM, as root).");
            return;
        }
        I18n.setCurrent("en");
        String name = ReinstallReturn.latest();
        System.out.println("=== going back to " + (name.isEmpty() ? "(no way back)" : name) + " ===");
        JSONObject r = ReinstallReturn.goBack(name, line -> System.out.println("[WAY BACK] " + line));
        System.out.println(r.optBoolean("success") ? "[WAY BACK] " + r.optString("note") : "[STOPPED] " + r.optString("error"));
        System.out.println("=== outcome: " + (r.optBoolean("success") ? "succeeded" : "FAILED") + " ===");
        System.exit(r.optBoolean("success") ? 0 : 1);
    }
}
