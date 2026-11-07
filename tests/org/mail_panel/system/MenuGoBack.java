package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;

/**
 * The driver of menu item 6 (ReinstallReturn.goBack on the most recent reinstallation way back),
 * without the confirmation window and without rebooting: whoever runs it reboots. Like
 * MenuReinstall, only on a test clone.
 *   java -cp "tests:freebsd-mail-panel-1.0.jar" org.mail_panel.system.MenuGoBack
 */
public class MenuGoBack {
    public static void main(String[] args) {
        I18n.setCurrent("en");
        String name = ReinstallReturn.latest();
        System.out.println("=== going back to " + (name.isEmpty() ? "(no way back)" : name) + " ===");
        JSONObject r = ReinstallReturn.goBack(name, line -> System.out.println("[WAY BACK] " + line));
        System.out.println(r.optBoolean("success") ? "[WAY BACK] " + r.optString("note") : "[STOPPED] " + r.optString("error"));
        System.out.println("=== outcome: " + (r.optBoolean("success") ? "succeeded" : "FAILED") + " ===");
        System.exit(r.optBoolean("success") ? 0 : 1);
    }
}
