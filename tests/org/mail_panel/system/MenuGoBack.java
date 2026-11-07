package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;

/**
 * Il conduttore della voce 6 del menu (ReinstallReturn.goBack sulla via di ritorno di reinstallazione
 * piu' recente), senza la finestra di conferma e senza riavviare: il riavvio lo fa chi lo lancia. Come
 * MenuReinstall, solo su un clone di prova.
 *   java -cp "tests:freebsd-mail-panel-1.0.jar" org.mail_panel.system.MenuGoBack
 */
public class MenuGoBack {
    public static void main(String[] args) {
        I18n.setCurrent("en");
        String name = ReinstallReturn.latest();
        System.out.println("=== ritorno a " + (name.isEmpty() ? "(nessuna via di ritorno)" : name) + " ===");
        JSONObject r = ReinstallReturn.goBack(name, line -> System.out.println("[WAY BACK] " + line));
        System.out.println(r.optBoolean("success") ? "[WAY BACK] " + r.optString("note") : "[STOPPED] " + r.optString("error"));
        System.out.println("=== esito: " + (r.optBoolean("success") ? "riuscito" : "FALLITO") + " ===");
        System.exit(r.optBoolean("success") ? 0 : 1);
    }
}
