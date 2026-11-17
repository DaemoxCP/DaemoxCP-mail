package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Downloads Cloudflare's official lists and compares them with the ones compiled into the panel.
 * It is the same function the card shows: here it is exercised for real, over the network.
 */
public class CloudflareRangesTest {
    public static void main(String[] a) {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");   // the panel's note, printed at the end, in English
        JSONObject r = UpdateManager.cloudflareRanges();
        System.out.println("verified:    " + r.optBoolean("verified", false));
        if (!r.optBoolean("success", false)) {
            System.out.println("ERROR: " + r.optString("error", ""));
            System.exit(1);
        }
        System.out.println("official:    v4=" + r.optInt("officialV4") + "  v6=" + r.optInt("officialV6"));
        System.out.println("in the panel: v4=" + r.optInt("compiledV4") + "  v6=" + r.optInt("compiledV6"));
        System.out.println("aligned:     " + r.optBoolean("aligned"));
        JSONArray m = r.optJSONArray("missing"), p = r.optJSONArray("extra");
        System.out.println("\nMISSING from the panel (" + (m == null ? 0 : m.length()) + "):");
        for (int i = 0; m != null && i < m.length(); i++) System.out.println("   " + m.getString(i));
        System.out.println("EXTRA in the panel (" + (p == null ? 0 : p.length()) + "):");
        for (int i = 0; p != null && i < p.length(); i++) System.out.println("   " + p.getString(i));
        System.out.println("\n" + r.optString("note", ""));
    }
}
