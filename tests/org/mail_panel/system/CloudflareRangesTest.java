package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Scarica le liste ufficiali di Cloudflare e le confronta con quelle compilate nel pannello.
 * E' la stessa funzione che la scheda mostra: qui la si esercita davvero, in rete.
 */
public class CloudflareRangesTest {
    public static void main(String[] a) {
        JSONObject r = UpdateManager.cloudflareRanges();
        System.out.println("verificato:  " + r.optBoolean("verified", false));
        if (!r.optBoolean("success", false)) {
            System.out.println("ERRORE: " + r.optString("error", ""));
            System.exit(1);
        }
        System.out.println("ufficiali:   v4=" + r.optInt("officialV4") + "  v6=" + r.optInt("officialV6"));
        System.out.println("nel pannello: v4=" + r.optInt("compiledV4") + "  v6=" + r.optInt("compiledV6"));
        System.out.println("allineata:   " + r.optBoolean("aligned"));
        JSONArray m = r.optJSONArray("missing"), p = r.optJSONArray("extra");
        System.out.println("\nMANCANTI nel pannello (" + (m == null ? 0 : m.length()) + "):");
        for (int i = 0; m != null && i < m.length(); i++) System.out.println("   " + m.getString(i));
        System.out.println("IN PIU' nel pannello (" + (p == null ? 0 : p.length()) + "):");
        for (int i = 0; p != null && i < p.length(); i++) System.out.println("   " + p.getString(i));
        System.out.println("\n" + r.optString("note", ""));
    }
}
