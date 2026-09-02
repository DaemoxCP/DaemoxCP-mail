package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Scarica le liste ufficiali di Cloudflare e le confronta con quelle compilate nel pannello.
 * E' la stessa funzione che la scheda mostra: qui la si esercita davvero, in rete.
 */
public class ProvaIntervalliCf {
    public static void main(String[] a) {
        JSONObject r = UpdateManager.intervalliCloudflare();
        System.out.println("verificato:  " + r.optBoolean("verificato", false));
        if (!r.optBoolean("success", false)) {
            System.out.println("ERRORE: " + r.optString("error", ""));
            System.exit(1);
        }
        System.out.println("ufficiali:   v4=" + r.optInt("ufficialiV4") + "  v6=" + r.optInt("ufficialiV6"));
        System.out.println("nel pannello: v4=" + r.optInt("compilatiV4") + "  v6=" + r.optInt("compilatiV6"));
        System.out.println("allineata:   " + r.optBoolean("allineata"));
        JSONArray m = r.optJSONArray("mancanti"), p = r.optJSONArray("inPiu");
        System.out.println("\nMANCANTI nel pannello (" + (m == null ? 0 : m.length()) + "):");
        for (int i = 0; m != null && i < m.length(); i++) System.out.println("   " + m.getString(i));
        System.out.println("IN PIU' nel pannello (" + (p == null ? 0 : p.length()) + "):");
        for (int i = 0; p != null && i < p.length(); i++) System.out.println("   " + p.getString(i));
        System.out.println("\n" + r.optString("nota", ""));
    }
}
