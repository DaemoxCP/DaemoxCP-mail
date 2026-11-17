package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * La porta 25 in uscita: il server puo' consegnare la posta agli altri server? (reperto 246)
 *
 * <p>Molti provider la chiudono sugli account nuovi: Hetzner Cloud chiude 25 e 465 in uscita e le apre su richiesta,
 * dopo la prima fattura pagata. Con la 25 chiusa la posta in arrivo funziona e quella in uscita resta in coda senza
 * che niente lo dica chiaramente. Qui ci si collega alla 25 di tre server di posta grandi, si legge solo il saluto
 * (220), si scrive QUIT e si chiude: nessun messaggio, nessun indirizzo. Basta una connessione riuscita per dire che la
 * porta e' aperta; se nessuno risponde e i nomi si risolvono, e' chiusa.
 */
public final class OutboundSmtp {

    private OutboundSmtp() {}

    /** Server che rispondono sempre sulla 25: Gmail, iCloud, Outlook.com (i loro MX). */
    static final List<String> HOSTS = List.of("gmail-smtp-in.l.google.com", "mx01.mail.icloud.com",
            "outlook-com.olc.protection.outlook.com");
    static final int TIMEOUT_MS = 8000;

    /** Il saluto di un server sulla porta 25, o un'eccezione. */
    interface Dialer {
        String banner(String host) throws IOException;
    }

    static Dialer dialer = host -> {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, 25), TIMEOUT_MS);
            s.setSoTimeout(TIMEOUT_MS);
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
            String line;
            try {
                line = in.readLine();
            } catch (java.net.SocketTimeoutException e) {
                line = "";   // collegati, ma nessun saluto in tempo: la porta e' comunque aperta
            }
            OutputStream out = s.getOutputStream();
            out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            return line == null ? "" : line;
        }
    };

    /** open (almeno una connessione riuscita), blocked (nomi risolti, nessuna connessione), unknown (nessun nome risolto). */
    public static JSONObject check() {
        JSONArray tried = new JSONArray();
        int resolved = 0;
        String openOn = null;
        for (String host : HOSTS) {
            JSONObject t = new JSONObject().put("host", host);
            try {
                String b = dialer.banner(host);
                resolved++;
                // Collegati: la porta e' aperta, anche se il saluto non e' 220 (un rifiuto e' pur sempre una risposta).
                t.put("result", b.startsWith("220") ? "greeted" : "answered");
                if (openOn == null) openOn = host;
            } catch (UnknownHostException e) {
                t.put("result", "noName");
            } catch (IOException e) {
                resolved++;
                t.put("result", "noConnection");
            }
            tried.put(t);
            if (openOn != null) break;
        }
        String state = openOn != null ? "open" : resolved > 0 ? "blocked" : "unknown";
        return new JSONObject().put("success", true).put("state", state).put("tried", tried)
                .put("openOn", openOn == null ? "" : openOn);
    }
}
