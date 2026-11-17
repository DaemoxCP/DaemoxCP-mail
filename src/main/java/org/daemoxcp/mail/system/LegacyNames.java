package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * I nomi che le versioni vecchie del pannello hanno lasciato sui server, e quelli di adesso.
 *
 * <p>Fino a fine ottobre 2026 il pannello scriveva sul disco e nei servizi nomi italiani: file e
 * cartelle, la jail della 443, i boot environment, le chiavi dello stato del salto di versione,
 * la frequenza del rapporto. Il codice adesso e' tutto in inglese (r26), ma i server gia' avviati
 * hanno ancora quei nomi, e il pannello nuovo li deve riconoscere per portarli ai nomi di adesso
 * senza rompere niente.
 *
 * <p>Quei nomi vecchi stanno in un posto solo, il file di dati legacy-names.json dentro il jar,
 * e non nel codice: e' una scelta del committente (30/10/2026). Ogni sezione e' un elenco di
 * coppie [vecchio, nuovo], nell'ordine in cui vanno applicate (dove conta: una cartella prima dei
 * file che contiene). Il codice chiede la sezione e non scrive mai un nome vecchio.
 *
 * <p>Quando nessun server avra' piu' una versione di prima, il file si svuota e il codice che lo
 * legge non trova piu' niente da fare.
 */
public final class LegacyNames {

    private static final Logger LOGGER = Logger.getLogger(LegacyNames.class.getName());
    static final String RESOURCE = "/legacy-names.json";

    private static volatile JSONObject data;

    private LegacyNames() {}

    private static JSONObject data() {
        JSONObject d = data;
        if (d != null) return d;
        try (InputStream in = LegacyNames.class.getResourceAsStream(RESOURCE)) {
            if (in == null) throw new IllegalStateException(RESOURCE + " is not in the jar");
            d = new JSONObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            // Senza il file le migrazioni non trovano niente da fare: il pannello parte lo stesso,
            // ma lo deve dire, perche' un server vecchio resterebbe a meta'.
            LOGGER.severe("[LegacyNames] cannot read " + RESOURCE + ": " + e);
            d = new JSONObject();
        }
        data = d;
        return d;
    }

    /** Le coppie [vecchio, nuovo] di una sezione, nell'ordine del file. */
    public static List<String[]> pairs(String section) {
        JSONArray a = data().optJSONArray(section);
        if (a == null) return List.of();
        List<String[]> out = new ArrayList<>();
        for (int i = 0; i < a.length(); i++) {
            JSONArray p = a.optJSONArray(i);
            if (p != null && p.length() == 2) out.add(new String[]{p.getString(0), p.getString(1)});
        }
        return Collections.unmodifiableList(out);
    }

    /** La stessa sezione come mappa vecchio -> nuovo, nell'ordine del file. */
    public static Map<String, String> map(String section) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String[] p : pairs(section)) m.put(p[0], p[1]);
        return m;
    }

    /** I nomi vecchi che oggi si chiamano {@code current}. */
    public static List<String> oldNamesOf(String section, String current) {
        List<String> out = new ArrayList<>();
        for (String[] p : pairs(section)) if (p[1].equals(current)) out.add(p[0]);
        return out;
    }

    /** Il nome di adesso: quello nuovo se {@code value} e' un nome vecchio, altrimenti com'e'. */
    public static String current(String section, String value) {
        if (value == null) return null;
        for (String[] p : pairs(section)) if (p[0].equals(value)) return p[1];
        return value;
    }

    /** Il nome vecchio della sezione che ne ha uno solo, o "" se non c'e'. */
    public static String single(String section) {
        List<String[]> p = pairs(section);
        return p.isEmpty() ? "" : p.get(0)[0];
    }
}
