package org.daemoxcp.mail.security;

import org.daemoxcp.mail.i18n.I18n;

/**
 * The country names live in the language files (country.<code>), and the key is built from the
 * code: check_lang.py cannot check it. A country without its key would show "country.xx" on the
 * page without errors. Here every country of the catalog, in both languages.
 */
public class CountryNamesTest {

    private static int failures = 0;

    public static void main(String[] args) {
        java.util.Map<String, org.json.JSONObject> files = new java.util.HashMap<>();
        try {
            // Each language's file is read, not localName(): a key missing in English falls back to
            // Italian, and the English page would show the Italian name without errors.
            for (String lang : new String[] {"it", "en"}) {
                org.json.JSONObject file;
                try (java.io.InputStream in = I18n.class.getResourceAsStream("/lang/" + lang + ".json")) {
                    file = new org.json.JSONObject(new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
                } catch (java.io.IOException e) { throw new java.io.UncheckedIOException(e); }
                files.put(lang, file);
                int missing = 0;
                for (CountryCatalog.Country c : CountryCatalog.getAll()) {
                    if (file.optString("country." + c.code(), "").isBlank()) {
                        missing++;
                        if (missing <= 5) System.out.println("  missing in " + lang + ".json: country." + c.code());
                    }
                }
                check(lang + ".json: every country of the catalog (" + CountryCatalog.getAll().size() + ") has its name", missing == 0);
            }
            // The Italian names were chosen by hand (it.json); the expected ones come from that file.
            org.json.JSONObject it = files.get("it");
            I18n.setCurrent("it");
            check("in Italian the names chosen by hand (it.json): it, cz, cw",
                    it.getString("country.it").equals(CountryCatalog.byCode("it").localName())
                    && it.getString("country.cz").equals(CountryCatalog.byCode("cz").localName())
                    && it.getString("country.cw").equals(CountryCatalog.byCode("cw").localName())
                    && !it.getString("country.cz").equals("Czechia"));
            I18n.setCurrent("en");
            check("in English the earlier ones (CLDR): Italy, Czechia, Curaçao",
                    "Italy".equals(CountryCatalog.byCode("it").localName())
                    && "Czechia".equals(CountryCatalog.byCode("cz").localName())
                    && "Curaçao".equals(CountryCatalog.byCode("cw").localName()));
            check("and in the JSON for the page the name is the language's", "Italy".equals(CountryCatalog.byCode("it").toJson().getString("name")));
        } finally {
            I18n.clearCurrent();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }
}
