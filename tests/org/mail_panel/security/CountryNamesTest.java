package org.mail_panel.security;

import org.mail_panel.i18n.I18n;

/**
 * I nomi dei paesi stanno nei file di lingua (country.<codice>), e la chiave si costruisce dal
 * codice: check_lang.py non la puo' controllare. Un paese senza la sua chiave mostrerebbe in
 * pagina "country.xx" senza errori. Qui ogni paese del catalogo, in tutte e due le lingue.
 */
public class CountryNamesTest {

    private static int failures = 0;

    public static void main(String[] args) {
        try {
            // Si guarda il file di ogni lingua, non localName(): una chiave che manca in inglese
            // ricade sull'italiano, e la pagina inglese mostrerebbe "Repubblica Ceca" senza errori.
            for (String lang : new String[] {"it", "en"}) {
                org.json.JSONObject file;
                try (java.io.InputStream in = I18n.class.getResourceAsStream("/lang/" + lang + ".json")) {
                    file = new org.json.JSONObject(new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
                } catch (java.io.IOException e) { throw new java.io.UncheckedIOException(e); }
                int missing = 0;
                for (CountryCatalog.Country c : CountryCatalog.getAll()) {
                    if (file.optString("country." + c.code(), "").isBlank()) {
                        missing++;
                        if (missing <= 5) System.out.println("  manca in " + lang + ".json: country." + c.code());
                    }
                }
                check(lang + ".json: ogni paese del catalogo (" + CountryCatalog.getAll().size() + ") ha il suo nome", missing == 0);
            }
            I18n.setCurrent("it");
            check("in italiano i nomi scelti a mano: Italia, Repubblica Ceca, Curacao",
                    "Italia".equals(CountryCatalog.byCode("it").localName())
                    && "Repubblica Ceca".equals(CountryCatalog.byCode("cz").localName())
                    && "Curacao".equals(CountryCatalog.byCode("cw").localName()));
            I18n.setCurrent("en");
            check("in inglese quelli di prima (CLDR): Italy, Czechia, Curaçao",
                    "Italy".equals(CountryCatalog.byCode("it").localName())
                    && "Czechia".equals(CountryCatalog.byCode("cz").localName())
                    && "Curaçao".equals(CountryCatalog.byCode("cw").localName()));
            check("e nel JSON per la pagina il nome e' quello della lingua", "Italy".equals(CountryCatalog.byCode("it").toJson().getString("name")));
        } finally {
            I18n.clearCurrent();
        }
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }
}
