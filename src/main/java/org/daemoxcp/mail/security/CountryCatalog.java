package org.daemoxcp.mail.security;

import java.util.*;

import org.daemoxcp.mail.i18n.I18n;

/**
 * Catalogo paesi ISO-3166-1 alpha-2 con flag emoji; i nomi stanno nei file di lingua (country.<codice>).
 *
 * Lista completa di ~250 paesi/territori. La proprieta' "common" indica
 * i paesi piu' frequentemente usati come whitelist per server europei
 * (mostrati in cima alla UI per comodita').
 *
 * Source: ISO-3166-1. I nomi italiani sono quelli scelti a mano (senza accenti, Repubblica Ceca);
 * quelli inglesi vengono da CLDR, come li mostrava la pagina prima che stessero nei file di lingua.
 */
public final class CountryCatalog {

    public record Country(String code, String flag, boolean common) {
        /** Il nome nella lingua della richiesta, dai file di lingua (country.<codice>). */
        public String localName() {
            return I18n.tr("country." + code);
        }

        public org.json.JSONObject toJson() {
            return new org.json.JSONObject()
                .put("code", code)
                .put("name", localName())
                .put("flag", flag)
                .put("common", common);
        }
    }

    private static final List<Country> COUNTRIES = List.of(
        // ==== Paesi comuni in cima (Europa + grandi paesi) ====
        new Country("it", "🇮🇹", true),
        new Country("fr", "🇫🇷", true),
        new Country("de", "🇩🇪", true),
        new Country("es", "🇪🇸", true),
        new Country("gb", "🇬🇧", true),
        new Country("ch", "🇨🇭", true),
        new Country("at", "🇦🇹", true),
        new Country("nl", "🇳🇱", true),
        new Country("be", "🇧🇪", true),
        new Country("pt", "🇵🇹", true),
        new Country("ie", "🇮🇪", true),
        new Country("se", "🇸🇪", true),
        new Country("no", "🇳🇴", true),
        new Country("dk", "🇩🇰", true),
        new Country("fi", "🇫🇮", true),
        new Country("pl", "🇵🇱", true),
        new Country("cz", "🇨🇿", true),
        new Country("gr", "🇬🇷", true),
        new Country("us", "🇺🇸", true),
        new Country("ca", "🇨🇦", true),
        new Country("au", "🇦🇺", true),
        new Country("nz", "🇳🇿", true),
        new Country("jp", "🇯🇵", true),

        // ==== Resto del mondo (alfabetico) ====
        new Country("ad", "🇦🇩", false),
        new Country("ae", "🇦🇪", false),
        new Country("af", "🇦🇫", false),
        new Country("ag", "🇦🇬", false),
        new Country("ai", "🇦🇮", false),
        new Country("al", "🇦🇱", false),
        new Country("am", "🇦🇲", false),
        new Country("ao", "🇦🇴", false),
        new Country("aq", "🇦🇶", false),
        new Country("ar", "🇦🇷", false),
        new Country("as", "🇦🇸", false),
        new Country("aw", "🇦🇼", false),
        new Country("ax", "🇦🇽", false),
        new Country("az", "🇦🇿", false),
        new Country("ba", "🇧🇦", false),
        new Country("bb", "🇧🇧", false),
        new Country("bd", "🇧🇩", false),
        new Country("bf", "🇧🇫", false),
        new Country("bg", "🇧🇬", false),
        new Country("bh", "🇧🇭", false),
        new Country("bi", "🇧🇮", false),
        new Country("bj", "🇧🇯", false),
        new Country("bl", "🇧🇱", false),
        new Country("bm", "🇧🇲", false),
        new Country("bn", "🇧🇳", false),
        new Country("bo", "🇧🇴", false),
        new Country("bq", "🇧🇶", false),
        new Country("br", "🇧🇷", false),
        new Country("bs", "🇧🇸", false),
        new Country("bt", "🇧🇹", false),
        new Country("bw", "🇧🇼", false),
        new Country("by", "🇧🇾", false),
        new Country("bz", "🇧🇿", false),
        new Country("cc", "🇨🇨", false),
        new Country("cd", "🇨🇩", false),
        new Country("cf", "🇨🇫", false),
        new Country("cg", "🇨🇬", false),
        new Country("ci", "🇨🇮", false),
        new Country("ck", "🇨🇰", false),
        new Country("cl", "🇨🇱", false),
        new Country("cm", "🇨🇲", false),
        new Country("cn", "🇨🇳", false),
        new Country("co", "🇨🇴", false),
        new Country("cr", "🇨🇷", false),
        new Country("cu", "🇨🇺", false),
        new Country("cv", "🇨🇻", false),
        new Country("cw", "🇨🇼", false),
        new Country("cx", "🇨🇽", false),
        new Country("cy", "🇨🇾", false),
        new Country("dj", "🇩🇯", false),
        new Country("dm", "🇩🇲", false),
        new Country("do", "🇩🇴", false),
        new Country("dz", "🇩🇿", false),
        new Country("ec", "🇪🇨", false),
        new Country("ee", "🇪🇪", false),
        new Country("eg", "🇪🇬", false),
        new Country("eh", "🇪🇭", false),
        new Country("er", "🇪🇷", false),
        new Country("et", "🇪🇹", false),
        new Country("fj", "🇫🇯", false),
        new Country("fk", "🇫🇰", false),
        new Country("fm", "🇫🇲", false),
        new Country("fo", "🇫🇴", false),
        new Country("ga", "🇬🇦", false),
        new Country("gd", "🇬🇩", false),
        new Country("ge", "🇬🇪", false),
        new Country("gf", "🇬🇫", false),
        new Country("gg", "🇬🇬", false),
        new Country("gh", "🇬🇭", false),
        new Country("gi", "🇬🇮", false),
        new Country("gl", "🇬🇱", false),
        new Country("gm", "🇬🇲", false),
        new Country("gn", "🇬🇳", false),
        new Country("gp", "🇬🇵", false),
        new Country("gq", "🇬🇶", false),
        new Country("gt", "🇬🇹", false),
        new Country("gu", "🇬🇺", false),
        new Country("gw", "🇬🇼", false),
        new Country("gy", "🇬🇾", false),
        new Country("hk", "🇭🇰", false),
        new Country("hn", "🇭🇳", false),
        new Country("hr", "🇭🇷", false),
        new Country("ht", "🇭🇹", false),
        new Country("hu", "🇭🇺", false),
        new Country("id", "🇮🇩", false),
        new Country("il", "🇮🇱", false),
        new Country("im", "🇮🇲", false),
        new Country("in", "🇮🇳", false),
        new Country("io", "🇮🇴", false),
        new Country("iq", "🇮🇶", false),
        new Country("ir", "🦁", false),
        new Country("is", "🇮🇸", false),
        new Country("je", "🇯🇪", false),
        new Country("jm", "🇯🇲", false),
        new Country("jo", "🇯🇴", false),
        new Country("ke", "🇰🇪", false),
        new Country("kg", "🇰🇬", false),
        new Country("kh", "🇰🇭", false),
        new Country("ki", "🇰🇮", false),
        new Country("km", "🇰🇲", false),
        new Country("kn", "🇰🇳", false),
        new Country("kp", "🇰🇵", false),
        new Country("kr", "🇰🇷", false),
        new Country("kw", "🇰🇼", false),
        new Country("ky", "🇰🇾", false),
        new Country("kz", "🇰🇿", false),
        new Country("la", "🇱🇦", false),
        new Country("lb", "🇱🇧", false),
        new Country("lc", "🇱🇨", false),
        new Country("li", "🇱🇮", false),
        new Country("lk", "🇱🇰", false),
        new Country("lr", "🇱🇷", false),
        new Country("ls", "🇱🇸", false),
        new Country("lt", "🇱🇹", false),
        new Country("lu", "🇱🇺", false),
        new Country("lv", "🇱🇻", false),
        new Country("ly", "🇱🇾", false),
        new Country("ma", "🇲🇦", false),
        new Country("mc", "🇲🇨", false),
        new Country("md", "🇲🇩", false),
        new Country("me", "🇲🇪", false),
        new Country("mf", "🇲🇫", false),
        new Country("mg", "🇲🇬", false),
        new Country("mh", "🇲🇭", false),
        new Country("mk", "🇲🇰", false),
        new Country("ml", "🇲🇱", false),
        new Country("mm", "🇲🇲", false),
        new Country("mn", "🇲🇳", false),
        new Country("mo", "🇲🇴", false),
        new Country("mp", "🇲🇵", false),
        new Country("mq", "🇲🇶", false),
        new Country("mr", "🇲🇷", false),
        new Country("ms", "🇲🇸", false),
        new Country("mt", "🇲🇹", false),
        new Country("mu", "🇲🇺", false),
        new Country("mv", "🇲🇻", false),
        new Country("mw", "🇲🇼", false),
        new Country("mx", "🇲🇽", false),
        new Country("my", "🇲🇾", false),
        new Country("mz", "🇲🇿", false),
        new Country("na", "🇳🇦", false),
        new Country("nc", "🇳🇨", false),
        new Country("ne", "🇳🇪", false),
        new Country("nf", "🇳🇫", false),
        new Country("ng", "🇳🇬", false),
        new Country("ni", "🇳🇮", false),
        new Country("np", "🇳🇵", false),
        new Country("nr", "🇳🇷", false),
        new Country("nu", "🇳🇺", false),
        new Country("om", "🇴🇲", false),
        new Country("pa", "🇵🇦", false),
        new Country("pe", "🇵🇪", false),
        new Country("pf", "🇵🇫", false),
        new Country("pg", "🇵🇬", false),
        new Country("ph", "🇵🇭", false),
        new Country("pk", "🇵🇰", false),
        new Country("pm", "🇵🇲", false),
        new Country("pn", "🇵🇳", false),
        new Country("pr", "🇵🇷", false),
        new Country("pw", "🇵🇼", false),
        new Country("py", "🇵🇾", false),
        new Country("qa", "🇶🇦", false),
        new Country("re", "🇷🇪", false),
        new Country("ro", "🇷🇴", false),
        new Country("rs", "🇷🇸", false),
        new Country("ru", "🇷🇺", false),
        new Country("rw", "🇷🇼", false),
        new Country("sa", "🇸🇦", false),
        new Country("sb", "🇸🇧", false),
        new Country("sc", "🇸🇨", false),
        new Country("sd", "🇸🇩", false),
        new Country("sg", "🇸🇬", false),
        new Country("sh", "🇸🇭", false),
        new Country("si", "🇸🇮", false),
        new Country("sj", "🇸🇯", false),
        new Country("sk", "🇸🇰", false),
        new Country("sl", "🇸🇱", false),
        new Country("sm", "🇸🇲", false),
        new Country("sn", "🇸🇳", false),
        new Country("so", "🇸🇴", false),
        new Country("sr", "🇸🇷", false),
        new Country("ss", "🇸🇸", false),
        new Country("st", "🇸🇹", false),
        new Country("sv", "🇸🇻", false),
        new Country("sx", "🇸🇽", false),
        new Country("sy", "🇸🇾", false),
        new Country("sz", "🇸🇿", false),
        new Country("tc", "🇹🇨", false),
        new Country("td", "🇹🇩", false),
        new Country("tg", "🇹🇬", false),
        new Country("th", "🇹🇭", false),
        new Country("tj", "🇹🇯", false),
        new Country("tk", "🇹🇰", false),
        new Country("tl", "🇹🇱", false),
        new Country("tm", "🇹🇲", false),
        new Country("tn", "🇹🇳", false),
        new Country("to", "🇹🇴", false),
        new Country("tr", "🇹🇷", false),
        new Country("tt", "🇹🇹", false),
        new Country("tv", "🇹🇻", false),
        new Country("tw", "🇹🇼", false),
        new Country("tz", "🇹🇿", false),
        new Country("ua", "🇺🇦", false),
        new Country("ug", "🇺🇬", false),
        new Country("uy", "🇺🇾", false),
        new Country("uz", "🇺🇿", false),
        new Country("va", "🇻🇦", false),
        new Country("vc", "🇻🇨", false),
        new Country("ve", "🇻🇪", false),
        new Country("vg", "🇻🇬", false),
        new Country("vi", "🇻🇮", false),
        new Country("vn", "🇻🇳", false),
        new Country("vu", "🇻🇺", false),
        new Country("wf", "🇼🇫", false),
        new Country("ws", "🇼🇸", false),
        new Country("ye", "🇾🇪", false),
        new Country("yt", "🇾🇹", false),
        new Country("za", "🇿🇦", false),
        new Country("zm", "🇿🇲", false),
        new Country("zw", "🇿🇼", false)
    );

    // ================================================================
    // GRUPPI PRESET — selezione rapida di insiemi comuni
    // ================================================================
    public record CountryGroup(String id, String label, String icon, List<String> codes,
                                String description) {
        public org.json.JSONObject toJson() {
            return new org.json.JSONObject()
                .put("id", id)
                .put("label", I18n.tr(label))
                .put("icon", icon)
                .put("description", I18n.tr(description))
                .put("codes", new org.json.JSONArray(codes));
        }
    }

    // EU 27 (Italia, Francia, Germania, ecc.)
    private static final List<String> EU27 = List.of(
        "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr",
        "de", "gr", "hu", "ie", "it", "lv", "lt", "lu", "mt", "nl",
        "pl", "pt", "ro", "sk", "si", "es", "se"
    );

    // EFTA: Svizzera, Norvegia, Islanda, Liechtenstein
    private static final List<String> EFTA = List.of("ch", "no", "is", "li");

    // Schengen = EU 27 (esclusi IE/CY) + EFTA (escluso LI/PA differenze trascurabili)
    // Per semplicità prendiamo EU+EFTA come "Europa allargata"
    private static final List<String> EU_PLUS_EFTA = concat(EU27, EFTA);

    // G7
    private static final List<String> G7 = List.of("it", "fr", "de", "gb", "us", "ca", "jp");

    // NATO (32 stati al 2024+)
    private static final List<String> NATO = List.of(
        "al", "be", "bg", "ca", "hr", "cz", "dk", "ee", "fi", "fr",
        "de", "gr", "hu", "is", "it", "lv", "lt", "lu", "me", "nl",
        "mk", "no", "pl", "pt", "ro", "sk", "si", "es", "se", "tr",
        "gb", "us"
    );

    // Nord America
    private static final List<String> NORTH_AMERICA = List.of("us", "ca", "mx");

    // Solo USA (preset rapido)
    private static final List<String> USA_ONLY = List.of("us");

    // Solo Italia
    private static final List<String> ITALY_ONLY = List.of("it");

    private static final List<CountryGroup> GROUPS = List.of(
        new CountryGroup("italy",    "server.cgroup.italy.label",        "🇮🇹", ITALY_ONLY,
            "server.cgroup.italy.desc"),
        new CountryGroup("eu27",     "server.cgroup.eu27.label", "🇪🇺", EU27,
            "server.cgroup.eu27.desc"),
        new CountryGroup("eu_efta",  "server.cgroup.eu_efta.label", "🇪🇺", EU_PLUS_EFTA,
            "server.cgroup.eu_efta.desc"),
        new CountryGroup("g7",       "server.cgroup.g7.label",                 "🌐", G7,
            "server.cgroup.g7.desc"),
        new CountryGroup("nato",     "server.cgroup.nato.label",          "🛡", NATO,
            "server.cgroup.nato.desc"),
        new CountryGroup("usa",      "server.cgroup.usa.label",        "🇺🇸", USA_ONLY,
            "server.cgroup.usa.desc"),
        new CountryGroup("north_am", "server.cgroup.north_am.label",       "🌎", NORTH_AMERICA,
            "server.cgroup.north_am.desc")
    );

    public static List<CountryGroup> getGroups() {
        return GROUPS;
    }

    public static org.json.JSONArray groupsToJsonArray() {
        org.json.JSONArray arr = new org.json.JSONArray();
        for (CountryGroup g : GROUPS) arr.put(g.toJson());
        return arr;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        java.util.List<String> out = new java.util.ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    private CountryCatalog() {}

    public static List<Country> getAll() {
        return COUNTRIES;
    }

    public static Country byCode(String code) {
        if (code == null) return null;
        String cc = code.toLowerCase();
        for (Country c : COUNTRIES) if (c.code.equals(cc)) return c;
        return null;
    }

    public static org.json.JSONArray toJsonArray() {
        org.json.JSONArray arr = new org.json.JSONArray();
        for (Country c : COUNTRIES) arr.put(c.toJson());
        return arr;
    }
}
