package org.mail_panel.security;

import java.util.*;

/**
 * Catalogo paesi ISO-3166-1 alpha-2 con nome italiano e flag emoji.
 *
 * Lista completa di ~250 paesi/territori. La proprieta' "common" indica
 * i paesi piu' frequentemente usati come whitelist per server europei
 * (mostrati in cima alla UI per comodita').
 *
 * Source: ISO-3166-1, con nomi adattati in italiano.
 */
public final class CountryCatalog {

    public record Country(String code, String name, String flag, boolean common) {
        public org.json.JSONObject toJson() {
            return new org.json.JSONObject()
                .put("code", code)
                .put("name", name)
                .put("flag", flag)
                .put("common", common);
        }
    }

    private static final List<Country> COUNTRIES = List.of(
        // ==== Paesi comuni in cima (Europa + grandi paesi) ====
        new Country("it", "Italia",            "🇮🇹", true),
        new Country("fr", "Francia",           "🇫🇷", true),
        new Country("de", "Germania",          "🇩🇪", true),
        new Country("es", "Spagna",            "🇪🇸", true),
        new Country("gb", "Regno Unito",       "🇬🇧", true),
        new Country("ch", "Svizzera",          "🇨🇭", true),
        new Country("at", "Austria",           "🇦🇹", true),
        new Country("nl", "Paesi Bassi",       "🇳🇱", true),
        new Country("be", "Belgio",            "🇧🇪", true),
        new Country("pt", "Portogallo",        "🇵🇹", true),
        new Country("ie", "Irlanda",           "🇮🇪", true),
        new Country("se", "Svezia",            "🇸🇪", true),
        new Country("no", "Norvegia",          "🇳🇴", true),
        new Country("dk", "Danimarca",         "🇩🇰", true),
        new Country("fi", "Finlandia",         "🇫🇮", true),
        new Country("pl", "Polonia",           "🇵🇱", true),
        new Country("cz", "Repubblica Ceca",   "🇨🇿", true),
        new Country("gr", "Grecia",            "🇬🇷", true),
        new Country("us", "Stati Uniti",       "🇺🇸", true),
        new Country("ca", "Canada",            "🇨🇦", true),
        new Country("au", "Australia",         "🇦🇺", true),
        new Country("nz", "Nuova Zelanda",     "🇳🇿", true),
        new Country("jp", "Giappone",          "🇯🇵", true),

        // ==== Resto del mondo (alfabetico) ====
        new Country("ad", "Andorra",                            "🇦🇩", false),
        new Country("ae", "Emirati Arabi Uniti",                "🇦🇪", false),
        new Country("af", "Afghanistan",                        "🇦🇫", false),
        new Country("ag", "Antigua e Barbuda",                  "🇦🇬", false),
        new Country("ai", "Anguilla",                           "🇦🇮", false),
        new Country("al", "Albania",                            "🇦🇱", false),
        new Country("am", "Armenia",                            "🇦🇲", false),
        new Country("ao", "Angola",                             "🇦🇴", false),
        new Country("aq", "Antartide",                          "🇦🇶", false),
        new Country("ar", "Argentina",                          "🇦🇷", false),
        new Country("as", "Samoa Americane",                    "🇦🇸", false),
        new Country("aw", "Aruba",                              "🇦🇼", false),
        new Country("ax", "Isole Aland",                        "🇦🇽", false),
        new Country("az", "Azerbaigian",                        "🇦🇿", false),
        new Country("ba", "Bosnia ed Erzegovina",               "🇧🇦", false),
        new Country("bb", "Barbados",                           "🇧🇧", false),
        new Country("bd", "Bangladesh",                         "🇧🇩", false),
        new Country("bf", "Burkina Faso",                       "🇧🇫", false),
        new Country("bg", "Bulgaria",                           "🇧🇬", false),
        new Country("bh", "Bahrein",                            "🇧🇭", false),
        new Country("bi", "Burundi",                            "🇧🇮", false),
        new Country("bj", "Benin",                              "🇧🇯", false),
        new Country("bl", "Saint-Barthelemy",                   "🇧🇱", false),
        new Country("bm", "Bermuda",                            "🇧🇲", false),
        new Country("bn", "Brunei",                             "🇧🇳", false),
        new Country("bo", "Bolivia",                            "🇧🇴", false),
        new Country("bq", "Caraibi Olandesi",                   "🇧🇶", false),
        new Country("br", "Brasile",                            "🇧🇷", false),
        new Country("bs", "Bahamas",                            "🇧🇸", false),
        new Country("bt", "Bhutan",                             "🇧🇹", false),
        new Country("bw", "Botswana",                           "🇧🇼", false),
        new Country("by", "Bielorussia",                        "🇧🇾", false),
        new Country("bz", "Belize",                             "🇧🇿", false),
        new Country("cc", "Isole Cocos",                        "🇨🇨", false),
        new Country("cd", "Congo (Kinshasa)",                   "🇨🇩", false),
        new Country("cf", "Repubblica Centrafricana",           "🇨🇫", false),
        new Country("cg", "Congo (Brazzaville)",                "🇨🇬", false),
        new Country("ci", "Costa d'Avorio",                     "🇨🇮", false),
        new Country("ck", "Isole Cook",                         "🇨🇰", false),
        new Country("cl", "Cile",                               "🇨🇱", false),
        new Country("cm", "Camerun",                            "🇨🇲", false),
        new Country("cn", "Cina",                               "🇨🇳", false),
        new Country("co", "Colombia",                           "🇨🇴", false),
        new Country("cr", "Costa Rica",                         "🇨🇷", false),
        new Country("cu", "Cuba",                               "🇨🇺", false),
        new Country("cv", "Capo Verde",                         "🇨🇻", false),
        new Country("cw", "Curacao",                            "🇨🇼", false),
        new Country("cx", "Isola di Natale",                    "🇨🇽", false),
        new Country("cy", "Cipro",                              "🇨🇾", false),
        new Country("dj", "Gibuti",                             "🇩🇯", false),
        new Country("dm", "Dominica",                           "🇩🇲", false),
        new Country("do", "Repubblica Dominicana",              "🇩🇴", false),
        new Country("dz", "Algeria",                            "🇩🇿", false),
        new Country("ec", "Ecuador",                            "🇪🇨", false),
        new Country("ee", "Estonia",                            "🇪🇪", false),
        new Country("eg", "Egitto",                             "🇪🇬", false),
        new Country("eh", "Sahara Occidentale",                 "🇪🇭", false),
        new Country("er", "Eritrea",                            "🇪🇷", false),
        new Country("et", "Etiopia",                            "🇪🇹", false),
        new Country("fj", "Figi",                               "🇫🇯", false),
        new Country("fk", "Isole Falkland",                     "🇫🇰", false),
        new Country("fm", "Micronesia",                         "🇫🇲", false),
        new Country("fo", "Isole Faroe",                        "🇫🇴", false),
        new Country("ga", "Gabon",                              "🇬🇦", false),
        new Country("gd", "Grenada",                            "🇬🇩", false),
        new Country("ge", "Georgia",                            "🇬🇪", false),
        new Country("gf", "Guyana Francese",                    "🇬🇫", false),
        new Country("gg", "Guernsey",                           "🇬🇬", false),
        new Country("gh", "Ghana",                              "🇬🇭", false),
        new Country("gi", "Gibilterra",                         "🇬🇮", false),
        new Country("gl", "Groenlandia",                        "🇬🇱", false),
        new Country("gm", "Gambia",                             "🇬🇲", false),
        new Country("gn", "Guinea",                             "🇬🇳", false),
        new Country("gp", "Guadalupa",                          "🇬🇵", false),
        new Country("gq", "Guinea Equatoriale",                 "🇬🇶", false),
        new Country("gt", "Guatemala",                          "🇬🇹", false),
        new Country("gu", "Guam",                               "🇬🇺", false),
        new Country("gw", "Guinea-Bissau",                      "🇬🇼", false),
        new Country("gy", "Guyana",                             "🇬🇾", false),
        new Country("hk", "Hong Kong",                          "🇭🇰", false),
        new Country("hn", "Honduras",                           "🇭🇳", false),
        new Country("hr", "Croazia",                            "🇭🇷", false),
        new Country("ht", "Haiti",                              "🇭🇹", false),
        new Country("hu", "Ungheria",                           "🇭🇺", false),
        new Country("id", "Indonesia",                          "🇮🇩", false),
        new Country("il", "Israele",                            "🇮🇱", false),
        new Country("im", "Isola di Man",                       "🇮🇲", false),
        new Country("in", "India",                              "🇮🇳", false),
        new Country("io", "Territorio Britannico Oceano Indiano","🇮🇴", false),
        new Country("iq", "Iraq",                               "🇮🇶", false),
        new Country("ir", "Iran",                               "🦁", false),
        new Country("is", "Islanda",                            "🇮🇸", false),
        new Country("je", "Jersey",                             "🇯🇪", false),
        new Country("jm", "Giamaica",                           "🇯🇲", false),
        new Country("jo", "Giordania",                          "🇯🇴", false),
        new Country("ke", "Kenya",                              "🇰🇪", false),
        new Country("kg", "Kirghizistan",                       "🇰🇬", false),
        new Country("kh", "Cambogia",                           "🇰🇭", false),
        new Country("ki", "Kiribati",                           "🇰🇮", false),
        new Country("km", "Comore",                             "🇰🇲", false),
        new Country("kn", "Saint Kitts e Nevis",                "🇰🇳", false),
        new Country("kp", "Corea del Nord",                     "🇰🇵", false),
        new Country("kr", "Corea del Sud",                      "🇰🇷", false),
        new Country("kw", "Kuwait",                             "🇰🇼", false),
        new Country("ky", "Isole Cayman",                       "🇰🇾", false),
        new Country("kz", "Kazakistan",                         "🇰🇿", false),
        new Country("la", "Laos",                               "🇱🇦", false),
        new Country("lb", "Libano",                             "🇱🇧", false),
        new Country("lc", "Saint Lucia",                        "🇱🇨", false),
        new Country("li", "Liechtenstein",                      "🇱🇮", false),
        new Country("lk", "Sri Lanka",                          "🇱🇰", false),
        new Country("lr", "Liberia",                            "🇱🇷", false),
        new Country("ls", "Lesotho",                            "🇱🇸", false),
        new Country("lt", "Lituania",                           "🇱🇹", false),
        new Country("lu", "Lussemburgo",                        "🇱🇺", false),
        new Country("lv", "Lettonia",                           "🇱🇻", false),
        new Country("ly", "Libia",                              "🇱🇾", false),
        new Country("ma", "Marocco",                            "🇲🇦", false),
        new Country("mc", "Monaco",                             "🇲🇨", false),
        new Country("md", "Moldavia",                           "🇲🇩", false),
        new Country("me", "Montenegro",                         "🇲🇪", false),
        new Country("mf", "Saint-Martin (Francese)",            "🇲🇫", false),
        new Country("mg", "Madagascar",                         "🇲🇬", false),
        new Country("mh", "Isole Marshall",                     "🇲🇭", false),
        new Country("mk", "Macedonia del Nord",                 "🇲🇰", false),
        new Country("ml", "Mali",                               "🇲🇱", false),
        new Country("mm", "Myanmar",                            "🇲🇲", false),
        new Country("mn", "Mongolia",                           "🇲🇳", false),
        new Country("mo", "Macao",                              "🇲🇴", false),
        new Country("mp", "Isole Marianne Settentrionali",      "🇲🇵", false),
        new Country("mq", "Martinica",                          "🇲🇶", false),
        new Country("mr", "Mauritania",                         "🇲🇷", false),
        new Country("ms", "Montserrat",                         "🇲🇸", false),
        new Country("mt", "Malta",                              "🇲🇹", false),
        new Country("mu", "Mauritius",                          "🇲🇺", false),
        new Country("mv", "Maldive",                            "🇲🇻", false),
        new Country("mw", "Malawi",                             "🇲🇼", false),
        new Country("mx", "Messico",                            "🇲🇽", false),
        new Country("my", "Malesia",                            "🇲🇾", false),
        new Country("mz", "Mozambico",                          "🇲🇿", false),
        new Country("na", "Namibia",                            "🇳🇦", false),
        new Country("nc", "Nuova Caledonia",                    "🇳🇨", false),
        new Country("ne", "Niger",                              "🇳🇪", false),
        new Country("nf", "Isola Norfolk",                      "🇳🇫", false),
        new Country("ng", "Nigeria",                            "🇳🇬", false),
        new Country("ni", "Nicaragua",                          "🇳🇮", false),
        new Country("np", "Nepal",                              "🇳🇵", false),
        new Country("nr", "Nauru",                              "🇳🇷", false),
        new Country("nu", "Niue",                               "🇳🇺", false),
        new Country("om", "Oman",                               "🇴🇲", false),
        new Country("pa", "Panama",                             "🇵🇦", false),
        new Country("pe", "Peru",                               "🇵🇪", false),
        new Country("pf", "Polinesia Francese",                 "🇵🇫", false),
        new Country("pg", "Papua Nuova Guinea",                 "🇵🇬", false),
        new Country("ph", "Filippine",                          "🇵🇭", false),
        new Country("pk", "Pakistan",                           "🇵🇰", false),
        new Country("pm", "Saint Pierre e Miquelon",            "🇵🇲", false),
        new Country("pn", "Pitcairn",                           "🇵🇳", false),
        new Country("pr", "Porto Rico",                         "🇵🇷", false),
        new Country("pw", "Palau",                              "🇵🇼", false),
        new Country("py", "Paraguay",                           "🇵🇾", false),
        new Country("qa", "Qatar",                              "🇶🇦", false),
        new Country("re", "Riunione",                           "🇷🇪", false),
        new Country("ro", "Romania",                            "🇷🇴", false),
        new Country("rs", "Serbia",                             "🇷🇸", false),
        new Country("ru", "Russia",                             "🇷🇺", false),
        new Country("rw", "Ruanda",                             "🇷🇼", false),
        new Country("sa", "Arabia Saudita",                     "🇸🇦", false),
        new Country("sb", "Isole Salomone",                     "🇸🇧", false),
        new Country("sc", "Seychelles",                         "🇸🇨", false),
        new Country("sd", "Sudan",                              "🇸🇩", false),
        new Country("sg", "Singapore",                          "🇸🇬", false),
        new Country("sh", "Sant'Elena",                         "🇸🇭", false),
        new Country("si", "Slovenia",                           "🇸🇮", false),
        new Country("sj", "Svalbard e Jan Mayen",               "🇸🇯", false),
        new Country("sk", "Slovacchia",                         "🇸🇰", false),
        new Country("sl", "Sierra Leone",                       "🇸🇱", false),
        new Country("sm", "San Marino",                         "🇸🇲", false),
        new Country("sn", "Senegal",                            "🇸🇳", false),
        new Country("so", "Somalia",                            "🇸🇴", false),
        new Country("sr", "Suriname",                           "🇸🇷", false),
        new Country("ss", "Sud Sudan",                          "🇸🇸", false),
        new Country("st", "Sao Tome e Principe",                "🇸🇹", false),
        new Country("sv", "El Salvador",                        "🇸🇻", false),
        new Country("sx", "Sint Maarten",                       "🇸🇽", false),
        new Country("sy", "Siria",                              "🇸🇾", false),
        new Country("sz", "Eswatini",                           "🇸🇿", false),
        new Country("tc", "Isole Turks e Caicos",               "🇹🇨", false),
        new Country("td", "Ciad",                               "🇹🇩", false),
        new Country("tg", "Togo",                               "🇹🇬", false),
        new Country("th", "Thailandia",                         "🇹🇭", false),
        new Country("tj", "Tagikistan",                         "🇹🇯", false),
        new Country("tk", "Tokelau",                            "🇹🇰", false),
        new Country("tl", "Timor Est",                          "🇹🇱", false),
        new Country("tm", "Turkmenistan",                       "🇹🇲", false),
        new Country("tn", "Tunisia",                            "🇹🇳", false),
        new Country("to", "Tonga",                              "🇹🇴", false),
        new Country("tr", "Turchia",                            "🇹🇷", false),
        new Country("tt", "Trinidad e Tobago",                  "🇹🇹", false),
        new Country("tv", "Tuvalu",                             "🇹🇻", false),
        new Country("tw", "Taiwan",                             "🇹🇼", false),
        new Country("tz", "Tanzania",                           "🇹🇿", false),
        new Country("ua", "Ucraina",                            "🇺🇦", false),
        new Country("ug", "Uganda",                             "🇺🇬", false),
        new Country("uy", "Uruguay",                            "🇺🇾", false),
        new Country("uz", "Uzbekistan",                         "🇺🇿", false),
        new Country("va", "Vaticano",                           "🇻🇦", false),
        new Country("vc", "Saint Vincent e Grenadine",          "🇻🇨", false),
        new Country("ve", "Venezuela",                          "🇻🇪", false),
        new Country("vg", "Isole Vergini Britanniche",          "🇻🇬", false),
        new Country("vi", "Isole Vergini Americane",            "🇻🇮", false),
        new Country("vn", "Vietnam",                            "🇻🇳", false),
        new Country("vu", "Vanuatu",                            "🇻🇺", false),
        new Country("wf", "Wallis e Futuna",                    "🇼🇫", false),
        new Country("ws", "Samoa",                              "🇼🇸", false),
        new Country("ye", "Yemen",                              "🇾🇪", false),
        new Country("yt", "Mayotte",                            "🇾🇹", false),
        new Country("za", "Sudafrica",                          "🇿🇦", false),
        new Country("zm", "Zambia",                             "🇿🇲", false),
        new Country("zw", "Zimbabwe",                           "🇿🇼", false)
    );

    // ================================================================
    // GRUPPI PRESET — selezione rapida di insiemi comuni
    // ================================================================
    public record CountryGroup(String id, String label, String icon, List<String> codes,
                                String description) {
        public org.json.JSONObject toJson() {
            return new org.json.JSONObject()
                .put("id", id)
                .put("label", label)
                .put("icon", icon)
                .put("description", description)
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
        new CountryGroup("italy",    "Solo Italia",        "🇮🇹", ITALY_ONLY,
            "Solo IP italiani"),
        new CountryGroup("eu27",     "Unione Europea (27)", "🇪🇺", EU27,
            "Tutti i 27 stati membri UE"),
        new CountryGroup("eu_efta",  "EU + EFTA (Schengen)", "🇪🇺", EU_PLUS_EFTA,
            "UE + Svizzera, Norvegia, Islanda, Liechtenstein (31 paesi)"),
        new CountryGroup("g7",       "G7",                 "🌐", G7,
            "Italia, Francia, Germania, UK, USA, Canada, Giappone"),
        new CountryGroup("nato",     "NATO (32)",          "🛡", NATO,
            "Tutti gli stati membri NATO"),
        new CountryGroup("usa",      "Stati Uniti",        "🇺🇸", USA_ONLY,
            "Solo USA"),
        new CountryGroup("north_am", "Nord America",       "🌎", NORTH_AMERICA,
            "USA, Canada, Messico")
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
