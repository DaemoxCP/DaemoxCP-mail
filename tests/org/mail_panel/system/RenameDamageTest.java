package org.mail_panel.system;

import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * Le rinomine fatte sul testo possono colpire stringhe che non sono nomi del codice.
 *
 * Il 25/10/2026 la rinomina delle chiavi JSON (so -> os, prova -> test, posta -> mail) aveva
 * cambiato anche: le dieci righe "extension=pdo_mysql.so" del php.ini di Roundcube (diventate
 * ".os": PHP non avrebbe caricato le estensioni), sette comandi di shell su libssl.so e
 * libmysqlclient.so.24, i due nomi vecchi in PathMigration (la migrazione di quei file non
 * avveniva piu', e la guardia old == new lo taceva) e l'identificatore del profilo Apple.
 * Nessuna prova lo vedeva: servono FreeBSD, Roundcube, un iPhone. Questa guarda i sorgenti.
 *
 * Il 30/10/2026 (punto 88 dei reperti) si e' visto il danno nei commenti: le rinomine del 16/10 e
 * del 24/10 avevano cambiato "che" in whichLabel, "riga" in lineItem, "gia'" in already', "uno
 * script" in "one script", "gli intervalli" in "gli ranges" anche nei commenti italiani dei file
 * che gli script scrivono sul server e delle pagine. Il punto 5 li cerca.
 */
public class RenameDamageTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length > 0 ? args[0] : ".");
        List<Path> java;
        try (Stream<Path> s = Files.walk(root.resolve("src/main/java"))) {
            java = s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }

        // 1. una libreria condivisa si chiama .so: ".os" dopo un nome e' una rinomina sbagliata.
        //    L'unica eccezione e' la chiave di lingua up.os ({{t:up.os}}).
        Pattern os = Pattern.compile("[A-Za-z0-9_)]\\.os(?![A-Za-z0-9_])");
        List<String> bad = new ArrayList<>();
        for (Path f : java) {
            List<String> lines = Files.readAllLines(f);
            for (int i = 0; i < lines.size(); i++) {
                String l = lines.get(i).replace("up.os", "");
                if (os.matcher(l).find()) bad.add(root.relativize(f) + ":" + (i + 1) + ": " + lines.get(i).trim());
            }
        }
        bad.stream().limit(10).forEach(b -> System.out.println("  " + b));
        check("nessuna stringa nomina una libreria .os invece di .so", bad.isEmpty());

        // 2. I nomi di prima stanno nel file di dati: una coppia con lo stesso nome di qua e di la'
        //    non migra niente (una rinomina fatta a testo li cambierebbe tutti e due).
        org.json.JSONObject legacy = new org.json.JSONObject(Files.readString(root.resolve("src/main/resources/legacy-names.json")));
        int pairs = 0; List<String> same = new ArrayList<>();
        for (String section : legacy.keySet()) {
            org.json.JSONArray a = legacy.getJSONArray(section);
            for (int i = 0; i < a.length(); i++) {
                pairs++;
                if (a.getJSONArray(i).getString(0).equals(a.getJSONArray(i).getString(1))) same.add(section + ": " + a.getJSONArray(i).getString(0));
            }
        }
        same.forEach(x -> System.out.println("  stesso nome: " + x));
        check("legacy-names.json: " + pairs + " coppie, ognuna da un nome vecchio a uno nuovo", pairs > 0 && same.isEmpty());

        // 3. il php.ini di Roundcube carica le estensioni col loro nome vero.
        String rc = Files.readString(root.resolve("src/main/java/org/mail_panel/scripts/RoundcubeScript.java"));
        check("Roundcube: extension=pdo_mysql.so e intl.so nel php.ini",
                rc.contains("extension=pdo_mysql.so") && rc.contains("extension=intl.so"));

        // 4. il profilo Apple tiene l'identificatore che i dispositivi conoscono (dal 30/10/2026:
        //    cambiarlo ancora farebbe installare un secondo profilo accanto al primo).
        String ap = Files.readString(root.resolve("src/main/java/org/mail_panel/system/AppleProfile.java"));
        check("profilo Apple: PayloadIdentifier ...mail e semi \"mail:\" e \"profile:\" invariati",
                ap.contains("<string>%s.mail</string>") && ap.contains("deterministic(\"mail:\"")
                        && ap.contains("deterministic(\"profile:\""));

        // 5. I commenti italiani dei testi generati (text block e letterali del Java, le pagine):
        //    una parola italiana sostituita dal nome inglese che le ha dato una rinomina. Le coppie
        //    vengono dalle mappe in tools/renames, quelle col nome vecchio fatto di sole minuscole
        //    (una parola, non un identificatore). Si segnala solo cio' che in italiano non puo'
        //    stare: un identificatore camelCase (whichLabel), una parola inglese con l'apostrofo
        //    dell'accento (already'), una parola grammaticale inglese in una frase italiana (where,
        //    stays, one), un articolo che davanti a quella iniziale non si usa (l'fingerprint, gli
        //    ranges). Non si vede un sostantivo dopo un articolo giusto ("il verdict", "la fix",
        //    "della mail"): non si distingue da un prestito come "il port" o "il log".
        Map<String, Set<String>> renamed = new TreeMap<>();
        try (Stream<Path> s = Files.list(root.resolve("tools/renames"))) {
            for (Path f : s.filter(p -> p.toString().endsWith(".txt")).sorted().toList()) {
                for (String l : Files.readAllLines(f)) {
                    String[] w = l.trim().split("\\s+");
                    if (w.length == 2 && w[0].matches("[a-z]{2,}") && !w[1].equalsIgnoreCase(w[0]))
                        renamed.computeIfAbsent(w[1], k -> new TreeSet<>()).add(w[0]);
                }
            }
        }
        List<Path> pages;
        try (Stream<Path> s = Files.walk(root.resolve("src/main/resources/pages"))) {
            pages = s.filter(p -> p.toString().endsWith(".js") || p.toString().endsWith(".html")).sorted().toList();
        }
        int examined = 0;
        List<String> damaged = new ArrayList<>();
        for (Path f : Stream.concat(java.stream(), pages.stream()).toList()) {
            String src = Files.readString(f);
            List<Map.Entry<Integer, String>> texts = f.toString().endsWith(".java") ? generatedTexts(src) : numbered(src);
            for (Map.Entry<Integer, String> t : texts) {
                String c = commentOf(t.getValue());
                if (c == null) continue;
                examined++;
                for (String why : damageIn(c, renamed))
                    damaged.add(root.relativize(f) + ":" + t.getKey() + "  " + why + "  | " + c.strip());
            }
        }
        damaged.stream().limit(40).forEach(b -> System.out.println("  " + b));
        check(renamed.size() + " nomi dalle mappe di tools/renames, " + examined
                + " righe di commento nei testi generati: nessuna parola italiana rinominata",
                renamed.size() > 100 && examined > 2000 && damaged.isEmpty());

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    // ---------------- il punto 5 ----------------

    private static final Pattern WORD = Pattern.compile("[A-Za-z][A-Za-z0-9]*");
    private static final Pattern CAMEL = Pattern.compile("[a-z]+[A-Z][A-Za-z0-9]*");
    /** Parole che bastano a dire che una frase e' italiana: due in una riga. */
    private static final Pattern ITALIAN = Pattern.compile(
            "(?<![A-Za-z])(di|che|il|la|non|per|del|della|un|una|si|con|sono|gli|nel|e'|c'e'|perche'|anche|come|solo|piu'|cosi'|gia')(?![A-Za-z])");
    /** Parole grammaticali inglesi: in una frase italiana non ci stanno mai. */
    private static final Set<String> FUNCTION = Set.of("where", "when", "which", "while", "still", "already",
            "stays", "one", "real", "only", "also");
    /** Un articolo eliso (l', un', dell'...) e' italiano solo davanti a una vocale (o a una h). */
    private static final Pattern ELISION = Pattern.compile("(?<![A-Za-z])(?:[lL]|[uU]n|[dDnNsS][aeu]ll|[aA]ll|[cC]oll|[qQ]uell|[qQ]uest)'$");
    /** gli, lo e uno vogliono una vocale, una s impura, una z, gn, ps: non "gli ranges". */
    private static final Pattern GLI = Pattern.compile("(?<![A-Za-z])(?:[gG]li|[lL]o|[uU]no)\\s+$");

    /** Le parole sospette di una riga di commento: tipo, nome inglese e parola italiana di prima. */
    static List<String> damageIn(String comment, Map<String, Set<String>> renamed) {
        // Fra virgolette doppie ci sono comandi e valori ("which dig"), non frasi.
        String c = comment.replaceAll("\"[^\"]*\"", "\"\"");
        boolean italian = ITALIAN.matcher(c.toLowerCase(Locale.ROOT)).results().count() >= 2;
        List<String> out = new ArrayList<>();
        Matcher m = WORD.matcher(c);
        while (m.find()) {
            String w = m.group();
            Set<String> old = renamed.get(w);
            if (old == null) continue;
            String before = c.substring(0, m.start());
            char prev = m.start() > 0 ? c.charAt(m.start() - 1) : ' ';
            boolean accent = m.end() < c.length() && c.charAt(m.end()) == '\''
                    && prev != '\'' && (m.end() + 1 >= c.length() || !Character.isLetter(c.charAt(m.end() + 1)));
            String why = null;
            if (accent) why = "accento";
            else if (CAMEL.matcher(w).matches()) why = "identificatore";
            else if (italian && FUNCTION.contains(w)) why = "parola inglese";
            else if (ELISION.matcher(before).find() && w.matches("[b-df-gj-np-tv-z].*")) why = "elisione";
            else if (GLI.matcher(before).find() && w.matches("[b-df-gj-np-rtv-xy].*") && !w.matches("(gn|ps|pn).*"))
                why = "articolo";
            if (why != null) out.add(why + " " + w + " (era " + String.join("/", old) + ")");
        }
        return out;
    }

    /** La parte di commento di una riga di testo generato: # ; // /* * <!-- --, o null. */
    static String commentOf(String line) {
        String s = line.strip();
        if (s.startsWith("#") || s.startsWith(";") || s.startsWith("//") || s.startsWith("/*")
                || s.startsWith("*") || s.startsWith("<!--") || s.startsWith("-- ")) return s;
        Matcher m = Pattern.compile("(?<![:\\\\])//\\s").matcher(line);
        return m.find() ? line.substring(m.start()) : null;
    }

    /** Le righe di un file di testo, numerate da 1. */
    static List<Map.Entry<Integer, String>> numbered(String src) {
        List<Map.Entry<Integer, String>> out = new ArrayList<>();
        String[] l = src.split("\n", -1);
        for (int i = 0; i < l.length; i++) out.add(Map.entry(i + 1, l[i]));
        return out;
    }

    /**
     * Il testo che il Java genera: il contenuto dei text block e dei letterali, riga per riga, con
     * la riga del sorgente. I commenti del Java si saltano: non finiscono da nessuna parte.
     */
    static List<Map.Entry<Integer, String>> generatedTexts(String src) {
        List<Map.Entry<Integer, String>> out = new ArrayList<>();
        int i = 0, n = src.length(), line = 1;
        while (i < n) {
            char c = src.charAt(i);
            if (c == '\n') { line++; i++; }
            else if (src.startsWith("//", i)) {
                int j = src.indexOf('\n', i);
                i = j < 0 ? n : j;
            } else if (src.startsWith("/*", i)) {
                int j = src.indexOf("*/", i + 2);
                for (int k = i; k < j; k++) if (src.charAt(k) == '\n') line++;
                i = j + 2;
            } else if (src.startsWith("\"\"\"", i)) {
                int start = src.indexOf('\n', i) + 1;
                int j = start;
                while (true) {
                    j = src.indexOf("\"\"\"", j);
                    if (src.charAt(j - 1) == '\\') { j += 3; continue; }
                    break;
                }
                line++;
                String[] l = src.substring(start, j).split("\n", -1);
                for (int k = 0; k < l.length; k++) out.add(Map.entry(line + k, l[k]));
                line += l.length - 1;
                i = j + 3;
            } else if (c == '"' || c == '\'') {
                int j = i + 1;
                while (src.charAt(j) != c) j += src.charAt(j) == '\\' ? 2 : 1;
                if (c == '"') for (String part : src.substring(i + 1, j).split("\\\\n", -1)) out.add(Map.entry(line, part));
                i = j + 1;
            } else i++;
        }
        return out;
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }
}
