package org.mail_panel.system;

import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * Renames made on the text can hit strings that are not names of the code.
 *
 * On 25/10/2026 the rename of the JSON keys (so -> os, prova -> test, posta -> mail) had also
 * changed: the ten "extension=pdo_mysql.so" lines of Roundcube's php.ini (become ".os": PHP would not
 * have loaded the extensions), seven shell commands on libssl.so and libmysqlclient.so.24, the two
 * old names in PathMigration (the migration of those files no longer happened, and the old == new
 * guard kept it quiet) and the Apple profile's identifier. No test saw it: it needs FreeBSD,
 * Roundcube, an iPhone. This one looks at the sources.
 *
 * On 30/10/2026 (point 88 of the reperti) the damage in the comments was seen: the renames of 16/10
 * and 24/10 had changed "che" into whichLabel, "riga" into lineItem, "gia'" into already', "uno
 * script" into "one script", "gli intervalli" into "gli ranges" also in the Italian comments of the
 * files the scripts write on the server and of the pages. Point 5 looks for them; point 6, since
 * 31/10 (point 90 of the reperti), does the same in the comments of the code and of the tests, where
 * #21 had damaged 110 of them ("la correzione c'e'?" had become "la fix c'e'?"). The Italian words
 * and forms quoted in this class are the data it looks for.
 */
public class RenameDamageTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        Path root = Path.of(args.length > 0 ? args[0] : ".");
        List<Path> java;
        try (Stream<Path> s = Files.walk(root.resolve("src/main/java"))) {
            java = s.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }

        // 1. a shared library is called .so: ".os" after a name is a wrong rename.
        //    The only exception is the language key up.os ({{t:up.os}}).
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
        check("no string names a .os library instead of .so", bad.isEmpty());

        // 2. The old names live in the data file: a pair with the same name on both sides migrates
        //    nothing (a rename made on the text would change both).
        org.json.JSONObject legacy = new org.json.JSONObject(Files.readString(root.resolve("src/main/resources/legacy-names.json")));
        int pairs = 0; List<String> same = new ArrayList<>();
        for (String section : legacy.keySet()) {
            org.json.JSONArray a = legacy.getJSONArray(section);
            for (int i = 0; i < a.length(); i++) {
                pairs++;
                if (a.getJSONArray(i).getString(0).equals(a.getJSONArray(i).getString(1))) same.add(section + ": " + a.getJSONArray(i).getString(0));
            }
        }
        same.forEach(x -> System.out.println("  same name: " + x));
        check("legacy-names.json: " + pairs + " pairs, each from an old name to a new one", pairs > 0 && same.isEmpty());

        // 3. Roundcube's php.ini loads the extensions with their real name.
        String rc = Files.readString(root.resolve("src/main/java/org/mail_panel/scripts/RoundcubeScript.java"));
        check("Roundcube: extension=pdo_mysql.so and intl.so in php.ini",
                rc.contains("extension=pdo_mysql.so") && rc.contains("extension=intl.so"));

        // 4. the Apple profile keeps the identifier the devices know (since 30/10/2026: changing it
        //    again would make a second profile be installed next to the first).
        String ap = Files.readString(root.resolve("src/main/java/org/mail_panel/system/AppleProfile.java"));
        check("Apple profile: PayloadIdentifier ...mail and seeds \"mail:\" and \"profile:\" unchanged",
                ap.contains("<string>%s.mail</string>") && ap.contains("deterministic(\"mail:\"")
                        && ap.contains("deterministic(\"profile:\""));

        // 5. The Italian comments of the generated texts (text blocks and literals of the Java, the
        //    pages): an Italian word replaced by the English name a rename gave it. The pairs come
        //    from the maps in tools/renames, those whose old name is made only of lowercase letters
        //    (a word, not an identifier). Only what cannot stand in Italian is reported: a camelCase
        //    identifier (whichLabel), an English word with the accent's apostrophe (already'), an
        //    English function word in an Italian sentence (where, stays, one), an article not used
        //    before that initial (l'fingerprint, gli ranges). A noun after a right article cannot be
        //    seen ("il verdict", "la fix", "della mail"): it cannot be told from a loanword like "il
        //    port" or "il log". And since 31/10 a camelCase that, comments removed, is nowhere in the
        //    code: the Italian name a rename changed everywhere except in the comment
        //    (@param tieniInoltri above a parameter called keepForwards).
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
        Set<String> codeWords = codeWords(root);
        int examined = 0;
        List<String> damaged = new ArrayList<>();
        for (Path f : Stream.concat(java.stream(), pages.stream()).toList()) {
            String src = Files.readString(f);
            List<Map.Entry<Integer, String>> texts = f.toString().endsWith(".java") ? generatedTexts(src) : numbered(src);
            for (Map.Entry<Integer, String> t : texts) {
                String c = commentOf(t.getValue());
                if (c == null) continue;
                examined++;
                for (String why : damageIn(c, renamed, codeWords))
                    damaged.add(root.relativize(f) + ":" + t.getKey() + "  " + why + "  | " + c.strip());
            }
        }
        damaged.stream().limit(40).forEach(b -> System.out.println("  " + b));
        check(renamed.size() + " names from the maps of tools/renames, " + examined
                + " comment lines in the generated texts: no renamed Italian word",
                renamed.size() > 100 && examined > 2000 && damaged.isEmpty());

        // 6. The same signals in the comments of the code: the comments of the Java (panel, tests,
        //    tools), those of the .js and .py of the tests and tools, the two READMEs. Not this
        //    class: its comments quote the damaged forms on purpose.
        List<Path> code = new ArrayList<>(java);
        for (String dir : new String[]{"tests", "tools"}) {
            try (Stream<Path> s = Files.walk(root.resolve(dir))) {
                s.filter(p -> p.toString().matches(".*\\.(java|js|py)$") && !p.toString().contains("/renames/"))
                        .filter(p -> !p.getFileName().toString().equals("RenameDamageTest.java"))
                        .sorted().forEach(code::add);
            }
        }
        code.add(root.resolve("tests/README.md"));
        code.add(root.resolve("README.md"));
        int examinedCode = 0;
        List<String> damagedCode = new ArrayList<>();
        for (Path f : code) {
            if (!Files.isRegularFile(f)) continue;
            String name = f.getFileName().toString(), src = Files.readString(f);
            List<Map.Entry<Integer, String>> lines = name.endsWith(".java") ? javaComments(src) : numbered(src);
            for (Map.Entry<Integer, String> t : lines) {
                String c = name.endsWith(".md") || name.endsWith(".java") ? t.getValue() : commentOf(t.getValue());
                if (c == null || c.isBlank()) continue;
                examinedCode++;
                for (String why : damageIn(c, renamed, codeWords))
                    damagedCode.add(root.relativize(f) + ":" + t.getKey() + "  " + why + "  | " + c.strip());
            }
        }
        damagedCode.stream().limit(40).forEach(b -> System.out.println("  " + b));
        check(examinedCode + " comment lines of the code and of the READMEs: no renamed Italian word",
                examinedCode > 10000 && damagedCode.isEmpty());

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    // ---------------- point 5 ----------------

    /** A whole word: not a piece of rotate_start, mail-panel-auth, key.one or real(). */
    private static final Pattern WORD = Pattern.compile("(?<![A-Za-z0-9_.-])[A-Za-z][A-Za-z0-9]*(?![A-Za-z0-9_(-])");
    private static final Pattern CAMEL = Pattern.compile("[a-z]+[A-Z][A-Za-z0-9]*");
    /** Words that are enough to say a sentence is Italian: two in a line. */
    private static final Pattern ITALIAN = Pattern.compile(
            "(?<![A-Za-z])(di|che|il|la|non|per|del|della|un|una|si|con|sono|gli|nel|e'|c'e'|perche'|anche|come|solo|piu'|cosi'|gia')(?![A-Za-z])");
    /** English function words: in an Italian sentence they never belong. */
    private static final Set<String> FUNCTION = Set.of("where", "when", "while", "still", "already",
            "stays", "one", "real", "only", "also");
    /** An elided article (l', un', dell'...) is Italian only before a vowel (or an h). */
    private static final Pattern ELISION = Pattern.compile("(?<![A-Za-z])(?:[lL]|[uU]n|[dDnNsS][aeu]ll|[aA]ll|[cC]oll|[qQ]uell|[qQ]uest)'$");
    /** gli, lo and uno want a vowel, an impure s, a z, gn, ps: not "gli ranges". */
    private static final Pattern GLI = Pattern.compile("(?<![A-Za-z])(?:[gG]li|[lL]o|[uU]no)\\s+$");

    /** The suspicious words of a comment line: kind, English name and the Italian word of before. */
    static List<String> damageIn(String comment, Map<String, Set<String>> renamed, Set<String> codeWords) {
        // Between quotes, double or single, there are commands and values ("which dig", '--restart'),
        // and between backticks or in {@code} names of the code: not sentences.
        String c = comment.replaceAll("\"[^\"]*\"", "\"\"")
                .replaceAll("(?<![A-Za-z])'[^'\\n]*'(?![A-Za-z])", "''")
                .replaceAll("`[^`]*`|\\{@(?:code|link) [^}]*\\}", "");
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
            if (accent) why = "accent";
            else if (CAMEL.matcher(w).matches()) why = "identifier";
            else if (italian && FUNCTION.contains(w)) why = "English word";
            else if (ELISION.matcher(before).find() && w.matches("[b-df-gj-np-tv-z].*")) why = "elision";
            else if (GLI.matcher(before).find() && w.matches("[b-df-gj-np-rtv-xy].*") && !w.matches("(gn|ps|pn).*"))
                why = "article";
            if (why != null) out.add(why + " " + w + " (was " + String.join("/", old) + ")");
        }
        if (italian) {
            Matcher d = DEAD.matcher(c);
            while (d.find()) if (!codeWords.contains(d.group()) && !renamed.containsKey(d.group()))
                out.add("a name that is not in the code " + d.group());
        }
        return out;
    }

    /**
     * A camelCase with at least two lowercase letters in front (jBCrypt is a library's name), that is
     * not a code example: followed by ".method" or by "(" it is (autoDns.create(...)).
     */
    private static final Pattern DEAD = Pattern.compile("(?<![A-Za-z0-9_.$-])[a-z]{2,}[A-Z][A-Za-z0-9]*(?![A-Za-z0-9_(-])(?!\\.[A-Za-z])");
    /** A literal on one line, a // comment or a block comment. */
    private static final Pattern STRING_OR_COMMENT = Pattern.compile("\"(?:[^\"\\\\\\n]|\\\\.)*\"|//[^\\n]*|/\\*.*?\\*/", Pattern.DOTALL);

    /**
     * All the names that appear in the code, comments removed: Java, JavaScript, HTML, JSON and Python
     * of the panel, of the tests and of the tools. The comments inside the text blocks (the pages)
     * are removed too: a name that is only there does not exist.
     */
    static Set<String> codeWords(Path root) throws java.io.IOException {
        Set<String> out = new HashSet<>();
        Pattern word = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*");
        for (String dir : new String[]{"src", "tests", "tools"}) {
            try (Stream<Path> s = Files.walk(root.resolve(dir))) {
                for (Path f : s.filter(p -> p.toString().matches(".*\\.(java|js|html|json|py|sh)$"))
                        .filter(p -> !p.toString().contains("/vendor/")).toList()) {
                    String text = Files.readString(f);
                    String n = f.toString();
                    if (n.endsWith(".java") || n.endsWith(".js"))
                        text = STRING_OR_COMMENT.matcher(text).replaceAll(m -> m.group().startsWith("\"") ? Matcher.quoteReplacement(m.group()) : " ");
                    else if (n.endsWith(".py") || n.endsWith(".sh"))
                        text = text.replaceAll("(?m)^\\s*#.*$", " ");
                    Matcher m = word.matcher(text);
                    while (m.find()) out.add(m.group());
                }
            }
        }
        return out;
    }

    /** The comment part of a line of generated text: # ; // /* * <!-- --, or null. */
    static String commentOf(String line) {
        String s = line.strip();
        if (s.startsWith("#") || s.startsWith(";") || s.startsWith("//") || s.startsWith("/*")
                || s.startsWith("*") || s.startsWith("<!--") || s.startsWith("-- ")) return s;
        Matcher m = Pattern.compile("(?<![:\\\\])//\\s").matcher(line);
        return m.find() ? line.substring(m.start()) : null;
    }

    /**
     * The comments of the Java (// and the /* ... *\/ blocks, Javadoc included), line by line, with
     * the source line. The literals and the text blocks are skipped: they are point 5.
     */
    static List<Map.Entry<Integer, String>> javaComments(String src) {
        List<Map.Entry<Integer, String>> out = new ArrayList<>();
        int i = 0, n = src.length(), line = 1;
        while (i < n) {
            char c = src.charAt(i);
            if (c == '\n') { line++; i++; }
            else if (src.startsWith("//", i)) {
                int j = src.indexOf('\n', i);
                if (j < 0) j = n;
                out.add(Map.entry(line, src.substring(i, j)));
                i = j;
            } else if (src.startsWith("/*", i)) {
                int j = src.indexOf("*/", i + 2) + 2;
                String[] l = src.substring(i, j).split("\n", -1);
                for (int k = 0; k < l.length; k++) out.add(Map.entry(line + k, l[k]));
                line += l.length - 1;
                i = j;
            } else if (src.startsWith("\"\"\"", i)) {
                int j = src.indexOf('\n', i);
                while (true) {
                    j = src.indexOf("\"\"\"", j);
                    if (src.charAt(j - 1) == '\\') { j += 3; continue; }
                    break;
                }
                for (int k = i; k < j; k++) if (src.charAt(k) == '\n') line++;
                i = j + 3;
            } else if (c == '"' || c == '\'') {
                int j = i + 1;
                while (src.charAt(j) != c) j += src.charAt(j) == '\\' ? 2 : 1;
                i = j + 1;
            } else i++;
        }
        return out;
    }

    /** The lines of a text file, numbered from 1. */
    static List<Map.Entry<Integer, String>> numbered(String src) {
        List<Map.Entry<Integer, String>> out = new ArrayList<>();
        String[] l = src.split("\n", -1);
        for (int i = 0; i < l.length; i++) out.add(Map.entry(i + 1, l[i]));
        return out;
    }

    /**
     * The text the Java generates: the content of the text blocks and of the literals, line by line,
     * with the source line. The Java comments are skipped: they end up nowhere.
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
