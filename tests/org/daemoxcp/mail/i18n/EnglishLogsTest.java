package org.daemoxcp.mail.i18n;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The panel's log lines are in English, the same for everyone (decided on 19/11/2026): only what a person reads in the
 * pages and the console is translated. Found on the real server the same evening: «Auto-apply firewall config al boot».
 *
 *  1. The checks can fail: an Italian log line in a sample is found, an English one is not.
 *  2. The texts written in a log call (a java.util.logging logger: info, warning, severe, fine, config, log; and
 *     System.out / System.err, which go to the service's log) have no Italian word.
 *  3. The same for the message of an exception created in the code: it ends up in the log.
 *
 * Only the strings written in the code are read, never the comments (they stay in Italian) nor the translation keys
 * (al.sourceDomain is a name). An Italian word is one of a short list that English does not have (al, della, sono,
 * gia', senza...), so an English text never trips it.
 *
 * Usage (from the project root):
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.i18n.EnglishLogsTest
 */
public class EnglishLogsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** Italian words that are not English words: an English log line never contains one. */
    static final Set<String> ITALIAN = Set.of(
            "al", "allo", "alla", "agli", "alle", "del", "dello", "della", "dei", "degli", "delle", "nel", "nello", "nella",
            "nei", "negli", "nelle", "sul", "sullo", "sulla", "sui", "sugli", "sulle", "dal", "dallo", "dalla", "dagli",
            "dalle", "il", "gli", "una", "che", "con", "sono", "gia", "già", "anche", "ancora", "dopo", "questo", "questa",
            "quello", "quella", "perche", "perché", "piu", "più", "puo", "può", "cioè", "errore", "avvio", "riavvio",
            "utente", "servizio", "cartella", "nessun", "nessuno", "nessuna", "impossibile", "senza", "ogni", "essere",
            "pronto", "fallito", "fallita", "riuscito", "riuscita", "manca", "chiave", "attivo", "attiva", "trovato",
            "trovata", "è");

    /** A log call, or an exception created with a message: what follows is its '('. */
    static final Pattern CALL = Pattern.compile(
            "\\b(?:LOGGER|LOG|log|logger|[a-z][A-Za-z]*)\\s*\\.\\s*(?:info|warning|severe|fine|finer|finest|config|log)\\s*\\("
            + "|System\\s*\\.\\s*(?:out|err)\\s*\\.\\s*(?:println|print|printf|format)\\s*\\("
            + "|\\bnew\\s+[A-Z][A-Za-z]*(?:Exception|Error)\\s*\\(");

    static final Pattern WORD = Pattern.compile("[\\p{L}]+'?");

    /** A translation key (al.sourceDomain, console.ipf.fwNotReloaded): a name, not a text, so its parts are not words. */
    static final Pattern KEY = Pattern.compile("[a-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+");

    /** The string literals inside the parentheses that open at src[from - 1]; comments are skipped. */
    static List<String> literals(String src, int from) {
        List<String> out = new ArrayList<>();
        int depth = 1, i = from, n = src.length();
        while (i < n && depth > 0) {
            char c = src.charAt(i);
            if (src.startsWith("\"\"\"", i)) {
                int end = src.indexOf("\"\"\"", i + 3);
                if (end < 0) break;
                out.add(src.substring(i + 3, end));
                i = end + 3;
            } else if (c == '"') {
                StringBuilder sb = new StringBuilder();
                int j = i + 1;
                while (j < n && src.charAt(j) != '"' && src.charAt(j) != '\n') {
                    if (src.charAt(j) == '\\' && j + 1 < n) { sb.append(src.charAt(j + 1)); j += 2; continue; }
                    sb.append(src.charAt(j++));
                }
                out.add(sb.toString());
                i = j + 1;
            } else if (c == '\'') {
                int j = i + 1;
                if (j < n && src.charAt(j) == '\\') j += 2; else j++;
                i = src.indexOf('\'', j) + 1;
                if (i <= 0) break;
            } else if (src.startsWith("//", i)) {
                int end = src.indexOf('\n', i);
                i = end < 0 ? n : end;
            } else if (src.startsWith("/*", i)) {
                int end = src.indexOf("*/", i + 2);
                i = end < 0 ? n : end + 2;
            } else {
                if (c == '(') depth++;
                else if (c == ')') depth--;
                i++;
            }
        }
        return out;
    }

    /** The Italian words of a text, in the order they appear. */
    static List<String> italianWords(String text) {
        List<String> out = new ArrayList<>();
        Matcher m = WORD.matcher(text);
        while (m.find()) {
            String w = m.group().toLowerCase(Locale.ROOT);
            boolean apostrophe = w.endsWith("'");
            if (apostrophe) w = w.substring(0, w.length() - 1);
            // «e'» is the old spelling of «è»: the apostrophe makes it Italian, a lone «e» alone could be anything.
            if (ITALIAN.contains(w) || (apostrophe && w.equals("e"))) out.add(w);
        }
        return out;
    }

    /** The log calls and exception messages of a source file that have Italian words, with their line. */
    static List<String> italianLogLines(String file, String src) {
        List<String> out = new ArrayList<>();
        String code = withoutComments(src);
        Matcher m = CALL.matcher(code);
        while (m.find()) {
            List<String> texts = new ArrayList<>();
            for (String l : literals(code, m.end())) if (!KEY.matcher(l).matches()) texts.add(l);
            String text = String.join(" ", texts);
            List<String> words = italianWords(text);
            if (!words.isEmpty())
                out.add(file + ":" + line(code, m.start()) + " " + new TreeSet<>(words) + " «"
                        + (text.length() > 90 ? text.substring(0, 90) + "…" : text) + "»");
        }
        return out;
    }

    /** The source with comments blanked out (strings kept), so a commented-out call is not read. */
    static String withoutComments(String src) {
        StringBuilder sb = new StringBuilder(src);
        int i = 0, n = src.length();
        while (i < n) {
            if (src.startsWith("\"\"\"", i)) {
                int end = src.indexOf("\"\"\"", i + 3);
                i = end < 0 ? n : end + 3;
            } else if (src.charAt(i) == '"') {
                int j = i + 1;
                while (j < n && src.charAt(j) != '"' && src.charAt(j) != '\n') j += src.charAt(j) == '\\' ? 2 : 1;
                i = j + 1;
            } else if (src.charAt(i) == '\'') {
                int j = i + 1;
                if (j < n && src.charAt(j) == '\\') j += 2; else j++;
                int end = src.indexOf('\'', j);
                i = end < 0 ? n : end + 1;
            } else if (src.startsWith("//", i)) {
                int end = src.indexOf('\n', i);
                if (end < 0) end = n;
                for (int k = i; k < end; k++) sb.setCharAt(k, ' ');
                i = end;
            } else if (src.startsWith("/*", i)) {
                int end = src.indexOf("*/", i + 2);
                end = end < 0 ? n : end + 2;
                for (int k = i; k < end; k++) if (sb.charAt(k) != '\n') sb.setCharAt(k, ' ');
                i = end;
            } else {
                i++;
            }
        }
        return sb.toString();
    }

    static int line(String src, int at) {
        int n = 1;
        for (int i = 0; i < at; i++) if (src.charAt(i) == '\n') n++;
        return n;
    }

    static String show(List<String> list) {
        return list.isEmpty() ? "" : ": " + String.join(" | ", list.subList(0, Math.min(list.size(), 15)))
                + (list.size() > 15 ? " | … " + (list.size() - 15) + " more" : "");
    }

    public static void main(String[] a) throws Exception {
        System.out.println("== 1. The checks can fail ==");
        check("an Italian log line is found",
                italianLogLines("x", "LOGGER.info(\"Auto-apply firewall config al boot (mode=\" + m + \")\");").size() == 1);
        check("the same line in English is not",
                italianLogLines("x", "LOGGER.info(\"Auto-apply firewall config at boot (mode=\" + m + \")\");").isEmpty());
        check("an Italian word on the next line of the call, in System.err and in LOGGER.log, is found",
                italianLogLines("x", "System.err.println(\"[X] the copy failed:\"\n + \" nessun file\");\n"
                        + "LOGGER.log(Level.WARNING, \"gia' fatto\", e);").size() == 2);
        check("an Italian exception message is found", italianLogLines("x", "throw new IllegalStateException(\"copia fallita\");").size() == 1);
        check("a comment in Italian, a commented-out call and a translation key are not",
                italianLogLines("x", "// il pannello al boot\nLOGGER.info(\"started\"); // al boot\n/* LOGGER.info(\"al boot\"); */\n"
                        + "System.out.println(I18n.tr(\"console.al.boot\"));\nLOGGER.info(\"non-empty, per day, e.g. a file\");").isEmpty());
        check("«e'» is Italian, a lone «e» is not", italianWords("x e' y").size() == 1 && italianWords("x e y").isEmpty());

        System.out.println("\n== 2-3. The log lines and exception messages of the panel ==");
        List<String> found = new ArrayList<>();
        int files = 0;
        try (Stream<Path> s = Files.walk(Path.of("src/main/java"))) {
            for (Path p : s.filter(x -> x.toString().endsWith(".java")).sorted().toList()) {
                files++;
                found.addAll(italianLogLines(p.toString().replaceFirst("^src/main/java/org/daemoxcp/mail/", ""), Files.readString(p)));
            }
        }
        check("no Italian word in a log line or an exception message (" + files + " files read)" + show(found), found.isEmpty() && files > 100);

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
