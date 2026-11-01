package org.mail_panel.system;

import org.mail_panel.scripts.FullMailServerScript;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Il php.ini che l'installazione scrive, misurato facendolo leggere a PHP.
 *
 * Il pacchetto php84 non installa nessun php.ini: in /usr/local/etc ci sono solo i campioni
 * php.ini-production e php.ini-development. Senza quel file PHP parte sui valori compilati
 * dentro, e php-fpm non se ne lamenta. Misurato su FreeBSD 15.1 con php84-8.4.26, senza
 * php.ini: upload_max_filesize 2M, post_max_size 8M, display_errors ACCESO, log_errors
 * SPENTO, expose_php acceso, session.save_path vuoto (cioe' /tmp).
 *
 * Quello che va provato qui, e che leggere il file non direbbe:
 *  - che PHP quel file lo accetta e che i valori diventano davvero quelli. Un refuso in una
 *    direttiva PHP non lo segnala: la ignora e tiene il predefinito. Quindi non si guarda il
 *    testo, si lancia "php -c" e si legge ini_get;
 *  - che il limite di caricamento e quello di Postfix sono d'accordo. Sono due numeri in due
 *    punti dello stesso script (r26): se PHP sta sotto, l'allegato viene rifiutato prima che
 *    Postfix dica la sua, e il messaggio che l'utente legge parla della cosa sbagliata.
 *
 * Si lancia sulla VM, dove php c'e':
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PhpIniTest
 */
public class PhpIniTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("php-ini");
        String script = new FullMailServerScript().getScriptContent();

        OUT.println("\n== Lo script scrive un php.ini ==");
        String ini = between(script, "cat > /usr/local/etc/php.ini << 'PHPINIEOF'\n", "\nPHPINIEOF\n");
        check("c'e' un blocco php.ini nello script", ini != null && !ini.isBlank());
        if (ini == null) { OUT.println("\n" + (++failed) + " CONTROLLI FALLITI"); System.exit(1); }
        check("e lo script si ferma se non riesce a scriverlo",
                script.contains("if [ ! -f /usr/local/etc/php.ini ]"));
        // Di roundcube, non piu' di www: la webmail ha il suo utente (RoundcubeUser).
        check("la cartella delle sessioni la crea, 700 e di roundcube",
                script.contains("mkdir -p /var/db/mailpanel/php_sessions")
                        && script.contains("chown -R roundcube:roundcube /var/db/mailpanel/php_sessions; chmod 700 /var/db/mailpanel/php_sessions")
                        && !script.contains("chown www:www /var/db/mailpanel/php_sessions"));
        check("il registro degli errori esiste e ruota",
                script.contains("touch /var/log/php_errors.log")
                        && script.contains("/usr/local/etc/newsyslog.conf.d/php-errors.conf"));

        OUT.println("\n== PHP lo legge, e i valori diventano quelli ==");
        if (!onPath("php")) {
            check("php c'e' (questa prova va lanciata sulla VM, non sul Mac)", false);
            OUT.println("\n" + failed + " CONTROLLI FALLITI");
            System.exit(1);
        }
        Path iniFile = home.resolve("php.ini");
        Files.writeString(iniFile, ini + "\n", StandardCharsets.UTF_8);
        Map<String, String> got = effective(iniFile);
        for (Map.Entry<String, String> e : got.entrySet())
            OUT.println(String.format("  %-26s [%s]", e.getKey(), e.getValue()));

        check("date.timezone e' UTC (r13)", "UTC".equals(got.get("date.timezone")));
        check("expose_php spento (r19: la versione di PHP non si annuncia)",
                "".equals(got.get("expose_php")) || "0".equals(got.get("expose_php")));
        check("display_errors spento, log_errors acceso (r19: all'utente niente, nel registro tutto)",
                ("".equals(got.get("display_errors")) || "0".equals(got.get("display_errors")))
                        && "1".equals(got.get("log_errors")));
        check("il registro degli errori ha un percorso, fuori dalla document root",
                got.get("error_log") != null && got.get("error_log").startsWith("/var/log/"));
        check("allow_url_include spento",
                "".equals(got.get("allow_url_include")) || "0".equals(got.get("allow_url_include")));
        // Se l'estensione session non c'e', TUTTE le sue direttive tornano vuote e i due
        // controlli qui sotto cadrebbero dicendo la cosa sbagliata: non "php.ini e' scritto
        // male" ma "manca php84-session". Succede davvero, perche' su FreeBSD session e' un
        // pacchetto a parte -- lo installa questo stesso script, ma non il solo php84.
        check("l'estensione session c'e' (senza, i controlli qui sotto non distinguono niente:"
                + " pkg install -y php84-session)", !"".equals(got.get("session.save_path")));
        check("le sessioni NON stanno in /tmp",
                got.get("session.save_path") != null && !got.get("session.save_path").isEmpty()
                        && !got.get("session.save_path").startsWith("/tmp"));
        check("il cookie di sessione e' HttpOnly, Secure e strict mode",
                "1".equals(got.get("session.cookie_httponly"))
                        && "1".equals(got.get("session.cookie_secure"))
                        && "1".equals(got.get("session.use_strict_mode")));

        OUT.println("\n== Il limite di PHP e quello di Postfix sono d'accordo ==");
        long upload = bytes(got.get("upload_max_filesize"));
        long post = bytes(got.get("post_max_size"));
        long memory = bytes(got.get("memory_limit"));
        long postfix = postfixMessageSizeLimit(script);
        OUT.println("  upload_max_filesize " + upload + "  post_max_size " + post
                + "  memory_limit " + memory + "  message_size_limit " + postfix);
        check("Postfix dichiara un limite in questo stesso script", postfix > 0);
        check("PHP non e' piu' stretto di Postfix: " + upload + " >= " + postfix, upload >= postfix);
        check("post_max_size sta sopra upload_max_filesize (nella richiesta c'e' anche il resto)",
                post > upload);
        check("memory_limit sta sopra post_max_size", memory > post);
        check("e non e' piu' il predefinito da 2M che si trova senza php.ini", upload > 2L * 1024 * 1024);

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }

    static final String[] WANTED = {
        "upload_max_filesize", "post_max_size", "memory_limit", "date.timezone",
        "session.save_path", "expose_php", "display_errors", "log_errors", "error_log",
        "allow_url_include", "session.cookie_httponly", "session.cookie_secure",
        "session.use_strict_mode",
    };

    /** I valori che PHP ha davvero dopo aver letto quel file. */
    static Map<String, String> effective(Path iniFile) throws Exception {
        StringBuilder php = new StringBuilder();
        for (String k : WANTED) php.append("echo \"").append(k).append("=\", ini_get(\"").append(k).append("\"), \"\\n\";");
        ProcessBuilder pb = new ProcessBuilder("php", "-c", iniFile.toAbsolutePath().toString(),
                "-r", php.toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        Map<String, String> got = new HashMap<>();
        for (String line : out.split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0) got.put(line.substring(0, eq), line.substring(eq + 1).trim());
        }
        if (got.size() < WANTED.length) {
            OUT.println(out);
            throw new IllegalStateException("php non ha risposto per tutte le direttive");
        }
        return got;
    }

    /** Il message_size_limit che lo script scrive in main.cf di Postfix. */
    static long postfixMessageSizeLimit(String script) {
        for (String line : script.split("\n")) {
            String t = line.trim();
            if (!t.startsWith("message_size_limit")) continue;
            int eq = t.indexOf('=');
            if (eq < 0) continue;
            try { return Long.parseLong(t.substring(eq + 1).trim()); } catch (NumberFormatException ignored) {}
        }
        return -1;
    }

    /** "50M" -> 52428800, come li legge PHP. */
    static long bytes(String shorthand) {
        if (shorthand == null || shorthand.isEmpty()) return -1;
        String s = shorthand.trim();
        char last = s.charAt(s.length() - 1);
        long multiplier = switch (Character.toLowerCase(last)) {
            case 'k' -> 1024L;
            case 'm' -> 1024L * 1024;
            case 'g' -> 1024L * 1024 * 1024;
            default -> 1L;
        };
        if (multiplier != 1L) s = s.substring(0, s.length() - 1);
        try { return Long.parseLong(s.trim()) * multiplier; } catch (NumberFormatException e) { return -1; }
    }

    static String between(String text, String start, String end) {
        int a = text.indexOf(start);
        if (a < 0) return null;
        int b = text.indexOf(end, a + start.length());
        return b < 0 ? null : text.substring(a + start.length(), b);
    }

    static boolean onPath(String command) {
        String path = System.getenv("PATH");
        if (path == null) return false;
        for (String dir : path.split(":"))
            if (Files.isExecutable(Path.of(dir, command))) return true;
        return false;
    }
}
