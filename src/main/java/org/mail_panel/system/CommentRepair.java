package org.mail_panel.system;

import org.mail_panel.security.Fail2banManager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * I commenti che una rinomina fatta sul testo ha rovinato nei file che il pannello scrive sul
 * server, rimessi a posto anche sui server gia' installati (30/10/2026).
 *
 * <p>La rinomina dei nomi JavaScript del 24/10/2026 e quella delle chiavi JSON del 16/10/2026
 * hanno cambiato parole italiane anche dentro i commenti degli script d'installazione: "che" e'
 * diventato "whichLabel", "riga" "lineItem", "gia'" "already'", "bloccati" "lockedPackages".
 * Non rompono niente, ma chi apre php.ini, nginx.conf o la lista permaban sul server trova frasi
 * senza senso. Il codice di oggi scrive di nuovo l'italiano; qui si sistemano i file scritti prima.
 *
 * <p>Le righe rovinate e quelle giuste stanno nella sezione "damagedComments" di
 * legacy-names.json, non nel codice: sono testo di prima, e una rinomina futura fatta sul testo
 * le cambierebbe di nuovo. Si sostituisce una riga solo se e' un commento (# o ;) uguale, a meno
 * dei rientri, a una riga rovinata: il rientro resta, le altre righe non si toccano, e un file
 * che l'amministratore ha cambiato altrove tiene le sue modifiche. Un commento non cambia quello
 * che il servizio fa, quindi niente nginx -t ne' reload. La scrittura e' quella di PanelMarker:
 * file temporaneo accanto, stessi permessi e proprietario, rename. Ripeterla non trova niente.
 */
public final class CommentRepair {

    private static final Logger LOGGER = Logger.getLogger(CommentRepair.class.getName());

    static final String SECTION = "damagedComments";

    private CommentRepair() {}

    /**
     * I file scritti con quei commenti: php.ini, la rotazione del suo registro e nginx.conf
     * dall'installazione completa, il file di nginx di Roundcube dall'installazione del solo
     * componente, la lista permaban, e gli script d'installazione che restano nella cartella del
     * pannello.
     */
    static List<Path> files() {
        return List.of(
                Path.of("/usr/local/etc/php.ini"),
                Path.of("/usr/local/etc/newsyslog.conf.d/php-errors.conf"),
                Path.of("/usr/local/etc/nginx/nginx.conf"),
                Path.of("/usr/local/etc/nginx/sites-enabled/roundcube.conf"),
                Path.of(Fail2banManager.PERMABAN_FILE),
                Path.of("install_scripts", "install_mail_server.sh"),
                Path.of("install_scripts", "install_roundcube.sh"));
    }

    public static void ensureAtBoot() {
        try {
            List<String> problems = new ArrayList<>();
            List<String> done = repair(files(), problems);
            if (!done.isEmpty()) LOGGER.info("[CommentRepair] comments repaired in " + String.join(", ", done));
            if (!problems.isEmpty()) LOGGER.warning("[CommentRepair] " + String.join("; ", problems));
        } catch (Throwable t) {
            LOGGER.warning("[CommentRepair] failed: " + t);
        }
    }

    /** Le coppie riga rovinata -> riga giusta, senza rientri; solo quelle fra due commenti. */
    static Map<String, String> pairs() {
        Map<String, String> out = new LinkedHashMap<>();
        for (String[] p : LegacyNames.pairs(SECTION))
            if (comment(p[0]) && comment(p[1])) out.put(p[0].strip(), p[1].strip());
        return out;
    }

    static boolean comment(String line) {
        String s = line.stripLeading();
        return s.startsWith("#") || s.startsWith(";");
    }

    /**
     * Lo stesso testo con le righe rovinate rimesse a posto, ognuna col suo rientro. Si confronta
     * la riga intera: una riga rovinata comincia con # o ;, quindi cambia solo un commento, e la
     * stessa frase dentro un'altra riga (un echo che la stampa) resta com'e'.
     */
    static String repaired(String content, Map<String, String> pairs) {
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String fixed = pairs.get(lines[i].strip());
            if (fixed == null) continue;
            String indent = lines[i].substring(0, lines[i].length() - lines[i].stripLeading().length());
            lines[i] = indent + fixed;
        }
        return String.join("\n", lines);
    }

    /** I file sistemati; un file che non c'e' si salta, un errore va in problems. */
    static List<String> repair(List<Path> files, List<String> problems) {
        Map<String, String> pairs = pairs();
        List<String> done = new ArrayList<>();
        if (pairs.isEmpty()) return done;
        for (Path p : files) {
            try {
                if (!Files.isRegularFile(p)) continue;
                // Un collegamento si segue: il file da sistemare e' quello a cui punta.
                Path real = p.toRealPath();
                String before = Files.readString(real, StandardCharsets.UTF_8);
                String after = repaired(before, pairs);
                if (after.equals(before)) continue;
                PanelMarker.replaceKeeping(real, after);
                done.add(p.toString());
            } catch (IOException | RuntimeException e) {
                problems.add(p + ": " + e.getMessage());
            }
        }
        return done;
    }
}
