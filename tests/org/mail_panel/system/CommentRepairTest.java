package org.mail_panel.system;

import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.scripts.RoundcubeScript;
import org.mail_panel.security.Fail2banManager;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * I commenti rovinati dalle rinomine fatte sul testo tornano a posto all'avvio
 * (CommentRepair.repair), in una cartella temporanea.
 *
 * I file "di prima" si costruiscono da quelli che il codice di oggi scrive, rimettendo le righe
 * rovinate prese dal file di dati: la prova non scrive nessuna riga rovinata. Dopo la
 * riparazione ogni file deve essere identico byte per byte a quello di oggi, con gli stessi
 * permessi; una seconda passata non deve trovare niente; le righe dell'amministratore, un file
 * che non c'e' e una riga rovinata che non e' un commento restano come sono. L'effetto sui file
 * veri lo misura la prova sulla VM (reperti).
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.CommentRepairTest
 */
public class CommentRepairTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** Il corpo di un here-document dello script: quello che finisce nel file sul server. */
    static String heredoc(String script, String end) {
        int start = script.indexOf("<< '" + end + "'\n");
        if (start < 0) start = script.indexOf("<< " + end + "\n");
        start = script.indexOf('\n', start) + 1;
        int stop = script.indexOf("\n" + end + "\n", start);
        if (stop < 0) {
            // here-document rientrato (RoundcubeScript): la riga di chiusura ha davanti degli spazi
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\n[ \t]*" + end + "\n").matcher(script);
            if (!m.find(start)) throw new IllegalStateException("here-document " + end + " non trovato");
            stop = m.start();
        }
        return script.substring(start, stop + 1);
    }

    /** Il testo di prima: ogni riga giusta, col suo rientro, torna quella rovinata. */
    static String damaged(String today, Map<String, String> pairs) {
        Map<String, String> back = new LinkedHashMap<>();
        pairs.forEach((bad, good) -> back.put(good, bad));
        return CommentRepair.repaired(today, back);
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> pairs = CommentRepair.pairs();
        String full = new FullMailServerScript().getScriptContent();
        String roundcube = new RoundcubeScript().getScriptContent();

        System.out.println("\n== Il file di dati ==");
        check("damagedComments: " + pairs.size() + " righe, tutte commento rovinato -> commento diverso",
                pairs.size() == LegacyNames.pairs(CommentRepair.SECTION).size() && pairs.size() > 20
                        && pairs.entrySet().stream().allMatch(e -> !e.getKey().equals(e.getValue())));
        String today = full + roundcube + Fail2banManager.PERMABAN_HEADER;
        List<String> missing = new ArrayList<>(), stillThere = new ArrayList<>();
        pairs.forEach((bad, good) -> {
            if (!today.lines().map(String::strip).toList().contains(good)) missing.add(good);
            if (today.lines().map(String::strip).toList().contains(bad)) stillThere.add(bad);
        });
        missing.forEach(x -> System.out.println("        non scritta dal codice: " + x));
        stillThere.forEach(x -> System.out.println("        ancora scritta dal codice: " + x));
        check("ogni riga giusta e' quella che il codice di oggi scrive", missing.isEmpty());
        check("nessuna riga rovinata e' ancora scritta dal codice", stillThere.isEmpty());

        // I file come li scrive il codice di oggi, con i nomi che hanno sul server.
        Map<String, String> files = new LinkedHashMap<>();
        files.put("php.ini", heredoc(full, "PHPINIEOF"));
        files.put("php-errors.conf", heredoc(full, "PHPLOGEOF"));
        files.put("nginx.conf", heredoc(full, "NGINX_CONF"));
        files.put("roundcube.conf", heredoc(roundcube, "NGINXCONF"));
        files.put("permaban.list", Fail2banManager.PERMABAN_HEADER + "203.0.113.7\n");
        files.put("install_mail_server.sh", full);
        files.put("install_roundcube.sh", roundcube);

        System.out.println("\n== Un server installato prima ==");
        Path dir = Files.createTempDirectory("comment-repair");
        List<Path> paths = new ArrayList<>();
        int damagedFiles = 0;
        for (Map.Entry<String, String> e : files.entrySet()) {
            Path p = dir.resolve(e.getKey());
            String before = damaged(e.getValue(), pairs);
            if (!before.equals(e.getValue())) damagedFiles++;
            Files.writeString(p, before);
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-r-----"));
            paths.add(p);
        }
        check("i file di prima hanno davvero le righe rovinate (" + damagedFiles + " su " + files.size() + ")",
                damagedFiles == files.size());

        // php.ini: l'amministratore ha aggiunto una riga e un suo commento; il file e' un collegamento.
        Path realIni = dir.resolve("php.ini.real");
        String adminIni = Files.readString(dir.resolve("php.ini")) + "; il mio commento\nmemory_limit = 512M\n";
        Files.writeString(realIni, adminIni);
        Files.setPosixFilePermissions(realIni, PosixFilePermissions.fromString("rw-r-----"));
        Files.delete(dir.resolve("php.ini"));
        Files.createSymbolicLink(dir.resolve("php.ini"), realIni.getFileName());

        // Una riga rovinata che non e' un commento: un echo che la stampa.
        String bad = pairs.keySet().iterator().next();
        Path echo = dir.resolve("echo.sh");
        Files.writeString(echo, "echo \"" + bad + "\"\n");
        paths.add(echo);
        paths.add(dir.resolve("non-esiste.conf"));

        List<String> problems = new ArrayList<>();
        List<String> done = CommentRepair.repair(paths, problems);
        problems.forEach(x -> System.out.println("        " + x));
        check("riparati " + done.size() + " file, senza errori", done.size() == files.size() && problems.isEmpty());
        for (Map.Entry<String, String> e : files.entrySet()) {
            if (e.getKey().equals("php.ini")) continue;
            Path p = dir.resolve(e.getKey());
            check("  " + e.getKey() + " identico a quello di oggi, permessi rw-r-----",
                    Files.readString(p).equals(e.getValue())
                            && PosixFilePermissions.toString(Files.getPosixFilePermissions(p)).equals("rw-r-----"));
        }
        check("php.ini: sistemato il file vero, le righe dell'amministratore restano, il collegamento resta",
                Files.isSymbolicLink(dir.resolve("php.ini"))
                        && Files.readString(realIni).equals(files.get("php.ini") + "; il mio commento\nmemory_limit = 512M\n")
                        && PosixFilePermissions.toString(Files.getPosixFilePermissions(realIni)).equals("rw-r-----"));
        check("una riga rovinata fuori da un commento non si tocca",
                Files.readString(echo).equals("echo \"" + bad + "\"\n"));
        try (var s = Files.list(dir)) {
            check("nessun file temporaneo rimasto", s.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")));
        }

        System.out.println("\n== Al secondo avvio ==");
        List<String> again = CommentRepair.repair(paths, problems);
        check("una seconda passata non trova niente", again.isEmpty() && problems.isEmpty());

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }
}
