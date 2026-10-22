package org.mail_panel.security;

import org.mail_panel.Main;
import org.mail_panel.scripts.FullMailServerScript;

import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;

/**
 * La password di root di MySQL, che prima non esisteva, e le due strade da cui i segreti
 * uscivano dal pannello.
 *
 * Quello che va provato qui, e che compilare non direbbe:
 *  - la prima password si GENERA, e una volta generata non cambia piu'. Se cambiasse a ogni
 *    installazione, quella scritta nel file e quella impostata in MySQL non sarebbero piu'
 *    lo stesso segreto e nessuno entrerebbe piu' come root;
 *  - la password di root non contiene caratteri che la spezzerebbero dove finisce davvero:
 *    dentro IDENTIFIED BY '...' in un here-document, e dentro un file di opzioni di MySQL.
 *    Non si guarda l'alfabeto: si fa espandere il here-document a /bin/sh e si guarda la
 *    riga che ne esce;
 *  - la password dell'UTENTE DEL PANNELLO ha un alfabeto piu' stretto, e il motivo non e'
 *    la pigrizia: quella finisce in un URL (mysql://utente:password@host/db). Qui si
 *    ricostruisce l'URL e lo si rilegge, perche' una chiocciola o un segno di percento
 *    dentro la password lo spezzerebbero in silenzio;
 *  - i segreti non passano piu' per gli argomenti ne' per lo standard output. Il controllo
 *    non guarda il codice: lancia uno script vero con executeScriptWithSecrets, cattura
 *    tutto quello che il pannello stampa, e pretende che il segreto non ci sia e che sia
 *    arrivato al figlio;
 *  - lo script e il chiamante sono due parti della stessa cosa (r26): se uno sposta un
 *    argomento e l'altro no, l'installazione configura il database col nome dell'host. Qui
 *    si legge l'elenco dei posizionali dallo script generato e si confronta con quello che
 *    Main gli passa.
 *
 * Si lancia da una cartella qualunque:
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.security.MysqlRootPasswordTest
 */
public class MysqlRootPasswordTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** L'ordine dei posizionali che Main.installMailServer passa allo script, in ordine. */
    static final List<String> ARGUMENTS_FROM_THE_PANEL = List.of(
            "MYSQL_HOST", "MYSQL_PORT", "MYSQL_USER", "MYSQL_DATABASE", "MAIL_HOSTNAME",
            "ROUNDCUBE_DOMAIN", "ROUNDCUBE_PORT", "ROUNDCUBE_SSL_CERT", "ROUNDCUBE_SSL_KEY",
            "ROUNDCUBE_SSL_CHAIN");

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("mysql-root-password");
        PanelSecrets.dir = home.resolve("secrets");
        reset();
        // Senza questo, executeScript aspetta un ENTER quando la prova gira da un terminale.
        var interactive = Main.class.getDeclaredField("nonInteractive");
        interactive.setAccessible(true);
        interactive.set(null, true);

        OUT.println("\n== La prima password di root ==");
        check("all'inizio non c'e'", PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD).isEmpty());
        String generated = PanelSecrets.ensureMysqlRootPassword();
        check("dopo c'e', ed e' lunga 28", generated.length() == 28);
        check("la seconda chiamata restituisce LA STESSA, non una nuova",
                generated.equals(PanelSecrets.ensureMysqlRootPassword()));
        reset();
        check("riletta dal file e' ancora quella",
                generated.equals(PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD)));
        PanelSecrets.setText(PanelSecrets.MYSQL_ROOT_PASSWORD, "messa-a-mano");
        check("una password messa a mano non viene sostituita",
                "messa-a-mano".equals(PanelSecrets.ensureMysqlRootPassword()));
        check("il file e' leggibile solo da root, la cartella solo attraversabile da root",
                "rw-------".equals(permissions(PanelSecrets.dir.resolve("panel-secrets.properties")))
                        && "rwx------".equals(permissions(PanelSecrets.dir)));

        OUT.println("\n== La password di root sopravvive al here-document dell'installazione ==");
        // Non si guarda l'alfabeto: si prende la riga ESATTA dello script, la si fa espandere
        // a /bin/sh, e poi la si rilegge come la legge MySQL. I due passaggi rompono per
        // motivi diversi, e uno solo non basta: la barra rovescia la mangia la shell (in un
        // here-document non quotato "\\" diventa "\"), mentre l'apice attraversa la shell
        // intatto e chiude il letterale in faccia a MySQL. Misurato: con un controllo che
        // confrontava solo il testo espanso, un alfabeto con l'apice passava la prova.
        int through = 0, mangledByShell = 0, mangledBySql = 0;
        for (int i = 0; i < 200; i++) {
            String password = PanelSecrets.newPassword(28);
            String expanded = expandHereDocument(password);
            String wanted = "ALTER USER 'root'@'localhost' IDENTIFIED BY '" + password + "';";
            if (!wanted.equals(expanded)) { mangledByShell++; continue; }
            if (!password.equals(passwordAsMysqlReadsIt(expanded))) { mangledBySql++; continue; }
            through++;
        }
        check("200 password generate arrivano a MySQL intatte (" + through + " su 200; "
                + mangledByShell + " rotte dalla shell, " + mangledBySql + " dal letterale SQL)",
                mangledByShell == 0 && mangledBySql == 0);

        // Lo stesso, nella seconda forma in cui la password finisce: il file di opzioni.
        // Un '#' non quotato apre un commento, e MySQL leggerebbe mezza password.
        int readBack = 0;
        for (int i = 0; i < 200; i++) {
            String password = PanelSecrets.newPassword(28);
            if (password.equals(optionFileValue(optionFile(password)))) readBack++;
        }
        check("200 password rilette dal file di opzioni come MySQL lo legge (" + readBack + " su 200)",
                readBack == 200);

        OUT.println("\n== La password dell'utente del pannello finisce in un URL ==");
        int urlOk = 0, urlBroken = 0;
        for (int i = 0; i < 500; i++) {
            String password = PanelSecrets.newAlphanumericPassword(24);
            try {
                URI dsn = new URI("mysql://mailpanel:" + password + "@127.0.0.1/roundcubemail");
                boolean same = ("mailpanel:" + password).equals(dsn.getUserInfo())
                        && "127.0.0.1".equals(dsn.getHost())
                        && "/roundcubemail".equals(dsn.getPath());
                if (same) urlOk++; else urlBroken++;
            } catch (Exception e) {
                urlBroken++;
            }
        }
        check("500 password del pannello dentro mysql://utente:password@host/db, rilette uguali ("
                + urlOk + " su 500)", urlBroken == 0);
        // Provato a fallire: con l'alfabeto di root l'URL si rompe. Se un giorno smettesse
        // di rompersi, questo controllo non distinguerebbe piu' niente e va tolto.
        int richBroken = 0;
        for (int i = 0; i < 500; i++) {
            String password = PanelSecrets.newPassword(24);
            try {
                URI dsn = new URI("mysql://mailpanel:" + password + "@127.0.0.1/roundcubemail");
                if (!("mailpanel:" + password).equals(dsn.getUserInfo())
                        || !"127.0.0.1".equals(dsn.getHost())) richBroken++;
            } catch (Exception e) {
                richBroken++;
            }
        }
        check("e con l'alfabeto di root lo stesso URL si rompe (" + richBroken + " su 500): e' per"
                + " questo che i due alfabeti sono diversi", richBroken > 250);

        OUT.println("\n== Il segreto non passa piu' per lo schermo ne' per gli argomenti ==");
        Path script = home.resolve("echo-secret.sh");
        Files.writeString(script, "#!/bin/sh\n"
                + "# Scrive la LUNGHEZZA del segreto, mai il segreto: se lo stampasse, questa\n"
                + "# prova non distinguerebbe piu' lo standard output del pannello da quello\n"
                + "# dello script.\n"
                + "printf '%s' \"${MYSQL_ROOT_PASSWORD}\" > \"$1/arrived\"\n"
                + "echo \"the child got ${#MYSQL_ROOT_PASSWORD} characters\"\n", StandardCharsets.UTF_8);
        String secret = PanelSecrets.newPassword(28);
        String printed = capture(() -> Main.executeScriptWithSecrets(script.toString(),
                "prova", Map.of("MYSQL_ROOT_PASSWORD", secret), home.toString()));
        check("il segreto arriva al figlio nell'ambiente",
                secret.equals(Files.readString(home.resolve("arrived"), StandardCharsets.UTF_8)));
        check("e non compare in niente di quello che il pannello stampa", !printed.contains(secret));
        check("al suo posto si dice quanti argomenti ci sono", printed.contains("1 (hidden"));
        // E se un giorno qualcuno rimette un segreto FRA GLI ARGOMENTI, non deve comparire
        // lo stesso: qui glielo si passa apposta come argomento e si guarda lo schermo.
        String asArgument = PanelSecrets.newPassword(28);
        String withSecretArgument = capture(() -> Main.executeScriptWithSecrets(script.toString(),
                "prova", Map.of("MYSQL_ROOT_PASSWORD", secret), home.toString(), asArgument));
        check("un segreto passato come argomento non finisce comunque sullo schermo",
                !withSecretArgument.contains(asArgument));
        String plain = capture(() -> Main.executeScript(script.toString(), "prova", home.toString()));
        check("senza segreti gli argomenti si stampano come prima", plain.contains(home.toString()));

        OUT.println("\n== Lo script e il pannello sono d'accordo su chi e' il numero N ==");
        String text = new FullMailServerScript().getScriptContent();
        for (int i = 0; i < ARGUMENTS_FROM_THE_PANEL.size(); i++) {
            String name = ARGUMENTS_FROM_THE_PANEL.get(i);
            String position = i < 9 ? "\"$" + (i + 1) + "\"" : "\"${" + (i + 1) + "}\"";
            check("argomento " + (i + 1) + " = " + name, text.contains(name + "=" + position));
        }
        check("nessuna password e' piu' un argomento posizionale",
                !text.contains("MYSQL_PASSWORD=\"$") && !text.contains("MYSQL_ROOT_PASSWORD=\"$"));
        check("lo script si ferma se le password non sono nell'ambiente",
                text.contains("MYSQL_PASSWORD not in the environment")
                        && text.contains("MYSQL_ROOT_PASSWORD not in the environment"));
        check("root non entra piu' senza password dove si fa il lavoro",
                !text.contains("mysql -u root < ") && !text.contains("mysql -u root << ROUNDCUBE_DB")
                        && text.contains("--defaults-extra-file=\"$MYSQL_ROOT_CNF\""));
        check("il file SQL col segreto non sta piu' in /tmp", !text.contains("/tmp/mysql_setup.sql"));
        Path generatedScript = home.resolve("install_mail_server.sh");
        Files.writeString(generatedScript, text, StandardCharsets.UTF_8);
        check("lo script generato passa sh -n", run("/bin/sh", "-n", generatedScript.toString()) == 0);

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** La riga dell'installazione, espansa da /bin/sh esattamente come nello script. */
    static String expandHereDocument(String password) throws Exception {
        String shell = "MYSQL_ROOT_PASSWORD='" + password.replace("'", "'\\''") + "'\n"
                + "cat << EOROOT\n"
                + "ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';\n"
                + "EOROOT\n";
        return output("/bin/sh", "-c", shell).trim();
    }

    /**
     * La password che MySQL legge da quella riga, o null se la riga non e' piu' l'istruzione
     * che doveva essere.
     *
     * <p>Legge il letterale fra apici come lo legge MySQL: la barra rovescia e' un'escape,
     * due apici di fila sono un apice, il primo apice non escapato chiude. Dopo il letterale
     * deve restare esattamente {@code ;}: se la password contiene un apice, il letterale
     * chiude in mezzo e quello che resta e' spazzatura, cioe' un'istruzione rotta — che e'
     * esattamente il guasto che l'alfabeto deve impedire.
     */
    static String passwordAsMysqlReadsIt(String statement) {
        String head = "ALTER USER 'root'@'localhost' IDENTIFIED BY '";
        if (!statement.startsWith(head)) return null;
        StringBuilder value = new StringBuilder();
        int i = head.length();
        while (i < statement.length()) {
            char c = statement.charAt(i);
            if (c == '\\' && i + 1 < statement.length()) {          // escape di MySQL
                value.append(unescape(statement.charAt(i + 1)));
                i += 2;
            } else if (c == '\'' && i + 1 < statement.length() && statement.charAt(i + 1) == '\'') {
                value.append('\'');                                  // '' e' un apice
                i += 2;
            } else if (c == '\'') {
                return statement.substring(i + 1).equals(";") ? value.toString() : null;
            } else {
                value.append(c);
                i++;
            }
        }
        return null;                                                 // letterale mai chiuso
    }

    /** Le escape di MySQL che cambiano il carattere; le altre danno il carattere stesso. */
    static char unescape(char c) {
        switch (c) {
            case '0': return '\0';
            case 'n': return '\n';
            case 'r': return '\r';
            case 't': return '\t';
            case 'b': return '\b';
            case 'Z': return (char) 26;
            default:  return c;
        }
    }

    /** Il file di opzioni come lo scrive lo script. */
    static String optionFile(String password) throws Exception {
        String shell = "MYSQL_ROOT_PASSWORD='" + password.replace("'", "'\\''") + "'\n"
                + "cat << EOCNF\n[client]\nuser=root\npassword=\"$MYSQL_ROOT_PASSWORD\"\nEOCNF\n";
        return output("/bin/sh", "-c", shell);
    }

    /**
     * Il valore che MySQL legge da quel file: taglia a un '#' non quotato, toglie le
     * virgolette intorno. E' la regola dei file di opzioni, scritta qui apposta per
     * misurare che la forma scelta regga.
     */
    static String optionFileValue(String file) {
        for (String line : file.split("\n")) {
            if (!line.startsWith("password=")) continue;
            String value = line.substring("password=".length());
            if (value.startsWith("\"")) {
                int end = value.indexOf('"', 1);
                return end < 0 ? null : value.substring(1, end);
            }
            int hash = value.indexOf('#');
            return hash < 0 ? value.trim() : value.substring(0, hash).trim();
        }
        return null;
    }

    static String output(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        return out;
    }

    static int run(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        OUT.print(new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        return p.waitFor();
    }

    /** Tutto quello che il pannello scrive mentre fa una cosa. */
    static String capture(ThrowingRunnable what) throws Exception {
        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        PrintStream before = System.out;
        System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
        try { what.run(); } finally { System.setOut(before); }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    interface ThrowingRunnable { void run() throws Exception; }

    static String permissions(Path p) throws Exception {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }

    static void reset() throws Exception {
        var m = PanelSecrets.class.getDeclaredMethod("reset");
        m.setAccessible(true);
        m.invoke(null);
    }
}
