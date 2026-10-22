package org.mail_panel.security;

import org.mail_panel.webserver.SSLMailServer;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Il filtro di fail2ban del pannello, misurato con fail2ban-regex e non dedotto.
 *
 * La riga del registro e il filtro sono due meta' della stessa cosa (r26): la riga la scrive
 * SSLMailServer.auditLine, il filtro lo scrive Fail2banAutoSetup.filterContent, e qui si
 * prendono tutte e due DAL CODICE. Cambiarne una sola non rompe niente a vista — il pannello
 * parte, la pagina Firewall dice "jail attiva" — semplicemente non viene piu' bloccato
 * nessuno, che e' indistinguibile da "nessuno ci sta provando".
 *
 * Quello che va provato qui, e che compilare non direbbe:
 *  - fail2ban riconosce la DATA di ogni riga. Senza data non e' che non blocca: usa l'ora in
 *    cui ha letto la riga, quindi al riavvio del servizio un registro vecchio viene riletto
 *    come se fosse appena successo;
 *  - il failregex prende la riga nelle DUE forme in cui fail2ban gliela puo' dare: con la
 *    data (quando il datepattern non prende) e senza (quando prende, perche' allora la
 *    toglie). Il vecchio "^\S+ \[" reggeva una forma sola e stava in piedi per caso, sui
 *    decimali dei nanosecondi;
 *  - una riga di accesso RIUSCITO non fa bloccare nessuno.
 *
 * Si lancia sulla VM, dove fail2ban c'e':
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.security.Fail2banFilterTest
 */
public class Fail2banFilterTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** Il vecchio filtro, parola per parola: serve a misurare che il nuovo prenda di piu'. */
    static final String OLD_FILTER = "[Definition]\n\n"
            + "failregex = ^\\S+ \\[(?:LOGIN_FAILURE|LOGIN_2FA_FAILURE|LOGIN_INVALID_INPUT"
            + "|LOGIN_BLOCKED|CSRF_FAILURE)\\] ip=<HOST>\n\n"
            + "ignoreregex = ^\\S+ \\[(?:LOGIN_SUCCESS)\\]\n\n"
            + "datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S\n";

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("fail2ban-filter");

        OUT.println("\n== La riga che il pannello scrive ==");
        String line = SSLMailServer.auditLine("LOGIN_FAILURE", "203.0.113.9", "admin", "passkey refused");
        OUT.println("  " + line.trim());
        check("finisce con la Z di UTC, non con l'ora locale",
                line.matches("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z \\[.*\n"));
        check("non ha i decimali dei nanosecondi, che prima tenevano su il filtro per caso",
                !line.substring(0, line.indexOf(' ')).contains("."));
        // r13: il momento e' UTC, non l'ora del server. Lo si misura confrontandolo con
        // l'orologio UTC, non col fuso di questa macchina.
        String nowUtc = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
        check("ed e' davvero UTC (" + line.substring(0, 20) + " contro " + nowUtc + ")",
                Math.abs(java.time.Instant.parse(line.substring(0, line.indexOf(' ')))
                        .getEpochSecond() - java.time.Instant.now().getEpochSecond()) <= 2);
        check("l'indirizzo e l'utente ci sono dove il filtro li cerca",
                line.contains("[LOGIN_FAILURE] ip=203.0.113.9 user=admin"));

        OUT.println("\n== fail2ban legge quel registro col filtro del pannello ==");
        if (!Files.isExecutable(Path.of("/usr/local/bin/fail2ban-regex"))) {
            check("fail2ban-regex c'e' (questa prova va lanciata sulla VM, non sul Mac)", false);
            OUT.println("\n" + failed + " CONTROLLI FALLITI");
            System.exit(1);
        }

        // Il registro: righe vere, prese dal codice. Dieci fallimenti e cinque accessi
        // riusciti, piu' le forme che prima si perdevano.
        StringBuilder log = new StringBuilder();
        for (int i = 0; i < 10; i++)
            log.append(SSLMailServer.auditLine("LOGIN_FAILURE", "203.0.113." + (10 + i), "admin", "code refused"));
        for (int i = 0; i < 5; i++)
            log.append(SSLMailServer.auditLine("LOGIN_SUCCESS", "203.0.113." + (10 + i), "admin", "ok"));
        log.append(SSLMailServer.auditLine("CSRF_FAILURE", "198.51.100.7", "", "bad token"));
        log.append(SSLMailServer.auditLine("PASSKEY_REGISTER_FAILED", "198.51.100.8", "admin", "refused"));
        Path logFile = home.resolve("mail-panel-auth.log");
        Files.writeString(logFile, log, StandardCharsets.UTF_8);
        int lines = log.toString().split("\n").length;

        Path filter = home.resolve("mail-panel-auth.conf");
        Files.writeString(filter, Fail2banAutoSetup.filterContent(), StandardCharsets.UTF_8);
        Result now = fail2banRegex(logFile, filter);
        OUT.println("  " + now);
        check("fail2ban riconosce la data di TUTTE le " + lines + " righe", now.dates == lines);
        check("prende i 12 fallimenti e nessun altro", now.matched == 12);
        check("i 5 accessi riusciti non fanno bloccare nessuno", now.missed == 5);

        OUT.println("\n== Col filtro di prima, sulle stesse righe ==");
        Path old = home.resolve("old.conf");
        Files.writeString(old, OLD_FILTER, StandardCharsets.UTF_8);
        Result before = fail2banRegex(logFile, old);
        OUT.println("  " + before);
        // Qui sta il difetto: la Z non entra nel vecchio datepattern, quindi fail2ban non
        // riconosce NESSUNA data e usa l'ora in cui legge. E senza data tolta, il vecchio
        // failregex prende comunque le righe: e' per questo che non si vedeva niente.
        check("il vecchio datepattern non riconosce nemmeno una data (" + before.dates + " su "
                + lines + "): e' il difetto, non una differenza di gusto", before.dates == 0);
        check("il nuovo ne riconosce " + now.dates + " su " + lines, now.dates > before.dates);

        OUT.println("\n== E con la data tolta, che e' la forma che fail2ban passa davvero ==");
        // Quando il datepattern prende, fail2ban toglie la data PRIMA di cercare. Si misura
        // dando al filtro un registro gia' senza data: il vecchio failregex non prende piu'
        // niente, perche' resta uno spazio dove lui vuole uno \S+.
        StringBuilder stripped = new StringBuilder();
        for (String l : log.toString().split("\n"))
            stripped.append(l.substring(l.indexOf(' '))).append("\n");    // via la data, resta lo spazio
        Path strippedFile = home.resolve("stripped.log");
        Files.writeString(strippedFile, stripped, StandardCharsets.UTF_8);
        Result oldStripped = fail2banRegex(strippedFile, old);
        Result newStripped = fail2banRegex(strippedFile, filter);
        OUT.println("  vecchio: " + oldStripped);
        OUT.println("  nuovo:   " + newStripped);
        check("il vecchio failregex non prende piu' niente senza la data (" + oldStripped.matched + ")",
                oldStripped.matched == 0);
        check("il nuovo prende tutti e 12 i fallimenti anche cosi' (" + newStripped.matched + ")",
                newStripped.matched == 12);

        OUT.println("\n== L'anchor che decide se un blocco ferma davvero un pacchetto ==");
        check("riconosce anchor \"f2b/*\"",
                Fail2banAutoSetup.hasF2bAnchor("set skip on lo\nanchor \"f2b/*\"\npass\n"));
        check("riconosce anchor f2b/* senza virgolette",
                Fail2banAutoSetup.hasF2bAnchor("anchor f2b/*\n"));
        check("una riga COMMENTATA non conta",
                !Fail2banAutoSetup.hasF2bAnchor("# anchor \"f2b/*\"\npass\n"));
        check("e un pf.conf che non lo nomina non ce l'ha",
                !Fail2banAutoSetup.hasF2bAnchor("set skip on lo\ntable <permaban> persist\npass\n"));

        OUT.println("\n== Un filtro vecchio del pannello si riscrive, uno a mano no ==");
        check("quello di oggi si lascia stare",
                !Fail2banAutoSetup.shouldRewriteFilter(Fail2banAutoSetup.filterContent()));
        check("uno vecchio scritto dal pannello si riscrive",
                Fail2banAutoSetup.shouldRewriteFilter(Fail2banAutoSetup.MARKER + "\n" + OLD_FILTER));
        check("uno modificato a mano non si tocca",
                !Fail2banAutoSetup.shouldRewriteFilter("# il mio filtro\n" + OLD_FILTER));
        check("se non c'e' si scrive", Fail2banAutoSetup.shouldRewriteFilter(null));

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Quello che conta nell'uscita di fail2ban-regex. */
    record Result(int matched, int missed, int dates) {
        @Override public String toString() {
            return matched + " righe prese, " + missed + " no, " + dates + " date riconosciute";
        }
    }

    static final Pattern LINES = Pattern.compile("Lines: (\\d+) lines, (\\d+) ignored, (\\d+) matched, (\\d+) missed");
    // "|  [10] ^Year-Month-DayT24hour:Minute:SecondZone offset". Il modello comincia con '^',
    // non con una lettera: la prima versione cercava \w+ e contava zero date qualunque cosa
    // fosse successa davvero.
    static final Pattern DATE_HIT = Pattern.compile("\\|\\s*\\[(\\d+)\\]\\s+\\S+.*");

    static Result fail2banRegex(Path log, Path filter) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/fail2ban-regex",
                log.toAbsolutePath().toString(), filter.toAbsolutePath().toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        Matcher m = LINES.matcher(out);
        if (!m.find()) {
            OUT.println(out);
            throw new IllegalStateException("fail2ban-regex non ha stampato il riepilogo");
        }
        int matched = Integer.parseInt(m.group(3)), missed = Integer.parseInt(m.group(4));
        // Le date: la sezione "Date template hits" elenca [N] per modello. Se la sezione e'
        // vuota, nessuna data e' stata riconosciuta.
        int dates = 0;
        boolean inDates = false;
        for (String l : out.split("\n")) {
            if (l.startsWith("Date template hits")) { inDates = true; continue; }
            if (inDates) {
                if (l.startsWith("`-")) break;
                Matcher d = DATE_HIT.matcher(l);
                if (d.matches()) dates += Integer.parseInt(d.group(1));
            }
        }
        return new Result(matched, missed, dates);
    }
}
