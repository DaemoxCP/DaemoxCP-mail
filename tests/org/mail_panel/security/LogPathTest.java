package org.mail_panel.security;

import java.util.List;

/**
 * Da dove si ricavano i log che una jail sorveglia.
 *
 * Le due uscite di fail2ban-client hanno forme diverse, e una lettura che funziona su una
 * sola delle due e' il difetto che questa prova esiste per impedire: la scheda mostrava il
 * log e il controllo del filtro diceva che non ce n'era.
 */
public class LogPathTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) {
        System.out.println("\n== uscita di \"get <jail> logpath\" (caratteri di albero) ==");
        List<String> r = Fail2banManager.pathsIn(
            "Current monitored log file(s):\n`- /usr/local/www/roundcube/logs/userlogins\n");
        require("trova il percorso preceduto da \"`-\"",
                r.equals(List.of("/usr/local/www/roundcube/logs/userlogins")));

        System.out.println("\n== piu' file, con \"|-\" e \"`-\" ==");
        r = Fail2banManager.pathsIn(
            "Current monitored log file(s):\n|- /var/log/maillog\n`- /var/log/auth.log\n");
        require("li trova entrambi, nell'ordine",
                r.equals(List.of("/var/log/maillog", "/var/log/auth.log")));

        System.out.println("\n== uscita di \"status <jail>\" ==");
        r = Fail2banManager.pathsIn(
            "Status for the jail: dovecot\n|- Filter\n|  |- Currently failed: 0\n"
          + "|  `- File list:    /var/log/maillog\n`- Actions\n   |- Currently banned: 0\n");
        require("trova il file dopo \"File list:\"", r.equals(List.of("/var/log/maillog")));

        System.out.println("\n== cio' che NON e' un log sorvegliato ==");
        r = Fail2banManager.pathsIn("/usr/local/bin/fail2ban-client: comando non trovato");
        require("il percorso del comando stesso viene scartato", r.isEmpty());
        r = Fail2banManager.pathsIn("Sorry but the jail 'x' does not exist");
        require("un messaggio senza percorsi non ne inventa", r.isEmpty());
        require("null non fa esplodere niente", Fail2banManager.pathsIn(null).isEmpty());

        System.out.println("\n== nessun duplicato ==");
        r = Fail2banManager.pathsIn("|- /var/log/maillog\n`- /var/log/maillog\n");
        require("lo stesso file compare una volta sola", r.size() == 1);

        System.out.println("\n== e la lettura VECCHIA sullo stesso caso ==");
        // Com'era: si pretendeva una riga che COMINCIASSE con "/", dopo aver tolto solo
        // trattini, asterischi e spazi. Il carattere di albero restava, e la riga non passava.
        String line = "`- /usr/local/www/roundcube/logs/userlogins";
        boolean old = line.trim().replaceAll("^[-*\\s]+", "").startsWith("/");
        System.out.println("  la riga passava il vecchio controllo? " + old);
        require("la lettura vecchia BOCCIA un log che c'e': il difetto si riproduce", !old);

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
