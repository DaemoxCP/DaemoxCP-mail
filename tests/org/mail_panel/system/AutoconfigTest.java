package org.mail_panel.system;

/** Il verdetto della scheda Autoconfig: la riga che dichiarava non servito un file servito. */
public class AutoconfigTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) {
        System.out.println("\n== pronto(elencoLetto, esaminati, funzionanti) ==");

        require("cinque domini su cinque: pronto",
                Autoconfig.ready(true, 5, 5));
        require("quattro su cinque NON basta: un dominio resta da configurare a mano",
                !Autoconfig.ready(true, 5, 4));
        require("zero su cinque: non pronto",
                !Autoconfig.ready(true, 5, 0));

        // "0 == 0" e' vero, e senza la condizione esaminati>0 il pannello direbbe verde
        // proprio quando non ha guardato niente. E' il falso verde piu' silenzioso.
        require("ZERO domini provati non e' verde, anche se 0 su 0 'tornano'",
                !Autoconfig.ready(true, 0, 0));

        // Se l'elenco dei domini non si e' potuto leggere, non e' stato provato nulla:
        // "non ho controllato" non e' "va bene".
        require("elenco non letto: non pronto, qualunque cosa dicano i conteggi",
                !Autoconfig.ready(false, 5, 5));
        require("elenco non letto e zero prove: non pronto",
                !Autoconfig.ready(false, 0, 0));

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
