package org.mail_panel.system;

/** Il verdetto della scheda Autoconfig: la riga che dichiarava non servito un file servito. */
public class AutoconfigTest {

    static int falliti = 0;
    static void esigi(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    public static void main(String[] a) {
        System.out.println("\n== pronto(elencoLetto, esaminati, funzionanti) ==");

        esigi("cinque domini su cinque: pronto",
                Autoconfig.pronto(true, 5, 5));
        esigi("quattro su cinque NON basta: un dominio resta da configurare a mano",
                !Autoconfig.pronto(true, 5, 4));
        esigi("zero su cinque: non pronto",
                !Autoconfig.pronto(true, 5, 0));

        // "0 == 0" e' vero, e senza la condizione esaminati>0 il pannello direbbe verde
        // proprio quando non ha guardato niente. E' il falso verde piu' silenzioso.
        esigi("ZERO domini provati non e' verde, anche se 0 su 0 'tornano'",
                !Autoconfig.pronto(true, 0, 0));

        // Se l'elenco dei domini non si e' potuto leggere, non e' stato provato nulla:
        // "non ho controllato" non e' "va bene".
        esigi("elenco non letto: non pronto, qualunque cosa dicano i conteggi",
                !Autoconfig.pronto(false, 5, 5));
        esigi("elenco non letto e zero prove: non pronto",
                !Autoconfig.pronto(false, 0, 0));

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
