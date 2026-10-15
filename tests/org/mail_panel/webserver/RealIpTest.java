package org.mail_panel.webserver;

/**
 * Da quale pezzo di X-Forwarded-For si ricava l'indirizzo di chi bussa.
 *
 * E' la riga che, letta da sinistra, rendeva inutile il limite dei tentativi di accesso:
 * bastava cambiare l'intestazione a ogni prova per non essere mai lockedPackages.
 */
public class RealIpTest {

    static int falliti = 0;
    static void esigi(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }
    static void atteso(String intestazione, String voluto) {
        String avuto = SSLMailServer.ipDaForwardedFor(intestazione);
        boolean ok = (voluto == null) ? (avuto == null) : voluto.equals(avuto);
        System.out.println((ok ? "  OK   " : "  FALLITO ")
                + String.format("%-46s -> %s", "\"" + intestazione + "\"", avuto)
                + (ok ? "" : "   (atteso " + voluto + ")"));
        if (!ok) falliti++;
    }

    public static void main(String[] a) {
        System.out.println("\n== il caso normale dietro Cloudflare ==");
        // Cloudflare accoda il mittente vero in fondo a quello che il client ha mandato.
        atteso("203.0.113.9", "203.0.113.9");
        atteso("9.9.9.9, 203.0.113.9", "203.0.113.9");

        System.out.println("\n== la falsificazione che prima passava ==");
        // Prima si prendeva il PRIMO pezzo: qui avrebbe restituito 1.2.3.4, cioe' un indirizzo
        // scelto da chi bussa. Cambiandolo a ogni tentativo, nessun blocco sarebbe mai scattato.
        esigi("un indirizzo messo dal client non vince sul valore aggiunto dal proxy",
                !"1.2.3.4".equals(SSLMailServer.ipDaForwardedFor("1.2.3.4, 203.0.113.9")));
        atteso("1.2.3.4, 203.0.113.9", "203.0.113.9");

        System.out.println("\n== catene con piu' proxy fidati in coda ==");
        atteso("203.0.113.9, 172.68.1.1", "203.0.113.9");
        atteso("203.0.113.9, 172.68.1.1, 104.16.0.5", "203.0.113.9");

        System.out.println("\n== valori non validi: si saltano, non si accettano ==");
        atteso("pippo, 203.0.113.9", "203.0.113.9");
        atteso("203.0.113.9, pippo", "203.0.113.9");
        atteso("pippo", null);
        atteso("", null);
        atteso(null, null);

        System.out.println("\n== se sono TUTTI fidati non si inventa niente ==");
        // Chi chiama ripiega sull'indirizzo TCP: meglio un indirizzo vero e inutile che uno
        // plausibile e falso.
        atteso("127.0.0.1", null);
        atteso("172.68.1.1, 104.16.0.5", null);

        System.out.println("\n== spazi e forme sciatte ==");
        atteso("  203.0.113.9  ,  172.68.1.1  ", "203.0.113.9");
        atteso("203.0.113.9,172.68.1.1", "203.0.113.9");

        System.out.println("\n== e il confronto CIDR e' sui bit, non sulle stringhe ==");
        esigi("104.23.255.255 e' dentro 104.16.0.0/13 (un confronto testuale lo mancherebbe)",
                org.mail_panel.security.TrustedProxy.isTrustedProxy("104.23.255.255"));
        esigi("173.245.64.1 NON e' dentro 173.245.48.0/20 (un confronto testuale lo accetterebbe)",
                !org.mail_panel.security.TrustedProxy.isTrustedProxy("173.245.64.1"));
        esigi("188.114.97.7 e' riconosciuto: e' l'indirizzo su cui rispondono i due pannelli",
                org.mail_panel.security.TrustedProxy.isTrustedProxy("188.114.97.7"));

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
