package org.mail_panel.webserver;

import org.mail_panel.database.MailDatabase;

import java.util.ArrayList;
import java.util.List;

/**
 * Che cosa il pannello dice dopo aver creato, modificato, disattivato o eliminato un alias.
 *
 * Postfix legge solo gli alias con active=1 e li applica prima delle caselle. Da quando un alias
 * si puo' disattivare, "c'e' la riga casella -> casella" non vuol piu' dire "la casella tiene una
 * copia": la vecchia logica guardava la riga e non se era attiva, e taceva proprio nel caso in cui
 * la casella aveva smesso di ricevere.
 */
public class AliasMessagesTest {

    static int falliti = 0;
    static void esigi(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    static MailDatabase.Alias alias(String sorgente, String destinazione, boolean attivo) {
        MailDatabase.Alias a = new MailDatabase.Alias();
        a.source = sorgente;
        a.destination = destinazione;
        a.active = attivo;
        return a;
    }

    static List<MailDatabase.Alias> tabella(MailDatabase.Alias... righe) {
        return new ArrayList<>(List.of(righe));
    }

    static String nota(String indirizzo, boolean casella, List<MailDatabase.Alias> righe) {
        return SSLMailServer.dopoGliAlias(indirizzo, casella, righe);
    }

    /** La logica di prima (creazione soltanto): una riga casella -> casella bastava, attiva o no. */
    static boolean vecchiaAvvisava(String sorgente, boolean casella, List<MailDatabase.Alias> righe) {
        boolean copiaInCasella = false;
        for (MailDatabase.Alias a : righe)
            if (a.source.equals(sorgente) && a.destination.equals(sorgente)) copiaInCasella = true;
        return casella && !copiaInCasella;
    }

    public static void main(String[] x) {
        String io = "info@domain-a.test", fuori = "report@domain-b.test", altro = "owner@domain-b.test";

        System.out.println("\n== una casella ==");
        esigi("senza alias riceve: niente da dire", nota(io, true, tabella()) == null);
        esigi("con solo \"se stessa -> se stessa\" riceve: niente da dire",
                nota(io, true, tabella(alias(io, io, true))) == null);
        esigi("inoltrata ma con la copia attiva: niente da dire",
                nota(io, true, tabella(alias(io, fuori, true), alias(io, io, true))) == null);
        esigi("con l'inoltro disattivato riceve di nuovo: niente da dire",
                nota(io, true, tabella(alias(io, fuori, false))) == null);

        String n = nota(io, true, tabella(alias(io, fuori, true)));
        esigi("inoltrata senza copia: lo dice", n != null && n.contains("va solo a " + fuori));
        esigi("  e dice di AGGIUNGERE la copia, che non c'e'", n != null && n.contains("aggiungi l'alias " + io + " -> " + io));

        n = nota(io, true, tabella(alias(io, fuori, true), alias(io, altro, true)));
        esigi("con due destinazioni le nomina tutte e due", n != null && n.contains("va solo a " + fuori + ", " + altro));

        n = nota(io, true, tabella(alias(io, fuori, true), alias(io, io, false)));
        esigi("copia DISATTIVATA: la casella non riceve, e lo dice", n != null && n.contains("va solo a " + fuori));
        esigi("  e dice di RIATTIVARLA: aggiungerla darebbe \"Alias gia' esistente\"",
                n != null && n.contains("riattiva l'alias " + io + " -> " + io));

        esigi("gli alias di un altro indirizzo dello stesso dominio non contano",
                nota(io, true, tabella(alias("sales@domain-a.test", fuori, true))) == null);

        System.out.println("\n== un indirizzo che non e' una casella ==");
        String solo = "dmarc@domain-a.test";
        esigi("con un alias attivo esiste: niente da dire", nota(solo, false, tabella(alias(solo, fuori, true))) == null);
        n = nota(solo, false, tabella(alias(solo, fuori, false)));
        esigi("con l'unico alias disattivato la posta viene rifiutata, e lo dice", n != null && n.contains("viene rifiutata"));
        esigi("dopo aver eliminato l'ultimo alias, idem", nota(solo, false, tabella()) != null);
        esigi("un altro alias ancora attivo lo tiene in vita",
                nota(solo, false, tabella(alias(solo, fuori, false), alias(solo, altro, true))) == null);
        esigi("un catch-all ATTIVO del dominio raccoglie la sua posta: niente rifiuto",
                nota(solo, false, tabella(alias(solo, fuori, false), alias("@domain-a.test", altro, true))) == null);
        esigi("un catch-all disattivato non raccoglie niente",
                nota(solo, false, tabella(alias("@domain-a.test", altro, false))) != null);
        esigi("il confronto e' esatto: xdmarc@... non tiene in vita dmarc@...",
                nota(solo, false, tabella(alias("x" + solo, fuori, true))) != null);
        esigi("una sorgente senza @ (riga vecchia) non fa saltare niente",
                nota("postmaster", false, tabella(alias("postmaster", fuori, true))) == null);

        System.out.println("\n== e la logica di prima taceva proprio qui ==");
        List<MailDatabase.Alias> copiaSpenta = tabella(alias(io, fuori, true), alias(io, io, false));
        esigi("la vecchia logica NON avvisava con la copia disattivata (se un giorno avvisa, questa prova non distingue piu')",
                !vecchiaAvvisava(io, true, copiaSpenta));
        esigi("la nuova si'", nota(io, true, copiaSpenta) != null);

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
