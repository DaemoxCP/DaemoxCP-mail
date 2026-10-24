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

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static MailDatabase.Alias alias(String source, String destination, boolean active) {
        MailDatabase.Alias a = new MailDatabase.Alias();
        a.source = source;
        a.destination = destination;
        a.active = active;
        return a;
    }

    static List<MailDatabase.Alias> tabella(MailDatabase.Alias... lines) {
        return new ArrayList<>(List.of(lines));
    }

    static String note(String address, boolean mailbox, List<MailDatabase.Alias> lines) {
        return SSLMailServer.afterAliases(address, mailbox, lines);
    }

    /** La logica di prima (creazione soltanto): una riga casella -> casella bastava, attiva o no. */
    static boolean oldWarned(String source, boolean mailbox, List<MailDatabase.Alias> lines) {
        boolean copyInMailbox = false;
        for (MailDatabase.Alias a : lines)
            if (a.source.equals(source) && a.destination.equals(source)) copyInMailbox = true;
        return mailbox && !copyInMailbox;
    }

    public static void main(String[] x) {
        String io = "info@domain-a.test", outside = "report@domain-b.test", other = "owner@domain-b.test";

        System.out.println("\n== una casella ==");
        require("senza alias riceve: niente da dire", note(io, true, tabella()) == null);
        require("con solo \"se stessa -> se stessa\" riceve: niente da dire",
                note(io, true, tabella(alias(io, io, true))) == null);
        require("inoltrata ma con la copia attiva: niente da dire",
                note(io, true, tabella(alias(io, outside, true), alias(io, io, true))) == null);
        require("con l'inoltro disattivato riceve di nuovo: niente da dire",
                note(io, true, tabella(alias(io, outside, false))) == null);

        String n = note(io, true, tabella(alias(io, outside, true)));
        require("inoltrata senza copia: lo dice", n != null && n.contains("va solo a " + outside));
        require("  e dice di AGGIUNGERE la copia, che non c'e'", n != null && n.contains("aggiungi l'alias " + io + " -> " + io));

        n = note(io, true, tabella(alias(io, outside, true), alias(io, other, true)));
        require("con due destinazioni le nomina tutte e due", n != null && n.contains("va solo a " + outside + ", " + other));

        n = note(io, true, tabella(alias(io, outside, true), alias(io, io, false)));
        require("copia DISATTIVATA: la casella non riceve, e lo dice", n != null && n.contains("va solo a " + outside));
        require("  e dice di RIATTIVARLA: aggiungerla darebbe \"Alias gia' esistente\"",
                n != null && n.contains("riattiva l'alias " + io + " -> " + io));

        require("gli alias di un altro indirizzo dello stesso dominio non contano",
                note(io, true, tabella(alias("sales@domain-a.test", outside, true))) == null);

        System.out.println("\n== un indirizzo che non e' una casella ==");
        String solo = "dmarc@domain-a.test";
        require("con un alias attivo esiste: niente da dire", note(solo, false, tabella(alias(solo, outside, true))) == null);
        n = note(solo, false, tabella(alias(solo, outside, false)));
        require("con l'unico alias disattivato la posta viene rifiutata, e lo dice", n != null && n.contains("viene rifiutata"));
        require("dopo aver eliminato l'ultimo alias, idem", note(solo, false, tabella()) != null);
        require("un altro alias ancora attivo lo tiene in vita",
                note(solo, false, tabella(alias(solo, outside, false), alias(solo, other, true))) == null);
        require("un catch-all ATTIVO del dominio raccoglie la sua posta: niente rifiuto",
                note(solo, false, tabella(alias(solo, outside, false), alias("@domain-a.test", other, true))) == null);
        require("un catch-all disattivato non raccoglie niente",
                note(solo, false, tabella(alias("@domain-a.test", other, false))) != null);
        require("il confronto e' esatto: xdmarc@... non tiene in vita dmarc@...",
                note(solo, false, tabella(alias("x" + solo, outside, true))) != null);
        require("una sorgente senza @ (riga vecchia) non fa saltare niente",
                note("postmaster", false, tabella(alias("postmaster", outside, true))) == null);

        System.out.println("\n== e la logica di prima taceva proprio qui ==");
        List<MailDatabase.Alias> copyOff = tabella(alias(io, outside, true), alias(io, io, false));
        require("la vecchia logica NON avvisava con la copia disattivata (se un giorno avvisa, questa prova non distingue piu')",
                !oldWarned(io, true, copyOff));
        require("la nuova si'", note(io, true, copyOff) != null);

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
