package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.integration.SieveGenerator;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Le regole Sieve del pannello gia' scritte, riscritte dal database come il pannello le scrive adesso (reperto 229).
 *
 * <p>Quando cambia quello che SieveGenerator scrive, le regole gia' sui server restavano come erano finche' qualcuno non
 * salvava di nuovo la casella. Col reperto 229 «Sposta» e «Copia» creano la cartella che non c'e' (fileinto :create):
 * senza questo passo un filtro scritto prima verso una cartella nuova avrebbe continuato a non spostare niente.
 *
 * <p>All'avvio della parte root, dopo SieveRulesOwner, MailSpoolSticky, SieveStorage e SieveForcedKeep: per ogni casella
 * del database si genera il testo come adesso e lo si confronta col file. Si scrive solo se:
 * <ul>
 *   <li>il file c'e', comincia con una delle righe require che il pannello ha scritto (e' suo, non uno script fatto a
 *       mano) ed e' diverso;</li>
 *   <li>oppure il file non c'e' e la casella ha regole nel database (una scrittura rifiutata prima, reperto 223).</li>
 * </ul>
 * La scrittura e' quella di SieveGenerator.saveSieveScript: RootOnlyPath, compilata con sievec. Al secondo avvio i testi
 * sono uguali e non si scrive niente. Nel log le caselle col loro numero, mai l'indirizzo.
 */
public final class SieveRulesRefresh {

    private static final Logger LOGGER = Logger.getLogger(SieveRulesRefresh.class.getName());

    private SieveRulesRefresh() {}

    /** Una casella: il numero (per il log) e l'indirizzo (per il percorso). */
    record Box(int id, String email) {}

    /** Quello che serve, per provarlo senza MySQL ne' /var/mail. */
    interface Rules {
        List<Box> mailboxes() throws Exception;
        /** Il testo che il pannello scriverebbe adesso per la casella. */
        String generate(Box b);
        /** Il file com'e', null se non c'e'. */
        String current(Box b);
        /** Scrive e compila; falso se non e' stato scritto (il motivo e' nel log di chi scrive). */
        boolean write(Box b, String script);
    }

    /** Quante caselle riscritte e quali no (i numeri). */
    record Outcome(int written, List<Integer> notWritten) {}

    /** Le righe require che il pannello ha scritto, dalla piu' nuova: uno script che comincia cosi' e' suo. */
    static boolean panelScript(String script) {
        if (script == null) return false;
        return script.startsWith(SieveGenerator.REQUIRE) || script.startsWith(SieveGenerator.REQUIRE_BEFORE_MAILBOX)
                || script.startsWith(SieveForcedKeep.REQUIRE_WITHOUT_DATE);
    }

    /** Puro rispetto a {@link Rules}. */
    static Outcome refresh(Rules r) throws Exception {
        int written = 0;
        List<Integer> failed = new ArrayList<>();
        for (Box b : r.mailboxes()) {
            String now = r.generate(b);
            if (now == null) continue;
            String cur = r.current(b);
            boolean write;
            if (cur == null) write = !now.equals(SieveGenerator.REQUIRE);   // regole nel database, file mancante
            else write = panelScript(cur) && !cur.equals(now);
            if (!write) continue;
            if (r.write(b, now)) written++;
            else failed.add(b.id());
        }
        return new Outcome(written, failed);
    }

    /** All'avvio della parte root, col generatore del server. */
    public static void ensureAtBoot(SieveGenerator generator) {
        try {
            MailDatabase db = Main.mailDatabase;
            if (generator == null || db == null || !Main.mysqlAvailable) return;
            Outcome o = refresh(new Rules() {
                @Override public List<Box> mailboxes() throws Exception {
                    List<Box> out = new ArrayList<>();
                    for (MailDatabase.Mailbox m : db.getAllMailboxes()) out.add(new Box(m.id, m.email));
                    return out;
                }
                @Override public String generate(Box b) { return generator.generateSieveScript(b.id(), db); }
                @Override public String current(Box b) { return generator.getSieveScript(b.email()); }
                @Override public boolean write(Box b, String script) { return generator.saveSieveScript(b.email(), script); }
            });
            if (o.written() > 0)
                LOGGER.info("[SieveRulesRefresh] DONE: " + o.written() + " Sieve rule file(s) of the panel written again from the"
                        + " database as the panel writes them now (move and copy create a folder that is not there yet)");
            if (!o.notWritten().isEmpty())
                LOGGER.warning("[SieveRulesRefresh] the rules of mailbox(es) #" + o.notWritten() + " were not written again:"
                        + " they keep the earlier text; the reason is in the lines of SieveGenerator above");
        } catch (Throwable t) {
            LOGGER.warning("[SieveRulesRefresh] failed: " + t);
        }
    }
}
