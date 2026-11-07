package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Le decisioni di PendingDbPassword, con un MySQL finto: un insieme di password che accetta, e un
 * interruttore per «non risponde». Nessun file vero: il file di Postfix sta in una cartella
 * temporanea (PendingDbPassword.postfixMap).
 *
 * La regola che si prova: la password del pannello cambia SOLO in una che MySQL ha accettato davanti
 * a noi, e una password in attesa si butta solo quando MySQL ha detto di no.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PendingDbPasswordTest
 */
public class PendingDbPasswordTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** Le password del pannello, in memoria. */
    static final class FakeStore implements PendingDbPassword.Store {
        String current = "", pending = "";
        int adopts = 0;
        boolean pendingWriteFails = false;
        public String current() { return current; }
        public void adopt(String p) { current = p; adopts++; }
        public String pending() { return pending; }
        public void setPending(String p) {
            if (pendingWriteFails) throw new IllegalStateException("prova: file dei segreti non scrivibile");
            pending = p == null ? "" : p;
        }
    }

    /** MySQL finto: accetta le password dell'insieme, o non risponde affatto. */
    static final class FakeMysql implements PendingDbPassword.Probe {
        final Set<String> accepts = new HashSet<>();
        boolean answers = true;
        final List<String> asked = new ArrayList<>();
        FakeMysql knows(String... p) { accepts.addAll(List.of(p)); return this; }
        public PendingDbPassword.Answer ask(String p) {
            asked.add(p);
            if (!answers) return PendingDbPassword.Answer.NO_ANSWER;
            if (p == null || p.isEmpty()) return PendingDbPassword.Answer.REJECTED;
            return accepts.contains(p) ? PendingDbPassword.Answer.ACCEPTED : PendingDbPassword.Answer.REJECTED;
        }
    }

    static Path map;

    static void postfix(String user, String password) throws Exception {
        Files.writeString(map, "# scritto dallo script\nuser = " + user + "\npassword = " + password
                + "\nhosts = 127.0.0.1\ndbname = mailserver\nquery = SELECT domain FROM domains WHERE domain='%s' AND active=1\n");
    }

    static void noPostfix() throws Exception {
        Files.deleteIfExists(map);
    }

    public static void main(String[] args) throws Exception {
        Path d = Files.createTempDirectory("pending-db-password");
        map = d.resolve("mysql-virtual-domains.cf");
        PendingDbPassword.postfixMap = map;
        final String U = "mailpanel";

        System.out.println("== Lo script esce prima della fase 3 (Roundcube, parametro, turno, pacchetti) ==");
        FakeStore s = new FakeStore();
        s.current = "Vecchia1";
        FakeMysql m = new FakeMysql().knows("Vecchia1");
        PendingDbPassword.Prepared pr = PendingDbPassword.prepare(s, m, U);
        check("prima dello script la password del pannello NON cambia", s.current.equals("Vecchia1") && s.adopts == 0);
        check("la nuova e' in attesa, ed e' quella data allo script", !pr.password().isEmpty() && pr.password().equals(s.pending));
        check("la nuova e' diversa dalla vecchia, 24 lettere e cifre", !pr.password().equals("Vecchia1") && pr.password().matches("[A-Za-z0-9]{24}"));
        PendingDbPassword.Result r = PendingDbPassword.settle(s, m, U);
        check("MySQL non la conosce: si tiene la vecchia", r.outcome() == PendingDbPassword.Outcome.OLD_KEPT && s.current.equals("Vecchia1"));
        check("e la nuova si butta", s.pending.isEmpty());
        check("il messaggio lo dice", !r.message().isEmpty());

        System.out.println("\n== Lo script fallisce DOPO la fase 3, o riesce ==");
        s = new FakeStore();
        s.current = "Vecchia1";
        m = new FakeMysql().knows("Vecchia1");
        pr = PendingDbPassword.prepare(s, m, U);
        m.accepts.clear();
        m.knows(pr.password());                       // lo script l'ha data a MySQL
        r = PendingDbPassword.settle(s, m, U);
        check("MySQL accetta la nuova: adesso e' quella del pannello", r.outcome() == PendingDbPassword.Outcome.NEW_ADOPTED && s.current.equals(pr.password()));
        check("l'attesa e' tolta", s.pending.isEmpty());

        System.out.println("\n== MySQL non risponde dopo lo script ==");
        s = new FakeStore();
        s.current = "Vecchia1";
        m = new FakeMysql().knows("Vecchia1");
        pr = PendingDbPassword.prepare(s, m, U);
        m.answers = false;
        r = PendingDbPassword.settle(s, m, U);
        check("non si decide", r.outcome() == PendingDbPassword.Outcome.UNDECIDED);
        check("la password del pannello resta quella di prima", s.current.equals("Vecchia1") && s.adopts == 0);
        check("la nuova resta in attesa", s.pending.equals(pr.password()));

        System.out.println("\n== Un'installazione dopo, con MySQL ancora muto: riusa quella in attesa ==");
        String left = s.pending;
        pr = PendingDbPassword.prepare(s, m, U);
        check("allo script va di nuovo quella in attesa, non una nuova", pr.password().equals(left) && s.pending.equals(left));
        check("e lo dice", !pr.note().isEmpty());
        check("la password del pannello non cambia", s.current.equals("Vecchia1"));

        System.out.println("\n== Un'installazione dopo, e MySQL conosce quella rimasta in attesa ==");
        s = new FakeStore();
        s.current = "Vecchia1";
        s.pending = "Rimasta1";
        m = new FakeMysql().knows("Rimasta1");
        pr = PendingDbPassword.prepare(s, m, U);
        check("quella rimasta diventa del pannello prima di tutto", s.current.equals("Rimasta1"));
        check("e allo script ne va una nuova, in attesa", !pr.password().equals("Rimasta1") && s.pending.equals(pr.password()));

        System.out.println("\n== Un'installazione dopo, e MySQL non conosce quella rimasta ==");
        s = new FakeStore();
        s.current = "Vecchia1";
        s.pending = "Rimasta1";
        m = new FakeMysql().knows("Vecchia1");
        pr = PendingDbPassword.prepare(s, m, U);
        check("si tiene la vecchia", s.current.equals("Vecchia1"));
        check("la rimasta e' buttata, allo script una nuova", !pr.password().equals("Rimasta1") && s.pending.equals(pr.password()));

        System.out.println("\n== La password in attesa non si scrive ==");
        s = new FakeStore();
        s.current = "Vecchia1";
        s.pendingWriteFails = true;
        boolean refused = false;
        try { PendingDbPassword.prepare(s, new FakeMysql().knows("Vecchia1"), U); }
        catch (IllegalStateException e) { refused = true; }
        check("prepare si rifiuta (lo script non deve partire)", refused);
        check("la password del pannello non cambia", s.current.equals("Vecchia1") && s.adopts == 0);

        System.out.println("\n== Arresto fra l'adozione e la pulizia: le due uguali ==");
        s = new FakeStore();
        s.current = "Nuova1";
        s.pending = "Nuova1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("Nuova1"), U);
        check("si chiude senza cambiare niente", r.outcome() == PendingDbPassword.Outcome.NEW_ADOPTED && s.current.equals("Nuova1") && s.pending.isEmpty());

        System.out.println("\n== MySQL rifiuta tutte e due, nessuna copia di Postfix ==");
        noPostfix();
        s = new FakeStore();
        s.current = "Vecchia1";
        s.pending = "Nuova1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("Altra1"), U);
        check("nessuna accettata", r.outcome() == PendingDbPassword.Outcome.NONE_ACCEPTED);
        check("la password del pannello non cambia", s.current.equals("Vecchia1") && s.adopts == 0);
        check("la nuova, rifiutata da MySQL, si butta", s.pending.isEmpty());

        System.out.println("\n== MySQL rifiuta tutte e due, e accetta quella di Postfix ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Vecchia1";
        s.pending = "Nuova1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("Postfix1"), U);
        check("quella di Postfix diventa del pannello", r.outcome() == PendingDbPassword.Outcome.COPY_ADOPTED && s.current.equals("Postfix1"));
        check("l'attesa e' tolta", s.pending.isEmpty());

        System.out.println("\n== Server rotto dalla versione di prima: niente in attesa, password rifiutata ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Rotta1";
        m = new FakeMysql().knows("Postfix1");
        r = PendingDbPassword.settle(s, m, U);
        check("si adotta quella di Postfix, che MySQL accetta", r.outcome() == PendingDbPassword.Outcome.COPY_ADOPTED && s.current.equals("Postfix1"));
        check("e il messaggio nomina il file", r.message().contains(map.toString()));

        System.out.println("\n== Copia di Postfix rifiutata anche lei ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Rotta1";
        r = PendingDbPassword.settle(s, new FakeMysql().knows("Altra1"), U);
        check("nessuna accettata, niente cambia", r.outcome() == PendingDbPassword.Outcome.NONE_ACCEPTED && s.current.equals("Rotta1") && s.adopts == 0);

        System.out.println("\n== Copia di Postfix di un altro utente ==");
        postfix("altroutente", "Postfix1");
        s = new FakeStore();
        s.current = "Rotta1";
        m = new FakeMysql().knows("Postfix1");
        r = PendingDbPassword.settle(s, m, U);
        check("non si guarda nemmeno", r.outcome() == PendingDbPassword.Outcome.NONE_ACCEPTED && s.current.equals("Rotta1") && !m.asked.contains("Postfix1"));

        System.out.println("\n== Il caso di sempre: niente in attesa, password accettata ==");
        postfix(U, "Postfix1");
        s = new FakeStore();
        s.current = "Buona1";
        m = new FakeMysql().knows("Buona1", "Postfix1");
        r = PendingDbPassword.settle(s, m, U);
        check("niente da fare, niente cambia", r.outcome() == PendingDbPassword.Outcome.NOTHING_TO_DO && s.current.equals("Buona1") && s.adopts == 0);
        check("una domanda sola a MySQL", m.asked.equals(List.of("Buona1")));
        check("niente da dire", r.message().isEmpty());

        System.out.println("\n== Pannello mai installato ==");
        s = new FakeStore();
        m = new FakeMysql();
        r = PendingDbPassword.settle(s, m, U);
        check("niente da fare, MySQL non interrogato", r.outcome() == PendingDbPassword.Outcome.NOTHING_TO_DO && m.asked.isEmpty());

        System.out.println("\n== Niente in attesa, MySQL muto ==");
        s = new FakeStore();
        s.current = "Buona1";
        m = new FakeMysql();
        m.answers = false;
        r = PendingDbPassword.settle(s, m, U);
        check("non si cambia niente", r.outcome() == PendingDbPassword.Outcome.NOTHING_TO_DO && s.current.equals("Buona1") && s.adopts == 0);

        System.out.println("\n== MySQL muto sulla vecchia dopo aver rifiutato la nuova ==");
        s = new FakeStore();
        s.current = "Vecchia1";
        s.pending = "Nuova1";
        PendingDbPassword.Probe flaky = p -> p.equals("Nuova1") ? PendingDbPassword.Answer.REJECTED : PendingDbPassword.Answer.NO_ANSWER;
        r = PendingDbPassword.settle(s, flaky, U);
        check("non si decide: la nuova resta in attesa", r.outcome() == PendingDbPassword.Outcome.UNDECIDED && s.pending.equals("Nuova1") && s.current.equals("Vecchia1"));

        System.out.println("\n== Il file di Postfix ==");
        Files.writeString(map, "user=mailpanel\npassword=  Spazi1  \n#password = Commento\n");
        check("valori senza spazi intorno, commenti saltati", PendingDbPassword.postfixCopy("mailpanel").equals("Spazi1"));
        Files.writeString(map, "password = Senzautente\n");
        check("senza utente: niente", PendingDbPassword.postfixCopy("mailpanel").isEmpty());
        noPostfix();
        check("senza file: niente", PendingDbPassword.postfixCopy("mailpanel").isEmpty());

        Files.deleteIfExists(map);
        Files.deleteIfExists(d);
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
