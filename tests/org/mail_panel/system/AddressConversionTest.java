package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Trasformare un alias in casella e una casella in alias (AddressTransform e MailDatabase).
 *
 * Prima parte, senza database: quando si puo' e quando no (raccolte, nomi che uscirebbero da
 * /var/vmail, domini non del pannello, indirizzi che sono gia' caselle), le destinazioni (valide,
 * esistenti se sono sui domini del pannello, senza giri che tornano all'indirizzo), la posta sul
 * disco (contata, messa da parte, rimessa a posto), l'fingerprint dell'anteprima.
 *
 * Seconda parte, su un MySQL vero (lo stesso del pannello: mysql80-server): le due transazioni,
 * guardate con le stesse query che usa Postfix. Che una trasformazione a meta' non resti mai:
 * se l'ultimo passo fallisce, il database torna com'era. Si salta se MySQL non e' indicato:
 *   -Dmysql.porta=33062 -Dmysql.utente=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova
 */
public class AddressConversionTest {

    static int falliti = 0;

    static void vero(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    static MailDatabase.Alias alias(int id, String sorgente, String destinazione, boolean attivo) {
        MailDatabase.Alias a = new MailDatabase.Alias();
        a.id = id;
        a.source = sorgente;
        a.destination = destinazione;
        a.active = attivo;
        return a;
    }

    static MailDatabase.Mailbox mailbox(int id, String email) {
        MailDatabase.Mailbox m = new MailDatabase.Mailbox();
        m.id = id;
        m.email = email;
        m.active = true;
        m.receiveEnabled = true;
        return m;
    }

    static AddressTransform.Stato stato(String indirizzo, boolean delPannello, MailDatabase.Mailbox m,
                                          List<MailDatabase.Alias> sorgente, List<MailDatabase.Alias> verso) {
        return new AddressTransform.Stato(indirizzo, delPannello, m, sorgente, verso, AddressTransform.Posta.NESSUNA,
                m == null ? null : new AddressTransform.Perdite(false, List.of(), 0));
    }

    /** Una rete finta: domini del pannello, caselle che ricevono, alias attivi. */
    static final class FakeNetwork implements AddressTransform.Rete {
        final Set<String> domini;
        final Set<String> caselle;
        final Map<String, List<String>> alias = new HashMap<>();
        FakeNetwork(Set<String> domini, Set<String> caselle) { this.domini = domini; this.caselle = caselle; }
        FakeNetwork con(String da, String a) { alias.computeIfAbsent(da, k -> new ArrayList<>()).add(a); return this; }
        @Override public boolean dominioDelPannello(String d) { return domini.contains(d); }
        @Override public boolean riceve(String a) { return caselle.contains(a); }
        @Override public List<String> destinazioniAttive(String s) { return alias.getOrDefault(s, List.of()); }
    }

    static String errore(AddressTransform.Stato s, JSONArray d, AddressTransform.Rete r) {
        try {
            AddressTransform.destinazioni(s, d, r);
            return null;
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        } catch (SQLException e) {
            return "SQL " + e.getMessage();
        }
    }

    public static void main(String[] a) throws Exception {
        Path radice = Files.createTempDirectory("prova-trasforma");
        try {
            AddressTransform.vmail = radice.resolve("vmail");
            AddressTransform.sieve = radice.resolve("sieve");
            regole();
            destinazioni();
            disco(radice);
            database();
        } finally {
            try (Stream<Path> s = Files.walk(radice)) { s.sorted((x, y) -> y.compareTo(x)).forEach(p -> p.toFile().delete()); }
        }
        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }

    static void regole() {
        System.out.println("\n== Alias -> casella: quando si puo' ==");
        List<MailDatabase.Alias> una = List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true));
        vero("una raccolta (@domain-d.test) no: non ha un nome prima della @",
                AddressTransform.motivoNoCasella(stato("@domain-d.test", true, null, una, List.of())).contains("raccolta"));
        vero("\"..@domain-d.test\" no: come percorso uscirebbe da /var/vmail",
                AddressTransform.motivoNoCasella(stato("..@domain-d.test", true, null, una, List.of())) != null);
        vero("un dominio che non e' del pannello no",
                AddressTransform.motivoNoCasella(stato("dmarc@altro.it", false, null, una, List.of())).contains("non è fra i domini"));
        vero("un indirizzo che e' gia' una casella no",
                AddressTransform.motivoNoCasella(stato("dmarc@domain-d.test", true, mailbox(5, "dmarc@domain-d.test"), una, List.of())).contains("già una casella"));
        vero("un indirizzo senza alias no",
                AddressTransform.motivoNoCasella(stato("dmarc@domain-d.test", true, null, List.of(), List.of())).contains("non ha alias"));
        AddressTransform.Stato ok = stato("dmarc@domain-d.test", true, null,
                List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true), alias(2, "dmarc@domain-d.test", "vecchio@x.it", false)),
                List.of(alias(3, "postmaster@domain-d.test", "dmarc@domain-d.test", true)));
        vero("dmarc@domain-d.test -> owner@example.net: si puo'", AddressTransform.motivoNoCasella(ok) == null);
        JSONObject ant = AddressTransform.anteprimaACasella(ok, ZoneId.of("Europe/Rome"));
        vero("l'anteprima elenca le destinazioni (anche quella disattiva) e chi arriva qui", ant.getBoolean("possibile")
                && ant.getJSONArray("destinazioni").length() == 2 && ant.getJSONArray("versoQui").getJSONObject(0).getString("sorgente").equals("postmaster@domain-d.test"));
        String prima = AddressTransform.fingerprint(ok);
        AddressTransform.Stato cambiato = stato("dmarc@domain-d.test", true, null,
                List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true), alias(2, "dmarc@domain-d.test", "vecchio@x.it", true)),
                ok.versoQui());
        vero("l'fingerprint cambia se un alias cambia (riattivato)", !prima.equals(AddressTransform.fingerprint(cambiato)));
        vero("e non cambia se non cambia niente", prima.equals(AddressTransform.fingerprint(ok)));

        System.out.println("\n== Casella -> alias: cosa si perde ==");
        MailDatabase.Mailbox m = mailbox(7, "info@domain-d.test");
        m.receiveEnabled = false;
        AddressTransform.Stato c = new AddressTransform.Stato("info@domain-d.test", true, m,
                List.of(alias(4, "info@domain-d.test", "info@domain-d.test", true), alias(5, "info@domain-d.test", "capo@x.it", true)),
                List.of(), AddressTransform.Posta.NESSUNA,
                new AddressTransform.Perdite(true, List.of("owner@example.net", "info@domain-d.test"), 3));
        JSONObject aa = AddressTransform.anteprimaAAlias(c, ZoneId.of("Europe/Rome"));
        JSONObject per = aa.getJSONObject("perdite");
        vero("risposta automatica, 3 filtri, inoltri e solo invio", per.getBoolean("rispostaAutomatica") && per.getInt("filtri") == 3
                && per.getJSONArray("inoltri").length() == 2 && per.getBoolean("soloInvio"));
        vero("le destinazioni proposte sono gli inoltri della casella, senza se stessa",
                aa.getJSONArray("proposte").toList().equals(List.of("owner@example.net")));
        vero("l'alias su se stessa e' segnalato (se ne andra'), gli altri restano", aa.getBoolean("copia")
                && aa.getJSONArray("giaInoltrata").getJSONObject(0).getString("destinazione").equals("capo@x.it"));
        vero("su un alias (non casella): non si puo'", !AddressTransform.anteprimaAAlias(ok, ZoneId.of("Europe/Rome")).getBoolean("possibile"));
    }

    static void destinazioni() {
        System.out.println("\n== Casella -> alias: le destinazioni ==");
        AddressTransform.Stato s = stato("info@domain-d.test", true, mailbox(7, "info@domain-d.test"), List.of(), List.of());
        FakeNetwork r = new FakeNetwork(Set.of("domain-d.test", "domain-c.test"), Set.of("owner@domain-d.test", "info@domain-d.test"));
        r.con("vendite@domain-d.test", "owner@domain-d.test");
        vero("nessuna destinazione: no", errore(s, new JSONArray(), r).contains("almeno una"));
        vero("l'indirizzo stesso: no", errore(s, new JSONArray().put("info@domain-d.test"), r).contains("stesso"));
        vero("un indirizzo non valido: no", errore(s, new JSONArray().put("non un indirizzo"), r).contains("non è un indirizzo valido"));
        vero("su un tuo dominio ma inesistente: no (la posta verrebbe rifiutata)",
                errore(s, new JSONArray().put("nessuno@domain-d.test"), r).contains("verrebbe rifiutata"));
        vero("una tua casella: si'", errore(s, new JSONArray().put("owner@domain-d.test"), r) == null);
        vero("un tuo alias attivo: si'", errore(s, new JSONArray().put("vendite@domain-d.test"), r) == null);
        r.con("@domain-c.test", "owner@domain-d.test");
        vero("un indirizzo qualsiasi di un dominio con raccolta: si'", errore(s, new JSONArray().put("chiunque@domain-c.test"), r) == null);
        vero("un indirizzo esterno: si'", errore(s, new JSONArray().put("owner@example.net"), r) == null);
        JSONArray molte = new JSONArray();
        for (int k = 0; k < 21; k++) molte.put("persona" + k + "@esterno.it");
        vero("piu' di 20: no", errore(s, molte, r).contains("Al massimo"));
        r.con("giro@domain-d.test", "info@domain-d.test");
        String g = errore(s, new JSONArray().put("giro@domain-d.test"), r);
        vero("un alias che riporta all'indirizzo: no, con la strada: " + g, g != null && g.contains("giro@domain-d.test -> info@domain-d.test"));
        r.con("a@domain-d.test", "b@domain-d.test").con("b@domain-d.test", "info@domain-d.test");
        vero("anche a due passi", errore(s, new JSONArray().put("a@domain-d.test"), r).contains("a@domain-d.test -> b@domain-d.test -> info@domain-d.test"));
        AddressTransform.Stato conAlias = stato("info@domain-d.test", true, mailbox(7, "info@domain-d.test"),
                List.of(alias(9, "info@domain-d.test", "giro@domain-d.test", true)), List.of());
        vero("e anche se il giro passa da un alias che l'indirizzo ha gia'",
                errore(conAlias, new JSONArray().put("owner@example.net"), r).contains("giro@domain-d.test"));
        try {
            List<String> d = AddressTransform.destinazioni(s, new JSONArray().put(" Owner@Domain-d.test ").put("owner@domain-d.test"), r);
            vero("spazi e maiuscole tolti, doppioni una volta sola: " + d, d.equals(List.of("owner@domain-d.test")));
        } catch (Exception e) {
            vero("spazi e maiuscole: " + e.getMessage(), false);
        }
    }

    static void disco(Path radice) throws Exception {
        System.out.println("\n== La posta sul disco ==");
        Path dir = AddressTransform.vmail.resolve("domain-d.test").resolve("dmarc");
        for (String f : new String[] { "cur/1.M1", "new/2.M2", ".Archivio/cur/3.M3", ".Archivio/new/4.M4", "dovecot-uidlist", "tmp/5.M5" }) {
            Path p = dir.resolve(f);
            Files.createDirectories(p.getParent());
            Files.writeString(p, "x".repeat(100));
        }
        Path filtri = AddressTransform.sieve.resolve("domain-d.test").resolve("dmarc").resolve(".dovecot.sieve");
        Files.createDirectories(filtri.getParent());
        Files.writeString(filtri, "redirect \"vecchio@x.it\";\n");
        AddressTransform.Posta p = AddressTransform.posta("dmarc@domain-d.test");
        vero("4 messaggi (cur e new, anche nelle cartelle; non tmp, non i file di Dovecot), 400 byte, e i filtri: "
                + p.messaggi() + ", " + p.byteTotali(), p.presente() && p.messaggi() == 4 && p.byteTotali() == 400 && p.filtri());
        vero("un indirizzo senza cartella: niente", !AddressTransform.posta("nessuno@domain-d.test").presente());
        vero("\"..@domain-d.test\" non diventa un percorso", AddressTransform.cartella(AddressTransform.vmail, "..@domain-d.test") == null
                && AddressTransform.cartella(AddressTransform.vmail, ".a@domain-d.test") == null);
        List<Path[]> spostate = AddressTransform.archivia("dmarc@domain-d.test", 1_790_000_000_000L);
        vero("messa da parte: posta e filtri in .archivio-pannello, con la data", spostate.size() == 2 && !Files.exists(dir)
                && spostate.get(0)[1].toString().contains(".archivio-pannello/domain-d.test/dmarc-20260921T")
                && Files.exists(spostate.get(0)[1].resolve("cur/1.M1")) && Files.exists(spostate.get(1)[1].resolve(".dovecot.sieve")));
        AddressTransform.rimetti(spostate);
        vero("e rimessa a posto, se il resto non riesce", Files.exists(dir.resolve("cur/1.M1")) && Files.exists(filtri));
        List<Path[]> primo = AddressTransform.archivia("dmarc@domain-d.test", 1_790_000_000_000L);
        Files.createDirectories(dir.resolve("cur"));
        Files.writeString(dir.resolve("cur/6.M6"), "y");
        List<Path[]> secondo = AddressTransform.archivia("dmarc@domain-d.test", 1_790_000_000_000L);
        vero("due archiviazioni nello stesso secondo non si sovrascrivono: " + secondo.get(0)[1].getFileName(),
                !primo.get(0)[1].equals(secondo.get(0)[1]) && Files.exists(primo.get(0)[1].resolve("cur/1.M1"))
                && Files.exists(secondo.get(0)[1].resolve("cur/6.M6")));
    }

    // ===================== Su MySQL =====================

    static String postfixAlias(Connection c, String indirizzo) throws SQLException {
        // Le query di mysql-virtual-aliases.cf e mysql-virtual-mailboxes.cf (FullMailServerScript).
        List<String> d = new ArrayList<>();
        try (PreparedStatement p = c.prepareStatement("SELECT destination FROM aliases WHERE source=? AND active=1 ORDER BY destination")) {
            p.setString(1, indirizzo);
            try (ResultSet r = p.executeQuery()) { while (r.next()) d.add(r.getString(1)); }
        }
        return String.join(",", d);
    }

    static String postfixCasella(Connection c, String indirizzo) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') "
                + "FROM mailboxes WHERE email=? AND active=1 AND receive_enabled=1")) {
            p.setString(1, indirizzo);
            try (ResultSet r = p.executeQuery()) { return r.next() ? r.getString(1) : ""; }
        }
    }

    static int conta(Connection c, String sql, Object... parametri) throws SQLException {
        try (PreparedStatement p = c.prepareStatement(sql)) {
            for (int k = 0; k < parametri.length; k++) p.setObject(k + 1, parametri[k]);
            try (ResultSet r = p.executeQuery()) { r.next(); return r.getInt(1); }
        }
    }

    static void database() throws Exception {
        String porta = System.getProperty("mysql.porta");
        if (porta == null) {
            System.out.println("\n== MySQL non indicato (-Dmysql.porta=...): salto la parte sul database ==");
            return;
        }
        System.out.println("\n== Su MySQL " + porta + ": le due trasformazioni, come le vede Postfix ==");
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.utente", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(porta), System.getProperty("mysql.database", "mailpanel_prova"));
        if (!db.connect()) { vero("connessione a MySQL", false); return; }
        db.dropAllTables();
        db.createSchema();
        Connection c = db.getConnection();
        try (var st = c.createStatement(); ResultSet r = st.executeQuery("SELECT VERSION()")) { r.next(); System.out.println("  MySQL " + r.getString(1)); }

        int dom = db.addDomain("domain-d.test", "prova");
        db.addAlias(dom, "dmarc@domain-d.test", "owner@example.net");
        db.addAlias(dom, "postmaster@domain-d.test", "dmarc@domain-d.test");
        vero("prima: dmarc@ e' solo alias", postfixAlias(c, "dmarc@domain-d.test").equals("owner@example.net")
                && postfixCasella(c, "dmarc@domain-d.test").isEmpty());

        int id = db.trasformaAliasInCasella(dom, "dmarc@domain-d.test", "Una-password-lunga-42", "DMARC", 512, false);
        vero("dopo: casella (domain-d.test/dmarc/), e nessun alias con quella sorgente", id > 0
                && postfixCasella(c, "dmarc@domain-d.test").equals("domain-d.test/dmarc/") && postfixAlias(c, "dmarc@domain-d.test").isEmpty());
        vero("postmaster@ -> dmarc@ resta: arriva nella casella", postfixAlias(c, "postmaster@domain-d.test").equals("dmarc@domain-d.test"));
        MailDatabase.Mailbox m = db.getMailbox(id);
        vero("la password e' un hash bcrypt (quello che Dovecot verifica), quota e nome salvati",
                conta(c, "SELECT COUNT(*) FROM mailboxes WHERE id=? AND password LIKE '$2a$%'", id) == 1 && m.quotaMb == 512 && "DMARC".equals(m.name));

        db.addAlias(dom, "info@domain-d.test", "capo@esterno.it");
        db.addAlias(dom, "info@domain-d.test", "segreteria@esterno.it");
        int id2 = db.trasformaAliasInCasella(dom, "info@domain-d.test", "Una-password-lunga-42", "", 1024, true);
        vero("tenendo gli inoltri: le destinazioni restano e la casella ne riceve una copia (info@ -> info@)",
                id2 > 0 && postfixAlias(c, "info@domain-d.test").equals("capo@esterno.it,info@domain-d.test,segreteria@esterno.it"));

        boolean rifiutato;
        int prima = conta(c, "SELECT COUNT(*) FROM aliases");
        try {
            db.trasformaAliasInCasella(dom, "dmarc@domain-d.test", "Una-password-lunga-42", "", 1024, false);
            rifiutato = false;
        } catch (SQLException e) {
            rifiutato = true;
        }
        vero("una seconda casella con lo stesso indirizzo: rifiutata dal vincolo UNIQUE, alias intatti",
                rifiutato && conta(c, "SELECT COUNT(*) FROM aliases") == prima);

        System.out.println("\n== Casella -> alias, su MySQL ==");
        db.createForwardingRule(id, "owner@example.net", true);
        db.createSieveFilter(id, "Spam", 1, "[]", "[]");
        db.saveAutoResponder(id, true, "Assente", "Torno lunedi'", null, null, 24);
        try (PreparedStatement p = c.prepareStatement("INSERT INTO rate_limits (target_type, target_id) VALUES ('mailbox', ?)")) {
            p.setInt(1, id);
            p.executeUpdate();
        }
        db.addAlias(dom, "dmarc@domain-d.test", "dmarc@domain-d.test");
        int vecchio = db.addAlias(dom, "dmarc@domain-d.test", "owner@example.net");
        db.updateAliasStatus(vecchio, false);

        int righePrima = conta(c, "SELECT COUNT(*) FROM aliases");
        try {
            // L'ultimo passo (la casella) fallisce: id giusto, indirizzo sbagliato.
            db.trasformaCasellaInAlias(id, dom, "altro@domain-d.test", List.of("x@esterno.it"));
            rifiutato = false;
        } catch (SQLException e) {
            rifiutato = true;
        }
        vero("se l'ultimo passo fallisce, niente resta a meta': alias, limite e casella com'erano", rifiutato
                && conta(c, "SELECT COUNT(*) FROM aliases") == righePrima
                && conta(c, "SELECT COUNT(*) FROM aliases WHERE source='altro@domain-d.test'") == 0
                && conta(c, "SELECT COUNT(*) FROM rate_limits WHERE target_id=?", id) == 1
                && postfixCasella(c, "dmarc@domain-d.test").equals("domain-d.test/dmarc/"));

        db.trasformaCasellaInAlias(id, dom, "dmarc@domain-d.test", List.of("owner@example.net", "postmaster@domain-c.test"));
        vero("dopo: niente casella, alias verso le due destinazioni (quella disattiva riattivata)",
                postfixCasella(c, "dmarc@domain-d.test").isEmpty()
                && postfixAlias(c, "dmarc@domain-d.test").equals("owner@example.net,postmaster@domain-c.test"));
        vero("l'alias su se stessa se n'e' andato (senza casella porterebbe al nulla)",
                conta(c, "SELECT COUNT(*) FROM aliases WHERE source='dmarc@domain-d.test' AND destination='dmarc@domain-d.test'") == 0);
        vero("inoltri, filtri, risposta automatica e limite di invio se ne sono andati con la casella",
                conta(c, "SELECT COUNT(*) FROM forwarding_rules WHERE mailbox_id=?", id) == 0
                && conta(c, "SELECT COUNT(*) FROM sieve_filters WHERE mailbox_id=?", id) == 0
                && conta(c, "SELECT COUNT(*) FROM auto_responders WHERE mailbox_id=?", id) == 0
                && conta(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='mailbox' AND target_id=?", id) == 0);
        vero("postmaster@ -> dmarc@ continua: ora va alle destinazioni dell'alias",
                postfixAlias(c, "postmaster@domain-d.test").equals("dmarc@domain-d.test"));

        System.out.println("\n== Andata e ritorno, con lo stato letto dal database ==");
        AddressTransform.Stato s = AddressTransform.stato(db, "dmarc@domain-d.test");
        vero("dmarc@ si puo' ritrasformare in casella", AddressTransform.motivoNoCasella(s) == null && s.versoQui().size() == 1);
        AddressTransform.Stato si = AddressTransform.stato(db, "info@domain-d.test");
        try {
            AddressTransform.destinazioni(si, new JSONArray().put("postmaster@domain-d.test"), AddressTransform.rete(db));
            vero("info@ verso postmaster@ (che va a dmarc@, alias): si' dal database", true);
        } catch (IllegalArgumentException e) {
            vero("info@ verso postmaster@: " + e.getMessage(), false);
        }
        db.addAlias(dom, "giro@domain-d.test", "info@domain-d.test");
        try {
            AddressTransform.destinazioni(si, new JSONArray().put("giro@domain-d.test"), AddressTransform.rete(db));
            vero("info@ verso giro@ (che torna a info@): doveva essere rifiutato", false);
        } catch (IllegalArgumentException e) {
            vero("info@ verso giro@ (che torna a info@): rifiutato dal database", e.getMessage().contains("giro@domain-d.test -> info@domain-d.test"));
        }
        db.close();
    }
}
