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
 * disco (contata, messa da parte, rimessa a posto), l'impronta dell'anteprima.
 *
 * Seconda parte, su un MySQL vero (lo stesso del pannello: mysql80-server): le due transazioni,
 * guardate con le stesse query che usa Postfix. Che una trasformazione a meta' non resti mai:
 * se l'ultimo passo fallisce, il database torna com'era. Si salta se MySQL non e' indicato:
 *   -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova
 */
public class AddressConversionTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static MailDatabase.Alias alias(int id, String source, String destination, boolean active) {
        MailDatabase.Alias a = new MailDatabase.Alias();
        a.id = id;
        a.source = source;
        a.destination = destination;
        a.active = active;
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

    static AddressTransform.AddressState state(String address, boolean ofPanel, MailDatabase.Mailbox m,
                                          List<MailDatabase.Alias> source, List<MailDatabase.Alias> target) {
        return new AddressTransform.AddressState(address, ofPanel, m, source, target, AddressTransform.MailContent.NONE,
                m == null ? null : new AddressTransform.Losses(false, List.of(), 0));
    }

    /** Una rete finta: domini del pannello, caselle che ricevono, alias attivi. */
    static final class FakeNetwork implements AddressTransform.Network {
        final Set<String> domains;
        final Set<String> mailboxes;
        final Map<String, List<String>> alias = new HashMap<>();
        FakeNetwork(Set<String> domains, Set<String> mailboxes) { this.domains = domains; this.mailboxes = mailboxes; }
        FakeNetwork route(String from, String to) { alias.computeIfAbsent(from, k -> new ArrayList<>()).add(to); return this; }
        @Override public boolean panelDomain(String d) { return domains.contains(d); }
        @Override public boolean receives(String a) { return mailboxes.contains(a); }
        @Override public List<String> activeDestinations(String s) { return alias.getOrDefault(s, List.of()); }
    }

    static String error(AddressTransform.AddressState s, JSONArray d, AddressTransform.Network r) {
        try {
            AddressTransform.destinations(s, d, r);
            return null;
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        } catch (SQLException e) {
            return "SQL " + e.getMessage();
        }
    }

    public static void main(String[] a) throws Exception {
        Path root = Files.createTempDirectory("prova-trasforma");
        try {
            AddressTransform.vmail = root.resolve("vmail");
            AddressTransform.sieve = root.resolve("sieve");
            rules();
            destinations();
            disk(root);
            database();
        } finally {
            try (Stream<Path> s = Files.walk(root)) { s.sorted((x, y) -> y.compareTo(x)).forEach(p -> p.toFile().delete()); }
        }
        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }

    static void rules() {
        System.out.println("\n== Alias -> casella: quando si puo' ==");
        List<MailDatabase.Alias> oneAlias = List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true));
        real("una raccolta (@domain-d.test) no: non ha un nome prima della @",
                AddressTransform.noMailboxReason(state("@domain-d.test", true, null, oneAlias, List.of())).contains("raccolta"));
        real("\"..@domain-d.test\" no: come percorso uscirebbe da /var/vmail",
                AddressTransform.noMailboxReason(state("..@domain-d.test", true, null, oneAlias, List.of())) != null);
        real("un dominio che non e' del pannello no",
                AddressTransform.noMailboxReason(state("dmarc@altro.it", false, null, oneAlias, List.of())).contains("non è fra i domini"));
        real("un indirizzo che e' gia' una casella no",
                AddressTransform.noMailboxReason(state("dmarc@domain-d.test", true, mailbox(5, "dmarc@domain-d.test"), oneAlias, List.of())).contains("già una casella"));
        real("un indirizzo senza alias no",
                AddressTransform.noMailboxReason(state("dmarc@domain-d.test", true, null, List.of(), List.of())).contains("non ha alias"));
        AddressTransform.AddressState ok = state("dmarc@domain-d.test", true, null,
                List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true), alias(2, "dmarc@domain-d.test", "vecchio@x.it", false)),
                List.of(alias(3, "postmaster@domain-d.test", "dmarc@domain-d.test", true)));
        real("dmarc@domain-d.test -> owner@example.net: si puo'", AddressTransform.noMailboxReason(ok) == null);
        JSONObject preview = AddressTransform.previewToMailbox(ok, ZoneId.of("Europe/Rome"));
        real("l'anteprima elenca le destinazioni (anche quella disattiva) e chi arriva qui", preview.getBoolean("possible")
                && preview.getJSONArray("destinations").length() == 2 && preview.getJSONArray("towardsHere").getJSONObject(0).getString("source").equals("postmaster@domain-d.test"));
        String before = AddressTransform.fingerprint(ok);
        AddressTransform.AddressState changed = state("dmarc@domain-d.test", true, null,
                List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true), alias(2, "dmarc@domain-d.test", "vecchio@x.it", true)),
                ok.towardsHere());
        real("l'fingerprint cambia se un alias cambia (riattivato)", !before.equals(AddressTransform.fingerprint(changed)));
        real("e non cambia se non cambia niente", before.equals(AddressTransform.fingerprint(ok)));

        System.out.println("\n== Casella -> alias: cosa si perde ==");
        MailDatabase.Mailbox m = mailbox(7, "info@domain-d.test");
        m.receiveEnabled = false;
        AddressTransform.AddressState c = new AddressTransform.AddressState("info@domain-d.test", true, m,
                List.of(alias(4, "info@domain-d.test", "info@domain-d.test", true), alias(5, "info@domain-d.test", "capo@x.it", true)),
                List.of(), AddressTransform.MailContent.NONE,
                new AddressTransform.Losses(true, List.of("owner@example.net", "info@domain-d.test"), 3));
        JSONObject aa = AddressTransform.previewToAlias(c, ZoneId.of("Europe/Rome"));
        JSONObject per = aa.getJSONObject("losses");
        real("risposta automatica, 3 filtri, inoltri e solo invio", per.getBoolean("autoReply") && per.getInt("filters") == 3
                && per.getJSONArray("forwards").length() == 2 && per.getBoolean("sendOnly"));
        real("le destinazioni proposte sono gli inoltri della casella, senza se stessa",
                aa.getJSONArray("proposals").toList().equals(List.of("owner@example.net")));
        real("l'alias su se stessa e' segnalato (se ne andra'), gli altri restano", aa.getBoolean("copy")
                && aa.getJSONArray("alreadyForwarded").getJSONObject(0).getString("destination").equals("capo@x.it"));
        real("su un alias (non casella): non si puo'", !AddressTransform.previewToAlias(ok, ZoneId.of("Europe/Rome")).getBoolean("possible"));
    }

    static void destinations() {
        System.out.println("\n== Casella -> alias: le destinazioni ==");
        AddressTransform.AddressState s = state("info@domain-d.test", true, mailbox(7, "info@domain-d.test"), List.of(), List.of());
        FakeNetwork r = new FakeNetwork(Set.of("domain-d.test", "domain-c.test"), Set.of("owner@domain-d.test", "info@domain-d.test"));
        r.route("vendite@domain-d.test", "owner@domain-d.test");
        real("nessuna destinazione: no", error(s, new JSONArray(), r).contains("almeno una"));
        real("l'indirizzo stesso: no", error(s, new JSONArray().put("info@domain-d.test"), r).contains("stesso"));
        real("un indirizzo non valido: no", error(s, new JSONArray().put("non un indirizzo"), r).contains("non è un indirizzo valido"));
        real("su un tuo dominio ma inesistente: no (la posta verrebbe rifiutata)",
                error(s, new JSONArray().put("nessuno@domain-d.test"), r).contains("verrebbe rifiutata"));
        real("una tua casella: si'", error(s, new JSONArray().put("owner@domain-d.test"), r) == null);
        real("un tuo alias attivo: si'", error(s, new JSONArray().put("vendite@domain-d.test"), r) == null);
        r.route("@domain-c.test", "owner@domain-d.test");
        real("un indirizzo qualsiasi di un dominio con raccolta: si'", error(s, new JSONArray().put("chiunque@domain-c.test"), r) == null);
        real("un indirizzo esterno: si'", error(s, new JSONArray().put("owner@example.net"), r) == null);
        JSONArray many = new JSONArray();
        for (int k = 0; k < 21; k++) many.put("persona" + k + "@esterno.it");
        real("piu' di 20: no", error(s, many, r).contains("Al massimo"));
        r.route("giro@domain-d.test", "info@domain-d.test");
        String g = error(s, new JSONArray().put("giro@domain-d.test"), r);
        real("un alias che riporta all'indirizzo: no, con la strada: " + g, g != null && g.contains("giro@domain-d.test -> info@domain-d.test"));
        r.route("a@domain-d.test", "b@domain-d.test").route("b@domain-d.test", "info@domain-d.test");
        real("anche a due passi", error(s, new JSONArray().put("a@domain-d.test"), r).contains("a@domain-d.test -> b@domain-d.test -> info@domain-d.test"));
        AddressTransform.AddressState withAlias = state("info@domain-d.test", true, mailbox(7, "info@domain-d.test"),
                List.of(alias(9, "info@domain-d.test", "giro@domain-d.test", true)), List.of());
        real("e anche se il giro passa da un alias che l'indirizzo ha gia'",
                error(withAlias, new JSONArray().put("owner@example.net"), r).contains("giro@domain-d.test"));
        try {
            List<String> d = AddressTransform.destinations(s, new JSONArray().put(" Owner@Domain-d.test ").put("owner@domain-d.test"), r);
            real("spazi e maiuscole tolti, doppioni una volta sola: " + d, d.equals(List.of("owner@domain-d.test")));
        } catch (Exception e) {
            real("spazi e maiuscole: " + e.getMessage(), false);
        }
    }

    static void disk(Path root) throws Exception {
        System.out.println("\n== La posta sul disco ==");
        Path dir = AddressTransform.vmail.resolve("domain-d.test").resolve("dmarc");
        for (String f : new String[] { "cur/1.M1", "new/2.M2", ".Archivio/cur/3.M3", ".Archivio/new/4.M4", "dovecot-uidlist", "tmp/5.M5" }) {
            Path p = dir.resolve(f);
            Files.createDirectories(p.getParent());
            Files.writeString(p, "x".repeat(100));
        }
        Path filters = AddressTransform.sieve.resolve("domain-d.test").resolve("dmarc").resolve(".dovecot.sieve");
        Files.createDirectories(filters.getParent());
        Files.writeString(filters, "redirect \"vecchio@x.it\";\n");
        AddressTransform.MailContent p = AddressTransform.mail("dmarc@domain-d.test");
        real("4 messaggi (cur e new, anche nelle cartelle; non tmp, non i file di Dovecot), 400 byte, e i filtri: "
                + p.messages() + ", " + p.totalBytes(), p.present() && p.messages() == 4 && p.totalBytes() == 400 && p.filters());
        real("un indirizzo senza cartella: niente", !AddressTransform.mail("nessuno@domain-d.test").present());
        real("\"..@domain-d.test\" non diventa un percorso", AddressTransform.folder(AddressTransform.vmail, "..@domain-d.test") == null
                && AddressTransform.folder(AddressTransform.vmail, ".to@domain-d.test") == null);
        List<Path[]> moved = AddressTransform.archive("dmarc@domain-d.test", 1_790_000_000_000L);
        real("messa da parte: posta e filtri in .panel-archive, con la data", moved.size() == 2 && !Files.exists(dir)
                && moved.get(0)[1].toString().contains(".panel-archive/domain-d.test/dmarc-20260921T")
                && moved.get(1)[1].getFileName().toString().endsWith("-filters")
                && Files.exists(moved.get(0)[1].resolve("cur/1.M1")) && Files.exists(moved.get(1)[1].resolve(".dovecot.sieve")));
        AddressTransform.restore(moved);
        real("e rimessa a posto, se il resto non riesce", Files.exists(dir.resolve("cur/1.M1")) && Files.exists(filters));
        List<Path[]> first = AddressTransform.archive("dmarc@domain-d.test", 1_790_000_000_000L);
        Files.createDirectories(dir.resolve("cur"));
        Files.writeString(dir.resolve("cur/6.M6"), "y");
        List<Path[]> second = AddressTransform.archive("dmarc@domain-d.test", 1_790_000_000_000L);
        real("due archiviazioni nello stesso secondo non si sovrascrivono: " + second.get(0)[1].getFileName(),
                !first.get(0)[1].equals(second.get(0)[1]) && Files.exists(first.get(0)[1].resolve("cur/1.M1"))
                && Files.exists(second.get(0)[1].resolve("cur/6.M6")));
    }

    // ===================== Su MySQL =====================

    static String postfixAlias(Connection c, String address) throws SQLException {
        // Le query di mysql-virtual-aliases.cf e mysql-virtual-mailboxes.cf (FullMailServerScript).
        List<String> d = new ArrayList<>();
        try (PreparedStatement p = c.prepareStatement("SELECT destination FROM aliases WHERE source=? AND active=1 ORDER BY destination")) {
            p.setString(1, address);
            try (ResultSet r = p.executeQuery()) { while (r.next()) d.add(r.getString(1)); }
        }
        return String.join(",", d);
    }

    static String postfixMailbox(Connection c, String address) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') "
                + "FROM mailboxes WHERE email=? AND active=1 AND receive_enabled=1")) {
            p.setString(1, address);
            try (ResultSet r = p.executeQuery()) { return r.next() ? r.getString(1) : ""; }
        }
    }

    static int count(Connection c, String sql, Object... parameters) throws SQLException {
        try (PreparedStatement p = c.prepareStatement(sql)) {
            for (int k = 0; k < parameters.length; k++) p.setObject(k + 1, parameters[k]);
            try (ResultSet r = p.executeQuery()) { r.next(); return r.getInt(1); }
        }
    }

    static void database() throws Exception {
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("\n== MySQL non indicato (-Dmysql.port=...): salto la parte sul database ==");
            return;
        }
        System.out.println("\n== Su MySQL " + port + ": le due trasformazioni, come le vede Postfix ==");
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_prova"));
        if (!db.connect()) { real("connessione a MySQL", false); return; }
        db.dropAllTables();
        db.createSchema();
        Connection c = db.getConnection();
        try (var st = c.createStatement(); ResultSet r = st.executeQuery("SELECT VERSION()")) { r.next(); System.out.println("  MySQL " + r.getString(1)); }

        int dom = db.addDomain("domain-d.test", "prova");
        db.addAlias(dom, "dmarc@domain-d.test", "owner@example.net");
        db.addAlias(dom, "postmaster@domain-d.test", "dmarc@domain-d.test");
        real("prima: dmarc@ e' solo alias", postfixAlias(c, "dmarc@domain-d.test").equals("owner@example.net")
                && postfixMailbox(c, "dmarc@domain-d.test").isEmpty());

        int id = db.transformAliasToMailbox(dom, "dmarc@domain-d.test", "Una-password-lunga-42", "DMARC", 512, false);
        real("dopo: casella (domain-d.test/dmarc/), e nessun alias con quella sorgente", id > 0
                && postfixMailbox(c, "dmarc@domain-d.test").equals("domain-d.test/dmarc/") && postfixAlias(c, "dmarc@domain-d.test").isEmpty());
        real("postmaster@ -> dmarc@ resta: arriva nella casella", postfixAlias(c, "postmaster@domain-d.test").equals("dmarc@domain-d.test"));
        MailDatabase.Mailbox m = db.getMailbox(id);
        real("la password e' un hash bcrypt (quello che Dovecot verifica), quota e nome salvati",
                count(c, "SELECT COUNT(*) FROM mailboxes WHERE id=? AND password LIKE '$2a$%'", id) == 1 && m.quotaMb == 512 && "DMARC".equals(m.name));

        db.addAlias(dom, "info@domain-d.test", "capo@esterno.it");
        db.addAlias(dom, "info@domain-d.test", "segreteria@esterno.it");
        int id2 = db.transformAliasToMailbox(dom, "info@domain-d.test", "Una-password-lunga-42", "", 1024, true);
        real("tenendo gli inoltri: le destinazioni restano e la casella ne riceve una copia (info@ -> info@)",
                id2 > 0 && postfixAlias(c, "info@domain-d.test").equals("capo@esterno.it,info@domain-d.test,segreteria@esterno.it"));

        boolean refused;
        int before = count(c, "SELECT COUNT(*) FROM aliases");
        try {
            db.transformAliasToMailbox(dom, "dmarc@domain-d.test", "Una-password-lunga-42", "", 1024, false);
            refused = false;
        } catch (SQLException e) {
            refused = true;
        }
        real("una seconda casella con lo stesso indirizzo: rifiutata dal vincolo UNIQUE, alias intatti",
                refused && count(c, "SELECT COUNT(*) FROM aliases") == before);

        System.out.println("\n== Casella -> alias, su MySQL ==");
        db.createForwardingRule(id, "owner@example.net", true);
        db.createSieveFilter(id, "Spam", 1, "[]", "[]");
        db.saveAutoResponder(id, true, "Assente", "Torno lunedi'", null, null, 24);
        try (PreparedStatement p = c.prepareStatement("INSERT INTO rate_limits (target_type, target_id) VALUES ('mailbox', ?)")) {
            p.setInt(1, id);
            p.executeUpdate();
        }
        db.addAlias(dom, "dmarc@domain-d.test", "dmarc@domain-d.test");
        int old = db.addAlias(dom, "dmarc@domain-d.test", "owner@example.net");
        db.updateAliasStatus(old, false);

        int linesBefore = count(c, "SELECT COUNT(*) FROM aliases");
        try {
            // L'ultimo passo (la casella) fallisce: id giusto, indirizzo sbagliato.
            db.transformMailboxToAlias(id, dom, "altro@domain-d.test", List.of("x@esterno.it"));
            refused = false;
        } catch (SQLException e) {
            refused = true;
        }
        real("se l'ultimo passo fallisce, niente resta a meta': alias, limite e casella com'erano", refused
                && count(c, "SELECT COUNT(*) FROM aliases") == linesBefore
                && count(c, "SELECT COUNT(*) FROM aliases WHERE source='altro@domain-d.test'") == 0
                && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_id=?", id) == 1
                && postfixMailbox(c, "dmarc@domain-d.test").equals("domain-d.test/dmarc/"));

        db.transformMailboxToAlias(id, dom, "dmarc@domain-d.test", List.of("owner@example.net", "postmaster@domain-c.test"));
        real("dopo: niente casella, alias verso le due destinazioni (quella disattiva riattivata)",
                postfixMailbox(c, "dmarc@domain-d.test").isEmpty()
                && postfixAlias(c, "dmarc@domain-d.test").equals("owner@example.net,postmaster@domain-c.test"));
        real("l'alias su se stessa se n'e' andato (senza casella porterebbe al nulla)",
                count(c, "SELECT COUNT(*) FROM aliases WHERE source='dmarc@domain-d.test' AND destination='dmarc@domain-d.test'") == 0);
        real("inoltri, filtri, risposta automatica e limite di invio se ne sono andati con la casella",
                count(c, "SELECT COUNT(*) FROM forwarding_rules WHERE mailbox_id=?", id) == 0
                && count(c, "SELECT COUNT(*) FROM sieve_filters WHERE mailbox_id=?", id) == 0
                && count(c, "SELECT COUNT(*) FROM auto_responders WHERE mailbox_id=?", id) == 0
                && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='mailbox' AND target_id=?", id) == 0);
        real("postmaster@ -> dmarc@ continua: ora va alle destinazioni dell'alias",
                postfixAlias(c, "postmaster@domain-d.test").equals("dmarc@domain-d.test"));

        System.out.println("\n== Andata e ritorno, con lo stato letto dal database ==");
        AddressTransform.AddressState s = AddressTransform.state(db, "dmarc@domain-d.test");
        real("dmarc@ si puo' ritrasformare in casella", AddressTransform.noMailboxReason(s) == null && s.towardsHere().size() == 1);
        AddressTransform.AddressState si = AddressTransform.state(db, "info@domain-d.test");
        try {
            AddressTransform.destinations(si, new JSONArray().put("postmaster@domain-d.test"), AddressTransform.network(db));
            real("info@ verso postmaster@ (che va a dmarc@, alias): si' dal database", true);
        } catch (IllegalArgumentException e) {
            real("info@ verso postmaster@: " + e.getMessage(), false);
        }
        db.addAlias(dom, "giro@domain-d.test", "info@domain-d.test");
        try {
            AddressTransform.destinations(si, new JSONArray().put("giro@domain-d.test"), AddressTransform.network(db));
            real("info@ verso giro@ (che torna a info@): doveva essere rifiutato", false);
        } catch (IllegalArgumentException e) {
            real("info@ verso giro@ (che torna a info@): rifiutato dal database", e.getMessage().contains("giro@domain-d.test -> info@domain-d.test"));
        }
        db.close();
    }
}
