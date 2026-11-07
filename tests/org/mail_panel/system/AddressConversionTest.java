package org.mail_panel.system;

import org.mail_panel.TestSql;

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
 * Turning an alias into a mailbox and a mailbox into an alias (AddressTransform and MailDatabase).
 *
 * First part, without a database: when it can be done and when not (catch-alls, names that would
 * leave /var/vmail, domains that are not the panel's, addresses that are already mailboxes), the
 * destinations (valid, existing if they are on the panel's domains, without loops that come back to
 * the address), the mail on disk (counted, set aside, put back), the preview's fingerprint.
 *
 * Second part, on a real MySQL (the same as the panel: mysql80-server): the two transactions, looked
 * at with the same queries Postfix uses. That a half-done conversion never stays: if the last step
 * fails, the database goes back as it was. It is skipped if MySQL is not given:
 *   -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_test
 */
public class AddressConversionTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
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

    /** A fake network: the panel's domains, receiving mailboxes, active aliases. */
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
        org.mail_panel.i18n.I18n.setCurrent("en");
        Path root = Files.createTempDirectory("transform-test");
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
        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }

    static void rules() {
        System.out.println("\n== Alias -> mailbox: when it can be done ==");
        List<MailDatabase.Alias> oneAlias = List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true));
        real("a catch-all (@domain-d.test) no: it has no name before the @",
                AddressTransform.noMailboxReason(state("@domain-d.test", true, null, oneAlias, List.of())).contains("catch-all"));
        real("\"..@domain-d.test\" no: as a path it would leave /var/vmail",
                AddressTransform.noMailboxReason(state("..@domain-d.test", true, null, oneAlias, List.of())) != null);
        real("a domain that is not the panel's no",
                AddressTransform.noMailboxReason(state("dmarc@other.example", false, null, oneAlias, List.of())).contains("not one of the panel's domains"));
        real("an address that is already a mailbox no",
                AddressTransform.noMailboxReason(state("dmarc@domain-d.test", true, mailbox(5, "dmarc@domain-d.test"), oneAlias, List.of())).contains("already a mailbox"));
        real("an address without aliases no",
                AddressTransform.noMailboxReason(state("dmarc@domain-d.test", true, null, List.of(), List.of())).contains("has no alias"));
        AddressTransform.AddressState ok = state("dmarc@domain-d.test", true, null,
                List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true), alias(2, "dmarc@domain-d.test", "old@x.it", false)),
                List.of(alias(3, "postmaster@domain-d.test", "dmarc@domain-d.test", true)));
        real("dmarc@domain-d.test -> owner@example.net: it can be done", AddressTransform.noMailboxReason(ok) == null);
        JSONObject preview = AddressTransform.previewToMailbox(ok, ZoneId.of("Europe/Rome"));
        real("the preview lists the destinations (the inactive one too) and who arrives here", preview.getBoolean("possible")
                && preview.getJSONArray("destinations").length() == 2 && preview.getJSONArray("towardsHere").getJSONObject(0).getString("source").equals("postmaster@domain-d.test"));
        String before = AddressTransform.fingerprint(ok);
        AddressTransform.AddressState changed = state("dmarc@domain-d.test", true, null,
                List.of(alias(1, "dmarc@domain-d.test", "owner@example.net", true), alias(2, "dmarc@domain-d.test", "old@x.it", true)),
                ok.towardsHere());
        real("the fingerprint changes if an alias changes (turned back on)", !before.equals(AddressTransform.fingerprint(changed)));
        real("and it does not change if nothing changes", before.equals(AddressTransform.fingerprint(ok)));

        System.out.println("\n== Mailbox -> alias: what is lost ==");
        MailDatabase.Mailbox m = mailbox(7, "info@domain-d.test");
        m.receiveEnabled = false;
        AddressTransform.AddressState c = new AddressTransform.AddressState("info@domain-d.test", true, m,
                List.of(alias(4, "info@domain-d.test", "info@domain-d.test", true), alias(5, "info@domain-d.test", "boss@x.it", true)),
                List.of(), AddressTransform.MailContent.NONE,
                new AddressTransform.Losses(true, List.of("owner@example.net", "info@domain-d.test"), 3));
        JSONObject aa = AddressTransform.previewToAlias(c, ZoneId.of("Europe/Rome"));
        JSONObject per = aa.getJSONObject("losses");
        real("auto-reply, 3 filters, forwards and send-only", per.getBoolean("autoReply") && per.getInt("filters") == 3
                && per.getJSONArray("forwards").length() == 2 && per.getBoolean("sendOnly"));
        real("the proposed destinations are the mailbox's forwards, without itself",
                aa.getJSONArray("proposals").toList().equals(List.of("owner@example.net")));
        real("the alias to itself is pointed out (it will go away), the others stay", aa.getBoolean("copy")
                && aa.getJSONArray("alreadyForwarded").getJSONObject(0).getString("destination").equals("boss@x.it"));
        real("on an alias (not a mailbox): it cannot be done", !AddressTransform.previewToAlias(ok, ZoneId.of("Europe/Rome")).getBoolean("possible"));
    }

    static void destinations() {
        System.out.println("\n== Mailbox -> alias: the destinations ==");
        AddressTransform.AddressState s = state("info@domain-d.test", true, mailbox(7, "info@domain-d.test"), List.of(), List.of());
        FakeNetwork r = new FakeNetwork(Set.of("domain-d.test", "domain-c.test"), Set.of("owner@domain-d.test", "info@domain-d.test"));
        r.route("sales@domain-d.test", "owner@domain-d.test");
        real("no destination: no", error(s, new JSONArray(), r).contains("At least one"));
        real("the address itself: no", error(s, new JSONArray().put("info@domain-d.test"), r).contains("itself"));
        real("an invalid address: no", error(s, new JSONArray().put("not an address"), r).contains("is not a valid address"));
        real("on one of your domains but not existing: no (the mail would be rejected)",
                error(s, new JSONArray().put("nobody@domain-d.test"), r).contains("would be rejected"));
        real("one of your mailboxes: yes", error(s, new JSONArray().put("owner@domain-d.test"), r) == null);
        real("one of your active aliases: yes", error(s, new JSONArray().put("sales@domain-d.test"), r) == null);
        r.route("@domain-c.test", "owner@domain-d.test");
        real("any address of a domain with a catch-all: yes", error(s, new JSONArray().put("anyone@domain-c.test"), r) == null);
        real("an outside address: yes", error(s, new JSONArray().put("owner@example.net"), r) == null);
        JSONArray many = new JSONArray();
        for (int k = 0; k < 21; k++) many.put("person" + k + "@outside.example");
        real("more than 20: no", error(s, many, r).contains("At most"));
        r.route("loop@domain-d.test", "info@domain-d.test");
        String g = error(s, new JSONArray().put("loop@domain-d.test"), r);
        real("an alias that leads back to the address: no, with the path: " + g, g != null && g.contains("loop@domain-d.test -> info@domain-d.test"));
        r.route("a@domain-d.test", "b@domain-d.test").route("b@domain-d.test", "info@domain-d.test");
        real("even in two steps", error(s, new JSONArray().put("a@domain-d.test"), r).contains("a@domain-d.test -> b@domain-d.test -> info@domain-d.test"));
        AddressTransform.AddressState withAlias = state("info@domain-d.test", true, mailbox(7, "info@domain-d.test"),
                List.of(alias(9, "info@domain-d.test", "loop@domain-d.test", true)), List.of());
        real("and even if the loop goes through an alias the address already has",
                error(withAlias, new JSONArray().put("owner@example.net"), r).contains("loop@domain-d.test"));
        try {
            List<String> d = AddressTransform.destinations(s, new JSONArray().put(" Owner@Domain-d.test ").put("owner@domain-d.test"), r);
            real("spaces and upper case removed, duplicates once: " + d, d.equals(List.of("owner@domain-d.test")));
        } catch (Exception e) {
            real("spaces and upper case: " + e.getMessage(), false);
        }
    }

    static void disk(Path root) throws Exception {
        System.out.println("\n== The mail on disk ==");
        Path dir = AddressTransform.vmail.resolve("domain-d.test").resolve("dmarc");
        for (String f : new String[] { "cur/1.M1", "new/2.M2", ".Archive/cur/3.M3", ".Archive/new/4.M4", "dovecot-uidlist", "tmp/5.M5" }) {
            Path p = dir.resolve(f);
            Files.createDirectories(p.getParent());
            Files.writeString(p, "x".repeat(100));
        }
        Path filters = AddressTransform.sieve.resolve("domain-d.test").resolve("dmarc").resolve(".dovecot.sieve");
        Files.createDirectories(filters.getParent());
        Files.writeString(filters, "redirect \"old@x.it\";\n");
        AddressTransform.MailContent p = AddressTransform.mail("dmarc@domain-d.test");
        real("4 messages (cur and new, also in the folders; not tmp, not Dovecot's files), 400 bytes, and the filters: "
                + p.messages() + ", " + p.totalBytes(), p.present() && p.messages() == 4 && p.totalBytes() == 400 && p.filters());
        real("an address without a folder: nothing", !AddressTransform.mail("nobody@domain-d.test").present());
        real("\"..@domain-d.test\" does not become a path", AddressTransform.folder(AddressTransform.vmail, "..@domain-d.test") == null
                && AddressTransform.folder(AddressTransform.vmail, ".to@domain-d.test") == null);
        List<Path[]> moved = AddressTransform.archive("dmarc@domain-d.test", 1_790_000_000_000L);
        real("set aside: mail and filters in .panel-archive, with the date", moved.size() == 2 && !Files.exists(dir)
                && moved.get(0)[1].toString().contains(".panel-archive/domain-d.test/dmarc-20260921T")
                && moved.get(1)[1].getFileName().toString().endsWith("-filters")
                && Files.exists(moved.get(0)[1].resolve("cur/1.M1")) && Files.exists(moved.get(1)[1].resolve(".dovecot.sieve")));
        AddressTransform.restore(moved);
        real("and put back, if the rest does not succeed", Files.exists(dir.resolve("cur/1.M1")) && Files.exists(filters));
        List<Path[]> first = AddressTransform.archive("dmarc@domain-d.test", 1_790_000_000_000L);
        Files.createDirectories(dir.resolve("cur"));
        Files.writeString(dir.resolve("cur/6.M6"), "y");
        List<Path[]> second = AddressTransform.archive("dmarc@domain-d.test", 1_790_000_000_000L);
        real("two archivings in the same second do not overwrite each other: " + second.get(0)[1].getFileName(),
                !first.get(0)[1].equals(second.get(0)[1]) && Files.exists(first.get(0)[1].resolve("cur/1.M1"))
                && Files.exists(second.get(0)[1].resolve("cur/6.M6")));
    }

    // ===================== On MySQL =====================

    static String postfixAlias(Connection c, String address) throws SQLException {
        // The queries of mysql-virtual-aliases.cf and mysql-virtual-mailboxes.cf (FullMailServerScript).
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
            System.out.println("\n== MySQL not given (-Dmysql.port=...): the database part is skipped ==");
            return;
        }
        System.out.println("\n== On MySQL " + port + ": the two conversions, as Postfix sees them ==");
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_test"));
        if (!db.connect()) { real("connection to MySQL", false); return; }
        db.dropAllTables();
        db.createSchema();
        Connection c = TestSql.mysql();
        try (var st = c.createStatement(); ResultSet r = st.executeQuery("SELECT VERSION()")) { r.next(); System.out.println("  MySQL " + r.getString(1)); }

        int dom = db.addDomain("domain-d.test", "test");
        db.addAlias(dom, "dmarc@domain-d.test", "owner@example.net");
        db.addAlias(dom, "postmaster@domain-d.test", "dmarc@domain-d.test");
        real("before: dmarc@ is only an alias", postfixAlias(c, "dmarc@domain-d.test").equals("owner@example.net")
                && postfixMailbox(c, "dmarc@domain-d.test").isEmpty());

        int id = db.transformAliasToMailbox(dom, "dmarc@domain-d.test", "A-long-password-42", "DMARC", 512, false);
        real("after: a mailbox (domain-d.test/dmarc/), and no alias with that source", id > 0
                && postfixMailbox(c, "dmarc@domain-d.test").equals("domain-d.test/dmarc/") && postfixAlias(c, "dmarc@domain-d.test").isEmpty());
        real("postmaster@ -> dmarc@ stays: it arrives in the mailbox", postfixAlias(c, "postmaster@domain-d.test").equals("dmarc@domain-d.test"));
        MailDatabase.Mailbox m = db.getMailbox(id);
        real("the password is a bcrypt hash (what Dovecot checks), quota and name saved",
                count(c, "SELECT COUNT(*) FROM mailboxes WHERE id=? AND password LIKE '$2a$%'", id) == 1 && m.quotaMb == 512 && "DMARC".equals(m.name));

        db.addAlias(dom, "info@domain-d.test", "boss@outside.example");
        db.addAlias(dom, "info@domain-d.test", "office@outside.example");
        int id2 = db.transformAliasToMailbox(dom, "info@domain-d.test", "A-long-password-42", "", 1024, true);
        real("keeping the forwards: the destinations stay and the mailbox gets a copy (info@ -> info@)",
                id2 > 0 && postfixAlias(c, "info@domain-d.test").equals("boss@outside.example,info@domain-d.test,office@outside.example"));

        boolean refused;
        int before = count(c, "SELECT COUNT(*) FROM aliases");
        try {
            db.transformAliasToMailbox(dom, "dmarc@domain-d.test", "A-long-password-42", "", 1024, false);
            refused = false;
        } catch (SQLException e) {
            refused = true;
        }
        real("a second mailbox with the same address: refused by the UNIQUE constraint, aliases untouched",
                refused && count(c, "SELECT COUNT(*) FROM aliases") == before);

        System.out.println("\n== Mailbox -> alias, on MySQL ==");
        db.createForwardingRule(id, "owner@example.net", true);
        db.createSieveFilter(id, "Spam", 1, "[]", "[]");
        db.saveAutoResponder(id, true, "Away", "Back on Monday", null, null, 24);
        try (PreparedStatement p = c.prepareStatement("INSERT INTO rate_limits (target_type, target_id) VALUES ('mailbox', ?)")) {
            p.setInt(1, id);
            p.executeUpdate();
        }
        db.addAlias(dom, "dmarc@domain-d.test", "dmarc@domain-d.test");
        int old = db.addAlias(dom, "dmarc@domain-d.test", "owner@example.net");
        db.updateAliasStatus(old, false);

        int linesBefore = count(c, "SELECT COUNT(*) FROM aliases");
        try {
            // The last step (the mailbox) fails: right id, wrong address.
            db.transformMailboxToAlias(id, dom, "other@domain-d.test", List.of("x@outside.example"));
            refused = false;
        } catch (SQLException e) {
            refused = true;
        }
        real("if the last step fails, nothing stays half-done: aliases, limit and mailbox as they were", refused
                && count(c, "SELECT COUNT(*) FROM aliases") == linesBefore
                && count(c, "SELECT COUNT(*) FROM aliases WHERE source='other@domain-d.test'") == 0
                && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_id=?", id) == 1
                && postfixMailbox(c, "dmarc@domain-d.test").equals("domain-d.test/dmarc/"));

        db.transformMailboxToAlias(id, dom, "dmarc@domain-d.test", List.of("owner@example.net", "postmaster@domain-c.test"));
        real("after: no mailbox, an alias towards the two destinations (the inactive one turned back on)",
                postfixMailbox(c, "dmarc@domain-d.test").isEmpty()
                && postfixAlias(c, "dmarc@domain-d.test").equals("owner@example.net,postmaster@domain-c.test"));
        real("the alias to itself went away (without the mailbox it would lead nowhere)",
                count(c, "SELECT COUNT(*) FROM aliases WHERE source='dmarc@domain-d.test' AND destination='dmarc@domain-d.test'") == 0);
        real("forwards, filters, auto-reply and sending limit went away with the mailbox",
                count(c, "SELECT COUNT(*) FROM forwarding_rules WHERE mailbox_id=?", id) == 0
                && count(c, "SELECT COUNT(*) FROM sieve_filters WHERE mailbox_id=?", id) == 0
                && count(c, "SELECT COUNT(*) FROM auto_responders WHERE mailbox_id=?", id) == 0
                && count(c, "SELECT COUNT(*) FROM rate_limits WHERE target_type='mailbox' AND target_id=?", id) == 0);
        real("postmaster@ -> dmarc@ goes on: now it goes to the alias's destinations",
                postfixAlias(c, "postmaster@domain-d.test").equals("dmarc@domain-d.test"));

        System.out.println("\n== There and back, with the state read from the database ==");
        AddressTransform.AddressState s = AddressTransform.state(db, "dmarc@domain-d.test");
        real("dmarc@ can be turned into a mailbox again", AddressTransform.noMailboxReason(s) == null && s.towardsHere().size() == 1);
        AddressTransform.AddressState si = AddressTransform.state(db, "info@domain-d.test");
        try {
            AddressTransform.destinations(si, new JSONArray().put("postmaster@domain-d.test"), AddressTransform.network(db));
            real("info@ towards postmaster@ (which goes to dmarc@, an alias): yes from the database", true);
        } catch (IllegalArgumentException e) {
            real("info@ towards postmaster@: " + e.getMessage(), false);
        }
        db.addAlias(dom, "loop@domain-d.test", "info@domain-d.test");
        try {
            AddressTransform.destinations(si, new JSONArray().put("loop@domain-d.test"), AddressTransform.network(db));
            real("info@ towards loop@ (which comes back to info@): it should have been refused", false);
        } catch (IllegalArgumentException e) {
            real("info@ towards loop@ (which comes back to info@): refused by the database", e.getMessage().contains("loop@domain-d.test -> info@domain-d.test"));
        }
        db.close();
    }
}
