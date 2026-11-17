package org.daemoxcp.mail.system;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * The once-only change of the panel's MySQL password (reperto 232) against a REAL MySQL, the test one, as its root:
 * the catalog statements (PDP_ACCOUNTS, PDP_RETAIN, PDP_SET, PDP_DISCARD) and the logins are MySQL's, not a fake's.
 * A test user with two local accounts (localhost and 127.0.0.1) and the same password, as the installer makes them.
 *
 *  1. the change: DONE; the new password gets in, the old one gets "Access denied" (1045); neither account has a
 *     second password left (mysql.user); the second run does nothing;
 *  2. RETAIN refused on localhost (a wrapper around the real accounts): ROLLED_BACK; the password of before gets in,
 *     the attempted one does not, no second password;
 *  3. killed before the panel adopts: MySQL takes both; PendingDbPassword.settle adopts the new one; the run then
 *     finishes it (RESUMED), the old one refused, no second password.
 * Nothing touches the real MySQL: it refuses to run on port 3306. The state and the panel's store are in memory.
 *
 * Usage (on the VM, with the test MySQL of tests/README.md):
 *   java -Ddaemoxcp.mail.mysql.port=33062 -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelDbPasswordMysqlTest
 */
public class PanelDbPasswordMysqlTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String port;
    static final String USER = "pdptest";
    static final String OLD = "PdpTestOldPassword0123456789";

    static Connection root() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port
                + "/?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", "root", "");
    }

    static void exec(String sql, String... params) throws SQLException {
        try (Connection c = root(); PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) ps.setString(i + 1, params[i]);
            ps.execute();
        }
    }

    static void fresh() throws SQLException {
        for (String h : new String[]{"localhost", "127.0.0.1"}) {
            exec("DROP USER IF EXISTS ?@?", USER, h);
            exec("CREATE USER ?@? IDENTIFIED BY ?", USER, h, OLD);
        }
    }

    /** 0 if it gets in, otherwise MySQL's error code. */
    static int login(String password) {
        try (Connection c = DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port
                + "/?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", USER, password)) {
            return c.isValid(5) ? 0 : -1;
        } catch (SQLException e) {
            return e.getErrorCode();
        }
    }

    /** How many of the user's accounts still have a second password. */
    static int seconds() throws SQLException {
        try (Connection c = root(); PreparedStatement ps = c.prepareStatement(
                "SELECT COUNT(*) FROM mysql.user WHERE user = ? AND JSON_EXTRACT(User_attributes, '$.additional_password') IS NOT NULL")) {
            ps.setString(1, USER);
            try (ResultSet rs = ps.executeQuery()) { rs.next(); return rs.getInt(1); }
        }
    }

    static final class Store implements PendingDbPassword.Store {
        String current = OLD, pending = "";
        boolean killOnAdopt;
        @Override public String current() { return current; }
        @Override public void adopt(String p) { if (killOnAdopt) throw new RuntimeException("killed"); current = p; }
        @Override public String pending() { return pending; }
        @Override public void setPending(String p) { pending = p; }
    }

    static final class State implements PanelDbPassword.State {
        String value = "";
        @Override public String get() { return value; }
        @Override public void set(String v) { value = v; }
    }

    static final PanelDbPassword.Places NO_FILES = new PanelDbPassword.Places() {
        @Override public List<String> usersOf(String password) { return List.of(); }
        @Override public List<String> rewriteCopies(String old, String f) { return List.of(); }
    };

    public static void main(String[] args) throws Exception {
        port = System.getProperty("daemoxcp.mail.mysql.port");
        if (port == null || port.equals("3306")) {
            System.out.println("Give the test MySQL's port with -Ddaemoxcp.mail.mysql.port (never 3306, the real one).");
            System.exit(2);
        }
        PendingDbPassword.Probe probe = PendingDbPassword.mysqlProbe("127.0.0.1", port, USER);
        PanelDbPassword.Accounts real = PanelDbPassword.mysqlAccounts();
        try {
            System.out.println("== 1. The change");
            fresh();
            check("before: the old password gets in", login(OLD) == 0);
            List<PanelDbPassword.Account> accounts = real.list(USER);
            check("PDP_ACCOUNTS reads both accounts, no second password (" + accounts + ")", accounts != null && accounts.size() == 2
                    && accounts.stream().noneMatch(PanelDbPassword.Account::secondary));
            Store s = new Store();
            State st = new State();
            PanelDbPassword.Result r = PanelDbPassword.run(s, probe, real, NO_FILES, st, USER, () -> "PdpTestNewPasswordAAAA0123456789");
            check("DONE (" + r.detail() + ")", r.outcome() == PanelDbPassword.Outcome.DONE);
            check("  the new one gets in", login(s.current) == 0 && s.current.equals("PdpTestNewPasswordAAAA0123456789"));
            check("  the old one: Access denied (1045)", login(OLD) == 1045);
            check("  no second password on any account", seconds() == 0);
            r = PanelDbPassword.run(s, probe, real, NO_FILES, st, USER, () -> "PdpTestNewPasswordBBBB0123456789");
            check("a second run: NOTHING, the same password", r.outcome() == PanelDbPassword.Outcome.NOTHING && login(s.current) == 0
                    && s.current.equals("PdpTestNewPasswordAAAA0123456789"));

            System.out.println("\n== 2. RETAIN refused on localhost: back as it was");
            fresh();
            PanelDbPassword.Accounts refusing = new PanelDbPassword.Accounts() {
                @Override public List<PanelDbPassword.Account> list(String u) { return real.list(u); }
                @Override public boolean retain(String h, String u, String p) { return !h.equals("localhost") && real.retain(h, u, p); }
                @Override public boolean setPrimary(String h, String u, String p) { return real.setPrimary(h, u, p); }
                @Override public boolean discard(String h, String u) { return real.discard(h, u); }
            };
            s = new Store();
            st = new State();
            r = PanelDbPassword.run(s, probe, refusing, NO_FILES, st, USER, () -> "PdpTestNewPasswordCCCC0123456789");
            check("ROLLED_BACK (" + r.detail() + ")", r.outcome() == PanelDbPassword.Outcome.ROLLED_BACK);
            check("  the old one gets in, the attempted one does not", login(OLD) == 0 && login("PdpTestNewPasswordCCCC0123456789") == 1045);
            check("  no second password, nothing waiting, no state", seconds() == 0 && s.pending.isEmpty() && st.value.isEmpty() && OLD.equals(s.current));

            System.out.println("\n== 3. Killed before the panel adopts");
            fresh();
            s = new Store();
            st = new State();
            s.killOnAdopt = true;
            boolean died = false;
            try {
                PanelDbPassword.run(s, probe, real, NO_FILES, st, USER, () -> "PdpTestNewPasswordDDDD0123456789");
            } catch (RuntimeException e) {
                died = true;
            }
            check("the process dies; MySQL takes both passwords", died && login(OLD) == 0 && login("PdpTestNewPasswordDDDD0123456789") == 0);
            s.killOnAdopt = false;
            PendingDbPassword.Result settled = PendingDbPassword.settle(s, probe, USER);
            check("the next start adopts the new one: " + settled.outcome(), settled.outcome() == PendingDbPassword.Outcome.NEW_ADOPTED
                    && s.current.equals("PdpTestNewPasswordDDDD0123456789"));
            r = PanelDbPassword.run(s, probe, real, NO_FILES, st, USER, () -> "PdpTestNewPasswordEEEE0123456789");
            check("then RESUMED (" + r.detail() + ")", r.outcome() == PanelDbPassword.Outcome.RESUMED);
            check("  the new one gets in, the old one 1045, no second password", login(s.current) == 0 && login(OLD) == 1045 && seconds() == 0);
        } finally {
            for (String h : new String[]{"localhost", "127.0.0.1"}) {
                try { exec("DROP USER IF EXISTS ?@?", USER, h); } catch (SQLException ignored) { }
            }
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
