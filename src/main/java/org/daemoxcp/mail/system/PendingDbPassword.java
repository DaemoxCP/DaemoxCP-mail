package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.PanelSecrets;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.logging.Logger;

/**
 * The panel's MySQL password changes only when MySQL knows it.
 *
 * <p>Why it exists: measured on 2026-11-06 on the FreeBSD 15.1 VM (finding 156). The full
 * installation from the menu generated the new password of the panel's MySQL user and wrote it
 * RIGHT AWAY into the secrets file, then launched install_mail_server.sh, which sets it in MySQL only
 * at phase 3. Every exit before that point (Roundcube not configured, a missing parameter, the
 * package turn taken, a locked package, pkg failing) left the panel with a password that MySQL
 * rejected, until the next reinstallation.
 *
 * <p>Now the new password is born <em>pending</em> ({@link PanelSecrets#MYSQL_PASSWORD_PENDING}),
 * next to the panel's one, which is not touched. When the script finishes, MySQL is asked: if it
 * accepts the pending one, it becomes the panel's; if it rejects it and accepts the old one, the
 * new one is thrown away. MySQL decides, not the script's exit code: a script that fails AFTER
 * phase 3 has already changed the password, and Postfix and Dovecot have already written it into
 * their files.
 *
 * <p>If the panel dies while the script is working, the pending password stays in the file, and
 * the next startup asks the same question ({@link #settleAtStartup}). If MySQL does not answer,
 * nothing is decided: the pending password stays, and the next installation gives MySQL that one
 * again, instead of throwing it away for a new one that MySQL certainly does not know.
 *
 * <p>At startup there is also the remedy for the servers already broken by the previous version,
 * which had no pending password: if MySQL rejects the panel's password, the one Postfix uses is
 * tried ({@link #postfixMap}, written by the script at phase 6 and deleted only at phase 1, so
 * intact after every early exit). If MySQL accepts it, it is the right one and becomes the
 * panel's. A password that MySQL has not accepted in front of us is never chosen.
 */
public final class PendingDbPassword {

    private static final Logger LOGGER = Logger.getLogger(PendingDbPassword.class.getName());

    private PendingDbPassword() {}

    /** What MySQL says about a password. */
    public enum Answer { ACCEPTED, REJECTED, NO_ANSWER }

    /** How a decision ended. */
    public enum Outcome {
        /** Nothing pending, and the panel's password is fine (or there is nothing to ask). */
        NOTHING_TO_DO,
        /** MySQL accepts the pending password: it is now the panel's. */
        NEW_ADOPTED,
        /** MySQL does not know the pending password and accepts the previous one: that one is kept. */
        OLD_KEPT,
        /** MySQL rejects the panel's password and accepts Postfix's: it is now the panel's. */
        COPY_ADOPTED,
        /** MySQL does not answer: nothing is decided, the pending password stays. */
        UNDECIDED,
        /** MySQL rejects every password the panel knows: nothing changes. */
        NONE_ACCEPTED,
        /** Another panel process holds the turn (perhaps an installation): that process decides. */
        NOT_NOW
    }

    /** The outcome, with the message to show ("" if there is nothing to say). */
    public record Result(Outcome outcome, String message) {}

    /** The password for the script, and what happened to the one left pending from before. */
    public record Prepared(String password, String note) {}

    /** Where the passwords are kept. In production the secrets file (and SQLite); in tests a fake. */
    public interface Store {
        /** The password the panel uses to log into MySQL ("" if there is none yet). */
        String current();
        /** From now on this is the panel's password. */
        void adopt(String password);
        /** The pending password ("" if there is none). */
        String pending();
        /** Writes the pending password; with "" it removes it. */
        void setPending(String password);
    }

    /** The question to MySQL: does the panel's user get in with this password? */
    public interface Probe {
        Answer ask(String password);
    }

    /**
     * The Postfix file with the password of the panel's user. It is a variable only so that the
     * tests do not read the real one.
     */
    static Path postfixMap = Path.of("/usr/local/etc/postfix/mysql-virtual-domains.cf");

    // ---------------------------------------------------------------- the decision

    /**
     * Before the script: the password the script will give to MySQL, written as pending.
     *
     * <p>If a pending password already exists (an earlier installation that did not reach the
     * decision), that one is decided first. If MySQL cannot answer, it is reused: MySQL might
     * know it, and throwing it away for a new one would leave the panel without the only right
     * password if this script too stops before reaching MySQL.
     *
     * @throws IllegalStateException if the password cannot be written as pending: the script must
     *         not start, because it would change MySQL without the panel knowing to what.
     */
    public static Prepared prepare(Store store, Probe probe, String user) {
        String note = "";
        String left = store.pending();
        if (!left.isEmpty()) {
            Result r = settle(store, probe, user);
            if (r.outcome() == Outcome.UNDECIDED)
                return new Prepared(left, I18n.tr("server.dbPassword.reused"));
            note = r.message();
        }
        String fresh = PanelSecrets.newAlphanumericPassword(24);
        store.setPending(fresh);
        if (!fresh.equals(store.pending()))
            throw new IllegalStateException("the new password was not kept aside");
        return new Prepared(fresh, note);
    }

    /**
     * After the script (or at startup): which password MySQL knows. The caller holds the package
     * turn, or is a test: an installation in progress in another process would change MySQL
     * while the decision is being made here.
     */
    public static Result settle(Store store, Probe probe, String user) {
        String pending = store.pending();
        String current = store.current();

        if (!pending.isEmpty()) {
            Answer p = probe.ask(pending);
            if (p == Answer.ACCEPTED) {
                // First adopt it, then clear the pending one: a stop in between leaves the two
                // equal, and the next decision finds both of them accepted.
                store.adopt(pending);
                store.setPending("");
                return new Result(Outcome.NEW_ADOPTED, I18n.tr("server.dbPassword.newAdopted"));
            }
            if (p == Answer.NO_ANSWER) return undecided();
            Answer c = current.isEmpty() || current.equals(pending) ? Answer.REJECTED : probe.ask(current);
            if (c == Answer.NO_ANSWER) return undecided();
            if (c == Answer.ACCEPTED) {
                store.setPending("");
                return new Result(Outcome.OLD_KEPT, I18n.tr("server.dbPassword.oldKept"));
            }
            // MySQL said no to both: the new one is of no use any more.
            Result copy = tryPostfixCopy(store, probe, user, pending, current);
            store.setPending("");
            if (copy != null) return copy;
            return new Result(Outcome.NONE_ACCEPTED, I18n.tr("server.dbPassword.noneAccepted",
                    Map.of("user", String.valueOf(user), "file", String.valueOf(postfixMap))));
        }

        if (current.isEmpty()) return new Result(Outcome.NOTHING_TO_DO, "");   // never installed
        Answer c = probe.ask(current);
        if (c != Answer.REJECTED) return new Result(Outcome.NOTHING_TO_DO, "");
        Result copy = tryPostfixCopy(store, probe, user, "", current);
        if (copy != null) return copy;
        return new Result(Outcome.NONE_ACCEPTED, I18n.tr("server.dbPassword.noneAccepted",
                Map.of("user", String.valueOf(user), "file", String.valueOf(postfixMap))));
    }

    private static Result undecided() {
        return new Result(Outcome.UNDECIDED, I18n.tr("server.dbPassword.undecided"));
    }

    /** Postfix's password, if it is a different one and MySQL accepts it. null otherwise. */
    private static Result tryPostfixCopy(Store store, Probe probe, String user, String pending, String current) {
        String copy = postfixCopy(user);
        if (copy.isEmpty() || copy.equals(pending) || copy.equals(current)) return null;
        if (probe.ask(copy) != Answer.ACCEPTED) return null;
        store.adopt(copy);
        return new Result(Outcome.COPY_ADOPTED, I18n.tr("server.dbPassword.copyAdopted",
                Map.of("file", String.valueOf(postfixMap))));
    }

    /**
     * The password in the Postfix file, if the file belongs to the panel's user; "" otherwise (file
     * missing, unreadable, owned by another user). The format is the one the script writes:
     * {@code key = value}, one per line.
     */
    static String postfixCopy(String user) {
        try {
            if (!Files.isRegularFile(postfixMap)) return "";
            String fileUser = null, password = null;
            for (String line : Files.readAllLines(postfixMap, StandardCharsets.UTF_8)) {
                int eq = line.indexOf('=');
                if (eq < 0 || line.trim().startsWith("#")) continue;
                String key = line.substring(0, eq).trim();
                String value = line.substring(eq + 1).trim();
                if (key.equals("user")) fileUser = value;
                else if (key.equals("password")) password = value;
            }
            if (password == null || fileUser == null || !fileUser.equals(user)) return "";
            return password;
        } catch (Exception e) {
            return "";
        }
    }

    // ---------------------------------------------------------------- the real panel

    /** The real panel's passwords: the secrets file, and the SQLite column if it is still filled in. */
    public static Store panelStore(org.daemoxcp.mail.sqli.dataBaseManager db) {
        return new Store() {
            public String current() { return db.mysqlPassword(); }
            public void adopt(String password) { db.setMysqlPassword(password); }
            public String pending() { return PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD_PENDING); }
            public void setPending(String password) { PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD_PENDING, password); }
        };
    }

    /**
     * The real question to MySQL, without choosing a database: all that counts is whether the user
     * gets in. "Access denied" (1045, SQLSTATE 28000) is a no; anything else (connection refused,
     * timeout, MySQL still starting up) is "does not answer", and decides nothing.
     */
    public static Probe mysqlProbe(String host, String port, String user) {
        return password -> {
            if (password == null || password.isEmpty()) return Answer.REJECTED;
            String url = "jdbc:mysql://" + host + ":" + port + "/?connectTimeout=5000&socketTimeout=10000"
                    + "&useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
            try (Connection c = org.daemoxcp.mail.database.CatalogGuard.open(url, user, password)) {
                return c.isValid(5) ? Answer.ACCEPTED : Answer.NO_ANSWER;
            } catch (SQLException e) {
                if (e.getErrorCode() == 1045 || "28000".equals(e.getSQLState())) return Answer.REJECTED;
                return Answer.NO_ANSWER;
            }
        };
    }

    /** MySQL host, port and user from the panel's configuration, with the usual values if it is missing. */
    public static String[] mysqlTarget(org.daemoxcp.mail.sqli.dataBaseManager db) {
        String host = "127.0.0.1", port = "3306", user = Product.ID;
        try (ResultSet r = db.get_data_config()) {
            if (r.next()) {
                if (notBlank(r.getString("mysql_host"))) host = r.getString("mysql_host");
                if (notBlank(r.getString("mysql_port"))) port = r.getString("mysql_port");
                if (notBlank(r.getString("mysql_user"))) user = r.getString("mysql_user");
            }
        } catch (Exception e) {
            // configuration not created yet: the usual values
        }
        return new String[]{host, port, user};
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    /**
     * At the startup of every panel process, before anyone logs into MySQL.
     *
     * <p>The usual case (nothing pending, MySQL accepts the panel's password) costs one connection
     * and does not take the turn. The turn is needed only when there is something to decide: if
     * another process holds it, an installation may be running there, which will decide by itself at
     * the end; nothing is touched here.
     */
    public static Result settleAtStartup(org.daemoxcp.mail.sqli.dataBaseManager db) {
        Store store = panelStore(db);
        String[] t = mysqlTarget(db);
        Probe probe = mysqlProbe(t[0], t[1], t[2]);
        String pending, current;
        try {
            pending = store.pending();
            current = store.current();
        } catch (RuntimeException e) {
            return new Result(Outcome.NOTHING_TO_DO, "");    // secrets file unreadable: whoever reads it already reports it
        }
        if (pending.isEmpty()) {
            if (current.isEmpty()) return new Result(Outcome.NOTHING_TO_DO, "");
            if (probe.ask(current) != Answer.REJECTED) return new Result(Outcome.NOTHING_TO_DO, "");
        }
        // takeForLocks and not take: a package list left open has nothing to do with the password.
        String refusal = PackageQueue.takeForLocks("db-password", I18n.tr("server.dbPassword.turn"));
        if (refusal != null) {
            String msg = pending.isEmpty() ? "" : I18n.tr("server.dbPassword.notNow", Map.of("why", refusal));
            if (!msg.isEmpty()) LOGGER.info(msg);
            return new Result(Outcome.NOT_NOW, msg);
        }
        try {
            Result r = settle(store, probe, t[2]);
            if (!r.message().isEmpty()) LOGGER.warning(r.message());
            return r;
        } catch (RuntimeException e) {
            LOGGER.warning("Deciding the panel's MySQL password failed: " + e.getMessage());
            return new Result(Outcome.UNDECIDED, "");
        } finally {
            PackageQueue.release("db-password");
        }
    }
}
