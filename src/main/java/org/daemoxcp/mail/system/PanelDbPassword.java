package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MysqlRoot;
import org.daemoxcp.mail.database.SqlCatalog;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * The password of the panel's MySQL user, changed once (finding 232).
 *
 * <p>On the servers installed before PR #91 that password was, for their whole life, in Roundcube's
 * config.inc.php, readable by the webmail. Now the webmail logs in with its own user (RoundcubeDbUser), Postfix and
 * Dovecot with theirs (MailDbUsers), the web part with daemoxcp_mail_web: the panel's password is used only by the
 * panel. But whoever had taken it still has it, and with it reads and writes the whole mail database. Removing it
 * from the webmail was not enough: it must be changed.
 *
 * <p>Without stopping anything, with MySQL's dual password (8.0.14 and later):
 * <ol>
 *   <li>the state is written ("halfway", with the SHA-256 fingerprint of the old one: not the old one itself) and
 *       the new password pending (PendingDbPassword): a stop from here on is decided by the next startup;</li>
 *   <li>{@code ALTER USER ... IDENTIFIED BY new RETAIN CURRENT PASSWORD} on every local account of the user
 *       (localhost and 127.0.0.1: MySQL maps 127.0.0.1 to the localhost account): from here on both are valid;</li>
 *   <li>MySQL must accept both in front of us; then the panel adopts the new one (new connections re-read it
 *       from the secrets file, the open ones stay good) and the copies left by old scripts that contain the old
 *       one receive it;</li>
 *   <li>{@code DISCARD OLD PASSWORD} on every account; MySQL must refuse the old one, accept the new one, and no
 *       account must still have a second password. The state becomes "done", with the UTC date.</li>
 * </ol>
 * Until step 3 an error puts MySQL back as it was (the old one primary again, the second one discarded) and
 * removes the new one; at the next startup it is retried. After step 3 the panel is already on the new one and
 * there is no going back: if the DISCARD fails it is redone at the next startup (the state stays "halfway", and
 * the fingerprint says that the panel is no longer on the old one).
 *
 * <p>It does not start, and writes it in the log, if: the state already says "done" (the installation writes it
 * too, because it generates a password the webmail never had); the panel does not have a password yet, or has a
 * pending one (an installation that is deciding); MySQL as root does not answer, or does not accept the panel's
 * password right now; an account already has a second password that is not ours; the password still appears in a
 * Postfix, Dovecot or webmail file (someone still logs in with it: changing it would break that). The accounts
 * of the same user for other hosts are not touched, and the log names them.
 *
 * <p>What keeps the old one, which afterwards opens nothing any more: the backup copies (/var/db/daemoxcp-mail,
 * the boot environments), and a MySQL restored from before, which would also bring back the old password.
 */
public final class PanelDbPassword {

    private static final Logger LOGGER = Logger.getLogger(PanelDbPassword.class.getName());

    private PanelDbPassword() {}

    /** The halfway state: it is followed by the SHA-256 fingerprint (hexadecimal) of the old password. */
    static final String RETAINED = "retained:";
    /** The state once done: it is followed by the UTC date. */
    static final String DONE = "done ";

    /** The hosts of a local account: MySQL maps 127.0.0.1 to localhost, and IPv6. */
    static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "::1");

    /** An account of the panel's user: the host, and whether it already has a second password. */
    record Account(String host, boolean secondary) {}

    /** MySQL come root. */
    interface Accounts {
        /** The user's accounts; null if MySQL does not answer (or does not know dual passwords). */
        List<Account> list(String user);
        /** The new password, with the current one staying valid alongside it. */
        boolean retain(String host, String user, String password);
        /** This password as the primary one; the second one, if there is one, stays. */
        boolean setPrimary(String host, String user, String password);
        /** The second password removed. */
        boolean discard(String host, String user);
    }

    /** The files outside the panel. */
    interface Places {
        /** The services' files in which the password appears (a file that cannot be read counts). */
        List<String> usersOf(String password);
        /** The copies left by old scripts: where the old one is, the new one. Those not rewritten, with the reason. */
        List<String> rewriteCopies(String old, String fresh);
    }

    /** The state, in root's secrets file. */
    interface State {
        String get();
        void set(String value);
    }

    public enum Outcome {
        /** Already done, or nothing to change (panel not installed). */
        NOTHING,
        /** Changed now. */
        DONE,
        /** A rotation left halfway, finished now. */
        RESUMED,
        /** Not changed, for a reason that does not go away by itself: the detail states it. */
        LEFT,
        /** Not now (MySQL does not answer, the turn belongs to someone else): at the next startup. */
        NOT_NOW,
        /** Something went wrong before the panel adopted the new one: everything as it was. */
        ROLLED_BACK,
        /** Halfway: the panel works, the next startup finishes the rest. */
        INCOMPLETE
    }

    public record Result(Outcome outcome, String detail) {}

    static String nz(String s) {
        return s == null ? "" : s;
    }

    static String fingerprint(String password) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The decision and the change, pure with respect to the interfaces. */
    static Result run(PendingDbPassword.Store store, PendingDbPassword.Probe probe, Accounts db, Places places, State state,
                      String user, Supplier<String> generator) {
        String mark = nz(state.get());
        if (mark.startsWith(DONE)) return new Result(Outcome.NOTHING, "");
        String current = nz(store.current());
        if (current.isEmpty()) return new Result(Outcome.NOTHING, "the panel has no MySQL password yet");
        if (!nz(store.pending()).isEmpty())
            return new Result(Outcome.NOT_NOW, "a new password of an installation is still waiting to be decided");

        List<Account> all = db.list(user);
        if (all == null) return new Result(Outcome.NOT_NOW, "MySQL does not answer as root, or has no dual passwords (8.0.14+)");
        List<Account> local = all.stream().filter(a -> LOCAL_HOSTS.contains(a.host())).toList();
        List<String> others = all.stream().map(Account::host).filter(h -> !LOCAL_HOSTS.contains(h)).toList();
        if (local.isEmpty()) return new Result(Outcome.LEFT, "the MySQL user " + user + " has no account on this machine");

        if (mark.startsWith(RETAINED)) {
            if (!fingerprint(current).equals(mark.substring(RETAINED.length()))) {
                // The panel is already on the new one (adopted here, or at startup with PendingDbPassword):
                // only the DISCARD is left.
                return finish(probe, db, state, user, local, others, null, current, Outcome.RESUMED);
            }
            // Still on the old one: the new one was never adopted. MySQL goes back to the old one alone,
            // and we start over.
            if (local.stream().anyMatch(Account::secondary) && !backToOld(db, local, user, current))
                return new Result(Outcome.INCOMPLETE, "an earlier change stopped half way, and MySQL could not be put back"
                        + " to the panel's password alone: the panel keeps working (MySQL accepts it), retried at the next start");
            state.set("");
            all = db.list(user);
            if (all == null) return new Result(Outcome.NOT_NOW, "MySQL does not answer as root");
            local = all.stream().filter(a -> LOCAL_HOSTS.contains(a.host())).toList();
        }

        List<String> withSecond = local.stream().filter(Account::secondary).map(Account::host).toList();
        if (!withSecond.isEmpty())
            return new Result(Outcome.LEFT, "the account(s) " + user + "@" + withSecond + " already have a second password,"
                    + " not set by the panel: left alone");
        PendingDbPassword.Answer now = probe.ask(current);
        if (now != PendingDbPassword.Answer.ACCEPTED)
            return new Result(now == PendingDbPassword.Answer.REJECTED ? Outcome.LEFT : Outcome.NOT_NOW,
                    "MySQL does not accept the panel's password now (" + now + ")");
        List<String> users = places.usersOf(current);
        if (!users.isEmpty())
            return new Result(Outcome.LEFT, "the password is still written in " + users + ": what reads it would stop"
                    + " entering MySQL");

        String fresh = generator.get();
        if (fresh == null || fresh.length() < 24 || fresh.equals(current))
            return new Result(Outcome.NOT_NOW, "no new password");
        String retained = RETAINED + fingerprint(current);
        state.set(retained);
        if (!retained.equals(nz(state.get()))) return new Result(Outcome.NOT_NOW, "the state could not be written");
        store.setPending(fresh);
        if (!fresh.equals(nz(store.pending()))) {
            state.set("");
            return new Result(Outcome.NOT_NOW, "the new password could not be kept aside");
        }

        List<Account> changed = new ArrayList<>();
        for (Account a : local) {
            changed.add(a);   // even if it fails: a halfway ALTER is put back like the others
            if (!db.retain(a.host(), user, fresh))
                return rollBack(store, db, state, user, changed, current, "MySQL refused the new password for " + user + "@" + a.host());
        }
        PendingDbPassword.Answer f = probe.ask(fresh), o = probe.ask(current);
        if (f != PendingDbPassword.Answer.ACCEPTED || o != PendingDbPassword.Answer.ACCEPTED)
            return rollBack(store, db, state, user, changed, current,
                    "after the change MySQL should accept both passwords; new: " + f + ", previous: " + o);

        store.adopt(fresh);
        if (!fresh.equals(nz(store.current()))) {
            store.adopt(current);
            return rollBack(store, db, state, user, changed, current, "the panel could not adopt the new password");
        }
        store.setPending("");
        List<String> notRewritten = places.rewriteCopies(current, fresh);
        Result r = finish(probe, db, state, user, local, others, current, fresh, Outcome.DONE);
        if (!notRewritten.isEmpty())
            return new Result(r.outcome(), r.detail() + "; copies left with the previous password: " + notRewritten);
        return r;
    }

    /** The DISCARD and the checks. old is null when it is no longer known (resuming after a stop). */
    private static Result finish(PendingDbPassword.Probe probe, Accounts db, State state, String user, List<Account> local,
                                 List<String> others, String old, String fresh, Outcome ok) {
        List<String> notDiscarded = new ArrayList<>();
        for (Account a : local) if (!db.discard(a.host(), user)) notDiscarded.add(a.host());
        List<Account> after = db.list(user);
        List<String> stillSecond = after == null ? List.of("?")
                : after.stream().filter(a -> LOCAL_HOSTS.contains(a.host()) && a.secondary()).map(Account::host).toList();
        if (!stillSecond.isEmpty())
            return new Result(Outcome.INCOMPLETE, "the panel uses the new password, but the previous one is still valid on "
                    + user + "@" + stillSecond + (notDiscarded.isEmpty() ? "" : " (DISCARD refused on " + notDiscarded + ")")
                    + ": discarded at the next start");
        PendingDbPassword.Answer f = probe.ask(fresh);
        if (f != PendingDbPassword.Answer.ACCEPTED)
            return new Result(Outcome.INCOMPLETE, "MySQL does not accept the panel's new password after the change (" + f + ")");
        if (old != null) {
            PendingDbPassword.Answer o = probe.ask(old);
            if (o != PendingDbPassword.Answer.REJECTED)
                return new Result(Outcome.INCOMPLETE, "MySQL still answers " + o + " to the previous password");
        }
        state.set(DONE + Instant.now().truncatedTo(ChronoUnit.SECONDS));
        return new Result(ok, "on " + user + "@" + local.stream().map(Account::host).toList()
                + (others.isEmpty() ? "" : "; accounts of the same user for other hosts not touched: " + others));
    }

    /** Every account changed again to the old one alone; then the new one and the state are removed. */
    private static Result rollBack(PendingDbPassword.Store store, Accounts db, State state, String user, List<Account> changed,
                                   String old, String why) {
        if (!backToOld(db, changed, user, old))
            return new Result(Outcome.INCOMPLETE, why + "; and putting MySQL back failed: the panel keeps working with its"
                    + " password (MySQL accepts it), the rest is decided at the next start");
        store.setPending("");
        state.set("");
        return new Result(Outcome.ROLLED_BACK, why + ": MySQL is back as it was, retried at the next start");
    }

    private static boolean backToOld(Accounts db, List<Account> accounts, String user, String old) {
        boolean ok = true;
        for (Account a : accounts) ok &= db.setPrimary(a.host(), user, old) && db.discard(a.host(), user);
        return ok;
    }

    // ===================== The production server =====================

    /** Where the webmail, Postfix and Dovecot write how they log in to MySQL. */
    static final List<Path> SERVICE_DIRS = List.of(Path.of("/usr/local/etc/postfix"), Path.of("/usr/local/etc/dovecot"),
            Path.of(RoundcubeDbUser.ROUNDCUBE_DIR, "config"), Path.of("/usr/local/etc/mail"));
    /**
     * The copies left by the per-component scripts: /usr/local/etc/mail/mysql_password (FullMailStackScript, from
     * which DovecotConfig re-reads it if it does not receive it) and /usr/local/etc/daemoxcp-mail/mysql.json
     * (MySQLMailScript; formerly /usr/local/etc/mailpanel, moved by ProductRename). If they have the old one they
     * receive the new one; if they have something else they stay as they are.
     */
    static final List<Path> COPIES = List.of(Path.of("/usr/local/etc/mail/mysql_password"),
            Path.of("/usr/local/etc/daemoxcp-mail/mysql.json"));

    static final long MAX_FILE = 2L * 1024 * 1024;

    /**
     * A backup-copy name, which no service reads (.bak, .orig, .old, ~, .sample, .save, a date at the end, the
     * panel's temporary file): with the old one inside it does not block, because after the change it opens
     * nothing any more.
     */
    static boolean backupName(String name) {
        return name.endsWith(".bak") || name.endsWith(".orig") || name.endsWith(".old") || name.endsWith("~")
                || name.endsWith(".sample") || name.endsWith(".save") || name.endsWith(TEMP_SUFFIX)
                || LegacyNames.pairs("tempSuffixes").stream().anyMatch(p -> name.endsWith(p[0]))
                || name.matches(".*[.-][0-9]{8,}$");
    }

    /** The temporary file the panel writes next to the real one before renaming it into its place. */
    static final String TEMP_SUFFIX = ".daemoxcp-mail.tmp";

    /**
     * The files under dirs (up to three levels, without following links) that contain the password, except the
     * copies and the backup-copy names.
     */
    static List<String> usersOf(List<Path> dirs, List<Path> copies, String password) {
        List<String> out = new ArrayList<>();
        byte[] needle = password.getBytes(StandardCharsets.UTF_8);
        for (Path dir : dirs) {
            if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) continue;
            try (Stream<Path> s = Files.walk(dir, 3)) {
                for (Path f : (Iterable<Path>) s::iterator) {
                    if (copies.contains(f) || !Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)
                            || backupName(f.getFileName().toString())) continue;
                    try {
                        if (Files.size(f) > MAX_FILE) continue;
                        if (contains(Files.readAllBytes(f), needle)) out.add(f.toString());
                    } catch (IOException e) {
                        out.add(f + " (cannot be read)");
                    }
                }
            } catch (IOException | RuntimeException e) {
                out.add(dir + " (cannot be read)");
            }
        }
        return out;
    }

    static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return true;
        }
        return false;
    }

    /** The copies with the old one rewritten with the new one, same owner and permissions; those not rewritten. */
    static List<String> rewriteCopies(List<Path> copies, String old, String fresh) {
        List<String> left = new ArrayList<>();
        for (Path f : copies) {
            try {
                if (!Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) continue;
                String text = Files.readString(f, StandardCharsets.UTF_8);
                if (!text.contains(old)) continue;
                RoundcubeDbUser.write(f, text.replace(old, fresh), RoundcubeDbUser.FileState.of(f, text).withoutOthers());
            } catch (IOException | RuntimeException e) {
                left.add(f + " (" + e.getClass().getSimpleName() + ")");
            }
        }
        return left;
    }

    /** MySQL's error code, never the message: in an ALTER USER it might repeat the password. */
    static String errorCode(Shell.Result r) {
        String o = r == null ? "" : r.outputTrim();
        if (o.startsWith("ERROR ")) {
            int sp = o.indexOf(' ', 6);
            return "MySQL error " + (sp > 0 ? o.substring(6, sp) : "?");
        }
        return r != null && r.timedOut() ? "timed out" : "failed";
    }

    static Accounts mysqlAccounts() {
        return new Accounts() {
            @Override public List<Account> list(String user) {
                Shell.Result r = MysqlRoot.rootJdbc(null, SqlCatalog.PDP_ACCOUNTS, user);
                if (!r.success()) {
                    LOGGER.info("[PanelDbPassword] the accounts of " + user + " cannot be read: " + errorCode(r));
                    return null;
                }
                List<Account> out = new ArrayList<>();
                for (String line : r.output().split("\n")) {
                    if (line.isBlank()) continue;
                    String[] c = line.split("\t");
                    if (c.length != 2) return null;
                    out.add(new Account(c[0], "1".equals(c[1].trim())));
                }
                return out;
            }
            @Override public boolean retain(String host, String user, String password) {
                return done("RETAIN", host, MysqlRoot.rootJdbc(null, SqlCatalog.PDP_RETAIN, user, host, password));
            }
            @Override public boolean setPrimary(String host, String user, String password) {
                return done("back to the previous password", host, MysqlRoot.rootJdbc(null, SqlCatalog.PDP_SET, user, host, password));
            }
            @Override public boolean discard(String host, String user) {
                return done("DISCARD OLD PASSWORD", host, MysqlRoot.rootJdbc(null, SqlCatalog.PDP_DISCARD, user, host));
            }
            private boolean done(String what, String host, Shell.Result r) {
                if (r.success()) return true;
                LOGGER.info("[PanelDbPassword] " + what + " on @" + host + ": " + errorCode(r));
                return false;
            }
        };
    }

    static State secretsState() {
        return new State() {
            @Override public String get() { return PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD_ROTATION); }
            @Override public void set(String value) { PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD_ROTATION, value); }
        };
    }

    /**
     * The installation has just given the panel a new password, which the webmail never had: there is nothing
     * to change.
     */
    public static void markFreshFromInstallation() {
        try {
            secretsState().set(DONE + Instant.now().truncatedTo(ChronoUnit.SECONDS) + " (installation)");
        } catch (RuntimeException e) {
            LOGGER.info("[PanelDbPassword] the state could not be written after the installation: " + e.getClass().getSimpleName());
        }
    }

    /** At the start of the root part, after RoundcubeDbUser and MailDbUsers. */
    public static Result ensureAtBoot() {
        try {
            if (Main.dbManager == null || !Main.mysqlAvailable) return new Result(Outcome.NOT_NOW, "MySQL not available");
            State state = secretsState();
            if (nz(state.get()).startsWith(DONE)) return new Result(Outcome.NOTHING, "");
            String refusal = PackageQueue.takeForLocks("db-password", I18n.tr("server.dbPassword.rotationTurn"));
            if (refusal != null) {
                LOGGER.info("[PanelDbPassword] not now, the package turn is held by " + PackageQueue.holderForLog());
                return new Result(Outcome.NOT_NOW, refusal);
            }
            Result r;
            try {
                String[] t = PendingDbPassword.mysqlTarget(Main.dbManager);
                r = run(PendingDbPassword.panelStore(Main.dbManager), PendingDbPassword.mysqlProbe(t[0], t[1], t[2]),
                        mysqlAccounts(), new Places() {
                            @Override public List<String> usersOf(String password) { return PanelDbPassword.usersOf(SERVICE_DIRS, COPIES, password); }
                            @Override public List<String> rewriteCopies(String old, String fresh) { return PanelDbPassword.rewriteCopies(COPIES, old, fresh); }
                        }, state, t[2], () -> PanelSecrets.newAlphanumericPassword(32));
            } finally {
                PackageQueue.release("db-password");
            }
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE, RESUMED -> LOGGER.info("[PanelDbPassword] DONE: the password of the panel's MySQL user changed"
                        + (r.outcome() == Outcome.RESUMED ? " (finished after an earlier start)" : "")
                        + ", the previous one no longer opens MySQL; " + r.detail());
                case NOT_NOW -> LOGGER.info("[PanelDbPassword] not now: " + r.detail());
                default -> LOGGER.warning("[PanelDbPassword] " + r.outcome() + ": " + r.detail());
            }
            return r;
        } catch (Throwable t) {
            LOGGER.warning("[PanelDbPassword] failed: " + t.getClass().getName());
            return new Result(Outcome.NOT_NOW, t.getClass().getName());
        }
    }
}
