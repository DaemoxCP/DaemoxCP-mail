package org.daemoxcp.mail.system;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The password of the panel's MySQL user changed once (reperto 232), against a fake MySQL that keeps a primary and a
 * secondary password per account as MySQL 8 does (RETAIN CURRENT PASSWORD, DISCARD OLD PASSWORD; a client on
 * 127.0.0.1 lands on the localhost account), and the real PendingDbPassword.settle for the start after a crash.
 *
 *  1. the change: both local accounts get the new password and lose the old one, an account for another host is not
 *     touched and is named, the panel adopts the new one, nothing is left waiting, the old one is refused, the copies
 *     get the new one, the state says done; a second run does nothing;
 *  2. what does not start, changing nothing: done already, no password yet, an installation's password waiting,
 *     MySQL not answering, the password still written in a service's file, an account that already has a second
 *     password, a too short new password;
 *  3. what goes wrong before the panel adopts the new one (RETAIN refused on the second account, MySQL not accepting
 *     both after it): MySQL back to the old password alone, the panel on it, nothing waiting; the next run does it;
 *  4. DISCARD refused: the panel works with the new one, the state stays half way; the next run finishes (RESUMED);
 *  5. the process killed at three points (before any RETAIN, after the first, before the panel adopts): the next start
 *     (settle, then the run) always ends with one password, the new or a newer one, that the panel has;
 *  6. putting MySQL back failing: INCOMPLETE, and the panel still enters;
 *  7. the real file helpers: a service file with the password blocks, a backup name, a link and the copies do not;
 *     a copy with the old password gets the new one with its mode (minus others), one without it is untouched; the
 *     MySQL error is reduced to its code.
 * It calls nothing on the machine besides temporary files.
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.PanelDbPasswordTest
 */
public class PanelDbPasswordTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String USER = "daemoxcp_mail";
    static final String OLD = "OldPanelPassword0123456789";

    /** MySQL: per host the primary and the secondary password; the probe enters through localhost. */
    static final class Mysql implements PanelDbPassword.Accounts, PendingDbPassword.Probe {
        final Map<String, String[]> accounts = new LinkedHashMap<>();
        boolean down, noAnswer;
        String refuseRetainOn, refuseSetOn;
        boolean refuseDiscard;
        String killRetainOn;
        String noAnswerFor;

        Mysql account(String host, String primary, String secondary) { accounts.put(host, new String[]{primary, secondary}); return this; }
        String primary(String host) { return accounts.get(host)[0]; }
        String secondary(String host) { return accounts.get(host)[1]; }

        @Override public List<PanelDbPassword.Account> list(String user) {
            if (down) return null;
            List<PanelDbPassword.Account> out = new ArrayList<>();
            accounts.keySet().stream().sorted().forEach(h -> out.add(new PanelDbPassword.Account(h, accounts.get(h)[1] != null)));
            return out;
        }
        @Override public boolean retain(String host, String user, String password) {
            if (host.equals(killRetainOn)) throw new RuntimeException("killed before RETAIN on " + host);
            if (host.equals(refuseRetainOn)) return false;
            String[] a = accounts.get(host);
            a[1] = a[0];
            a[0] = password;
            return true;
        }
        @Override public boolean setPrimary(String host, String user, String password) {
            if (host.equals(refuseSetOn)) return false;
            accounts.get(host)[0] = password;
            return true;
        }
        @Override public boolean discard(String host, String user) {
            if (refuseDiscard) return false;
            accounts.get(host)[1] = null;
            return true;
        }
        @Override public PendingDbPassword.Answer ask(String password) {
            if (noAnswer || (password != null && password.equals(noAnswerFor))) return PendingDbPassword.Answer.NO_ANSWER;
            String[] a = accounts.get("localhost");
            return password != null && (password.equals(a[0]) || password.equals(a[1]))
                    ? PendingDbPassword.Answer.ACCEPTED : PendingDbPassword.Answer.REJECTED;
        }
    }

    static final class Store implements PendingDbPassword.Store {
        String current = OLD, pending = "";
        boolean killOnAdopt;
        @Override public String current() { return current; }
        @Override public void adopt(String password) {
            if (killOnAdopt) throw new RuntimeException("killed before the panel adopts");
            current = password;
        }
        @Override public String pending() { return pending; }
        @Override public void setPending(String password) { pending = password; }
    }

    static final class State implements PanelDbPassword.State {
        String value = "";
        @Override public String get() { return value; }
        @Override public void set(String v) { value = v; }
    }

    static final class Places implements PanelDbPassword.Places {
        List<String> users = List.of();
        final List<String[]> rewritten = new ArrayList<>();
        @Override public List<String> usersOf(String password) { return users; }
        @Override public List<String> rewriteCopies(String old, String fresh) { rewritten.add(new String[]{old, fresh}); return List.of(); }
    }

    static int n = 0;
    static final Supplier<String> NEW = () -> "NewPanelPassword" + String.format("%016d", ++n);

    static Mysql standard() {
        return new Mysql().account("localhost", OLD, null).account("127.0.0.1", OLD, null).account("%", "SomethingElse", null);
    }

    static PanelDbPassword.Result run(Store s, Mysql m, Places p, State st) {
        return PanelDbPassword.run(s, m, m, p, st, USER, NEW);
    }

    /** One password on both local accounts, the panel's, no second one, and the old one refused. */
    static boolean settledOn(Mysql m, Store s, String password) {
        return password.equals(s.current) && s.pending.isEmpty()
                && password.equals(m.primary("localhost")) && password.equals(m.primary("127.0.0.1"))
                && m.secondary("localhost") == null && m.secondary("127.0.0.1") == null;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The change");
        Mysql m = standard();
        Store s = new Store();
        State st = new State();
        Places p = new Places();
        PanelDbPassword.Result r = run(s, m, p, st);
        String fresh = s.current;
        check("DONE (" + r.detail() + ")", r.outcome() == PanelDbPassword.Outcome.DONE);
        check("  the panel has a new password, 32 characters here, nothing waiting", !OLD.equals(fresh) && fresh.length() >= 24 && s.pending.isEmpty());
        check("  both local accounts on it, no second password", settledOn(m, s, fresh));
        check("  the old one refused, the new one accepted", m.ask(OLD) == PendingDbPassword.Answer.REJECTED && m.ask(fresh) == PendingDbPassword.Answer.ACCEPTED);
        check("  the account for another host untouched, and named", "SomethingElse".equals(m.primary("%")) && m.secondary("%") == null
                && r.detail().contains("[%]"));
        check("  the copies asked to go from the old to the new", p.rewritten.size() == 1 && OLD.equals(p.rewritten.get(0)[0])
                && fresh.equals(p.rewritten.get(0)[1]));
        check("  the state says done, and holds no password", st.value.startsWith(PanelDbPassword.DONE) && !st.value.contains(OLD)
                && !st.value.contains(fresh));
        r = run(s, m, p, st);
        check("a second run: NOTHING, nothing changed", r.outcome() == PanelDbPassword.Outcome.NOTHING && settledOn(m, s, fresh)
                && p.rewritten.size() == 1);

        System.out.println("\n== 2. What does not start");
        Object[][] refusals = {
                {"done already", PanelDbPassword.Outcome.NOTHING},
                {"no password yet", PanelDbPassword.Outcome.NOTHING},
                {"an installation's password waiting", PanelDbPassword.Outcome.NOT_NOW},
                {"MySQL not answering as root", PanelDbPassword.Outcome.NOT_NOW},
                {"MySQL not answering to the panel's password", PanelDbPassword.Outcome.NOT_NOW},
                {"the password in a service's file", PanelDbPassword.Outcome.LEFT},
                {"a second password already there", PanelDbPassword.Outcome.LEFT},
        };
        for (Object[] c : refusals) {
            String what = (String) c[0];
            Mysql mm = standard();
            Store ss = new Store();
            State tt = new State();
            Places pp = new Places();
            switch (what) {
                case "done already" -> tt.value = PanelDbPassword.DONE + "2026-11-15T10:00:00Z (installation)";
                case "no password yet" -> ss.current = "";
                case "an installation's password waiting" -> ss.pending = "InstallationPassword012345";
                case "MySQL not answering as root" -> mm.down = true;
                case "MySQL not answering to the panel's password" -> mm.noAnswer = true;
                case "the password in a service's file" -> pp.users = List.of("/usr/local/etc/postfix/mysql-virtual-domains.cf");
                case "a second password already there" -> mm.accounts.get("localhost")[1] = "AdminsOwnSecond";
                default -> { }
            }
            String stateBefore = tt.value, pendingBefore = ss.pending, secondBefore = mm.secondary("localhost");
            PanelDbPassword.Result x = run(ss, mm, pp, tt);
            boolean untouched = OLD.equals(mm.primary("localhost")) && OLD.equals(mm.primary("127.0.0.1"))
                    && java.util.Objects.equals(secondBefore, mm.secondary("localhost")) && mm.secondary("127.0.0.1") == null
                    && pendingBefore.equals(ss.pending) && stateBefore.equals(tt.value) && pp.rewritten.isEmpty();
            check(what + ": " + c[1] + ", nothing changed (" + x.detail() + ")", x.outcome() == c[1] && untouched);
        }
        Mysql mm = standard();
        Store ss = new Store();
        PanelDbPassword.Result shortOne = PanelDbPassword.run(ss, mm, mm, new Places(), new State(), USER, () -> "short");
        check("a too short new password: NOT_NOW, nothing changed", shortOne.outcome() == PanelDbPassword.Outcome.NOT_NOW
                && OLD.equals(mm.primary("localhost")) && ss.pending.isEmpty());

        System.out.println("\n== 3. Wrong before the panel adopts: back as it was, then done");
        for (String fault : new String[]{"RETAIN refused on localhost", "MySQL not answering to the new one"}) {
            Mysql f = standard();
            Store fs = new Store();
            State ft = new State();
            Places fp = new Places();
            if (fault.startsWith("RETAIN")) f.refuseRetainOn = "localhost";
            else f.noAnswerFor = "NewPanelPassword" + String.format("%016d", n + 1);
            PanelDbPassword.Result x = run(fs, f, fp, ft);
            check(fault + ": ROLLED_BACK (" + x.detail() + ")", x.outcome() == PanelDbPassword.Outcome.ROLLED_BACK);
            check("  MySQL on the old password alone, the panel on it, nothing waiting, no state", settledOn(f, fs, OLD) && ft.value.isEmpty()
                    && fp.rewritten.isEmpty());
            f.refuseRetainOn = null;
            f.noAnswerFor = null;
            x = run(fs, f, fp, ft);
            check("  the next run: DONE", x.outcome() == PanelDbPassword.Outcome.DONE && settledOn(f, fs, fs.current) && !OLD.equals(fs.current)
                    && f.ask(OLD) == PendingDbPassword.Answer.REJECTED);
        }

        System.out.println("\n== 4. DISCARD refused: finished at the next run");
        Mysql d = standard();
        Store ds = new Store();
        State dt = new State();
        d.refuseDiscard = true;
        PanelDbPassword.Result x = run(ds, d, new Places(), dt);
        String dFresh = ds.current;
        check("INCOMPLETE (" + x.detail() + ")", x.outcome() == PanelDbPassword.Outcome.INCOMPLETE);
        check("  the panel on the new one, MySQL takes both, the state half way", !OLD.equals(dFresh)
                && d.ask(dFresh) == PendingDbPassword.Answer.ACCEPTED && d.ask(OLD) == PendingDbPassword.Answer.ACCEPTED
                && dt.value.startsWith(PanelDbPassword.RETAINED) && !dt.value.contains(OLD));
        d.refuseDiscard = false;
        x = run(ds, d, new Places(), dt);
        check("  the next run: RESUMED, the old one refused, done", x.outcome() == PanelDbPassword.Outcome.RESUMED
                && settledOn(d, ds, dFresh) && d.ask(OLD) == PendingDbPassword.Answer.REJECTED && dt.value.startsWith(PanelDbPassword.DONE));

        System.out.println("\n== 5. Killed half way: the next start ends with one password, the panel's");
        for (String where : new String[]{"before any RETAIN", "after RETAIN on the first account", "before the panel adopts"}) {
            Mysql k = standard();
            Store ks = new Store();
            State kt = new State();
            switch (where) {
                case "before any RETAIN" -> k.killRetainOn = "127.0.0.1";
                case "after RETAIN on the first account" -> k.killRetainOn = "localhost";
                default -> ks.killOnAdopt = true;
            }
            boolean died = false;
            try { run(ks, k, new Places(), kt); } catch (RuntimeException e) { died = true; }
            check(where + ": the process dies", died);
            k.killRetainOn = null;
            ks.killOnAdopt = false;
            // The next start: settleAtStartup first (Main), then the boot step.
            PendingDbPassword.Result settled = PendingDbPassword.settle(ks, k, USER);
            check("  the start decides the waiting password: " + settled.outcome(), settled.outcome() == PendingDbPassword.Outcome.NEW_ADOPTED
                    || settled.outcome() == PendingDbPassword.Outcome.OLD_KEPT);
            x = run(ks, k, new Places(), kt);
            check("  then " + x.outcome() + ": one password on both accounts, the panel's, not the old one (" + x.detail() + ")",
                    (x.outcome() == PanelDbPassword.Outcome.DONE || x.outcome() == PanelDbPassword.Outcome.RESUMED)
                            && settledOn(k, ks, ks.current) && !OLD.equals(ks.current) && k.ask(OLD) == PendingDbPassword.Answer.REJECTED
                            && kt.value.startsWith(PanelDbPassword.DONE));
        }

        System.out.println("\n== 6. Putting MySQL back fails");
        Mysql b = standard();
        Store bs = new Store();
        b.refuseRetainOn = "localhost";
        b.refuseSetOn = "127.0.0.1";
        x = run(bs, b, new Places(), new State());
        check("INCOMPLETE, and the panel still enters with its password (" + x.detail() + ")",
                x.outcome() == PanelDbPassword.Outcome.INCOMPLETE && OLD.equals(bs.current) && b.ask(OLD) == PendingDbPassword.Answer.ACCEPTED);

        System.out.println("\n== 7. The real file helpers");
        Path base = Files.createTempDirectory("pdp-test");
        try {
            Path postfix = Files.createDirectories(base.resolve("postfix"));
            Path dovecot = Files.createDirectories(base.resolve("dovecot/conf.d"));
            Path mail = Files.createDirectories(base.resolve("mail"));
            Files.writeString(postfix.resolve("mysql-virtual-domains.cf"), "user = postfix\npassword = Other\n");
            Path used = Files.writeString(dovecot.resolve("auth-sql.conf.ext"), "connect = user=daemoxcp_mail password=" + OLD + "\n");
            Files.writeString(postfix.resolve("mysql-virtual-domains.cf.bak"), "password = " + OLD + "\n");
            Files.writeString(postfix.resolve("main.cf-20261101"), "password = " + OLD + "\n");
            Path outside = Files.writeString(base.resolve("outside.cf"), "password = " + OLD + "\n");
            Files.createSymbolicLink(postfix.resolve("linked.cf"), outside);
            Path copy = Files.writeString(mail.resolve("mysql_password"), OLD + "\n");
            Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("rw-r--r--"));
            Path other = Files.writeString(mail.resolve("mysql.json"), "{\"password\": \"SomethingElse\"}\n");
            List<Path> dirs = List.of(postfix, base.resolve("dovecot"), mail, base.resolve("missing"));
            List<Path> copies = List.of(copy, other);
            List<String> users = PanelDbPassword.usersOf(dirs, copies, OLD);
            check("usersOf: the Dovecot file, nothing else (" + users + ")", users.equals(List.of(used.toString())));
            check("  nothing for a password nobody has", PanelDbPassword.usersOf(dirs, copies, "NobodyHasThisOne0123456").isEmpty());
            Files.delete(used);
            check("  without it: nothing (the .bak, the dated copy, the link and the copies do not count)",
                    PanelDbPassword.usersOf(dirs, copies, OLD).isEmpty());
            List<String> left = PanelDbPassword.rewriteCopies(copies, OLD, "NewOne0123456789012345678");
            check("rewriteCopies: nothing left (" + left + ")", left.isEmpty());
            check("  the copy has the new one", Files.readString(copy, StandardCharsets.UTF_8).equals("NewOne0123456789012345678\n"));
            check("  with its mode, others taken away", PosixFilePermissions.toString(Files.getPosixFilePermissions(copy)).equals("rw-r-----"));
            check("  the other copy untouched", Files.readString(other, StandardCharsets.UTF_8).equals("{\"password\": \"SomethingElse\"}\n"));
            check("backupName: .bak .orig .old ~ .sample .save, a date; not .cf or .conf.ext",
                    PanelDbPassword.backupName("a.cf.bak") && PanelDbPassword.backupName("a.orig") && PanelDbPassword.backupName("a.old")
                            && PanelDbPassword.backupName("a.cf~") && PanelDbPassword.backupName("a.sample") && PanelDbPassword.backupName("a.save")
                            && PanelDbPassword.backupName("main.cf-20261101") && !PanelDbPassword.backupName("mysql-virtual-domains.cf")
                            && !PanelDbPassword.backupName("auth-sql.conf.ext"));
        } finally {
            try (var w = Files.walk(base)) { w.sorted(java.util.Comparator.reverseOrder()).forEach(f -> f.toFile().delete()); }
        }
        String code = PanelDbPassword.errorCode(new org.daemoxcp.mail.util.Shell.Result(1,
                "ERROR 1064 (42000): You have an error in your SQL syntax near 'SecretValue' RETAIN", false, List.of()));
        check("errorCode: only the code (" + code + ")", code.equals("MySQL error 1064") && !code.contains("Secret"));
        check("fingerprint: SHA-256, not the password", PanelDbPassword.fingerprint(OLD).length() == 64
                && !PanelDbPassword.fingerprint(OLD).contains(OLD) && PanelDbPassword.fingerprint(OLD).equals(PanelDbPassword.fingerprint(OLD)));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
