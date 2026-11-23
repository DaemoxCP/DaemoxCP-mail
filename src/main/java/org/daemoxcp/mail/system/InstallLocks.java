package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The full installation on a server where the panel has already started: the locked packages
 * are unlocked first, with the list saved, and locked again at the end, even if it fails.
 *
 * Why it exists: measured on 2026-11-05 on the FreeBSD 15.1 VM (finding 126). At startup the
 * panel locks the packages of the mail stack with pkg lock (39 on that machine,
 * UpdateManager.applyLockPolicy). The reinstallation from the menu launched the script without
 * touching them: phase 1 stopped dovecot, rspamd, clamav, redis, nginx and php-fpm and deleted
 * their configurations, phase 2 stopped on "mysql84-server-8.4.11_4 is locked and may not be
 * modified", the script exited 1 and mail stayed down (dovecot and nginx would not even restart
 * by hand, without a configuration). Launched again after pkg unlock -a -y, it succeeded.
 *
 * The unlocking follows the rules of package jobs (PackageQueue): the package turn before
 * anything else, even against another panel process; the list on disk BEFORE unlocking, so that
 * if the process dies halfway the next startup locks them again; and if something goes wrong
 * before the script, everything is put back as it was and nothing is stopped. ALL the locked
 * packages are unlocked, not only those of the stack: pkg install may need to upgrade a
 * dependency too, and a locked dependency stops phase 2 in the same way. At the end exactly
 * that list is locked again, that is the previous state, including locks set by hand.
 */
public final class InstallLocks {

    private static final Logger LOGGER = Logger.getLogger(InstallLocks.class.getName());

    private InstallLocks() {}

    /** The prefix of the full reinstallation's turn, written in the job's record (turnId). */
    public static final String REINSTALL_TURN_PREFIX = "reinstall-";

    /** The pkg commands needed here. In tests a fake one, for the faults that the real pkg does not produce. */
    interface Pkg {
        /** The locked packages, one name-version per line ("" if none), or null if pkg does not answer. */
        String lockList();
        boolean unlock(String name);
        boolean lock(String name);
        boolean installed(String name);
    }

    /**
     * Reading the locked packages is "pkg query -e '%k = 1' '%n-%v'", not "pkg lock -l -q".
     * Measured on the VM on 2026-11-05 (pkg 2.8.4, on a copy of the database): when there is
     * no locked package, "pkg lock -l -q" exits with 1 and writes nothing, that is like an
     * error; the query exits 0 with the list or empty, and 1 only with a broken database. With
     * lock -l, on a server without locks (a clean install) the reinstallation would have
     * refused, saying that pkg does not answer.
     */
    static Pkg real() {
        return new Pkg() {
            public String lockList() {
                Shell.Result r = Shell.run(Duration.ofSeconds(60), "pkg", "query", "-e", "%k = 1", "%n-%v");
                return r.success() ? r.outputTrim() : null;
            }
            public boolean unlock(String name) { return valid(name) && Shell.run(Duration.ofSeconds(30), "pkg", "unlock", "-y", name).success(); }
            public boolean lock(String name) { return valid(name) && Shell.run(Duration.ofSeconds(30), "pkg", "lock", "-y", name).success(); }
            public boolean installed(String name) { return valid(name) && Shell.run(Duration.ofSeconds(15), "pkg", "info", "-e", name).success(); }
            private boolean valid(String name) { return UpdateManager.isValidName(name); }
        };
    }

    /**
     * The turn taken and the unlocked packages. It is always closed with {@link #finish}: that is
     * where the packages are locked again and the turn is released.
     */
    public static final class Held {
        final String turnId;
        final List<String> unlocked;
        private boolean finished;

        Held(String turnId, List<String> unlocked) {
            this.turnId = turnId;
            this.unlocked = List.copyOf(unlocked);
        }

        /** The unlocked packages, to lock again at the end. */
        public List<String> unlocked() { return unlocked; }
    }

    /**
     * The outcome of the preparation: either the turn taken ({@code held} not null, and {@code report}
     * says what was unlocked), or the refusal ({@code refusal} not null): in that case nothing was
     * changed, or it was put back as it was, and the script must not start.
     */
    public record Start(Held held, String refusal, String report) {}

    /** Takes the turn and unlocks the locked packages, before the script stops anything. */
    public static Start prepare(String description) {
        return prepare(description, real(), () -> null);
    }

    /**
     * Like {@link #prepare(String)}, with a step in the middle: {@code onTurn} runs with the turn already
     * taken and BEFORE any unlocking. It is the place for the way back (PackageWayBack): a boot
     * environment made here has the locked packages as they were and no open unlock list,
     * so starting again from there is starting again from the previous server. If {@code onTurn}
     * returns a reason, nothing is unlocked, the turn is released and the reason is the refusal.
     */
    public static Start prepare(String description, java.util.function.Supplier<String> onTurn) {
        return prepare(description, real(), onTurn);
    }

    static Start prepare(String description, Pkg pkg) {
        return prepare(description, pkg, () -> null);
    }

    static Start prepare(String description, Pkg pkg, java.util.function.Supplier<String> onTurn) {
        // "reinstall-": it is recognised by the notice of an interrupted job (PackageRecovery), which for the
        // reinstallation also says that mail may be down and where the way back is.
        // "install-" is already used by the installation of a package from the web page.
        String id = REINSTALL_TURN_PREFIX + System.nanoTime();
        // take, not takeForLocks: with the list of an interrupted job on disk the packages
        // might already be unlocked, and a new list could not even be written.
        String refusal = PackageQueue.take(id, description);
        if (refusal != null) return new Start(null, refusal, "");
        String notNow;
        try {
            notNow = onTurn.get();
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "The step before the unlock failed", e);
            notNow = String.valueOf(e.getMessage());
        }
        if (notNow != null) {
            PackageQueue.release(id);
            return new Start(null, notNow, "");
        }
        boolean listWritten = false;
        List<String> locked = List.of();
        try {
            String before = pkg.lockList();
            if (before == null) {
                PackageQueue.release(id);
                return new Start(null, I18n.tr("server.reinstall.cannotRead"), "");
            }
            locked = new ArrayList<>(UpdateManager.lockedNames(before));
            if (locked.isEmpty()) return new Start(new Held(id, locked), null, I18n.tr("server.reinstall.noLocks"));

            // First the list on disk, then the unlocking: if the list cannot be written, nothing is unlocked.
            String stateError = PackageQueue.writeState(locked);
            if (stateError != null) {
                PackageQueue.release(id);
                return new Start(null, I18n.tr("server.reinstall.noList", java.util.Map.of("err", stateError)), "");
            }
            listWritten = true;
            for (String n : locked) pkg.unlock(n);

            // The output of pkg unlock is not enough: the locks are read again. A package left locked
            // would stop phase 2 with the services already stopped, that is exactly the defect to avoid.
            String after = pkg.lockList();
            Set<String> still = after == null ? new TreeSet<>(locked) : stillAmong(locked, after);
            if (!still.isEmpty()) {
                String back = relock(locked, pkg);
                PackageQueue.release(id);
                return new Start(null, I18n.tr("server.reinstall.unlockFailed", java.util.Map.of(
                        "list", String.join(", ", still), "back", back)), "");
            }
            return new Start(new Held(id, locked), null, I18n.tr("server.reinstall.unlocked", java.util.Map.of(
                    "n", String.valueOf(locked.size()), "file", String.valueOf(PackageQueue.list))));
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Preparing the installation failed", e);
            String back = "";
            try { if (listWritten) back = " " + relock(locked, pkg); }
            catch (RuntimeException x) { LOGGER.log(Level.WARNING, "Locking the packages again failed", x); }
            finally { PackageQueue.release(id); }
            return new Start(null, I18n.tr("server.reinstall.noList", java.util.Map.of("err", String.valueOf(e))) + back, "");
        }
    }

    /**
     * Locks again the packages unlocked by {@link #prepare}, brings the lock tracking back in line
     * (the note and the annotations: reinstalling a package deletes its annotation) and releases
     * the turn. To be called in a finally. Does not throw: returns what happened.
     */
    public static String finish(Held held) {
        return finish(held, real(), true);
    }

    static String finish(Held held, Pkg pkg, boolean refreshTrace) {
        if (held == null || held.finished) return "";
        held.finished = true;
        try {
            return held.unlocked.isEmpty() ? "" : relock(held.unlocked, pkg);
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Locking the packages again failed", e);
            return I18n.tr("server.reinstall.relockUnknown", java.util.Map.of("file", String.valueOf(PackageQueue.list)));
        } finally {
            if (refreshTrace) UpdateManager.refreshLockTrace();
            PackageQueue.release(held.turnId);
        }
    }

    /**
     * Locks 'names' again, then re-reads the locks and closes the list on disk only if every
     * package still installed is locked again. One that the installation removed cannot be
     * locked, and does not keep the list open: the same criterion as the recovery at startup.
     */
    static String relock(List<String> names, Pkg pkg) {
        List<String> gone = new ArrayList<>(), kept = new ArrayList<>();
        for (String n : names) {
            if (!pkg.installed(n)) { gone.add(n); continue; }
            kept.add(n);
            pkg.lock(n);
        }
        String after = pkg.lockList();
        if (after == null)
            return I18n.tr("server.reinstall.relockUnknown", java.util.Map.of("file", String.valueOf(PackageQueue.list)));
        Set<String> nowLocked = UpdateManager.lockedNames(after);
        List<String> notLocked = new ArrayList<>();
        for (String n : kept) if (!nowLocked.contains(n)) notLocked.add(n);
        if (!notLocked.isEmpty())
            return I18n.tr("server.reinstall.relockFailed", java.util.Map.of(
                    "list", String.join(", ", notLocked), "file", String.valueOf(PackageQueue.list)));
        PackageQueue.deleteState();
        return gone.isEmpty()
                ? I18n.tr("server.reinstall.relocked", java.util.Map.of("n", String.valueOf(kept.size())))
                : I18n.tr("server.reinstall.relockedGone", java.util.Map.of(
                        "n", String.valueOf(kept.size()), "list", String.join(", ", gone)));
    }

    /** Which of 'names' still show up as locked in the list of locked packages. */
    private static Set<String> stillAmong(List<String> names, String lockOutput) {
        Set<String> now = UpdateManager.lockedNames(lockOutput), r = new TreeSet<>();
        for (String n : names) if (now.contains(n)) r.add(n);
        return r;
    }
}
