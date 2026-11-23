package org.daemoxcp.mail.system;

import java.nio.ByteBuffer;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One job at a time on the packages, and the list for locking them again really written before
 * unlocking them.
 *
 * Guided upgrade, maintenance, upgrade of the unlocked ones, Roundcube, the JVM, the Python
 * switch, the MySQL migration, the relinking of the libraries, the cleanup of the MySQL client,
 * the installation of the components, the locking and the removal of packages: all of them
 * change the packages or their locks, and two at once step on each other's toes. The second one
 * overwrote the first one's list on disk; the first one, when finishing, deleted it while the
 * second one still had unlocked packages; and an interruption at that moment left them unlocked
 * without the startup knowing it. A "pkg upgrade" of the unlocked ones, started while the
 * maintenance had removed Dovecot's lock, upgraded Dovecot too. And the plan computed by one is
 * no longer valid if the other changes the packages in the meantime.
 *
 * The turn is taken in the request, BEFORE starting the job: so before the checks, the plan and
 * any unlock. It is released when the job ends, whatever happens. Whoever finds it taken does
 * not start, and knows who holds it.
 *
 * The turn holds across PROCESSES, not only within this one. Until 2026-11-06 it was an
 * AtomicReference: measured on the VM, a second Java process took it while the first held it,
 * and every start of the jar (even the console menu open while the web panel upgrades) locked
 * again the packages of a running job and deleted its list, making its pkg upgrade fail
 * ("is locked and may not be modified"). Now whoever takes the turn also holds an fcntl lock on
 * TURN_LOCK_PATH: the system removes it by itself when the process dies, so an interrupted job
 * does not leave the turn taken forever.
 */
public final class PackageQueue {

    private static final Logger LOGGER = Logger.getLogger(PackageQueue.class.getName());

    private PackageQueue() {}

    /**
     * The list of the packages that a running job has unlocked. A job's finally does not run if
     * the process dies (panel restart, kill, JVM crash): this file is the only thing that
     * survives, and at startup the panel locks again what is written in it.
     */
    public static final String STATE_PATH = "/var/db/daemoxcp-mail-maintenance-locks";

    /** Where the list lives. It is a variable only so that the tests do not write in /var/db. */
    static Path list = Path.of(STATE_PATH);

    private record Turn(String id, String description, long start) {}

    private static final AtomicReference<Turn> IN_PROGRESS = new AtomicReference<>();

    /** The cross-process lock of the turn. Written inside is who holds it, to tell whoever finds it taken. */
    public static final String TURN_LOCK_PATH = "/var/db/daemoxcp-mail/package-turn.lock";

    /** Where the lock lives. It is a variable only so that the tests do not write in /var/db. */
    static Path turnLock = Path.of(TURN_LOCK_PATH);

    /**
     * The job that holds the turn, written on disk when it takes it and removed when it releases it: who it is,
     * when it started, from which process, and how packages and services were at the start. If the process dies
     * halfway it stays, and it is from here that the running panel understands what the job changed and
     * completes it (InterruptedJobRecovery): even a job that had unlocked nothing, and which therefore did not
     * leave the list. It sits next to the turn lock, so the tests that move the lock move it too.
     */
    static Path running() {
        return turnLock.resolveSibling("package-job-running.json");
    }

    /**
     * How packages and services were at the start of a job ({"inventory": {name: version}, "services": {name:
     * running}}): provided by UpdateManager, which knows how to ask the system for it. Empty until someone sets it.
     */
    static volatile java.util.function.Supplier<JSONObject> snapshot = JSONObject::new;

    /**
     * The channel and the lock of whoever holds the turn in THIS process. They are touched only by
     * whoever holds IN_PROGRESS: a second channel opened and closed on the same file, in the same
     * process, would remove the fcntl lock (it is the POSIX rule, the FileChannel documentation
     * recalls it too), so here only one is opened at a time.
     */
    private static FileChannel lockChannel;
    private static FileLock fileLock;

    /**
     * Takes the turn for the job 'id'. null if it took it; otherwise the reason why the job
     * cannot start, to be shown as it is.
     *
     * It does not take it even if on disk there is the list of a job that did not close: those
     * packages might still be unlocked, and a "pkg upgrade" or a "pkg install" would change
     * them as if nothing were wrong.
     */
    public static String take(String id, String description) {
        return take(id, description, true);
    }

    /**
     * Like take, but also with the list of an interrupted job on disk. Only for putting back or
     * removing locks: putting them back is precisely the remedy for that list.
     */
    public static String takeForLocks(String id, String description) {
        return take(id, description, false);
    }

    private static String take(String id, String description, boolean notWithOpenList) {
        Turn fresh = new Turn(id, description, System.currentTimeMillis());
        while (!IN_PROGRESS.compareAndSet(null, fresh)) {
            String holder = holder();
            if (holder != null) return busy(holder);
            // Released between the two steps: try again.
        }
        // Then the cross-process turn: another panel (or a console menu) may hold it.
        String other = takeFileLock(fresh);
        if (other != null) {
            IN_PROGRESS.compareAndSet(fresh, null);
            return other;
        }
        if (notWithOpenList && statePresent()) {
            release(id);
            // The Java upgrade's list is there by design while the script works: it is not a job that did not
            // finish, and restarting the panel would be the wrong advice (finding 210).
            if (jobRecord().optBoolean("expectsRestart")) return I18n.tr("server.turn.javaRunning");
            return I18n.tr("server.turn.openList", java.util.Map.of("file", String.valueOf(list)));
        }
        // A real job (not the restoring of the locks) leaves its trace as long as it holds the turn.
        if (notWithOpenList) writeRunning(fresh);
        return null;
    }

    private static void writeRunning(Turn t) {
        JSONObject r = new JSONObject()
                .put("id", t.id())
                .put("description", t.description())
                .put("startedUtc", java.time.Instant.ofEpochMilli(t.start()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
                .put("startedEpoch", t.start() / 1000)
                .put("pid", ProcessHandle.current().pid())
                .put("expectsRestart", false);
        try {
            JSONObject snap = snapshot.get();
            if (snap != null) for (String k : snap.keySet()) r.put(k, snap.get(k));
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Cannot take the snapshot of packages and services for " + t.id(), e);
        }
        writeJson(running(), r);
    }

    private static void writeJson(Path f, JSONObject r) {
        try {
            Files.createDirectories(f.getParent());
            Path tmp = f.resolveSibling(f.getFileName() + ".tmp");
            Files.writeString(tmp, r.toString(2) + "\n", StandardCharsets.UTF_8);
            Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + f, e);
        }
    }

    /**
     * Who holds the turn, for the log: the pid of whoever took the lock and, if it is theirs, the job id; in English
     * for everyone. The description stays out: it is in the panel's language and serves whoever reads the page, and
     * the logs are in English (EnglishLogsTest; seen on the VM on 2026-11-22, `aggiornamento di ...` ("upgrade
     * of ...") in the log of a panel in Italian).
     *
     * <p>Who holds the turn is told by the lock file, which only whoever has just taken it writes. Not so the job's
     * trace: that of a killed job stays on disk until someone completes it, and meanwhile someone else may have taken
     * the turn, for example the service guardian that puts the locks back. Seen on the VM on 2026-11-22 (test M4 of
     * UpdaterRobustnessE2ETest): the log said "job guid-..., pid 95770; a job is running there", that is the job
     * just killed, while the service held the turn. The job is named only if its trace belongs to that pid.
     */
    public static String holderForLog() {
        Turn t = IN_PROGRESS.get();
        if (t != null) return "job " + t.id() + " in this process";
        long pid = lockPid();
        if (pid <= 0) return "another panel process";
        JSONObject r = runningRecord();
        String id = r.optString("id", "");
        if (!id.isEmpty() && r.optLong("pid", 0) == pid) return "job " + id + ", pid " + pid;
        return "another panel process, pid " + pid;
    }

    private static final java.util.regex.Pattern LOCK_PID = java.util.regex.Pattern.compile("^pid ([0-9]{1,10}),");

    /** The pid written in the lock file by whoever took it last ("pid N, ...", takeFileLock); 0 if it cannot be read. */
    static long lockPid() {
        try {
            java.util.regex.Matcher m = LOCK_PID.matcher(new String(Files.readAllBytes(turnLock), StandardCharsets.UTF_8).trim());
            return m.find() ? Long.parseLong(m.group(1)) : 0;
        } catch (Exception e) {
            return 0;     // without the file we only say that it is another process
        }
    }

    /** The trace of the job that holds (or held) the turn, or an empty object if there is none. */
    public static JSONObject runningRecord() {
        try { return new JSONObject(Files.readString(running())); }
        catch (Exception e) { return new JSONObject(); }
    }

    /** Removes the trace: whoever completed an interrupted job, or the job itself when it releases the turn. */
    static void deleteRunning() {
        try { Files.deleteIfExists(running()); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot remove " + running(), e); }
    }

    /**
     * The cross-process lock, for the turn just taken in this process. null if taken; otherwise
     * the message for whoever finds it taken (or for whoever cannot even open the file: without the
     * lock we do not start, because a turn that does not hold across processes is the one that broke).
     */
    private static String takeFileLock(Turn t) {
        FileChannel c = null;
        try {
            Files.createDirectories(turnLock.getParent());
            c = FileChannel.open(turnLock, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
            FileLock l;
            try { l = c.tryLock(); }
            catch (OverlappingFileLockException e) { l = null; }   // does not happen: IN_PROGRESS comes first
            if (l == null) {
                String who = new String(Files.readAllBytes(turnLock), StandardCharsets.UTF_8).trim();
                c.close();
                return busy(I18n.tr("server.turn.otherProcess", java.util.Map.of("who", who.isEmpty() ? "?" : who)));
            }
            String who = "pid " + ProcessHandle.current().pid() + ", " + t.description()
                    + " (" + java.time.Instant.ofEpochMilli(t.start()).truncatedTo(java.time.temporal.ChronoUnit.SECONDS) + ")";
            c.truncate(0);
            c.write(ByteBuffer.wrap((who + "\n").getBytes(StandardCharsets.UTF_8)), 0);
            lockChannel = c;
            fileLock = l;
            return null;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot take the package turn lock " + turnLock, e);
            if (c != null) try { c.close(); } catch (Exception ignored) { }
            return I18n.tr("server.turn.lockFileError", java.util.Map.of("file", String.valueOf(turnLock), "err", org.daemoxcp.mail.util.ErrorText.detail("PackageQueue", e)));
        }
    }

    /** Releases the turn, but only if it belongs to 'id': a job cannot free another one's. */
    public static void release(String id) {
        Turn t = IN_PROGRESS.get();
        if (t == null || !t.id().equals(id)) return;
        // The job has finished (well or badly, but inside its finally): its trace is no longer needed.
        if (id.equals(runningRecord().optString("id"))) deleteRunning();
        // First the cross-process lock, then this process's turn: the other way round, another
        // thread could take the turn and find the file still locked by us.
        try {
            if (fileLock != null) fileLock.release();
            if (lockChannel != null) lockChannel.close();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot release the package turn lock " + turnLock, e);
        } finally {
            fileLock = null;
            lockChannel = null;
        }
        IN_PROGRESS.compareAndSet(t, null);
    }

    /** The id of the job that holds the turn now, or null if it is free (finding 206: the page follows it). */
    public static String holderId() {
        Turn t = IN_PROGRESS.get();
        return t == null ? null : t.id();
    }

    /** Who holds the turn now ("maintenance, running for 3 minutes"), or null if it is free. */
    public static String holder() {
        Turn t = IN_PROGRESS.get();
        if (t == null) return null;
        long min = (System.currentTimeMillis() - t.start()) / 60000;
        return t.description() + ", " + (min < 1 ? I18n.tr("server.turn.justStarted")
                : min == 1 ? I18n.tr("server.turn.running.one")
                : I18n.tr("server.turn.running.other", java.util.Map.of("n", String.valueOf(min))));
    }

    /**
     * While a job changes the packages, a plan computed now would see removed locks and
     * versions that are changing: null if it can be computed, otherwise the reason.
     */
    public static String planNotNow() {
        String holder = holder();
        return holder == null ? null
             : I18n.tr("server.turn.busyPlan", java.util.Map.of("who", String.valueOf(holder)));
    }

    /** The message for whoever finds the turn taken. */
    static String busy(String holder) {
        return I18n.tr("server.turn.busy", java.util.Map.of("who", String.valueOf(holder)));
    }

    /**
     * Starts in a thread the job that has ALREADY taken the turn 'id', and releases the turn when the
     * job ends, even with an error. If the thread does not start, it releases it immediately.
     */
    public static void start(String id, String name, Runnable work) {
        try {
            // The language of whoever requested the job follows the job into its thread (messages and logs)
            Thread t = new Thread(I18n.withCurrent(() -> {
                try { work.run(); }
                finally { release(id); }
            }), name);
            t.setDaemon(true);   // as before: a job does not keep alive a panel that is shutting down
            t.start();
        } catch (RuntimeException | Error e) {
            release(id);
            throw e;
        }
    }

    /**
     * Writes on disk the list of the packages about to be unlocked, BEFORE unlocking them, and
     * says whether it succeeded: null if the list is written and forced to disk, otherwise the reason.
     * If it is not null, the caller must NOT unlock anything.
     *
     * Before, a write error (disk full, /var/db not writable) ended in a warning and the job
     * unlocked anyway: if the process then died, the startup had no list from which to lock
     * again. The file is created only if it does not exist (CREATE_NEW, atomic): if it exists, it
     * is the list of an interrupted job that the startup could not close, and overwriting it
     * would lose precisely the packages to lock again.
     */
    public static String writeState(List<String> packages) {
        String error = writeState(list, packages);
        if (error == null) writeJobRecord(packages, false);
        return error;
    }

    /**
     * Like writeState, for a job that hands the packages to a script outside the panel and expects
     * to be restarted by it (the JVM upgrade): at the restart the list is there by design, and
     * must not be mistaken for an interrupted job.
     */
    public static String writeStateForRestart(List<String> packages) {
        String error = writeState(list, packages);
        if (error == null) {
            writeJobRecord(packages, true);
            // The turn's trace too: at the intended restart the process died by design, it was not interrupted.
            JSONObject r = runningRecord();
            if (!r.isEmpty()) writeJson(running(), r.put("expectsRestart", true));
        }
        return error;
    }

    /** Next to the list: which job wrote it, when, and from which process. */
    static Path jobRecordPath() {
        return list.resolveSibling(list.getFileName() + ".job.json");
    }

    /**
     * Who wrote the list, to tell at startup WHICH job was interrupted. If it cannot be written
     * nothing stops: the list is enough to lock again, this only serves to explain.
     */
    private static void writeJobRecord(List<String> packages, boolean expectsRestart) {
        Turn t = IN_PROGRESS.get();
        JSONObject r = new JSONObject()
                .put("description", t == null ? "" : t.description())
                .put("turnId", t == null ? "" : t.id())
                .put("startedUtc", java.time.Instant.ofEpochMilli(t == null ? System.currentTimeMillis() : t.start())
                        .truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
                .put("pid", ProcessHandle.current().pid())
                .put("expectsRestart", expectsRestart)
                .put("packages", new JSONArray(packages));
        try {
            Path tmp = jobRecordPath().resolveSibling(jobRecordPath().getFileName() + ".tmp");
            Files.writeString(tmp, r.toString(2) + "\n", StandardCharsets.UTF_8);
            Files.move(tmp, jobRecordPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + jobRecordPath(), e);
        }
    }

    /** The job that wrote the list, or an empty object if unknown (list from an older panel). */
    public static JSONObject jobRecord() {
        try { return new JSONObject(Files.readString(jobRecordPath())); }
        catch (Exception e) { return new JSONObject(); }
    }

    static String writeState(Path f, List<String> packages) {
        boolean created = false;
        try (FileChannel c = FileChannel.open(f, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            created = true;
            ByteBuffer b = ByteBuffer.wrap((String.join("\n", packages) + "\n").getBytes(StandardCharsets.US_ASCII));
            while (b.hasRemaining()) c.write(b);
            c.force(true);
            return null;
        } catch (FileAlreadyExistsException e) {
            return I18n.tr("server.turn.listExists", java.util.Map.of("file", String.valueOf(f)));
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + f, e);
            // A list written halfway must not remain: the startup would read it as real.
            if (created) {
                try { Files.deleteIfExists(f); }
                catch (Exception x) { LOGGER.log(Level.WARNING, "Cannot remove " + f, x); }
            }
            return I18n.tr("server.turn.cannotWrite", java.util.Map.of("file", String.valueOf(f), "err", String.valueOf(e)));
        }
    }

    /** Deletes the list. Only the job that wrote it does so, after locking everything again. */
    public static void deleteState() {
        try { Files.deleteIfExists(list); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot remove " + list, e); }
        try { Files.deleteIfExists(jobRecordPath()); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Cannot remove " + jobRecordPath(), e); }
    }

    /** Whether there is a list from an unfinished job. */
    public static boolean statePresent() {
        return Files.exists(list);
    }
}
