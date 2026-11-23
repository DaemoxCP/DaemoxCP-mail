package org.daemoxcp.mail.system;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * One panel at a time. The root part of the separated panel opens no ports: a second start did not find the port
 * taken and took the place of the first one's web part, leaving two root parts alive, each with its scheduled jobs
 * (certificate renewal, DKIM rotation, report). Measured on the VM on 2026-11-17, clean install: the panel started
 * from the menu and then "service daemoxcp_mail start".
 *
 * The instance lock is a lock on a file, held by the process as long as it lives: the system releases it when the
 * process dies, even if killed, so an orphan lock never remains. The file contains the pid of whoever holds it,
 * only to say so. Whoever arrives second waits a little (the restart after the Java upgrade starts the new one only
 * when the old one has exited, but a moment of overlap must not stop it), then gives up without touching the one
 * that is running.
 */
public final class PanelInstanceLock {

    private static final Logger LOGGER = Logger.getLogger(PanelInstanceLock.class.getName());

    /** Next to the other data of the root part. */
    public static final Path FILE = Path.of(DataFolderRename.NEW, "panel-root.lock");

    private static FileChannel channel;
    private static FileLock lock;

    private PanelInstanceLock() {}

    /**
     * The panel's instance lock: null if it now belongs to this process, otherwise the pid of whoever holds it ("?"
     * if unknown).
     */
    public static String acquire(Duration wait) {
        return acquire(FILE, wait);
    }

    static synchronized String acquire(Path file, Duration wait) {
        if (lock != null && lock.isValid()) return null;
        FileChannel ch = null;
        try {
            Files.createDirectories(file.getParent());
            ch = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE);
            long end = System.nanoTime() + wait.toNanos();
            while (true) {
                FileLock l;
                try {
                    l = ch.tryLock();
                } catch (OverlappingFileLockException e) {
                    l = null;
                }
                if (l != null) {
                    ch.truncate(0);
                    ch.write(ByteBuffer.wrap((ProcessHandle.current().pid() + "\n").getBytes(StandardCharsets.US_ASCII)), 0);
                    ch.force(false);
                    channel = ch;
                    lock = l;
                    return null;
                }
                if (System.nanoTime() >= end) break;
                Thread.sleep(500);
            }
            String holder = Files.readString(file, StandardCharsets.US_ASCII).trim();
            ch.close();
            return holder.matches("[0-9]{1,10}") ? holder : "?";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            closeQuietly(ch);
            return "?";
        } catch (Exception e) {
            // A lock that cannot even be opened must not keep the panel off: we say so and go on.
            LOGGER.warning("[PanelInstanceLock] cannot use " + file + ": " + e.getMessage() + " (started without the check)");
            closeQuietly(ch);
            return null;
        }
    }

    /** Only for the tests: releases the lock (on exit the system releases it anyway). */
    static synchronized void release() {
        try {
            if (lock != null) lock.release();
        } catch (Exception ignored) { }
        closeQuietly(channel);
        lock = null;
        channel = null;
    }

    private static void closeQuietly(FileChannel ch) {
        try {
            if (ch != null) ch.close();
        } catch (Exception ignored) { }
    }
}
