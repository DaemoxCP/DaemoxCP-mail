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
 * Un pannello alla volta. La parte root del pannello separato non apre porte: un secondo avvio non trovava la porta
 * occupata e prendeva il posto della parte web del primo, lasciando vive due parti root, ognuna coi suoi lavori
 * pianificati (rinnovo dei certificati, rotazione DKIM, rapporto). Misurato sulla VM il 17/11/2026, installazione da
 * zero: il pannello acceso dal menu e poi "service daemoxcp_mail start".
 *
 * Il lucchetto e' un lock su un file, tenuto dal processo finche' vive: il sistema lo libera quando il processo muore,
 * anche ucciso, quindi non resta mai un lucchetto orfano. Nel file c'e' il pid di chi lo tiene, solo per dirlo.
 * Chi arriva secondo aspetta un poco (il riavvio dopo l'aggiornamento di Java accende il nuovo solo quando il vecchio
 * e' uscito, ma un attimo di sovrapposizione non deve fermarlo), poi rinuncia senza toccare quello che gira.
 */
public final class PanelInstanceLock {

    private static final Logger LOGGER = Logger.getLogger(PanelInstanceLock.class.getName());

    /** Accanto agli altri dati della parte root. */
    public static final Path FILE = Path.of(DataFolderRename.NEW, "panel-root.lock");

    private static FileChannel channel;
    private static FileLock lock;

    private PanelInstanceLock() {}

    /** Il lucchetto del pannello: null se adesso e' di questo processo, altrimenti il pid di chi lo tiene ("?" se non si sa). */
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
            // Un lucchetto che non si puo' nemmeno aprire non deve tenere spento il pannello: si dice e si va avanti.
            LOGGER.warning("[PanelInstanceLock] cannot use " + file + ": " + e.getMessage() + " (started without the check)");
            closeQuietly(ch);
            return null;
        }
    }

    /** Solo per le prove: lascia il lucchetto (all'uscita lo lascia comunque il sistema). */
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
