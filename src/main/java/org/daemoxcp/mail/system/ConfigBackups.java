package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Le copie di sicurezza che il pannello fa di un file di configurazione prima di cambiarlo: se ne tengono le ultime
 * {@link #KEEP} per file, le piu' vecchie si cancellano.
 *
 * Fino alla 0.9.0 non se ne cancellava nessuna. Ogni «Applica» del firewall, ogni passaggio di PfPolicy, ogni modifica
 * di resolv.conf, di unbound o di una jail lasciava una copia in piu', per sempre: sul server vero, il 18/11/2026, 221
 * copie di /etc/pf.conf e 267 dell'anchor del firewall (trovato percorrendo tutte le funzioni del pannello). Non pesano
 * molto, ma crescono senza fine e nascondono fra centinaia di nomi quella che serve per tornare indietro.
 *
 * Le copie sono quelle che il pannello scrive, e solo quelle:
 *  - accanto all'originale, «file.bak.MILLISECONDI» (13 cifre): {@link #copy} le fa e toglie le vecchie;
 *  - nella cartella delle copie di fail2ban, «file.bak.AAAAMMGG-HHMMSS» (Fail2banManager): li' {@link #prune} prima
 *    di farne una nuova.
 * Un nome scritto a mano con un'altra forma (pf.conf.bak, pf.conf.bak.20250101, pf.conf.orig) non si tocca mai; ne'
 * un collegamento o una cartella col nome di una copia; ne' le copie una tantum di BanActionRepair («.before-pf-»).
 * Le piu' recenti si riconoscono dal momento scritto nel nome, non dalla data del file.
 *
 * {@link #ensureAtBoot} toglie le copie in piu' gia' lasciate dalle versioni di prima, una volta, al primo avvio:
 * al secondo non trova niente e non scrive niente.
 */
public final class ConfigBackups {

    private static final Logger LOGGER = Logger.getLogger(ConfigBackups.class.getName());

    /** Quante copie si tengono per ogni file: abbastanza per tornare indietro di parecchi passi. */
    public static final int KEEP = 10;

    /** I file di cui il pannello fa una copia accanto all'originale. */
    static final List<Path> BESIDE = List.of(
            Path.of("/etc/pf.conf"),
            Path.of("/etc/pf.anchors/panel-fw.conf"),
            Path.of("/etc/sysctl.conf"),
            Path.of("/etc/rc.conf"),
            Path.of("/etc/resolv.conf"),
            Path.of("/usr/local/etc/unbound/unbound.conf"),
            Path.of("/var/unbound/unbound.conf"),
            Path.of("/var/unbound/forward.conf"),
            Path.of("/usr/local/etc/rspamd/local.d/antivirus.conf"));

    /** La cartella delle copie dei file di fail2ban (Fail2banManager, BanActionRepair): fuori da jail.d. */
    public static final Path FAIL2BAN_FOLDER = Path.of(DataFolderRename.NEW, "fail2ban-backups");

    /** Una copia del pannello: il nome del file, «.bak.», i millisecondi (13 cifre) o AAAAMMGG-HHMMSS. */
    static final Pattern COPY = Pattern.compile("(.+)\\.bak\\.([0-9]{13}|[0-9]{8}-[0-9]{6})");

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private ConfigBackups() {}

    /**
     * Copia original accanto a se', come «original.bak.MILLISECONDI», poi toglie le copie oltre le ultime {@link #KEEP}.
     * Torna il percorso della copia nuova. Due copie nello stesso millisecondo hanno comunque due nomi.
     */
    public static Path copy(Path original, CopyOption... options) throws IOException {
        Path dir = original.toAbsolutePath().getParent();
        String name = original.getFileName().toString();
        long t = System.currentTimeMillis();
        Path target;
        while (Files.exists(target = dir.resolve(name + ".bak." + t), LinkOption.NOFOLLOW_LINKS)) t++;
        Files.copy(original, target, options);
        prune(dir, name, KEEP);
        return target;
    }

    /**
     * In dir, le copie di name oltre le ultime keep: cancellate, dalla piu' vecchia. Torna quante. Non solleva: una
     * copia che non si cancella si dice nel log e non ferma il lavoro che l'ha chiesta.
     */
    public static int prune(Path dir, String name, int keep) {
        int removed = 0;
        try {
            List<Path> copies = copiesOf(dir, name);
            for (int i = 0; i < copies.size() - Math.max(keep, 0); i++) {
                if (Files.deleteIfExists(copies.get(i))) removed++;
            }
        } catch (IOException e) {
            LOGGER.warning("[ConfigBackups] old copies of " + dir.resolve(name) + " not removed (" + removed + " were): " + e);
        }
        return removed;
    }

    /** Le copie di name in dir, dalla piu' vecchia alla piu' recente: solo file veri, mai attraverso collegamenti. */
    static List<Path> copiesOf(Path dir, String name) throws IOException {
        List<Path> found = new ArrayList<>();
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) return found;
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                Matcher m = COPY.matcher(p.getFileName().toString());
                if (m.matches() && m.group(1).equals(name) && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) found.add(p);
            }
        }
        found.sort(Comparator.comparingLong(ConfigBackups::moment).thenComparing(p -> p.getFileName().toString()));
        return found;
    }

    /** Il momento scritto nel nome di una copia, in millisecondi. */
    static long moment(Path copy) {
        Matcher m = COPY.matcher(copy.getFileName().toString());
        if (!m.matches()) return Long.MIN_VALUE;
        String stamp = m.group(2);
        if (stamp.length() == 13) return Long.parseLong(stamp);
        // Fail2banManager scrive l'ora del server (LocalDateTime.now()): si legge con lo stesso fuso.
        return LocalDateTime.parse(stamp, STAMP).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    /** I nomi dei file che hanno copie in dir (per la cartella di fail2ban, dove ce ne sono di diversi). */
    static TreeSet<String> namesIn(Path dir) throws IOException {
        TreeSet<String> names = new TreeSet<>();
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) return names;
        try (Stream<Path> s = Files.list(dir)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                Matcher m = COPY.matcher(p.getFileName().toString());
                if (m.matches()) names.add(m.group(1));
            }
        }
        return names;
    }

    /** Le copie in piu' dei file in beside e di quelli nella cartella folder: cosa e' stato tolto, vuoto se niente. */
    static String clean(List<Path> beside, Path folder) throws IOException {
        StringBuilder done = new StringBuilder();
        for (Path f : beside) note(done, f, prune(f.getParent(), f.getFileName().toString(), KEEP));
        for (String name : namesIn(folder)) note(done, folder.resolve(name), prune(folder, name, KEEP));
        return done.toString();
    }

    private static void note(StringBuilder done, Path file, int removed) {
        if (removed == 0) return;
        if (!done.isEmpty()) done.append("; ");
        done.append(file).append(' ').append(removed);
    }

    public static void ensureAtBoot() {
        try {
            String done = clean(BESIDE, FAIL2BAN_FOLDER);
            if (done.isEmpty()) return;
            LOGGER.info("[ConfigBackups] DONE: old copies of the configuration files removed, the latest " + KEEP
                    + " of each kept (" + done + ")");
        } catch (Throwable t) {
            LOGGER.warning("[ConfigBackups] old copies not checked: " + t);
        }
    }
}
