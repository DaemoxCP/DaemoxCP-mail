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
 * The backup copies the panel makes of a configuration file before changing it: the last {@link #KEEP} per
 * file are kept, the older ones are deleted.
 *
 * Up to 0.9.0 none were ever deleted. Every "Apply" of the firewall, every PfPolicy pass, every change to
 * resolv.conf, to unbound or to a jail left one more copy, forever: on the production server, on 2026-11-18, 221
 * copies of /etc/pf.conf and 267 of the firewall anchor (found by going through all the panel's functions). They do
 * not weigh much, but they grow without end and hide, among hundreds of names, the one you need to go back.
 *
 * The copies are the ones the panel writes, and only those:
 *  - next to the original, "file.bak.MILLISECONDS" (13 digits): {@link #copy} makes them and removes the old ones;
 *  - in the fail2ban backup folder, "file.bak.YYYYMMDD-HHMMSS" (Fail2banManager): there {@link #prune} runs before
 *    making a new one.
 * A name written by hand in another form (pf.conf.bak, pf.conf.bak.20250101, pf.conf.orig) is never touched; nor
 * a link or a folder with the name of a copy; nor the one-off copies of BanActionRepair (".before-pf-").
 * The most recent ones are recognised by the moment written in the name, not by the file's date.
 *
 * {@link #ensureAtBoot} removes the extra copies already left by earlier versions, once, at the first startup:
 * at the second it finds nothing and writes nothing.
 */
public final class ConfigBackups {

    private static final Logger LOGGER = Logger.getLogger(ConfigBackups.class.getName());

    /** How many copies are kept for each file: enough to go back quite a few steps. */
    public static final int KEEP = 10;

    /** The files of which the panel makes a copy next to the original. */
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

    /** The folder of the copies of fail2ban's files (Fail2banManager, BanActionRepair): outside jail.d. */
    public static final Path FAIL2BAN_FOLDER = Path.of(DataFolderRename.NEW, "fail2ban-backups");

    /** A copy made by the panel: the file name, ".bak.", the milliseconds (13 digits) or YYYYMMDD-HHMMSS. */
    static final Pattern COPY = Pattern.compile("(.+)\\.bak\\.([0-9]{13}|[0-9]{8}-[0-9]{6})");

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");

    private ConfigBackups() {}

    /**
     * Copies original next to itself, as "original.bak.MILLISECONDS", then removes the copies beyond the
     * last {@link #KEEP}. Returns the path of the new copy. Two copies in the same millisecond still get
     * two names.
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
     * In dir, the copies of name beyond the last keep: deleted, oldest first. Returns how many. Does not throw:
     * a copy that cannot be deleted is reported in the log and does not stop the job that asked for it.
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

    /** The copies of name in dir, from the oldest to the most recent: only real files, never through links. */
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

    /** The moment written in the name of a copy, in milliseconds. */
    static long moment(Path copy) {
        Matcher m = COPY.matcher(copy.getFileName().toString());
        if (!m.matches()) return Long.MIN_VALUE;
        String stamp = m.group(2);
        if (stamp.length() == 13) return Long.parseLong(stamp);
        // Fail2banManager writes the server's time (LocalDateTime.now()): it is read with the same time zone.
        return LocalDateTime.parse(stamp, STAMP).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    /**
     * The names of the files with copies in dir (for the fail2ban folder, where there are copies of
     * different files).
     */
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

    /**
     * The extra copies of the files in beside and of those in the folder folder: what was removed, empty if
     * nothing.
     */
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
