package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * The way back of a package job: a boot environment created BEFORE touching them.
 *
 * Measured on the VM on 2026-11-06 (finding 147): after a guided upgrade there was no new boot
 * environment, and the previous package was nowhere to be found. An upgrade that breaks a service
 * could only be chased forward. The release upgrade already made its boot environment (and did not
 * start without it): now all package jobs do it.
 *
 * The rules:
 *  - on a system with boot environments (bectl check succeeds) the job does NOT start if the
 *    creation fails: it is the same choice as for the release upgrade;
 *  - on a system without them (UFS), we go ahead as before, and the log says so;
 *  - if in the end no package changed (a refused job, an empty plan), the boot environment just
 *    created is removed: otherwise the refusals would push out the real ways back;
 *  - if something changed, the last KEEP created before a package job are kept and the oldest
 *    are removed. Never the one in use nor the one for the next boot. The snapshot it was born
 *    from is removed only if no other clone uses it.
 *
 * The prefix is different from the release upgrade's ("before-"): the last way back of the
 * release upgrade (lastPanelBootEnvironment) must not become that of a package upgrade.
 */
public final class PackageWayBack {

    private PackageWayBack() {}

    private static final Logger LOGGER = Logger.getLogger(PackageWayBack.class.getName());

    static final String PREFIX = "packages-before-";
    static final int KEEP = 3;

    /** The names this class creates and can therefore remove: nothing else gets through. */
    static final java.util.regex.Pattern OWN = java.util.regex.Pattern.compile(
            "^packages-before-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}-[a-z0-9-]{1,40}$");

    /*
     * The way back of the full reinstallation from the menu has its own name and its own pruning.
     * Before, it was "packages-before-...-reinstall" and counted among the KEEP of the package jobs:
     * three upgrades after a reinstallation removed it (finding 162), and a test launched on the
     * clone after three reinstallations had removed a real one. Now the package jobs do not see it,
     * and it prunes only its own: it is the only copy of the server from before (configurations,
     * mailboxes, databases), and a reinstallation is done rarely.
     */
    static final String REINSTALL_PREFIX = "reinstall-before-";
    static final int REINSTALL_KEEP = 2;
    public static final java.util.regex.Pattern REINSTALL_OWN = java.util.regex.Pattern.compile(
            "^reinstall-before-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}$");

    /** The data that, if they sit inside the boot environment, go back with it. */
    static final List<String> DATA = List.of("/var/vmail", "/var/db/mysql");

    /** What is known after before(): the name created ("" if none) and the packages' fingerprint. */
    public record Prepared(String name, String inventory) {}

    private static Shell.Result run(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd);
    }

    static String inventory() {
        return run("pkg query %n-%v 2>/dev/null | sort | sha256", 120).outputTrim();
    }

    /** The name of a new boot environment for the job 'kind', with the UTC time: alphabetical order is time order. */
    static String nameFor(String kind, ZonedDateTime when) {
        String k = (kind == null ? "job" : kind.toLowerCase(java.util.Locale.ROOT)).replaceAll("[^a-z0-9-]", "-");
        if (k.isEmpty()) k = "job";
        if (k.length() > 40) k = k.substring(0, 40);
        return PREFIX + when.withZoneSameInstant(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss")) + "-" + k;
    }

    /**
     * Before the job. Creates the boot environment and writes how to go back. Throws
     * IllegalStateException if the system has boot environments but the creation fails: the
     * caller must not touch the packages.
     */
    public static Prepared before(Consumer<String> log, String kind) {
        return create(log, nameFor(kind, ZonedDateTime.now()));
    }

    /** The name of the way back of a reinstallation, with the UTC time. */
    static String reinstallName(ZonedDateTime when) {
        return REINSTALL_PREFIX + when.withZoneSameInstant(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss"));
    }

    /**
     * The free space the reinstallation wants before starting. Measured on the VM: with the
     * packages already installed the reinstallation wrote 54 MB net (2026-11-06, finding 170);
     * with the eleven main packages to download and reinstall, and pkg's cache empty, 358 MB,
     * 81 of them cache (2026-11-07, finding 174). 1 GB is almost three times the worst measured case,
     * for the peaks during extraction and for the mail that arrives meanwhile. A disk that fills up
     * halfway leaves mail off worse than a reinstallation that does not start.
     */
    static long reinstallMinFree = 1L << 30;

    /**
     * Before the reinstallation, on systems with boot environments: if the pool has less than
     * reinstallMinFree free, the reason for the refusal; otherwise null, and the log says how much
     * space the way back will keep occupied. Measured (finding 170): the reinstallation empties
     * /var/vmail and recreates MySQL, but the old blocks are not freed, the way back's snapshot keeps
     * them. With 500 MB of mail, 516 MB. As long as the way back is there, the new mail fills the
     * disk next to the old.
     */
    public static String reinstallSpace(Consumer<String> log) {
        if (!run("bectl check", 30).success()) return null;
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        String avail = root.isEmpty() ? "" : run("zfs get -Hp -o value available " + root + " 2>/dev/null", 30).outputTrim();
        if (!avail.matches("[0-9]+")) return null;      // unknown: nothing is stopped for this
        long free = Long.parseLong(avail);
        long data = 0;
        for (String path : dataInside()) {
            String kb = run("du -sk " + path + " 2>/dev/null | cut -f1", 600).outputTrim();
            if (kb.matches("[0-9]+")) data += Long.parseLong(kb) * 1024;
        }
        if (free < reinstallMinFree)
            return I18n.tr("server.reinstall.noSpace", Map.of("free", mb(free), "need", mb(reinstallMinFree)));
        log.accept(I18n.tr("server.reinstall.wayBackSpace", Map.of("data", mb(data), "free", mb(free))));
        return null;
    }

    static String mb(long bytes) {
        return String.valueOf(Math.round(bytes / 1048576.0));
    }

    /**
     * The space a way back really keeps occupied: the blocks only it has, that is those of the
     * snapshot it was born from (zfs "used" of the snapshot). The "used" of the boot environment, just
     * created, is 0: bectl list and the tab said "0 MB" for a way back that held 516
     * (measured, finding 170). -1 if unknown.
     */
    static long pinnedBytes(String name) {
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        String parent = root.contains("/") ? root.substring(0, root.lastIndexOf('/')) : "";
        if (parent.isEmpty()) return -1;
        String origin = run("zfs get -H -o value origin " + parent + "/" + name + " 2>/dev/null", 30).outputTrim();
        if (!origin.contains("@")) return -1;
        String used = run("zfs get -Hp -o value used " + origin + " 2>/dev/null", 30).outputTrim();
        return used.matches("[0-9]+") ? Long.parseLong(used) : -1;
    }

    /** The most recent reinstallation way back on this system, or "" if there is none. */
    static String newestReinstallWayBack() {
        String newest = "";
        for (String line : run("bectl list -H 2>/dev/null | cut -f1", 60).outputTrim().split("\n")) {
            String n = line.trim();
            if (REINSTALL_OWN.matcher(n).matches() && n.compareTo(newest) > 0) newest = n;
        }
        return newest;
    }

    /** Before the full reinstallation: like {@link #before}, with the reinstallation's name. */
    public static Prepared beforeInstallation(Consumer<String> log) {
        return create(log, reinstallName(ZonedDateTime.now()));
    }

    private static Prepared create(Consumer<String> log, String name) {
        String inv = inventory();
        if (!run("bectl check", 30).success()) {
            log.accept(I18n.tr("server.um.x.wbUnsupported"));
            return new Prepared("", inv);
        }
        Shell.Result c = run("bectl create " + name + " 2>&1", 300);
        boolean listed = run("bectl list -H 2>/dev/null | cut -f1", 60).outputTrim().lines().anyMatch(name::equals);
        if (!c.success() || !listed) {
            String err = c.outputTrim().isEmpty() ? "exit " + c.exitCode() : c.outputTrim();
            throw org.daemoxcp.mail.util.ShownException.of("server.um.x.wbFailed", Map.of("name", name, "err", err));
        }
        log.accept(I18n.tr("server.um.x.wbCreated", Map.of("name", name)));
        log.accept(I18n.tr("server.um.x.wbHowBack", Map.of("name", name)));
        List<String> inside = dataInside();
        if (!inside.isEmpty())
            log.accept(I18n.tr("server.um.x.wbDataInside", Map.of("paths", String.join(", ", inside))));
        LOGGER.info("Way back created before a package job: " + name);
        return new Prepared(name, inv);
    }

    /**
     * After the job, however it ended. If no package changed, the boot environment just
     * created is not needed and is removed; otherwise the oldest ones are pruned.
     */
    public static void after(Consumer<String> log, Prepared p) {
        if (p == null || p.name().isEmpty()) return;
        if (p.inventory().equals(inventory()) && !p.inventory().isEmpty()) {
            String err = destroy(p.name());
            log.accept(err == null ? I18n.tr("server.um.x.wbNotNeeded", Map.of("name", p.name()))
                                   : I18n.tr("server.um.x.wbPruneFailed", Map.of("name", p.name(), "err", err)));
            return;
        }
        prune(log, KEEP);
    }

    /**
     * After the full reinstallation from the menu. Unlike the package jobs, there identical
     * packages do not mean that nothing changed: the script stops the services, deletes and
     * rewrites the configurations, empties /var/vmail and recreates the MySQL tables even when it
     * installs nothing new. So the boot environment is removed only if the script stopped
     * BEFORE changing anything ({@code systemTouched} false: it did not reach phase 1) and the
     * packages are identical; otherwise it stays, we say how to go back to it, and the oldest are pruned.
     */
    public static void afterInstallation(Consumer<String> log, Prepared p, boolean systemTouched) {
        if (p == null || p.name().isEmpty()) return;
        if (!systemTouched && p.inventory().equals(inventory()) && !p.inventory().isEmpty()) {
            String err = destroy(p.name());
            log.accept(err == null ? I18n.tr("server.reinstall.wayBackNotNeeded", Map.of("name", p.name()))
                                   : I18n.tr("server.um.x.wbPruneFailed", Map.of("name", p.name(), "err", err)));
            return;
        }
        log.accept(I18n.tr("server.reinstall.wayBackKept", Map.of("name", p.name())));
        prune(log, REINSTALL_OWN, REINSTALL_KEEP, "server.reinstall.wayBackPruned");
    }

    /** Removes the oldest package boot environments, keeping the last 'keep'. */
    static void prune(Consumer<String> log, int keep) {
        prune(log, OWN, keep, "server.um.x.wbPruned");
    }

    /** Removes the oldest among those of the pattern 'own', keeping the last 'keep'. */
    static void prune(Consumer<String> log, java.util.regex.Pattern ownNames, int keep, String prunedKey) {
        List<String> own = new ArrayList<>();
        for (String line : run("bectl list -H 2>/dev/null", 60).outputTrim().split("\n")) {
            String[] f = line.split("\t");
            if (f.length < 2 || !ownNames.matcher(f[0].trim()).matches()) continue;
            // N = in use now, R = at the next boot, T = only at the next boot: never touch them.
            if (f[1].contains("N") || f[1].contains("R") || f[1].contains("T")) continue;
            own.add(f[0].trim());
        }
        java.util.Collections.sort(own);
        for (int i = 0; i < own.size() - keep; i++) {
            String err = destroy(own.get(i));
            log.accept(err == null ? I18n.tr(prunedKey, Map.of("name", own.get(i), "keep", String.valueOf(keep)))
                                   : I18n.tr("server.um.x.wbPruneFailed", Map.of("name", own.get(i), "err", err)));
        }
    }

    /**
     * Removes a boot environment created by this class, and the snapshot it was born from if no
     * other clone uses it. null if removed, otherwise the reason. It does not use "bectl destroy -o":
     * after a promotion the origin snapshot may belong to another boot environment.
     */
    static String destroy(String name) {
        if (!OWN.matcher(name).matches() && !REINSTALL_OWN.matcher(name).matches())
            return "not a boot environment made before a package job or a reinstallation";
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        String parent = root.contains("/") ? root.substring(0, root.lastIndexOf('/')) : "";
        String origin = parent.isEmpty() ? "" : run("zfs get -H -o value origin " + parent + "/" + name + " 2>/dev/null", 30).outputTrim();
        Shell.Result d = run("bectl destroy -F " + name + " 2>&1", 300);
        if (!d.success()) return d.outputTrim().isEmpty() ? "exit " + d.exitCode() : d.outputTrim();
        if (origin.matches("[A-Za-z0-9_./:-]+@[A-Za-z0-9_.:-]+")) {
            String clones = run("zfs get -H -o value clones " + origin + " 2>/dev/null", 30).outputTrim();
            if (clones.isEmpty() || "-".equals(clones)) run("zfs destroy " + origin + " 2>&1", 120);
        }
        return null;
    }

    /** Which of the DATA sit inside the boot environment in use (that is, would go back with it). */
    static List<String> dataInside() {
        List<String> r = new ArrayList<>();
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        if (root.isEmpty()) return r;
        for (String path : DATA) {
            if (!new java.io.File(path).isDirectory()) continue;
            String ds = run("zfs list -H -o name " + path + " 2>/dev/null", 30).outputTrim();
            if (ds.equals(root) || ds.startsWith(root + "/")) r.add(path);
        }
        return r;
    }
}
