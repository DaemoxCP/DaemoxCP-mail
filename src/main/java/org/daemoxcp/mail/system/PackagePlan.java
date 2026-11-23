package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The EXACT plan of a package upgrade, and whether a vulnerability really has a
 * fixed version.
 *
 * Two questions the panel answered only halfway.
 *
 * 1. "If I upgrade X, what changes?" The preflight read "X 1.2 -> 1.3" from the catalogue and
 *    that was all. But pkg, to upgrade X, may upgrade dependencies, install new ones, reinstall
 *    them or remove them: X's line is one of the lines of a plan that nobody showed. And for a
 *    LOCKED package the plan could not even be asked for, because pkg upgrade -n skips the
 *    locked ones.
 *
 *    Here the plan is asked of pkg on a COPY of its database, in which the same locks that
 *    the real upgrade will remove are removed. The answer is the one pkg would really give:
 *    every package, from which version to which, and whether the target version is still
 *    vulnerable. The real database is not touched.
 *
 * 2. "Is the patch there or not?" pkg audit says "vulnerable" and that is all. But VuXML, the
 *    database it reads from, says for every problem WHICH versions are vulnerable (for example
 *    "< 1.30.5,3"), that is, from which version on the problem is fixed. Placed next to the
 *    version the catalogue offers, it becomes an exact answer: it is fixed by upgrading; or the
 *    fix exists but your branch does not have it yet; or a fixed version does not exist.
 *
 * The formats read here are those of pkg's source (src/utils.c, src/audit.c,
 * src/version.c), not remembered ones: a line misread here means promising an
 * upgrade different from the one that will happen.
 */
public final class PackagePlan {

    private PackagePlan() {}

    // ===================== reading pkg's plan =====================

    /** The headers pkg prints for each type of change, and the name we use here. */
    private static final String[][] SECTIONS = {
        {"Installed packages to be UPGRADED:",    "upgrade"},
        {"Installed packages to be DOWNGRADED:",  "downgrade"},
        {"New packages to be INSTALLED:",         "install"},
        {"Installed packages to be REINSTALLED:", "reinstall"},
        {"Installed packages to be REMOVED:",     "remove"},
        {"Installed packages LOCKED:",            "locked"},
        {"New packages to be FETCHED:",           "download"},
        {"New groups to be UPGRADED:",            "group"},
        {"New groups to be INSTALLED:",           "group"},
    };

    /** The totals pkg writes at the bottom of the plan: the parser's cross-check. */
    private static final String[][] TOTALS = {
        {"Number of packages to be upgraded: ",    "upgrade"},
        {"Number of packages to be downgraded: ",  "downgrade"},
        {"Number of packages to be installed: ",   "install"},
        {"Number of packages to be reinstalled: ", "reinstall"},
        {"Number of packages to be removed: ",     "remove"},
        {"Number of packages to be fetched: ",     "download"},
    };

    private static final String VULNERABLE = " (vulnerable!)";

    private static final Pattern FROM_TO = Pattern.compile("^(\\S+): (\\S+) -> (\\S+)(?: \\[([^\\]]+)\\])?$");
    // A new installation: "name: version", the repository if there is more than one and the reason if pkg knows
    // it. pkg 2.9 (src/utils.c, display_summary_item, PKG_DISPLAY_INSTALL) writes the reason for dependencies
    // pulled in: "py312-pyproject-hooks: 1.3.3 [FreeBSD-ports] (required by py312-build)". Without the reason in
    // the model, on the VM on 2026-11-21 the Python switch stopped with "a line I cannot read", and so did every
    // plan that installs a new dependency, "Update all" included.
    private static final Pattern REPO_VERSION_NAME = Pattern.compile("^(\\S+): (\\S+)(?: \\[([^\\]]+)\\])?(?: \\((.*)\\))?$");
    private static final Pattern REINSTALL = Pattern.compile("^(\\S+)-([^\\s-]+)(?: \\[([^\\]]+)\\])?(?: \\((.*)\\))?$");
    private static final Pattern REMOVES = Pattern.compile("^(\\S+): (\\S+)(?: \\((.*)\\))?$");
    private static final Pattern PROTECTED_IN_PLAN = Pattern.compile(
            "^Package (\\S+)-([^\\s-]+) is locked and may not be (\\S+)(?: to version (\\S+))?");
    private static final Pattern PROTECTED_EVENT = Pattern.compile("^(\\S+)-([^\\s-]+) is locked and may not be modified$");
    // pkg 2.9: when a file conflict cannot be solved by removing the package in the way (because another one
    // still needs it), pkg holds back the upgrade and says so after the integrity check, with the packages
    // already downloaded:
    //   "  - fakelib0-0.9 [replacement] conflicts with fakelib-1.0 [installed] on /usr/local/bin/fake-tool"
    //   "fakeapp-1.1 is held back to solve the problem"
    // and then "Your packages are up to date.". Measured on the VM on 2026-11-22 with pkg 2.9.2
    // (PackageReplacementE2ETest): before, pkg proposed removing the other package too; now it removes nothing
    // and the plan stays empty.
    private static final Pattern CONFLICT = Pattern.compile(
            "^- (\\S+)-([^\\s-]+) \\[[^\\]]*\\] conflicts with (\\S+)-([^\\s-]+) \\[installed\\] on (\\S+)$");
    private static final Pattern HELD_BACK = Pattern.compile("^(\\S+)-([^\\s-]+) is held back to solve the problem$");

    /**
     * The plan as {@code pkg upgrade -n} prints it, read section by section.
     *
     * Pure function: it receives the text and launches nothing, so it can be tested with real
     * outputs. If a line inside a section cannot be read, or the counts do not match the totals
     * pkg prints by itself, the plan comes out with "measured" false: a plan read halfway and
     * presented as complete is worse than no plan.
     */
    static JSONObject readPlan(String output) {
        JSONArray changes = new JSONArray(), lockedPackages = new JSONArray();
        JSONArray errors = new JSONArray(), warnings = new JSONArray(), unreadable = new JSONArray();
        JSONArray heldBack = new JSONArray(), conflicts = new JSONArray();
        Set<String> seenConflicts = new LinkedHashSet<>();
        Map<String, Integer> counted = new HashMap<>(), declared = new HashMap<>();
        Set<String> alreadyLocked = new LinkedHashSet<>();
        boolean updated = false, hasConflicts = false;
        String section = null;

        for (String raw : (output == null ? "" : output).split("\n")) {
            String line = raw.replace("\r", "");
            String t = line.trim();

            String fresh = null;
            for (String[] s : SECTIONS) if (t.equals(s[0])) fresh = s[1];
            if (fresh != null) { section = fresh; continue; }

            if (section != null && line.startsWith("\t") && !t.isEmpty()) {
                if (!readEntry(section, t, changes, lockedPackages, alreadyLocked)) unreadable.put(t);
                else if (!"locked".equals(section) && !"group".equals(section))
                    counted.merge(section, 1, Integer::sum);
                continue;
            }
            section = null;   // an empty or non-indented line closes the section
            if (t.isEmpty()) continue;

            Matcher held = HELD_BACK.matcher(t);
            if (held.find()) {
                heldBack.put(new JSONObject().put("name", held.group(1)).put("version", held.group(2)));
                continue;
            }
            Matcher cf = CONFLICT.matcher(t);
            if (cf.find()) {
                if (seenConflicts.add(t))
                    conflicts.put(new JSONObject().put("name", cf.group(1)).put("version", cf.group(2))
                            .put("installed", cf.group(3)).put("installedVersion", cf.group(4)).put("file", cf.group(5)));
                continue;
            }
            Matcher ev = PROTECTED_EVENT.matcher(t);
            if (ev.find()) {
                if (alreadyLocked.add(ev.group(1)))
                    lockedPackages.put(new JSONObject().put("name", ev.group(1)).put("version", ev.group(2))
                            .put("action", "modified").put("destination", ""));
                continue;
            }
            boolean total = false;
            for (String[] tt : TOTALS) {
                if (t.startsWith(tt[0])) {
                    try { declared.put(tt[1], Integer.parseInt(t.substring(tt[0].length()).trim())); }
                    catch (NumberFormatException e) { unreadable.put(t); }
                    total = true;
                }
            }
            if (total) continue;
            if (t.equals("Your packages are up to date.")) { updated = true; continue; }
            if (t.startsWith("Conflicts with the existing packages")) { hasConflicts = true; continue; }
            if (t.startsWith("pkg:")) {
                if (t.toLowerCase().contains("warning")) warnings.put(t); else errors.put(t);
            }
            // The rest (sizes, "Checking for upgrades", "Updating ... repository catalogue")
            // does not change the plan.
        }

        JSONObject r = new JSONObject().put("changes", changes).put("lockedPackages", lockedPackages)
                .put("pkgErrors", errors).put("pkgWarnings", warnings)
                .put("nothingToDo", updated || (changes.isEmpty() && lockedPackages.isEmpty() && errors.isEmpty()))
                .put("hasConflicts", hasConflicts)
                .put("heldBack", heldBack).put("conflicts", conflicts);

        if (unreadable.length() > 0)
            return r.put("measured", false).put("unreadable", unreadable)
                    .put("error", I18n.tr("server.plan.unreadableLines", java.util.Map.of("n", String.valueOf(unreadable.length()), "first", String.valueOf(unreadable.getString(0)))));
        // pkg prints a total for each type that appears: the two counts must match, in
        // both directions. A type counted without a total is a total I did not read.
        Set<String> kinds = new LinkedHashSet<>(counted.keySet());
        kinds.addAll(declared.keySet());
        for (String type : kinds) {
            int a = counted.getOrDefault(type, 0), b = declared.getOrDefault(type, -1);
            if (a != b)
                return r.put("measured", false)
                        .put("error", I18n.tr("server.plan.countMismatch", java.util.Map.of("b", String.valueOf(b < 0 ? I18n.tr("server.plan.noTotal") : String.valueOf(b)), "kind", String.valueOf(type), "a", String.valueOf(a))));
        }
        return r.put("measured", true);
    }

    /** An indented line of a section. false if it does not have the form the section expects. */
    private static boolean readEntry(String section, String t, JSONArray changes, JSONArray lockedPackages, Set<String> alreadyLocked) {
        boolean vulnerable = t.endsWith(VULNERABLE);
        String s = vulnerable ? t.substring(0, t.length() - VULNERABLE.length()) : t;
        Matcher m;
        switch (section) {
            case "upgrade", "downgrade" -> {
                m = FROM_TO.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), m.group(2), m.group(3), "", m.group(4), vulnerable));
            }
            case "install" -> {
                m = REPO_VERSION_NAME.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), "", m.group(2), m.group(4), m.group(3), vulnerable));
            }
            case "reinstall" -> {
                m = REINSTALL.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), m.group(2), m.group(2), m.group(4), m.group(3), vulnerable));
            }
            case "remove" -> {
                m = REMOVES.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), m.group(2), "", m.group(3), null, false));
            }
            case "locked" -> {
                m = PROTECTED_IN_PLAN.matcher(s);
                if (!m.find()) return false;
                if (alreadyLocked.add(m.group(1)))
                    lockedPackages.put(new JSONObject().put("name", m.group(1)).put("version", m.group(2))
                            .put("action", m.group(3)).put("destination", m.group(4) == null ? "" : m.group(4)));
            }
            case "download", "group" -> { /* do not change installed packages */ }
            default -> { return false; }
        }
        return true;
    }

    private static JSONObject entry(String type, String name, String from, String to, String reason,
                                   String repo, boolean vulnerable) {
        return new JSONObject().put("type", type).put("name", name).put("from", from).put("to", to)
                .put("reason", reason == null ? "" : reason).put("repo", repo == null ? "" : repo)
                .put("stillVulnerable", vulnerable);
    }

    /**
     * The fingerprint of a plan: what was approved and what is executed must match.
     *
     * Inside are the locks to remove and every change with its versions, in a fixed
     * order. Between reading the plan and the click a catalogue update may happen: with the
     * fingerprint, the panel notices and stops instead of executing a plan different from the
     * one that was read.
     */
    static String signature(JSONObject plan) {
        List<String> lines = new ArrayList<>();
        JSONArray sb = plan.optJSONArray("unlockedPackages");
        for (int i = 0; sb != null && i < sb.length(); i++) lines.add("unlock " + sb.getString(i));
        JSONArray c = plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            lines.add(x.optString("type") + " " + x.optString("name") + " " + x.optString("from") + " " + x.optString("to"));
        }
        java.util.Collections.sort(lines);
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * The fingerprint of the plan's CHANGES only, without the locks to remove.
     *
     * It is used to compare two plans computed under different conditions: the approved one,
     * where the package was still locked and had to be unlocked, and the one recomputed after the
     * real unlock, where there is nothing left to unlock. The full signature would differ for
     * that reason alone; this one answers the question that matters, that is "would pkg do the
     * same things?".
     */
    public static String changesSignature(JSONObject plan) {
        List<String> lines = new ArrayList<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            lines.add(x.optString("type") + " " + x.optString("name") + " " + x.optString("from") + " " + x.optString("to"));
        }
        java.util.Collections.sort(lines);
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /** The plan's changes in readable lines, to show two plans side by side. */
    public static List<String> changesInLines(JSONObject plan) {
        List<String> lines = new ArrayList<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String a = x.optString("to");
            lines.add(typeName(x.optString("type")) + " " + x.optString("name")
                    + (x.optString("from").isEmpty() ? "" : " " + x.optString("from"))
                    + (a.isEmpty() || a.equals(x.optString("from")) ? "" : " -> " + a));
        }
        java.util.Collections.sort(lines);
        return lines;
    }

    // ===================== asking pkg for the plan =====================

    /** Only plausible package names: they end up in a command line. */
    /** The type of change ("upgrade", "remove"...) in the reader's language. */
    public static String typeName(String type) {
        return switch (type == null ? "" : type) {
            case "upgrade" -> I18n.tr("up.tUpgrade");
            case "install" -> I18n.tr("up.tInstall");
            case "reinstall" -> I18n.tr("up.tReinstall");
            case "remove" -> I18n.tr("up.tRemove");
            case "downgrade" -> I18n.tr("up.tDowngrade");
            default -> String.valueOf(type);
        };
    }

    static boolean isValidName(String n) {
        return n != null && n.matches("[A-Za-z0-9._+-]{1,64}");
    }

    private static String sh(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).outputTrim();
    }

    /** pkg's database folder: we ask pkg for it instead of assuming it. */
    static String dbFolder() {
        String d = sh("pkg config PKG_DBDIR 2>/dev/null", 30);
        return d.matches("/[A-Za-z0-9._/-]{1,200}") ? d : "/var/db/pkg";
    }

    /**
     * What {@code pkg upgrade} would do on 'pacchetti' (all of them, if the list is empty) after
     * removing the lock from 'daSbloccare'.
     *
     * If there is nothing to unlock, the simulation runs on the real database: {@code -n} does
     * not write anything. If there is, it runs on a full copy of pkg's folder (catalogue
     * included), made in /var/tmp and deleted right after: it is the only way to know what pkg
     * would do on a locked package without really removing its lock.
     *
     * {@code -U}: the catalogue is not downloaded again, the existing one is used. The panel
     * updates it before showing the status; what matters here is that the simulation and the
     * execution use the SAME one.
     */
    public static JSONObject simulate(List<String> toUnlock, List<String> packages) {
        return simulate(new Command("upgrade", packages, List.of()), toUnlock);
    }

    /**
     * What a job asks of pkg: "upgrade" (the given packages, or all of them) or "install" (the given ones), after
     * removing the packages of 'forget' (which the job removes first, with pkg delete, even with -f).
     */
    record Command(String verb, List<String> args, List<String> forget) {
        String shown() {
            String list = args.isEmpty() ? "" : " " + String.join(" ", args);
            String f = forget.isEmpty() ? "" : "pkg delete -f " + String.join(" ", forget) + " ; ";
            return f + "pkg " + verb + " -n -U" + list;
        }
    }

    /**
     * As above, for any command. The database copy is made if there is something to unlock or to forget; the
     * packages to forget are removed from the copy with JDBC (the rows, not the files: PKGDB_FORGET_PACKAGE), and
     * the real database is never touched.
     */
    static JSONObject simulate(Command cmd, List<String> toUnlock) {
        if (!"upgrade".equals(cmd.verb()) && !"install".equals(cmd.verb())) return failed("unknown pkg command: " + cmd.verb());
        for (String n : toUnlock) if (!isValidName(n)) return failed(I18n.tr("server.plan.badName", java.util.Map.of("n", String.valueOf(n))));
        for (String n : cmd.args()) if (!isValidName(n)) return failed(I18n.tr("server.plan.badName", java.util.Map.of("n", String.valueOf(n))));
        for (String n : cmd.forget()) if (!isValidName(n)) return failed(I18n.tr("server.plan.badName", java.util.Map.of("n", String.valueOf(n))));
        String list = cmd.args().isEmpty() ? "" : " " + String.join(" ", cmd.args());
        String prefix = "pkg";
        String copy = null;
        try {
            if (!toUnlock.isEmpty() || !cmd.forget().isEmpty()) {
                String db = dbFolder();
                long kb = number(sh("du -sk " + db + " 2>/dev/null | cut -f1", 120));
                long free = number(sh("df -k /var/tmp 2>/dev/null | tail -1 | awk '{print $4}'", 30));
                if (kb <= 0) return failed(I18n.tr("server.plan.cannotMeasure", java.util.Map.of("db", String.valueOf(db))));
                if (free < kb * 2)
                    return failed(I18n.tr("server.plan.noSpace", java.util.Map.of("mb", String.valueOf(kb / 1024), "free", String.valueOf(free / 1024))));
                copy = sh("mktemp -d /var/tmp/panel-simulation.XXXXXX 2>/dev/null", 30);
                if (!copy.matches("/var/tmp/panel-simulation\\.[A-Za-z0-9]{6,}")) {
                    String oddFolder = copy;
                    copy = null;
                    return failed(I18n.tr("server.plan.mktempFailed", java.util.Map.of("d", String.valueOf(oddFolder))));
                }
                Shell.Result cp = Shell.runShell(Duration.ofSeconds(600), "cp -Rp " + db + "/. " + copy + "/ 2>&1");
                if (!cp.success()) return failed(I18n.tr("server.plan.copyFailed", java.util.Map.of("out", String.valueOf(cp.outputTrim()))));
                prefix = "pkg -o PKG_DBDIR=" + copy;
                for (String n : toUnlock) {
                    Shell.Result u = Shell.runShell(Duration.ofSeconds(60), prefix + " unlock -y " + n + " 2>&1");
                    if (!u.success()) return failed(I18n.tr("server.plan.unlockFailed", java.util.Map.of("n", String.valueOf(n), "out", String.valueOf(u.outputTrim()))));
                }
                String forgotten = forget(copy, cmd.forget());
                if (forgotten != null) return failed(forgotten);
            }
            Shell.Result r = Shell.runShell(Duration.ofSeconds(600), prefix + " " + cmd.verb() + " -n -U" + list + " 2>&1");
            JSONObject plan = readPlan(r.output());
            return plan.put("success", true).put("code", r.exitCode()).put("output", r.outputTrim())
                    .put("onBackup", copy != null)
                    .put("command", cmd.shown());
        } finally {
            // The copy always goes away. The path is the one created by mktemp and verified above.
            if (copy != null) Shell.runShell(Duration.ofSeconds(300), "rm -rf " + copy);
        }
    }

    /**
     * Forgets those packages in the COPY of pkg's database (folder 'copy', created by mktemp above): database rows,
     * not files. null if it worked, otherwise the reason. A name that is not there is an error: the plan would say
     * to remove something that is not there.
     */
    private static String forget(String copy, List<String> names) {
        if (names.isEmpty()) return null;
        if (copy == null || !copy.matches("/var/tmp/panel-simulation\\.[A-Za-z0-9]{6,}")) return "not a simulation copy: " + copy;
        try (java.sql.Connection c = org.daemoxcp.mail.database.CatalogGuard.open("jdbc:sqlite:" + copy + "/local.sqlite")) {
            try (java.sql.Statement st = c.createStatement()) {
                st.execute(org.daemoxcp.mail.database.SqlCatalog.PKGDB_FOREIGN_KEYS_ON);
            }
            try (java.sql.PreparedStatement ps = c.prepareStatement(org.daemoxcp.mail.database.SqlCatalog.PKGDB_FORGET_PACKAGE)) {
                for (String n : names) {
                    ps.setString(1, n);
                    if (ps.executeUpdate() != 1) return I18n.tr("server.plan.notInstalledToRemove", java.util.Map.of("n", n));
                }
            }
            return null;
        } catch (java.sql.SQLException e) {
            return "the copy of pkg's database: " + e.getMessage();
        }
    }

    /**
     * The plan of a job that first removes some packages (pkg delete, even with -f: the MySQL migration, the Python
     * switch) and then installs others (pkg install -U). On the database copy the ones to remove are forgotten and
     * pkg is asked what it would install: that is what pkg will really do after the removal, without the conflicts
     * with packages that by then will no longer be there. At the top of the plan the removals, with the installed
     * version; the locks of the removed packages are among those to remove (the job removes them, in the list on
     * disk).
     */
    public static JSONObject planRemoveThenInstall(List<String> remove, List<String> install, Set<String> protectedNames,
                                                   Function<JSONObject, String> reasonNotToUnlock) {
        return planRemoveThenInstall(remove, install, List.of(), protectedNames, reasonNotToUnlock);
    }

    /**
     * The same, with some locks removed from the start ('unlockFirst', only among those that exist): the
     * dependencies already installed that the new package wants as they are. pkg does not use a locked package for
     * a dependency and looks for another one that provides the same library: on the VM, on 2026-11-09,
     * dovecot24-mysql asked for mysql84-client 8.4.13, the installed one, and with the lock the plan installed
     * mysql267-client alongside it (finding 213).
     */
    public static JSONObject planRemoveThenInstall(List<String> remove, List<String> install, java.util.Collection<String> unlockFirst,
                                                   Set<String> protectedNames, Function<JSONObject, String> reasonNotToUnlock) {
        Map<String, String> installedNow = versionsOnly(installed());
        for (String n : remove)
            if (!isValidName(n) || !installedNow.containsKey(n))
                return failed(I18n.tr("server.plan.notInstalledToRemove", java.util.Map.of("n", String.valueOf(n))));
        LinkedHashSet<String> seed = new LinkedHashSet<>();
        for (String n : unlockFirst) if (isValidName(n) && protectedNames.contains(n)) seed.add(n);
        JSONObject plan = planWith(new Command("install", install, remove), seed, protectedNames,
                reasonNotToUnlock, n -> null, true);
        if (!plan.optBoolean("measured")) return plan;
        JSONArray changes = new JSONArray();
        for (String n : remove)
            changes.put(entry("remove", n, installedNow.get(n), "", I18n.tr("server.plan.removedFirst"), "", false)
                    .put("intended", true));
        JSONArray rest = plan.optJSONArray("changes");
        for (int i = 0; rest != null && i < rest.length(); i++) changes.put(rest.get(i));
        LinkedHashSet<String> unlock = new LinkedHashSet<>();
        for (String n : remove) if (protectedNames.contains(n)) unlock.add(n);
        JSONArray before = plan.optJSONArray("unlockedPackages");
        for (int i = 0; before != null && i < before.length(); i++) unlock.add(before.getString(i));
        plan.put("changes", changes).put("unlockedPackages", new JSONArray(new ArrayList<>(unlock)))
            .put("removedFirst", new JSONArray(remove));
        return plan.put("signature", signature(plan));
    }

    /**
     * The plan to upgrade 'pacchetti' removing only the necessary locks.
     *
     * We start by unlocking, in the copy, the requested packages that are locked. If pkg finds
     * other locked packages on its way -- a dependency that must change as well -- it names
     * them: they are added to the list and the count is redone, but only if the caller's rule
     * allows unlocking them. Those that cannot be unlocked remain as an obstacle, with their
     * name and the reason: that is exactly what one needs to know before pressing.
     *
     * @param protectedNames          the packages locked now
     * @param reasonNotToUnlock receives the locked package that pkg named (name, version
     *                          and, if pkg says it, the version it would go to); returns null if
     *                          it can be unlocked, otherwise the reason
     */
    public static JSONObject planFor(List<String> packages, Set<String> protectedNames,
                                      Function<JSONObject, String> reasonNotToUnlock) {
        return planFor(packages, protectedNames, reasonNotToUnlock, n -> null);
    }

    /**
     * @param installedTwin receives the name of a package that the plan WOULD INSTALL and
     *                      returns the name of an ALREADY installed package of the
     *                      same family, or null. It is used to recognise when pkg is
     *                      working around a lock: see the loop in planWith.
     */
    public static JSONObject planFor(List<String> packages, Set<String> protectedNames,
                                      Function<JSONObject, String> reasonNotToUnlock,
                                      Function<String, String> installedTwin) {
        LinkedHashSet<String> unlock = new LinkedHashSet<>();
        for (String p : packages) if (protectedNames.contains(p)) unlock.add(p);
        return planWith(new Command("upgrade", packages, List.of()), unlock, protectedNames, reasonNotToUnlock, installedTwin, true);
    }

    /**
     * The plan of the full maintenance: everything pkg would upgrade, with 'toUnlock'
     * unlocked. Here a locked package that pkg names and that cannot be unlocked is not an
     * obstacle: it is one of those held back on purpose, pkg skips it and upgrades the rest. It
     * stays in the plan, with its reason, so that the reader knows what will NOT be upgraded.
     */
    public static JSONObject fullPlan(Set<String> toUnlock, Set<String> protectedNames,
                                         Function<JSONObject, String> reasonNotToUnlock) {
        return fullPlan(toUnlock, protectedNames, reasonNotToUnlock, n -> null);
    }

    public static JSONObject fullPlan(Set<String> toUnlock, Set<String> protectedNames,
                                         Function<JSONObject, String> reasonNotToUnlock,
                                         Function<String, String> installedTwin) {
        return planWith(new Command("upgrade", List.of(), List.of()), new LinkedHashSet<>(toUnlock), protectedNames,
                reasonNotToUnlock, installedTwin, false);
    }

    private static JSONObject planWith(Command cmd, LinkedHashSet<String> unlock, Set<String> protectedNames,
                                       Function<JSONObject, String> reasonNotToUnlock,
                                       Function<String, String> installedTwin, boolean blockersBlock) {
        List<String> packages = cmd.args();
        JSONObject plan = null;
        JSONArray blockers = new JSONArray();
        JSONArray unlockedFamily = new JSONArray();
        for (int round = 0; round < 6; round++) {
            plan = simulate(cmd, new ArrayList<>(unlock));
            if (!plan.optBoolean("success") || !plan.optBoolean("measured")) break;
            blockers = new JSONArray();
            boolean added = false;
            JSONArray bl = plan.getJSONArray("lockedPackages");
            for (int i = 0; i < bl.length(); i++) {
                JSONObject block = bl.getJSONObject(i);
                String n = block.getString("name");
                if (unlock.contains(n)) continue;
                String no = !protectedNames.contains(n)
                        ? I18n.tr("server.plan.lockedUnknown")
                        : reasonNotToUnlock.apply(block);
                if (no != null) { blockers.put(new JSONObject().put("name", n).put("reason", no)); continue; }
                unlock.add(n);
                added = true;
            }
            if (familyAddition(plan, unlock, protectedNames, installedTwin, blockers, unlockedFamily))
                added = true;
            if (!added) break;
        }
        plan.put("unlockedPackages", new JSONArray(new ArrayList<>(unlock))).put("blockers", blockers)
             .put("familyUnlocked", unlockedFamily);

        // The requested packages that the plan does NOT change: pkg would leave them where they are.
        JSONArray stopped = new JSONArray();
        JSONArray changes = plan.optJSONArray("changes");
        for (String p : packages) {
            boolean change = false;
            for (int i = 0; changes != null && i < changes.length(); i++)
                if (p.equals(changes.getJSONObject(i).optString("name"))) change = true;
            if (!change) stopped.put(p);
        }
        plan.put("unchangedPackages", stopped);

        // pkg upgrades itself first. In a real upgrade, if the catalogue has a more recent pkg,
        // pkg installs that one, relaunches itself and then does the rest; with -n it skips this
        // step, so the simulation does not show it. An "exact" plan that keeps quiet about a
        // package that will change is not exact: it is added at the top, goes into the
        // fingerprint and is verified.
        JSONObject before = plan.optBoolean("measured") ? pkgToUpdate() : null;
        if (before != null && changes != null) {
            boolean already = false;
            for (int i = 0; i < changes.length(); i++) if ("pkg".equals(changes.getJSONObject(i).optString("name"))) already = true;
            if (!already) {
                JSONArray withPkg = new JSONArray().put(entry("upgrade", "pkg", before.getString("from"), before.getString("to"),
                        I18n.tr("server.plan.pkgFirst"), "", false));
                for (int i = 0; i < changes.length(); i++) withPkg.put(changes.get(i));
                plan.put("changes", withPkg);
                changes = withPkg;
            }
        }

        boolean runnable = plan.optBoolean("success") && plan.optBoolean("measured")
                && (!blockersBlock || (blockers.isEmpty() && plan.optJSONArray("lockedPackages") != null
                                             && plan.getJSONArray("lockedPackages").length() == 0))
                && plan.getJSONArray("pkgErrors").length() == 0 && !plan.optBoolean("hasConflicts")
                && changes != null && changes.length() > 0
                // If none of the requested packages changes, there is nothing to execute: not even
                // if the plan contains pkg upgrading itself.
                && (packages.isEmpty() || stopped.length() < packages.size());
        return plan.put("runnable", runnable).put("signature", plan.optBoolean("measured") ? signature(plan) : "");
    }

    /**
     * An "install" that belongs to the same family as an ALREADY installed package is not
     * an addition: it is pkg working around a lock.
     *
     * For pkg a locked package is not "not to be changed": it is **not available**. If a
     * library that package provides is needed, the solver looks for another provider -- and
     * installs it, even if it fights over files with the one already there.
     *
     * Measured on the FreeBSD 15.1 VM on 2026-10-23. With mysql84-client locked, upgrading
     * postfix-mysql produced a plan with "install mysql97-client 9.7.2"; the two provide
     * the same libmysqlclient.so.24 and both claim /usr/local/bin/comp_err, so the
     * execution died halfway with "mysql97-client conflicts with mysql84-client
     * (installs files into the same place)", exit 3. Unlocking mysql84-client TOO, in the
     * same simulation mysql97-client **disappears from the plan**: pkg goes back to using
     * what is there. The plan told the truth about what pkg would have done; it was pkg that
     * had been blinded by the lock.
     *
     * We unlock only when the catalogue has the SAME version that is installed, that is when
     * unlocking cannot change anything: the purpose is to make pkg see what is already there,
     * not to upgrade it. If the catalogue has a more recent one, unlocking would be an
     * upgrade nobody asked for (and for the MySQL clients the warning says to wait): then
     * it is an obstacle, with its reason. And if the twin is not even locked, the lock has
     * nothing to do with it: it is a real conflict between two members of the family.
     *
     * @return true if it widened the list to unlock, that is, if the plan must be redone
     */
    private static boolean familyAddition(JSONObject plan, LinkedHashSet<String> unlock,
                                            Set<String> protectedNames, Function<String, String> installedTwin,
                                            JSONArray blockers, JSONArray unlockedFamily) {
        boolean added = false;
        JSONArray changes = plan.optJSONArray("changes");
        for (int i = 0; changes != null && i < changes.length(); i++) {
            JSONObject c = changes.getJSONObject(i);
            if (!"install".equals(c.optString("type"))) continue;
            String newName = c.optString("name");
            String twin = installedTwin == null ? null : installedTwin.apply(newName);
            if (twin == null || twin.equals(newName) || unlock.contains(twin)
                    || !isValidName(twin)) continue;
            if (alreadyBlocked(blockers, twin)) continue;
            if (!protectedNames.contains(twin)) {
                blockers.put(new JSONObject().put("name", newName)
                        .put("reason", I18n.tr("server.plan.familyConflict",
                                java.util.Map.of("newer", String.valueOf(newName), "twin", String.valueOf(twin)))));
                continue;
            }
            String installed = sh("pkg query %v " + twin + " 2>/dev/null", 20).trim();
            String catalog = "";
            for (String line : sh("pkg rquery -U %v " + twin + " 2>/dev/null", 30).split("\n")) {
                String x = line.trim();
                if (validVersion(x)) { catalog = x; break; }
            }
            if (!validVersion(installed) || !installed.equals(catalog)) {
                blockers.put(new JSONObject().put("name", twin)
                        .put("reason", I18n.tr("server.plan.familyLockedNewer",
                                java.util.Map.of("newer", String.valueOf(newName), "twin", String.valueOf(twin),
                                        "installed", String.valueOf(installed.isEmpty() ? "?" : installed),
                                        "catalog", String.valueOf(catalog.isEmpty() ? "?" : catalog)))));
                continue;
            }
            unlock.add(twin);
            unlockedFamily.put(new JSONObject().put("installed", twin).put("wouldInstall", newName)
                    .put("version", installed));
            added = true;
        }
        return added;
    }

    private static boolean alreadyBlocked(JSONArray blockers, String name) {
        for (int i = 0; i < blockers.length(); i++)
            if (name.equals(blockers.getJSONObject(i).optString("name"))) return true;
        return false;
    }

    /** The installed pkg and the catalogue's one, if the catalogue has a more recent one; otherwise null. */
    static JSONObject pkgToUpdate() {
        String from = sh("pkg query %v pkg 2>/dev/null", 30), to = "";
        for (String line : sh("pkg rquery -U %v pkg 2>/dev/null", 60).split("\n"))
            if (validVersion(line.trim())) { to = line.trim(); break; }
        if (!validVersion(from) || !validVersion(to)) return null;
        try {
            return pkgComparison().compare(to, from) > 0 ? new JSONObject().put("from", from).put("to", to) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The installed versions without the lock state: {@code name -> version}. */
    public static Map<String, String> versionsOnly(Map<String, String[]> installed) {
        Map<String, String> r = new java.util.TreeMap<>();
        if (installed != null)
            for (Map.Entry<String, String[]> e : installed.entrySet())
                if (e.getValue() != null && e.getValue().length > 0) r.put(e.getKey(), e.getValue()[0]);
        return r;
    }

    /**
     * What REALLY changed, compared with the signed plan.
     *
     * {@link #verifyOutcome} walks through the lines of the PLAN: it sees a package of the plan
     * that did not get where it should, and it cannot see a changed package that was not in
     * the plan. On 2026-10-18, on the VM, it happened: the signed plan (465385a9d669def8) had
     * ten changes and no removal; during the execution pkg found a conflict
     * (lmdb0 against lmdb on /usr/local/bin/mdb_copy), redid the computation and REMOVED
     * lmdb. The comparison checked its ten, found them all "ok" and concluded
     * "verification passed". The removal was in pkg's log and in no verdict.
     *
     * Here we look from the other direction: the inventory of the installed packages before
     * and after. Every difference the plan does not explain is a divergence. The plan's
     * signature exists to guarantee that what was shown is what gets executed, and on a mail
     * server an unexpected removal is precisely the case it must catch.
     *
     * A reinstallation leaves no trace in the inventory (same version) and so cannot
     * appear here: that case is covered by {@link #verifyOutcome}. The two checks are
     * complementary and both are needed.
     *
     * Pure function: it receives the two inventories and the plan, so it can be tested with real outputs.
     *
     * @return one entry per divergence: {@code name}, {@code happened}
     *         ("removed", "installed", "changed"), {@code from}, {@code to}, {@code why}
     */
    public static JSONArray divergences(Map<String, String> before, Map<String, String> after,
                                       JSONObject plan) {
        Map<String, String> a = before == null ? Map.of() : before;
        Map<String, String> b = after == null ? Map.of() : after;

        // The plan's lines by name. A name can appear only once: if it appeared twice the
        // plan would be ambiguous, and the first is kept because it is the one shown.
        Map<String, JSONObject> planned = new HashMap<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            planned.putIfAbsent(x.optString("name"), x);
        }

        Set<String> names = new java.util.TreeSet<>(a.keySet());
        names.addAll(b.keySet());
        JSONArray outside = new JSONArray();
        for (String name : names) {
            String versionA = a.get(name), versionB = b.get(name);
            String happened = versionA == null ? "installed" : versionB == null ? "removed"
                            : versionA.equals(versionB) ? null : "changed";
            if (happened == null) continue;   // nothing changed for this package

            JSONObject p = planned.get(name);
            if (p == null) {
                outside.put(divergenceEntry(name, happened, versionA, versionB,
                        I18n.tr("server.plan.d.notInPlan")));
                continue;
            }
            // It was in the plan: the type and the target version must match.
            String type = p.optString("type"), expected = p.optString("to");
            boolean matches = switch (happened) {
                case "removed" -> "remove".equals(type);
                case "installed" -> "install".equals(type) && expected.equals(versionB);
                default -> ("upgrade".equals(type) || "downgrade".equals(type)) && expected.equals(versionB);
            };
            if (matches) continue;
            outside.put(divergenceEntry(name, happened, versionA, versionB,
                    I18n.tr("server.plan.d.planSaid", java.util.Map.of(
                            "kind", String.valueOf(typeName(type)),
                            "expected", String.valueOf(expected.isEmpty() ? I18n.tr("server.plan.removed") : expected)))));
        }
        return outside;
    }

    private static JSONObject divergenceEntry(String name, String happened, String from, String a, String why) {
        return new JSONObject().put("name", name).put("happened", happened)
                .put("from", from == null ? "" : from).put("to", a == null ? "" : a)
                .put("why", why);
    }

    /** A divergence stated in one line, in the reader's language. */
    public static String divergenceInLine(JSONObject d) {
        String name = d.optString("name");
        String text = switch (d.optString("happened")) {
            case "removed" -> I18n.tr("server.plan.d.removed", java.util.Map.of("name", name, "version", String.valueOf(d.optString("from"))));
            case "installed" -> I18n.tr("server.plan.d.installed", java.util.Map.of("name", name, "version", String.valueOf(d.optString("to"))));
            default -> I18n.tr("server.plan.d.changed", java.util.Map.of("name", name,
                    "from", String.valueOf(d.optString("from")), "to", String.valueOf(d.optString("to"))));
        };
        return text + " — " + d.optString("why");
    }

    /**
     * After the real upgrade: is every package of the plan where the plan said?
     * One line per change, with what was expected and what is there.
     */
    public static JSONArray verifyOutcome(JSONObject plan) {
        JSONArray outcome = new JSONArray();
        JSONArray c = plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String name = x.optString("name");
            if (!isValidName(name)) continue;
            String now = sh("pkg query %v " + name + " 2>/dev/null", 30);
            String expected = "remove".equals(x.optString("type")) ? "" : x.optString("to");
            outcome.put(new JSONObject().put("name", name).put("type", x.optString("type"))
                    .put("expected", expected.isEmpty() ? I18n.tr("server.plan.removed") : expected)
                    .put("found", now.isEmpty() ? I18n.tr("server.plan.notInstalled") : now)
                    .put("ok", expected.equals(now)));
        }
        return outcome;
    }

    // ===================== is the fix there? =====================

    /** Comparison of two versions, with pkg's rules. Negative, zero or positive. */
    public interface VersionComparator { int compare(String a, String b); }

    /** Only plausible versions: they end up in a command line. */
    static boolean validVersion(String v) {
        return v != null && v.matches("[A-Za-z0-9._,+~]{1,64}");
    }

    /**
     * The comparison is done by pkg itself ({@code pkg version -t}), not by a copy of its rules:
     * epoch after the comma, port revision after the underscore, "p", "a", "b", "rc".
     * Rewriting them here would mean getting them wrong in the case that matters. The answers are
     * remembered: the same comparison is not asked twice.
     */
    public static VersionComparator pkgComparison() {
        Map<String, Integer> already = new HashMap<>();
        return (a, b) -> {
            if (!validVersion(a) || !validVersion(b))
                throw new IllegalArgumentException("version not comparable: " + a + " / " + b);
            return already.computeIfAbsent(a + " " + b, k -> {
                String o = sh("pkg version -t '" + a + "' '" + b + "'", 15);
                return switch (o) {
                    case "<" -> -1;
                    case "=" -> 0;
                    case ">" -> 1;
                    default -> throw new IllegalStateException("pkg version -t answered \"" + o + "\"");
                };
            });
        };
    }

    /** One end of a VuXML range, as pkg writes it: operator and version. */
    record Bound(String op, String version) {}

    private static final Pattern BOUND = Pattern.compile("^(<=|>=|<|>|=)\\s*(\\S+)$");

    /** "&gt;= 1.25.0 : &lt; 1.30.5,3" becomes two ends; "&lt; 1.30.5,3" just one. */
    static List<Bound> bounds(String interval) {
        List<Bound> r = new ArrayList<>();
        for (String part : interval.split(":")) {
            Matcher m = BOUND.matcher(part.trim());
            if (m.find()) r.add(new Bound(m.group(1), m.group(2)));
        }
        return r;
    }

    static boolean inside(String v, List<Bound> es, VersionComparator c) {
        if (es.isEmpty()) return false;
        for (Bound e : es) {
            int x = c.compare(v, e.version());
            boolean ok = switch (e.op()) {
                case "<" -> x < 0;
                case "<=" -> x <= 0;
                case ">" -> x > 0;
                case ">=" -> x >= 0;
                case "=" -> x == 0;
                default -> false;
            };
            if (!ok) return false;
        }
        return true;
    }

    private static boolean insideAny(String v, JSONArray ranges, VersionComparator c) {
        for (int i = 0; ranges != null && i < ranges.length(); i++)
            if (inside(v, bounds(ranges.getString(i)), c)) return true;
        return false;
    }

    /**
     * {@code pkg audit -Rjson} reduced to what is needed: for each package the version and the
     * problems, each with the ranges of vulnerable versions.
     *
     * Beware of the option's form: it is {@code -Rjson}, joined. With {@code -R json}
     * pkg takes "json" for the name of a package and produces another format.
     */
    static JSONObject readAudit(String json) {
        JSONObject outside = new JSONObject();
        int g = json == null ? -1 : json.indexOf('{');
        if (g < 0) return outside;
        JSONObject top = new JSONObject(json.substring(g));
        JSONObject pk = top.optJSONObject("packages");
        if (pk == null) return outside;
        for (String name : pk.keySet()) {
            JSONObject p = pk.getJSONObject(name);
            JSONArray issues = new JSONArray();
            JSONArray is = p.optJSONArray("issues");
            for (int i = 0; is != null && i < is.length(); i++) {
                JSONObject x = is.getJSONObject(i);
                issues.put(new JSONObject()
                        .put("ranges", x.optJSONArray("Affected versions") == null ? new JSONArray()
                                : x.getJSONArray("Affected versions"))
                        .put("description", x.optString("description", ""))
                        .put("cve", x.optJSONArray("cve") == null ? new JSONArray() : x.getJSONArray("cve"))
                        .put("url", x.optString("url", "")));
            }
            outside.put(name, new JSONObject().put("version", p.optString("version", "")).put("issues", issues));
        }
        return outside;
    }

    /**
     * The answer to "is the fix there?" for a package: the installed version, the one the
     * catalogue offers, and the VuXML ranges of each problem.
     *
     * Verdicts, from best to worst:
     *  - "fixed-by-upgrade": the catalogue has a more recent version that VuXML does not
     *    consider vulnerable for any of the problems;
     *  - "upgrade-not-enough": the catalogue has a more recent version, but for at least one
     *    problem it is still vulnerable;
     *  - "fix-outside-branch": the catalogue goes no further, but VuXML states from which
     *    version the problem is fixed -- the fix exists, it is not in your branch yet;
     *  - "fix-not-stated": vulnerable up to a version included, without saying the first
     *    fixed one;
     *  - "no-fix": VuXML sets no upper limit, that is, no published version
     *    is fixed;
     *  - "unknown": a range cannot be read or the comparison did not answer.
     */
    static JSONObject assessFix(String installed, String catalog, JSONArray issues, VersionComparator c) {
        JSONObject r = new JSONObject().put("installedVersion", installed).put("catalog", catalog == null ? "" : catalog);
        try {
            boolean newerCatalog = catalog != null && !catalog.isEmpty() && c.compare(catalog, installed) > 0;
            JSONArray details = new JSONArray();
            String firstFixed = null;          // the highest among the first fixed versions
            String upTo = null;                  // a "<=": vulnerable up to and including this one
            boolean withoutLimit = false, unreadable = false, onlyThis = false;
            List<String> stillOpenInCatalog = new ArrayList<>();
            for (int i = 0; issues != null && i < issues.length(); i++) {
                JSONObject p = issues.getJSONObject(i);
                JSONArray ranges = p.optJSONArray("ranges");
                List<Bound> its = null;
                for (int k = 0; ranges != null && k < ranges.length(); k++) {
                    List<Bound> es = bounds(ranges.getString(k));
                    if (inside(installed, es, c)) { its = es; break; }
                }
                JSONObject d = new JSONObject().put("description", p.optString("description"))
                        .put("cve", p.optJSONArray("cve")).put("url", p.optString("url"))
                        .put("ranges", ranges);
                if (its == null) {
                    unreadable = true;
                    d.put("type", "unknown");
                } else {
                    Bound upperBound = null;
                    boolean exact = false;
                    for (Bound e : its) {
                        if (e.op().equals("<") || e.op().equals("<=")) upperBound = e;
                        if (e.op().equals("=")) exact = true;
                    }
                    if (exact) {
                        onlyThis = true;
                        d.put("type", "this-version-only");
                    } else if (upperBound == null) {
                        withoutLimit = true;
                        d.put("type", "no-upper-bound");
                    } else if (upperBound.op().equals("<")) {
                        d.put("type", "fixed-in").put("firstFixed", upperBound.version());
                        if (firstFixed == null || c.compare(upperBound.version(), firstFixed) > 0) firstFixed = upperBound.version();
                    } else {
                        d.put("type", "vulnerable-up-to").put("upTo", upperBound.version());
                        upTo = upperBound.version();
                    }
                }
                if (newerCatalog && insideAny(catalog, ranges, c)) {
                    stillOpenInCatalog.add(p.optString("description"));
                    d.put("openInCatalog", true);
                }
                details.put(d);
            }
            r.put("issues", details);
            if (firstFixed != null) r.put("firstFixed", firstFixed);

            String verdict, explain;
            if (unreadable) {
                verdict = "unknown";
                explain = I18n.tr("server.plan.v.unknownRange");
            } else if (newerCatalog && stillOpenInCatalog.isEmpty()) {
                verdict = "fixed-by-upgrade";
                explain = I18n.tr("server.plan.v.fixedByUpgrade", java.util.Map.of("v", String.valueOf(catalog)));
            } else if (newerCatalog) {
                verdict = "upgrade-not-enough";
                explain = I18n.tr("server.plan.v.upgradeNotEnough", java.util.Map.of("v", String.valueOf(catalog), "list", String.valueOf(String.join("; ", stillOpenInCatalog))))
                        + (firstFixed != null ? " " + I18n.tr("server.plan.v.fixedFrom", java.util.Map.of("v", String.valueOf(firstFixed))) : "");
            } else if (withoutLimit) {
                verdict = "no-fix";
                explain = I18n.tr("server.plan.v.noFix");
            } else if (upTo != null && firstFixed == null) {
                verdict = "fix-not-stated";
                explain = I18n.tr("server.plan.v.fixNotStated", java.util.Map.of("upTo", String.valueOf(upTo), "cat", String.valueOf(emptyIf(catalog, installed))));
            } else if (onlyThis && firstFixed == null) {
                verdict = "fix-outside-branch";
                explain = I18n.tr("server.plan.v.onlyThis", java.util.Map.of("v", String.valueOf(installed)));
            } else if (firstFixed != null) {
                verdict = "fix-outside-branch";
                explain = I18n.tr("server.plan.v.fixOutsideBranch", java.util.Map.of("fixed", String.valueOf(firstFixed), "cat", String.valueOf(emptyIf(catalog, installed))));
            } else {
                verdict = "unknown";
                explain = I18n.tr("server.plan.v.noComparable");
            }
            return r.put("verdict", verdict).put("explanation", explain);
        } catch (RuntimeException e) {
            return r.put("verdict", "unknown").put("explanation", I18n.tr("server.plan.v.compareFailed", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("PackagePlan", e))));
        }
    }

    private static String emptyIf(String catalog, String installed) {
        return catalog == null || catalog.isEmpty() ? installed + " " + I18n.tr("server.plan.noNewer") : catalog;
    }

    /**
     * For each vulnerable package: whether and where the fix exists. It reads the vulnerability
     * database already downloaded (the caller decides whether to download it again first) and the catalogue.
     */
    public static JSONObject fixes() {
        Shell.Result a = Shell.runShell(Duration.ofSeconds(180), "pkg audit -Rjson 2>/dev/null");
        // pkg audit exits with 0 without vulnerabilities and with a different code when it finds some:
        // what matters is whether the JSON is there, not the code.
        String out = a.output();
        if (out == null || out.indexOf('{') < 0)
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.plan.auditUnreadable", java.util.Map.of("c", String.valueOf(a.exitCode()))));
        JSONObject vuln;
        try { vuln = readAudit(out); }
        catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.plan.auditJson", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("PackagePlan", e))));
        }
        VersionComparator c = pkgComparison();
        JSONObject per = new JSONObject();
        for (String name : vuln.keySet()) {
            if (!isValidName(name)) continue;
            JSONObject v = vuln.getJSONObject(name);
            String catalog = "";
            for (String line : sh("pkg rquery -U %v " + name + " 2>/dev/null", 60).split("\n")) {
                String x = line.trim();
                if (!validVersion(x)) continue;
                try { if (catalog.isEmpty() || c.compare(x, catalog) > 0) catalog = x; }
                catch (RuntimeException ignore) { /* the one that was there stays */ }
            }
            per.put(name, assessFix(v.getString("version"), catalog, v.getJSONArray("issues"), c));
        }
        return new JSONObject().put("success", true).put("packages", per);
    }

    // ===================== utilita' =====================

    // ===================== the package overview =====================

    private static final Pattern TO_UPDATE = Pattern.compile("^(\\S+)-([^\\s-]+)\\s+<\\s.*\\(remote has ([^)]+)\\)\\s*$");

    /**
     * The "<" lines of {@code pkg version -U -vRL=}: name -> catalogue version. The others
     * ("?" not in the catalogue, ">" newer than the catalogue, "!" not comparable) are not
     * available upgrades and are left out.
     */
    public static Map<String, String> toUpdate(String output) {
        Map<String, String> r = new java.util.TreeMap<>();
        for (String line : (output == null ? "" : output).split("\n")) {
            Matcher m = TO_UPDATE.matcher(line.trim());
            if (m.find() && isValidName(m.group(1)) && validVersion(m.group(3))) r.put(m.group(1), m.group(3));
        }
        return r;
    }

    /** From {@code pkg query '%n\t%v\t%k'}: name -> {version, "1" if locked}. */
    public static Map<String, String[]> installed(String output) {
        Map<String, String[]> r = new java.util.TreeMap<>();
        for (String line : (output == null ? "" : output).split("\n")) {
            String[] c = line.split("\t");
            if (c.length == 3 && isValidName(c[0].trim()) && validVersion(c[1].trim()))
                r.put(c[0].trim(), new String[]{c[1].trim(), c[2].trim()});
        }
        return r;
    }

    /** The installed packages, read now. */
    public static Map<String, String[]> installed() {
        return installed(Shell.runShell(Duration.ofSeconds(60), "pkg query '%n\t%v\t%k' 2>/dev/null").output());
    }

    /** The upgrades available in the catalogue already downloaded: -U, no network. */
    public static Shell.Result readToUpdate() {
        return Shell.runShell(Duration.ofSeconds(180), "pkg version -U -vRL= 2>&1");
    }

    private static JSONObject failed(String error) {
        return new JSONObject().put("success", false).put("measured", false).put("error", error)
                .put("changes", new JSONArray()).put("lockedPackages", new JSONArray()).put("pkgErrors", new JSONArray());
    }

    private static long number(String s) {
        try { return Long.parseLong(s.trim().split("\\s+")[0]); } catch (Exception e) { return -1; }
    }
}
