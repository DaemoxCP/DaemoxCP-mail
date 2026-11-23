package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.ErrorText;
import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Package protection, updates and vulnerabilities for the mail stack.
 *
 * The point of this class is not "to show that there are updates": pkg already does
 * that. The point is to answer the question that pkg CANNOT ask itself -- does *this*
 * update break *this* mail server? -- and to physically prevent the ones that
 * would break it.
 *
 * The case that motivated all of it: the panel generates the Dovecot configuration with
 * the 2.3 syntax (mail_location, passdb/userdb without a name, variables %u %d %n).
 * Dovecot 2.4 does not degrade on that configuration: it REFUSES to start. A trivial
 * "pkg upgrade" would stop the mail, and no version number would say so.
 */
public final class UpdateManager {

    private static final Logger LOGGER = Logger.getLogger(UpdateManager.class.getName());

    static {
        // Every job that takes the package turn records what packages and services were like at the start: if it
        // dies halfway, the panel in service knows what it changed and completes it (InterruptedJobRecovery).
        PackageQueue.snapshot = UpdateManager::jobSnapshot;
    }

    /** The installed packages (name -> version) and the services running now: the snapshot at the start of a job. */
    static JSONObject jobSnapshot() {
        JSONObject inv = new JSONObject();
        for (Map.Entry<String, String> e : PackagePlan.versionsOnly(PackagePlan.installed()).entrySet()) inv.put(e.getKey(), e.getValue());
        JSONObject svc = new JSONObject();
        for (Map.Entry<String, Boolean> e : servicesState().entrySet()) svc.put(e.getKey(), e.getValue());
        return new JSONObject().put("inventory", inv).put("services", svc);
    }
    private static final Map<String, Job> JOBS = new ConcurrentHashMap<>();

    /** List of the packages unlocked during a maintenance, to put them back in place after a crash. */
    private static final String MAINTENANCE_STATE = PackageQueue.STATE_PATH;

    private UpdateManager() {}

    // ===================== running commands =====================

    /** Shell command, full output. Explicit timeout: a pkg that does not return would block an HTTP thread. */
    private static String sh(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).outputTrim();
    }

    private static String sh(String cmd) { return sh(cmd, 60); }

    private static boolean ok(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).success();
    }

    private static boolean ok(String cmd) { return ok(cmd, 30); }

    /**
     * A package name ends up inside a command line: only plausible names are
     * accepted. It is not theory -- "roundcube-php84" and "py311-fail2ban" contain digits
     * and hyphens, so the rule must be precise without being permissive.
     */
    public static boolean isValidName(String n) {
        // The first character a letter or a digit: the name ends up in pkg and service commands, and one that
        // starts with a hyphen would become one of their options. No FreeBSD package or service starts that way
        // (finding 205).
        return n != null && n.matches("[A-Za-z0-9][A-Za-z0-9._+-]{0,63}");
    }

    /**
     * A package counts as locked only if it appears as a WHOLE LINE in `pkg lock -l`.
     * With a naive contains(), "curl" would match inside "php84-curl-8.4.19" and the
     * panel would declare locked a package that is not.
     */
    private static boolean locked(String lockList, String name) {
        for (String line : lockList.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.endsWith(":")) continue;   // "Currently locked packages:"
            if (t.equals(name)) return true;
            // In "name-version" there is ONLY ONE cut: the last hyphen, and what follows
            // must be a version, that is, start with a digit. Trying every hyphen,
            // "php84-curl-8.4.24" also produced the prefix "php84", and the panel
            // declared php84 locked because of one of its extensions. FreeBSD port
            // versions contain no hyphens (8.4.24, 1.7.2,1, 1.1.0_8, 25.0.3+9.f.1),
            // so a single cut is enough and is exact.
            int d = t.lastIndexOf('-');
            if (d > 0 && d + 1 < t.length() && Character.isDigit(t.charAt(d + 1))
                    && t.substring(0, d).equals(name)) return true;
        }
        return false;
    }

    // ===================== which packages concern mail =====================

    /**
     * Packages are RECOGNIZED, not listed. Hard-coding "mysql80-server" or "php84"
     * means having to rewrite this class at the first version change -- and that is
     * exactly the mistake that this panel's installation scripts already
     * contain. Here we start from what is actually installed and classify it.
     */
    private static final String[][] ROLES = {
        {"^postfix(-.*)?$",            "SMTP (Postfix)"},
        // With the port flavors: dovecot-mysql IS Dovecot, not one of its components, and it is the
        // package the installation puts in. The same for dovecot24-mysql of 2.4.
        {"^dovecot[0-9]*(-(mysql|pgsql|sqlite3|ldap|cdb))?$", "IMAP/POP3 (Dovecot)"},
        {"^dovecot[0-9]*-pigeonhole(-.*)?$", "server.um.role.sieve"},
        {"^dovecot[0-9]*-.*$",         "server.um.role.dovecotPart"},
        {"^rspamd$",                   "server.um.role.rspamd"},
        {"^redis(-.*)?$",              "server.um.locked.1"},
        {"^clamav(-.*)?$",             "Antivirus"},
        {"^roundcube(-php[0-9]+)?$",   "Webmail (Roundcube)"},
        {"^nginx(-.*)?$",              "server.um.locked.2"},
        {"^php[0-9]+$",                "PHP"},
        {"^php[0-9]+-.+$",             "server.um.role.phpExt"},
        {"^mysql[0-9]+-server$",       "Database (server)"},
        {"^mysql[0-9]+-client$",       "Database (client)"},
        {"^py[0-9]+-fail2ban$",        "server.um.role.fail2ban"},
        {"^(py[0-9]+-)?certbot$",      "server.um.locked.3"},
        {"^unbound$",                  "server.um.role.unbound"},
        {"^opendkim$",                 "server.um.role.opendkim"},
        {"^openssl[0-9]*$",            "server.um.role.openssl"},
        {"^openjdk[0-9]*$",            "server.um.locked.4"},
    };

    /** Role of the package in the mail stack, or null if it does not concern it. */
    private static String roleOf(String name) {
        for (String[] r : ROLES) if (name.matches(r[0])) return I18n.tr(r[1]);
        return null;
    }

    /**
     * Services that this panel manages. Each row lists the POSSIBLE names of the same
     * service, because the rc.d script can be called in different ways: PHP-FPM is "php_fpm"
     * (with the underscore, as the rest of the panel calls it) and the resolver can be
     * "unbound" from the port or "local_unbound" from the base system.
     *
     * It is not a detail: a wrong name does not produce an error, it produces a SILENCE. The
     * service simply does not appear among the checked ones, and an update that
     * stopped it would be declared successful. It happened: php-fpm with the hyphen was never
     * found, so the webmail was not watched at all.
     */
    public static final String[][] SERVICES = {
        {"postfix"}, {"dovecot"}, {"rspamd"}, {"redis"},
        // Both spellings: the panel itself, in Main.java, tries "clamav_clamd" and then
        // "clamav-clamd", a sign that the name of the rc.d script changes between port versions.
        {"clamav_clamd", "clamav-clamd"}, {"clamav_freshclam", "clamav-freshclam"},
        {"mysql-server"}, {"nginx"},
        {"php_fpm", "php-fpm"},
        {"fail2ban"},
        {"unbound", "local_unbound"},
        // pf and ntpd belong to the base system and pkg does not update them, but if they were running
        // before and are not afterwards something happened anyway, and it is worth noticing:
        // without a firewall the server is exposed, without the right time DKIM and TLS break.
        {"pf"},
        {"ntpd"},
        // They are NOT added, and the reason must be written down because they look like omissions:
        //  - sendmail: the panel STOPS it on purpose, it conflicts with Postfix. Putting it
        //    here would mean declaring a correct state broken.
        //  - roundcube: it is not a daemon, there is no rc.d script at all. The reference to
        //    "service roundcube" elsewhere in the panel is most likely a mistake.
    };

    /**
     * What became of the services, compared with how they were BEFORE the job.
     *
     * "Not running now" does not mean "crashed". On this machine local_unbound is not
     * even enabled and ntpd does not start: a check that looks only at the present declares
     * EVERY update broken. Measured on the FreeBSD 15.1 VM on 2026-10-23: a guided
     * nginx update that succeeded in every single step -- plan followed, service
     * restarted, pid changed, package locked again -- ended in "error" with "a service
     * did not restart as it should", for two services that were not running even
     * before.
     *
     * An alarm that always rings teaches people to ignore it, and when it rings for real nobody
     * tells it apart. That it was not running even before is said anyway: it is something
     * to know, not a failure of this job.
     *
     * It lives in one place only because four jobs ask for it (maintenance, guided
     * update, update of the unlocked packages, MySQL migration) and the same decision
     * written four times became four different decisions: one right and three wrong.
     *
     * @param before the state of the services at the start of the job, from {@link #servicesState()}
     * @return true if at least one service that was running is no longer running now
     */
    private static boolean fallenServices(Job job, Map<String, Boolean> before) {
        return fallenServices(job, before, servicesState());
    }

    /** The comparison itself, without asking the system anything: that way it can be tested. */
    static boolean fallenServices(Job job, Map<String, Boolean> before, Map<String, Boolean> now) {
        java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<>(before.keySet());
        names.addAll(now.keySet());   // a service that appeared with the update is visible
        boolean fallen = false;
        for (String s : names) {
            boolean wasActive = Boolean.TRUE.equals(before.get(s));
            boolean active = Boolean.TRUE.equals(now.get(s));
            if (wasActive && !active) {
                fallen = true;
                job.write(I18n.tr("server.um.runMaintenanceJob.21", java.util.Map.of("key", String.valueOf(s))));
                continue;
            }
            job.write("    " + s + ": "
                    + (active ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMaintenanceJob.22"))
                    + (!active && !wasActive ? I18n.tr("server.um.runMaintenanceJob.23") : ""));
        }
        return fallen;
    }

    /** Which services are running now. Only those actually present on the system. */
    static Map<String, Boolean> servicesState() {
        Map<String, Boolean> m = new LinkedHashMap<>();
        for (String[] candidates : SERVICES) {
            // A service that is not installed has not "crashed": it must be told apart, otherwise
            // the final check would report as broken something that was never there. Presence
            // is decided by the rc.d script, not by the result of "status": that is non-zero
            // both for a stopped service and for a nonexistent one, and would mix up the two.
            for (String s : candidates) {
                if (!isValidName(s)) continue;
                if (!ok("test -f /usr/local/etc/rc.d/" + s + " -o -f /etc/rc.d/" + s, 10)) continue;
                m.put(s, ok("service " + s + " status", 15));
                break;   // found the right name: the others are the same service
            }
        }
        return m;
    }

    public static JSONObject packagesStatus() {
        JSONObject r = new JSONObject();
        String lock = sh("pkg lock -l 2>/dev/null");

        // Name and version of ALL packages in a single query: querying them one by one
        // would mean dozens of fork+exec at every click.
        Map<String, String> versions = new LinkedHashMap<>();
        for (String line : sh("pkg query '%n %v' 2>/dev/null", 30).split("\n")) {
            int sp = line.indexOf(' ');
            if (sp > 0) versions.put(line.substring(0, sp).trim(), line.substring(sp + 1).trim());
        }

        JSONArray arr = new JSONArray();
        int protectedNames = 0, totals = 0;
        for (Map.Entry<String, String> e : versions.entrySet()) {
            String name = e.getKey();
            if (!isValidName(name)) continue;
            String role = roleOf(name);
            if (role == null) continue;
            boolean lk = locked(lock, name);
            totals++;
            if (lk) protectedNames++;
            arr.put(new JSONObject()
                    .put("name", name).put("role", role)
                    .put("version", e.getValue()).put("locked", lk).put("installed", true));
        }
        r.put("success", true).put("packages", arr)
         .put("installedCount", totals).put("lockedCount", protectedNames);
        return r;
    }

    /**
     * Locks or unlocks the packages. Waits for the package turn: changing the locks
     * while a job has removed them and must put them back would corrupt its restore.
     * With the list of an interrupted job on disk, instead, it may: putting the locks back is
     * exactly the remedy.
     */
    public static JSONObject packagesLock(boolean lock, String onlyThis) {
        String id = "lock-" + System.nanoTime();
        String refusal = PackageQueue.takeForLocks(id, I18n.tr("server.um.packagesLock.1"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        try {
            JSONObject outcome = changeLocks(lock, onlyThis);
            // The trace on the machine states how things are now: if an administrator unlocks
            // from the panel, neither the note nor the annotation must keep calling it locked.
            refreshLockTrace();
            return outcome;
        }
        finally { PackageQueue.release(id); }
    }

    private static JSONObject changeLocks(boolean lock, String onlyThis) {
        if (!onlyThis.isEmpty() && !isValidName(onlyThis)) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
        }
        StringBuilder log = new StringBuilder();
        int changedCount = 0;
        boolean found = false;
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            String name = p.getString("name");
            if (!onlyThis.isEmpty() && !onlyThis.equals(name)) continue;
            found = true;
            if (p.getBoolean("locked") == lock) {
                log.append("  ").append(name).append(": ").append(I18n.tr("server.um.x.lockAlready")).append("\n");
                continue;
            }
            boolean done = ok("pkg " + (lock ? "lock" : "unlock") + " -y " + name);
            log.append("  ").append(name).append(": ")
               .append(done ? (lock ? I18n.tr("server.um.x.lockDone") : I18n.tr("server.um.x.unlockDone")) : I18n.tr("server.um.x.lockFailed")).append("\n");
            if (done) { changedCount++; rememberUnlock(name, !lock); }
        }
        // A package that is not part of the stack (a vulnerable dependency, one locked by hand):
        // the packages table shows it with its button, so it is locked or unlocked like the others.
        if (!onlyThis.isEmpty() && !found) {
            String[] iv = PackagePlan.installed().get(onlyThis);
            if (iv == null) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.ov.notInstalled", java.util.Map.of("name", onlyThis)));
            if ("1".equals(iv[1]) == lock) log.append("  ").append(onlyThis).append(": ").append(I18n.tr("server.um.x.lockAlready")).append("\n");
            else {
                boolean done = ok("pkg " + (lock ? "lock" : "unlock") + " -y " + onlyThis);
                log.append("  ").append(onlyThis).append(": ")
                   .append(done ? (lock ? I18n.tr("server.um.x.lockDone") : I18n.tr("server.um.x.unlockDone")) : I18n.tr("server.um.x.lockFailed")).append("\n");
                if (done) { changedCount++; rememberUnlock(onlyThis, !lock); }
            }
        }
        return new JSONObject().put("success", true).put("changed", changedCount).put("output", log.toString());
    }

    // ===================== the locking rule =====================

    /**
     * The mail stack packages stay locked: that is how a pkg upgrade, from here or from
     * SSH, does not replace them without the checks of the guided update. The only exceptions
     * are those an administrator unlocked with the panel: that choice is remembered
     * (setting pkg.unlocked_by_admin) and respected.
     */
    static final String UNLOCKED_BY_HAND = "pkg.unlocked_by_admin";

    static Set<String> unlockedByHand() {
        Set<String> r = new TreeSet<>();
        if (org.daemoxcp.mail.Main.mailDatabase == null) return r;
        for (String n : org.daemoxcp.mail.Main.mailDatabase.getSetting(UNLOCKED_BY_HAND, "").split(","))
            if (isValidName(n.trim())) r.add(n.trim());
        return r;
    }

    /** Remembers (or forgets) that an administrator unlocked this package on purpose. */
    static synchronized void rememberUnlock(String name, boolean unlocked) {
        if (org.daemoxcp.mail.Main.mailDatabase == null) return;
        Set<String> r = unlockedByHand();
        if (unlocked) r.add(name); else r.remove(name);
        if (r.isEmpty()) org.daemoxcp.mail.Main.mailDatabase.deleteSetting(UNLOCKED_BY_HAND);
        else org.daemoxcp.mail.Main.mailDatabase.setSetting(UNLOCKED_BY_HAND, String.join(",", r));
    }

    /**
     * At startup: locks every installed stack package that is not locked, except those
     * unlocked on purpose by an administrator. Does nothing if there is the state of an
     * interrupted job (that must be restored first) or if the panel database does not respond:
     * without the list of the intended unlocks it would lock those too.
     */
    public static String applyLockPolicy() {
        if (PackageQueue.statePresent() || org.daemoxcp.mail.Main.mailDatabase == null) return "";
        // This one too runs at the startup of every process: if another panel is working on the
        // packages, the locks it removed are its own (finding 147). For example the complete
        // reinstallation from the menu, which unlocked them on purpose: locking them now would
        // stop its pkg halfway (finding 154). It is said in the log: by returning "" as when there
        // is nothing to do, whoever read the service log did not know the rule had been skipped.
        String refusal = PackageQueue.takeForLocks("startup-lock-policy", I18n.tr("server.recovery.turnLockPolicy"));
        if (refusal != null) {
            // The caller prints it in the service log: in English, with who holds the turn, not with the
            // translated reason (EnglishLogsTest).
            String msg = "Package lock rule not applied at this start (it is applied at the next one): the package turn is held by "
                    + PackageQueue.holderForLog();
            LOGGER.info(msg);
            return msg;
        }
        try {
            // With the turn in hand, look again: a job's list may have appeared between the
            // first look and the turn, and then that one must be restored first.
            if (PackageQueue.statePresent()) return "";
            return applyLockPolicyOnTurn();
        }
        finally { PackageQueue.release("startup-lock-policy"); }
    }

    private static String applyLockPolicyOnTurn() {
        Set<String> unlockedByHand = unlockedByHand();
        List<String> lockedPackages = new ArrayList<>(), failed = new ArrayList<>();
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            String n = p.getString("name");
            if (p.getBoolean("locked") || unlockedByHand.contains(n) || !isValidName(n)) continue;
            if (ok("pkg lock -y " + n)) lockedPackages.add(n); else failed.add(n);
        }
        // The trace is brought back up to date at every startup, even when there was nothing to lock:
        // it states how things are NOW, and a trace that falls behind is worse than no trace at all.
        // It is also the point that repairs what fell behind outside the panel: the script
        // that updates Java locks again with pkg lock and then restarts the panel.
        refreshLockTrace();
        if (lockedPackages.isEmpty() && failed.isEmpty()) return "";
        String msg = "Mail stack packages locked at startup: " + (lockedPackages.isEmpty() ? "none" : String.join(", ", lockedPackages))
                + (failed.isEmpty() ? "" : "; could not lock: " + String.join(", ", failed));
        LOGGER.info(msg);
        return msg;
    }

    // ===================== the lock trace on the machine =====================

    /**
     * Where the panel explains, on the machine, why those packages are locked.
     *
     * The lock does not expire and nobody removes it at shutdown: it is the rule, and it is right
     * as long as the panel is there. But if the panel is uninstalled, or simply never starts
     * again, those packages stay locked forever -- and a locked package does not even
     * receive security fixes.
     *
     * Who would notice? Measured on the FreeBSD 15.1 VM on 2026-10-23, with 40 packages
     * locked: `pkg upgrade` names the locked ones in a passing line, does not put them in the
     * summary and ends with exit status ZERO. From the system one cannot tell who locked them,
     * nor why, nor how to free them: `pkg lock -l` lists the names and nothing else.
     *
     * This file is the answer to those three questions, and it outlives the panel.
     */
    static final String LOCK_NOTE = "/var/db/daemoxcp-mail/locked-packages.txt";

    /** Where the note lives. It is a variable only so that the tests do not write in /var/db. */
    static Path lockNotePath = Paths.get(LOCK_NOTE);

    /** The command that frees everything, written in one place only because it appears in several texts. */
    static final String UNLOCK_ALL_COMMAND = "pkg unlock -a -y";

    /**
     * The text of the note. Pure function: it receives the list and the moment, so it can be tested.
     *
     * In Italian like the comments of the other files the panel generates on the machine
     * (the pkg branch override, the fail2ban filter, the permaban list): it is read by whoever
     * administers the server, not by the program. Always in the panel's original language, never in
     * that of whoever triggered the write: the note is rewritten also inside the jobs
     * started from the pages, and it would change language depending on who clicked. The signature
     * in English, as in all of them (PanelMarker).
     */
    static String lockNoteText(java.util.Collection<String> locked, String when) {
        return lockNoteText(locked, when, I18n.SOURCE_LANGUAGE);
    }

    /**
     * The note in a given language. The texts live in the language files (server.lockNote.*, r11);
     * each paragraph is split here into comment lines, so a translation cannot break the
     * format: outside the comments only the package names remain, which is what gets read.
     */
    static String lockNoteText(java.util.Collection<String> locked, String when, String lang) {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(PanelMarker.WRITTEN).append(" on ").append(when).append(" (UTC).\n");
        noteComment(sb, I18n.t(lang, "server.lockNote.title"));
        sb.append("#\n");
        noteComment(sb, I18n.t(lang, "server.lockNote.why"));
        sb.append("#\n");
        noteComment(sb, I18n.t(lang, "server.lockNote.how"));
        sb.append("#\n");
        noteComment(sb, I18n.t(lang, "server.lockNote.warning"));
        sb.append("#\n");
        sb.append("#     ").append(UNLOCK_ALL_COMMAND).append("\n");
        sb.append("#\n");
        noteComment(sb, I18n.t(lang, "server.lockNote.single"));
        noteComment(sb, I18n.t(lang, "server.lockNote.state"));
        sb.append("\n");
        if (locked.isEmpty()) noteComment(sb, I18n.t(lang, "server.lockNote.none"));
        for (String n : locked) sb.append(n).append('\n');
        return sb.toString();
    }

    /** A paragraph as "# " lines of at most 84 columns, broken between words. */
    private static void noteComment(StringBuilder sb, String text) {
        StringBuilder line = new StringBuilder();
        for (String word : text.trim().split("\\s+")) {
            if (line.length() > 0 && line.length() + 1 + word.length() > 82) {
                sb.append("# ").append(line).append('\n');
                line.setLength(0);
            }
            if (line.length() > 0) line.append(' ');
            line.append(word);
        }
        if (line.length() > 0) sb.append("# ").append(line).append('\n');
    }

    /**
     * Writes the note with the packages locked NOW. If there are none, it deletes it:
     * a note listing locks that no longer exist would send people looking for a problem
     * that is not there.
     */
    static synchronized void writeLockNote() {
        try {
            Set<String> locked = new TreeSet<>();
            for (String n : lockedNames()) if (roleOf(n) != null) locked.add(n);
            Path f = lockNotePath;
            if (locked.isEmpty()) { Files.deleteIfExists(f); return; }
            if (f.getParent() != null) Files.createDirectories(f.getParent());
            String when = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
            // Atomic write: a file read halfway by someone investigating a stopped server
            // would be a way to go wrong precisely at the worst moment.
            Path tmp = f.resolveSibling(f.getFileName() + ".tmp");
            Files.writeString(tmp, lockNoteText(locked, when), StandardCharsets.UTF_8);
            Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            // The note is an explanation, not a mechanism: if it cannot be written, the panel
            // works anyway. But it is said, because without it the machine no longer
            // explains its own locks.
            LOGGER.log(Level.WARNING, "Cannot write " + lockNotePath, e);
        }
    }

    /**
     * The warning about the packages that would stay locked without the panel, or "" if
     * there are none.
     *
     * It is needed where someone is taking the panel out of the way: it is the only moment when
     * the question "and the locks?" arises by itself, and it is the moment when nobody asked it.
     */
    static String locksStayWarning() {
        Set<String> locked = new TreeSet<>();
        for (String n : lockedNames()) if (roleOf(n) != null) locked.add(n);
        if (locked.isEmpty()) return "";
        return I18n.tr("server.um.x.locksStayWarning", java.util.Map.of(
                "n", String.valueOf(locked.size()), "cmd", UNLOCK_ALL_COMMAND, "file", LOCK_NOTE));
    }

    /**
     * The lock trace brought back in line with the machine: the note and the annotations.
     *
     * It is called where the locks can be changed: at startup, from the locks button
     * and at the end of every job on the package turn (withLockTrace). It never
     * throws: the trace is an explanation, not a mechanism, and a failure of it must not
     * make the job that called it fail.
     */
    static void refreshLockTrace() {
        writeLockNote();
        try {
            int[] done = syncLockMarks();
            if (done[0] + done[1] + done[2] > 0)
                LOGGER.info("Lock marks: " + done[0] + " added, " + done[1] + " removed, " + done[2] + " rewritten");
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Cannot update the lock marks", e);
        }
    }

    /**
     * The job on the package turn, with the lock trace brought back in line when it
     * ends, even with an error. It wraps ALL the jobs of the turn, so a new job
     * that locks again does not have to remember it.
     */
    static Runnable withLockTrace(Runnable work) {
        return () -> {
            try { work.run(); }
            finally { refreshLockTrace(); }
        };
    }

    /**
     * The job on the package turn, with the ownership of the webmail files reasserted
     * when it ends: the post-install of roundcube-php84 does "chown www:www" of logs and temp at every
     * installation and update (measured on the FreeBSD 15.1 VM on 2026-10-31), and the PHP of
     * Roundcube, which runs as roundcube, could no longer write there. It wraps all the jobs of
     * the turn, like withLockTrace: even those that update Roundcube without saying so.
     */
    static Runnable withWebmailOwnership(Runnable work) {
        return () -> {
            try { work.run(); }
            finally {
                try {
                    java.util.List<String> changed = RoundcubeUser.repairOwnership();
                    if (!changed.isEmpty()) LOGGER.info("Webmail files given back to " + RoundcubeUser.USER + ": " + changed);
                } catch (RuntimeException e) {
                    LOGGER.log(Level.WARNING, "Cannot give the webmail files back to " + RoundcubeUser.USER, e);
                }
            }
        };
    }

    /**
     * Puts the annotation on every package locked by the panel that does not have it, and removes
     * it from those that no longer are. Returns {added, removed}.
     *
     * The annotation is the sign at the point where someone asks the question: whoever sees
     * "nginx-1.30.6,3 is locked and may not be modified" and investigates with `pkg info -A nginx`
     * finds the line, and the line points to the note.
     *
     * Before, only the package just locked at startup was annotated. Measured on the FreeBSD
     * 15.1 VM on 2026-10-24: reinstalling a package -- and so also updating it -- deletes
     * its annotations, and no re-locking rewrote them. Of 39 packages locked by the
     * panel the annotation was on one, redis: the sign disappeared precisely from the
     * packages the panel had updated.
     *
     * It costs two reads (pkg query) and one command for each sign to change, so in steady
     * state none. If one of the two reads fails nothing is touched: with the list of locks
     * empty because of an error, the signs would be removed from all of them.
     *
     * The locked ones are read with pkg query and not with "pkg lock -l": measured on the VM on
     * 2026-11-07 (pkg 2.8.4), with no package locked "pkg lock -l" exits with 1 ("No locked
     * packages were found"), that is, like an error, and everything stopped here: the signs left
     * on the unlocked packages never went away again (finding 173). The same trap as
     * InstallLocks.real().
     */
    static int[] syncLockMarks() {
        Shell.Result lock = Shell.runShell(Duration.ofSeconds(30), "pkg query -e '%k = 1' '%n-%v'");
        Shell.Result annotations = Shell.runShell(Duration.ofSeconds(60), "pkg query -a '%n %At %Av'");
        if (!lock.success() || !annotations.success()) {
            LOGGER.warning("Lock marks not updated: cannot read the locks or the annotations");
            return new int[]{0, 0, 0};
        }
        Set<String> locked = new TreeSet<>();
        for (String n : lockedNames(lock.outputTrim())) if (roleOf(n) != null) locked.add(n);
        String out = annotations.outputTrim();
        int added = 0, removed = 0, rewritten = 0;
        for (String cmd : lockMarkCommands(locked, markedIn(out), staleMarksIn(out))) {
            if (!ok(cmd, 20)) continue;
            if (cmd.contains(" -A ")) added++; else if (cmd.contains(" -M ")) rewritten++; else removed++;
        }
        // The signs with the previous key (section "pkgMarkKeys"): the one with the current key has just been
        // put on by the loop above on the locked packages, so the old ones are simply removed.
        for (String cmd : oldKeyCommands(out)) if (ok(cmd, 20)) rewritten++;
        return new int[]{added, removed, rewritten};
    }

    /**
     * The packages that carry the panel's annotation, from an output of
     * `pkg query -a '%n %At %Av'` (or '%n %At'): one line per annotation, "name key value".
     * Pure function.
     */
    static Set<String> markedIn(String output) {
        Set<String> r = new TreeSet<>();
        for (String line : output.split("\n")) {
            String[] c = line.trim().split(" ", 3);
            if (c.length >= 2 && MARK_KEY.equals(c[1]) && isValidName(c[0])) r.add(c[0]);
        }
        return r;
    }

    /**
     * Those whose sign no longer says what the panel writes now: the previous text, in
     * Italian, on servers installed before the end of October 2026. The sign is only an
     * explanation for whoever reads it with pkg info -A, so there is no need to recognize it: it
     * is enough that it is not the current one. Pure function, on the output of
     * `pkg query -a '%n %At %Av'`.
     */
    static Set<String> staleMarksIn(String output) {
        Set<String> r = new TreeSet<>();
        for (String line : output.split("\n")) {
            String[] c = line.trim().split(" ", 3);
            if (c.length >= 2 && MARK_KEY.equals(c[1]) && isValidName(c[0])
                    && !(c.length == 3 && MARK_VALUE.equals(c[2]))) r.add(c[0]);
        }
        return r;
    }

    /**
     * The commands that bring the signs from the annotated state to the locked one: add
     * where missing, remove where the lock is no longer there. Pure function, so it can be tested.
     *
     * The rule is the same as the note's (the mail stack, locked now): the two traces
     * must say the same thing.
     */
    static java.util.List<String> lockMarkCommands(Set<String> locked, Set<String> marked) {
        return lockMarkCommands(locked, marked, Set.of());
    }

    /** As above, and in addition rewrites the signs left with the previous text on the packages still locked. */
    static java.util.List<String> lockMarkCommands(Set<String> locked, Set<String> marked, Set<String> stale) {
        java.util.List<String> r = new ArrayList<>();
        for (String n : new TreeSet<>(stale)) {
            if (!locked.contains(n) || !marked.contains(n)) continue;
            String cmd = rewriteMarkCommand(n);
            if (cmd != null) r.add(cmd);
        }
        for (String n : new TreeSet<>(locked)) {
            if (marked.contains(n)) continue;
            String cmd = markCommand(n);
            if (cmd != null) r.add(cmd);
        }
        for (String n : new TreeSet<>(marked)) {
            if (locked.contains(n)) continue;
            String cmd = removeMarkCommand(n);
            if (cmd != null) r.add(cmd);
        }
        return r;
    }

    /** The command that removes the annotation, or null if the name does not pass the filter. */
    static String removeMarkCommand(String name) {
        if (!isValidName(name)) return null;
        return "pkg annotate -y -D " + name + " " + MARK_KEY;
    }

    /** The key of the annotation in the pkg database. */
    static final String MARK_KEY = Product.ID + "_lock";

    /**
     * The commands that remove the signs with a previous key (section "pkgMarkKeys" of legacy-names.json), from
     * an output of `pkg query -a '%n %At %Av'`. Pure function.
     */
    static java.util.List<String> oldKeyCommands(String output) {
        java.util.List<String> r = new ArrayList<>();
        java.util.List<String> oldKeys = LegacyNames.oldNamesOf("pkgMarkKeys", MARK_KEY);
        for (String line : output.split("\n")) {
            String[] c = line.trim().split(" ", 3);
            if (c.length >= 2 && oldKeys.contains(c[1]) && isValidName(c[0]))
                r.add("pkg annotate -y -D " + c[0] + " " + c[1]);
        }
        return r;
    }

    /** The value: it points to the note and to the command that frees everything. */
    static final String MARK_VALUE = "locked by " + Product.NAME + ": see " + LOCK_NOTE
            + " - unlock with " + UNLOCK_ALL_COMMAND;

    /**
     * The command that writes the annotation, or null if the name does not pass the filter.
     *
     * It lives in a function of its own because the value contains spaces, a path and an em
     * dash: it is a command line, and a command line is tested by running it, not by
     * reading it. In this project an apostrophe inside a text has already passed intact
     * through a here-document only to break further on.
     */
    static String markCommand(String name) {
        if (!isValidName(name)) return null;
        return "pkg annotate -y -A " + name + " " + MARK_KEY + " '" + MARK_VALUE + "'";
    }

    /** The command that rewrites the value of a sign already there, or null if the name does not pass the filter. */
    static String rewriteMarkCommand(String name) {
        if (!isValidName(name)) return null;
        return "pkg annotate -y -M " + name + " " + MARK_KEY + " '" + MARK_VALUE + "'";
    }

    // ===================== the packages overview =====================

    /**
     * The single overview of the packages for the Updates page: for each one the installed and
     * catalog version, lock, vulnerabilities with the verdict on the fix, and whether it
     * can be updated from here. Read-only and without network. Inside: the mail stack
     * packages, plus every other vulnerable or locked package; the others with an update
     * (libraries, dependencies) only listed separately.
     */
    public static JSONObject packagesOverview() {
        JSONObject r = new JSONObject();
        Map<String, String[]> inst = PackagePlan.installed();
        if (inst.isEmpty()) return r.put("success", false).put("error", I18n.tr("server.um.ov.noPkgDb"));
        Shell.Result ev = PackagePlan.readToUpdate();
        Map<String, String> update = PackagePlan.toUpdate(ev.output());
        if (ev.exitCode() != 0 && update.isEmpty())
            r.put("catalogError", "pkg version -U -vRL= (" + ev.exitCode() + ")" + (ev.output().isBlank() ? "" : ": " + ev.output().trim()));
        JSONObject fixes = PackagePlan.fixes();
        JSONObject vuln = fixes.optBoolean("success") ? fixes.getJSONObject("packages") : new JSONObject();
        if (!fixes.optBoolean("success")) r.put("vulnError", fixes.optString("error"));

        String jvm = jvmPackage();
        java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<>();
        for (Map.Entry<String, String[]> e : inst.entrySet())
            if (roleOf(e.getKey()) != null) names.add(e.getKey());
        for (Map.Entry<String, String[]> e : inst.entrySet())
            if (vuln.has(e.getKey()) || "1".equals(e.getValue()[1])) names.add(e.getKey());

        JSONArray rows = new JSONArray();
        int updatable = 0, vulnerable = 0, resolvable = 0, lockedPackages = 0, unlockedStack = 0;
        boolean panelRestart = false;
        for (String n : names) {
            String[] iv = inst.get(n);
            String role = roleOf(n);
            boolean locked = "1".equals(iv[1]);
            String available = update.getOrDefault(n, "");
            JSONObject row = new JSONObject().put("name", n).put("installed", iv[0]).put("available", available)
                    .put("update", !available.isEmpty()).put("locked", locked).put("stack", role != null)
                    .put("role", role == null ? "" : role);
            // The family (FAMILIES): its packages are updated together, so the page makes ONE step of them. On
            // the production server the row said "1 of 30", 27 of which were php84 and its extensions (finding 203).
            String fam = familyOf(n);
            if (fam != null) row.put("family", fam).put("familyReason", familyReason(n));
            if (locked) lockedPackages++;
            if (role != null && !locked) unlockedStack++;
            String why = "";
            boolean eJvm = n.equals(jvm);
            if (!available.isEmpty()) {
                updatable++;
                boolean jump = significantJump(n, iv[0], available);
                row.put("majorJump", jump);
                JSONObject ad = warningFor(n, jump);
                if (ad != null) {
                    row.put("advisory", ad);
                    if ("wait".equals(ad.optString("level"))) why = ad.optString("text");
                }
            }
            if (eJvm) {
                row.put("panelRuntime", true).put("inUse", I18n.tr("server.um.ov.panelRuns"));
                // The panel's JDK has its own procedure: stop the panel, update, start it again.
                if (!available.isEmpty()) { why = I18n.tr("server.um.ov.javaFlow"); row.put("javaFlow", true); }
                String inUse = System.getProperty("java.version", "");
                String pkgName = iv[0].replaceAll("[+_].*$", "");
                if (!inUse.isEmpty() && !pkgName.isEmpty() && !pkgName.equals(inUse)) {
                    panelRestart = true;
                    row.put("panelRestart", I18n.tr("server.um.ov.panelRestart", java.util.Map.of("running", inUse, "installed", iv[0])));
                }
            }
            row.put("canUpdate", !available.isEmpty() && why.isEmpty()).put("whyNot", why);
            JSONObject v = vuln.optJSONObject(n);
            if (v != null) {
                vulnerable++;
                if ("fixed-by-upgrade".equals(v.optString("verdict"))) resolvable++;
                row.put("vuln", v);
            }
            rows.put(row);
        }
        JSONArray others = new JSONArray();
        for (Map.Entry<String, String> e : update.entrySet()) {
            if (names.contains(e.getKey()) || !inst.containsKey(e.getKey())) continue;
            others.put(new JSONObject().put("name", e.getKey()).put("installed", inst.get(e.getKey())[0]).put("available", e.getValue()));
        }
        // The dedicated procedures needed now, read from the same data: the page shows a row for each one
        // only when there is something to do (finding 193). Nothing slow: names and versions already read above.
        JSONObject procedures = new JSONObject();
        procedures.put("java", jvm != null && !jvm.isEmpty() && update.containsKey(jvm));
        String webmail = null;
        for (String n : inst.keySet()) if (n.matches("roundcube(-php[0-9]+)?")) webmail = n;
        procedures.put("roundcube", webmail != null && update.containsKey(webmail)).put("roundcubePackage", webmail == null ? "" : webmail);
        boolean olderMysql = false;
        for (String n : inst.keySet()) {
            Matcher mm = Pattern.compile("^mysql([0-9]+)-server$").matcher(n);
            if (mm.find() && Integer.parseInt(mm.group(1)) < 84) olderMysql = true;
        }
        procedures.put("mysql84", olderMysql);
        String python = pyDefault();
        boolean olderPython = false;
        for (String n : inst.keySet()) {
            Matcher mp = Pattern.compile("^(?:py|python)(3[0-9]{2})(?:-|$)").matcher(n);
            if (mp.find() && !mp.group(1).equals(python)) olderPython = true;
        }
        procedures.put("python", olderPython);
        // Dovecot 2.4, a separate package in the latest branch: the row is there as long as 2.3 with the MySQL
        // flavor is installed and the catalog offers 2.4 (finding 213). The switch is not mandatory: 2.3 still
        // receives the critical fixes.
        procedures.put("dovecot24", inst.containsKey("dovecot-mysql") && !inst.containsKey("dovecot24-mysql")
                && !sh("pkg rquery -U %v dovecot24-mysql 2>/dev/null", 30).isBlank());
        r.put("procedures", procedures);
        return r.put("success", true).put("packages", rows).put("others", others)
                .put("summary", new JSONObject().put("updates", updatable + others.length()).put("stackUpdates", updatable)
                        .put("vulnerable", vulnerable).put("fixable", resolvable).put("locked", lockedPackages)
                        .put("stackUnlocked", unlockedStack).put("panelRestart", panelRestart));
    }

    // ===================== mail stack specific warnings =====================

    /**
     * Columns: name expression, level on a major version jump, text.
     *
     * The "wait" level is not decorative: the automatic maintenance does NOT unlock the
     * packages that carry it. A warning that merely appears while the button next to it
     * updates anyway is not a warning.
     */
    private static final String[][] WARNINGS = {
        {"^dovecot.*", "wait",
         "server.um.changeLocks.2"},
        {"^roundcube.*", "wait",
         "server.um.changeLocks.3"},
        {"^php[0-9]+.*", "wait",
         "server.um.changeLocks.4"},
        {"^mysql[0-9]+-server$", "wait",
         "server.um.changeLocks.5"},
        {"^mysql[0-9]+-client$", "wait",
         "server.um.changeLocks.6"},
        {"^postfix.*", "review",
         "server.um.changeLocks.7"},
        {"^rspamd$", "review",
         "server.um.changeLocks.8"},
        {"^redis.*", "review",
         "server.um.changeLocks.9"},
        {"^clamav.*", "review",
         "server.um.changeLocks.10"},
        {"^nginx.*", "review",
         "server.um.changeLocks.11"},
        {"^py[0-9]+-fail2ban$", "review",
         "server.um.changeLocks.12"},
        {"^(py[0-9]+-)?certbot$", "review",
         "server.um.changeLocks.13"},
        {"^unbound$", "review",
         "server.um.changeLocks.14"},
        {"^openjdk[0-9]*$", "wait",
         "server.um.changeLocks.15"},
        {"^openssl[0-9]*$", "review",
         "server.um.changeLocks.16"},
    };

    /**
     * How many version digits mark a breaking change, per package.
     *
     * Looking only at the first digit is the mistake that makes everything else useless: Dovecot
     * 2.3 -> 2.4 rewrites the configuration format and PHP 8.4 -> 8.5 changes paths
     * and sockets, but for both the first digit does not move. Treating them as "minor
     * updates, normally safe" would be false precisely on the two most dangerous cases.
     */
    private static final String[][] VERSION_DEPTH = {
        {"^dovecot.*",           "2"},   // 2.3 -> 2.4: incompatible configuration
        {"^php[0-9]+.*",         "2"},   // 8.4 -> 8.5: paths, socket, package names
        {"^mysql[0-9]+-.*",      "2"},   // 8.0 -> 8.4: data dictionary, removed options
        {"^roundcube.*",         "2"},   // 1.5 -> 1.6: database schema
        {"^rspamd$",             "2"},   // minor versions change options and keys in Redis
        {"^postfix.*",           "2"},   // 3.10 -> 3.11 changes the compatibility_level defaults
    };

    /** Compares the first N digits of two versions: true if they changed. */
    static boolean significantJump(String name, String from, String to) {
        int digits = 1;
        for (String[] r : VERSION_DEPTH) if (name.matches(r[0])) { digits = Integer.parseInt(r[1]); break; }
        return !versionPrefix(from, digits).equals(versionPrefix(to, digits));
    }

    /** The first n numeric components of a version, e.g. ("2.3.21", 2) -> "2.3". */
    static String versionPrefix(String v, int n) {
        if (v == null) return "";
        String[] parts = v.split("[._,+~]");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n && i < parts.length; i++) {
            if (i > 0) sb.append('.');
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    /**
     * Packages whose risk does NOT depend on the version number, and for which the
     * warning therefore always applies, even on an update of only the trailing digits.
     *
     * The case is openjdk: the problem is not what changes between two versions, it is that the panel
     * is running on it. As soon as the JVM files are replaced, the process in memory
     * can no longer launch commands: the job that is doing the update cannot even
     * lock the package again and stops halfway, leaving everything exposed.
     * Treating it with the general rule "minor jumps are safe" means cancelling the
     * protection precisely in the case it was written for.
     */
    private static final String[] ALWAYS_WAIT = { "^openjdk[0-9]*$" };

    private static boolean versionIndependentRisk(String name) {
        for (String r : ALWAYS_WAIT) if (name.matches(r)) return true;
        return false;
    }

    /** Warning for a package, or null if it has no specific one. */
    private static JSONObject warningFor(String name, boolean majorJump) {
        for (String[] a : WARNINGS) {
            if (!name.matches(a[0])) continue;
            if (!majorJump && "wait".equals(a[1]) && !versionIndependentRisk(name)) {
                return new JSONObject().put("level", "ok").put("text",
                        I18n.tr("server.um.warningFor.1"));
            }
            // A warning written for the worst case, shown on an update of only the
            // trailing digits, says something false: it speaks of a "major change" when there
            // is no jump. Whoever reads it either gets alarmed for nothing or stops
            // trusting the text.
            String text = majorJump ? I18n.tr(a[2])
                    : I18n.tr("server.um.warningFor.2", java.util.Map.of("p", I18n.tr(a[2])));
            return new JSONObject().put("level", a[1]).put("text", text);
        }
        if (majorJump) {
            return new JSONObject().put("level", "review").put("text",
                    I18n.tr("server.um.warningFor.3"));
        }
        return null;
    }

    /**
     * Available versions for the LOCKED packages. It needs a command other than
     * `pkg upgrade -n`: that one skips the locked ones and does not say what version they
     * would go to, so on its own it would suggest that they have no updates.
     */
    public static JSONArray lockedUpdates() {
        String v = sh("pkg version -U -vRL= 2>/dev/null", 60);
        String lock = sh("pkg lock -l 2>/dev/null");
        JSONArray arr = new JSONArray();
        Pattern p = Pattern.compile("^(\\S+)-([^\\s-]+)\\s+<\\s+.*\\(.*has ([^)]+)\\)");
        for (String line : v.split("\n")) {
            Matcher m = p.matcher(line.trim());
            if (!m.find()) continue;
            String name = m.group(1), current = m.group(2), available = m.group(3);
            if (roleOf(name) == null) continue;
            if (!locked(lock, name)) continue;
            boolean major = significantJump(name, current, available);
            JSONObject row = new JSONObject().put("name", name).put("current", current)
                    .put("available", available).put("majorJump", major)
                    .put("role", roleOf(name));
            JSONObject a = warningFor(name, major);
            if (a != null) row.put("advisory", a);
            arr.put(row);
        }
        return arr;
    }

    /**
     * Update and vulnerability status. All read-only: `pkg upgrade -n` is
     * a simulation and `pkg audit` only queries the vulnerability database.
     */
    public static JSONObject updatesStatus() {
        JSONObject r = new JSONObject();
        ok("pkg update -q", 120);

        // The simulation must be read in FULL. The "is locked" lines of the locked packages
        // take up dozens of them, and an early cut would fall in the middle of the list, making
        // packages that do have updates show up as "without updates". Only what is shown
        // on screen is cut, never what is analysed.
        // The plan of the update of the UNLOCKED packages, with its signature. Before, there was a
        // raw "pkg upgrade -n" here and the text ended up on the page as it was: whoever pressed
        // "Upgrade unlocked" approved a text, not a plan, and nothing tied that
        // text to what would be executed. It was the only one of the three package jobs
        // without plan or signature -- and the only one that compared nothing at the end.
        //
        // No unlocking: that is the point of this update, so the rule always refuses,
        // and the locked ones stay in the plan with their reason (pkg skips them). And no
        // family twin to unlock, for the same reason: here nothing is unlocked.
        JSONObject unprotectedPlan = judged(PackagePlan.fullPlan(java.util.Set.of(), lockedNames(),
                b -> I18n.tr("server.um.x.staysLockedHere")));
        String blocked = cardBlockedReason(unprotectedPlan);
        r.put("plan", planForCard(unprotectedPlan))
         .put("signature", unprotectedPlan.optString("signature"))
         .put("blockedReason", blocked == null ? "" : blocked);
        String fullSimulation = unprotectedPlan.optString("output");
        StringBuilder shown = new StringBuilder();
        int omitted = 0;
        for (String l : fullSimulation.split("\n")) {
            if (l.contains("is locked and may not be modified") || l.startsWith("Checking for upgrades")) { omitted++; continue; }
            shown.append(l).append("\n");
        }
        r.put("dryRun", shown.toString().trim()
                + (omitted > 0 ? I18n.tr("server.um.updatesStatus.1", java.util.Map.of("omitted", String.valueOf(omitted))) : ""));
        r.put("upToDate", fullSimulation.contains("Your packages are up to date"));

        // Which MAIL packages would be touched, and whether they are locked.
        JSONArray involved = new JSONArray();
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            if (fullSimulation.contains(p.getString("name") + ":")) {
                involved.put(new JSONObject().put("name", p.getString("name"))
                        .put("role", p.getString("role")).put("locked", p.getBoolean("locked")));
            }
        }
        r.put("affectedMailPackages", involved);
        r.put("lockedUpdates", lockedUpdates());

        // --- Known vulnerabilities ---
        String audit = sh("pkg audit -F 2>&1", 180);
        r.put("audit", audit.length() > 4000 ? audit.substring(audit.length() - 4000) : audit);

        // Vulnerability <-> lock cross-check. That is the point: a locked package does NOT
        // receive security fixes. The lock protects from unexpected changes, it is not
        // a state to stay in forever, and whoever sets it must be able to see that.
        JSONArray vulnerable = new JSONArray();
        String lock = sh("pkg lock -l 2>/dev/null");

        // Which packages have a more recent version in the catalog, LOCKED ONES INCLUDED.
        //
        // It is needed because "pkg upgrade -n" skips the locked ones: from the simulation one
        // cannot know whether a fix exists for a locked package. "pkg version", instead,
        // compares the versions and does not care about the lock, so it answers for those too.
        Set<String> updatable = new java.util.LinkedHashSet<>();
        for (String line : sh("pkg version -U -vRL= 2>/dev/null", 60).split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            // "name-1.2.3    <   needs updating (index has 1.2.4)"
            //
            // Only "<" means that a more recent version exists. ">" (installed newer
            // than the catalog), "?" (not in the catalog) and "!" (comparison failed) are
            // differences, not updates: taking them as such would tell whoever reads that
            // a fix exists for a vulnerable package when it does not.
            String[] fields = t.split("\\s+");
            if (fields.length < 2 || !"<".equals(fields[1])) continue;
            String pv = fields[0];
            int dash = pv.lastIndexOf('-');
            if (dash > 0) updatable.add(pv.substring(0, dash));
        }
        Matcher m = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        Set<String> seen = new java.util.LinkedHashSet<>();
        while (m.find()) seen.add(m.group(1));
        for (String name : seen) {
            boolean lk = locked(lock, name);
            String role = roleOf(name);
            // Does a more recent version exist? It is a different question from "the update
            // would apply it", and it must be kept separate: for a locked package the second
            // is always no, but the first can be yes.
            boolean hasUpdate = updatable.contains(name);
            JSONObject v = new JSONObject().put("name", name).put("locked", lk)
                    .put("mailPackage", role != null).put("role", role == null ? "" : role)
                    .put("updateAvailable", hasUpdate)
                    // Before, there was "!lk && simulazione.contains(nome)" here, and for a
                    // locked package it was always false -- while the card wrote "locked,
                    // so it does NOT receive the fix", that is, it stated that a fix
                    // existed. Nobody had checked it: the simulation skips the locked
                    // ones, so that information simply cannot be derived from there.
                    .put("fixedByUpgrade", !lk && (hasUpdate
                            || fullSimulation.contains(name + ":")));
            // The detail is needed to decide: "has a vulnerability" does not say whether it is a
            // remote code execution or a denial of service that does not concern you.
            JSONObject d = vulnerabilityDetail(audit, name);
            v.put("cve", d.getJSONArray("cve"));
            v.put("description", d.getString("description"));
            v.put("references", d.getJSONArray("references"));
            vulnerable.put(v);
        }
        // "There is a more recent version" does not answer "is there a fix?": the more recent
        // version may still be vulnerable, and the fix may exist in a version that your
        // catalog does not have. The VuXML ranges say so.
        if (vulnerable.length() > 0) {
            JSONObject fixes = PackagePlan.fixes();
            if (fixes.optBoolean("success")) {
                JSONObject per = fixes.getJSONObject("packages");
                for (int i = 0; i < vulnerable.length(); i++) {
                    JSONObject v = vulnerable.getJSONObject(i);
                    if (per.has(v.getString("name"))) v.put("fix", per.getJSONObject(v.getString("name")));
                }
            } else {
                r.put("fixesError", fixes.optString("error"));
            }
        }
        r.put("vulnerable", vulnerable);
        // Lesson paid for on the other server on 30 August: mysql80-server had been updated to
        // 8.0.46 but the process kept running on the 8.0.45 binaries, so the fix was not
        // in service although it showed as installed. It applies to every shared library.
        r.put("restartNote",
            I18n.tr("server.um.updatesStatus.2"));

        // --- Base system: kernel and userland compared. If they differ, a reboot is missing. ---
        String k = sh("freebsd-version -k", 15), run = sh("freebsd-version -r", 15), u = sh("freebsd-version -u", 15);
        r.put("kernel", k).put("running", run).put("userland", u);
        r.put("rebootPending", !k.isEmpty() && !run.isEmpty() && !k.equals(run));

        r.put("success", true);
        return r;
    }

    /**
     * Extracts from the `pkg audit` report the block about a package: description,
     * CVE identifiers and references. Without this the panel would only say "it is
     * vulnerable", which is not enough to decide whether it is worth unlocking and updating.
     */
    /** The line with which pkg audit closes the report. It is the proof that the check took place. */
    private static final Pattern FULL_AUDIT = Pattern.compile(
            "(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found");

    /**
     * The pkg audit report for ONE precise version of a package.
     *
     * Two traps, measured on the FreeBSD 15.1 VM on 2026-10-23, which together made
     * this check unable to say anything at all.
     *
     * 1. `pkg audit name`, with the name alone, does not answer "is the installed version
     *    vulnerable?" but "does VuXML have entries for this name?". On nginx 1.30.6,3, just
     *    updated and not vulnerable, it answered "nginx is vulnerable" with 25 problems,
     *    listing ranges like "< 1.8.1_3,2" that have nothing to do with it; `pkg audit` without
     *    arguments, which looks at the installed versions, did not name it at all at the
     *    same moment. And the header of that report is "nginx is vulnerable:", WITHOUT the
     *    version, so vulnerabilityDetail -- which looks for "name-version is vulnerable:"
     *    -- never entered the block: always zero CVEs, in both directions.
     *    On php84 8.4.26, truly vulnerable, the panel's report was "[ok] No known
     *    vulnerability recorded for this package", while pkg said
     *    "php84 is vulnerable" and PackagePlan.fixes, which asks the question correctly,
     *    found the fix in 8.4.27.
     *    The form that answers the right question is `pkg audit name-version`: with
     *    "nginx-1.30.6,3" it says "0 problem(s)", with "php84-8.4.26" it finds the only real problem.
     *
     * 2. If the vulnerability database is not there, pkg answers "vulnxml file vuln.xml
     *    does not exist" and whoever looks only for the "is vulnerable" lines concludes "no
     *    vulnerabilities". It is the worst case: a reassurance instead of an "I could not
     *    check". The exit code does not help to tell them apart -- measured: 1
     *    without the database, 0 both with problems found and without. What tells a
     *    report that was done from one that was not is the final line "N problem(s) in M package(s)
     *    found.", and that one is required.
     *
     * The count shown is the one in the final line, not the number of CVEs: a VuXML entry
     * may have no CVE identifier at all, and counting the CVEs would lose it.
     */
    static JSONObject auditReport(String name, String version) {
        JSONObject r = emptyAuditReport(name, version);
        if (!isValidName(name) || !PackagePlan.validVersion(version))
            return r.put("done", false).put("problems", 0)
                    .put("error", I18n.tr("server.um.x.auditNoVersion"));
        return readAuditReport(sh("pkg audit '" + name + "-" + version + "' 2>&1", 120), name, r);
    }

    /** Reading the report, separate from the command: pure function, tested with real outputs. */
    static JSONObject readAuditReport(String out, String name, JSONObject r) {
        Matcher m = FULL_AUDIT.matcher(out == null ? "" : out);
        if (!m.find())
            return r.put("done", false).put("problems", 0)
                    .put("error", I18n.tr("server.um.x.auditNotDone", java.util.Map.of("out", String.valueOf(summarizeOutput(out)))));
        JSONObject detail = vulnerabilityDetail(out, name);
        int problems;
        try { problems = Integer.parseInt(m.group(1)); } catch (NumberFormatException e) { problems = 0; }
        return r.put("done", true).put("problems", problems)
                .put("cve", detail.getJSONArray("cve")).put("description", detail.getString("description"))
                .put("references", detail.getJSONArray("references"));
    }

    /** An empty report to fill in, for whoever reads an output already in hand. */
    static JSONObject emptyAuditReport(String name, String version) {
        return new JSONObject().put("name", name == null ? "" : name)
                .put("version", version == null ? "" : version)
                .put("cve", new JSONArray()).put("references", new JSONArray()).put("description", "");
    }

    static JSONObject vulnerabilityDetail(String audit, String pkgName) {
        JSONArray cve = new JSONArray();
        JSONArray references = new JSONArray();
        StringBuilder description = new StringBuilder();
        boolean inside = false;
        java.util.LinkedHashSet<String> seenCves = new java.util.LinkedHashSet<>();
        for (String line : audit.split("\n")) {
            String t = line.trim();
            // Start of the block: "<name>-<version> is vulnerable:"
            if (t.matches("^" + java.util.regex.Pattern.quote(pkgName) + "-[0-9]\\S* is vulnerable:.*")) {
                inside = true;
                continue;
            }
            if (!inside) continue;
            // The block ends when another one starts or at the first empty line after the text.
            if (t.endsWith("is vulnerable:") || (t.isEmpty() && description.length() > 0)) break;
            if (t.startsWith("CVE:")) {
                for (String c : t.substring(4).trim().split("[\\s,]+")) {
                    if (c.matches("CVE-[0-9]{4}-[0-9]+")) seenCves.add(c);
                }
            } else if (t.startsWith("WWW:")) {
                String u = t.substring(4).trim();
                if (u.startsWith("https://") || u.startsWith("http://")) references.put(u);
            } else if (!t.isEmpty()) {
                if (description.length() > 0) description.append(' ');
                description.append(t);
            }
        }
        for (String c : seenCves) cve.put(c);
        String desc = description.toString();
        if (desc.length() > 600) desc = desc.substring(0, 600) + "...";
        return new JSONObject().put("cve", cve).put("references", references).put("description", desc);
    }

    public static JSONObject maintenancePreview() {
        ok("pkg update -q", 120);
        JSONArray arr = lockedUpdates();
        int majors = 0, expectedOnes = 0;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            if (o.getBoolean("majorJump")) majors++;
            if (o.has("advisory") && "wait".equals(o.getJSONObject("advisory").getString("level"))) expectedOnes++;
        }
        // The exact plan of the whole maintenance, computed on a copy of the pkg database
        // with the same unlocks the real job will make. The table above gives the locked
        // packages; this one gives EVERYTHING that will change, dependencies included.
        JSONObject plan = judged(maintenancePlan(arr).getJSONObject("plan"));
        String blocked = cardBlockedReason(plan);
        return new JSONObject().put("success", true).put("packages", arr)
                .put("blockedReason", blocked == null ? "" : blocked)
                .put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""))
                .put("majorCount", majors).put("waitCount", expectedOnes)
                .put("generalNote",
                    I18n.tr("server.um.maintenancePreview.1"));
    }

    // ===================== compatibility of the live configuration =====================

    private static final String DOVECOT_DIR = "/usr/local/etc/dovecot";
    private static final String MYCNF = "/usr/local/etc/mysql/my.cnf";

    /**
     * Constructs that Dovecot 2.4 no longer accepts. Columns: regular expression to look for
     * in the configuration files, description, what to put in its place.
     *
     * Taken from the official 2.3 -> 2.4 upgrade notes, not from memory: here a wrong entry
     * means telling an administrator that they can update when they cannot.
     */
    private static final String[][] DOVECOT_24_BREAKS = {
        {"^[[:space:]]*mail_location[[:space:]]*=", "mail_location",
         "server.um.maintenancePreview.2"},
        {"^[[:space:]]*passdb[[:space:]]*\\{", "server.um.dovecot24.passdbNoName",
         "server.um.maintenancePreview.3"},
        {"^[[:space:]]*userdb[[:space:]]*\\{", "server.um.dovecot24.userdbNoName",
         "server.um.maintenancePreview.4"},
        {"^[[:space:]]*ssl_dh[[:space:]]*=", "ssl_dh",
         "server.um.maintenancePreview.5"},
        {"^[[:space:]]*default_fields[[:space:]]*=", "default_fields",
         "server.um.maintenancePreview.6"},
        {"^[[:space:]]*override_fields[[:space:]]*=", "override_fields",
         "server.um.maintenancePreview.6"},
        {"^[[:space:]]*service_count[[:space:]]*=", "service_count",
         "server.um.maintenancePreview.7"},
        {"^[[:space:]]*idle_kill[[:space:]]*=", "idle_kill",
         "server.um.dovecot24.idleKill"},
        {"fts[-_]lucene|fts[-_]squat", "server.um.maintenancePreview.8",
         "server.um.maintenancePreview.9"},
        {"imap[-_]zlib", "server.um.dovecot24.imapZlib",
         "server.um.maintenancePreview.10"},
        {"old[-_]stats", "server.um.dovecot24.oldStats", "server.um.dovecot24.removed"},
        {"^[[:space:]]*((director|replicator)[[:space:]]*\\{|director_servers)", "director / replicator",
         "server.um.maintenancePreview.11"},
        {"driver[[:space:]]*=[[:space:]]*checkpassword", "passdb checkpassword", "server.um.maintenancePreview.12"},
    };

    /**
     * The files that Dovecot ACTUALLY reads. The difference is not a detail: under
     * /usr/local/etc/dovecot the port also leaves example-config/, a tree of
     * sample configurations that Dovecot never opens. Scanning it means
     * reporting problems in files nobody uses -- and making an update look blocking
     * because of an LDAP example that is not even active.
     *
     * The set is rebuilt the way Dovecot builds it: start from dovecot.conf and
     * follow the !include directives that are NOT commented out, plus the .conf.ext named in the args.
     */
    private static List<String> fileDovecot() { return fileDovecotIn(DOVECOT_DIR); }

    /** As above, but on any folder: it is the only way to test it without an installed Dovecot. */
    static List<String> fileDovecotIn(String dir) {
        java.util.LinkedHashSet<String> alive = new java.util.LinkedHashSet<>();
        String root = dir + "/dovecot.conf";
        if (!ok("test -f " + root, 10)) return new ArrayList<>();
        alive.add(root);

        // The conf.d/*.conf files come in only if dovecot.conf really includes them: a
        // commented-out "#!include" line brings nothing in, and treating it as active
        // would reintroduce the same mistake as the examples.
        if (ok("grep -qE '^[[:space:]]*!include[[:space:]]+conf\\.d/\\*\\.conf' " + root, 10)) {
            for (String f : sh("ls -1 " + dir + "/conf.d/*.conf 2>/dev/null", 15).split("\n")) {
                if (validDovecotPath(dir, f.trim())) alive.add(f.trim());
            }
        }

        // The .conf.ext files are not included by a glob: they come in only if named explicitly,
        // by an active !include or by an args = of passdb/userdb.
        for (int round = 0; round < 3; round++) {   // three levels are enough and prevent an infinite loop
            int before = alive.size();
            String list = String.join(" ", alive);
            // -H and not -h: we need to know FROM WHICH file each reference comes, because a
            // relative include is resolved against the folder of the file that contains it.
            // "!include auth-sql.conf.ext" inside conf.d/10-auth.conf means
            // conf.d/auth-sql.conf.ext, not a file in the root: resolving it from the root
            // means not finding it, and not finding it means declaring compatible a
            // configuration that is not -- precisely the file that contains the passdb entries.
            // Commented-out lines stay out: a disabled include brings nothing in.
            // The grep casts a wide net and the comment filtering is done here: expressing
            // "non-commented line that contains args" in a single POSIX expression is possible
            // but fragile, and an oversight there means not following a reference -- that is,
            // declaring compatible a configuration that is not.
            String references = sh("grep -HE '^[[:space:]]*(!include(_try)?[[:space:]]|.*args[[:space:]]*=)' "
                    + list + " 2>/dev/null", 20);
            for (String line : references.split("\n")) {
                int c = line.indexOf(':');
                if (c <= 0) continue;
                String source = line.substring(0, c);
                String content = line.substring(c + 1);
                if (content.trim().startsWith("#")) continue;   // include or args disabled
                String base = source.contains("/") ? source.substring(0, source.lastIndexOf('/')) : dir;
                Matcher m = Pattern.compile("([A-Za-z0-9._/-]*[A-Za-z0-9._-]+\\.conf(\\.ext)?)").matcher(content);
                while (m.find()) {
                    String ref = m.group(1);
                    String absolute = ref.startsWith("/") ? ref : base + "/" + ref;
                    if (validDovecotPath(dir, absolute) && ok("test -f " + absolute, 10)) alive.add(absolute);
                }
            }
            if (alive.size() == before) break;
        }
        return new ArrayList<>(alive);
    }

    /**
     * A path ends up inside a command: it must be under the Dovecot folder, have a
     * harmless shape, and NOT come from the examples tree.
     */
    static boolean validDovecotPath(String dir, String p) {
        return p.startsWith(dir + "/")
                && !p.contains("/example-config/")
                && p.matches("[A-Za-z0-9._/-]{1,256}");
    }

    /**
     * The check that really matters: not "what version do I have" but "does MY configuration
     * survive the next version?". The very question that a version number
     * cannot represent.
     */
    public static JSONObject dovecotCompatibility() {
        JSONObject r = new JSONObject();
        // The package can be called dovecot, dovecot-mysql or dovecot-pgsql depending on the
        // flavor chosen: they are the same port and exclude each other, so on a system with
        // the MySQL flavor the name "dovecot" is NOT installed and the query would return nothing.
        // The binary is the most direct answer; the port origin is the exact fallback.
        // First the PACKAGE, then the binary. It is not irrelevant: "dovecot --version" gives the
        // upstream version (2.3.21.1) while pkg gives the port's one with the FreeBSD revision
        // (2.3.21.1_3). Putting the binary first ends up comparing two numbers of a different
        // nature, and the card shows an available update that does not exist.
        // The query by ORIGIN works with the flavors too, where the name "dovecot" is not
        // installed at all: that is the reason why the binary had become the first.
        // After the guided switch (finding 213) the package is the 2.4 one, a separate port (mail/dovecot24): the
        // installed and available versions are asked of its origin, or the card would say "installed 2.4.5,
        // available 2.3".
        String origin = sh("pkg query -e '%o = \"mail/dovecot24\"' %o 2>/dev/null | head -1", 20).trim();
        if (!"mail/dovecot24".equals(origin)) origin = "mail/dovecot";
        String installed = sh("pkg query -e '%o = \"" + origin + "\"' %v 2>/dev/null | head -1", 20);
        if (installed.isEmpty()) {
            installed = sh("dovecot --version 2>/dev/null | awk '{print $1}'", 20);
        }
        String available = sh("pkg rquery -U -e '%o = \"" + origin + "\"' %v 2>/dev/null | head -1", 30);
        if (available.isEmpty() && "mail/dovecot".equals(origin)) available = sh("pkg rquery -U %v dovecot 2>/dev/null", 30);
        r.put("installed", installed).put("available", available).put("origin", origin);

        // Which Dovecot packages the repository offers. It is not curiosity: if 2.4 were a
        // DIFFERENT PACKAGE (like mysql80 and mysql84) then no pkg upgrade could ever
        // get there, and the risk would not be "an update breaks the mail" but "a
        // deliberate migration". They are two opposite scenarios and they change what must be built.
        JSONArray offered = new JSONArray();
        for (String line : sh("pkg rquery -U -g '%n %v' 'dovecot*' 2>/dev/null", 30).split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            offered.put(new JSONObject().put("name", t.substring(0, sp)).put("version", t.substring(sp + 1).trim()));
        }
        r.put("repoPackages", offered);

        // Dovecot's own judgement on the configuration. Until now the panel wrote the
        // files and restarted without ever asking the server whether it accepted them: a syntax
        // error would have been found with the service already stopped. doveconf -n is the
        // equivalent of "mysqld --validate-config", and it applies today, regardless of 2.4.
        Shell.Result dc = Shell.runShell(Duration.ofSeconds(30), "doveconf -n 2>&1 >/dev/null");
        r.put("doveconfAvailable", !dc.outputTrim().contains("not found"));
        String errors = dc.outputTrim();
        r.put("doveconfOk", dc.success() && errors.isEmpty());
        r.put("doveconfOutput", errors.length() > 3000 ? errors.substring(0, 3000) : errors);

        int majorInstalled = majorVersion(installed), majorAvailable = majorVersion(available);
        int minInst = minorVersion(installed), minorAvailable = minorVersion(available);
        // 2.3 -> 2.4 is a MINOR version jump in the numbers but a total break in practice:
        // comparing only the major digit would let it pass as harmless.
        boolean jumpTo24 = majorAvailable > majorInstalled || (majorAvailable == majorInstalled && minorAvailable > minInst);
        r.put("breakingUpgradeAvailable", jumpTo24 && !installed.isEmpty() && !available.isEmpty());
        r.put("on24", majorInstalled > 2 || (majorInstalled == 2 && minInst >= 4));

        List<String> file = fileDovecot();
        r.put("configFilesScanned", file.size());
        JSONArray issues = new JSONArray();
        if (file.isEmpty()) {
            r.put("scanned", false);
            r.put("note", I18n.tr("server.um.dovecotCompatibility.1", java.util.Map.of("dovecotDir", String.valueOf(DOVECOT_DIR))));
        } else {
            r.put("scanned", true);
            String list = String.join(" ", file);
            for (String[] rot : DOVECOT_24_BREAKS) {
                String found = sh("grep -lE \"" + outsideComments(rot[0]) + "\" " + list + " 2>/dev/null", 20);
                if (found.isEmpty()) continue;
                List<String> where = new ArrayList<>();
                for (String f : found.split("\n")) if (!f.trim().isEmpty()) where.add(f.trim());
                issues.put(new JSONObject().put("construct", I18n.tr(rot[1])).put("replacement", I18n.tr(rot[2]))
                        .put("files", new JSONArray(where)));
            }
            // Single-letter variables: %u %d %n %h and the forms with modifiers (%2.256Nu).
            // The new syntax is %{...}, which does not match this expression.
            String var = sh("grep -lE '" + SINGLE_LETTER_VARS + "' " + list + " 2>/dev/null", 20);
            if (!var.isEmpty()) {
                List<String> where = new ArrayList<>();
                for (String f : var.split("\n")) if (!f.trim().isEmpty()) where.add(f.trim());
                issues.put(new JSONObject()
                        .put("construct", I18n.tr("server.um.x.singleLetterVars"))
                        .put("replacement", I18n.tr("server.um.dovecotCompatibility.4"))
                        .put("files", new JSONArray(where)));
            }
            // In 2.4 this directive is mandatory and must be the first: its absence
            // is in itself the proof that the configuration is still in 2.3 format.
            if (sh("grep -lE '^[[:space:]]*dovecot_config_version' " + list + " 2>/dev/null", 20).isEmpty()) {
                issues.put(new JSONObject()
                        .put("construct", I18n.tr("server.um.x.noConfigVersion"))
                        .put("replacement", I18n.tr("server.um.dovecotCompatibility.6"))
                        .put("files", new JSONArray()));
            }
            if (sh("grep -lE '^[[:space:]]*dovecot_storage_version' " + list + " 2>/dev/null", 20).isEmpty()) {
                issues.put(new JSONObject()
                        .put("construct", I18n.tr("server.um.x.noStorageVersion"))
                        .put("replacement", I18n.tr("server.um.dovecotCompatibility.8"))
                        .put("files", new JSONArray()));
            }
        }
        r.put("issues", issues);
        r.put("compatible24", issues.length() == 0);
        r.put("source", I18n.tr("server.um.dovecotCompatibility.9"));
        r.put("success", true);
        return r;
    }

    /**
     * The 2.3 single-letter variables (%u, %d, %n, %2.256Nu) outside comments. Before, they were looked for in
     * the whole line, and the panel's 2.4 configuration, which in a comment explains "%d -> %{user | domain}",
     * came out as not ready for 2.4 on a 2.4 that worked (finding 213). The new syntax, %{...}, does not match.
     */
    static final String SINGLE_LETTER_VARS = "^[^#]*%[0-9.]*[A-Za-z]([^{A-Za-z]|$)";

    /** A construct looked for only outside comments: those already anchored at line start are so by themselves. */
    static String outsideComments(String re) {
        return re.startsWith("^") ? re : "^[^#]*(" + re + ")";
    }

    private static int majorVersion(String v) {
        Matcher m = Pattern.compile("^([0-9]+)").matcher(v == null ? "" : v);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    private static int minorVersion(String v) {
        Matcher m = Pattern.compile("^[0-9]+\\.([0-9]+)").matcher(v == null ? "" : v);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** Options of the live my.cnf that MySQL 8.4 has removed: with just one of these the server does not start. */
    private static final String[][] MYCNF_REMOVED_84 = {
        {"default_authentication_plugin", "authentication_policy"},
        {"expire_logs_days",              "server.um.minorVersion.1"},
        {"master_info_repository",        "server.um.minorVersion.2"},
        {"relay_log_info_repository",     "server.um.minorVersion.2"},
        {"slave_rows_search_algorithms",  "server.um.minorVersion.2"},
        {"transaction_write_set_extraction", "server.um.minorVersion.2"},
        {"binlog_transaction_dependency_tracking", "server.um.minorVersion.3"},
        {"log_bin_use_v1_events",         "server.um.minorVersion.2"},
        {"skip_host_cache",               "host_cache_size = 0"},
        {"character_set_client_handshake", "server.um.minorVersion.2"},
    };

    public static JSONObject mysqlCompatibility() {
        JSONObject r = new JSONObject();
        String pkgServer = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        r.put("package", pkgServer);
        if (pkgServer.isEmpty()) {
            return r.put("success", true).put("present", false)
                    .put("note", I18n.tr("server.um.mysqlCompatibility.1"));
        }
        if (!isValidName(pkgServer)) {
            return r.put("success", false).put("error", I18n.tr("server.um.mysqlCompatibility.2"));
        }
        r.put("present", true).put("version", sh("pkg query %v " + pkgServer, 20));
        // 8.0 is at end of life: it must be said even when everything works, because the moment when
        // it would stop working does not come with advance notice.
        r.put("eol", pkgServer.startsWith("mysql80"));
        JSONArray issues = new JSONArray();
        if (Files.exists(Paths.get(MYCNF))) {
            for (String[] o : MYCNF_REMOVED_84) {
                // In my.cnf '_' and '-' are equivalent, and some options are switches
                // written without '=': looking only for "name =" would miss some of them.
                String v = o[0].replaceAll("[_-]", "[_-]");
                if (ok("grep -qE '^[[:space:]]*" + v + "[[:space:]]*(=|$)' " + MYCNF + " 2>/dev/null", 15)) {
                    issues.put(new JSONObject().put("option", o[0]).put("replacement", I18n.tr(o[1])));
                }
            }
            r.put("mycnfPresent", true);
        } else {
            r.put("mycnfPresent", false);
        }
        r.put("issues", issues);
        return r.put("success", true);
    }

    /**
     * PHP, webmail and panel must name the same PHP version. It is a coupling that
     * is not visible anywhere until it breaks: the roundcube package carries the
     * version in its name, the panel scripts write it in the paths and in the php-fpm socket.
     */
    public static JSONObject webmailCompatibility() {
        JSONObject r = new JSONObject();
        String php = sh("pkg query %n 2>/dev/null | grep -E '^php[0-9]+$' | head -1", 20);
        String roundcube = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20);
        if (!php.isEmpty() && !isValidName(php)) php = "";
        if (!roundcube.isEmpty() && !isValidName(roundcube)) roundcube = "";
        r.put("php", php).put("roundcube", roundcube);
        r.put("phpVersion", php.isEmpty() ? "" : sh("pkg query %v " + php, 20));
        r.put("roundcubeVersion", roundcube.isEmpty() ? "" : sh("pkg query %v " + roundcube, 20));

        JSONArray note = new JSONArray();
        Matcher mp = Pattern.compile("^php([0-9]+)$").matcher(php);
        Matcher mr = Pattern.compile("^roundcube-php([0-9]+)$").matcher(roundcube);
        String vPhp = mp.find() ? mp.group(1) : "";
        String vRc = mr.find() ? mr.group(1) : "";
        if (!vPhp.isEmpty() && !vRc.isEmpty() && !vPhp.equals(vRc)) {
            note.put(I18n.tr("server.um.webmailCompatibility.1", java.util.Map.of("vRc", String.valueOf(vRc), "vPhp", String.valueOf(vPhp))));
        }
        // What the panel names in its own scripts: if it diverges from what is installed, the
        // next generated script would point to a path that does not exist.
        if (!vPhp.isEmpty() && !("84".equals(vPhp))) {
            note.put(I18n.tr("server.um.webmailCompatibility.2", java.util.Map.of("vPhp", String.valueOf(vPhp))));
        }
        r.put("notes", note);
        r.put("consistent", note.length() == 0);
        return r.put("success", true);
    }

    /**
     * Content of the configuration files that Dovecot actually reads, read-only.
     *
     * It is needed for a precise reason: the panel has THREE Dovecot configuration generators
     * that have diverged from each other over time (userdb static versus userdb sql, Sieve present
     * or absent, different protocols). To unify them one must know which variant is
     * actually in service, and the only honest way is to read it, not to deduce it from the code.
     *
     * The credentials are masked BEFORE leaving here: dovecot-sql.conf contains the
     * password of the mailbox database, and this text ends up in a web page.
     */
    public static JSONObject dumpDovecotConfig() {
        JSONArray files = new JSONArray();
        for (String f : fileDovecot()) {
            String content = sh("cat " + f + " 2>/dev/null", 20);
            content = maskCredentials(content);
            if (content.length() > 20000) content = content.substring(0, 20000) + "\n... " + I18n.tr("server.um.x.truncated");
            files.put(new JSONObject().put("path", f).put("content", content)
                    .put("lines", content.isEmpty() ? 0 : content.split("\n").length));
        }
        return new JSONObject().put("success", true).put("files", files).put("count", files.length());
    }

    /**
     * Removes every password from the text. Deliberately coarse: better to mask something
     * harmless than to let a credential through into a web page.
     */
    static String maskCredentials(String text) {
        if (text == null) return "";
        return text
                .replaceAll("(?i)(password\\s*=\\s*)\\S+", "$1********")
                .replaceAll("(?i)(password=)[^\\s;]+", "$1********")
                .replaceAll("(?i)(pass\\s*=\\s*)\\S+", "$1********")
                .replaceAll("(?i)(secret\\s*=\\s*)\\S+", "$1********");
    }

    /**
     * Postfix has no announced break like Dovecot 2.4: it has a different, and
     * declared, mechanism called compatibility_level.
     *
     * Since 3.0, when Postfix changes a default value in an incompatible way, it does NOT
     * apply it: it keeps using the old one and writes in the log "using backwards-compatible
     * default setting name=value". The safety net is removed by raising
     * compatibility_level to the version number. So the right question for Postfix is not
     * "what will break?" but "which old settings am I relying on right now?",
     * and Postfix itself writes the answer.
     *
     * Source: https://www.postfix.org/COMPATIBILITY_README.html and postconf(5).
     */
    // What changes at each Postfix compatibility level: in PostfixLevels, which the installation also reads.

    /**
     * Postfix has no announced break like Dovecot 2.4: it has a different, and
     * declared, mechanism called compatibility_level.
     *
     * Since 3.0, when a default value changes in an incompatible way, Postfix does NOT
     * apply it: it keeps using the old one until the administrator raises the level.
     * So the right question is not "what will break?" but "how far behind am I, and what
     * would change if I caught up?".
     *
     * The first version of this check decided based on whether "postfix check"
     * printed something, and produced the absurd sentence "it is using 0 old settings,
     * listed below" with no list. The right comparison is between the level set and
     * the one Postfix itself indicates in its own message.
     */
    public static JSONObject postfixCompatibility() {
        JSONObject r = new JSONObject().put("success", true);
        String pkg = sh("pkg query %n 2>/dev/null | grep -E '^postfix(-[a-z]+)?$' | head -1", 20).trim();
        if (pkg.isEmpty() || !isValidName(pkg))
            return r.put("present", false).put("note", I18n.tr("server.um.postfixCompatibility.1"));
        r.put("present", true).put("package", pkg)
         .put("version", sh("pkg query %v " + pkg, 20))
         .put("repoVersion", sh("pkg rquery -U %v " + pkg + " 2>/dev/null", 30));

        if (!ok("command -v postconf >/dev/null 2>&1", 15))
            return r.put("readable", false)
                    .put("note", I18n.tr("server.um.postfixCompatibility.2"));
        r.put("readable", true);

        String set = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        r.put("level", set)
         .put("explicitLevel", ok("postconf -n 2>/dev/null | grep -q '^compatibility_level'", 20));

        String check = sh("postfix check 2>&1", 60);
        // The field had been lost in the rewrite, and the interface showed the heading
        // "postfix check:" followed by nothing: a title without content looks like a fault.
        r.put("check", check.isBlank() ? "" : check).put("cleanCheck", check.isBlank());

        // The level Postfix itself says to raise to, taken from its message.
        String recommended = "";
        Matcher mc = Pattern.compile("compatibility_level=([0-9.]+)").matcher(check);
        if (mc.find()) recommended = mc.group(1);
        r.put("recommended", recommended);

        // What would change: only the levels STRICTLY between the one set and the one indicated.
        JSONArray changes = new JSONArray();
        double from = levelNumber(set), to = levelNumber(recommended);
        if (to > from) {
            String written = sh("postconf -n 2>/dev/null | sed -E 's/[[:space:]]*=.*//'", 30);
            java.util.Set<String> decided = new java.util.HashSet<>();
            for (String x : written.split("\n")) if (!x.isBlank()) decided.add(x.trim());
            for (String[] l : PostfixLevels.ALL) {
                double n = levelNumber(l[0]);
                if (!(n > from && n <= to)) continue;
                JSONArray pieces = new JSONArray();
                int open = 0;
                for (String entry : l[2].split("\\s+")) {
                    if (entry.isBlank()) continue;
                    // "name@gate=value": the parameter counts only if the gate has that value.
                    String name = entry, gate = "", expected = "";
                    int at = entry.indexOf('@');
                    if (at > 0) {
                        name = entry.substring(0, at);
                        String g = entry.substring(at + 1);
                        int eq = g.indexOf('=');
                        if (eq > 0) { gate = g.substring(0, eq); expected = g.substring(eq + 1); }
                    }
                    if (!isValidName(name)) continue;
                    boolean already = decided.contains(name);
                    String gateValue = gate.isEmpty() || !isValidName(gate) ? ""
                            : sh("postconf -h " + gate + " 2>/dev/null", 15).trim();
                    boolean relevant = gate.isEmpty() || expected.equalsIgnoreCase(gateValue);
                    if (!already && relevant) open++;
                    JSONObject o = new JSONObject().put("name", name).put("alreadyDecided", already)
                            .put("value", already ? sh("postconf -h " + name + " 2>/dev/null", 15).trim() : "")
                            .put("relevant", relevant);
                    if (!gate.isEmpty())
                        o.put("gate", gate).put("gateValue", gateValue).put("expectedGate", expected);
                    pieces.put(o);
                }
                changes.put(new JSONObject().put("level", l[0]).put("change", l[1])
                        .put("parameters", pieces).put("openHere", open));
            }
        }
        r.put("changes", changes);

        String warnings = sh("grep -hE 'using backwards-compatible default setting [a-z0-9_]+=' "
                + "/var/log/maillog /var/log/maillog.[0-9] 2>/dev/null "
                + "| sed -E 's/.*using backwards-compatible default setting //' "
                + "| sed -E 's/[[:space:]]*(to|;).*//' | sort -u | head -40", 60);
        JSONArray lines = new JSONArray();
        for (String l : warnings.split("\n")) if (!l.isBlank()) lines.put(l.trim());
        r.put("supports", lines);

        boolean back = to > from;
        r.put("back", back);
        r.put("verdict", back ? "LEVEL_BEHIND" : "ALIGNED");
        r.put("explanation", back
                ? I18n.tr("server.um.postfixCompatibility.4", java.util.Map.of("configured", String.valueOf(set), "recommended", String.valueOf(recommended)))
                : (set.isBlank()
                   ? I18n.tr("server.um.postfixCompatibility.5")
                   : I18n.tr("server.um.postfixCompatibility.6", java.util.Map.of("configured", String.valueOf(set)))));
        int openTotal = 0;
        for (int i = 0; i < changes.length(); i++) openTotal += changes.getJSONObject(i).getInt("openHere");
        r.put("openHere", openTotal);
        r.put("effectHere", !back ? ""
                : (openTotal == 0
                   ? I18n.tr("server.um.postfixCompatibility.7")
                   : (openTotal == 1
                      ? I18n.tr("server.um.x.pfOpen.one")
                      : I18n.tr("server.um.x.pfOpen.other", java.util.Map.of("n", String.valueOf(openTotal))))));
        r.put("howToRaise", back
                ? I18n.tr("server.um.postfixCompatibility.10", java.util.Map.of("recommended", String.valueOf(recommended)))
                : "");
        r.put("source", I18n.tr("server.um.postfixCompatibility.11"));
        return r;
    }

    /**
     * The maximum analysis time of a message, and whether that limit has ever been reached.
     *
     * rspamadm configtest warns that task_timeout (8s) is lower than the theoretical maximum of the
     * symbols cache (10s). It is a consistency check ADDED in 4.1.0, not a fault
     * that has appeared now, and the documentation calls it informational. Those 10 seconds
     * are the sum of the limits of the individual symbols: for them to be really reached, each
     * one would have to use up its own time on the same message.
     *
     * Raising a timeout because a warning names it would be a choice made on a theory.
     * Here we look at whether it has EVER happened: if rspamd has never interrupted an analysis,
     * there is nothing to fix; if it has, we see how many times and when.
     */
    public static JSONObject rspamdTimeoutDiagnostics() {
        JSONObject r = new JSONObject().put("success", true);
        if (!ok("pkg info -e rspamd", 20))
            return r.put("present", false).put("note", I18n.tr("server.um.rspamdTimeoutDiagnostics.1"));
        r.put("present", true);

        String ct = ok("command -v rspamadm >/dev/null 2>&1", 15)
                ? sh("rspamadm configtest 2>&1", 60) : "";
        r.put("configtest", ct);
        Matcher m = Pattern.compile("task_timeout ([0-9.]+) is less than maximum symbols cache timeout ([0-9.]+)")
                .matcher(ct);
        if (m.find()) r.put("taskTimeout", m.group(1)).put("theoreticalMax", m.group(2)).put("warns", true);
        else r.put("warns", false);

        JSONArray symbols = new JSONArray();
        Matcher ms = Pattern.compile("([A-Z0-9_]+)\\(([0-9.]+)\\)").matcher(ct);
        while (ms.find())
            symbols.put(new JSONObject().put("name", ms.group(1)).put("seconds", ms.group(2)));
        r.put("symbols", symbols);

        // The proof, if there is any, is in the log. I do not look for a precise sentence -- I do not
        // know it, and inventing it would give zero results that would look like good news. I look for
        // the word and show what is there, grouped.
        String log = "/var/log/rspamd/rspamd.log";
        boolean logC = ok("test -r " + log, 15);
        r.put("log", log).put("logReadable", logC);
        // A single reader for the whole history, compressed files included.
        String reader = "for f in " + log + " /var/log/rspamd/rspamd.log.*; do "
                + "[ -f \"$f\" ] || continue; case \"$f\" in "
                + "*.bz2) bzip2 -dc \"$f\" 2>/dev/null;; *.gz) gzip -dc \"$f\" 2>/dev/null;; "
                + "*.xz) xz -dc \"$f\" 2>/dev/null;; *.zst) zstd -dc \"$f\" 2>/dev/null;; "
                + "*) cat \"$f\" 2>/dev/null;; esac; done";
        if (logC) {
            // The first line in rspamd's format, not the newsyslog marker.
            r.put("since", sh("(" + reader + ") | grep -m1 -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' "
                    + "| cut -c1-19", 120).trim());
            r.put("until", sh("grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' " + log
                    + " 2>/dev/null | tail -1 | cut -c1-19", 60).trim());
            String rot = sh("ls /var/log/rspamd/rspamd.log.* 2>/dev/null | wc -l", 30).trim().replaceAll("[^0-9]", "");
            int rotations = rot.isEmpty() ? 0 : Integer.parseInt(rot);
            String compressed = sh("ls /var/log/rspamd/rspamd.log.*.[bg]z* 2>/dev/null | wc -l", 30)
                    .trim().replaceAll("[^0-9]", "");
            r.put("rotations", rotations)
             .put("compressedRotations", compressed.isEmpty() ? 0 : Integer.parseInt(compressed));
            String lines = sh("(" + reader + ") | grep -i 'timeout' "
                    + "| sed -E 's/^[^;]*; //' | sed -E 's/[0-9a-f]{8,}/<id>/g' "
                    + "| sed -E 's/[0-9]+\\.[0-9]+/<n>/g' | sort | uniq -c | sort -rn | head -15", 300);
            JSONArray groups = new JSONArray();
            int realOnes = 0, warning = 0;
            for (String l : lines.split("\n")) {
                String t = l.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                try {
                    int times = Integer.parseInt(t.substring(0, sp));
                    String msg = t.substring(sp + 1).trim();
                    // rspamd_worker_check_and_adjust_timeout is the consistency check that
                    // rspamd runs at startup: it is the warning, not one of its effects.
                    boolean isWarning = msg.contains("check_and_adjust_timeout")
                            || msg.contains("symbols cache timeout")
                            || msg.contains("symbols by execution time");
                    if (isWarning) warning += times; else realOnes += times;
                    groups.put(new JSONObject().put("times", times).put("messageText", msg)
                            .put("isWarning", isWarning));
                } catch (NumberFormatException ignored) { }
            }
            r.put("inLog", groups).put("interruptions", realOnes).put("warningRepeats", warning);
            String tot = sh("(" + reader + ") | grep -ci 'timeout'", 300).trim().replaceAll("[^0-9]", "");
            r.put("occurrences", tot.isEmpty() ? 0 : Integer.parseInt(tot));
            String totalLines = sh("(" + reader + ") | wc -l", 300).trim().replaceAll("[^0-9]", "");
            r.put("logLines2", totalLines.isEmpty() ? 0 : Integer.parseInt(totalLines));
            String onlyCurrent = sh("wc -l < " + log + " 2>/dev/null", 60).trim().replaceAll("[^0-9]", "");
            r.put("currentLines", onlyCurrent.isEmpty() ? 0 : Integer.parseInt(onlyCurrent));
        }

        int occ = r.optInt("occurrences", -1);
        int logLines2 = r.optInt("logLines2", 0);
        // A small sample does not entitle anyone to say "never". The threshold is not a magic number:
        // below a thousand lines a mail log typically covers a few hours, and in a few hours
        // the slow message that would trigger the case may simply not have come through.
        boolean wideSample = logLines2 >= 1000;
        String period = r.optString("since", "").isEmpty() ? ""
                : " " + I18n.tr("server.um.x.rsLogSpan", java.util.Map.of("since", String.valueOf(r.optString("since")), "until", String.valueOf(r.optString("until"))));
        String rotate = r.optInt("rotations", 0) > 0
                ? " " + (r.optInt("compressedRotations", 0) > 0
                     ? I18n.tr("server.um.x.rsRotZ", java.util.Map.of("n", String.valueOf(r.optInt("rotations")), "z", String.valueOf(r.optInt("compressedRotations")), "lines", String.valueOf(r.optInt("currentLines", 0))))
                     : I18n.tr("server.um.x.rsRot", java.util.Map.of("n", String.valueOf(r.optInt("rotations")), "lines", String.valueOf(r.optInt("currentLines", 0)))))
                : I18n.tr("server.um.rspamdTimeoutDiagnostics.2");
        r.put("wideSample", wideSample);
        int interruptions = r.optInt("interruptions", occ);
        r.put("verdict", !logC ? "LOG_UNREADABLE"
                : (interruptions > 0 ? "SCANS_INTERRUPTED"
                                    : (wideSample ? "NO_SCAN_INTERRUPTED"
                                                     : "NO_TRACE_SHORT_LOG")));
        String decomposition = occ == 0 ? ""
                : " " + I18n.tr("server.um.x.rsSplit", java.util.Map.of("occurrences", String.valueOf(occ), "warnings", String.valueOf(r.optInt("warningRepeats", 0)), "interruptions", String.valueOf(interruptions)));
        r.put("explanation", !logC
                ? I18n.tr("server.um.rspamdTimeoutDiagnostics.7", java.util.Map.of("log", String.valueOf(log)))
                : (interruptions == 0
                   ? (occ == 0
                        ? I18n.tr("server.um.rspamdTimeoutDiagnostics.8", java.util.Map.of("logLines", String.valueOf(logLines2)))
                        : I18n.tr("server.um.rspamdTimeoutDiagnostics.9", java.util.Map.of("logLines", String.valueOf(logLines2), "breakdown", String.valueOf(decomposition))))
                     + period + rotate
                     + (wideSample
                        ? I18n.tr("server.um.rspamdTimeoutDiagnostics.10")
                        : I18n.tr("server.um.rspamdTimeoutDiagnostics.11", java.util.Map.of("logLines", String.valueOf(logLines2))))
                     + " " + I18n.tr("server.um.x.rsTheoretical")
                   : I18n.tr("server.um.rspamdTimeoutDiagnostics.12", java.util.Map.of("interruptions", String.valueOf(interruptions), "logLines", String.valueOf(logLines2), "breakdown", String.valueOf(decomposition), "period", String.valueOf(period), "rotate", String.valueOf(rotate)))));
        r.put("ifNeeded", I18n.tr("server.um.rspamdTimeoutDiagnostics.13"));
        r.put("source", I18n.tr("server.um.rspamdTimeoutDiagnostics.14"));
        return r;
    }

    /**
     * Raises the Postfix compatibility level, from the panel.
     *
     * It is not a command pasted into a button: it is the same thing one would do by hand,
     * plus the three things that get forgotten by hand -- the copy of main.cf before touching
     * it, the check that the value has REALLY changed, and the automatic rollback if
     * something does not add up.
     *
     * The outcome is told by the system, not by the exit code of postconf: the value is read
     * again, Postfix is asked whether it is still up, and "postfix check" is run again to see
     * whether the warning has actually gone.
     */
    public static JSONObject raisePostfixCompatibilityLevel(String target) {
        JSONObject r = new JSONObject().put("pkgName", "postfix");
        if (target == null || !target.matches("[0-9]+(\\.[0-9]+)?"))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.1", java.util.Map.of("target", String.valueOf(target))));
        if (!ok("command -v postconf >/dev/null 2>&1", 15))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.2"));

        StringBuilder log = new StringBuilder();
        String before = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        log.append(I18n.tr("server.um.x.pfLevelBefore", java.util.Map.of("v", String.valueOf(before)))).append("\n");
        if (before.equals(target))
            return r.put("success", true).put("alreadyAtLevel", true).put("before", before).put("after", before)
                    .put("log", log.toString())
                    .put("note", I18n.tr("server.um.raisePostfixCompatibilityLevel.3", java.util.Map.of("target", String.valueOf(target))));

        if (levelNumber(target) < levelNumber(before))
            return r.put("success", false).put("before", before)
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.4", java.util.Map.of("before", String.valueOf(before), "target", String.valueOf(target))));

        // The copy comes before everything: it is what makes the rest reversible.
        String mainCf = sh("postconf -h config_directory 2>/dev/null", 20).trim();
        if (mainCf.isEmpty()) mainCf = "/usr/local/etc/postfix";
        mainCf = mainCf + "/main.cf";
        if (!ok("test -f " + mainCf, 15))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.5", java.util.Map.of("mainCf", String.valueOf(mainCf))));
        String copy = "/var/db/daemoxcp-mail/main.cf-" + sh("date '+%Y%m%d-%H%M%S'", 15).trim();
        sh("mkdir -p /var/db/daemoxcp-mail && cp -p " + mainCf + " " + copy, 30);
        boolean copyOk = ok("test -s " + copy, 15);
        r.put("copy", copy).put("copyOk", copyOk);
        log.append(copyOk ? I18n.tr("server.um.raisePostfixCompatibilityLevel.6", java.util.Map.of("copy", String.valueOf(copy)))
                           : I18n.tr("server.um.raisePostfixCompatibilityLevel.7"));
        if (!copyOk)
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.8"));

        log.append("--- ").append(I18n.tr("server.um.x.pfWrite")).append(" ---\n")
           .append(sh("postconf -e compatibility_level=" + target + " 2>&1", 60)).append("\n");

        String after = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        log.append(I18n.tr("server.um.x.pfLevelAfter", java.util.Map.of("v", String.valueOf(after)))).append("\n");
        r.put("before", before).put("after", after);
        if (!after.equals(target)) {
            sh("cp -p " + copy + " " + mainCf, 30);
            log.append(I18n.tr("server.um.x.pfUnchanged")).append("\n");
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.9", java.util.Map.of("after", String.valueOf(after))));
        }

        log.append("--- ").append(I18n.tr("server.um.x.pfReload")).append(" ---\n")
           .append(sh("postfix reload 2>&1", 60)).append("\n");

        // Is Postfix still up? The question is not rhetorical: a main.cf accepted by
        // postconf may still not be to the master's liking.
        boolean active = ok("service postfix status", 30);
        r.put("active", active);
        log.append(active ? I18n.tr("server.um.x.pfUpAfter") : I18n.tr("server.um.x.pfDownAfter")).append("\n");
        if (!active) {
            sh("cp -p " + copy + " " + mainCf, 30);
            sh("service postfix start 2>&1 || postfix start 2>&1", 60);
            boolean climbed = ok("service postfix status", 30);
            log.append(I18n.tr("server.um.x.pfRestored", java.util.Map.of("outcome", String.valueOf(climbed ? I18n.tr("server.um.x.pfBackUp") : I18n.tr("server.um.raisePostfixCompatibilityLevel.10"))))).append("\n");
            return r.put("success", false).put("log", log.toString())
                    .put("error", climbed
                            ? I18n.tr("server.um.x.pfDownBack")
                            : I18n.tr("server.um.x.pfDownStill"));
        }

        String check = sh("postfix check 2>&1", 60);
        boolean warningVia = !check.contains("backwards-compatible");
        r.put("check", check).put("warningVia", warningVia);
        log.append("--- postfix check ---\n").append(check.isBlank() ? I18n.tr("server.um.x.noMessage") : check).append("\n");

        return r.put("success", true).put("log", log.toString())
                .put("note", warningVia
                        ? I18n.tr("server.um.x.pfRaisedClean", java.util.Map.of("before", String.valueOf(before), "after", String.valueOf(after), "copy", String.valueOf(copy)))
                        : I18n.tr("server.um.x.pfRaisedWarn", java.util.Map.of("before", String.valueOf(before), "after", String.valueOf(after), "copy", String.valueOf(copy))));
    }

    /** "3.11" -> 3.11, "2" -> 2. It only serves to order the levels among themselves. */
    private static double levelNumber(String v) {
        if (v == null) return -1;
        Matcher m = Pattern.compile("^([0-9]+)(?:\\.([0-9]+))?").matcher(v.trim());
        if (!m.find()) return -1;
        double n = Double.parseDouble(m.group(1));
        if (m.group(2) != null) n += Double.parseDouble(m.group(2)) / 100.0;
        return n;
    }

    /**
     * Rspamd changes by degrees, and the changes that matter are not of syntax but of
     * BEHAVIOR: an option that disappears, a default that flips, a symbol that
     * changes name. A file that stays valid can therefore produce different results.
     *
     * The entries below come one by one from the official 4.0 and 4.1 release notes.
     */
    private static final String[][] RSPAMD_CONSTRUCTS = {
        {"(^|[^A-Za-z0-9_])ssl[[:space:]]*=[[:space:]]*true", "server.um.levelNumber.1",
         "server.um.levelNumber.2", "broken"},
        {"include_content_urls", "include_content_urls",
         "server.um.levelNumber.3", "behavior"},
        {"token_bucket", "server.um.levelNumber.4",
         "server.um.levelNumber.5", "behavior"},
        {"senderscore_reputation", "senderscore_reputation",
         "server.um.levelNumber.6", "behavior"},
        {"MX_NXDOMAIN|MX_MISSING", "server.um.rspamd4.mxSymbols",
         "server.um.levelNumber.7", "behavior"},
    };

    public static JSONObject rspamdCompatibility() {
        JSONObject r = new JSONObject().put("success", true);
        if (!ok("pkg info -e rspamd", 20))
            return r.put("present", false).put("note", I18n.tr("server.um.rspamdTimeoutDiagnostics.1"));
        r.put("present", true)
         .put("version", sh("pkg query %v rspamd", 20))
         .put("repoVersion", sh("pkg rquery -U %v rspamd 2>/dev/null", 30));

        String etc = "/usr/local/etc/rspamd";
        boolean c = ok("test -d " + etc, 15);
        r.put("configPresent", c);
        JSONArray issues = new JSONArray();
        int filesRead = 0;
        if (c) {
            String n = sh("grep -rIl '' " + etc + " 2>/dev/null | wc -l", 60).trim().replaceAll("[^0-9]", "");
            filesRead = n.isEmpty() ? 0 : Integer.parseInt(n);
            for (String[] k : RSPAMD_CONSTRUCTS) {
                String where = sh("grep -rIlE '" + k[0] + "' " + etc + " 2>/dev/null | head -20", 60);
                if (where.isBlank()) continue;
                JSONArray yours = new JSONArray(), ofPackage = new JSONArray();
                for (String f : where.split("\n")) {
                    String t = f.trim();
                    if (t.isEmpty()) continue;
                    if (!t.matches("[A-Za-z0-9_./+-]{1,256}")) continue;
                    boolean ownedByPkg = !sh("pkg which -q " + t + " 2>/dev/null", 20).trim().isEmpty();
                    (ownedByPkg ? ofPackage : yours).put(t);
                }
                if (yours.length() == 0 && ofPackage.length() == 0) continue;
                issues.put(new JSONObject().put("construct", I18n.tr(k[1])).put("whatChanges", I18n.tr(k[2]))
                        .put("type", yours.length() > 0 ? k[3] : "default")
                        .put("files", yours).put("packageFiles", ofPackage));
            }
        }
        r.put("filesRead", filesRead).put("issues", issues);

        // rspamadm configtest is the equivalent of doveconf -n: rspamd says so, not me.
        if (ok("command -v rspamadm >/dev/null 2>&1", 15)) {
            String t = sh("rspamadm configtest 2>&1", 60);
            r.put("configtest", t).put("configtestOk", t.toLowerCase().contains("syntax ok"));
        } else {
            r.put("configtest", I18n.tr("server.um.rspamdCompatibility.1")).put("configtestOk", false);
        }

        // The Bayes recalculation concerns ONLY installations with Redis split across several
        // servers: saying so avoids scaring those who are not in that case.
        int redis = 0;
        if (c) {
            String rr = sh("grep -rhoE 'servers[[:space:]]*=[[:space:]]*\"[^\"]+\"' " + etc
                    + "/local.d/redis.conf 2>/dev/null | head -1", 20);
            redis = rr.isBlank() ? 1 : rr.split(",").length;
        }
        r.put("redisServer", redis)
         .put("bayes", redis > 1
                ? I18n.tr("server.um.rspamdCompatibility.2")
                : I18n.tr("server.um.rspamdCompatibility.3"));

        int broken = 0, yoursTotal = 0, packageOnly = 0;
        for (int i = 0; i < issues.length(); i++) {
            JSONObject q = issues.getJSONObject(i);
            int nYours = q.getJSONArray("files").length();
            yoursTotal += nYours;
            if (nYours == 0) packageOnly++;
            if (nYours > 0 && "broken".equals(q.getString("type"))) broken++;
        }
        r.put("yours", yoursTotal).put("packageOnly", packageOnly);
        r.put("verdict", broken > 0 ? "INVALID_CONSTRUCT"
                : (yoursTotal > 0 ? "BEHAVIOR_DIFFS"
                               : "NOTHING_TO_REPORT"));
        r.put("explanation", broken > 0
                ? I18n.tr("server.um.rspamdCompatibility.7", java.util.Map.of("broken", String.valueOf(broken)))
                : (yoursTotal > 0
                   ? I18n.tr("server.um.rspamdCompatibility.8")
                   : I18n.tr("server.um.x.rsClean")
                     + (packageOnly > 0
                        ? " " + I18n.tr("server.um.x.rsOnlyPkg", java.util.Map.of("n", String.valueOf(packageOnly)))
                        : "")));
        r.put("source", I18n.tr("server.um.rspamdCompatibility.9"));
        return r;
    }

    /** The checks together: it is what one looks at before pressing "update". */
    public static JSONObject compatibilityReport() {
        return new JSONObject().put("success", true)
                .put("dovecot", dovecotCompatibility())
                .put("postfix", postfixCompatibility())
                .put("rspamd", rspamdCompatibility())
                .put("mysql", mysqlCompatibility())
                .put("webmail", webmailCompatibility());
    }

    // ===================== jobs in progress =====================

    /**
     * The job running now, in words, or null: the package turn (PackageQueue) or a panel job that has
     * not yet written its end. For the restart, which is not scheduled on top of a half-done job.
     */
    public static String runningWork() {
        String holder = PackageQueue.holder();
        if (holder != null) return holder;
        // Until the end is written the job is running, even with the outcome already set (visibleStatus). One
        // stuck for more than six hours is not a job, it is a defect: it must not prevent the restart forever,
        // which is often the cure.
        long now = System.currentTimeMillis();
        for (Job j : JOBS.values()) {
            String v = j.visibleStatus();
            if (("running".equals(v) || "pending".equals(v)) && now - j.startedAt < 6 * 3_600_000L)
                return j.type + " (" + j.id + ")";
        }
        return null;
    }

    /**
     * The package job running now, for "Update the server" (finding 206): who holds the turn, since when,
     * and its id if it is a job the page can follow. The owner, refused twice while a search was running:
     * "it does not show what it is doing or anything". The turn is the one of this process (PackageQueue):
     * the panel's jobs, whoever started them, from this page, from another one or from another tab.
     */
    public static JSONObject packageTurn() {
        JSONObject r = new JSONObject().put("success", true);
        String who = PackageQueue.holder();
        if (who == null) {
            // The Java update: the script works outside the panel, so the panel's turn is free.
            // On the production server, on 2026-11-09, "Update everything" handed over to it and the script
            // worked for 4 minutes: after reloading the page, the card said "1 step to do: Java" and a
            // warning about a job "that has not finished", nothing about what was happening
            // (finding 210). Now the turn says so, with its log.
            JSONObject java = javaUpdateInProgress();
            if (java == null) return r.put("running", false);
            String text = java.optString("text");
            return r.put("running", true).put("java", true).put("who", I18n.tr("server.um.javaRunningWho"))
                    .put("log", text.length() > 6000 ? text.substring(text.length() - 6000) : text);
        }
        r.put("running", true).put("who", who);
        String id = PackageQueue.holderId();
        if (id != null && JOBS.containsKey(id)) r.put("jobId", id);
        return r;
    }

    /** A long operation that the panel follows while it happens. */
    public static final class Job {
        public final String id;
        public final String type;
        public volatile String status = "pending";
        public volatile String errorMessage = "";
        /** The final message of a successful job, to be shown as it is (e.g. the branch change). */
        public volatile String outcome = "";
        public volatile int step, total;
        public final long startedAt = System.currentTimeMillis();
        public volatile long finishedAt;
        private final StringBuilder log = new StringBuilder();
        /**
         * The on-disk log of this job (JobJournal), or null if it could not be opened. It is opened at the
         * first line, not when the job is born: a job refused because the turn belongs to another one writes
         * nothing, and before it left a log with the start and without the end, which Diagnostics counted
         * among those "finished without an end". On the production server, on 2026-11-09, two "Update the
         * packages" pressed during a search (finding 206).
         */
        private java.nio.file.Path journal;
        private boolean journalOpened;
        /**
         * What must be done before the end is written: the cleanup of the way back (withWayBack). Before, it
         * ran after the job, so after the end: on the VM, on 2026-11-09, "Update everything" wrote "Way back:
         * older boot environment ... removed" after "=== end", and the list of logs, which reads the last
         * line, reported it as "without an end" (finding 207). And the page saw the job finished while bectl
         * was still working.
         */
        private final java.util.List<Runnable> beforeEnd = new java.util.ArrayList<>();

        Job(String id, String type) {
            this.id = id;
            this.type = type;
        }

        private java.nio.file.Path journal() {
            if (!journalOpened) {
                journalOpened = true;
                journal = JobJournal.open(id, type, startedAt);
            }
            return journal;
        }

        public synchronized void write(String line) {
            log.append('[')
               .append(new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date()))
               .append("] ").append(line).append('\n');
            // A pkg upgrade of a hundred packages produces thousands of lines: without a cap the
            // job would keep all the output in memory and the page would become unreadable.
            if (log.length() > 200_000) log.delete(0, log.length() - 150_000);
            JobJournal.append(journal(), line);
        }

        public void advance(int s, int t) { this.step = s; this.total = t; }

        /**
         * The end of the job: the time, and in the on-disk log the outcome (status, error, duration). Once
         * only: whoever writes it second changes nothing.
         */
        public void finish() {
            synchronized (this) { if (finishedAt != 0) return; }
            // Outside the lock: bectl can take minutes, and meanwhile the page asks for the status (toJson).
            runBeforeEnd();
            synchronized (this) {
                if (finishedAt != 0) return;
                finishedAt = System.currentTimeMillis();
                JobJournal.end(journal(), status, errorMessage, outcome, (finishedAt - startedAt) / 1000);
            }
        }

        /** To be done before the end is written, once only. The end is written by the job's thread. */
        void beforeEnd(Runnable r) {
            synchronized (this) { beforeEnd.add(r); }
        }

        /** What is waiting for the end, now: each one once only, even if one throws an exception. */
        void runBeforeEnd() {
            java.util.List<Runnable> todo;
            synchronized (this) {
                todo = new java.util.ArrayList<>(beforeEnd);
                beforeEnd.clear();
            }
            for (Runnable r : todo) {
                try { r.run(); }
                catch (RuntimeException e) { LOGGER.warning("[Job " + id + "] before the end: " + e); }
            }
        }

        /** Writes the end, if the job has not already written it by itself: see withEndMarked. */
        void markFinished() { finish(); }

        /**
         * The status as whoever is waiting for the job must see it.
         *
         * A job writes "completed" or "error" when it has an outcome, but it often still has things
         * to do: the full maintenance writes "completed" as soon as pkg upgrade exits with 0, and
         * AFTERWARDS compares with the plan and the inventory, locks the packages again, checks
         * locks and services -- and each of these steps can change the outcome to "error".
         * The page stops asking at the first outcome it sees: a job that went wrong could
         * appear as successful, and the lines of the final check did not reach the screen.
         * Measured on the VM on 2026-10-23: a probe stopped at the first "completed" found 14
         * packages out of 39 still to be locked again.
         *
         * So an outcome is visible only when the end is written, that is, when the job has
         * really finished. Until then the job is "running", as it is.
         *
         * The order of the two reads matters: first the end, then the status. They are volatile
         * fields and the job writes the status BEFORE the end, so whoever sees the end also sees
         * the status there was at that point. In the opposite order one could read the status from
         * before the finally and the end from after it, and show as final a "completed" already
         * superseded.
         */
        String visibleStatus() {
            long f = finishedAt;
            String s = status;
            return f == 0 && ("completed".equals(s) || "error".equals(s)) ? "running" : s;
        }

        public synchronized JSONObject toJson() {
            return new JSONObject()
                    .put("id", id).put("type", type).put("status", visibleStatus())
                    .put("step", step).put("total", total)
                    .put("percent", total > 0 ? (step * 100 / total) : 0)
                    .put("errorMessage", errorMessage)
                    .put("result", outcome)
                    .put("elapsedSeconds", ((finishedAt > 0 ? finishedAt : System.currentTimeMillis()) - startedAt) / 1000)
                    .put("consoleLog", log.toString());
        }
    }

    public static JSONObject jobStatus(String id) {
        Job j = JOBS.get(id);
        // "unknown": the panel no longer knows the job (it has restarted). The page stops asking and says
        // where the on-disk log is, instead of asking forever.
        return j == null ? new JSONObject().put("success", false).put("unknown", true).put("error", I18n.tr("server.um.jobStatus.1"))
                         : new JSONObject().put("success", true).put("job", j.toJson());
    }

    /**
     * Runs a long command, writing the output to the job's log as it arrives.
     * Shell.run collects everything and returns at the end: for a pkg upgrade lasting minutes
     * it would mean a frozen page without knowing whether it is working.
     */
    static int runLogged(Job job, String command, int timeoutSeconds) throws Exception {
        return runLogged(job, command, timeoutSeconds, null);
    }

    static int runLogged(Job job, String command, int timeoutSeconds, StringBuilder capture) throws Exception {
        return runLogged(job, command, timeoutSeconds, capture, null);
    }

    /** The exit code of a command stopped when the time runs out, like timeout(1). */
    static final int TIMED_OUT = 124;

    /**
     * A command that changes the packages or the system, which does NOT stop when the time runs out.
     *
     * Measured on the VM on 2026-11-06 (finding 147): when the time ran out the log said "terminating
     * the process", but the process terminated was the shell; pkg, its child, kept going and finished,
     * and runLogged returned only at the end of pkg with IOException instead of a code. The job
     * ended in error while pkg was still installing. Really stopping it is not the cure: a pkg
     * killed in the middle of an installation leaves packages half installed. So for these
     * commands the time becomes a warning threshold: it says it is still working and waits.
     * Downloading (-F) and simulating (-n), instead, can be stopped.
     */
    static boolean mustNotBeKilled(String command) {
        for (String part : command.split("[;&|]")) {
            String c = part.trim();
            String[] w = c.split("\\s+");
            if (w.length == 0) continue;
            String cmd = w[0].substring(w[0].lastIndexOf('/') + 1);
            if (cmd.equals("pkg") || cmd.equals("pkg-static")) {
                String sub = null;
                for (int i = 1; i < w.length; i++) if (!w[i].startsWith("-")) { sub = w[i]; break; }
                if (sub == null || !Set.of("upgrade", "install", "delete", "remove", "autoremove", "add").contains(sub)) continue;
                List<String> words = List.of(w);
                if (words.contains("-n") || words.contains("--dry-run") || words.contains("-F") || words.contains("--fetch-only")) continue;
                return true;
            }
            if (cmd.equals("freebsd-update") && (List.of(w).contains("install") || List.of(w).contains("rollback"))) return true;
        }
        return false;
    }

    /** Stops the process and ALL its descendants: first gently, after 10 seconds forcibly. */
    static void stopTree(Process p) {
        List<ProcessHandle> tree = p.descendants().toList();
        tree.forEach(ProcessHandle::destroy);
        p.destroy();
        long until = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < until && (p.isAlive() || tree.stream().anyMatch(ProcessHandle::isAlive))) {
            try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
        tree.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
        if (p.isAlive()) p.destroyForcibly();
    }

    static int runLogged(Job job, String command, int timeoutSeconds,
                            StringBuilder capture, Map<String, String> environment) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        org.daemoxcp.mail.util.Shell.applyPath(pb);
        if (environment != null) pb.environment().putAll(environment);
        // Standard input is /dev/null, as in Shell: the default pipe of
        // ProcessBuilder never reaches EOF, so a command that reads would stay
        // stuck for the whole timeout -- here 1800 or 3600 seconds. The full reason is
        // on the NO_STDIN field of Shell.
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
        pb.redirectErrorStream(true);
        Process p = pb.start();

        // The timeout must be watched from OUTSIDE. Putting it only on the final waitFor would
        // be of no use: if the process hangs without closing standard output,
        // readLine waits forever and the waitFor is never reached.
        boolean keepWaiting = mustNotBeKilled(command);
        java.util.concurrent.atomic.AtomicBoolean stopped = new java.util.concurrent.atomic.AtomicBoolean(false);
        Thread guard = localizedThread(() -> {
            try {
                long waited = 0;
                while (!p.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS)) {
                    waited += timeoutSeconds;
                    if (keepWaiting) {
                        job.write(I18n.tr("server.um.runLogged.pkgStillRunning", java.util.Map.of(
                                "cmd", command.trim().split("\\s+")[0], "minutes", String.valueOf(Math.max(1, waited / 60)))));
                        continue;
                    }
                    stopped.set(true);
                    job.write(I18n.tr("server.um.runLogged.stopped", java.util.Map.of("timeoutSeconds", String.valueOf(timeoutSeconds))));
                    stopTree(p);
                    return;
                }
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }, "update-watchdog");
        guard.setDaemon(true);
        guard.start();

        // The output is read in a separate thread, and the end is decided by the PROCESS, not by the output.
        // A process that the command launched and let go (a subshell with "&", a daemon that
        // does not close standard output) leaves the tree and keeps the pipe open: by reading it
        // here to the end, runLogged would have waited for it, timeout or not. Measured on the VM on
        // 2026-11-06: "(sleep 71 &); sleep 63" with a 3-second timeout returned after 71.
        java.util.concurrent.CountDownLatch drained = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<java.io.IOException> readError = new java.util.concurrent.atomic.AtomicReference<>();
        Thread reader = localizedThread(() -> {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = br.readLine()) != null) {
                    job.write(l);
                    if (capture != null) synchronized (capture) { capture.append(l).append('\n'); }
                }
            } catch (java.io.IOException e) {
                // After stopTree the stream closes under the read: what has arrived is everything.
                if (!stopped.get()) readError.set(e);
            } finally {
                drained.countDown();
            }
        }, "update-output");
        reader.setDaemon(true);
        reader.start();
        int code = p.waitFor();
        guard.interrupt();
        if (!drained.await(stopped.get() ? 5 : OUTPUT_GRACE_SECONDS, java.util.concurrent.TimeUnit.SECONDS))
            job.write(I18n.tr("server.um.runLogged.outputHeld"));
        if (readError.get() != null) throw readError.get();
        return stopped.get() ? TIMED_OUT : code;
    }

    /** How long the output is waited for after the end of the command, before no longer waiting for it. */
    static int OUTPUT_GRACE_SECONDS = 30;

    // ===================== state on disk, to survive a crash =====================

    /**
     * The final block of runMaintenanceJob is not executed if the process dies
     * (panel restart, kill, JVM crash): the packages would stay unlocked and
     * nobody would notice until a later update takes a service
     * down. This file is the only thing that survives.
     *
     * It is written with PackageQueue.writeState, which says whether it succeeded: before, a write
     * error ended up in a warning and the job unlocked anyway. Whoever fails to write it
     * unlocks nothing.
     */
    private static void clearState() {
        PackageQueue.deleteState();
    }

    /**
     * To be called at panel startup. If the state file exists, a package job did not
     * reach the end: the listed packages must be locked again right away. Locking again something
     * already locked has no effect, so it is safe even if in fact everything went well.
     *
     * Three things measured on the VM on 2026-11-06 (finding 147), and the answer to each:
     *  - every start of the jar passes through here, even the console menu opened while the web panel
     *    is updating: without the turn between processes it locked again the packages of the running
     *    job and deleted their list. Now the turn is taken, and if another process holds it nothing
     *    is touched;
     *  - if pkg is still working (the panel was killed, not pkg), "pkg lock" fails and the
     *    package stayed unlocked until the NEXT restart. Now it retries on its own every
     *    half minute, until pkg has finished;
     *  - the interruption was noted only in the log. Now there is a warning (PackageRecovery) that the
     *    Updates page and the report show until someone checks.
     */
    public static String restoreLocksAfterCrash() {
        return restoreLocksAfterCrash(I18n.tr("server.recovery.turnAtStartup"));
    }

    /** How often the running service checks whether a package job died halfway. */
    static int watchSeconds = 60;
    private static Thread interruptionWatch;

    /**
     * The watchdog of the --web service: every watchSeconds, the startup restore if a package
     * job died halfway WHILE the panel was running.
     *
     * <p>Measured on the VM on 2026-11-06 (finding 165): the complete reinstallation killed halfway
     * left the 39 packages unlocked with the list on disk, and the running service did not
     * notice: the restore was done only by its next startup, that is, even days later. The
     * same for any job of another panel process (the menu, a console command).
     */
    public static synchronized void startInterruptionWatch() {
        if (interruptionWatch != null && interruptionWatch.isAlive()) return;
        interruptionWatch = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(watchSeconds * 1000L);
                    watchOnce();      // whatever it finds, the restore already writes in the log
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (RuntimeException e) {
                    LOGGER.warning("Watching for interrupted package jobs failed: " + e.getMessage());
                }
            }
        }, "package-job-watch");
        interruptionWatch.setDaemon(true);
        interruptionWatch.start();
    }

    /**
     * One round of the watchdog. The startup restore only if the list is there, it is not the one left
     * on purpose by the JVM update (the restart that the update itself performs closes it), and whoever
     * wrote it is gone. The turn is then checked by the restore: if someone else holds it, it does not
     * touch anything. "" if there was nothing to do.
     */
    static String watchOnce() {
        String relock = relockOnce();
        // Then, with the packages locked and pkg stopped, the interrupted job is completed: services put back in
        // service and checked (InterruptedJobRecovery). Only here, in the panel in service: not in the console menu.
        String completed = InterruptedJobRecovery.completeIfInterrupted(new RecoveryMachine());
        return relock + completed;
    }

    private static String relockOnce() {
        if (!PackageQueue.statePresent()) return "";
        JSONObject job = PackageQueue.jobRecord();
        if (job.optBoolean("expectsRestart")) return "";
        long pid = job.optLong("pid", 0);
        long self = ProcessHandle.current().pid();
        if (pid == self && PackageQueue.holder() != null) return "";     // a job of this process
        if (pid > 0 && pid != self && ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) return "";
        return restoreLocksAfterCrash(I18n.tr("server.recovery.turnWatch"));
    }

    /** The real system for InterruptedJobRecovery: pkg, the rc.d services, the mail searches. */
    static final class RecoveryMachine implements InterruptedJobRecovery.Machine {
        @Override public long now() { return java.time.Instant.now().getEpochSecond(); }
        @Override public boolean pkgRunning() { return !PackageRecovery.pkgRunning().isEmpty(); }
        @Override public Map<String, String> inventory() { return PackagePlan.versionsOnly(PackagePlan.installed()); }
        @Override public Map<String, Long> installTimes(java.util.Collection<String> names) {
            Map<String, Long> out = new LinkedHashMap<>();
            for (String n : names) {
                if (!isValidName(n)) continue;
                long t = number(sh("pkg query %t " + n + " 2>/dev/null", 20).trim());
                if (t > 0) out.put(n, t);
            }
            return out;
        }
        @Override public java.util.List<String> servicesOf(String pkg) {
            java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
            for (String logical : servicesToRestart(pkg)) {
                String real = realServiceName(logical);
                if (real != null) out.add(real);
            }
            return new ArrayList<>(out);
        }
        @Override public Map<String, Boolean> servicesState() { return UpdateManager.servicesState(); }
        @Override public String pid(String service) { return servicePid(service); }
        @Override public long processStart(String pid) {
            if (pid == null || !pid.matches("[0-9]{1,10}")) return -1;
            String e = sh("ps -o etimes= -p " + pid + " 2>/dev/null", 10).trim();
            return e.matches("[0-9]+") ? now() - Long.parseLong(e) : -1;
        }
        @Override public Shell.Result configTest(String service) {
            String test = testConfigOf(service);
            return test == null ? null : Shell.runShell(Duration.ofSeconds(60), test + " 2>&1");
        }
        @Override public boolean restart(String service) { return isValidName(service) && ok("service " + service + " restart", 120); }
        @Override public boolean start(String service) { return isValidName(service) && ok("service " + service + " start", 120); }
        @Override public boolean running(String service) { return isValidName(service) && ok("service " + service + " status", 20); }
        @Override public String dataCheck(String service) {
            String[] after = testAfterOf(service);
            if (after == null) return null;
            String out = sh(after[1], 30).trim();
            return number(out) > 0 ? "" : I18n.tr("server.recovery.complete.dataEmpty", java.util.Map.of("s", service,
                    "what", I18n.tr(after[2])));
        }
        @Override public java.util.List<String> checksumFailures(java.util.Collection<String> pkgs) {
            java.util.List<String> names = new ArrayList<>();
            for (String p : pkgs) if (isValidName(p)) names.add(p);
            if (names.isEmpty()) return java.util.List.of();
            java.util.LinkedHashSet<String> bad = new java.util.LinkedHashSet<>();
            String out = sh("pkg check -s " + String.join(" ", names) + " 2>&1", 600);
            for (String line : out.split("\n")) {
                String l = line.trim();
                if (!l.contains("checksum mismatch") && !l.contains("missing file")) continue;
                for (String n : names) if (l.startsWith(n + "-")) bad.add(n);
            }
            return new ArrayList<>(bad);
        }
        @Override public String reinstall(java.util.List<String> pkgs) {
            for (String p : pkgs) if (!isValidName(p)) return "invalid package name: " + p;
            java.util.List<String> toUnlock = new ArrayList<>();
            Set<String> locked = lockedNames();
            for (String p : pkgs) if (locked.contains(p)) toUnlock.add(p);
            if (!toUnlock.isEmpty()) {
                // The rules of every unlock: the list on disk first, then the unlock; and it always locks again.
                String err = PackageQueue.writeState(toUnlock);
                if (err != null) return err;
                for (String p : toUnlock) if (!ok("pkg unlock -y " + p, 30)) { relockAll(toUnlock); return "cannot unlock " + p; }
            }
            try {
                Shell.Result r = Shell.runShell(Duration.ofSeconds(1800), "pkg install -f -y -U " + String.join(" ", pkgs) + " 2>&1");
                if (r.success()) return null;
                String[] lines = r.outputTrim().split("\n");
                return "pkg install -f exit " + r.exitCode() + ": " + lines[lines.length - 1];
            } finally {
                if (!toUnlock.isEmpty()) relockAll(toUnlock);
            }
        }
        private static void relockAll(java.util.List<String> names) {
            int done = 0;
            for (String p : names) if (ok("pkg info -e " + p, 15) && ok("pkg lock -y " + p, 30)) done++;
            if (done == names.size()) clearState();
        }
        @Override public String mailLookups() {
            java.util.List<String> problems = new ArrayList<>();
            Path map = Paths.get("/usr/local/etc/postfix/mysql-virtual-mailboxes.cf");
            if (Files.isRegularFile(map) && ok("service postfix status", 15)) {
                Shell.Result r = Shell.run(Duration.ofSeconds(30), "/usr/local/sbin/postmap", "-q", MailDbUsers.PROBE, "mysql:" + map);
                if (!MailDbUsers.postmapAnswered(r)) problems.add("postmap -q: exit " + r.exitCode() + " " + r.outputTrim());
            }
            if (Files.isExecutable(Paths.get(DovecotAuthWorker.DOVEADM)) && DovecotAuthWorker.running()) {
                int rc = DovecotAuthWorker.lookup();
                if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) problems.add("doveadm auth lookup: exit " + rc);
            }
            return problems.isEmpty() ? null : String.join("; ", problems);
        }
    }

    static String restoreLocksAfterCrash(String turnDescription) {
        // PackageQueue.list, not the path written here: it is the same file, but it is the one read
        // by PackageRecovery.statePackages and by the tests, which move it into a folder of their own.
        Path f = PackageQueue.list;
        if (!Files.exists(f)) return "";
        String refusal = PackageQueue.takeForLocks("startup-restore", turnDescription);
        if (refusal != null) {
            // In English, as above: the caller prints it in the log.
            // Without "a job is running there", which was there before: whoever holds the turn can also be the
            // watchdog of another process that is putting the locks back (test M4, 2026-11-22). Who it is is said
            // by holderForLog.
            String msg = "A list of unlocked packages is on disk, but another panel process holds the package turn ("
                    + PackageQueue.holderForLog() + "): the list is not touched.";
            LOGGER.info(msg);
            return msg;
        }
        try {
            JSONObject job = PackageQueue.jobRecord();
            List<String> names = PackageRecovery.statePackages();
            Set<String> lockedNow = lockedNames();
            List<String> unlockedNow = new ArrayList<>();
            for (String n : names) if (!lockedNow.contains(n) && ok("pkg info -e " + n, 15)) unlockedNow.add(n);
            String pkgNow = PackageRecovery.pkgRunning();
            // The JVM update leaves the list on purpose and has itself restarted by its script:
            // if the script has already locked everything again and pkg is no longer working, it
            // is not an interruption.
            boolean expected = job.optBoolean("expectsRestart") && unlockedNow.isEmpty() && pkgNow.isEmpty();
            if (!expected) PackageRecovery.recordInterruption(job, names, unlockedNow, pkgNow);
            StringBuilder log = new StringBuilder();
            boolean done = relockFromState(f, log);
            String msg = "Interrupted package job detected: " + log;
            if (!done) {
                msg += (pkgNow.isEmpty() ? "" : "pkg is still working (" + pkgNow.replace("\n", "; ") + "): ")
                        + "retrying every " + PackageRecovery.retrySeconds + " seconds until they are protected again.\n";
                PackageRecovery.retryInBackground(UpdateManager::retryRelock);
            } else if (!expected) {
                PackageRecovery.markRelocked();
            }
            LOGGER.warning(msg);
            return msg;
        } finally {
            PackageQueue.release("startup-restore");
        }
    }

    /**
     * Locks the packages in the list again. True if at the end they are all locked (or no longer
     * installed) and the list has been removed; false if some did not get locked again, and then
     * the list stays.
     */
    static boolean relockFromState(Path f, StringBuilder log) {
        int done = 0, totals = 0, skipped = 0;
        try {
            for (String line : Files.readString(f).split("\n")) {
                String n = line.trim();
                if (n.isEmpty()) continue;
                if (!isValidName(n)) { log.append("  name ignored: ").append(n).append('\n'); continue; }
                totals++;
                if (!ok("pkg info -e " + n, 15)) { skipped++; log.append("  ").append(n).append(": not installed, skipped\n"); continue; }
                if (ok("pkg lock -y " + n, 30)) { done++; log.append("  ").append(n).append(": protected again\n"); }
                else log.append("  ").append(n).append(": PROTECTING AGAIN FAILED\n");
            }
            log.insert(0, done + "/" + totals + " packages protected again.\n");
            if (done + skipped == totals) { clearState(); log.append("State cleared.\n"); return true; }
            log.append("Some were not protected again: the state stays.\n");
        } catch (Exception e) {
            log.append("Restore ERROR: ").append(e.getMessage()).append('\n');
        }
        return false;
    }

    /**
     * One attempt of the background restore (PackageRecovery.retryInBackground): true when
     * the list is no longer there, that is, when there is nothing left to do. It takes the turn at
     * every attempt, so as not to step on a job started in the meantime.
     */
    static boolean retryRelock() {
        Path f = PackageQueue.list;
        if (!Files.exists(f)) return true;
        if (PackageQueue.takeForLocks("relock-retry", I18n.tr("server.recovery.turnRetry")) != null) return false;
        try {
            StringBuilder log = new StringBuilder();
            if (!relockFromState(f, log)) return false;
            PackageRecovery.markRelocked();
            refreshLockTrace();
            LOGGER.warning("Packages of the interrupted job protected again in the background: " + log);
            return true;
        } finally {
            PackageQueue.release("relock-retry");
        }
    }

    /** Set of the packages locked now, names without version. */
    private static Set<String> lockedNames() {
        return lockedNames(sh("pkg lock -l 2>/dev/null"));
    }

    // ===================== the two jobs =====================

    /**
     * Rewrites ONLY the Dovecot configuration from the single source, without touching the
     * packages. It was needed: before, to apply a fix to the configuration one had to go
     * through the reinstallation of the package -- `pkg delete` and reinstallation -- which is
     * out of proportion for rewriting some text files and introduces unrelated risks.
     *
     * The reload happens only if doveconf accepted: if it refuses, the fragment has
     * already put back the previous configuration and exits non-zero, so here nothing is
     * reloaded and the service carries on as it was.
     */
    /**
     * The MTA-STS activation as a background job.
     *
     * Issuing the certificate takes longer than a proxy's time limit: kept inside
     * an HTTP request, the browser receives an error page while on the server
     * the operation continues, and whoever is watching is left not knowing what happened to a
     * production certificate. Here the request returns immediately with an identifier and the
     * page follows the progress, as for the package updates.
     */
    public static JSONObject startMtaStsActivation() {
        String id = "mtasts-" + System.currentTimeMillis();
        Job j = new Job(id, "mtasts");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                org.json.JSONObject outcome = org.daemoxcp.mail.system.MtaStsSetup.run(j);
                j.write("");
                j.write(outcome.optString("note", outcome.optString("error", "")));
                j.write("");
                j.write("--- " + I18n.tr("server.um.x.fullResult") + " ---");
                j.write(outcome.toString(2));
                j.status = outcome.optBoolean("success", false) ? "completed" : "error";
                if (!outcome.optBoolean("success", false))
                    j.errorMessage = outcome.optString("error", I18n.tr("server.um.x.seqInterrupted"));
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.finish();
            }
        }, "mtasts-enable");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * "Set up everything" for a domain, as a background job.
     *
     * Before, it was a synchronous call, and that was fine as long as the sequence only
     * wrote a few records. Now it includes waiting for DNS propagation and, if needed,
     * issuing the certificate: minutes, not seconds. Behind a proxy that request
     * would time out, and whoever is watching would be left not knowing what happened.
     */
    public static JSONObject startDomainSetup(int domainId) {
        String id = "domain-" + domainId + "-" + System.currentTimeMillis();
        Job j = new Job(id, "configure_domain");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                org.json.JSONObject outcome =
                        org.daemoxcp.mail.system.DomainSetup.run(domainId, j);
                j.write("");
                j.write(outcome.optString("note", outcome.optString("error", "")));
                j.write("");
                j.write("--- " + I18n.tr("server.um.x.fullResult") + " ---");
                j.write(outcome.toString(2));
                j.status = outcome.optBoolean("success", false) ? "completed" : "error";
                if (!outcome.optBoolean("success", false))
                    j.errorMessage = outcome.optString("error", I18n.tr("server.um.x.confInterrupted"));
                // Reached the end with some steps not in order: the page says so, not "Setup completed" in green
                // with one step out of ten (finding 250).
                else if (outcome.optInt("succeeded", 0) < outcome.optInt("total", 0))
                    j.outcome = I18n.tr("server.cfgdom.partial", java.util.Map.of("ok", String.valueOf(outcome.optInt("succeeded", 0)),
                            "tot", String.valueOf(outcome.optInt("total", 0))));
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.finish();
            }
        }, "configure-domain");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    public static JSONObject startDovecotRegeneration() {
        String id = "dovecot-cfg-" + System.currentTimeMillis();
        Job j = new Job(id, "dovecot_config");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> runDovecotRegeneration(j), "dovecot-config");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    private static void runDovecotRegeneration(Job job) {
        job.status = "running";
        java.nio.file.Path script = null;
        try {
            job.advance(1, 3);
            job.write(I18n.tr("server.um.runDovecotRegeneration.1"));
            job.write("");

            boolean activeBefore = ok("service dovecot status", 15);
            job.write(activeBefore ? I18n.tr("server.um.x.dcBeforeUp") : I18n.tr("server.um.x.dcBeforeDown"));

            String fragment = org.daemoxcp.mail.scripts.DovecotConfig.fromPanelConfig().scriptFragment();
            script = java.nio.file.Files.createTempFile("dovecot-config-", ".sh");
            java.nio.file.Files.writeString(script, "#!/bin/sh\nset -e\n" + fragment + "\n");
            java.nio.file.Files.setPosixFilePermissions(script,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));

            job.advance(2, 3);
            job.write("");
            job.write(I18n.tr("server.um.runDovecotRegeneration.2"));
            // The password goes through the ENVIRONMENT: not in the text of the script (which ends
            // up on disk) nor on the command line (visible in the process list).
            Map<String, String> environment = new LinkedHashMap<>();
            String pw = panelDbPassword();
            if (!pw.isEmpty()) environment.put("DB_PASS", pw);
            job.write("    " + (environment.containsKey("DB_PASS")
                    ? I18n.tr("server.um.x.dbPassFromPanel")
                    : I18n.tr("server.um.x.dbPassScript")));
            int code = runLogged(job, "sh " + script, 300, null, environment);
            if (code != 0) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runDovecotRegeneration.3");
                job.write("");
                job.write(job.errorMessage);
                return;
            }

            job.advance(3, 3);
            job.write("");
            job.write(I18n.tr("server.um.x.dcReload33"));
            if (!activeBefore) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.4"));
                job.status = "completed";
                return;
            }
            boolean ok1 = ok("service dovecot reload", 60);
            job.write("    reload: " + (ok1 ? I18n.tr("server.um.x.done") : I18n.tr("server.um.runDovecotRegeneration.5")));
            if (!ok1) ok("service dovecot restart", 60);

            boolean activeAfter = ok("service dovecot status", 20);
            job.write("    " + (activeAfter ? I18n.tr("server.um.x.dcAfterUp") : I18n.tr("server.um.x.dcAfterDown")));
            if (!activeAfter) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runDovecotRegeneration.6");
                return;
            }
            // The configuration just written delivers from the socket into the Postfix queue: Postfix is brought
            // in line (finding 234).
            String lmtp = LmtpSocket.alignPostfix();
            if (!lmtp.isEmpty()) job.write("    " + lmtp);

            // === Functional test: does authentication still work? ===
            // This step rewrites dovecot-sql.conf, that is, the file with which Dovecot queries
            // the database to authenticate. "The service is running" says nothing about that:
            // Dovecot stays running even with wrong credentials, and it is the users who notice.
            // The SAME query that the panel has just written in the configuration is run,
            // with the SAME credentials, on a real mailbox.
            job.write("");
            job.write(I18n.tr("server.um.x.authTest"));
            String mailbox = mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_FIRST_ACTIVE_MAILBOX).trim();
            if (mailbox.isEmpty()) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.7"));
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runDovecotRegeneration.8"));
                return;
            }
            if (!mailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.9"));
                job.status = "completed";
                return;
            }
            // The same condition as the password_query written in the file, without extracting the
            // password: what matters is that the row is there and reachable, not its content.
            String found = mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_ACTIVE_MAILBOX_COUNT, mailbox).trim();
            if ("1".equals(found)) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.10", java.util.Map.of("mailbox", String.valueOf(mailbox))));
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runDovecotRegeneration.11"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runDovecotRegeneration.12", java.util.Map.of("mailbox", String.valueOf(mailbox), "foundOnes", String.valueOf(found)));
                job.write("    " + I18n.tr("server.um.x.alarm", java.util.Map.of("m", String.valueOf(job.errorMessage))));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (script != null) try { java.nio.file.Files.deleteIfExists(script); } catch (Exception ignored) {}
            // The regeneration writes the connection with the panel's user: we go back to Dovecot's
            // (MailDbUsers), which reads only address, hash and state of the mailboxes.
            if ("completed".equals(job.status)) MailDbUsers.ensureAtBoot();
            job.finish();
        }
    }

    /**
     * A catalog query with the panel's credentials, taken from the configuration, via JDBC: the
     * values as parameters. The rows one per line and the columns separated by a tab, as the
     * mysql client used before wrote them; "" if MySQL does not respond. Before, it went through
     * "sh -c" with the SQL text inside the command line.
     */
    private static String mysqlOut(String sql, Object... params) {
        String user = Product.ID, pass = "", db = Product.ID, host = "127.0.0.1", port = "3306";
        try (java.sql.ResultSet rs = org.daemoxcp.mail.Main.dbManager.get_data_config()) {
            if (rs.next()) {
                String u = rs.getString("mysql_user"), p2 = org.daemoxcp.mail.Main.dbManager.mysqlPassword();
                String d = rs.getString("mysql_database"), h = rs.getString("mysql_host"), po = rs.getString("mysql_port");
                if (u != null && !u.isBlank()) user = u.trim();
                if (p2 != null) pass = p2;
                if (d != null && !d.isBlank()) db = d.trim();
                if (h != null && !h.isBlank()) host = h.trim();
                if (po != null && po.matches("[0-9]{1,5}")) port = po.trim();
            }
        } catch (Exception ignored) {}
        if (!user.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !host.matches("[A-Za-z0-9._-]{1,128}")) return "";
        return jdbcRows(host, port, db, user, pass, sql, params);
    }

    /**
     * A catalog query via JDBC, with that user on that database: the rows one per line, the columns
     * separated by a tab; "" if it cannot log in or MySQL refuses. Host, port and database have already
     * passed a strict format; the values go as parameters.
     */
    static String jdbcRows(String host, String port, String db, String user, String password, String sql, Object... params) {
        Shell.Result r = org.daemoxcp.mail.database.MysqlRoot.jdbc(host, port, db, user, password, sql, params);
        return r.success() ? r.outputTrim() : "";
    }

    /**
     * Privileged query as root, with the password from the secrets file (MysqlRoot).
     *
     * It is needed to read mysql.user, which the application user cannot see: the alternative
     * would be to ask for a GRANT to be run by hand, that is, exactly the dictating of commands
     * that we want to avoid. Before, it got in through the socket without a password, which on
     * FreeBSD works only where root has no password: that is, where anyone gets in. Since
     * 2026-11-07 root has its own password also on the servers installed before
     * (MysqlRoot.ensureAtBoot).
     */
    private static String mysqlRootOut(String sql) {
        return org.daemoxcp.mail.database.MysqlRoot.query(sql);
    }

    /**
     * The panel connects as the application user, not as root: it might not have the
     * permission to read mysql.user. The difference is decisive -- "no account uses
     * mysql_native_password" and "I could not look" produce the same emptiness but
     * mean the opposite, and taking the second for the first means migrating convinced
     * that there is nobody to save.
     */
    private static boolean canReadMysqlUsers() {
        if (!mysqlRootOut(org.daemoxcp.mail.database.SqlCatalog.UM_CAN_READ_ACCOUNTS).trim().isEmpty()) return true;
        return !mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_CAN_READ_ACCOUNTS).trim().isEmpty();
    }

    /** The read of mysql.user, with the account that manages to do it. */
    private static String usersWithNativePlugin() {
        String q = org.daemoxcp.mail.database.SqlCatalog.UM_NATIVE_PASSWORD_ACCOUNTS;
        String r = mysqlRootOut(q);
        return r.isEmpty() ? mysqlOut(q) : r;
    }

    /**
     * Which authentication plugins are in use, with how many accounts each.
     *
     * Saying "nobody uses mysql_native_password" is proving an absence, and an absence is
     * easily mistaken for a silent error. Listing the plugins present is a positive proof:
     * if the sum of the accounts adds up and the names are the expected ones, the read really
     * took place. It also serves to see sha256_password, which is deprecated too.
     */
    private static JSONArray pluginInUse() {
        String q = org.daemoxcp.mail.database.SqlCatalog.UM_AUTH_PLUGINS;
        String out = mysqlRootOut(q);
        if (out.isEmpty()) out = mysqlOut(q);
        JSONArray arr = new JSONArray();
        for (String line : out.split("\n")) {
            String t = line.trim();
            int sp = t.lastIndexOf(' ');
            if (sp <= 0) continue;
            arr.put(new JSONObject().put("plugin", t.substring(0, sp).trim())
                    .put("accounts", (int) number(t.substring(sp + 1))));
        }
        return arr;
    }

    /** The plugins found, in readable form. */
    private static String describePlugin(JSONArray a) {
        if (a.length() == 0) return I18n.tr("server.um.describePlugin.1");
        StringBuilder sb = new StringBuilder();
        int tot = 0;
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.getJSONObject(i);
            if (sb.length() > 0) sb.append(", ");
            sb.append(o.getString("plugin")).append(' ').append(o.getInt("accounts"));
            tot += o.getInt("accounts");
        }
        return I18n.tr("server.um.describePlugin.2", java.util.Map.of("sb", String.valueOf(sb), "tot", String.valueOf(tot)));
    }

    /** Number from command output; 0 if it contains no digits. */
    private static long number(String v) {
        try { return Long.parseLong(v == null ? "" : v.trim().replaceAll("[^0-9]", "")); }
        catch (Exception e) { return 0L; }
    }

    /** Two sentences in a note, without blank lines if the second one is missing. */
    private static String joinNotes(String a, String b) {
        return b == null || b.isEmpty() ? a : a + "\n\n" + b;
    }

    /**
     * Downloads the packages that the update will install and recomputes the plan: the plan
     * depends on what is in the pkg CACHE.
     *
     * Measured on the FreeBSD 15.1 VM on 2026-10-23, twice on the same package and on the
     * same catalog, two minutes apart:
     *
     *   without the files in /var/cache/pkg -> 3 changes: installs lmdb0, installs mysql97-client,
     *                                          upgrades postfix-mysql
     *   with the files in /var/cache/pkg    -> 4 changes: the same PLUS "removes lmdb 1.0.2,1"
     *
     * The integrity check of pkg finds file conflicts only when the packages are
     * downloaded: without them, `pkg upgrade -n` cannot see that lmdb0 and lmdb both claim
     * /usr/local/bin/mdb_copy, and the removal that follows does not appear in the plan. It
     * appears during the run, when the solver redoes its sums.
     *
     * It is not a detail: the panel REFUSES the plans that remove packages ("The plan
     * removes packages: pkg would remove lmdb 1.0.2,1. The panel does not run updates
     * that take packages off the server"), and that refusal was bypassed every time the
     * packages had not been downloaded yet -- that is, at the first attempt, always. It is the
     * explanation of finding 14: the signed plan 465385a9d669def8 contained no removals and
     * the run removed lmdb.
     *
     * The download does not add work: it is the same bytes that would be needed an instant
     * later. What it adds is the chance to stop before.
     *
     * @return null if pkg would do the same things, otherwise the reason to stop
     */
    /** What fetchAndRecheck decided: stop (stop not null) or go ahead with the given plan. */
    record Recheck(String stop, JSONObject plan) {}

    private static Recheck fetchAndRecheck(Job job, String fetchCommand, JSONObject approved,
                                              java.util.function.Supplier<JSONObject> recompute) throws Exception {
        job.write("  " + I18n.tr("server.um.x.fetchFirst"));
        int fetchCode = runLogged(job, fetchCommand, 1800);
        if (fetchCode != 0) {
            // Without the files, the plan remains the incomplete one: that is said, instead of
            // carrying on pretending the check was done.
            job.write("  " + I18n.tr("server.um.x.fetchFailed", java.util.Map.of("code", String.valueOf(fetchCode))));
            return new Recheck(I18n.tr("server.um.x.fetchFailed", java.util.Map.of("code", String.valueOf(fetchCode))), approved);
        }
        JSONObject now = recompute.get();
        if (!now.optBoolean("measured")) {
            job.write("  " + I18n.tr("server.um.x.replanFailed"));
            return new Recheck(I18n.tr("server.um.x.replanFailed"), approved);
        }
        String before = PackagePlan.changesSignature(approved), after = PackagePlan.changesSignature(now);
        if (before.equals(after)) {
            job.write("  " + I18n.tr("server.um.x.planUnchanged", java.util.Map.of("f", String.valueOf(after))));
            return new Recheck(null, approved);
        }
        // Grown by removals only: it is the case of lmdb -> lmdb0, where pkg sees the file conflict
        // only after downloading. If each one is a harmless replacement we go ahead with the
        // new plan, and the evidence is written here, in the job's log.
        java.util.List<String> added = onlyAddedRemovals(approved, now);
        if (added != null && !added.isEmpty()) {
            judged(now);
            String mapsNow = PostfixMaps.planBlocker(now);
            if (mapsNow != null) {
                job.write("  " + mapsNow);
                return new Recheck(mapsNow, approved);
            }
            if (removalsRefused(now).isEmpty()) {
                job.write("  " + I18n.tr("server.um.x.planGrewReplacement", java.util.Map.of("list", String.join(", ", added))));
                JSONArray v = now.getJSONArray("replacements");
                for (int i = 0; i < v.length(); i++) {
                    JSONObject x = v.getJSONObject(i);
                    job.write("    " + x.optString("name") + " " + x.optString("version"));
                    for (String e : jsonArrayToList(x.optJSONArray("evidence"))) job.write("      ok  " + e);
                    for (String e : jsonArrayToList(x.optJSONArray("problems"))) job.write("      !!  " + e);
                }
                LOGGER.info("Plan grew after fetching only by replacements, going on: " + before + " -> " + after
                        + "; " + v);
                return new Recheck(null, now);
            }
            // The reason for the stop is this one, not the generic "the plan has changed": it tells
            // whoever reads which removals the panel does not carry out.
            String why = removalsReason(now);
            job.write("  " + why);
            LOGGER.warning("Plan grew after fetching by removals the panel refuses: " + before + " -> " + after + "; " + now.getJSONArray("replacements"));
            return new Recheck(why, approved);
        }
        // pkg 2.9 holds back the update (a file conflict that shows only with the packages downloaded): that
        // is the reason, and it is said; if something else remains in the plan, it must be approved again anyway.
        String held = heldBackReason(now);
        if (held != null) {
            JSONArray left = now == null ? null : now.optJSONArray("changes");
            String why = (left == null || left.isEmpty()) ? held : held + " " + I18n.tr("server.um.x.planGrewStop");
            job.write("  " + why);
            LOGGER.warning("pkg held back after fetching the packages: " + before + " -> " + after + "; " + now.optJSONArray("heldBack"));
            return new Recheck(why, approved);
        }
        job.write("  " + I18n.tr("server.um.x.planGrew", java.util.Map.of("before", String.valueOf(before), "after", String.valueOf(after))));
        job.write("  " + I18n.tr("server.um.x.planApproved"));
        for (String r : PackagePlan.changesInLines(approved)) job.write("      " + r);
        job.write("  " + I18n.tr("server.um.x.planNow"));
        for (String r : PackagePlan.changesInLines(now)) job.write("      " + r);
        LOGGER.warning("Plan changed after fetching the packages: " + before + " -> " + after
                + "; approved=" + PackagePlan.changesInLines(approved) + "; now=" + PackagePlan.changesInLines(now));
        return new Recheck(I18n.tr("server.um.x.planGrewStop"), approved);
    }

    /**
     * "name version" of the removals that the new plan adds to the approved one; null if
     * something else changes too (one more installation or update, a different version).
     */
    static java.util.List<String> onlyAddedRemovals(JSONObject approved, JSONObject now) {
        java.util.Set<String> a = changeKeys(approved);
        if (!changeKeys(now).containsAll(a)) return null;
        java.util.List<String> added = new ArrayList<>();
        JSONArray c = now == null ? null : now.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            if (a.contains(changeKey(x))) continue;
            if (!"remove".equals(x.optString("type"))) return null;
            added.add(x.optString("name") + " " + x.optString("from"));
        }
        return added;
    }

    private static java.util.Set<String> changeKeys(JSONObject plan) {
        java.util.Set<String> keys = new java.util.HashSet<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) keys.add(changeKey(c.getJSONObject(i)));
        return keys;
    }

    private static String changeKey(JSONObject x) {
        return x.optString("type") + "|" + x.optString("name") + "|" + x.optString("from") + "|" + x.optString("to");
    }

    /** JSONArray of strings -> Java list, so they can be joined and looped over. */
    private static java.util.List<String> jsonArrayToList(JSONArray a) {
        java.util.List<String> l = new ArrayList<>();
        for (int i = 0; a != null && i < a.length(); i++) {
            String v = a.optString(i, "");
            if (!v.isEmpty()) l.add(v);
        }
        return l;
    }

    /**
     * The changes that the panel does NOT carry out: removals and downgrades.
     *
     * It is a rule of the panel, not a fact of pkg: an update that takes a
     * package off a mail server, or takes its version back, must be decided by
     * a person who knows who uses it. It was written in one place only -- the card of a
     * locked package -- and was missing from the other two jobs that run a plan.
     *
     * Measured on the FreeBSD 15.1 VM on 2026-10-23, on the same machine and on the same
     * package: the guided update of postfix-mysql stops ("The plan removes
     * packages: pkg would remove lmdb 1.0.2,1"), while the full maintenance gave
     * runnable=true on a plan that contained "removes lmdb 1.0.2,1" and no obstacle.
     * Two opposite answers to the same question, and the permissive one was on the button
     * "Full maintenance", that is, on the one pressed to update everything.
     *
     * @return {@code removes} and {@code downgrades}: the changes, already in readable form
     */
    static JSONObject destructiveChanges(JSONObject plan) {
        JSONArray removed = new JSONArray(), downgrades = new JSONArray();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String n = x.optString("name");
            // The removals that the job itself declares (MySQL 8.0 in the migration, the old
            // Python in the switch) are the job, not a side effect: they are in the signed plan,
            // whoever presses reads them, and the inventory checks them. The others follow the rule.
            if (x.optBoolean("intended")) continue;
            switch (x.optString("type")) {
                case "remove" -> removed.put(n + " " + x.optString("from"));
                case "downgrade" -> downgrades.put(n + " " + x.optString("from") + " -> " + x.optString("to"));
                default -> { }
            }
        }
        return new JSONObject().put("removes", removed).put("downgrades", downgrades);
    }

    /**
     * The plan with the verdict on each removal (PackageReplacement), put once only in the
     * "replacements" key: it is read by the rule below, by the page and by the job's log.
     */
    static JSONObject judged(JSONObject plan) {
        if (plan == null || plan.has("replacements")) return plan;
        if (destructiveChanges(plan).getJSONArray("removes").isEmpty()) return plan.put("replacements", new JSONArray());
        return plan.put("replacements", PackageReplacement.judgePlan(plan));
    }

    /** The verdict on each removal of the plan, by "name version". */
    private static Map<String, JSONObject> verdictsByKey(JSONObject plan) {
        Map<String, JSONObject> m = new LinkedHashMap<>();
        JSONArray v = plan == null ? null : plan.optJSONArray("replacements");
        for (int i = 0; v != null && i < v.length(); i++) {
            JSONObject x = v.getJSONObject(i);
            m.put(x.optString("name") + " " + x.optString("version"), x);
        }
        return m;
    }

    /**
     * "name version" of the plan's removals that the panel does not carry out: all those that are not
     * a harmless replacement. Something that stays installed would disappear or stop working, or it
     * could not be measured (a removal without a verdict counts as such). There is no way to confirm
     * them: see PackageReplacement.
     */
    static java.util.List<String> removalsRefused(JSONObject plan) {
        Map<String, JSONObject> v = verdictsByKey(plan);
        java.util.List<String> refused = new ArrayList<>();
        for (String r : jsonArrayToList(destructiveChanges(plan).getJSONArray("removes"))) {
            JSONObject x = v.get(r);
            if (x == null || !x.optBoolean("safe")) refused.add(r);
        }
        return refused;
    }

    /** The reason for the removals that stop the plan, or null if there are none. */
    static String removalsReason(JSONObject plan) {
        java.util.List<String> refused = removalsRefused(plan);
        return refused.isEmpty() ? null
                : I18n.tr("server.um.x.planRemovesNever", java.util.Map.of("list", String.join(", ", refused)));
    }

    /**
     * Why pkg holds back some updates (pkg 2.9, "is held back to solve the problem": PackagePlan.readPlan),
     * in words, or null if it holds none back. For each conflict the new package, the installed one that is
     * in the way with the shared file, and who still needs the installed one (pkg query %rn: it is the reason
     * why pkg does not remove it). Measured on the VM on 2026-11-22 with pkg 2.9.2: without this the card
     * showed an empty plan without saying why, and the job stopped with the generic "the plan has changed".
     */
    static String heldBackReason(JSONObject plan) {
        JSONArray held = plan == null ? null : plan.optJSONArray("heldBack");
        if (held == null || held.isEmpty()) return null;
        java.util.List<String> heldShown = new ArrayList<>();
        java.util.Set<String> heldNames = new java.util.HashSet<>();
        for (int i = 0; i < held.length(); i++) {
            JSONObject h = held.getJSONObject(i);
            heldShown.add(h.optString("name") + " " + h.optString("version"));
            heldNames.add(h.optString("name"));
        }
        java.util.List<String> parts = new ArrayList<>();
        JSONArray conflicts = plan.optJSONArray("conflicts");
        for (int i = 0; conflicts != null && i < conflicts.length(); i++) {
            JSONObject c = conflicts.getJSONObject(i);
            String installed = c.optString("installed");
            java.util.List<String> users = new ArrayList<>();
            if (isValidName(installed))
                for (String u : sh("pkg query %rn " + installed + " 2>/dev/null", 30).split("\n"))
                    if (!u.isBlank() && !heldNames.contains(u.trim()) && !u.trim().equals(installed)) users.add(u.trim());
            java.util.Map<String, String> v = java.util.Map.of(
                    "new", c.optString("name") + " " + c.optString("version"),
                    "installed", installed + " " + c.optString("installedVersion"),
                    "file", c.optString("file"),
                    "users", String.join(", ", users));
            parts.add(I18n.tr(users.isEmpty() ? "server.um.x.pkgHeldBackConflict" : "server.um.x.pkgHeldBackConflictUsers", v));
        }
        String heldList = String.join(", ", heldShown);
        return parts.isEmpty()
                ? I18n.tr("server.um.x.pkgHeldBackPlain", java.util.Map.of("held", heldList))
                : I18n.tr("server.um.x.pkgHeldBack", java.util.Map.of("held", heldList, "conflicts", String.join("; ", parts)));
    }

    /**
     * The reason to show in the cards of the unlocked packages and of the maintenance: the one of the
     * destructive changes; if there is none and the plan has nothing to do because pkg holds everything
     * back, the one from pkg.
     */
    static String cardBlockedReason(JSONObject plan) {
        String destructive = destructivePlanReason(plan);
        if (destructive != null) return destructive;
        JSONArray ch = plan == null ? null : plan.optJSONArray("changes");
        return ch == null || ch.isEmpty() ? heldBackReason(plan) : null;
    }

    /**
     * The reason why a plan is not run, or null if it touches nothing in that way.
     * The three jobs that run a plan ask for it, so there is only one rule.
     *
     * A removal passes only if it is a harmless replacement (the verdict is in the plan, see
     * judged); downgrades never pass.
     */
    static String destructivePlanReason(JSONObject plan) {
        JSONObject d = destructiveChanges(plan);
        java.util.List<String> reasons = new ArrayList<>();
        String removals = removalsReason(plan);
        if (removals != null) reasons.add(removals);
        // A plan that can change the library of a Postfix map type, if a map of that
        // type could not be rebuilt identical to before (PostfixMaps).
        String maps = PostfixMaps.planBlocker(plan);
        if (maps != null) reasons.add(maps);
        if (!d.getJSONArray("downgrades").isEmpty())
            reasons.add(I18n.tr("server.um.x.planDowngrades", java.util.Map.of("list",
                    String.valueOf(String.join(", ", jsonArrayToList(d.getJSONArray("downgrades")))))));
        return reasons.isEmpty() ? null : String.join(" ", reasons);
    }

    /** The names of the divergences, for the error message of a job. */
    private static String divergenceList(JSONArray divergences) {
        java.util.List<String> names = new ArrayList<>();
        for (int i = 0; i < divergences.length(); i++) names.add(divergences.getJSONObject(i).optString("name"));
        return String.join(", ", names);
    }

    /** The error message of a job that found changes outside the plan. */
    private static String divergenceMessage(JSONArray d) {
        return d.length() == 1
            ? I18n.tr("server.um.x.divergenceFound.one", java.util.Map.of("list", String.valueOf(divergenceList(d))))
            : I18n.tr("server.um.x.divergenceFound.other", java.util.Map.of(
                    "n", String.valueOf(d.length()), "list", String.valueOf(divergenceList(d))));
    }

    /**
     * Compares the package inventory with the one from before the update and writes
     * in the job's log what REALLY changed.
     *
     * It lives in one place only because two jobs do it (the guided update and the
     * full maintenance) and a decision written twice becomes two decisions.
     *
     * @param who for the panel log: which job found the divergence
     * @return the divergences, empty if everything that changed was in the plan
     */
    private static JSONArray compareWithInventory(Job job, Map<String, String> before,
                                                     JSONObject plan, String who) {
        JSONArray outside = PackagePlan.divergences(before,
                PackagePlan.versionsOnly(PackagePlan.installed()), plan);
        job.write("  " + I18n.tr("server.um.x.divergenceHeader"));
        if (outside.isEmpty()) {
            job.write("    ok  " + I18n.tr("server.plan.d.none"));
            return outside;
        }
        for (int i = 0; i < outside.length(); i++)
            job.write("    NO  " + PackagePlan.divergenceInLine(outside.getJSONObject(i)));
        job.write("  " + I18n.tr("server.um.x.divergenceNote"));
        // Outside the job's log, which lives in memory and goes away with the panel: a
        // change that nobody approved on a mail server must stay written down.
        // Only package names and versions, no secrets (r19).
        LOGGER.warning(who + ": " + outside.length() + " change(s) outside the signed plan: " + outside);
        return outside;
    }

    // ===================== the signed plan, in every job that runs pkg =====================
    //
    // The guided update, the Roundcube update, the Python switch and the migration to
    // MySQL 8.4 run pkg, and they must give the same guarantees: an exact plan computed on a
    // copy of the pkg database, signed and approved by whoever presses; recomputed at the start
    // and after downloading the packages; the inventory before and after, every line of the plan
    // checked. The rules live here once: written in four jobs they would become four rules.

    /**
     * The checks on the plan, the same for every job that runs one: obstacles, pkg errors,
     * removals (except those the job declares, see PackagePlan.planRemoveThenInstall),
     * Postfix maps, downgrades, requested packages that would not change.
     *
     * @param asked        the packages the job asks pkg for: if one does not change, the plan does not do its job
     * @param family       the job's packages: locks to be removed outside these are reported
     * @param blockedBefore true if an earlier check has already stopped the job: then the green
     *                     "exact plan" line is not written, because the job will not start
     * @return true if the plan cannot be run
     */
    static boolean addPlanChecks(JSONArray checks, JSONObject plan, java.util.List<String> asked,
                                 java.util.Collection<String> family, boolean blockedBefore) {
        boolean block = false;
        if (!plan.optBoolean("success") || !plan.optBoolean("measured")) {
            addCheck(checks, "plan", I18n.tr("server.um.packagePreflight.15"), "block",
                    I18n.tr("server.um.x.noPlan", java.util.Map.of("e", String.valueOf(plan.optString("error", "?")))));
            block = true;
        } else {
            JSONArray changes = plan.getJSONArray("changes");
            // Removals and downgrades from the shared function: the rule is the same for the
            // two jobs, and written twice it would become two rules (and it did).
            JSONObject destructive = destructiveChanges(plan);
            java.util.List<String> removed = jsonArrayToList(destructive.getJSONArray("removes"));
            java.util.List<String> downgrades = jsonArrayToList(destructive.getJSONArray("downgrades"));
            java.util.List<String> stillVulnerable = new ArrayList<>(), lines = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                String n = c.getString("name");
                if (c.optBoolean("stillVulnerable")) stillVulnerable.add(n + " " + c.getString("to"));
                lines.add(n + " " + (c.getString("from").isEmpty() ? I18n.tr("server.um.x.newPkg") : c.getString("from"))
                        + (c.getString("to").isEmpty() ? " " + I18n.tr("server.um.x.removedPkg") : " -> " + c.getString("to")));
            }
            JSONArray blockerList = plan.getJSONArray("blockers");
            for (int i = 0; i < blockerList.length(); i++) {
                JSONObject x = blockerList.getJSONObject(i);
                addCheck(checks, "plan-blocker", I18n.tr("server.um.packagePreflight.16"), "block",
                        I18n.tr("server.um.x.blockedBy", java.util.Map.of("name", String.valueOf(x.getString("name")), "reason", String.valueOf(x.getString("reason")))));
                block = true;
            }
            JSONArray err = plan.getJSONArray("pkgErrors");
            if (err.length() > 0 || plan.optBoolean("hasConflicts")) {
                addCheck(checks, "plan-errors", I18n.tr("server.um.packagePreflight.17"), "block",
                        String.join(" | ", jsonArrayToList(err)) + (plan.optBoolean("hasConflicts") ? " " + I18n.tr("server.um.x.pkgConflicts") : ""));
                block = true;
            }
            if (!removed.isEmpty()) {
                // A harmless replacement is a warning; the others stop, and the page shows the evidence.
                if (removalsRefused(plan).isEmpty()) {
                    addCheck(checks, "plan-removals", I18n.tr("server.um.packagePreflight.18"), "review",
                            I18n.tr("server.um.x.removalsAccepted", java.util.Map.of("list", String.join(", ", removed))));
                } else {
                    addCheck(checks, "plan-removals", I18n.tr("server.um.packagePreflight.18"), "block",
                            removalsReason(plan));
                    block = true;
                }
            }
            String mapsBlocker = PostfixMaps.planBlocker(plan);
            if (mapsBlocker != null) {
                addCheck(checks, "plan-maps", I18n.tr("server.um.x.mapsCheck"), "block", mapsBlocker);
                block = true;
            }
            if (!downgrades.isEmpty()) {
                addCheck(checks, "plan-downgrades", I18n.tr("server.um.packagePreflight.19"), "block",
                        I18n.tr("server.um.x.planDowngrades", java.util.Map.of("list", String.valueOf(String.join(", ", downgrades)))));
                block = true;
            }
            java.util.List<String> stoppedAsked = new ArrayList<>(asked);
            stoppedAsked.retainAll(jsonArrayToList(plan.getJSONArray("unchangedPackages")));
            // pkg 2.9 holding back the update because of a file conflict: the why instead of "does not change".
            String heldBack = heldBackReason(plan);
            if (heldBack != null) {
                addCheck(checks, "plan-held-back", I18n.tr("server.um.x.pkgHeldBackCheck"), "block", heldBack);
                block = true;
                JSONArray hb = plan.getJSONArray("heldBack");
                for (int i = 0; i < hb.length(); i++) stoppedAsked.remove(hb.getJSONObject(i).optString("name"));
            }
            if (!stoppedAsked.isEmpty()) {
                addCheck(checks, "plan-stopped", I18n.tr("server.um.packagePreflight.20"), "block",
                        I18n.tr("server.um.packagePreflight.21", java.util.Map.of("name", String.join(", ", stoppedAsked))));
                block = true;
            }
            if (!stillVulnerable.isEmpty()) {
                addCheck(checks, "plan-vulnerable", I18n.tr("server.um.packagePreflight.22"), "review",
                        I18n.tr("server.um.x.stillVulnerable", java.util.Map.of("list", String.valueOf(String.join(", ", stillVulnerable)))));
            }
            java.util.List<String> extra = new ArrayList<>(jsonArrayToList(plan.getJSONArray("unlockedPackages")));
            extra.removeAll(family);
            // The ones pkg changes, and the ones it uses as they are but only without a lock (mysql84-client for
            // Dovecot 2.4, finding 213): saying that pkg "changes" them was false.
            java.util.List<String> asTheyAre = new ArrayList<>();
            for (String n : extra) {
                boolean changed = false;
                for (int i = 0; i < changes.length(); i++) if (n.equals(changes.getJSONObject(i).optString("name"))) changed = true;
                if (!changed) asTheyAre.add(n);
            }
            extra.removeAll(asTheyAre);
            if (!extra.isEmpty()) {
                addCheck(checks, "plan-dependencies", I18n.tr("server.um.packagePreflight.23"), "review",
                        I18n.tr("server.um.x.depsProtected", java.util.Map.of("list", String.valueOf(String.join(", ", extra)))));
            }
            if (!asTheyAre.isEmpty()) {
                addCheck(checks, "plan-dependencies-kept", I18n.tr("server.um.packagePreflight.23"), "review",
                        I18n.tr("server.um.x.depsAsTheyAre", java.util.Map.of("list", String.join(", ", asTheyAre))));
            }
            if (!block && !blockedBefore) {
                addCheck(checks, "plan", I18n.tr("server.um.packagePreflight.15"), "ok",
                        (changes.length() == 1
                         ? I18n.tr("server.um.x.pkgChanges.one", java.util.Map.of("lines", String.valueOf(String.join("; ", lines))))
                         : I18n.tr("server.um.x.pkgChanges.other", java.util.Map.of("n", String.valueOf(changes.length()), "lines", String.valueOf(String.join("; ", lines))))));
            }
        }
        return block;
    }

    /**
     * The changes that the confirmation of "Update everything" showed, name -> target version: they exist only in
     * the thread of its job (finding 207). The steps of that job compute their plan when their turn comes, and
     * often find it different from the one read before: the previous steps have already updated something it
     * would have updated (postfix-mysql and lmdb, nginx and pcre2). With the fingerprint alone the step would
     * stop; this way it starts if each of its changes is among those shown, at the same version, and nothing
     * is removed or goes back.
     */
    static final ThreadLocal<Map<String, String>> APPROVED_CHANGES = new ThreadLocal<>();

    /**
     * Is the plan run? If the fingerprint is the one read, yes; inside "Update everything", also if it stays
     * within what was shown.
     */
    static boolean planAccepted(String approvedSignature, String currentSignature, JSONObject plan) {
        if (currentSignature != null && !currentSignature.isEmpty() && currentSignature.equals(approvedSignature)) return true;
        return withinApproved(plan, APPROVED_CHANGES.get());
    }

    /** Is every change of the plan among the approved ones, at the same version? No removals and no going back. */
    static boolean withinApproved(JSONObject plan, Map<String, String> approved) {
        if (approved == null || plan == null || !plan.optBoolean("measured", false)) return false;
        JSONArray changes = plan.optJSONArray("changes");
        if (changes == null) return false;
        for (int i = 0; i < changes.length(); i++) if (changes.optJSONObject(i) == null) return false;
        return outsideApproved(plan, approved).isEmpty();
    }

    /**
     * The changes of the plan that the confirmation did not show, as log lines ("install lmdb0 -> 0.9.36_1"):
     * empty if they were all there. On the production server, on 2026-11-09, postfix-mysql was waiting for
     * mysql84-client and its complete plan was not known: when its turn came it also installed lmdb0, a new
     * library, and the step stopped saying only "the plan has changed" (finding 208). Now it says which line.
     */
    static List<String> outsideApproved(JSONObject plan, Map<String, String> approved) {
        List<String> out = new ArrayList<>();
        JSONArray changes = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; changes != null && i < changes.length(); i++) {
            JSONObject c = changes.optJSONObject(i);
            if (c == null) continue;
            String type = c.optString("type"), name = c.optString("name"), to = c.optString("to");
            String version = approved == null ? null : approved.get(name);
            boolean shown = version != null && (type.equals("reinstall")
                    || ((type.equals("upgrade") || type.equals("install")) && version.equals(to)));
            if (!shown) out.addAll(PackagePlan.changesInLines(new JSONObject().put("changes", new JSONArray().put(c))));
        }
        return out;
    }

    /**
     * The refusal of a plan that is not the one read, written in full in the log: the two fingerprints, the
     * plan as it is now, and inside "Update everything" the changes that the confirmation did not show.
     * Returns the reason: inside the chain, those changes; outside, 'standaloneKey'.
     */
    static String planRefused(Job job, JSONObject plan, String approvedSignature, String currentSignature, String standaloneKey) {
        job.write(I18n.tr("server.um.runGuidedUpdate.3", java.util.Map.of("approvedSignature", String.valueOf(approvedSignature),
                "currentSignature", String.valueOf(currentSignature))));
        List<String> lines = PackagePlan.changesInLines(plan);
        if (!lines.isEmpty()) {
            job.write("  " + I18n.tr("server.um.x.planNow"));
            for (String line : lines) job.write("    " + line);
        }
        job.write(I18n.tr("server.um.runGuidedUpdate.4"));
        Map<String, String> shown = APPROVED_CHANGES.get();
        List<String> outside = shown == null || plan == null || !plan.optBoolean("measured", false) ? List.of() : outsideApproved(plan, shown);
        if (outside.isEmpty()) return I18n.tr(standaloneKey);
        String list = String.join("; ", outside);
        job.write("  " + I18n.tr("server.um.everything.notShown", java.util.Map.of("changes", list)));
        return I18n.tr("server.um.everything.outsideShown", java.util.Map.of("changes", list));
    }

    /**
     * Is the plan recomputed at the start of the job the approved one? null if yes, and then it
     * writes it in the log line by line; otherwise the reason not to start.
     */
    static String approvedPlanMismatch(Job job, JSONObject plan, String currentSignature, String approvedSignature) {
        if (plan == null || !planAccepted(approvedSignature, currentSignature, plan))
            return planRefused(job, plan, approvedSignature, currentSignature, "server.um.plan.changedSinceRead");
        job.write("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(currentSignature))));
        for (String line : PackagePlan.changesInLines(plan)) job.write("    " + line);
        return null;
    }

    /** The format of the fingerprint that comes from the page: sixteen hexadecimal digits, or nothing. */
    static boolean validSignature(String s) {
        return s != null && s.matches("[0-9a-f]{16}");
    }

    /**
     * What is snapshotted right before running the plan: the package inventory, the
     * configuration with the listening addresses (InstallSideEffects), the Postfix maps.
     */
    record PlanWatch(Map<String, String> inventoryBefore, InstallSideEffects.Watch sideEffects,
                     PostfixMaps.Before mapsBefore) {
        /**
         * Only for the tests (SignedJobsE2ETest, -Doutside): a real change between the snapshot and pkg, like
         * someone installing a package from SSH while the job is running. Only whoever controls the process sets
         * it: in the panel in service it is always null.
         */
        static volatile Runnable afterTaken;

        static PlanWatch take(InstallSideEffects.Watch sideEffects) {
            Map<String, String> inventory = PackagePlan.versionsOnly(PackagePlan.installed());
            sideEffects.takeBefore();
            PlanWatch w = new PlanWatch(inventory, sideEffects, PostfixMaps.before());
            Runnable r = afterTaken;
            if (r != null) r.run();
            return w;
        }
    }

    /**
     * How the run of the plan went: the changes outside the plan, the lines of the plan not
     * respected, the Postfix maps problem (null if there is none).
     */
    record PlanOutcome(JSONArray outsidePlan, boolean planNotFollowed, String mapsProblem) {
        boolean clean() { return outsidePlan.isEmpty() && !planNotFollowed && mapsProblem == null; }
    }

    /**
     * After pkg, even if it exited with an error (that is precisely the case in which the machine may
     * have been left halfway): inventory against plan, configuration touched by the scripts, Postfix
     * maps, and every line of the plan at the version it stated.
     *
     * @param restartFollows true if the job restarts the services right afterwards (see InstallSideEffects)
     */
    // The stop reasons already translated (the maps text, PostfixMaps.Outcome.problem, and the one of
    // fetchAndRecheck, Recheck.stop) reach the page with ShownException.translated: with IllegalStateException
    // ErrorText replaced them with "the details are in the panel log", and the page no longer said which map
    // nor that the plan had changed (found by PostfixMapsJobsE2ETest and PackageReplacementE2ETest on 1.0.0
    // build 793, 2026-11-22).
    static PlanOutcome checkPlanOutcome(Job job, PlanWatch watch, JSONObject plan, String who, boolean restartFollows) {
        JSONArray outside = compareWithInventory(job, watch.inventoryBefore(), plan, who);
        watch.sideEffects().checkConfig(job, plan, outside, restartFollows);
        String maps = PostfixMaps.afterUpgrade(watch.mapsBefore(), l -> job.write("  " + l)).problem();
        job.write(I18n.tr("server.um.runGuidedUpdate.12"));
        boolean notFollowed = false;
        JSONArray verification = PackagePlan.verifyOutcome(plan);
        for (int i = 0; i < verification.length(); i++) {
            JSONObject v = verification.getJSONObject(i);
            job.write("    " + (v.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of(
                    "name", String.valueOf(v.getString("name")), "expected", String.valueOf(v.getString("expected")),
                    "found", String.valueOf(v.getString("found")))));
            if (!v.getBoolean("ok")) notFollowed = true;
        }
        if (notFollowed) job.write(I18n.tr("server.um.runGuidedUpdate.13"));
        return new PlanOutcome(outside, notFollowed, maps);
    }

    /** The outcome sentences for a plan not respected or with changes outside the plan; empty if it went as it said. */
    static java.util.List<String> planProblems(PlanOutcome o) {
        java.util.List<String> p = new ArrayList<>();
        if (o == null) return p;
        if (o.planNotFollowed()) p.add(I18n.tr("server.um.plan.notFollowed"));
        if (!o.outsidePlan().isEmpty()) p.add(divergenceMessage(o.outsidePlan()));
        if (o.mapsProblem() != null) p.add(o.mapsProblem());
        return p;
    }

    /**
     * The installed and downloadable packages that the plan installs, upgrades or reinstalls: the ones
     * pkg will download. For pkg fetch, before recomputing the plan (see fetchAndRecheck).
     */
    static java.util.List<String> planDownloads(JSONObject plan) {
        java.util.List<String> out = new ArrayList<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String t = x.optString("type"), n = x.optString("name");
            if (("install".equals(t) || "upgrade".equals(t) || "reinstall".equals(t) || "downgrade".equals(t))
                    && isValidName(n) && !out.contains(n)) out.add(n);
        }
        return out;
    }

    /**
     * Locks again the packages in the list that are installed now; those that the job removed
     * (or that never arrived) are skipped, as the startup restore does. The list on disk
     * is closed only if all the installed ones turn out locked.
     *
     * @return the packages that could not be locked again
     */
    static java.util.List<String> relockListed(Job job, java.util.List<String> names) {
        java.util.List<String> failed = new ArrayList<>();
        int done = 0;
        for (String n : names) {
            if (!isValidName(n) || !ok("pkg info -e " + n, 15)) continue;
            if (ok("pkg lock -y " + n, 30)) done++; else failed.add(n);
        }
        job.write("");
        job.write(failed.isEmpty()
                ? I18n.tr("server.um.x.reprotectAll", java.util.Map.of("n", String.valueOf(done)))
                : I18n.tr("server.um.x.reprotectSome", java.util.Map.of("list", String.valueOf(String.join(", ", failed)))));
        if (failed.isEmpty()) clearState();
        else job.write(I18n.tr("server.um.runPythonTransition.21", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
        return failed;
    }

    /**
     * Removes the locks that the plan removes, after writing the list on disk (with 'alsoListed',
     * the packages that the job locks at the end). If the list is not written nothing is unlocked.
     *
     * @return the list written, to be passed to relockListed in the finally even if the unlock fails halfway
     */
    static java.util.List<String> unlockForPlan(Job job, JSONObject plan, java.util.List<String> alsoListed) {
        java.util.List<String> toUnlock = jsonArrayToList(plan.optJSONArray("unlockedPackages"));
        java.util.List<String> listed = new ArrayList<>(toUnlock);
        for (String n : alsoListed) if (!listed.contains(n)) listed.add(n);
        for (String m : listed)
            if (!isValidName(m)) throw new IllegalStateException("invalid package name in the plan: " + m);
        if (listed.isEmpty()) return listed;
        String stateError = PackageQueue.writeState(listed);
        if (stateError != null)
            throw new IllegalStateException("I could not save the list for the restore, so I did not unlock anything: " + stateError);
        for (String m : toUnlock) {
            boolean u = ok("pkg unlock -y " + m, 30);
            job.write("    " + m + ": " + (u ? I18n.tr("server.um.x.unlocked") : I18n.tr("server.um.runGuidedUpdate.8")));
            if (!u) throw new IllegalStateException("I could not unlock " + m);
        }
        return listed;
    }

    /**
     * The MySQL family that the version IN THE REPOSITORY of a package requires, when it is
     * different from the installed one; null if there is no conflict.
     *
     * It lives in a single method because both the preflight and the plan use it: if the constraint
     * lived in only one of them, the plan would propose a step that the preflight then refuses,
     * and a guide that proposes what it then denies guides nothing.
     */
    static String mysqlFamilyConflict(String name) {
        if (!isValidName(name)) return null;
        String installed = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        if (installed.isEmpty()) return null;
        // The WHOLE family is looked at, not only the named package: php84 does not depend on
        // MySQL, but php84-mysqli and php84-pdo_mysql do, and they are updated together with it.
        // Checking only the name written in the step would let through exactly the same
        // trap as postfix, with the difference that here nobody would see it coming.
        for (String member : familyMembers(name)) {
            if (!isValidName(member)) continue;
            String deps = sh("pkg rquery -U %dn " + member + " 2>/dev/null", 30);
            Matcher m = Pattern.compile("mysql([0-9]+)-client").matcher(deps);
            if (!m.find()) continue;
            String required = "mysql" + m.group(1) + "-client";
            if (!required.equals(installed)) return required;
        }
        return null;
    }

    /** A line of the checks report: outcome, what was checked, why it matters. */
    private static void addCheck(JSONArray a, String id, String label, String level, String detail) {
        a.put(new JSONObject().put("id", id).put("label", label)
                .put("level", level).put("detail", detail));
    }

    // ===================== MySQL 8.0 -> 8.4 migration =====================

    /**
     * Preliminary checks for the switch to MySQL 8.4, all READ-ONLY.
     *
     * On this machine the migration has an obstacle that did not exist on the web panel:
     * Postfix and Dovecot read the virtual mailboxes from the database through the LIBRARY of
     * mysql80-client. If the packages that the repository provides are built against 8.0,
     * replacing that library would leave them without it, and the mail server would not start again.
     * It is not something to find out halfway through the migration: pkg is asked beforehand.
     */
    public static JSONObject mysql84Preflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean block = false;

        // --- 1. Where we start from ---
        String srvPkg = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        String cliPkg = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        r.put("srvPkg", srvPkg).put("cliPkg", cliPkg);
        if (srvPkg.isEmpty()) {
            addCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "block",
                    I18n.tr("server.um.mysql84Preflight.2"));
            block = true;
        } else if (srvPkg.startsWith("mysql84")) {
            addCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "ok",
                    I18n.tr("server.um.mysql84Preflight.3", java.util.Map.of("srvPkg", String.valueOf(srvPkg))));
            r.put("alreadyDone", true);
        } else {
            String v = sh("pkg query %v " + srvPkg, 20);
            addCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "ok",
                    I18n.tr("server.um.mysql84Preflight.4", java.util.Map.of("srvPkg", String.valueOf(srvPkg), "v", String.valueOf(v), "cliPkg", String.valueOf(cliPkg))));
        }

        // --- 2. The target exists ---
        String srv84 = sh("pkg rquery -U %v mysql84-server 2>/dev/null", 30);
        String cli84 = sh("pkg rquery -U %v mysql84-client 2>/dev/null", 30);
        r.put("target", srv84);
        if (srv84.isEmpty() || cli84.isEmpty()) {
            addCheck(checks, "target", I18n.tr("server.um.mysql84Preflight.5"), "block",
                    I18n.tr("server.um.mysql84Preflight.6"));
            block = true;
        } else {
            addCheck(checks, "target", I18n.tr("server.um.mysql84Preflight.5"), "ok",
                    I18n.tr("server.um.x.my84Avail", java.util.Map.of("s", String.valueOf(srv84), "c", String.valueOf(cli84))));
        }

        // --- 3. THE CRITICAL POINT: who uses the client library, and what it requires from the repository ---
        JSONArray dependents = new JSONArray();
        boolean conflict = false;
        if (!cliPkg.isEmpty()) {
            for (String line : sh("pkg query %rn " + cliPkg + " 2>/dev/null", 30).split("\n")) {
                String d = line.trim();
                if (!isValidName(d) || d.equals(srvPkg)) continue;
                // What the repository version of this dependent requires: if it still names
                // mysql80-client, 8.4 does not satisfy it and the package must be rebuilt.
                String deps = sh("pkg rquery -U %dn " + d + " 2>/dev/null", 30);
                boolean wants80 = deps.contains(cliPkg);
                boolean wants84 = deps.contains("mysql84-client");
                if (wants80 && !wants84) conflict = true;
                dependents.put(new JSONObject().put("name", d)
                        .put("requires", wants84 ? "mysql84-client" : (wants80 ? cliPkg : I18n.tr("server.um.mysql84Preflight.7")))
                        .put("compatible", !wants80 || wants84));
            }
        }
        r.put("dependents", dependents).put("libraryConflict", conflict);
        if (conflict) {
            addCheck(checks, "library", I18n.tr("server.um.mysql84Preflight.8"), "block",
                    I18n.tr("server.um.mysql84Preflight.9", java.util.Map.of("cliPkg", String.valueOf(cliPkg))));
            block = true;
        } else {
            addCheck(checks, "library", I18n.tr("server.um.mysql84Preflight.8"),
                    dependents.length() == 0 ? "ok" : "review",
                    dependents.length() == 0
                        ? I18n.tr("server.um.mysql84Preflight.10", java.util.Map.of("cliPkg", String.valueOf(cliPkg)))
                        : I18n.tr("server.um.mysql84Preflight.11", java.util.Map.of("length", String.valueOf(dependents.length()))));
        }

        // --- 4. Is the running process the one from the package? ---
        boolean su = ok("service mysql-server status", 15);
        String runVer = su ? mysqlOut(org.daemoxcp.mail.database.SqlCatalog.MAIL_SERVER_VERSION) : "";
        if (!su) {
            addCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), "block",
                    I18n.tr("server.um.mysql84Preflight.12"));
            block = true;
        } else if (runVer.isEmpty()) {
            addCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), "block",
                    I18n.tr("server.um.mysql84Preflight.13"));
            block = true;
        } else {
            String pkgVer = sh("pkg query %v " + srvPkg, 20).split("[_,]")[0];
            boolean matches = pkgVer.isEmpty() || runVer.startsWith(pkgVer);
            addCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), matches ? "ok" : "block",
                    matches ? I18n.tr("server.um.mysql84Preflight.14", java.util.Map.of("runVer", String.valueOf(runVer)))
                             : I18n.tr("server.um.mysql84Preflight.15", java.util.Map.of("runVer", String.valueOf(runVer), "pkgVer", String.valueOf(pkgVer))));
            if (!matches) block = true;
            r.put("runningVersion", runVer);
        }

        // --- 5. my.cnf: options removed in 8.4 ---
        JSONObject cm = mysqlCompatibility();
        JSONArray issues = cm.optJSONArray("issues");
        if (issues != null && issues.length() > 0) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < issues.length(); i++) sb.append(issues.getJSONObject(i).getString("option")).append(' ');
            addCheck(checks, "mycnf", I18n.tr("server.um.mysql84Preflight.16"), "block",
                    I18n.tr("server.um.mysql84Preflight.17", java.util.Map.of("p", String.valueOf(sb.toString().trim()))));
            block = true;
        } else {
            addCheck(checks, "mycnf", I18n.tr("server.um.mysql84Preflight.16"), "ok",
                    I18n.tr("server.um.mysql84Preflight.18"));
        }

        // --- 6. Accounts with the plugin that 8.4 no longer enables ---
        JSONArray nativeOnes = new JSONArray();
        boolean readable = su && !runVer.isEmpty() && canReadMysqlUsers();
        if (readable) {
            for (String l : usersWithNativePlugin().split("\n")) {
                if (!l.trim().isEmpty()) nativeOnes.put(l.trim());
            }
        }
        r.put("nativePasswordUsers", nativeOnes).put("userTableReadable", readable);
        if (readable) r.put("authPlugins", pluginInUse());
        if (!readable) {
            addCheck(checks, "auth", I18n.tr("server.um.mysql84Preflight.19"), "block",
                    I18n.tr("server.um.mysql84Preflight.20"));
            block = true;
        } else {
            addCheck(checks, "auth", I18n.tr("server.um.mysql84Preflight.19"), nativeOnes.length() > 0 ? "review" : "ok",
                    nativeOnes.length() == 0
                        ? I18n.tr("server.um.mysql84Preflight.21", java.util.Map.of("p", String.valueOf(describePlugin(pluginInUse()))))
                        : I18n.tr("server.um.x.nativeUsers", java.util.Map.of("n", String.valueOf(nativeOnes.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(nativeOnes))))));
        }

        // --- 7. Space for the cold copy ---
        String dataDir = sh("grep -E '^[[:space:]]*datadir[[:space:]]*=' /usr/local/etc/mysql/my.cnf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' '", 15);
        if (dataDir.isEmpty()) dataDir = "/var/db/mysql";
        long dirKb = number(sh("du -sk " + dataDir + " 2>/dev/null | awk '{print $1}'", 120));
        long freeKb = number(sh("df -k /var/db 2>/dev/null | tail -1 | awk '{print $4}'", 20));
        long needed = (long) (dirKb * 1.15) + 512L * 1024L;
        r.put("dataDir", dataDir).put("dataDirMb", dirKb / 1024).put("freeMb", freeKb / 1024);
        if (dirKb <= 0 || freeKb < needed) {
            addCheck(checks, "space", I18n.tr("server.um.mysql84Preflight.22"), "block",
                    I18n.tr("server.um.mysql84Preflight.23", java.util.Map.of("p", String.valueOf((needed / 1024)), "p2", String.valueOf((freeKb / 1024)))));
            block = true;
        } else {
            addCheck(checks, "space", I18n.tr("server.um.mysql84Preflight.22"), "ok",
                    I18n.tr("server.um.x.dataDirSpace", java.util.Map.of("dir", String.valueOf(dataDir), "mb", String.valueOf((dirKb / 1024)), "free", String.valueOf((freeKb / 1024)))));
        }

        // --- 8. Inventory, to compare again at the end of the migration ---
        long schemes = 0, tables = 0, mailboxes = 0;
        if (su && !runVer.isEmpty()) {
            schemes = number(mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_SCHEMATA));
            tables = number(mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_USER_TABLES));
            mailboxes = number(mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_MAILBOXES));
        }
        r.put("schemaCount", schemes).put("tableCount", tables).put("mailboxCount", mailboxes);
        addCheck(checks, "inventory", I18n.tr("server.um.mysql84Preflight.24"), schemes > 0 ? "ok" : "review",
                schemes > 0 ? I18n.tr("server.um.mysql84Preflight.25", java.util.Map.of("schemas", String.valueOf(schemes), "tables", String.valueOf(tables), "mailboxes", String.valueOf(mailboxes)))
                           : I18n.tr("server.um.mysql84Preflight.26"));

        // --- 9. What stops, and for how long ---
        addCheck(checks, "services", I18n.tr("server.um.x.servicesInvolved"), "review",
                I18n.tr("server.um.mysql84Preflight.27"));

        // --- 10. The EXACT plan, as in the guided update ---
        // On a copy of the pkg database the current server and client are forgotten (the job
        // removes them with pkg delete -f) and pkg is asked what it would do installing 8.4: what
        // it will really do, dependencies included. It is signed and approved.
        if (!r.optBoolean("alreadyDone", false) && isValidName(srvPkg) && isValidName(cliPkg)) {
            JSONObject plan = mysql84Plan(srvPkg, cliPkg);
            if (addPlanChecks(checks, plan, MYSQL84_PACKAGES,
                    java.util.List.of(srvPkg, cliPkg, MYSQL84_PACKAGES.get(0), MYSQL84_PACKAGES.get(1)), block)) block = true;
            r.put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""));
        }

        r.put("success", true).put("checks", checks)
         .put("canProceed", !block && !r.optBoolean("alreadyDone", false)).put("blocked", block);
        return r;
    }

    /** The packages that the migration installs. */
    static final java.util.List<String> MYSQL84_PACKAGES = java.util.List.of("mysql84-server", "mysql84-client");

    /**
     * The mail packages tied to the MySQL client: Postfix and Dovecot in the MySQL flavor, which for Dovecot
     * changes name with the version (dovecot-mysql for 2.3, dovecot24-mysql for 2.4). After the client is
     * replaced, the ones that were there before must still be there: on the VM after a clean install
     * (Dovecot 2.4), on 2026-11-21, the migration looked only for dovecot-mysql, reported it as "MISSING"
     * and ended with an error on a mail system that worked.
     */
    static final java.util.List<String> MAIL_MYSQL_PACKAGES = java.util.List.of("postfix-mysql", "dovecot-mysql", "dovecot24-mysql");

    /** The exact plan of the migration: remove the current server and client, then install 8.4. */
    private static JSONObject mysql84Plan(String srvPkg, String cliPkg) {
        return judged(PackagePlan.planRemoveThenInstall(java.util.List.of(srvPkg, cliPkg), MYSQL84_PACKAGES,
                lockedNames(), UpdateManager::reasonNotToUnlock));
    }

    private static final String MYSQL84_BACKUP = "/var/db/daemoxcp-mail/mysql84";

    /** Inserts a directive right after [mysqld], if it is not already there. Atomic write. */
    private static boolean addMysqldDirective(String line) {
        java.nio.file.Path f = Paths.get("/usr/local/etc/mysql/my.cnf");
        try {
            java.util.List<String> lines = Files.readAllLines(f);
            String key = line.split("=")[0].trim();
            for (String r : lines) if (!r.trim().startsWith("#") && r.trim().startsWith(key)) return true;
            java.util.List<String> fresh = new ArrayList<>();
            boolean put = false;
            for (String r : lines) {
                fresh.add(r);
                if (!put && r.trim().equalsIgnoreCase("[mysqld]")) {
                    fresh.add("# added by the panel: in 8.4 mysql_native_password is not active by default");
                    fresh.add(line);
                    put = true;
                }
            }
            if (!put) return false;
            java.nio.file.Path tmp = Paths.get("/tmp/my.cnf.daemoxcp-mail-84");
            Files.write(tmp, fresh);
            return ok("mv " + tmp + " /usr/local/etc/mysql/my.cnf", 30)
                && ok("chmod 644 /usr/local/etc/mysql/my.cnf", 15);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not add " + line + " to my.cnf", e);
            return false;
        }
    }

    /** Files and logical bytes of a tree: measured with stat, NEVER with du. */
    private static long[] measure(String dir) {
        long file = number(sh("find " + dir + " -type f 2>/dev/null | wc -l", 120));
        long logicalBytes = number(sh("find " + dir + " -type f -exec stat -f %z {} + 2>/dev/null "
                + "| awk '{s+=$1} END {print s+0}'", 120));
        return new long[]{file, logicalBytes};
    }

    /**
     * Starts a package job in its own thread, after taking the turn: one at a time
     * (see PackageQueue). If the turn belongs to someone else, or there is the list of a job that did not
     * close, the job does not start and the response says why.
     */
    /**
     * A job thread that writes in the language of whoever started it: the I18n ThreadLocal does not
     * pass to new threads by itself, and without this the log of a job would always come out in Italian.
     */
    private static Thread localizedThread(Runnable work, String name) {
        return new Thread(I18n.withCurrent(work), name);
    }

    /** The thread of a Job: as above, and with the end written in any case (withEndMarked). */
    private static Thread localizedThread(Job j, Runnable work, String name) {
        return localizedThread(withEndMarked(j, work), name);
    }

    /**
     * The work of a Job, with the end written in any case when the thread exits.
     *
     * An outcome becomes visible only once the end is written (Job.visibleStatus): a job that
     * gave an outcome and exited without writing the end -- because of a forgotten return, or of
     * an exception outside its try -- would stay "running" forever in the eyes of the
     * page. Every job already writes its own end as its last step; this is the
     * floor, and it does not move the end of a job that wrote it.
     */
    static Runnable withEndMarked(Job j, Runnable work) {
        return () -> {
            try { work.run(); }
            finally { j.markFinished(); }
        };
    }

    /**
     * The job with its way back (PackageWayBack): the boot environment before, and the cleanup
     * after (it is removed if no package changed, otherwise the oldest ones are). If the boot
     * environment cannot be created on a system that has them, the job ends in error without starting.
     */
    static Runnable withWayBack(Job j, String kind, Runnable work) {
        return () -> {
            PackageWayBack.Prepared wb;
            try {
                wb = PackageWayBack.before(j::write, kind);
            } catch (IllegalStateException e) {
                j.status = "error";
                j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
                j.write(e.getMessage());
                return;
            }
            j.write("");
            // Before the end is written: if the job writes it itself, the cleanup runs there; if not, here.
            j.beforeEnd(() -> PackageWayBack.after(j::write, wb));
            try { work.run(); }
            finally { j.runBeforeEnd(); }
        };
    }

    private static JSONObject startOnTurn(String id, Job j, String description, String threadName, Runnable work) {
        String refusal = PackageQueue.take(id, description);
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        // First of all the way back: a boot environment, or the job touches nothing.
        work = withWayBack(j, threadName, work);
        // Every job of the turn may have removed and restored locks, or upgraded locked
        // packages (which lose the annotation that way): the record is brought up to date at the end.
        work = withLockTrace(work);
        work = withWebmailOwnership(work);
        JOBS.put(id, j);
        PackageQueue.start(id, threadName, withEndMarked(j, work));
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * @param approvedSignature the signature of the plan that whoever presses has read: the job recomputes the
     *                          plan and starts only if it is the same (see startGuidedUpdate)
     */
    public static JSONObject startMysql84Migration(String approvedSignature) {
        if (!validSignature(approvedSignature))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.plan.signatureMissing"));
        String id = "my84-" + System.currentTimeMillis();
        Job j = new Job(id, "mysql84_migration");
        return startOnTurn(id, j, I18n.tr("server.um.x.jobMy84"), "mysql84-migration",
                () -> runMigration84(j, approvedSignature));
    }

    /**
     * Migration to MySQL 8.4.
     *
     * Compared with the same operation on the web panel there are two differences that come
     * from the nature of this machine: Postfix and Dovecot read the mailboxes from the database
     * through the client library, so they are stopped BEFORE and checked again AFTER; and the
     * final check is not satisfied with "the service is running" but asks Postfix and
     * Dovecot to actually resolve a mailbox. A service that is up but no longer reads the
     * users is the worst way of looking fine.
     */
    private static void runMigration84(Job job, String approvedSignature) {
        job.status = "running";
        final int TOT = 12;
        // The on-disk list of this job, to lock again in the finally: empty until it is written.
        java.util.List<String> listed = new ArrayList<>();
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        PlanOutcome outcome = null;
        String backupDir = "", dataDir = "/var/db/mysql", srvPkg = "", cliPkg = "";
        boolean mysqlStopped = false, replacedPackages = false, reachedEnd = false;
        boolean postfixWasActive = false, dovecotWasActive = false;
        // The state of the services BEFORE: without this, "not running now" would be taken for
        // "gone down now" even for a service that had never started.
        Map<String, Boolean> servicesBefore = servicesState();
        long schemesBefore = 0, tablesBefore = 0, mailboxesBefore = 0;
        String testMailbox = "";
        try {
            job.advance(1, TOT);
            job.write("=== " + I18n.tr("server.um.x.jobMy84Title") + " ===");
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = mysql84Preflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("alreadyDone", false)
                        ? I18n.tr("server.um.runMigration84.2") : I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.write("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            srvPkg = pf.optString("srvPkg", "");
            cliPkg = pf.optString("cliPkg", "");
            dataDir = pf.optString("dataDir", "/var/db/mysql");
            schemesBefore = pf.optLong("schemaCount", 0);
            tablesBefore = pf.optLong("tableCount", 0);
            mailboxesBefore = pf.optLong("mailboxCount", 0);
            testMailbox = mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_FIRST_ACTIVE_MAILBOX).trim();
            job.write("  " + srvPkg + " + " + cliPkg + " -> mysql84-server + mysql84-client");
            // The plan that was read is carried out, or nothing is: before stopping the mail.
            JSONObject plan = pf.optJSONObject("plan");
            String mismatch = approvedPlanMismatch(job, plan, pf.optString("signature", null), approvedSignature);
            if (mismatch != null) {
                job.status = "error";
                job.errorMessage = mismatch;
                return;
            }
            // The packages the plan installs are downloaded and the plan is computed again: until they
            // are in the cache pkg does not see the file conflicts (see fetchAndRecheck). All with the
            // mail still in service: a plan that has grown stops here, without having touched anything.
            final String srv0 = srvPkg, cli0 = cliPkg;
            java.util.List<String> downloads = planDownloads(plan);
            if (!downloads.isEmpty()) {
                Recheck grown = fetchAndRecheck(job, "pkg fetch -y -U " + String.join(" ", downloads) + " 2>&1", plan,
                        () -> mysql84Plan(srv0, cli0));
                if (grown.stop() != null) throw org.daemoxcp.mail.util.ShownException.translated(grown.stop());
                plan = grown.plan();
            }
            // The inventory, the configuration and the addresses listening now, with everything in
            // service: it is what the end is compared against.
            PlanWatch watch = PlanWatch.take(sideEffects);
            // The mail packages tied to the MySQL client that are there now: the ones step 6 looks for later.
            java.util.List<String> mailMysqlBefore = new ArrayList<>();
            for (String d : MAIL_MYSQL_PACKAGES) if (ok("pkg info -e " + d, 20)) mailMysqlBefore.add(d);
            job.write(I18n.tr("server.um.runMigration84.5", java.util.Map.of("schemasBefore", String.valueOf(schemesBefore), "tablesBefore", String.valueOf(tablesBefore), "mailboxesBefore", String.valueOf(mailboxesBefore))));
            job.write("  " + (testMailbox.isEmpty()
                    ? I18n.tr("server.um.x.testBoxNone")
                    : I18n.tr("server.um.x.testBox", java.util.Map.of("mailbox", String.valueOf(testMailbox)))));

            job.advance(2, TOT);
            job.write("");
            job.write("[2/" + TOT + "] " + I18n.tr("server.um.x.stopPfDc"));
            postfixWasActive = ok("service postfix status", 20);
            dovecotWasActive = ok("service dovecot status", 20);
            if (postfixWasActive) { ok("service postfix stop", 60); job.write(I18n.tr("server.um.runMigration84.6")); }
            else job.write(I18n.tr("server.um.runMigration84.7"));
            if (dovecotWasActive) { ok("service dovecot stop", 60); job.write(I18n.tr("server.um.runMigration84.8")); }
            else job.write(I18n.tr("server.um.runMigration84.9"));

            job.advance(3, TOT);
            job.write("");
            job.write("[3/" + TOT + "] " + I18n.tr("server.um.x.stopMysql"));
            ok("service mysql-server stop", 120);
            boolean down = false;
            for (int i = 0; i < 120; i++) {
                if (!ok("service mysql-server status", 10) && !ok("pgrep -q mysqld", 10)) { down = true; break; }
                try { Thread.sleep(1000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            if (!down) throw new IllegalStateException("MySQL did not stop: a copy taken while the server is running could not be restored");
            mysqlStopped = true;
            job.write("    " + I18n.tr("server.um.x.stoppedConfirmed"));

            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.10", java.util.Map.of("total", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date for the copy");
            backupDir = MYSQL84_BACKUP + "/" + ts;
            if (!ok("mkdir -p " + backupDir + "/pkg", 30)) throw new IllegalStateException("cannot create " + backupDir);
            ok("cp -p /usr/local/etc/mysql/my.cnf " + backupDir + "/my.cnf", 30);
            ok("printf '%s\\n%s\\n' " + srvPkg + " " + cliPkg + " > " + backupDir + "/packages.txt", 20);
            job.write(I18n.tr("server.um.runMigration84.11"));
            ok("pkg fetch -y -o " + backupDir + "/pkg " + srvPkg + " " + cliPkg + " >/dev/null 2>&1", 600);
            job.write("    " + I18n.tr("server.um.x.pkgsKept", java.util.Map.of("n", String.valueOf(number(sh("find " + backupDir + "/pkg -name '*.pkg' | wc -l", 30))))));

            long[] before = measure(dataDir);
            job.write("    " + I18n.tr("server.um.x.copying", java.util.Map.of("dir", String.valueOf(dataDir), "n", String.valueOf(before[0]), "mb", String.valueOf((before[1] / 1024 / 1024)))));
            String cpOut = sh("cp -Rp " + dataDir + " " + backupDir + "/datadir 2>&1; echo EXIT=$?", 1800);
            int cpCode = -1;
            for (String l : cpOut.split("\n")) {
                if (l.startsWith("EXIT=")) { cpCode = (int) number(l); continue; }
                if (!l.trim().isEmpty()) job.write("      cp: " + l);
            }
            if (cpCode != 0) throw new IllegalStateException("cp exited with code " + cpCode);
            ok("sync", 120);
            long[] after = measure(backupDir + "/datadir");
            if (after[0] != before[0] || after[1] != before[1]) {
                throw new IllegalStateException("the copy does not match: " + after[0] + " files / " + after[1]
                        + " bytes against " + before[0] + " / " + before[1]);
            }
            if (!ok("test -f " + backupDir + "/datadir/ibdata1", 15)) {
                throw new IllegalStateException("ibdata1 is missing from the copy: it is not a data folder that can be restored");
            }
            ok("printf '%s\\n%s\\n' " + before[0] + " " + before[1] + " > " + backupDir + "/manifest.txt", 20);
            job.write(I18n.tr("server.um.runMigration84.12", java.util.Map.of("p", String.valueOf(after[0]), "p2", String.valueOf((after[1] / 1024 / 1024)))));
            job.write(I18n.tr("server.um.runMigration84.13", java.util.Map.of("backupDir", String.valueOf(backupDir))));

            job.advance(5, TOT);
            job.write("");
            job.write("[5/" + TOT + "] " + I18n.tr("server.um.x.replacingPkgs"));
            // The locks the plan removes (current server and client, and the dependencies the
            // plan upgrades), with the on-disk list first: the list also includes 8.4, which is
            // locked at the end. The finally locks again what is there, even if the job stops halfway.
            listed = unlockForPlan(job, plan, MYSQL84_PACKAGES);
            int delCode = runLogged(job, "pkg delete -f -y " + srvPkg + " " + cliPkg + " 2>&1", 300);
            replacedPackages = true;
            // -U: the same catalog the plan was computed on.
            int insCode = delCode != 0 ? -1 : runLogged(job, "pkg install -y -U " + String.join(" ", MYSQL84_PACKAGES) + " 2>&1", 900);
            if (insCode == 4) {
                job.write(I18n.tr("server.um.runGuidedUpdate.10"));
                insCode = runLogged(job, "pkg install -y -U " + String.join(" ", MYSQL84_PACKAGES) + " 2>&1", 900);
            }
            // The comparison with the plan before deciding whether to stop: a pkg that ended badly is
            // exactly the case in which the machine may have been left halfway. The services restart
            // further down.
            outcome = checkPlanOutcome(job, watch, plan, "MySQL 8.4 migration", true);
            if (delCode != 0) throw new IllegalStateException("pkg delete exited with code " + delCode
                    + ": the data is intact, the copy is in " + backupDir);
            if (insCode != 0 || !ok("pkg info -e mysql84-server", 20) || !ok("pkg info -e mysql84-client", 20)) {
                throw new IllegalStateException("the 8.4 installation did not succeed: the data is intact, the copy is in " + backupDir);
            }
            if (outcome.mapsProblem() != null) throw org.daemoxcp.mail.util.ShownException.translated(outcome.mapsProblem());

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.14", java.util.Map.of("total", String.valueOf(TOT))));
            boolean lost = false;
            for (String d : mailMysqlBefore) {
                boolean c = ok("pkg info -e " + d, 20);
                job.write("    " + d + ": " + (c ? I18n.tr("server.um.x.present") : I18n.tr("server.um.x.missing")));
                if (!c) lost = true;
            }
            if (lost) job.write(I18n.tr("server.um.runMigration84.15"));

            job.advance(7, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.16", java.util.Map.of("total", String.valueOf(TOT))));
            if (ok("test -f " + backupDir + "/my.cnf", 15)) {
                ok("cp -p " + backupDir + "/my.cnf /usr/local/etc/mysql/my.cnf", 30);
                ok("chmod 644 /usr/local/etc/mysql/my.cnf", 15);
                job.write("    " + I18n.tr("server.um.x.mycnfRestored"));
            }
            JSONArray nativeOnes = pf.optJSONArray("nativePasswordUsers");
            if (nativeOnes != null && nativeOnes.length() > 0) {
                job.write("    " + I18n.tr("server.um.x.nativeAdd", java.util.Map.of("n", String.valueOf(nativeOnes.length()))));
                // In Java line by line, NOT with sed: BSD sed does not interpret \n in the
                // replacement and would insert the letter "n" instead of a line break, producing
                // a malformed my.cnf precisely in the step meant to keep any account from
                // being locked out. On this machine the branch does not trigger, but a defect
                // that cannot be seen today is just a defect that is waiting.
                job.write("    " + (addMysqldDirective("mysql-native-password=ON")
                        ? I18n.tr("server.um.runMigration84.17") : I18n.tr("server.um.runMigration84.18")));
            }

            job.advance(8, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.19", java.util.Map.of("total", String.valueOf(TOT))));
            String bin = sh("which mysqld 2>/dev/null", 15);
            if (bin.isEmpty()) bin = "/usr/local/libexec/mysqld";
            String val = sh("su -m mysql -c '" + bin + " --validate-config' 2>&1", 120);
            if (!val.isEmpty()) {
                for (String l : val.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
                if (val.toLowerCase().matches("(?s).*(error|unknown variable|aborting).*")) {
                    throw new IllegalStateException("mysqld 8.4 does not accept my.cnf: the data was not touched, "
                            + "the copy is in " + backupDir);
                }
            } else job.write("    " + I18n.tr("server.um.x.acceptedClean"));

            job.advance(9, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.21", java.util.Map.of("total", String.valueOf(TOT))));
            ok("service mysql-server start", 120);
            String newVer = "";
            for (int i = 0; i < 200; i++) {
                newVer = mysqlOut(org.daemoxcp.mail.database.SqlCatalog.MAIL_SERVER_VERSION).trim();
                if (!newVer.isEmpty()) break;
                try { Thread.sleep(3000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                if (i % 5 == 4) job.write(I18n.tr("server.um.runMigration84.22", java.util.Map.of("p", String.valueOf(((i + 1) * 3)))));
            }
            if (newVer.isEmpty()) throw new IllegalStateException("MySQL 8.4 does not answer: the copy is in " + backupDir);
            mysqlStopped = false;
            job.write("    VERSION() = " + newVer);
            if (!newVer.startsWith("8.4")) throw new IllegalStateException("the running version is " + newVer + ", not an 8.4");

            job.advance(10, TOT);
            job.write("");
            job.write("[10/" + TOT + "] " + I18n.tr("server.um.x.inventory"));
            long sd = number(mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_SCHEMATA));
            long td = number(mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_USER_TABLES));
            long cd = number(mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_MAILBOXES));
            job.write(I18n.tr("server.um.runMigration84.23", java.util.Map.of("schemasBefore", String.valueOf(schemesBefore), "schemasAfter", String.valueOf(sd), "tablesBefore", String.valueOf(tablesBefore), "tablesAfter2", String.valueOf(td), "mailboxesBefore", String.valueOf(mailboxesBefore), "mailboxesAfter", String.valueOf(cd))));
            boolean inventoryOk = sd >= schemesBefore && td >= tablesBefore && cd >= mailboxesBefore;
            if (!inventoryOk) job.write(I18n.tr("server.um.runMigration84.24", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            else job.write("    " + I18n.tr("server.um.x.inventoryIntact"));

            job.advance(11, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.25", java.util.Map.of("total", String.valueOf(TOT))));
            boolean l1 = ok("pkg lock -y mysql84-server", 30), l2 = ok("pkg lock -y mysql84-client", 30);
            job.write("    " + I18n.tr("server.um.x.protect84", java.util.Map.of("s", String.valueOf(l1 ? "ok" : I18n.tr("server.um.x.failedF")), "c", String.valueOf(l2 ? "ok" : I18n.tr("server.um.x.failedF")))));
            if (postfixWasActive) { ok("service postfix start", 120); job.write("    postfix: " + (ok("service postfix status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26"))); }
            if (dovecotWasActive) { ok("service dovecot start", 120); job.write("    dovecot: " + (ok("service dovecot status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26"))); }

            job.advance(12, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.27", java.util.Map.of("total", String.valueOf(TOT))));
            // "The service is running" is not enough: after replacing the client library the
            // point is whether Postfix and Dovecot CAN STILL query the database.
            boolean testOk = true;
            // The address ends up inside a command: only what really is an address is
            // accepted. It comes from the database and not from outside, but the validation
            // costs one line and the Dovecot job already had it: treating the same thing
            // twice in two different ways is how an oversight survives.
            if (!testMailbox.isEmpty()
                    && !testMailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.write(I18n.tr("server.um.runMigration84.28"));
                testMailbox = "";
            }
            if (testMailbox.isEmpty()) {
                job.write(I18n.tr("server.um.runMigration84.29"));
            } else {
                // THIS is the test that counts: postmap queries MySQL through the client
                // library that was just replaced. If it works, the replacement held.
                String mapFile = "/usr/local/etc/postfix/mysql-virtual-mailboxes.cf";
                if (ok("test -f " + mapFile, 15)) {
                    String q = sh("postmap -q '" + testMailbox + "' mysql:" + mapFile + " 2>&1", 60);
                    // Looking only for the word "error" was wrong: postmap writes "fatal:",
                    // and the check declared a failure successful while printing the
                    // proof of it. All the forms are recognized, and above all the
                    // answer is required to BE a result: an address, not a message.
                    String ql = q.toLowerCase();
                    boolean pOk = !q.trim().isEmpty()
                            && !ql.contains("error") && !ql.contains("fatal")
                            && !ql.contains("warning") && !ql.contains("not found")
                            && !ql.contains("dlopen") && !ql.contains("unsupported")
                            && !ql.startsWith("postmap:");
                    job.write("    " + (pOk
                            ? I18n.tr("server.um.x.pfQueryYes", java.util.Map.of("mailbox", String.valueOf(testMailbox), "r", String.valueOf(q.trim())))
                            : I18n.tr("server.um.x.pfQueryNo", java.util.Map.of("mailbox", String.valueOf(testMailbox), "r", String.valueOf(q.trim())))));
                    if (!pOk) testOk = false;
                } else {
                    job.write(I18n.tr("server.um.runMigration84.30", java.util.Map.of("mapFile", String.valueOf(mapFile))));
                    testOk = false;
                }

                // This one, instead, proves less than it seems, and that must be said: the
                // userdb here is "static", so doveadm answers without querying the database.
                // It shows that Dovecot is alive and resolves users, not that its SQL passdb
                // works.
                String du = sh("doveadm user '" + testMailbox + "' 2>&1 | head -5", 60);
                boolean dOk = du.toLowerCase().contains("uid") || du.toLowerCase().contains("home");
                job.write("    " + (dOk
                        ? I18n.tr("server.um.x.dcResolveYes", java.util.Map.of("mailbox", String.valueOf(testMailbox)))
                        : I18n.tr("server.um.x.dcResolveNo", java.util.Map.of("mailbox", String.valueOf(testMailbox), "r", String.valueOf(du.trim())))));
                if (!dOk) testOk = false;

                // Dovecot's SQL path is tested like this: the same query that is in its
                // dovecot-sql.conf, run with the same credentials.
                String lines = mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_ACTIVE_MAILBOX_COUNT, testMailbox).trim();
                boolean sOk = "1".equals(lines);
                job.write("    " + (sOk
                        ? I18n.tr("server.um.x.dcAuthYes", java.util.Map.of("mailbox", String.valueOf(testMailbox)))
                        : I18n.tr("server.um.x.dcAuthNo", java.util.Map.of("mailbox", String.valueOf(testMailbox), "lines", String.valueOf(lines)))));
                if (!sOk) testOk = false;
            }

            job.write("");
            job.write(I18n.tr("server.um.runMigration84.31"));
            boolean fallen = fallenServices(job, servicesBefore);
            sideEffects.checkListening(job);
            java.util.List<String> problems = planProblems(outcome);
            problems.addAll(sideEffects.problems());

            reachedEnd = true;
            if (!inventoryOk || !testOk || fallen || lost || !l1 || !l2 || !problems.isEmpty()) {
                job.status = "error";
                problems.add(I18n.tr("server.um.runMigration84.32", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                job.errorMessage = String.join(" ", problems);
            } else {
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runMigration84.33", java.util.Map.of("newVer", String.valueOf(newVer))));
                job.write(I18n.tr("server.um.runMigration84.34", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            for (String p : sideEffects.problems()) job.errorMessage += " " + p;
            if (outcome != null && !outcome.outsidePlan().isEmpty()) job.errorMessage += " " + divergenceMessage(outcome.outsidePlan());
            job.write("");
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // Every package on the list that is installed now gets locked: 8.4 if it arrived,
            // 8.0 if the job stopped before removing it, the unlocked dependencies.
            if (!listed.isEmpty() && !relockListed(job, listed).isEmpty() && "completed".equals(job.status)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runGuidedUpdate.42");
            }
            if (!reachedEnd) {
                if (mysqlStopped && !replacedPackages) {
                    job.write("");
                    job.write(I18n.tr("server.um.runMigration84.35"));
                    ok("service mysql-server start", 120);
                    if (postfixWasActive) ok("service postfix start", 120);
                    if (dovecotWasActive) ok("service dovecot start", 120);
                } else if (replacedPackages) {
                    job.write("");
                    job.write(I18n.tr("server.um.runMigration84.36"));
                    if (!backupDir.isEmpty()) job.write(I18n.tr("server.um.runMigration84.37", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                }
            }
            job.finish();
        }
    }

    // ===================== switch to Dovecot 2.4 (finding 213) =====================

    /**
     * Where the move keeps the configuration and the 2.3 packages as they were: the road back, one
     * folder per move, root only.
     */
    private static final String DOVECOT24_BACKUP = "/var/db/daemoxcp-mail/dovecot24";

    /** The installed Dovecot packages, by origin (server and Pigeonhole, of 2.3 and of 2.4): {name, version}. */
    static Map<String, String[]> dovecotPackages() {
        return dovecotPackages(sh("pkg query '%o %n %v' 2>/dev/null", 30));
    }

    /** The same from the lines of "pkg query '%o %n %v'": testable without pkg. */
    static Map<String, String[]> dovecotPackages(String pkgQuery) {
        Map<String, String[]> m = new LinkedHashMap<>();
        for (String line : pkgQuery.split("\n")) {
            String[] c = line.trim().split(" ");
            if (c.length == 3 && c[0].matches("mail/dovecot(24)?(-pigeonhole)?") && isValidName(c[1]))
                m.put(c[0], new String[]{c[1], c[2]});
        }
        return m;
    }

    /**
     * The 2.4 packages in place of the 2.3 ones: the same flavor, Pigeonhole only if it was there. The panel writes
     * the MySQL connection into the configuration, so the flavor is MySQL or nothing: null for everything else.
     */
    static java.util.List<String> dovecot24Targets(String server23, String sieve23) {
        if (!"dovecot-mysql".equals(server23)) return null;
        java.util.List<String> t = new ArrayList<>(java.util.List.of("dovecot24-mysql"));
        if (sieve23 != null && !sieve23.isEmpty()) {
            if (!"dovecot-pigeonhole-mysql".equals(sieve23)) return null;
            t.add("dovecot24-pigeonhole-mysql");
        }
        return t;
    }

    /** The panel's MySQL password, from its configuration: "" if it cannot be read. */
    private static String panelDbPassword() {
        try (java.sql.ResultSet rs = org.daemoxcp.mail.Main.dbManager.get_data_config()) {
            if (rs.next()) {
                String pw = org.daemoxcp.mail.Main.dbManager.mysqlPassword();
                return pw == null ? "" : pw;
            }
        } catch (Exception ignored) {}
        return "";
    }

    /** The password of Dovecot's main user (the Roundcube one), or null if there is none. */
    private static String dovecotMasterPassword() {
        try {
            Path p = Paths.get(org.daemoxcp.mail.integration.RoundcubeSsoManager.MASTER_PASSWORD_FILE);
            if (!Files.isRegularFile(p)) return null;
            String pw = Files.readString(p, StandardCharsets.UTF_8).trim();
            return pw.isEmpty() ? null : pw;
        } catch (Exception e) {
            return null;
        }
    }

    /** The certificate file Dovecot presents (ssl_server_cert_file in 2.4, ssl_cert in 2.3), or null. */
    private static Path dovecotCertificatePath() {
        for (String key : new String[]{"ssl_server_cert_file", "ssl_cert"}) {
            String v = sh("doveconf -h " + key + " 2>/dev/null", 20).trim();
            if (v.startsWith("<")) v = v.substring(1).trim();
            if (v.matches("/[A-Za-z0-9._/-]{1,255}") && Files.isRegularFile(Paths.get(v))) return Paths.get(v);
        }
        return null;
    }

    /** The MySQL user Dovecot reads the mailboxes with, from its configuration (2.4 or 2.3); "" if it cannot be read. */
    static String dovecotDbUser() {
        try {
            Path auth = Paths.get(DOVECOT_DIR, "conf.d", "auth-sql.conf.ext"), sql = Paths.get(DOVECOT_DIR, "dovecot-sql.conf");
            if (Files.isRegularFile(auth)) {
                MailDbUsers.Login l = MailDbUsers.dovecot24Login(Files.readString(auth, StandardCharsets.UTF_8));
                if (l != null) return l.user();
            }
            if (Files.isRegularFile(sql)) {
                MailDbUsers.Login l = MailDbUsers.dovecot23Login(Files.readString(sql, StandardCharsets.UTF_8));
                if (l != null) return l.user();
            }
        } catch (Exception ignored) {}
        return "";
    }

    /**
     * Where Postfix delivers with LMTP, from its virtual_transport: {host, port}. Null if it is not a TCP address (a
     * socket, or another transport): then the LMTP test is not done, and the log says so.
     */
    static String[] lmtpTarget(String transport) {
        Matcher m = Pattern.compile("^lmtp:(?:inet:)?(127\\.0\\.0\\.1|localhost|\\[::1\\]|::1):([0-9]{1,5})$")
                .matcher(transport == null ? "" : transport.trim());
        if (!m.find()) return null;
        String host = m.group(1).replace("[", "").replace("]", "");
        return new String[]{"localhost".equals(host) ? "127.0.0.1" : host, m.group(2)};
    }

    /**
     * The Unix socket Postfix delivers to with LMTP, from its virtual_transport and its queue: lmtp:unix:private/X
     * is relative to the queue (finding 234). Null if it is not a Unix socket, or if the names do not have the
     * expected form.
     */
    static Path lmtpSocket(String transport, String queueDirectory) {
        Matcher m = Pattern.compile("^lmtp:unix:([A-Za-z0-9._/-]{1,200})$").matcher(transport == null ? "" : transport.trim());
        if (!m.find() || m.group(1).contains("..")) return null;
        String p = m.group(1);
        if (p.startsWith("/")) return Paths.get(p);
        String q = queueDirectory == null ? "" : queueDirectory.trim();
        if (!q.matches("/[A-Za-z0-9._/-]{1,200}") || q.contains("..")) return null;
        return Paths.get(q, p);
    }

    /** The Dovecot authentication socket Postfix uses for sending; null if Postfix does not ask Dovecot. */
    private static Path postfixAuthSocket() {
        if (!"dovecot".equals(sh("postconf -h smtpd_sasl_type 2>/dev/null", 20).trim())) return null;
        String p = sh("postconf -h smtpd_sasl_path 2>/dev/null", 20).trim();
        String q = sh("postconf -h queue_directory 2>/dev/null", 20).trim();
        if (!p.matches("[A-Za-z0-9._/-]{1,200}") || !q.matches("/[A-Za-z0-9._/-]{1,200}")) return null;
        return Paths.get(p.startsWith("/") ? p : q + "/" + p);
    }

    /**
     * What the mail tests saw: for each test null if it passed, otherwise the reason; the addresses Dovecot
     * listens on; the Sieve extensions announced (null without ManageSieve); the user the process that looks up
     * passwords runs as (auth-worker, "" if root: DovecotAuthWorker).
     */
    record MailState(LinkedHashMap<String, String> results, Set<String> listeners, Set<String> sieve, String workerUser) {
        java.util.List<String> failed() {
            java.util.List<String> f = new ArrayList<>();
            for (Map.Entry<String, String> e : results.entrySet()) if (e.getValue() != null) f.add(e.getKey() + ": " + e.getValue());
            return f;
        }
    }

    /**
     * The real mail tests, the same before (on 2.3) and after (on 2.4), written to the log one per line: the
     * configuration according to Dovecot, the socket through which Postfix lets senders in, the mailbox according
     * to doveadm, the LMTP delivery stopped before the message, the IMAP login on 993 with the main user (like
     * Roundcube) and the ManageSieve greeting. None of them changes anything (MailProbes).
     */
    private static MailState mailTests(Job job, String mailbox, String masterPassword, boolean sieve) {
        LinkedHashMap<String, String> res = new LinkedHashMap<>();
        Shell.Result dc = Shell.runShell(Duration.ofSeconds(30), "doveconf -n 2>&1 >/dev/null");
        res.put("doveconf -n", dc.success() && dc.outputTrim().isEmpty() ? null : firstLineOf(dc.outputTrim()));
        Set<String> listeners = MailProbes.dovecotListeners(sh("sockstat -46lq -P tcp 2>/dev/null", 20));
        Path auth = postfixAuthSocket();
        if (auth != null) res.put(I18n.tr("server.um.dv24move.tAuth"), MailProbes.authSocket(auth, 10_000));
        if (mailbox != null) {
            String du = sh("doveadm user '" + mailbox + "' 2>&1 | head -5", 60);
            res.put("doveadm user " + mailbox, du.contains("uid") && du.contains("home") ? null : firstLineOf(du));
            String transport = sh("postconf -h virtual_transport 2>/dev/null", 20);
            String[] lmtp = lmtpTarget(transport);
            Path lmtpUnix = lmtp == null ? lmtpSocket(transport, sh("postconf -h queue_directory 2>/dev/null", 20)) : null;
            if (lmtp != null) res.put(I18n.tr("server.um.dv24move.tLmtp", Map.of("mailbox", mailbox)),
                    MailProbes.lmtpRecipient(lmtp[0], Integer.parseInt(lmtp[1]), mailbox, 15_000));
            else if (lmtpUnix != null) res.put(I18n.tr("server.um.dv24move.tLmtp", Map.of("mailbox", mailbox)),
                    MailProbes.lmtpRecipient(lmtpUnix, mailbox, 15_000));
            else job.write("    " + I18n.tr("server.um.dv24move.noLmtp"));
            Path cert = dovecotCertificatePath();
            if (masterPassword != null && cert != null && listeners.stream().anyMatch(l -> l.endsWith(":993"))) {
                String imap;
                try {
                    imap = MailProbes.imapLogin("127.0.0.1", 993, MailProbes.leafCertificate(cert),
                            mailbox + "*" + org.daemoxcp.mail.integration.RoundcubeSsoManager.MASTER_USER, masterPassword, 15_000);
                } catch (Exception e) {
                    imap = cert + ": " + e.getMessage();
                }
                res.put(I18n.tr("server.um.dv24move.tImap", Map.of("mailbox", mailbox)), imap);
            } else job.write("    " + I18n.tr("server.um.dv24move.noImap"));
        }
        // The users of the Dovecot processes (ServiceUsers): on 2.4 one privilege too many is not a fault that
        // shows, but the move must not bring it in.
        java.util.List<String> su = new ArrayList<>();
        for (ServiceUsers.Problem p : ServiceUsers.now().problems()) if (p.service().contains("dovecot")) su.add(p.logText());
        res.put(I18n.tr("server.um.dv24move.tUsers"), su.isEmpty() ? null : String.join("; ", su));
        // POP3, if it is on: the open port is not enough (on 2.4 pop3-login can die at every connection, Pop3).
        if (listeners.stream().anyMatch(l -> l.endsWith(":110")))
            res.put("POP3 110", MailProbes.pop3Greeting("127.0.0.1", 110, 10_000));
        Set<String> ext = null;
        if (sieve) {
            ext = MailProbes.sieveExtensions("127.0.0.1", 4190, 10_000);
            res.put("ManageSieve 4190", ext == null ? I18n.tr("server.um.dv24move.noSieve") : null);
        }
        for (Map.Entry<String, String> e : res.entrySet())
            job.write("    " + (e.getValue() == null ? "ok  " : "NO  ") + e.getKey() + (e.getValue() == null ? "" : ": " + e.getValue()));
        job.write("    " + I18n.tr("server.um.dv24move.listening", Map.of("list", String.join(", ", listeners))));
        if (ext != null) job.write("    " + I18n.tr("server.um.dv24move.sieveExt", Map.of("n", String.valueOf(ext.size()))));
        String worker = sh("doveconf -h service/auth-worker/user 2>/dev/null", 20).trim();
        job.write("    " + I18n.tr("server.um.dv24move.worker", Map.of("user", worker.isEmpty() ? "root" : worker)));
        return new MailState(res, listeners, ext, worker);
    }

    private static String firstLineOf(String s) {
        String t = s == null ? "" : s.trim();
        int i = t.indexOf('\n');
        t = i < 0 ? t : t.substring(0, i);
        return t.isEmpty() ? "?" : (t.length() > 300 ? t.substring(0, 300) : t);
    }

    /**
     * What stops the move, comparing the tests after with those before: a failed test, a listening address lost
     * or newly appeared, a Sieve extension gone (the users' rules use it). Empty if everything is as before or
     * better.
     */
    static java.util.List<String> mailStateProblems(MailState before, MailState after) {
        java.util.List<String> p = new ArrayList<>(after.failed());
        for (String k : before.results().keySet())
            if (!after.results().containsKey(k)) p.add(I18n.tr("server.um.dv24move.notRun", Map.of("test", k)));
        Set<String> lost = new TreeSet<>(before.listeners()), added = new TreeSet<>(after.listeners());
        lost.removeAll(after.listeners());
        added.removeAll(before.listeners());
        if (!lost.isEmpty()) p.add(I18n.tr("server.um.dv24move.portsLost", Map.of("list", String.join(", ", lost))));
        if (!added.isEmpty()) p.add(I18n.tr("server.um.dv24move.portsAdded", Map.of("list", String.join(", ", added))));
        if (before.sieve() != null && after.sieve() != null) {
            Set<String> gone = new TreeSet<>(before.sieve());
            gone.removeAll(after.sieve());
            if (!gone.isEmpty()) p.add(I18n.tr("server.um.dv24move.sieveLost", Map.of("list", String.join(" ", gone))));
        }
        // The process that looks up passwords does not go back to root: if it ran as an internal user it stays so.
        String wb = before.workerUser() == null ? "" : before.workerUser(), wa = after.workerUser() == null ? "" : after.workerUser();
        if (!wb.isEmpty() && !"root".equals(wb) && !wb.equals(wa))
            p.add(I18n.tr("server.um.dv24move.workerChanged", Map.of("before", wb, "after", wa.isEmpty() ? "root" : wa)));
        return p;
    }

    /**
     * Before the move to Dovecot 2.4: what is there, what would replace it, whether the configuration is the
     * panel's, whether the tests can be run, and the exact pkg plan to approve. Changes nothing.
     *
     * 2.4 is a separate package (dovecot24-mysql in the latest branch): nothing moves to it by itself. It does not
     * read the 2.3 configurations, so the move changes packages and configuration together, with the mail stopped,
     * and tests the mail before and after; like the migration to MySQL 8.4.
     */
    public static JSONObject dovecot24Preflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean block = false;
        Map<String, String[]> pk = dovecotPackages();
        String[] s23 = pk.get("mail/dovecot"), p23 = pk.get("mail/dovecot-pigeonhole"), s24 = pk.get("mail/dovecot24");
        java.util.List<String> remove = new ArrayList<>();
        java.util.List<String> install = null;
        String label = I18n.tr("server.um.dv24move.cInstalled");
        if (s24 != null) {
            r.put("alreadyDone", true);
            addCheck(checks, "pkg", label, "ok", I18n.tr("server.um.dv24move.already", Map.of("name", s24[0], "v", s24[1])));
        } else if (s23 == null) {
            block = true;
            addCheck(checks, "pkg", label, "block", I18n.tr("server.um.dv24move.none"));
        } else {
            remove.add(s23[0]);
            if (p23 != null) remove.add(p23[0]);
            install = dovecot24Targets(s23[0], p23 == null ? "" : p23[0]);
            java.util.List<String> now = new ArrayList<>();
            now.add(s23[0] + " " + s23[1]);
            if (p23 != null) now.add(p23[0] + " " + p23[1]);
            if (install == null) {
                block = true;
                addCheck(checks, "pkg", label, "block", I18n.tr("server.um.dv24move.flavor", Map.of("list", String.join(", ", now))));
            } else addCheck(checks, "pkg", label, "ok", I18n.tr("server.um.dv24move.now", Map.of("list", String.join(", ", now))));
        }
        r.put("remove", new JSONArray(remove)).put("install", new JSONArray(install == null ? java.util.List.of() : install));
        if (install == null) return r.put("success", true).put("checks", checks).put("canProceed", false).put("blocked", block);

        // 2.4 in the catalog: the quarterly branch does not have it yet.
        java.util.List<String> offered = new ArrayList<>(), missing = new ArrayList<>();
        for (String n : install) {
            String v = sh("pkg rquery -U %v " + n + " 2>/dev/null", 30).trim();
            if (v.isEmpty()) missing.add(n); else offered.add(n + " " + v);
        }
        if (!missing.isEmpty()) {
            block = true;
            addCheck(checks, "target", I18n.tr("server.um.dv24move.cTarget"), "block",
                    I18n.tr("server.um.dv24move.notOffered", Map.of("list", String.join(", ", missing))));
        } else addCheck(checks, "target", I18n.tr("server.um.dv24move.cTarget"), "ok",
                I18n.tr("server.um.dv24move.offered", Map.of("list", String.join(", ", offered))));

        // The configuration is rewritten from scratch: one written by hand would be lost.
        boolean ours = ok("grep -qF" + dovecotSignatureOptions() + " " + DOVECOT_DIR + "/dovecot.conf", 15);
        if (!ours) block = true;
        addCheck(checks, "config", I18n.tr("server.um.dv24move.cConfig"), ours ? "ok" : "block",
                I18n.tr(ours ? "server.um.dv24move.configOurs" : "server.um.dv24move.configNotOurs"));

        // Who else uses the 2.3 packages: the move removes them with -f, and they would be left without them.
        java.util.List<String> users = new ArrayList<>();
        for (String n : remove)
            for (String d : sh("pkg query %rn " + n + " 2>/dev/null", 20).split("\n"))
                if (!d.isBlank() && !remove.contains(d.trim()) && !users.contains(d.trim())) users.add(d.trim());
        if (!users.isEmpty()) block = true;
        addCheck(checks, "dependents", I18n.tr("server.um.dv24move.cDependents"), users.isEmpty() ? "ok" : "block",
                users.isEmpty() ? I18n.tr("server.um.dv24move.noDependents")
                                : I18n.tr("server.um.dv24move.dependents", Map.of("list", String.join(", ", users))));

        boolean running = ok("service dovecot status", 20);
        if (!running) block = true;
        addCheck(checks, "running", I18n.tr("server.um.dv24move.cRunning"), running ? "ok" : "block",
                I18n.tr(running ? "server.um.dv24move.running" : "server.um.dv24move.notRunning"));

        boolean pw = !panelDbPassword().isEmpty();
        if (!pw) block = true;
        addCheck(checks, "dbpass", I18n.tr("server.um.dv24move.cDbPass"), pw ? "ok" : "block",
                I18n.tr(pw ? "server.um.dv24move.dbPass" : "server.um.dv24move.noDbPass"));

        // The tests: what can be tested before and after.
        String mailbox = mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_FIRST_ACTIVE_MAILBOX).trim();
        if (!MailProbes.MAILBOX.matcher(mailbox).matches()) mailbox = "";
        boolean master = dovecotMasterPassword() != null, cert = dovecotCertificatePath() != null;
        r.put("testMailbox", mailbox);
        String tests = mailbox.isEmpty() ? I18n.tr("server.um.dv24move.testsNoMailbox")
                : I18n.tr("server.um.dv24move.tests", Map.of("mailbox", mailbox))
                  + (master && cert ? "" : " " + I18n.tr("server.um.dv24move.testsNoImap"));
        // Also among the things to know before starting: the tests go into a real mailbox (read-only).
        addCheck(checks, "tests", I18n.tr("server.um.dv24move.cTests"), "review", tests);

        addCheck(checks, "services", I18n.tr("server.um.x.servicesInvolved"), "review", I18n.tr("server.um.dv24move.downtime"));

        JSONObject plan = dovecot24Plan(remove, install);
        java.util.List<String> family = new ArrayList<>(remove);
        family.addAll(install);
        if (addPlanChecks(checks, plan, install, family, block)) block = true;
        java.util.List<String> otherMysql = otherMysqlInPlan(plan, PackagePlan.installed().keySet());
        if (!otherMysql.isEmpty()) {
            block = true;
            addCheck(checks, "mysql", I18n.tr("server.um.dv24move.cMysql"), "block",
                    I18n.tr("server.um.dv24move.otherMysql", Map.of("list", String.join(", ", otherMysql))));
        }
        r.put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""));
        return r.put("success", true).put("checks", checks).put("canProceed", !block).put("blocked", block);
    }

    /**
     * The exact plan: remove the 2.3 packages, then install the 2.4 ones, with what they bring along. The
     * dependencies already installed and locked at the version 2.4 asks for are unlocked for pkg, which would
     * otherwise look for others (PackagePlan.planRemoveThenInstall); they stay as they are and are locked again at
     * the end.
     */
    private static JSONObject dovecot24Plan(java.util.List<String> remove, java.util.List<String> install) {
        Set<String> locked = lockedNames();
        StringBuilder deps = new StringBuilder();
        for (String n : install) deps.append(sh("pkg rquery -U '%dn %dv' " + n + " 2>/dev/null", 30)).append('\n');
        java.util.List<String> asTheyAre = dependenciesAsTheyAre(deps.toString(), locked, PackagePlan.versionsOnly(PackagePlan.installed()));
        return judged(PackagePlan.planRemoveThenInstall(remove, install, asTheyAre, locked, UpdateManager::reasonNotToUnlock));
    }

    /**
     * Among the dependencies ("pkg rquery '%dn %dv'", one per line) the ones that are installed, locked, and
     * exactly at the requested version: pkg would use them as they are, if they were not locked. Pure function.
     */
    static java.util.List<String> dependenciesAsTheyAre(String rquery, Set<String> locked, Map<String, String> installed) {
        java.util.List<String> out = new ArrayList<>();
        for (String line : rquery.split("\n")) {
            String[] c = line.trim().split(" ");
            if (c.length == 2 && isValidName(c[0]) && locked.contains(c[0]) && c[1].equals(installed.get(c[0])) && !out.contains(c[0]))
                out.add(c[0]);
        }
        return out;
    }

    /**
     * The MySQL packages the plan would install next to the one that is there ("mysql267-client 26.7.0"): two
     * MySQL clients, and Postfix and Dovecot that could load the wrong one. Empty if there are none, or if there
     * is no MySQL.
     */
    static java.util.List<String> otherMysqlInPlan(JSONObject plan, Set<String> installedNames) {
        java.util.List<String> out = new ArrayList<>();
        boolean anyMysql = installedNames.stream().anyMatch(n -> n.matches("mysql[0-9]+-(client|server)"));
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; anyMysql && c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String n = x.optString("name");
            if ("install".equals(x.optString("type")) && n.matches("mysql[0-9]+-(client|server)") && !installedNames.contains(n))
                out.add(n + " " + x.optString("to"));
        }
        return out;
    }

    /**
     * Only for the tests (Dovecot24MoveE2ETest): extra problems after the tests on 2.4, to make the move roll back
     * on the VM with a real fault. Only whoever holds the process sets it: in the running panel it is always
     * null.
     */
    static volatile java.util.function.Supplier<java.util.List<String>> dovecot24ProblemsForTest;

    /**
     * @param approvedSignature the signature of the plan that whoever presses has read: the job recomputes the plan
     *                          and starts only if it is the same
     */
    public static JSONObject startDovecot24Move(String approvedSignature) {
        if (!validSignature(approvedSignature))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.plan.signatureMissing"));
        String id = "dc24-" + System.currentTimeMillis();
        Job j = new Job(id, "dovecot24_move");
        return startOnTurn(id, j, I18n.tr("server.um.dv24move.job"), "dovecot24-move", () -> runDovecot24Move(j, approvedSignature));
    }

    /**
     * The move to Dovecot 2.4, guided and tested.
     *
     * The mail tests run first, on 2.3: if one already fails now the job stops without touching anything,
     * because afterwards it could not prove anything. Then the copy (configuration and 2.3 packages, rebuilt from
     * the installed ones with pkg create), Dovecot stopped, the packages changed according to the signed plan, the
     * 2.4 configuration written and approved by doveconf, Dovecot started, Dovecot's MySQL user put back
     * (MailDbUsers), and the same tests. If even one fails, or a port changes, or a Sieve extension disappears,
     * 2.3 goes back in place from the copy, and it is tested too. Meanwhile Postfix stays on and keeps the mail in
     * the queue; at the end it delivers it.
     */
    private static void runDovecot24Move(Job job, String approvedSignature) {
        job.status = "running";
        final int TOT = 8;
        java.util.List<String> listed = new ArrayList<>();
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        PlanOutcome outcome = null;
        Map<String, Boolean> servicesBefore = servicesState();
        String backupDir = "";
        java.util.List<String> remove = new ArrayList<>(), install = new ArrayList<>(), pkgFiles = new ArrayList<>();
        boolean dovecotStopped = false, replaced = false;
        String mailbox = null, masterPassword = null, dbUserBefore = "";
        boolean sieve = false;
        MailState before = null;
        JSONObject plan = null;
        Path script = null;
        try {
            job.advance(1, TOT);
            job.write("=== " + I18n.tr("server.um.dv24move.title") + " ===");
            job.write("");
            job.write("[1/" + TOT + "] " + I18n.tr("server.um.dv24move.s1"));
            JSONObject pf = dovecot24Preflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr(pf.optBoolean("alreadyDone", false) ? "server.um.dv24move.alreadyStop" : "server.um.dv24move.blockedStop");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.write("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label") + ": " + c.optString("detail"));
                }
                return;
            }
            remove = jsonArrayToList(pf.optJSONArray("remove"));
            install = jsonArrayToList(pf.optJSONArray("install"));
            job.write("  " + String.join(" + ", remove) + " -> " + String.join(" + ", install));
            plan = pf.optJSONObject("plan");
            String mismatch = approvedPlanMismatch(job, plan, pf.optString("signature", null), approvedSignature);
            if (mismatch != null) {
                job.status = "error";
                job.errorMessage = mismatch;
                return;
            }
            final java.util.List<String> rm0 = java.util.List.copyOf(remove), in0 = java.util.List.copyOf(install);
            java.util.List<String> downloads = planDownloads(plan);
            if (!downloads.isEmpty()) {
                Recheck grown = fetchAndRecheck(job, "pkg fetch -y -U " + String.join(" ", downloads) + " 2>&1", plan,
                        () -> dovecot24Plan(rm0, in0));
                if (grown.stop() != null) {
                    job.status = "error";
                    job.errorMessage = grown.stop();
                    return;
                }
                plan = grown.plan();
            }
            PlanWatch watch = PlanWatch.take(sideEffects);
            String mb = pf.optString("testMailbox", "");
            mailbox = MailProbes.MAILBOX.matcher(mb).matches() ? mb : null;
            masterPassword = dovecotMasterPassword();
            sieve = install.contains("dovecot24-pigeonhole-mysql");
            dbUserBefore = dovecotDbUser();
            job.write("");
            job.write("  " + I18n.tr("server.um.dv24move.before"));
            before = mailTests(job, mailbox, masterPassword, sieve);
            if (!before.failed().isEmpty()) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.dv24move.beforeFailed", Map.of("list", String.join("; ", before.failed())));
                return;
            }

            job.advance(2, TOT);
            job.write("");
            job.write("[2/" + TOT + "] " + I18n.tr("server.um.dv24move.s2"));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date for the copy");
            backupDir = DOVECOT24_BACKUP + "/" + ts;
            if (!ok("mkdir -p -m 700 " + DOVECOT24_BACKUP + " && chmod 700 " + DOVECOT24_BACKUP + " && mkdir -m 700 " + backupDir
                    + " && mkdir -m 700 " + backupDir + "/pkg", 30))
                throw new IllegalStateException("cannot create " + backupDir);
            if (!ok("cp -Rp " + DOVECOT_DIR + " " + backupDir + "/etc", 120) || !ok("test -f " + backupDir + "/etc/dovecot.conf", 15))
                throw new IllegalStateException("the copy of " + DOVECOT_DIR + " did not succeed");
            for (String n : remove) {
                String nv = sh("pkg query %n-%v " + n + " 2>/dev/null", 20).trim();
                String file = backupDir + "/pkg/" + nv + ".pkg";
                if (!nv.matches("[A-Za-z0-9._+-]{1,120}") || runLogged(job, "pkg create -o " + backupDir + "/pkg " + n + " 2>&1", 300) != 0
                        || !ok("test -s " + file, 15))
                    throw new IllegalStateException("pkg create " + n + " did not produce " + file);
                pkgFiles.add(file);
            }
            job.write("    " + I18n.tr("server.um.dv24move.copied", Map.of("dir", backupDir, "n", String.valueOf(pkgFiles.size()))));

            job.advance(3, TOT);
            job.write("");
            job.write("[3/" + TOT + "] " + I18n.tr("server.um.dv24move.s3"));
            ok("service dovecot stop", 60);
            dovecotStopped = true;
            boolean down = false;
            for (int i = 0; i < 30 && !down; i++) {
                down = !ok("service dovecot status", 10);
                if (!down) try { Thread.sleep(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            if (!down) throw new IllegalStateException("Dovecot did not stop");
            job.write("    " + I18n.tr("server.um.dv24move.stopped"));

            job.advance(4, TOT);
            job.write("");
            job.write("[4/" + TOT + "] " + I18n.tr("server.um.x.replacingPkgs"));
            listed = unlockForPlan(job, plan, install);
            int delCode = runLogged(job, "pkg delete -f -y " + String.join(" ", remove) + " 2>&1", 300);
            replaced = true;
            int insCode = delCode != 0 ? -1 : runLogged(job, "pkg install -y -U " + String.join(" ", install) + " 2>&1", 900);
            if (insCode == 4) {
                job.write(I18n.tr("server.um.runGuidedUpdate.10"));
                insCode = runLogged(job, "pkg install -y -U " + String.join(" ", install) + " 2>&1", 900);
            }
            outcome = checkPlanOutcome(job, watch, plan, "Dovecot 2.4 move", true);
            if (delCode != 0) throw new IllegalStateException("pkg delete exited with code " + delCode);
            for (String n : install)
                if (insCode != 0 || !ok("pkg info -e " + n, 20)) throw org.daemoxcp.mail.util.ShownException.of("server.um.dv24move.notInstalled", Map.of("n", n));
            if (outcome.mapsProblem() != null) throw org.daemoxcp.mail.util.ShownException.translated(outcome.mapsProblem());

            job.advance(5, TOT);
            job.write("");
            job.write("[5/" + TOT + "] " + I18n.tr("server.um.dv24move.s5"));
            script = Files.createTempFile("dovecot24-config-", ".sh");
            Files.setPosixFilePermissions(script, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            Files.writeString(script, "#!/bin/sh\nset -e\n" + org.daemoxcp.mail.scripts.DovecotConfig.fromPanelConfig().scriptFragment() + "\n");
            // The password from the ENVIRONMENT, as in the regeneration: not in the text of the script nor on the
            // command line.
            Map<String, String> env = new LinkedHashMap<>();
            env.put("DB_PASS", panelDbPassword());
            if (runLogged(job, "sh " + script, 300, null, env) != 0)
                throw org.daemoxcp.mail.util.ShownException.of("server.um.dv24move.configRefused");

            job.advance(6, TOT);
            job.write("");
            job.write("[6/" + TOT + "] " + I18n.tr("server.um.dv24move.s6"));
            if (!startDovecot(job)) throw org.daemoxcp.mail.util.ShownException.of("server.um.dv24move.notStarted");
            dovecotStopped = false;
            // The written configuration reads with the panel's user: it goes back to Dovecot's own, as after the
            // regeneration (MailDbUsers), before the tests, so that what is tested is what remains.
            MailDbUsers.ensureAtBoot();
            // POP3 as the administrator chose it: the written configuration has only IMAP (Pop3).
            Pop3.ensureAtBoot();
            // And Postfix on the LMTP socket of the written configuration (finding 234), before the tests.
            String lmtp = LmtpSocket.alignPostfix();
            if (!lmtp.isEmpty()) job.write("    " + lmtp);
            // The panel's Sieve rules compiled by the 2.4 Pigeonhole: the 2.3 compiled ones are no longer valid, and
            // Dovecot would recompile them at every message with two errors in the maillog (finding 241).
            SieveBinaries.Result sieveBinaries = SieveBinaries.refreshNow();
            job.write("    " + I18n.tr("server.um.dv24move.sieveBinaries", Map.of("done", String.valueOf(sieveBinaries.recompiled()),
                    "same", String.valueOf(sieveBinaries.unchanged()))));
            String dbUserAfter = dovecotDbUser();
            job.write("    " + I18n.tr("server.um.dv24move.dbUser", Map.of("before", dbUserBefore.isEmpty() ? "?" : dbUserBefore,
                    "after", dbUserAfter.isEmpty() ? "?" : dbUserAfter)));

            job.advance(7, TOT);
            job.write("");
            job.write("[7/" + TOT + "] " + I18n.tr("server.um.dv24move.s7"));
            MailState after = mailTests(job, mailbox, masterPassword, sieve);
            java.util.List<String> problems = mailStateProblems(before, after);
            if (!dbUserBefore.isEmpty() && !dbUserBefore.equals(dbUserAfter))
                problems.add(I18n.tr("server.um.dv24move.dbUserChanged", Map.of("before", dbUserBefore, "after", dbUserAfter)));
            if (!sieveBinaries.failed().isEmpty())
                problems.add(I18n.tr("server.um.dv24move.sieveBinariesFailed", Map.of("n", String.valueOf(sieveBinaries.failed().size()))));
            sideEffects.checkListening(job);
            problems.addAll(sideEffects.problems());
            problems.addAll(planProblems(outcome));
            java.util.function.Supplier<java.util.List<String>> forTest = dovecot24ProblemsForTest;
            if (forTest != null) problems.addAll(forTest.get());
            if (!problems.isEmpty()) throw new IllegalStateException(String.join(" ", problems));
            // The database password in a file nobody reads any more: the copy of the move is enough to go back.
            ok("rm -f " + DOVECOT_DIR + "/dovecot-sql.conf.pre-2.4", 15);
            ok("postqueue -f", 60);
            job.write("    " + I18n.tr("server.um.dv24move.queueFlushed"));

            job.advance(8, TOT);
            job.write("");
            job.write("[8/" + TOT + "] " + I18n.tr("server.um.dv24move.s8"));
            boolean fallen = fallenServices(job, servicesBefore);
            String version = sh("pkg query %v " + install.get(0) + " 2>/dev/null", 20).trim();
            if (fallen) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.dv24move.fallen", Map.of("dir", backupDir));
            } else {
                job.status = "completed";
                job.outcome = I18n.tr("server.um.dv24move.done", Map.of("v", version));
                job.write("");
                job.write(job.outcome);
                job.write(I18n.tr("server.um.dv24move.copyKept", Map.of("dir", backupDir)));
            }
        } catch (Exception e) {
            job.status = "error";
            String why = String.valueOf(e.getMessage());
            job.write("");
            job.write(I18n.tr("server.um.startMtaStsActivation.1", Map.of("message", why)));
            if (replaced) {
                boolean back = dovecot23Back(job, backupDir, pkgFiles, install, plan, mailbox, masterPassword, sieve, before);
                job.errorMessage = I18n.tr(back ? "server.um.dv24move.rolledBack" : "server.um.dv24move.notRolledBack",
                        Map.of("why", why, "dir", backupDir.isEmpty() ? "-" : backupDir));
            } else {
                job.errorMessage = why;
                if (dovecotStopped) {
                    job.write(I18n.tr("server.um.dv24move.restart23"));
                    job.write("    dovecot: " + (startDovecot(job) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26")));
                }
            }
            if (outcome != null && !outcome.outsidePlan().isEmpty()) job.errorMessage += " " + divergenceMessage(outcome.outsidePlan());
        } finally {
            if (script != null) try { Files.deleteIfExists(script); } catch (Exception ignored) {}
            // Every package on the list installed now gets locked: 2.4 if it stayed, 2.3 if it came back.
            if (!listed.isEmpty() && !relockListed(job, listed).isEmpty() && "completed".equals(job.status)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runGuidedUpdate.42");
            }
            job.finish();
        }
    }

    /** Starts Dovecot and waits for it to answer, up to 30 seconds. */
    private static boolean startDovecot(Job job) {
        ok("service dovecot start", 120);
        for (int i = 0; i < 30; i++) {
            if (ok("service dovecot status", 10)) {
                job.write("    dovecot: " + I18n.tr("server.um.x.running"));
                return true;
            }
            try { Thread.sleep(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        return false;
    }

    /**
     * Puts 2.3 back as it was, from the copy of the move: out with the 2.4 packages and what the plan brought only
     * for them, in with the 2.3 ones rebuilt by pkg create, the previous configuration, Dovecot started, and again
     * the tests of before. The 2.4 configuration stays in the copy (etc-2.4-refused), to be read.
     *
     * @return true if 2.3 came back and passes the tests of before
     */
    private static boolean dovecot23Back(Job job, String backupDir, java.util.List<String> pkgFiles, java.util.List<String> install,
                                         JSONObject plan, String mailbox, String masterPassword, boolean sieve, MailState before) {
        job.write("");
        job.write(I18n.tr("server.um.dv24move.backTitle", Map.of("dir", backupDir.isEmpty() ? "-" : backupDir)));
        if (backupDir.isEmpty() || pkgFiles.isEmpty()) {
            job.write("    " + I18n.tr("server.um.dv24move.noCopy"));
            return false;
        }
        try {
            ok("service dovecot stop", 60);
            java.util.List<String> present = new ArrayList<>();
            for (String n : install) if (ok("pkg info -e " + n, 15)) present.add(n);
            if (!present.isEmpty() && runLogged(job, "pkg delete -f -y " + String.join(" ", present) + " 2>&1", 300) != 0)
                return false;
            // The dependencies the plan installed for 2.4 and that nobody uses any more.
            JSONArray changes = plan == null ? null : plan.optJSONArray("changes");
            for (int i = 0; changes != null && i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                String n = c.optString("name");
                if (!"install".equals(c.optString("type")) || install.contains(n) || !isValidName(n) || !ok("pkg info -e " + n, 15)) continue;
                if (sh("pkg query %rn " + n + " 2>/dev/null", 20).isBlank()) runLogged(job, "pkg delete -y " + n + " 2>&1", 300);
            }
            for (String f : pkgFiles)
                if (runLogged(job, "pkg add " + f + " 2>&1", 300) != 0) return false;
            if (!ok("rm -rf " + backupDir + "/etc-2.4-refused && mv " + DOVECOT_DIR + " " + backupDir + "/etc-2.4-refused && cp -Rp "
                    + backupDir + "/etc " + DOVECOT_DIR, 120)) return false;
            job.write("    " + I18n.tr("server.um.dv24move.configBack"));
            if (!startDovecot(job)) return false;
            // The panel's rules compiled again by 2.3, if 2.4 had already recompiled them (finding 241).
            SieveBinaries.Result sieveBinaries = SieveBinaries.refreshNow();
            job.write("    " + I18n.tr("server.um.dv24move.sieveBinaries", Map.of("done", String.valueOf(sieveBinaries.recompiled()),
                    "same", String.valueOf(sieveBinaries.unchanged()))));
            job.write("    " + I18n.tr("server.um.dv24move.testsAgain"));
            MailState again = mailTests(job, mailbox, masterPassword, sieve);
            ok("postqueue -f", 60);
            java.util.List<String> p = before == null ? again.failed() : mailStateProblems(before, again);
            if (!p.isEmpty()) job.write("    " + String.join(" ", p));
            return p.isEmpty();
        } catch (Exception e) {
            job.write("    " + e.getMessage());
            return false;
        }
    }

    // ===================== guided Roundcube update =====================

    private static final String RC_DIR = "/usr/local/www/roundcube";

    /**
     * Credentials of the webmail database, read from config.inc.php.
     *
     * They are not guessed: the authoritative ones are what Roundcube really uses, that is the DSN
     * in its configuration -- roundcube, its own user, after RoundcubeDbUser; the panel's one
     * on servers where the migration has not succeeded yet. The reading is done in Java
     * and not with a chain of grep and sed: nothing to protect in a shell, and the password
     * never goes through a command line. It is the same as RoundcubeDbUser.activeDsn (commented
     * lines excluded, the last assignment wins): the database copy and the migration
     * must see the same connection.
     */
    static JSONObject dsnRoundcube() {
        JSONObject r = new JSONObject().put("ok", false);
        try {
            java.nio.file.Path f = Paths.get(RC_DIR + "/config/config.inc.php");
            if (!Files.exists(f)) return r.put("error", I18n.tr("server.um.dsnRoundcube.1", java.util.Map.of("rcDir", String.valueOf(RC_DIR))));
            RoundcubeDbUser.Dsn d = RoundcubeDbUser.activeDsn(Files.readString(f, StandardCharsets.UTF_8));
            if (d == null) return r.put("error", I18n.tr("server.um.dsnRoundcube.2"));
            return new JSONObject().put("ok", true).put("driver", d.driver()).put("user", d.user())
                    .put("pass", d.password()).put("host", d.host()).put("db", d.db());
        } catch (Exception e) {
            return r.put("error", org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e));
        }
    }

    /** A catalog query on the webmail database, with the credentials Roundcube itself uses (JDBC). */
    private static String rcQuery(String sql, Object... params) {
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok")) return "";
        String u = d.getString("user"), h = d.getString("host"), db = d.getString("db");
        if (!u.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !h.matches("[A-Za-z0-9._-]{1,128}(:[0-9]{1,5})?")) return "";
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        String port = h.contains(":") ? h.substring(h.indexOf(':') + 1) : "3306";
        return jdbcRows(host, port, db, u, d.getString("pass"), sql, params);
    }

    /**
     * Preliminary checks for the Roundcube major version jump. Read-only.
     *
     * The delicate point is not the package but the database SCHEMA: 1.7 changes it, and
     * until bin/updatedb.sh is run the webmail does not work. And the schema upgrade
     * cannot be undone, so a copy of the database taken beforehand is needed.
     */
    /**
     * The "root ...roundcube" lines in the nginx configurations, with the exact position.
     *
     * From 1.7 Roundcube requires the web server to point to the public_html subfolder:
     * all the rest of the installation stops being servable, and that is intended -- it is a
     * protection. But on this server nginx points to the root of the application (the panel
     * itself writes it that way in five places), so after the upgrade the webmail
     * would stop working. It must be found BEFORE, not discovered after.
     */
    private static JSONArray nginxRoundcubeRoots() {
        JSONArray outside = new JSONArray();
        String out = sh("grep -rn '^[[:space:]]*root[[:space:]].*roundcube' "
                + "/usr/local/etc/nginx/ 2>/dev/null", 60);
        for (String line : out.split("\n")) {
            Matcher m = Pattern.compile("^([^:]+):([0-9]+):\\s*root\\s+([^;]+);").matcher(line.trim());
            if (!m.find()) continue;
            String path = m.group(3).trim();
            outside.put(new JSONObject().put("file", m.group(1)).put("line", Integer.parseInt(m.group(2)))
                    .put("root", path)
                    .put("already", path.endsWith("/public_html") || path.endsWith("/public_html/")));
        }
        return outside;
    }

    /** True if the version is 1.7 or later, that is if it requires the public_html root. */
    static boolean wantsPublicHtml(String version) {
        Matcher m = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(version == null ? "" : version);
        if (!m.find()) return false;
        int ma = Integer.parseInt(m.group(1)), mi = Integer.parseInt(m.group(2));
        return ma > 1 || (ma == 1 && mi >= 7);
    }

    public static JSONObject roundcubePreflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean block = false;

        String pkg = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20);
        String ver = pkg.isEmpty() ? "" : sh("pkg query %v " + pkg, 20);
        String available = pkg.isEmpty() ? "" : sh("pkg rquery -U %v " + pkg, 30);
        r.put("pkg", pkg).put("current", ver).put("available", available);
        if (pkg.isEmpty()) {
            addCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "block", I18n.tr("server.um.roundcubePreflight.2"));
            block = true;
        } else if (available.isEmpty() || available.equals(ver)) {
            // It is not an obstacle to solve: there is nothing to do. Calling it a "block"
            // and then writing "resolve the red lines" sets the user looking for a fault that
            // does not exist -- and it is the opposite of what the line means to say.
            addCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "ok",
                    available.isEmpty()
                        ? I18n.tr("server.um.roundcubePreflight.3", java.util.Map.of("pkg", String.valueOf(pkg), "ver", String.valueOf(ver)))
                        : I18n.tr("server.um.x.jvLatest", java.util.Map.of("pkg", String.valueOf(pkg), "cur", String.valueOf(ver))));
            r.put("already", !available.isEmpty()).put("unknown", available.isEmpty());
            block = true;
        } else {
            addCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "ok", pkg + " " + ver + " -> " + available);
        }

        // The PHP family required by the new version must be the installed one.
        String phpInst = sh("pkg query %n 2>/dev/null | grep -E '^php[0-9]+$' | head -1", 20);
        Matcher mp = Pattern.compile("roundcube-php([0-9]+)").matcher(pkg);
        String phpRc = mp.find() ? "php" + mp.group(1) : "";
        boolean phpOk = phpRc.isEmpty() || phpRc.equals(phpInst);
        addCheck(checks, "php", I18n.tr("server.um.roundcubePreflight.4"), phpOk ? "ok" : "block",
                phpOk ? I18n.tr("server.um.roundcubePreflight.5", java.util.Map.of("p", String.valueOf((phpRc.isEmpty() ? phpInst : phpRc))))
                      : I18n.tr("server.um.roundcubePreflight.6", java.util.Map.of("phpRc", String.valueOf(phpRc), "phpInst", String.valueOf(phpInst))));
        if (!phpOk) block = true;

        // The script that upgrades the schema: without it, the step cannot be completed.
        boolean updatedb = ok("test -x " + RC_DIR + "/bin/updatedb.sh", 15)
                        || ok("test -f " + RC_DIR + "/bin/updatedb.sh", 15);
        addCheck(checks, "updatedb", I18n.tr("server.um.roundcubePreflight.7"), updatedb ? "ok" : "block",
                updatedb ? I18n.tr("server.um.x.updatedbPresent", java.util.Map.of("file", String.valueOf(RC_DIR + "/bin/updatedb.sh")))
                         : I18n.tr("server.um.roundcubePreflight.8", java.util.Map.of("rcDir", String.valueOf(RC_DIR))));
        if (!updatedb) block = true;

        // Credentials and state of the database, read from Roundcube's configuration.
        JSONObject dsn = dsnRoundcube();
        long tables = 0;
        if (!dsn.optBoolean("ok")) {
            addCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "block",
                    I18n.tr("server.um.x.rcNoCreds", java.util.Map.of("error", String.valueOf(dsn.optString("error", "")))));
            block = true;
        } else {
            tables = number(rcQuery(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_SCHEMA_TABLES, dsn.getString("db")));
            r.put("db", dsn.getString("db")).put("dbUser", dsn.getString("user")).put("tables", tables);
            if (tables == 0) {
                addCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "block",
                        I18n.tr("server.um.x.rcDbNoAnswer", java.util.Map.of("db", String.valueOf(dsn.getString("db")))));
                block = true;
            } else {
                addCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "ok",
                        I18n.tr("server.um.x.rcDbOk", java.util.Map.of("db", String.valueOf(dsn.getString("db")), "user", String.valueOf(dsn.getString("user")), "tables", String.valueOf(tables))));
            }
        }

        // A way back is not announced: it is tested, now, for real.
        JSONObject test = testCopy();
        String dbName = dsn.optBoolean("ok") ? dsn.getString("db") : "roundcubemail";
        if (!test.optBoolean("ok")) {
            String inherited = inheritedOptions();
            String gtid = gtidState();
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "block",
                    I18n.tr("server.um.x.rcCopyFails", java.util.Map.of("db", String.valueOf(dbName), "error", String.valueOf(test.optString("error"))))
                    + (inherited.isEmpty() ? ""
                       : "  ||  " + I18n.tr("server.um.x.rcDumpOpts", java.util.Map.of("o", String.valueOf(inherited))))
                    + "  ||  " + (gtid.isEmpty() ? I18n.tr("server.um.x.gtidUnreadable")
                       : I18n.tr("server.um.x.serverState", java.util.Map.of("s", String.valueOf(gtid)))));
            block = true;
        } else if ("server.um.dumpMode.root".equals(test.optString("mode"))) {
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "wait",
                    I18n.tr("server.um.x.rcCopyRoot", java.util.Map.of("db", String.valueOf(dbName), "history", String.valueOf(test.optString("history")), "gtid", String.valueOf(gtidState()))));
        } else if (!"server.um.dumpMode.full".equals(test.optString("mode"))) {
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "wait",
                    I18n.tr("server.um.x.rcCopyReduced", java.util.Map.of("db", String.valueOf(dbName), "mode", String.valueOf(I18n.tr(test.getString("mode"))), "history", String.valueOf(test.optString("history")))));
        } else {
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "ok",
                    I18n.tr("server.um.roundcubePreflight.11", java.util.Map.of("dbName", String.valueOf(dbName))));
        }

        // It asks nothing of the reader: it says what the procedure does. Under the yellow "CHECK"
        // label it looked like something still to do, among lines that were all green.
        addCheck(checks, "opcache", I18n.tr("server.um.roundcubePreflight.12"), "note",
                I18n.tr("server.um.roundcubePreflight.13"));

        // nginx root: from 1.7 it must point to public_html, otherwise the webmail
        // stops working right after the upgrade.
        JSONArray roots = nginxRoundcubeRoots();
        // The right question is not "am I moving to 1.7?" but "does the version I will have require
        // public_html, and does nginx point to it?". A server ALREADY on 1.7 with the old root has
        // the webmail already broken now: asking only about the move I would not notice it, and
        // I would say "must not be touched" precisely in the case where it must be touched at once.
        java.util.List<String> toMove = new ArrayList<>();
        for (int i = 0; i < roots.length(); i++) {
            JSONObject x = roots.getJSONObject(i);
            if (!x.getBoolean("already"))
                toMove.add(x.getString("file") + ":" + x.getInt("line") + " -> " + x.getString("root") + "/public_html");
        }
        boolean demands = wantsPublicHtml(available);
        boolean already17 = wantsPublicHtml(ver);
        boolean serve = demands && !toMove.isEmpty();
        r.put("roots", roots).put("rootChange", serve);
        if (!demands) {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "ok",
                    I18n.tr("server.um.roundcubePreflight.15", java.util.Map.of("available", String.valueOf(available))));
        } else if (roots.length() == 0) {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "block",
                    I18n.tr("server.um.roundcubePreflight.16", java.util.Map.of("available", String.valueOf(available))));
            block = true;
        } else if (toMove.isEmpty()) {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "ok",
                    I18n.tr("server.um.roundcubePreflight.17"));
        } else {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "wait",
                    (already17
                     ? I18n.tr("server.um.roundcubePreflight.18", java.util.Map.of("ver", String.valueOf(ver)))
                     : I18n.tr("server.um.roundcubePreflight.19", java.util.Map.of("available", String.valueOf(available))))
                    + I18n.tr("server.um.x.rcRootFix", java.util.Map.of("n", String.valueOf(toMove.size()), "lines", String.valueOf(String.join(" ; ", toMove)))));
        }

        // The EXACT plan, as in the guided update: what pkg would do upgrading the
        // webmail, computed on a copy of its database with the same locks removed. It is
        // computed only if there really is an update: otherwise there is nothing to sign.
        if (!pkg.isEmpty() && !available.isEmpty() && !available.equals(ver)) {
            JSONObject plan = roundcubePlan(pkg);
            if (addPlanChecks(checks, plan, java.util.List.of(pkg), java.util.List.of(pkg), block)) block = true;
            r.put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""));
        }

        r.put("success", true).put("checks", checks).put("canProceed", !block).put("blocked", block);
        return r;
    }

    /** The exact plan to upgrade the webmail: the same computation as the guided one. */
    private static JSONObject roundcubePlan(String pkg) {
        return judged(PackagePlan.planFor(java.util.List.of(pkg), lockedNames(),
                UpdateManager::reasonNotToUnlock, UpdateManager::installedFamilyTwin));
    }

    /**
     * Moves the nginx root to public_html, as Roundcube requires from 1.7.
     *
     * Line-by-line rewriting and atomic rewrite of the file: no sed, which on BSD
     * behaves differently from what one is used to and has already written a literal "n" in
     * place of a line break in this very project.
     */
    private static String moveNginxRoot(Job job, String backupDir) {
        JSONArray roots = nginxRoundcubeRoots();
        java.util.List<String> touched = new ArrayList<>();
        try {
            for (int i = 0; i < roots.length(); i++) {
                JSONObject x = roots.getJSONObject(i);
                if (x.getBoolean("already")) continue;
                String file = x.getString("file"), root = x.getString("root");
                if (!ok("test -f " + file, 10)) continue;
                // If public_html is not there, this build does not use it: it is not a fault,
                // and declaring it one would fail a successful upgrade -- which is the way
                // to get rolled back for no reason. The judge remains the final test: if
                // the webmail does not answer, that test says so.
                if (!ok("test -d " + root + "/public_html", 10)) {
                    job.write(I18n.tr("server.um.moveNginxRoot.1", java.util.Map.of("root", String.valueOf(root))));
                    job.write(I18n.tr("server.um.moveNginxRoot.2"));
                    return "unneeded";
                }
                String name = file.replaceAll(".*/", "");
                ok("cp -p " + file + " " + backupDir + "/nginx-" + name, 30);
                java.util.List<String> lines = Files.readAllLines(Paths.get(file));
                int n = x.getInt("line") - 1;
                if (n < 0 || n >= lines.size()) { job.write(I18n.tr("server.um.moveNginxRoot.3", java.util.Map.of("file", String.valueOf(file), "p", String.valueOf((n + 1))))); return "failed"; }
                String old = lines.get(n);
                if (!old.contains(root)) { job.write("    " + I18n.tr("server.um.x.lineNoLonger", java.util.Map.of("file", String.valueOf(file), "line", String.valueOf((n + 1)), "root", String.valueOf(root)))); return "failed"; }
                // Pointing to a folder that exists is not enough: there must be something to serve.
                if (!ok("test -f " + root + "/public_html/index.php", 10)) {
                    job.write(I18n.tr("server.um.moveNginxRoot.4", java.util.Map.of("root", String.valueOf(root))));
                    job.write(I18n.tr("server.um.moveNginxRoot.5"));
                    return "failed";
                }
                lines.set(n, old.replace(root + ";", root + "/public_html;"));
                Files.write(Paths.get(file), lines);
                touched.add(file);
                job.write("    " + file + ":" + (n + 1) + "  root -> " + root + "/public_html");
            }
            if (touched.isEmpty()) { job.write(I18n.tr("server.um.moveNginxRoot.6")); return "unneeded"; }

            // Before reloading: does nginx accept this configuration?
            String test = sh("nginx -t 2>&1", 60);
            boolean good = test.toLowerCase().contains("syntax is ok") && test.toLowerCase().contains("test is successful");
            if (!good) {
                for (String l : test.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
                for (String f : touched) {
                    String name = f.replaceAll(".*/", "");
                    ok("cp -p " + backupDir + "/nginx-" + name + " " + f, 30);
                }
                job.write(I18n.tr("server.um.moveNginxRoot.7"));
                return "failed";
            }
            job.write(I18n.tr("server.um.moveNginxRoot.8"));
            String svc = realServiceName("nginx");
            if (svc == null) { job.write(I18n.tr("server.um.moveNginxRoot.9")); return "failed"; }
            boolean reloadOutcome = ok("service " + svc + " reload", 60);
            job.write("    " + (reloadOutcome ? I18n.tr("server.um.x.reloadedYes") : I18n.tr("server.um.x.reloadedNo")));
            return reloadOutcome ? "done" : "failed";
        } catch (Exception e) {
            job.write(I18n.tr("server.um.moveNginxRoot.10", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            return "failed";
        }
    }

    /** Copy of the webmail database. The final marker of mysqldump proves it is complete. */
    /**
     * Copy of the webmail database, with the reason for the failure when it fails.
     *
     * The previous version sent stderr to /dev/null and returned true/false: when it did not
     * succeed, the panel only knew that it had not succeeded -- that is, exactly nothing
     * useful. The mysqldump error IS the diagnosis; throwing it away was the worst defect here.
     *
     * Two options deserve an explanation, because they look like details and they are not:
     *  - --no-tablespaces: without it, the MySQL 8 mysqldump queries the tablespace information
     *    and to do so requires the PROCESS privilege, which an application user does not have and
     *    must not have. It is the most common cause of an "Access denied" that has nothing to do
     *    with the tables to copy.
     *  - --routines and --triggers require still more privileges (SHOW_ROUTINE, TRIGGER). On the
     *    Roundcube schema there is none of that, so if the first attempt fails there it is
     *    retried without them -- and that is WRITTEN DOWN, instead of delivering a poorer copy
     *    than the one promised while pretending nothing happened.
     */
    /**
     * The ways of copying, from the most complete to the least demanding. One list for both the test and the
     * real copy.
     */
    /**
     * The ways of copying, from the least privileged to the most powerful. Third column: with which user.
     *
     * --no-tablespaces: without it, the MySQL 8 mysqldump reads the tablespace information and to
     *   do so requires PROCESS, which an application user does not have and must not have.
     * --set-gtid-purged=OFF: if the server has GTIDs enabled, mysqldump in AUTO mode (the
     *   default) wants to record which GTIDs are already applied, and to get them consistent it
     *   runs FLUSH TABLES + FLUSH TABLES WITH READ LOCK, which require RELOAD. No options file
     *   is involved: mysqldump decides it by looking at the server. For a copy to be put back
     *   on the same server that information is not needed, so it is turned off.
     * --skip-lock-all-tables --skip-flush-logs: the other two roads that lead to the same
     *   FLUSH. Turning them off explicitly is the only way to know what is being run.
     * --no-defaults: ignores every options file. It must come first on the command line.
     * root on the socket: last resort, and it always works because root has all the privileges.
     *   It is last on purpose: a copy is made with the minimum necessary, not the maximum possible.
     */
    private static final String[][] COPY_MODES = {
        {"--single-transaction --no-tablespaces --skip-lock-all-tables --skip-flush-logs "
         + "--set-gtid-purged=OFF --routines --triggers", "server.um.dumpMode.full", "app"},
        {"--single-transaction --no-tablespaces --skip-lock-all-tables --skip-flush-logs "
         + "--set-gtid-purged=OFF", "server.um.dumpMode.noRoutines", "app"},
        {"--no-defaults --single-transaction --no-tablespaces --skip-lock-all-tables "
         + "--skip-flush-logs --set-gtid-purged=OFF", "server.um.dumpMode.noDefaults", "app"},
        {"--single-transaction --no-tablespaces --set-gtid-purged=OFF --routines --triggers",
         "server.um.dumpMode.root", "root"},
    };

    /**
     * Can the panel get into MySQL as root through the unix socket?
     *
     * It is tested, not presumed: a trivial query is run and we look at whether it answers. Presuming
     * it would mean offering as a last resort a road that is not there, and finding that out at the
     * moment it is the only one left.
     */
    private static boolean mysqlRootAvailable() {
        return "1".equals(mysqlRootOut(org.daemoxcp.mail.database.SqlCatalog.MYSQL_ROOT_PING).trim());
    }

    /** The connection part of the line, according to the user chosen by the mode. */
    private static String copyConnection(String who, JSONObject dsn) {
        String h = dsn.getString("host");
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        return "root".equals(who)
                ? "-u root " + dsn.getString("db")                       // unix socket, no password
                : "-u " + dsn.getString("user") + " -h " + host + " " + dsn.getString("db");
    }

    /** Why mysqldump does that FLUSH: we look at the server, we do not deduce it. */
    private static String gtidState() {
        String r = mysqlRootOut(org.daemoxcp.mail.database.SqlCatalog.UM_GTID_STATE);
        return r == null ? "" : r.trim();
    }

    /**
     * Where the options I did not ask for come from.
     *
     * "--print-defaults" prints the command line mysqldump really builds for itself, options
     * from the configuration files included. It is needed because an error on a FLUSH TABLES that
     * nobody asked for is incomprehensible until you see who asked for it: and at that point it
     * stops being a mystery and becomes a line in a file.
     */
    private static String inheritedOptions() {
        String o = sh("mysqldump --print-defaults 2>&1 | tail -2", 30).replace("\n", " ").trim();
        return o.isEmpty() ? "" : o;
    }

    /**
     * Tests the copy BEFORE it is needed, without the data.
     *
     * A way back that has never been traveled is not a way back: it is a hope.
     * Here a mysqldump --no-data is really run, which takes an instant and tests
     * exactly what matters -- that the command is there, that the credentials get in, that the
     * privileges are enough and that the file reaches the end. If this does not pass, there is no
     * point starting: that is what happened on 2026-08-31, discovered at step 2 instead of here.
     */
    private static JSONObject testCopy() {
        String tmp = "/var/db/daemoxcp-mail/test-dump.sql";
        ok("mkdir -p /var/db/daemoxcp-mail", 20);
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok"))
            return new JSONObject().put("ok", false)
                    .put("error", I18n.tr("server.um.x.credsUnreadable", java.util.Map.of("reason", String.valueOf(d.optString("error", I18n.tr("server.um.x.reasonUnknown"))))));
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return new JSONObject().put("ok", false)
                    .put("error", I18n.tr("server.um.testCopy.1"));
        StringBuilder history = new StringBuilder();
        try {
            for (String[] m : COPY_MODES) {
                if ("root".equals(m[2]) && !mysqlRootAvailable()) {
                    history.append("[").append(I18n.tr(m[1])).append("] ").append(I18n.tr("server.um.x.notTriedRoot")).append("  ");
                    continue;
                }
                JSONObject e = rcDumpOneAttempt(m[0] + " --no-data",
                        copyConnection(m[2], d), "root".equals(m[2]) ? null : d.getString("pass"), tmp);
                if (e.optBoolean("ok"))
                    return new JSONObject().put("ok", true).put("mode", m[1])
                            .put("history", history.toString().trim());
                history.append("[").append(I18n.tr(m[1])).append("] ").append(e.optString("error")).append("  ");
            }
            return new JSONObject().put("ok", false).put("error", history.toString().trim());
        } finally {
            ok("rm -f " + tmp + " " + tmp + ".err", 20);
        }
    }

    private static JSONObject rcDump(String destination) {
        JSONObject r = new JSONObject().put("ok", false);
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok"))
            return r.put("error", I18n.tr("server.um.x.rcCredsUnreadable", java.util.Map.of("reason", String.valueOf(d.optString("error", I18n.tr("server.um.x.reasonUnknown"))))));
        String u = d.getString("user"), db = d.getString("db");
        String h = d.getString("host");
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        if (!u.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !host.matches("[A-Za-z0-9._-]{1,128}"))
            return r.put("error", I18n.tr("server.um.rcDump.1", java.util.Map.of("u", String.valueOf(u), "host", String.valueOf(host), "db", String.valueOf(db))));
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return r.put("error", I18n.tr("server.um.testCopy.1"));

        StringBuilder history = new StringBuilder();
        for (String[] t : COPY_MODES) {
            if ("root".equals(t[2]) && !mysqlRootAvailable()) {
                history.append("[").append(I18n.tr(t[1])).append("] ").append(I18n.tr("server.um.x.notTriedNoRoot")).append("  ");
                continue;
            }
            JSONObject e = rcDumpOneAttempt(t[0], copyConnection(t[2], d),
                    "root".equals(t[2]) ? null : d.getString("pass"), destination);
            if (e.optBoolean("ok")) {
                r.put("ok", true).put("mode", t[1]);
                if (!t[1].equals("server.um.dumpMode.full")) r.put("reduced", history.toString().trim());
                return r;
            }
            history.append("[").append(I18n.tr(t[1])).append("] ").append(e.optString("error")).append("  ");
        }
        return r.put("error", history.toString().trim());
    }

    private static JSONObject rcDumpOneAttempt(String options, String connection,
                                                String pass, String dest) {
        JSONObject r = new JSONObject().put("ok", false);
        String err = dest + ".err";
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c",
                    "mysqldump " + options + " " + connection + " > " + dest + " 2> " + err);
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            // The password is in the environment and not on the command line: that way it does not show in ps.
            // For the attempt as root there is no password: it gets in through the unix socket.
            if (pass != null && !pass.isEmpty()) pb.environment().put("MYSQL_PWD", pass);
            Process pr = pb.start();
            if (!pr.waitFor(1800, java.util.concurrent.TimeUnit.SECONDS)) {
                pr.destroyForcibly();
                return r.put("error", I18n.tr("server.um.rcDumpOneAttempt.1"));
            }
            String message = sh("cat " + err + " 2>/dev/null", 30).replace("\n", " ").trim();
            if (pr.exitValue() != 0)
                return r.put("error", message.isEmpty()
                        ? I18n.tr("server.um.x.exitNoMsg", java.util.Map.of("c", String.valueOf(pr.exitValue())))
                        : I18n.tr("server.um.x.exitMsg", java.util.Map.of("c", String.valueOf(pr.exitValue()), "m", String.valueOf(message))));
            // mysqldump ends with "Dump completed": without that line the file is truncated,
            // and a truncated file that looks like a backup is worse than no backup.
            if (!ok("tail -3 " + dest + " | grep -q 'Dump completed'", 60))
                return r.put("error", I18n.tr("server.um.x.dumpTruncated")
                        + (message.isEmpty() ? "" : " (" + message + ")"));
            ok("rm -f " + err, 15);
            return r.put("ok", true);
        } catch (Exception e) {
            return r.put("error", org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e));
        }
    }

    /**
     * Why the webmail does not answer. Read-only.
     *
     * A 403 is not guessed: nginx writes the exact reason in its error log, and the two
     * possible reasons lead to opposite remedies -- "Permission denied" is a problem of
     * permissions on the file, "directory index of ... is forbidden" means that nginx finds
     * no index file to serve. Confusing them means fixing the wrong thing.
     */
    /**
     * Queries the webmail ON THE ORIGIN, not through whatever stands in front of it.
     *
     * On 2026-08-31 the final test failed a successful upgrade because it asked port
     * 443 while nginx listens on 8443: Cloudflare answered, with a 403 of its own, and nothing
     * appeared in the nginx log because the request had never reached the server.
     * Here the port is read from the real server block, and the name is resolved to 127.0.0.1
     * to bypass whatever stands in front. If despite everything a CDN answers, that is said
     * instead of mistaking its answer for the server's.
     */
    private static JSONObject testWebmailOrigin() {
        JSONObject r = new JSONObject().put("ok", false);
        JSONArray roots = nginxRoundcubeRoots();
        if (roots.length() == 0) return r.put("error", I18n.tr("server.um.testWebmailOrigin.1"));
        String file = roots.getJSONObject(0).getString("file");
        int line = roots.getJSONObject(0).getInt("line");
        // listen and server_name are in the same block, a few lines above the root.
        int from = Math.max(1, line - 10);
        String head = sh("sed -n '" + from + "," + line + "p' " + file + " 2>/dev/null", 30);
        String port = "", name = "";
        for (String l : head.split("\n")) {
            Matcher mp = Pattern.compile("^\\s*listen\\s+([0-9]{1,5})\\b").matcher(l);
            if (mp.find()) port = mp.group(1);
            Matcher mn = Pattern.compile("^\\s*server_name\\s+([A-Za-z0-9._-]+)\\s*;").matcher(l);
            if (mn.find() && !"_".equals(mn.group(1))) name = mn.group(1);
        }
        if (port.isEmpty()) return r.put("error", I18n.tr("server.um.testWebmailOrigin.2"));
        if (name.isEmpty()) {
            try { name = org.daemoxcp.mail.Main.dbManager.getRoundcubeDomain(); } catch (Exception ignored) {}
        }
        if (name == null || !name.matches("[A-Za-z0-9._-]{1,255}"))
            return r.put("error", I18n.tr("server.um.testWebmailOrigin.3"));
        // --resolve sets right both the name in the Host header and the one in TLS,
        // but sends the request to the local address: it is the way to talk to the server and nothing else.
        String url = "https://" + name + ":" + port + "/";
        String out = sh("curl -sk -m 20 -D - -o /dev/null --resolve " + name + ":" + port
                + ":127.0.0.1 " + url + " 2>&1", 60);
        Matcher mc = Pattern.compile("HTTP/[0-9.]+\\s+([0-9]{3})").matcher(out);
        String code = mc.find() ? mc.group(1) : "";
        boolean cdn = out.toLowerCase().contains("cf-ray") || out.toLowerCase().contains("server: cloudflare");
        return r.put("ok", code.startsWith("2") || code.startsWith("3"))
                .put("code", code.isEmpty() ? I18n.tr("server.um.testWebmailOrigin.4") : code)
                .put("url", url).put("viaCdn", cdn).put("headers", out.trim());
    }

    /**
     * What PHP REALLY receives when the request goes through nginx.
     *
     * It is the last unknown left: static.php resolves the file with
     * realpath(INSTALL_PATH . PATH_INFO), the file is there, the permissions are there, and it
     * answers 404 anyway. So either PATH_INFO does not arrive as I think, or it arrives empty --
     * and "empty" is not the same as "absent", because the PHP ?? operator does not fall back on
     * an empty string and static.php would end up with a null path.
     *
     * A probe with an unpredictable name is written, it gets a single request and it is deleted
     * at once, even if something goes wrong. It prints only the six variables that are needed,
     * not the whole environment.
     */
    public static JSONObject probePathInfo() {
        String name = "rc-probe-" + Long.toHexString(System.nanoTime()) + ".php";
        String file = RC_DIR + "/public_html/" + name;
        try {
            Files.writeString(Paths.get(file),
                "<?php header('Content-Type: text/plain');\n"
              + "foreach (['PATH_INFO','PATH_TRANSLATED','ORIG_PATH_INFO','SCRIPT_FILENAME',\n"
              + "          'SCRIPT_NAME','REQUEST_URI'] as $k) {\n"
              + "    echo $k, ' = ', array_key_exists($k, $_SERVER)\n"
              + "        ? '[' . $_SERVER[$k] . ']' : '(not set)', \"\\n\";\n"
              + "}\n"
              + "echo 'cgi.fix_pathinfo = ', ini_get('cgi.fix_pathinfo'), \"\\n\";\n");
            ok("chmod 644 " + file, 15);
            JSONObject pw = testWebmailOrigin();
            String url = pw.optString("url", "");
            if (url.isEmpty()) return new JSONObject().put("ok", false).put("error", I18n.tr("server.um.probePathInfo.2"));
            String n = url.replaceAll("^https://", "").replaceAll(":.*$", "");
            String port = url.replaceAll(".*:", "").replaceAll("/.*$", "");
            String res = "--resolve " + n + ":" + port + ":127.0.0.1 ";
            String u = "https://" + n + ":" + port + "/" + name + "/skins/elastic/deps/bootstrap.min.css";
            String out = sh("curl -sk -m 20 " + res + "'" + u + "' 2>&1 | head -c 1200", 60);
            return new JSONObject().put("ok", true).put("url", u).put("output", out.trim());
        } catch (Exception e) {
            return new JSONObject().put("ok", false).put("error", org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e));
        } finally {
            // The probe disappears in any case: no PHP file must remain in the web root.
            ok("rm -f " + file, 20);
        }
    }

    /**
     * An output CSS is 160 KB of text: printing it in full hides the answer instead of
     * showing it. Here we say what came out, we do not pour it out.
     */
    private static String summarizeOutput(String out) {
        if (out == null) return I18n.tr("server.um.x.nothing");
        String t = out.trim();
        if (t.isEmpty()) return I18n.tr("server.um.summarizeOutput.1");
        String first = t.length() > 200 ? t.substring(0, 200) : t;
        boolean looksLikeCss = t.contains("{") && (t.contains(";") || t.contains("}"));
        boolean looksLikeError = t.toLowerCase().contains("not found") || t.toLowerCase().contains("404")
                || t.toLowerCase().contains("fatal") || t.toLowerCase().contains("warning");
        return (looksLikeError ? I18n.tr("server.um.summarizeOutput.2") : looksLikeCss ? I18n.tr("server.um.summarizeOutput.3") : I18n.tr("server.um.x.output"))
                + " " + I18n.tr("server.um.x.charsPlus", java.util.Map.of("n", String.valueOf(t.length()))) + "\n" + first.replace("\n", " ");
    }

    /**
     * Really downloads a stylesheet and looks at what it is like.
     *
     * It is the only test that tells "the webmail answers" apart from "the webmail shows": in 1.7
     * the assets go through static.php with the path INSIDE the URI, and if nginx does not notice
     * every CSS comes back as an HTML page -- the page opens, and there is nothing.
     */
    private static JSONObject testCssAsset(String name, String port) {
        JSONObject r = new JSONObject().put("ok", false);
        String base = "https://" + name + ":" + port;
        String res = "--resolve " + name + ":" + port + ":127.0.0.1 ";
        String html = sh("curl -sk -m 20 " + res + base + "/ 2>/dev/null | head -80", 60);
        Matcher m = Pattern.compile("href=\"([^\"]*\\.css[^\"]*)\"").matcher(html);
        if (!m.find()) return r.put("error", I18n.tr("server.um.testCssAsset.1"));
        String css = m.group(1).replace("&amp;", "&");
        // The link is relative ("static.php/skins/..."): it must be made absolute, otherwise curl
        // has no URL to call and answers 000 -- which would look like a server fault.
        String url = css.startsWith("http") ? css
                   : css.startsWith("/") ? base + css
                   : base + "/" + css;
        String out = sh("curl -sk -m 20 -o /dev/null -w '%{http_code} %{content_type}' " + res
                + "'" + url + "' 2>&1", 60).trim();
        // The full headers say WHO answered: "X-Powered-By: PHP" means that the
        // request reached PHP and the problem is inside the application; its absence
        // means that nginx stopped it, and then the problem is in the routing.
        String head = sh("curl -sk -m 20 -D - -o /dev/null " + res + "'" + url + "' 2>&1", 60).trim();
        boolean good = out.startsWith("200") && out.contains("text/css");
        return r.put("ok", good).put("url", url).put("answer", out)
                .put("headers", head)
                .put("fromPhp", head.toLowerCase().contains("x-powered-by: php"));
    }

    /**
     * Teaches nginx to serve the Roundcube 1.7 assets.
     *
     * The problem in one line: 1.7 asks for the stylesheets as
     *   /static.php/skins/elastic/deps/bootstrap.min.css
     * that is a PHP script followed by a path. A "location ~ \.php$" does not catch it,
     * because that URI ends in .css and not in .php: it ends up in "location /", which sends it to
     * index.php, which answers HTML. The page opens and has neither graphics nor JavaScript.
     *
     * The cure is a location that recognizes the script even when it has a path attached, and
     * that passes the separate path to PHP (PATH_INFO), which is how static.php knows which file
     * to deliver. Nothing else: the configuration is the one from the official wiki, without additions.
     * I had put a "try_files $fastcgi_script_name =404" in it to stop automated probes
     * before PHP, and that line was the cause of the fault: its internal redirect rewrites
     * the URI to the script name alone, PATH_INFO arrives empty and every asset becomes a 404.
     * If one day that protection were wanted, the form that does NOT break the path is
     *   if (!-f $document_root$fastcgi_script_name) { return 404; }
     * verified with real nginx and PHP. But it is not in the documentation, so it is not here.
     *
     * fastcgi_pass is NOT invented: it is taken from the block that is there, because on another
     * installation it could be a TCP address instead of a socket.
     */
    public static JSONObject repairNginxPathInfo(boolean run) {
        JSONObject r = new JSONObject();
        try {
            JSONArray roots = nginxRoundcubeRoots();
            if (roots.length() == 0)
                return r.put("success", false).put("error", I18n.tr("server.um.testWebmailOrigin.1"));
            String file = roots.getJSONObject(0).getString("file");
            int rootLine = roots.getJSONObject(0).getInt("line");
            java.util.List<String> lines = Files.readAllLines(Paths.get(file));

            // The PHP location inside this server block.
            int start = -1;
            for (int i = rootLine; i < Math.min(lines.size(), rootLine + 60); i++) {
                String t = lines.get(i);
                if (t.contains("location") && t.contains(".php") && t.contains("{")) { start = i; break; }
            }
            if (start < 0)
                return r.put("success", false).put("error",
                        I18n.tr("server.um.repairNginxPathInfo.1"));
            // Already in place? The WHOLE block is looked at, not the next line: after a previous
            // repair the second line may be the rewrite for the secure URLs, and by looking
            // only there the panel would repair a second time what is already repaired.
            boolean haSplit = false, haTryFiles = false;
            for (int i = start; i < Math.min(lines.size(), start + 25); i++) {
                if (lines.get(i).contains("fastcgi_split_path_info")) haSplit = true;
                // This line CANCELS the previous one: it is there but it is not enough, in fact it breaks things.
                if (lines.get(i).contains("try_files") && lines.get(i).contains("fastcgi_script_name"))
                    haTryFiles = true;
                if (lines.get(i).trim().equals("}")) break;
            }
            if (haSplit && !haTryFiles)
                return r.put("success", true).put("alreadyOk", true)
                        .put("note", I18n.tr("server.um.repairNginxPathInfo.2"));
            if (haSplit && haTryFiles)
                r.put("reason", I18n.tr("server.um.repairNginxPathInfo.3"));

            // Braces inside quotes are NOT blocks: the rewrite line for the secure
            // URLs contains "{16}", and counting it would close the block in the wrong place,
            // rewriting half the configuration. The text after # is also a comment, not code.
            int braces = 0, end = -1;
            for (int i = start; i < lines.size(); i++) {
                boolean quotes = false;
                for (char c : lines.get(i).toCharArray()) {
                    if (c == '"') { quotes = !quotes; continue; }
                    if (quotes) continue;
                    if (c == '#') break;
                    if (c == '{') braces++;
                    else if (c == '}') braces--;
                }
                if (braces == 0) { end = i; break; }
            }
            if (end < 0)
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.4"));

            // use_secure_urls puts a 16-character prefix in front of every URL: if it is on
            // the rewrite line is needed, in BOTH blocks, otherwise nothing matches any more.
            // It is not presumed: it is read from Roundcube's configuration.
            boolean safeUrls = ok("grep -qE \"^[^/]*.use_secure_urls.*=.*(true|1)\" "
                    + RC_DIR + "/config/config.inc.php", 20);
            r.put("safeUrls", safeUrls);

            String passes = "";
            for (int i = start; i <= end; i++) {
                Matcher mp = Pattern.compile("fastcgi_pass\\s+([^;]+);").matcher(lines.get(i));
                if (mp.find()) passes = mp.group(1).trim();
            }
            if (passes.isEmpty())
                return r.put("success", false).put("error",
                        I18n.tr("server.um.repairNginxPathInfo.5"));

            String ind = lines.get(start).replaceAll("[^ \t].*$", "");
            String i2 = ind + "    ";
            // Modeled on the example of the official Roundcube wiki (Installation page),
            // WITHOUT additions. I had put a "try_files $fastcgi_script_name =404" in it to
            // prevent automated probes from reaching PHP: that line does an internal
            // redirect that rewrites the URI to the script name alone, and from that
            // moment $fastcgi_path_info is recomputed on a URI that no longer has the
            // path. Result: PATH_INFO reaches static.php EMPTY, and since the PHP ??
            // operator does not fall back on an empty string, every stylesheet becomes a 404.
            // Reproduced with real nginx and PHP: it is exactly the fault of 2026-08-31.
            java.util.List<String> fresh = new ArrayList<>(java.util.List.of(
                ind + "# Roundcube 1.7 serves its assets as /static.php/path/to/file.css:",
                ind + "# a PHP script with a path attached. A location that wants .php",
                ind + "# at the end of the URI does not catch it, and the style sheet comes back as HTML.",
                ind + "# Configuration from Roundcube's official wiki (Installation page).",
                ind + "location ~ \\.php {"));
            if (safeUrls) fresh.add(i2 + "rewrite \"^/[a-zA-Z0-9]{16}/(.*)$\" /$1;");
            fresh.addAll(java.util.List.of(
                i2 + "include fastcgi_params;",
                i2 + "fastcgi_index index.php;",
                i2 + "fastcgi_split_path_info ^(.+\\.php)(/.+)$;",
                i2 + "fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
                i2 + "fastcgi_param PATH_INFO $fastcgi_path_info;",
                i2 + "fastcgi_pass " + passes + ";",
                ind + "}"));

            r.put("success", true).put("file", file).put("from", start + 1).put("to", end + 1)
             .put("current", String.join("\n", lines.subList(start, end + 1)))
             .put("proposed", String.join("\n", fresh));
            if (!run) return r.put("executed", false);

            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}"))
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.10"));
            String bk = "/var/db/daemoxcp-mail/nginx/" + ts;
            ok("mkdir -p " + bk, 30);
            if (!ok("cp -p " + file + " " + bk + "/nginx.conf", 30))
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.11", java.util.Map.of("file", String.valueOf(file))));

            java.util.List<String> out = new ArrayList<>(lines.subList(0, start));
            out.addAll(fresh);
            out.addAll(lines.subList(end + 1, lines.size()));
            Files.write(Paths.get(file), out);

            String test = sh("nginx -t 2>&1", 60).toLowerCase();
            if (!(test.contains("syntax is ok") && test.contains("test is successful"))) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                return r.put("success", false).put("executed", false)
                        .put("error", I18n.tr("server.um.x.nginxRejected", java.util.Map.of("out", String.valueOf(sh("nginx -t 2>&1", 60).replace("\n", " ")))));
            }
            String svc = realServiceName("nginx");
            if (svc == null || !ok("service " + svc + " reload", 60)) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                if (svc != null) ok("service " + svc + " reload", 60);
                return r.put("success", false).put("executed", false)
                        .put("error", I18n.tr("server.um.repairNginxPathInfo.12"));
            }

            // The test that counts: does the CSS come back as CSS?
            JSONObject pw = testWebmailOrigin();
            String name = pw.optString("url", "").replaceAll("^https://", "").replaceAll(":.*$", "");
            String port = pw.optString("url", "").replaceAll(".*:", "").replaceAll("/.*$", "");
            JSONObject css = name.isEmpty() ? new JSONObject().put("ok", false).put("error", I18n.tr("server.um.probePathInfo.2"))
                                            : testCssAsset(name, port);
            r.put("executed", true).put("backup", bk + "/nginx.conf").put("css", css);
            if (!css.optBoolean("ok")) {
                r.put("caution", I18n.tr("server.um.x.cssStillWrong", java.util.Map.of("r", String.valueOf(css.optString("answer", css.optString("error"))), "file", String.valueOf(bk + "/nginx.conf"))));
            }
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("repairNginxPathInfo", e));
        }
    }

    public static JSONObject roundcubeDiagnostics() {
        JSONObject r = new JSONObject();
        JSONArray entries = new JSONArray();
        try {
            // 1. Where nginx points now
            JSONArray roots = nginxRoundcubeRoots();
            String root = roots.length() > 0 ? roots.getJSONObject(0).getString("root") : RC_DIR;
            String file = roots.length() > 0 ? roots.getJSONObject(0).getString("file") : "?";
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.1"))
                    .put("text", I18n.tr("server.um.roundcubeDiagnostics.2", java.util.Map.of("root", String.valueOf(root), "file", String.valueOf(file)))));

            // 2. The error log: that is where nginx says WHY
            String logPath = sh("grep -hE '^[[:space:]]*error_log' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 30).trim();
            if (!logPath.matches("/[A-Za-z0-9._/-]{1,200}")) logPath = "/var/log/nginx/error.log";
            String log = sh("tail -25 " + logPath + " 2>&1", 30);
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.3", java.util.Map.of("logPath", String.valueOf(logPath))))
                    .put("text", log.isEmpty() ? I18n.tr("server.um.x.empty") : log));

            // 3. Permissions along the whole path: a single non-traversable folder is enough
            StringBuilder perm = new StringBuilder();
            String[] pieces = root.split("/");
            StringBuilder acc = new StringBuilder();
            for (String piece : pieces) {
                if (piece.isEmpty()) continue;
                acc.append('/').append(piece);
                perm.append(sh("ls -ld " + acc + " 2>&1", 20)).append('\n');
            }
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.4"))
                    .put("text", perm.toString().trim()));

            // 4. What is really in the served folder
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.5", java.util.Map.of("root", String.valueOf(root))))
                    .put("text", sh("ls -la " + root + " 2>&1 | head -25", 30)));

            // 5. Which user nginx runs as: it is the one that must be able to read
            String user = sh("grep -hE '^[[:space:]]*user[[:space:]]' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 20).trim();
            String proc = sh("ps -axo user,command 2>/dev/null | grep '[n]ginx: worker' | head -2", 30);
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.7"))
                    .put("text", I18n.tr("server.um.x.nginxUserDeclared", java.util.Map.of("u", String.valueOf(user.isEmpty() ? I18n.tr("server.um.x.nginxUserNobody") : user)))
                            + "\n" + (proc.isEmpty() ? I18n.tr("server.um.x.noWorker") : proc)));

            // 6. The SERVER's answer, bypassing whatever stands in front
            JSONObject pw = testWebmailOrigin();
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.8"))
                    .put("text", pw.optBoolean("ok")
                            ? I18n.tr("server.um.x.urlAnswers", java.util.Map.of("url", String.valueOf(pw.optString("url")), "code", String.valueOf(pw.optString("code")))) + "\n\n"
                              + pw.optString("headers")
                            : I18n.tr("server.um.x.noAnswer", java.util.Map.of("r", String.valueOf(pw.optString("code", pw.optString("error")))))
                              + (pw.optBoolean("viaCdn") ? "  " + I18n.tr("server.um.x.cdnAnswered") : "")
                              + "\n\n" + pw.optString("headers")));

            // 6b. The .htaccess says how Roundcube wants to be served: it is the authoritative source
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.9", java.util.Map.of("root", String.valueOf(root))))
                    .put("text", sh("cat " + root + "/.htaccess 2>&1", 30)));

            // 6c. The assets: in 1.7 they go through static.php, and that is where nginx usually gets it wrong.
            if (pw.optBoolean("ok")) {
                String u = pw.optString("url");
                String hName = u.replaceAll("^https://", "").replaceAll(":.*$", "");
                String hPort = u.replaceAll(".*:", "").replaceAll("/.*$", "");
                JSONObject css = testCssAsset(hName, hPort);
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.10"))
                        .put("text", css.optString("url", I18n.tr("server.um.x.noLinkFound")) + "\n  -> "
                            + css.optString("answer", css.optString("error"))
                            + (css.optBoolean("ok") ? "   " + I18n.tr("server.um.x.correct")
                               : I18n.tr("server.um.roundcubeDiagnostics.11"))
                            + "\n\n" + I18n.tr("server.um.x.whoAnswered") + " " + (css.optBoolean("fromPhp")
                                ? I18n.tr("server.um.roundcubeDiagnostics.12")
                                : I18n.tr("server.um.roundcubeDiagnostics.13"))
                            + "\n\n" + css.optString("headers", "")));

                // Does the file static.php should serve really exist on disk?
                String pathInfo = css.optString("url", "").replaceAll(".*/static\\.php", "").replaceAll("\\?.*$", "");
                if (!pathInfo.isEmpty() && pathInfo.matches("/[A-Za-z0-9._/-]{1,200}")) {
                    String expected = RC_DIR + pathInfo;
                    entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.14"))
                            .put("text", "PATH_INFO: " + pathInfo + "\n"
                                + sh("ls -l " + expected + " 2>&1", 20) + "\n"
                                + sh("ls -d " + RC_DIR + "/skins/*/ 2>&1 | head -5", 20)));
                }

                // The experiment that separates the two possibilities: static.php run by hand,
                // with a known PATH_INFO and no web server in between. If the file comes out
                // here, the application works and the problem is in what nginx sends it; if
                // it fails here too, the problem is inside static.php or its paths.
                if (!pathInfo.isEmpty() && pathInfo.matches("/[A-Za-z0-9._/-]{1,200}")) {
                    String cd = "cd " + RC_DIR + "/public_html && ";
                    String reqUri = "/static.php" + pathInfo;
                    String withPathInfo = sh(cd + "env PATH_INFO='" + pathInfo + "' REQUEST_URI='" + reqUri
                            + "' REQUEST_METHOD=GET php static.php 2>&1 | head -c 400", 60);
                    String withoutPathInfo = sh(cd + "env -u PATH_INFO REQUEST_URI='" + reqUri
                            + "' REQUEST_METHOD=GET php static.php 2>&1 | head -c 400", 60);
                    entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.15"))
                            .put("text",
                                "--- " + I18n.tr("server.um.x.withPathInfo", java.util.Map.of("v", String.valueOf(pathInfo))) + " ---\n"
                                + summarizeOutput(withPathInfo)
                                + "\n\n--- " + I18n.tr("server.um.x.withoutPathInfo", java.util.Map.of("v", String.valueOf(reqUri))) + " ---\n"
                                + summarizeOutput(withoutPathInfo)));
                }

                // What PHP receives going through nginx: it is the other half of the bisection.
                JSONObject probe = probePathInfo();
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.16"))
                        .put("text", probe.optBoolean("ok")
                            ? I18n.tr("server.um.x.testRequest", java.util.Map.of("url", String.valueOf(probe.optString("url")))) + "\n\n"
                              + probe.optString("output")
                            : I18n.tr("server.um.x.notSucceeded", java.util.Map.of("e", String.valueOf(probe.optString("error"))))));

                // The real code installed on THIS server, not the one in the upstream repository.
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.17"))
                        .put("text", sh("head -45 " + RC_DIR + "/public_html/static.php 2>&1", 30)));

                // PHP may be confined: if it is not allowed to go outside public_html,
                // static.php does not reach the skins and answers 404 while working.
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.18"))
                        .put("text", sh("grep -rhnE '^[^;]*(open_basedir|chroot|chdir)' "
                            + "/usr/local/etc/php.ini /usr/local/etc/php-fpm.conf "
                            + "/usr/local/etc/php-fpm.d/ /usr/local/etc/php/ 2>/dev/null | head -12", 30)
                            .trim().isEmpty()
                            ? I18n.tr("server.um.roundcubeDiagnostics.19")
                            : sh("grep -rhnE '^[^;]*(open_basedir|chroot|chdir)' "
                                + "/usr/local/etc/php.ini /usr/local/etc/php-fpm.conf "
                                + "/usr/local/etc/php-fpm.d/ /usr/local/etc/php/ 2>/dev/null | head -12", 30)));
            }

            // 7. The server block, as it is now on disk
            if (!"?".equals(file)) {
                int line = roots.getJSONObject(0).getInt("line");
                int from = Math.max(1, line - 12), a2 = line + 22;
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.20", java.util.Map.of("line", String.valueOf(line))))
                        .put("text", sh("sed -n '" + from + "," + a2 + "p' " + file + " 2>&1", 30)));
            }
            return r.put("success", true).put("entries", entries);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("roundcubeDiagnostics", e));
        }
    }

    /**
     * @param approvedSignature the signature of the plan that whoever presses has read: the job recomputes the
     *                          plan and starts only if it is the same (see startGuidedUpdate)
     */
    public static JSONObject startRoundcubeUpdate(String approvedSignature) {
        if (!validSignature(approvedSignature))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.plan.signatureMissing"));
        String id = "rc-" + System.currentTimeMillis();
        Job j = new Job(id, "roundcube");
        return startOnTurn(id, j, I18n.tr("server.um.startRoundcubeUpdate.1"), "roundcube-update",
                () -> runRoundcubeUpdate(j, approvedSignature));
    }

    /**
     * Major version jump of Roundcube.
     *
     * The package is the easy part. The part that breaks is the database SCHEMA: 1.7
     * changes it, and until bin/updatedb.sh is run the webmail does not work. And that change
     * cannot be undone, so the database copy comes before everything else.
     * The other pitfall is OPcache: once the PHP files are updated, php-fpm would keep serving the
     * old code already compiled in memory -- updated on disk, not in service.
     */
    private static void runRoundcubeUpdate(Job job, String approvedSignature) {
        try {
            roundcubeSteps(job, approvedSignature);
        } finally {
            job.finish();
        }
    }

    /** The steps of the Roundcube update, without closing the log: "Update all" uses them too (finding 207). */
    private static void roundcubeSteps(Job job, String approvedSignature) {
        job.status = "running";
        final int TOT = 8;
        // The on-disk list of this job, to lock again in the finally: empty until it is written.
        java.util.List<String> listed = new ArrayList<>();
        String pkg = "", backupDir = "";
        Map<String, Boolean> servicesBefore = servicesState();
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        PlanOutcome outcome = null;
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runRoundcubeUpdate.1"));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = roundcubePreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.write("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            pkg = pf.optString("pkg", "");
            long tablesBefore = pf.optLong("tables", 0);
            job.write("  " + pkg + " " + pf.optString("current") + " -> " + pf.optString("available"));
            // The plan that was read is carried out, or nothing is: before the database copy and
            // everything else, so a changed plan leaves nothing behind.
            JSONObject plan = pf.optJSONObject("plan");
            String mismatch = approvedPlanMismatch(job, plan, pf.optString("signature", null), approvedSignature);
            if (mismatch != null) {
                job.status = "error";
                job.errorMessage = mismatch;
                return;
            }
            job.write("  " + I18n.tr("server.um.x.dbTables", java.util.Map.of("db", String.valueOf(pf.optString("db")), "n", String.valueOf(tablesBefore))));

            job.advance(2, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.2", java.util.Map.of("total", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            backupDir = "/var/db/daemoxcp-mail/roundcube/" + ts;
            if (!ok("mkdir -p " + backupDir, 30)) throw new IllegalStateException("cannot create " + backupDir);
            ok("cp -p " + RC_DIR + "/config/config.inc.php " + backupDir + "/config.inc.php", 30);
            JSONObject cp = rcDump(backupDir + "/roundcube.sql");
            if (!cp.optBoolean("ok")) {
                job.write("    " + cp.optString("error"));
                throw new IllegalStateException("the database copy did not succeed: I do not go ahead "
                        + "without a way back. The reason is the line above.");
            }
            if (cp.has("reduced")) {
                job.write("    " + I18n.tr("server.um.x.copyReduced", java.util.Map.of("mode", String.valueOf(I18n.tr(cp.optString("mode"))))));
                job.write("    " + I18n.tr("server.um.x.didNotPass", java.util.Map.of("r", String.valueOf(cp.getString("reduced")))));
                job.write(I18n.tr("server.um.runRoundcubeUpdate.3"));
            }
            job.write("    " + I18n.tr("server.um.x.copyVerified", java.util.Map.of("file", String.valueOf(backupDir + "/roundcube.sql"), "kb", String.valueOf(number(sh("wc -c < " + backupDir + "/roundcube.sql", 30)) / 1024))));
            job.write(I18n.tr("server.um.runRoundcubeUpdate.4"));

            job.advance(3, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.5", java.util.Map.of("total", String.valueOf(TOT))));
            // The locks the plan removes, not one fewer nor one more; the on-disk list
            // first, and from here on the finally locks again even if the unlocking failed halfway.
            final String rcPkg = pkg;
            listed = unlockForPlan(job, plan, java.util.List.of());
            // First download and compute again: until the packages are downloaded pkg does not see
            // the file conflicts (see fetchAndRecheck). -U: the same catalog as the plan.
            Recheck grown = fetchAndRecheck(job, "pkg upgrade -F -y -U " + pkg + " 2>&1", plan,
                    () -> roundcubePlan(rcPkg));
            if (grown.stop() != null) throw org.daemoxcp.mail.util.ShownException.translated(grown.stop());
            plan = grown.plan();
            PlanWatch watch = PlanWatch.take(sideEffects);
            StringBuilder cat = new StringBuilder();
            int code = runLogged(job, "pkg upgrade -y -U " + pkg + " 2>&1", 1800, cat);
            // 4 = EX_NEEDRESTART: pkg upgraded itself and stopped there: the same command, once more.
            if (code == 4) {
                job.write(I18n.tr("server.um.runGuidedUpdate.10"));
                code = runLogged(job, "pkg upgrade -y -U " + pkg + " 2>&1", 1800, cat);
            }
            // The comparison before deciding whether to stop: a pkg that ended badly is exactly the case
            // in which the machine may have been left halfway. php-fpm restarts further down.
            outcome = checkPlanOutcome(job, watch, plan, "Roundcube update", true);
            if (code != 0) throw new IllegalStateException("pkg upgrade exited with code " + code);
            if (outcome.mapsProblem() != null) throw org.daemoxcp.mail.util.ShownException.translated(outcome.mapsProblem());
            for (String m : messagesAskingForAction(cat.toString())) {
                job.write("    " + I18n.tr("server.um.x.pkgAsks", java.util.Map.of("m", String.valueOf(m.replace("\n", " | ")))));
            }

            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.6", java.util.Map.of("total", String.valueOf(TOT))));
            // The package may have put a sample config in place of yours.
            JSONObject dsnAfter = dsnRoundcube();
            if (!dsnAfter.optBoolean("ok")) {
                ok("cp -p " + backupDir + "/config.inc.php " + RC_DIR + "/config/config.inc.php", 30);
                job.write(I18n.tr("server.um.runRoundcubeUpdate.7"));
            } else job.write("    " + I18n.tr("server.um.x.confIntact"));

            job.advance(5, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.8", java.util.Map.of("total", String.valueOf(TOT))));
            String out = sh("cd " + RC_DIR + " && php bin/updatedb.sh --package=roundcube --dir=SQL 2>&1", 900);
            for (String l : out.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
            String ol = out.toLowerCase();
            if (ol.contains("error") || ol.contains("fatal") || ol.contains("failed")) {
                throw new IllegalStateException("updatedb.sh reported an error: the database copy is in "
                        + backupDir + "/roundcube.sql");
            }

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.9", java.util.Map.of("total", String.valueOf(TOT))));
            String rootOutcome = "unneeded";
            if (pf.optBoolean("rootChange", false)) {
                rootOutcome = moveNginxRoot(job, backupDir);
                if ("failed".equals(rootOutcome))
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.10", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            } else job.write(I18n.tr("server.um.runRoundcubeUpdate.11"));
            boolean rootOk = !"failed".equals(rootOutcome);

            job.advance(7, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.12", java.util.Map.of("total", String.valueOf(TOT))));
            // The package has just set logs and temp back to www:www: they go back to the webmail before
            // php-fpm restarts, not at the end of the job, because the test below already uses them.
            java.util.List<String> given = RoundcubeUser.repairOwnership();
            if (!given.isEmpty())
                job.write(I18n.tr("server.um.runRoundcubeUpdate.ownership", java.util.Map.of("user", RoundcubeUser.USER,
                        "n", String.valueOf(given.size()))));
            String svc = realServiceName("php_fpm");
            // php-fpm not restarted, or back up with the same pid: the webmail is still serving the old code.
            boolean phpHeld = false;
            if (svc != null && sideEffects.configChangedByScript()) {
                // A script changed the configuration and the plan did not say so: restarting would
                // put it into effect without anyone having read it (finding 42). As in the guided
                // update, php-fpm stays with the previous one and the reader decides.
                phpHeld = true;
                job.write(I18n.tr("server.drift.restartHeld", java.util.Map.of("list", svc)));
                job.write(I18n.tr("server.drift.restartHeldCost"));
                job.write("      service " + svc + " restart");
            } else if (svc != null) {
                String test = testConfigOf(svc);
                Shell.Result pr = test == null ? null : Shell.runShell(Duration.ofSeconds(60), test + " 2>&1");
                if (pr != null && !pr.success()) {
                    // Restarting it with a configuration it refuses would just shut it down.
                    job.write(I18n.tr("server.um.runGuidedUpdate.22", java.util.Map.of("s", svc)));
                    for (String l : pr.outputTrim().split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
                    job.write(I18n.tr("server.um.runGuidedUpdate.23"));
                    phpHeld = true;
                } else {
                    String pidBefore = servicePid(svc);
                    ok("service " + svc + " restart", 120);
                    boolean up = cameUp(svc);
                    String pidAfter = servicePid(svc);
                    job.write("    " + svc + ": " + (up ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26"))
                            + (pidBefore.isEmpty() || pidAfter.isEmpty() ? "" : "  (pid " + pidBefore + " -> " + pidAfter + ")"));
                    // The same pid is the previous process still standing: OPcache would serve the old version.
                    if (!up || (!pidBefore.isEmpty() && pidBefore.equals(pidAfter))) phpHeld = true;
                }
            } else job.write(I18n.tr("server.um.runRoundcubeUpdate.13"));

            job.advance(8, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.14", java.util.Map.of("total", String.valueOf(TOT))));
            long tablesAfter = number(rcQuery(org.daemoxcp.mail.database.SqlCatalog.UM_COUNT_SCHEMA_TABLES, pf.optString("db")));
            job.write(I18n.tr("server.um.runRoundcubeUpdate.15", java.util.Map.of("tablesBefore", String.valueOf(tablesBefore), "tablesAfter", String.valueOf(tablesAfter))));
            boolean tabOk = tablesAfter >= tablesBefore;
            if (!tabOk) job.write(I18n.tr("server.um.runRoundcubeUpdate.16"));

            // Does the webmail really answer? It is not enough that the files are updated.
            //
            // And it must be asked OF THE SERVER. Asking the public name you end up talking
            // to what stands in front -- a CDN, a proxy -- and taking its answer for the
            // server's: it happened here, with a Cloudflare 403 mistaken for a webmail
            // fault while nginx had not even seen the request.
            JSONObject pw = testWebmailOrigin();
            boolean testedWeb = !pw.has("error") || pw.has("code");
            boolean webOk = pw.optBoolean("ok");
            if (!testedWeb) {
                job.write("    " + I18n.tr("server.um.x.webTestNotRun", java.util.Map.of("e", String.valueOf(pw.optString("error")))));
                webOk = true;   // not tested does not mean broken: I do not fail what I have not measured
            } else if (webOk) {
                job.write("    " + I18n.tr("server.um.x.urlAnswersOrigin", java.util.Map.of("url", String.valueOf(pw.optString("url")), "code", String.valueOf(pw.optString("code")))));
            } else {
                job.write("    " + I18n.tr("server.um.x.urlAnswersBad", java.util.Map.of("url", String.valueOf(pw.optString("url")), "code", String.valueOf(pw.optString("code")))));
                if (pw.optBoolean("viaCdn"))
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.17"));
            }

            job.write("");
            boolean fallen = fallenServices(job, servicesBefore);
            sideEffects.checkListening(job);
            java.util.List<String> problems = planProblems(outcome);
            problems.addAll(sideEffects.problems());
            if (phpHeld) problems.add(sideEffects.configChangedByScript()
                    ? I18n.tr("server.drift.restartHeldProblem", java.util.Map.of("list", String.valueOf(svc)))
                    : I18n.tr("server.um.runGuidedUpdate.37"));
            if (fallen && problems.isEmpty()) problems.add(I18n.tr("server.um.runGuidedUpdate.37"));

            if (!problems.isEmpty()) {
                job.status = "error";
                problems.add(I18n.tr("server.um.runRoundcubeUpdate.24", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                job.errorMessage = String.join(" ", problems);
            } else if (tabOk && webOk && rootOk) {
                job.status = "completed";
                job.write("");
                // "In service" can be said only if someone has seen it answer. Without that
                // test the job may have gone perfectly well, but the verdict would be greener
                // than the tests I have: so I say so, and you do the check.
                job.write(testedWeb
                        ? I18n.tr("server.um.runRoundcubeUpdate.18")
                        : I18n.tr("server.um.runRoundcubeUpdate.19"));
                if (!testedWeb)
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.20"));
                if ("unneeded".equals(rootOutcome) && pf.optBoolean("rootChange", false))
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.21"));
                job.write(I18n.tr("server.um.runRoundcubeUpdate.22", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                job.write(I18n.tr("server.um.runRoundcubeUpdate.23"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRoundcubeUpdate.24", java.util.Map.of("backupDir", String.valueOf(backupDir)));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            // pkg stopped halfway after a script has already written: both are stated.
            for (String p : sideEffects.problems()) job.errorMessage += " " + p;
            if (outcome != null && !outcome.outsidePlan().isEmpty()) job.errorMessage += " " + divergenceMessage(outcome.outsidePlan());
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (!listed.isEmpty() && !relockListed(job, listed).isEmpty() && "completed".equals(job.status)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runGuidedUpdate.42");
            }
        }
    }

    // ===================== update of the panel JVM =====================

    private static final String JDK_DIR = "/var/db/daemoxcp-mail/jdk";
    /** Where what the panel writes ends up when it restarts detached from the terminal. */
    private static final String PANEL_LOG = "/var/db/daemoxcp-mail/panel.log";
    /** The panel service: its script and the pidfile that daemon -p writes for it (RcScriptRepair). */
    static final String RC_NAME = PanelRcScript.NAME;
    static String rcScript = PanelRcScript.PATH;
    static String rcPidfile = PanelRcScript.PIDFILE;

    /** True if this process was started by the service: the script is there and its pidfile holds our pid. */
    static boolean startedByService(long pid) {
        try {
            return Files.isRegularFile(Paths.get(rcScript))
                    && Files.readString(Paths.get(rcPidfile)).trim().equals(String.valueOf(pid));
        } catch (java.io.IOException | RuntimeException e) {
            return false;
        }
    }

    /**
     * The command line that restarts THIS panel, rebuilt from the live process.
     *
     * It is not read from a script on disk: that might be old, missing, or not be the
     * one the panel was really started with. What is taken is the java in use, the
     * options this virtual machine started with and the jar file this class was
     * loaded from. If the panel was started with just "java -jar x.jar", the rebuilt
     * line is just as bare -- and that is how it should be: it restarts as it was.
     */
    public static String startCommand(boolean webOnly) {
        StringBuilder c = new StringBuilder(System.getProperty("java.home", "") + "/bin/java");
        for (String a : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            // The measurement options are not carried over: they belong to whoever was observing.
            if (a.startsWith("-agentlib") || a.startsWith("-javaagent") || a.startsWith("-Xdebug")) continue;
            c.append(' ').append(a);
        }
        String jar = jarPath();
        if (!jar.isEmpty()) c.append(" -jar ").append(jar);
        return webOnly ? c.append(" --web").toString() : c.toString();
    }

    /** The jar file this panel runs from, or an empty string if it is not a jar. */
    public static String jarPath() {
        try {
            java.io.File f = new java.io.File(
                    UpdateManager.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            // The jar moved to the new name by this process (PanelServiceRename): the virtual machine still
            // knows it by the previous name, the disk by the current one.
            java.io.File now = new java.io.File(PanelServiceRename.current(f.getAbsolutePath()));
            return now.isFile() ? now.getAbsolutePath() : "";
        } catch (Exception e) { return ""; }
    }

    /**
     * Writes run.sh next to the jar, if it is not already there.
     *
     * It is not a file to distribute: it is a convenience the panel creates for itself, and for
     * that reason it mirrors the REAL startup instead of a line written by hand months ago. If it
     * already exists it does not touch it: it might have been adapted, and overwriting it would
     * erase the adaptation without saying anything.
     */
    public static String createRunSh() {
        try {
            String jar = jarPath();
            if (jar.isEmpty()) return "";
            Path f = Paths.get(jar).getParent().resolve("run.sh");
            if (Files.exists(f)) return "";
            Files.writeString(f, "#!/bin/sh\n"
                + "# Created by the panel: it mirrors how the panel was really started.\n"
                + "# Without arguments: the on-screen menu (a terminal is needed).\n"
                + "# With --web: only the web server, without menu and without terminal.\n"
                // The folder is not the jar's but the one the panel STARTED from:
                // "./database" and "./install_scripts" are relative to it. In the normal case
                // they coincide, but if they did not, a run.sh that enters the jar's folder
                // would create a second empty database next to the first, without saying
                // anything.
                + "cd '" + System.getProperty("user.dir", ".") + "' || exit 1\n"
                + "exec " + startCommand(false) + " \"$@\"\n");
            ok("chmod 700 " + f, 15);
            return I18n.tr("server.um.createRunSh.1", java.util.Map.of("f", String.valueOf(f)));
        } catch (Exception e) { return ""; }
    }

    /**
     * How the panel is relaunched after stopping it.
     *
     * It is not guessed: the command line of THIS process is rebuilt -- same java,
     * same virtual machine options, same jar file -- and --web is added to it.
     *
     * The --web is the key to everything. The panel has an on-screen interface that requires a
     * terminal, and a detached script does not have one: relaunching it normally would make it die
     * an instant later, leaving the web panel off. In web-only mode the terminal is not
     * needed, so the return is certain. What is lost is the on-screen MENU, not the panel: to
     * get it back it is enough to stop the process and restart it from SSH without --web.
     */
    private static JSONObject restartStrategy() {
        String dir = System.getProperty("user.dir", "");
        // Started by the service (/usr/local/etc/rc.d/daemoxcp_mail, as at machine boot): it is started again
        // with the service. With the rebuilt daemon(8) line the panel came back up without the service's
        // pidfile: "service daemoxcp_mail status" reported it stopped, a stop did not stop it and a start
        // started a second one (finding 195). The service redoes the same line as always, with its pidfile
        // and its log.
        if (startedByService(ProcessHandle.current().pid())) {
            String command = "/usr/sbin/service " + RC_NAME + " onestart";
            return new JSONObject()
                    .put("dir", dir)
                    .put("menuCommand", startCommand(false))
                    .put("jar", jarPath())
                    .put("command", command)
                    .put("log", PANEL_LOG)
                    .put("line", command)
                    .put("service", true)
                    .put("note", I18n.tr("server.um.restartStrategy.service", java.util.Map.of("p", command)))
                    .put("ok", true);
        }
        String binJava = System.getProperty("java.home", "") + "/bin/java";
        String jar = jarPath();

        String command = startCommand(true);

        return new JSONObject()
                .put("dir", dir)
                .put("menuCommand", startCommand(false))
                .put("jar", jar)
                .put("command", command)
                // -f sends the three descriptors to /dev/null, and on its own throws away
                // EVERYTHING the panel writes: it happened on 2026-08-31, panel started again
                // and silent, with no way of knowing what it was doing. -o brings stdout and
                // stderr back into a file, and for daemon(8) the two options combine exactly
                // like this: first /dev/null, then the redirection to the file. -t gives the
                // process a recognizable name in ps, so it is found without looking for
                // "java" among all the javas.
                .put("log", PANEL_LOG)
                .put("line", "/usr/sbin/daemon -f -o " + PANEL_LOG + " -t " + RC_NAME + ""
                        + " -- /bin/sh -c \"cd '" + dir + "' && exec " + command + "\"")
                .put("note", jar.isEmpty()
                        ? I18n.tr("server.um.restartStrategy.1")
                        : I18n.tr("server.um.restartStrategy.2", java.util.Map.of("p", String.valueOf(startCommand(false)))))
                .put("ok", !jar.isEmpty());
    }

    /**
     * The port the panel is listening on NOW, asked of the operating system.
     *
     * It could be read from the configuration, but the configuration says what had been
     * requested, not what is happening. Here we need to know where to knock again after the
     * restart, so only the fact counts: which port this PID has opened. If it cannot be
     * established 0 is returned, and the script skips the check instead of checking the
     * wrong port and declaring a fault that does not exist.
     */
    private static int listeningPort(long pid) {
        for (String line : sh("sockstat -46l 2>/dev/null").split("\n")) {
            String[] c = line.trim().split("\\s+");
            if (c.length < 6 || !c[2].equals(String.valueOf(pid))) continue;
            String address = c[5];
            int i = Math.max(address.lastIndexOf(':'), address.lastIndexOf('.'));
            if (i < 0) continue;
            try {
                int port = Integer.parseInt(address.substring(i + 1));
                if (port > 0 && port < 65536) return port;
            } catch (NumberFormatException ignored) { }
        }
        return 0;
    }

    /** The package that owns the JVM THIS process runs on. Not deduced from the name. */
    private static String jvmPackage() {
        String home = System.getProperty("java.home", "");
        if (home.isEmpty()) return "";
        // "pkg which -q" answers NAME-VERSION (openjdk25-25.0.2+10.f.1_2), not the name.
        // With that "pkg rquery" finds nothing, and an empty answer looks like "you are fine".
        // The normalization is done by pkg itself: it is the only one that knows where the name
        // ends, given that versions contain + . _ and names contain digits and hyphens.
        String nv = sh("pkg which -q " + home + "/bin/java 2>/dev/null").trim();
        if (!nv.matches("[A-Za-z0-9._+-]{1,80}")) return "";
        // I do not take even pkg's answer for granted: I accept it only if the package
        // with that name really exists. That is what distinguishes a name from a string.
        String name = sh("pkg query %n " + nv + " 2>/dev/null").trim();
        if (name.matches("[A-Za-z0-9._+-]{1,64}") && ok("pkg info -e " + name, 15)) return name;
        // Fallback: I cut at the last hyphen followed by a digit, where the version begins,
        // and I accept the result only if pkg confirms that that package really exists.
        Matcher m = Pattern.compile("^(.+)-[0-9][^-]*$").matcher(nv);
        return m.find() && ok("pkg info -e " + m.group(1), 15) ? m.group(1) : "";
    }

    /**
     * Preliminary checks for the JVM update. All read-only.
     *
     * This update is different from all the others for one reason only: the panel RUNS ON
     * IT. Replacing the JVM files under a live process breaks the startup of subprocesses
     * (jspawnhelper stops matching the JVM in memory), so from that moment every
     * command would fail and every state reported by the panel would be false. That is why the
     * job is done by a detached script: first the panel stops, then it is updated, then it restarts.
     */
    public static JSONObject javaPreflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean lock = false;
        try {
            String pkg = jvmPackage();
            String home = System.getProperty("java.home", "");
            if (pkg.isEmpty()) {
                addCheck(checks, "pkg", I18n.tr("server.um.x.jvmInUse"), "block",
                        I18n.tr("server.um.javaPreflight.1", java.util.Map.of("home", String.valueOf(home))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", true).put("canProceed", false);
            }
            r.put("pkg", pkg);
            String vIns = sh("pkg query %v " + pkg + " 2>/dev/null").trim();
            String vRepo = sh("pkg rquery -U %v " + pkg + " 2>/dev/null").trim();
            r.put("current", vIns).put("available", vRepo).put("home", home);
            addCheck(checks, "pkg", I18n.tr("server.um.x.jvmInUse"), "ok",
                    I18n.tr("server.um.javaPreflight.2", java.util.Map.of("pkg", String.valueOf(pkg), "vIns", String.valueOf(vIns), "home", String.valueOf(home))));
            if (vRepo.isEmpty()) {
                addCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "block",
                        I18n.tr("server.um.javaPreflight.3", java.util.Map.of("pkg", String.valueOf(pkg))));
                lock = true;
            } else if (vRepo.equals(vIns)) {
                addCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "ok",
                        I18n.tr("server.um.javaPreflight.4", java.util.Map.of("vIns", String.valueOf(vIns))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", false).put("canProceed", false).put("already", true);
            } else {
                addCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "wait",
                        I18n.tr("server.um.javaPreflight.5", java.util.Map.of("vIns", String.valueOf(vIns), "vRepo", String.valueOf(vRepo), "home", String.valueOf(home))));
            }

            JSONObject st = restartStrategy();
            r.put("restart", st);
            if (!st.optBoolean("ok")) {
                addCheck(checks, "start", I18n.tr("server.um.javaPreflight.6"), "block", st.getString("note"));
                lock = true;
            } else {
                addCheck(checks, "start", I18n.tr("server.um.javaPreflight.6"), "wait", st.getString("note"));
                addCheck(checks, "cmd", I18n.tr("server.um.javaPreflight.7"), "ok",
                        st.optBoolean("service") ? st.getString("command") : "in " + st.getString("dir") + ":  " + st.getString("command"));
            }

            if (!ok("test -x /usr/sbin/daemon", 10)) {
                addCheck(checks, "daemon", I18n.tr("server.um.x.scriptDetach"), "block",
                        I18n.tr("server.um.javaPreflight.8"));
                lock = true;
            } else {
                addCheck(checks, "daemon", I18n.tr("server.um.x.scriptDetach"), "ok",
                        I18n.tr("server.um.javaPreflight.9"));
            }

            // Way back: a package rebuilt from the INSTALLED files, not downloaded from the
            // repository. If the repository no longer has the old version, it is the only way.
            long free = number(sh("df -k /var/db | tail -1 | awk '{print $4}'", 30)) / 1024;
            long large = number(sh("pkg query %sb " + pkg + " 2>/dev/null", 30)) / 1024 / 1024;
            r.put("spaceMb", free).put("jdkMb", large);
            if (large > 0 && free < large * 2) {
                addCheck(checks, "space", I18n.tr("server.um.javaPreflight.10"), "block",
                        I18n.tr("server.um.javaPreflight.11", java.util.Map.of("p", String.valueOf((large * 2)), "free", String.valueOf(free))));
                lock = true;
            } else {
                addCheck(checks, "space", I18n.tr("server.um.javaPreflight.10"), "ok",
                        I18n.tr("server.um.javaPreflight.12", java.util.Map.of("size", String.valueOf(large), "jdkDir", String.valueOf(JDK_DIR), "free", String.valueOf(free))));
            }

            addCheck(checks, "down", I18n.tr("server.um.x.downtime"), "wait",
                    I18n.tr("server.um.javaPreflight.13"));

            // The EXACT plan, as for Roundcube, Python and MySQL: what pkg would do upgrading the JVM,
            // computed on a copy of its database with the same locks removed. Before, the page said only
            // "25.0.4 -> 25.0.5", and pkg also upgraded four X11 libraries without anyone having
            // read it (finding 195). The job starts only with the signature of this plan.
            if (!vRepo.isEmpty()) {
                JSONObject plan = javaPlan(pkg);
                if (addPlanChecks(checks, plan, java.util.List.of(pkg), java.util.List.of(pkg), lock)) lock = true;
                r.put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""))
                 .put("unlock", plan.optJSONArray("unlockedPackages") == null ? new JSONArray() : plan.getJSONArray("unlockedPackages"));
            }

            r.put("success", true).put("checks", checks)
             .put("blocked", lock).put("canProceed", !lock);
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("javaPreflight", e));
        }
    }

    /**
     * Prepares the script, checks it and launches it detached. Then the panel dies: from that
     * moment on the only witness is the log file, which is read again when the panel starts again.
     */
    public static JSONObject startJavaUpdate(String approvedSignature) {
        if (!validSignature(approvedSignature))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.plan.signatureMissing"));
        // The turn covers the preparation and the launch. Then the script works outside the panel:
        // from there on it is covered by the on-disk list, which stops any other package job
        // until the restarted panel closes it.
        String id = "jdk-" + System.nanoTime();
        String refusal = PackageQueue.take(id, I18n.tr("server.um.startJavaUpdate.1"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        try { return startJavaUpdateNow(approvedSignature); }
        finally { PackageQueue.release(id); }
    }

    /** The exact plan to upgrade the JVM: the same computation as for Roundcube and the guided update. */
    private static JSONObject javaPlan(String pkg) {
        return judged(PackagePlan.planFor(java.util.List.of(pkg), lockedNames(),
                UpdateManager::reasonNotToUnlock, UpdateManager::installedFamilyTwin));
    }

    /**
     * What the script must know, decided by the panel before shutting down.
     *
     * @param unlock       the locks the plan removes (the JVM and the locked dependencies): removed before
     *                     downloading, put back after, and written into the on-disk list that the restarted
     *                     panel reads again
     * @param service      true if the panel was started by the service: then it is started again with the service
     * @param port         the port the panel answers on now (of the web part, if separated); 0 if unknown
     * @param listenerUser the user that must hold that port after the restart (daemoxcp_mail if separated), or empty
     * @param webSupervisorPidFile the pidfile of the web part's supervisor, or empty if the panel is not separated
     * @param panelLog     the panel log (PANEL_LOG; another one only in the tests)
     */
    record JavaScriptPlan(String pkg, String home, String backupDir, String log, long pid, java.util.List<String> unlock,
                          String startLine, String dir, boolean service, int port, String listenerUser,
                          String webSupervisorPidFile, String panelLog) { }

    private static JSONObject startJavaUpdateNow(String approvedSignature) {
        try {
            JSONObject pf = javaPreflight();
            if (!pf.optBoolean("canProceed", false))
                return new JSONObject().put("success", false)
                        .put("error", pf.optBoolean("already", false)
                                ? I18n.tr("server.um.x.alreadyLatest") : I18n.tr("server.um.startJavaUpdateNow.1"));
            // Is the plan recomputed now the one read on the page? Otherwise we do not start.
            if (!planAccepted(approvedSignature, pf.optString("signature", ""), pf.optJSONObject("plan")))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.plan.changedSinceRead"));
            String pkg = pf.getString("pkg");
            if (!isValidName(pkg)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
            // The locks to remove are exactly those of the plan (the JVM, if locked, and the locked
            // dependencies): put back at the end, not one more nor one fewer.
            java.util.List<String> unlock = new ArrayList<>();
            for (String n : jsonArrayToList(pf.optJSONArray("unlock") == null ? new JSONArray() : pf.getJSONArray("unlock"))) {
                if (!isValidName(n)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
                if (!unlock.contains(n)) unlock.add(n);
            }
            JSONObject st = pf.getJSONObject("restart");
            // In UTC, like every date that is written (the name of the folder and of the report too).
            String ts = sh("date -u '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.10"));
            String bk = JDK_DIR + "/" + ts;
            String log = bk + ".log";
            if (!ok("mkdir -p " + bk, 30))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startJavaUpdateNow.2", java.util.Map.of("backup", String.valueOf(bk))));

            long pid = ProcessHandle.current().pid();
            // When separated, the port is held by the web part (user daemoxcp_mail), not by this process: asked
            // of this one, the port was 0 and the script skipped the check, declaring successful a panel that was
            // never checked (finding 195). And after the restart daemoxcp_mail must still hold it: if root held
            // it, the separation would not have come back.
            int port = listeningPort(pid);
            String listenerUser = "", webSupervisor = "";
            if (PanelSeparation.active()) {
                int webPort = listeningPort(PanelSeparation.readPid(PanelSeparation.webPid()));
                if (webPort > 0) port = webPort;
                listenerUser = PanelSeparation.USER;
                webSupervisor = PanelSeparation.supervisorPid().toString();
            }

            String script = javaUpdateScript(new JavaScriptPlan(pkg, pf.optString("home"), bk, log, pid, unlock,
                    st.getString("line"), st.getString("dir"), st.optBoolean("service"), port, listenerUser, webSupervisor, PANEL_LOG));
            String path = bk + "/upgrade-jdk.sh";
            Files.writeString(Paths.get(path), script);
            ok("chmod 700 " + path, 15);

            // A script that cannot be parsed is not run: better to find out now than with the panel off.
            String syntaxCheck = sh("sh -n " + path + " 2>&1", 30);
            if (!syntaxCheck.trim().isEmpty())
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.startJavaUpdateNow.4", java.util.Map.of("trim", String.valueOf(syntaxCheck.trim()))));

            // The panel marks the unlocked packages: if the script died halfway, at the next
            // startup restoreLocksAfterCrash() locks them again by itself. If the list cannot be
            // written, the script does not start. As long as the list is there, no other package job
            // starts: the script works outside the panel, and the panel's turn does not see it.
            String stateError = PackageQueue.writeStateForRestart(unlock);
            if (stateError != null)
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.startJavaUpdateNow.5", java.util.Map.of("stateError", String.valueOf(stateError))));
            if (!ok("/usr/sbin/daemon -f -- /bin/sh " + path, 30)) {
                clearState();
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.startJavaUpdateNow.6", java.util.Map.of("path", String.valueOf(path))));
            }
            return new JSONObject().put("success", true).put("log", log)
                    .put("note", st.getString("note"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("startJavaUpdateNow", e));
        }
    }

    /**
     * The Java update in progress now, or null: the list of unlocked packages written for the script (which
     * waits for the panel restart), and the script's log without its end, touched less than 30 minutes ago. An
     * older log without an end is a dead script: then the usual warning about the list applies.
     */
    static JSONObject javaUpdateInProgress() {
        if (!PackageQueue.statePresent() || !PackageQueue.jobRecord().optBoolean("expectsRestart")) return null;
        JSONObject st = javaUpdateStatus();
        if (!st.optBoolean("present") || st.optBoolean("finished")) return null;
        try {
            long age = System.currentTimeMillis() - Files.getLastModifiedTime(Paths.get(st.getString("file"))).toMillis();
            return age < 30 * 60_000L ? st : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** The last report left by the script, to be read again once the panel is back up. */
    public static JSONObject javaUpdateStatus() {
        try {
            String last = sh("ls -1t " + JDK_DIR + "/*.log 2>/dev/null | head -1").trim();
            if (last.isEmpty())
                return new JSONObject().put("success", true).put("present", false);
            String text = sh("cat " + last + " 2>/dev/null", 30);
            // The log of a script written before 2026-10-29 has the old markers: they
            // are brought to the current names (data file), then only those are looked at.
            for (String[] m : LegacyNames.pairs("javaScriptOutcomes")) text = text.replace(m[0], m[1]);
            boolean finished = text.contains("=== OUTCOME:");
            boolean succeeded = text.contains("=== OUTCOME: SUCCEEDED");
            // The markers stay fixed in the file (they are read again above); to the reader they are
            // shown in their language
            String shown = text.replace("=== OUTCOME: SUCCEEDED", "=== " + I18n.tr("server.um.jvs.outcomeOk"))
                    .replace("=== OUTCOME: CANCELLED", "=== " + I18n.tr("server.um.jvs.outcomeCancelled"))
                    .replace("=== OUTCOME: TO CHECK", "=== " + I18n.tr("server.um.jvs.outcomeCheck"));
            return new JSONObject().put("success", true).put("present", true)
                    .put("file", last).put("text", shown).put("finished", finished)
                    .put("succeeded", succeeded);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("javaUpdateStatus", e));
        }
    }

    /**
     * The detached script that updates the JVM. In order: the way back, the download with the panel still
     * running, the stop (root part and web part), the update from the packages already downloaded, the java
     * test, the locks put back and the restart, then the check that the panel really answers.
     *
     * The lines it prints are in the language of whoever started the update; the "=== OUTCOME: ... ===" lines
     * stay fixed, because javaUpdateStatus reads them again. An {UPPERCASE} placeholder in the texts is a
     * variable of this script (echo): JavaUpdateScriptTest checks that each one is assigned here.
     */
    static String javaUpdateScript(JavaScriptPlan p) {
        // The title of the web supervisor, and the previous ones: the web part was started by the version that is
        // running.
        String title = "(" + String.join("|", PanelSeparation.titles()) + ")";
        StringBuilder s = new StringBuilder();
        java.util.function.Consumer<String> line = l -> s.append(l).append('\n');
        line.accept("#!/bin/sh");
        line.accept("# Generated by the panel: it updates the JVM the panel itself runs on.");
        line.accept("exec >> " + shellQuote(p.log()) + " 2>&1");
        line.accept("echo \"=== $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===\"");
        line.accept(echo(I18n.tr("server.um.jvs.title")));
        line.accept("PKG=" + shellQuote(p.pkg()));
        line.accept("BACKUP_DIR=" + shellQuote(p.backupDir()));
        line.accept("JAVA=" + shellQuote(p.home() + "/bin/java"));
        line.accept("UNLOCK=" + shellQuote(String.join(" ", p.unlock())));
        line.accept("PANEL_PID=" + p.pid());
        line.accept("PORT=" + Math.max(0, p.port()));
        line.accept("LISTENER_USER=" + shellQuote(p.listenerUser()));
        line.accept("SERVICE=" + (p.service() ? 1 : 0));
        line.accept("WEB_SUPERVISOR_PIDFILE=" + shellQuote(p.webSupervisorPidFile()));
        line.accept("WAY_BACK=''");
        line.accept("UPGRADE_RC=1");
        line.accept("DO_UPGRADE=1");
        line.accept("");
        line.accept("# The protections the plan removes, put back on what is still installed.");
        line.accept("relock() {");
        line.accept("  for NAME in $UNLOCK; do");
        line.accept("    pkg info -e \"$NAME\" || continue");
        line.accept("    if pkg lock -y \"$NAME\" >/dev/null 2>&1; then " + echo(I18n.tr("server.um.jvs.relocked"))
                + "; else " + echo(I18n.tr("server.um.jvs.relockFailed")) + "; fi");
        line.accept("  done");
        line.accept("}");
        line.accept("");
        line.accept(echo(I18n.tr("server.um.jvs.s1")));
        line.accept("if pkg create -o \"$BACKUP_DIR\" \"$PKG\"; then");
        line.accept("  # pkg create makes .pkg on recent versions and .txz on older ones: the way back is not");
        line.accept("  # tied to an extension, otherwise it would disappear for no reason.");
        line.accept("  WAY_BACK=$(ls -1 \"$BACKUP_DIR\"/\"$PKG\"-* 2>/dev/null | head -1)");
        line.accept("  if [ -n \"$WAY_BACK\" ]; then " + echo(I18n.tr("server.um.jvs.wayBack"))
                + "; else " + echo(I18n.tr("server.um.jvs.noFile")) + "; DO_UPGRADE=0; fi");
        line.accept("else");
        line.accept("  " + echo(I18n.tr("server.um.jvs.createFailed")) + "; DO_UPGRADE=0");
        line.accept("fi");
        line.accept("");
        line.accept(echo(I18n.tr("server.um.jvs.s2")));
        line.accept("if [ $DO_UPGRADE -eq 1 ]; then");
        line.accept("  for NAME in $UNLOCK; do pkg unlock -y \"$NAME\"; done");
        line.accept("  # Only the download (-F): the panel still answers, and the packages stay as they are.");
        line.accept("  if ! pkg upgrade -F -y \"$PKG\"; then " + echo(I18n.tr("server.um.jvs.fetchFailed")) + "; DO_UPGRADE=0; fi");
        line.accept("fi");
        line.accept("if [ $DO_UPGRADE -eq 0 ]; then");
        line.accept("  relock");
        line.accept("  " + echo(I18n.tr("server.um.jvs.cancelRestart")));
        line.accept("fi");
        line.accept("");
        line.accept(echo(I18n.tr("server.um.jvs.s3")));
        line.accept("kill \"$PANEL_PID\" 2>/dev/null");
        line.accept("i=0");
        line.accept("while kill -0 \"$PANEL_PID\" 2>/dev/null; do");
        line.accept("  i=$((i+1)); [ $i -ge 45 ] && break; sleep 1");
        line.accept("done");
        line.accept("if kill -0 \"$PANEL_PID\" 2>/dev/null; then");
        line.accept("  " + echo(I18n.tr("server.um.jvs.forceKill")));
        line.accept("  kill -9 \"$PANEL_PID\" 2>/dev/null; sleep 2");
        line.accept("fi");
        line.accept(echo(I18n.tr("server.um.jvs.stopped")));
        line.accept("# The root part stops the web part on its way out; killed by force it cannot, and a web part left");
        line.accept("# running would keep the port and the old JVM. Its supervisor is recognised by its title.");
        line.accept("if [ -n \"$WEB_SUPERVISOR_PIDFILE\" ]; then");
        line.accept("  WEB_SUPERVISOR=$(cat \"$WEB_SUPERVISOR_PIDFILE\" 2>/dev/null)");
        line.accept("  if [ -n \"$WEB_SUPERVISOR\" ] && ps -o command= -p \"$WEB_SUPERVISOR\" 2>/dev/null | grep -qE '^daemon: "
                + title + "\\['; then");
        line.accept("    kill \"$WEB_SUPERVISOR\" 2>/dev/null");
        line.accept("    k=0; while kill -0 \"$WEB_SUPERVISOR\" 2>/dev/null && [ $k -lt 30 ]; do k=$((k+1)); sleep 1; done");
        line.accept("    kill -0 \"$WEB_SUPERVISOR\" 2>/dev/null && kill -9 \"$WEB_SUPERVISOR\" 2>/dev/null");
        line.accept("    " + echo(I18n.tr("server.um.jvs.webStopped")));
        line.accept("  fi");
        line.accept("fi");
        line.accept("");
        line.accept(echo(I18n.tr("server.um.jvs.s4")));
        line.accept("if [ $DO_UPGRADE -eq 1 ]; then");
        line.accept("  if pkg upgrade -y \"$PKG\"; then UPGRADE_RC=0; else " + echo(I18n.tr("server.um.jvs.upgradeFailed")) + "; fi");
        line.accept("fi");
        line.accept("");
        line.accept(echo(I18n.tr("server.um.jvs.s5")));
        line.accept("if \"$JAVA\" -version 2>&1; then");
        line.accept("  " + echo(I18n.tr("server.um.jvs.javaOk")));
        line.accept("elif [ -n \"$WAY_BACK\" ]; then");
        line.accept("  " + echo(I18n.tr("server.um.jvs.javaKo")));
        line.accept("  if pkg add -f \"$WAY_BACK\"; then " + echo(I18n.tr("server.um.jvs.prevBack"))
                + "; else " + echo(I18n.tr("server.um.jvs.restoreFailed")) + "; fi");
        line.accept("  \"$JAVA\" -version 2>&1 || " + echo(I18n.tr("server.um.jvs.javaStillKo")));
        line.accept("  UPGRADE_RC=1");
        line.accept("else");
        line.accept("  " + echo(I18n.tr("server.um.jvs.javaStillKo")));
        line.accept("fi");
        line.accept("");
        line.accept(echo(I18n.tr("server.um.jvs.s6")));
        line.accept("relock");
        line.accept("mkdir -p " + shellQuote(java.nio.file.Paths.get(p.panelLog()).getParent().toString()));
        line.accept("# The log is appended forever: above 10 MB it is set aside, so it does not grow");
        line.accept("# without end and a copy of what was there before still remains.");
        line.accept("if [ -f " + shellQuote(p.panelLog()) + " ] && [ $(stat -f %z " + shellQuote(p.panelLog()) + ") -gt 10485760 ]; then");
        line.accept("  mv " + shellQuote(p.panelLog()) + " " + shellQuote(p.panelLog() + ".1"));
        line.accept("fi");
        line.accept("cd " + shellQuote(p.dir()) + " || " + echo(I18n.tr("server.um.jvs.noCd", java.util.Map.of("d", String.valueOf(p.dir())))));
        line.accept(p.startLine());
        line.accept("");
        line.accept(echo(I18n.tr("server.um.jvs.s7")));
        line.accept("PANEL_UP=1");
        line.accept("if [ \"$PORT\" -gt 0 ]; then");
        line.accept("  # Who holds the port, and whether an HTTPS server answers there (any status: the panel answers only");
        line.accept("  # to its name). -46l and not -4l: the JVM can open the socket in IPv6. The sixth column is the");
        line.accept("  # local address; its end is the port.");
        line.accept("  j=0; USER_NOW=''");
        line.accept("  while [ $j -lt 180 ]; do");
        line.accept("    USER_NOW=$(sockstat -46l -p \"$PORT\" 2>/dev/null | awk -v p=\"$PORT\" 'NR > 1 && $6 ~ (\"[:.]\" p \"$\") { print $1; exit }')");
        line.accept("    if [ -n \"$USER_NOW\" ] && curl -sk -m 5 -o /dev/null \"https://127.0.0.1:$PORT/index\"; then PANEL_UP=0; break; fi");
        line.accept("    j=$((j+1)); sleep 1");
        line.accept("  done");
        line.accept("  if [ $PANEL_UP -eq 0 ]; then " + echo(I18n.tr("server.um.jvs.listening", java.util.Map.of("port", String.valueOf(p.port()))))
                + "; else " + echo(I18n.tr("server.um.jvs.notListening", java.util.Map.of("port", String.valueOf(p.port())))) + "; fi");
        line.accept("  # Separated, the port must be held by the web part's user again: held by root, the panel came back");
        line.accept("  # without the separation, and that is not the state it was in.");
        line.accept("  if [ $PANEL_UP -eq 0 ] && [ -n \"$LISTENER_USER\" ] && [ \"$USER_NOW\" != \"$LISTENER_USER\" ]; then");
        line.accept("    " + echo(I18n.tr("server.um.jvs.wrongUser", java.util.Map.of("port", String.valueOf(p.port())))) + "; PANEL_UP=1");
        line.accept("  fi");
        line.accept("else");
        line.accept("  " + echo(I18n.tr("server.um.jvs.noPort")) + "; PANEL_UP=2");
        line.accept("fi");
        line.accept("# Started by the service, the service must see it again (its pidfile): otherwise a stop would not");
        line.accept("# stop it and a start would start a second one.");
        line.accept("if [ $SERVICE -eq 1 ] && ! /usr/sbin/service " + RC_NAME + " status >/dev/null 2>&1; then");
        line.accept("  " + echo(I18n.tr("server.um.jvs.serviceBlind")) + "; PANEL_UP=1");
        line.accept("fi");
        line.accept("");
        line.accept("if [ $DO_UPGRADE -eq 0 ]; then");
        line.accept("  echo \"=== OUTCOME: CANCELLED ($(date -u '+%Y-%m-%d %H:%M:%S UTC')) ===\"");
        line.accept("elif [ $UPGRADE_RC -eq 0 ] && [ $PANEL_UP -eq 0 ]; then");
        line.accept("  echo \"=== OUTCOME: SUCCEEDED ($(date -u '+%Y-%m-%d %H:%M:%S UTC')) ===\"");
        line.accept("  " + echo(I18n.tr("server.um.jvs.keepBack")));
        line.accept("  " + echo(I18n.tr("server.um.jvs.panelLog", java.util.Map.of("f", String.valueOf(p.panelLog())))));
        line.accept("else");
        line.accept("  echo \"=== OUTCOME: TO CHECK ($(date -u '+%Y-%m-%d %H:%M:%S UTC')) ===\"");
        line.accept("  echo \"upgrade=$UPGRADE_RC  panel_up=$PANEL_UP  way_back=$WAY_BACK\"");
        line.accept("fi");
        return s.toString();
    }

    /**
     * An "echo" line for a script: the text in single quotes, so the shell expands
     * nothing inside it; the {UPPERCASE} placeholders become shell variables.
     */
    private static String echo(String text) {
        StringBuilder sb = new StringBuilder("echo ");
        Matcher m = Pattern.compile("\\{([A-Z_]{1,20})\\}").matcher(text);
        int last = 0;
        while (m.find()) {
            sb.append(shellQuote(text.substring(last, m.start()))).append("\"$").append(m.group(1)).append('"');
            last = m.end();
        }
        return sb.append(shellQuote(text.substring(last))).toString();
    }

    private static String shellQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    // ===================== switch py311 -> py312 =====================

    /**
     * Reads the list of what "pkg autoremove" would remove.
     *
     * The point is not counting: it is being able to say NO. autoremove reasons about the whole
     * system, not only about Python, and once launched it asks nothing more. So either the list
     * is read in full and every name is recognized, or the cleanup is skipped. "readable" is
     * false also when the names read are fewer than those pkg declares: it would mean that
     * something escapes the reading, and it is exactly the line that escaped that would do damage.
     */
    static JSONObject analyzeAutoremove(String out, String expectedPrefix) {
        // The prefix arrives as "py311-": the version is derived from it to also recognize
        // the interpreter "python311", which is as much part of the family as the others.
        final String verPy = expectedPrefix != null && expectedPrefix.startsWith("py")
                ? expectedPrefix.replaceAll("[^0-9]", "") : "";
        JSONObject r = new JSONObject();
        java.util.List<String> removed = new ArrayList<>(), foreign = new ArrayList<>();
        String o = out == null ? "" : out;
        if (o.toLowerCase().contains("nothing to do")) {
            return r.put("readable", true).put("howMany", 0)
                    .put("removed", new JSONArray()).put("foreign", new JSONArray());
        }
        int declared = -1;
        java.util.regex.Matcher mn = Pattern.compile(
                "(?i)number of packages to be removed:\\s*([0-9]+)").matcher(o);
        if (mn.find()) declared = Integer.parseInt(mn.group(1));

        boolean inside = false;
        for (String line : o.split("\n")) {
            if (line.matches("(?i).*packages to be REMOVED:\\s*")) { inside = true; continue; }
            if (!inside) continue;
            if (line.trim().isEmpty()) { inside = false; continue; }
            java.util.regex.Matcher m = Pattern.compile(
                    "^[ \\t]+([A-Za-z0-9._+-]+):[ \\t]").matcher(line);
            if (!m.find()) { inside = false; continue; }
            removed.add(m.group(1));
            if (!(m.group(1).startsWith(expectedPrefix)
                    || (!verPy.isEmpty() && m.group(1).equals("python" + verPy))))
                foreign.add(m.group(1));
        }
        boolean readable = declared >= 0 && removed.size() == declared;
        return r.put("readable", readable)
                .put("howMany", declared < 0 ? removed.size() : declared)
                .put("removed", new JSONArray(removed))
                .put("foreign", new JSONArray(foreign));
    }


    /** Default Python version according to bsd.default-versions.mk, without the dot: "312". */
    private static String pyDefault() {
        // A single source: the same table that feeds the "Defaults consistency" tab.
        // If tomorrow the ports default moves to 3.13, this procedure follows it by itself.
        for (String[] line : DEFAULTS) {
            if ("Python".equals(line[0])) return line[1].replace(".", "");
        }
        return "312";
    }

    /**
     * Does a package belong to the old Python family?
     *
     * The "py311-" prefix is not enough: the interpreter is called "python311", without a hyphen,
     * and looking only for the prefix the panel declared it "unrelated to Python" -- an absurd
     * sentence for anyone reading it, and the symptom of a wrong classification. The family is
     * both.
     */
    static boolean pythonFamily(String name, String version) {
        return name != null && (name.startsWith("py" + version + "-") || name.equals("python" + version));
    }

    /** The py3XX-* installed on request (not pulled in as a dependency). They are the ones to move. */
    private static java.util.List<String> pythonToMove(String old) {
        java.util.List<String> l = new ArrayList<>();
        for (String r : sh("pkg query '%n %a' 2>/dev/null").split("\n")) {
            String[] c = r.trim().split("\\s+");
            if (c.length != 2) continue;
            if (c[0].startsWith("py" + old + "-") && "0".equals(c[1])) l.add(c[0]);
        }
        java.util.Collections.sort(l);
        return l;
    }

    /**
     * Preliminary checks, all read-only.
     *
     * py311 and py312 are not two versions of the same package: they are DIFFERENT packages, so
     * "pkg upgrade" will never touch them and they would stay on a Python that sooner or later
     * goes out of support. The move is done by hand, and has two points where something breaks:
     *  - the commands in /usr/local/bin (certbot, fail2ban-server) belong to ONE of the two, so
     *    they collide: they must be seen BEFORE, with a simulation;
     *  - "pkg autoremove" at the end can take away more than expected, because it reasons about
     *    the whole system and not only about Python. Here the list is looked at before running it.
     */
    public static JSONObject pythonPreflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean lock = false;
        try {
            String fresh = pyDefault();
            String old = null;
            for (String r2 : sh("pkg query %n 2>/dev/null").split("\n")) {
                java.util.regex.Matcher m = Pattern.compile("^py(3[0-9]{2})-").matcher(r2.trim());
                if (m.find() && !m.group(1).equals(fresh)) {
                    if (old == null || m.group(1).compareTo(old) < 0) old = m.group(1);
                }
            }
            r.put("newVersion", fresh);
            if (old == null) {
                addCheck(checks, "ver", I18n.tr("server.um.pythonPreflight.1"), "ok",
                        I18n.tr("server.um.pythonPreflight.2", java.util.Map.of("newer", String.valueOf(fresh))));
                return r.put("success", true).put("checks", checks)
                        .put("canProceed", false).put("blocked", false).put("already", true);
            }
            r.put("old", old);
            addCheck(checks, "ver", I18n.tr("server.um.pythonPreflight.1"), "wait",
                    I18n.tr("server.um.pythonPreflight.3", java.util.Map.of("old", String.valueOf(old), "newer", String.valueOf(fresh))));

            final String vec = old;
            java.util.List<String> leaf = pythonToMove(vec);
            long tot = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + vec + "-")).count();
            if (leaf.isEmpty()) {
                addCheck(checks, "leaf", I18n.tr("server.um.pythonPreflight.4"), "block",
                        I18n.tr("server.um.pythonPreflight.5", java.util.Map.of("tot", String.valueOf(tot), "old", String.valueOf(old))));
                lock = true;
            } else {
                addCheck(checks, "leaf", I18n.tr("server.um.pythonPreflight.4"), "ok",
                        String.join(", ", leaf) + "  " + I18n.tr("server.um.x.pyDepsFollow", java.util.Map.of("n", String.valueOf((tot - leaf.size())))));
            }
            r.put("leaf", new JSONArray(leaf));

            // Is there a matching py312 for each one? Without it, the move would leave a hole.
            java.util.List<String> newOnes = new ArrayList<>(), missing = new ArrayList<>();
            for (String v : leaf) {
                String n = "py" + fresh + "-" + v.substring(("py" + old + "-").length());
                if (!isValidName(n)) continue;
                if (sh("pkg rquery -U %n " + n + " 2>/dev/null").trim().isEmpty()) missing.add(n);
                else newOnes.add(n);
            }
            r.put("newPackages", new JSONArray(newOnes));
            if (!missing.isEmpty()) {
                addCheck(checks, "repo", I18n.tr("server.um.pythonPreflight.6"), "block",
                        I18n.tr("server.um.x.pyNoCounterpart", java.util.Map.of("newer", String.valueOf(fresh), "list", String.valueOf(String.join(", ", missing)))));
                lock = true;
            } else if (!newOnes.isEmpty()) {
                addCheck(checks, "repo", I18n.tr("server.um.pythonPreflight.6"), "ok",
                        I18n.tr("server.um.x.pyAllCounterparts", java.util.Map.of("list", String.valueOf(String.join(", ", newOnes)))));
            }

            // Who depends on the packages I am about to remove? If someone depends on them, removing
            // them would take it away too: that is exactly the case not to discover after the fact.
            // Beware of the obvious that is not obvious: py311-certbot-nginx DEPENDS on py311-certbot,
            // and they move together. A dependent that belongs to the same py<old> family is not a
            // problem, because it too disappears and is reborn. The problem is only an EXTERNAL
            // dependent, which would be left without what it depends on.
            java.util.List<String> withDependents = new ArrayList<>();
            for (String v : leaf) {
                if (!isValidName(v)) continue;
                java.util.List<String> external = new ArrayList<>();
                for (String d : sh("pkg query %rn " + v + " 2>/dev/null").split("\n")) {
                    String t = d.trim();
                    if (t.isEmpty() || t.startsWith("py" + vec + "-")) continue;
                    external.add(t);
                }
                if (!external.isEmpty()) withDependents.add(v + " <- " + String.join(", ", external));
            }
            if (!withDependents.isEmpty()) {
                addCheck(checks, "dependents", I18n.tr("server.um.pythonPreflight.7"), "block",
                        I18n.tr("server.um.x.rmPullsOthers", java.util.Map.of("list", String.valueOf(String.join(" ; ", withDependents)))));
                lock = true;
            } else {
                addCheck(checks, "dependents", I18n.tr("server.um.pythonPreflight.7"), "ok",
                        I18n.tr("server.um.pythonPreflight.8"));
            }

            // A real simulation: it is the only way to know which files collide.
            if (!newOnes.isEmpty()) {
                String sim = sh("pkg install -n " + String.join(" ", newOnes) + " 2>&1", 300);
                boolean conflicts = sim.toLowerCase().contains("conflicts with");
                r.put("conflict", conflicts);
                if (conflicts) {
                    java.util.List<String> lines = new ArrayList<>();
                    for (String l2 : sim.split("\n")) if (l2.toLowerCase().contains("conflict")) lines.add(l2.trim());
                    addCheck(checks, "sim", I18n.tr("server.um.pythonPreflight.9"), "wait",
                            I18n.tr("server.um.x.pyCollide", java.util.Map.of("lines", String.valueOf(String.join(" | ", lines)), "old", String.valueOf(old))));
                } else {
                    addCheck(checks, "sim", I18n.tr("server.um.pythonPreflight.9"), "ok",
                            I18n.tr("server.um.pythonPreflight.10"));
                }
            }

            // Services involved: those must be stopped and restarted, and checked afterwards.
            java.util.List<String> touchedServices = new ArrayList<>();
            for (String v : leaf) {
                String base = v.substring(("py" + old + "-").length());
                String svc = realServiceName(base);
                if (svc != null) touchedServices.add(svc);
            }
            r.put("services", new JSONArray(touchedServices));
            addCheck(checks, "svc", I18n.tr("server.um.x.servicesInvolved"), "ok", touchedServices.isEmpty()
                    ? I18n.tr("server.um.pythonPreflight.11")
                    : I18n.tr("server.um.x.svcStopStart", java.util.Map.of("list", String.valueOf(String.join(", ", touchedServices)))));

            // What autoremove would remove. If it touches stuff that is not py<old>, it is not run.
            JSONObject an = analyzeAutoremove(sh("pkg autoremove -n 2>&1", 180), "py" + vec + "-");
            java.util.List<String> foreign = jsonArrayToList(an.optJSONArray("foreign"));
            r.put("autoremoveForeign", new JSONArray(foreign));
            if (!an.optBoolean("readable", false)) {
                addCheck(checks, "auto", I18n.tr("server.um.x.autoremoveTitle"), "wait",
                        I18n.tr("server.um.pythonPreflight.12"));
            } else {
                addCheck(checks, "auto", I18n.tr("server.um.x.autoremoveTitle"), foreign.isEmpty() ? "ok" : "wait",
                        foreign.isEmpty()
                        ? (an.optInt("howMany", 0) == 0 ? I18n.tr("server.um.x.noOrphans")
                           : I18n.tr("server.um.x.onlyPyOrphans", java.util.Map.of("oldVer", String.valueOf(vec), "n", String.valueOf(an.optInt("howMany", 0)))))
                        : I18n.tr("server.um.x.foreignOrphans", java.util.Map.of("list", String.valueOf(String.join(", ", foreign)))));
            }

            addCheck(checks, "backup", I18n.tr("server.um.pythonPreflight.13"), "ok",
                    I18n.tr("server.um.pythonPreflight.14"));

            // The EXACT plan of the move, as in the guided update: on a copy of the pkg
            // database, what pkg delete will remove (the packages and whoever depends on
            // them) is forgotten and pkg is asked what it would install. It is signed and approved.
            if (!lock && !newOnes.isEmpty()) {
                java.util.List<String> removed = reverseClosure(leaf);
                JSONObject plan = pythonPlan(removed, newOnes);
                java.util.List<String> family = new ArrayList<>(removed);
                family.addAll(newOnes);
                // A counterpart already installed (py312-packaging, a dependency of another one)
                // does not change in the plan, and that is right: the job only has to remove the
                // old one. The "would not change" check applies to the ones the job really installs.
                java.util.List<String> toInstall = new ArrayList<>();
                for (String n : newOnes) if (!ok("pkg info -e " + n, 15)) toInstall.add(n);
                if (addPlanChecks(checks, plan, toInstall, family, lock)) lock = true;
                r.put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""))
                 .put("removedFirst", new JSONArray(removed));
            }

            r.put("success", true).put("checks", checks)
             .put("blocked", lock).put("canProceed", !lock && !newOnes.isEmpty());
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("pythonPreflight", e));
        }
    }

    /**
     * The leftovers of the old Python family, removed one by one instead of with autoremove.
     *
     * autoremove reasons about the whole system: here it would also take away capstone, which has
     * nothing to do with Python, and for this reason it is rightly skipped. But that way the old
     * interpreter stays installed with its vulnerabilities. The way out is not to run autoremove
     * turning a blind eye: it is to remove ONLY the packages of the family, one at a time, each
     * after checking that nobody requires it any more. That way the list of what disappears is
     * written in full before starting, and contains no surprises.
     *
     * In repeated passes because dependencies free up in a chain: as long as py311-pyinotify
     * is there, python311 has a dependent and cannot be removed; once that is removed, it can be.
     */
    /**
     * Who refers to the old interpreter, among the things that WILL REMAIN.
     *
     * pkg knows the dependencies between packages, not a file written by hand with
     * "#!/usr/local/bin/python3.11" at the top. That is the only thing the removal could
     * break without any automatic check noticing, and it is the reason why
     * this check exists.
     *
     * The right question is not "does anyone name python3.11?" -- the py311 themselves do, and
     * they are about to disappear -- but "does something that will survive name it?". For each
     * file found pkg is asked whose it is: if it belongs to the family being removed, it
     * disappears with it and is not a problem; if it belongs to ANOTHER package, or to none
     * because a person wrote it, then it is exactly the case to report.
     */
    static JSONObject interpreterReferences(String old) {
        JSONObject r = new JSONObject();
        JSONArray issues = new JSONArray(), harmless = new JSONArray(), quotes = new JSONArray();
        // 311 -> 3\.11 : the dot must be escaped, otherwise in the regex it matches any
        // character and "python3x11" would be counted as a reference.
        String escapedOld = old.length() == 3
                ? old.charAt(0) + "\\." + old.substring(1) : old;

        // I look for whoever EXECUTES the interpreter, not whoever names it. The difference is not
        // theoretical: the first version of this check found /home/panel/admin/updates.html, that
        // is the panel page -- and the line that triggered it was the warning I wrote myself,
        // which contains "#!/usr/local/bin/python3.11" as an example. A text that talks about
        // the interpreter does not execute it.
        //
        // The three forms that really execute it:
        //   - the #! line at the top of a script
        //   - the full path of the binary, which is how cron and the rc scripts invoke it
        //   - "env python3.11", the other common form of shebang
        String[] modes = {
            "^#!.*python" + escapedOld,
            "/usr/local/bin/python" + escapedOld,
            "env[[:space:]]+python" + escapedOld,
        };
        StringBuilder e = new StringBuilder();
        for (String m : modes) e.append("-e '").append(m).append("' ");

        String where = "/etc /usr/local/etc /usr/local/bin /usr/local/sbin /usr/local/libexec "
                + "/usr/local/www /root /var/cron /var/spool/cron /home";
        // Left out: the files of the Python packages (they disappear with them) and the pages the panel
        // generates by itself. Those are nobody's scripts: I write them at every startup.
        String mineOutside = "";
        try {
            String jar = jarPath();
            if (!jar.isEmpty()) {
                String dirJar = Paths.get(jar).getParent().toString();
                mineOutside = " | grep -v '^" + dirJar + "/admin/'";
            }
        } catch (Exception ignored) { }

        String cmd = "grep -rIl " + e.toString().trim() + " " + where
                + " 2>/dev/null | grep -v '^/usr/local/lib/python'"
                + " | grep -viE '\\.(html?|md|log|bak|orig|sample)$'" + mineOutside + " | head -300";
        String out = sh(cmd, 300);
        int reviewed = 0;
        for (String f : out.split("\n")) {
            String file = f.trim();
            if (file.isEmpty()) continue;
            reviewed++;
            String prop = sh("pkg which -q " + file + " 2>/dev/null", 20).trim();
            String name = prop.isEmpty() ? "" : sh("pkg query %n " + prop + " 2>/dev/null", 20).trim();
            boolean ofFamily = !name.isEmpty() && pythonFamily(name, old);

            // A file that NAMES the path of the interpreter does not necessarily execute it: a text
            // that quotes it matches just like a script that launches it, and grep cannot tell them
            // apart. The difference is made by two verifiable facts: the file is executable, or it
            // is where the system goes to fetch things to execute (cron, rc.d). Everything else is
            // very probably prose, and must not block a legitimate removal -- but it still ends
            // up in a separate list, because "probable" is not "certain".
            boolean runnable = ok("test -x " + file, 10);
            boolean executionPlace = file.startsWith("/var/cron/") || file.startsWith("/var/spool/cron/")
                    || file.startsWith("/usr/local/etc/rc.d/") || file.startsWith("/etc/rc.d/")
                    || file.startsWith("/etc/periodic/") || file.startsWith("/usr/local/etc/periodic/")
                    || file.equals("/etc/crontab") || file.startsWith("/etc/rc.conf");
            // The line that triggered the check: without it, the reader cannot judge
            // whether it is a real execution or a quotation.
            String line = sh("grep -m1 -hIE " + e.toString().trim().replace("-e ", "-e ")
                    + " " + file + " 2>/dev/null | head -c 160", 20).trim();
            JSONObject v = new JSONObject().put("file", file).put("line", line)
                    .put("owner", name.isEmpty()
                            ? (prop.isEmpty() ? I18n.tr("server.um.interpreterReferences.1") : prop) : name);
            v.put("runnable", runnable).put("executionPlace", executionPlace);
            if (ofFamily) harmless.put(v);
            else if (runnable || executionPlace) issues.put(v);
            else quotes.put(v);
        }
        return r.put("reviewed", reviewed).put("issues", issues).put("harmless", harmless)
                .put("quotes", quotes).put("command", cmd);
    }

    /** The leftovers of the old Python; with execute, it removes them, in the package turn. */
    public static JSONObject pythonLeftovers(boolean run) {
        if (!run) return pythonLeftoversNow(false);
        String id = "restipy-" + System.nanoTime();
        String refusal = PackageQueue.take(id, I18n.tr("server.um.pythonLeftovers.1"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        try { return pythonLeftoversNow(true); }
        finally { refreshLockTrace(); PackageQueue.release(id); }
    }

    private static JSONObject pythonLeftoversNow(boolean run) {
        JSONObject r = new JSONObject();
        try {
            String fresh = pyDefault();
            java.util.LinkedHashSet<String> old = new java.util.LinkedHashSet<>();
            for (String n : sh("pkg query %n 2>/dev/null").split("\n")) {
                Matcher m = Pattern.compile("^(?:py|python)(3[0-9]{2})(?:-|$)").matcher(n.trim());
                if (m.find() && !m.group(1).equals(fresh)) old.add(m.group(1));
            }
            if (old.isEmpty())
                return r.put("success", true).put("nothing", true)
                        .put("note", I18n.tr("server.um.pythonLeftoversNow.1", java.util.Map.of("newer", String.valueOf(fresh))));
            r.put("old", new JSONArray(old));

            java.util.List<String> family = new ArrayList<>();
            for (String v : old)
                for (String n : sh("pkg query %n 2>/dev/null").split("\n"))
                    if (pythonFamily(n.trim(), v)) family.add(n.trim());

            JSONArray detail = new JSONArray();
            java.util.List<String> removable = new ArrayList<>(), heldBack = new ArrayList<>();
            for (String n : family) {
                if (!isValidName(n)) continue;
                String ver = sh("pkg query %v " + n + " 2>/dev/null", 20).trim();
                long kb = number(sh("pkg query %sb " + n + " 2>/dev/null", 20)) / 1024;
                java.util.List<String> who = new ArrayList<>();
                for (String d : sh("pkg query %rn " + n + " 2>/dev/null").split("\n")) {
                    String t = d.trim();
                    if (!t.isEmpty()) who.add(t);
                }
                // A dependent that also belongs to the family will disappear first: it does not hold back.
                java.util.List<String> external = new ArrayList<>();
                for (String c : who) if (!family.contains(c)) external.add(c);
                boolean free = external.isEmpty();
                (free ? removable : heldBack).add(n);
                detail.put(new JSONObject().put("name", n).put("version", ver).put("kb", kb)
                        .put("free", free).put("heldBackBy", new JSONArray(external)));
            }
            r.put("detail", detail).put("removable", new JSONArray(removable))
             .put("heldBack", new JSONArray(heldBack));

            // Who names the old interpreter among what remains: pkg does not know, it must be searched for.
            JSONObject ref = interpreterReferences(old.iterator().next());
            r.put("references", ref);
            if (!run || removable.isEmpty()) return r.put("success", true).put("executed", false);
            if (ref.getJSONArray("issues").length() > 0)
                return r.put("success", false).put("executed", false)
                        .put("error", I18n.tr("server.um.x.pyRefsLeft", java.util.Map.of("n", String.valueOf(ref.getJSONArray("issues").length()))));

            // Repeated passes: at each round the ones removed are those that at THAT moment no
            // longer have anyone requiring them.
            JSONArray removed = new JSONArray(), failed = new JSONArray();
            java.util.List<String> remaining = new ArrayList<>(family);
            for (int round = 0; round < 6 && !remaining.isEmpty(); round++) {
                boolean something = false;
                for (String n : new ArrayList<>(remaining)) {
                    if (!isValidName(n) || !ok("pkg info -e " + n, 15)) { remaining.remove(n); continue; }
                    String dependents = sh("pkg query %rn " + n + " 2>/dev/null").trim();
                    if (!dependents.isEmpty()) continue;                      // still required: on the next round
                    boolean wasLocked = locked(sh("pkg lock -l 2>/dev/null"), n);
                    if (wasLocked) ok("pkg unlock -y " + n, 30);
                    if (ok("pkg delete -y " + n, 300)) { removed.put(n); something = true; }
                    else {
                        failed.put(n);
                        // If the removal does not succeed, the package stays: and then it must stay
                        // as it was, locked. Unlocking it and leaving it like that would be worse
                        // than not having tried, because the next update could touch it.
                        if (wasLocked) ok("pkg lock -y " + n, 30);
                    }
                    remaining.remove(n);
                }
                if (!something) break;
            }
            r.put("executed", true).put("removed", removed).put("failed", failed)
             .put("remain", new JSONArray(remaining));
            // Check: how many packages of the old family are still installed.
            long still = 0;
            for (String v : old)
                still += sh("pkg query %n 2>/dev/null").lines().filter(x -> pythonFamily(x, v)).count();
            r.put("stillPresent", still);
            return r.put("success", true);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("pythonLeftoversNow", e));
        }
    }

    /**
     * What {@code pkg delete -y nomi} without -f really removes: those packages and, in a chain,
     * whoever depends on them. Read with pkg query, which does not look at locks: pkg delete -n on a
     * locked package refuses, and here they are all locked.
     */
    static java.util.List<String> reverseClosure(java.util.List<String> names) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        java.util.ArrayDeque<String> todo = new java.util.ArrayDeque<>();
        for (String n : names) if (isValidName(n) && out.add(n)) todo.add(n);
        while (!todo.isEmpty()) {
            String n = todo.poll();
            for (String d : sh("pkg query %rn " + n + " 2>/dev/null").split("\n")) {
                String t = d.trim();
                if (isValidName(t) && out.add(t)) todo.add(t);
            }
        }
        return new ArrayList<>(out);
    }

    /** The exact plan of the Python move: remove 'removed', then install 'newOnes'. */
    private static JSONObject pythonPlan(java.util.List<String> removed, java.util.List<String> newOnes) {
        return judged(PackagePlan.planRemoveThenInstall(removed, newOnes, lockedNames(), UpdateManager::reasonNotToUnlock));
    }

    /**
     * @param approvedSignature the signature of the plan that whoever presses has read: the job recomputes the
     *                          plan and starts only if it is the same (see startGuidedUpdate)
     */
    public static JSONObject startPythonTransition(String approvedSignature) {
        if (!validSignature(approvedSignature))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.plan.signatureMissing"));
        String id = "py-" + System.currentTimeMillis();
        Job j = new Job(id, "python");
        return startOnTurn(id, j, I18n.tr("server.um.startPythonTransition.1"), "python-move",
                () -> runPythonTransition(j, approvedSignature));
    }

    private static void runPythonTransition(Job job, String approvedSignature) {
        job.status = "running";
        final int TOT = 7;
        boolean installedNew = false;
        // The list written to disk by this run: empty until it is written.
        java.util.List<String> listOnDisk = new ArrayList<>();
        Map<String, Boolean> servicesBefore = servicesState();
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        PlanOutcome outcome = null;
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runPythonTransition.1"));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = pythonPreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("already", false)
                        ? I18n.tr("server.um.runPythonTransition.2") : I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.write("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            String old = pf.getString("old"), fresh = pf.getString("newVersion");
            java.util.List<String> leaf = jsonArrayToList(pf.optJSONArray("leaf"));
            java.util.List<String> newOnes = jsonArrayToList(pf.optJSONArray("newPackages"));
            java.util.List<String> services = jsonArrayToList(pf.optJSONArray("services"));
            job.write("  py" + old + " -> py" + fresh);
            job.write("  " + String.join(", ", leaf));
            // The plan that was read is carried out, or nothing is: before the copies and before
            // stopping any service.
            JSONObject plan = pf.optJSONObject("plan");
            String mismatch = approvedPlanMismatch(job, plan, pf.optString("signature", null), approvedSignature);
            if (mismatch != null) {
                job.status = "error";
                job.errorMessage = mismatch;
                return;
            }
            // The packages the plan installs are downloaded and the plan is computed again: until they
            // are in the cache pkg does not see the file conflicts (see fetchAndRecheck).
            java.util.List<String> downloads = planDownloads(plan);
            if (!downloads.isEmpty()) {
                Recheck grown = fetchAndRecheck(job, "pkg fetch -y -U " + String.join(" ", downloads) + " 2>&1", plan,
                        () -> pythonPlan(reverseClosure(leaf), newOnes));
                if (grown.stop() != null) throw org.daemoxcp.mail.util.ShownException.translated(grown.stop());
                plan = grown.plan();
            }
            // The inventory, the configuration and the addresses listening now, before stopping the
            // services: it is what the administrator left, and what the end is compared against.
            PlanWatch watch = PlanWatch.take(sideEffects);

            job.advance(2, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.3", java.util.Map.of("total", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            String bk = "/var/db/daemoxcp-mail/python/" + ts;
            if (!ok("mkdir -p " + bk, 30)) throw new IllegalStateException("cannot create " + bk);
            sh("pkg query '%n %v' > " + bk + "/packages-before.txt 2>/dev/null", 60);
            for (String d : new String[]{"/usr/local/etc/fail2ban", "/usr/local/etc/letsencrypt"}) {
                if (!ok("test -d " + d, 10)) { job.write(I18n.tr("server.um.runPythonTransition.5", java.util.Map.of("d", String.valueOf(d)))); continue; }
                String name = d.substring(d.lastIndexOf('/') + 1);
                if (!ok("tar -cf " + bk + "/" + name + ".tar -C " + d + " . 2>/dev/null", 300))
                    throw new IllegalStateException("copy of " + d + " failed");
                long n = number(sh("tar -tf " + bk + "/" + name + ".tar 2>/dev/null | wc -l", 60));
                if (n < 1) throw new IllegalStateException("the copy of " + d + " is empty");
                job.write("    " + d + " -> " + name + ".tar " + I18n.tr("server.um.x.entries", java.util.Map.of("n", String.valueOf(n))));
            }
            job.write("    " + I18n.tr("server.um.x.copiesIn", java.util.Map.of("dir", String.valueOf(bk))));

            job.advance(3, TOT);
            job.write("");
            job.write("[3/" + TOT + "] " + I18n.tr("server.um.x.stoppingSvcs"));
            if (services.isEmpty()) job.write("    " + I18n.tr("server.um.x.none"));
            for (String s : services) {
                boolean wasActive = ok("service " + s + " status", 20);
                if (wasActive) { ok("service " + s + " stop", 120); job.write(I18n.tr("server.um.runPythonTransition.6", java.util.Map.of("s", String.valueOf(s)))); }
                else job.write("    " + s + ": " + I18n.tr("server.um.x.wasStopped"));
            }

            job.advance(4, TOT);
            job.write("");
            job.write("[4/" + TOT + "] " + I18n.tr("server.um.x.pySwap", java.util.Map.of("old", String.valueOf(old), "newer", String.valueOf(fresh))));
            // The on-disk list BEFORE unlocking: the locks the plan removes (the old ones, which
            // must be locked again if they remain, and the dependencies) and the new ones, which
            // must be locked at the end. If the panel dies in the middle, the startup locks those
            // it finds installed. If the list cannot be written, nothing is touched.
            listOnDisk.addAll(unlockForPlan(job, plan, newOnes));
            // The order matters: first remove, then install. That way no file has to be forced,
            // which is exactly the error that broke the MySQL client.
            StringBuilder catDel = new StringBuilder();
            int cd = runLogged(job, "pkg delete -y " + String.join(" ", leaf) + " 2>&1", 900, catDel);
            StringBuilder catIns = new StringBuilder();
            int ci = -1;
            if (cd == 0) {
                // -U: the same catalog the plan was computed on.
                ci = runLogged(job, "pkg install -y -U " + String.join(" ", newOnes) + " 2>&1", 1800, catIns);
                // 4 = EX_NEEDRESTART: pkg upgraded itself and stopped there.
                if (ci == 4) {
                    job.write(I18n.tr("server.um.runGuidedUpdate.10"));
                    ci = runLogged(job, "pkg install -y -U " + String.join(" ", newOnes) + " 2>&1", 1800, catIns);
                }
            }
            // The comparison with the plan before deciding whether to stop: a pkg that ended badly is
            // exactly the case in which the machine may have been left halfway. The services restart
            // further down.
            outcome = checkPlanOutcome(job, watch, plan, "Python transition", !services.isEmpty());
            if (cd != 0) throw new IllegalStateException("pkg delete exited with code " + cd);
            if (ci != 0) {
                job.write("");
                job.write(I18n.tr("server.um.runPythonTransition.7"));
                job.write(I18n.tr("server.um.x.toGoBack", java.util.Map.of("cmd", String.valueOf("pkg install -y " + String.join(" ", leaf)))));
                throw new IllegalStateException("pkg install exited with code " + ci);
            }
            if (outcome.mapsProblem() != null) throw org.daemoxcp.mail.util.ShownException.translated(outcome.mapsProblem());
            installedNew = true;
            for (String m : messagesAskingForAction(catIns.toString()))
                job.write("    " + I18n.tr("server.um.x.pkgAsks", java.util.Map.of("m", String.valueOf(m.replace("\n", " | ")))));

            job.advance(5, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.8", java.util.Map.of("total", String.valueOf(TOT))));
            String ar = sh("pkg autoremove -n 2>&1", 180);
            JSONObject an = analyzeAutoremove(ar, "py" + old + "-");
            java.util.List<String> foreign = jsonArrayToList(an.optJSONArray("foreign"));
            if (!an.optBoolean("readable", false)) {
                job.write(I18n.tr("server.um.runPythonTransition.9"));
                job.write(I18n.tr("server.um.runPythonTransition.10"));
                for (String l2 : ar.split("\n")) if (!l2.trim().isEmpty()) job.write("      " + l2);
            } else if (!foreign.isEmpty()) {
                job.write("    " + I18n.tr("server.um.x.skippedForeign", java.util.Map.of("list", String.valueOf(String.join(", ", foreign)))));
                job.write(I18n.tr("server.um.runPythonTransition.11", java.util.Map.of("old", String.valueOf(old))));
            } else if (an.optInt("howMany", 0) == 0) {
                job.write(I18n.tr("server.um.runPythonTransition.12"));
            } else {
                // The autoremove has its exact plan too: the list just read, all of it from
                // the old family. It is run and the inventory is compared with that list: one
                // extra package removed is a divergence, as in the signed plan.
                JSONObject autoremovePlan = PackagePlan.readPlan(ar);
                if (!autoremovePlan.optBoolean("measured")) {
                    job.write(I18n.tr("server.um.runPythonTransition.9"));
                    job.write(I18n.tr("server.um.runPythonTransition.10"));
                } else {
                    job.write("    " + I18n.tr("server.um.x.toRemove", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(an.optJSONArray("removed")))))));
                    Map<String, String> beforeAutoremove = PackagePlan.versionsOnly(PackagePlan.installed());
                    runLogged(job, "pkg autoremove -y 2>&1", 900);
                    JSONArray outsideAutoremove = compareWithInventory(job, beforeAutoremove, autoremovePlan,
                            "Python transition autoremove");
                    boolean autoremoveFollowed = true;
                    for (Object v : PackagePlan.verifyOutcome(autoremovePlan))
                        if (!((JSONObject) v).getBoolean("ok")) autoremoveFollowed = false;
                    if (!outsideAutoremove.isEmpty() || !autoremoveFollowed)
                        outcome = new PlanOutcome(merge(outcome.outsidePlan(), outsideAutoremove),
                                outcome.planNotFollowed() || !autoremoveFollowed, outcome.mapsProblem());
                }
            }

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.13", java.util.Map.of("total", String.valueOf(TOT))));
            boolean servicesOk = true;
            for (String s : services) {
                ok("service " + s + " start", 120);
                boolean su = ok("service " + s + " status", 30);
                job.write("    " + s + ": " + (su ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runPythonTransition.14")));
                if (!su) servicesOk = false;
            }
            if (services.isEmpty()) job.write("    " + I18n.tr("server.um.x.none"));

            job.advance(7, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.15", java.util.Map.of("total", String.valueOf(TOT))));
            // That the package is installed does not say that the command starts: it is the lesson
            // of the MySQL client, where everything looked fine and postmap did not find the library.
            // I do not guess the name of the command from the name of the package: for py311-fail2ban
            // I would get it wrong (the commands are fail2ban-server and fail2ban-client, not
            // "fail2ban"). I ask pkg which executable files it really installed.
            boolean commandsOk = true;
            for (String n : newOnes) {
                if (!isValidName(n)) continue;
                int tested = 0;
                for (String f : sh("pkg query %Fp " + n + " 2>/dev/null").split("\n")) {
                    String t = f.trim();
                    if (!t.startsWith("/usr/local/bin/") && !t.startsWith("/usr/local/sbin/")) continue;
                    if (t.contains("test")) continue;   // no test suites launched by mistake
                    if (!ok("test -x " + t, 10)) continue;
                    if (++tested > 4) break;
                    String o = sh(t + " --version 2>&1", 120);
                    String ol = o.toLowerCase();
                    boolean good = !o.trim().isEmpty() && !ol.contains("not found") && !ol.contains("traceback")
                            && !ol.contains("importerror") && !ol.contains("modulenotfound")
                            && !ol.contains("no module named");
                    job.write("    " + t + " --version: "
                            + (good ? o.split("\n")[0].trim() : I18n.tr("server.um.x.failedArrow", java.util.Map.of("o", String.valueOf(o.trim())))));
                    if (!good) commandsOk = false;
                }
                if (tested == 0) job.write(I18n.tr("server.um.runPythonTransition.16", java.util.Map.of("n", String.valueOf(n))));
            }
            long left = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + old + "-")).count();
            job.write(I18n.tr("server.um.runPythonTransition.17", java.util.Map.of("old", String.valueOf(old), "left", String.valueOf(left))));

            job.write("");
            boolean fallen = fallenServices(job, servicesBefore);
            sideEffects.checkListening(job);
            java.util.List<String> problems = planProblems(outcome);
            problems.addAll(sideEffects.problems());
            if (!problems.isEmpty() || fallen) {
                job.status = "error";
                if (problems.isEmpty()) problems.add(I18n.tr("server.um.runGuidedUpdate.37"));
                problems.add(I18n.tr("server.um.runPythonTransition.20", java.util.Map.of("backup", String.valueOf(bk))));
                job.errorMessage = String.join(" ", problems);
            } else if (servicesOk && commandsOk) {
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runPythonTransition.18", java.util.Map.of("newer", String.valueOf(fresh))));
                job.write(I18n.tr("server.um.runPythonTransition.19", java.util.Map.of("backup", String.valueOf(bk))));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runPythonTransition.20", java.util.Map.of("backup", String.valueOf(bk)));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            // The comparison with the plan and the scripts that wrote are stated here too: pkg stopped
            // halfway is exactly the case in which they matter.
            for (String p : sideEffects.problems()) job.errorMessage += " " + p;
            if (outcome != null && !outcome.outsidePlan().isEmpty()) job.errorMessage += " " + divergenceMessage(outcome.outsidePlan());
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // Every package on the list that is installed now gets locked: the newcomers and,
            // if the move stopped before removing them, the old ones.
            if (!listOnDisk.isEmpty()) {
                java.util.List<String> failed = relockListed(job, listOnDisk);
                if (!failed.isEmpty() && "completed".equals(job.status)) {
                    job.status = "error";
                    job.errorMessage = I18n.tr("server.um.runGuidedUpdate.42");
                }
                if (!installedNew) {
                    java.util.List<String> stillThere = new ArrayList<>();
                    for (String n : listOnDisk) if (ok("pkg info -e " + n, 15) && n.startsWith("py")) stillThere.add(n);
                    if (!stillThere.isEmpty())
                        job.write(I18n.tr("server.um.x.unlockedNotReplaced", java.util.Map.of("list", String.join(", ", stillThere))));
                }
            }
            job.finish();
        }
    }

    /** Two lists of divergences in one. */
    private static JSONArray merge(JSONArray a, JSONArray b) {
        JSONArray out = new JSONArray();
        for (int i = 0; a != null && i < a.length(); i++) out.put(a.get(i));
        for (int i = 0; b != null && i < b.length(); i++) out.put(b.get(i));
        return out;
    }

    // ===================== guided maintenance plan =====================

    /** The grep options for the dovecot.conf signature, the current one and the previous ones: " -e 'signature' ...". */
    static String dovecotSignatureOptions() {
        StringBuilder b = new StringBuilder();
        for (String f : PanelMarker.forms("dovecotSignature", org.daemoxcp.mail.scripts.DovecotConfig.SIGNATURE))
            b.append(" -e '").append(f).append('\'');
        return b.toString();
    }

    /**
     * The plan: what must be done on THIS machine, in which order, and where you are.
     *
     * The state of each step is not stored anywhere: it is DERIVED every time
     * from the real state of the system. A flag saved on disk could say "done" for a
     * step that someone has undone, or lag behind after a restore; a check
     * derived from the facts cannot lie. It costs a few more seconds and it is worth it.
     */
    public static JSONObject maintenancePlan() {
        ok("pkg update -q", 120);
        JSONArray steps = new JSONArray();

        // Data collected only ONCE: pkg audit and the simulation are slow, and repeating them
        // for every step would turn the plan into a wait of minutes.
        String audit = sh("pkg audit -F 2>&1", 180);
        String dry = sh("pkg upgrade -n 2>&1", 180);
        String lock = sh("pkg lock -l 2>/dev/null");
        JSONObject state = packagesStatus();
        JSONArray packages = state.getJSONArray("packages");

        // What already has a dedicated procedure (phases F, G, H) must not appear ALSO as a package
        // step: it would be the same operation written twice with different words, and the reader
        // cannot know whether they are one or two. They are decided here, once, and apply to
        // both lists further down and to the phases.
        final String rcPkg = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20).trim();
        final String jvmPkg = jvmPackage();
        final String pyNew = pyDefault();
        java.util.function.Predicate<String> covered = n ->
                   (!rcPkg.isEmpty() && rcPkg.equals(n))
                || (!jvmPkg.isEmpty() && jvmPkg.equals(n))
                || (n.matches("^py3[0-9]{2}-.*") && !n.startsWith("py" + pyNew + "-"));

        // --- Step 1: the whole locked stack ---
        int installed = state.getInt("installedCount"), protectedNames = state.getInt("lockedCount");
        boolean allLocked = installed > 0 && protectedNames == installed;
        steps.put(repeatable(step("phase-protection", "phase", I18n.tr("server.um.x.stepProtect"),
                allLocked ? "done" : "todo",
                I18n.tr("server.um.maintenancePlan.1", java.util.Map.of("lockedNames", String.valueOf(protectedNames), "installedNames", String.valueOf(installed))),
                I18n.tr("server.um.maintenancePlan.2"),
                allLocked ? null : new JSONObject().put("type", "packages_lock_all")),
                new JSONObject().put("type", "packages_lock_all")));

        // --- Step 2: upgrade what is not locked ---
        Matcher mUp = Pattern.compile("Number of packages to be upgraded:\\s*([0-9]+)").matcher(dry);
        int toUpdate = mUp.find() ? Integer.parseInt(mUp.group(1)) : 0;
        Matcher mIn = Pattern.compile("Number of packages to be installed:\\s*([0-9]+)").matcher(dry);
        int toInstall = mIn.find() ? Integer.parseInt(mIn.group(1)) : 0;
        boolean updatedContext = (toUpdate + toInstall) == 0;
        steps.put(step("phase-unprotected", "phase", I18n.tr("server.um.maintenancePlan.3"),
                updatedContext ? "done" : "todo",
                updatedContext ? I18n.tr("server.um.maintenancePlan.4")
                        : I18n.tr("server.um.maintenancePlan.5", java.util.Map.of("toUpdate", String.valueOf(toUpdate), "toInstall", String.valueOf(toInstall))),
                I18n.tr("server.um.maintenancePlan.6"),
                updatedContext ? null : new JSONObject().put("type", "updates_apply")));

        // --- Steps 3..N: one step for each locked vulnerable package with a fix ---
        // The order is by number of CVEs closed: first what brings the most benefit.
        java.util.List<JSONObject> vulnerable = new ArrayList<>();
        Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
        while (mv.find()) seen.add(mv.group(1));
        for (String name : seen) {
            if (roleOf(name) == null) continue;              // not part of the mail stack
            if (covered.test(name)) continue;                 // already has its dedicated phase
            String cur = sh("pkg query %v " + name + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + name + " 2>/dev/null", 20);
            if (cur.isEmpty() || av.isEmpty() || av.equals(cur)) continue;   // no fix available
            boolean major = significantJump(name, cur, av);
            JSONObject warning = warningFor(name, major);
            int nCve = vulnerabilityDetail(audit, name).getJSONArray("cve").length();
            JSONObject o = new JSONObject().put("name", name).put("cur", cur).put("av", av)
                    .put("cve", nCve).put("major", major);
            if (warning != null) o.put("warning", warning);
            vulnerable.add(o);
        }
        vulnerable.sort((x, y) -> Integer.compare(y.getInt("cve"), x.getInt("cve")));
        // A single step per family: proposing "upgrade mysql80-server" and then "upgrade
        // mysql80-client" would mean proposing the same operation twice, and the first
        // would not even succeed because the other half stays locked.
        java.util.LinkedHashSet<String> seenFamilies = new java.util.LinkedHashSet<>();
        java.util.List<JSONObject> unique = new ArrayList<>();
        for (JSONObject v : vulnerable) {
            String fam = familyOf(v.getString("name"));
            String key = fam == null ? v.getString("name") : fam;
            if (seenFamilies.add(key)) unique.add(v);
        }
        vulnerable = unique;
        for (JSONObject v : vulnerable) {
            String name = v.getString("name");
            boolean wait = v.has("warning") && "wait".equals(v.getJSONObject("warning").getString("level"));
            java.util.List<String> mem = familyMembers(name);
            String title = mem.size() > 1
                    ? I18n.tr("server.um.x.updLinkedCve", java.util.Map.of("name", String.valueOf(name), "n", String.valueOf((mem.size() - 1)), "cve", String.valueOf(v.getInt("cve"))))
                    : I18n.tr("server.um.x.updCve", java.util.Map.of("name", String.valueOf(name), "cve", String.valueOf(v.getInt("cve"))));
            steps.put(step("pkg-" + name, "package", title,
                    wait ? "manual" : "todo",
                    name + " " + v.getString("cur") + " -> " + v.getString("av")
                        + (v.getBoolean("major") ? I18n.tr("server.um.maintenancePlan.7") : I18n.tr("server.um.maintenancePlan.8")),
                    wait ? v.getJSONObject("warning").getString("text")
                            : I18n.tr("server.um.maintenancePlan.9"),
                    wait ? null : new JSONObject().put("type", "package_update").put("package", name)));
        }

        // --- MySQL migration, if needed: it is HERE because it is a prerequisite of some
        //     later steps (Postfix requires the 8.4 library) and because it comes after the
        //     independent security updates, which are more urgent and less invasive.
        //     A plan that says "first do X" without containing X does not guide: it sends you searching.
        String srvMysql = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        if (!srvMysql.isEmpty()) {
            boolean already84 = srvMysql.startsWith("mysql84");
            String available84 = already84 ? "" : sh("pkg rquery -U %v mysql84-server 2>/dev/null", 30);
            if (already84) {
                steps.put(step("phase-mysql84", "phase", I18n.tr("server.um.maintenancePlan.10"), "done",
                        I18n.tr("server.um.maintenancePlan.11", java.util.Map.of("srvMysql", String.valueOf(srvMysql))),
                        I18n.tr("server.um.maintenancePlan.12"), null));
            } else if (!available84.isEmpty()) {
                steps.put(step("phase-mysql84", "phase", I18n.tr("server.um.maintenancePlan.10"), "manual",
                        I18n.tr("server.um.maintenancePlan.13", java.util.Map.of("srvMysql", String.valueOf(srvMysql), "available84", String.valueOf(available84))),
                        I18n.tr("server.um.maintenancePlan.14"), null));
            }
        }

        // --- Steps for the locked packages that have an update but no CVE ---
        // They are not urgent, but "update everything that can be updated" is a legitimate request
        // and the plan must be able to represent it, otherwise they would stay invisible forever.
        for (int i = 0; i < packages.length(); i++) {
            JSONObject p = packages.getJSONObject(i);
            String name = p.getString("name");
            if (seen.contains(name)) continue;               // already covered as vulnerable
            if (covered.test(name)) continue;                 // already has its dedicated phase
            String fam = familyOf(name);
            String key = fam == null ? name : fam;
            if (!seenFamilies.add(key)) continue;         // already covered by its family
            String cur = p.optString("version", "");
            String av = sh("pkg rquery -U %v " + name + " 2>/dev/null", 20);
            if (cur.isEmpty() || av.isEmpty() || av.equals(cur)) continue;
            boolean major = significantJump(name, cur, av);
            JSONObject warning = warningFor(name, major);
            boolean wait = warning != null && "wait".equals(warning.getString("level"));
            // If the new package requires another MySQL family, the step is not "to do":
            // it is blocked until MySQL has been migrated. Offering it would mean proposing
            // an operation that the preflight refuses a second later.
            String conflict = mysqlFamilyConflict(name);
            if (conflict != null) {
                java.util.List<String> memC = familyMembers(name);
                steps.put(step("pkg-" + name, "package", memC.size() > 1
                            ? I18n.tr("server.um.maintenancePlan.17", java.util.Map.of("name", String.valueOf(name), "p", String.valueOf(memC.size() - 1)))
                            : I18n.tr("server.um.maintenancePlan.18", java.util.Map.of("name", String.valueOf(name))),
                        "manual",
                        I18n.tr("server.um.maintenancePlan.15", java.util.Map.of("name", String.valueOf(name), "cur", String.valueOf(cur), "av", String.valueOf(av))),
                        I18n.tr("server.um.maintenancePlan.16", java.util.Map.of("conflict", String.valueOf(conflict))),
                        null));
                continue;
            }
            java.util.List<String> mem = familyMembers(name);
            String title = mem.size() > 1
                    ? I18n.tr("server.um.maintenancePlan.17", java.util.Map.of("name", String.valueOf(name), "p", String.valueOf((mem.size() - 1))))
                    : I18n.tr("server.um.maintenancePlan.18", java.util.Map.of("name", String.valueOf(name)));
            steps.put(step("pkg-" + name, "package", title, wait ? "manual" : "todo",
                    name + " " + cur + " -> " + av
                        + (major ? I18n.tr("server.um.maintenancePlan.7") : I18n.tr("server.um.maintenancePlan.8"))
                        + " " + I18n.tr("server.um.x.noKnownVuln"),
                    wait ? warning.getString("text")
                            : (warning != null ? warning.getString("text")
                                           : I18n.tr("server.um.maintenancePlan.19")),
                    wait ? null : new JSONObject().put("type", "package_update").put("package", name)));
        }

        // --- rspamd caches left over from a previous update ---
        // It exists as a step only as long as those files are there: it is the same principle as
        // the derived state, and it disappears by itself when it is no longer needed.
        // A "zero files found" can mean two opposite things: that they have already been
        // deleted, or that I looked in the wrong place. They are told apart by looking at whether
        // the folder exists and contains something: an absence is proven, not presumed.
        boolean rspamdPresent = ok("pkg info -e rspamd", 20);
        boolean rspamdFolder = ok("test -d /var/db/rspamd", 15);
        long fileRspamd = rspamdFolder
                ? number(sh("find /var/db/rspamd -type f 2>/dev/null | wc -l", 60)) : 0;
        long unser = rspamdFolder
                ? number(sh("find /var/db/rspamd -type f -name '*.unser' 2>/dev/null | wc -l", 60)) : 0;
        if (rspamdPresent && !rspamdFolder) {
            steps.put(step("phase-rspamd-cache", "phase", I18n.tr("server.um.maintenancePlan.20"), "manual",
                    I18n.tr("server.um.maintenancePlan.21"),
                    I18n.tr("server.um.maintenancePlan.22"), null));
        } else if (unser > 0) {
            steps.put(step("phase-rspamd-cache", "phase", I18n.tr("server.um.maintenancePlan.23"), "todo",
                    I18n.tr("server.um.maintenancePlan.24", java.util.Map.of("unser", String.valueOf(unser))),
                    I18n.tr("server.um.maintenancePlan.25"),
                    new JSONObject().put("type", "rspamd_clean_cache")));
        } else if (rspamdPresent && rspamdFolder) {
            steps.put(step("phase-rspamd-cache", "phase", I18n.tr("server.um.maintenancePlan.26"), "done",
                    I18n.tr("server.um.maintenancePlan.27", java.util.Map.of("rspamdFile", String.valueOf(fileRspamd))),
                    I18n.tr("server.um.maintenancePlan.28"), null));
        }

        // --- Final step: Dovecot configuration from the single source ---
        // The state is derived from the live file: the header is written only by the new generator.
        // The previous one too: a server that has not yet changed signature is already regenerated.
        boolean regenerated = ok("grep -qF" + dovecotSignatureOptions() + " "
                + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        boolean sieveActive = ok("grep -qE '^protocols.*sieve' " + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        steps.put(repeatable(step("phase-dovecot", "phase", I18n.tr("server.um.maintenancePlan.30"),
                regenerated ? "done" : "todo",
                regenerated ? (sieveActive
                        ? I18n.tr("server.um.x.dcSingleSieve")
                        : I18n.tr("server.um.x.dcSingleNoSieve"))
                    : I18n.tr("server.um.maintenancePlan.31"),
                I18n.tr("server.um.maintenancePlan.32"),
                regenerated ? null : new JSONObject().put("type", "dovecot_config_regen")),
                new JSONObject().put("type", "dovecot_config_regen")));

        // --- The three operations that a simple "pkg upgrade" cannot do ---
        // They are in the plan even if the action lives in a dedicated tab: a plan that is silent
        // about what is left to do implicitly says "you are fine", and that is not true. The state
        // is derived with light queries -- no simulations, which here would cost minutes.

        // Roundcube: the package would upgrade by itself, but the major version jump
        // changes the database SCHEMA, and without bin/updatedb.sh the webmail does not work.
        if (!rcPkg.isEmpty() && isValidName(rcPkg)) {
            String cur = sh("pkg query %v " + rcPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + rcPkg + " 2>/dev/null", 20);
            boolean rcUnknown = cur.isEmpty() || av.isEmpty();
            boolean toDoRc = !rcUnknown && !av.equals(cur);
            // A webmail already on 1.7 with the old root is broken NOW: if the plan
            // looked only at the version it would say "done" while the webmail does not answer.
            String crookedRoot = null;
            if (wantsPublicHtml(cur) || wantsPublicHtml(av)) {
                JSONArray rd = nginxRoundcubeRoots();
                for (int i = 0; i < rd.length(); i++)
                    if (!rd.getJSONObject(i).getBoolean("already"))
                        crookedRoot = rd.getJSONObject(i).getString("file");
            }
            if (crookedRoot != null) { toDoRc = true; rcUnknown = false; }
            int cveRc = vulnerabilityDetail(audit, rcPkg).getJSONArray("cve").length();
            steps.put(step("phase-roundcube", "phase", I18n.tr("server.um.x.stepRoundcube")
                        + (cveRc > 0 ? " (" + cveRc + " CVE)" : ""),
                    (toDoRc || rcUnknown) ? "manual" : "done",
                    rcUnknown ? I18n.tr("server.um.x.rcRepoUnknown", java.util.Map.of("pkg", String.valueOf(rcPkg), "cur", String.valueOf(cur.isEmpty() ? I18n.tr("server.um.x.unknownF") : cur)))
                        : !toDoRc ? I18n.tr("server.um.x.rcLatest", java.util.Map.of("pkg", String.valueOf(rcPkg), "cur", String.valueOf(cur)))
                        : (av.equals(cur)
                           ? I18n.tr("server.um.maintenancePlan.33", java.util.Map.of("rcPkg", String.valueOf(rcPkg), "cur", String.valueOf(cur), "crookedRoot", String.valueOf(crookedRoot)))
                           : rcPkg + " " + cur + " -> " + av
                             + (crookedRoot != null ? I18n.tr("server.um.maintenancePlan.34") : "")),
                    toDoRc
                    ? I18n.tr("server.um.maintenancePlan.35")
                    : I18n.tr("server.um.maintenancePlan.36"), null));
        }

        // Python: py311 and py312 are different packages, not two versions of the same one.
        java.util.LinkedHashSet<String> pyOld = new java.util.LinkedHashSet<>();
        for (String n : sh("pkg query %n 2>/dev/null").split("\n")) {
            Matcher m = Pattern.compile("^py(3[0-9]{2})-").matcher(n.trim());
            if (m.find() && !m.group(1).equals(pyNew)) pyOld.add(m.group(1));
        }
        if (!pyOld.isEmpty()) {
            String list = String.join(", ", pythonToMove(pyOld.iterator().next()));
            steps.put(step("phase-python", "phase", I18n.tr("server.um.maintenancePlan.37"),
                    "manual",
                    I18n.tr("server.um.x.pyInstalled", java.util.Map.of("oldOnes", String.valueOf(String.join("/py", pyOld)), "newer", String.valueOf(pyNew)))
                    + (list.isEmpty() ? "." : ": " + list),
                    I18n.tr("server.um.maintenancePlan.38", java.util.Map.of("p", String.valueOf(pyOld.iterator().next()), "pyNew", String.valueOf(pyNew))), null));
        } else {
            steps.put(step("phase-python", "phase", I18n.tr("server.um.maintenancePlan.37"),
                    "done", I18n.tr("server.um.maintenancePlan.39", java.util.Map.of("pyNew", String.valueOf(pyNew))),
                    I18n.tr("server.um.runPythonTransition.2"), null));
        }

        // JVM: the panel runs on it, so it cannot update it while staying up.
        if (!jvmPkg.isEmpty()) {
            String cur = sh("pkg query %v " + jvmPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + jvmPkg + " 2>/dev/null", 20);
            // Three states, not two. The repository not answering does NOT mean "you are fine":
            // it means I do not know, and saying so is the only honest answer.
            boolean unknownJv = cur.isEmpty() || av.isEmpty();
            boolean toDoJv = !unknownJv && !av.equals(cur);
            int cveJv = vulnerabilityDetail(audit, jvmPkg).getJSONArray("cve").length();
            steps.put(step("phase-jvm", "phase", I18n.tr("server.um.x.stepJvm")
                        + (cveJv > 0 ? " (" + cveJv + " CVE)" : ""),
                    (toDoJv || unknownJv) ? "manual" : "done",
                    unknownJv ? I18n.tr("server.um.x.jvRepoUnknown", java.util.Map.of("pkg", String.valueOf(jvmPkg), "cur", String.valueOf(cur.isEmpty() ? I18n.tr("server.um.x.unknownF") : cur)))
                        : toDoJv ? jvmPkg + " " + cur + " -> " + av
                             : I18n.tr("server.um.x.jvLatest", java.util.Map.of("pkg", String.valueOf(jvmPkg), "cur", String.valueOf(cur))),
                    unknownJv
                    ? I18n.tr("server.um.maintenancePlan.40")
                    : toDoJv
                    ? I18n.tr("server.um.maintenancePlan.41")
                    : I18n.tr("server.um.maintenancePlan.42"), null));
        }

        // Vulnerabilities without an available fix: they are not a step, but they must be known.
        JSONArray withoutRemedy = new JSONArray();
        for (String name : seen) {
            String cur = sh("pkg query %v " + name + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + name + " 2>/dev/null", 20);
            if (!cur.isEmpty() && (av.isEmpty() || av.equals(cur))) withoutRemedy.put(name);
        }

        int toDo = 0;
        for (int i = 0; i < steps.length(); i++) if ("todo".equals(steps.getJSONObject(i).getString("state"))) toDo++;
        return new JSONObject().put("success", true).put("steps", steps)
                .put("toDo", toDo).put("total", steps.length())
                .put("withoutRemedy", withoutRemedy);
    }

    /**
     * A step of the plan, identified by a stable KEY and not by a number.
     *
     * The numbers shifted: the steps on single packages disappear when the package has nothing
     * left to do -- it is the consequence of the state being derived instead of stored -- and
     * what was "number 3" became another one. Whoever follows a guide must be able to say "I
     * did openssl", not "I did number three" and then discover that three is now nginx.
     */
    /**
     * The letter of each phase, tied to its KEY and not to the order of appearance.
     *
     * Assigning them while going through the list looked stable as long as the phases were
     * always the same four. But a phase that appears only when needed -- like the cleanup of
     * the rspamd caches -- would shift all the ones after it, and "Phase C" would again mean
     * different things at different moments: exactly the defect of the numbers, only slower to
     * show.
     */
    private static final java.util.Map<String, String> PHASE_LETTER = java.util.Map.of(
        "phase-protection",   "A",
        "phase-unprotected",  "B",
        "phase-mysql84",      "C",
        "phase-dovecot",      "D",
        "phase-rspamd-cache", "E",
        "phase-roundcube",    "F",
        "phase-python",       "G",
        "phase-jvm",          "H"
    );

    /**
     * Marks a step as REDOABLE: already done, but repeatable without harm.
     *
     * It applies only to the steps that rewrite something idempotently -- the Dovecot
     * configuration, the locking of packages -- and it is needed because the derived state, on
     * its own, makes it impossible to repeat what appears already done. After an improvement of
     * the generator one wants to regenerate, and not being able to is a limitation, not a
     * safeguard.
     *
     * It does NOT apply to package updates (redoing them means nothing) nor to the MySQL
     * migration, which rewrites the data dictionary and is not repeatable by definition.
     */
    private static JSONObject repeatable(JSONObject step, JSONObject action) {
        if ("done".equals(step.optString("state")) && action != null) step.put("redoAction", action);
        return step;
    }

    private static JSONObject step(String key, String group, String title, String state,
                                    String situation, String why, JSONObject action) {
        JSONObject o = new JSONObject().put("key", key).put("group", group)
                .put("title", title).put("state", state)
                .put("situation", situation).put("why", why);
        if ("phase".equals(group)) o.put("letter", PHASE_LETTER.getOrDefault(key, "?"));
        if (action != null) o.put("action", action);
        return o;
    }

    // ===================== guided update of a single package =====================

    /**
     * Packages that must move TOGETHER.
     *
     * It is not an aesthetic preference: mysql80-server depends on mysql80-client, and if the
     * client stays locked a "pkg upgrade mysql80-server" finds a locked dependency and does
     * not complete. The same goes for php84 with its twenty-eight extensions, which carry the
     * version number in their name. Treating them as separate steps means proposing
     * an operation that cannot succeed.
     */
    private static final String[][] FAMILIES = {
        {"^mysql[0-9]+-(server|client)$",  "server.um.step.1"},
        {"^php[0-9]+(-.+)?$",              "server.um.step.2"},
        {"^dovecot[0-9]*(-.+)?$",          "server.um.family.dovecot"},
    };

    /** The expression of the family the package belongs to, or null if it stands alone. */
    static String familyOf(String name) {
        for (String[] f : FAMILIES) if (name.matches(f[0])) return f[0];
        return null;
    }

    static String familyReason(String name) {
        for (String[] f : FAMILIES) if (name.matches(f[0])) return I18n.tr(f[1]);
        return "";
    }

    /**
     * An ALREADY installed package that is "the same thing at another version" as 'nome', or
     * null. PackagePlan needs it to recognize when pkg works around a lock by installing
     * another member of the family: the reason is on PackagePlan.familyAddition.
     *
     * Two conditions, both necessary, because either one alone gets it wrong:
     *
     *  - **the same declared family** (FAMIGLIE). Without this, python311 and python312
     *    would look like twins, and instead they coexist perfectly well.
     *  - **the same skeleton**, that is the same name with the digits replaced: mysql97-client
     *    and mysql84-client both become "mysql#-client", while mysql84-server becomes
     *    "mysql#-server". Without this, the twin of mysql97-client could turn out to be
     *    mysql84-server, which is of the same family but does not occupy the same place.
     */
    static String installedFamilyTwin(String name) {
        if (!isValidName(name)) return null;
        String family = familyOf(name);
        if (family == null) return null;
        String skeleton = nameSkeleton(name);
        for (String line : sh("pkg query %n 2>/dev/null", 30).split("\n")) {
            String t = line.trim();
            if (!isValidName(t) || t.equals(name) || !t.matches(family)) continue;
            if (skeleton.equals(nameSkeleton(t))) return t;
        }
        return null;
    }

    /** The name with the digits replaced: "mysql84-client" -> "mysql#-client". */
    static String nameSkeleton(String name) {
        return name == null ? "" : name.replaceAll("[0-9]+", "#");
    }

    /** All the INSTALLED packages that belong to the same family. At least the package itself. */
    static java.util.List<String> familyMembers(String name) {
        java.util.List<String> members = new ArrayList<>();
        String fam = familyOf(name);
        if (fam == null) { members.add(name); return members; }
        for (String line : sh("pkg query %n 2>/dev/null", 30).split("\n")) {
            String t = line.trim();
            if (isValidName(t) && t.matches(fam)) members.add(t);
        }
        if (members.isEmpty()) members.add(name);
        return members;
    }

    /**
     * Which service depends on which package. It is needed for the part that cost dearly yesterday:
     * updating a package does NOT update the running process, which keeps using the
     * files already loaded in memory. Without a restart, the vulnerability stays open while
     * appearing fixed.
     */
    private static final String[][] SERVICE_OF = {
        {"^postfix.*",                        "postfix"},
        {"^dovecot[0-9]*(-[a-z]+)?$",         "dovecot"},
        {"^dovecot[0-9]*-pigeonhole.*",       "dovecot"},
        {"^rspamd$",                          "rspamd"},
        {"^redis.*",                          "redis"},
        // The same package runs two daemons, and both load libclamav. With only the clamd
        // line, measured on latest on 2026-10-24: clamav 1.5.4_1,1 -> 1.5.4_2,1, clamd
        // restarted, and freshclam still with the previous program (procstat no longer found
        // its executable) under a "clamav in service".
        {"^clamav.*",                         "clamav_clamd"},
        {"^clamav.*",                         "clamav_freshclam"},
        {"^nginx.*",                          "nginx"},
        {"^php[0-9]+.*",                      "php_fpm"},
        {"^mysql[0-9]+-server$",              "mysql-server"},
        {"^py[0-9]+-fail2ban$",               "fail2ban"},
        {"^unbound$",                         "unbound"},
    };

    /** Packages that are shared libraries: here a "no dependents" must be taken with caution. */
    private static final String SHARED_LIBRARIES =
            "^(openssl[0-9]*|expat|libxml2|zlib|libiconv|pcre2?|curl|libssh2|nghttp2|icu|libsodium)$";

    /** All the services of a package: a package can run more than one (clamav). */
    private static java.util.List<String> directServices(String pkgName) {
        java.util.List<String> r = new ArrayList<>();
        for (String[] row : SERVICE_OF) if (pkgName.matches(row[0])) r.add(row[1]);
        return r;
    }

    /**
     * The services to restart after updating a package. For a shared library like openssl
     * it is not enough to look at the package itself: pkg is asked WHO depends on it and
     * those packages are translated into services. A hand-written list would age in
     * silence, and a forgotten service means a vulnerability that stays open.
     */
    static java.util.List<String> servicesToRestart(String pkgName) {
        java.util.LinkedHashSet<String> services = new java.util.LinkedHashSet<>();
        services.addAll(directServices(pkgName));
        if (!isValidName(pkgName)) return new ArrayList<>(services);
        for (String line : sh("pkg query %rn " + pkgName + " 2>/dev/null", 30).split("\n")) {
            String dependents = line.trim();
            if (!isValidName(dependents)) continue;
            services.addAll(directServices(dependents));
        }
        return new ArrayList<>(services);
    }

    /** Actual name of the rc.d script among the candidates, or null if the service is not there. */
    static String realServiceName(String logical) {
        for (String[] candidates : SERVICES) {
            boolean belongs = false;
            for (String c : candidates) if (c.equals(logical)) belongs = true;
            if (!belongs) continue;
            for (String c : candidates) {
                if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) return c;
            }
            return null;
        }
        return ok("test -f /usr/local/etc/rc.d/" + logical + " -o -f /etc/rc.d/" + logical, 10) ? logical : null;
    }

    /**
     * Fishes out of the post-install messages the ones that ASK for an action.
     *
     * pkg prints them in the middle of hundreds of lines and then moves on: an "it is recommended
     * to remove the cache files" scrolls past and nobody does it. Rspamd 4.1 had one that
     * concerned spam classification, and it went unnoticed exactly that way.
     * Here the imperative phrasings are recognized and the message is printed again AT THE END,
     * where people really look.
     */
    static java.util.List<String> messagesAskingForAction(String outputPkg) {
        java.util.List<String> outside = new ArrayList<>();
        // The common indentation is removed, not only that of the first line: a script that
        // writes everything indented by four spaces, printed again with trim(), would have the
        // first line on the left and the others shifted.
        for (String block : outputBlocks(outputPkg))
            if (asksForAction(block)) outside.add(block.stripTrailing().stripIndent().strip());
        return outside;
    }

    /** "[4/4] Installing postfix-mysql-3.11.7_3,1...": pkg saying where it is. */
    private static final Pattern PKG_PROGRESS = Pattern.compile("^\\[\\d+/\\d+\\] .*");

    /** The lines with which pkg starts talking again, for example when an update relaunches itself. */
    private static final Pattern PKG_RESTARTS = Pattern.compile(
            "^(Checking integrity|Checking for upgrades|Updating .* repository catalogue).*");

    /** The edge of a box: "=====..." alone on the line. */
    private static final Pattern BOX_EDGE = Pattern.compile("^={10,}\\s*$");

    /**
     * Two sentences that pkg and the ports print at EVERY update and that during an update
     * ask for nothing. The first is pkg's, for every configuration file that differs from its
     * sample; the second is the ports', for every user or group of the package being
     * uninstalled, and here the package is reinstalled right after. Measured in the real
     * output of the postfix-mysql update of 2026-10-24: keeping them would mean printing
     * again as "to do" two things that are wrong to do.
     */
    private static final Pattern[] NOTICES_NOT_ACTIONS = {
        Pattern.compile("^You may need to manually remove \\S+ if it is no longer needed\\.?\\s*$"),
        Pattern.compile("^==> You should manually remove the \"[^\"]+\" (user|group)\\s*$"),
    };

    /**
     * The pkg output split into the pieces that a reader would take for a message.
     *
     * Before, only the "Message from" blocks were read. But an installation script writes
     * while it runs, and pkg prints those lines wherever they fall, OUTSIDE any block. Measured
     * on the postfix-mysql update of 2026-10-24 (finding 42): 61 lines, and the two things
     * that mattered were both outside -- "COMPATIBILITY: editing main.cf, setting
     * inet_protocols=ipv4", that is IPv6 removed at the next restart, and the "Postfix was
     * *not* activated in mailer.conf" box. The only "Message from" block was the one of the
     * OLD version, which was being uninstalled. Result: zero messages.
     *
     * The pieces:
     *  - a "Message from" block, up to the next one or until pkg starts talking again;
     *  - a box between two lines of "=====", with its empty lines inside;
     *  - outside these, a paragraph: consecutive lines between two empty lines or two pkg
     *    progress lines. The lines of a script are between the progress line of its
     *    package and that of the next one.
     */
    static java.util.List<String> outputBlocks(String outputPkg) {
        java.util.List<String> blocks = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        String mode = "paragraph";   // "paragraph", "message", "box"
        for (String line : (outputPkg == null ? "" : outputPkg).split("\n")) {
            if (line.startsWith("Message from ")) {
                closeBlock(blocks, current);
                mode = "message";
                current.append(line).append('\n');
                continue;
            }
            boolean pkgSpeaks = PKG_PROGRESS.matcher(line).matches() || PKG_RESTARTS.matcher(line).matches();
            if ("message".equals(mode)) {
                if (!pkgSpeaks) { current.append(line).append('\n'); continue; }
                closeBlock(blocks, current);
                mode = "paragraph";
            }
            if (BOX_EDGE.matcher(line).matches()) {
                closeBlock(blocks, current);
                mode = "box".equals(mode) ? "paragraph" : "box";
                continue;
            }
            if (pkgSpeaks) {
                closeBlock(blocks, current);
                mode = "paragraph";
                continue;
            }
            boolean notice = false;
            for (Pattern p : NOTICES_NOT_ACTIONS) if (p.matcher(line).matches()) notice = true;
            if (notice) continue;
            if (line.trim().isEmpty() && "paragraph".equals(mode)) { closeBlock(blocks, current); continue; }
            current.append(line).append('\n');
        }
        closeBlock(blocks, current);
        return blocks;
    }

    private static void closeBlock(java.util.List<String> blocks, StringBuilder current) {
        if (!current.toString().trim().isEmpty()) blocks.add(current.toString());
        current.setLength(0);
    }

    /** «Editing /usr/local/etc/postfix/master.cf, adding...», «COMPATIBILITY: editing .../main.cf». */
    private static final Pattern SCRIPT_EDITS_A_FILE = Pattern.compile("(?s).*\\bediting /.*");

    private static boolean asksForAction(String text) {
        String t = text.toLowerCase();
        return t.contains("it is recommended") || t.contains("you should") || t.contains("you may need")
            || t.contains("you need to") || t.contains("remember to")
            || t.contains("following command") || t.contains("action is needed")
            // A script that says it modified a file, or changed a default value for
            // compatibility, does not ask for anything in words: it has already done it.
            // It is the first thing to read, because what it did takes effect at the
            // restart (finding 42: "Specify inet_protocols explicitly if you want to
            // enable IPv6").
            || t.contains("compatibility:") || t.contains("explicitly")
            || SCRIPT_EDITS_A_FILE.matcher(t).matches();
    }

    /**
     * Prints again at the end of the log the messages that ask for an action or say they changed
     * something. The three jobs that update packages ask for it: before, only the guided update
     * did it, and the full maintenance -- the one that updates everything -- let the messages
     * of all the packages scroll by in the middle of the pkg output.
     */
    private static void writeActionMessages(Job job, String pkgOutput) {
        java.util.List<String> messages = messagesAskingForAction(pkgOutput);
        if (messages.isEmpty()) return;
        job.write("");
        job.write(I18n.tr("server.um.runGuidedUpdate.33"));
        job.write(I18n.tr("server.um.runGuidedUpdate.34"));
        for (String m : messages) {
            for (String l : m.split("\n")) if (!l.trim().isEmpty()) job.write("  " + l);
            job.write("");
        }
    }

    /**
     * Command that asks a service whether its configuration is valid, BEFORE restarting it.
     *
     * Restarting blindly after an update is the way to discover a syntax error with the
     * service already stopped. On Dovecot this check already existed; it was not there for the
     * others, and it is a disparity without reason: nginx between 1.28 and 1.30 can change
     * directives, and Postfix changes its defaults between versions.
     */
    private static final String[][] CONFIG_TEST = {
        {"nginx",        "nginx -t"},
        {"postfix",      "postfix check"},
        {"dovecot",      "doveconf -n >/dev/null"},
        {"rspamd",       "rspamadm configtest"},
        {"mysql-server", "su -m mysql -c '$(which mysqld 2>/dev/null || echo /usr/local/libexec/mysqld) --validate-config'"},
    };

    static String testConfigOf(String service) {
        for (String[] r : CONFIG_TEST) if (r[0].equals(service)) return r[1];
        return null;
    }

    /**
     * Tests to run AFTER the restart, to see whether the service has found its data again.
     *
     * "The process has restarted" does not say whether it has gone back to doing its job. Redis
     * restarted with the dump not read back starts empty: rspamd keeps working, but without
     * Bayesian training, without greylisting and without limits -- and nobody notices until
     * spam starts getting through again. It was written in my warning and nothing checked
     * it: a warning that does not verify is just a sentence.
     */
    private static final String[][] TEST_AFTER = {
        // From the socket, where there is one (RedisSocket, finding 235): with the port closed
        // "redis-cli DBSIZE" prints nothing, and every redis update would say it restarted empty.
        {"redis", "if [ -S " + RedisSocket.SOCKET + " ]; then redis-cli -s " + RedisSocket.SOCKET + " DBSIZE; else redis-cli DBSIZE;"
                + " fi 2>/dev/null", "server.um.testConfigOf.1"},
    };

    static String[] testAfterOf(String service) {
        for (String[] r : TEST_AFTER) if (r[0].equals(service)) return r;
        return null;
    }

    /**
     * Has the service restarted? It is asked several times, not once: MySQL 8.4 upgrades its data at startup, and
     * going from 8.4.11 to 8.4.13 on the VM "service mysql-server status" said it was not running right after the
     * restart, and it was running a few seconds later. A single look took it for down, and "Update all" stopped
     * with the service still starting (finding 207). Up to five minutes for MySQL, thirty seconds for the others.
     */
    static boolean cameUp(String service) {
        return waitUntil("mysql-server".equals(service) ? 300 : 30, 2000, () -> ok("service " + service + " status", 20));
    }

    /**
     * True as soon as check answers yes, false if it does not within seconds seconds; pauseMs between one attempt
     * and the next.
     */
    static boolean waitUntil(int seconds, long pauseMs, java.util.function.BooleanSupplier check) {
        long until = System.currentTimeMillis() + seconds * 1000L;
        while (true) {
            if (check.getAsBoolean()) return true;
            if (System.currentTimeMillis() >= until) return false;
            try {
                Thread.sleep(pauseMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /** The pid of a service, or an empty string. Comparing it before and after proves that it really restarted. */
    static String servicePid(String service) {
        if (!isValidName(service)) return "";
        String o = sh("service " + service + " status 2>/dev/null", 15);
        Matcher m = Pattern.compile("pid[s]?[: ]+([0-9]+)").matcher(o.toLowerCase());
        return m.find() ? m.group(1) : "";
    }

    /**
     * Preliminary checks for the update of ONE locked package. All read-only: it says
     * what would happen, which vulnerabilities would be closed and which services will
     * have to be restarted, before anyone presses anything.
     */
    public static JSONObject packagePreflight(String name) {
        JSONObject r = new JSONObject();
        if (!isValidName(name)) return r.put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
        JSONArray checks = new JSONArray();
        boolean block = false;

        // The packages that must move together are unlocked and updated together:
        // otherwise a dependency left locked blocks the whole operation. It must be known
        // right away, because the services to restart also depend on this.
        java.util.List<String> family = familyMembers(name);

        String version = sh("pkg query %v " + name + " 2>/dev/null", 20);
        if (version.isEmpty()) {
            addCheck(checks, "installed", I18n.tr("server.um.packagePreflight.1"), "block",
                    I18n.tr("server.um.packagePreflight.2", java.util.Map.of("name", String.valueOf(name))));
            block = true;
        } else {
            addCheck(checks, "installed", I18n.tr("server.um.packagePreflight.1"), "ok", name + " " + version);
        }
        r.put("name", name).put("current", version).put("role", roleOf(name) == null ? "" : roleOf(name));

        String available = sh("pkg rquery -U %v " + name + " 2>/dev/null", 30);
        r.put("available", available);
        boolean major = !version.isEmpty() && !available.isEmpty()
                && significantJump(name, version, available);
        r.put("majorJump", major);
        if (available.isEmpty() || available.equals(version)) {
            addCheck(checks, "update", I18n.tr("server.um.packagePreflight.3"), "block",
                    I18n.tr("server.um.packagePreflight.4"));
            block = true;
        } else {
            addCheck(checks, "update", I18n.tr("server.um.packagePreflight.3"), "ok",
                    version + " -> " + available + (major ? I18n.tr("server.um.packagePreflight.5") : I18n.tr("server.um.packagePreflight.6")));
        }

        JSONObject warning = warningFor(name, major);
        if (warning != null) {
            r.put("advisory", warning);
            if ("wait".equals(warning.getString("level"))) {
                addCheck(checks, "warning", I18n.tr("server.um.packagePreflight.7"), "block", warning.getString("text"));
                block = true;
            } else {
                addCheck(checks, "warning", I18n.tr("server.um.packagePreflight.7"), warning.getString("level"), warning.getString("text"));
            }
        }

        // Does the new package require a MySQL family different from the installed one?
        // It is the case of postfix-mysql 3.11, which in the repository depends on mysql84-client:
        // on the system there is still mysql80-client, and the two conflict. Updating it before
        // having migrated MySQL means either a failure or an unwanted library replacement,
        // with mysql80-server still depending on it.
        String mysqlInstalled = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        if (!available.isEmpty()) {
            String required = mysqlFamilyConflict(name);
            if (required != null) {
                StringBuilder who = new StringBuilder();
                for (String member : family) {
                    if (!isValidName(member)) continue;
                    if (sh("pkg rquery -U %dn " + member + " 2>/dev/null", 30).contains(required)) {
                        if (who.length() > 0) who.append(", ");
                        who.append(member);
                    }
                }
                addCheck(checks, "mysqlfamily", I18n.tr("server.um.packagePreflight.8"), "block",
                        I18n.tr("server.um.x.mysqlFamilyBlock", java.util.Map.of("who", String.valueOf(who.length() > 0 ? who.toString() : name), "required", String.valueOf(required), "installedValue", String.valueOf(mysqlInstalled), "version", String.valueOf(required.replace("-client", "")))));
                block = true;
                r.put("mysqlFamilyConflict", required);
            }
        }

        // Vulnerabilities that this update would close: it is the reason to do it. It is
        // asked for the INSTALLED version, and a report is required: the reason for both
        // things is on auditReport.
        JSONObject report = auditReport(name, version);
        r.put("cve", report.getJSONArray("cve")).put("vulnDescription", report.getString("description"))
         .put("references", report.getJSONArray("references")).put("vulnChecked", report.optBoolean("done"));
        int problems = report.optInt("problems");
        if (!report.optBoolean("done"))
            addCheck(checks, "vulnerabilities", I18n.tr("server.um.x.knownVulns"), "review",
                    report.optString("error"));
        else
            addCheck(checks, "vulnerabilities", I18n.tr("server.um.x.knownVulns"), problems > 0 ? "review" : "ok",
                    problems > 0 ? I18n.tr("server.um.x.openCves", java.util.Map.of("n", String.valueOf(problems), "d", String.valueOf(report.getString("description"))))
                                 : I18n.tr("server.um.packagePreflight.9"));

        // Services to restart. The sore point: without a restart the fix does not go into
        // service. And they must be computed on the WHOLE family, not on the named package alone:
        // updating mysql80-server together with mysql80-client, it is the programs linked to the
        // CLIENT (Postfix, Dovecot, php-fpm) that keep the old library in memory. Looking only at
        // the name written in the step would leave them out, and it is exactly the case in which
        // the fix appears installed without being in service.
        java.util.LinkedHashSet<String> logicalNames = new java.util.LinkedHashSet<>();
        for (String member : family) logicalNames.addAll(servicesToRestart(member));
        JSONArray services = new JSONArray();
        for (String logical : logicalNames) {
            String real = realServiceName(logical);
            if (real == null) continue;
            services.put(new JSONObject().put("name", real)
                    .put("running", ok("service " + real + " status", 15))
                    .put("pid", servicePid(real)));
        }
        r.put("services", services);
        // What pkg answered, in full: a "none" without the evidence is not information,
        // and on a shared library it is the error that defeats the update.
        JSONArray foundDeps = new JSONArray();
        for (String member : family) {
            for (String line : sh("pkg query %rn " + member + " 2>/dev/null", 30).split("\n")) {
                String d = line.trim();
                if (isValidName(d) && !family.contains(d)) foundDeps.put(d);
            }
        }
        r.put("reverseDeps", foundDeps);
        addCheck(checks, "services", I18n.tr("server.um.packagePreflight.10"), "review",
                services.length() == 0
                    ? (foundDeps.length() == 0
                       ? I18n.tr("server.um.x.noSvcZero")
                       : I18n.tr("server.um.x.noSvcSome", java.util.Map.of("n", String.valueOf(foundDeps.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(foundDeps))))))
                    : I18n.tr("server.um.packagePreflight.11", java.util.Map.of("length", String.valueOf(services.length()))));

        if (Files.exists(Paths.get(MAINTENANCE_STATE))) {
            addCheck(checks, "state", I18n.tr("server.um.packagePreflight.12"), "block",
                    I18n.tr("server.um.packagePreflight.13", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
            block = true;
        }

        r.put("family", new JSONArray(family));
        if (family.size() > 1) {
            addCheck(checks, "family", I18n.tr("server.um.packagePreflight.14"), "review",
                    I18n.tr("server.um.x.familyTogether", java.util.Map.of("n", String.valueOf(family.size()), "reason", String.valueOf(familyReason(name)), "list", String.valueOf(String.join(", ", family)))));
        }

        String lockList = sh("pkg lock -l 2>/dev/null");
        java.util.List<String> lockedNow = new ArrayList<>();
        for (String m : family) if (locked(lockList, m)) lockedNow.add(m);
        r.put("wasLocked", !lockedNow.isEmpty());
        r.put("lockedMembers", new JSONArray(lockedNow));

        // The EXACT plan. Up to here there was only "name version -> catalog version", but
        // to update, pkg can also change dependencies, install new ones, remove some: pkg
        // is asked, on a copy of its database in which the same locks are removed that the
        // real update will remove. The real database is not touched.
        JSONObject plan = judged(PackagePlan.planFor(family, lockedNames(lockList),
                UpdateManager::reasonNotToUnlock, UpdateManager::installedFamilyTwin));
        if (addPlanChecks(checks, plan, java.util.List.of(name), family, block)) block = true;
        if (plan.optBoolean("success") && plan.optBoolean("measured")) {
            JSONArray changes = plan.getJSONArray("changes");
            // The services to restart are computed on everything the plan changes, not only
            // on the family: a dependency like openssl stays in the memory of its users.
            java.util.LinkedHashSet<String> serviceNames = new java.util.LinkedHashSet<>();
            for (int i = 0; i < services.length(); i++) serviceNames.add(services.getJSONObject(i).getString("name"));
            java.util.List<String> forDependencies = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                if ("remove".equals(c.getString("type")) || family.contains(c.getString("name"))) continue;
                for (String logical : servicesToRestart(c.getString("name"))) {
                    String real = realServiceName(logical);
                    if (real == null || !serviceNames.add(real)) continue;
                    services.put(new JSONObject().put("name", real)
                            .put("running", ok("service " + real + " status", 15))
                            .put("pid", servicePid(real)));
                    forDependencies.add(real + " " + I18n.tr("server.um.x.forPkg", java.util.Map.of("name", String.valueOf(c.getString("name")))));
                }
            }
            if (!forDependencies.isEmpty()) {
                addCheck(checks, "plan-services", I18n.tr("server.um.packagePreflight.24"), "review",
                        I18n.tr("server.um.x.depsServices", java.util.Map.of("list", String.valueOf(String.join(", ", forDependencies)))));
            }
        }
        r.put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""));

        java.util.List<String> toUnlock = jsonArrayToList(plan.optJSONArray("unlockedPackages") == null
                ? new JSONArray() : plan.getJSONArray("unlockedPackages"));
        addCheck(checks, "protection", I18n.tr("server.um.packagePreflight.25"), "ok",
                toUnlock.isEmpty()
                    ? I18n.tr("server.um.packagePreflight.26")
                    : I18n.tr("server.um.x.willUnlock", java.util.Map.of("list", String.valueOf(String.join(", ", toUnlock)))));

        // If among those to unlock there is a package nobody asked for, the reason must be
        // said: it is there because otherwise pkg would install another member of its
        // family in its place (PackagePlan.familyAddition).
        JSONArray family2 = plan.optJSONArray("familyUnlocked");
        for (int i = 0; family2 != null && i < family2.length(); i++) {
            JSONObject f = family2.getJSONObject(i);
            addCheck(checks, "unlockedfamily", I18n.tr("server.um.x.familyUnlockedLabel"), "review",
                    I18n.tr("server.um.x.familyUnlockedWhy", java.util.Map.of(
                            "twin", String.valueOf(f.optString("installed")),
                            "version", String.valueOf(f.optString("version")),
                            "newer", String.valueOf(f.optString("wouldInstall")))));
        }

        r.put("success", true).put("checks", checks).put("canProceed", !block).put("blocked", block);
        return r;
    }

    /** The packages locked now, by name, from an output of "pkg lock -l". */
    static Set<String> lockedNames(String lockOutput) {
        Set<String> r = new java.util.TreeSet<>();
        for (String line : lockOutput.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.endsWith(":")) continue;
            int d = t.lastIndexOf('-');
            String n = d > 0 && d + 1 < t.length() && Character.isDigit(t.charAt(d + 1)) ? t.substring(0, d) : t;
            if (isValidName(n)) r.add(n);
        }
        return r;
    }

    /**
     * Can the lock be removed from a package that pkg must change to make room for the chosen
     * one? Not if its warning says to wait: it is the rule that keeps it out of the full
     * maintenance, and it must apply also when it comes in through the back door, as a
     * dependency of another one.
     */
    static String reasonNotToUnlock(JSONObject isProtected) {
        String n = isProtected.optString("name"), from = isProtected.optString("version"), to = isProtected.optString("destination");
        // If pkg does not say which version it would go to, the worst case is assumed.
        boolean major = to.isEmpty() || significantJump(n, from, to);
        JSONObject av = warningFor(n, major);
        if (av != null && "wait".equals(av.optString("level")))
            return I18n.tr("server.um.x.protectedWait", java.util.Map.of("t", String.valueOf(av.optString("text"))));
        return null;
    }

    /** The plan as the tab shows it: the pkg output is shortened, the rest stays as it is. */
    private static JSONObject planForCard(JSONObject plan) {
        JSONObject p = new JSONObject(plan.toString());
        String u = p.optString("output", "");
        if (u.length() > 6000) p.put("output", "...\n" + u.substring(u.length() - 6000));
        return p;
    }

    /**
     * @param approvedSignature the signature of the plan that whoever presses has read in the tab. The job
     *                          recomputes the plan and starts only if it is the same: between the reading
     *                          and the click the catalog may have changed, and then a plan that nobody
     *                          has seen would be executed.
     */
    public static JSONObject startGuidedUpdate(String name, String approvedSignature) {
        if (!isValidName(name)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
        if (approvedSignature == null || !approvedSignature.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startGuidedUpdate.1"));
        String id = "guid-" + System.currentTimeMillis();
        Job j = new Job(id, "guided_update");
        // The turn is taken here, before the checks and any unlocking: two updates
        // approved from two tabs cannot start together.
        final String pkgName2 = name;
        return startOnTurn(id, j, I18n.tr("server.um.startGuidedUpdate.2", java.util.Map.of("name", String.valueOf(name))), "guided-update",
                () -> runGuidedUpdate(j, pkgName2, approvedSignature));
    }

    /**
     * "Update all" (finding 207): everything there is to update, in a single job, in this order: the FreeBSD
     * patches, the other packages (one plan), the mail server steps (one package, or a family with its main
     * one), Roundcube with its procedure (database copy, schema), and last the panel's Java, which stops the
     * panel and starts it again with its script. The owner, 2026-11-09: "there is still disorganization [...]
     * you must substantially rethink everything in a logical and simple way, why do I have Webmail (Roundcube)
     * separate, with a separate update of its own?".
     *
     * Each step is the usual job (the same checks, the same re-locking, the same restarts), and it runs if its
     * plan is the one that was read (the signature) or, if it has changed in the meantime because an earlier
     * step has already updated something, if each of its changes is among those shown in the confirmation
     * (APPROVED_CHANGES). One turn and one way back for all; at the first step that fails the job stops, and
     * says which one and which ones did not start.
     *
     * @param steps    the steps, in order; kind: os, plain, package (with the name of the main one), roundcube, java
     * @param approved the changes shown in the confirmation: name -> target version
     */
    public static JSONObject startEverything(java.util.List<EverythingStep> steps, Map<String, String> approved) {
        String bad = everythingProblem(steps, approved);
        if (bad != null) return new JSONObject().put("success", false).put("error", bad);
        String id = "all-" + System.currentTimeMillis();
        Job j = new Job(id, "update_everything");
        java.util.List<EverythingStep> list = new ArrayList<>(steps);
        Map<String, String> ok = new java.util.HashMap<>(approved);
        return startOnTurn(id, j, I18n.tr("server.um.everything.job", java.util.Map.of("n", String.valueOf(list.size()))),
                "update-everything", () -> runEverything(j, list, ok));
    }

    /** One step of "Update all": what it is (kind), the main package for the steps of a package, the fingerprint. */
    public record EverythingStep(String kind, String name, String signature) { }

    private static final java.util.List<String> EVERYTHING_ORDER = java.util.List.of("os", "plain", "package", "roundcube", "java");
    private static final java.util.regex.Pattern VERSION = java.util.regex.Pattern.compile("[A-Za-z0-9._,+-]{1,64}");

    /**
     * Null if the steps can be run; otherwise the reason. From 1 to 30 steps, in the fixed order (patches, other
     * packages, mail server steps, Roundcube, Java), each at most once except packages, a family only once, valid
     * names and fingerprints; the approved changes with valid names and versions, at most 2000.
     */
    static String everythingProblem(java.util.List<EverythingStep> steps, Map<String, String> approved) {
        String bad = I18n.tr("server.um.everything.bad");
        if (steps == null || approved == null || steps.isEmpty() || steps.size() > 30 || approved.size() > 2000) return bad;
        int last = -1;
        java.util.Set<String> families = new java.util.HashSet<>();
        for (EverythingStep st : steps) {
            if (st == null) return bad;
            int at = EVERYTHING_ORDER.indexOf(st.kind());
            if (at < 0 || at < last || (at == last && !"package".equals(st.kind()))) return bad;
            last = at;
            switch (st.kind()) {
                case "os" -> { if (!st.name().isEmpty() || !st.signature().isEmpty()) return bad; }
                case "package" -> {
                    // The empty fingerprint: a step that the checks stopped only because of a package that an
                    // earlier step updates (postfix-mysql after mysql84-client). It is checked when its turn comes,
                    // and it runs only if its plan stays among the changes shown (APPROVED_CHANGES).
                    if (!isValidName(st.name()) || !(st.signature().isEmpty() || validSignature(st.signature()))) return bad;
                    String family = familyOf(st.name());
                    if (!families.add(family == null ? st.name() : family)) return bad;
                }
                default -> { if (!st.name().isEmpty() || !validSignature(st.signature())) return bad; }
            }
        }
        for (Map.Entry<String, String> e : approved.entrySet())
            if (!isValidName(e.getKey()) || e.getValue() == null || !VERSION.matcher(e.getValue()).matches()) return bad;
        return null;
    }

    private static void runEverything(Job job, java.util.List<EverythingStep> steps, Map<String, String> approved) {
        int total = steps.size();
        APPROVED_CHANGES.set(approved);
        // The outcome of the FreeBSD patches ("Installed: ... a restart is needed"): the outcome of the chain
        // would replace it, and the missing restart could no longer be read under the line. It is appended to
        // the outcome, whether successful or stopped.
        String osNote = "";
        try {
            for (int i = 0; i < total; i++) {
                EverythingStep st = steps.get(i);
                String label = everythingLabel(st);
                job.status = "running";
                job.errorMessage = "";
                job.write("");
                job.write("=== " + I18n.tr("server.um.everything.step", java.util.Map.of(
                        "i", String.valueOf(i + 1), "n", String.valueOf(total), "name", label)) + " ===");
                switch (st.kind()) {
                    case "os" -> {
                        osPatchSteps(job);
                        if ("completed".equals(job.status) && job.outcome != null) osNote = job.outcome;
                    }
                    case "plain" -> updateJobSteps(job, st.signature());
                    case "package" -> guidedUpdateSteps(job, st.name(), st.signature());
                    case "roundcube" -> roundcubeSteps(job, st.signature());
                    case "java" -> {
                        // Last: the script for Java stops the panel and starts it again, outside this job.
                        JSONObject r = startJavaUpdateNow(st.signature());
                        if (r.optBoolean("success")) {
                            job.status = "completed";
                            job.write("  " + I18n.tr("server.um.everything.javaHanded"));
                        } else {
                            job.status = "error";
                            job.errorMessage = r.optString("error", "");
                        }
                    }
                    default -> { job.status = "error"; job.errorMessage = I18n.tr("server.um.everything.bad"); }
                }
                if (!"completed".equals(job.status)) {
                    java.util.List<String> rest = new ArrayList<>();
                    for (EverythingStep after : steps.subList(i + 1, total)) rest.add(everythingLabel(after));
                    String why = job.errorMessage == null ? "" : job.errorMessage;
                    job.status = "error";
                    job.errorMessage = I18n.tr(rest.isEmpty() ? "server.um.everything.stoppedLast" : "server.um.everything.stopped",
                            java.util.Map.of("i", String.valueOf(i + 1), "n", String.valueOf(total), "name", label,
                                    "why", why, "rest", String.join(", ", rest)))
                            + (osNote.isEmpty() ? "" : " " + osNote);
                    job.write("");
                    job.write("=== " + job.errorMessage + " ===");
                    return;
                }
            }
            boolean javaLast = "java".equals(steps.get(total - 1).kind());
            job.status = "completed";
            job.outcome = I18n.tr(javaLast ? "server.um.everything.doneJava" : "server.um.everything.done",
                    java.util.Map.of("n", String.valueOf(total))) + (osNote.isEmpty() ? "" : " " + osNote);
            job.write("");
            job.write("=== " + job.outcome + " ===");
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
        } finally {
            APPROVED_CHANGES.remove();
            job.finish();
        }
    }

    /** The name of a step, for the log and for the messages. */
    private static String everythingLabel(EverythingStep st) {
        return switch (st.kind()) {
            case "os" -> I18n.tr("server.um.everything.patches");
            case "plain" -> I18n.tr("server.um.everything.plain");
            case "roundcube" -> I18n.tr("server.um.everything.roundcube");
            case "java" -> I18n.tr("server.um.everything.java");
            default -> st.name();
        };
    }

    /**
     * Updates ONE locked package and puts back into service what depends on it.
     *
     * The order is the one we learned the hard way yesterday, on the other server:
     * unlock, update, ALWAYS RE-LOCK (even on error), then restart the
     * services and verify that they REALLY came back by comparing the pid. A package
     * updated with the process still on the old files is an open vulnerability that
     * shows as closed: the worst way of standing still.
     */
    private static void runGuidedUpdate(Job job, String name, String approvedSignature) {
        try {
            guidedUpdateSteps(job, name, approvedSignature);
        } finally {
            job.finish();
        }
    }

    /**
     * The steps of the guided update of ONE package (with its family), without closing the job: they are used by
     * the job for one package and by the "Update all" job, which runs more than one, one after the other, in the
     * same log (finding 205). At the end job.status says how it went: "completed", or "error" with the reason in
     * errorMessage.
     */
    private static void guidedUpdateSteps(Job job, String name, String approvedSignature) {
        job.status = "running";
        final int TOT = 6;
        boolean planNotFollowed = false;
        JSONArray outsidePlan = new JSONArray();
        JSONObject plan;
        java.util.List<String> toRelock2 = new ArrayList<>();
        java.util.List<String> pkgFamily = new ArrayList<>();
        boolean manualRecheck = false;
        java.util.List<String> services = new ArrayList<>();
        Map<String, String> pidBefore = new LinkedHashMap<>();
        Map<String, Boolean> activeBefore = new LinkedHashMap<>();
        // activeBefore covers only the services that will be restarted; the final picture
        // needs the state of ALL of them, taken before touching anything.
        Map<String, Boolean> servicesBefore = servicesState();
        // What the plan cannot tell: what the install scripts do to the live
        // configuration and to the listening addresses (see InstallSideEffects).
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        // The services that this job did NOT restart because a script changed the
        // configuration: they go into the outcome, with the command to restart them after looking at it.
        java.util.List<String> heldRestarts = new ArrayList<>();
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runGuidedUpdate.1", java.util.Map.of("name", String.valueOf(name))));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = packagePreflight(name);
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level"))) {
                        job.write("  [" + c.optString("level").toUpperCase() + "] "
                                + c.optString("label") + ": " + c.optString("detail"));
                    }
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            String versionBefore = pf.optString("current", "");
            String wait = pf.optString("available", "");
            pkgFamily = jsonArrayToList(pf.optJSONArray("family") == null
                    ? new JSONArray().put(name) : pf.getJSONArray("family"));

            // The plan that was read is run, or nothing. The preflight above has just
            // recalculated it: if the fingerprint is not the approved one, something has changed in
            // the meantime (usually the catalog) and nobody has seen the plan that would run.
            plan = pf.getJSONObject("plan");
            String currentSignature = pf.optString("signature", "");
            if (!planAccepted(approvedSignature, currentSignature, plan)) {
                job.status = "error";
                job.errorMessage = planRefused(job, plan, approvedSignature, currentSignature, "server.um.runGuidedUpdate.2");
                return;
            }
            job.write("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(currentSignature))));
            JSONArray planChanges = plan.getJSONArray("changes");
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                job.write("    " + PackagePlan.typeName(c.getString("type")) + " " + c.getString("name") + " "
                        + (c.getString("from").isEmpty() ? "" : c.getString("from"))
                        + (c.getString("to").isEmpty() || c.getString("to").equals(c.getString("from")) ? "" : " -> " + c.getString("to")));
            }
            // Exactly what the plan unlocked in the copy is unlocked: not one less
            // (pkg would stop), not one more (it would stay unprotected for no reason).
            java.util.List<String> protectedNames = jsonArrayToList(plan.getJSONArray("unlockedPackages"));
            JSONArray sv = pf.optJSONArray("services");
            for (int i = 0; sv != null && i < sv.length(); i++) {
                JSONObject o = sv.getJSONObject(i);
                String n = o.getString("name");
                services.add(n);
                pidBefore.put(n, o.optString("pid", ""));
                activeBefore.put(n, o.optBoolean("running", false));
            }
            job.write("  " + name + " " + versionBefore + " -> " + wait);
            if (pkgFamily.size() > 1) {
                job.write(I18n.tr("server.um.runGuidedUpdate.5", java.util.Map.of("p", String.valueOf((pkgFamily.size() - 1)), "p2", String.valueOf(familyReason(name)))));
            }
            job.write("  " + I18n.tr("server.um.x.svcInvolvedList", java.util.Map.of("list", String.valueOf(services.isEmpty() ? I18n.tr("server.um.x.none") : String.join(", ", services)))));

            job.advance(2, TOT);
            job.write("");
            job.write("[2/" + TOT + "] " + I18n.tr("server.um.x.tempUnlock"));
            if (protectedNames.isEmpty()) {
                job.write(I18n.tr("server.um.runGuidedUpdate.6"));
            } else {
                // The list is saved BEFORE unlocking: if the panel dies now, the
                // restore at startup knows what to re-lock. If it cannot be written, nothing
                // is unlocked: an interruption would leave them unlocked without a trace.
                for (String m : protectedNames)
                    if (!isValidName(m)) throw new IllegalStateException("invalid package name in the plan: " + m);
                String stateError = PackageQueue.writeState(protectedNames);
                if (stateError != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I did not unlock anything: " + stateError);
                job.write(I18n.tr("server.um.runGuidedUpdate.7", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
                // All of them must be re-locked, even an unlock that failed or timed out halfway: pkg lock on an
                // already locked package changes nothing, and this way the list on disk is closed
                // only when all of them show as locked.
                toRelock2.addAll(protectedNames);
                for (String m : protectedNames) {
                    boolean u = ok("pkg unlock -y " + m, 30);
                    job.write("    " + m + ": " + (u ? I18n.tr("server.um.x.unlocked") : I18n.tr("server.um.runGuidedUpdate.8")));
                    if (!u) throw new IllegalStateException("I could not unlock " + m);
                }
            }

            job.advance(3, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.9", java.util.Map.of("total", String.valueOf(TOT))));
            StringBuilder list = new StringBuilder();
            for (String m : pkgFamily) if (isValidName(m)) list.append(' ').append(m);

            // First the packages are downloaded and the plan is recalculated: until they are downloaded,
            // pkg does not see the file conflicts and the plan can grow during the run.
            // The full reason, with the measurement, is on fetchAndRecheck.
            final java.util.List<String> family = pkgFamily;
            Recheck grown = fetchAndRecheck(job, "pkg upgrade -F -y -U" + list + " 2>&1", plan,
                    () -> PackagePlan.planFor(family, lockedNames(), UpdateManager::reasonNotToUnlock,
                            UpdateManager::installedFamilyTwin));
            if (grown.stop() != null) throw org.daemoxcp.mail.util.ShownException.translated(grown.stop());
            plan = grown.plan();
            // The output is needed twice: shown as it scrolls by, and read again at the end to
            // fish out the messages that ask for an action.
            StringBuilder captured = new StringBuilder();
            // The inventory BEFORE: it is the only way to notice a package that changes
            // without being in the plan. The line-by-line comparison of the plan cannot see it.
            Map<String, String> inventoryBefore = PackagePlan.versionsOnly(PackagePlan.installed());
            // And the configuration with the listening addresses, at the same moment: the plan
            // says which packages change, not what their scripts rewrite.
            sideEffects.takeBefore();
            // Who reads each type of Postfix map, and the content of the maps that are not regenerated
            // from text, beforehand: if the library has changed afterwards, the maps are regenerated as before.
            PostfixMaps.Before mapsBefore = PostfixMaps.before();
            // -U: the same catalog the plan was calculated on. Downloading it again now could
            // bring versions different from the approved ones.
            int code = runLogged(job, "pkg upgrade -y -U" + list + " 2>&1", 1800, captured);
            // 4 = EX_NEEDRESTART: pkg has updated itself. Recent versions relaunch themselves
            // and do the rest; if this one stopped there, it is relaunched once, unchanged.
            if (code == 4) {
                job.write(I18n.tr("server.um.runGuidedUpdate.10"));
                code = runLogged(job, "pkg upgrade -y -U" + list + " 2>&1", 1800, captured);
            }

            // The comparison with the inventory is done RIGHT AWAY, before deciding whether to stop: a
            // pkg that exits non-zero is exactly the case in which the machine may have been
            // left halfway, and then knowing what changed matters more, not
            // less. Measured on the VM on 2026-10-23: a guided update of
            // postfix-mysql stopped halfway with exit 3 (mysql97-client in conflict
            // with mysql84-client over the same files) after the solver had added to the
            // plan a removal that the signed plan did not have.
            outsidePlan = compareWithInventory(job, inventoryBefore, plan,
                    "Guided update of " + name);
            // This too before deciding whether to stop, for the same reason. The restart of the
            // services below puts into effect what a script has written.
            sideEffects.checkConfig(job, plan, outsidePlan, !services.isEmpty());
            // The maps before the services are restarted, and even if pkg exited with an error: that is
            // exactly when the machine may have been left halfway.
            String mapsProblem = PostfixMaps.afterUpgrade(mapsBefore, l -> job.write("  " + l)).problem();

            if (code != 0) throw new IllegalStateException("pkg upgrade exited with code " + code);
            if (mapsProblem != null) throw org.daemoxcp.mail.util.ShownException.translated(mapsProblem);

            String versionAfter = sh("pkg query %v " + name + " 2>/dev/null", 20);
            job.write(I18n.tr("server.um.runGuidedUpdate.11", java.util.Map.of("versionAfter", String.valueOf(versionAfter))));
            if (versionAfter.equals(versionBefore)) {
                throw new IllegalStateException("the version did not change: the update had no effect");
            }
            // Every line of the plan, checked: not "pkg exited with 0", but "every package is
            // at the version the plan said".
            job.write(I18n.tr("server.um.runGuidedUpdate.12"));
            JSONArray verification = PackagePlan.verifyOutcome(plan);
            for (int i = 0; i < verification.length(); i++) {
                JSONObject v = verification.getJSONObject(i);
                job.write("    " + (v.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("name", String.valueOf(v.getString("name")), "expected", String.valueOf(v.getString("expected")), "found", String.valueOf(v.getString("found")))));
                if (!v.getBoolean("ok")) planNotFollowed = true;
            }
            if (planNotFollowed) job.write(I18n.tr("server.um.runGuidedUpdate.13"));


            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.14", java.util.Map.of("total", String.valueOf(TOT), "name", String.valueOf(name))));
            job.write(I18n.tr("server.um.runGuidedUpdate.15"));
            boolean servicesProblem = false;
            if (services.isEmpty()) {
                JSONArray rd = pf.optJSONArray("reverseDeps");
                job.write("  " + (rd == null || rd.length() == 0
                        ? I18n.tr("server.um.x.noRestartZero")
                        : I18n.tr("server.um.x.noRestartSome", java.util.Map.of("n", String.valueOf(rd.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(rd)))))));
                if (name.matches(SHARED_LIBRARIES)) {
                    job.write(I18n.tr("server.um.runGuidedUpdate.16", java.util.Map.of("name", String.valueOf(name))));
                    job.write(I18n.tr("server.um.runGuidedUpdate.17"));
                    job.write(I18n.tr("server.um.runGuidedUpdate.18"));
                    job.write(I18n.tr("server.um.runGuidedUpdate.19"));
                    job.write(I18n.tr("server.um.runGuidedUpdate.20"));
                    manualRecheck = true;
                }
            }
            // A script changed the configuration and the plan did not say so: restarting
            // would put into effect a change that nobody has read. It is finding 42 -
            // inet_protocols = ipv4 written into main.cf, and the restart that takes IPv6 away from a
            // mail server that showed as "in service". So there is no restart: the services keep
            // the previous configuration, still in memory, and whoever reads decides. The cost is
            // written below, and it is the same state in which the full maintenance always leaves
            // the machine: updated, with the old processes until someone restarts
            // them.
            boolean holdRestarts = sideEffects.configChangedByScript() && !services.isEmpty();
            if (holdRestarts) {
                job.write(I18n.tr("server.drift.restartHeld", java.util.Map.of("list", String.join(", ", services))));
                job.write(I18n.tr("server.drift.restartHeldCost"));
            }
            for (String s : services) {
                if (holdRestarts) {
                    heldRestarts.add(s);
                    job.write("      service " + s + " restart");
                    continue;
                }
                if (!Boolean.TRUE.equals(activeBefore.get(s))) {
                    job.write(I18n.tr("server.um.runGuidedUpdate.21", java.util.Map.of("s", String.valueOf(s))));
                    continue;
                }
                // The service is asked whether it accepts its own configuration BEFORE
                // restarting it: if it does not, restarting it would just shut it down. Better
                // to leave it up with the old one and say so.
                String test = testConfigOf(s);
                if (test != null) {
                    Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), test + " 2>&1");
                    if (!pr.success()) {
                        job.write(I18n.tr("server.um.runGuidedUpdate.22", java.util.Map.of("s", String.valueOf(s))));
                        for (String l : pr.outputTrim().split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
                        job.write(I18n.tr("server.um.runGuidedUpdate.23"));
                        servicesProblem = true;
                        continue;
                    }
                    job.write(I18n.tr("server.um.runGuidedUpdate.24", java.util.Map.of("s", String.valueOf(s))));
                }
                boolean r1 = ok("service " + s + " restart", 120);
                boolean active = cameUp(s);
                String pidAfter = servicePid(s);
                String pidP = pidBefore.getOrDefault(s, "");
                String note = "";
                if (!pidP.isEmpty() && !pidAfter.isEmpty()) {
                    note = pidP.equals(pidAfter)
                        ? I18n.tr("server.um.runGuidedUpdate.25", java.util.Map.of("pidAfter", String.valueOf(pidAfter)))
                        : "  (pid " + pidP + " -> " + pidAfter + ")";
                    if (pidP.equals(pidAfter)) servicesProblem = true;
                }
                job.write("    " + s + ": " + (r1 ? I18n.tr("server.um.x.restarted") : I18n.tr("server.um.runGuidedUpdate.26"))
                        + ", " + (active ? I18n.tr("server.um.x.nowRunning") : I18n.tr("server.um.x.nowNotRunning")) + note);
                if (!active) servicesProblem = true;

                // Did it find its data again, or did it start back up empty?
                String[] after = testAfterOf(s);
                if (after != null && active) {
                    String out = sh(after[1], 30).trim();
                    long n = number(out);
                    job.write("      " + I18n.tr(after[2]) + ": " + (out.isEmpty() ? I18n.tr("server.um.runGuidedUpdate.27") : String.valueOf(n)));
                    if (n == 0) {
                        job.write(I18n.tr("server.um.runGuidedUpdate.28"));
                        job.write(I18n.tr("server.um.runGuidedUpdate.29"));
                        job.write("      " + I18n.tr("server.um.x.rsGreyLimits"));
                        servicesProblem = true;
                    }
                }
            }

            job.advance(5, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.30", java.util.Map.of("total", String.valueOf(TOT))));
            // On the NEW version, the one just installed: asking with the name alone
            // would answer a different question (see auditReport).
            JSONObject reportAfter = auditReport(name, versionAfter);
            if (!reportAfter.optBoolean("done")) {
                // "I could not check" is not "there are no vulnerabilities".
                job.write("  " + reportAfter.optString("error"));
                job.write("  " + I18n.tr("server.um.x.auditUncertain"));
            } else if (reportAfter.optInt("problems") == 0) {
                job.write(I18n.tr("server.um.runGuidedUpdate.31", java.util.Map.of("name", String.valueOf(name))));
            } else {
                job.write("  " + I18n.tr("server.um.x.cvesLeft", java.util.Map.of("n", String.valueOf(reportAfter.optInt("problems")), "name", String.valueOf(name), "d", String.valueOf(reportAfter.getString("description")))));
                job.write(I18n.tr("server.um.runGuidedUpdate.32"));
            }

            writeActionMessages(job, captured.toString());

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.35", java.util.Map.of("total", String.valueOf(TOT))));
            boolean fallen = fallenServices(job, servicesBefore);
            sideEffects.checkListening(job);
            java.util.List<String> effects = sideEffects.problems();
            if (!heldRestarts.isEmpty())
                effects.add(I18n.tr("server.drift.restartHeldProblem", java.util.Map.of("list", String.join(", ", heldRestarts))));

            if (planNotFollowed || !outsidePlan.isEmpty()) {
                // Two different failures, and the message tells them apart: "plan not followed" is
                // a package of the plan that did not get where it should have, the divergence is
                // something that changed without being in the plan. They can show up
                // together, so both are reported.
                job.status = "error";
                java.util.List<String> problems = new ArrayList<>();
                if (planNotFollowed) problems.add(I18n.tr("server.um.runGuidedUpdate.36"));
                if (!outsidePlan.isEmpty()) problems.add(divergenceMessage(outsidePlan));
                problems.addAll(effects);
                job.errorMessage = String.join(" ", problems);
            } else if (servicesProblem || fallen) {
                job.status = "error";
                java.util.List<String> problems = new ArrayList<>();
                problems.add(I18n.tr("server.um.runGuidedUpdate.37"));
                problems.addAll(effects);
                job.errorMessage = String.join(" ", problems);
            } else if (!effects.isEmpty()) {
                // Every step succeeded - plan, restart, pid, services - and it is exactly the case
                // of finding 42: the package is in service, but with a configuration that
                // nobody approved, or without an address that answered before.
                job.status = "error";
                job.errorMessage = String.join(" ", effects);
            } else if (manualRecheck) {
                // It is not an error, but not a "done and verified" either: calling it completed
                // would be asserting something that the panel could not check.
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runGuidedUpdate.38", java.util.Map.of("name", String.valueOf(name), "versionAfter", String.valueOf(versionAfter))));
                job.write(I18n.tr("server.um.runGuidedUpdate.39"));
                job.write(I18n.tr("server.um.runGuidedUpdate.40"));
            } else {
                job.status = "completed";
                job.write("");
                job.write("=== " + I18n.tr("server.um.x.inService", java.util.Map.of("name", String.valueOf(name), "v", String.valueOf(versionAfter))) + " ===");
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            // pkg stopped halfway after a script has already written: both are reported.
            for (String p : sideEffects.problems()) job.errorMessage += " " + p;
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // The re-lock ALWAYS happens, whatever went wrong above.
            if (!toRelock2.isEmpty()) {
                job.write("");
                job.write(I18n.tr("server.um.x.reprotecting", java.util.Map.of("n", String.valueOf(toRelock2.size()))));
                int relockedCount = 0;
                for (String m : toRelock2) {
                    boolean relocked = ok("pkg info -e " + m, 15) && ok("pkg lock -y " + m, 30);
                    if (relocked) relockedCount++;
                    else job.write(I18n.tr("server.um.runGuidedUpdate.41", java.util.Map.of("m", String.valueOf(m))));
                }
                job.write("  " + I18n.tr("server.um.x.reprotectedCount", java.util.Map.of("n", String.valueOf(relockedCount), "tot", String.valueOf(toRelock2.size()))));
                if (relockedCount == toRelock2.size()) clearState();
                else {
                    job.write(I18n.tr("server.um.runPythonTransition.21", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
                    if ("completed".equals(job.status)) {
                        job.status = "error";
                        job.errorMessage = I18n.tr("server.um.runGuidedUpdate.42");
                    }
                }
            }
        }
    }

    /**
     * Deletes ONLY the rspamd Hyperscan caches and restarts the service.
     *
     * It is a deletion, that is the category of operation that can make something disappear:
     * the path and the criterion are written here and do not come from the request, and at the
     * end the panel PROVES it touched nothing else by counting the remaining files before and after.
     * "I deleted only those" is a claim, and claims get verified.
     */
    public static JSONObject startRspamdCacheCleanup() {
        String id = "rspamd-cache-" + System.currentTimeMillis();
        Job j = new Job(id, "rspamd_cache");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                final String DIR = "/var/db/rspamd";
                j.advance(1, 4);
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.1"));
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.2"));
                long unserBefore = number(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long othersBefore = number(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.3", java.util.Map.of("unserBefore", String.valueOf(unserBefore))));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.4", java.util.Map.of("othersBefore", String.valueOf(othersBefore))));
                if (unserBefore == 0) {
                    j.status = "completed";
                    j.write(I18n.tr("server.um.startRspamdCacheCleanup.5"));
                    return;
                }
                for (String f : sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null", 60).split("\n")) {
                    if (!f.trim().isEmpty()) j.write("      " + f.trim());
                }

                j.advance(2, 4);
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.6"));
                ok("find " + DIR + " -type f -name '*.unser' -delete", 120);

                j.advance(3, 4);
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.7"));
                long unserAfter = number(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long othersAfter = number(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.8", java.util.Map.of("unserAfter", String.valueOf(unserAfter))));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.9", java.util.Map.of("othersBefore", String.valueOf(othersBefore), "othersAfter", String.valueOf(othersAfter))));
                if (othersAfter != othersBefore) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.10", java.util.Map.of("othersBefore", String.valueOf(othersBefore), "othersAfter", String.valueOf(othersAfter)));
                    j.write("    " + I18n.tr("server.um.x.alarm", java.util.Map.of("m", String.valueOf(j.errorMessage))));
                    return;
                }
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.11"));

                j.advance(4, 4);
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.12"));
                Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), "rspamadm configtest 2>&1");
                if (!pr.success()) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.13");
                    j.write("    " + pr.outputTrim());
                    return;
                }
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.14"));
                String pidBefore = servicePid("rspamd");
                ok("service rspamd restart", 120);
                boolean active = ok("service rspamd status", 30);
                String pidAfter = servicePid("rspamd");
                j.write("    rspamd: " + (active ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26"))
                        + (pidBefore.isEmpty() || pidAfter.isEmpty() ? "" : "  (pid " + pidBefore + " -> " + pidAfter + ")"));
                if (!active) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.15");
                } else {
                    j.status = "completed";
                    j.write("");
                    j.write(I18n.tr("server.um.startRspamdCacheCleanup.16"));
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.finish();
            }
        }, "rspamd-cache");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Packages that require a shared library that is NO longer on the disk.
     *
     * It is the hole that stopped the mail: after replacing mysql80-client with
     * mysql84-client, postfix-mysql and dovecot-mysql stayed built against
     * libmysqlclient.so.21 and no longer loaded. The preflight had verified that the
     * REPOSITORY provided them compatible with 8.4 - and that was true - but not that the
     * INSTALLED ones were. They are two different things and I had treated them as one.
     *
     * Here there is no guessing: pkg is asked which libraries each package requires (%B) and
     * we look at whether they really exist.
     */
    public static JSONObject packagesWithMissingLibraries() {
        JSONArray broken = new JSONArray();
        java.util.LinkedHashSet<String> missingLibraries = new java.util.LinkedHashSet<>();
        for (String line : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            String name = t.substring(0, sp).trim();
            String lib = t.substring(sp + 1).trim();
            if (!isValidName(name) || lib.isEmpty()) continue;
            if (!lib.matches("[A-Za-z0-9._+-]{1,128}")) continue;
            if (missingLibraries.contains(lib)) { broken.put(new JSONObject().put("name", name).put("lib", lib)); continue; }
            // A library is there if the linker can find it among those known to the system.
            if (!ok("ldconfig -r 2>/dev/null | grep -q ' " + lib + "$' || " +
                    "find /lib /usr/lib /usr/local/lib -name '" + lib + "' -maxdepth 3 2>/dev/null | grep -q .", 30)) {
                missingLibraries.add(lib);
                broken.put(new JSONObject().put("name", name).put("lib", lib));
            }
        }
        return new JSONObject().put("success", true).put("packages", broken)
                .put("missingLibs", new JSONArray(new ArrayList<>(missingLibraries)));
    }

    /**
     * "openssl: no package requires it, it can be removed" was a conclusion too
     * confident for the way it was calculated. `pkg query %rn` says who DECLARES it in the
     * pkg registry; it does not say who is really opening it.
     *
     * The difference matters because there are TWO OpenSSLs on the disk: the base system one in
     * /usr/lib, which is not a package, does not appear in pkg and is not touched, and the port in
     * /usr/local/lib. If the two copies carry the same soname, no reading of the registry
     * can tell which of the two gets opened, because the two names are identical.
     *
     * So three distinct things are measured, and the third is the only one that decides:
     *   1. who declares the package                        -> pkg query %rn
     *   2. who requires its sonames                        -> pkg query %B  (ambiguous if the
     *      sonames of the port and those of base coincide)
     *   3. which LIVE processes have mapped a library in /usr/local/lib -> procstat -v
     *
     * procstat(1) shows "process virtual memory mappings, including [...] mapped object
     * information": it is what is open now, not what someone declared when
     * the package was built. However, it requires being the owner of the process
     * or root; if one is not, the list comes back empty and would look like "nobody uses it".
     * That is why the number of processes mapping any libssl/libcrypto is also counted: if
     * that total is zero on a mail server with TLS enabled, the measurement did not work
     * and that must be said, instead of passing silence off as an answer.
     */
    /**
     * The openssl case came up thanks to the owner's intuition, not because the panel
     * knew how to look for it: nobody declared the port, but a panel script installs it
     * and the panel runs its command. Asking intuition to repeat itself at
     * every removal is exactly the way to get it wrong the time nobody thinks of it.
     *
     * Here the question becomes a measurement, and it holds for ANY package: before removing it,
     * does the panel use it in its own scripts?
     *
     * No hand-written list is consulted, which would go stale at the first change:
     * the jar THAT IS RUNNING is read. The names of the commands the panel invokes are
     * string constants inside its classes, so the panel's classes are extracted from
     * the jar and searched for the names of the executables that the package installs.
     *
     * Two precautions, because a search can fail in ways that look like an answer:
     *  - the bytes read from the jar are counted: if they are zero, the read did not
     *    succeed and that must be said, instead of concluding "it does not use it";
     *  - very short names (tr, cut, ls) would appear everywhere by chance, so below
     *    four characters no decision is made and that is declared.
     */
    /**
     * Which packages are even CANDIDATES for removal: those installed
     * explicitly (not pulled in as a dependency) and that no other package
     * declares. They are the only ones on which it makes sense to ask the question, and
     * it is the list that the "does the panel use it?" check must go through before
     * removing anything.
     *
     * It is obtained with two reads instead of one query per package:
     * the list of the explicit ones, and the set of all the names that appear as a dependency
     * of something. The difference between the two is the answer.
     */
    public static JSONObject removalCandidates() {
        java.util.LinkedHashSet<String> explicit = new java.util.LinkedHashSet<>();
        for (String n : sh("pkg query -e '%a = 0' '%n' 2>/dev/null", 60).split("\n"))
            if (isValidName(n.trim())) explicit.add(n.trim());

        java.util.HashSet<String> required = new java.util.HashSet<>();
        for (String line : sh("pkg query '%n %dn' 2>/dev/null", 120).split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp > 0) required.add(t.substring(sp + 1).trim());
        }

        String lock = sh("pkg lock -l 2>/dev/null", 30);

        JSONArray outside = new JSONArray();
        int withRole = 0;
        for (String n : explicit) {
            if (required.contains(n)) continue;
            String role = roleOf(n);
            if (role != null) withRole++;
            boolean essential = n.equals("pkg") || n.equals("pkg-devel");
            outside.put(new JSONObject().put("name", n)
                    .put("version", sh("pkg query %v " + n + " 2>/dev/null", 20))
                    .put("isProtected", locked(lock, n))
                    .put("role", role == null ? "" : role)
                    .put("essential", essential)
                    .put("warning", essential
                            ? I18n.tr("server.um.removalCandidates.1")
                            : (role == null ? "" : I18n.tr("server.um.removalCandidates.2"))));
        }
        return new JSONObject().put("success", true).put("candidates", outside)
                .put("explicitTotal", explicit.size()).put("withRole", withRole)
                .put("caution", I18n.tr("server.um.removalCandidates.3"))
                .put("explanation", I18n.tr("server.um.removalCandidates.4"));
    }

    /**
     * The places where the panel, the packages and the administrator leave things that get
     * run LATER: renewal scripts, cron, rc.d, periodic, configurations. The jar does not
     * contain them, so searching only in there is not enough.
     */
    private static final String[][] PLACES = {
        {"/etc",                    "server.um.removalCandidates.5"},
        {"/usr/local/etc",          "server.um.removalCandidates.6"},
        {"/var/cron/tabs",          "server.um.place.userCrontabs"},
        {"/var/db/daemoxcp-mail",       "server.um.removalCandidates.7"},
        {"/root",                   "server.um.place.root"},
        {"/usr/local/bin",          "server.um.removalCandidates.8"},
        {"/usr/local/sbin",         "server.um.removalCandidates.9"},
        {"/usr/local/www/roundcube","server.um.removalCandidates.10"},
    };

    /**
     * The in-depth analysis before removing a package. It comes from a precise request:
     * "I don't want scripts or anything else to stop working afterwards".
     *
     * The check on the jar answered only one question - does the panel invoke its commands? -
     * and that question is the least dangerous, because a command invoked by its bare name
     * falls back on its own to the other copy in the PATH. What really breaks is a reference
     * that CANNOT fall back:
     *
     *   - an absolute path inside the package (/usr/local/bin/openssl): the file disappears,
     *     and whoever names it fails;
     *   - a soname provided by the package (libssl.so.12): the library disappears, and
     *     whoever links to it no longer starts.
     *
     * So two lists are kept strictly apart: the references that BREAK and those that
     * HOLD. And the search covers three different places, because two out of three are enough
     * to be misled: inside the jar, among the installed packages (who declares those sonames),
     * and in the text files of the system, where the scripts that run later live.
     *
     * Every search declares how many text files it examined. A search that finds
     * nothing because it looked nowhere is indistinguishable, in the result, from
     * one that looked and found nothing: the count is what tells them apart.
     */
    public static JSONObject deepAnalysis(String pkgName) {
        if (!isValidName(pkgName))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        if (!ok("pkg info -e " + pkgName, 20))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.2", java.util.Map.of("pkg", String.valueOf(pkgName))));

        JSONObject r = new JSONObject().put("success", true).put("pkgName", pkgName);

        // --- what the package puts on the disk: absolute paths and sonames ---
        String list = sh("pkg query '%Fp' " + pkgName + " 2>/dev/null", 60);
        if (list.isBlank()) list = sh("pkg info -l " + pkgName + " 2>/dev/null", 60);
        java.util.LinkedHashSet<String> paths = new java.util.LinkedHashSet<>();
        java.util.LinkedHashSet<String> bases = new java.util.LinkedHashSet<>();
        for (String line : list.split("\n")) {
            String f = line.trim();
            if (!f.matches("(/usr)?(/local)?/(s?bin|libexec)(/[A-Za-z0-9._+-]{1,64}){1,2}")) continue;
            paths.add(f);
            bases.add(f.substring(f.lastIndexOf('/') + 1));
        }
        java.util.LinkedHashSet<String> soname = new java.util.LinkedHashSet<>();
        for (String l : sh("pkg query %b " + pkgName + " 2>/dev/null", 30).split("\n"))
            if (l.trim().matches("[A-Za-z0-9._+-]{1,128}")) soname.add(l.trim());
        r.put("paths", new JSONArray(new ArrayList<>(paths)))
         .put("soname", new JSONArray(new ArrayList<>(soname)));

        // The reasons why a removal breaks something: absolute path, or soname.
        java.util.LinkedHashSet<String> breakOnes = new java.util.LinkedHashSet<>(paths);
        breakOnes.addAll(soname);
        for (String sn : soname) { breakOnes.add("/usr/local/lib/" + sn); }
        r.put("searched", new JSONArray(new ArrayList<>(breakOnes)));

        // --- 1. which of the installed packages declare those sonames ---
        JSONArray declareSoname = new JSONArray();
        if (!soname.isEmpty()) {
            for (String line : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
                String t = line.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                String n = t.substring(0, sp).trim(), lib = t.substring(sp + 1).trim();
                if (!n.equals(pkgName) && soname.contains(lib))
                    declareSoname.put(new JSONObject().put("pkgName", n).put("library", lib));
            }
        }
        r.put("declareSoname", declareSoname);

        // --- 2. the running jar: absolute paths and sonames, not just the bare names ---
        String jar = jarPath();
        JSONArray inJar = new JSONArray();
        long jarBytes = 0;
        int blockingJars = 0;
        String myFile = UpdateManager.class.getSimpleName();
        if (jar != null && !jar.isBlank() && ok("test -r " + jar, 15)) {
            String n = sh("tar -xOf " + jar + " 'org/daemoxcp/mail/*' 2>/dev/null | wc -c", 120)
                    .trim().replaceAll("[^0-9]", "");
            if (!n.isEmpty()) jarBytes = Long.parseLong(n);
            if (jarBytes > 0) {
                StringBuilder pat = new StringBuilder();
                for (String x : breakOnes) pat.append(" -e '").append(x).append("'");
                // Extraction into a temporary folder: only that way can grep tell WHICH class.
                String output = sh("d=$(mktemp -d) && tar -xf " + jar + " -C \"$d\" 'org/daemoxcp/mail/*' "
                        + "2>/dev/null; grep -rlaF" + pat + " \"$d\" 2>/dev/null "
                        + "| sed \"s|^$d/||\"; rm -rf \"$d\"", 240);
                for (String line : output.split("\n")) {
                    String f = line.trim();
                    if (f.isEmpty() || !f.endsWith(".class")) continue;
                    String className = f.substring(f.lastIndexOf('/') + 1).replace(".class", "");
                    boolean mine = className.equals(myFile) || className.startsWith(myFile + "$");
                    if (!mine) blockingJars++;
                    inJar.put(new JSONObject().put("className", className).put("file", f)
                            .put("selfReference", mine));
                }
            }
        }
        r.put("jar", jar == null ? "" : jar).put("jarBytes", jarBytes)
         .put("jarRead", jarBytes > 0).put("inJar", inJar).put("blockingJars", blockingJars)
         .put("checkClass", myFile);

        // --- 3. the text files of the system: where the scripts that run later live ---
        JSONArray places = new JSONArray();
        int totalBreak = 0, totalHold = 0;
        StringBuilder patternsBreak = new StringBuilder();
        for (String x : breakOnes) patternsBreak.append(" -e '").append(x).append("'");
        StringBuilder patternsHold = new StringBuilder();
        for (String b : bases) if (b.length() >= 4) patternsHold.append(" -e '").append(b).append("'");

        for (String[] L : PLACES) {
            if (!ok("test -d " + L[0], 15)) continue;
            JSONObject u = new JSONObject().put("where", L[0]).put("whatItContains", I18n.tr(L[1]));
            // How many text files exist here: it is the proof that the search looked.
            String cnt = sh("grep -rIl '' " + L[0] + " 2>/dev/null | wc -l", 180).trim().replaceAll("[^0-9]", "");
            int reviewed = cnt.isEmpty() ? 0 : Integer.parseInt(cnt);
            u.put("filesReviewed", reviewed);

            JSONArray breaks = new JSONArray();
            if (patternsBreak.length() > 0) {
                for (String line : sh("grep -rInIF" + patternsBreak + " " + L[0]
                        + " 2>/dev/null | head -40", 240).split("\n")) {
                    if (line.isBlank()) continue;
                    breaks.put(line.length() > 300 ? line.substring(0, 300) + "..." : line);
                }
            }
            int hold = 0;
            if (patternsHold.length() > 0) {
                String q = sh("grep -rIwoF" + patternsHold + " " + L[0] + " 2>/dev/null | wc -l", 240)
                        .trim().replaceAll("[^0-9]", "");
                if (!q.isEmpty()) hold = Integer.parseInt(q);
            }
            u.put("breakOnes", breaks).put("hold", hold);
            totalBreak += breaks.length();
            totalHold += hold;
            places.put(u);
        }
        r.put("places", places).put("totalBreak", totalBreak).put("totalHold", totalHold);

        // --- the verdict ---
        // The reference in the class that RUNS this check does not block: it is
        // the analysis naming what it must inspect, not a use that would break.
        boolean blocking = totalBreak > 0 || blockingJars > 0 || declareSoname.length() > 0;
        r.put("blocking", blocking);
        r.put("verdict", blocking ? "REFS_WOULD_BREAK" : "NO_REF_BREAKS");
        int auto = inJar.length() - blockingJars;
        r.put("explanation", blocking
                ? I18n.tr("server.um.deepAnalysis.5", java.util.Map.of("pkg", String.valueOf(pkgName)))
                : I18n.tr("server.um.x.deepClean", java.util.Map.of("pkg", String.valueOf(pkgName), "n", String.valueOf(totalHold)))
                  + (auto > 0
                     ? " " + (auto == 1
                        ? I18n.tr("server.um.x.deepSelf.one", java.util.Map.of("file", String.valueOf(myFile)))
                        : I18n.tr("server.um.x.deepSelf.other", java.util.Map.of("n", String.valueOf(auto), "file", String.valueOf(myFile))))
                     : ""));
        r.put("caveat", I18n.tr("server.um.deepAnalysis.6"));
        return r;
    }

    /**
     * The jar's verdict lets the removal go ahead: the panel does not use its commands (even if it is a
     * library: who requires it is told by pkg query %rn, checked before, and the files on the disk are looked
     * at by deepAnalysis, after), or it names them but they are not this package's. On 2026-10-25 the verdicts
     * switched to English, and the Italian prefix of the library verdict had stayed here: the removal of an
     * unused library was refused. Pure function.
     */
    static boolean removableByJarVerdict(String v) {
        return "PANEL_DOES_NOT_USE".equals(v) || "NAMES_NOT_THEIRS".equals(v) || "LIBRARY_ONLY".equals(v);
    }

    /**
     * The removal of a package, done by the panel and not dictated as a command to run over SSH.
     *
     * It is not a button that runs "pkg delete": it is the check that decides whether to run it.
     * It refuses on its own in the cases where the removal would do damage, and in those where it
     * could not establish that it would not - which is the same thing. Then it verifies the outcome
     * by looking at the system, not at pkg's exit code: the package is really gone,
     * no other package has been left without a library, the services are still up.
     *
     * It waits for the package turn (see PackageQueue).
     */
    public static JSONObject removePackage(String name) {
        String id = "remove-" + System.nanoTime();
        String refusal = PackageQueue.take(id, I18n.tr("server.um.removePackage.1", java.util.Map.of("name", String.valueOf(name))));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        StringBuilder wayBack = new StringBuilder();
        PackageWayBack.Prepared wb;
        try { wb = PackageWayBack.before(l -> wayBack.append(l).append('\n'), "remove-" + name); }
        catch (IllegalStateException e) {
            PackageQueue.release(id);
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("removePackage", e));
        }
        JSONObject r = null;
        try { return r = removePackageNow(name); }
        finally {
            PackageWayBack.after(l -> wayBack.append(l).append('\n'), wb);
            if (r != null) r.put("log", wayBack + r.optString("log", ""));
            refreshLockTrace();
            PackageQueue.release(id);
        }
    }

    private static JSONObject removePackageNow(String name) {
        if (!isValidName(name))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        StringBuilder log = new StringBuilder();
        JSONObject r = new JSONObject().put("pkgName", name);

        if (!ok("pkg info -e " + name, 20)) {
            log.append(I18n.tr("server.um.x.rmNotInstalled", java.util.Map.of("name", String.valueOf(name)))).append("\n")
               .append(I18n.tr("server.um.x.rmChecksAnyway")).append("\n");
            JSONObject lib0 = packagesWithMissingLibraries();
            JSONArray broken0 = lib0.optJSONArray("packages");
            boolean fault0 = broken0 != null && broken0.length() > 0;
            r.put("missingLibraries", lib0).put("services", servicesJson())
             .put("removed", true).put("alreadyAbsent", true).put("fault", fault0)
             .put("after", countLines(sh("pkg query %n 2>/dev/null", 60)));
            log.append("--- ").append(I18n.tr("server.um.x.check")).append(" ---\n")
               .append(fault0 ? I18n.tr("server.um.removePackageNow.1", java.util.Map.of("length", String.valueOf(broken0.length())))
                               : I18n.tr("server.um.removePackageNow.2")).append("\n");
            return r.put("success", true).put("log", log.toString())
                    .put("note", fault0
                            ? I18n.tr("server.um.removePackageNow.3", java.util.Map.of("name", String.valueOf(name), "name2", String.valueOf(name)))
                            : I18n.tr("server.um.removePackageNow.4", java.util.Map.of("name", String.valueOf(name))));
        }

        // --- who declares it: if anyone does, it is not touched ---
        String declare = sh("pkg query %rn " + name + " 2>/dev/null", 30).trim();
        if (!declare.isEmpty())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.x.rmDeclaredDep", java.util.Map.of("list", String.valueOf(declare.replace("\n", ", ")))));

        // --- and the panel? the same measurement as the tab, redone now ---
        JSONObject use = panelUsage(name);
        r.put("use", use);
        String v = use.optString("verdict", "");
        if (!removableByJarVerdict(v))
            return new JSONObject().put("success", false).put("use", use)
                    .put("error", I18n.tr("server.um.x.rmJarSays", java.util.Map.of("v", String.valueOf(v))) + " "
                            + use.optString("explanation", ""));

        // --- and the references on the disk? the jar is only one of the three places ---
        JSONObject deepResult = deepAnalysis(name);
        r.put("deep", deepResult);
        if (deepResult.optBoolean("blocking"))
            return new JSONObject().put("success", false).put("deep", deepResult)
                    .put("error", I18n.tr("server.um.removePackageNow.5", java.util.Map.of("name", String.valueOf(name))));

        // --- snapshot before, to be able to compare after ---
        int before = countLines(sh("pkg query %n 2>/dev/null", 60));
        log.append(I18n.tr("server.um.x.pkgsBefore", java.util.Map.of("n", String.valueOf(before)))).append("\n");

        boolean isProtected = locked(sh("pkg lock -l 2>/dev/null", 30), name);
        log.append(isProtected ? I18n.tr("server.um.x.protBeforeYes") : I18n.tr("server.um.x.protBeforeNo")).append("\n");
        if (isProtected) {
            log.append("--- ").append(I18n.tr("server.um.x.unlockSection")).append(" ---\n")
               .append(sh("pkg unlock -y " + name + " 2>&1", 60)).append("\n");
            if (locked(sh("pkg lock -l 2>/dev/null", 30), name)) {
                log.append(I18n.tr("server.um.x.stillProtected")).append("\n");
                return r.put("success", false).put("log", log.toString())
                        .put("error", I18n.tr("server.um.removePackageNow.6", java.util.Map.of("name", String.valueOf(name))));
            }
            log.append(I18n.tr("server.um.x.protRemoved")).append("\n");
        }

        String deleteOutput = sh("pkg delete -y " + name + " 2>&1", 180);
        log.append("--- ").append(I18n.tr("server.um.x.removalSection")).append(" ---\n").append(deleteOutput).append("\n");

        // The outcome is told by the system, not by the exit code.
        boolean via = !ok("pkg info -e " + name, 20);
        int after = countLines(sh("pkg query %n 2>/dev/null", 60));
        log.append(I18n.tr("server.um.x.pkgsAfter", java.util.Map.of("n", String.valueOf(after)))).append("\n");
        r.put("before", before).put("after", after).put("removed", via);

        if (!via) {
            if (isProtected) log.append("--- riprotezione ---\n").append(sh("pkg lock -y " + name + " 2>&1", 60));
            // pkg states the reason in its output: report it instead of leaving
            // the user to read the log to understand why.
            String why = deleteOutput.contains("locked")
                    ? I18n.tr("server.um.removePackageNow.7")
                    : (deleteOutput.contains("vital") ? I18n.tr("server.um.x.markedVital") : "");
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.x.stillInstalled")
                            + why + (isProtected ? ". " + I18n.tr("server.um.x.reprotectedAsBefore") : "."));
        }

        // --- the check that matters: has anything been left without a library? ---
        JSONObject lib = packagesWithMissingLibraries();
        JSONArray broken = lib.optJSONArray("packages");
        r.put("missingLibraries", lib);
        r.put("services", servicesJson());

        boolean fault = broken != null && broken.length() > 0;
        log.append("--- ").append(I18n.tr("server.um.x.check")).append(" ---\n")
           .append(fault ? I18n.tr("server.um.removePackageNow.1", java.util.Map.of("length", String.valueOf(broken.length())))
                          : I18n.tr("server.um.removePackageNow.2")).append("\n");
        return r.put("success", true).put("log", log.toString()).put("fault", fault)
                .put("note", fault
                        ? I18n.tr("server.um.removePackageNow.8", java.util.Map.of("name", String.valueOf(name), "name2", String.valueOf(name)))
                        : I18n.tr("server.um.removePackageNow.9"));
    }

    /**
     * External tools the panel depends on, with the folder in which the port puts them.
     * It is not a decorative list: if one of them cannot be reached, the function that uses it
     * fails far from here and with a message that talks about something else.
     */
    private static final String[][] TOOLS = {
        {"mysqldump",       "/usr/local/bin",  "server.um.removePackageNow.10"},
        {"mysql",           "/usr/local/bin",  "server.um.removePackageNow.11"},
        {"doveadm",         "/usr/local/bin",  "server.um.removePackageNow.12"},
        {"postmap",         "/usr/local/sbin", "server.um.removePackageNow.13"},
        {"postconf",        "/usr/local/sbin", "server.um.removePackageNow.14"},
        {"rspamadm",        "/usr/local/bin",  "server.um.removePackageNow.15"},
        {"fail2ban-client", "/usr/local/bin",  "server.um.tool.fail2ban"},
        {"nginx",           "/usr/local/sbin", "server.um.removePackageNow.16"},
        {"pkg",             "/usr/local/sbin", "server.um.removePackageNow.17"},
        {"openssl",         "/usr/bin",        "server.um.removePackageNow.18"},
        {"procstat",        "/usr/bin",        "server.um.removePackageNow.19"},
        {"bectl",           "/sbin",           "server.um.removePackageNow.20"},
    };

    /**
     * The environment in which the panel runs commands. It comes from a failure that took
     * half an hour to understand: the Roundcube preflight said "mysqldump is not installed
     * or is not in the panel's PATH" while mysql84-client was properly installed.
     * The two things that message lumped together are very different, and telling them apart
     * is trivial: one looks at whether the file is on the disk, and separately whether the PATH reaches it.
     */
    public static JSONObject panelBootEnvironment() {
        JSONObject r = new JSONObject().put("success", true)
                .put("inheritedPath", org.daemoxcp.mail.util.Shell.inheritedPath())
                .put("pathUsed", org.daemoxcp.mail.util.Shell.fullPath());
        JSONArray a = new JSONArray();
        int unreachable = 0, absent = 0;
        for (String[] t : TOOLS) {
            String resolved = sh("command -v " + t[0] + " 2>/dev/null", 15).trim();
            String expected = t[1] + "/" + t[0];
            boolean onDisk = ok("test -x " + expected, 15);
            String state;
            if (!resolved.isEmpty()) state = "reachable";
            else if (onDisk) { state = "NOT_IN_PATH"; unreachable++; }
            else { state = "not-installed"; absent++; }
            a.put(new JSONObject().put("command", t[0]).put("expectedIn", t[1]).put("purpose", t[2])
                    .put("resolved", resolved).put("onDisk", onDisk).put("state", state));
        }
        return r.put("tools", a).put("unreachable", unreachable).put("absent", absent)
                .put("explanation", unreachable > 0
                        ? I18n.tr("server.um.panelBootEnvironment.3", java.util.Map.of("unreachable", String.valueOf(unreachable)))
                        : (absent > 0
                           ? I18n.tr("server.um.panelBootEnvironment.4", java.util.Map.of("absent", String.valueOf(absent)))
                           : I18n.tr("server.um.panelBootEnvironment.5")));
    }

    /**
     * The preview of the configuration that the panel would write on a Dovecot 2.4.
     *
     * It is there so that it can be read NOW, while the repository does not have 2.4 yet and there
     * is no hurry. A template seen for the first time on the day the
     * package arrives is a template that gets read in a rush.
     *
     * It writes nothing: it takes the same files the script would write, fills in the
     * real values from the database and hides the password.
     */
    public static JSONObject dovecot24Preview() {
        JSONObject r = new JSONObject().put("success", true);
        try {
            org.daemoxcp.mail.scripts.DovecotConfig c = org.daemoxcp.mail.scripts.DovecotConfig.fromPanelConfig();
            // Every flavor, of 2.3 and of 2.4: like the script (DovecotConfig).
            boolean pigeonhole = !sh("pkg query -g %n 'dovecot-pigeonhole*' 'dovecot24-pigeonhole*' 2>/dev/null", 15).isBlank();
            JSONArray file = new JSONArray();
            for (var f : org.daemoxcp.mail.scripts.DovecotConfig.file24()) {
                String text = f.content()
                        .replace("${DB_USER}", c.getDbUser())
                        .replace("${DB_NAME}", c.getDbName())
                        .replace("${DB_PASS}", "«" + I18n.tr("server.um.x.dbPassHidden") + "»")
                        .replace("${SIEVE_PROTO}", pigeonhole ? " sieve" : "");
                file.put(new JSONObject().put("path", "/usr/local/etc/dovecot/" + f.path())
                        .put("content", text));
            }
            JSONArray ver = new JSONArray();
            for (String[] v : org.daemoxcp.mail.scripts.DovecotConfig.checks24())
                ver.put(new JSONObject().put("state", v[0]).put("setting", v[1]).put("note", v[2]));
            return r.put("file", file).put("checks", ver)
                    .put("dbName", c.getDbName()).put("dbUser", c.getDbUser())
                    .put("pigeonhole", pigeonhole)
                    .put("installedVersion", sh("pkg query -e '%o = \"mail/dovecot\" || %o = \"mail/dovecot24\"' %v 2>/dev/null | head -1", 20))
                    .put("caveat", I18n.tr("server.um.dovecot24Preview.1"));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.dovecot24Preview.2", java.util.Map.of("message", ErrorText.detail("dovecot24Preview", e))));
        }
    }

    /**
     * Everything a periodic report must be able to say, gathered in a single read.
     *
     * It lives here and not in the class that sends the email for a precise reason: here live the
     * tools that query the system, and duplicating them elsewhere would mean having two
     * versions that drift apart over time. The report class composes the text, this one
     * gathers the facts.
     *
     * The "toDo" key is the report's reason for being: a list of things to do,
     * sorted by urgency, already written in Italian. If it is empty, there is nothing to do -
     * and that must be said too, otherwise an email that arrives every week becomes noise
     * that people stop reading.
     */
    /**
     * With updateDatabase = false it does not touch the network: it is the form for the preview.
     *
     * "pkg audit -F" downloads the vulnerability database. The preview used to call it, so
     * pressing "view the report" could hang on a slow network while the tab
     * promised a read. Whoever looks sees the number and, next to it, how old the
     * database is: that way they know what they are looking at instead of believing it up to date.
     */
    public static JSONObject reportData() { return reportData(true); }

    /**
     * How many stack packages have a newer version in the catalog, how many of
     * those are locked - that is, held back by the lock - and the list to show.
     *
     * Pure function: it receives the rows of {@link #packagesStatus()} and the map name ->
     * catalog version, so it can be tested without pkg. The keys it reads are the ones that
     * packagesStatus REALLY sets ("name", "version", "locked"), and the test checks them one
     * by one against a real row: it was precisely a wrong key that made this
     * count silent, and a wrong key is seen neither by the compiler nor by a test written on
     * made-up rows.
     */
    static JSONObject countUpdates(JSONArray lines, Map<String, String> available) {
        int totals = 0, protectedNames = 0, withUpdate = 0, heldBack = 0;
        JSONArray toUpdate = new JSONArray();
        for (int i = 0; lines != null && i < lines.length(); i++) {
            JSONObject x = lines.getJSONObject(i);
            totals++;
            boolean isProtected = x.optBoolean("locked");
            if (isProtected) protectedNames++;
            String name = x.optString("name", "");
            String installed = x.optString("version", "");
            String catalog = available == null ? "" : available.getOrDefault(name, "");
            if (catalog.isEmpty() || catalog.equals(installed)) continue;
            withUpdate++;
            if (isProtected) heldBack++;
            if (toUpdate.length() < 25)
                toUpdate.put(name + " " + installed + " -> " + catalog
                        + (isProtected ? " " + I18n.tr("server.um.x.heldSuffix") : ""));
        }
        return new JSONObject().put("totals", totals).put("protectedNames", protectedNames)
                .put("withUpdate", withUpdate).put("heldBack", heldBack)
                .put("toUpdate", toUpdate);
    }

    public static JSONObject reportData(boolean updateDatabase) {
        JSONObject r = new JSONObject();
        JSONArray toDo = new JSONArray();

        // The automatic send updates the catalog, the preview does not.
        //
        // All the queries to the repository now have "-U", that is they do NOT download the catalog
        // on their own: that is right, because a read must not go to the network by surprise. But
        // without someone updating it, the line "N packages have a newer version" is
        // calculated on a catalog stuck at who knows when, and a report that says "nothing to
        // update" because it looks at old data is worse than a report that does not arrive.
        //
        // So the catalog update is HERE, explicit, and only in the real send - where
        // going to the network is expected. The preview stays a read, and its line on the age of
        // the catalog tells whoever looks how old the data they are seeing is.
        // The outcome is kept: a failed "pkg update" leaves the previous catalog, and the report
        // must be able to say so instead of presenting that catalog as just refreshed.
        boolean refreshedCatalog = updateDatabase && ok("pkg update -q", 120);
        r.put("refreshedCatalog", refreshedCatalog);

        // --- sistema ---
        JSONObject os = operatingSystem();
        r.put("system", os);
        String kernel = os.optString("installedKernel", ""), running = os.optString("runningKernel", "");
        if (!kernel.isEmpty() && !running.isEmpty() && !kernel.equals(running))
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.tr("mail.report.title.restart"))
                    .put("what", I18n.tr("server.um.reportData.1", java.util.Map.of("kernel", String.valueOf(kernel), "running", String.valueOf(running))))
                    .put("where", I18n.tr("server.um.reportData.2")));
        String end = os.optString("endOfSupport", "");
        long eolDays = daysToDate(end);
        r.put("daysToEndOfSupport", eolDays);
        if (eolDays >= 0 && eolDays < 120)
            toDo.put(new JSONObject().put("urgency", eolDays < 45 ? 1 : 3)
                    .put("title", I18n.tr("mail.report.title.endOfSupport"))
                    .put("what", I18n.tr("server.um.reportData.3", java.util.Map.of("eolDays", String.valueOf(eolDays), "end", String.valueOf(end))))
                    .put("where", I18n.tr("server.um.reportData.4")));

        // --- packages ---
        //
        // The catalog versions are asked of pkg: they are not in the rows of packagesStatus,
        // and the report line read them from two keys that those rows never
        // had ("current" and "available"), so it was ALWAYS zero. Measured on the VM on
        // 2026-10-23: "with update: 0" while at the same moment packagesOverview,
        // which does ask for the versions, counted 2 in the stack and 5 in total. A line that
        // cannot say anything but zero is worse than a missing line: it reassures.
        JSONObject pk = packagesStatus();
        r.put("packages", pk);
        JSONObject count = countUpdates(pk.optJSONArray("packages"),
                PackagePlan.toUpdate(PackagePlan.readToUpdate().output()));
        int withUpdate = count.getInt("withUpdate");
        int heldBack = count.getInt("heldBack");
        JSONArray toUpdate = count.getJSONArray("toUpdate");
        r.put("totalPackages", count.getInt("totals")).put("lockedPackageCount", count.getInt("protectedNames"))
         .put("packagesWithUpdate", withUpdate).put("toUpdate", toUpdate)
         .put("heldBackPackages", heldBack);
        // Those that the lock holds back have their own entry below, with the right place to
        // apply them: counting them here too made it say the same thing twice ("update 1
        // package" and "apply 1 held-back update", for the same openjdk25 on the VM on
        // 2026-11-06), with two different indications of where to do it.
        int freeUpdates = withUpdate - heldBack;
        if (freeUpdates > 0)
            toDo.put(new JSONObject().put("urgency", 2)
                    .put("title", I18n.trn("mail.report.title.updates", freeUpdates, java.util.Map.of()))
                    .put("what", freeUpdates == 1
                            ? I18n.tr("server.um.x.newerInRepo.one")
                            : I18n.tr("server.um.x.newerInRepo.other", java.util.Map.of("n", String.valueOf(freeUpdates))))
                    .put("where", I18n.tr("server.um.reportData.5")));
        // An update that exists and that the lock holds back is different news from an
        // available update: `pkg upgrade`, from here or from SSH, skips it and exits 0.
        // Measured on the VM on 2026-10-23: with nginx and postfix-mysql locked, `pkg upgrade -n`
        // names them in a passing line, does not put them in the summary and ends with exit
        // ZERO. Whoever reads only the exit code concludes that there was nothing to do.
        if (heldBack > 0)
            toDo.put(new JSONObject().put("urgency", 2)
                    .put("title", I18n.trn("mail.report.title.held", heldBack, java.util.Map.of()))
                    .put("what", heldBack == 1
                            ? I18n.tr("server.um.x.heldByLock.one")
                            : I18n.tr("server.um.x.heldByLock.other", java.util.Map.of("n", String.valueOf(heldBack))))
                    .put("where", I18n.tr("server.um.reportData.8")));

        // --- vulnerabilities, separating those that can be remedied ---
        //
        // No "tail": it was there, and it was a silent loss. Each pkg audit block takes
        // four or five lines, so beyond ~8 vulnerabilities the first ones fell out of the
        // window and disappeared from BOTH lists - the one with a fix and the one without. The
        // report looked calmer than the server was, and nothing flagged it.
        //
        // "-F" downloads the vulnerability database from the network, so only the real send
        // does it: the preview promises a read and must remain a read.
        String audit = sh("pkg audit" + (updateDatabase ? " -F" : "") + " 2>&1", 180);
        r.put("audit", audit);
        r.put("vulnDbDays", daysSince("/var/db/pkg/vuln.xml"));
        r.put("vulnDbUpdatedNow", updateDatabase);
        // With "-U" the queries to the repository read the catalog that is there: its age
        // is part of the result, otherwise "the repository has version X" sounds like
        // a check just made on the pkg servers, which it is not.
        //
        // The date comes from PkgCatalog, and it is the publication date on the server. Before, this
        // looked at /var/db/pkg/repo-FreeBSD.sqlite, which does not exist on FreeBSD 15: every
        // report said "age unknown".
        JSONObject cat = PkgCatalog.read();
        long catalogDays = cat.optLong("days", -1);
        r.put("catalog", cat).put("catalogDays", catalogDays).put("catalogDate", cat.optString("data"));
        if (updateDatabase && !refreshedCatalog)
            toDo.put(new JSONObject().put("urgency", 2)
                    .put("title", I18n.tr("mail.report.title.catalogNotRefreshed"))
                    .put("what", catalogDays < 0
                            ? I18n.tr("server.um.x.pkgUpdateFailed")
                            : I18n.tr("server.um.x.pkgUpdateFailedDated", java.util.Map.of("howMuch", String.valueOf(PkgCatalog.howMuch(catalogDays)), "data", String.valueOf(cat.optString("data")))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));
        else if (catalogDays < 0)
            toDo.put(new JSONObject().put("urgency", 3)
                    .put("title", I18n.tr("mail.report.title.catalogUnknown"))
                    .put("what", cat.optString("note") + " " + I18n.tr("server.um.x.noCatalogDate"))
                    .put("where", I18n.tr("server.um.x.updatesPage")));
        else if (catalogDays >= 7 && !refreshedCatalog)
            // After a successful "pkg update", an old catalog is the latest the server offers:
            // there is nothing to do. Without it (the preview), there may be a newer catalog.
            toDo.put(new JSONObject().put("urgency", catalogDays >= 28 ? 2 : 3)
                    .put("title", I18n.tr("mail.report.title.catalogOld"))
                    .put("what", I18n.tr("server.um.x.catalogOld", java.util.Map.of("howMuch", String.valueOf(PkgCatalog.howMuch(catalogDays)), "data", String.valueOf(cat.optString("data")))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));

        JSONArray withRemedy = new JSONArray(), withoutRemedy = new JSONArray();
        JSONArray notUnderstood = new JSONArray();
        int found = 0;
        // "There is a fix" without saying that the package is locked is false
        // reassurance: the fix exists in the catalog and no `pkg upgrade` will ever apply it,
        // because the lock skips it. On the VM, on 2026-10-23, that was exactly the case of
        // nginx: catalog 1.30.6,3, that is the version from which VuXML considers the
        // problem fixed, and the package locked by the panel.
        Set<String> lockedNow = lockedNames();
        for (String line : audit.split("\n")) {
            Matcher m = Pattern.compile("^([A-Za-z0-9._+-]+)-([0-9][^\\s]*) is vulnerable").matcher(line.trim());
            if (!m.find()) continue;
            found++;
            String name = m.group(1), installed = m.group(2);
            if (!isValidName(name)) {
                // A name that the filter does not accept must not disappear: if it did, it would
                // end up neither among those with a fix nor among those without, and the count
                // would still add up. Today pkg's names all fit the filter and this branch never
                // fires - but an element the program does not understand is counted and reported.
                notUnderstood.put(line.trim());
                continue;
            }
            String inRepo = sh("pkg rquery -U %v " + name + " 2>/dev/null", 30).trim();
            if (!inRepo.isEmpty() && !inRepo.equals(installed))
                withRemedy.put(name + ": " + installed + " -> " + inRepo
                        + (lockedNow.contains(name) ? " " + I18n.tr("server.um.x.heldSuffixFix") : ""));
            else
                withoutRemedy.put(name + " " + installed);
        }

        // The cross-check that pkg audit gives for free: at the end it prints "N problem(s) in M
        // package(s) found.". If what we read does not match those totals, the
        // result is not shown as if it were complete - it says that it does not add up. A partial
        // list passed off as whole is worse than no list.
        Matcher tot = Pattern.compile("(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found")
                .matcher(audit);
        if (tot.find()) {
            int declaredPackages = Integer.parseInt(tot.group(2));
            r.put("vulnDeclaredPackages", declaredPackages);
            if (declaredPackages != found)
                r.put("vulnCountMismatch", I18n.tr("server.um.reportData.6", java.util.Map.of("declaredPackages", String.valueOf(declaredPackages), "foundCount", String.valueOf(found))));
        } else {
            r.put("vulnCountMismatch", I18n.tr("server.um.reportData.7"));
        }
        if (notUnderstood.length() > 0) r.put("vulnNotUnderstood", notUnderstood);

        r.put("vulnWithRemedy", withRemedy).put("vulnWithoutRemedy", withoutRemedy);
        if (withRemedy.length() > 0)
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.trn("mail.report.title.securityFixes", withRemedy.length(), java.util.Map.of()))
                    .put("what", withRemedy.length() == 1
                            ? I18n.tr("server.um.x.vulnFix.one", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(withRemedy)))))
                            : I18n.tr("server.um.x.vulnFix.other", java.util.Map.of("n", String.valueOf(withRemedy.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(withRemedy))))))
                    .put("where", I18n.tr("server.um.reportData.8")));

        // --- missing libraries ---
        JSONArray broken = packagesWithMissingLibraries().optJSONArray("packages");
        r.put("missingLibraries", broken == null ? new JSONArray() : broken);
        if (broken != null && broken.length() > 0)
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.tr("mail.report.title.missingLibraries"))
                    .put("what", I18n.tr("server.um.reportData.9", java.util.Map.of("length", String.valueOf(broken.length()))))
                    .put("where", I18n.tr("server.um.reportData.10")));

        // --- services ---
        JSONArray services = servicesJson();
        r.put("services", services);
        JSONArray down = new JSONArray();
        for (int i = 0; i < services.length(); i++)
            if (!services.getJSONObject(i).getBoolean("active")) down.put(services.getJSONObject(i).getString("name"));
        r.put("inactiveServices", down);
        if (down.length() > 0)
            toDo.put(new JSONObject().put("urgency", 0)
                    .put("title", I18n.tr("mail.report.title.servicesDown", java.util.Map.of("list", String.join(", ", jsonArrayToList(down)))))
                    .put("what", I18n.tr("server.um.x.svcDown", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(down))))))
                    .put("where", I18n.tr("server.um.reportData.11")));

        // --- an interrupted package job, and the stack packages left without a lock ---
        //
        // The report is the only channel that reaches whoever does not open the panel. Measured on the VM
        // on 2026-11-06 (finding 147): with a stack package unlocked and the list of an
        // interrupted job on disk, the things to do did not mention them.
        List<String> stillUnprotected = PackageRecovery.statePackages();
        if (PackageQueue.statePresent())
            toDo.put(new JSONObject().put("urgency", 0)
                    .put("title", I18n.tr("server.recovery.unprotectedTitle"))
                    .put("what", I18n.tr("server.recovery.unprotected", java.util.Map.of(
                            "n", String.valueOf(stillUnprotected.size()),
                            "list", String.join(" ", stillUnprotected))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));
        // The warning of an interrupted job; the reinstallation with its urgency and its title (finding 172).
        JSONObject interrupted = PackageRecovery.reportItem();
        if (interrupted != null) toDo.put(interrupted);
        Set<String> byHand = unlockedByHand();
        List<String> loose = new ArrayList<>();
        JSONArray stack = pk.optJSONArray("packages");
        for (int i = 0; stack != null && i < stack.length(); i++) {
            JSONObject x = stack.getJSONObject(i);
            String n = x.optString("name");
            if (!x.optBoolean("locked") && !byHand.contains(n) && !stillUnprotected.contains(n)) loose.add(n);
        }
        if (!loose.isEmpty())
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.tr("server.recovery.looseTitle"))
                    .put("what", I18n.tr("server.recovery.loose", java.util.Map.of(
                            "n", String.valueOf(loose.size()), "list", String.join(" ", loose))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));

        // --- space ---
        String df = sh("df -h / 2>/dev/null | tail -1", 30);
        r.put("space", df);
        Matcher mp = Pattern.compile("([0-9]+)%").matcher(df);
        if (mp.find()) {
            int used = Integer.parseInt(mp.group(1));
            r.put("usedPercent", used);
            if (used >= 85)
                toDo.put(new JSONObject().put("urgency", used >= 92 ? 0 : 2)
                        .put("title", I18n.tr("mail.report.title.disk", java.util.Map.of("used", String.valueOf(used))))
                        .put("what", I18n.tr("server.um.reportData.12", java.util.Map.of("used", String.valueOf(used))))
                        .put("where", I18n.tr("server.um.reportData.13")));
        }

        // --- boot environments ---
        JSONObject be = bootEnvironments();
        r.put("environments", be);

        r.put("branch", branchRepositories());
        r.put("toDo", sortByUrgency(toDo));
        return r;
    }

    /** Days from today to a date written as dd/mm/yyyy; -1 if not readable. */
    private static long daysToDate(String dd_mm_yyyy) {
        Matcher m = Pattern.compile("([0-9]{2})/([0-9]{2})/([0-9]{4})").matcher(dd_mm_yyyy == null ? "" : dd_mm_yyyy);
        if (!m.find()) return -1;
        try {
            java.time.LocalDate d = java.time.LocalDate.of(Integer.parseInt(m.group(3)),
                    Integer.parseInt(m.group(2)), Integer.parseInt(m.group(1)));
            return java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.now(), d);
        } catch (Exception e) { return -1; }
    }

    /** The things to do, most urgent first. 0 = a service is down, 3 = to be scheduled. */
    private static JSONArray sortByUrgency(JSONArray a) {
        java.util.List<JSONObject> l = new ArrayList<>();
        for (int i = 0; i < a.length(); i++) l.add(a.getJSONObject(i));
        l.sort(java.util.Comparator.comparingInt(x -> x.optInt("urgency", 9)));
        JSONArray out = new JSONArray();
        for (JSONObject x : l) out.put(x);
        return out;
    }

    /** servicesState() as a JSON list, for the tabs that show it. */
    private static JSONArray servicesJson() {
        JSONArray a = new JSONArray();
        for (var e : servicesState().entrySet())
            a.put(new JSONObject().put("name", e.getKey()).put("active", e.getValue()));
        return a;
    }

    private static int countLines(String s) {
        int n = 0;
        for (String l : s.split("\n")) if (!l.isBlank()) n++;
        return n;
    }

    /** Reads the output of "sort | uniq -c": count, space, value. */
    private static void countIn(String output, java.util.Map<String, Integer> where) {
        for (String line : output.split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            try { where.put(t.substring(sp + 1).trim(), Integer.parseInt(t.substring(0, sp))); }
            catch (NumberFormatException ignored) { }
        }
    }

    public static JSONObject panelUsage(String pkgName) {
        JSONObject r = new JSONObject().put("success", true).put("pkgName", pkgName);
        if (!isValidName(pkgName))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        if (!ok("pkg info -e " + pkgName, 20))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.panelUsage.1", java.util.Map.of("pkg", String.valueOf(pkgName))));

        // --- 1. which executables the package installs ---
        String list = sh("pkg query '%Fp' " + pkgName + " 2>/dev/null", 60);
        String asListed = "pkg query %Fp";
        if (list.isBlank()) {   // format not available: fall back on pkg info -l
            list = sh("pkg info -l " + pkgName + " 2>/dev/null", 60);
            asListed = "pkg info -l";
        }
        java.util.LinkedHashMap<String, String> runnables = new java.util.LinkedHashMap<>();
        for (String line : list.split("\n")) {
            String f = line.trim();
            if (!f.startsWith("/")) continue;
            if (!f.matches("(/usr)?(/local)?/(s?bin|libexec)(/[A-Za-z0-9._+-]{1,64}){1,2}")) continue;
            String name = f.substring(f.lastIndexOf('/') + 1);
            runnables.putIfAbsent(name, f);
        }
        r.put("asListed", asListed).put("runnablesFound", runnables.size());

        // --- 2. the panel's classes, from the running jar ---
        String jar = jarPath();
        r.put("jar", jar == null ? "" : jar);
        long bytesRead = 0;
        String extract = null;
        if (jar != null && !jar.isBlank() && ok("test -r " + jar, 15)) {
            // bsdtar (libarchive) is in the base system and reads zip archives, so jars too.
            extract = "tar -xOf " + jar + " 'org/daemoxcp/mail/*' 2>/dev/null";
            String n = sh(extract + " | wc -c", 120).trim().replaceAll("[^0-9]", "");
            if (!n.isEmpty()) bytesRead = Long.parseLong(n);
            if (bytesRead == 0 && ok("command -v unzip >/dev/null 2>&1", 15)) {
                extract = "unzip -p " + jar + " 'org/daemoxcp/mail/*' 2>/dev/null";
                n = sh(extract + " | wc -c", 120).trim().replaceAll("[^0-9]", "");
                if (!n.isEmpty()) bytesRead = Long.parseLong(n);
            }
        }
        boolean readSucceeded = bytesRead > 0;
        r.put("bytesRead", bytesRead).put("readSucceeded", readSucceeded);

        // --- 3. a single pass: which of those names appear in the classes ---
        // Two counts, not one. Searching by SUBSTRING is useless: "gif" appears 127
        // times in the panel's classes, but inside JSON.stringify and writeNewsyslogIfMissing,
        // never as a command. Searching by WHOLE WORD brings it down to zero, which is the truth.
        // The second count is stricter still: the name followed by a space, that is a
        // command with arguments. It serves to tell "openssl x509 -in ..." from the name appearing
        // by chance. The verdict is based on the whole word; the other number is there to get
        // an idea, because a name like "test" stays ambiguous by nature.
        java.util.Map<String, Integer> counts = new java.util.HashMap<>();
        java.util.Map<String, Integer> withArguments = new java.util.HashMap<>();
        java.util.List<String> tooShort = new ArrayList<>();
        if (readSucceeded && !runnables.isEmpty()) {
            StringBuilder whole = new StringBuilder(), withSpace = new StringBuilder();
            for (String name : runnables.keySet()) {
                if (name.length() < 4) { tooShort.add(name); continue; }
                whole.append(" -e '").append(name).append("'");
                withSpace.append(" -e '").append(name).append(" '");
            }
            if (whole.length() > 0) {
                countIn(sh(extract + " | grep -aowF" + whole + " | sort | uniq -c", 180), counts);
                countIn(sh(extract + " | grep -aoF" + withSpace + " | sort | uniq -c", 180), withArguments);
            }
        }

        // --- 4. for each command used: is there another copy that would remain? ---
        JSONArray used = new JSONArray();
        for (var e : runnables.entrySet()) {
            Integer c = counts.get(e.getKey());
            if (c == null || c == 0) continue;
            String elsewhere = "";
            for (String d : new String[]{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}) {
                String cand = d + "/" + e.getKey();
                if (cand.equals(e.getValue())) continue;
                if (ok("test -x " + cand, 15)) { elsewhere = cand; break; }
            }
            // Knowing that a second copy exists is not enough: one must know WHICH of the two
            // runs now. If the PATH already picks the other one, removing the package changes
            // nothing - saying "it would become another binary" would be false, and would contradict
            // the box above that has just measured who wins in the PATH.
            String inUseNow = sh("command -v " + e.getKey() + " 2>/dev/null", 15).trim();
            boolean isItsOwn = inUseNow.equals(e.getValue());
            used.put(new JSONObject().put("command", e.getKey()).put("path", e.getValue())
                    .put("occurrences", c)
                    .put("withArguments", withArguments.getOrDefault(e.getKey(), 0))
                    .put("otherCopy", elsewhere)
                    .put("inUseNow", inUseNow).put("isItsOwn", isItsOwn)
                    .put("wouldStay", !elsewhere.isEmpty())
                    .put("effect", isItsOwn
                            ? (elsewhere.isEmpty()
                               ? I18n.tr("server.um.panelUsage.2")
                               : I18n.tr("server.um.panelUsage.3", java.util.Map.of("elsewhere", String.valueOf(elsewhere))))
                            : (inUseNow.isEmpty()
                               ? I18n.tr("server.um.panelUsage.4")
                               : I18n.tr("server.um.panelUsage.5", java.util.Map.of("inUseNow", String.valueOf(inUseNow))))));
        }
        // A package may have no command at all and still be needed, because it is a
        // LIBRARY: nobody types it, but something links to it. giflib is exactly
        // this. Saying it here prevents "I do not use its commands" from being read as "it
        // can be removed": for a library the right question is a different one, and it is the
        // one asked by the tab of packages without the library they require.
        JSONArray libraries = new JSONArray();
        for (String l : sh("pkg query %b " + pkgName + " 2>/dev/null", 30).split("\n"))
            if (l.trim().matches("[A-Za-z0-9._+-]{1,128}")) libraries.put(l.trim());
        r.put("providesLibraries", libraries);
        r.put("commandsUsed", used).put("namesTooShort", new JSONArray(tooShort));

        String verdict, explanation;
        if (!readSucceeded) {
            verdict = "UNDETERMINED";
            explanation = I18n.tr("server.um.x.jarUnreadable", java.util.Map.of("jar", String.valueOf(jar == null || jar.isBlank() ? I18n.tr("server.um.x.jarUnknown") : jar)));
        } else if (used.length() == 0) {
            verdict = libraries.length() > 0 ? "LIBRARY_ONLY"
                                             : "PANEL_DOES_NOT_USE";
            explanation = I18n.tr("server.um.x.jarNoUse", java.util.Map.of("byte", String.valueOf(bytesRead), "n", String.valueOf(runnables.size()), "pkg", String.valueOf(pkgName)))
                    + (libraries.length() > 0
                       ? " " + I18n.tr("server.um.x.jarLibs", java.util.Map.of("n", String.valueOf(libraries.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(libraries)))))
                       : "")
                    + (tooShort.isEmpty() ? ""
                       : " " + I18n.tr("server.um.x.jarShortNames", java.util.Map.of("n", String.valueOf(tooShort.size()), "list", String.valueOf(String.join(", ", tooShort)))));
        } else {
            int withoutReplacement = 0, reallyItsOwn = 0;
            for (int i = 0; i < used.length(); i++) {
                JSONObject u = used.getJSONObject(i);
                if (u.getBoolean("isItsOwn")) {
                    reallyItsOwn++;
                    if (!u.getBoolean("wouldStay")) withoutReplacement++;
                }
            }
            if (reallyItsOwn == 0) {
                // It names them, but it is not this package that provides the binaries that run.
                verdict = "NAMES_NOT_THEIRS";
                explanation = used.length() == 1
                        ? I18n.tr("server.um.x.namesOther.one", java.util.Map.of("pkg", String.valueOf(pkgName)))
                        : I18n.tr("server.um.x.namesOther.other", java.util.Map.of("n", String.valueOf(used.length()), "pkg", String.valueOf(pkgName)));
                return r.put("verdict", verdict).put("explanation", explanation)
                        .put("why", I18n.tr("server.um.panelUsage.10"));
            }
            verdict = withoutReplacement > 0 ? "USES_NO_SPARE" : "USES";
            explanation = (used.length() == 1
                    ? I18n.tr("server.um.x.usesCmds.one")
                    : I18n.tr("server.um.x.usesCmds.other", java.util.Map.of("n", String.valueOf(used.length()))))
                    + " " + (withoutReplacement > 0
                       ? (withoutReplacement == 1
                          ? I18n.tr("server.um.x.noSpare.one")
                          : I18n.tr("server.um.x.noSpare.other", java.util.Map.of("n", String.valueOf(withoutReplacement))))
                       : I18n.tr("server.um.x.allSpare"));
        }
        return r.put("verdict", verdict).put("explanation", explanation)
                .put("why", I18n.tr("server.um.panelUsage.10"));
    }

    /**
     * The parsing of the scan's output, separated from the command that produces it: that way it can be
     * tested without FreeBSD, which is the only way to know that it really reads what it believes it does.
     * A line is "pid TAB command TAB path [path ...]". The path in /usr/local
     * is the port; the one in /usr/lib is the base system.
     */
    static JSONArray analyzeMappings(String scan) {
        JSONArray processes = new JSONArray();
        if (scan == null) return processes;
        for (String line : scan.split("\n")) {
            String[] c = line.split("\t");
            if (c.length < 3 || c[0].trim().isEmpty()) continue;
            JSONArray libs = new JSONArray();
            boolean port = false;
            for (String v : c[2].trim().split("\\s+")) {
                if (v.isEmpty()) continue;
                libs.put(v);
                if (v.startsWith("/usr/local/")) port = true;
            }
            processes.put(new JSONObject().put("pid", c[0].trim())
                    .put("command", c[1].trim()).put("libraries", libs).put("usesThePort", port));
        }
        return processes;
    }

    public static JSONObject opensslUsage() {
        JSONObject r = new JSONObject().put("success", true);
        if (!ok("pkg info -e openssl", 20)) {
            return r.put("installed", false).put("verdict", "absent")
                    .put("explanation", I18n.tr("server.um.opensslUsage.1"));
        }
        r.put("installed", true).put("version", sh("pkg query %v openssl", 20));

        // --- 1. who declares it in the registry ---
        JSONArray declare = new JSONArray();
        for (String s : sh("pkg query %rn openssl 2>/dev/null", 30).split("\n"))
            if (isValidName(s.trim())) declare.put(s.trim());
        r.put("declare", declare);

        // --- 2. the sonames of the two copies, and whether they overlap ---
        java.util.LinkedHashSet<String> sonPort = new java.util.LinkedHashSet<>();
        for (String s : sh("pkg query %b openssl 2>/dev/null", 30).split("\n")) {
            String t = s.trim();
            if (t.matches("lib(ssl|crypto)\\.so(\\.[0-9]+)*")) sonPort.add(t);
        }
        java.util.LinkedHashSet<String> sonBase = new java.util.LinkedHashSet<>();
        for (String s : sh("ls /usr/lib/libssl.so.* /usr/lib/libcrypto.so.* 2>/dev/null", 20).split("\n")) {
            String t = s.trim();
            int sl = t.lastIndexOf('/');
            if (sl >= 0 && sl + 1 < t.length()) sonBase.add(t.substring(sl + 1));
        }
        java.util.LinkedHashSet<String> common = new java.util.LinkedHashSet<>(sonPort);
        common.retainAll(sonBase);
        r.put("portSoname", new JSONArray(new ArrayList<>(sonPort)))
         .put("baseSoname", new JSONArray(new ArrayList<>(sonBase)))
         .put("sharedSoname", new JSONArray(new ArrayList<>(common)))
         .put("ambiguous", !common.isEmpty());

        // --- 2b. who requires those sonames (valid only if they are NOT shared with base) ---
        JSONArray require = new JSONArray();
        if (!sonPort.isEmpty()) {
            for (String line : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
                String t = line.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                String name = t.substring(0, sp).trim(), lib = t.substring(sp + 1).trim();
                if (isValidName(name) && sonPort.contains(lib))
                    require.put(new JSONObject().put("pkgName", name).put("library", lib));
            }
        }
        r.put("requireTheSoname", require);

        // --- 3. the measurement that decides: what is mapped NOW by live processes ---
        JSONArray processes = new JSONArray();
        JSONArray useThePort = new JSONArray();
        boolean hasProcstat = ok("command -v procstat >/dev/null 2>&1", 15);
        int withLibssl = 0;
        if (hasProcstat) {
            String scan = sh("for p in $(ps -axo pid=); do "
                    + "m=$(procstat -v $p 2>/dev/null | awk '/lib(ssl|crypto)\\.so/ {print $NF}' | sort -u | tr '\\n' ' '); "
                    + "[ -n \"$m\" ] && printf '%s\\t%s\\t%s\\n' \"$p\" \"$(ps -o comm= -p $p 2>/dev/null)\" \"$m\"; "
                    + "done", 240);
            processes = analyzeMappings(scan);
            withLibssl = processes.length();
            for (int i = 0; i < processes.length(); i++)
                if (processes.getJSONObject(i).getBoolean("usesThePort")) useThePort.put(processes.getJSONObject(i));
        }
        boolean reliableMeasure = hasProcstat && withLibssl > 0;

        // --- 4. the command, not just the libraries. procstat sees LIVE processes: an
        // "openssl x509" lasts milliseconds and is almost never caught. But the panel
        // certainly does invoke it (AcmeManager reads certificates this way, and the install
        // scripts generate passwords and keys with "openssl rand"), and it invokes it WITHOUT
        // an absolute path. In FreeBSD's PATH /usr/local/bin comes before /usr/bin,
        // so with the port installed it is its binary that wins. Ignoring this would
        // mean saying "nobody uses it" of a program that runs every time the
        // panel looks at a certificate.
        JSONArray binaries = new JSONArray();
        for (String path : new String[]{"/usr/local/bin/openssl", "/usr/bin/openssl"}) {
            if (!ok("test -x " + path, 15)) continue;
            binaries.put(new JSONObject().put("path", path)
                    .put("version", sh(path + " version 2>&1 | head -1", 20))
                    .put("pkgName", sh("pkg which -q " + path + " 2>/dev/null", 20))
                    .put("fromPort", path.startsWith("/usr/local/")));
        }
        String winner = sh("command -v openssl 2>/dev/null", 15).trim();
        boolean portCommand = winner.startsWith("/usr/local/");
        boolean baseHasCommand = ok("test -x /usr/bin/openssl", 15);
        r.put("binaries", binaries).put("commandInPath", winner)
         .put("portCommand", portCommand).put("baseHasCommand", baseHasCommand)
         .put("explicit", "0".equals(sh("pkg query %a openssl 2>/dev/null", 20).trim()))
         .put("whoInvokesIt", I18n.tr("server.um.opensslUsage.2"));

        r.put("processes", processes).put("useThePort", useThePort)
         .put("processesWithTls", withLibssl).put("reliableMeasure", reliableMeasure)
         .put("howMeasured", hasProcstat
                 ? I18n.tr("server.um.opensslUsage.3", java.util.Map.of("withLibssl", String.valueOf(withLibssl)))
                 : I18n.tr("server.um.opensslUsage.4"));

        // --- the verdict, in the order in which the evidence weighs ---
        String verdict, explanation;
        if (useThePort.length() > 0) {
            verdict = "IN_USE_NOW";
            explanation = useThePort.length() == 1
                    ? I18n.tr("server.um.x.portLibOpen.one")
                    : I18n.tr("server.um.x.portLibOpen.other", java.util.Map.of("n", String.valueOf(useThePort.length())));
        } else if (declare.length() > 0) {
            verdict = "REQUIRED";
            explanation = I18n.tr("server.um.x.declaredBy", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(declare)))));
        } else if (portCommand) {
            verdict = "COMMAND_IS_ITS";
            explanation = I18n.tr("server.um.x.cmdIsPort", java.util.Map.of("winner", String.valueOf(winner))) + " "
                    + (baseHasCommand
                       ? I18n.tr("server.um.x.baseHasCmd")
                       : I18n.tr("server.um.x.baseNoCmd"));
        } else if (!reliableMeasure) {
            verdict = "UNDETERMINED";
            explanation = I18n.tr("server.um.opensslUsage.7");
        } else {
            verdict = "NOBODY_USES";
            explanation = I18n.tr("server.um.opensslUsage.9", java.util.Map.of("withLibssl", String.valueOf(withLibssl)));
        }
        r.put("verdict", verdict).put("explanation", explanation);

        r.put("note", I18n.tr("server.um.opensslUsage.10"));
        r.put("whyItIsHere", I18n.tr("server.um.opensslUsage.11"));
        r.put("panel", panelUsage("openssl"));
        // This text used to say to type "pkg unlock" and "pkg delete" on the command line.
        // Since removal became a button, dictating the commands is worse than useless:
        // the button redoes the checks and verifies afterwards, a human hand does not.
        r.put("howToRemove", I18n.tr("server.um.opensslUsage.12"));
        return r;
    }

    /**
     * Who declares what, on the MySQL clients. It serves to answer with facts a question that
     * would otherwise be answered by intuition: why was a 9.7 client installed when the
     * FreeBSD ports default (Mk/bsd.default-versions.mk, branches main and 2026Q3) is 8.4?
     *
     * Three distinct things are looked at, which are easy to confuse as one:
     *  - what the INSTALLED package declares
     *  - what the version in the REPOSITORY declares
     *  - which packages really provide the contested library
     */
    public static JSONObject mysqlClientDiagnostics() {
        JSONObject r = new JSONObject();
        JSONArray client = new JSONArray();
        for (String line : sh("pkg query '%n %v' 2>/dev/null | grep -E '^mysql[0-9]+-(client|server) '", 30).split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp > 0) client.put(new JSONObject().put("name", t.substring(0, sp)).put("version", t.substring(sp + 1).trim()));
        }
        r.put("mysqlPackages", client);

        JSONArray dependents = new JSONArray();
        for (String pk : MAIL_MYSQL_PACKAGES) {
            if (!ok("pkg info -e " + pk, 20)) continue;
            dependents.put(new JSONObject().put("name", pk)
                    .put("version", sh("pkg query %v " + pk, 20))
                    .put("installedDependencies", sh("pkg query %dn " + pk + " 2>/dev/null | tr '\n' ' '", 30))
                    .put("repositoryDependencies", sh("pkg rquery -U %dn " + pk + " 2>/dev/null | tr '\n' ' '", 30))
                    .put("requiredLibraries", sh("pkg query %B " + pk + " 2>/dev/null | tr '\n' ' '", 30)));
        }
        r.put("dependents", dependents);

        // Who provides the contested library, and which package the file on the disk comes from.
        r.put("provideLib", sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20));
        r.put("fileLib", sh("ls -l /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20));
        // Files the two packages fight over: how many of them 8.4 lost.
        r.put("hasConflicts", sh("pkg check -s mysql84-client 2>&1 | head -20", 180));
        return r.put("success", true);
    }

    /**
     * The FreeBSD ports defaults, read from the official source.
     *
     * Columns: component, default value, how what is installed is detected,
     * what departing from it entails.
     *
     * SOURCE: Mk/bsd.default-versions.mk from the official ports repository
     * (cgit.freebsd.org), branches main and 2026Q3 - they match. Verified on 2026-08-31.
     *
     * It is a dated snapshot, not a live read: the panel does not go on the internet.
     * It must be re-verified when the quarter changes, and the tab says so instead of making people
     * believe it is always up to date. It serves to answer the question we lacked today -
     * "is what I installed what the system expects?" - before a
     * migration, not after.
     */
    private static final String[][] DEFAULTS = {
        {"MySQL", "8.4",
         "pkg query %n | grep -E '^mysql[0-9]+-server$'",
         "server.um.mysqlClientDiagnostics.1"},
        {"PHP", "8.4",
         "pkg query %n | grep -E '^php[0-9]+$'",
         "server.um.mysqlClientDiagnostics.2"},
        {"Python", "3.12",
         "pkg query %n | grep -E '^py[0-9]+-' | sed 's/-.*//' | sort -u | tr '\n' ' '",
         "server.um.mysqlClientDiagnostics.3"},
        {"OpenSSL", "base",
         "pkg query %n | grep -E '^openssl[0-9]*$' | tr '\n' ' '",
         "server.um.mysqlClientDiagnostics.4"},
        {"Perl", "5.42",
         "pkg query %v perl5 2>/dev/null",
         "server.um.mysqlClientDiagnostics.5"},
        {"Java", "25",
         "pkg query %n | grep -E '^openjdk[0-9]+$' | tr '\n' ' '",
         "server.um.mysqlClientDiagnostics.6"},
    };

    /**
     * Compares the official defaults with what is really installed.
     * The "installed" column comes from the system, the "default" one from the official source:
     * the comparison is the point, because it is the divergence that breaks things.
     */
    /**
     * Which package branch this system is served from.
     *
     * It changes how long a fix takes to arrive, and it is the answer to the question "why does
     * the repository not have the version that closes this vulnerability yet". It is not read from
     * a file picked by eye: pkg merges /etc/pkg/FreeBSD.conf with any files in
     * /usr/local/etc/pkg/repos/, and only pkg knows which one won. "pkg -vv" prints the
     * EFFECTIVE configuration, the one really in use.
     *
     * Note on the meaning, from the FreeBSD Handbook: quarterly is cut from HEAD in
     * January, April, July and October, and still receives security fixes - even
     * as a version update. What it keeps out are new features, not fixes.
     */
    /**
     * A single report, in text, to copy and paste.
     *
     * The data is all already there, but scattered across six tabs: when it has to be sent to someone
     * one ends up copying pieces by hand, and the pieces that get forgotten are always the ones that
     * were needed. Here they are together, in the order in which one would ask for them.
     *
     * Two deliberate choices:
     *  - the installed versions and the repository ones are read with only TWO queries
     *    (pkg query and pkg rquery -U on everything) and joined here: querying pkg 41 times for 41
     *    packages would take minutes for the same information.
     *  - NOTHING secret goes in: names, versions, states and warnings. No configuration
     *    file, no password, no key. A report made to be
     *    pasted must be pasteable without rereading it line by line.
     */
    /**
     * End of support of the FreeBSD releases, from the official security page.
     *
     * A dated snapshot like DEFAULTS, for the same reason: the panel does not go on the internet.
     * Source: https://www.FreeBSD.org/security/ - read on 2026-08-31.
     * To be reread when a new release comes out: a wrong end-of-support date is worse
     * than no date, because it reassures instead of prompting a check.
     */
    private static final String[][] END_OF_SUPPORT = {
        {"15.1", "31/03/2027", "server.um.mysqlClientDiagnostics.7"},
        {"15.0", "30/09/2026", "server.um.mysqlClientDiagnostics.8"},
        {"14.4", "31/12/2026", "server.um.mysqlClientDiagnostics.9"},
    };
    private static final String SUPPORT_SOURCE =
        "server.um.mysqlClientDiagnostics.10";

    /**
     * When the table above was copied, in a form a program can read.
     *
     * The same information is already inside SUPPORT_SOURCE, but inside a sentence: to show it
     * next to the end-of-support date it would have to be extracted from the text with a regular
     * expression. A piece of data a program needs goes in a field, it is not fished out
     * of prose written for a human being - it is the same mistake by which the MTA-STS plan
     * looked for the word "Cloudflare" inside a reason.
     */
    private static final String SUPPORT_SOURCE_READ = "31/08/2026";

    /**
     * State of the base operating system: version, patch level, restart needed,
     * end of support, updates already downloaded.
     *
     * The packages are one half of the server; the other is the system underneath, which pkg does not
     * touch and which none of the tabs looked at until now. All read-only: "freebsd-update fetch"
     * DOWNLOADS, so it lives in a separate, declared action, not in here.
     */
    public static JSONObject operatingSystem() {
        JSONObject r = new JSONObject();
        try {
            String kernel = sh("freebsd-version -k 2>/dev/null", 20).trim();     // installed kernel
            String running = sh("freebsd-version -r 2>/dev/null", 20).trim();     // running kernel
            String userland = sh("freebsd-version -u 2>/dev/null", 20).trim();   // userland
            String uname = sh("uname -r 2>/dev/null", 20).trim();
            String arch = sh("uname -mi 2>/dev/null", 20).trim();
            r.put("installedKernel", kernel).put("runningKernel", running)
             .put("userland", userland).put("uname", uname).put("arch", arch);

            // The Handbook: if freebsd-version -k and uname -r differ, the installed kernel
            // is not the running one - that is, a restart is missing.
            boolean restart = !kernel.isEmpty() && !uname.isEmpty() && !kernel.equals(uname);
            r.put("restartNeeded", restart);

            // End of support: the X.Y part of the userland is compared with the official table.
            Matcher m = Pattern.compile("^([0-9]+\\.[0-9]+)").matcher(userland);
            String series = m.find() ? m.group(1) : "";
            String eol = "", eolNotes = "";
            for (String[] e : END_OF_SUPPORT)
                if (e[0].equals(series)) { eol = e[1]; eolNotes = I18n.tr(e[2]); }
            // "I do not know this series" is a piece of information, and it must be said.
            //
            // Before, if the series was not in the table, eol stayed empty and the tab showed
            // nothing: a silence that reads as "nothing to report". But the case in which the
            // series is missing is exactly the one in which the system is NEWER than the snapshot,
            // that is the one in which the table should be reread. The defect hid exactly
            // where it wanted to be noticed.
            r.put("series", series).put("endOfSupport", eol).put("supportNotes", eolNotes)
             .put("knownSeries", !eol.isEmpty())
             .put("supportSourceRead", SUPPORT_SOURCE_READ)
             .put("supportSource", I18n.tr(SUPPORT_SOURCE));

            boolean release = userland.contains("-RELEASE");
            r.put("updatableWithFreebsdUpdate", release);
            if (!release) {
                r.put("updatesNote", I18n.tr("server.um.operatingSystem.1", java.util.Map.of("userland", String.valueOf(userland))));
            } else {
                // updatesready does NOT download: it only says whether something is already ready to install.
                String ready = sh("freebsd-update updatesready 2>&1", 60).trim();
                r.put("alreadyReady", ready);
                boolean readyExist = !ready.toLowerCase().contains("no updates are available");
                r.put("readyExist", readyExist);
                // What they would bring, if installed: the version (from the tag file) and whether the kernel
                // is included, that is whether a restart will be needed afterwards (finding 185).
                if (readyExist) {
                    r.put("readyTarget", OsPatch.target(sh("cat /var/db/freebsd-update/tag 2>/dev/null", 10)));
                    r.put("readyKernel", number(sh("cat /var/db/freebsd-update/*-install/INDEX-NEW 2>/dev/null"
                            + " | cut -d'|' -f1 | grep -c '^/boot/kernel/'", 30)) > 0);
                }
            }
            return r.put("success", true);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("operatingSystem", e));
        }
    }

    /**
     * Looks for updates to the base system. It DOWNLOADS, it does not install.
     *
     * It is in a separate action precisely because it writes: "freebsd-update fetch" downloads the
     * patches into /var/db/freebsd-update and leaves them there. Installing them is another command, and it
     * requires a restart if it touches the kernel: I do not start that from a button unless it is a
     * decision made by looking at what would change.
     */
    public static JSONObject startSystemUpdateSearch() {
        String id = "osf-" + System.currentTimeMillis();
        Job j = new Job(id, "os-fetch");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                j.advance(1, 1);
                j.write(I18n.tr("server.um.startSystemUpdateSearch.1"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.2"));
                j.write("");
                JSONObject os = operatingSystem();
                if (!os.optBoolean("updatableWithFreebsdUpdate", false)) {
                    j.status = "error";
                    j.errorMessage = os.optString("updatesNote", I18n.tr("server.um.findSystemUpdates.1"));
                    j.write(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(j.errorMessage))));
                    return;
                }
                j.write(I18n.tr("server.um.x.youAreAt", java.util.Map.of("uname", String.valueOf(os.optString("uname")))));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.4"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.5"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.6"));
                j.write("");

                // Heartbeat: without it, a command that downloads for minutes without a newline looks
                // stuck. It is not an embellishment - it is the difference between "it is working" and
                // "it is dead", which could not otherwise be told apart from the log.
                final long start = System.currentTimeMillis();
                final java.util.concurrent.atomic.AtomicBoolean finished =
                        new java.util.concurrent.atomic.AtomicBoolean(false);
                Thread heartbeat = localizedThread(() -> {
                    try {
                        while (!finished.get()) {
                            Thread.sleep(30000);
                            if (finished.get()) break;
                            j.write(I18n.tr("server.um.startSystemUpdateSearch.7", java.util.Map.of("p", String.valueOf(((System.currentTimeMillis() - start) / 1000)))));
                        }
                    } catch (InterruptedException ignored) { }
                }, "os-fetch-heartbeat");
                heartbeat.setDaemon(true);
                heartbeat.start();

                StringBuilder cat = new StringBuilder();
                int code;
                try {
                    code = runLogged(j, "freebsd-update --not-running-from-cron fetch 2>&1", 1800, cat);
                } finally {
                    finished.set(true);
                    heartbeat.interrupt();
                }
                String b2 = cat.toString().toLowerCase();
                boolean nobody = b2.contains("no updates needed") || b2.contains("has no updates available");
                j.write("");
                if (code != 0 && !nobody) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startSystemUpdateSearch.8", java.util.Map.of("code", String.valueOf(code)));
                    j.write(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(j.errorMessage))));
                    return;
                }
                j.write(nobody
                        ? I18n.tr("server.um.startSystemUpdateSearch.9")
                        : I18n.tr("server.um.startSystemUpdateSearch.10"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.11", java.util.Map.of("p", String.valueOf(((System.currentTimeMillis() - start) / 1000)))));
                j.status = "completed";
            } catch (Exception e) {
                j.status = "error"; j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally { j.finish(); }
        }, "os-fetch");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    // ===================== FreeBSD patches, installed by the panel (finding 185) =====================

    /** The last patch installation done by the panel: it serves to tell, afterwards, whether the restart is missing. */
    static Path osPatchState = Paths.get("/var/db/daemoxcp-mail/system/os-patch.json");
    /** The freebsd-update configuration the panel installs with: see OsPatch.installConfig. */
    static Path osPatchConfig = Paths.get("/var/db/daemoxcp-mail/system/freebsd-update.conf");

    /**
     * Installs the updates of the base system: first it downloads them (the ready ones may be old: on
     * the production server they were from 22 October), then the boot environment to go back, then
     * "freebsd-update install", then it checks the versions and says whether a restart is needed.
     *
     * It takes the package turn (PackageQueue): a pkg upgrade and an installation of the base
     * system at the same time step on each other's toes (the system libraries under the packages being
     * updated), and the turn also holds across processes.
     */
    public static JSONObject startOsPatchInstall() {
        String id = "osp-" + System.currentTimeMillis();
        String refusal = PackageQueue.take(id, I18n.tr("server.osPatch.turn"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        Job j = new Job(id, "os-patch");
        JOBS.put(id, j);
        PackageQueue.start(id, "os-patch", () -> runOsPatchInstall(j));
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    private static void runOsPatchInstall(Job j) {
        try {
            osPatchSteps(j);
        } finally {
            j.finish();
        }
    }

    /** The steps of the FreeBSD patches, without closing the log: "Update all" uses them too (finding 207). */
    private static void osPatchSteps(Job j) {
        j.status = "running";
        final int TOT = 5;
        try {
            j.advance(1, TOT);
            j.write("=== " + I18n.tr("server.osPatch.title") + " ===");
            j.write("");
            j.write(I18n.tr("server.osPatch.step1", Map.of("total", String.valueOf(TOT))));
            JSONObject os = operatingSystem();
            if (!os.optBoolean("updatableWithFreebsdUpdate", false))
                throw org.daemoxcp.mail.util.ShownException.translated(os.optString("updatesNote", I18n.tr("server.um.findSystemUpdates.1")));
            String fromUserland = os.optString("userland");
            j.write("    " + I18n.tr("server.osPatch.now", Map.of("userland", fromUserland, "kernel", os.optString("uname"))));
            long freeKb = number(sh("df -k / | awk 'NR==2 {print $4}'", 20));
            if (freeKb < 1024L * 1024L)
                throw org.daemoxcp.mail.util.ShownException.of("server.osPatch.noSpace", Map.of("mb", String.valueOf(freeKb / 1024)));
            if (ok("pgrep -f '/usr/sbin/freebsd-update' >/dev/null", 10))
                throw org.daemoxcp.mail.util.ShownException.of("server.osPatch.otherRunning");
            if (!ok("bectl check", 30))
                throw org.daemoxcp.mail.util.ShownException.of("server.osPatch.noBootEnvironments");

            j.advance(2, TOT);
            j.write("");
            j.write(I18n.tr("server.osPatch.step2", Map.of("total", String.valueOf(TOT))));
            StringBuilder fetched = new StringBuilder();
            int code = runLogged(j, "freebsd-update --not-running-from-cron fetch 2>&1", 1800, fetched);
            if (code != 0 && !OsPatch.nothingToFetch(fetched.toString()))
                throw org.daemoxcp.mail.util.ShownException.of("server.um.startSystemUpdateSearch.8", Map.of("code", String.valueOf(code)));
            String ready = sh("freebsd-update updatesready 2>&1", 60);
            if (OsPatch.nothingToInstall(ready)) {
                j.write("");
                j.write(I18n.tr("server.osPatch.upToDate", Map.of("userland", fromUserland)));
                j.outcome = I18n.tr("server.osPatch.upToDate", Map.of("userland", fromUserland));
                j.status = "completed";
                return;
            }
            String target = OsPatch.target(sh("cat /var/db/freebsd-update/tag 2>/dev/null", 10));
            boolean kernelInside = number(sh("cat /var/db/freebsd-update/*-install/INDEX-NEW 2>/dev/null"
                    + " | cut -d'|' -f1 | grep -c '^/boot/kernel/'", 30)) > 0;
            j.write("    " + I18n.tr("server.osPatch.toInstall", Map.of("target", target.isEmpty() ? "?" : target))
                    + (kernelInside ? " " + I18n.tr("server.osPatch.withKernel") : ""));

            j.advance(3, TOT);
            j.write("");
            j.write(I18n.tr("server.osPatch.step3", Map.of("total", String.valueOf(TOT))));
            String ts = sh("date -u '+%Y%m%d-%H%M%S'", 15).trim();
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            String be = BE_PREFIX + "freebsd-patches-" + ts;
            if (!ok("bectl create " + be, 300) || !ok("bectl list -H 2>/dev/null | cut -f1 | grep -qx '" + be + "'", 30))
                throw org.daemoxcp.mail.util.ShownException.of("server.osPatch.beFailed", Map.of("be", be));
            j.write("    " + I18n.tr("server.osPatch.beCreated", Map.of("be", be)));

            j.advance(4, TOT);
            j.write("");
            j.write(I18n.tr("server.osPatch.step4", Map.of("total", String.valueOf(TOT))));
            Files.createDirectories(osPatchConfig.getParent());
            Files.writeString(osPatchConfig, OsPatch.installConfig(Files.readString(Paths.get("/etc/freebsd-update.conf"))));
            boolean rebootFirst = false;
            for (int round = 1; round <= 3; round++) {
                StringBuilder out = new StringBuilder();
                code = runLogged(j, "freebsd-update -f " + osPatchConfig + " install 2>&1", 3600, out);
                if (code != 0 && !OsPatch.nothingToInstall(out.toString()))
                    throw org.daemoxcp.mail.util.ShownException.of("server.osPatch.installFailed", Map.of("code", String.valueOf(code), "be", be));
                if (OsPatch.asksRebootFirst(out.toString())) { rebootFirst = true; break; }
                if (OsPatch.nothingToInstall(sh("freebsd-update updatesready 2>&1", 60))) break;
            }

            j.advance(5, TOT);
            j.write("");
            j.write(I18n.tr("server.osPatch.step5", Map.of("total", String.valueOf(TOT))));
            String installedKernel = sh("freebsd-version -k 2>/dev/null", 20).trim();
            String runningKernel = sh("uname -r 2>/dev/null", 20).trim();
            String userland = sh("freebsd-version -u 2>/dev/null", 20).trim();
            j.write("    " + I18n.tr("server.um.x.kernelInstalled", Map.of("k", installedKernel)));
            j.write("    " + I18n.tr("server.um.x.kernelRunning", Map.of("k", runningKernel)));
            j.write("    userland:             " + userland);
            long now = java.time.Instant.now().getEpochSecond();
            JSONObject state = new JSONObject().put("from", fromUserland).put("to", userland)
                    .put("installedKernel", installedKernel).put("installedAt", now).put("bootEnvironment", be)
                    .put("continueAfterReboot", rebootFirst);
            Files.writeString(osPatchState, state.toString(2));
            boolean reboot = rebootFirst || !installedKernel.equals(runningKernel);
            j.write("");
            j.outcome = reboot
                    ? I18n.tr("server.osPatch.doneReboot", Map.of("to", userland, "kernel", installedKernel))
                    : I18n.tr("server.osPatch.doneAdvised", Map.of("to", userland));
            j.write(j.outcome);
            if (rebootFirst) j.write(I18n.tr("server.osPatch.continueAfterReboot"));
            j.write(I18n.tr("server.osPatch.wayBack", Map.of("be", be)));
            j.status = "completed";
        } catch (Exception e) {
            j.status = "error";
            j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            j.write(I18n.tr("server.um.startMtaStsActivation.1", Map.of("message", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Looks for updates to everything, for the "Update the server" tab (finding 186): the package
     * catalog (pkg update), the vulnerability list (pkg audit -F) and the base system patches
     * (freebsd-update fetch, if the release receives them). It only downloads: it installs nothing.
     * Before, each one was in a different tab, and the package overview compares with the catalog already
     * downloaded, without network: without a pkg update the counts were those of the last time.
     *
     * With the package turn: a pkg update while another job installs changes the catalog under
     * its plan.
     */
    public static JSONObject startUpdatesSearch() {
        String id = "srch-" + System.currentTimeMillis();
        String refusal = PackageQueue.take(id, I18n.tr("server.search.turn"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        Job j = new Job(id, "search");
        JOBS.put(id, j);
        PackageQueue.start(id, "updates-search", () -> runUpdatesSearch(j));
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    private static void runUpdatesSearch(Job j) {
        j.status = "running";
        final int TOT = 3;
        try {
            j.advance(1, TOT);
            j.write(I18n.tr("server.search.step1", Map.of("total", String.valueOf(TOT))));
            int code = runLogged(j, "pkg update 2>&1", 600);
            if (code != 0) throw org.daemoxcp.mail.util.ShownException.of("server.search.pkgFailed", Map.of("code", String.valueOf(code)));

            j.advance(2, TOT);
            j.write("");
            j.write(I18n.tr("server.search.step2", Map.of("total", String.valueOf(TOT))));
            // pkg audit also exits with 1 when it finds vulnerable packages: what counts is the downloaded list.
            runLogged(j, "pkg audit -F -q 2>&1 | tail -5", 600);

            j.advance(3, TOT);
            j.write("");
            j.write(I18n.tr("server.search.step3", Map.of("total", String.valueOf(TOT))));
            JSONObject os = operatingSystem();
            if (!os.optBoolean("updatableWithFreebsdUpdate", false)) {
                j.write("    " + os.optString("updatesNote", I18n.tr("server.um.findSystemUpdates.1")));
            } else {
                StringBuilder out = new StringBuilder();
                code = runLogged(j, "freebsd-update --not-running-from-cron fetch 2>&1", 1800, out);
                if (code != 0 && !OsPatch.nothingToFetch(out.toString()))
                    throw org.daemoxcp.mail.util.ShownException.of("server.um.startSystemUpdateSearch.8", Map.of("code", String.valueOf(code)));
            }
            j.write("");
            j.outcome = I18n.tr("server.search.done");
            j.write(j.outcome);
            j.status = "completed";
        } catch (Exception e) {
            j.status = "error";
            j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            j.write(I18n.tr("server.um.startMtaStsActivation.1", Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            j.finish();
        }
    }

    /**
     * Whether the server needs a restart, for every page of the panel (the strip at the top): light reads,
     * without freebsd-update or pkg. Also a restart already scheduled, so that it can be canceled.
     */
    public static JSONObject rebootState() {
        String installedKernel = sh("freebsd-version -k 2>/dev/null", 10).trim();
        String runningKernel = sh("uname -r 2>/dev/null", 10).trim();
        java.time.Instant boot = PanelInfo.bootTime(sh("sysctl -n kern.boottime 2>/dev/null", 10));
        long installedAt = 0;
        String to = "";
        try {
            if (Files.isRegularFile(osPatchState)) {
                JSONObject st = new JSONObject(Files.readString(osPatchState));
                installedAt = st.optLong("installedAt", 0);
                to = st.optString("to", "");
            }
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "os-patch state unreadable", e);
        }
        JSONObject r = OsPatch.rebootState(installedKernel, runningKernel, installedAt, boot, to);
        RestartLock.forget();
        RestartLock.State lock = RestartLock.current();
        r.put("scheduled", lock.scheduled());
        if (lock.at() > 0) r.put("at", lock.at());
        if (!lock.known()) r.put("scheduledUnknown", true);
        return r;
    }

    /**
     * Looks for updates to the base system. It DOWNLOADS, it does not install.
     *
     * It runs inside an asynchronous job and not inside the HTTP request: on a system at p0
     * "freebsd-update fetch" has to download months of patches and takes minutes, and on 2026-08-31
     * the browser dropped the connection before the server answered - job done,
     * response lost, and on screen only a "Broken pipe". Long-running operations are followed
     * by polling, like all the others in here.
     */
    private static JSONObject findSystemUpdates() {
        try {
            JSONObject os = operatingSystem();
            if (!os.optBoolean("updatableWithFreebsdUpdate", false))
                return new JSONObject().put("success", false)
                        .put("error", os.optString("updatesNote", I18n.tr("server.um.findSystemUpdates.1")));
            String out = sh("freebsd-update --not-running-from-cron fetch 2>&1", 900);
            String b = out.toLowerCase();
            boolean nobody = b.contains("no updates needed") || b.contains("has no updates available");
            return new JSONObject().put("success", true).put("output", out.trim())
                    .put("noUpdate", nobody)
                    .put("note", nobody
                        ? I18n.tr("server.um.startSystemUpdateSearch.9")
                        : I18n.tr("server.um.findSystemUpdates.2"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("findSystemUpdates", e));
        }
    }

    /**
     * Preliminary checks for the release jump of the base system. All read-only.
     *
     * Sources: FreeBSD Handbook, chapter "Updating and Upgrading FreeBSD" (the
     * freebsd-update upgrade procedure), the bectl(8) manual for boot environments, and the page
     * https://www.FreeBSD.org/security/ for the end-of-support dates.
     *
     * The point that decides everything: 15.0 and 15.1 have the SAME package ABI
     * (FreeBSD:15:arch), because the ABI carries only the major number. The Handbook requires
     * "pkg-static upgrade -f" only for MAJOR version jumps, precisely because of the
     * ABI change. Here the ABI does not change: the 41 locked packages must not be touched. Were
     * it a major jump, it would be a different procedure.
     */
    /**
     * The panel's rc.d script: content, and installation on request.
     *
     * It is needed because today, if the server restarts for any reason, the panel stays
     * off and nobody reports it. With this it comes back up on its own, in --web mode.
     *
     * Structure taken from the official article "Practical rc.d scripting in BSD" in the
     * FreeBSD documentation: the PROVIDE/REQUIRE/KEYWORD lines for rcorder, the inclusion of
     * /etc/rc.subr, name, rcvar, load_rc_config and run_rc_command.
     *
     * Two choices that the documentation itself suggests:
     *  - the panel is NOT a daemon: it stays in the foreground. The documentation says that in such
     *    cases one defines a custom start_cmd, and here daemon(8) is used to detach it, with -p
     *    for the pidfile and -o for the log.
     *  - procname is the path of java, not /usr/sbin/daemon: rc.subr compares the pid in the
     *    pidfile with procname, and daemon -p writes the pid of the CHILD - which after the exec is
     *    java. Getting this wrong, "service daemoxcp_mail status" would always say it is not running.
     *
     * REQUIRE stays LOGIN and nothing else: the panel tolerates MySQL being down (it reports it and
     * carries on), so tying it to mysql would make it more fragile without gaining anything.
     */
    /**
     * Server restart from the panel.
     *
     * It is the most irreversible action the panel can perform, and it makes sense only since the
     * panel comes back up on its own: without the rc.d script, pressing this button would mean
     * switching off the only interface you are using it from. That is why, without rc.d enabled,
     * it refuses instead of warning.
     *
     * The restart is SCHEDULED, not immediate, for two reasons. The first is technical: shutdown
     * with a future time keeps running until the given moment (shutdown(8) manual),
     * so it must be launched detached or the HTTP response would never arrive. The second is human:
     * one minute is the window to change one's mind, and the panel has a button to cancel it.
     * (On FreeBSD it is canceled by terminating the shutdown process: "-c" is power cycle, not cancel.)
     */
    /**
     * Cancels a scheduled restart.
     *
     * On FreeBSD there is no option to cancel: the shutdown(8) manual says
     * "A scheduled shutdown can be canceled by killing the shutdown process (a SIGTERM should
     * suffice)". Beware of "shutdown -c": on Linux it cancels, on FreeBSD it is POWER CYCLE -
     * it switches the machine off and on again. On 2026-08-31 I wrote it from memory and got it
     * wrong: it is exactly the kind of memory that must be verified before using it.
     */
    /**
     * Where a command really is, asked of the system instead of remembered.
     *
     * On 2026-08-31 the restart button restarted nothing because I had written
     * /usr/sbin/shutdown from memory. "daemon" forks and then execs: if the exec fails, the
     * failure happens in the child and the parent exits successfully anyway - so not even the
     * exit code revealed it. The manual does not state the path, so the answer
     * is not choosing between /sbin and /usr/sbin: it is asking.
     */
    private static String commandPath(String name, String... candidates) {
        if (!name.matches("[a-z0-9_-]{1,32}")) return "";
        String v = sh("command -v " + name + " 2>/dev/null", 20).trim();
        if (v.startsWith("/") && ok("test -x " + v, 10)) return v;
        for (String c : candidates) if (ok("test -x " + c, 10)) return c;
        return "";
    }

    public static JSONObject cancelReboot() {
        try {
            String pid = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            if (!pid.matches("[0-9]{1,7}")) pid = sh("pgrep -f '/shutdown -r' 2>/dev/null | head -1", 20).trim();
            if (!pid.matches("[0-9]{1,7}"))
                return new JSONObject().put("success", true).put("existedBefore", false)
                        .put("note", I18n.tr("server.um.cancelReboot.1"));
            String line = sh("ps -o command= -p " + pid + " 2>/dev/null", 20).trim();
            boolean done = ok("kill " + pid, 20);
            // The proof that matters: is the process really gone?
            String still = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            boolean via = still.isEmpty();
            if (via) RestartLock.cleared(); else RestartLock.forget();
            return new JSONObject().put("success", via).put("existedBefore", true)
                    .put("pid", pid).put("command", line)
                    .put("note", via
                        ? I18n.tr("server.um.cancelReboot.2", java.util.Map.of("pid", String.valueOf(pid), "line", String.valueOf(line)))
                        : I18n.tr("server.um.cancelReboot.3", java.util.Map.of("still", String.valueOf(still), "still2", String.valueOf(still))))
                    .put("error", via ? "" : I18n.tr("server.um.cancelReboot.4"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("cancelReboot", e));
        }
    }

    public static JSONObject restartServer(boolean run, int minutes) {
        JSONObject r = new JSONObject();
        try {
            if (minutes < 0 || minutes > 60) minutes = 1;
            JSONObject os = operatingSystem();
            r.put("installedKernel", os.optString("installedKernel"))
             .put("runningKernel", os.optString("uname"))
             .put("restartNeeded", os.optBoolean("restartNeeded"))
             .put("minutes", minutes);

            JSONObject startup = autoStart();
            boolean rc = startup.optBoolean("installed", false);
            boolean enabled = startup.optBoolean("enabled", false);
            r.put("rcActive", startup.optBoolean("active", false));
            r.put("autoStart", startup);
            if (!(rc && enabled)) {
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.restartServer.1"));
            }

            // What stops: listing it beforehand is better than finding out afterwards.
            JSONArray services = new JSONArray();
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                if (ok("service " + svc + " status", 20)) services.put(svc);
            }
            r.put("services", services);
            r.put("effect", I18n.tr("server.um.restartServer.2", java.util.Map.of("length", String.valueOf(services.length()))));

            // A running job would be cut off halfway by the restart (a pkg replacing the libraries, a file
            // rewritten without the reload): as long as there is one, the restart is not scheduled. This is
            // already said in the dialog, before the button.
            String busy = runningWork();
            if (busy != null) {
                return r.put("success", false).put("busy", busy)
                        .put("error", I18n.tr("server.restartLock.busy", java.util.Map.of("what", busy)));
            }

            String pending = sh("ps -axo command | grep '^shutdown ' | head -1", 20).trim();
            r.put("gaScheduled", pending);
            // The manual: "-f  Ignore the presence of the /var/run/noshutdown file". If that
            // file exists, shutdown refuses - and it is better to know that before pressing.
            boolean noshutdown = ok("test -f /var/run/noshutdown", 10);
            r.put("noshutdown", noshutdown);
            String shPrev = commandPath("shutdown", "/sbin/shutdown", "/usr/sbin/shutdown");
            String dmPrev = commandPath("daemon", "/usr/sbin/daemon", "/sbin/daemon");
            r.put("shutdownPath", shPrev.isEmpty() ? I18n.tr("server.um.restartServer.3") : shPrev)
             .put("daemonPath", dmPrev.isEmpty() ? I18n.tr("server.um.restartServer.3") : dmPrev);
            if (noshutdown)
                r.put("noshutdownWarning", I18n.tr("server.um.restartServer.4"));
            if (!run) return r.put("success", true).put("executed", false);

            String msg = "Restart requested by " + Product.NAME;
            String shutdown = commandPath("shutdown", "/sbin/shutdown", "/usr/sbin/shutdown");
            String daemon = commandPath("daemon", "/usr/sbin/daemon", "/sbin/daemon");
            if (shutdown.isEmpty() || daemon.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.x.noShutdownCmd", java.util.Map.of("cmd", String.valueOf(shutdown.isEmpty() ? "shutdown" : "daemon"))));
            String logR = "/var/db/daemoxcp-mail/reboot.log";
            ok("mkdir -p /var/db/daemoxcp-mail", 20);
            ok("rm -f " + logR, 15);
            // Detached: shutdown with a future time does not return until it is time. And with -o
            // instead of just -f, if it refuses it tells someone: the first version sent
            // its output to /dev/null and on 2026-08-31 the restart did not happen without
            // anyone knowing why.
            ok(daemon + " -f -o " + logR + " " + shutdown + " -r +" + minutes + " '" + msg + "'", 30);

            // "daemon" exits immediately and successfully regardless: its exit code says
            // nothing about shutdown. The only proof is that the shutdown process EXISTS.
            ok("sleep 2", 15);
            String pidS = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            String output = sh("cat " + logR + " 2>/dev/null", 20).trim();
            if (!pidS.matches("[0-9]{1,7}")) {
                boolean nosh = ok("test -f /var/run/noshutdown", 10);
                return r.put("success", false).put("executed", false)
                        .put("output", output)
                        .put("error", I18n.tr("server.um.x.restartNotScheduled")
                            + (nosh ? "  " + I18n.tr("server.um.x.noshutdownCause")
                                    : "")
                            + "  " + (output.isEmpty() ? I18n.tr("server.um.x.shutdownSilent")
                                             : I18n.tr("server.um.x.shutdownWrote", java.util.Map.of("u", String.valueOf(output)))));
            }
            RestartLock.record(pidS, System.currentTimeMillis() + minutes * 60_000L);
            return r.put("success", true).put("executed", true).put("pid", pidS)
                    .put("output", output)
                    .put("note", minutes == 1
                        ? I18n.tr("server.um.x.restartIn.one")
                        : I18n.tr("server.um.x.restartIn.other", java.util.Map.of("n", String.valueOf(minutes))))
                    .put("cancel", I18n.tr("server.um.restartServer.6"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("restartServer", e));
        }
    }

    /**
     * Does the panel come back up on its own after a server restart?
     *
     * The answer already existed, but only INSIDE restartServer(): it served to refuse a
     * restart, and it was never told to anyone. So the most important fact - whether the
     * panel switches back on or not - was discovered only by trying to restart, that is at the
     * worst moment to discover it.
     *
     * It matters more than it seems: inside the web server live the DKIM rotation
     * scheduler, the automatic certificate renewal and the periodic report. If the panel does not
     * restart, those things do not break - they stop where they are, and nobody reports it.
     */
    /**
     * Is the list of Cloudflare ranges compiled into the panel still the official one?
     *
     * Why it is needed. The panel trusts CF-Connecting-IP only if the request comes from
     * an address it recognizes as Cloudflare; the list of those addresses is written by hand
     * inside TrustedProxy and must be kept equal to cloudflare.com/ips-v4 and ips-v6.
     *
     * If Cloudflare adds a range and starts serving from there, the panel stops
     * recognizing it: from that moment ALL visitors become a single address - that
     * of the edge - and the login attempt limit applies to all of them together. Five
     * wrong attempts by anyone would lock you out too. It is not a hole, it is a
     * lockout: it fails by becoming stricter, which is the quietest way of breaking.
     *
     * This function only READS: it downloads the two official lists and compares them. It does not
     * update anything on its own - a list of who is trustworthy is not rewritten without
     * a human being having looked at it.
     */
    public static JSONObject cloudflareRanges() {
        JSONObject r = new JSONObject().put("updatedOn", org.daemoxcp.mail.security.TrustedProxy.UPDATED_ON);
        // What the panel BELIEVES is always shown, even if the network does not answer: it is
        // its own knowledge, it does not depend on cloudflare.com. A list that decides whom to trust and
        // that nobody can read is a secret rule; and the moment the comparison
        // fails is exactly when one needs to be able to look at what is written in it.
        r.put("listV4", new JSONArray(org.daemoxcp.mail.security.TrustedProxy.cloudflareV4()));
        r.put("listV6", new JSONArray(org.daemoxcp.mail.security.TrustedProxy.cloudflareV6()));
        try {
            java.util.List<String> v4 = downloadIntervals("https://www.cloudflare.com/ips-v4", true);
            java.util.List<String> v6 = downloadIntervals("https://www.cloudflare.com/ips-v6", false);

            // A minimum threshold, not just "not empty".
            //
            // Without it, a partial response or an error page from which two lines survive
            // would give a short official list. No "missing" range - so no
            // red - and instead a dozen "no longer official": the panel would advise
            // REMOVING from the trust list ranges that Cloudflare very much uses. A
            // wrong piece of advice is worse than a wrong green, because whoever follows it breaks
            // something of their own with their own hands.
            //
            // Cloudflare has published at least 15 IPv4 and 7 IPv6 ranges for years. The threshold
            // is deliberately below that: it must trigger on a broken response, not on a legitimate
            // update of the list.
            final int MIN_V4 = 10, MIN_V6 = 5;
            if (v4.size() < MIN_V4 || v6.size() < MIN_V6)
                return r.put("success", false).put("verified", false)
                        .put("officialV4", v4.size()).put("officialV6", v6.size())
                        .put("error", I18n.tr("server.um.cloudflareRanges.1", java.util.Map.of("size", String.valueOf(v4.size()), "size2", String.valueOf(v6.size()), "minimumV4", String.valueOf(MIN_V4), "minimumV6", String.valueOf(MIN_V6))));

            java.util.List<String> myV4 = org.daemoxcp.mail.security.TrustedProxy.cloudflareV4();
            java.util.List<String> myV6 = org.daemoxcp.mail.security.TrustedProxy.cloudflareV6();

            // Missing = present at Cloudflare and NOT in the panel. They are the ones that matter:
            // they are the addresses from which the panel would not recognize the proxy.
            JSONArray missing = new JSONArray();
            for (String c : v4) if (!myV4.contains(c)) missing.put(c);
            for (String c : v6) if (!myV6.contains(c)) missing.put(c);

            // Extra = in the panel and no longer official. They do no direct harm, but they are
            // trust granted to addresses that Cloudflare no longer uses.
            JSONArray extra = new JSONArray();
            for (String c : myV4) if (!v4.contains(c)) extra.put(c);
            for (String c : myV6) if (!v6.contains(c)) extra.put(c);

            r.put("success", true).put("verified", true)
             .put("officialV4", v4.size()).put("officialV6", v6.size())
             .put("compiledV4", myV4.size()).put("compiledV6", myV6.size())
             .put("missing", missing).put("extra", extra)
             .put("aligned", missing.length() == 0 && extra.length() == 0);

            r.put("note", missing.length() > 0
                ? I18n.tr("server.um.cloudflareRanges.2", java.util.Map.of("length", String.valueOf(missing.length())))
                : extra.length() > 0
                  ? I18n.tr("server.um.cloudflareRanges.3", java.util.Map.of("length", String.valueOf(extra.length())))
                  : I18n.tr("server.um.cloudflareRanges.4"));
            return r;
        } catch (Exception e) {
            return r.put("success", false).put("verified", false)
                    .put("error", I18n.tr("server.um.cloudflareRanges.5", java.util.Map.of("message", ErrorText.detail("cloudflareRanges", e))));
        }
    }

    /**
     * One line per range, blank lines and comments discarded.
     *
     * @param ipv4 the expected family: a line of the wrong family is discarded. The
     *             shape check alone does not tell an IPv6 CIDR from an IPv4 one, and a
     *             list that arrived on the wrong file would skew the comparison.
     */
    public static java.util.List<String> downloadIntervals(String url, boolean ipv4) {
        java.util.List<String> out = new java.util.ArrayList<>();
        try {
            var http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(8)).build();
            var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(15)).GET().build();
            var resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return out;
            for (String line : resp.body().split("\n")) {
                String c = line.trim();
                // Only what has the shape of a CIDR is accepted: nothing from an error page or from
                // an unexpected response must get into a trust list.
                if (c.isEmpty() || c.startsWith("#")) continue;
                // Two filters, not one. The shape must hold for the WHOLE line - so a line
                // of HTML that contains a CIDR does not pass - and the line must be a real CIDR
                // of the right family.
                if (!c.matches("[0-9a-fA-F:.]+/[0-9]{1,3}")) continue;
                boolean looksLikeV4 = c.indexOf(':') < 0;
                if (looksLikeV4 != ipv4) continue;
                if (!validCidr(c, ipv4)) continue;
                out.add(c);
            }
        } catch (Exception ignore) { }
        return out;
    }

    /** The CIDR can really be written: a valid literal address and a prefix in the right range. */
    private static boolean validCidr(String cidr, boolean ipv4) {
        try {
            int i = cidr.indexOf('/');
            int prefix = Integer.parseInt(cidr.substring(i + 1));
            if (prefix < 0 || prefix > (ipv4 ? 32 : 128)) return false;
            byte[] b = java.net.InetAddress.getByName(cidr.substring(0, i)).getAddress();
            return b.length == (ipv4 ? 4 : 16);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * The summary for the Home page: versions, restart needed, how many updates, how many
     * vulnerabilities. FAST - and speed here is a requirement, not a whim.
     *
     * updatesStatus() answers the same questions but runs "pkg update" and "pkg upgrade -n":
     * up to five minutes, with the network in the middle. In a page that is opened all the time it
     * would be a Home page that keeps spinning. Here the catalog ALREADY downloaded and the vulnerability
     * database ALREADY present are read: no network request.
     *
     * The price of that choice is that the numbers can be old, and that must be said instead of
     * hidden: the AGE of the catalog and of the database is reported too. A precise count
     * derived from three-week-old data is a number that looks like a measurement and is not one -
     * for the real simulation there is still the Updates page, which does it on purpose.
     */
    public static JSONObject systemSummary() {
        JSONObject r = new JSONObject();
        try {
            r.put("os", operatingSystem());

            // How many packages differ from the local catalog, BROKEN DOWN BY REASON.
            //
            // "pkg version -L=" shows everything that is not "=" , and the manual (pkg-version(8))
            // lists four different cases: "<" installed is older, ">" installed is newer
            // than the catalog, "?" not present in the catalog, "!" comparison failed.
            // Only the first means "there is an update".
            //
            // Counting them all together and calling them "newer version available" gave a
            // number that matched nothing: here it said 5 while "pkg upgrade -n"
            // answered "Your packages are up to date", that is zero. A number that no
            // other screen confirms casts doubt on all the others.
            String list = sh("pkg version -U -vRL= 2>/dev/null", 60);
            int toUpdate = 0, mostRecent = 0, outsideCatalog = 0, notComparable = 0;
            for (String line : list.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                String[] fields = t.split("\\s+");
                String state = fields.length > 1 ? fields[1] : "";
                switch (state) {
                    case "<" -> toUpdate++;
                    case ">" -> mostRecent++;
                    case "?" -> outsideCatalog++;
                    case "!" -> notComparable++;
                    default -> { }
                }
            }
            r.put("toUpdate", toUpdate)
             .put("newerThanCatalog", mostRecent)
             .put("outsideCatalog", outsideCatalog)
             .put("notComparable", notComparable);

            // The age of the catalog: without it, the number above looks more precise than it is.
            // It is the publication date on the server (see PkgCatalog).
            JSONObject cat = PkgCatalog.read();
            r.put("catalogDays", cat.optLong("days", -1)).put("catalogDate", cat.optString("data"))
             .put("catalogNote", cat.optString("note"));

            // Vulnerabilities from the local database: "pkg audit" without -F does not download.
            String audit = sh("pkg audit -q 2>/dev/null", 60);
            int vuln = 0;
            for (String line : audit.split("\n")) if (!line.trim().isEmpty()) vuln++;
            r.put("vulnerable", vuln);
            r.put("vulnDbDays", daysSince("/var/db/pkg/vuln.xml"));

            return r.put("success", true);
        } catch (Exception e) {
            return r.put("success", false).put("error", ErrorText.forPage("systemSummary", e));
        }
    }

    /** For how many days a file has not been touched. -1 if it does not exist or cannot be read. */
    private static long daysSince(String path) {
        try {
            String m = sh("stat -f %m " + path + " 2>/dev/null", 15).trim();
            if (m.isEmpty()) return -1;
            long epoch = Long.parseLong(m);
            return (System.currentTimeMillis() / 1000L - epoch) / 86400L;
        } catch (Exception e) {
            return -1;
        }
    }

    public static JSONObject autoStart() {
        JSONObject r = new JSONObject();
        try {
            String path = ok("test -f " + PanelRcScript.PATH, 10)
                    ? PanelRcScript.PATH
                    : (ok("test -f /etc/rc.d/" + RC_NAME, 10) ? "/etc/rc.d/" + RC_NAME : null);
            boolean installed = path != null;
            String enabledBy = sh("sysrc -n " + RC_NAME + "_enable 2>/dev/null", 20).trim();
            boolean enabled = "YES".equalsIgnoreCase(enabledBy) || "yes".equalsIgnoreCase(enabledBy)
                    || "true".equalsIgnoreCase(enabledBy) || "1".equals(enabledBy);
            r.put("success", true)
             .put("installed", installed)
             .put("enabled", enabled)
             .put("active", installed && enabled)
             .put("path", path == null ? "" : path)
             .put("sysrcValue", enabledBy);
            r.put("reason", installed && enabled
                ? I18n.tr("server.um.autoStart.1")
                : !installed
                  ? I18n.tr("server.um.autoStart.2")
                  : I18n.tr("server.um.x.rcNotEnabled", java.util.Map.of("v", String.valueOf(enabledBy.isEmpty() ? I18n.tr("server.um.x.notSet") : enabledBy))));
            return r;
        } catch (Exception e) {
            // "I could not check" is not "all is well": whoever reads must see it.
            return r.put("success", false).put("active", false)
                    .put("reason", I18n.tr("server.um.autoStart.3", java.util.Map.of("message", ErrorText.detail("autoStart", e))));
        }
    }

    /**
     * Removes the automatic start: disables daemoxcp_mail_enable and removes the rc.d script.
     *
     * It does NOT stop the panel. If you are reading these lines from a panel started by the
     * service, that process keeps running: slamming the door in its face while you press the
     * button would be absurd. The only change is that at the next restart it does not come back up -
     * and with it the DKIM rotation scheduler, the certificate renewal and the
     * periodic report do not come back up either.
     *
     * Three precautions, all learned at someone else's expense:
     *
     *  - Before deleting, a COPY is made, and if the copy fails nothing is deleted. An
     *    rc.d script deleted without a copy can only be rewritten by reinstalling it.
     *  - "sysrc -x" on a variable that does not exist has an undocumented outcome: in that case
     *    it is not even called. No blind commands are given to a boot
     *    configuration file.
     *  - The verdict is NOT read from exit codes: "sysrc -n" is read again and the file is
     *    checked again. A command that "succeeds" without having done the thing is the most
     *    common way of telling oneself that it went well.
     *
     * @param run false = preview, touches nothing.
     */
    public static JSONObject removePanelRcScript(boolean run) {
        JSONObject r = new JSONObject();
        try {
            JSONObject before = autoStart();
            r.put("before", before);
            String path = before.optString("path", "");
            boolean installed = before.optBoolean("installed", false);
            String value = before.optString("sysrcValue", "").trim();
            boolean variableExists = !value.isEmpty();

            String copy = DataFolderRename.NEW + "/" + RC_NAME + ".rc.removed";
            r.put("path", path).put("copy", copy)
             .put("installed", installed).put("variableExists", variableExists);

            // Whoever is removing the panel's automatic start must know that the locks
            // stay: it is the only point where the question arises by itself.
            String locksWarning = locksStayWarning();
            if (!locksWarning.isEmpty()) r.put("locksStay", locksWarning);

            if (!installed && !variableExists)
                return r.put("success", true).put("executed", false).put("nothingToDo", true)
                        .put("note", joinNotes(I18n.tr("server.um.removePanelRcScript.1"), locksWarning));

            if (!run)
                return r.put("success", true).put("executed", false)
                        .put("note", joinNotes(I18n.tr("server.um.x.rcRmPreview", java.util.Map.of("actions", String.valueOf((variableExists ? I18n.tr("server.um.x.rcRmVar") : "")
                                + (variableExists && installed ? " " + I18n.tr("server.um.x.and") + " " : "")
                                + (installed ? I18n.tr("server.um.x.rcRmFile", java.util.Map.of("file", String.valueOf(path), "copy", String.valueOf(copy))) : "")))), locksWarning));

            ok("mkdir -p /var/db/daemoxcp-mail", 20);

            // 1. The copy BEFORE everything: if it fails, nothing goes on.
            if (installed) {
                ok("cp -p " + path + " " + copy, 20);
                if (!ok("test -s " + copy, 10))
                    return r.put("success", false)
                            .put("error", I18n.tr("server.um.removePanelRcScript.2", java.util.Map.of("path", String.valueOf(path), "copy", String.valueOf(copy))));
                r.put("copyDone", true);
            }

            // 2. The variable, only if it really exists.
            if (variableExists) ok("sysrc -x " + RC_NAME + "_enable", 30);

            // 3. Lo script.
            if (installed) ok("rm -f " + path, 20);

            // 4. The verdict: it is READ AGAIN, not inferred from the exit codes.
            JSONObject after = autoStart();
            r.put("after", after);
            boolean fileStays = after.optBoolean("installed", false);
            boolean varStays = !after.optString("sysrcValue", "").trim().isEmpty();
            if (fileStays || varStays) {
                java.util.List<String> stays = new java.util.ArrayList<>();
                if (fileStays) stays.add(I18n.tr("server.um.removePanelRcScript.3", java.util.Map.of("path", String.valueOf(path))));
                if (varStays) stays.add(I18n.tr("server.um.x.rcVarStill", java.util.Map.of("v", String.valueOf(after.optString("sysrcValue", "")))));
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.x.rcRmIncomplete", java.util.Map.of("stays", String.valueOf(String.join("; ", stays)), "copy", String.valueOf(copy))));
            }

            return r.put("success", true).put("executed", true)
                    .put("note", joinNotes(I18n.tr("server.um.removePanelRcScript.4", java.util.Map.of("copy", String.valueOf(copy))), locksWarning));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.um.removePanelRcScript.5", java.util.Map.of("message", ErrorText.detail("removePanelRcScript", e))));
        }
    }

    public static JSONObject panelRcScript(boolean run) {
        JSONObject r = new JSONObject();
        try {
            String dir = System.getProperty("user.dir", "");
            String jar = jarPath();
            String binJava = System.getProperty("java.home", "") + "/bin/java";
            if (jar.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.panelRcScript.1"));
            StringBuilder option = new StringBuilder();
            for (String o : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
                if (o.startsWith("-agentlib") || o.startsWith("-javaagent") || o.startsWith("-Xdebug")) continue;
                option.append(' ').append(o);
            }
            String path = PanelRcScript.PATH;
            r.put("path", path).put("dir", dir).put("jar", jar).put("java", binJava);
            String text = PanelRcScript.text(dir, binJava, jar, option.toString().trim());
            r.put("text", text);

            boolean exists = ok("test -f " + path, 10);
            String enabled = sh("sysrc -n " + RC_NAME + "_enable 2>/dev/null", 20).trim();
            r.put("exists", exists).put("enabled", enabled);
            if (!run) return r.put("success", true).put("executed", false);

            // Checks the syntax BEFORE putting it where the system will run it at startup:
            // a broken rc.d script can stop the boot sequence.
            String tmp = DataFolderRename.NEW + "/" + RC_NAME + ".rc.test";
            ok("mkdir -p /var/db/daemoxcp-mail", 20);
            Files.writeString(Paths.get(tmp), text);
            String syntaxCheck = sh("sh -n " + tmp + " 2>&1", 30).trim();
            if (!syntaxCheck.isEmpty()) {
                ok("rm -f " + tmp, 15);
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.panelRcScript.3", java.util.Map.of("syntax", String.valueOf(syntaxCheck))));
            }
            if (exists) ok("cp -p " + path + " " + DataFolderRename.NEW + "/" + RC_NAME + ".rc.previous", 20);
            Files.writeString(Paths.get(path), text);
            ok("chmod 755 " + path, 15);
            ok("rm -f " + tmp, 15);
            boolean sysrc = ok("sysrc " + RC_NAME + "_enable=YES", 30);

            // The test that matters: does rc.subr load it without errors?
            String test = sh("service " + RC_NAME + " rcvar 2>&1", 30).trim();
            boolean loaded = test.contains(RC_NAME + "_enable");
            return r.put("success", true).put("executed", true)
                    .put("enabledNow", sysrc ? sh("sysrc -n " + RC_NAME + "_enable 2>/dev/null", 20).trim() : "?")
                    .put("loaded", loaded).put("rcvar", test)
                    .put("note", I18n.tr("server.um.panelRcScript.4"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("panelRcScript", e));
        }
    }

    /**
     * Which versions it makes sense to go to, starting from the installed one.
     *
     * A free text field let one write 16.0 (major jump, all packages to be
     * rebuilt), 15.9 (does not exist), or 14.4 (backwards). The panel knows which releases are
     * supported and knows where it starts from: it can offer only the sensible choices instead of
     * accepting anything and then complaining about it.
     */
    /**
     * How the installed version relates to the chosen one.
     *
     * A function of its own because it must be TESTABLE. Inside the preflight it was unreachable by
     * any test: the first check looks at whether the system is a -RELEASE, and on a
     * machine that is not FreeBSD it stops there. A test that does not get to exercise what it
     * must verify passes and proves nothing.
     *
     * Returns: "backward", "same", "minor", "major", "unreadable".
     */
    static String updateDirection(String current, String target) {
        Matcher a = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(current == null ? "" : current);
        Matcher b = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(target == null ? "" : target);
        if (!a.find() || !b.find()) return "unreadable";
        int a1 = Integer.parseInt(a.group(1)), a2 = Integer.parseInt(a.group(2));
        int b1 = Integer.parseInt(b.group(1)), b2 = Integer.parseInt(b.group(2));
        if (b1 < a1 || (b1 == a1 && b2 < a2)) return "backward";
        if (b1 == a1 && b2 == a2) return "same";
        return b1 == a1 ? "minor" : "major";
    }

    public static JSONObject targetVersions() {
        try {
            JSONObject os = operatingSystem();
            String series = os.optString("series");
            Matcher m = Pattern.compile("^([0-9]+)\\.([0-9]+)$").matcher(series);
            if (!m.find())
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.targetVersions.1", java.util.Map.of("series", String.valueOf(series))));
            int majorExpected = Integer.parseInt(m.group(1)), minorExpected = Integer.parseInt(m.group(2));
            JSONArray outside = new JSONArray();
            for (String[] e : END_OF_SUPPORT) {
                Matcher m2 = Pattern.compile("^([0-9]+)\\.([0-9]+)$").matcher(e[0]);
                if (!m2.find()) continue;
                int ma = Integer.parseInt(m2.group(1)), mi = Integer.parseInt(m2.group(2));
                if (ma != majorExpected) continue;          // major jumps do not go through here
                if (mi <= minorExpected) continue;          // if same or backward: it is not an update
                outside.put(new JSONObject().put("version", e[0])
                        .put("endOfSupport", e[1]).put("note", I18n.tr(e[2])));
            }
            return new JSONObject().put("success", true).put("current", series)
                    .put("versions", outside)
                    .put("source", I18n.tr(SUPPORT_SOURCE))
                    .put("note", outside.length() == 0
                        ? I18n.tr("server.um.targetVersions.2", java.util.Map.of("series", String.valueOf(series)))
                        : I18n.tr("server.um.targetVersions.3", java.util.Map.of("majorNow", String.valueOf(majorExpected), "p", String.valueOf((majorExpected + 1)))));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("targetVersions", e));
        }
    }

    public static JSONObject systemUpgradePreflight(String targetVersion) {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean lock = false;
        try {
            if (targetVersion == null || !targetVersion.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
                return r.put("success", false).put("error", I18n.tr("server.um.systemUpgradePreflight.1"));
            String target = targetVersion + "-RELEASE";
            r.put("target", target);

            JSONObject os = operatingSystem();
            String userland = os.optString("userland"), uname = os.optString("uname");
            r.put("current", userland).put("uname", uname).put("arch", os.optString("arch"));

            if (!userland.contains("-RELEASE")) {
                addCheck(checks, "kind", I18n.tr("server.um.systemUpgradePreflight.2"), "block",
                        I18n.tr("server.um.systemUpgradePreflight.3", java.util.Map.of("userland", String.valueOf(userland))));
                return r.put("success", true).put("checks", checks).put("blocked", true).put("canProceed", false);
            }
            addCheck(checks, "current", I18n.tr("server.um.x.currentVersion"), "ok",
                    I18n.tr("server.um.x.userlandKernel", java.util.Map.of("u", String.valueOf(userland), "k", String.valueOf(uname)))
                    + (os.optBoolean("restartNeeded")
                       ? I18n.tr("server.um.systemUpgradePreflight.4") : ""));
            if (os.optBoolean("restartNeeded")) {
                addCheck(checks, "restartPending", I18n.tr("server.um.systemUpgradePreflight.5"), "block",
                        I18n.tr("server.um.systemUpgradePreflight.6"));
                lock = true;
            }

            // Minor or major jump? It changes whether the packages must be rebuilt.
            String majorExpected = userland.replaceAll("[^0-9.].*$", "").replaceAll("\\..*$", "");
            String majorNew = targetVersion.replaceAll("\\..*$", "");
            boolean minor = majorExpected.equals(majorNew);

            // Direction: decided by a separate function, which can be put to the test.
            String direction = updateDirection(os.optString("series"), targetVersion);
            r.put("direction", direction);
            if ("backward".equals(direction) || "same".equals(direction)) {
                addCheck(checks, "direction", I18n.tr("server.um.systemUpgradePreflight.7"), "block",
                        "same".equals(direction)
                        ? I18n.tr("server.um.systemUpgradePreflight.8", java.util.Map.of("target", String.valueOf(targetVersion)))
                        : I18n.tr("server.um.x.targetOlder", java.util.Map.of("target", String.valueOf(targetVersion), "series", String.valueOf(os.optString("series")))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", true).put("canProceed", false);
            }
            r.put("minorJump", minor);
            String abiName = sh("pkg config abi 2>/dev/null", 20).trim();
            r.put("abiName", abiName);
            if (!minor) lock = true;
            addCheck(checks, "abi", I18n.tr("server.um.systemUpgradePreflight.9"), minor ? "ok" : "block",
                    minor
                    ? I18n.tr("server.um.systemUpgradePreflight.10", java.util.Map.of("abi", String.valueOf(abiName), "majorNow", String.valueOf(majorExpected), "majorNew", String.valueOf(majorNew)))
                    : I18n.tr("server.um.systemUpgradePreflight.11", java.util.Map.of("majorNow", String.valueOf(majorExpected), "majorNew", String.valueOf(majorNew))));

            // End of support of the target version: moving to something that expires soon
            // solves nothing.
            String eolNew = "", noteNew = "";
            for (String[] e : END_OF_SUPPORT) if (e[0].equals(targetVersion)) { eolNew = e[1]; noteNew = I18n.tr(e[2]); }
            r.put("targetEndOfSupport", eolNew);
            addCheck(checks, "eol", I18n.tr("server.um.systemUpgradePreflight.12"), eolNew.isEmpty() ? "wait" : "ok",
                    eolNew.isEmpty()
                    ? I18n.tr("server.um.systemUpgradePreflight.13", java.util.Map.of("target", String.valueOf(targetVersion)))
                    : I18n.tr("server.um.x.supportedUntil", java.util.Map.of("target", String.valueOf(target), "eol", String.valueOf(eolNew), "note", String.valueOf(noteNew), "series", String.valueOf(os.optString("series")), "end", String.valueOf(os.optString("endOfSupport")))));

            // Custom kernel: the Handbook warns that it is not updated.
            String kconf = sh("sysctl -n kern.conftxt 2>/dev/null | head -1", 20).trim();
            boolean generic = os.optString("arch").contains("GENERIC");
            addCheck(checks, "kernel", "Kernel", generic ? "ok" : "wait",
                    generic
                    ? I18n.tr("server.um.systemUpgradePreflight.14")
                    : I18n.tr("server.um.x.notGeneric", java.util.Map.of("arch", String.valueOf(os.optString("arch")))));

            // Boot environments: they are the real way back from a base update.
            boolean be = ok("bectl check", 30);
            r.put("bootEnvironment", be);
            if (be) {
                String list = sh("bectl list -H 2>/dev/null | awk '{print $1\" (\"$2\") \"$4}'", 30);
                r.put("existingBes", list);
                addCheck(checks, "be", I18n.tr("server.um.systemUpgradePreflight.15"), "ok",
                        I18n.tr("server.um.x.beSupported", java.util.Map.of("list", String.valueOf(list.replace("\n", " | ")))));
            } else {
                addCheck(checks, "be", I18n.tr("server.um.systemUpgradePreflight.15"), "wait",
                        I18n.tr("server.um.systemUpgradePreflight.16"));
            }

            // Space: the boot environment is a clone, but the downloaded files and the old libraries
            // take up space anyway.
            long freeMb = number(sh("df -m / | tail -1 | awk '{print $4}'", 30));
            r.put("freeMb", freeMb);
            addCheck(checks, "space", I18n.tr("server.um.x.spaceRoot"), freeMb > 5000 ? "ok" : "block",
                    I18n.tr("server.um.x.mbFreeRoot", java.util.Map.of("n", String.valueOf(freeMb))) + " " + (freeMb > 5000
                        ? I18n.tr("server.um.systemUpgradePreflight.17")
                        : I18n.tr("server.um.systemUpgradePreflight.18")));
            if (freeMb <= 5000) lock = true;

            // The panel itself: two restarts, and it does not come back up on its own.
            // Careful about what is asserted. The file is there and sysrc says YES: those are facts. That
            // the panel COMES BACK UP is a prediction, and the only proof is having started it once
            // with "service daemoxcp_mail start". Saying "it will come back up on its own" because a file
            // exists is the same gap between "installed" and "works" that I keep getting wrong.
            boolean rc = ok("test -f " + PanelRcScript.PATH + " -o -f /etc/rc.d/" + RC_NAME, 10);
            String enabledBy = sh("sysrc -n " + RC_NAME + "_enable 2>/dev/null", 20).trim();
            boolean enabled = "YES".equalsIgnoreCase(enabledBy) || "yes".equalsIgnoreCase(enabledBy)
                    || "true".equalsIgnoreCase(enabledBy) || "1".equals(enabledBy);
            boolean tested = ok("test -f " + PanelRcScript.PIDFILE, 10);
            r.put("rcPanel", rc).put("rcEnabled", enabled).put("rcTested", tested);
            addCheck(checks, "panel", I18n.tr("server.um.systemUpgradePreflight.19"),
                    (rc && enabled && tested) ? "ok" : "wait",
                    !rc
                    ? I18n.tr("server.um.systemUpgradePreflight.20")
                    : !enabled
                    ? I18n.tr("server.um.systemUpgradePreflight.21", java.util.Map.of("enabled", String.valueOf(enabledBy)))
                    : tested
                    ? I18n.tr("server.um.systemUpgradePreflight.22")
                    : I18n.tr("server.um.systemUpgradePreflight.23"));

            // The services that must come back up: they are noted down NOW so they can be compared AFTERWARDS.
            JSONArray services = new JSONArray();
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                services.put(new JSONObject().put("name", svc).put("active", ok("service " + svc + " status", 20)));
            }
            r.put("services", services);
            addCheck(checks, "services", I18n.tr("server.um.systemUpgradePreflight.24"), "ok",
                    I18n.tr("server.um.systemUpgradePreflight.25", java.util.Map.of("length", String.valueOf(services.length()))));

            // Pending security patches: the Handbook says to apply them BEFORE upgrading.
            String pl = uname.contains("-p") ? uname.replaceAll(".*-p", "p") : "p0 " + I18n.tr("server.um.x.noPatch");
            addCheck(checks, "patch", I18n.tr("server.um.systemUpgradePreflight.26"), "wait",
                    I18n.tr("server.um.systemUpgradePreflight.27", java.util.Map.of("pl", String.valueOf(pl))));

            r.put("success", true).put("checks", checks)
             .put("blocked", lock).put("canProceed", !lock);
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("systemUpgradePreflight", e));
        }
    }

    public static JSONObject startSystemPreparation(String target) {
        if (target == null || !target.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.systemUpgradePreflight.1"));
        String id = "sys-" + System.currentTimeMillis();
        Job j = new Job(id, "system");
        JOBS.put(id, j);
        final String b = target;
        Thread t = localizedThread(j, () -> runSystemPreparation(j, b), "system-prep");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Prepares the release jump: copy of /etc, boot environment, pending patches.
     *
     * It does not upgrade the release: it puts the system in the condition the Handbook says it
     * must be in before starting, and creates the way back. The real jump is interactive
     * (it asks for confirmation, it may open an editor to merge the files in /etc) and involves two
     * restarts during which this page does not exist: that part is done by a person, with the
     * instructions that the panel generates from the real values of this server.
     */
    private static void runSystemPreparation(Job job, String target) {
        job.status = "running";
        final int TOT = 4;
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runSystemPreparation.1", java.util.Map.of("target", String.valueOf(target))));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = systemUpgradePreflight(target);
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if ("block".equals(c.optString("level")))
                        job.write("  [" + I18n.tr("server.um.x.blockTag") + "] " + c.optString("label") + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            job.write("  " + pf.optString("current") + " -> " + pf.optString("target")
                    + "   " + (pf.optBoolean("minorJump") ? I18n.tr("server.um.x.jumpMinor")
                                                          : I18n.tr("server.um.x.jumpMajor")));

            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            String bk = "/var/db/daemoxcp-mail/system/" + ts;
            if (!ok("mkdir -p " + bk, 30)) throw new IllegalStateException("cannot create " + bk);

            job.advance(2, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runSystemPreparation.2", java.util.Map.of("total", String.valueOf(TOT))));
            if (!ok("tar -cf " + bk + "/etc.tar -C /etc . 2>/dev/null", 600))
                throw new IllegalStateException("copy of /etc failed");
            long entries = number(sh("tar -tf " + bk + "/etc.tar 2>/dev/null | wc -l", 120));
            if (entries < 50) throw new IllegalStateException("the copy of /etc has only " + entries
                    + " entries: not credible, I stop");
            job.write("    /etc -> " + bk + "/etc.tar " + I18n.tr("server.um.x.entries", java.util.Map.of("n", String.valueOf(entries))));
            sh("pkg query '%n %v' > " + bk + "/packages.txt 2>/dev/null", 120);
            sh("freebsd-version -kru > " + bk + "/version.txt 2>/dev/null", 30);
            StringBuilder el = new StringBuilder();
            JSONArray sv = pf.optJSONArray("services");
            for (int i = 0; sv != null && i < sv.length(); i++)
                el.append(sv.getJSONObject(i).getString("name")).append(' ')
                  .append(sv.getJSONObject(i).getBoolean("active") ? "active" : "stopped").append('\n');
            Files.writeString(Paths.get(bk + "/services.txt"), el.toString());
            job.write(I18n.tr("server.um.runSystemPreparation.3"));

            job.advance(3, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runSystemPreparation.4", java.util.Map.of("total", String.valueOf(TOT))));
            String beName = BE_PREFIX + target.replace(".", "") + "-" + ts;
            if (!pf.optBoolean("bootEnvironment", false)) {
                job.write(I18n.tr("server.um.runSystemPreparation.5"));
                job.write(I18n.tr("server.um.runSystemPreparation.6"));
            } else if (ok("bectl create " + beName, 300)) {
                boolean c1 = ok("bectl list -H 2>/dev/null | grep -q '^" + beName + "'", 30);
                job.write("    " + (c1 ? I18n.tr("server.um.x.beCreatedOk", java.util.Map.of("be", String.valueOf(beName))) : I18n.tr("server.um.x.beCreatedMissing", java.util.Map.of("be", String.valueOf(beName)))));
                if (!c1) throw new IllegalStateException("the boot environment does not appear to have been created: I stop");
                job.write(I18n.tr("server.um.runSystemPreparation.8", java.util.Map.of("beName", String.valueOf(beName))));
                job.write("");
                for (String l : sh("bectl list 2>/dev/null", 60).split("\n")) job.write("      " + l);
            } else throw new IllegalStateException("bectl create failed: without a way back I do not go on");

            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runSystemPreparation.9", java.util.Map.of("total", String.valueOf(TOT))));
            job.write(I18n.tr("server.um.runSystemPreparation.10"));
            String fetch = sh("freebsd-update --not-running-from-cron fetch 2>&1", 1800);
            for (String l : fetch.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
            boolean none = fetch.toLowerCase().contains("no updates needed")
                    || fetch.toLowerCase().contains("has no updates available");
            if (none) {
                job.write(I18n.tr("server.um.runSystemPreparation.11"));
            } else {
                StringBuilder cat = new StringBuilder();
                runLogged(job, "freebsd-update install 2>&1", 1800, cat);
                // The criterion is the Handbook's: INSTALLED kernel versus RUNNING
                // kernel. Looking for the word "kernel" in the output was a guess, and
                // on 2026-08-31 it missed a case in which the restart was really needed: the
                // panel printed "p13 / p0 / p13" and said nothing. Having the data
                // and not drawing the conclusion is like not having it.
                JSONObject afterJ = operatingSystem();
                job.write("    " + I18n.tr("server.um.x.kernelInstalled", java.util.Map.of("k", String.valueOf(afterJ.optString("installedKernel")))));
                job.write("    " + I18n.tr("server.um.x.kernelRunning", java.util.Map.of("k", String.valueOf(afterJ.optString("uname")))));
                job.write("    userland:             " + afterJ.optString("userland"));
                if (afterJ.optBoolean("restartNeeded")) {
                    job.write("");
                    job.write(I18n.tr("server.um.runSystemPreparation.12"));
                    job.write(I18n.tr("server.um.runSystemPreparation.13"));
                    job.write(I18n.tr("server.um.runSystemPreparation.14"));
                    job.write(I18n.tr("server.um.runSystemPreparation.15"));
                    job.write(I18n.tr("server.um.runSystemPreparation.16"));
                } else {
                    job.write(I18n.tr("server.um.runSystemPreparation.17"));
                }
            }

            // The preparation done is remembered: the page guides the next step (the command over SSH) even if
            // it is reopened tomorrow, and a jump prepared but not started can be canceled (cancelVersionJump).
            writeJumpState(new JSONObject().put("phase", "prepared").put("target", target)
                    .put("preparedUtc", java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString())
                    .put("bootEnvironment", beName).put("steps", new JSONArray()));
            job.status = "completed";
            job.write("");
            job.write("=== " + I18n.tr("server.um.x.prepDone") + " ===");
            job.write(I18n.tr("server.um.runSystemPreparation.18", java.util.Map.of("backup", String.valueOf(bk), "beName", String.valueOf(beName))));
            job.write(I18n.tr("server.um.runSystemPreparation.19"));
            job.write(I18n.tr("server.um.runSystemPreparation.20"));
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.finish();
        }
    }

    /**
     * The instructions for the part a person must do over SSH, on the real values.
     *
     * It is not a deferral: it is the recognition that that part requires decisions. freebsd-update
     * can open an editor to merge files in /etc - on this server they are master.passwd,
     * rc.conf, the Postfix files - and a merge decided by an automatism is the way to break
     * something without anyone noticing. The sequence is the Handbook's, chapter
     * "Updating and Upgrading FreeBSD".
     */
    public static JSONObject systemUpgradeInstructions(String target) {
        try {
            if (target == null || !target.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.systemUpgradeInstructions.1"));
            JSONObject pf = systemUpgradePreflight(target);
            String be = lastPanelBootEnvironment(sh("bectl list -H 2>/dev/null", 30));
            String startup = startCommand(false);
            String dir = System.getProperty("user.dir", "/home/panel");
            boolean minor = pf.optBoolean("minorJump", true);

            // The instructions must know whether the panel comes back up on its own, otherwise they say
            // the opposite of the tab next to them. Three states, not two: the script exists, it is enabled,
            // and it has been tested at least once (the pidfile proves it).
            boolean rcC = pf.optBoolean("rcPanel", false);
            boolean rcA = pf.optBoolean("rcEnabled", false);
            boolean rcP = pf.optBoolean("rcTested", false);
            boolean returnsOnly = rcC && rcA;

            JSONArray steps = new JSONArray();
            steps.put(new JSONObject().put("n", 1)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.3"))
                .put("cmd", "freebsd-update -r " + target + "-RELEASE upgrade")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.4")));
            steps.put(new JSONObject().put("n", 2)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.5"))
                .put("cmd", "freebsd-update install")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.6")));
            steps.put(new JSONObject().put("n", 3)
                .put("title", I18n.tr("server.um.x.restart"))
                .put("cmd", "shutdown -r now")
                .put("note", returnsOnly
                    ? (rcP
                       ? I18n.tr("server.um.x.rcBackTested")
                       : I18n.tr("server.um.x.rcBackUntested", java.util.Map.of("dir", String.valueOf(dir), "startup", String.valueOf(startup))))
                    : I18n.tr("server.um.systemUpgradeInstructions.7")));
            steps.put(new JSONObject().put("n", 4)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.8"))
                .put("cmd", "freebsd-update install")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.9")));
            if (minor) {
                steps.put(new JSONObject().put("n", 5)
                    .put("title", I18n.tr("server.um.systemUpgradeInstructions.10"))
                    .put("cmd", I18n.tr("server.um.systemUpgradeInstructions.11"))
                    .put("note", I18n.tr("server.um.x.abiStays", java.util.Map.of("abi", String.valueOf(pf.optString("abiName"))))));
            } else {
                steps.put(new JSONObject().put("n", 5)
                    .put("title", I18n.tr("server.um.x.reinstallAll"))
                    .put("cmd", "pkg-static upgrade -f")
                    .put("note", I18n.tr("server.um.systemUpgradeInstructions.12")));
            }
            steps.put(new JSONObject().put("n", 6)
                .put("title", I18n.tr("server.um.x.lastFuCall"))
                .put("cmd", "freebsd-update install")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.13")));
            steps.put(new JSONObject().put("n", 7)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.14"))
                .put("cmd", "shutdown -r now")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.15", java.util.Map.of("target", String.valueOf(target)))));
            steps.put(new JSONObject().put("n", 8)
                .put("title", returnsOnly ? I18n.tr("server.um.x.checkTitle") : I18n.tr("server.um.systemUpgradeInstructions.16"))
                .put("cmd", returnsOnly ? I18n.tr("server.um.systemUpgradeInstructions.17") : "cd " + dir + " && " + startup)
                .put("note", returnsOnly
                    ? I18n.tr("server.um.systemUpgradeInstructions.18", java.util.Map.of("dir", String.valueOf(dir), "startup", String.valueOf(startup)))
                    : I18n.tr("server.um.systemUpgradeInstructions.19")));

            return new JSONObject().put("success", true).put("steps", steps)
                .put("target", target)
                .put("rcActive", returnsOnly).put("rcTested", rcP)
                .put("returnInfo", be.isEmpty()
                    ? I18n.tr("server.um.systemUpgradeInstructions.20")
                    : I18n.tr("server.um.systemUpgradeInstructions.21", java.util.Map.of("be", String.valueOf(be))))
                .put("source", I18n.tr("server.um.systemUpgradeInstructions.22"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("systemUpgradeInstructions", e));
        }
    }

    /**
     * Verification after the release jump, comparing with what had been noted down BEFORE.
     *
     * "The system switched on" is not a verification: a service may not have restarted and
     * nobody notice it until someone tries to send a mail. Here the comparison is with
     * the inventory taken during the preparation - version, packages, services - because a
     * comparison needs two terms, and the first must be taken when things were working.
     */
    // ===================== guided continuation of the release jump =====================

    /** Where the panel remembers how far along the jump it is, to find it again after a restart. */
    private static final String VERSION_JUMP_STATE = "/var/db/daemoxcp-mail/system/version-jump.json";

    /**
     * What freebsd-update says to do, read by whoever runs it instead of by the user.
     *
     * freebsd-update has no exit code that distinguishes "finished" from "reboot and call me again":
     * it writes it in English, at the end of the output, and until now that line was read by the owner. The
     * three sentences below are the ones it really prints, seen on the server on 2026-08-31:
     *   - "Kernel updates have been installed.  Please reboot and run ... again"
     *   - "No updates are available to install."
     *   - "Installing updates... done."
     * When in doubt "again" is returned, that is it is run again: rerunning when it is not needed costs
     * a command and does no harm, stopping too early leaves the system halfway.
     */
    static String whatFreebsdUpdateAsks(String output) {
        String u = output == null ? "" : output.toLowerCase();
        if (u.contains("please reboot")) return "restart";
        // This is a DIFFERENT request from the "run me again", and it is in the same message:
        // "Completing this upgrade requires removing old shared object files. Please rebuild
        // all installed 3rd party software ... and then run 'freebsd-update install' again."
        // On 2026-08-31 the panel saw only the second half and carried on silently,
        // while the first half asked for the packages to be rebuilt. Two instructions in one
        // sentence: reading only one is worse than reading neither.
        if (u.contains("rebuild all installed 3rd party software")
                || u.contains("removing old shared object files")) return "rebuild";
        if (u.contains("no updates are available to install")
                || u.contains("no updates needed")) return "finished";
        if (u.contains("run '/usr/sbin/freebsd-update install'")
                || u.contains("run 'freebsd-update")) return "again";
        return "again";
    }

    private static JSONObject readJumpState() {
        try {
            if (!ok("test -f " + VERSION_JUMP_STATE, 10)) return new JSONObject();
            return upgradeOldJumpState(new JSONObject(Files.readString(Paths.get(VERSION_JUMP_STATE))));
        } catch (Exception e) { return new JSONObject(); }
    }

    // The keys and values that the jump state had before 2026-10-24 and 2026-10-29 are in the
    // data file (LegacyNames: jumpKeys, jumpStepKeys, jumpAsks, jumpPhases), not here.

    /** The prefix of the boot environments that the panel creates before a release jump. */
    static final String BE_PREFIX = "before-";

    /**
     * A boot environment created by the panel: with the current prefix or with that of the earlier
     * versions (data file), which is still there on servers already running.
     */
    static boolean panelBootEnvironment(String name) {
        if (name.startsWith(BE_PREFIX)) return true;
        for (String old : LegacyNames.oldNamesOf("bootEnvironmentPrefix", BE_PREFIX))
            if (!old.isEmpty() && name.startsWith(old)) return true;
        return false;
    }

    /**
     * The most recent way back, from "bectl list -H": the last one created with the current prefix
     * and, only if there is none, the last one with the earlier prefix. A current name is always more
     * recent than an earlier one, even if it comes first in the alphabetical list.
     */
    static String lastPanelBootEnvironment(String bectlList) {
        String now = "", before = "";
        for (String line : bectlList == null ? new String[0] : bectlList.split("\n")) {
            String name = line.split("\t")[0].trim();
            if (name.startsWith(BE_PREFIX)) now = name;
            else if (panelBootEnvironment(name)) before = name;
        }
        return now.isEmpty() ? before : now;
    }

    /**
     * "cat" of a file of the inventory taken before a jump: the current name and, if it is missing,
     * those of the copies made by the earlier versions (data file).
     */
    static String inventoryCat(String dir, String name) {
        StringBuilder c = new StringBuilder("cat " + dir + "/" + name + " 2>/dev/null");
        for (String old : LegacyNames.oldNamesOf("inventoryFiles", name))
            c.append(" || cat ").append(dir).append('/').append(old).append(" 2>/dev/null");
        return c.toString();
    }

    /**
     * The state of a jump written by the earlier panel, read with the current names.
     *
     * A version jump spans a restart, and the panel may be updated right
     * in the middle: the file was written by the old code, with the Italian keys, and the new
     * code reads it back. Without this translation the phase would look empty, and the jump would
     * declare itself never started. A new key already present wins: it is not overwritten.
     */
    static JSONObject upgradeOldJumpState(JSONObject st) {
        for (String[] k : LegacyNames.pairs("jumpKeys"))
            if (st.has(k[0]) && !st.has(k[1])) st.put(k[1], st.remove(k[0]));
        if (st.has("phase")) st.put("phase", LegacyNames.current("jumpPhases", st.optString("phase")));
        JSONArray steps = st.optJSONArray("steps");
        for (int i = 0; steps != null && i < steps.length(); i++) {
            JSONObject s = steps.optJSONObject(i);
            if (s == null) continue;
            for (String[] k : LegacyNames.pairs("jumpStepKeys"))
                if (s.has(k[0]) && !s.has(k[1])) s.put(k[1], s.remove(k[0]));
            if (s.has("asks")) s.put("asks", LegacyNames.current("jumpAsks", s.optString("asks")));
        }
        return st;
    }

    private static void writeJumpState(JSONObject st) {
        try {
            ok("mkdir -p /var/db/daemoxcp-mail/system", 20);
            Files.writeString(Paths.get(VERSION_JUMP_STATE), st.toString(2));
        } catch (Exception ignored) { }
    }

    /** The state of the jump, for the tab: where we are and what is needed now. */
    public static JSONObject versionJumpStatus() {
        JSONObject st = readJumpState();
        JSONObject os = operatingSystem();
        JSONObject r = new JSONObject()
                .put("success", true)
                .put("inProgress", st.has("phase"))
                .put("phase", st.optString("phase", ""))
                .put("target", st.optString("target", ""))
                .put("steps", st.optJSONArray("steps") == null ? new JSONArray() : st.getJSONArray("steps"))
                .put("installedKernel", os.optString("installedKernel"))
                .put("runningKernel", os.optString("uname"))
                .put("userland", os.optString("userland"))
                .put("restartNeeded", os.optBoolean("restartNeeded"))
                .put("bootEnvironment", st.optString("bootEnvironment", ""))
                // SSH step done: freebsd-update has downloaded the chosen release and awaits installation.
                .put("upgradeFetched", !st.optString("target", "").isEmpty() && os.optBoolean("readyExist")
                        && os.optString("readyTarget", "").startsWith(st.optString("target") + "-"));
        // If we were waiting for a restart and the kernel now matches, the restart has happened.
        if ("awaiting-restart".equals(st.optString("phase")) && !os.optBoolean("restartNeeded"))
            r.put("restartHappened", true);
        return r;
    }

    /**
     * Cancels a release jump that was prepared and not started: only its state is removed. Not after
     * freebsd-update has installed something: from there one goes forward, or back with the boot environment.
     */
    public static JSONObject cancelVersionJump() {
        JSONObject st = readJumpState();
        if (!"prepared".equals(st.optString("phase")))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.jumpCancel.started"));
        try {
            Files.deleteIfExists(Paths.get(VERSION_JUMP_STATE));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("cancelVersionJump", e));
        }
        return new JSONObject().put("success", true)
                .put("note", I18n.tr("server.um.jumpCancel.done", java.util.Map.of("be", st.optString("bootEnvironment", "?"))));
    }

    public static JSONObject startResumeVersionJump(String target) {
        String id = "jump-" + System.currentTimeMillis();
        Job j = new Job(id, "jump");
        JOBS.put(id, j);
        final String b = target == null || target.isEmpty()
                ? readJumpState().optString("target", "") : target;
        Thread t = localizedThread(j, () -> runJumpContinuation(j, b), "jump-release");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Runs "freebsd-update install" as many times as needed, reading what it asks to do.
     *
     * It is not a blind loop: after each run it looks at what freebsd-update wrote and
     * acts accordingly - if it asks for a restart, it stops, notes it on disk and schedules
     * the restart; if it says there is nothing else, it finishes; otherwise it runs again. The cap of
     * six rounds is a safety net, not a forecast: if it reaches it, it means something is happening
     * that I had not foreseen, and at that point it is right to stop and show it.
     */
    private static void runJumpContinuation(Job job, String target) {
        job.status = "running";
        try {
            boolean rebuildRequested = false;
            JSONObject st = readJumpState();
            JSONArray steps = st.optJSONArray("steps") == null ? new JSONArray() : st.getJSONArray("steps");
            if (!target.isEmpty()) st.put("target", target);

            job.write(I18n.tr("server.um.runJumpContinuation.1"));
            JSONObject before = operatingSystem();
            job.write(I18n.tr("server.um.x.kernelLine", java.util.Map.of("k", String.valueOf(before.optString("installedKernel")), "u", String.valueOf(before.optString("uname")), "l", String.valueOf(before.optString("userland")))));
            job.write("");

            if (before.optBoolean("restartNeeded")) {
                job.write(I18n.tr("server.um.runJumpContinuation.2"));
                job.write(I18n.tr("server.um.runJumpContinuation.3"));
                st.put("phase", "awaiting-restart").put("steps", steps);
                writeJumpState(st);
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runJumpContinuation.4");
                return;
            }

            for (int round = 1; round <= 6; round++) {
                job.advance(round, 6);
                job.write("--- freebsd-update install " + I18n.tr("server.um.x.round", java.util.Map.of("n", String.valueOf(round))) + " ---");
                StringBuilder cat = new StringBuilder();
                int code = runLogged(job, "freebsd-update install 2>&1", 3600, cat);
                String asks = whatFreebsdUpdateAsks(cat.toString());
                JSONObject after = operatingSystem();
                steps.put(new JSONObject().put("round", round).put("code", code)
                        .put("asks", asks).put("kernel", after.optString("installedKernel"))
                        .put("userland", after.optString("userland")));
                job.write("");
                job.write("    " + I18n.tr("server.um.x.fuAsks") + " " + (
                        "restart".equals(asks) ? I18n.tr("server.um.x.fuAsksRestart")
                      : "finished".equals(asks)  ? I18n.tr("server.um.x.fuAsksNothing")
                      : "rebuild".equals(asks)
                        ? I18n.tr("server.um.runJumpContinuation.5")
                      : I18n.tr("server.um.runJumpContinuation.6")));
                if ("rebuild".equals(asks)) {
                    rebuildRequested = true;
                    job.write("");
                    job.write(I18n.tr("server.um.runJumpContinuation.7"));
                    job.write(I18n.tr("server.um.runJumpContinuation.8"));
                    job.write(I18n.tr("server.um.runJumpContinuation.9"));
                    job.write(I18n.tr("server.um.runJumpContinuation.10"));
                }
                job.write("    " + I18n.tr("server.um.x.kernelNow", java.util.Map.of("k", String.valueOf(after.optString("installedKernel")), "u", String.valueOf(after.optString("uname")), "l", String.valueOf(after.optString("userland")))));

                if (code != 0 && !"finished".equals(asks)) {
                    st.put("phase", "error").put("steps", steps);
                    writeJumpState(st);
                    job.status = "error";
                    job.errorMessage = I18n.tr("server.um.runJumpContinuation.11", java.util.Map.of("code", String.valueOf(code)));
                    job.write(I18n.tr("server.um.runJumpContinuation.12", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                    return;
                }
                if ("restart".equals(asks)) {
                    st.put("phase", "awaiting-restart").put("steps", steps);
                    writeJumpState(st);
                    job.write("");
                    job.write(I18n.tr("server.um.runJumpContinuation.13"));
                    job.write(I18n.tr("server.um.runJumpContinuation.14"));
                    job.write(I18n.tr("server.um.runJumpContinuation.15"));
                    job.status = "completed";
                    return;
                }
                if ("finished".equals(asks)) {
                    st.put("phase", "finished").put("steps", steps);
                    writeJumpState(st);
                    job.write("");
                    job.write(I18n.tr("server.um.runJumpContinuation.16"));
                    if (after.optBoolean("restartNeeded")) {
                        job.write(I18n.tr("server.um.runJumpContinuation.17"));
                        job.write(I18n.tr("server.um.runJumpContinuation.18"));
                        st.put("phase", "awaiting-final-restart");
                        writeJumpState(st);
                    } else {
                        job.write(I18n.tr("server.um.x.youAreOn", java.util.Map.of("v", String.valueOf(after.optString("userland")))));
                    }
                    // The question "do the packages need rebuilding?" is not answered with an opinion
                    // on the ABI: pkg is asked which libraries each package requires and we look at
                    // whether they exist. It is the only direct proof.
                    if (rebuildRequested) {
                        job.write("");
                        job.write("--- " + I18n.tr("server.um.x.fuRebuildCheck") + " ---");
                        JSONObject lib = packagesWithMissingLibraries();
                        JSONArray broken = lib.optJSONArray("packages");
                        int howMany = broken == null ? 0 : broken.length();
                        if (howMany == 0) {
                            job.write(I18n.tr("server.um.runJumpContinuation.19"));
                            job.write(I18n.tr("server.um.runJumpContinuation.20"));
                            job.write(I18n.tr("server.um.runJumpContinuation.21"));
                        } else {
                            job.write(I18n.tr("server.um.runJumpContinuation.22", java.util.Map.of("howMany", String.valueOf(howMany))));
                            for (int i = 0; i < Math.min(howMany, 20); i++)
                                job.write("      " + broken.getJSONObject(i).optString("name")
                                        + "  ->  " + broken.getJSONObject(i).optString("missing"));
                            job.write(I18n.tr("server.um.runJumpContinuation.23"));
                            job.write(I18n.tr("server.um.runJumpContinuation.24"));
                        }
                        st.put("rebuild", howMany == 0 ? I18n.tr("server.um.runJumpContinuation.25") : I18n.tr("server.um.x.neededN", java.util.Map.of("n", String.valueOf(howMany))));
                    }
                    job.write(I18n.tr("server.um.runJumpContinuation.26"));
                    job.status = "completed";
                    return;
                }
            }
            st.put("phase", "too-many-rounds").put("steps", steps);
            writeJumpState(st);
            job.status = "error";
            job.errorMessage = I18n.tr("server.um.runJumpContinuation.27");
            job.write(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.finish();
        }
    }

    /**
     * The boot environments, explained instead of listed.
     *
     * "bectl list" is a table for whoever already knows what they are looking at: an Active column with
     * abbreviations (N, R, NR), names generated by different programs, and no indication of what
     * can be touched. Dumping it into a line with dashes in between, as the panel used to do,
     * is not informing: it is shifting the work of understanding to the other side.
     *
     * The abbreviations, from the bectl(8) manual: N = the one booted now, R = the one that will boot
     * at the next restart, NR = both. A dash means it just sits there.
     */
    public static JSONObject bootEnvironments() {
        JSONObject r = new JSONObject();
        try {
            if (!ok("bectl check", 20))
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.bootEnvironments.1"));
            JSONArray outside = new JSONArray();
            for (String line : sh("bectl list -H 2>/dev/null", 60).split("\n")) {
                String[] c = line.split("\t");
                if (c.length < 5) continue;
                String name = c[0].trim(), active = c[1].trim(), space = c[3].trim(), created = c[4].trim();
                boolean inUse = active.contains("N");
                boolean atRestart = active.contains("R");

                // Who created it can be told from the name: the panel uses BE_PREFIX (or the prefix
                // of the earlier versions), and freebsd-update uses <version>_<date>. Knowing that
                // changes what keeping it means.
                String origin, explain;
                if (PackageWayBack.REINSTALL_OWN.matcher(name).matches()) {
                    // The way back from a full reinstallation from the menu: the previous server,
                    // configurations, mailboxes and databases included.
                    origin = I18n.tr("server.um.bootEnvironments.reinstallOrigin");
                    explain = I18n.tr("server.um.bootEnvironments.reinstallExplain");
                    // Its "used" is 0 right after creation: the space it holds is in the snapshot it was
                    // born from (finding 170). This is said, or it looks free.
                    long pinned = PackageWayBack.pinnedBytes(name);
                    if (pinned >= 0) explain += " " + I18n.tr("server.um.bootEnvironments.keepsSpace",
                            java.util.Map.of("space", PackageWayBack.mb(pinned)));
                } else if (PackageWayBack.OWN.matcher(name).matches()) {
                    // The way back of a package job (PackageWayBack): without this
                    // branch it fell into "origin not recognized, look at it before touching it".
                    origin = I18n.tr("server.um.bootEnvironments.packagesOrigin");
                    explain = I18n.tr("server.um.bootEnvironments.packagesExplain");
                    long pinned = PackageWayBack.pinnedBytes(name);
                    if (pinned >= 0) explain += " " + I18n.tr("server.um.bootEnvironments.keepsSpace",
                            java.util.Map.of("space", PackageWayBack.mb(pinned)));
                } else if (panelBootEnvironment(name)) {
                    origin = I18n.tr("server.um.bootEnvironments.2");
                    explain = I18n.tr("server.um.bootEnvironments.3");
                } else if (name.matches("^[0-9]+\\.[0-9].*_[0-9]{4}-[0-9]{2}-[0-9]{2}.*")) {
                    origin = I18n.tr("server.um.bootEnvironments.4");
                    explain = I18n.tr("server.um.bootEnvironments.5");
                } else if ("default".equals(name)) {
                    origin = I18n.tr("server.um.bootEnvironments.6");
                    explain = I18n.tr("server.um.bootEnvironments.7");
                } else {
                    origin = I18n.tr("server.um.bootEnvironments.8");
                    explain = I18n.tr("server.um.bootEnvironments.9");
                }

                outside.put(new JSONObject()
                        .put("name", name).put("space", space).put("created", created)
                        .put("inUse", inUse).put("atRestart", atRestart).put("shortName", active)
                        .put("origin", origin).put("explanation", explain)
                        .put("state", inUse && atRestart ? I18n.tr("server.um.bootEnvironments.10")
                                    : inUse ? I18n.tr("server.um.bootEnvironments.11")
                                    : atRestart ? I18n.tr("server.um.bootEnvironments.12")
                                    : I18n.tr("server.um.bootEnvironments.13"))
                        .put("deletable", !inUse && !atRestart)
                        .put("why", inUse || atRestart
                                ? I18n.tr("server.um.bootEnvironments.14")
                                : I18n.tr("server.um.bootEnvironments.15")));
            }
            return r.put("success", true).put("environments", outside)
                    .put("whatTheyAre", I18n.tr("server.um.bootEnvironments.16"))
                    .put("howToGoBack", I18n.tr("server.um.bootEnvironments.17"))
                    .put("whenToDelete", I18n.tr("server.um.bootEnvironments.18"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("bootEnvironments", e));
        }
    }

    /**
     * Deletes a boot environment, but only one that can be deleted.
     *
     * Three protections, and none is theoretical: the one in use is not touched (you would switch off
     * the system under your own feet), the one that would boot at the next restart is not touched (the
     * server would not get back up), and the name must be one of those that really exist - not a string
     * that came from outside. The check does not trust what the button asks for: it rereads the
     * list and decides on that.
     */
    public static JSONObject deleteBootEnvironment(String name) {
        try {
            if (name == null || !name.matches("[A-Za-z0-9._:-]{1,128}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deleteBootEnvironment.1"));
            JSONObject el = bootEnvironments();
            if (!el.optBoolean("success")) return el;
            JSONArray environment = el.getJSONArray("environments");
            JSONObject found = null;
            for (int i = 0; i < environment.length(); i++)
                if (name.equals(environment.getJSONObject(i).getString("name"))) found = environment.getJSONObject(i);
            if (found == null)
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.deleteBootEnvironment.2", java.util.Map.of("name", String.valueOf(name))));
            if (!found.getBoolean("deletable"))
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.x.beNoDelete", java.util.Map.of("name", String.valueOf(name), "state", String.valueOf(found.getString("state")), "why", String.valueOf(found.getString("why")))));

            String output = sh("bectl destroy -F " + name + " 2>&1", 300).trim();
            // The proof is that it no longer appears in the list, not that the command exited with zero.
            boolean via = !ok("bectl list -H 2>/dev/null | cut -f1 | grep -qx '" + name + "'", 30);
            return new JSONObject().put("success", via).put("name", name)
                    .put("space", found.getString("space"))
                    .put("output", output)
                    .put("note", via
                        ? I18n.tr("server.um.x.beDeleted", java.util.Map.of("name", String.valueOf(name), "space", String.valueOf(found.getString("space"))))
                        : I18n.tr("server.um.deleteBootEnvironment.3"))
                    .put("error", via ? "" : I18n.tr("server.um.deleteBootEnvironment.4", java.util.Map.of("output", String.valueOf(output))));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("deleteBootEnvironment", e));
        }
    }

    public static JSONObject verifyAfterUpdate() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        try {
            String dir = sh("ls -1dt /var/db/daemoxcp-mail/system/*/ 2>/dev/null | head -1", 30).trim();
            if (dir.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.verifyAfterUpdate.1"));
            r.put("inventory", dir);

            JSONObject os = operatingSystem();
            String before = sh("(" + inventoryCat(dir, "version.txt") + ") | tr '\n' ' '", 30).trim();
            addCheck(checks, "ver", I18n.tr("server.um.x.version"), "ok",
                    I18n.tr("server.um.x.versionBeforeNow", java.util.Map.of("before", String.valueOf(before), "k", String.valueOf(os.optString("installedKernel")), "l", String.valueOf(os.optString("userland")))));
            if (os.optBoolean("restartNeeded")) {
                addCheck(checks, "restart", I18n.tr("server.um.x.restartTitle"), "wait",
                        I18n.tr("server.um.x.restartMissing", java.util.Map.of("k", String.valueOf(os.optString("installedKernel")), "u", String.valueOf(os.optString("uname")))));
            } else {
                addCheck(checks, "restart", I18n.tr("server.um.x.restartTitle"), "ok",
                        I18n.tr("server.um.verifyAfterUpdate.2"));
            }

            // Services: those that were active before must be active now.
            java.util.List<String> off = new ArrayList<>(), absent = new ArrayList<>();
            int checked = 0;
            // A copy made before 2026-10-24 has the file and the state with the earlier names.
            for (String line : sh(inventoryCat(dir, "services.txt"), 30).split("\n")) {
                String[] c = line.trim().split("\\s+");
                if (c.length != 2 || !"active".equals(LegacyNames.current("inventoryServiceStates", c[1]))) continue;
                checked++;
                if (!ok("test -f /usr/local/etc/rc.d/" + c[0] + " -o -f /etc/rc.d/" + c[0], 10)) { absent.add(c[0]); continue; }
                if (!ok("service " + c[0] + " status", 20)) off.add(c[0]);
            }
            addCheck(checks, "services", I18n.tr("server.um.verifyAfterUpdate.3"),
                    (off.isEmpty() && absent.isEmpty()) ? "ok" : "block",
                    (off.isEmpty() && absent.isEmpty())
                    ? I18n.tr("server.um.verifyAfterUpdate.4", java.util.Map.of("checked", String.valueOf(checked)))
                    : I18n.tr("server.um.x.svcMissing", java.util.Map.of("n", String.valueOf(checked))) + " "
                      + (off.isEmpty() ? "" : I18n.tr("server.um.x.svcOff", java.util.Map.of("list", String.valueOf(String.join(", ", off)))) + "  ")
                      + (absent.isEmpty() ? "" : I18n.tr("server.um.x.svcGone", java.util.Map.of("list", String.valueOf(String.join(", ", absent))))));

            // Packages: none must have disappeared.
            java.util.Map<String, String> now = new java.util.HashMap<>();
            for (String line : sh("pkg query '%n %v' 2>/dev/null", 120).split("\n")) {
                String[] c = line.trim().split("\\s+");
                if (c.length == 2) now.put(c[0], c[1]);
            }
            java.util.List<String> missing = new ArrayList<>(), different = new ArrayList<>();
            int totalBefore = 0;
            // A copy made before 2026-10-29 has the file with the earlier name.
            for (String line : sh(inventoryCat(dir, "packages.txt"), 60).split("\n")) {
                String[] c = line.trim().split("\\s+");
                if (c.length != 2) continue;
                totalBefore++;
                String v = now.get(c[0]);
                if (v == null) missing.add(c[0]);
                else if (!v.equals(c[1])) different.add(c[0] + " " + c[1] + " -> " + v);
            }
            addCheck(checks, "pkg", I18n.tr("server.um.x.packages"), missing.isEmpty() ? "ok" : "block",
                    missing.isEmpty()
                    ? I18n.tr("server.um.x.pkgsNoneGone", java.util.Map.of("before", String.valueOf(totalBefore), "now", String.valueOf(now.size())))
                      + (different.isEmpty() ? "" : ". " + I18n.tr("server.um.x.pkgsChanged", java.util.Map.of("list", String.valueOf(String.join(", ", different)))))
                    : I18n.tr("server.um.x.pkgsGone", java.util.Map.of("n", String.valueOf(missing.size()), "list", String.valueOf(String.join(", ", missing)))));

            // Locks: after an operation of this scale they must be confirmed again.
            JSONObject st = packagesStatus();
            int inst = st.optInt("installedCount"), lock = st.optInt("lockedCount");
            addCheck(checks, "lock", I18n.tr("server.um.packagePreflight.25"), inst == lock ? "ok" : "wait",
                    I18n.tr("server.um.x.lockOfInst", java.util.Map.of("lock", String.valueOf(lock), "inst", String.valueOf(inst)))
                    + (inst == lock ? "" : ": " + I18n.tr("server.um.x.someUnlocked")));

            // The boot environments: the old one must be kept until you are sure.
            JSONObject be = bootEnvironments();
            if (be.optBoolean("success")) {
                r.put("environments", be);
                JSONArray el = be.getJSONArray("environments");
                int free = 0;
                for (int i = 0; i < el.length(); i++) if (el.getJSONObject(i).getBoolean("deletable")) free++;
                addCheck(checks, "be", I18n.tr("server.um.verifyAfterUpdate.5"), "ok",
                        I18n.tr("server.um.verifyAfterUpdate.6", java.util.Map.of("length", String.valueOf(el.length()), "free", String.valueOf(free))));
            }

            boolean fault = false;
            for (int i = 0; i < checks.length(); i++)
                if ("block".equals(checks.getJSONObject(i).getString("level"))) fault = true;
            return r.put("success", true).put("checks", checks).put("allGood", !fault);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("verifyAfterUpdate", e));
        }
    }

    public static JSONObject systemReport() {
        StringBuilder t = new StringBuilder();
        try {
            ok("pkg update -q", 180);
            t.append("=== ").append(I18n.tr("server.um.x.repTitle")).append(" ===\n");
            t.append("data: ").append(sh("date '+%Y-%m-%d %H:%M:%S %Z'", 15)).append('\n');
            t.append("host: ").append(sh("hostname", 15)).append('\n');
            t.append("FreeBSD: ").append(sh("freebsd-version -kru 2>/dev/null | tr '\n' ' '", 20)).append('\n');
            t.append("ABI pkg: ").append(sh("pkg config abi 2>/dev/null", 20)).append('\n');

            JSONObject branch = branchRepositories();
            JSONObject os = operatingSystem();
            t.append("\n--- ").append(I18n.tr("server.um.x.repOs")).append(" ---\n");
            t.append(I18n.tr("server.um.x.repKernel", java.util.Map.of("k", String.valueOf(os.optString("installedKernel")), "u", String.valueOf(os.optString("uname"))))).append('\n');
            t.append(I18n.tr("server.um.x.repUserland", java.util.Map.of("u", String.valueOf(os.optString("userland")), "a", String.valueOf(os.optString("arch"))))).append('\n');
            if (os.optBoolean("restartNeeded"))
                t.append(I18n.tr("server.um.x.repRestartNeeded")).append('\n');
            if (!os.optString("endOfSupport").isEmpty())
                t.append(I18n.tr("server.um.x.repEol", java.util.Map.of("series", String.valueOf(os.optString("series")), "end", String.valueOf(os.optString("endOfSupport")), "note", String.valueOf(os.optString("supportNotes"))))).append('\n');
            else
                t.append(I18n.tr("server.um.x.repEolUnknown")).append('\n');
            t.append(I18n.tr("server.um.x.repSource", java.util.Map.of("f", String.valueOf(os.optString("supportSource"))))).append('\n');
            if (os.has("alreadyReady"))
                t.append(I18n.tr("server.um.x.repFetched", java.util.Map.of("v", String.valueOf(os.optString("alreadyReady"))))).append('\n');
            if (os.has("updatesNote"))
                t.append(os.optString("updatesNote")).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repBranch")).append(" ---\n");
            t.append(branch.optString("branch")).append("   ").append(branch.optString("url")).append('\n');
            t.append(branch.optString("explanation")).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repDefaults")).append(" ---\n");
            JSONArray lines = defaultsConsistency().optJSONArray("lines");
            for (int i = 0; lines != null && i < lines.length(); i++) {
                JSONObject x = lines.getJSONObject(i);
                t.append(String.format(I18n.tr("server.um.systemReport.1"),
                        x.optString("component"), x.optString("defaultValue"),
                        x.optString("installed"), x.optString("outcome")));
                if (x.has("outsideDefault"))
                    t.append("           ").append(I18n.tr("server.um.x.repOutside", java.util.Map.of("v", String.valueOf(x.getString("outsideDefault"))))).append('\n');
            }

            // Only two queries, then they are joined: it is the only way not to take minutes.
            java.util.Map<String, String> inst = new java.util.LinkedHashMap<>(), repo = new java.util.HashMap<>();
            for (String r2 : sh("pkg query '%n %v' 2>/dev/null", 120).split("\n")) {
                String[] c = r2.trim().split("\\s+");
                if (c.length == 2) inst.put(c[0], c[1]);
            }
            for (String r2 : sh("pkg rquery -U '%n %v' 2>/dev/null", 180).split("\n")) {
                String[] c = r2.trim().split("\\s+");
                if (c.length == 2) repo.put(c[0], c[1]);
            }
            String lock = sh("pkg lock -l 2>/dev/null");

            t.append("\n--- ").append(I18n.tr("server.um.x.repStack")).append(" ---\n");
            t.append(String.format("%-28s %-22s %-22s %-9s %s%n",
                    I18n.tr("server.um.x.colPackage"), I18n.tr("server.um.x.colInstalled"), I18n.tr("server.um.systemReport.2"), I18n.tr("server.um.x.colProtected"), I18n.tr("server.um.x.colRole")));
            int different = 0;
            for (java.util.Map.Entry<String, String> e : inst.entrySet()) {
                String role = roleOf(e.getKey());
                if (role == null) continue;
                String available = repo.getOrDefault(e.getKey(), I18n.tr("server.um.x.absentInRepo"));
                boolean diff = !available.equals(e.getValue()) && !I18n.tr("server.um.x.absentInRepo").equals(available);
                if (diff) different++;
                t.append(String.format("%-28s %-22s %-22s %-9s %s%s%n",
                        e.getKey(), e.getValue(), available,
                        locked(lock, e.getKey()) ? I18n.tr("server.um.x.yes") : "NO", role, diff ? I18n.tr("server.um.systemReport.3") : ""));
            }
            t.append(I18n.tr("server.um.x.repNewer", java.util.Map.of("n", String.valueOf(different)))).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repVulns")).append(" ---\n");
            String audit = sh("pkg audit -F 2>&1", 240);
            t.append(audit.isEmpty() ? I18n.tr("server.um.systemReport.4") : audit + "\n");
            t.append("\n").append(I18n.tr("server.um.x.repFixPerPkg")).append('\n');
            Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
            java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
            while (mv.find()) seen.add(mv.group(1));
            if (seen.isEmpty()) t.append("  ").append(I18n.tr("server.um.x.repNoPkg")).append('\n');
            for (String n : seen) {
                String cur = inst.getOrDefault(n, "?"), av = repo.getOrDefault(n, I18n.tr("server.um.x.absentInRepo"));
                t.append(String.format(I18n.tr("server.um.systemReport.5"), n, cur, av,
                        I18n.tr("server.um.x.absentInRepo").equals(av) ? I18n.tr("server.um.x.repoUnknownPkg")
                        : av.equals(cur) ? I18n.tr("server.um.x.noFixSameVersion")
                        : I18n.tr("server.um.systemReport.6", java.util.Map.of("av", String.valueOf(av)))));
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repMissingLibs")).append(" ---\n");
            JSONObject lib = packagesWithMissingLibraries();
            JSONArray broken = lib.optJSONArray("packages");
            if (broken == null || broken.length() == 0) {
                t.append(I18n.tr("server.um.x.repLibsOk")).append('\n');
            } else {
                t.append(I18n.tr("server.um.x.repLibsLost", java.util.Map.of("n", String.valueOf(broken.length())))).append('\n');
                for (int i = 0; i < broken.length(); i++)
                    t.append("  ").append(broken.getJSONObject(i).optString("name"))
                     .append("  ->  ").append(broken.getJSONObject(i).optString("missing")).append('\n');
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repBe")).append(" ---\n");
            JSONObject be2 = bootEnvironments();
            if (!be2.optBoolean("success")) t.append(I18n.tr("server.um.x.notAvailable")).append('\n');
            else {
                JSONArray aa = be2.getJSONArray("environments");
                for (int i = 0; i < aa.length(); i++) {
                    JSONObject x = aa.getJSONObject(i);
                    t.append(String.format("  %-40s %-12s %-8s %s%n", x.getString("name"),
                            x.getBoolean("inUse") ? I18n.tr("server.um.x.inUseCaps") : x.getBoolean("atRestart") ? I18n.tr("server.um.systemReport.7") : I18n.tr("server.um.systemReport.8"),
                            x.getString("space"), x.getString("origin")));
                }
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repServices")).append(" ---\n");
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                t.append(String.format("  %-18s %s%n", svc, ok("service " + svc + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runPythonTransition.14")));
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repSpace")).append(" ---\n");
            t.append(sh("df -h / /var /usr 2>/dev/null | sort -u", 30)).append('\n');
            t.append("\n=== ").append(I18n.tr("server.um.x.repEnd")).append(" ===\n");
            return new JSONObject().put("success", true).put("text", t.toString());
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", ErrorText.forPage("systemReport", e))
                    .put("partial", t.toString());
        }
    }

    /**
     * The branch for the defaults tab: PkgBranch reads it, like the "Package branch" tab.
     * Before, this took the first pkg.FreeBSD.org address, which could be the one for the
     * kernel modules, and a mixed branch could not be seen.
     */
    public static JSONObject branchRepositories() {
        JSONObject st = PkgBranch.state(PkgBranch.real());
        if (!st.optBoolean("success"))
            return new JSONObject().put("success", true).put("branch", I18n.tr("server.um.branchRepositories.1")).put("url", "")
                    .put("explanation", st.optString("error")).put("where", "");
        String url = "";
        JSONArray repo = st.getJSONArray("repository");
        for (int i = 0; i < repo.length(); i++) {
            JSONObject x = repo.getJSONObject(i);
            if (x.optBoolean("enabled") && "packages".equals(x.optString("type"))) { url = x.optString("url"); break; }
        }
        return new JSONObject().put("success", true).put("branch", st.getString("branch")).put("url", url)
                .put("explanation", st.getString("explanation"))
                .put("where", I18n.tr("server.um.branchRepositories.2"));
    }

    public static JSONObject branchStatus() { return PkgBranch.state(PkgBranch.real()); }

    public static JSONObject branchPreview(String target) {
        if (!PkgBranch.BRANCHES.contains(target)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.branchPreview.1"));
        return PkgBranch.preview(PkgBranch.real(), target);
    }

    /**
     * The branch change, on the package turn: rewriting where pkg gets the packages
     * from while another job is installing them would change the packages under its feet.
     */
    public static JSONObject startBranchChange(String target, String fingerprint) {
        if (!PkgBranch.BRANCHES.contains(target)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.branchPreview.1"));
        if (fingerprint == null || !fingerprint.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startBranchChange.1"));
        String id = "branch-" + System.currentTimeMillis();
        Job j = new Job(id, "pkg_branch");
        return startOnTurn(id, j, I18n.tr("server.um.startBranchChange.2", java.util.Map.of("destination", String.valueOf(target))), "pkg-branch", () -> {
            j.status = "running";
            try {
                JSONObject r = PkgBranch.change(PkgBranch.real(), j::write, target, fingerprint);
                if (r.optBoolean("success")) {
                    j.outcome = r.optString("messageText");
                    j.status = "completed";
                } else {
                    j.errorMessage = r.optString("error");
                    j.status = "error";
                }
            } catch (RuntimeException e) {
                j.errorMessage = I18n.tr("server.um.startBranchChange.3", java.util.Map.of("message", org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e)));
                j.status = "error";
            } finally {
                j.finish();
            }
        });
    }

    public static JSONObject defaultsConsistency() {
        JSONArray lines = new JSONArray();
        for (String[] d : DEFAULTS) {
            String installed = sh(d[2], 60).trim().replace("\n", " ");
            String outcome, outside = "";
            if (installed.isEmpty()) {
                outcome = "absent";
            } else if ("base".equals(d[1])) {
                // The default is the base system: the installed port is the anomaly.
                outcome = "port-beside-base";
            } else {
                // ALL the installed values are compared, one by one. Looking for whether the
                // default appears "somewhere" in the string was wrong: with
                // py311 and py312 together it found py312 and declared everything consistent, hiding
                // exactly the divergence the tab exists to show. The presence of the
                // default does not prove the absence of anything else.
                String expectedDigits = d[1].replaceAll("[^0-9]", "");
                java.util.List<String> nonconforming = new ArrayList<>();
                int conforming = 0;
                for (String tok : installed.split("\\s+")) {
                    if (tok.isBlank()) continue;
                    if (tok.replaceAll("[^0-9]", "").contains(expectedDigits)) conforming++;
                    else nonconforming.add(tok);
                }
                if (nonconforming.isEmpty() && conforming > 0) outcome = "consistent";
                else if (conforming == 0) outcome = "DIVERGES";
                else { outcome = "MIXED"; outside = String.join(", ", nonconforming); }
            }
            JSONObject line = new JSONObject().put("component", d[0]).put("defaultValue", d[1])
                    .put("installed", installed).put("outcome", outcome).put("why", I18n.tr(d[3]));
            if (!outside.isEmpty()) line.put("outsideDefault", outside);

            // "Port installed next to the base system" describes, it does not answer. The question
            // one asks when reading it is just one: can I remove it? It depends on who requires it,
            // and the panel can ask that instead of leaving it to guesswork.
            // Only for the inconsistent rows, and only for the values that really are package
            // names: for Python the column contains prefixes (py311), not packages, and
            // querying them would give an empty result that would look like "nobody requires it".
            if (!"consistent".equals(outcome) && !"absent".equals(outcome)) {
                JSONArray who = new JSONArray();
                for (String tok : installed.split("\\s+")) {
                    if (tok.isBlank() || !isValidName(tok)) continue;
                    if (!ok("pkg info -e " + tok, 15)) continue;   // it is a prefix, not a package
                    String dependents = sh("pkg query %rn " + tok + " 2>/dev/null", 30).trim();
                    who.put(new JSONObject().put("pkgName", tok)
                            .put("requiredBy", dependents.isEmpty() ? new JSONArray()
                                    : new JSONArray(java.util.List.of(dependents.split("\n")))));
                }
                if (who.length() > 0) line.put("dependents", who);
            }
            lines.put(line);
        }
        return new JSONObject().put("success", true).put("lines", lines)
                .put("branch", branchRepositories())
                .put("source", I18n.tr("server.um.defaultsConsistency.2"))
                .put("caveat", I18n.tr("server.um.defaultsConsistency.3"));
    }

    /**
     * Removes a stray MySQL client and restores the files of the correct client.
     *
     * The situation that makes it necessary: a "pkg install -f" pulled in mysql97-client
     * and with it overwrote 19 files of mysql84-client - the commands and the headers, NOT the shared
     * library, which in fact stayed the 8.4 one and is the reason why the mail
     * kept working.
     *
     * The order is deliberate: first the stray one is removed, then the right one is reinstalled.
     * That way any file the removal takes away is put back right after. The reverse order
     * would leave the removal free to delete what had just been restored.
     */
    public static JSONObject startForeignClientCleanup(String foreign, String correct) {
        if (!isValidName(foreign) || !isValidName(correct)
                || !foreign.matches("mysql[0-9]+-client") || !correct.matches("mysql[0-9]+-client")) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startForeignClientCleanup.1"));
        }
        String id = "cleanclient-" + System.currentTimeMillis();
        Job j = new Job(id, "clean_client");
        return startOnTurn(id, j, I18n.tr("server.um.startForeignClientCleanup.2"), "clean-client", () -> {
            j.status = "running";
            boolean unlocked = false;
            try {
                j.advance(1, 5);
                j.write(I18n.tr("server.um.startForeignClientCleanup.3", java.util.Map.of("foreign", String.valueOf(foreign), "correct", String.valueOf(correct))));
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.4", java.util.Map.of("foreign", String.valueOf(foreign))));
                String dependents = sh("pkg query %rn " + foreign + " 2>/dev/null", 30).trim();
                if (!dependents.isEmpty()) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.x.someoneDepends", java.util.Map.of("pkg", String.valueOf(foreign), "dependents", String.valueOf(dependents.replace("\n", " "))));
                    j.write("    " + j.errorMessage);
                    return;
                }
                j.write(I18n.tr("server.um.startForeignClientCleanup.5", java.util.Map.of("foreign", String.valueOf(foreign))));
                String libBefore = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.write("    " + I18n.tr("server.um.x.libOwner", java.util.Map.of("p", String.valueOf(libBefore.isEmpty() ? I18n.tr("server.um.x.nobodyP") : libBefore))));

                j.advance(2, 5);
                j.write("");
                j.write("[2/5] " + I18n.tr("server.um.x.removingPkg", java.util.Map.of("pkg", String.valueOf(foreign))));
                for (String l : sh("pkg delete -y " + foreign + " 2>&1", 300).split("\n")) {
                    if (!l.trim().isEmpty()) j.write("    " + l);
                }

                j.advance(3, 5);
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.6", java.util.Map.of("correct", String.valueOf(correct))));
                if (locked(sh("pkg lock -l 2>/dev/null"), correct)) {
                    // First the list on disk, then the unlock: if the list cannot be written, nothing is unlocked.
                    String stateError = PackageQueue.writeState(java.util.List.of(correct));
                    if (stateError != null)
                        throw new IllegalStateException("I could not save the list for the restore, so I do not unlock " + correct + ": " + stateError);
                    // From here on the finally re-locks and closes the list, even if the unlock failed halfway.
                    unlocked = true;
                    if (!ok("pkg unlock -y " + correct, 30)) throw new IllegalStateException("I could not unlock " + correct);
                    j.write("    " + I18n.tr("server.um.x.unlockedTemp"));
                }
                int code = runLogged(j, "pkg install -f -y " + correct + " 2>&1", 900);
                if (code != 0) throw new IllegalStateException("pkg install exited with code " + code);

                j.advance(4, 5);
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.7"));
                String chk = sh("pkg check -s " + correct + " 2>&1", 300);
                long nonconforming = 0;
                for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) nonconforming++;
                j.write(I18n.tr("server.um.startForeignClientCleanup.8", java.util.Map.of("nonconforming", String.valueOf(nonconforming))));
                if (nonconforming > 0) {
                    for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) j.write("      " + l.trim());
                }

                j.advance(5, 5);
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.9"));
                String libAfter = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.write("    " + I18n.tr("server.um.x.libOwner", java.util.Map.of("p", String.valueOf(libAfter.isEmpty() ? I18n.tr("server.um.x.nobodyMissing") : libAfter))));
                JSONArray broken = packagesWithMissingLibraries().getJSONArray("packages");
                j.write(I18n.tr("server.um.startForeignClientCleanup.10", java.util.Map.of("length", String.valueOf(broken.length()))));
                String mailbox = mysqlOut(org.daemoxcp.mail.database.SqlCatalog.UM_FIRST_ACTIVE_MAILBOX).trim();
                boolean postfixOk = true;
                if (mailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                    String q = sh("postmap -q '" + mailbox + "' mysql:/usr/local/etc/postfix/mysql-virtual-mailboxes.cf 2>&1", 60);
                    String ql = q.toLowerCase();
                    postfixOk = !q.trim().isEmpty() && !ql.contains("error") && !ql.contains("fatal")
                            && !ql.contains("not found") && !ql.contains("dlopen") && !ql.startsWith("postmap:");
                    j.write("    " + (postfixOk
                            ? I18n.tr("server.um.x.pfResolveYes", java.util.Map.of("mailbox", String.valueOf(mailbox), "r", String.valueOf(q.trim())))
                            : I18n.tr("server.um.x.pfResolveNo", java.util.Map.of("mailbox", String.valueOf(mailbox), "r", String.valueOf(q.trim())))));
                }
                if (nonconforming == 0 && broken.length() == 0 && !libAfter.isEmpty() && postfixOk) {
                    j.status = "completed";
                    j.write("");
                    j.write(I18n.tr("server.um.startForeignClientCleanup.11"));
                } else {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startForeignClientCleanup.12");
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                if (unlocked) {
                    boolean r = ok("pkg info -e " + correct, 15) && ok("pkg lock -y " + correct, 30);
                    j.write("");
                    j.write(r ? I18n.tr("server.um.x.reprotectOk", java.util.Map.of("pkg", String.valueOf(correct))) : I18n.tr("server.um.x.reprotectFail", java.util.Map.of("pkg", String.valueOf(correct))));
                    if (r) clearState();
                }
                j.finish();
            }
        });
    }

    public static JSONObject startRelinking() {
        String id = "relink-" + System.currentTimeMillis();
        Job j = new Job(id, "relink");
        return startOnTurn(id, j, I18n.tr("server.um.startRelinking.1"), "relink", () -> runRelinking(j));
    }

    /**
     * Reinstalls from the repository the packages left without the library they require, so that
     * they are linked again to the one present, and puts back into service what depends on them.
     */
    private static void runRelinking(Job job) {
        job.status = "running";
        java.util.List<String> unlockedPackages = new ArrayList<>();
        try {
            job.advance(1, 5);
            job.write(I18n.tr("server.um.runRelinking.1"));
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.2"));
            JSONObject d = packagesWithMissingLibraries();
            JSONArray broken = d.getJSONArray("packages");
            if (broken.length() == 0) {
                job.write(I18n.tr("server.um.runRelinking.3"));
                job.status = "completed";
                return;
            }
            java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<>();
            for (int i = 0; i < broken.length(); i++) {
                JSONObject o = broken.getJSONObject(i);
                job.write("    " + I18n.tr("server.um.x.requiresMissing", java.util.Map.of("name", String.valueOf(o.getString("name")), "lib", String.valueOf(o.getString("lib")))));
                names.add(o.getString("name"));
            }

            job.advance(2, 5);
            job.write("");
            job.write("[2/5] " + I18n.tr("server.um.x.tempUnlock"));
            String lock = sh("pkg lock -l 2>/dev/null");
            java.util.List<String> toUnlock = new ArrayList<>();
            for (String n : names) if (locked(lock, n)) toUnlock.add(n);
            if (!toUnlock.isEmpty()) {
                // First the list on disk, then the unlock: if the list cannot be written, nothing is unlocked.
                String stateError = PackageQueue.writeState(toUnlock);
                if (stateError != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I did not unlock anything: " + stateError);
                // All of them must be re-locked, even a failed unlock: that way the list on disk is closed.
                unlockedPackages.addAll(toUnlock);
                for (String n : toUnlock)
                    job.write("    " + n + ": " + (ok("pkg unlock -y " + n, 30) ? I18n.tr("server.um.x.unlocked") : I18n.tr("server.um.runRelinking.4")));
            } else job.write(I18n.tr("server.um.runRelinking.5"));

            job.advance(3, 5);
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.6"));
            StringBuilder el = new StringBuilder();
            for (String n : names) el.append(' ').append(n);
            // FIRST a dry run: if pkg reports file conflicts, we stop.
            // "-f" serves to force the REINSTALLATION, but it also forces going over the
            // conflicts - and those are two different things. Confusing them got the
            // files of the MySQL 8.4 client overwritten with those of another package.
            String simulation = sh("pkg install -f -n" + el + " 2>&1", 600);
            if (simulation.toLowerCase().contains("conflicts with")) {
                job.write(I18n.tr("server.um.runRelinking.7"));
                for (String l : simulation.split("\n")) {
                    if (l.toLowerCase().contains("conflict")) job.write("      " + l.trim());
                }
                throw new IllegalStateException("the operation would overwrite files of another package: "
                        + "which package must stay has to be decided by hand, not forced.");
            }
            int code = runLogged(job, "pkg install -f -y" + el + " 2>&1", 1800);
            if (code != 0) throw new IllegalStateException("pkg install exited with code " + code);

            job.advance(4, 5);
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.8"));
            java.util.LinkedHashSet<String> services = new java.util.LinkedHashSet<>();
            for (String n : names) services.addAll(servicesToRestart(n));
            for (String logical : services) {
                String real = realServiceName(logical);
                if (real == null) continue;
                String test = testConfigOf(real);
                if (test != null && !Shell.runShell(Duration.ofSeconds(60), test + " 2>&1").success()) {
                    job.write(I18n.tr("server.um.runRelinking.9", java.util.Map.of("real", String.valueOf(real))));
                    continue;
                }
                ok("service " + real + " restart", 120);
                job.write("    " + real + ": " + (ok("service " + real + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26")));
            }

            job.advance(5, 5);
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.10"));
            JSONArray still = packagesWithMissingLibraries().getJSONArray("packages");
            if (still.length() == 0) {
                job.write(I18n.tr("server.um.runRelinking.11"));
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runRelinking.12"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRelinking.13", java.util.Map.of("length", String.valueOf(still.length())));
                for (int i = 0; i < still.length(); i++) {
                    JSONObject o = still.getJSONObject(i);
                    job.write("    " + I18n.tr("server.um.x.stillBroken", java.util.Map.of("name", String.valueOf(o.getString("name")), "lib", String.valueOf(o.getString("lib")))));
                }
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (!unlockedPackages.isEmpty()) {
                job.write("");
                job.write(I18n.tr("server.um.x.reprotecting", java.util.Map.of("n", String.valueOf(unlockedPackages.size()))));
                int n = 0;
                for (String p2 : unlockedPackages) if (ok("pkg info -e " + p2, 15) && ok("pkg lock -y " + p2, 30)) n++;
                job.write("  " + I18n.tr("server.um.x.reprotectedCount", java.util.Map.of("n", String.valueOf(n), "tot", String.valueOf(unlockedPackages.size()))));
                if (n == unlockedPackages.size()) clearState();
            }
            job.finish();
        }
    }

    /** @param approvedSignature the fingerprint of the plan shown by the preview: that one is run, or nothing. */
    public static JSONObject startMaintenance(String approvedSignature) {
        if (approvedSignature == null || !approvedSignature.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startMaintenance.1"));
        String id = "maint-" + System.currentTimeMillis();
        Job j = new Job(id, "maintenance");
        return startOnTurn(id, j, I18n.tr("server.um.x.turnMaintenance"), "update-maintenance", () -> runMaintenanceJob(j, approvedSignature));
    }

    /** @param approvedSignature the signature of the plan read in the tab: that one is run, or nothing. */
    public static JSONObject startUnlockedPackagesUpdate(String approvedSignature) {
        if (approvedSignature == null || !approvedSignature.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startUnlockedPackagesUpdate.2"));
        String id = "upd-" + System.currentTimeMillis();
        Job j = new Job(id, "update");
        return startOnTurn(id, j, I18n.tr("server.um.startUnlockedPackagesUpdate.1"), "update-plain",
                () -> runUpdateJob(j, approvedSignature));
    }

    /** Updates only what is not locked: it is pkg itself that skips the locked packages. */
    private static void runUpdateJob(Job job, String approvedSignature) {
        try {
            updateJobSteps(job, approvedSignature);
        } finally {
            job.finish();
        }
    }

    /** The steps of the job on the other packages, without closing the log: "Update all" uses them too (finding 207). */
    private static void updateJobSteps(Job job, String approvedSignature) {
        job.status = "running";
        // The state of the services BEFORE the update: it is the only way to tell a
        // service that went down from one that was not active even before.
        Map<String, Boolean> servicesBefore = servicesState();
        // As in the other two: what the scripts do to the configuration and addresses.
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        final int TOTAL_STEPS = 4;
        job.advance(1, TOTAL_STEPS);
        job.write(I18n.tr("server.um.runUpdateJob.1"));
        job.write(I18n.tr("server.um.runUpdateJob.2"));
        job.write("");
        try {
            // The plan that was read is run, or nothing: like the other two jobs.
            JSONObject plan = PackagePlan.fullPlan(java.util.Set.of(), lockedNames(),
                    b -> I18n.tr("server.um.x.staysLockedHere"));
            if (!plan.optBoolean("measured"))
                throw new IllegalStateException("I could not work out the exact plan: "
                        + plan.optString("error", "?"));
            String currentSignature = plan.optString("signature");
            if (!planAccepted(approvedSignature, currentSignature, plan)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runUpdateJob.7");
                job.write(I18n.tr("server.um.runGuidedUpdate.3", java.util.Map.of("approvedSignature", String.valueOf(approvedSignature), "currentSignature", String.valueOf(currentSignature))));
                job.write(I18n.tr("server.um.runUpdateJob.8"));
                return;
            }
            // Like the maintenance: a plan that cannot be run is not run, and the reason
            // is given. Without this, pressing the button on an up-to-date machine
            // launched a pkg upgrade that did nothing and declared itself successful.
            if (!plan.optBoolean("runnable")) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.x.planNotRunnable", java.util.Map.of("errors", String.valueOf(String.join(" | ", jsonArrayToList(plan.getJSONArray("pkgErrors"))))))
                        + (plan.getJSONArray("changes").isEmpty() ? " " + I18n.tr("server.um.x.nothingToUpdate") : "");
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                return;
            }
            // The same rule as the other two: no removals, no downgrades.
            String destructive = destructivePlanReason(judged(plan));
            if (destructive != null) {
                job.status = "error";
                job.errorMessage = destructive;
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(destructive))));
                job.write(I18n.tr("server.um.x.destructiveByHand"));
                return;
            }
            job.write("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(currentSignature))));
            JSONArray planChanges = plan.getJSONArray("changes");
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                job.write("    " + PackagePlan.typeName(c.getString("type")) + " " + c.getString("name") + " " + c.getString("from")
                        + (c.getString("to").isEmpty() || c.getString("to").equals(c.getString("from")) ? "" : " -> " + c.getString("to")));
            }

            job.advance(2, TOTAL_STEPS);
            job.write("");
            // As in the other two: first download and recalculate, because the plan depends
            // on what is in pkg's cache (see fetchAndRecheck).
            Recheck grown = fetchAndRecheck(job, "pkg upgrade -F -y -U 2>&1", plan,
                    () -> PackagePlan.fullPlan(java.util.Set.of(), lockedNames(),
                            b -> I18n.tr("server.um.x.staysLockedHere")));
            if (grown.stop() != null) throw org.daemoxcp.mail.util.ShownException.translated(grown.stop());
            plan = grown.plan();

            Map<String, String> inventoryBefore = PackagePlan.versionsOnly(PackagePlan.installed());
            sideEffects.takeBefore();

            job.advance(3, TOTAL_STEPS);
            job.write("");
            // The output is kept here too, to fish out the scripts' messages at the end.
            StringBuilder captured = new StringBuilder();
            // Who reads each type of Postfix map, and the content of the maps that are not regenerated
            // from text, beforehand: if the library has changed afterwards, the maps are regenerated as before.
            PostfixMaps.Before mapsBefore = PostfixMaps.before();
            // -U: the same catalog the plan was calculated on. Before, it was missing, that is
            // it downloaded the catalog again and could install versions different from those shown.
            int code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            // 4 = EX_NEEDRESTART: pkg has updated itself. Recent versions relaunch themselves
            // and do the rest; if this one stopped there, it is relaunched once, unchanged.
            if (code == 4) {
                job.write(I18n.tr("server.um.runUpdateJob.3"));
                code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            }

            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.13"));
            boolean planNotFollowed = false;
            JSONArray verification = PackagePlan.verifyOutcome(plan);
            for (int i = 0; i < verification.length(); i++) {
                JSONObject v2 = verification.getJSONObject(i);
                job.write("    " + (v2.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("name", String.valueOf(v2.getString("name")), "expected", String.valueOf(v2.getString("expected")), "found", String.valueOf(v2.getString("found")))));
                if (!v2.getBoolean("ok")) planNotFollowed = true;
            }
            JSONArray outsidePlan = compareWithInventory(job, inventoryBefore, plan,
                    "Update of the unprotected packages");
            // This job restarts nothing: what a script has written takes
            // effect at the next restart of the service, and that must be said beforehand.
            sideEffects.checkConfig(job, plan, outsidePlan, false);
            // The maps AFTER the configuration check, as in the guided update: a map that
            // the panel rebuilds from its content, without its text next to it, would be taken by the
            // check for a file changed by a script (measured on the VM on 2026-10-31). And even
            // if pkg exited with an error: that is exactly when the machine may have been left halfway.
            String mapsProblem = PostfixMaps.afterUpgrade(mapsBefore, l -> job.write("  " + l)).problem();
            writeActionMessages(job, captured.toString());

            job.advance(4, TOTAL_STEPS);
            job.write("");
            job.write(I18n.tr("server.um.runUpdateJob.4", java.util.Map.of("code", String.valueOf(code))));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.31"));
            boolean fallen = fallenServices(job, servicesBefore);
            sideEffects.checkListening(job);
            java.util.List<String> problems = new ArrayList<>();
            if (code != 0) problems.add(I18n.tr("server.um.runUpdateJob.5", java.util.Map.of("code", String.valueOf(code))));
            if (planNotFollowed) problems.add(I18n.tr("server.um.runMaintenanceJob.14"));
            if (!outsidePlan.isEmpty()) problems.add(divergenceMessage(outsidePlan));
            if (fallen) problems.add(I18n.tr("server.um.runUpdateJob.6"));
            if (mapsProblem != null) problems.add(mapsProblem);
            problems.addAll(sideEffects.problems());
            job.status = problems.isEmpty() ? "completed" : "error";
            job.errorMessage = String.join(" ", problems);
        } catch (Exception e) {
            job.status = "error"; job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Unlocks -> updates -> re-locks EXACTLY what was locked.
     * The re-lock is in a finally: it must happen even if the update fails or
     * throws an exception. Leaving the packages unlocked after an error is the worst
     * scenario, because nobody notices until a later upgrade takes away
     * a service.
     */
    /**
     * Who stays locked during the full maintenance, and why; and the exact plan that
     * results. The preview and the real job call THIS function: if the decision were
     * written twice, sooner or later it would become two different decisions, and the preview
     * would show a plan that the job does not run.
     */
    private static JSONObject maintenancePlan(JSONArray lockedPackages) {
        Map<String, String> why = new LinkedHashMap<>();
        for (int i = 0; i < lockedPackages.length(); i++) {
            JSONObject o = lockedPackages.getJSONObject(i);
            if (o.has("advisory") && "wait".equals(o.getJSONObject("advisory").getString("level")))
                why.put(o.getString("name"), I18n.tr("server.um.x.waitAdvisory"));
        }
        // Evidence from the field beats the generic warning: if the LIVE Dovecot configuration
        // contains constructs that the new version does not accept, that package is not
        // unlocked, full stop. It is not an assumption about the version, it is what is on the disk.
        JSONObject dc = dovecotCompatibility();
        if (dc.optBoolean("scanned", false) && !dc.optBoolean("compatible24", true)) {
            for (String n : sh("pkg query %n 2>/dev/null | grep -E '^dovecot' ", 20).split("\n")) {
                String t = n.trim();
                if (isValidName(t))
                    why.put(t, I18n.tr("server.um.x.diskConfConstructs", java.util.Map.of("n", String.valueOf(dc.optJSONArray("issues").length()))));
            }
        }
        Set<String> protectedNames = lockedNames();
        Set<String> toUnlock = new TreeSet<>(protectedNames);
        toUnlock.removeAll(why.keySet());
        JSONObject plan = PackagePlan.fullPlan(toUnlock, protectedNames,
                b -> why.containsKey(b.optString("name"))
                        ? I18n.tr("server.um.x.staysProtected", java.util.Map.of("reason", String.valueOf(why.get(b.optString("name")))))
                        : reasonNotToUnlock(b),
                UpdateManager::installedFamilyTwin);
        return new JSONObject().put("plan", plan).put("heldBack", new JSONObject(why))
                .put("protectedNames", new JSONArray(new ArrayList<>(protectedNames)));
    }

    private static void runMaintenanceJob(Job job, String approvedSignature) {
        job.status = "running";
        List<String> toRelock = new ArrayList<>();
        JSONObject plan = null;
        boolean planNotFollowed = false;
        // The state file is deleted only if THIS run wrote it. Before, it was deleted
        // when "all the packages to re-lock" were re-locked - and with the empty list of a
        // refusal to start they always were: a maintenance that refused because an
        // interrupted one existed deleted its state, that is the list that startup uses to re-lock.
        boolean stateWritten = false;
        Set<String> lockedBefore = new TreeSet<>();
        Map<String, Boolean> servicesBefore = new LinkedHashMap<>();
        // As in the other two: what the scripts do to the configuration and addresses. If the
        // job stops before pkg upgrade it takes no snapshot, and at the end it says nothing.
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        // The end is written ONLY by the finally, as its last line. The refusals to start below
        // also exit through the finally, which still writes the re-lock and the verification:
        // with the end written before the return, their outcome became visible (see
        // Job.visibleStatus) while the job was still writing.
        try {
            if (Files.exists(Paths.get(MAINTENANCE_STATE))) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMaintenanceJob.1", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE)));
                job.write(I18n.tr("server.um.runMaintenanceJob.2", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                job.write(I18n.tr("server.um.runMaintenanceJob.3"));
                return;
            }

            job.advance(1, 4);
            job.write(I18n.tr("server.um.runMaintenanceJob.4"));
            job.write("");
            lockedBefore = lockedNames();
            servicesBefore = servicesState();
            job.write(I18n.tr("server.um.x.initialState", java.util.Map.of("n", String.valueOf(lockedBefore.size()))));
            job.write(I18n.tr("server.um.x.svcRunningList", java.util.Map.of("list", String.valueOf(servicesBefore.entrySet().stream()
                    .filter(Map.Entry::getValue).map(Map.Entry::getKey)
                    .collect(java.util.stream.Collectors.joining(", "))))));
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.5"));

            // --- Who stays locked, and why: the same function as the preview ---
            JSONObject decision = maintenancePlan(lockedUpdates());
            plan = decision.getJSONObject("plan");
            JSONObject why = decision.getJSONObject("heldBack");
            for (String n : new TreeSet<>(why.keySet()))
                job.write("    " + n + "  -> " + I18n.tr("server.um.x.heldBack", java.util.Map.of("reason", String.valueOf(why.getString(n)))));

            // The plan that was read is run, or nothing.
            if (!plan.optBoolean("measured")) {
                throw new IllegalStateException("I could not work out the exact plan: "
                        + plan.optString("error", "?"));
            }
            if (!plan.optString("signature", "").equals(approvedSignature)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMaintenanceJob.6");
                job.write(I18n.tr("server.um.runGuidedUpdate.3", java.util.Map.of("approvedSignature", String.valueOf(approvedSignature), "currentSignature", String.valueOf(plan.optString("signature")))));
                job.write(I18n.tr("server.um.runMaintenanceJob.7"));
                return;
            }
            if (!plan.optBoolean("runnable")) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.x.planNotRunnable", java.util.Map.of("errors", String.valueOf(String.join(" | ", jsonArrayToList(plan.getJSONArray("pkgErrors"))))))
                        + (plan.getJSONArray("changes").isEmpty() ? " " + I18n.tr("server.um.x.nothingToUpdate") : "");
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                return;
            }
            // The same rule as a package's tab: the panel does not run plans
            // that remove or downgrade packages. It was missing here, and this is the job that
            // gets pressed to update everything.
            String destructive = destructivePlanReason(judged(plan));
            if (destructive != null) {
                job.status = "error";
                job.errorMessage = destructive;
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(destructive))));
                job.write(I18n.tr("server.um.x.destructiveByHand"));
                return;
            }
            toRelock.addAll(jsonArrayToList(plan.getJSONArray("unlockedPackages")));
            job.write("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(plan.getString("signature")))));
            JSONArray planChanges = plan.getJSONArray("changes");
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                job.write("    " + PackagePlan.typeName(c.getString("type")) + " " + c.getString("name") + " " + c.getString("from")
                        + (c.getString("to").isEmpty() || c.getString("to").equals(c.getString("from")) ? "" : " -> " + c.getString("to")));
            }
            job.write("  " + I18n.tr("server.um.x.willRelock", java.util.Map.of("n", String.valueOf(toRelock.size()))));
            if (why.length() > 0) {
                job.write("  " + I18n.tr("server.um.x.heldBackN", java.util.Map.of("n", String.valueOf(why.length()))));
                job.write(I18n.tr("server.um.runMaintenanceJob.9"));
            }

            job.advance(2, 4);
            job.write("");
            job.write("[2/4] " + I18n.tr("server.um.x.tempUnlock"));
            // The list is saved BEFORE unlocking: if the panel dies now, the restore
            // at startup knows what to re-lock. If it cannot be written, nothing is unlocked.
            if (!toRelock.isEmpty()) {
                String stateError = PackageQueue.writeState(toRelock);
                if (stateError != null) {
                    toRelock.clear();   // nothing was unlocked: nothing to re-lock
                    job.status = "error";
                    job.errorMessage = I18n.tr("server.um.runMaintenanceJob.10", java.util.Map.of("stateError", String.valueOf(stateError)));
                    job.write(I18n.tr("server.um.runMaintenanceJob.11", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                    return;
                }
                stateWritten = true;
                job.write(I18n.tr("server.um.runGuidedUpdate.7", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
            }
            for (String n : toRelock) ok("pkg unlock -y " + n, 30);

            job.advance(3, 4);
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.12"));
            // As in the guided update: first download and recalculate, because the
            // plan depends on what is in pkg's cache (see fetchAndRecheck).
            Recheck grown = fetchAndRecheck(job, "pkg upgrade -F -y -U 2>&1", plan,
                    () -> maintenancePlan(lockedUpdates()).getJSONObject("plan"));
            if (grown.stop() != null) throw org.daemoxcp.mail.util.ShownException.translated(grown.stop());
            plan = grown.plan();

            // The inventory BEFORE, to notice what changes without being in the plan.
            // It is taken after the download, right before the update: the download
            // installs nothing, but the inventory must capture the exact moment.
            Map<String, String> inventoryBefore = PackagePlan.versionsOnly(PackagePlan.installed());
            sideEffects.takeBefore();
            // The output is kept here too, to fish out the scripts' messages at the end.
            StringBuilder captured = new StringBuilder();
            // Who reads each type of Postfix map, and the content of the maps that are not regenerated
            // from text, beforehand: if the library has changed afterwards, the maps are regenerated as before.
            PostfixMaps.Before mapsBefore = PostfixMaps.before();
            // -U: the same catalog the plan was calculated on.
            int code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            // 4 = EX_NEEDRESTART: pkg has updated itself. Recent versions relaunch themselves
            // and do the rest; if this one stopped there, it is relaunched once, unchanged.
            if (code == 4) {
                job.write(I18n.tr("server.um.runUpdateJob.3"));
                code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            }
            job.write(I18n.tr("server.um.runUpdateJob.4", java.util.Map.of("code", String.valueOf(code))));
            if (code != 0) { job.status = "error"; job.errorMessage = I18n.tr("server.um.runUpdateJob.5", java.util.Map.of("code", String.valueOf(code))); }
            else job.status = "completed";

            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.13"));
            JSONArray verification = PackagePlan.verifyOutcome(plan);
            for (int i = 0; i < verification.length(); i++) {
                JSONObject v = verification.getJSONObject(i);
                job.write("    " + (v.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("name", String.valueOf(v.getString("name")), "expected", String.valueOf(v.getString("expected")), "found", String.valueOf(v.getString("found")))));
                if (!v.getBoolean("ok")) planNotFollowed = true;
            }

            // And from the other direction: every difference between the earlier inventory and the
            // current one that the plan does not explain. The comparison above walks the PLAN and
            // cannot see a changed package that was not in the plan.
            JSONArray outsidePlan = compareWithInventory(job, inventoryBefore, plan, "Maintenance");
            // The maintenance restarts nothing: what a script has written takes effect
            // at the next restart, which is what whoever reads the list below is about to do.
            sideEffects.checkConfig(job, plan, outsidePlan, false);
            // The maps AFTER the configuration check, as in the guided update: a map that
            // the panel rebuilds from its content, without its text next to it, would be taken by the
            // check for a file changed by a script (measured on the VM on 2026-10-31). And even
            // if pkg exited with an error: that is exactly when the machine may have been left halfway.
            String mapsProblem = PostfixMaps.afterUpgrade(mapsBefore, l -> job.write("  " + l)).problem();

            // The problems are added to the message already there (for example pkg's non-zero
            // exit): none of the three must hide the others.
            java.util.List<String> problems = new ArrayList<>();
            if (planNotFollowed) problems.add(I18n.tr("server.um.runMaintenanceJob.14"));
            if (!outsidePlan.isEmpty()) problems.add(divergenceMessage(outsidePlan));
            if (mapsProblem != null) problems.add(mapsProblem);
            if (!problems.isEmpty()) {
                job.status = "error";
                job.errorMessage = (job.errorMessage == null || job.errorMessage.isEmpty()
                        ? "" : job.errorMessage + " ") + String.join(" ", problems);
            }

            // Updating a package does not update the process that uses it: until it restarts it runs
            // on the old files, and the fix shows as installed without being in service. The
            // full maintenance restarts nothing on its own (the guided update does, one
            // package at a time), but it says exactly what needs restarting.
            java.util.LinkedHashSet<String> toRestart = new java.util.LinkedHashSet<>();
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                if ("remove".equals(c.getString("type"))) continue;
                for (String logical : servicesToRestart(c.getString("name"))) {
                    String real = realServiceName(logical);
                    if (real != null) toRestart.add(real);
                }
            }
            if (!toRestart.isEmpty()) {
                job.write("");
                job.write(I18n.tr("server.um.x.toRestart", java.util.Map.of("list", String.valueOf(String.join(", ", toRestart)))));
                job.write(I18n.tr("server.um.runMaintenanceJob.15"));
            }
            writeActionMessages(job, captured.toString());

        } catch (Exception e) {
            job.status = "error"; job.errorMessage = org.daemoxcp.mail.util.ErrorText.detail("UpdateManager", e);
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // The re-lock ALWAYS happens, whatever went wrong above.
            job.advance(4, 4);
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.16"));
            int done = 0;
            for (String n : toRelock) {
                if (ok("pkg info -e " + n, 15) && ok("pkg lock -y " + n, 30)) done++;
                else job.write(I18n.tr("server.um.runMaintenanceJob.17", java.util.Map.of("n", String.valueOf(n))));
            }
            job.write("  " + I18n.tr("server.um.x.reprotectedCount", java.util.Map.of("n", String.valueOf(done), "tot", String.valueOf(toRelock.size()))));
            if (done == toRelock.size()) { if (stateWritten) clearState(); }
            else {
                job.write(I18n.tr("server.um.runMaintenanceJob.18"));
                job.write(I18n.tr("server.um.runPythonTransition.21", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
            }

            // === Checking its own work: having run the steps is not enough. ===
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.19"));
            boolean alarm = false;

            Set<String> lockedAfter = lockedNames();
            Set<String> missing = new TreeSet<>(lockedBefore);
            missing.removeAll(lockedAfter);
            if (missing.isEmpty()) {
                job.write(I18n.tr("server.um.runMaintenanceJob.20", java.util.Map.of("size", String.valueOf(lockedAfter.size()))));
            } else {
                alarm = true;
                job.write("  " + I18n.tr("server.um.x.protLost", java.util.Map.of("list", String.valueOf(String.join(", ", missing)))));
            }

            // This comparison was right only here, and hand-written: now it is the same
            // one the other three jobs use.
            if (fallenServices(job, servicesBefore)) alarm = true;

            // And the configuration and the addresses: neither of the two counts above sees them.
            sideEffects.checkListening(job);
            java.util.List<String> effects = sideEffects.problems();
            if (!effects.isEmpty()) {
                alarm = true;
                job.errorMessage = (job.errorMessage == null || job.errorMessage.isEmpty()
                        ? "" : job.errorMessage + " ") + String.join(" ", effects);
            }

            if (alarm) {
                job.status = "error";
                if (job.errorMessage == null || job.errorMessage.isEmpty()) {
                    job.errorMessage = I18n.tr("server.um.runMaintenanceJob.24");
                }
            } else if ("completed".equals(job.status)) {
                job.write("");
                job.write(I18n.tr("server.um.runMaintenanceJob.25"));
            }
            job.finish();
        }
    }
}
