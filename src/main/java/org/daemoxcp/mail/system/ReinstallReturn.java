package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Going back to the server as it was before a full reinstallation, without losing the mail that arrived
 * afterwards. Used by the console menu (menu option 6) and by the Updates page (the warning about the
 * interrupted reinstallation), with the same code.
 *
 * <p>Why it exists (finding 169): the reinstallation's way back is a boot environment, and /var/vmail is
 * inside it. Just activating it brought the mail back to the moment it was created: the messages that
 * arrived afterwards were lost. And the only way to choose it was to read the warning and type
 * bectl activate in a shell.
 *
 * <p>Here, before activating it: Postfix and Dovecot are stopped (the mail does not change while it is
 * being copied), the boot environment is mounted, and the current mail files that are MISSING there are
 * added (tar -k: a file that already exists is not touched). Maildir is one file per message, so the
 * earlier messages stay and the new ones are added; Dovecot sees them on the first read. It is not
 * rollback-panel.sh, which REPLACES the mail: after a reinstallation the current mail is the mail the
 * reinstallation emptied, and replacing it would lose precisely the earlier mail. Then bectl activate.
 * No reboot here: the caller does it, when the administrator decides.
 *
 * <p>What does NOT catch up: the MySQL database is the earlier one (mailboxes, domains, aliases and
 * administrators created afterwards must be redone: after a reinstallation it is the recreated empty one
 * anyway); the Postfix queue is the earlier one (this is said if it is not empty now).
 */
public final class ReinstallReturn {

    private static final Logger LOGGER = Logger.getLogger(ReinstallReturn.class.getName());

    private ReinstallReturn() {}

    static String vmail = "/var/vmail";

    private static Shell.Result run(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd);
    }

    /** The way back of the most recent reinstallation, or "" if there is none. */
    public static String latest() {
        return PackageWayBack.newestReinstallWayBack();
    }

    /** What is needed to decide: name, when, whether mail and database are inside it, the boot environment in use. */
    public static JSONObject describe() {
        JSONObject r = new JSONObject().put("success", true);
        String name = latest();
        r.put("wayBack", name);
        if (name.isEmpty()) return r;
        r.put("createdUtc", name.substring(PackageWayBack.REINSTALL_PREFIX.length()));
        r.put("dataInside", new org.json.JSONArray(PackageWayBack.dataInside()));
        return r;
    }

    /**
     * Goes back to 'name': the current mail merged in, then bectl activate. If something goes wrong before
     * the activation, nothing has changed and the mail starts again. Does not reboot.
     */
    public static JSONObject goBack(String name, Consumer<String> log) {
        JSONObject r = new JSONObject();
        if (name == null || !PackageWayBack.REINSTALL_OWN.matcher(name).matches())
            return r.put("success", false).put("error", I18n.tr("server.wayBack.notReinstall", Map.of("name", String.valueOf(name))));
        String state = null;
        for (String line : run("bectl list -H 2>/dev/null", 60).outputTrim().split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && f[0].trim().equals(name)) state = f[1].trim();
        }
        if (state == null)
            return r.put("success", false).put("error", I18n.tr("server.wayBack.missing", Map.of("name", name)));
        if (state.contains("N"))
            return r.put("success", false).put("error", I18n.tr("server.wayBack.alreadyRunning", Map.of("name", name)));

        // The package turn: going back changes packages and configurations together, and a
        // package job halfway through (in this process or in another) would be broken by it.
        String refusal = PackageQueue.takeForLocks("way-back", I18n.tr("server.wayBack.turn"));
        if (refusal != null) return r.put("success", false).put("error", refusal);
        String mnt = "", mntDir = "";
        List<String> stopped = new ArrayList<>();
        boolean activated = false;
        try {
            mntDir = run("mktemp -d /var/tmp/daemoxcp-mail-way-back.XXXXXX", 30).outputTrim();
            if (!mntDir.matches("/var/tmp/daemoxcp-mail-way-back\\.[A-Za-z0-9]+")) {
                String err = mntDir;
                mntDir = "";
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotMount", Map.of("name", name, "err", err)));
            }
            mnt = mntDir;
            Shell.Result m = run("bectl mount " + name + " " + mnt + " 2>&1", 120);
            if (!m.success())
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotMount", Map.of("name", name, "err", m.outputTrim())));

            int merged = 0;
            if (PackageWayBack.dataInside().contains(vmail) && new java.io.File(vmail).isDirectory()) {
                for (String svc : List.of("postfix", "dovecot"))
                    if (run("service " + svc + " status >/dev/null 2>&1", 30).success()) {
                        run("service " + svc + " stop >/dev/null 2>&1", 120);
                        stopped.add(svc);
                    }
                String parent = vmail.substring(0, vmail.lastIndexOf('/'));
                String base = vmail.substring(vmail.lastIndexOf('/') + 1);
                long before = count(mnt + vmail);
                // -k: a file that already exists in the boot environment is not overwritten.
                // -p: owners and permissions.
                Shell.Result c = run("tar -cpf - -C " + parent + " " + base + " | tar -xpkf - -C " + mnt + parent + " 2>&1", 3600);
                long after = count(mnt + vmail);
                if (!c.success() || after < before) {
                    return r.put("success", false).put("error", I18n.tr("server.wayBack.mergeFailed",
                            Map.of("name", name, "err", c.outputTrim().isEmpty() ? "exit " + c.exitCode() : c.outputTrim())));
                }
                merged = (int) (after - before);
                log.accept(I18n.tr("server.wayBack.merged", Map.of("n", String.valueOf(merged), "name", name)));
            }
            String queued = run("postqueue -j 2>/dev/null | wc -l", 30).outputTrim();
            if (queued.matches("[0-9]+") && !queued.equals("0"))
                log.accept(I18n.tr("server.wayBack.queued", Map.of("n", queued)));

            Shell.Result u = run("bectl umount " + name + " 2>&1", 120);
            if (!u.success())
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotMount", Map.of("name", name, "err", u.outputTrim())));
            mnt = "";
            Shell.Result a = run("bectl activate " + name + " 2>&1", 120);
            if (!a.success())
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotActivate", Map.of("name", name, "err", a.outputTrim())));
            activated = true;
            log.accept(I18n.tr("server.wayBack.activated", Map.of("name", name)));
            LOGGER.warning("Way back of a reinstallation activated for the next boot: " + name + ", " + merged + " mail files merged in");
            return r.put("success", true).put("name", name).put("merged", merged)
                    .put("note", I18n.tr("server.wayBack.rebootNeeded", Map.of("name", name)));
        } finally {
            if (!mnt.isEmpty()) run("bectl umount " + name + " >/dev/null 2>&1", 120);
            if (!mntDir.isEmpty()) run("rmdir " + mntDir + " 2>/dev/null", 30);
            // Until the activation nothing has changed: the mail starts again. Afterwards, it stays
            // stopped until the reboot.
            if (!activated) for (String svc : stopped) run("service " + svc + " start >/dev/null 2>&1", 120);
            PackageQueue.release("way-back");
        }
    }

    private static long count(String dir) {
        String n = run("find " + dir + " -type f 2>/dev/null | wc -l", 600).outputTrim();
        return n.matches("[0-9]+") ? Long.parseLong(n) : -1;
    }
}
