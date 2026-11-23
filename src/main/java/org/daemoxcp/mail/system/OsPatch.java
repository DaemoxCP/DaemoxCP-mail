package org.daemoxcp.mail.system;

import org.json.JSONObject;

import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The base system patches installed by the panel, and the restart they ask for (finding 185).
 *
 * <p>Until 2026-11-07 the panel could only DOWNLOAD the patches ("freebsd-update fetch"):
 * installing them was possible only inside the upgrade to a new release. On the production server
 * the patches up to p6 had been waiting, downloaded, since 22 October, and nobody saw it except in
 * one line of the system tab. The real work is in UpdateManager.runOsPatchInstall; here are the
 * decisions, which can be tested without a system underneath.
 */
public final class OsPatch {

    private OsPatch() {}

    /** The freebsd-update "tag" file: "freebsd-update|arm64|15.1-RELEASE|6|<hash>|<end of support>". */
    private static final Pattern TAG = Pattern.compile("^freebsd-update\\|[^|]+\\|([0-9]{1,2}\\.[0-9]{1,2}-[A-Z]+[A-Z0-9-]*)\\|([0-9]{1,4})\\|");

    /**
     * The version the downloaded patches lead to, from the tag file: "15.1-RELEASE-p6". Empty if the
     * tag is not there or does not have that form; "15.1-RELEASE" for level 0.
     */
    static String target(String tag) {
        if (tag == null) return "";
        Matcher m = TAG.matcher(tag.trim());
        if (!m.find()) return "";
        int p = Integer.parseInt(m.group(2));
        return p == 0 ? m.group(1) : m.group(1) + "-p" + p;
    }

    /**
     * freebsd-update install has installed the kernel and asks to reboot BEFORE going on
     * (it happens in release upgrades: "Please reboot and run freebsd-update install again").
     * Between two patches of the same release it installs everything in a single run.
     */
    static boolean asksRebootFirst(String output) {
        String o = output == null ? "" : output.toLowerCase();
        return o.contains("reboot") && o.contains("install") && o.contains("again");
    }

    /** The output of freebsd-update when there is nothing to install. */
    static boolean nothingToInstall(String output) {
        String o = output == null ? "" : output.toLowerCase();
        return o.contains("no updates are available to install");
    }

    /** The output of "freebsd-update fetch" when the release is already at the latest patch. */
    static boolean nothingToFetch(String output) {
        String o = output == null ? "" : output.toLowerCase();
        return o.contains("no updates needed") || o.contains("has no updates available");
    }

    /**
     * Whether the server must be restarted, and why.
     *
     * <ul>
     *   <li>"needed": the installed kernel is not the running one (the Handbook's criterion):
     *   kernel patches do not take effect until a restart;</li>
     *   <li>"advised": the patches were installed after the last boot, but the kernel is the
     *   right one. The running services still use the old libraries (libc, the system's
     *   OpenSSL) until they restart: the restart restarts them all together;</li>
     *   <li>"none": nothing to do. If the panel installed patches before the last boot,
     *   "done" says which.</li>
     * </ul>
     *
     * @param installedAt when the panel installed the latest patches (epoch seconds), 0 if never
     * @param boot        when the server was started, null if unknown
     */
    static JSONObject rebootState(String installedKernel, String runningKernel, long installedAt, Instant boot, String installedTo) {
        String installed = installedKernel == null ? "" : installedKernel.trim();
        String running = runningKernel == null ? "" : runningKernel.trim();
        boolean kernel = !installed.isEmpty() && !running.isEmpty() && !installed.equals(running);
        boolean afterBoot = installedAt > 0 && boot != null && installedAt > boot.getEpochSecond();
        String state = kernel ? "needed" : afterBoot ? "advised" : "none";
        JSONObject r = new JSONObject().put("success", true).put("state", state)
                .put("installedKernel", installed).put("runningKernel", running)
                .put("bootedAt", boot == null ? "" : boot.toString())
                .put("patchesInstalledAt", installedAt > 0 ? Instant.ofEpochSecond(installedAt).toString() : "");
        if (installedAt > 0 && boot != null && !afterBoot && !kernel) r.put("done", installedTo == null ? "" : installedTo);
        return r;
    }

    /**
     * The configuration file with which the panel launches "freebsd-update install": the system's
     * one, with CreateBootEnv no. The panel creates the boot environment beforehand, with a name that
     * says what was in it, and checks that it exists: without it, it does not install. Left to
     * freebsd-update, if bectl does not create it (bectl check fails) the installation goes ahead
     * anyway, with no way back. A CreateBootEnv line that is already active is removed:
     * freebsd-update refuses duplicates.
     */
    static String installConfig(String system) {
        StringBuilder out = new StringBuilder();
        for (String line : (system == null ? "" : system).split("\n", -1)) {
            if (line.trim().matches("(?i)CreateBootEnv\\s+.*")) continue;
            out.append(line).append('\n');
        }
        while (out.length() > 1 && out.charAt(out.length() - 1) == '\n' && out.charAt(out.length() - 2) == '\n') out.setLength(out.length() - 1);
        out.append("# The panel creates its own boot environment before installing (finding 185).\n");
        out.append("CreateBootEnv no\n");
        return out.toString();
    }
}
