package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * At service startup: the panel's service takes the new name (DaemoxCP Mail, 2026-11-17).
 *
 * <p>Up to this version: the script /usr/local/etc/rc.d/mailpanel, the mailpanel_* variables in rc.conf, the
 * pidfile /var/run/mailpanel.pid and the jar freebsd-mail-panel-1.0.jar. They become daemoxcp_mail (script,
 * variables, pidfile) and daemoxcp-mail-1.0.jar. The panel that makes this switch has almost always been started
 * by the old script itself (upgrade-panel.sh puts the new jar in place of the old one and starts it with the
 * previous service): it keeps running, and the new service must recognise it as its own, so that the next stop
 * really stops it.
 *
 * <p>So, in this order, all or nothing:
 * <ol>
 *   <li>from the old script (only if the panel wrote it) the values: folder, java, jar, options; from rc.conf
 *       the mailpanel_* variables the administrator has set;</li>
 *   <li>the jar ALSO takes the new name, with a link to the same file in the same folder. It is not moved:
 *       measured on the VM on 2026-11-17, with the jar moved while it was running the virtual machine no longer
 *       found the SQLite driver (ServiceLoader re-reads the jar by name) and the panel stopped halfway through
 *       startup. The earlier name is removed by the next start, which already runs from the new name
 *       (oldJarNames);</li>
 *   <li>the new script (PanelRcScript, signed by the panel) is written alongside, tested with sh -n and put in
 *       its place; the variables move into rc.conf with the new name (the -Dmailpanel.* options with the new
 *       prefix);</li>
 *   <li>the pidfile takes the new name: it is the pid of this java, and rc.subr compares it with procname (the
 *       java), so "service daemoxcp_mail status" and "stop" find this process;</li>
 *   <li>the old script leaves rc.d (a copy stays in the data folder) and the old variables leave rc.conf;</li>
 *   <li>the check: "service daemoxcp_mail rcvar" loads the script and reports the same enablement as before.</li>
 * </ol>
 * At the first step that does not add up everything is put back as it was. The run.sh script next to the jar, if
 * the panel wrote it, mentions the jar: the path changes there too.
 *
 * <p>The earlier names are in legacy-names.json (sections "rcNames", "jarNames").
 */
public final class PanelServiceRename {

    private static final Logger LOGGER = Logger.getLogger(PanelServiceRename.class.getName());
    private static final Duration T = Duration.ofSeconds(30);

    /** The service's variables, without the prefix. */
    static final List<String> VARIABLES = List.of("enable", "dir", "java", "jar", "opts", "log");

    /** The jars moved in this process: earlier path -> current path (UpdateManager.jarPath). */
    private static final Map<String, String> MOVED_JARS = new ConcurrentHashMap<>();

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** The system, kept separate so it can be tested without touching the real service. */
    interface Services {
        /** The value of a variable set in rc.conf (sysrc -n), or null if it is not set. */
        String rcConf(String variable);
        /** sysrc with these arguments: null if it worked, otherwise what it says. */
        String sysrc(String... args);
        /** sh -n on the file: null if it is fine, otherwise what it says. */
        String syntax(Path script);
        /** The output of "service NAME rcvar", or null if rc.subr does not load it. */
        String rcvar(String name);
        /** The data folder, where the copy of the earlier script stays. */
        Path dataFolder();
    }

    private PanelServiceRename() {}

    /** The current jar, if this process moved it; otherwise the given one. */
    public static String current(String jar) {
        return jar == null ? null : MOVED_JARS.getOrDefault(jar, jar);
    }

    public static void ensureAtBoot() {
        oldJarNames();
        for (String[] p : LegacyNames.pairs("rcNames")) {
            for (String dir : List.of("/usr/local/etc/rc.d", "/etc/rc.d")) {
                try {
                    Report r = rename(Path.of(dir, p[0]), p[0], new RealServices());
                    if (r.outcome() == Outcome.NOTHING) continue;
                    String line = "[PanelServiceRename] " + r.outcome() + ": " + r.detail();
                    if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
                } catch (Throwable t) {
                    LOGGER.warning("[PanelServiceRename] " + dir + "/" + p[0] + ": " + t);
                }
            }
        }
    }

    /**
     * The panel runs from the jar with the current name: the earlier name alongside, if it is the same file (the link
     * left by the switch), goes away. A different file with the earlier name is not touched. The log line is not that
     * of a migration: the switch already said so at the previous startup, and the second start of upgrade-panel.sh
     * must stay silent.
     */
    static void oldJarNames() {
        try {
            Path running = Path.of(PanelServiceRename.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (!Files.isRegularFile(running) || !running.getFileName().toString().startsWith(Product.SLUG + "-")) return;
            String rest = running.getFileName().toString().substring(Product.SLUG.length());
            for (String old : LegacyNames.oldNamesOf("jarNames", Product.SLUG)) {
                Path o = running.resolveSibling(old + rest);
                if (Files.isRegularFile(o, LinkOption.NOFOLLOW_LINKS) && Files.isSameFile(o, running)) {
                    Files.delete(o);
                    LOGGER.info("[PanelServiceRename] the jar's name of before (" + o + ") removed: the panel runs from " + running);
                }
            }
        } catch (Exception e) {
            LOGGER.info("[PanelServiceRename] the jar's name of before is still there: " + e.getMessage());
        }
    }

    // ===================== pure functions =====================

    /** The default values of an rc.d script, from the lines ": ${NAME_x:="value"}". */
    static Map<String, String> defaults(String script, String oldName) {
        Map<String, String> out = new LinkedHashMap<>();
        Matcher m = Pattern.compile("(?m)^: \\$\\{" + Pattern.quote(oldName) + "_([a-z]+):=\"(.*)\"\\}$").matcher(script);
        while (m.find()) out.put(m.group(1), m.group(2));
        return out;
    }

    /** The jar with the new name, in the same folder, if its name is one of the earlier ones; otherwise the same one. */
    static String renamedJar(String jar) {
        if (jar == null || jar.isEmpty()) return jar;
        Path p = Path.of(jar);
        String file = p.getFileName().toString();
        for (String old : LegacyNames.oldNamesOf("jarNames", Product.SLUG)) {
            if (file.startsWith(old + "-") && file.endsWith(".jar")) {
                String rest = file.substring(old.length());
                return (p.getParent() == null ? Path.of(Product.SLUG + rest) : p.getParent().resolve(Product.SLUG + rest)).toString();
            }
        }
        return jar;
    }

    /** The virtual machine's options with the earlier properties (-Dmailpanel.*) given the current prefix. */
    static String renamedOptions(String opts) {
        String out = opts == null ? "" : opts;
        for (String[] p : LegacyNames.pairs("propertyPrefixes"))
            out = out.replace("-D" + p[0], "-D" + p[1]);
        return out;
    }

    // ===================== the switchover =====================

    static Report rename(Path oldScript, String oldName, Services sv) throws IOException {
        if (!Files.isRegularFile(oldScript, LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        Path newScript = Path.of(PanelRcScript.PATH);
        if (Files.exists(newScript, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.LEFT, "both " + oldScript + " and " + newScript + " exist: " + oldScript + " left as it is");
        String text = Files.readString(oldScript, StandardCharsets.UTF_8);
        if (!RcScriptRepair.writtenByPanel(text))
            return new Report(Outcome.LEFT, oldScript + " was not written by the panel: left as it is");
        Map<String, String> def = defaults(text, oldName);
        if (!def.containsKey("jar") || !def.containsKey("java") || !def.containsKey("dir"))
            return new Report(Outcome.LEFT, oldScript + " has no jar, java or folder: left as it is");

        // The variables the administrator has set in rc.conf (at least _enable, if the service is on).
        Map<String, String> set = new LinkedHashMap<>();
        for (String v : VARIABLES) {
            String value = sv.rcConf(oldName + "_" + v);
            if (value != null) set.put(v, value);
        }
        String oldJar = set.getOrDefault("jar", def.get("jar"));
        String newJar = renamedJar(oldJar);
        String opts = renamedOptions(def.getOrDefault("opts", ""));
        String newText = PanelRcScript.text(def.get("dir"), def.get("java"), renamedJar(def.get("jar")), opts);

        Path oldPid = Path.of("/var/run/" + oldName + ".pid"), newPid = Path.of(PanelRcScript.PIDFILE);
        Path copy = sv.dataFolder().resolve(oldName + ".rc.removed");
        Path temp = newScript.resolveSibling("." + newScript.getFileName() + ".panel-new");
        boolean jarMoved = false, scriptWritten = false, pidMoved = false, oldRemoved = false;
        List<String> varsWritten = new ArrayList<>(), varsRemoved = new ArrayList<>();
        try {
            // 1. the jar: the same file under the new name too (a link); the earlier one stays until the restart.
            if (!newJar.equals(oldJar) && Files.isRegularFile(Path.of(oldJar)) && !Files.exists(Path.of(newJar))) {
                Files.createLink(Path.of(newJar), Path.of(oldJar));
                jarMoved = true;
                MOVED_JARS.put(oldJar, newJar);
            }
            // 2. the new script
            Files.writeString(temp, newText, StandardCharsets.UTF_8);
            String syntax = sv.syntax(temp);
            if (syntax != null) throw new IllegalStateException("sh -n refuses the new script: " + syntax);
            Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rwxr-xr-x"));
            Files.move(temp, newScript, StandardCopyOption.ATOMIC_MOVE);
            scriptWritten = true;
            // 3. rc.conf
            for (Map.Entry<String, String> e : set.entrySet()) {
                String value = switch (e.getKey()) {
                    case "jar" -> newJar;
                    case "opts" -> renamedOptions(e.getValue());
                    default -> DataFolderRename.rewritten(e.getValue(), LegacyNames.pairs("dataFolders"));
                };
                String p = sv.sysrc(PanelRcScript.NAME + "_" + e.getKey() + "=" + value);
                if (p != null) throw new IllegalStateException("sysrc " + PanelRcScript.NAME + "_" + e.getKey() + ": " + p);
                varsWritten.add(e.getKey());
            }
            // 4. the pidfile
            if (Files.isRegularFile(oldPid) && !Files.exists(newPid)) {
                Files.move(oldPid, newPid, StandardCopyOption.ATOMIC_MOVE);
                pidMoved = true;
            }
            // 5. the old script leaves rc.d, the old variables leave rc.conf
            Files.createDirectories(copy.getParent());
            Files.move(oldScript, copy, StandardCopyOption.REPLACE_EXISTING);
            oldRemoved = true;
            for (String v : set.keySet()) {
                String p = sv.sysrc("-x", oldName + "_" + v);
                if (p != null) throw new IllegalStateException("sysrc -x " + oldName + "_" + v + ": " + p);
                varsRemoved.add(v);
            }
            // 6. the check
            String rcvar = sv.rcvar(PanelRcScript.NAME);
            String enabled = set.getOrDefault("enable", "NO");
            if (rcvar == null || !rcvar.contains(PanelRcScript.NAME + "_enable=\"" + enabled + "\"") && !rcvar.contains(PanelRcScript.NAME + "_enable=" + enabled))
                throw new IllegalStateException("service " + PanelRcScript.NAME + " rcvar says " + (rcvar == null ? "nothing" : rcvar.replace('\n', ' ')));
        } catch (IOException | RuntimeException e) {
            List<String> problems = new ArrayList<>();
            try { Files.deleteIfExists(temp); } catch (IOException x) { problems.add(temp + ": " + x.getMessage()); }
            for (String v : varsRemoved) if (sv.sysrc(oldName + "_" + v + "=" + set.get(v)) != null) problems.add("rc.conf " + oldName + "_" + v);
            for (String v : varsWritten) sv.sysrc("-x", PanelRcScript.NAME + "_" + v);
            try {
                if (oldRemoved) Files.move(copy, oldScript, StandardCopyOption.ATOMIC_MOVE);
                if (pidMoved) Files.move(newPid, oldPid, StandardCopyOption.ATOMIC_MOVE);
                if (scriptWritten) Files.deleteIfExists(newScript);
                if (jarMoved) {
                    Files.deleteIfExists(Path.of(newJar));
                    MOVED_JARS.remove(oldJar);
                }
            } catch (IOException x) {
                problems.add(x.getMessage());
            }
            return new Report(Outcome.ROLLED_BACK, e.getMessage()
                    + (problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems)));
        }

        // run.sh next to the jar, if the panel wrote it: it mentions the jar and goes with it.
        String runSh = "";
        if (jarMoved) {
            Path run = Path.of(newJar).resolveSibling("run.sh");
            try {
                if (Files.isRegularFile(run, LinkOption.NOFOLLOW_LINKS)) {
                    String r = Files.readString(run, StandardCharsets.UTF_8);
                    String n = r.replace(oldJar, newJar);
                    if (!n.equals(r)) {
                        PanelMarker.replaceKeeping(run, n);
                        runSh = ", run.sh updated";
                    }
                }
            } catch (IOException e) {
                runSh = ", run.sh NOT updated (" + e.getMessage() + ")";
            }
        }
        return new Report(Outcome.DONE, oldScript + " -> " + newScript + " (copy of the old one in " + copy + ")"
                + (set.isEmpty() ? "" : ", rc.conf " + set.keySet() + " now " + PanelRcScript.NAME + "_*")
                + (pidMoved ? ", pidfile " + newPid : "") + (jarMoved ? ", jar also " + newJar + " (the same file: the old name goes at the next start)" : "") + runSh);
    }

    // ===================== the real system =====================

    static final class RealServices implements Services {
        @Override public String rcConf(String variable) {
            Shell.Result r = Shell.run(T, "sysrc", "-n", variable);
            return r.success() ? r.outputTrim() : null;
        }
        @Override public String sysrc(String... args) {
            String[] cmd = new String[args.length + 1];
            cmd[0] = "sysrc";
            System.arraycopy(args, 0, cmd, 1, args.length);
            Shell.Result r = Shell.run(T, cmd);
            return r.success() ? null : r.outputTrim();
        }
        @Override public String syntax(Path script) {
            Shell.Result r = Shell.run(T, "sh", "-n", script.toString());
            return r.success() ? null : r.outputTrim();
        }
        @Override public String rcvar(String name) {
            Shell.Result r = Shell.run(T, "service", name, "rcvar");
            return r.success() ? r.outputTrim() : null;
        }
        @Override public Path dataFolder() { return Path.of(DataFolderRename.NEW); }
    }
}
