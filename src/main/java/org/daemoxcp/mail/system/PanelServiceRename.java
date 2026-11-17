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
 * All'avvio del servizio: il servizio del pannello prende il nome nuovo (DaemoxCP Mail, 17/11/2026).
 *
 * <p>Fino a questa versione: lo script /usr/local/etc/rc.d/mailpanel, le variabili mailpanel_* in rc.conf, il pidfile
 * /var/run/mailpanel.pid e il jar freebsd-mail-panel-1.0.jar. Diventano daemoxcp_mail (script, variabili, pidfile) e
 * daemoxcp-mail-1.0.jar. Il pannello che fa questo passaggio e' quasi sempre partito proprio dallo script vecchio
 * (upgrade-panel.sh mette il jar nuovo al posto di quello vecchio e lo avvia col servizio di prima): continua a
 * girare, e il servizio nuovo lo deve riconoscere come suo, perche' il prossimo stop lo fermi davvero.
 *
 * <p>Quindi, in quest'ordine, tutto o niente:
 * <ol>
 *   <li>dallo script vecchio (solo se l'ha scritto il pannello) i valori: cartella, java, jar, opzioni; da rc.conf le
 *       variabili mailpanel_* che l'amministratore ha impostato;</li>
 *   <li>il jar prende il nome nuovo nella stessa cartella. La macchina virtuale che lo sta usando lo tiene aperto e
 *       non se ne accorge; chi chiede al pannello il suo jar (UpdateManager.jarPath) riceve il nome nuovo;</li>
 *   <li>lo script nuovo (PanelRcScript, firmato dal pannello) si scrive accanto, si prova con sh -n e si mette al suo
 *       posto; le variabili passano in rc.conf col nome nuovo (le opzioni -Dmailpanel.* col prefisso nuovo);</li>
 *   <li>il pidfile prende il nome nuovo: e' il pid di questa java, e rc.subr lo confronta con procname (la java), quindi
 *       "service daemoxcp_mail status" e "stop" trovano questo processo;</li>
 *   <li>lo script vecchio esce da rc.d (una copia resta nella cartella dei dati) e le variabili vecchie da rc.conf;</li>
 *   <li>il controllo: "service daemoxcp_mail rcvar" carica lo script e dice la stessa abilitazione di prima.</li>
 * </ol>
 * Al primo passo che non torna si rimette tutto com'era. Lo script run.sh accanto al jar, se l'ha scritto il pannello,
 * cita il jar: il percorso cambia anche li'.
 *
 * <p>I nomi di prima stanno in legacy-names.json (sezioni "rcNames", "jarNames").
 */
public final class PanelServiceRename {

    private static final Logger LOGGER = Logger.getLogger(PanelServiceRename.class.getName());
    private static final Duration T = Duration.ofSeconds(30);

    /** Le variabili del servizio, senza il prefisso. */
    static final List<String> VARIABLES = List.of("enable", "dir", "java", "jar", "opts", "log");

    /** I jar spostati in questo processo: percorso di prima -> percorso di adesso (UpdateManager.jarPath). */
    private static final Map<String, String> MOVED_JARS = new ConcurrentHashMap<>();

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Il sistema, separato per provarlo senza toccare il servizio vero. */
    interface Services {
        /** Il valore di una variabile impostata in rc.conf (sysrc -n), o null se non e' impostata. */
        String rcConf(String variable);
        /** sysrc con questi argomenti: null se e' andato, altrimenti cosa dice. */
        String sysrc(String... args);
        /** sh -n sul file: null se va bene, altrimenti cosa dice. */
        String syntax(Path script);
        /** L'uscita di "service NOME rcvar", o null se rc.subr non lo carica. */
        String rcvar(String name);
        /** La cartella dei dati, dove resta la copia dello script di prima. */
        Path dataFolder();
    }

    private PanelServiceRename() {}

    /** Il jar di adesso, se questo processo l'ha spostato; altrimenti quello dato. */
    public static String current(String jar) {
        return jar == null ? null : MOVED_JARS.getOrDefault(jar, jar);
    }

    public static void ensureAtBoot() {
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

    // ===================== funzioni pure =====================

    /** I valori predefiniti di uno script rc.d, dalle righe ": ${NOME_x:="valore"}". */
    static Map<String, String> defaults(String script, String oldName) {
        Map<String, String> out = new LinkedHashMap<>();
        Matcher m = Pattern.compile("(?m)^: \\$\\{" + Pattern.quote(oldName) + "_([a-z]+):=\"(.*)\"\\}$").matcher(script);
        while (m.find()) out.put(m.group(1), m.group(2));
        return out;
    }

    /** Il jar col nome nuovo, nella stessa cartella, se il suo nome e' uno di prima; altrimenti lo stesso. */
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

    /** Le opzioni della macchina virtuale con le proprieta' di prima (-Dmailpanel.*) col prefisso di adesso. */
    static String renamedOptions(String opts) {
        String out = opts == null ? "" : opts;
        for (String[] p : LegacyNames.pairs("propertyPrefixes"))
            out = out.replace("-D" + p[0], "-D" + p[1]);
        return out;
    }

    // ===================== il passaggio =====================

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

        // Le variabili che l'amministratore ha impostato in rc.conf (almeno _enable, se il servizio e' acceso).
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
            // 1. il jar
            if (!newJar.equals(oldJar) && Files.isRegularFile(Path.of(oldJar)) && !Files.exists(Path.of(newJar))) {
                Files.move(Path.of(oldJar), Path.of(newJar), StandardCopyOption.ATOMIC_MOVE);
                jarMoved = true;
                MOVED_JARS.put(oldJar, newJar);
            }
            // 2. lo script nuovo
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
            // 4. il pidfile
            if (Files.isRegularFile(oldPid) && !Files.exists(newPid)) {
                Files.move(oldPid, newPid, StandardCopyOption.ATOMIC_MOVE);
                pidMoved = true;
            }
            // 5. lo script vecchio esce da rc.d, le variabili vecchie da rc.conf
            Files.createDirectories(copy.getParent());
            Files.move(oldScript, copy, StandardCopyOption.REPLACE_EXISTING);
            oldRemoved = true;
            for (String v : set.keySet()) {
                String p = sv.sysrc("-x", oldName + "_" + v);
                if (p != null) throw new IllegalStateException("sysrc -x " + oldName + "_" + v + ": " + p);
                varsRemoved.add(v);
            }
            // 6. il controllo
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
                    Files.move(Path.of(newJar), Path.of(oldJar), StandardCopyOption.ATOMIC_MOVE);
                    MOVED_JARS.remove(oldJar);
                }
            } catch (IOException x) {
                problems.add(x.getMessage());
            }
            return new Report(Outcome.ROLLED_BACK, e.getMessage()
                    + (problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems)));
        }

        // run.sh accanto al jar, se l'ha scritto il pannello: cita il jar e va con lui.
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
                + (pidMoved ? ", pidfile " + newPid : "") + (jarMoved ? ", jar " + newJar : "") + runSh);
    }

    // ===================== il sistema vero =====================

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
