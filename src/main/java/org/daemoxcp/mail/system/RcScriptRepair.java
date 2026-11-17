package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * All'avvio: lo script di avvio che il pannello ha scritto il giorno dell'installazione
 * (/usr/local/etc/rc.d/mailpanel) cita ancora i file coi nomi di prima.
 *
 * <p>PathMigration rinomina /var/db/mailpanel/pannello.log in panel.log, ma lo script di un server
 * installato prima della rinomina fa scrivere a daemon(8) proprio quel nome (mailpanel_log). Al
 * riavvio successivo il log ripartirebbe col nome vecchio, accanto al nuovo: PathMigration vedrebbe
 * i due nomi e, giustamente, non sceglierebbe, e il pannello mostrerebbe un log fermo. Visto sul
 * server vero il 31/10/2026, dove lo script l'aveva scritto la versione dell'11/10. Sulla VM non si
 * vedeva: li' il pannello si avviava a mano, senza script.
 *
 * <p>E i due messaggi dello script, che nascevano in italiano («Avvio mailpanel (solo web). Registro: ...» dopo
 * service mailpanel start): fuori dai file di lingua il pannello parla inglese, e la guida d'installazione e' in
 * inglese. Visto seguendo la guida sulla VM pulita il 16/11/2026 (MESSAGES).
 *
 * <p>Si tocca solo lo script scritto dal pannello (riconosciuto dalla riga MARKER), e dentro solo i
 * percorsi interi che il file di dati da' per rinominati (LegacyNames, sezione "files") e le righe intere dei
 * messaggi di prima. Lo script
 * nuovo si scrive accanto, si prova con sh -n, prende proprietario e permessi del vecchio e lo
 * sostituisce con un rename: rc(8) non vede mai uno script a meta'. Ripeterlo non cambia niente.
 */
public final class RcScriptRepair {

    private static final Logger LOGGER = Logger.getLogger(RcScriptRepair.class.getName());

    /** La riga con cui il pannello firma lo script (UpdateManager la scrive da qui). */
    static final String MARKER = "Generato dal pannello il giorno dell'installazione";

    static final List<Path> SCRIPTS = List.of(Path.of("/usr/local/etc/rc.d/mailpanel"), Path.of("/etc/rc.d/mailpanel"));

    /** I due messaggi dello script (UpdateManager li scrive da qui). */
    static final String STARTING = "echo \"Starting ${name} (web only). Log: ${mailpanel_log}\"";
    static final String RUNNING = "echo \"${name}: already running (pid $(cat ${pidfile}))\"";

    /** Le righe dei messaggi come le scrivevano le versioni di prima, e quelle di adesso. */
    static final List<String[]> MESSAGES = List.of(
            new String[] {"echo \"Avvio ${name} (solo web). Registro: ${mailpanel_log}\"", STARTING},
            new String[] {"echo \"${name}: gia' in esecuzione (pid $(cat ${pidfile}))\"", RUNNING});

    private RcScriptRepair() {}

    enum Outcome { NOTHING, NOT_OURS, REFUSED, DONE }

    record Report(Outcome outcome, String detail) {}

    /**
     * Lo script coi percorsi di adesso al posto di quelli di prima. Un percorso conta solo intero:
     * seguito da virgolette, da uno spazio, da ";" o "/", o dalla fine della riga.
     */
    static String current(String script, List<String[]> pairs) {
        String s = script;
        for (String[] p : pairs)
            s = Pattern.compile(Pattern.quote(p[0]) + "(?=[\"'\\s;/]|$)", Pattern.MULTILINE)
                    .matcher(s).replaceAll(Matcher.quoteReplacement(p[1]));
        return s;
    }

    /** Lo script coi messaggi di adesso al posto di quelli di prima: solo righe intere. */
    static String currentMessages(String script) {
        String s = script;
        for (String[] m : MESSAGES)
            s = Pattern.compile("^([ \\t]*)" + Pattern.quote(m[0]) + "$", Pattern.MULTILINE)
                    .matcher(s).replaceAll("$1" + Matcher.quoteReplacement(m[1]));
        return s;
    }

    /** I percorsi di prima che lo script cita, nell'ordine del file di dati. */
    static List<String> oldPathsIn(String script, List<String[]> pairs) {
        List<String> out = new ArrayList<>();
        for (String[] p : pairs)
            if (Pattern.compile(Pattern.quote(p[0]) + "(?=[\"'\\s;/]|$)", Pattern.MULTILINE).matcher(script).find()) out.add(p[0]);
        return out;
    }

    /** Ripara uno script. syntaxCheck prova il file scritto accanto (sh -n sul server). */
    static Report repair(Path script, List<String[]> pairs, Function<Path, Shell.Result> syntaxCheck) throws IOException {
        if (!Files.isRegularFile(script, LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        String text = Files.readString(script, StandardCharsets.UTF_8);
        List<String> old = oldPathsIn(text, pairs);
        String repaired = currentMessages(current(text, pairs));
        boolean messages = !currentMessages(text).equals(text);
        if (repaired.equals(text)) return new Report(Outcome.NOTHING, "");
        if (!text.contains(MARKER))
            return new Report(Outcome.NOT_OURS, script + " cites " + (old.isEmpty() ? "the old messages" : old)
                    + " but was not written by the panel: left alone");
        // Un file che comincia col punto: rc(8) prende gli script di rc.d con un glob, che non lo vede.
        Path temp = script.resolveSibling("." + script.getFileName() + ".panel-new");
        try {
            Files.writeString(temp, repaired, StandardCharsets.UTF_8);
            Shell.Result check = syntaxCheck.apply(temp);
            if (!check.success())
                return new Report(Outcome.REFUSED, "sh -n refused the repaired " + script + ": " + check.outputTrim() + "; left as it was");
            sameOwnerAndMode(script, temp);
            Files.move(temp, script, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return new Report(Outcome.DONE, script + ": " + (old.isEmpty() ? "" : old + " now with the current names")
                    + (old.isEmpty() || !messages ? "" : ", ") + (messages ? "messages in English" : ""));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static void sameOwnerAndMode(Path from, Path to) throws IOException {
        PosixFileAttributes a = Files.readAttributes(from, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        PosixFileAttributeView v = Files.getFileAttributeView(to, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        v.setOwner(a.owner());
        v.setGroup(a.group());
        v.setPermissions(a.permissions());
    }

    public static void ensureAtBoot() {
        for (Path p : SCRIPTS) {
            try {
                Report r = repair(p, LegacyNames.pairs("files"),
                        f -> Shell.run(Duration.ofSeconds(30), "sh", "-n", f.toString()));
                if (r.outcome() == Outcome.NOTHING) continue;
                String line = "[RcScriptRepair] " + r.outcome() + ": " + r.detail();
                if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
            } catch (Throwable t) {
                LOGGER.warning("[RcScriptRepair] " + p + ": " + t);
            }
        }
    }
}
