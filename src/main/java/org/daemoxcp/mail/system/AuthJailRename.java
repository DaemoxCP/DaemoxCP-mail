package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.Fail2banAutoSetup;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * All'avvio del servizio: la jail di fail2ban degli accessi al pannello prende il nome nuovo (DaemoxCP Mail,
 * 17/11/2026): mail-panel-auth diventa daemoxcp-mail-auth.
 *
 * <p>Il nome viaggia fra quattro posti, come quello della superficie pubblica (PublicSurfaceRename): il registro
 * degli accessi che scrive il pannello (/var/log/NOME.log), il filtro (filter.d/NOME.conf), la sezione [NOME] di
 * jail.local che lo legge e banna in pf (ancora f2b/NOME), e la rotazione di newsyslog. Se se ne sposta uno solo, la
 * jail guarda un registro che nessuno scrive piu' e non banna niente, senza dare errori. Quindi tutto o niente:
 * <ol>
 *   <li>il registro con le sue copie ruotate prende il nome nuovo (il pannello, appena partito, non l'ha ancora
 *       aperto: scrivera' gia' sul nome nuovo);</li>
 *   <li>il filtro prende il nome nuovo, con la firma di adesso;</li>
 *   <li>in jail.local la sezione cambia nome, filtro, registro e nome dell'azione; il resto resta com'era, anche
 *       quello che l'amministratore ha cambiato a mano;</li>
 *   <li>la rotazione di newsyslog prende nome e registro nuovi;</li>
 *   <li>nel database di fail2ban i ban e la posizione nel registro passano alla jail nuova (senza ribannare: la
 *       jail recidive li conterebbe, vedi PublicSurfaceRename);</li>
 *   <li>fail2ban-client -t, reload, e la jail nuova deve esserci.</li>
 * </ol>
 * Al primo passo che non torna si rimette tutto com'era e si ricarica fail2ban: al prossimo avvio si riprova.
 *
 * <p>Il nome di prima sta in legacy-names.json (sezione "authJail").
 */
public final class AuthJailRename {

    private static final Logger LOGGER = Logger.getLogger(AuthJailRename.class.getName());

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Dove stanno i file: fissi sul server, cartelle temporanee nella prova. */
    record Places(Path f2bDir, Path logDir, Path newsyslogDir) {}

    /** fail2ban, separato per provarlo senza il servizio vero. */
    interface Services {
        /** fail2ban gira e risponde. */
        boolean running();
        /** fail2ban-client -t: null se la configurazione va, altrimenti cosa dice. */
        String test();
        /** fail2ban-client reload: null se e' andato. */
        String reload();
        /** La jail c'e' in fail2ban. */
        boolean jailExists(String jail);
        /** Ban e posizione nel registro della jail {@code from} passano a {@code to}. */
        boolean moveState(String from, String to, String fromLog, String toLog);
    }

    private AuthJailRename() {}

    public static void ensureAtBoot() {
        Places at = new Places(Path.of("/usr/local/etc/fail2ban"), Path.of("/var/log"), Path.of("/usr/local/etc/newsyslog.conf.d"));
        for (String[] p : LegacyNames.pairs("authJail")) {
            try {
                Report r = rename(p[0], p[1], at, new RealServices());
                if (r.outcome() == Outcome.NOTHING) continue;
                String line = "[AuthJailRename] " + r.outcome() + ": " + r.detail();
                if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
            } catch (Throwable t) {
                LOGGER.warning("[AuthJailRename] failed: " + t);
            }
        }
    }

    // ===================== funzioni pure =====================

    /**
     * jail.local con la sezione [oldName] chiamata [newName]: dentro la sezione cambiano il nome del filtro, il
     * registro e il nome dell'azione; il resto del file e della sezione resta com'era. Null se la sezione non c'e'.
     */
    static String renamedSection(String jailLocal, String oldName, String newName, String oldLog, String newLog) {
        Matcher h = Pattern.compile("(?m)^\\[" + Pattern.quote(oldName) + "\\]\\s*$").matcher(jailLocal);
        if (!h.find()) return null;
        int start = h.start();
        Matcher next = Pattern.compile("(?m)^\\[").matcher(jailLocal);
        int end = next.find(h.end()) ? next.start() : jailLocal.length();
        String section = jailLocal.substring(start, end)
                .replace("[" + oldName + "]", "[" + newName + "]")
                .replace(oldLog, newLog);
        section = Pattern.compile("(?m)^(filter\\s*=\\s*)" + Pattern.quote(oldName) + "\\s*$").matcher(section)
                .replaceAll("$1" + Matcher.quoteReplacement(newName));
        section = section.replace("name=" + oldName + ",", "name=" + newName + ",").replace("name=" + oldName + "]", "name=" + newName + "]");
        // La riga di testa che il pannello scrive sopra la sezione, se c'e', prende la firma di adesso.
        String before = PanelMarker.current(jailLocal.substring(0, start), "productComments");
        return before + section + jailLocal.substring(end);
    }

    // ===================== il passaggio =====================

    private record Step(Path from, Path to, String before) {}

    static Report rename(String oldName, String newName, Places at, Services sv) throws IOException {
        Path jailLocal = at.f2bDir().resolve("jail.local");
        Path oldFilter = at.f2bDir().resolve("filter.d").resolve(oldName + ".conf");
        Path newFilter = at.f2bDir().resolve("filter.d").resolve(newName + ".conf");
        Path oldNewsyslog = at.newsyslogDir().resolve(oldName + ".conf");
        Path newNewsyslog = at.newsyslogDir().resolve(newName + ".conf");
        String oldLog = at.logDir().resolve(oldName + ".log").toString();
        String newLog = at.logDir().resolve(newName + ".log").toString();

        String jail = Files.isRegularFile(jailLocal) ? Files.readString(jailLocal, StandardCharsets.UTF_8) : "";
        boolean section = Pattern.compile("(?m)^\\[" + Pattern.quote(oldName) + "\\]\\s*$").matcher(jail).find();
        boolean anything = section || Files.exists(oldFilter, LinkOption.NOFOLLOW_LINKS) || Files.exists(Path.of(oldLog), LinkOption.NOFOLLOW_LINKS)
                || Files.exists(oldNewsyslog, LinkOption.NOFOLLOW_LINKS);
        if (!anything) return new Report(Outcome.NOTHING, "");
        if (Pattern.compile("(?m)^\\[" + Pattern.quote(newName) + "\\]\\s*$").matcher(jail).find() || Files.exists(newFilter, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.LEFT, "both " + oldName + " and " + newName + " exist in fail2ban: " + oldName + " left as it is");
        if (Files.exists(oldFilter) && !Fail2banAutoSetup.ownFilter(Files.readString(oldFilter, StandardCharsets.UTF_8)))
            return new Report(Outcome.LEFT, oldFilter + " was not written by the panel: left as it is");

        List<Path[]> movedLogs = new ArrayList<>();
        List<Step> written = new ArrayList<>();
        boolean filterMoved = false, newsyslogMoved = false;
        String newJail = section ? renamedSection(jail, oldName, newName, oldLog, newLog) : null;
        try {
            // 1. il registro e le sue copie ruotate (NOME.log.0.bz2 ...)
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(at.logDir(), oldName + ".log*")) {
                for (Path f : ds) {
                    Path to = at.logDir().resolve(newName + f.getFileName().toString().substring(oldName.length()));
                    if (Files.exists(to, LinkOption.NOFOLLOW_LINKS)) continue;
                    Files.move(f, to, StandardCopyOption.ATOMIC_MOVE);
                    movedLogs.add(new Path[] {f, to});
                }
            }
            // 2. il filtro, con la firma di adesso
            if (Files.exists(oldFilter, LinkOption.NOFOLLOW_LINKS)) {
                String f = Files.readString(oldFilter, StandardCharsets.UTF_8);
                Files.move(oldFilter, newFilter, StandardCopyOption.ATOMIC_MOVE);
                filterMoved = true;
                String n = PanelMarker.current(f, Fail2banAutoSetup.MARKER_SECTION).replace(oldLog, newLog)
                        .replace("/" + oldName + ".conf", "/" + newName + ".conf");
                if (!n.equals(f)) {
                    PanelMarker.replaceKeeping(newFilter, n);
                    written.add(new Step(newFilter, newFilter, f));
                }
            }
            // 3. la sezione di jail.local
            if (newJail != null) {
                PanelMarker.replaceKeeping(jailLocal, newJail);
                written.add(new Step(jailLocal, jailLocal, jail));
            }
            // 4. newsyslog
            if (Files.exists(oldNewsyslog, LinkOption.NOFOLLOW_LINKS)) {
                String f = Files.readString(oldNewsyslog, StandardCharsets.UTF_8);
                Files.move(oldNewsyslog, newNewsyslog, StandardCopyOption.ATOMIC_MOVE);
                newsyslogMoved = true;
                String n = PanelMarker.current(f, "newsyslogHeaders").replace(oldLog, newLog);
                if (!n.equals(f)) {
                    PanelMarker.replaceKeeping(newNewsyslog, n);
                    written.add(new Step(newNewsyslog, newNewsyslog, f));
                }
            }
        } catch (IOException | RuntimeException e) {
            String back = putBack(movedLogs, written, filterMoved ? new Path[] {oldFilter, newFilter} : null,
                    newsyslogMoved ? new Path[] {oldNewsyslog, newNewsyslog} : null);
            return new Report(Outcome.ROLLED_BACK, "moving failed (" + e.getMessage() + ")" + back);
        }

        if (!sv.running())
            return new Report(Outcome.DONE, oldName + " -> " + newName + " (fail2ban is not running: it reads the new names when it starts)");
        String problem = sv.test();
        if (problem == null) {
            if (section && !sv.moveState(oldName, newName, oldLog, newLog))
                LOGGER.warning("[AuthJailRename] the bans of " + oldName + " were not carried over: they expire within the hour");
            problem = sv.reload();
            if (problem == null && section && !sv.jailExists(newName)) problem = "fail2ban has no jail " + newName + " after the reload";
        }
        if (problem != null) {
            String back = putBack(movedLogs, written, filterMoved ? new Path[] {oldFilter, newFilter} : null,
                    newsyslogMoved ? new Path[] {oldNewsyslog, newNewsyslog} : null);
            sv.reload();
            return new Report(Outcome.ROLLED_BACK, problem + back);
        }
        return new Report(Outcome.DONE, oldName + " -> " + newName + ": log " + newLog + (movedLogs.size() > 1 ? " (with "
                + (movedLogs.size() - 1) + " rotated copies)" : "") + ", filter, jail.local, newsyslog; fail2ban reloaded");
    }

    private static String putBack(List<Path[]> logs, List<Step> written, Path[] filter, Path[] newsyslog) {
        List<String> problems = new ArrayList<>();
        for (int i = written.size() - 1; i >= 0; i--) {
            Step s = written.get(i);
            try { PanelMarker.replaceKeeping(s.to(), s.before()); } catch (IOException e) { problems.add(s.to() + ": " + e.getMessage()); }
        }
        for (Path[] p : new Path[][] {newsyslog, filter}) {
            if (p == null) continue;
            try { Files.move(p[1], p[0], StandardCopyOption.ATOMIC_MOVE); } catch (IOException e) { problems.add(p[1] + ": " + e.getMessage()); }
        }
        for (Path[] l : logs) {
            try { Files.move(l[1], l[0], StandardCopyOption.ATOMIC_MOVE); } catch (IOException e) { problems.add(l[1] + ": " + e.getMessage()); }
        }
        return problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems);
    }

    static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);
        private static final Duration LONG = Duration.ofSeconds(120);

        @Override public boolean running() {
            return Shell.resolve("fail2ban-client") != null && Shell.run(SHORT, "fail2ban-client", "ping").success();
        }
        @Override public String test() {
            Shell.Result r = Shell.run(LONG, "fail2ban-client", "-t");
            return r.success() ? null : r.outputTrim();
        }
        @Override public String reload() {
            Shell.Result r = Shell.run(LONG, "fail2ban-client", "reload");
            return r.success() ? null : r.outputTrim();
        }
        @Override public boolean jailExists(String jail) {
            Shell.Result r = Shell.run(SHORT, "fail2ban-client", "status", jail);
            return r.success() && !r.output().contains("does not exist");
        }
        @Override public boolean moveState(String from, String to, String fromLog, String toLog) {
            return PublicSurfaceRename.moveFail2banJailState(from, to, fromLog, toLog, "AuthJailRename");
        }
    }
}
