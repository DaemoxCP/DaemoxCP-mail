package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * All'avvio: la superficie pubblica sulla 443 passa da "mailpanel-pubblico" a "mailpanel-public"
 * sui server installati prima della rinomina (r26, 30/10/2026).
 *
 * <p>PathMigration sposta i file che legge solo il pannello. Questi no: il nome viaggia fra tre
 * servizi. nginx include NOME.conf e scrive /var/log/nginx/NOME-access.log; fail2ban legge quel
 * log con filter.d/NOME.conf e jail.d/NOME.conf, e banna in pf nell'ancora f2b/NOME, tabella
 * f2b-NOME. Se se ne sposta uno solo la jail guarda un log che nessuno scrive piu', e non banna
 * niente senza dare nessun errore. Quindi tutto o niente.
 *
 * <p>Come si comporta:
 * <ul>
 *   <li>niente col nome vecchio: non fa niente, e non lancia neanche nginx -T (e' il caso di
 *       ogni avvio dopo il primo);</li>
 *   <li>un file vecchio che non ha scritto il pannello (manca la firma, vedi PanelMarker), il
 *       nome nuovo gia' presente accanto al vecchio, o due file vecchi in due cartelle di nginx:
 *       non tocca niente e lo scrive nel log, come PathMigration: scegliere non e' compito suo;</li>
 *   <li>altrimenti: sposta il log con le sue copie ruotate e i tre file cambiando il nome dentro;
 *       poi nginx -t e reload di nginx; sposta lo stato della jail nel database di fail2ban; reload
 *       di fail2ban, e chiede a fail2ban se la jail nuova c'e'. Al primo passo che fallisce
 *       rimette tutto com'era, stato compreso, e ricarica: al prossimo avvio ci riprova.</li>
 * </ul>
 *
 * <p>Il contenuto dei file vecchi resta quello, cambiato solo nel nome e nella firma (che passa
 * all'inglese come fa PanelMarker per i file gia' rinominati): e' una rinomina, non una
 * riparazione (quella la fanno installJail e BanActionRepair). Nei file scritti dal pannello il
 * nome vecchio compare solo dove e' un nome.
 *
 * <p>Con la superficie si sposta anche la cartella dei suoi file, /var/db/mailpanel/pubblico ->
 * public: nginx la legge (alias .../mta-sts.txt), quindi non sta in PathMigration ma qui, nello
 * stesso tutto-o-niente, e il percorso dentro il file di nginx cambia con lei. Misurato sul server
 * vero il 31/10/2026: con la cartella spostata da PathMigration e il file di nginx che citava
 * ancora quella vecchia, la politica MTA-STS sarebbe diventata un 404. Se la cartella e' gia'
 * quella nuova e il file di nginx (gia' rinominato) cita ancora la vecchia, si riscrive solo lui.
 *
 * <p>I ban: fail2ban li tiene per jail, nel suo database, e quando una jail parte rimette quelli
 * non ancora scaduti. Una jail con un altro nome partirebbe vuota. Quindi prima del reload si
 * passano alla jail nuova, nel database, i ban e la posizione raggiunta nel log: la jail nuova li
 * riprende col tempo che restava, e non rilegge da capo il log gia' letto. NON si ribannano con
 * "banip": ogni ban scrive una riga «Ban» nel log di fail2ban, e la jail recidive le conta (tre in
 * un giorno: una settimana su tutte le porte). Ribannare per una rinomina avrebbe potuto chiudere
 * fuori per una settimana, posta compresa, un indirizzo che aveva gia' due ban: e' successo al Mac
 * nella prova sulla VM del 30/10/2026. Se il database non si puo' aggiornare la rinomina va avanti
 * lo stesso, e i ban della jail vecchia scadono entro l'ora.
 */
public final class PublicSurfaceRename {

    private static final Logger LOGGER = Logger.getLogger(PublicSurfaceRename.class.getName());

    /** Il nome di prima, dal file di dati: serve solo a trovarlo sul disco. */
    static final String OLD_NAME = LegacyNames.single("publicSurface");
    static final String NEW_NAME = WebProtection.NAME;
    /** La cartella dei file pubblici: quella di prima dal file di dati, quella di adesso da WebProtection. */
    static final String OLD_FOLDER = LegacyNames.single("publicFolder");
    static final String NEW_FOLDER = WebProtection.PUBLIC_DIR;

    private PublicSurfaceRename() {}

    enum Outcome { NOTHING, SAME_NAMES, NOT_OURS, BOTH_NAMES, AMBIGUOUS, NGINX_UNREADABLE, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Dove stanno i file: fissi sul server, cartelle temporanee nella prova. */
    record Places(Path f2bDir, Path logDir, Path defaultNginxFolder, Path oldFolder, Path newFolder) {}

    /** Quello che serve da nginx e fail2ban, separato per provarlo senza i servizi veri. */
    interface Services {
        /** Le cartelle che nginx include (nginx -T); vuota senza nginx, null se nginx non risponde. */
        List<String> nginxFolders();
        boolean nginxRunning();
        Shell.Result nginxTest();
        Shell.Result nginxReload();
        boolean fail2banRunning();
        Shell.Result fail2banReload();
        /** Gli indirizzi bannati dalla jail, o null se fail2ban non ha quella jail. */
        List<String> banned(String jail);
        /**
         * Nel database di fail2ban, i ban e la posizione nel log della jail {@code from} passano a
         * {@code to} (col log {@code toLog} al posto di {@code fromLog}). Falso se non si e' potuto.
         */
        boolean moveJailState(String from, String to, String fromLog, String toLog);
    }

    public static void ensureAtBoot() {
        try {
            Places at = new Places(Path.of(WebProtection.F2B_DIR), Path.of(WebProtection.LOG_DIR),
                    Path.of(WebProtection.PROPOSED_FOLDER), OLD_FOLDER.isEmpty() ? null : Path.of(OLD_FOLDER), Path.of(NEW_FOLDER));
            Report r = migrate(at, new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[PublicSurfaceRename] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[PublicSurfaceRename] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) throws IOException {
        if (OLD_NAME.isEmpty()) return new Report(Outcome.NOTHING, "");
        // Una passata di rinomina sul codice puo' cambiare ANCHE il nome vecchio qui dentro:
        // senza questa guardia il risultato sarebbe un "niente da fare" falso.
        if (OLD_NAME.equals(NEW_NAME))
            return new Report(Outcome.SAME_NAMES, "old and new name are the same: the old name was renamed too");

        Path oldJail = at.f2bDir().resolve("jail.d").resolve(OLD_NAME + ".conf");
        Path newJail = oldJail.resolveSibling(NEW_NAME + ".conf");
        Path oldFilter = at.f2bDir().resolve("filter.d").resolve(OLD_NAME + ".conf");
        List<Path> oldLogs = logsNamed(at.logDir(), OLD_NAME);
        Path defaultConf = at.defaultNginxFolder().resolve(OLD_NAME + ".conf");
        Path oldFolder = at.oldFolder(), newFolder = at.newFolder();
        boolean folderMoves = oldFolder != null && exists(oldFolder);
        Path defaultNewConf = at.defaultNginxFolder().resolve(NEW_NAME + ".conf");
        boolean staleDefault = oldFolder != null && exists(defaultNewConf)
                && citesFolder(Files.readString(defaultNewConf, StandardCharsets.UTF_8), oldFolder);
        if (!exists(oldJail) && !exists(oldFilter) && oldLogs.isEmpty() && !exists(defaultConf) && !folderMoves && !staleDefault)
            return new Report(Outcome.NOTHING, "");

        // Il file di nginx sta in una delle cartelle che nginx include: si chiede a nginx quali.
        List<String> folders = sv.nginxFolders();
        if (folders == null)
            return new Report(Outcome.NGINX_UNREADABLE, "nginx -T failed: nothing moved, retrying at the next start");
        Set<Path> confs = new LinkedHashSet<>();
        for (String f : folders) {
            Path c = Path.of(f).resolve(OLD_NAME + ".conf");
            if (exists(c)) confs.add(c);
        }
        if (exists(defaultConf)) confs.add(defaultConf);
        if (confs.size() > 1)
            return new Report(Outcome.AMBIGUOUS, "more than one " + OLD_NAME + ".conf for nginx " + confs + ": nothing moved");
        Path oldConf = confs.isEmpty() ? null : confs.iterator().next();
        // Il file col nome nuovo che cita ancora la cartella vecchia: si riscrive al suo posto.
        Path staleConf = null;
        if (oldConf == null && oldFolder != null) {
            Set<Path> stale = new LinkedHashSet<>();
            for (String f : folders) {
                Path c = Path.of(f).resolve(NEW_NAME + ".conf");
                if (exists(c) && citesFolder(Files.readString(c, StandardCharsets.UTF_8), oldFolder)) stale.add(c);
            }
            if (staleDefault) stale.add(defaultNewConf);
            if (stale.size() > 1)
                return new Report(Outcome.AMBIGUOUS, "more than one " + NEW_NAME + ".conf for nginx " + stale + ": nothing moved");
            staleConf = stale.isEmpty() ? null : stale.iterator().next();
        }

        // Le coppie da spostare: vecchio -> nuovo, e come cambia il contenuto (null: non cambia).
        java.util.function.UnaryOperator<String> rewrite = c -> renamed(c, oldFolder, newFolder);
        List<Move> moves = new ArrayList<>();
        for (Path p : oldLogs)
            moves.add(new Move(p, p.resolveSibling(NEW_NAME + p.getFileName().toString().substring(OLD_NAME.length())), null));
        if (folderMoves) moves.add(new Move(oldFolder, newFolder, null));
        if (oldConf != null) moves.add(new Move(oldConf, oldConf.resolveSibling(NEW_NAME + ".conf"), rewrite));
        if (staleConf != null) moves.add(new Move(staleConf, staleConf, rewrite));
        if (exists(oldFilter)) moves.add(new Move(oldFilter, oldFilter.resolveSibling(NEW_NAME + ".conf"), rewrite));
        boolean jailMoves = exists(oldJail);
        if (jailMoves) moves.add(new Move(oldJail, newJail, rewrite));
        boolean confTouched = oldConf != null || staleConf != null;

        // Prima si guarda tutto, poi si tocca: nessun passo parte se uno solo non puo' partire.
        for (Move m : moves) {
            if (!m.from().equals(m.to()) && exists(m.to()))
                return new Report(Outcome.BOTH_NAMES, "both " + m.from() + " and " + m.to() + " exist: nothing moved");
            if (m.rewrites() && !PanelMarker.writtenByPanel(Files.readString(m.from(), StandardCharsets.UTF_8)))
                return new Report(Outcome.NOT_OURS, m.from() + " was not written by the panel: nothing moved, rename it by hand");
        }

        boolean f2bRunning = (jailMoves || exists(oldFilter)) && sv.fail2banRunning();
        List<String> bans = new ArrayList<>();
        if (f2bRunning) {
            List<String> b = sv.banned(OLD_NAME);
            if (b != null) bans.addAll(b);
        }
        String oldLog = at.logDir().resolve(OLD_NAME + "-access.log").toString();
        String newLog = at.logDir().resolve(NEW_NAME + "-access.log").toString();
        boolean stateMoved = false;
        boolean nginxRunning = confTouched && sv.nginxRunning();

        Deque<Move> done = new ArrayDeque<>();
        try {
            try {
                for (Move m : moves) { m.apply(); done.push(m); }
            } catch (IOException e) {
                return rollBack(done, sv, false, false, "could not move the files: " + e.getMessage());
            }

            if (confTouched) {
                Shell.Result t = sv.nginxTest();
                if (!t.success()) return rollBack(done, sv, false, false, "nginx -t refused the renamed file: " + t.outputTrim());
                if (nginxRunning) {
                    Shell.Result rl = sv.nginxReload();
                    if (!rl.success()) return rollBack(done, sv, true, false, "nginx reload failed: " + rl.outputTrim());
                }
            }
            if (f2bRunning) {
                if (jailMoves) stateMoved = sv.moveJailState(OLD_NAME, NEW_NAME, oldLog, newLog);
                Shell.Result rl = sv.fail2banReload();
                if (!rl.success()) {
                    if (stateMoved) sv.moveJailState(NEW_NAME, OLD_NAME, newLog, oldLog);
                    return rollBack(done, sv, nginxRunning, true, "fail2ban reload failed: " + rl.outputTrim());
                }
                if (jailMoves && sv.banned(NEW_NAME) == null) {
                    if (stateMoved) sv.moveJailState(NEW_NAME, OLD_NAME, newLog, oldLog);
                    return rollBack(done, sv, nginxRunning, true, "fail2ban does not report the jail " + NEW_NAME + " after the reload");
                }
            }
        } catch (RuntimeException e) {
            if (stateMoved) sv.moveJailState(NEW_NAME, OLD_NAME, newLog, oldLog);
            return rollBack(done, sv, nginxRunning, f2bRunning, "unexpected error: " + e);
        }

        StringBuilder d = new StringBuilder("moved");
        for (Move m : moves) d.append(' ').append(m.from()).append(" -> ").append(m.to().getFileName()).append(';');
        if (f2bRunning && sv.banned(OLD_NAME) != null)
            d.append(" WARNING: fail2ban still reports the old jail ").append(OLD_NAME).append(';');
        if (f2bRunning && jailMoves && !stateMoved)
            d.append(" WARNING: fail2ban database not updated, ").append(bans.size())
             .append(" bans of ").append(OLD_NAME).append(" not carried over (they expire within the hour);");
        else if (!bans.isEmpty()) {
            List<String> now = sv.banned(NEW_NAME);
            int kept = 0;
            if (now != null) for (String ip : bans) if (now.contains(ip)) kept++;
            d.append(' ').append(kept).append(" of ").append(bans.size()).append(" bans kept by ").append(NEW_NAME);
            if (kept < bans.size()) d.append(" (WARNING: some were not)");
        }
        return new Report(Outcome.DONE, d.toString());
    }

    /**
     * Rimette ogni file com'era, nell'ordine inverso, e ricarica i servizi gia' ricaricati. Lo
     * stato della jail nel database di fail2ban l'ha gia' rimesso il chiamante: ripartendo, la
     * jail vecchia riprende i suoi ban da li'.
     */
    private static Report rollBack(Deque<Move> done, Services sv,
                                   boolean reloadNginx, boolean reloadF2b, String why) {
        List<String> problems = new ArrayList<>();
        while (!done.isEmpty()) {
            Move m = done.pop();
            try { m.undo(); } catch (IOException e) { problems.add(m.from() + ": " + e.getMessage()); }
        }
        if (reloadNginx) {
            Shell.Result r = sv.nginxReload();
            if (!r.success()) problems.add("nginx reload: " + r.outputTrim());
        }
        if (reloadF2b) {
            Shell.Result r = sv.fail2banReload();
            if (!r.success()) problems.add("fail2ban reload: " + r.outputTrim());
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    /**
     * Uno spostamento (un file o una cartella), con quello che serve per disfarlo. Non segue i link.
     * from uguale a to: il file resta dov'e' e cambia solo dentro.
     */
    private static final class Move {
        private final Path from, to;
        private final java.util.function.UnaryOperator<String> rewrite;
        private String before;

        Move(Path from, Path to, java.util.function.UnaryOperator<String> rewrite) { this.from = from; this.to = to; this.rewrite = rewrite; }
        Path from() { return from; }
        Path to() { return to; }
        boolean rewrites() { return rewrite != null; }

        void apply() throws IOException {
            if (rewrite != null) before = Files.readString(from, StandardCharsets.UTF_8);
            // Si sposta il file invece di scriverne uno nuovo: proprietario e permessi restano.
            if (!from.equals(to)) Files.move(from, to);
            if (rewrite != null) Files.writeString(to, rewrite.apply(before), StandardCharsets.UTF_8);
        }

        void undo() throws IOException {
            if (rewrite != null) Files.writeString(to, before, StandardCharsets.UTF_8);
            if (!from.equals(to)) Files.move(to, from);
        }
    }

    /** Il contenuto col nome nuovo, la firma di adesso e, se c'e', la cartella nuova al posto della vecchia. */
    static String renamed(String content, Path oldFolder, Path newFolder) {
        String c = content.replace(OLD_NAME, NEW_NAME);
        if (oldFolder != null && newFolder != null)
            c = folderReference(oldFolder).matcher(c).replaceAll(Matcher.quoteReplacement(newFolder.toString()));
        return PanelMarker.current(c, PanelMarker.SIGNATURE);
    }

    /** La cartella come percorso intero: seguita da "/", da un separatore o dalla fine, non da altre lettere. */
    private static Pattern folderReference(Path folder) {
        return Pattern.compile(Pattern.quote(folder.toString()) + "(?=[/;\\s\"']|$)", Pattern.MULTILINE);
    }

    static boolean citesFolder(String content, Path folder) {
        return folderReference(folder).matcher(content).find();
    }

    /** NOME-access.log e le sue copie ruotate (NOME-access.log.0.bz2, ...), non quelle di altri. */
    static List<Path> logsNamed(Path dir, String name) throws IOException {
        if (!Files.isDirectory(dir)) return List.of();
        String log = name + "-access.log";
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> {
                String f = p.getFileName().toString();
                return (f.equals(log) || f.startsWith(log + ".")) && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS);
            }).sorted().toList();
        }
    }

    private static boolean exists(Path p) {
        return Files.exists(p, LinkOption.NOFOLLOW_LINKS);
    }

    /** Il file del database dall'uscita di "fail2ban-client get dbfile", o null se non ne usa uno. */
    static String fail2banDatabase(String output) {
        if (output == null) return null;
        for (String line : output.split("\n")) {
            String t = line.replaceFirst("^[`|\\s-]+", "").trim();
            if (t.startsWith("/") && !t.contains(" ")) return t;
        }
        return null;
    }

    private static final Pattern BANNED = Pattern.compile("Banned IP list:\\s*(.*)");

    /** Gli indirizzi dalla riga "Banned IP list:" di fail2ban-client status. */
    static List<String> bannedFrom(String status) {
        Matcher m = BANNED.matcher(status == null ? "" : status);
        if (!m.find()) return List.of();
        String list = m.group(1).trim();
        return list.isEmpty() ? List.of() : Arrays.asList(list.split("\\s+"));
    }

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(20);
        private static final Duration LONG = Duration.ofSeconds(90);

        @Override public List<String> nginxFolders() {
            if (Shell.resolve("nginx") == null) return List.of();
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? WebProtection.includedFolders(r.output()) : null;
        }
        // "one": funzionano anche se nginx_enable non e' YES in rc.conf.
        @Override public boolean nginxRunning() { return Shell.run(SHORT, "service", "nginx", "onestatus").success(); }
        @Override public Shell.Result nginxTest() { return Shell.run(SHORT, "nginx", "-t"); }
        @Override public Shell.Result nginxReload() { return Shell.run(SHORT, "service", "nginx", "onereload"); }
        @Override public boolean fail2banRunning() {
            return Shell.resolve("fail2ban-client") != null && Shell.run(SHORT, "fail2ban-client", "ping").success();
        }
        @Override public Shell.Result fail2banReload() { return Shell.run(LONG, "fail2ban-client", "reload"); }
        @Override public List<String> banned(String jail) {
            Shell.Result r = Shell.run(SHORT, "fail2ban-client", "status", jail);
            // Come in BanActionRepair: "non esiste" si legge anche nel testo, non solo nel codice.
            return r.success() && !r.output().contains("does not exist") ? bannedFrom(r.output()) : null;
        }
        @Override public boolean moveJailState(String from, String to, String fromLog, String toLog) {
            String db = fail2banDatabase(Shell.run(SHORT, "fail2ban-client", "get", "dbfile").output());
            if (db == null) {
                LOGGER.warning("[PublicSurfaceRename] fail2ban has no database file: bans not carried over");
                return false;
            }
            try (java.sql.Connection c = java.sql.DriverManager.getConnection("jdbc:sqlite:" + db);
                 java.sql.Statement st = c.createStatement()) {
                // fail2ban tiene il database aperto: si aspetta il suo turno invece di fallire.
                st.execute("PRAGMA busy_timeout = 10000");
                c.setAutoCommit(false);
                try {
                    // Lo schema e' quello di fail2ban (server/database.py): jails, bips, bans, logs.
                    exec(c, "INSERT OR IGNORE INTO jails(name, enabled) VALUES (?, 0)", to);
                    exec(c, "UPDATE OR IGNORE bips SET jail = ? WHERE jail = ?", to, from);
                    exec(c, "UPDATE OR IGNORE bans SET jail = ? WHERE jail = ?", to, from);
                    exec(c, "UPDATE OR IGNORE logs SET jail = ?, path = ? WHERE jail = ? AND path = ?", to, toLog, from, fromLog);
                    c.commit();
                    return true;
                } catch (java.sql.SQLException e) {
                    c.rollback();
                    throw e;
                }
            } catch (Exception e) {
                LOGGER.warning("[PublicSurfaceRename] cannot move the state of " + from + " to " + to
                        + " in " + db + ": " + e.getMessage());
                return false;
            }
        }

        private static void exec(java.sql.Connection c, String sql, String... args) throws java.sql.SQLException {
            try (java.sql.PreparedStatement ps = c.prepareStatement(sql)) {
                for (int i = 0; i < args.length; i++) ps.setString(i + 1, args[i]);
                ps.executeUpdate();
            }
        }
    }
}
