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
 *   <li>un file vecchio che non ha scritto il pannello (manca «Scritto dal pannello»), il nome
 *       nuovo gia' presente accanto al vecchio, o due file vecchi in due cartelle di nginx: non
 *       tocca niente e lo scrive nel log, come PathMigration: scegliere non e' compito suo;</li>
 *   <li>altrimenti: si segna gli indirizzi bannati dalla jail vecchia, sposta il log con le sue
 *       copie ruotate, sposta i tre file cambiando il nome dentro; poi nginx -t, reload di nginx,
 *       reload di fail2ban, e chiede a fail2ban se la jail nuova c'e'. Al primo passo che fallisce
 *       rimette tutto com'era e ricarica: al prossimo avvio ci riprova. Per ultimo rimette i ban
 *       nella jail nuova.</li>
 * </ul>
 *
 * <p>Il contenuto dei file vecchi resta quello, cambiato solo nel nome: e' una rinomina, non una
 * riparazione (quella la fanno installJail e BanActionRepair). Nei file scritti dal pannello il
 * nome vecchio compare solo dove e' un nome.
 *
 * <p>I ban: fail2ban li tiene per jail, una jail con un altro nome parte vuota, e fermando la
 * vecchia l'azione pf ne svuota la tabella. Rimessi nella nuova ripartono da capo (un'ora): meglio
 * che riaprire subito la porta a chi era appena stato fermato.
 */
public final class PublicSurfaceRename {

    private static final Logger LOGGER = Logger.getLogger(PublicSurfaceRename.class.getName());

    /** Il nome di prima. Esiste solo per trovarlo sul disco: il codice usa WebProtection.NAME. */
    static final String OLD_NAME = "mailpanel-pubblico";
    static final String NEW_NAME = WebProtection.NAME;

    /** La riga che il pannello scrive in testa ai tre file, fin dalla prima versione. */
    static final String MARKER = "Scritto dal pannello";

    private PublicSurfaceRename() {}

    enum Outcome { NOTHING, SAME_NAMES, NOT_OURS, BOTH_NAMES, AMBIGUOUS, NGINX_UNREADABLE, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Dove stanno i file: fissi sul server, cartelle temporanee nella prova. */
    record Places(Path f2bDir, Path logDir, Path defaultNginxFolder) {}

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
        Shell.Result ban(String jail, List<String> ips);
    }

    public static void ensureAtBoot() {
        try {
            Places at = new Places(Path.of(WebProtection.F2B_DIR), Path.of(WebProtection.LOG_DIR),
                    Path.of(WebProtection.PROPOSED_FOLDER));
            Report r = migrate(at, new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[PublicSurfaceRename] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[PublicSurfaceRename] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) throws IOException {
        // Una passata di rinomina sul codice puo' cambiare ANCHE il nome vecchio qui dentro:
        // senza questa guardia il risultato sarebbe un "niente da fare" falso.
        if (OLD_NAME.equals(NEW_NAME))
            return new Report(Outcome.SAME_NAMES, "old and new name are the same: the old name was renamed too");

        Path oldJail = at.f2bDir().resolve("jail.d").resolve(OLD_NAME + ".conf");
        Path newJail = oldJail.resolveSibling(NEW_NAME + ".conf");
        Path oldFilter = at.f2bDir().resolve("filter.d").resolve(OLD_NAME + ".conf");
        List<Path> oldLogs = logsNamed(at.logDir(), OLD_NAME);
        Path defaultConf = at.defaultNginxFolder().resolve(OLD_NAME + ".conf");
        if (!exists(oldJail) && !exists(oldFilter) && oldLogs.isEmpty() && !exists(defaultConf))
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

        // Le coppie da spostare: vecchio -> nuovo, e se dentro si cambia il nome.
        List<Move> moves = new ArrayList<>();
        for (Path p : oldLogs)
            moves.add(new Move(p, p.resolveSibling(NEW_NAME + p.getFileName().toString().substring(OLD_NAME.length())), false));
        if (oldConf != null) moves.add(new Move(oldConf, oldConf.resolveSibling(NEW_NAME + ".conf"), true));
        if (exists(oldFilter)) moves.add(new Move(oldFilter, oldFilter.resolveSibling(NEW_NAME + ".conf"), true));
        boolean jailMoves = exists(oldJail);
        if (jailMoves) moves.add(new Move(oldJail, newJail, true));

        // Prima si guarda tutto, poi si tocca: nessun passo parte se uno solo non puo' partire.
        for (Move m : moves) {
            if (exists(m.to()))
                return new Report(Outcome.BOTH_NAMES, "both " + m.from() + " and " + m.to() + " exist: nothing moved");
            if (m.renameInside() && !Files.readString(m.from(), StandardCharsets.UTF_8).contains(MARKER))
                return new Report(Outcome.NOT_OURS, m.from() + " was not written by the panel: nothing moved, rename it by hand");
        }

        boolean f2bRunning = (jailMoves || exists(oldFilter)) && sv.fail2banRunning();
        List<String> bans = new ArrayList<>();
        if (f2bRunning) {
            List<String> b = sv.banned(OLD_NAME);
            if (b != null) bans.addAll(b);
        }
        boolean nginxRunning = oldConf != null && sv.nginxRunning();

        Deque<Move> done = new ArrayDeque<>();
        try {
            try {
                for (Move m : moves) { m.apply(); done.push(m); }
            } catch (IOException e) {
                return rollBack(done, bans, sv, false, false, "could not move the files: " + e.getMessage());
            }

            if (oldConf != null) {
                Shell.Result t = sv.nginxTest();
                if (!t.success()) return rollBack(done, bans, sv, false, false, "nginx -t refused the renamed file: " + t.outputTrim());
                if (nginxRunning) {
                    Shell.Result rl = sv.nginxReload();
                    if (!rl.success()) return rollBack(done, bans, sv, true, false, "nginx reload failed: " + rl.outputTrim());
                }
            }
            if (f2bRunning) {
                Shell.Result rl = sv.fail2banReload();
                if (!rl.success()) return rollBack(done, bans, sv, nginxRunning, true, "fail2ban reload failed: " + rl.outputTrim());
                if (jailMoves && sv.banned(NEW_NAME) == null)
                    return rollBack(done, bans, sv, nginxRunning, true, "fail2ban does not report the jail " + NEW_NAME + " after the reload");
            }
        } catch (RuntimeException e) {
            return rollBack(done, bans, sv, nginxRunning, f2bRunning, "unexpected error: " + e);
        }

        StringBuilder d = new StringBuilder("moved");
        for (Move m : moves) d.append(' ').append(m.from()).append(" -> ").append(m.to().getFileName()).append(';');
        if (f2bRunning && sv.banned(OLD_NAME) != null)
            d.append(" WARNING: fail2ban still reports the old jail ").append(OLD_NAME).append(';');
        if (!bans.isEmpty()) {
            sv.ban(NEW_NAME, bans);
            List<String> now = sv.banned(NEW_NAME);
            int kept = 0;
            if (now != null) for (String ip : bans) if (now.contains(ip)) kept++;
            d.append(' ').append(kept).append(" of ").append(bans.size()).append(" bans carried over to ").append(NEW_NAME);
            if (kept < bans.size()) d.append(" (WARNING: some were not)");
        }
        return new Report(Outcome.DONE, d.toString());
    }

    /**
     * Rimette ogni file com'era, nell'ordine inverso, e ricarica i servizi gia' ricaricati. Se
     * fail2ban aveva gia' fermato la jail vecchia, ripartendo e' vuota: i ban si rimettono anche li'.
     */
    private static Report rollBack(Deque<Move> done, List<String> bans, Services sv,
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
            else if (!bans.isEmpty()) sv.ban(OLD_NAME, bans);
        }
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back"
                + (problems.isEmpty() ? "" : " EXCEPT: " + String.join("; ", problems)));
    }

    /** Uno spostamento, con quello che serve per disfarlo. Non segue i link. */
    private static final class Move {
        private final Path from, to;
        private final boolean renameInside;
        private String before;

        Move(Path from, Path to, boolean renameInside) { this.from = from; this.to = to; this.renameInside = renameInside; }
        Path from() { return from; }
        Path to() { return to; }
        boolean renameInside() { return renameInside; }

        void apply() throws IOException {
            if (renameInside) before = Files.readString(from, StandardCharsets.UTF_8);
            // Si sposta il file invece di scriverne uno nuovo: proprietario e permessi restano.
            Files.move(from, to);
            if (renameInside) Files.writeString(to, renamed(before), StandardCharsets.UTF_8);
        }

        void undo() throws IOException {
            if (renameInside) Files.writeString(to, before, StandardCharsets.UTF_8);
            Files.move(to, from);
        }
    }

    static String renamed(String content) {
        return content.replace(OLD_NAME, NEW_NAME);
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
        @Override public Shell.Result ban(String jail, List<String> ips) {
            List<String> cmd = new ArrayList<>(List.of("fail2ban-client", "set", jail, "banip"));
            cmd.addAll(ips);
            return Shell.run(LONG, cmd.toArray(new String[0]));
        }
    }
}
