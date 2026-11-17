package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * All'avvio del servizio: le cartelle dei dati del pannello prendono il nome nuovo (DaemoxCP Mail, 17/11/2026).
 *
 * <p>Fino a questa versione il pannello aveva due cartelle in /var/db: /var/db/mailpanel (i suoi registri, lo stato
 * degli aggiornamenti, le chiavi della webmail e di Dovecot, le sessioni PHP di Roundcube, i file pubblici di
 * MTA-STS) e /var/db/mail-panel (la lista dei ban permanenti, le zone geografiche del firewall, le copie di
 * fail2ban). Diventano una sola, /var/db/daemoxcp-mail: nessun nome dell'una c'e' anche nell'altra.
 *
 * <p>Non e' una rinomina del solo pannello: le due cartelle le leggono anche altri servizi, e un percorso vecchio
 * rimasto in un loro file diventa un errore senza avviso. Misurato nell'inventario del 17/11/2026:
 * <ul>
 *   <li>php.ini, session.save_path: le sessioni di Roundcube (php-fpm le cerca dove diceva all'avvio);</li>
 *   <li>il file di nginx della superficie pubblica, alias del file di MTA-STS: un 404 e la politica sparisce;</li>
 *   <li>/etc/pf.conf (la tabella permaban) e l'ancora panel-fw (le zone geografiche): li rilegge il prossimo
 *       caricamento di pf, che senza il file fallirebbe intero;</li>
 *   <li>l'azione dei ban permanenti di fail2ban, e lo script di avvio del pannello (il suo registro).</li>
 * </ul>
 * Quindi tutto insieme: si spostano le cartelle, si riscrivono i percorsi in ogni file che li cita fra quelli dei
 * servizi coinvolti, si controlla ogni servizio toccato (php-fpm -t, nginx -t, pfctl -n, doveconf, postfix check) e
 * si ricaricano quelli che leggono i percorsi solo all'avvio (php-fpm, nginx, fail2ban, Dovecot, Postfix). Poi si
 * verifica che i file a cui puntano gli alias di nginx li possa leggere www. Al primo passo che non torna si rimette
 * tutto com'era, file e cartelle, e si ricarica: al prossimo avvio si riprova.
 *
 * <p>pf non si ricarica: la tabella permaban e le zone sono gia' nel kernel, e il percorso conta solo al prossimo
 * caricamento, che a quel punto trova il file nuovo. Un ricaricamento di pf in piu' all'avvio non serve a niente.
 *
 * <p>Si cambia un percorso solo dove e' intero: "/var/db/mailpanel" seguito da "/" o dalla fine della parola, mai
 * "/var/db/mailpanel-qualcosa". I nomi di prima stanno in legacy-names.json (sezione "dataFolders").
 */
public final class DataFolderRename {

    private static final Logger LOGGER = Logger.getLogger(DataFolderRename.class.getName());

    /** La cartella di adesso, dal file di dati: e' il secondo nome di ogni coppia. */
    static final String NEW = "/var/db/" + Product.SLUG;

    /** I file che possono citare le cartelle, uno per uno. */
    static final List<String> FILES = List.of(
            "/usr/local/etc/php.ini", "/usr/local/etc/php-fpm.conf", "/etc/pf.conf",
            "/usr/local/etc/fail2ban/jail.local", "/usr/local/etc/nginx/nginx.conf",
            "/usr/local/etc/postfix/main.cf", "/usr/local/etc/postfix/master.cf",
            "/usr/local/etc/dovecot/dovecot.conf", "/etc/rc.conf",
            "/usr/local/etc/rc.d/mailpanel", "/usr/local/etc/rc.d/" + Product.ID);

    /** Le cartelle i cui file (non le sottocartelle) possono citarle. */
    static final List<String> FOLDERS = List.of(
            "/usr/local/etc/php-fpm.d", "/etc/pf.anchors", "/usr/local/etc/newsyslog.conf.d",
            "/usr/local/etc/fail2ban/jail.d", "/usr/local/etc/fail2ban/action.d", "/usr/local/etc/fail2ban/filter.d",
            "/usr/local/www/roundcube/config", "/usr/local/etc/nginx/conf.d", "/usr/local/etc/dovecot/conf.d",
            "/usr/local/etc/rspamd/local.d");

    enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Quello che serve dai servizi, separato per provarlo senza i servizi veri. */
    interface Services {
        /** Le cartelle che nginx include (nginx -T); vuota senza nginx, null se nginx non risponde. */
        List<String> nginxFolders();
        /** Il controllo della configurazione di un servizio: null se va bene, altrimenti cosa dice. */
        String test(Kind kind);
        /** Il ricaricamento: null se e' andato, altrimenti cosa dice. Un servizio spento non si ricarica. */
        String reload(Kind kind);
        /** Vero se l'utente www puo' leggere il file. */
        boolean readableByWww(Path file);
    }

    /** I servizi a cui appartiene un file, per sapere cosa controllare e cosa ricaricare. */
    enum Kind { PHP, NGINX, PF, FAIL2BAN, DOVECOT, POSTFIX, RSPAMD, OTHER }

    private DataFolderRename() {}

    public static void ensureAtBoot() {
        try {
            Report r = migrate(LegacyNames.pairs("dataFolders"), new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[DataFolderRename] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[DataFolderRename] failed: " + t);
        }
    }

    // ===================== funzioni pure =====================

    /** Il testo coi percorsi delle cartelle di prima sostituiti da quelli di adesso, solo dove il nome e' intero. */
    static String rewritten(String text, List<String[]> pairs) {
        String out = text;
        for (String[] p : pairs) {
            Pattern old = Pattern.compile(Pattern.quote(p[0]) + "(?![A-Za-z0-9_.-])");
            out = old.matcher(out).replaceAll(Matcher.quoteReplacement(p[1]));
        }
        return out;
    }

    /** A quale servizio appartiene un file, dal suo percorso. */
    static Kind kindOf(String path, Set<String> nginxFolders) {
        if (path.startsWith("/usr/local/etc/php")) return Kind.PHP;
        if (path.startsWith("/etc/pf.")) return Kind.PF;
        if (path.startsWith("/usr/local/etc/fail2ban/")) return Kind.FAIL2BAN;
        if (path.startsWith("/usr/local/etc/dovecot/")) return Kind.DOVECOT;
        if (path.startsWith("/usr/local/etc/postfix/")) return Kind.POSTFIX;
        if (path.startsWith("/usr/local/etc/rspamd/")) return Kind.RSPAMD;
        if (path.startsWith("/usr/local/etc/nginx/")) return Kind.NGINX;
        for (String f : nginxFolders) if (path.startsWith(f.endsWith("/") ? f : f + "/")) return Kind.NGINX;
        return Kind.OTHER;
    }

    /** Gli alias di nginx (il file a cui puntano) che stanno nella cartella di adesso. */
    static List<Path> aliasesInto(String nginxText) {
        List<Path> out = new ArrayList<>();
        Matcher m = Pattern.compile("(?m)^\\s*alias\\s+(" + Pattern.quote(NEW) + "/[^;\\s]+)\\s*;").matcher(nginxText);
        while (m.find()) out.add(Path.of(m.group(1)));
        return out;
    }

    // ===================== la migrazione =====================

    /** Un file cambiato: dove sta, com'era, com'e' adesso. */
    private record Changed(Path path, String before, String after, Kind kind) {}

    /** Una cartella o un file spostato, per poterlo rimettere. */
    private record Moved(Path from, Path to) {}

    static Report migrate(List<String[]> pairs, Services sv) {
        List<String[]> present = new ArrayList<>();
        for (String[] p : pairs) if (!p[0].equals(p[1]) && Files.exists(Path.of(p[0]), LinkOption.NOFOLLOW_LINKS)) present.add(p);
        if (present.isEmpty()) return new Report(Outcome.NOTHING, "");

        // Prima di toccare qualcosa: nessun nome di una cartella vecchia gia' presente in quella nuova.
        for (String[] p : present) {
            Path from = Path.of(p[0]), to = Path.of(p[1]);
            if (Files.isSymbolicLink(from) || !Files.isDirectory(from, LinkOption.NOFOLLOW_LINKS))
                return new Report(Outcome.LEFT, from + " is not a folder: left as it is");
            if (!Files.exists(to, LinkOption.NOFOLLOW_LINKS)) continue;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(from)) {
                for (Path c : ds) if (Files.exists(to.resolve(c.getFileName()), LinkOption.NOFOLLOW_LINKS))
                    return new Report(Outcome.LEFT, c + " and " + to.resolve(c.getFileName())
                            + " both exist: nothing moved, deciding which one counts is not a migration's job");
            } catch (IOException e) {
                return new Report(Outcome.LEFT, from + " cannot be read: " + e.getMessage());
            }
        }

        List<String> folders = sv.nginxFolders();
        if (folders == null) return new Report(Outcome.LEFT, "nginx -T failed: nothing moved, retrying at the next start");
        Set<String> nginxFolders = new LinkedHashSet<>(folders);

        // I file che citano le cartelle, con il testo nuovo: letti tutti prima di spostare qualcosa.
        Set<Path> candidates = new LinkedHashSet<>();
        for (String f : FILES) candidates.add(Path.of(f));
        Set<String> scan = new LinkedHashSet<>(FOLDERS);
        scan.addAll(nginxFolders);
        for (String d : scan) {
            Path dir = Path.of(d);
            if (!Files.isDirectory(dir)) continue;
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
                for (Path c : ds) candidates.add(c);
            } catch (IOException e) {
                return new Report(Outcome.LEFT, d + " cannot be read: " + e.getMessage());
            }
        }
        List<Changed> changes = new ArrayList<>();
        for (Path c : candidates) {
            try {
                if (!Files.isRegularFile(c) || Files.size(c) > 4L * 1024 * 1024) continue;
                Path real = c.toRealPath();
                String before = Files.readString(real, StandardCharsets.UTF_8);
                String after = rewritten(before, present);
                if (after.equals(before)) continue;
                if (changes.stream().anyMatch(x -> x.path().equals(real))) continue;
                changes.add(new Changed(real, before, after, kindOf(real.toString(), nginxFolders)));
            } catch (IOException | RuntimeException e) {
                // Un file che non si legge come testo (binario, codifica diversa) non cita le cartelle.
            }
        }

        List<Moved> moved = new ArrayList<>();
        List<Changed> written = new ArrayList<>();
        try {
            for (String[] p : present) moveFolder(Path.of(p[0]), Path.of(p[1]), moved);
            for (Changed c : changes) {
                PanelMarker.replaceKeeping(c.path(), c.after());
                written.add(c);
            }
        } catch (IOException | RuntimeException e) {
            String back = putBack(moved, written);
            return new Report(Outcome.ROLLED_BACK, "moving failed (" + e.getMessage() + ")" + back);
        }

        Set<Kind> touched = new LinkedHashSet<>();
        for (Changed c : changes) touched.add(c.kind());
        for (Kind k : touched) {
            if (k == Kind.OTHER) continue;
            String problem = sv.test(k);
            if (problem != null) {
                String back = putBack(moved, written);
                return new Report(Outcome.ROLLED_BACK, k + " refuses the new paths (" + problem + ")" + back);
            }
        }
        List<Kind> reloaded = new ArrayList<>();
        for (Kind k : touched) {
            if (k == Kind.OTHER || k == Kind.PF) continue;
            String problem = sv.reload(k);
            if (problem != null) {
                String back = putBack(moved, written);
                for (Kind r : reloaded) sv.reload(r);
                sv.reload(k);
                return new Report(Outcome.ROLLED_BACK, k + " did not reload (" + problem + ")" + back);
            }
            reloaded.add(k);
        }
        for (Changed c : changes) {
            if (c.kind() != Kind.NGINX) continue;
            for (Path a : aliasesInto(c.after())) {
                if (Files.exists(a) && !sv.readableByWww(a)) {
                    String back = putBack(moved, written);
                    for (Kind r : reloaded) sv.reload(r);
                    return new Report(Outcome.ROLLED_BACK, "www cannot read " + a + " after the move" + back);
                }
            }
        }

        List<String> what = new ArrayList<>();
        for (String[] p : present) what.add(p[0] + " -> " + p[1]);
        List<String> files = new ArrayList<>();
        for (Changed c : changes) files.add(c.path().toString());
        return new Report(Outcome.DONE, String.join(", ", what)
                + (files.isEmpty() ? "" : "; paths updated in " + String.join(", ", files))
                + (reloaded.isEmpty() ? "" : "; reloaded " + reloaded));
    }

    /**
     * Sposta una cartella: con un rename se quella nuova non c'e', altrimenti un nome alla volta (la cartella vecchia,
     * vuota, se ne va). Ogni passo resta in {@code moved}, per poterlo rimettere.
     */
    private static void moveFolder(Path from, Path to, List<Moved> moved) throws IOException {
        if (!Files.exists(to, LinkOption.NOFOLLOW_LINKS)) {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
            moved.add(new Moved(from, to));
            return;
        }
        List<Path> children = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(from)) {
            for (Path c : ds) children.add(c);
        }
        for (Path c : children) {
            Path t = to.resolve(c.getFileName());
            Files.move(c, t, StandardCopyOption.ATOMIC_MOVE);
            moved.add(new Moved(c, t));
        }
        PosixFileAttributes a = Files.readAttributes(from, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Files.delete(from);
        moved.add(new Moved(from, null));
        // Per rimetterla: con permessi e proprietario di prima.
        removedFolders.put(from, a);
    }

    /** Le cartelle vecchie tolte perche' rimaste vuote, con i loro attributi: per ricrearle uguali. */
    private static final Map<Path, PosixFileAttributes> removedFolders = new LinkedHashMap<>();

    /** Rimette tutto com'era, al contrario: i file, poi gli spostamenti. Dice cosa non e' riuscito. */
    private static String putBack(List<Moved> moved, List<Changed> written) {
        List<String> problems = new ArrayList<>();
        for (int i = written.size() - 1; i >= 0; i--) {
            Changed c = written.get(i);
            try {
                PanelMarker.replaceKeeping(c.path(), c.before());
            } catch (IOException | RuntimeException e) {
                problems.add(c.path() + ": " + e.getMessage());
            }
        }
        for (int i = moved.size() - 1; i >= 0; i--) {
            Moved m = moved.get(i);
            try {
                if (m.to() == null) {
                    Files.createDirectory(m.from());
                    PosixFileAttributes a = removedFolders.get(m.from());
                    if (a != null) {
                        Files.setPosixFilePermissions(m.from(), a.permissions());
                        Files.setOwner(m.from(), a.owner());
                        Files.setAttribute(m.from(), "posix:group", a.group());
                    }
                } else {
                    Files.move(m.to(), m.from(), StandardCopyOption.ATOMIC_MOVE);
                }
            } catch (IOException | RuntimeException e) {
                problems.add(m.from() + ": " + e.getMessage());
            }
        }
        return problems.isEmpty() ? "; everything put back as it was" : "; NOT put back: " + String.join(", ", problems);
    }

    // ===================== i servizi veri =====================

    static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(30);
        private static final Duration LONG = Duration.ofSeconds(120);

        @Override public List<String> nginxFolders() {
            if (Shell.resolve("nginx") == null) return List.of();
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? WebProtection.includedFolders(r.output()) : null;
        }

        @Override public String test(Kind kind) {
            Shell.Result r = switch (kind) {
                case PHP -> Shell.resolve("php-fpm") == null ? null : Shell.run(SHORT, "php-fpm", "-t");
                case NGINX -> Shell.resolve("nginx") == null ? null : Shell.run(SHORT, "nginx", "-t");
                case PF -> Shell.run(SHORT, "pfctl", "-nf", "/etc/pf.conf");
                case FAIL2BAN -> Shell.resolve("fail2ban-client") == null ? null : Shell.run(LONG, "fail2ban-client", "-t");
                case DOVECOT -> Shell.resolve("doveconf") == null ? null : Shell.run(SHORT, "doveconf", "-n");
                case POSTFIX -> Shell.resolve("postfix") == null ? null : Shell.run(LONG, "postfix", "check");
                case RSPAMD -> Shell.resolve("rspamadm") == null ? null : Shell.run(LONG, "rspamadm", "configtest");
                case OTHER -> null;
            };
            return r == null || r.success() ? null : firstLine(r.outputTrim());
        }

        @Override public String reload(Kind kind) {
            Shell.Result r = switch (kind) {
                case PHP -> running("php_fpm") ? Shell.run(LONG, "service", "php_fpm", "onereload") : null;
                case NGINX -> running("nginx") ? Shell.run(LONG, "service", "nginx", "onereload") : null;
                case FAIL2BAN -> Shell.resolve("fail2ban-client") != null && Shell.run(SHORT, "fail2ban-client", "ping").success()
                        ? Shell.run(LONG, "fail2ban-client", "reload") : null;
                case DOVECOT -> running("dovecot") ? Shell.run(LONG, "doveadm", "reload") : null;
                case POSTFIX -> running("postfix") ? Shell.run(LONG, "postfix", "reload") : null;
                case RSPAMD -> running("rspamd") ? Shell.run(LONG, "service", "rspamd", "onereload") : null;
                case PF, OTHER -> null;
            };
            return r == null || r.success() ? null : firstLine(r.outputTrim());
        }

        private static boolean running(String service) {
            return Shell.run(SHORT, "service", service, "onestatus").success();
        }

        @Override public boolean readableByWww(Path file) {
            return Shell.run(SHORT, "env", "-i", "/usr/sbin/chroot", "-u", "www", "-g", "www", "/", "/bin/test", "-r",
                    file.toString()).success();
        }

        private static String firstLine(String s) {
            int i = s.indexOf('\n');
            return i < 0 ? s : s.substring(0, i);
        }
    }
}
