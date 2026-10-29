package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Il ramo dei pacchetti ufficiali, quarterly o latest: quale e', e cambiarlo.
 *
 * Fonti, lette nel sorgente il 03/10/2026:
 *  - FreeBSD 15.0, usr.sbin/pkg/FreeBSD.conf.quarterly-release (il /etc/pkg/FreeBSD.conf di una
 *    RELEASE): FreeBSD-ports ".../${ABI}/quarterly", FreeBSD-ports-kmods
 *    ".../${ABI}/kmods_quarterly_${VERSION_MINOR}", FreeBSD-base spento. Su -STABLE i moduli
 *    sono ".../kmods_quarterly", senza la versione minore.
 *  - pkg, libpkg/pkg_config.c: i file *.conf di ogni cartella di REPOS_DIR si leggono in ordine
 *    alfabetico; un repository gia' definito si sovrascrive campo per campo e l'ultimo vince;
 *    ${ABI} e ${VERSION_MINOR} sono variabili del parser. Un blocco che sovrascrive rimette
 *    "priority" al suo valore (0 se non c'e') e "ip_version" a quello generale: se pkg -vv ne
 *    mostra altri, il file del pannello li riscrive uguali.
 *  - pkg, src/update.c: "pkg update" e' rigido, se un repository non si aggiorna esce con errore;
 *    libpkg/repo/binary/update.c rimette il catalogo di prima.
 *
 * Cambiare ramo qui vuol dire: scrivere un file del pannello, l'ultimo della cartella
 * /usr/local/etc/pkg/repos, che cambia solo l'indirizzo dei repository ufficiali; controllare
 * con pkg -vv che valga davvero; scaricare il catalogo del ramo nuovo. Se un passo non riesce,
 * tutto torna com'era. Nessun pacchetto viene aggiornato: gli aggiornamenti si decidono dopo, dal
 * loro piano. I file degli altri non si toccano mai, e il sistema base (FreeBSD-base) nemmeno.
 */
public final class PkgBranch {

    private PkgBranch() {}

    public static final Path FOLDER = Path.of("/usr/local/etc/pkg/repos");
    /** "zz": pkg legge i file in ordine alfabetico e l'ultimo vince. */
    public static final Path FILE = FOLDER.resolve("zz-panel-branch.conf");
    static final String MARK = "# Scritto dal pannello";
    static final String PKG = "/usr/local/sbin/pkg";
    public static final List<String> BRANCHES = List.of("quarterly", "latest");

    /** Il sistema da toccare: quello vero, o uno finto nelle prove. */
    public interface SystemAccess {
        /** L'uscita di "pkg -vv", o null se pkg non risponde. */
        String pkgVv();
        /** Il contenuto di un file piccolo, o null se non c'e'. */
        String read(Path p);
        /** I file *.conf della cartella, nell'ordine in cui li legge pkg. */
        List<String> fileConf(Path folder);
        void write(Path p, String content) throws IOException;
        void delete(Path p) throws IOException;
        /** "pkg update -f", riga per riga nel registro. */
        Outcome pkgUpdate(LineSink log);
        /** "pkg version -U -vRL=": i pacchetti diversi dal catalogo, senza scaricare niente. */
        String pkgVersions();
        Instant now();
    }

    public record Outcome(int code, String output) {}

    /** Dove va il racconto di un cambio di ramo (il registro del lavoro). */
    public interface LineSink { void line(String text); }

    /** Un repository come lo mostra pkg -vv, con quello che se ne capisce. */
    record Repo(String name, String url, boolean enabled, int priority, String ipVersion,
                String type, String branch, boolean withMinor) {}

    private static final Pattern OFFICIAL =
            Pattern.compile("^pkg\\+https?://pkg\\.freebsd\\.org/[^/]+/([A-Za-z0-9_]+)/?$", Pattern.CASE_INSENSITIVE);
    private static final Pattern MODULES = Pattern.compile("^kmods_(quarterly|latest)(_\\d+)?$");
    private static final Pattern BASE = Pattern.compile("^base_(release|latest|weekly)(_\\d+)?$");
    private static final Pattern NAME_PATTERN = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    /** I repository dall'uscita di pkg -vv (print_repository in src/utils.c). */
    static List<Repo> repository(String pkgVv) {
        List<Repo> list = new ArrayList<>();
        if (pkgVv == null) return list;
        String name = null, url = null, ip = null;
        boolean enabled = false, inside = false;
        int priority = 0;
        for (String line : pkgVv.split("\n")) {
            if (line.startsWith("Repositories:")) { inside = true; continue; }
            if (!inside) continue;
            Matcher m = Pattern.compile("^\\s+(\\S+):\\s*\\{").matcher(line);
            if (m.find()) { name = m.group(1); url = null; ip = null; enabled = false; priority = 0; continue; }
            if (name == null) continue;
            Matcher mu = Pattern.compile("^\\s*url\\s*:\\s*\"([^\"]*)\"").matcher(line);
            if (mu.find()) url = mu.group(1);
            Matcher ma = Pattern.compile("^\\s*enabled\\s*:\\s*(\\w+)").matcher(line);
            if (ma.find()) enabled = "yes".equalsIgnoreCase(ma.group(1));
            Matcher mp = Pattern.compile("^\\s*priority\\s*:\\s*(-?\\d{1,6})").matcher(line);
            if (mp.find()) priority = Integer.parseInt(mp.group(1));
            Matcher mi = Pattern.compile("^\\s*ip_version\\s*:\\s*([46])").matcher(line);
            if (mi.find()) ip = mi.group(1);
            if (line.trim().startsWith("}")) {
                if (url != null && NAME_PATTERN.matcher(name).matches()) list.add(classify(name, url, enabled, priority, ip));
                name = null;
            }
        }
        return list;
    }

    static Repo classify(String name, String url, boolean enabled, int priority, String ip) {
        Matcher u = OFFICIAL.matcher(url);
        if (!u.matches()) return new Repo(name, url, enabled, priority, ip, "external", "", false);
        String piece = u.group(1);
        if (BRANCHES.contains(piece)) return new Repo(name, url, enabled, priority, ip, "packages", piece, false);
        Matcher k = MODULES.matcher(piece);
        if (k.matches()) return new Repo(name, url, enabled, priority, ip, "modules", k.group(1), k.group(2) != null);
        Matcher b = BASE.matcher(piece);
        if (b.matches()) return new Repo(name, url, enabled, priority, ip, "base", b.group(1), b.group(2) != null);
        return new Repo(name, url, enabled, priority, ip, "other", piece, false);
    }

    /** L'unico repository acceso di quel tipo, o null (anche se ce n'e' piu' d'uno). */
    private static Repo enabled(List<Repo> repos, String type) {
        Repo found = null;
        for (Repo r : repos) {
            if (!r.enabled() || !r.type().equals(type)) continue;
            if (found != null) return null;
            found = r;
        }
        return found;
    }

    private static long enabledOnes(List<Repo> repos, String type) {
        return repos.stream().filter(r -> r.enabled() && r.type().equals(type)).count();
    }

    /** Il ramo che vale: quello dei pacchetti, "misti" se i moduli del kernel vanno per conto loro. */
    static String branch(List<Repo> repos) {
        Repo p = enabled(repos, "packages"), k = enabled(repos, "modules");
        if (p == null) return "none";
        if (k != null && !k.branch().equals(p.branch())) return "mixed";
        return p.branch();
    }

    static String explanation(String branch) {
        return switch (branch) {
            case "quarterly" -> I18n.tr("server.branch.quarterly");
            case "latest" -> I18n.tr("server.branch.latest");
            case "mixed" -> I18n.tr("server.branch.mixed");
            default -> I18n.tr("server.branch.unofficial");
        };
    }

    /** Lo stato: i repository, il ramo, il file del pannello e se si puo' cambiare. */
    public static JSONObject state(SystemAccess s) {
        String vv = s.pkgVv();
        if (vv == null)
            return new JSONObject().put("success", false).put("error", I18n.tr("server.branch.noPkgVv"));
        List<Repo> repos = repository(vv);
        if (repos.isEmpty())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.branch.noRepoRecognized"));
        String branch = branch(repos);
        String ours = s.read(FILE);
        JSONObject r = new JSONObject().put("success", true).put("branch", branch).put("explanation", explanation(branch))
                .put("repository", json(repos)).put("file", FILE.toString()).put("panelOwnedFile", ours != null)
                .put("fingerprint", fingerprint(repos, ours));
        if (ours != null) r.put("fileContent", ours.length() > 4000 ? ours.substring(0, 4000) : ours);
        List<String> after = fileAfter(s);
        if (!after.isEmpty()) r.put("fileAfter", new JSONArray(after));
        Repo base = enabled(repos, "base");
        if (base != null) r.put("base", I18n.tr("server.branch.baseFromPkg", java.util.Map.of("r", String.valueOf(base.branch()))));
        String reason = reasonNo(repos);
        r.put("changeable", reason == null);
        if (reason != null) r.put("reason", reason);
        else {
            JSONArray target = new JSONArray();
            for (String x : BRANCHES) if (!x.equals(branch)) target.put(x);
            r.put("destination", target);
        }
        return r;
    }

    /** Perche' non si puo' cambiare ramo da qui, o null se si puo'. */
    static String reasonNo(List<Repo> repos) {
        long p = enabledOnes(repos, "packages"), k = enabledOnes(repos, "modules");
        if (p == 0) return I18n.tr("server.branch.officialOff");
        if (p > 1 || k > 1) return I18n.tr("server.branch.manyOfficial");
        return null;
    }

    private static JSONArray json(List<Repo> repos) {
        JSONArray a = new JSONArray();
        for (Repo r : repos) {
            a.put(new JSONObject().put("name", r.name()).put("url", r.url()).put("enabled", r.enabled())
                    .put("type", r.type()).put("branch", r.branch()).put("official", !r.type().equals("external"))
                    .put("role", switch (r.type()) {
                        case "packages" -> I18n.tr("server.branch.kindPackages");
                        case "modules" -> I18n.tr("server.branch.kindKmods");
                        case "base" -> I18n.tr("server.branch.kindBase");
                        case "external" -> I18n.tr("server.branch.kindExternal");
                        default -> I18n.tr("server.branch.kindOfficial");
                    }));
        }
        return a;
    }

    /** I .conf della cartella letti DOPO quello del pannello: se cambiano l'indirizzo, vincono loro. */
    static List<String> fileAfter(SystemAccess s) {
        List<String> after = new ArrayList<>();
        String ours = FILE.getFileName().toString();
        for (String f : s.fileConf(FOLDER)) if (f.compareTo(ours) > 0) after.add(f);
        return after;
    }

    /** Impronta di cio' che l'anteprima ha letto: se cambia prima della conferma, non si procede. */
    static String fingerprint(List<Repo> repos, String ourFile) {
        StringBuilder b = new StringBuilder();
        for (Repo r : repos) b.append(r.name()).append('|').append(r.url()).append('|').append(r.enabled()).append('\n');
        b.append(ourFile == null ? "-" : ourFile);
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(b.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** L'indirizzo di un repository ufficiale sul ramo voluto, con le variabili di pkg come nel file di serie. */
    static String address(Repo r, String target) {
        if (r.type().equals("modules"))
            return "pkg+https://pkg.FreeBSD.org/${ABI}/kmods_" + target + (r.withMinor() ? "_${VERSION_MINOR}" : "");
        return "pkg+https://pkg.FreeBSD.org/${ABI}/" + target;
    }

    /** Il file del pannello per un ramo: solo l'indirizzo, piu' cio' che un blocco riscriverebbe di serie. */
    static String content(List<Repo> repos, String target, Instant when) {
        StringBuilder b = new StringBuilder();
        b.append(MARK).append(" il ").append(DateTimeFormatter.ofPattern("dd/MM/yyyy 'alle' HH:mm").format(when.atZone(ZoneOffset.UTC)))
         .append(" (UTC): ramo \"").append(target).append("\" dei pacchetti.\n")
         .append("# pkg legge i file di questa cartella in ordine alfabetico e per ogni campo vale\n")
         .append("# l'ultimo: per questo il nome comincia con \"zz\". Cambia solo l'indirizzo dei\n")
         .append("# repository ufficiali; il resto della configurazione resta quello di\n")
         .append("# /etc/pkg/FreeBSD.conf e degli altri file. Si cambia dal pannello\n")
         .append("# (Ramo dei pacchetti); cancellando questo file si torna al ramo di serie.\n");
        for (String type : List.of("packages", "modules")) {
            Repo r = enabled(repos, type);
            if (r == null) continue;
            b.append(r.name()).append(": { url: \"").append(address(r, target)).append('"');
            if (r.priority() != 0) b.append(", priority: ").append(r.priority());
            if (r.ipVersion() != null) b.append(", ip_version: ").append(r.ipVersion());
            b.append(" }\n");
        }
        return b.toString();
    }

    /** Cosa farebbe il cambio di ramo, senza farlo. */
    public static JSONObject preview(SystemAccess s, String target) {
        JSONObject st = state(s);
        if (!st.optBoolean("success")) return st;
        if (!BRANCHES.contains(target)) return new JSONObject().put("success", false).put("error", I18n.tr("server.branch.badBranch"));
        JSONObject r = new JSONObject().put("success", true).put("from", st.getString("branch")).put("destination", target)
                .put("fingerprint", st.getString("fingerprint"));
        if (!st.optBoolean("changeable")) return r.put("possible", false).put("reason", st.getString("reason"));
        if (target.equals(st.getString("branch"))) return r.put("possible", false).put("reason", I18n.tr("server.branch.alreadyOn", java.util.Map.of("r", String.valueOf(target))));
        List<Repo> repos = repository(s.pkgVv());
        JSONArray changes = new JSONArray();
        for (String type : List.of("packages", "modules")) {
            Repo x = enabled(repos, type);
            if (x != null) changes.put(new JSONObject().put("name", x.name()).put("from", x.url()).put("to", address(x, target)));
        }
        JSONArray warnings = new JSONArray();
        warnings.put(I18n.tr("server.branch.noUpdate", java.util.Map.of("r", String.valueOf(target))));
        if (target.equals("quarterly"))
            warnings.put(I18n.tr("server.branch.backToQuarterly"));
        else
            warnings.put(I18n.tr("server.branch.onLatest"));
        JSONArray after = st.optJSONArray("fileAfter");
        if (after != null && !after.isEmpty())
            warnings.put(I18n.tr("server.branch.laterFiles", java.util.Map.of("dir", String.valueOf(FOLDER), "list", String.valueOf(String.join(", ", strings(after))))));
        return r.put("possible", true).put("changes", changes).put("warnings", warnings).put("file", FILE.toString())
                .put("content", content(repos, target, s.now()))
                .put("howToReturn", howToReturn(st.getString("branch"), target, st.optBoolean("panelOwnedFile")));
    }

    /**
     * Come si torna indietro, detto prima di cambiare. Prima era vuoto proprio al primo cambio
     * (il file non era ancora del pannello), mentre i commenti del file scritto lo spiegavano:
     * l'informazione c'era e non arrivava a chi doveva decidere.
     */
    static String howToReturn(String from, String target, boolean panelOwnedFile) {
        String back = I18n.tr("server.branch.howToReturn", java.util.Map.of("from", from, "file", FILE.toString()));
        return panelOwnedFile
                ? back + " " + I18n.tr("server.branch.removeInstead", java.util.Map.of("r", String.valueOf(target)))
                : back;
    }

    private static List<String> strings(JSONArray a) {
        List<String> l = new ArrayList<>();
        for (int i = 0; i < a.length(); i++) l.add(a.getString(i));
        return l;
    }

    /** Il ramo che pkg vede adesso, rileggendo pkg -vv. */
    private static String effective(SystemAccess s) {
        List<Repo> repos = repository(s.pkgVv());
        return repos.isEmpty() ? "unreadable" : branch(repos);
    }

    /**
     * Cambia ramo. Va chiamato sul turno dei lavori sui pacchetti (PackageQueue). Ogni passo
     * finisce nel registro; se un passo non riesce, il file del pannello torna com'era.
     */
    public static JSONObject change(SystemAccess s, LineSink log, String target, String fingerprint) {
        JSONObject st = state(s);
        if (!st.optBoolean("success")) return st;
        if (!BRANCHES.contains(target)) return error(log, I18n.tr("server.branch.badBranch"));
        if (!st.optBoolean("changeable")) return error(log, st.getString("reason"));
        if (!st.getString("fingerprint").equals(fingerprint))
            return error(log, I18n.tr("server.branch.changedSincePreview"));
        String from = st.getString("branch");
        if (target.equals(from)) return error(log, I18n.tr("server.branch.alreadyOn", java.util.Map.of("r", String.valueOf(target))));
        List<Repo> repos = repository(s.pkgVv());
        String before = s.read(FILE);
        log.line(I18n.tr("server.branch.nowAsked", java.util.Map.of("from", String.valueOf(from), "destination", String.valueOf(target))));
        try {
            boolean done = false;
            if (before != null) {
                log.line("[1/3] " + I18n.tr("server.branch.removingFile", java.util.Map.of("f", String.valueOf(FILE))));
                s.delete(FILE);
                String without = effective(s);
                log.line("      " + I18n.tr("server.branch.withoutFile", java.util.Map.of("r", String.valueOf(without))));
                done = target.equals(without);
                if (done) log.line("      " + I18n.tr("server.branch.isAsked"));
            }
            if (!done) {
                log.line("[1/3] " + I18n.tr("server.branch.writing", java.util.Map.of("f", String.valueOf(FILE))));
                String fresh = content(repos, target, s.now());
                for (String line : fresh.split("\n")) if (!line.startsWith("#")) log.line("      " + line);
                s.write(FILE, fresh);
            }
            log.line("[2/3] " + I18n.tr("server.branch.checking"));
            String now = effective(s);
            log.line("      " + I18n.tr("server.branch.pkgSees", java.util.Map.of("r", String.valueOf(now))));
            if (!target.equals(now)) {
                restore(s, before);
                List<String> after = fileAfter(s);
                return error(log, I18n.tr("server.branch.wrongAfter", java.util.Map.of("now", String.valueOf(now), "destination", String.valueOf(target))) + " "
                        + (after.isEmpty() ? "" : I18n.tr("server.branch.decidedByLater", java.util.Map.of("list", String.valueOf(String.join(", ", after)))) + " ")
                        + I18n.tr("server.branch.restored"));
            }
            log.line("[3/3] " + I18n.tr("server.branch.downloading", java.util.Map.of("r", String.valueOf(target))));
            Outcome u = s.pkgUpdate(log);
            if (u.code() != 0) {
                restore(s, before);
                String matches = effective(s);
                return error(log, I18n.tr("server.branch.catalogFails", java.util.Map.of("r", String.valueOf(target), "c", String.valueOf(u.code()), "returns", String.valueOf(matches))));
            }
        } catch (IOException e) {
            try { restore(s, before); } catch (IOException ignored) { /* detto sotto */ }
            return error(log, I18n.tr("server.branch.cannotWrite", java.util.Map.of("dir", String.valueOf(FOLDER), "m", String.valueOf(e.getMessage()))));
        }
        // Cosa cambia per i pacchetti installati, dal catalogo appena scaricato.
        int updatable = 0;
        List<String> mostRecent = new ArrayList<>();
        String v = s.pkgVersions();
        if (v != null) {
            Matcher m = Pattern.compile("^(\\S+)\\s+([<>=?!])\\s", Pattern.MULTILINE).matcher(v);
            while (m.find()) {
                if (m.group(2).equals("<")) updatable++;
                else if (m.group(2).equals(">")) mostRecent.add(m.group(1));
            }
        }
        StringBuilder msg = new StringBuilder(I18n.tr("server.branch.done", java.util.Map.of("r", String.valueOf(target))));
        if (v == null) msg.append(" ").append(I18n.tr("server.branch.cannotCount"));
        else {
            msg.append(" ").append(updatable == 0 ? I18n.tr("server.branch.noneNewer")
                    : updatable == 1 ? I18n.tr("server.branch.updatable.one")
                    : I18n.tr("server.branch.updatable.other", java.util.Map.of("n", String.valueOf(updatable))));
            if (!mostRecent.isEmpty())
                msg.append(" ").append(mostRecent.size() == 1
                        ? I18n.tr("server.branch.newer.one", java.util.Map.of("r", String.valueOf(target)))
                        : I18n.tr("server.branch.newer.other", java.util.Map.of("n", String.valueOf(mostRecent.size()), "r", String.valueOf(target))));
        }
        log.line("");
        log.line(msg.toString());
        JSONObject r = new JSONObject().put("success", true).put("branch", target).put("messageText", msg.toString());
        if (v != null) {
            r.put("updatable", updatable).put("mostRecent", new JSONArray(mostRecent.size() > 30 ? mostRecent.subList(0, 30) : mostRecent));
            if (!mostRecent.isEmpty()) log.line(I18n.tr("server.branch.newerList", java.util.Map.of("list", String.valueOf(String.join(", ", mostRecent.size() > 30 ? mostRecent.subList(0, 30) : mostRecent)))));
        }
        return r;
    }

    private static void restore(SystemAccess s, String before) throws IOException {
        if (before == null) s.delete(FILE);
        else s.write(FILE, before);
    }

    private static JSONObject error(LineSink log, String text) {
        log.line(I18n.tr("server.branch.error", java.util.Map.of("t", String.valueOf(text))));
        return new JSONObject().put("success", false).put("error", text);
    }

    // ===== Il sistema vero =====

    public static SystemAccess real() {
        return new SystemAccess() {
            public String pkgVv() {
                Outcome e = run(null, 60, PKG, "-vv");
                return e.code() == 0 ? e.output() : null;
            }
            public String read(Path p) {
                try {
                    if (!Files.isRegularFile(p) || Files.size(p) > 65536) return null;
                    return Files.readString(p, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return null;
                }
            }
            public List<String> fileConf(Path folder) {
                List<String> l = new ArrayList<>();
                if (!Files.isDirectory(folder)) return l;
                try (Stream<Path> s = Files.list(folder)) {
                    s.map(x -> x.getFileName().toString())
                     .filter(n -> !n.startsWith(".") && n.length() > 5 && n.endsWith(".conf"))
                     .sorted().forEach(l::add);
                } catch (IOException e) {
                    // una cartella illeggibile si comporta come vuota: lo dira' pkg -vv
                }
                return l;
            }
            public void write(Path p, String content) throws IOException {
                Files.createDirectories(p.getParent());
                // Il file temporaneo comincia con un punto: se restasse li', pkg non lo leggerebbe.
                Path tmp = p.getParent().resolve("." + p.getFileName() + ".tmp");
                Files.writeString(tmp, content, StandardCharsets.UTF_8);
                try { Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--")); }
                catch (UnsupportedOperationException ignored) { /* non POSIX: solo nelle prove */ }
                Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            }
            public void delete(Path p) throws IOException { Files.deleteIfExists(p); }
            public Outcome pkgUpdate(LineSink log) { return run(log, 900, PKG, "update", "-f"); }
            public String pkgVersions() {
                Outcome e = run(null, 120, PKG, "version", "-U", "-vRL=");
                return e.code() == 0 ? e.output() : null;
            }
            public Instant now() { return Instant.now(); }
        };
    }

    /**
     * Un comando con argomenti separati (niente shell), con un tempo massimo sorvegliato da
     * fuori: un pkg fermo su una rete che non risponde non deve tenere il turno per sempre.
     */
    static Outcome run(LineSink log, int seconds, String... argv) {
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            org.mail_panel.util.Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            Thread guard = Thread.ofVirtual().start(() -> {
                try {
                    if (!p.waitFor(seconds, TimeUnit.SECONDS)) p.destroyForcibly();
                } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            });
            StringBuilder out = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = br.readLine()) != null) {
                    if (out.length() < 262144) out.append(l).append('\n');
                    if (log != null) log.line("      " + l);
                }
            }
            int code = p.waitFor();
            guard.interrupt();
            return new Outcome(code, out.toString());
        } catch (Exception e) {
            return new Outcome(-1, String.valueOf(e.getMessage()));
        }
    }
}
