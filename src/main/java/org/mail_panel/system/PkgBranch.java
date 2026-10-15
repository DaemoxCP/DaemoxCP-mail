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

    public static final Path CARTELLA = Path.of("/usr/local/etc/pkg/repos");
    /** "zz": pkg legge i file in ordine alfabetico e l'ultimo vince. */
    public static final Path FILE = CARTELLA.resolve("zz-pannello-ramo.conf");
    static final String MARCA = "# Scritto dal pannello";
    static final String PKG = "/usr/local/sbin/pkg";
    public static final List<String> RAMI = List.of("quarterly", "latest");

    /** Il sistema da toccare: quello vero, o uno finto nelle prove. */
    public interface Sistema {
        /** L'uscita di "pkg -vv", o null se pkg non risponde. */
        String pkgVv();
        /** Il contenuto di un file piccolo, o null se non c'e'. */
        String leggi(Path p);
        /** I file *.conf della cartella, nell'ordine in cui li legge pkg. */
        List<String> fileConf(Path cartella);
        void scrivi(Path p, String contenuto) throws IOException;
        void elimina(Path p) throws IOException;
        /** "pkg update -f", riga per riga nel registro. */
        Esito pkgUpdate(Registro registro);
        /** "pkg version -U -vRL=": i pacchetti diversi dal catalogo, senza scaricare niente. */
        String pkgVersioni();
        Instant adesso();
    }

    public record Esito(int codice, String uscita) {}

    /** Dove va il racconto di un cambio di ramo (il registro del lavoro). */
    public interface Registro { void riga(String testo); }

    /** Un repository come lo mostra pkg -vv, con quello che se ne capisce. */
    record Repo(String nome, String url, boolean acceso, int priorita, String ipVersion,
                String tipo, String ramo, boolean conMinore) {}

    private static final Pattern UFFICIALE =
            Pattern.compile("^pkg\\+https?://pkg\\.freebsd\\.org/[^/]+/([A-Za-z0-9_]+)/?$", Pattern.CASE_INSENSITIVE);
    private static final Pattern MODULI = Pattern.compile("^kmods_(quarterly|latest)(_\\d+)?$");
    private static final Pattern BASE = Pattern.compile("^base_(release|latest|weekly)(_\\d+)?$");
    private static final Pattern NOME = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    /** I repository dall'uscita di pkg -vv (print_repository in src/utils.c). */
    static List<Repo> repository(String pkgVv) {
        List<Repo> list = new ArrayList<>();
        if (pkgVv == null) return list;
        String nome = null, url = null, ip = null;
        boolean acceso = false, dentro = false;
        int priorita = 0;
        for (String riga : pkgVv.split("\n")) {
            if (riga.startsWith("Repositories:")) { dentro = true; continue; }
            if (!dentro) continue;
            Matcher m = Pattern.compile("^\\s+(\\S+):\\s*\\{").matcher(riga);
            if (m.find()) { nome = m.group(1); url = null; ip = null; acceso = false; priorita = 0; continue; }
            if (nome == null) continue;
            Matcher mu = Pattern.compile("^\\s*url\\s*:\\s*\"([^\"]*)\"").matcher(riga);
            if (mu.find()) url = mu.group(1);
            Matcher ma = Pattern.compile("^\\s*enabled\\s*:\\s*(\\w+)").matcher(riga);
            if (ma.find()) acceso = "yes".equalsIgnoreCase(ma.group(1));
            Matcher mp = Pattern.compile("^\\s*priority\\s*:\\s*(-?\\d{1,6})").matcher(riga);
            if (mp.find()) priorita = Integer.parseInt(mp.group(1));
            Matcher mi = Pattern.compile("^\\s*ip_version\\s*:\\s*([46])").matcher(riga);
            if (mi.find()) ip = mi.group(1);
            if (riga.trim().startsWith("}")) {
                if (url != null && NOME.matcher(nome).matches()) list.add(classifica(nome, url, acceso, priorita, ip));
                nome = null;
            }
        }
        return list;
    }

    static Repo classifica(String nome, String url, boolean acceso, int priorita, String ip) {
        Matcher u = UFFICIALE.matcher(url);
        if (!u.matches()) return new Repo(nome, url, acceso, priorita, ip, "esterno", "", false);
        String pezzo = u.group(1);
        if (RAMI.contains(pezzo)) return new Repo(nome, url, acceso, priorita, ip, "pacchetti", pezzo, false);
        Matcher k = MODULI.matcher(pezzo);
        if (k.matches()) return new Repo(nome, url, acceso, priorita, ip, "moduli", k.group(1), k.group(2) != null);
        Matcher b = BASE.matcher(pezzo);
        if (b.matches()) return new Repo(nome, url, acceso, priorita, ip, "base", b.group(1), b.group(2) != null);
        return new Repo(nome, url, acceso, priorita, ip, "altro", pezzo, false);
    }

    /** L'unico repository acceso di quel tipo, o null (anche se ce n'e' piu' d'uno). */
    private static Repo acceso(List<Repo> repos, String tipo) {
        Repo trovato = null;
        for (Repo r : repos) {
            if (!r.acceso() || !r.tipo().equals(tipo)) continue;
            if (trovato != null) return null;
            trovato = r;
        }
        return trovato;
    }

    private static long accesi(List<Repo> repos, String tipo) {
        return repos.stream().filter(r -> r.acceso() && r.tipo().equals(tipo)).count();
    }

    /** Il ramo che vale: quello dei pacchetti, "misti" se i moduli del kernel vanno per conto loro. */
    static String ramo(List<Repo> repos) {
        Repo p = acceso(repos, "pacchetti"), k = acceso(repos, "moduli");
        if (p == null) return "nessuno";
        if (k != null && !k.ramo().equals(p.ramo())) return "misti";
        return p.ramo();
    }

    static String spiegazione(String ramo) {
        return switch (ramo) {
            case "quarterly" -> I18n.tr("server.branch.quarterly");
            case "latest" -> I18n.tr("server.branch.latest");
            case "misti" -> I18n.tr("server.branch.mixed");
            default -> I18n.tr("server.branch.unofficial");
        };
    }

    /** Lo stato: i repository, il ramo, il file del pannello e se si puo' cambiare. */
    public static JSONObject stato(Sistema s) {
        String vv = s.pkgVv();
        if (vv == null)
            return new JSONObject().put("success", false).put("error", I18n.tr("server.branch.noPkgVv"));
        List<Repo> repos = repository(vv);
        if (repos.isEmpty())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.branch.noRepoRecognized"));
        String ramo = ramo(repos);
        String nostro = s.leggi(FILE);
        JSONObject r = new JSONObject().put("success", true).put("ramo", ramo).put("spiegazione", spiegazione(ramo))
                .put("repository", json(repos)).put("file", FILE.toString()).put("fileDelPannello", nostro != null)
                .put("impronta", impronta(repos, nostro));
        if (nostro != null) r.put("contenutoFile", nostro.length() > 4000 ? nostro.substring(0, 4000) : nostro);
        List<String> dopo = fileDopo(s);
        if (!dopo.isEmpty()) r.put("fileDopo", new JSONArray(dopo));
        Repo base = acceso(repos, "base");
        if (base != null) r.put("base", I18n.tr("server.branch.baseFromPkg", java.util.Map.of("r", String.valueOf(base.ramo()))));
        String motivo = motivoNo(repos);
        r.put("cambiabile", motivo == null);
        if (motivo != null) r.put("motivo", motivo);
        else {
            JSONArray verso = new JSONArray();
            for (String x : RAMI) if (!x.equals(ramo)) verso.put(x);
            r.put("verso", verso);
        }
        return r;
    }

    /** Perche' non si puo' cambiare ramo da qui, o null se si puo'. */
    static String motivoNo(List<Repo> repos) {
        long p = accesi(repos, "pacchetti"), k = accesi(repos, "moduli");
        if (p == 0) return I18n.tr("server.branch.officialOff");
        if (p > 1 || k > 1) return I18n.tr("server.branch.manyOfficial");
        return null;
    }

    private static JSONArray json(List<Repo> repos) {
        JSONArray a = new JSONArray();
        for (Repo r : repos) {
            a.put(new JSONObject().put("nome", r.nome()).put("url", r.url()).put("acceso", r.acceso())
                    .put("tipo", r.tipo()).put("ramo", r.ramo()).put("ufficiale", !r.tipo().equals("esterno"))
                    .put("ruolo", switch (r.tipo()) {
                        case "pacchetti" -> I18n.tr("server.branch.kindPackages");
                        case "moduli" -> I18n.tr("server.branch.kindKmods");
                        case "base" -> I18n.tr("server.branch.kindBase");
                        case "esterno" -> I18n.tr("server.branch.kindExternal");
                        default -> I18n.tr("server.branch.kindOfficial");
                    }));
        }
        return a;
    }

    /** I .conf della cartella letti DOPO quello del pannello: se cambiano l'indirizzo, vincono loro. */
    static List<String> fileDopo(Sistema s) {
        List<String> dopo = new ArrayList<>();
        String nostro = FILE.getFileName().toString();
        for (String f : s.fileConf(CARTELLA)) if (f.compareTo(nostro) > 0) dopo.add(f);
        return dopo;
    }

    /** Impronta di cio' che l'anteprima ha letto: se cambia prima della conferma, non si procede. */
    static String impronta(List<Repo> repos, String fileNostro) {
        StringBuilder b = new StringBuilder();
        for (Repo r : repos) b.append(r.nome()).append('|').append(r.url()).append('|').append(r.acceso()).append('\n');
        b.append(fileNostro == null ? "-" : fileNostro);
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(b.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** L'indirizzo di un repository ufficiale sul ramo voluto, con le variabili di pkg come nel file di serie. */
    static String indirizzo(Repo r, String verso) {
        if (r.tipo().equals("moduli"))
            return "pkg+https://pkg.FreeBSD.org/${ABI}/kmods_" + verso + (r.conMinore() ? "_${VERSION_MINOR}" : "");
        return "pkg+https://pkg.FreeBSD.org/${ABI}/" + verso;
    }

    /** Il file del pannello per un ramo: solo l'indirizzo, piu' cio' che un blocco riscriverebbe di serie. */
    static String contenuto(List<Repo> repos, String verso, Instant quando) {
        StringBuilder b = new StringBuilder();
        b.append(MARCA).append(" il ").append(DateTimeFormatter.ofPattern("dd/MM/yyyy 'alle' HH:mm").format(quando.atZone(ZoneOffset.UTC)))
         .append(" (UTC): ramo \"").append(verso).append("\" dei pacchetti.\n")
         .append("# pkg legge i file di questa cartella in ordine alfabetico e per ogni campo vale\n")
         .append("# l'ultimo: per questo il nome comincia con \"zz\". Cambia solo l'indirizzo dei\n")
         .append("# repository ufficiali; il resto della configurazione resta quello di\n")
         .append("# /etc/pkg/FreeBSD.conf e degli altri file. Si cambia dal pannello\n")
         .append("# (Ramo dei pacchetti); cancellando questo file si torna al ramo di serie.\n");
        for (String tipo : List.of("pacchetti", "moduli")) {
            Repo r = acceso(repos, tipo);
            if (r == null) continue;
            b.append(r.nome()).append(": { url: \"").append(indirizzo(r, verso)).append('"');
            if (r.priorita() != 0) b.append(", priority: ").append(r.priorita());
            if (r.ipVersion() != null) b.append(", ip_version: ").append(r.ipVersion());
            b.append(" }\n");
        }
        return b.toString();
    }

    /** Cosa farebbe il cambio di ramo, senza farlo. */
    public static JSONObject anteprima(Sistema s, String verso) {
        JSONObject st = stato(s);
        if (!st.optBoolean("success")) return st;
        if (!RAMI.contains(verso)) return new JSONObject().put("success", false).put("error", I18n.tr("server.branch.badBranch"));
        JSONObject r = new JSONObject().put("success", true).put("da", st.getString("ramo")).put("verso", verso)
                .put("impronta", st.getString("impronta"));
        if (!st.optBoolean("cambiabile")) return r.put("possibile", false).put("motivo", st.getString("motivo"));
        if (verso.equals(st.getString("ramo"))) return r.put("possibile", false).put("motivo", I18n.tr("server.branch.alreadyOn", java.util.Map.of("r", String.valueOf(verso))));
        List<Repo> repos = repository(s.pkgVv());
        JSONArray cambi = new JSONArray();
        for (String tipo : List.of("pacchetti", "moduli")) {
            Repo x = acceso(repos, tipo);
            if (x != null) cambi.put(new JSONObject().put("nome", x.nome()).put("da", x.url()).put("a", indirizzo(x, verso)));
        }
        JSONArray avvisi = new JSONArray();
        avvisi.put(I18n.tr("server.branch.noUpdate", java.util.Map.of("r", String.valueOf(verso))));
        if (verso.equals("quarterly"))
            avvisi.put(I18n.tr("server.branch.backToQuarterly"));
        else
            avvisi.put(I18n.tr("server.branch.onLatest"));
        JSONArray dopo = st.optJSONArray("fileDopo");
        if (dopo != null && !dopo.isEmpty())
            avvisi.put(I18n.tr("server.branch.laterFiles", java.util.Map.of("dir", String.valueOf(CARTELLA), "elenco", String.valueOf(String.join(", ", strings(dopo))))));
        return r.put("possibile", true).put("cambi", cambi).put("avvisi", avvisi).put("file", FILE.toString())
                .put("contenuto", contenuto(repos, verso, s.adesso()))
                .put("comeTorna", st.optBoolean("fileDelPannello")
                        ? I18n.tr("server.branch.removeInstead", java.util.Map.of("r", String.valueOf(verso)))
                        : "");
    }

    private static List<String> strings(JSONArray a) {
        List<String> l = new ArrayList<>();
        for (int i = 0; i < a.length(); i++) l.add(a.getString(i));
        return l;
    }

    /** Il ramo che pkg vede adesso, rileggendo pkg -vv. */
    private static String effettivo(Sistema s) {
        List<Repo> repos = repository(s.pkgVv());
        return repos.isEmpty() ? "illeggibile" : ramo(repos);
    }

    /**
     * Cambia ramo. Va chiamato sul turno dei lavori sui pacchetti (PackageQueue). Ogni passo
     * finisce nel registro; se un passo non riesce, il file del pannello torna com'era.
     */
    public static JSONObject cambia(Sistema s, Registro log, String verso, String impronta) {
        JSONObject st = stato(s);
        if (!st.optBoolean("success")) return st;
        if (!RAMI.contains(verso)) return errore(log, I18n.tr("server.branch.badBranch"));
        if (!st.optBoolean("cambiabile")) return errore(log, st.getString("motivo"));
        if (!st.getString("impronta").equals(impronta))
            return errore(log, I18n.tr("server.branch.changedSincePreview"));
        String da = st.getString("ramo");
        if (verso.equals(da)) return errore(log, I18n.tr("server.branch.alreadyOn", java.util.Map.of("r", String.valueOf(verso))));
        List<Repo> repos = repository(s.pkgVv());
        String prima = s.leggi(FILE);
        log.riga(I18n.tr("server.branch.nowAsked", java.util.Map.of("da", String.valueOf(da), "verso", String.valueOf(verso))));
        try {
            boolean fatto = false;
            if (prima != null) {
                log.riga("[1/3] " + I18n.tr("server.branch.removingFile", java.util.Map.of("f", String.valueOf(FILE))));
                s.elimina(FILE);
                String senza = effettivo(s);
                log.riga("      " + I18n.tr("server.branch.withoutFile", java.util.Map.of("r", String.valueOf(senza))));
                fatto = verso.equals(senza);
                if (fatto) log.riga("      " + I18n.tr("server.branch.isAsked"));
            }
            if (!fatto) {
                log.riga("[1/3] " + I18n.tr("server.branch.writing", java.util.Map.of("f", String.valueOf(FILE))));
                String nuovo = contenuto(repos, verso, s.adesso());
                for (String riga : nuovo.split("\n")) if (!riga.startsWith("#")) log.riga("      " + riga);
                s.scrivi(FILE, nuovo);
            }
            log.riga("[2/3] " + I18n.tr("server.branch.checking"));
            String ora = effettivo(s);
            log.riga("      " + I18n.tr("server.branch.pkgSees", java.util.Map.of("r", String.valueOf(ora))));
            if (!verso.equals(ora)) {
                ripristina(s, prima);
                List<String> dopo = fileDopo(s);
                return errore(log, I18n.tr("server.branch.wrongAfter", java.util.Map.of("ora", String.valueOf(ora), "verso", String.valueOf(verso))) + " "
                        + (dopo.isEmpty() ? "" : I18n.tr("server.branch.decidedByLater", java.util.Map.of("elenco", String.valueOf(String.join(", ", dopo)))) + " ")
                        + I18n.tr("server.branch.restored"));
            }
            log.riga("[3/3] " + I18n.tr("server.branch.downloading", java.util.Map.of("r", String.valueOf(verso))));
            Esito u = s.pkgUpdate(log);
            if (u.codice() != 0) {
                ripristina(s, prima);
                String torna = effettivo(s);
                return errore(log, I18n.tr("server.branch.catalogFails", java.util.Map.of("r", String.valueOf(verso), "c", String.valueOf(u.codice()), "torna", String.valueOf(torna))));
            }
        } catch (IOException e) {
            try { ripristina(s, prima); } catch (IOException ignorata) { /* detto sotto */ }
            return errore(log, I18n.tr("server.branch.cannotWrite", java.util.Map.of("dir", String.valueOf(CARTELLA), "m", String.valueOf(e.getMessage()))));
        }
        // Cosa cambia per i pacchetti installati, dal catalogo appena scaricato.
        int aggiornabili = 0;
        List<String> piuRecenti = new ArrayList<>();
        String v = s.pkgVersioni();
        if (v != null) {
            Matcher m = Pattern.compile("^(\\S+)\\s+([<>=?!])\\s", Pattern.MULTILINE).matcher(v);
            while (m.find()) {
                if (m.group(2).equals("<")) aggiornabili++;
                else if (m.group(2).equals(">")) piuRecenti.add(m.group(1));
            }
        }
        StringBuilder msg = new StringBuilder(I18n.tr("server.branch.done", java.util.Map.of("r", String.valueOf(verso))));
        if (v == null) msg.append(" ").append(I18n.tr("server.branch.cannotCount"));
        else {
            msg.append(" ").append(aggiornabili == 0 ? I18n.tr("server.branch.noneNewer")
                    : aggiornabili == 1 ? I18n.tr("server.branch.updatable.one")
                    : I18n.tr("server.branch.updatable.other", java.util.Map.of("n", String.valueOf(aggiornabili))));
            if (!piuRecenti.isEmpty())
                msg.append(" ").append(piuRecenti.size() == 1
                        ? I18n.tr("server.branch.newer.one", java.util.Map.of("r", String.valueOf(verso)))
                        : I18n.tr("server.branch.newer.other", java.util.Map.of("n", String.valueOf(piuRecenti.size()), "r", String.valueOf(verso))));
        }
        log.riga("");
        log.riga(msg.toString());
        JSONObject r = new JSONObject().put("success", true).put("ramo", verso).put("messaggio", msg.toString());
        if (v != null) {
            r.put("aggiornabili", aggiornabili).put("piuRecenti", new JSONArray(piuRecenti.size() > 30 ? piuRecenti.subList(0, 30) : piuRecenti));
            if (!piuRecenti.isEmpty()) log.riga(I18n.tr("server.branch.newerList", java.util.Map.of("elenco", String.valueOf(String.join(", ", piuRecenti.size() > 30 ? piuRecenti.subList(0, 30) : piuRecenti)))));
        }
        return r;
    }

    private static void ripristina(Sistema s, String prima) throws IOException {
        if (prima == null) s.elimina(FILE);
        else s.scrivi(FILE, prima);
    }

    private static JSONObject errore(Registro log, String testo) {
        log.riga(I18n.tr("server.branch.error", java.util.Map.of("t", String.valueOf(testo))));
        return new JSONObject().put("success", false).put("error", testo);
    }

    // ===== Il sistema vero =====

    public static Sistema reale() {
        return new Sistema() {
            public String pkgVv() {
                Esito e = esegui(null, 60, PKG, "-vv");
                return e.codice() == 0 ? e.uscita() : null;
            }
            public String leggi(Path p) {
                try {
                    if (!Files.isRegularFile(p) || Files.size(p) > 65536) return null;
                    return Files.readString(p, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return null;
                }
            }
            public List<String> fileConf(Path cartella) {
                List<String> l = new ArrayList<>();
                if (!Files.isDirectory(cartella)) return l;
                try (Stream<Path> s = Files.list(cartella)) {
                    s.map(x -> x.getFileName().toString())
                     .filter(n -> !n.startsWith(".") && n.length() > 5 && n.endsWith(".conf"))
                     .sorted().forEach(l::add);
                } catch (IOException e) {
                    // una cartella illeggibile si comporta come vuota: lo dira' pkg -vv
                }
                return l;
            }
            public void scrivi(Path p, String contenuto) throws IOException {
                Files.createDirectories(p.getParent());
                // Il file temporaneo comincia con un punto: se restasse li', pkg non lo leggerebbe.
                Path tmp = p.getParent().resolve("." + p.getFileName() + ".tmp");
                Files.writeString(tmp, contenuto, StandardCharsets.UTF_8);
                try { Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--")); }
                catch (UnsupportedOperationException ignorata) { /* non POSIX: solo nelle prove */ }
                Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            }
            public void elimina(Path p) throws IOException { Files.deleteIfExists(p); }
            public Esito pkgUpdate(Registro registro) { return esegui(registro, 900, PKG, "update", "-f"); }
            public String pkgVersioni() {
                Esito e = esegui(null, 120, PKG, "version", "-U", "-vRL=");
                return e.codice() == 0 ? e.uscita() : null;
            }
            public Instant adesso() { return Instant.now(); }
        };
    }

    /**
     * Un comando con argomenti separati (niente shell), con un tempo massimo sorvegliato da
     * fuori: un pkg fermo su una rete che non risponde non deve tenere il turno per sempre.
     */
    static Esito esegui(Registro registro, int secondi, String... argv) {
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            org.mail_panel.util.Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            Thread guardia = Thread.ofVirtual().start(() -> {
                try {
                    if (!p.waitFor(secondi, TimeUnit.SECONDS)) p.destroyForcibly();
                } catch (InterruptedException ignorata) { Thread.currentThread().interrupt(); }
            });
            StringBuilder out = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = br.readLine()) != null) {
                    if (out.length() < 262144) out.append(l).append('\n');
                    if (registro != null) registro.riga("      " + l);
                }
            }
            int codice = p.waitFor();
            guardia.interrupt();
            return new Esito(codice, out.toString());
        } catch (Exception e) {
            return new Esito(-1, String.valueOf(e.getMessage()));
        }
    }
}
