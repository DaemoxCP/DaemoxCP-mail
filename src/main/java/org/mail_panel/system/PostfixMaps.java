package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Le mappe di Postfix scritte in un file, e la libreria che le legge.
 *
 * <p>Postfix tiene alcune tabelle (alias, accessi, trasporti, e le sue cache) in file indicizzati:
 * hash e btree (Berkeley DB), lmdb, cdb, dbm, sdbm. Se un aggiornamento cambia la libreria che
 * legge un tipo, i file scritti dalla vecchia possono diventare illeggibili. Lo dice il port di
 * FreeBSD (databases/lmdb, pkg-message): «Databases created with LMDB 0.9.x cannot be opened with
 * LMDB 1.0». E il prossimo cambio non togliera' nessun pacchetto: lmdb0 convive con lmdb, e il
 * port di Postfix ha un'opzione per passare a LMDB 1.0 (mail/postfix: LMDB0 e LMDB1). Quindi non
 * si guardano le rimozioni: si guarda la libreria dietro ogni tipo.
 *
 * <p>Le mappe si possono rigenerare. La documentazione di Postfix (DATABASE_README della 3.11.7,
 * installata col pacchetto): i file «pubblici» si creano con postmap o postalias da un file di
 * testo, i «privati» sono cache tenute dai demoni. Quindi, se la libreria di un tipo cambia:
 * le mappe si rigenerano dal loro testo, le cache si cancellano (Postfix le ricrea), si controlla
 * che ogni mappa risponda per la sua prima chiave e si ricarica Postfix. Una mappa senza il suo
 * testo non si puo' rigenerare: se l'aggiornamento puo' cambiarne la libreria, il pannello si
 * ferma PRIMA.
 *
 * <p>La mappa si costruisce ACCANTO, da una copia del testo, e poi si rinomina sopra quella vecchia.
 * Misurato sulla VM il 31/10/2026: postmap sopra un file che la sua libreria non sa leggere si
 * ferma («MDB_INVALID: File is not an LMDB file»), che e' proprio il caso di un file della 0.9
 * davanti a LMDB 1.0. E cancellare prima lascerebbe Postfix senza la mappa finche' non e' pronta.
 *
 * <p>Su FreeBSD hash e btree li fornisce Berkeley DB 1.85 dentro la libc del sistema base
 * (libpostfix-util non e' collegata a nessun libdb di pacchetto, misurato sulla VM il 31/10/2026):
 * un aggiornamento dei pacchetti non li tocca. Se Postfix fosse costruito con un Berkeley DB di
 * pacchetto (db5, db18), la stessa regola varrebbe anche per loro.
 */
final class PostfixMaps {

    private PostfixMaps() {}

    /** I tipi scritti in un file, con le estensioni dei loro file. */
    static final Map<String, String[]> SUFFIXES = Map.of(
            "btree", new String[]{".db"}, "hash", new String[]{".db"}, "cdb", new String[]{".cdb"},
            "lmdb", new String[]{".lmdb"}, "dbm", new String[]{".dir", ".pag"}, "sdbm", new String[]{".dir", ".pag"});

    /** I tipi che Postfix ha dentro libpostfix-util; gli altri gli arrivano da un modulo (dynamicmaps). */
    static final Set<String> BUILT_IN = Set.of("btree", "dbm", "hash", "sdbm");

    /** I parametri le cui tabelle sono cache dei demoni (database privati): si cancellano, Postfix le ricrea. */
    static final Set<String> CACHES = Set.of("address_verify_map", "postscreen_cache_map",
            "smtpd_tls_session_cache_database", "smtp_tls_session_cache_database",
            "lmtp_tls_session_cache_database", "smtp_sasl_auth_cache_name", "lmtp_sasl_auth_cache_name");

    /** I parametri le cui tabelle si costruiscono con postalias. */
    static final Set<String> ALIASES = Set.of("alias_database", "alias_maps");

    /** In ordine di precedenza: se due parametri nominano la stessa tabella, vince l'ultimo. */
    enum Kind { PUBLIC, ALIAS, CACHE }

    /** Una tabella in uso: il parametro che la nomina, il tipo, il percorso senza estensione. */
    record Table(String parameter, String type, String path, Kind kind) {
        String name() { return type + ":" + path; }
    }

    /** Una libreria che legge un tipo: il nome con cui la si chiede, dove sta, chi la possiede. */
    record Lib(String soname, String path, String owner) {}

    /** Chi legge un tipo: l'oggetto di Postfix (modulo o libpostfix-util), il suo pacchetto, le librerie. */
    record Reader(String type, String object, String objectOwner, List<Lib> libs) {
        String signature() {
            List<String> s = new ArrayList<>();
            for (Lib l : libs) s.add(l.soname() + "=" + l.path() + "(" + l.owner() + ")");
            return s.isEmpty() ? "base" : String.join(";", s);
        }
    }

    /* ===================================================================
     * La lettura, come funzioni pure
     * =================================================================== */

    // "{" per le tabelle dentro unionmap:{...} e pipemap:{...}.
    private static final Pattern TABLE = Pattern.compile(
            "(?:^|[\\s,{])(?:proxy:)?(btree|cdb|dbm|hash|lmdb|sdbm):(/[A-Za-z0-9._/+-]+)");

    /**
     * Gli elenchi di proxymap: ripetono le tabelle nominate dagli altri parametri, cache comprese
     * (sulla VM proxy_write_maps elenca verify_cache e postscreen_cache). Non dicono che cosa sia una
     * tabella, e presi per primi farebbero di una cache una mappa da rigenerare.
     */
    static final Set<String> PROXY_LISTS = Set.of("proxy_read_maps", "proxy_write_maps");

    /**
     * Le tabelle di tipo file in uso, dalle uscite di postconf nell'ordine dato: "postconf -nx"
     * (i parametri scritti in main.cf), "postconf -Px" (servizio/tipo/nome = valore, cioe'
     * master.cf), "postconf -x" (tutti, predefiniti compresi). Una tabella nominata da piu'
     * parametri conta una volta, col nome del primo che la nomina: cosi' una mappa di
     * transport_maps non risulta di address_verify_transport_maps, che la eredita. Che cosa sia
     * lo decide invece qualunque parametro la nomini: cache prima di tutto (non ha testo), poi
     * alias (si costruisce con postalias), se no mappa pubblica. Cosi' hash:/etc/aliases resta un
     * alias anche se main.cf la scrive in local_recipient_maps.
     */
    static List<Table> tablesIn(String... postconfOutputs) {
        Map<String, Table> out = new LinkedHashMap<>();
        for (String text : postconfOutputs) {
            for (String line : (text == null ? "" : text).split("\n")) {
                int eq = line.indexOf(" = ");
                if (eq <= 0) continue;
                String param = line.substring(0, eq).trim();
                param = param.substring(param.lastIndexOf('/') + 1);
                if (PROXY_LISTS.contains(param)) continue;
                Kind kind = CACHES.contains(param) ? Kind.CACHE : ALIASES.contains(param) ? Kind.ALIAS : Kind.PUBLIC;
                Matcher m = TABLE.matcher(line.substring(eq + 3));
                while (m.find()) {
                    String name = m.group(1) + ":" + m.group(2);
                    Table seen = out.get(name);
                    if (seen == null) out.put(name, new Table(param, m.group(1), m.group(2), kind));
                    else if (kind.ordinal() > seen.kind().ordinal())
                        out.put(name, new Table(seen.parameter(), seen.type(), seen.path(), kind));
                }
            }
        }
        return new ArrayList<>(out.values());
    }

    /** Tipo -> modulo, dalle righe di dynamicmaps.cf ("lmdb /percorso/postfix-lmdb.so dict_... mkmap_..."). */
    static Map<String, String> pluginsFrom(String dynamicmaps) {
        Map<String, String> out = new TreeMap<>();
        for (String line : (dynamicmaps == null ? "" : dynamicmaps).split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            String[] f = t.split("\\s+");
            if (f.length >= 2 && SUFFIXES.containsKey(f[0])) out.put(f[0], f[1]);
        }
        return out;
    }

    /**
     * Le librerie di un'uscita di ldd che non sono del sistema base: quelle che un pacchetto puo'
     * cambiare. Per i tipi interni si tengono solo quelle di un database (libdb, gdbm).
     */
    static List<String[]> librariesFrom(String ldd, boolean onlyDatabases) {
        List<String[]> out = new ArrayList<>();
        Pattern line = Pattern.compile("^\\s*(\\S+)\\s+=>\\s+(\\S+)");
        for (String l : (ldd == null ? "" : ldd).split("\n")) {
            Matcher m = line.matcher(l);
            if (!m.find()) continue;
            String soname = m.group(1), path = m.group(2);
            if (path.startsWith("/lib/") || path.startsWith("/usr/lib/")) continue;
            if (onlyDatabases && !soname.matches("lib(db|gdbm|ndbm)[-.0-9].*")) continue;
            out.add(new String[]{soname, path});
        }
        return out;
    }

    /** I tipi la cui libreria e' diversa fra prima e dopo (un tipo comparso o sparito conta). */
    static Set<String> changed(Map<String, String> before, Map<String, String> after) {
        Set<String> out = new TreeSet<>();
        Set<String> types = new TreeSet<>(before.keySet());
        types.addAll(after.keySet());
        for (String t : types) if (!String.valueOf(before.get(t)).equals(String.valueOf(after.get(t)))) out.add(t);
        return out;
    }

    /**
     * La prima chiave che postmap o postalias mettono davvero nella tabella. Si leggono le righe
     * logiche come loro (postmap(1)): i commenti e le righe vuote si saltano, una riga che comincia
     * con uno spazio continua quella prima. Una voce senza valore postmap la salta con un avviso e
     * finisce bene (misurato sulla VM: «expected format: key whitespace value», uscita 0): cercarla
     * darebbe un falso allarme, quindi si salta anche qui.
     */
    static String firstKey(String source, boolean alias) {
        List<String> logical = new ArrayList<>();
        for (String line : (source == null ? "" : source).split("\n")) {
            if (line.isBlank() || line.trim().startsWith("#")) continue;
            if (Character.isWhitespace(line.charAt(0))) {
                if (!logical.isEmpty()) logical.set(logical.size() - 1, logical.getLast() + " " + line.trim());
                continue;
            }
            logical.add(line.trim());
        }
        for (String l : logical) {
            if (alias) {
                int c = l.indexOf(':');
                if (c > 0 && !l.substring(c + 1).isBlank()) return l.substring(0, c).trim();
            } else {
                String[] f = l.split("\\s+", 2);
                if (f.length == 2 && !f[1].isBlank()) return f[0];
            }
        }
        return "";
    }

    /**
     * I tipi il cui lettore puo' cambiare con questo piano. Per ogni libreria di pacchetto dietro
     * un tipo: il piano toglie il pacchetto che la possiede; o lo aggiorna, e la versione nuova
     * (catalogo, %b) non la fornisce piu'; o aggiorna il pacchetto del modulo di Postfix, e la
     * versione nuova (catalogo, %B) non la chiede piu'. I tipi del sistema base non cambiano mai.
     */
    static Set<String> typesThePlanMayChange(JSONObject plan, List<Reader> readers,
                                             java.util.function.Function<String, Set<String>> catalogProvides,
                                             java.util.function.Function<String, Set<String>> catalogRequires) {
        Map<String, String> planned = new LinkedHashMap<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++)
            planned.put(c.getJSONObject(i).optString("name"), c.getJSONObject(i).optString("type"));
        Set<String> out = new TreeSet<>();
        for (Reader r : readers) {
            for (Lib l : r.libs()) {
                String libChange = planned.get(l.owner());
                boolean gone = "remove".equals(libChange)
                        || (libChange != null && !catalogProvides.apply(l.owner()).contains(l.soname()));
                String objChange = planned.get(r.objectOwner());
                boolean relinked = objChange != null && !"remove".equals(objChange)
                        && !catalogRequires.apply(r.objectOwner()).contains(l.soname());
                if (gone || relinked) out.add(r.type());
            }
        }
        return out;
    }

    /* ===================================================================
     * Il sistema
     * =================================================================== */

    private static Shell.Result run(String... cmd) { return Shell.run(Duration.ofSeconds(60), cmd); }

    private static String postconf(String name) {
        Shell.Result r = run("postconf", "-h", name);
        return r.success() ? r.outputTrim() : "";
    }

    /** Postfix c'e'? Senza, nessuna mappa da guardare. */
    static boolean postfixInstalled() { return Shell.resolve("postconf") != null && run("postconf", "-h", "mail_version").success(); }

    /** Le tabelle di tipo file che Postfix usa adesso (parametri in vigore, predefiniti compresi, e master.cf). */
    static List<Table> tablesInUse() {
        if (!postfixInstalled()) return List.of();
        return tablesIn(run("postconf", "-nx").output(), run("postconf", "-Px").output(), run("postconf", "-x").output());
    }

    /** Chi legge ogni tipo di file, adesso. */
    static List<Reader> readers() {
        List<Reader> out = new ArrayList<>();
        if (!postfixInstalled()) return out;
        // I moduli: dynamicmaps.cf e dynamicmaps.cf.d/*.cf nella meta_directory.
        StringBuilder dm = new StringBuilder();
        Path meta = Path.of(postconf("meta_directory").isEmpty() ? "/usr/local/libexec/postfix" : postconf("meta_directory"));
        try {
            Path main = meta.resolve("dynamicmaps.cf");
            if (Files.isReadable(main)) dm.append(Files.readString(main)).append('\n');
            Path d = meta.resolve("dynamicmaps.cf.d");
            if (Files.isDirectory(d)) try (Stream<Path> s = Files.list(d)) {
                for (Path p : s.filter(p -> p.toString().endsWith(".cf")).sorted().toList())
                    dm.append(Files.readString(p)).append('\n');
            }
        } catch (Exception ignored) { }
        Map<String, String> plugins = new TreeMap<>(pluginsFrom(dm.toString()));
        // dynamicmaps.cf.d scrive il nome del modulo relativo a shlib_directory ("postfix-lmdb.so"):
        // misurato sulla VM, dove il percorso preso cosi' com'era non esisteva e lmdb restava fuori.
        String shlib = postconf("shlib_directory");
        boolean shared = !shlib.isEmpty() && !"no".equals(shlib);
        plugins.replaceAll((type, so) -> so.startsWith("/") || !shared ? so : Path.of(shlib, so).toString());
        // I tipi interni: la libreria di database a cui e' collegata libpostfix-util (o smtpd).
        String util = shared && Files.exists(Path.of(shlib, "libpostfix-util.so"))
                ? Path.of(shlib, "libpostfix-util.so").toString()
                : Path.of(postconf("daemon_directory"), "smtpd").toString();
        for (String type : new TreeSet<>(SUFFIXES.keySet())) {
            String object = BUILT_IN.contains(type) ? util : plugins.get(type);
            if (object == null || !Files.exists(Path.of(object))) continue;
            List<Lib> libs = new ArrayList<>();
            for (String[] l : librariesFrom(run("ldd", object).output(), BUILT_IN.contains(type)))
                libs.add(new Lib(l[0], l[1], ownerOf(l[1])));
            out.add(new Reader(type, object, ownerOf(object), libs));
        }
        return out;
    }

    private static String ownerOf(String file) {
        Shell.Result r = run("pkg", "which", "-q", file);
        String o = r.success() ? r.outputTrim() : "";
        return o.isEmpty() ? "base" : PackageReplacement.nameOf(o);
    }

    /** Tipo -> firma della sua libreria, adesso: da prendere prima di pkg upgrade. */
    static Map<String, String> librarySignature() {
        Map<String, String> out = new TreeMap<>();
        for (Reader r : readers()) out.put(r.type(), r.signature());
        return out;
    }

    /** I tipi i cui lettori sono di quel pacchetto (le sue librerie, non i moduli di Postfix). */
    static Set<String> typesReadBy(String packageName) {
        Set<String> out = new TreeSet<>();
        for (Reader r : readers()) for (Lib l : r.libs()) if (l.owner().equals(packageName)) out.add(r.type());
        return out;
    }

    /** Le tabelle di quei tipi che non si potrebbero rigenerare: pubbliche o alias senza il loro testo. */
    static List<Table> unrebuildable(Set<String> types) {
        List<Table> out = new ArrayList<>();
        for (Table t : tablesInUse())
            if (types.contains(t.type()) && t.kind() != Kind.CACHE && !Files.isRegularFile(Path.of(t.path()))) out.add(t);
        return out;
    }

    /**
     * Il motivo per non eseguire un piano che puo' cambiare la libreria di un tipo di cui una mappa
     * non ha il testo, o null. Lo chiedono le tre schede e i tre lavori, con la regola delle rimozioni.
     */
    static String planBlocker(JSONObject plan) {
        if (plan == null || !postfixInstalled()) return null;
        Set<String> types = typesThePlanMayChange(plan, readers(),
                p -> set(run("pkg", "rquery", "-U", "%b", p).output()),
                p -> set(run("pkg", "rquery", "-U", "%B", p).output()));
        if (types.isEmpty()) return null;
        List<Table> lost = unrebuildable(types);
        if (lost.isEmpty()) return null;
        List<String> names = new ArrayList<>();
        for (Table t : lost) names.add(t.name() + " (" + t.parameter() + ")");
        return I18n.tr("server.maps.blocked", Map.of("types", String.join(", ", types), "list", String.join(", ", names)));
    }

    private static Set<String> set(String lines) {
        Set<String> s = new LinkedHashSet<>();
        for (String l : (lines == null ? "" : lines).split("\n")) if (!l.isBlank()) s.add(l.trim());
        return s;
    }

    /** Com'e' andata la rigenerazione: le righe del registro le ha gia' scritte. */
    record Outcome(List<String> problems) {
        boolean ok() { return problems.isEmpty(); }
        String problem() { return problems.isEmpty() ? null : I18n.tr("server.maps.problem", Map.of("list", String.join("; ", problems))); }
    }

    /**
     * Costruisce la tabella da una copia del suo testo, accanto, e la rinomina sopra quella vecchia
     * (per dbm e sdbm, i due file). null se e' andata, altrimenti cosa e' andato storto; i file della
     * copia se ne vanno in ogni caso.
     */
    private static String rebuildBeside(Table t, String tool) {
        String temp = t.path() + ".panel-rebuild";
        String[] suffixes = SUFFIXES.get(t.type());
        try {
            // cp -p: la copia ha proprietario e permessi del testo, e postmap lavora come il suo proprietario.
            Shell.Result cp = run("cp", "-p", t.path(), temp);
            if (!cp.success()) return "cp: " + cp.outputTrim();
            Shell.Result r = run(tool, t.type() + ":" + temp);
            if (!r.success()) return r.outputTrim();
            for (String suffix : suffixes)
                Files.move(Path.of(temp + suffix), Path.of(t.path() + suffix), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            return null;
        } catch (Exception e) {
            return String.valueOf(e.getMessage());
        } finally {
            try {
                Files.deleteIfExists(Path.of(temp));
                for (String suffix : suffixes) Files.deleteIfExists(Path.of(temp + suffix));
            } catch (Exception ignored) { }
        }
    }

    /**
     * Dopo pkg upgrade: se la libreria di un tipo e' cambiata, le sue mappe si rigenerano dal testo,
     * le sue cache si cancellano, ogni mappa rigenerata deve rispondere per la sua prima chiave, e
     * Postfix si ricarica. Va chiamata anche se pkg e' uscito con un errore: e' proprio quando la
     * macchina puo' essere rimasta a meta'.
     */
    static Outcome afterUpgrade(Map<String, String> before, Consumer<String> log) {
        Map<String, String> after = librarySignature();
        Set<String> types = changed(before, after);
        if (types.isEmpty()) return new Outcome(List.of());
        log.accept(I18n.tr("server.maps.changed", Map.of("types", String.join(", ", types))));
        for (String t : types) log.accept("  " + t + ": " + before.getOrDefault(t, "-") + " -> " + after.getOrDefault(t, "-"));
        List<String> problems = new ArrayList<>();
        boolean touched = false;
        for (Table t : tablesInUse()) {
            if (!types.contains(t.type())) continue;
            String label = t.name() + " (" + t.parameter() + ")";
            if (t.kind() == Kind.CACHE) {
                for (String suffix : SUFFIXES.get(t.type())) {
                    try { Files.deleteIfExists(Path.of(t.path() + suffix)); } catch (Exception e) {
                        problems.add(label + ": " + e.getMessage());
                    }
                }
                log.accept(I18n.tr("server.maps.cacheDropped", Map.of("table", label)));
                touched = true;
                continue;
            }
            Path source = Path.of(t.path());
            if (!Files.isRegularFile(source)) {
                String p = I18n.tr("server.maps.noSource", Map.of("table", label, "path", t.path()));
                log.accept(p);
                problems.add(p);
                continue;
            }
            String tool = t.kind() == Kind.ALIAS ? "postalias" : "postmap";
            touched = true;
            String side = rebuildBeside(t, tool);
            if (side != null) {
                String p = I18n.tr("server.maps.rebuildFailed", Map.of("table", label, "cmd", tool + " " + t.name(), "out", side));
                log.accept(p);
                problems.add(p);
                continue;
            }
            String key;
            try { key = firstKey(Files.readString(source), t.kind() == Kind.ALIAS); } catch (Exception e) { key = ""; }
            if (key.isEmpty()) {
                log.accept(I18n.tr("server.maps.rebuiltNoKey", Map.of("table", label)));
                continue;
            }
            Shell.Result q = run(tool, "-q", key, t.name());
            if (q.success() && !q.outputTrim().isEmpty()) {
                log.accept(I18n.tr("server.maps.rebuilt", Map.of("table", label, "key", key)));
            } else {
                String p = I18n.tr("server.maps.notAnswering", Map.of("table", label, "key", key));
                log.accept(p);
                problems.add(p);
            }
        }
        if (!touched) {
            log.accept(I18n.tr("server.maps.none", Map.of("types", String.join(", ", types))));
            return new Outcome(problems);
        }
        if (run("postfix", "status").success()) {
            Shell.Result r = run("postfix", "reload");
            if (r.success()) log.accept(I18n.tr("server.maps.reloaded"));
            else {
                String p = I18n.tr("server.maps.reloadFailed", Map.of("out", r.outputTrim()));
                log.accept(p);
                problems.add(p);
            }
        }
        return new Outcome(problems);
    }
}
