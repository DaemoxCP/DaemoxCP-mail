package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
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
 * <p>Rigenerare dal testo e' giusto solo se il testo dice quello che c'e' nel database. Una voce
 * aggiunta con postmap -i (o postalias -i) sta solo nel database, e una riga del testo cambiata
 * senza rilanciare postmap non ci e' ancora: rigenerare cambierebbe quello che Postfix usa. Quindi,
 * PRIMA di pkg upgrade e con la libreria di adesso (dopo il database puo' non leggersi piu'), ogni
 * mappa si confronta col suo testo: il testo si costruisce in una copia accanto, con lo stesso
 * programma, e si confrontano i due contenuti come li legge Postfix.
 *
 * <p>Una mappa che non coincide col testo, o che il testo non ce l'ha, si ricostruisce dal suo
 * contenuto: prima di pkg upgrade lo si legge (postmap -s) e lo si tiene in memoria, dopo lo si da'
 * a postmap -i sullo stdin, e la mappa nuova deve avere la stessa impronta di prima. Misurato sulla
 * VM il 31/10/2026: lmdb e hash con voci aggiunte con -i, continuazioni e doppioni, gli alias veri e
 * alias con liste, "|comando", :include: e nomi fra virgolette tornano identici. Resta senza rimedio
 * solo una mappa che non si legge gia' prima, o il cui contenuto supera maxSavedBytes: per quella il
 * pannello si ferma prima, o dopo non la tocca e lo dice.
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

    private static String toolFor(Table t) { return t.kind() == Kind.ALIAS ? "postalias" : "postmap"; }

    private static String label(Table t) { return t.name() + " (" + t.parameter() + ")"; }

    /**
     * Le tabelle di quei tipi che dopo un cambio di libreria non si potrebbero rigenerare uguali a
     * prima, col perche': il database non si legge, o il testo non coincide (o non c'e') e il
     * contenuto e' troppo grande da tenere da parte.
     */
    static Map<String, String> unrebuildable(Set<String> types) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Table t : tablesInUse()) {
            if (!types.contains(t.type()) || t.kind() == Kind.CACHE) continue;
            String lost = way(t, false).lost();
            if (lost != null) out.put(label(t), lost);
        }
        return out;
    }

    /**
     * Il motivo per non eseguire un piano che puo' cambiare la libreria di un tipo di cui una mappa
     * non si potrebbe rigenerare dal testo, o null. Lo chiedono le tre schede e i tre lavori, con la
     * regola delle rimozioni.
     */
    static String planBlocker(JSONObject plan) {
        if (plan == null || !postfixInstalled()) return null;
        Set<String> types = typesThePlanMayChange(plan, readers(),
                p -> set(run("pkg", "rquery", "-U", "%b", p).output()),
                p -> set(run("pkg", "rquery", "-U", "%B", p).output()));
        if (types.isEmpty()) return null;
        Map<String, String> lost = unrebuildable(types);
        if (lost.isEmpty()) return null;
        List<String> names = new ArrayList<>();
        lost.forEach((table, why) -> names.add(table + ": " + why));
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
     * Costruisce la tabella da una copia del suo testo, accanto (temp, e il database temp + estensione).
     * null se e' andata, altrimenti cosa e' andato storto. I file li toglie dropBeside.
     */
    private static String buildBeside(Table t, String tool, String temp) {
        // cp -p: la copia ha proprietario e permessi del testo, e postmap lavora come il suo proprietario.
        Shell.Result cp = run("cp", "-p", t.path(), temp);
        if (!cp.success()) return "cp: " + cp.outputTrim();
        Shell.Result r = run(tool, t.type() + ":" + temp);
        return r.success() ? null : r.outputTrim();
    }

    private static void dropBeside(Table t, String temp) {
        try {
            Files.deleteIfExists(Path.of(temp));
            for (String suffix : SUFFIXES.get(t.type())) Files.deleteIfExists(Path.of(temp + suffix));
        } catch (Exception ignored) { }
    }

    /**
     * Costruisce la tabella da una copia del suo testo, accanto, e la rinomina sopra quella vecchia
     * (per dbm e sdbm, i due file). null se e' andata, altrimenti cosa e' andato storto; i file della
     * copia se ne vanno in ogni caso. Il database nuovo prende proprietario e permessi del vecchio:
     * misurato sulla VM, postmap sul posto li lascia com'erano (640 root:mail), ma costruito accanto
     * nasce coi permessi del testo e il gruppo wheel (644 root:wheel), e rinominato sopra li cambiava.
     */
    private static String rebuildBeside(Table t, String tool) {
        String temp = t.path() + ".panel-rebuild";
        try {
            String fail = buildBeside(t, tool, temp);
            if (fail != null) return fail;
            for (String suffix : SUFFIXES.get(t.type())) {
                Path old = Path.of(t.path() + suffix), fresh = Path.of(temp + suffix);
                if (Files.exists(old) && Files.exists(fresh)) sameOwnerAndMode(old, fresh);
            }
            for (String suffix : SUFFIXES.get(t.type()))
                Files.move(Path.of(temp + suffix), Path.of(t.path() + suffix), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            return null;
        } catch (Exception e) {
            return String.valueOf(e.getMessage());
        } finally {
            dropBeside(t, temp);
        }
    }

    /**
     * Il contenuto di una tabella come la legge Postfix ("postmap -s", "postalias -s"): quante voci,
     * quanti byte, e un'impronta che non dipende dall'ordine, la somma degli SHA-256 delle righe.
     * L'ordine conta poco per lmdb, ma per hash dipende dall'ordine in cui le voci sono state scritte
     * (misurato sulla VM: le stesse cinque voci in due ordini escono in due ordini). Non finisce mai
     * su disco ne' nel registro, perche' una mappa puo' tenere password (sasl_passwd).
     */
    record Digest(long entries, long bytes, BigInteger sum) {}

    private static final Duration DUMP_TIMEOUT = Duration.ofSeconds(300);

    /**
     * Quanto puo' pesare, al massimo, il contenuto di una mappa tenuto in memoria durante un
     * aggiornamento. Non e' final: le prove lo abbassano per provare una mappa che non ci sta.
     */
    static long maxSavedBytes = 32L * 1024 * 1024;

    /** Lo scarico di una tabella: l'impronta, e il contenuto se e' stato chiesto e se ci sta. */
    private record Read(Digest digest, byte[] content) {
        void forget() { if (content != null) java.util.Arrays.fill(content, (byte) 0); }
    }

    /**
     * Legge una tabella con tool -s, a flusso; il contenuto lo tiene solo se keepUpTo >= 0 e finche'
     * non supera keepUpTo byte. null se non si legge.
     */
    private static Read read(String tool, String table, long keepUpTo) {
        ProcessBuilder pb = new ProcessBuilder(tool, "-s", table);
        Shell.applyPath(pb);
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
        pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process p = null;
        try {
            p = pb.start();
            final Process proc = p;
            // Si legge mentre postmap scrive: una mappa grande riempirebbe la pipe e lo fermerebbe.
            java.util.concurrent.FutureTask<Read> reading = new java.util.concurrent.FutureTask<>(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.ISO_8859_1))) {
                    MessageDigest sha = MessageDigest.getInstance("SHA-256");
                    java.io.ByteArrayOutputStream kept = keepUpTo >= 0 ? new java.io.ByteArrayOutputStream() : null;
                    BigInteger sum = BigInteger.ZERO;
                    long n = 0, size = 0;
                    for (String line; (line = r.readLine()) != null; n++) {
                        byte[] b = line.getBytes(StandardCharsets.ISO_8859_1);
                        sum = sum.add(new BigInteger(1, sha.digest(b)));
                        size += b.length + 1;
                        if (kept != null && size > keepUpTo) kept = null;
                        if (kept != null) { kept.write(b); kept.write('\n'); }
                    }
                    return new Read(new Digest(n, size, sum), kept == null ? null : kept.toByteArray());
                }
            });
            Thread.ofVirtual().start(reading);
            if (!p.waitFor(DUMP_TIMEOUT.toSeconds(), java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            Read d = reading.get(30, java.util.concurrent.TimeUnit.SECONDS);
            if (p.exitValue() == 0) return d;
            d.forget();
            return null;
        } catch (Exception e) {
            if (p != null) p.destroyForcibly();
            return null;
        }
    }

    /** L'impronta di una tabella, o null se non si legge. */
    static Digest digest(String tool, String table) {
        Read r = read(tool, table, -1);
        return r == null ? null : r.digest();
    }

    /**
     * Se il database di una tabella e il suo testo dicono cose diverse, perche'; null se dicono la
     * stessa cosa, o se il database non c'e' ancora (non c'e' niente da perdere). Va chiamata prima
     * di pkg upgrade: dopo, il database puo' non leggersi piu'.
     */
    static String outOfSync(Table t) {
        boolean exists = false;
        for (String suffix : SUFFIXES.get(t.type())) exists |= Files.exists(Path.of(t.path() + suffix));
        if (!exists) return null;
        String tool = toolFor(t);
        Digest db = digest(tool, t.name());
        return db == null ? I18n.tr("server.maps.dbUnreadable") : compareWithText(t, tool, db);
    }

    /**
     * Il testo di t costruito in una copia accanto, con lo stesso programma, confrontato con
     * l'impronta del database: cosi' righe di continuazione, voci senza valore e doppioni contano
     * come per postmap. null se coincidono, altrimenti perche' no.
     */
    private static String compareWithText(Table t, String tool, Digest db) {
        String temp = t.path() + ".panel-check";
        try {
            String fail = buildBeside(t, tool, temp);
            Digest text = fail == null ? digest(tool, t.type() + ":" + temp) : null;
            if (text == null) return I18n.tr("server.maps.textUnbuildable", Map.of("out", fail == null ? tool + " -s" : fail));
            if (text.entries() == db.entries() && text.sum().equals(db.sum())) return null;
            return db.entries() != text.entries()
                    ? I18n.tr("server.maps.diffCounts", Map.of("db", String.valueOf(db.entries()), "text", String.valueOf(text.entries())))
                    : I18n.tr("server.maps.diffValues", Map.of("n", String.valueOf(db.entries())));
        } finally {
            dropBeside(t, temp);
        }
    }

    /**
     * Il contenuto di una tabella letto prima di pkg upgrade, come lo scarica postmap -s: da qui la si
     * ricostruisce dopo, uguale, anche senza testo o con un testo diverso. Sta solo in memoria e
     * l'array si azzera dopo l'uso. textDiffers: perche' il testo non coincide, o null se non c'e'.
     */
    static final class Saved {
        private byte[] content;
        final Digest digest;
        final String textDiffers;

        Saved(byte[] content, Digest digest, String textDiffers) {
            this.content = content;
            this.digest = digest;
            this.textDiffers = textDiffers;
        }

        byte[] content() { return content; }

        void forget() {
            if (content != null) java.util.Arrays.fill(content, (byte) 0);
            content = null;
        }

        /** Mai il contenuto: un Before puo' finire in un messaggio. */
        @Override public String toString() { return "Saved[" + digest.entries() + "]"; }
    }

    /**
     * Come si rigenera una tabella dopo un cambio di libreria: saved, dal contenuto letto prima; lost,
     * non si puo' (il perche'). Tutti e due null: dal testo, che coincide col database, o non c'e'
     * ancora nessun database (e allora non c'e' niente da perdere).
     */
    record Way(Saved saved, String lost) {}

    private static String megabytes(long bytes) { return ((bytes + 1048575) / 1048576) + " MB"; }

    /**
     * Come si potrebbe rigenerare t dopo un cambio di libreria, con la libreria di adesso. keep: tiene
     * il contenuto, se serve (before); senza, dice solo se si potrebbe (la scheda, il giudizio).
     */
    static Way way(Table t, boolean keep) {
        boolean dbExists = false;
        for (String suffix : SUFFIXES.get(t.type())) dbExists |= Files.exists(Path.of(t.path() + suffix));
        boolean hasText = Files.isRegularFile(Path.of(t.path()));
        if (!dbExists) return new Way(null, null);
        String tool = toolFor(t);
        Read db = read(tool, t.name(), keep ? maxSavedBytes : -1);
        if (db == null) return new Way(null, I18n.tr("server.maps.dbUnreadable"));
        String why = hasText ? compareWithText(t, tool, db.digest()) : I18n.tr("server.maps.reasonNoSource");
        if (why == null) {
            db.forget();
            return new Way(null, null);
        }
        if (db.digest().bytes() > maxSavedBytes) {
            db.forget();
            return new Way(null, I18n.tr("server.maps.tooLarge", Map.of("why", why,
                    "size", megabytes(db.digest().bytes()), "max", megabytes(maxSavedBytes))));
        }
        return new Way(keep ? new Saved(db.content(), db.digest(), hasText ? why : null) : null, null);
    }

    /**
     * Quello che serve sapere prima di pkg upgrade: chi legge ogni tipo; il contenuto delle mappe che
     * non si rigenerano dal testo (nome -> Saved); quelle che non si rigenerano affatto (nome -> perche').
     */
    record Before(Map<String, String> signatures, Map<String, Saved> saved, Map<String, String> lost) {
        Before(Map<String, String> signatures) { this(signatures, Map.of(), Map.of()); }

        /** Il contenuto tenuto da parte non serve piu': si azzera. */
        void forget() { saved.values().forEach(Saved::forget); }
    }

    /** Da prendere prima di pkg upgrade, nei tre lavori. */
    static Before before() {
        Map<String, Saved> saved = new TreeMap<>();
        Map<String, String> lost = new TreeMap<>();
        for (Table t : tablesInUse()) {
            if (t.kind() == Kind.CACHE) continue;
            Way w = way(t, true);
            if (w.saved() != null) saved.put(t.name(), w.saved());
            else if (w.lost() != null) lost.put(t.name(), w.lost());
        }
        return new Before(librarySignature(), saved, lost);
    }

    /** tool -i tabella, col contenuto sullo stdin: nessun file in mezzo. null se e' andata. */
    private static String feed(String tool, String table, byte[] content) {
        ProcessBuilder pb = new ProcessBuilder(tool, "-i", table);
        Shell.applyPath(pb);
        pb.redirectErrorStream(true);
        Process p = null;
        try {
            p = pb.start();
            final Process proc = p;
            java.util.concurrent.FutureTask<String> out = new java.util.concurrent.FutureTask<>(
                    () -> new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
            Thread.ofVirtual().start(out);
            try (java.io.OutputStream in = p.getOutputStream()) { in.write(content); }
            if (!p.waitFor(DUMP_TIMEOUT.toSeconds(), java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return tool + " -i: timeout";
            }
            String o = out.get(30, java.util.concurrent.TimeUnit.SECONDS).trim();
            return p.exitValue() == 0 ? null : o;
        } catch (Exception e) {
            if (p != null) p.destroyForcibly();
            return String.valueOf(e.getMessage());
        }
    }

    private static void sameOwnerAndMode(Path from, Path to) throws java.io.IOException {
        java.nio.file.attribute.PosixFileAttributes a = Files.readAttributes(from, java.nio.file.attribute.PosixFileAttributes.class);
        java.nio.file.attribute.PosixFileAttributeView v = Files.getFileAttributeView(to, java.nio.file.attribute.PosixFileAttributeView.class);
        v.setOwner(a.owner());
        v.setGroup(a.group());
        v.setPermissions(a.permissions());
    }

    /**
     * Ricostruisce t dal contenuto tenuto da parte, accanto, e la rinomina sopra la vecchia. La mappa
     * nuova deve avere la stessa impronta di quella di prima, e prende proprietario e permessi della
     * vecchia. Misurato sulla VM: postmap -i crea il database se non c'e', sempre root:wheel 644
     * qualunque fosse il vecchio, e su un database che c'e' AGGIUNGE: si parte da vuoto.
     */
    private static String rebuildFromSaved(Table t, Saved s) {
        String tool = toolFor(t), temp = t.path() + ".panel-rebuild";
        try {
            dropBeside(t, temp);
            String fail = feed(tool, t.type() + ":" + temp, s.content());
            if (fail != null) return fail;
            Digest now = digest(tool, t.type() + ":" + temp);
            if (!s.digest.equals(now))
                return I18n.tr("server.maps.savedMismatch", Map.of("before", String.valueOf(s.digest.entries()),
                        "now", now == null ? "?" : String.valueOf(now.entries())));
            for (String suffix : SUFFIXES.get(t.type())) {
                Path old = Path.of(t.path() + suffix), fresh = Path.of(temp + suffix);
                if (Files.exists(old) && Files.exists(fresh)) sameOwnerAndMode(old, fresh);
            }
            for (String suffix : SUFFIXES.get(t.type()))
                Files.move(Path.of(temp + suffix), Path.of(t.path() + suffix), java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE);
            return null;
        } catch (Exception e) {
            return String.valueOf(e.getMessage());
        } finally {
            dropBeside(t, temp);
        }
    }

    /**
     * Dopo pkg upgrade: se la libreria di un tipo e' cambiata, le sue mappe si rigenerano (dal
     * contenuto letto prima, se il testo non coincide o non c'e'; altrimenti dal testo), le sue cache
     * si cancellano, ogni mappa rigenerata si controlla, e Postfix si ricarica. Una mappa che non si
     * poteva rigenerare non si tocca, e conta come problema. Va chiamata anche se pkg e' uscito con un
     * errore: e' proprio quando la macchina puo' essere rimasta a meta'. Alla fine il contenuto tenuto
     * da parte si azzera.
     */
    static Outcome afterUpgrade(Before state, Consumer<String> log) {
        try {
            return rebuildChanged(state, log);
        } finally {
            state.forget();
        }
    }

    private static Outcome rebuildChanged(Before state, Consumer<String> log) {
        Map<String, String> before = state.signatures();
        Map<String, String> after = librarySignature();
        Set<String> types = changed(before, after);
        if (types.isEmpty()) return new Outcome(List.of());
        log.accept(I18n.tr("server.maps.changed", Map.of("types", String.join(", ", types))));
        for (String t : types) log.accept("  " + t + ": " + before.getOrDefault(t, "-") + " -> " + after.getOrDefault(t, "-"));
        List<String> problems = new ArrayList<>();
        boolean touched = false, any = false;
        for (Table t : tablesInUse()) {
            if (!types.contains(t.type())) continue;
            any = true;
            String label = label(t);
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
            String tool = toolFor(t);
            Saved saved = state.saved().get(t.name());
            if (saved != null) {
                touched = true;
                String side = rebuildFromSaved(t, saved);
                if (side != null) {
                    String p = I18n.tr("server.maps.rebuildFailed", Map.of("table", label, "cmd", tool + " -i " + t.name(), "out", side));
                    log.accept(p);
                    problems.add(p);
                    continue;
                }
                log.accept(I18n.tr("server.maps.rebuiltFromSaved", Map.of("table", label, "n", String.valueOf(saved.digest.entries()))));
                log.accept(saved.textDiffers == null ? I18n.tr("server.maps.textMissing", Map.of("table", label))
                        : I18n.tr("server.maps.textDiffers", Map.of("table", label, "why", saved.textDiffers)));
                continue;
            }
            String lost = state.lost().get(t.name());
            if (lost != null) {
                String p = I18n.tr("server.maps.notRebuilt", Map.of("table", label, "reason", lost));
                log.accept(p);
                problems.add(p);
                continue;
            }
            Path source = Path.of(t.path());
            if (!Files.isRegularFile(source)) {
                boolean dbExists = false;
                for (String suffix : SUFFIXES.get(t.type())) dbExists |= Files.exists(Path.of(t.path() + suffix));
                if (!dbExists) {
                    log.accept(I18n.tr("server.maps.nothing", Map.of("table", label)));
                    continue;
                }
                String p = I18n.tr("server.maps.noSource", Map.of("table", label, "path", t.path()));
                log.accept(p);
                problems.add(p);
                continue;
            }
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
            // «Nessuna mappa» solo se davvero non ce n'e': una che non si poteva rigenerare c'e', ed e' gia' nei problemi.
            if (!any) log.accept(I18n.tr("server.maps.none", Map.of("types", String.join(", ", types))));
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
