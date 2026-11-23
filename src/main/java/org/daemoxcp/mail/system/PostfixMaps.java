package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

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
 * Postfix's maps written to a file, and the library that reads them.
 *
 * <p>Postfix keeps some tables (aliases, access, transports, and its caches) in indexed files:
 * hash and btree (Berkeley DB), lmdb, cdb, dbm, sdbm. If an upgrade changes the library that
 * reads a type, the files written by the old one can become unreadable. The FreeBSD port says so
 * (databases/lmdb, pkg-message): "Databases created with LMDB 0.9.x cannot be opened with
 * LMDB 1.0". And the next change will not remove any package: lmdb0 coexists with lmdb, and the
 * Postfix port has an option to move to LMDB 1.0 (mail/postfix: LMDB0 and LMDB1). So the panel
 * does not look at the removals: it looks at the library behind each type.
 *
 * <p>The maps can be regenerated. Postfix's documentation (DATABASE_README of 3.11.7, installed
 * with the package): the "public" files are created with postmap or postalias from a text file,
 * the "private" ones are caches kept by the daemons. So, if the library of a type changes: the
 * maps are regenerated from their text, the caches are deleted (Postfix recreates them), every
 * map is checked to answer for its first key, and Postfix is reloaded. A map without its text
 * cannot be regenerated: if the upgrade can change its library, the panel stops BEFORE.
 *
 * <p>The map is built ALONGSIDE, from a copy of the text, and then renamed over the old one.
 * Measured on the VM on 2026-10-31: postmap over a file that its library cannot read stops
 * ("MDB_INVALID: File is not an LMDB file"), which is exactly the case of a 0.9 file in front
 * of LMDB 1.0. And deleting first would leave Postfix without the map until it is ready.
 *
 * <p>Regenerating from the text is right only if the text says what is in the database. An entry
 * added with postmap -i (or postalias -i) is only in the database, and a line of the text changed
 * without running postmap again is not in it yet: regenerating would change what Postfix uses.
 * So, BEFORE pkg upgrade and with the current library (afterwards the database may no longer be
 * readable), every map is compared with its text: the text is built in a copy alongside, with the
 * same program, and the two contents are compared as Postfix reads them.
 *
 * <p>A map that does not match its text, or that has no text, is rebuilt from its content: before
 * pkg upgrade it is read (postmap -s) and kept in memory, afterwards it is given to postmap -i on
 * stdin, and the new map must have the same fingerprint as before. Measured on the VM on
 * 2026-10-31: lmdb and hash with entries added with -i, continuations and duplicates, the real
 * aliases and aliases with lists, "|command", :include: and quoted names come back identical.
 * Only a map that is already unreadable before, or whose content exceeds maxSavedBytes, is left
 * without a remedy: for that one the panel stops before, or afterwards does not touch it and says
 * so.
 *
 * <p>On FreeBSD hash and btree are provided by Berkeley DB 1.85 inside the base system's libc
 * (libpostfix-util is not linked to any package libdb, measured on the VM on 2026-10-31): a
 * package upgrade does not touch them. If Postfix were built with a package Berkeley DB (db5,
 * db18), the same rule would apply to them too.
 */
final class PostfixMaps {

    private PostfixMaps() {}

    /** The types written to a file, with the extensions of their files. */
    static final Map<String, String[]> SUFFIXES = Map.of(
            "btree", new String[]{".db"}, "hash", new String[]{".db"}, "cdb", new String[]{".cdb"},
            "lmdb", new String[]{".lmdb"}, "dbm", new String[]{".dir", ".pag"}, "sdbm", new String[]{".dir", ".pag"});

    /** The types Postfix has built into libpostfix-util; the others come to it from a module (dynamicmaps). */
    static final Set<String> BUILT_IN = Set.of("btree", "dbm", "hash", "sdbm");

    /** The parameters whose tables are daemon caches (private databases): they are deleted, Postfix recreates them. */
    static final Set<String> CACHES = Set.of("address_verify_map", "postscreen_cache_map",
            "smtpd_tls_session_cache_database", "smtp_tls_session_cache_database",
            "lmtp_tls_session_cache_database", "smtp_sasl_auth_cache_name", "lmtp_sasl_auth_cache_name");

    /** The parameters whose tables are built with postalias. */
    static final Set<String> ALIASES = Set.of("alias_database", "alias_maps");

    /** In order of precedence: if two parameters name the same table, the last one wins. */
    enum Kind { PUBLIC, ALIAS, CACHE }

    /** A table in use: the parameter that names it, the type, the path without extension. */
    record Table(String parameter, String type, String path, Kind kind) {
        String name() { return type + ":" + path; }
    }

    /** A library that reads a type: the name it is requested by, where it is, who owns it. */
    record Lib(String soname, String path, String owner) {}

    /** Who reads a type: the Postfix object (module or libpostfix-util), its package, the libraries. */
    record Reader(String type, String object, String objectOwner, List<Lib> libs) {
        String signature() {
            List<String> s = new ArrayList<>();
            for (Lib l : libs) s.add(l.soname() + "=" + l.path() + "(" + l.owner() + ")");
            return s.isEmpty() ? "base" : String.join(";", s);
        }
    }

    /*
     * ===================================================================
     * Reading, as pure functions
     * ===================================================================
     */

    // "{" for the tables inside unionmap:{...} and pipemap:{...}.
    private static final Pattern TABLE = Pattern.compile(
            "(?:^|[\\s,{])(?:proxy:)?(btree|cdb|dbm|hash|lmdb|sdbm):(/[A-Za-z0-9._/+-]+)");

    /**
     * The proxymap lists: they repeat the tables named by the other parameters, caches included
     * (on the VM proxy_write_maps lists verify_cache and postscreen_cache). They do not say what a
     * table is, and if taken first they would turn a cache into a map to regenerate.
     */
    static final Set<String> PROXY_LISTS = Set.of("proxy_read_maps", "proxy_write_maps");

    /**
     * The file-type tables in use, from the postconf outputs in the given order: "postconf -nx"
     * (the parameters written in main.cf), "postconf -Px" (service/type/name = value, that is
     * master.cf), "postconf -x" (all, defaults included). A table named by several parameters
     * counts once, with the name of the first one that names it: this way a transport_maps map
     * does not show up as belonging to address_verify_transport_maps, which inherits it. What it
     * is, instead, is decided by any parameter that names it: cache first of all (it has no
     * text), then alias (built with postalias), otherwise public map. This way hash:/etc/aliases
     * stays an alias even if main.cf writes it in local_recipient_maps.
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

    /** Type -> module, from the lines of dynamicmaps.cf ("lmdb /path/postfix-lmdb.so dict_... mkmap_..."). */
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
     * The libraries in an ldd output that are not from the base system: the ones a package can
     * change. For the built-in types only those of a database are kept (libdb, gdbm).
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

    /** The types whose library differs between before and after (a type that appeared or disappeared counts). */
    static Set<String> changed(Map<String, String> before, Map<String, String> after) {
        Set<String> out = new TreeSet<>();
        Set<String> types = new TreeSet<>(before.keySet());
        types.addAll(after.keySet());
        for (String t : types) if (!String.valueOf(before.get(t)).equals(String.valueOf(after.get(t)))) out.add(t);
        return out;
    }

    /**
     * The first key that postmap or postalias really put into the table. The logical lines are read
     * the way they read them (postmap(1)): comments and empty lines are skipped, a line that starts
     * with a space continues the previous one. postmap skips an entry without a value with a warning
     * and ends fine (measured on the VM: "expected format: key whitespace value", exit 0): looking it
     * up would give a false alarm, so it is skipped here too.
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
     * The types whose reader can change with this plan. For every package library behind a
     * type: the plan removes the package that owns it; or upgrades it, and the new version
     * (catalog, %b) no longer provides it; or upgrades the package of the Postfix module, and
     * the new version (catalog, %B) no longer requires it. The base system types never change.
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

    /*
     * ===================================================================
     * The system
     * ===================================================================
     */

    private static Shell.Result run(String... cmd) { return Shell.run(Duration.ofSeconds(60), cmd); }

    private static String postconf(String name) {
        Shell.Result r = run("postconf", "-h", name);
        return r.success() ? r.outputTrim() : "";
    }

    /** Is Postfix there? Without it, no map to look at. */
    static boolean postfixInstalled() { return Shell.resolve("postconf") != null && run("postconf", "-h", "mail_version").success(); }

    /** The file-type tables Postfix uses now (parameters in force, defaults included, and master.cf). */
    static List<Table> tablesInUse() {
        if (!postfixInstalled()) return List.of();
        return tablesIn(run("postconf", "-nx").output(), run("postconf", "-Px").output(), run("postconf", "-x").output());
    }

    /** Who reads each file type, now. */
    static List<Reader> readers() {
        List<Reader> out = new ArrayList<>();
        if (!postfixInstalled()) return out;
        // The modules: dynamicmaps.cf and dynamicmaps.cf.d/*.cf in the meta_directory.
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
        // dynamicmaps.cf.d writes the module name relative to shlib_directory ("postfix-lmdb.so"):
        // measured on the VM, where the path taken as it was did not exist and lmdb was left out.
        String shlib = postconf("shlib_directory");
        boolean shared = !shlib.isEmpty() && !"no".equals(shlib);
        plugins.replaceAll((type, so) -> so.startsWith("/") || !shared ? so : Path.of(shlib, so).toString());
        // The built-in types: the database library that libpostfix-util (or smtpd) is linked to.
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

    /** Type -> signature of its library, now: to be taken before pkg upgrade. */
    static Map<String, String> librarySignature() {
        Map<String, String> out = new TreeMap<>();
        for (Reader r : readers()) out.put(r.type(), r.signature());
        return out;
    }

    /** The types whose readers belong to that package (its libraries, not the Postfix modules). */
    static Set<String> typesReadBy(String packageName) {
        Set<String> out = new TreeSet<>();
        for (Reader r : readers()) for (Lib l : r.libs()) if (l.owner().equals(packageName)) out.add(r.type());
        return out;
    }

    private static String toolFor(Table t) { return t.kind() == Kind.ALIAS ? "postalias" : "postmap"; }

    private static String label(Table t) { return t.name() + " (" + t.parameter() + ")"; }

    /**
     * The tables of those types that, after a library change, could not be regenerated identical to
     * before, with the reason: the database cannot be read, or the text does not match (or is
     * missing) and the content is too big to keep aside.
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
     * The reason not to run a plan that can change the library of a type with a map that could
     * not be regenerated from its text, or null. The three tabs and the three jobs ask for it,
     * together with the removals rule.
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

    /** How the regeneration went: it has already written the log lines. */
    record Outcome(List<String> problems) {
        boolean ok() { return problems.isEmpty(); }
        String problem() { return problems.isEmpty() ? null : I18n.tr("server.maps.problem", Map.of("list", String.join("; ", problems))); }
    }

    /**
     * Builds the table from a copy of its text, alongside (temp, and the database temp + extension).
     * null if it worked, otherwise what went wrong. dropBeside removes the files.
     */
    private static String buildBeside(Table t, String tool, String temp) {
        // cp -p: the copy has the owner and permissions of the text, and postmap works as its owner.
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
     * Builds the table from a copy of its text, alongside, and renames it over the old one
     * (for dbm and sdbm, the two files). null if it worked, otherwise what went wrong; the files of the
     * copy go away in any case. The new database takes the owner and permissions of the old one:
     * measured on the VM, postmap in place leaves them as they were (640 root:mail), but built alongside
     * the database is created with the text's permissions and the wheel group (644 root:wheel), and
     * renaming it over the old one changed them.
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
     * The content of a table as Postfix reads it ("postmap -s", "postalias -s"): how many entries,
     * how many bytes, and a fingerprint that does not depend on the order, the sum of the SHA-256 of
     * the lines. The order matters little for lmdb, but for hash it depends on the order in which the
     * entries were written (measured on the VM: the same five entries in two orders come out in two
     * orders). It never ends up on disk nor in the log, because a map can hold passwords (sasl_passwd).
     */
    record Digest(long entries, long bytes, BigInteger sum) {}

    private static final Duration DUMP_TIMEOUT = Duration.ofSeconds(300);

    /**
     * How much, at most, the content of a map kept in memory during an upgrade can weigh.
     * It is not final: the tests lower it to test a map that does not fit.
     */
    static long maxSavedBytes = 32L * 1024 * 1024;

    /** The dump of a table: the fingerprint, and the content if it was asked for and if it fits. */
    private record Read(Digest digest, byte[] content) {
        void forget() { if (content != null) java.util.Arrays.fill(content, (byte) 0); }
    }

    /**
     * Reads a table with tool -s, as a stream; it keeps the content only if keepUpTo >= 0 and as long
     * as it does not exceed keepUpTo bytes. null if it cannot be read.
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
            // It is read while postmap writes: a big map would fill the pipe and stop it.
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

    /** The fingerprint of a table, or null if it cannot be read. */
    static Digest digest(String tool, String table) {
        Read r = read(tool, table, -1);
        return r == null ? null : r.digest();
    }

    /**
     * If the database of a table and its text say different things, why; null if they say the
     * same thing, or if the database does not exist yet (there is nothing to lose). Must be called
     * before pkg upgrade: afterwards, the database may no longer be readable.
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
     * The text of t built in a copy alongside, with the same program, compared with the
     * database's fingerprint: this way continuation lines, entries without a value and duplicates
     * count as they do for postmap. null if they match, otherwise why not.
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
     * The content of a table read before pkg upgrade, as postmap -s dumps it: from here the table is
     * rebuilt afterwards, identical, even without text or with a different text. It lives only in
     * memory and the array is zeroed after use. textDiffers: why the text does not match, or null if
     * there is none.
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

        /** Never the content: a Before can end up in a message. */
        @Override public String toString() { return "Saved[" + digest.entries() + "]"; }
    }

    /**
     * How a table is regenerated after a library change: saved, from the content read before; lost,
     * it cannot be (the reason). Both null: from the text, which matches the database, or there is no
     * database yet (and then there is nothing to lose).
     */
    record Way(Saved saved, String lost) {}

    private static String megabytes(long bytes) { return ((bytes + 1048575) / 1048576) + " MB"; }

    /**
     * How t could be regenerated after a library change, with the current library. keep: keeps
     * the content, if needed (before); without it, it only says whether it could be done (the tab,
     * the verdict).
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
     * What must be known before pkg upgrade: who reads each type; the content of the maps that cannot
     * be regenerated from the text (name -> Saved); those that cannot be regenerated at all
     * (name -> why).
     */
    record Before(Map<String, String> signatures, Map<String, Saved> saved, Map<String, String> lost) {
        Before(Map<String, String> signatures) { this(signatures, Map.of(), Map.of()); }

        /** The content kept aside is no longer needed: it is zeroed. */
        void forget() { saved.values().forEach(Saved::forget); }
    }

    /** To be taken before pkg upgrade, in the three jobs. */
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

    /** tool -i table, with the content on stdin: no file in between. null if it worked. */
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
     * Rebuilds t from the content kept aside, alongside, and renames it over the old one. The new
     * map must have the same fingerprint as the previous one, and it takes the owner and permissions
     * of the old one. Measured on the VM: postmap -i creates the database if it does not exist, always
     * root:wheel 644 whatever the old one was, and on an existing database it ADDS: so it starts from
     * empty.
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
     * After pkg upgrade: if the library of a type has changed, its maps are regenerated (from the
     * content read before, if the text does not match or is missing; otherwise from the text), its
     * caches are deleted, every regenerated map is checked, and Postfix is reloaded. A map that could
     * not be regenerated is not touched, and counts as a problem. Must be called even if pkg exited
     * with an error: that is exactly when the machine may have been left halfway. At the end the
     * content kept aside is zeroed.
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
            // "No map" only if there really is none: one that could not be regenerated does exist,
            // and it is already among the problems.
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
