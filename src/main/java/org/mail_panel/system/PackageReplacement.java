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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Un aggiornamento che toglie un pacchetto: e' una sostituzione innocua, o no?
 *
 * <p>Il pannello rifiuta i piani che tolgono pacchetti: un aggiornamento che toglie qualcosa da
 * un server di posta va deciso da chi sa chi lo usa. Ma i port a volte sostituiscono una
 * libreria con un'altra che installa gli stessi file (a fine ottobre 2026 lmdb con lmdb0, per
 * Postfix), e allora aggiornare vuol dire togliere la vecchia: il rifiuto teneva Postfix fermo
 * finche' qualcuno non faceva lo scambio a mano. Il committente (31/10/2026): il pannello toglie
 * da solo il pacchetto vecchio quando dimostra che e' innocuo, e chiede quando non lo e'.
 *
 * <p>Innocuo vuol dire tutte e quattro:
 * <ol>
 *   <li>un pacchetto del piano prende il suo posto: pkg stesso lo dice, con la riga
 *       «X conflicts with Y on /percorso» (installano lo stesso file);</li>
 *   <li>nessun pacchetto installato che dipende da lui resta: o il piano lo aggiorna a una
 *       versione che non ne ha piu' bisogno (lo dice il catalogo), o non c'e';</li>
 *   <li>lo stesso per chi usa le sue librerie (pkg shlib);</li>
 *   <li>se e' una libreria che e' anche un formato di dati (lmdb, Berkeley DB, cdb), nessuna
 *       configurazione e nessun file di Postfix usa quel formato: la libreria nuova potrebbe non
 *       leggere i file scritti dalla vecchia.</li>
 * </ol>
 *
 * <p>Misurato sulla VM il 31/10/2026 con pacchetti finti e librerie ELF vere: nel caso innocuo
 * pkg toglie la libreria vecchia e il programma gira; se un altro programma usa ancora la
 * libreria vecchia, pkg toglie IN SILENZIO anche quello, e quel programma sparisce. E' il caso che
 * la regola 2 e la 1 fermano: nessuna riga di conflitto dice sostituito l'altro programma.
 */
final class PackageReplacement {

    private PackageReplacement() {}

    /** Che fine fa, secondo il piano, un pacchetto che usa quello che si toglie. */
    enum Use { UPGRADED_AWAY, REMOVED_TOO, STAYS }

    /** I fatti su una rimozione: raccolti dal sistema da {@link #facts}, scritti a mano nelle prove. */
    record Facts(String name, String version, String replacedBy, String sharedFile,
                 Map<String, Use> dependents, Map<String, Map<String, Use>> libraryUsers,
                 String dataFormat, List<String> dataUses, String error) {}

    record Verdict(String name, String version, boolean safe, String replacedBy,
                   List<String> evidence, List<String> problems) {
        JSONObject toJson() {
            return new JSONObject().put("name", name).put("version", version).put("safe", safe)
                    .put("replacedBy", replacedBy).put("evidence", new JSONArray(evidence))
                    .put("problems", new JSONArray(problems));
        }
    }

    /** Il giudizio, dai soli fatti: nessun comando qui dentro. */
    static Verdict judge(Facts f) {
        List<String> ok = new ArrayList<>(), no = new ArrayList<>();
        if (f.error() != null && !f.error().isEmpty()) {
            no.add(I18n.tr("server.replace.notMeasured", Map.of("err", f.error())));
            return new Verdict(f.name(), f.version(), false, "", ok, no);
        }
        // 1. qualcuno prende il suo posto
        if (f.replacedBy() == null || f.replacedBy().isEmpty())
            no.add(I18n.tr("server.replace.notReplaced"));
        else
            ok.add(I18n.tr("server.replace.replacedBy", Map.of("by", f.replacedBy(), "file", f.sharedFile())));
        // 2. chi dipende da lui
        if (f.dependents().isEmpty()) ok.add(I18n.tr("server.replace.noDependents"));
        f.dependents().forEach((p, use) -> (use == Use.UPGRADED_AWAY ? ok : no).add(I18n.tr(
                switch (use) {
                    case UPGRADED_AWAY -> "server.replace.dependentAway";
                    case REMOVED_TOO -> "server.replace.dependentRemoved";
                    case STAYS -> "server.replace.dependentStays";
                }, Map.of("p", p))));
        // 3. chi usa le sue librerie
        if (f.libraryUsers().isEmpty()) ok.add(I18n.tr("server.replace.noLibraries"));
        f.libraryUsers().forEach((lib, users) -> users.forEach((p, use) -> (use == Use.UPGRADED_AWAY ? ok : no).add(I18n.tr(
                switch (use) {
                    case UPGRADED_AWAY -> "server.replace.libraryAway";
                    case REMOVED_TOO -> "server.replace.libraryRemoved";
                    case STAYS -> "server.replace.libraryStays";
                }, Map.of("p", p, "lib", lib)))));
        // 4. il formato dei dati
        if (f.dataFormat() != null && !f.dataFormat().isEmpty()) {
            if (f.dataUses().isEmpty())
                ok.add(I18n.tr("server.replace.dataUnused", Map.of("fmt", f.dataFormat())));
            else
                no.add(I18n.tr("server.replace.dataUsed", Map.of("fmt", f.dataFormat(), "uses", String.join(", ", f.dataUses()))));
        }
        return new Verdict(f.name(), f.version(), no.isEmpty(),
                f.replacedBy() == null ? "" : f.replacedBy(), ok, no);
    }

    /* ===================================================================
     * I fatti, dal sistema
     * =================================================================== */

    /**
     * «X-v [repo] conflicts with Y-w [installed] on /percorso», come lo scrive pkg dopo aver
     * scaricato. Il nome del repository fra parentesi c'e' coi repository veri e non con quelli
     * locali: la riga di lmdb del 24/10/2026 e' «lmdb0-0.9.35 [FreeBSD-ports] conflicts with
     * lmdb-1.0.2,1 [installed] on /usr/local/bin/mdb_copy».
     */
    private static final Pattern CONFLICT = Pattern.compile(
            "^\\s*-\\s+(\\S+)(?:\\s+\\[[^\\]]*\\])?\\s+conflicts with\\s+(\\S+)(?:\\s+\\[[^\\]]*\\])?\\s+on\\s+(\\S+)\\s*$");

    record Conflict(String newName, String oldName, String file) {}

    static List<Conflict> conflicts(String pkgOutput) {
        List<Conflict> out = new ArrayList<>();
        for (String line : (pkgOutput == null ? "" : pkgOutput).split("\n")) {
            Matcher m = CONFLICT.matcher(line);
            if (m.matches()) out.add(new Conflict(nameOf(m.group(1)), nameOf(m.group(2)), m.group(3)));
        }
        return out;
    }

    /** Il nome da "nome-versione": la versione e' dopo l'ultimo trattino (postfix-mysql-3.11.7_3,1). */
    static String nameOf(String nameVersion) {
        int i = nameVersion.lastIndexOf('-');
        return i > 0 ? nameVersion.substring(0, i) : nameVersion;
    }

    /**
     * Le librerie che sono anche un formato di dati per Postfix: lo scheletro del nome del pacchetto
     * (senza le cifre in fondo: lmdb0 -> lmdb, db18 -> db), il tipo di mappa e l'estensione dei file.
     */
    private static final String[][] DATA_FORMATS = {
            {"lmdb", "lmdb", ".lmdb"}, {"db", "hash", ".db"}, {"db", "btree", ".db"}, {"tinycdb", "cdb", ".cdb"}};

    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9._+-]{1,100}");

    /** I giudizi su tutte le rimozioni di un piano, nell'ordine del piano. */
    static JSONArray judgePlan(JSONObject plan) {
        JSONArray out = new JSONArray();
        JSONArray changes = plan == null ? null : plan.optJSONArray("changes");
        if (changes == null) return out;
        Map<String, String> planned = new LinkedHashMap<>();
        for (int i = 0; i < changes.length(); i++) {
            JSONObject c = changes.getJSONObject(i);
            planned.put(c.optString("name"), c.optString("type"));
        }
        List<Conflict> conflicts = conflicts(plan.optString("output", ""));
        for (int i = 0; i < changes.length(); i++) {
            JSONObject c = changes.getJSONObject(i);
            if (!"remove".equals(c.optString("type"))) continue;
            out.put(judge(facts(c.optString("name"), c.optString("from"), planned, conflicts)).toJson());
        }
        return out;
    }

    static Facts facts(String name, String version, Map<String, String> planned, List<Conflict> conflicts) {
        if (!SAFE_NAME.matcher(name).matches())
            return new Facts(name, version, "", "", Map.of(), Map.of(), "", List.of(), "invalid package name");
        String by = "", file = "";
        for (Conflict k : conflicts) {
            String t = planned.get(k.newName());
            if (k.oldName().equals(name) && t != null && !"remove".equals(t)) { by = k.newName(); file = k.file(); break; }
        }
        Shell.Result rdeps = pkg("query", "%rn", name);
        Shell.Result libs = pkg("query", "%b", name);
        if (!rdeps.success() || !libs.success())
            return new Facts(name, version, by, file, Map.of(), Map.of(), "", List.of(),
                    "pkg query: " + (rdeps.success() ? libs : rdeps).outputTrim());

        Map<String, Use> dependents = new LinkedHashMap<>();
        for (String d : lines(rdeps.output()))
            dependents.put(d, use(d, planned, () -> lines(pkg("rquery", "-U", "%dn", d).output()).contains(name)));

        Map<String, Map<String, Use>> libraryUsers = new LinkedHashMap<>();
        for (String lib : lines(libs.output())) {
            Map<String, Use> users = new LinkedHashMap<>();
            for (String nv : lines(pkg("shlib", "-qR", lib).output())) {
                String p = nameOf(nv);
                if (p.equals(name)) continue;
                users.put(p, use(p, planned, () -> lines(pkg("rquery", "-U", "%B", p).output()).contains(lib)));
            }
            libraryUsers.put(lib, users);
        }

        String format = "";
        List<String> uses = new ArrayList<>();
        String skeleton = name.replaceAll("[0-9]+$", "");
        for (String[] f : DATA_FORMATS) {
            if (!f[0].equals(skeleton)) continue;
            format = format.isEmpty() ? f[1] : format + "/" + f[1];
            uses.addAll(postfixUses(f[1], f[2]));
        }
        return new Facts(name, version, by, file, dependents, libraryUsers, format,
                new ArrayList<>(new LinkedHashSet<>(uses)), "");
    }

    /** Il pacchetto p, che usava quello da togliere: lo aggiorna il piano a una versione che non ne ha bisogno? */
    private static Use use(String p, Map<String, String> planned, java.util.function.BooleanSupplier newStillNeeds) {
        String t = planned.get(p);
        if ("remove".equals(t)) return Use.REMOVED_TOO;
        if (t == null) return Use.STAYS;
        return newStillNeeds.getAsBoolean() ? Use.STAYS : Use.UPGRADED_AWAY;
    }

    /** Dove Postfix usa il tipo di mappa (main.cf, master.cf) e i file con quell'estensione. */
    static List<String> postfixUses(String mapType, String extension) {
        List<String> uses = new ArrayList<>();
        Shell.Result dir = Shell.run(Duration.ofSeconds(20), "postconf", "-h", "config_directory");
        if (!dir.success()) return uses;   // senza Postfix nessuno legge quelle mappe
        Path conf = Path.of(dir.outputTrim());
        for (String f : new String[]{"main.cf", "master.cf"}) {
            try {
                Path p = conf.resolve(f);
                if (Files.isReadable(p) && Pattern.compile("(^|[\\s,=])" + Pattern.quote(mapType) + ":", Pattern.MULTILINE)
                        .matcher(Files.readString(p)).find())
                    uses.add(p + " (" + mapType + ":)");
            } catch (Exception ignored) { }
        }
        try (Stream<Path> s = Files.walk(conf, 3)) {
            s.filter(p -> p.getFileName().toString().endsWith(extension) && Files.isRegularFile(p))
             .limit(10).forEach(p -> uses.add(p.toString()));
        } catch (Exception ignored) { }
        return uses;
    }

    private static Shell.Result pkg(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = "pkg";
        System.arraycopy(args, 0, cmd, 1, args.length);
        return Shell.run(Duration.ofSeconds(60), cmd);
    }

    private static List<String> lines(String s) {
        List<String> out = new ArrayList<>();
        for (String l : (s == null ? "" : s).split("\n")) if (!l.isBlank()) out.add(l.trim());
        return out;
    }

    /* ===================================================================
     * La regola, per i tre lavori e le tre schede
     * =================================================================== */

    /** "nome versione" di ogni rimozione che non e' innocua e che chi guarda non ha confermato. */
    static List<String> unconfirmed(JSONArray verdicts, Set<String> confirmed) {
        List<String> out = new ArrayList<>();
        for (int i = 0; verdicts != null && i < verdicts.length(); i++) {
            JSONObject v = verdicts.getJSONObject(i);
            String key = v.optString("name") + " " + v.optString("version");
            if (!v.optBoolean("safe") && (confirmed == null || !confirmed.contains(key))) out.add(key);
        }
        return out;
    }

    /** "nome versione" delle rimozioni innocue. */
    static List<String> safe(JSONArray verdicts) {
        List<String> out = new ArrayList<>();
        for (int i = 0; verdicts != null && i < verdicts.length(); i++) {
            JSONObject v = verdicts.getJSONObject(i);
            if (v.optBoolean("safe")) out.add(v.optString("name") + " " + v.optString("version"));
        }
        return out;
    }

    /** Le conferme mandate dalla pagina: "nome versione", nient'altro. */
    private static final Pattern CONFIRMATION = Pattern.compile("[A-Za-z0-9._+-]{1,100} [A-Za-z0-9._,+-]{1,60}");

    static Set<String> confirmations(JSONArray fromPage) {
        Set<String> out = new LinkedHashSet<>();
        for (int i = 0; fromPage != null && i < fromPage.length() && i < 50; i++) {
            String s = fromPage.optString(i, "");
            if (CONFIRMATION.matcher(s).matches()) out.add(s);
        }
        return out;
    }
}
