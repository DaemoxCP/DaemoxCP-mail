package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An upgrade that removes a package: is it a harmless replacement, or not?
 *
 * <p>The panel refuses plans that remove packages: an upgrade that removes something from a
 * mail server must be decided by someone who knows who uses it. But ports sometimes replace a
 * library with another one that installs the same files (at the end of October 2026 lmdb with
 * lmdb0, for Postfix), and then upgrading means removing the old one: the refusal kept Postfix
 * stuck until someone did the swap by hand. The owner (2026-10-31): the panel removes the old
 * package by itself when it proves that it is harmless, and otherwise does not remove it.
 *
 * <p>Harmless means all four:
 * <ol>
 *   <li>a package of the plan takes its place: pkg itself says so, with the line
 *       "X conflicts with Y on /path" (they install the same file);</li>
 *   <li>no installed package that depends on it remains: either the plan upgrades it to a
 *       version that no longer needs it (the catalogue says so), or there is none;</li>
 *   <li>the same for whoever uses its libraries (pkg shlib);</li>
 *   <li>if it reads a Postfix map type (lmdb, cdb, and Berkeley DB if it came from a package),
 *       every map of that type can be regenerated identical to before: after the upgrade
 *       PostfixMaps regenerates it, because the new library might not read the files of the
 *       old one.</li>
 * </ol>
 *
 * <p>Measured on the VM on 2026-10-31 with fake packages and real ELF libraries: in the harmless
 * case pkg removes the old library and the program runs; if another program still uses it and
 * declares it as a dependency, pkg SILENTLY removes that program too; if it uses it without
 * declaring it, pkg removes the library and leaves the program BROKEN ("Shared object not found").
 *
 * <p>If something that stays installed would disappear or stop working, if a Postfix map could
 * not be regenerated identical to before, or if it could not be measured, the panel does not
 * execute it (the owner, 2026-10-31: "this thing is very dangerous"). There is no way to confirm
 * it: the only case that could be confirmed, by typing the package name, was the format of the
 * data in use, and now the panel fixes that by itself by regenerating the maps (PostfixMaps).
 */
final class PackageReplacement {

    private PackageReplacement() {}

    /** What happens, according to the plan, to a package that uses the one being removed. */
    enum Use { UPGRADED_AWAY, REMOVED_TOO, STAYS }

    /** The facts about a removal: gathered from the system by {@link #facts}, written by hand in the tests. */
    record Facts(String name, String version, String replacedBy, String sharedFile,
                 Map<String, Use> dependents, Map<String, Map<String, Use>> libraryUsers,
                 String dataFormat, List<String> dataUses, String error) {}

    /** The judgement on a removal: harmless (safe) or not, with the evidence for the one and the other. */
    record Verdict(String name, String version, boolean safe, String replacedBy,
                   List<String> evidence, List<String> problems) {
        JSONObject toJson() {
            return new JSONObject().put("name", name).put("version", version).put("safe", safe)
                    .put("replacedBy", replacedBy).put("evidence", new JSONArray(evidence))
                    .put("problems", new JSONArray(problems));
        }
    }

    /** The judgement, from the facts alone: no command in here. */
    static Verdict judge(Facts f) {
        List<String> ok = new ArrayList<>(), no = new ArrayList<>();
        if (f.error() != null && !f.error().isEmpty()) {
            no.add(I18n.tr("server.replace.notMeasured", Map.of("err", f.error())));
            return new Verdict(f.name(), f.version(), false, "", ok, no);
        }
        // 1. something takes its place
        if (f.replacedBy() == null || f.replacedBy().isEmpty())
            no.add(I18n.tr("server.replace.notReplaced"));
        else
            ok.add(I18n.tr("server.replace.replacedBy", Map.of("by", f.replacedBy(), "file", f.sharedFile())));
        // 2. what depends on it
        if (f.dependents().isEmpty()) ok.add(I18n.tr("server.replace.noDependents"));
        f.dependents().forEach((p, use) -> (use == Use.UPGRADED_AWAY ? ok : no).add(I18n.tr(
                switch (use) {
                    case UPGRADED_AWAY -> "server.replace.dependentAway";
                    case REMOVED_TOO -> "server.replace.dependentRemoved";
                    case STAYS -> "server.replace.dependentStays";
                }, Map.of("p", p))));
        // 3. what uses its libraries
        if (f.libraryUsers().isEmpty()) ok.add(I18n.tr("server.replace.noLibraries"));
        f.libraryUsers().forEach((lib, users) -> users.forEach((p, use) -> (use == Use.UPGRADED_AWAY ? ok : no).add(I18n.tr(
                switch (use) {
                    case UPGRADED_AWAY -> "server.replace.libraryAway";
                    case REMOVED_TOO -> "server.replace.libraryRemoved";
                    case STAYS -> "server.replace.libraryStays";
                }, Map.of("p", p, "lib", lib)))));
        // 4. the Postfix maps it reads: they are regenerated identical to before, or they would be lost
        if (f.dataFormat() != null && !f.dataFormat().isEmpty()) {
            if (f.dataUses().isEmpty())
                ok.add(I18n.tr("server.replace.dataUnused", Map.of("fmt", f.dataFormat())));
            else
                no.add(I18n.tr("server.replace.dataUsed", Map.of("fmt", f.dataFormat(), "uses", String.join(", ", f.dataUses()))));
        }
        // Every problem here means that something disappears, breaks or is lost: it is not removed.
        return new Verdict(f.name(), f.version(), no.isEmpty(),
                f.replacedBy() == null ? "" : f.replacedBy(), ok, no);
    }

    /*
     * ===================================================================
     * The facts, from the system
     * ===================================================================
     */

    /**
     * "X-v [repo] conflicts with Y-w [installed] on /path", as pkg writes it after downloading.
     * The repository name in brackets is there with real repositories and not with local ones:
     * the lmdb line of 2026-10-24 is "lmdb0-0.9.35 [FreeBSD-ports] conflicts with
     * lmdb-1.0.2,1 [installed] on /usr/local/bin/mdb_copy".
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

    /** The name from "name-version": the version is after the last hyphen (postfix-mysql-3.11.7_3,1). */
    static String nameOf(String nameVersion) {
        int i = nameVersion.lastIndexOf('-');
        return i > 0 ? nameVersion.substring(0, i) : nameVersion;
    }

    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9._+-]{1,100}");

    /** The judgements on all the removals of a plan, in the plan's order. */
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

        // The Postfix maps that its libraries read and that afterwards would not be regenerated identical.
        Set<String> types = PostfixMaps.typesReadBy(name);
        List<String> lost = new ArrayList<>();
        PostfixMaps.unrebuildable(types).forEach((table, why) -> lost.add(table + ": " + why));
        return new Facts(name, version, by, file, dependents, libraryUsers, String.join("/", types), lost, "");
    }

    /** The package p, which used the one to be removed: does the plan upgrade it to a version that does not need it? */
    private static Use use(String p, Map<String, String> planned, java.util.function.BooleanSupplier newStillNeeds) {
        String t = planned.get(p);
        if ("remove".equals(t)) return Use.REMOVED_TOO;
        if (t == null) return Use.STAYS;
        return newStillNeeds.getAsBoolean() ? Use.STAYS : Use.UPGRADED_AWAY;
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
}
