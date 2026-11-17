package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The verdict on a package an upgrade takes away (PackageReplacement.judge) and the rule that uses
 * it (UpdateManager: removalsRefused, destructivePlanReason, onlyAddedRemovals). No commands: the
 * facts are written here. What pkg really answers is measured by PackageReplacementE2ETest on the
 * VM.
 *
 * The starting case is the real one of late October 2026: postfix-mysql 3.11.7_3,1 moves from lmdb
 * to lmdb0, which installs the same files, and pkg removes lmdb.
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PackageReplacementTest
 */
public class PackageReplacementTest {

    private static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failures++;
    }

    static final PackageReplacement.Use AWAY = PackageReplacement.Use.UPGRADED_AWAY;
    static final PackageReplacement.Use REMOVED = PackageReplacement.Use.REMOVED_TOO;
    static final PackageReplacement.Use STAYS = PackageReplacement.Use.STAYS;

    /** lmdb removed for lmdb0, as on the VM on 24/10/2026, with a single detail changed at will. */
    static PackageReplacement.Facts lmdb(String replacedBy, Map<String, PackageReplacement.Use> dependents,
                                         Map<String, Map<String, PackageReplacement.Use>> libs,
                                         List<String> dataUses, String error) {
        return new PackageReplacement.Facts("lmdb", "1.0.2,1", replacedBy, "/usr/local/bin/mdb_copy",
                dependents, libs, "lmdb", dataUses, error);
    }

    static Map<String, PackageReplacement.Use> one(String p, PackageReplacement.Use u) {
        Map<String, PackageReplacement.Use> m = new LinkedHashMap<>();
        m.put(p, u);
        return m;
    }

    static Map<String, Map<String, PackageReplacement.Use>> lib(String lib, Map<String, PackageReplacement.Use> users) {
        Map<String, Map<String, PackageReplacement.Use>> m = new LinkedHashMap<>();
        m.put(lib, users);
        return m;
    }

    static boolean says(PackageReplacement.Verdict v, String text) {
        for (String s : v.problems()) if (s.contains(text)) return true;
        return false;
    }

    static JSONObject change(String type, String name, String from, String to) {
        return new JSONObject().put("type", type).put("name", name).put("from", from).put("to", to);
    }

    static JSONObject plan(JSONObject... changes) {
        return new JSONObject().put("changes", new JSONArray(List.of((Object[]) changes)));
    }

    public static void main(String[] args) {
        System.out.println("\n== pkg's line ==");
        String real = "Checking integrity... done (1 conflicting)\n"
                + "  - lmdb0-0.9.35 [FreeBSD-ports] conflicts with lmdb-1.0.2,1 [installed] on /usr/local/bin/mdb_copy\n"
                + "Checking integrity... done (0 conflicting)\n";
        List<PackageReplacement.Conflict> k = PackageReplacement.conflicts(real);
        check("lmdb's real line (24/10/2026, with the repository name in brackets): lmdb0 in place of lmdb on mdb_copy",
                k.size() == 1 && k.get(0).newName().equals("lmdb0") && k.get(0).oldName().equals("lmdb")
                        && k.get(0).file().equals("/usr/local/bin/mdb_copy"));
        k = PackageReplacement.conflicts("  - fakelib0-0.9 conflicts with fakelib-1.0 on /usr/local/bin/fake-tool\n");
        check("the line of a local repository, without brackets (measured on the VM on 31/10/2026)",
                k.size() == 1 && k.get(0).newName().equals("fakelib0") && k.get(0).oldName().equals("fakelib"));
        check("the name from name-version, even with dashes in the name",
                PackageReplacement.nameOf("postfix-mysql-3.11.7_3,1").equals("postfix-mysql")
                        && PackageReplacement.nameOf("lmdb-1.0.2,1").equals("lmdb"));
        check("no conflict line, no replacement", PackageReplacement.conflicts("Number of packages to be removed: 1").isEmpty());

        System.out.println("\n== The verdict ==");
        PackageReplacement.Verdict v = PackageReplacement.judge(lmdb("lmdb0", one("postfix-mysql", AWAY),
                lib("liblmdb.so.1", one("postfix-mysql", AWAY)), List.of(), ""));
        check("lmdb -> lmdb0 as on the VM: harmless", v.safe() && v.problems().isEmpty() && v.replacedBy().equals("lmdb0"));
        check("  with the four pieces of evidence written", v.evidence().size() == 4);

        check("  and in the verdict there is nothing left to confirm", !v.toJson().has("confirmable"));

        v = PackageReplacement.judge(lmdb("", one("postfix-mysql", AWAY), lib("liblmdb.so.1", one("postfix-mysql", AWAY)), List.of(), ""));
        check("nobody takes its place: not harmless (it would vanish)", !v.safe() && v.problems().size() == 1);

        v = PackageReplacement.judge(lmdb("lmdb0", one("p5-LMDB", STAYS), lib("liblmdb.so.1", one("postfix-mysql", AWAY)), List.of(), ""));
        check("a package that depends on it stays: not harmless, and it names it", !v.safe() && says(v, "p5-LMDB"));

        v = PackageReplacement.judge(lmdb("lmdb0", one("fakeother", REMOVED), Map.of(), List.of(), ""));
        check("whoever depends on it would be removed too (measured: pkg removes it silently): not harmless",
                !v.safe() && says(v, "fakeother"));

        v = PackageReplacement.judge(lmdb("lmdb0", Map.of(), lib("liblmdb.so.1", one("py312-lmdb", STAYS)), List.of(), ""));
        check("a program uses its library and stays (measured: it stays BROKEN): not harmless, with the library",
                !v.safe() && says(v, "py312-lmdb") && says(v, "liblmdb.so.1"));

        v = PackageReplacement.judge(lmdb("lmdb0", one("postfix-mysql", AWAY), lib("liblmdb.so.1", one("postfix-mysql", AWAY)),
                List.of(), ""));
        check("Postfix has lmdb maps, all with their text: harmless, the panel regenerates them afterwards",
                v.safe() && v.evidence().stream().anyMatch(e -> e.contains("lmdb")));
        v = PackageReplacement.judge(lmdb("lmdb0", one("postfix-mysql", AWAY), lib("liblmdb.so.1", one("postfix-mysql", AWAY)),
                List.of("lmdb:/usr/local/etc/postfix/transport (transport_maps)"), ""));
        check("an lmdb map without its text: not harmless, it would be lost", !v.safe() && says(v, "transport_maps"));

        v = PackageReplacement.judge(lmdb("lmdb0", Map.of(), Map.of(), List.of(), "pkg query: database locked"));
        check("if it could not be measured it is not harmless", !v.safe() && says(v, "database locked"));

        v = PackageReplacement.judge(new PackageReplacement.Facts("fakelib", "1.0", "fakelib0", "/usr/local/bin/fake-tool",
                Map.of(), Map.of(), "", List.of(), ""));
        check("a library that is not a data format asks nothing about data", v.safe() && v.evidence().size() == 3);

        System.out.println("\n== The rule ==");
        JSONObject safe = plan(change("install", "lmdb0", "", "0.9.35"), change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"),
                change("remove", "lmdb", "1.0.2,1", ""));
        safe.put("replacements", new JSONArray().put(new JSONObject().put("name", "lmdb").put("version", "1.0.2,1").put("safe", true)));
        check("a harmless replacement passes on its own", UpdateManager.destructivePlanReason(safe) == null
                && UpdateManager.removalsRefused(safe).isEmpty());

        JSONObject unsafe = new JSONObject(safe.toString());
        unsafe.getJSONArray("replacements").getJSONObject(0).put("safe", false);
        String reason = UpdateManager.destructivePlanReason(unsafe);
        check("a removal that is not harmless stops, and the reason names it", reason != null && reason.contains("lmdb 1.0.2,1")
                && UpdateManager.removalsRefused(unsafe).equals(List.of("lmdb 1.0.2,1")));
        JSONObject stale = new JSONObject(unsafe.toString());
        stale.getJSONArray("replacements").getJSONObject(0).put("confirmable", true);
        check("  and a \"confirmable\" left in a verdict (an old one, or built by hand) changes nothing",
                UpdateManager.destructivePlanReason(stale) != null && UpdateManager.removalsRefused(stale).equals(List.of("lmdb 1.0.2,1")));

        JSONObject unjudged = plan(change("remove", "lmdb", "1.0.2,1", ""));
        check("a removal without a verdict stops (as it always did)", UpdateManager.destructivePlanReason(unjudged) != null
                && UpdateManager.removalsRefused(unjudged).equals(List.of("lmdb 1.0.2,1")));

        JSONObject down = plan(change("downgrade", "redis", "8.10.2", "8.9.0"));
        check("a downgrade stops", UpdateManager.destructivePlanReason(down) != null);

        JSONObject two = plan(change("remove", "fakelib", "1.0", ""), change("remove", "fakeother", "1.0", ""));
        two.put("replacements", new JSONArray()
                .put(new JSONObject().put("name", "fakelib").put("version", "1.0").put("safe", true))
                .put(new JSONObject().put("name", "fakeother").put("version", "1.0").put("safe", false)));
        check("two removals, one harmless and one not: it stops, and names only the other",
                UpdateManager.removalsRefused(two).equals(List.of("fakeother 1.0"))
                        && UpdateManager.destructivePlanReason(two).contains("fakeother 1.0")
                        && !UpdateManager.destructivePlanReason(two).contains("fakelib 1.0"));

        System.out.println("\n== The plan grown after the download ==");
        JSONObject approved = plan(change("install", "lmdb0", "", "0.9.35"), change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"));
        JSONObject grown = plan(change("install", "lmdb0", "", "0.9.35"), change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"),
                change("remove", "lmdb", "1.0.2,1", ""));
        check("grown by a removal: the removal is the only extra thing",
                List.of("lmdb 1.0.2,1").equals(UpdateManager.onlyAddedRemovals(approved, grown)));
        check("grown by an upgrade too: it is not only a removal",
                UpdateManager.onlyAddedRemovals(approved, plan(change("install", "lmdb0", "", "0.9.35"),
                        change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"), change("remove", "lmdb", "1.0.2,1", ""),
                        change("upgrade", "icu", "76.1,1", "77.1,1"))) == null);
        check("a version different from the approved one: it is not only a removal",
                UpdateManager.onlyAddedRemovals(approved, plan(change("install", "lmdb0", "", "0.9.36"),
                        change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"), change("remove", "lmdb", "1.0.2,1", ""))) == null);
        check("an approved change gone: it is not only a removal",
                UpdateManager.onlyAddedRemovals(approved, plan(change("remove", "lmdb", "1.0.2,1", ""))) == null);

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }
}
