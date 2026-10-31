package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Il giudizio su un pacchetto che un aggiornamento toglie (PackageReplacement.judge) e la regola
 * che lo usa (UpdateManager: removalsRefused, destructivePlanReason, onlyAddedRemovals). Niente
 * comandi: i fatti sono scritti qui. Quello che pkg risponde davvero lo misura
 * PackageReplacementE2ETest sulla VM.
 *
 * Il caso di partenza e' quello vero di fine ottobre 2026: postfix-mysql 3.11.7_3,1 passa da lmdb
 * a lmdb0, che installa gli stessi file, e pkg toglie lmdb.
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageReplacementTest
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

    /** lmdb tolto per lmdb0, come sulla VM il 24/10/2026, con un solo dettaglio cambiato a scelta. */
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
        System.out.println("\n== La riga di pkg ==");
        String real = "Checking integrity... done (1 conflicting)\n"
                + "  - lmdb0-0.9.35 [FreeBSD-ports] conflicts with lmdb-1.0.2,1 [installed] on /usr/local/bin/mdb_copy\n"
                + "Checking integrity... done (0 conflicting)\n";
        List<PackageReplacement.Conflict> k = PackageReplacement.conflicts(real);
        check("la riga vera di lmdb (24/10/2026, col nome del repository fra parentesi): lmdb0 al posto di lmdb su mdb_copy",
                k.size() == 1 && k.get(0).newName().equals("lmdb0") && k.get(0).oldName().equals("lmdb")
                        && k.get(0).file().equals("/usr/local/bin/mdb_copy"));
        k = PackageReplacement.conflicts("  - fakelib0-0.9 conflicts with fakelib-1.0 on /usr/local/bin/fake-tool\n");
        check("la riga di un repository locale, senza parentesi (misurata sulla VM il 31/10/2026)",
                k.size() == 1 && k.get(0).newName().equals("fakelib0") && k.get(0).oldName().equals("fakelib"));
        check("il nome da nome-versione, anche con trattini nel nome",
                PackageReplacement.nameOf("postfix-mysql-3.11.7_3,1").equals("postfix-mysql")
                        && PackageReplacement.nameOf("lmdb-1.0.2,1").equals("lmdb"));
        check("nessuna riga di conflitto, nessuna sostituzione", PackageReplacement.conflicts("Number of packages to be removed: 1").isEmpty());

        System.out.println("\n== Il giudizio ==");
        PackageReplacement.Verdict v = PackageReplacement.judge(lmdb("lmdb0", one("postfix-mysql", AWAY),
                lib("liblmdb.so.1", one("postfix-mysql", AWAY)), List.of(), ""));
        check("lmdb -> lmdb0 come sulla VM: innocua", v.safe() && v.problems().isEmpty() && v.replacedBy().equals("lmdb0"));
        check("  con le quattro prove scritte", v.evidence().size() == 4);

        check("  e nel giudizio non c'e' piu' niente da confermare", !v.toJson().has("confirmable"));

        v = PackageReplacement.judge(lmdb("", one("postfix-mysql", AWAY), lib("liblmdb.so.1", one("postfix-mysql", AWAY)), List.of(), ""));
        check("nessuno prende il suo posto: non innocua (sparirebbe)", !v.safe() && v.problems().size() == 1);

        v = PackageReplacement.judge(lmdb("lmdb0", one("p5-LMDB", STAYS), lib("liblmdb.so.1", one("postfix-mysql", AWAY)), List.of(), ""));
        check("un pacchetto che dipende da lui resta: non innocua, e lo nomina", !v.safe() && says(v, "p5-LMDB"));

        v = PackageReplacement.judge(lmdb("lmdb0", one("fakeother", REMOVED), Map.of(), List.of(), ""));
        check("chi dipende da lui verrebbe tolto anche lui (misurato: pkg lo toglie in silenzio): non innocua",
                !v.safe() && says(v, "fakeother"));

        v = PackageReplacement.judge(lmdb("lmdb0", Map.of(), lib("liblmdb.so.1", one("py312-lmdb", STAYS)), List.of(), ""));
        check("un programma usa la sua libreria e resta (misurato: resta ROTTO): non innocua, con la libreria",
                !v.safe() && says(v, "py312-lmdb") && says(v, "liblmdb.so.1"));

        v = PackageReplacement.judge(lmdb("lmdb0", one("postfix-mysql", AWAY), lib("liblmdb.so.1", one("postfix-mysql", AWAY)),
                List.of(), ""));
        check("Postfix ha mappe lmdb, tutte col loro testo: innocua, le rigenera il pannello dopo",
                v.safe() && v.evidence().stream().anyMatch(e -> e.contains("lmdb")));
        v = PackageReplacement.judge(lmdb("lmdb0", one("postfix-mysql", AWAY), lib("liblmdb.so.1", one("postfix-mysql", AWAY)),
                List.of("lmdb:/usr/local/etc/postfix/transport (transport_maps)"), ""));
        check("una mappa lmdb senza il suo testo: non innocua, si perderebbe", !v.safe() && says(v, "transport_maps"));

        v = PackageReplacement.judge(lmdb("lmdb0", Map.of(), Map.of(), List.of(), "pkg query: database locked"));
        check("se non si e' potuto misurare non e' innocua", !v.safe() && says(v, "database locked"));

        v = PackageReplacement.judge(new PackageReplacement.Facts("fakelib", "1.0", "fakelib0", "/usr/local/bin/fake-tool",
                Map.of(), Map.of(), "", List.of(), ""));
        check("una libreria che non e' un formato di dati non chiede niente sui dati", v.safe() && v.evidence().size() == 3);

        System.out.println("\n== La regola ==");
        JSONObject safe = plan(change("install", "lmdb0", "", "0.9.35"), change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"),
                change("remove", "lmdb", "1.0.2,1", ""));
        safe.put("replacements", new JSONArray().put(new JSONObject().put("name", "lmdb").put("version", "1.0.2,1").put("safe", true)));
        check("una sostituzione innocua passa da sola", UpdateManager.destructivePlanReason(safe) == null
                && UpdateManager.removalsRefused(safe).isEmpty());

        JSONObject unsafe = new JSONObject(safe.toString());
        unsafe.getJSONArray("replacements").getJSONObject(0).put("safe", false);
        String reason = UpdateManager.destructivePlanReason(unsafe);
        check("una rimozione non innocua si ferma, e il motivo la nomina", reason != null && reason.contains("lmdb 1.0.2,1")
                && UpdateManager.removalsRefused(unsafe).equals(List.of("lmdb 1.0.2,1")));
        JSONObject stale = new JSONObject(unsafe.toString());
        stale.getJSONArray("replacements").getJSONObject(0).put("confirmable", true);
        check("  e un «confirmable» rimasto in un giudizio (di prima, o costruito a mano) non cambia niente",
                UpdateManager.destructivePlanReason(stale) != null && UpdateManager.removalsRefused(stale).equals(List.of("lmdb 1.0.2,1")));

        JSONObject unjudged = plan(change("remove", "lmdb", "1.0.2,1", ""));
        check("una rimozione senza giudizio si ferma (com'era sempre)", UpdateManager.destructivePlanReason(unjudged) != null
                && UpdateManager.removalsRefused(unjudged).equals(List.of("lmdb 1.0.2,1")));

        JSONObject down = plan(change("downgrade", "redis", "8.10.2", "8.9.0"));
        check("una retrocessione si ferma", UpdateManager.destructivePlanReason(down) != null);

        JSONObject two = plan(change("remove", "fakelib", "1.0", ""), change("remove", "fakeother", "1.0", ""));
        two.put("replacements", new JSONArray()
                .put(new JSONObject().put("name", "fakelib").put("version", "1.0").put("safe", true))
                .put(new JSONObject().put("name", "fakeother").put("version", "1.0").put("safe", false)));
        check("due rimozioni, una innocua e una no: si ferma, e nomina solo l'altra",
                UpdateManager.removalsRefused(two).equals(List.of("fakeother 1.0"))
                        && UpdateManager.destructivePlanReason(two).contains("fakeother 1.0")
                        && !UpdateManager.destructivePlanReason(two).contains("fakelib 1.0"));

        System.out.println("\n== Il piano cresciuto dopo lo scaricamento ==");
        JSONObject approved = plan(change("install", "lmdb0", "", "0.9.35"), change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"));
        JSONObject grown = plan(change("install", "lmdb0", "", "0.9.35"), change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"),
                change("remove", "lmdb", "1.0.2,1", ""));
        check("cresciuto di una rimozione: la rimozione e' l'unica cosa in piu'",
                List.of("lmdb 1.0.2,1").equals(UpdateManager.onlyAddedRemovals(approved, grown)));
        check("cresciuto anche di un aggiornamento: non e' solo una rimozione",
                UpdateManager.onlyAddedRemovals(approved, plan(change("install", "lmdb0", "", "0.9.35"),
                        change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"), change("remove", "lmdb", "1.0.2,1", ""),
                        change("upgrade", "icu", "76.1,1", "77.1,1"))) == null);
        check("una versione diversa da quella approvata: non e' solo una rimozione",
                UpdateManager.onlyAddedRemovals(approved, plan(change("install", "lmdb0", "", "0.9.36"),
                        change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"), change("remove", "lmdb", "1.0.2,1", ""))) == null);
        check("un cambiamento approvato sparito: non e' solo una rimozione",
                UpdateManager.onlyAddedRemovals(approved, plan(change("remove", "lmdb", "1.0.2,1", ""))) == null);

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }
}
