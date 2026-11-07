package org.mail_panel.system;

import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The periodic report and the updates the lock holds back.
 *
 * The report's "with an update: N" line read the versions from two keys the rows of packagesStatus
 * never had ("current" and "available"): it was ALWAYS zero. Measured on the FreeBSD 15.1 VM on
 * 23/10/2026 — report 0, while packagesOverview at the same moment counted 2 updates of the stack
 * (nginx and postfix-mysql, both locked) and 5 in all. The report is the only channel that reaches
 * whoever does not open the page, so that silent line is the way a locked package stays behind
 * forever.
 *
 * Three layers, because a key defect is caught by none of the three alone:
 *  1. the logic, on rows built by hand — the case of the old keys included;
 *  2. the contract: the keys packagesStatus REALLY puts are the ones the count reads;
 *  3. the agreement with lockedUpdates, which computes the same thing another way.
 *
 * Layers 2 and 3 need pkg: without it, they are skipped SAYING SO, because a test that skips in
 * silence counts as green without having tested anything.
 */
public class HeldUpdatesReportTest {

    private static int failures = 0, skipped = 0;

    public static void main(String[] args) {

        // ===== 1. The logic =====
        JSONArray lines = new JSONArray()
                // as packagesStatus() puts them: name, role, version, locked, installed
                .put(line("nginx", "1.30.5_2,3", true))
                .put(line("postfix-mysql", "3.11.7_1,1", true))
                .put(line("dovecot", "2.3.21.1_3", true))     // no update
                .put(line("redis", "8.10.2", false))          // not protected, with an update
                .put(line("clamav", "1.5.4_1,1", false));     // not protected, without
        Map<String, String> catalog = new LinkedHashMap<>();
        catalog.put("nginx", "1.30.6,3");
        catalog.put("postfix-mysql", "3.11.7_3,1");
        catalog.put("redis", "8.11.0");
        catalog.put("libzip", "1.12.1");                     // not part of the stack: not relevant

        JSONObject c = UpdateManager.countUpdates(lines, catalog);
        check("it counts the stack's packages", c.getInt("totals") == 5);
        check("it counts the protected ones", c.getInt("protectedNames") == 3);
        check("it counts the available updates", c.getInt("withUpdate") == 3);
        check("it counts how many of those the lock holds back", c.getInt("heldBack") == 2);
        String list = c.getJSONArray("toUpdate").toString();
        check("the list says from which version to which", list.contains("nginx 1.30.5_2,3 -> 1.30.6,3"));
        check("the list marks the held-back ones", list.contains("nginx 1.30.5_2,3 -> 1.30.6,3 ("));
        check("and does not mark who is not protected", list.contains("redis 8.10.2 -> 8.11.0\"")
                || list.contains("redis 8.10.2 -> 8.11.0,"));

        // Same version in the catalog: it is not an update.
        JSONObject same = UpdateManager.countUpdates(
                new JSONArray().put(line("redis", "8.10.2", false)), Map.of("redis", "8.10.2"));
        check("the same version is not an update", same.getInt("withUpdate") == 0);

        // Empty catalog (pkg version did not answer): zero, and zero protected ones held back.
        JSONObject empty = UpdateManager.countUpdates(lines, Map.of());
        check("without a catalog nothing is made up",
             empty.getInt("withUpdate") == 0 && empty.getInt("heldBack") == 0);
        check("but the packages are counted all the same", empty.getInt("totals") == 5);

        // The defect, as a test case: a row with the WRONG keys counts nothing. It says why layer 2
        // exists: in here the count is right and the result is zero all the same.
        JSONArray oldKeys = new JSONArray().put(new JSONObject()
                .put("name", "nginx").put("current", "1.30.5_2,3").put("available", "1.30.6,3")
                .put("locked", true));
        JSONObject old = UpdateManager.countUpdates(oldKeys, catalog);
        check("a row without the 'version' key cannot tell the installed version",
             old.getJSONArray("toUpdate").getString(0).startsWith("nginx  -> "));

        // ===== 2. The contract with packagesStatus =====
        if (!hasPkg()) {
            skip("the real keys of packagesStatus: pkg is not on this machine");
            skip("the agreement between the report and lockedUpdates: pkg is not on this machine");
        } else {
            JSONObject st = UpdateManager.packagesStatus();
            JSONArray real = st.optJSONArray("packages");
            if (real == null || real.length() == 0) {
                skip("the real keys of packagesStatus: no stack package installed");
                skip("the agreement between the report and lockedUpdates: no stack package");
            } else {
                JSONObject r0 = real.getJSONObject(0);
                check("packagesStatus puts 'name'", r0.has("name"));
                check("packagesStatus puts 'version', the key the count reads", r0.has("version"));
                check("packagesStatus puts 'locked'", r0.has("locked"));
                check("packagesStatus does NOT put 'available': whoever reads it counts zero",
                     !r0.has("available"));

                // ===== 3. The agreement with the other way =====
                JSONArray heldBackElsewhere = UpdateManager.lockedUpdates();
                JSONObject report = UpdateManager.reportData(false);
                int fromReport = report.optInt("heldBackPackages", -1);
                if (heldBackElsewhere.length() == 0) {
                    skip("the agreement between the report and lockedUpdates: on this machine no"
                        + " protected package has an update, there is nothing to measure");
                } else {
                    check("the report counts the held-back ones like lockedUpdates ("
                         + fromReport + " against " + heldBackElsewhere.length() + ")",
                         fromReport == heldBackElsewhere.length());
                    check("and so the 'with an update' line cannot be zero",
                         report.optInt("packagesWithUpdate", 0) >= heldBackElsewhere.length());
                    boolean said = false;
                    JSONArray toDo = report.optJSONArray("toDo");
                    for (int i = 0; toDo != null && i < toDo.length(); i++)
                        if (toDo.getJSONObject(i).optString("what").contains("pkg upgrade")) said = true;
                    check("among the things to do it says that pkg upgrade skips them", said);
                }
            }
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " CHECKS SKIPPED (they say so above)");
        System.out.println(failures == 0 ? "ALL OK" : failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /** A row as packagesStatus() puts it. */
    private static JSONObject line(String name, String version, boolean isProtected) {
        return new JSONObject().put("name", name).put("role", "test")
                .put("version", version).put("locked", isProtected).put("installed", true);
    }

    private static boolean hasPkg() {
        return org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(15),
                "pkg -N >/dev/null 2>&1").success();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }

    private static void skip(String name) {
        System.out.println("  --   SKIPPED: " + name);
        skipped++;
    }
}
