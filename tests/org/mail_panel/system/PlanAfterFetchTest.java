package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The plan depends on what is in pkg's cache, so it must be read again after the download.
 *
 * Measured on the FreeBSD 15.1 VM on 23/10/2026, twice on the same package and the same catalog,
 * two minutes apart:
 *
 *   without the files in /var/cache/pkg -> 3 changes (installs lmdb0, installs mysql97-client,
 *                                          upgrades postfix-mysql)
 *   with the files in /var/cache/pkg    -> 4 changes, the same plus "removes lmdb 1.0.2,1"
 *
 * pkg's integrity check sees the conflicts on files only when the packages are downloaded. And the
 * panel REFUSES the plans that remove packages: that refusal was bypassed every time the packages
 * were not downloaded yet, that is at the first try.
 *
 * Here the comparison between two plans is tested: it must be blind to what necessarily changes
 * between the card and the run (the protections to remove) and sensitive to what matters (the
 * changes).
 */
public class PlanAfterFetchTest {

    private static int failures = 0;

    public static void main(String[] args) {

        // The approved plan: postfix-mysql was protected, so it had to be unlocked.
        JSONObject approved = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray().put("postfix-mysql"))
                .put("changes", new JSONArray()
                        .put(change("install", "lmdb0", "", "0.9.35"))
                        .put(change("install", "mysql97-client", "", "9.7.2"))
                        .put(change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1")));

        // The same plan computed again AFTER the real unlock: nothing left to unlock, and the
        // changes come in another order because another simulation lists them.
        JSONObject afterUnlock = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"))
                        .put(change("install", "mysql97-client", "", "9.7.2"))
                        .put(change("install", "lmdb0", "", "0.9.35")));

        // The plan with the removal that appears only after the download.
        JSONObject grown = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("install", "lmdb0", "", "0.9.35"))
                        .put(change("install", "mysql97-client", "", "9.7.2"))
                        .put(change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"))
                        .put(change("remove", "lmdb", "1.0.2,1", "")));

        String approvedSignature = PackagePlan.changesSignature(approved);
        String afterSignature = PackagePlan.changesSignature(afterUnlock);
        String grownSignature = PackagePlan.changesSignature(grown);

        check("the unlock already done does not change the changes' signature", approvedSignature.equals(afterSignature));
        check("nor does the order in which the simulation lists them", approvedSignature.equals(afterSignature));
        check("one more removal changes it", !approvedSignature.equals(grownSignature));
        check("the signature is 16 hex digits", approvedSignature.matches("[0-9a-f]{16}"));

        // The WHOLE signature, instead, would change for the unlock alone: that is why one on the
        // changes alone is needed. If one day somebody compared that one, the job would always
        // stop, and for the wrong reason.
        check("the whole signature changes for the unlock alone, and must not be used here",
             !PackagePlan.signature(approved).equals(PackagePlan.signature(afterUnlock)));

        // A different target version is a different plan.
        JSONObject otherVersion = new JSONObject()
                .put("measured", true).put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("install", "lmdb0", "", "0.9.35"))
                        .put(change("install", "mysql97-client", "", "9.7.2"))
                        .put(change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.8,1")));
        check("a different target version changes the signature",
             !approvedSignature.equals(PackagePlan.changesSignature(otherVersion)));

        // One package less in the plan is a different plan: the check looks in both directions,
        // not only at the additions.
        JSONObject reduced = new JSONObject()
                .put("measured", true).put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1")));
        check("one change less changes the signature", !approvedSignature.equals(PackagePlan.changesSignature(reduced)));

        // Empty plans: no exception, and two empty ones look alike.
        check("a plan without changes has a stable signature",
             PackagePlan.changesSignature(new JSONObject()).equals(
                     PackagePlan.changesSignature(new JSONObject().put("changes", new JSONArray()))));

        // The lines to show: one per change, readable, in a stable order.
        java.util.List<String> lines = PackagePlan.changesInLines(grown);
        check("the lines to show are one per change", lines.size() == 4);
        check("  and they name the package and the versions",
             lines.toString().contains("postfix-mysql 3.11.7_1,1 -> 3.11.7_3,1"));
        check("  the removal appears with the version that is there now",
             lines.toString().contains("lmdb 1.0.2,1"));
        check("  and the order does not depend on the simulation's",
             lines.equals(PackagePlan.changesInLines(reorder(grown))));

        // ===== The three package jobs ALL ask for the signature =====
        //
        // It was the missing invariant: the update of the unprotected ones started without it, that
        // is it ran a "pkg upgrade -y" nobody had approved line by line. The check happens before
        // taking the turn and before touching pkg, so it is tested here.
        for (String signature : new String[]{"", "   ", "abc", "ZZZZZZZZZZZZZZZZ", "0123456789abcde",
                                         "0123456789abcdef0", "0123456789ABCDEF"}) {
            check("the update of the unprotected ones refuses the signature \"" + signature + "\"",
                 !UpdateManager.startUnlockedPackagesUpdate(signature).optBoolean("success"));
            check("  the maintenance refuses the same",
                 !UpdateManager.startMaintenance(signature).optBoolean("success"));
            check("  and the guided update too",
                 !UpdateManager.startGuidedUpdate("nginx", signature).optBoolean("success"));
        }
        check("and with no signature at all (null) nothing starts",
             !UpdateManager.startUnlockedPackagesUpdate(null).optBoolean("success")
             && !UpdateManager.startMaintenance(null).optBoolean("success")
             && !UpdateManager.startGuidedUpdate("nginx", null).optBoolean("success"));

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static JSONObject change(String type, String name, String from, String a) {
        return new JSONObject().put("type", type).put("name", name).put("from", from).put("to", a);
    }

    /** The same plan with the changes the other way round. */
    private static JSONObject reorder(JSONObject plan) {
        JSONArray c = plan.getJSONArray("changes"), r = new JSONArray();
        for (int i = c.length() - 1; i >= 0; i--) r.put(c.get(i));
        return new JSONObject(plan.toString()).put("changes", r);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
