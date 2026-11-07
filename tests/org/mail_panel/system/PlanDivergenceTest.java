package org.mail_panel.system;

import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * What changed without being in the signed plan.
 *
 * The expected/found comparison of {@code verifyOutcome} walks the lines of the PLAN: it sees a
 * package of the plan that did not get where it should, and it can NOT see a changed package that
 * was not in the plan. On 18 October 2026, on the VM, it really happened: the signed plan
 * 465385a9d669def8 had ten changes and no removal, pkg found a conflict during the run (lmdb0
 * against lmdb on /usr/local/bin/mdb_copy), computed again and REMOVED lmdb. The verification
 * checked its ten, found them all "ok" and concluded "verification passed".
 *
 * Here the comparison with the inventory is tested, which looks from the other direction. The
 * first case is that reperto, with its data.
 *
 * The inventory lines are the real ones of {@code pkg query '%n\t%v\t%k'}, read by the real parser:
 * a test on maps built by hand would skip exactly the place where a key or format defect hides.
 */
public class PlanDivergenceTest {

    private static int failures = 0, skipped = 0;

    public static void main(String[] args) {

        // ===== 1. Reperto 14, with its data =====
        // Before: lmdb installed. The plan: install lmdb0, upgrade nginx, reinstall cyrus-sasl. No
        // removal. After: lmdb is no longer there.
        Map<String, String> before = PackagePlan.versionsOnly(PackagePlan.installed(
                "lmdb\t1.0.2,1\t0\n"
              + "nginx\t1.30.5_1,3\t1\n"
              + "cyrus-sasl\t2.1.28_5\t0\n"));
        Map<String, String> after = PackagePlan.versionsOnly(PackagePlan.installed(
                "lmdb0\t0.9.35\t0\n"
              + "nginx\t1.30.5_4,3\t1\n"
              + "cyrus-sasl\t2.1.28_5\t0\n"));
        JSONObject plan = plan(
                change("install", "lmdb0", "", "0.9.35"),
                change("upgrade", "nginx", "1.30.5_1,3", "1.30.5_4,3"),
                change("reinstall", "cyrus-sasl", "2.1.28_5", "2.1.28_5"));

        JSONArray d = PackagePlan.divergences(before, after, plan);
        check("reperto 14: the removal outside the plan is seen", d.length() == 1);
        if (d.length() == 1) {
            JSONObject x = d.getJSONObject(0);
            check("  it is lmdb", "lmdb".equals(x.optString("name")));
            check("  and it was removed", "removed".equals(x.optString("happened")));
            check("  with the version that was there", "1.0.2,1".equals(x.optString("from")));
            check("  and the reason is that it was not in the plan", !x.optString("why").isEmpty());
            check("  the line to show names the package",
                 PackagePlan.divergenceInLine(x).contains("lmdb"));
        }
        check("the planned installation and the planned upgrade are not divergences",
             d.length() == 1);

        // ===== 2. Everything as planned: no divergence =====
        check("plan followed to the letter: no divergence",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\nredis\t8.10.2\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\nredis\t8.10.2\t1\n")),
                 plan(change("upgrade", "nginx", "1.30.5_1,3", "1.30.6,3"))).isEmpty());

        // ===== 3. An installed package that was not in the plan =====
        JSONArray inst = PackagePlan.divergences(
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\n")),
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\nlibzip\t1.12.1\t0\n")),
                plan());
        check("an installation outside the plan is seen",
             inst.length() == 1 && "installed".equals(field(inst, "happened"))
             && "libzip".equals(field(inst, "name")));
        check("  and it says to which version", "1.12.1".equals(field(inst, "to")));

        // ===== 4. It was in the plan, but it ended at a DIFFERENT version =====
        JSONArray other = PackagePlan.divergences(
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.31.0,3\t1\n")),
                plan(change("upgrade", "nginx", "1.30.5_1,3", "1.30.6,3")));
        check("a target version different from the approved one is seen", other.length() == 1);
        check("  and the reason says what the plan said", field(other, "why").contains("1.30.6,3"));

        // ===== 5. A PLANNED removal is not a divergence =====
        check("a planned removal is not a divergence",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("lmdb\t1.0.2,1\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("")),
                 plan(change("remove", "lmdb", "1.0.2,1", ""))).isEmpty());

        // ===== 6. A reinstallation leaves no trace in the inventory =====
        // Same version before and after: it cannot be seen from here, and it MUST not be. That the
        // reinstallation happened is checked by verifyOutcome, which compares the plan's versions.
        // The two checks complement each other: this one looks at what changed without permission,
        // that one at what was promised and did not happen.
        check("a reinstallation produces no divergences",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("cyrus-sasl\t2.1.28_5\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("cyrus-sasl\t2.1.28_5\t0\n")),
                 plan(change("reinstall", "cyrus-sasl", "2.1.28_5", "2.1.28_5"))).isEmpty());

        // ===== 7. An upgrade promised and not done is NOT a divergence =====
        // It is not an oversight: nothing changed in the inventory, and that case is caught by
        // verifyOutcome ("expected 1.30.6,3, found 1.30.5_1,3"). If one day somebody made it appear
        // here too, the same fault would be said twice with two different names.
        //
        check("an upgrade promised and not done does not appear here (verifyOutcome catches it)",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                 plan(change("upgrade", "nginx", "1.30.5_1,3", "1.30.6,3"))).isEmpty());

        // ===== 8. A planned downgrade, and pkg updating itself =====
        check("a planned downgrade is not a divergence",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("redis\t8.10.2\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("redis\t8.9.0\t1\n")),
                 plan(change("downgrade", "redis", "8.10.2", "8.9.0"))).isEmpty());
        check("pkg updating itself, if the plan declares it, is not a divergence",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.1.0\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.2.0\t0\n")),
                 plan(change("upgrade", "pkg", "2.1.0", "2.2.0"))).isEmpty());
        check("and if the plan does NOT declare it, yes, it is a divergence",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.1.0\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.2.0\t0\n")),
                 plan()).length() == 1);

        // ===== 9. No measurable plan: no verdict is made up =====
        check("with a plan without changes, every change is outside the plan",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\n")),
                 new JSONObject()).length() == 1);
        check("identical inventories and an empty plan: nothing to say",
             PackagePlan.divergences(Map.of("nginx", "1.30.6,3"), Map.of("nginx", "1.30.6,3"),
                 new JSONObject()).isEmpty());

        // ===== 10. The contract with real pkg =====
        if (!hasPkg()) {
            skip("pkg's real inventory: pkg is not on this machine");
        } else {
            Map<String, String> inventory = PackagePlan.versionsOnly(PackagePlan.installed());
            check("the real inventory is not empty", !inventory.isEmpty());
            boolean sensibleVersions = true;
            for (Map.Entry<String, String> e : inventory.entrySet())
                if (e.getValue() == null || e.getValue().isEmpty()) sensibleVersions = false;
            check("and every package has a version", sensibleVersions);
            // Two inventories in a row, without touching anything: zero divergences. If this
            // failed, the comparison would give false alarms at every upgrade.
            check("two inventories in a row produce no divergences",
                 PackagePlan.divergences(inventory, PackagePlan.versionsOnly(PackagePlan.installed()),
                         new JSONObject()).isEmpty());
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " CHECKS SKIPPED (they say so above)");
        System.out.println(failures == 0 ? "ALL OK" : failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /** A field of the first divergence, or an empty string if there is none: a failing test must
     *  say EVERYTHING that is wrong, not stop at the first missing thing. */
    private static String field(JSONArray d, String key) {
        return d.length() == 0 ? "" : d.getJSONObject(0).optString(key);
    }

    private static JSONObject change(String type, String name, String from, String a) {
        return new JSONObject().put("type", type).put("name", name).put("from", from).put("to", a);
    }

    private static JSONObject plan(JSONObject... changeList) {
        JSONArray c = new JSONArray();
        for (JSONObject x : changeList) c.put(x);
        return new JSONObject().put("changes", c).put("measured", true);
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
