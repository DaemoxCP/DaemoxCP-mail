package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The panel does not run plans that REMOVE or DOWNGRADE packages.
 *
 * It is a rule of the panel, not a fact of pkg: an update that takes a package off a mail server,
 * or that brings its version back, must be decided by a person who knows who uses it.
 *
 * It was written in one place only — the card of a protected package — and it was missing in the
 * other two jobs that run a plan. Measured on the FreeBSD 15.1 VM on 23/10/2026, on the same
 * machine and the same package:
 *
 *   guided update of postfix-mysql -> "[block] The plan removes packages:
 *                                      pkg would remove lmdb 1.0.2,1"
 *   full maintenance                -> runnable=true, blockers [], and in the plan
 *                                      "removes lmdb 1.0.2,1"
 *
 * Two opposite answers to the same question, and the permissive one was on the button one presses
 * to update everything.
 *
 * Here the rule is tested, which is now a single function. That the three jobs really ask for it
 * shows on the machine: the full maintenance, on that VM, stops.
 */
public class DestructivePlanTest {

    private static int failures = 0;

    public static void main(String[] args) {

        // ===== The measured case: the maintenance plan on that machine =====
        JSONObject real = plan(
                change("install", "lmdb0", "", "0.9.35"),
                change("upgrade", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"),
                change("remove", "lmdb", "1.0.2,1", ""));
        String reason = UpdateManager.destructivePlanReason(real);
        check("the plan measured on the VM does not run", reason != null);
        check("  and the reason names the package and the version",
             reason != null && reason.contains("lmdb 1.0.2,1"));
        JSONObject d = UpdateManager.destructiveChanges(real);
        check("  one removal, no downgrade",
             d.getJSONArray("removes").length() == 1 && d.getJSONArray("downgrades").isEmpty());
        check("  and the installation and the upgrade have nothing to do with it",
             !d.getJSONArray("removes").toString().contains("lmdb0")
             && !d.getJSONArray("removes").toString().contains("postfix-mysql"));

        // ===== A downgrade =====
        JSONObject downgrade = plan(change("downgrade", "redis", "8.10.2", "8.9.0"));
        String m2 = UpdateManager.destructivePlanReason(downgrade);
        check("a downgrade does not run", m2 != null);
        check("  and the reason says from which version to which",
             m2 != null && m2.contains("8.10.2") && m2.contains("8.9.0"));

        // ===== Both together: both are said =====
        String m3 = UpdateManager.destructivePlanReason(plan(
                change("remove", "lmdb", "1.0.2,1", ""),
                change("downgrade", "redis", "8.10.2", "8.9.0")));
        check("removal and downgrade together: the reason says both",
             m3 != null && m3.contains("lmdb") && m3.contains("redis"));

        // ===== A plan that touches nothing that way: it runs =====
        check("upgrades, installations and reinstallations stop nothing",
             UpdateManager.destructivePlanReason(plan(
                 change("upgrade", "nginx", "1.30.5_2,3", "1.30.6,3"),
                 change("install", "lmdb0", "", "0.9.35"),
                 change("reinstall", "cyrus-sasl", "2.1.28_5", "2.1.28_5"))) == null);

        // ===== Empty or missing plans: no made-up reason =====
        check("a plan without changes does not stop",
             UpdateManager.destructivePlanReason(plan()) == null);
        check("a plan without the 'changes' key does not stop",
             UpdateManager.destructivePlanReason(new JSONObject()) == null);
        check("nor does a null plan",
             UpdateManager.destructivePlanReason(null) == null);
        check("on a null plan the list is empty, not null",
             UpdateManager.destructiveChanges(null).getJSONArray("removes").isEmpty());

        // ===== Many removals: all are named, not only the first =====
        String m4 = UpdateManager.destructivePlanReason(plan(
                change("remove", "lmdb", "1.0.2,1", ""),
                change("remove", "tinycdb", "0.81", ""),
                change("remove", "libtlsrpt", "0.5.1", "")));
        check("three removals, all named",
             m4 != null && m4.contains("lmdb") && m4.contains("tinycdb") && m4.contains("libtlsrpt"));

        // ===== The removals a job declares itself: they are the job, not a side effect =====
        // The MySQL 8.4 migration removes mysql80-server and mysql80-client, the Python transition
        // removes the old py3XX packages: PackagePlan.planRemoveThenInstall marks them "intended",
        // they are in the signed plan and the inventory checks them. Any OTHER removal follows the
        // rule, also inside the same plan.
        JSONObject migration = plan(
                change("remove", "mysql80-server", "8.0.46", "").put("intended", true),
                change("remove", "mysql80-client", "8.0.46", "").put("intended", true),
                change("install", "mysql84-server", "", "8.4.11"),
                change("install", "mysql84-client", "", "8.4.11"));
        check("the removals the job declares do not stop its plan",
             UpdateManager.destructivePlanReason(migration) == null);
        check("  and they are not counted as removals",
             UpdateManager.destructiveChanges(migration).getJSONArray("removes").isEmpty());
        String m5 = UpdateManager.destructivePlanReason(plan(
                change("remove", "mysql80-client", "8.0.46", "").put("intended", true),
                change("install", "mysql84-client", "", "8.4.11"),
                change("remove", "postfix-mysql", "3.11.7_3,1", "")));
        check("a removal the job did NOT declare still stops it, and only that one is named",
             m5 != null && m5.contains("postfix-mysql") && !m5.contains("mysql80-client"));
        check("\"intended\": false is an ordinary removal",
             UpdateManager.destructivePlanReason(plan(
                 change("remove", "lmdb", "1.0.2,1", "").put("intended", false))) != null);

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static JSONObject change(String type, String name, String from, String a) {
        return new JSONObject().put("type", type).put("name", name).put("from", from).put("to", a);
    }

    private static JSONObject plan(JSONObject... changeList) {
        JSONArray c = new JSONArray();
        for (JSONObject x : changeList) c.put(x);
        return new JSONObject().put("changes", c).put("measured", true).put("runnable", true);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
