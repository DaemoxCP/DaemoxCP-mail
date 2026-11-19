package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * The exact plan of an update and the answer to "is the fix there?".
 *
 * The outputs below have the shape pkg's source prints (src/utils.c for the plan, src/audit.c for
 * the JSON): sections with the entries indented by a tab, the totals at the end, " (vulnerable!)"
 * next to the target versions still vulnerable, the VuXML ranges like "&gt;= a : &lt; b".
 *
 * The case that prompted the class is at the end of the fix group: nginx 1.30.4,3, catalog stuck at
 * the same, VuXML saying "&lt; 1.30.5,3". The card said both "protected: the patch will not be
 * applied" and "no update in your branch", and it was not clear whether the patch existed.
 *
 * With the "simulation" argument it also tests the database copy, against a fake pkg: it must be
 * started by tests/pkg-simulation-test.sh, which puts the fake one in the PATH.
 *
 * The panel's texts are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class PackagePlanTest {

    private static int failed = 0;

    /** Simplified comparison for the tests: epoch after the comma, revision after "_", then the numbers. */
    static final PackagePlan.VersionComparator CMP = (a, b) -> {
        String[] ea = a.split(","), eb = b.split(",");
        int epochA = ea.length > 1 ? Integer.parseInt(ea[1]) : 0, epochB = eb.length > 1 ? Integer.parseInt(eb[1]) : 0;
        if (epochA != epochB) return Integer.compare(epochA, epochB);
        String[] ra = ea[0].split("_"), rb = eb[0].split("_");
        String[] pa = ra[0].split("[.+]"), pb = rb[0].split("[.+]");
        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
            long x = i < pa.length ? Long.parseLong(pa[i]) : 0, y = i < pb.length ? Long.parseLong(pb[i]) : 0;
            if (x != y) return Long.compare(x, y);
        }
        int versionA = ra.length > 1 ? Integer.parseInt(ra[1]) : 0, versionB = rb.length > 1 ? Integer.parseInt(rb[1]) : 0;
        return Integer.compare(versionA, versionB);
    };

    public static void main(String[] args) throws Exception {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        if (args.length > 0 && args[0].equals("simulation")) { simulation(); end(); return; }
        // The two family-twin cases that need a different fake pkg: the script starts them apart,
        // with V_CAT and MYSQL97 (see tests/pkg-simulation-test.sh).
        if (args.length > 0 && args[0].equals("family-new-catalog")) { familyNewCatalog(); end(); return; }
        if (args.length > 0 && args[0].equals("family-real-conflict")) { familyRealConflict(); end(); return; }

        // ---------------- the plan ----------------

        JSONObject p = PackagePlan.readPlan(String.join("\n",
            "Updating database digests format: . done",
            "Checking integrity... done (0 conflicting)",
            "The following 1 package(s) will be affected (of 0 checked):",
            "",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 1",
            "",
            "81 MiB to be downloaded."));
        real("kafka alone: measured", p.getBoolean("measured"));
        JSONObject k = p.getJSONArray("changes").getJSONObject(0);
        real("kafka alone: 4.3.0 -> 4.3.1",
            "upgrade".equals(k.getString("type")) && "kafka".equals(k.getString("name"))
            && "4.3.0".equals(k.getString("from")) && "4.3.1".equals(k.getString("to")));
        real("kafka alone: not vulnerable yet", !k.getBoolean("stillVulnerable"));

        String large = String.join("\n",
            "The following 5 package(s) will be affected (of 0 checked):",
            "",
            "Installed packages to be REMOVED:",
            "\tphp84-pecl-rdkafka: 6.0.3_1 (conflicts with php84-pecl-rdkafka6)",
            "",
            "New packages to be INSTALLED:",
            "\tpcre2: 10.45",
            "",
            "Installed packages to be REINSTALLED:",
            "\tphp84-8.4.19 (direct dependency changed: pcre2)",
            "",
            "Installed packages to be UPGRADED:",
            "\tnginx: 1.30.4,3 -> 1.30.5,3",
            "\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)",
            "",
            "Number of packages to be removed: 1",
            "Number of packages to be installed: 1",
            "Number of packages to be upgraded: 2",
            "Number of packages to be reinstalled: 1",
            "",
            "The process will require 2 MiB more space.",
            "12 MiB to be downloaded.");
        p = PackagePlan.readPlan(large);
        real("large plan: measured and with 5 changes", p.getBoolean("measured") && p.getJSONArray("changes").length() == 5);
        real("large plan: the removal has name, version and reason",
            find(p, "php84-pecl-rdkafka").getString("type").equals("remove")
            && find(p, "php84-pecl-rdkafka").getString("from").equals("6.0.3_1")
            && find(p, "php84-pecl-rdkafka").getString("reason").startsWith("conflicts with"));
        real("large plan: the new installation", "10.45".equals(find(p, "pcre2").getString("to")));
        real("large plan: the reinstallation separates name and version",
            "8.4.19".equals(find(p, "php84").getString("from")) && find(p, "php84").getString("reason").contains("pcre2"));
        real("large plan: nginx with the epoch", "1.30.5,3".equals(find(p, "nginx").getString("to")));
        real("large plan: openssl still vulnerable after the upgrade",
            find(p, "openssl35").getBoolean("stillVulnerable") && "3.5.3".equals(find(p, "openssl35").getString("to")));

        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages LOCKED:",
            "\tPackage openjdk21-21.0.8+9.1 is locked and may not be upgraded to version 21.0.9+10.1",
            "",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 1"));
        real("protected in the plan: measured", p.getBoolean("measured"));
        JSONObject b = p.getJSONArray("lockedPackages").getJSONObject(0);
        real("protected in the plan: name, version and where it would go",
            "openjdk21".equals(b.getString("name")) && "21.0.8+9.1".equals(b.getString("version"))
            && "21.0.9+10.1".equals(b.getString("destination")));

        p = PackagePlan.readPlan(String.join("\n",
            "Checking integrity... done (0 conflicting)",
            "",
            "php84-pecl-rdkafka-6.0.3_1 is locked and may not be modified",
            "Your packages are up to date."));
        real("protected as an event (older pkg): the name with dashes",
            p.getJSONArray("lockedPackages").length() == 1
            && "php84-pecl-rdkafka".equals(p.getJSONArray("lockedPackages").getJSONObject(0).getString("name")));

        p = PackagePlan.readPlan("Checking for upgrades (1 candidates): 100%\nYour packages are up to date.");
        real("nothing to do", p.getBoolean("measured") && p.getBoolean("nothingToDo") && p.getJSONArray("changes").isEmpty());

        p = PackagePlan.readPlan("pkg: No packages available to upgrade matching 'kafka' have been found in the repositories");
        real("a pkg error reported, not kept quiet", p.getJSONArray("pkgErrors").length() == 1);

        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tnginx: 1.30.4,3 -> 1.30.5,3 [FreeBSD-latest]",
            "",
            "Number of packages to be upgraded: 1"));
        real("with more repositories: the repository's name", "FreeBSD-latest".equals(find(p, "nginx").getString("repo")));

        // Totals that do not add up do not become a "complete" plan.
        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 2"));
        real("different total: not measured", !p.getBoolean("measured"));
        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka 4.3.0 4.3.1",
            "",
            "Number of packages to be upgraded: 1"));
        real("unreadable line: not measured", !p.getBoolean("measured") && p.getJSONArray("unreadable").length() == 1);
        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1"));
        real("missing total: not measured", !p.getBoolean("measured"));

        // ---------------- the fingerprint ----------------

        JSONObject a1 = PackagePlan.readPlan(large).put("unlockedPackages", new JSONArray().put("nginx"));
        String g2 = large.replace("\tnginx: 1.30.4,3 -> 1.30.5,3\n\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)",
                                   "\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)\n\tnginx: 1.30.4,3 -> 1.30.5,3");
        JSONObject a2 = PackagePlan.readPlan(g2).put("unlockedPackages", new JSONArray().put("nginx"));
        real("fingerprint: same plan in another order, same fingerprint", PackagePlan.signature(a1).equals(PackagePlan.signature(a2)));
        JSONObject a3 = PackagePlan.readPlan(large.replace("1.30.5,3", "1.30.6,3")).put("unlockedPackages", new JSONArray().put("nginx"));
        real("fingerprint: a different version changes the fingerprint", !PackagePlan.signature(a1).equals(PackagePlan.signature(a3)));
        JSONObject a4 = PackagePlan.readPlan(large).put("unlockedPackages", new JSONArray().put("nginx").put("php84"));
        real("fingerprint: one more protection to remove changes the fingerprint", !PackagePlan.signature(a1).equals(PackagePlan.signature(a4)));

        // ---------------- is the fix there? ----------------

        String audit = """
            {
                "pkg_count": 2,
                "packages": {
                    "nginx": {
                        "version": "1.30.4,3",
                        "issue_count": 1,
                        "issues": [
                            {
                                "Affected versions": [
                                    ">= 1.25.0 : < 1.30.5,3"
                                ],
                                "description": "nginx -- buffer overflow when using ngx_http_v3_module",
                                "cve": [
                                    "CVE-2026-90439"
                                ],
                                "url": "https://vuxml.FreeBSD.org/freebsd/0f2a9d3c-9a3d-11f1-9d0e-001b217b3468.html"
                            }
                        ],
                        "reverse dependencies": []
                    },
                    "curl": {
                        "version": "8.15.0",
                        "issue_count": 2,
                        "issues": [
                            { "Affected versions": ["< 8.16.0"], "description": "curl -- one", "cve": ["CVE-2026-1"], "url": "u1" },
                            { "Affected versions": ["< 8.17.0"], "description": "curl -- two", "cve": ["CVE-2026-2"], "url": "u2" }
                        ],
                        "reverse dependencies": ["git"]
                    }
                }
            }""";
        JSONObject va = PackagePlan.readAudit(audit);
        real("audit: two packages read", va.length() == 2);
        JSONArray nginxProblems = va.getJSONObject("nginx").getJSONArray("issues");
        real("audit: nginx's range", ">= 1.25.0 : < 1.30.5,3".equals(nginxProblems.getJSONObject(0).getJSONArray("ranges").getString(0)));
        real("audit: no vulnerable package", PackagePlan.readAudit("{\n    \"pkg_count\": 0\n}").length() == 0);

        // THE REAL CASE: 1.30.4,3 installed, catalog stuck at the same, VuXML "< 1.30.5,3".
        JSONObject v = PackagePlan.assessFix("1.30.4,3", "1.30.4,3", nginxProblems, CMP);
        real("nginx: the fix exists but not in the branch", "fix-outside-branch".equals(v.getString("verdict")));
        real("nginx: from 1.30.5,3", "1.30.5,3".equals(v.getString("firstFixed")));
        real("nginx: the text says the lock has nothing to do with it", v.getString("explanation").contains("the lock has nothing to do with it"));

        v = PackagePlan.assessFix("1.30.4,3", "1.30.5,3", nginxProblems, CMP);
        real("nginx with 1.30.5,3 in the catalog: upgrading solves it", "fixed-by-upgrade".equals(v.getString("verdict")));

        JSONArray curl = va.getJSONObject("curl").getJSONArray("issues");
        v = PackagePlan.assessFix("8.15.0", "8.16.0", curl, CMP);
        real("curl: 8.16.0 closes only one of the two", "upgrade-not-enough".equals(v.getString("verdict"))
            && "8.17.0".equals(v.getString("firstFixed")) && v.getString("explanation").contains("curl -- two"));
        v = PackagePlan.assessFix("8.15.0", "8.17.0", curl, CMP);
        real("curl: 8.17.0 closes both", "fixed-by-upgrade".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("8.15.0", "", curl, CMP);
        real("curl: catalog without the package, fix from 8.17.0",
            "fix-outside-branch".equals(v.getString("verdict")) && "8.17.0".equals(v.getString("firstFixed")));

        v = PackagePlan.assessFix("2.1", "2.1", issues(">= 0"), CMP);
        real("without an upper bound: no fix", "no-fix".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("2.1", "2.1", issues("<= 2.1"), CMP);
        real("'<=': fix not stated", "fix-not-stated".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("2.1", "2.1", issues("= 2.1"), CMP);
        real("'=': only that version, but the catalog has no other", "fix-outside-branch".equals(v.getString("verdict")));
        // More ranges: the one the installed version falls in counts, not the first.
        v = PackagePlan.assessFix("1.27.5", "1.27.5", issues("< 1.26.3", ">= 1.27.0 : < 1.28.1"), CMP);
        real("two version branches: the right branch's fix", "1.28.1".equals(v.getString("firstFixed")));
        v = PackagePlan.assessFix("1.27.5", "1.28.0", issues("< 1.26.3", ">= 1.27.0 : < 1.28.1"), CMP);
        real("two version branches: 1.28.0 is not enough", "upgrade-not-enough".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("3.0", "3.0", issues("< 2.0"), CMP);
        real("version outside every range: I don't know, I don't make it up", "unknown".equals(v.getString("verdict")));
        PackagePlan.VersionComparator broken = (x, y) -> { throw new IllegalStateException("pkg does not answer"); };
        v = PackagePlan.assessFix("1.30.4,3", "1.30.4,3", nginxProblems, broken);
        // The page reads a translated text; the raw reason (an exception's, in English) goes to the panel log (ErrorText).
        real("broken comparison: I don't know, and the reason is in the panel log, not on the page", "unknown".equals(v.getString("verdict"))
                && v.getString("explanation").contains(org.daemoxcp.mail.i18n.I18n.tr("server.detailsInLog"))
                && !v.getString("explanation").contains("pkg does not answer"));

        real("bounds: one", PackagePlan.bounds("< 1.30.5,3").size() == 1);
        real("bounds: two", PackagePlan.bounds(">= 1.25.0 : < 1.30.5,3").size() == 2);


        // ---------------- the packages overview ----------------
        // Lines taken from FreeBSD 15.1 (pkg 2.6): "<" with the catalog's version, "?" outside the
        // catalog, ">" newer, "=" does not appear with -L=.
        java.util.Map<String, String> update = PackagePlan.toUpdate(String.join("\n",
            "FreeBSD-acct-15.1                  ?   orphaned: base/FreeBSD-acct",
            "nginx-1.30.4,3                     <   needs updating (remote has 1.30.5_1,3)",
            "dovecot-mysql-2.3.21.1_3           <   needs updating (remote has 2.3.21.1_4)",
            "openjdk25-25.0.3+9.f.1             <   needs updating (remote has 25.0.4+7.f.1_1)",
            "clamav-1.5.4_1,1                   >   succeeds remote (remote has 1.5.2_3,1)",
            "broken-1.0                         <   needs updating (remote has ; rm -rf /)",
            ""));
        real("overview: the '<' lines give name and catalog version", "1.30.5_1,3".equals(update.get("nginx"))
            && "2.3.21.1_4".equals(update.get("dovecot-mysql")) && "25.0.4+7.f.1_1".equals(update.get("openjdk25")));
        real("overview: '?' and '>' are not updates", !update.containsKey("FreeBSD-acct") && !update.containsKey("clamav"));
        real("overview: a version with odd characters stays out", !update.containsKey("broken") && update.size() == 3);
        java.util.Map<String, String[]> ins = PackagePlan.installed("nginx\t1.30.4,3\t1\nclamav\t1.5.4_1,1\t0\nbad\t1 2\t0\n\n");
        real("overview: pkg query gives version and lock", ins.size() == 2 && "1".equals(ins.get("nginx")[1])
            && "1.5.4_1,1".equals(ins.get("clamav")[0]) && "0".equals(ins.get("clamav")[1]));
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        real("overview: the change type reads in the viewer's language",
            "upgrade".equals(PackagePlan.typeName("upgrade")) && "remove".equals(PackagePlan.typeName("remove")));

        end();
    }

    /**
     * The database copy against a fake pkg: it unlocks in the copy, widens the list with the
     * protected dependencies pkg names, leaves the real database untouched and deletes the copy.
     */
    static void simulation() throws Exception {
        String db = System.getenv("FAKE_DB");
        if (db == null) { real("FAKE_DB set (start tests/pkg-simulation-test.sh)", false); return; }
        Path locked = Path.of(db, "locked");
        Set<String> protectedNames = Set.of("kafka", "openjdk21", "nginx");
        int copiesBefore = remainingCopies();

        JSONObject p = PackagePlan.planFor(List.of("kafka"), protectedNames, x -> null);
        real("simulation: succeeded and measured", p.optBoolean("success") && p.optBoolean("measured"));
        real("simulation: pkg named openjdk21 and I added it",
            p.getJSONArray("unlockedPackages").toList().equals(List.of("kafka", "openjdk21")));
        real("simulation: the final plan upgrades kafka and openjdk21",
            find(p, "kafka") != null && find(p, "openjdk21") != null && p.getJSONArray("lockedPackages").isEmpty());
        // pkg updates itself before everything else, but with -n it does not say so: the plan must say it.
        JSONObject first = p.getJSONArray("changes").getJSONObject(0);
        real("simulation: pkg updating itself is at the top of the plan",
            "pkg".equals(first.getString("name")) && "2.1.0".equals(first.getString("from")) && "2.2.0".equals(first.getString("to")));
        real("simulation: runnable and with a fingerprint", p.getBoolean("runnable") && p.getString("signature").length() == 16);
        real("simulation: the REAL database is still protected",
            Files.exists(locked.resolve("kafka")) && Files.exists(locked.resolve("openjdk21")));
        real("simulation: the copy was deleted", remainingCopies() == copiesBefore);

        p = PackagePlan.planFor(List.of("kafka"), protectedNames,
                x -> x.getString("name").equals("openjdk21") && x.getString("destination").equals("21.0.9+10.1")
                     ? "it is the JDK the panel runs on" : null);
        real("simulation: the panel's JDK stays a blocker with its reason",
            p.getJSONArray("blockers").length() == 1
            && p.getJSONArray("blockers").getJSONObject(0).getString("reason").contains("JDK"));
        real("simulation: with a blocker it cannot run", !p.getBoolean("runnable"));
        real("simulation: here too the copy is gone", remainingCopies() == copiesBefore);

        p = PackagePlan.planFor(List.of("nginx"), protectedNames, x -> null);
        real("simulation: nginx has no updates, and says so", p.getJSONArray("unchangedPackages").toList().equals(List.of("nginx"))
            && !p.getBoolean("runnable"));

        // === The family twin: a lock that makes the package be REPLACED ===
        //
        // For pkg a protected package is not "not to be changed": it is unavailable. With
        // mysql84-client protected, the plan for postfix-mysql proposes "install mysql97-client" —
        // the two provide the same library and compete for the same files, so the run dies halfway.
        // Measured on the VM on 23/10/2026: exit 3,
        // «mysql97-client conflicts with mysql84-client (installs files into the same place)»;
        // and unlocking mysql84-client too, mysql97-client vanishes from the same simulation.
        Set<String> mysqlProtected = Set.of("kafka", "openjdk21", "nginx",
                "mysql84-client", "mysql84-server", "postfix-mysql");

        p = PackagePlan.planFor(List.of("postfix-mysql"), mysqlProtected, x -> null,
                UpdateManager::installedFamilyTwin);
        real("family: the plan is measured", p.optBoolean("measured"));
        real("family: it unlocks the protected twin too",
            p.getJSONArray("unlockedPackages").toList().contains("mysql84-client"));
        real("family: and so mysql97-client VANISHES from the plan", find(p, "mysql97-client") == null);
        real("family: the requested upgrade is still there", find(p, "postfix-mysql") != null);
        real("family: no blocker, so it can run",
            p.getJSONArray("blockers").isEmpty() && p.getBoolean("runnable"));
        JSONArray familyUnlocked = p.getJSONArray("familyUnlocked");
        real("family: the plan says WHICH twin it unlocked and why",
            familyUnlocked.length() == 1 && "mysql84-client".equals(familyUnlocked.getJSONObject(0).getString("installed"))
            && "mysql97-client".equals(familyUnlocked.getJSONObject(0).getString("wouldInstall")));
        real("family: and to which version", "8.4.11_1".equals(familyUnlocked.getJSONObject(0).getString("version")));

        // The name's skeleton: two conditions, because a single one gets it wrong.
        real("skeleton: the digits become #",
            "mysql#-client".equals(UpdateManager.nameSkeleton("mysql84-client"))
            && "mysql#-client".equals(UpdateManager.nameSkeleton("mysql97-client")));
        real("skeleton: the server is NOT the same place as the client",
            !UpdateManager.nameSkeleton("mysql84-server").equals(UpdateManager.nameSkeleton("mysql97-client")));
        real("twin: mysql84-server is not mysql97-client's twin",
            "mysql84-client".equals(UpdateManager.installedFamilyTwin("mysql97-client")));
        real("twin: python312 has no twins, it is not a declared family",
            UpdateManager.installedFamilyTwin("python313") == null);
        real("twin: a name that does not pass the filter queries nothing",
            UpdateManager.installedFamilyTwin("mysql97-client; rm -rf /") == null);

        JSONObject s = PackagePlan.simulate(List.of("ka fka"), List.of("kafka"));
        real("simulation: a name with a space does not reach the shell", !s.optBoolean("success"));
    }

    /**
     * The protected twin, but with the catalog having a NEWER version of it.
     *
     * Unlocking it to let pkg see what is there would be unlocking it to upgrade it, that is a
     * change nobody asked for — and for the MySQL clients the panel's warning says to wait. So it
     * stays a blocker, with its reason. The fake pkg says it with V_CAT.
     */
    static void familyNewCatalog() throws Exception {
        if (System.getenv("FAKE_DB") == null) { real("FAKE_DB set", false); return; }
        Set<String> protectedNames = Set.of("kafka", "openjdk21", "nginx",
                "mysql84-client", "mysql84-server", "postfix-mysql");
        JSONObject p = PackagePlan.planFor(List.of("postfix-mysql"), protectedNames, x -> null,
                UpdateManager::installedFamilyTwin);
        real("new catalog: the twin is NOT unlocked", p.getJSONArray("familyUnlocked").isEmpty()
            && !p.getJSONArray("unlockedPackages").toList().contains("mysql84-client"));
        real("new catalog: there is a blocker", p.getJSONArray("blockers").length() == 1);
        String reason = p.getJSONArray("blockers").length() == 1
                ? p.getJSONArray("blockers").getJSONObject(0).getString("reason") : "";
        real("new catalog: the reason names the two versions",
            reason.contains("8.4.11_1") && reason.contains("8.4.12"));
        real("new catalog: and it says the twin must be upgraded first", reason.contains("mysql84-client"));
        real("new catalog: so it cannot run", !p.getBoolean("runnable"));
        real("new catalog: and mysql97-client stays in the plan, it does not pretend it vanished",
            find(p, "mysql97-client") != null);
    }

    /**
     * The twin installed but NOT protected, with pkg proposing the other member anyway
     * (MYSQL97=always). Here the lock has nothing to do with it: it is a real conflict between two
     * members of the family, and it is declared instead of unlocking something that is not locked.
     */
    static void familyRealConflict() throws Exception {
        if (System.getenv("FAKE_DB") == null) { real("FAKE_DB set", false); return; }
        Set<String> protectedNames = Set.of("kafka", "openjdk21", "nginx", "postfix-mysql");
        JSONObject p = PackagePlan.planFor(List.of("postfix-mysql"), protectedNames, x -> null,
                UpdateManager::installedFamilyTwin);
        real("real conflict: nothing is unlocked", p.getJSONArray("familyUnlocked").isEmpty());
        real("real conflict: there is a blocker", p.getJSONArray("blockers").length() == 1);
        String reason = p.getJSONArray("blockers").length() == 1
                ? p.getJSONArray("blockers").getJSONObject(0).getString("reason") : "";
        real("real conflict: the reason names the two packages",
            reason.contains("mysql97-client") && reason.contains("mysql84-client"));
        real("real conflict: and it says the lock has nothing to do with it", !reason.isEmpty());
        real("real conflict: it cannot run", !p.getBoolean("runnable"));
    }

    private static int remainingCopies() throws Exception {
        try (var st = Files.list(Path.of("/var/tmp"))) {
            return (int) st.filter(x -> x.getFileName().toString().startsWith("panel-simulation.")).count();
        }
    }

    private static JSONArray issues(String... ranges) {
        return new JSONArray().put(new JSONObject().put("ranges", new JSONArray(List.of(ranges)))
                .put("description", "test").put("cve", new JSONArray()).put("url", ""));
    }

    private static JSONObject find(JSONObject plan, String name) {
        JSONArray c = plan.getJSONArray("changes");
        for (int i = 0; i < c.length(); i++) if (name.equals(c.getJSONObject(i).getString("name"))) return c.getJSONObject(i);
        return null;
    }

    private static void end() {
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
