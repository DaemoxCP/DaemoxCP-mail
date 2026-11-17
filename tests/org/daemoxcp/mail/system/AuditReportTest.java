package org.daemoxcp.mail.system;

import org.json.JSONObject;

/**
 * The vulnerability report of a package: the right question, and the proof that an answer came.
 *
 * The panel asked {@code pkg audit <name>}, with the name alone. Measured on the FreeBSD 15.1 VM on
 * 23/10/2026:
 *
 *  - with the name alone, pkg answers "does VuXML have entries for this name?", not "is the
 *    installed version vulnerable?": on nginx 1.30.6,3 just upgraded it answered "nginx is
 *    vulnerable" with 25 problems, while `pkg audit` without arguments did not name it at all. And
 *    the header is "nginx is vulnerable:", WITHOUT the version, so the details reader — which looks
 *    for "name-version is vulnerable:" — never entered the block: zero CVEs always, both ways;
 *  - on php84 8.4.26, really vulnerable, the panel's card said "[ok] No known vulnerability
 *    recorded for this package", while PackagePlan.fixes found the fix in 8.4.27;
 *  - without the vulnerability database pkg says "vulnxml file vuln.xml does not exist" and exits
 *    1, and whoever looks only for the "is vulnerable" lines concludes "no vulnerability": a
 *    reassurance instead of an "I could not check".
 *
 * The outputs used here are the real ones, copied from that measurement.
 */
public class AuditReportTest {

    private static int failures = 0, skipped = 0;

    /** The real report of `pkg audit 'php84-8.4.26'`, cut down to the pieces that matter. */
    private static final String VULNERABLE_REPORT =
            "php84-8.4.26 is vulnerable:\n"
          + "  Affected versions:\n"
          + "  < 8.4.27\n"
          + "  php -- multiple vulnerabilities\n"
          + "  CVE: CVE-2026-11111\n"
          + "  WWW: https://vuxml.FreeBSD.org/freebsd/d8e16d08-cd2f-11f1-8135-8447094a420f.html\n"
          + "\n"
          + "1 problem(s) in 1 package(s) found.\n";

    /** The real report of `pkg audit 'nginx-1.30.6,3'` after the upgrade. */
    private static final String CLEAN_REPORT = "0 problem(s) in 0 package(s) found.\n";

    /** What pkg answers without the vulnerability database. */
    private static final String REPORT_WITHOUT_DATABASE =
            "pkg: vulnxml file vuln.xml does not exist. Try running 'pkg audit -F' first\n";

    /** What it answered to the NAME ALONE: no version in the header. */
    private static final String NAME_ONLY_REPORT =
            "php84 is vulnerable:\n"
          + "  Affected versions:\n"
          + "  < 8.4.27\n"
          + "  php -- multiple vulnerabilities\n"
          + "  CVE: CVE-2026-11111\n"
          + "\n"
          + "3 problem(s) in 1 package(s) found.\n";

    public static void main(String[] args) {

        // ===== 1. A vulnerable package: the report says how many problems, and which =====
        JSONObject v = UpdateManager.readAuditReport(VULNERABLE_REPORT, "php84",
                UpdateManager.emptyAuditReport("php84", "8.4.26"));
        check("the report was made", v.optBoolean("done"));
        check("it counts 1 problem, like pkg's final line", v.optInt("problems") == 1);
        check("it reads the CVE", v.getJSONArray("cve").toString().contains("CVE-2026-11111"));
        check("it reads the description", v.optString("description").contains("multiple vulnerabilities"));
        check("it reads the reference", v.getJSONArray("references").toString().contains("vuxml.FreeBSD.org"));

        // ===== 2. A clean package: zero problems, but the check happened =====
        JSONObject p = UpdateManager.readAuditReport(CLEAN_REPORT, "nginx",
                UpdateManager.emptyAuditReport("nginx", "1.30.6,3"));
        check("the report of a clean package was made", p.optBoolean("done"));
        check("and it says zero problems", p.optInt("problems") == 0);

        // ===== 3. Without the database: "no vulnerability" is NOT said =====
        JSONObject s = UpdateManager.readAuditReport(REPORT_WITHOUT_DATABASE, "nginx",
                UpdateManager.emptyAuditReport("nginx", "1.30.6,3"));
        check("without the database the report does NOT show as made", !s.optBoolean("done"));
        check("and the reason names pkg audit -F", s.optString("error").contains("pkg audit -F"));
        check("and the problems are not counted as a reassuring zero",
             s.optInt("problems") == 0 && !s.optBoolean("done"));

        // ===== 4. Empty output (command not run, timeout): the same =====
        check("an empty output is not a report",
             !UpdateManager.readAuditReport("", "nginx", UpdateManager.emptyAuditReport("nginx", "1.0")).optBoolean("done"));
        check("nor is a null output",
             !UpdateManager.readAuditReport(null, "nginx", UpdateManager.emptyAuditReport("nginx", "1.0")).optBoolean("done"));

        // ===== 5. The report of the NAME ALONE: why the two fixes go together =====
        // Here the final line is there, so "done" is true, but the header does not carry the version
        // and the details stay empty: counting the CVEs would have given zero while pkg said "is
        // vulnerable". Asking with name and version is what makes the details readable; requiring
        // the final line is what tells a report from an error.
        JSONObject nameOnlyReport = UpdateManager.readAuditReport(NAME_ONLY_REPORT, "php84",
                UpdateManager.emptyAuditReport("php84", "8.4.26"));
        check("from the report of the name alone the details cannot be read", nameOnlyReport.getJSONArray("cve").isEmpty());
        check("  and the count would be 3 instead of 1", nameOnlyReport.optInt("problems") == 3);

        // ===== 6. A version that does not pass the filter does not become a command line =====
        JSONObject malformed = UpdateManager.auditReport("nginx", "1.0; rm -rf /");
        check("a non-conforming version is not run", !malformed.optBoolean("done"));
        check("  and it says so", !malformed.optString("error").isEmpty());
        check("a non-conforming name is not run",
             !UpdateManager.auditReport("ngi nx", "1.0").optBoolean("done"));

        // ===== 7. Against real pkg: whoever is vulnerable for pkg is for the report too =====
        if (!hasPkg()) {
            skip("the comparison with real pkg: pkg is not on this machine");
        } else {
            JSONObject fixes = PackagePlan.fixes();
            if (!fixes.optBoolean("success")) {
                skip("the comparison with real pkg: " + fixes.optString("error")
                    + " (it needs the vulnerability database: pkg audit -F)");
            } else {
                JSONObject byPackage = fixes.getJSONObject("packages");
                java.util.Map<String, String[]> inst = PackagePlan.installed();
                int checked = 0, agreeing = 0;
                StringBuilder disagreeing = new StringBuilder();
                for (String name : byPackage.keySet()) {
                    String[] iv = inst.get(name);
                    if (iv == null) continue;
                    JSONObject report = UpdateManager.auditReport(name, iv[0]);
                    checked++;
                    if (report.optBoolean("done") && report.optInt("problems") > 0) agreeing++;
                    else disagreeing.append(' ').append(name).append('(')
                                 .append(report.optBoolean("done") ? report.optInt("problems") + " problems" : "not made")
                                 .append(')');
                }
                if (checked == 0) {
                    skip("the comparison with real pkg: no vulnerable package on this machine");
                } else {
                    check("the " + checked + " packages pkg calls vulnerable are vulnerable in the report too"
                         + (disagreeing.length() > 0 ? " — disagreeing:" + disagreeing : ""),
                         agreeing == checked);
                }
                // And the case that unmasks the wrong question: a package pkg does NOT consider
                // vulnerable but that HAS a history in VuXML. With the name alone pkg answers with
                // all the entries of that name; with name and version it answers zero. On the VM it
                // is nginx, just brought to 1.30.6,3: 25 problems against 0.
                String withHistory = null;
                int nameOnly = 0;
                org.json.JSONArray stack = UpdateManager.packagesStatus().optJSONArray("packages");
                for (int i = 0; stack != null && i < stack.length() && withHistory == null; i++) {
                    String name = stack.getJSONObject(i).optString("name");
                    if (byPackage.has(name) || !inst.containsKey(name)) continue;
                    int n = declaredProblems(org.daemoxcp.mail.util.Shell.runShell(
                            java.time.Duration.ofSeconds(120), "pkg audit " + name + " 2>&1").output());
                    if (n > 0) { withHistory = name; nameOnly = n; }
                }
                if (withHistory == null) {
                    skip("the case of the name alone: on this machine no healthy package has entries"
                        + " in VuXML, so the difference cannot be measured");
                } else {
                    JSONObject report = UpdateManager.auditReport(withHistory, inst.get(withHistory)[0]);
                    check(withHistory + " " + inst.get(withHistory)[0] + ": pkg with the name alone says "
                         + nameOnly + " problems, the report for the installed version says "
                         + report.optInt("problems"),
                         report.optBoolean("done") && report.optInt("problems") == 0);
                }
            }
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " CHECKS SKIPPED (they say so above)");
        System.out.println(failures == 0 ? "ALL OK" : failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /** The number of problems from pkg audit's final line; -1 if that line is not there. */
    private static int declaredProblems(String out) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                "(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found")
                .matcher(out == null ? "" : out);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    private static boolean hasPkg() {
        return org.daemoxcp.mail.util.Shell.runShell(java.time.Duration.ofSeconds(15),
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
