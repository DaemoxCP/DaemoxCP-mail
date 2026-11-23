package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The notice of an interrupted package job in the periodic report (finding 172). It was already
 * there (UpdateManager.reportData), with the urgency and title of any job, the reinstallation
 * included, which may have left mail stopped.
 *  - without a notice, nothing; with the notice of any job, a thing to do;
 *  - with the reinstallation's, the most urgent one, which says how to go back;
 *  - the report text contains it;
 *  - with -De2e.vm=yes (VM): the report's real data (UpdateManager.reportData) contain it.
 * The notice lives in a temporary folder (PackageRecovery.notice).
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InterruptionReportTest
 */
public class InterruptionReportTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Path d = Files.createTempDirectory("interruption-report");
        PackageRecovery.notice = d.resolve("package-job-interrupted.json");
        try {
            check("without a notice, nothing in the report", PackageRecovery.reportItem() == null);

            PackageRecovery.recordInterruption(new JSONObject().put("description", "updating nginx").put("turnId", "upgrade-1"),
                    List.of("nginx"), List.of("nginx"), "");
            JSONObject item = PackageRecovery.reportItem();
            check("any job: a thing to do", item != null && item.optInt("urgency") == 1
                    && item.optString("title").equals(I18n.tr("server.recovery.title")) && item.optString("what").contains("updating nginx"));

            Files.delete(PackageRecovery.notice);
            PackageRecovery.recordInterruption(new JSONObject().put("description", "complete mail server installation")
                    .put("turnId", InstallLocks.REINSTALL_TURN_PREFIX + "7"), List.of("dovecot"), List.of("dovecot"), "");
            JSONObject n = PackageRecovery.notice().put("wayBack", "reinstall-before-2026-11-06-120000");
            Files.writeString(PackageRecovery.notice, n.toString());
            item = PackageRecovery.reportItem();
            check("the reinstallation: the most urgent", item != null && item.optInt("urgency") == 0
                    && item.optString("title").contains("mail may be stopped"));
            check("and it says how to go back", item.optString("what").contains("bectl activate reinstall-before-2026-11-06-120000"));

            JSONObject data = new JSONObject().put("toDo", new JSONArray().put(item));
            String text;
            try {
                text = ReportMail.message(new ReportMail.Context("en", "mail.e2e.test", "admin@e2e.test", true, "weekly",
                        java.time.ZonedDateTime.now()), data).text();
            } catch (RuntimeException e) {
                text = "ERROR: " + e;
            }
            // The text wraps at 72 columns: it is compared with normalized spaces.
            String flat = text.replaceAll("\\s+", " ");
            check("the report text contains it", flat.contains("mail may be stopped") && flat.contains("bectl activate reinstall-before-2026-11-06-120000"));

            if ("yes".equals(System.getProperty("e2e.vm"))) {
                JSONArray toDo = UpdateManager.reportData(false).optJSONArray("toDo");
                boolean found = false;
                for (int i = 0; toDo != null && i < toDo.length(); i++)
                    found |= toDo.getJSONObject(i).optInt("urgency", 9) == 0
                            && toDo.getJSONObject(i).optString("title").contains("mail may be stopped");
                check("the report's real data contain it, as the most urgent thing", found);
            } else {
                System.out.println("(skipped: the report's real data, it needs -De2e.vm=yes)");
            }
        } finally {
            Files.deleteIfExists(PackageRecovery.notice);
            Files.deleteIfExists(d);
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
