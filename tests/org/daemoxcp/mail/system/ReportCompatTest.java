package org.daemoxcp.mail.system;

/**
 * The periodic report settings saved before 24/10/2026 still hold.
 *
 * Until that day the frequency and the failed-outcome prefix were saved with the old names (data
 * file: reportFrequencies, reportFailedPrefix). Now the codes are in English; a schedule already
 * made must not stop running, and a failure already recorded must still stop close retries. The
 * old names are taken from the data file.
 */
public class ReportCompatTest {

    private static int failures = 0;

    public static void main(String[] args) {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");   // the panel's texts, shown below, in English
        check("the data file has the three old frequencies", LegacyNames.pairs("reportFrequencies").size() == 3);
        for (String[] p : LegacyNames.pairs("reportFrequencies"))
            check(p[0] + " reads as " + p[1], p[1].equals(PeriodicReport.normalizedFrequency(p[0])));
        String oldPrefix = LegacyNames.oldNamesOf("reportFailedPrefix", "failed: ").stream().findFirst().orElse("");
        check("the data file has the old prefix", !oldPrefix.isEmpty() && !oldPrefix.equals("failed: "));
        check("a value that is already new stays", "weekly".equals(PeriodicReport.normalizedFrequency("weekly")));
        check("a failure of today is recognised", PeriodicReport.isFailedOutcome("failed: auth"));
        check("and so is one saved with the old prefix", PeriodicReport.isFailedOutcome(oldPrefix + "auth"));
        check("a successful send is not", !PeriodicReport.isFailedOutcome("Delivered to gmail.com"));
        // The page receives the language file's text, not the saved code, whatever prefix is on
        // the disk.
        String shown = org.daemoxcp.mail.i18n.I18n.tr("server.rp.lastFailed", java.util.Map.of("error", "auth"));
        check("the page receives the outcome as translated text (" + shown + ")", shown.equals(PeriodicReport.shownOutcome("failed: auth")));
        check("  for the old prefix too", shown.equals(PeriodicReport.shownOutcome(oldPrefix + "auth")));
        check("  and an outcome that is not a failure passes as it is", "Delivered".equals(PeriodicReport.shownOutcome("Delivered")));
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
