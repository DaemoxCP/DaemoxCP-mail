package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * L'avviso di un lavoro sui pacchetti interrotto nel rapporto periodico (reperto 172). C'era gia'
 * (UpdateManager.reportData), con l'urgenza e il titolo di un lavoro qualunque anche per la
 * reinstallazione, che puo' aver lasciato la posta spenta.
 *  - senza avviso, niente; con l'avviso di un lavoro qualunque, una cosa da fare;
 *  - con quello della reinstallazione, la piu' urgente, che dice come tornare indietro;
 *  - il testo del rapporto la contiene;
 *  - con -De2e.vm=yes (VM): i dati veri del rapporto (UpdateManager.reportData) la contengono.
 * L'avviso sta in una cartella temporanea (PackageRecovery.notice).
 *   java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InterruptionReportTest
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
            check("senza avviso, niente nel rapporto", PackageRecovery.reportItem() == null);

            PackageRecovery.recordInterruption(new JSONObject().put("description", "updating nginx").put("turnId", "upgrade-1"),
                    List.of("nginx"), List.of("nginx"), "");
            JSONObject item = PackageRecovery.reportItem();
            check("un lavoro qualunque: una cosa da fare", item != null && item.optInt("urgency") == 1
                    && item.optString("title").equals(I18n.tr("server.recovery.title")) && item.optString("what").contains("updating nginx"));

            Files.delete(PackageRecovery.notice);
            PackageRecovery.recordInterruption(new JSONObject().put("description", "complete mail server installation")
                    .put("turnId", InstallLocks.REINSTALL_TURN_PREFIX + "7"), List.of("dovecot"), List.of("dovecot"), "");
            JSONObject n = PackageRecovery.notice().put("wayBack", "reinstall-before-2026-11-06-120000");
            Files.writeString(PackageRecovery.notice, n.toString());
            item = PackageRecovery.reportItem();
            check("la reinstallazione: la piu' urgente", item != null && item.optInt("urgency") == 0
                    && item.optString("title").contains("mail may be stopped"));
            check("e dice come tornare indietro", item.optString("what").contains("bectl activate reinstall-before-2026-11-06-120000"));

            JSONObject data = new JSONObject().put("toDo", new JSONArray().put(item));
            String text;
            try {
                text = ReportMail.message(new ReportMail.Context("en", "mail.e2e.test", "admin@e2e.test", true, "weekly",
                        java.time.ZonedDateTime.now()), data).text();
            } catch (RuntimeException e) {
                text = "ERRORE: " + e;
            }
            // Il testo va a capo a 72 colonne: si confronta con gli spazi normalizzati.
            String flat = text.replaceAll("\\s+", " ");
            check("il testo del rapporto la contiene", flat.contains("mail may be stopped") && flat.contains("bectl activate reinstall-before-2026-11-06-120000"));

            if ("yes".equals(System.getProperty("e2e.vm"))) {
                JSONArray toDo = UpdateManager.reportData(false).optJSONArray("toDo");
                boolean found = false;
                for (int i = 0; toDo != null && i < toDo.length(); i++)
                    found |= toDo.getJSONObject(i).optInt("urgency", 9) == 0
                            && toDo.getJSONObject(i).optString("title").contains("mail may be stopped");
                check("i dati veri del rapporto la contengono, come la cosa piu' urgente", found);
            } else {
                System.out.println("(saltato: i dati veri del rapporto, serve -De2e.vm=yes)");
            }
        } finally {
            Files.deleteIfExists(PackageRecovery.notice);
            Files.deleteIfExists(d);
        }
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
