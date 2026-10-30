package org.mail_panel.system;

/**
 * Le impostazioni del rapporto periodico salvate prima del 24/10/2026 valgono ancora.
 *
 * Fino a quel giorno la frequenza e il prefisso dell'esito fallito si salvavano coi nomi di
 * prima (file di dati: reportFrequencies, reportFailedPrefix). Adesso i codici sono in inglese;
 * una pianificazione gia' fatta non deve smettere di partire, e un fallimento gia' registrato
 * deve ancora fermare i tentativi ravvicinati. I nomi di prima si prendono dal file di dati.
 */
public class ReportCompatTest {

    private static int failures = 0;

    public static void main(String[] args) {
        check("il file di dati ha le tre frequenze di prima", LegacyNames.pairs("reportFrequencies").size() == 3);
        for (String[] p : LegacyNames.pairs("reportFrequencies"))
            check(p[0] + " si legge " + p[1], p[1].equals(PeriodicReport.normalizedFrequency(p[0])));
        String oldPrefix = LegacyNames.oldNamesOf("reportFailedPrefix", "failed: ").stream().findFirst().orElse("");
        check("il file di dati ha il prefisso di prima", !oldPrefix.isEmpty() && !oldPrefix.equals("failed: "));
        check("un valore gia' nuovo resta", "weekly".equals(PeriodicReport.normalizedFrequency("weekly")));
        check("un fallimento di oggi si riconosce", PeriodicReport.isFailedOutcome("failed: auth"));
        check("e anche uno salvato col prefisso vecchio", PeriodicReport.isFailedOutcome(oldPrefix + "auth"));
        check("un invio riuscito no", !PeriodicReport.isFailedOutcome("Consegnato a gmail.com"));
        // La pagina riceve il testo del file di lingua, non il codice salvato, qualunque
        // prefisso ci sia sul disco.
        String shown = org.mail_panel.i18n.I18n.tr("server.rp.lastFailed", java.util.Map.of("error", "auth"));
        check("la pagina riceve l'esito come testo tradotto (" + shown + ")", shown.equals(PeriodicReport.shownOutcome("failed: auth")));
        check("  anche per il prefisso vecchio", shown.equals(PeriodicReport.shownOutcome(oldPrefix + "auth")));
        check("  e un esito che non e' un fallimento passa com'e'", "Consegnato".equals(PeriodicReport.shownOutcome("Consegnato")));
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
