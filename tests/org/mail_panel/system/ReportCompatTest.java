package org.mail_panel.system;

/**
 * Le impostazioni del rapporto periodico salvate prima del 24/10/2026 valgono ancora.
 *
 * Fino a quel giorno la frequenza si salvava come "giornaliero", "settimanale" o "mensile", e
 * l'esito di un invio fallito cominciava con "fallito: ". Adesso i codici sono in inglese; una
 * pianificazione gia' fatta non deve smettere di partire, e un fallimento gia' registrato deve
 * ancora fermare i tentativi ravvicinati.
 */
public class ReportCompatTest {

    private static int failures = 0;

    public static void main(String[] args) {
        check("giornaliero si legge daily", "daily".equals(PeriodicReport.normalizedFrequency("giornaliero")));
        check("settimanale si legge weekly", "weekly".equals(PeriodicReport.normalizedFrequency("settimanale")));
        check("mensile si legge monthly", "monthly".equals(PeriodicReport.normalizedFrequency("mensile")));
        check("un valore gia' nuovo resta", "weekly".equals(PeriodicReport.normalizedFrequency("weekly")));
        check("un fallimento di oggi si riconosce", PeriodicReport.isFailedOutcome("failed: auth"));
        check("e anche uno salvato col prefisso vecchio", PeriodicReport.isFailedOutcome("fallito: auth"));
        check("un invio riuscito no", !PeriodicReport.isFailedOutcome("Consegnato a gmail.com"));
        // La pagina riceve il testo del file di lingua, non il codice salvato: in italiano e'
        // "fallito: auth", in inglese "failed: auth", qualunque prefisso ci sia sul disco.
        String shown = org.mail_panel.i18n.I18n.tr("server.rp.lastFailed", java.util.Map.of("error", "auth"));
        check("la pagina riceve l'esito come testo tradotto (" + shown + ")", shown.equals(PeriodicReport.shownOutcome("failed: auth")));
        check("  anche per il prefisso vecchio", shown.equals(PeriodicReport.shownOutcome("fallito: auth")));
        check("  e un esito che non e' un fallimento passa com'e'", "Consegnato".equals(PeriodicReport.shownOutcome("Consegnato")));
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
