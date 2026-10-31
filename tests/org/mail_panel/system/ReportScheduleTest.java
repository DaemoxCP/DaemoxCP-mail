package org.mail_panel.system;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Quando il rapporto periodico decide di partire.
 *
 * Va provato perche' il suo difetto non si vedeva da nessuna schermata: su un invio fallito
 * veniva scritto solo l'esito, non la data, e la data era l'unica cosa che questo metodo
 * guardava. La condizione "sono passati sei giorni" restava vera per sempre e lo scheduler
 * riprovava a ogni tick — uno ogni quarto d'ora, novantasei al giorno verso il server SMTP di
 * qualcun altro. Ogni singolo tentativo, preso da solo, era legittimo.
 */
public class ReportScheduleTest {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    private static final LocalDateTime NOW = LocalDateTime.of(2026, 9, 3, 18, 0);
    private static int failed = 0;

    private static String hoursAgo(int hours) { return NOW.minusHours(hours).format(ISO); }

    public static void main(String[] args) {
        // --- Il caso che si e' rotto in produzione ---
        // Settimanale, ultimo invio RIUSCITO otto giorni fa, ultimo tentativo fallito un minuto
        // fa. Senza la fix qui si riprovava, e si sarebbe riprovato al tick dopo, e al
        // tick dopo ancora, indefinitamente.
        real("dopo un fallimento non riprova subito",
            !PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(0), "failed: auth", NOW));
        real("non riprova nemmeno dopo 5 ore",
            !PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(5), "failed: auth", NOW));
        // Ma non deve nemmeno smettere per sempre: dopo la pausa si riprova.
        real("dopo 6 ore riprova",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(6), "failed: auth", NOW));
        real("dopo 7 ore riprova",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(7), "failed: auth", NOW));

        // --- La pausa NON deve rallentare il caso normale ---
        real("ultimo esito riuscito: parte come prima",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(0), "delivered", NOW));
        real("mai inviato: parte",
            PeriodicReport.isTheMoment("weekly", "8", "", "", "", NOW));
        real("settimanale, 3 giorni fa: NON parte",
            !PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 3), "", "", NOW));
        real("giornaliero, 21 ore fa: parte",
            PeriodicReport.isTheMoment("daily", "8", hoursAgo(21), "", "", NOW));
        real("mensile, 10 giorni fa: NON parte",
            !PeriodicReport.isTheMoment("monthly", "8", hoursAgo(24 * 10), "", "", NOW));
        real("prima dell'ora impostata: NON parte",
            !PeriodicReport.isTheMoment("weekly", "20", hoursAgo(24 * 8), "", "", NOW));

        // --- Un dato illeggibile non deve bloccare per sempre ---
        // La pausa esiste per non martellare un server altrui, non per zittire il rapporto:
        // se la data del tentativo non si sa leggere, si procede invece di restare fermi.
        real("data del tentativo illeggibile: non blocca",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), "garbage", "failed: auth", NOW));
        real("tentativo mai registrato: non blocca",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), "", "failed: auth", NOW));
        real("esito assente: non blocca",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(0), "", NOW));

        // --- Orologio andato indietro ---
        real("tentativo nel futuro: non blocca",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), NOW.plusHours(3).format(ISO),
                "failed: auth", NOW));

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
