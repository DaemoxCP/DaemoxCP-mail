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
    private static final LocalDateTime ADESSO = LocalDateTime.of(2026, 9, 3, 18, 0);
    private static int falliti = 0;

    private static String oreFa(int ore) { return ADESSO.minusHours(ore).format(ISO); }

    public static void main(String[] args) {
        // --- Il caso che si e' rotto in produzione ---
        // Settimanale, ultimo invio RIUSCITO otto giorni fa, ultimo tentativo fallito un minuto
        // fa. Senza la correzione qui si riprovava, e si sarebbe riprovato al tick dopo, e al
        // tick dopo ancora, indefinitamente.
        vero("dopo un fallimento non riprova subito",
            !RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), oreFa(0), "fallito: auth", ADESSO));
        vero("non riprova nemmeno dopo 5 ore",
            !RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), oreFa(5), "fallito: auth", ADESSO));
        // Ma non deve nemmeno smettere per sempre: dopo la pausa si riprova.
        vero("dopo 6 ore riprova",
            RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), oreFa(6), "fallito: auth", ADESSO));
        vero("dopo 7 ore riprova",
            RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), oreFa(7), "fallito: auth", ADESSO));

        // --- La pausa NON deve rallentare il caso normale ---
        vero("ultimo esito riuscito: parte come prima",
            RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), oreFa(0), "riuscito", ADESSO));
        vero("mai inviato: parte",
            RapportoPeriodico.eIlMomento("settimanale", "8", "", "", "", ADESSO));
        vero("settimanale, 3 giorni fa: NON parte",
            !RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 3), "", "", ADESSO));
        vero("giornaliero, 21 ore fa: parte",
            RapportoPeriodico.eIlMomento("giornaliero", "8", oreFa(21), "", "", ADESSO));
        vero("mensile, 10 giorni fa: NON parte",
            !RapportoPeriodico.eIlMomento("mensile", "8", oreFa(24 * 10), "", "", ADESSO));
        vero("prima dell'ora impostata: NON parte",
            !RapportoPeriodico.eIlMomento("settimanale", "20", oreFa(24 * 8), "", "", ADESSO));

        // --- Un dato illeggibile non deve bloccare per sempre ---
        // La pausa esiste per non martellare un server altrui, non per zittire il rapporto:
        // se la data del tentativo non si sa leggere, si procede invece di restare fermi.
        vero("data del tentativo illeggibile: non blocca",
            RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), "boh", "fallito: auth", ADESSO));
        vero("tentativo mai registrato: non blocca",
            RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), "", "fallito: auth", ADESSO));
        vero("esito assente: non blocca",
            RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), oreFa(0), "", ADESSO));

        // --- Orologio andato indietro ---
        vero("tentativo nel futuro: non blocca",
            RapportoPeriodico.eIlMomento("settimanale", "8", oreFa(24 * 8), ADESSO.plusHours(3).format(ISO),
                "fallito: auth", ADESSO));

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
