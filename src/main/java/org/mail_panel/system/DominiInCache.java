package org.mail_panel.system;

import org.mail_panel.Main;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * L'elenco dei domini gestiti, tenuto in memoria per qualche secondo.
 *
 * Perche' esiste. Le due rotte pubbliche del pannello — la configurazione per Thunderbird e
 * la politica MTA-STS — non sono autenticate, e non possono esserlo: le chiamano client di
 * posta e server mittenti che non hanno credenziali. Ma ogni richiesta faceva una query al
 * database per sapere se il dominio fosse nostro.
 *
 * Chiunque puo' chiamare quelle rotte quante volte vuole. Senza questa cache, mille richieste
 * al secondo diventano mille query al secondo, e a cadere non e' la pagina web: e' MySQL, cioe'
 * la POSTA. Un endpoint pubblico che tocca il database a ogni colpo e' una leva per spegnere
 * il servizio, non una comodita'.
 *
 * L'elenco dei domini cambia raramente — quando se ne aggiunge uno — quindi trenta secondi di
 * ritardo non danno alcun fastidio: un dominio appena creato risponde mezzo minuto dopo.
 */
public class DominiInCache {

    private static final long VALIDITA_MS = 30_000;

    private static volatile Set<String> elenco = null;
    private static volatile long scadenza = 0;

    private DominiInCache() {}

    /** I domini gestiti, in minuscolo. Rilegge dal database solo quando la copia e' scaduta. */
    public static Set<String> domini() {
        long ora = System.currentTimeMillis();
        Set<String> copia = elenco;
        if (copia != null && ora < scadenza) return copia;

        Set<String> nuovo = new LinkedHashSet<>();
        try {
            for (var d : Main.mailDatabase.getDomains())
                if (d.domain != null && !d.domain.isBlank())
                    nuovo.add(d.domain.trim().toLowerCase(Locale.ROOT));
        } catch (Exception e) {
            // Se il database non risponde si tiene la copia vecchia invece di svuotare
            // l'elenco: rispondere con dati di trenta secondi fa e' meglio che rispondere
            // "questo dominio non esiste" a un server mittente per un problema nostro.
            if (copia != null) {
                scadenza = ora + VALIDITA_MS;
                return copia;
            }
            return Set.of();
        }
        elenco = nuovo;
        scadenza = ora + VALIDITA_MS;
        return nuovo;
    }

    /** Il nome come sta nel database, se il dominio e' gestito. Altrimenti null. */
    public static String gestito(String richiesto) {
        if (richiesto == null) return null;
        String r = richiesto.trim().toLowerCase(Locale.ROOT);
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        return domini().contains(r) ? r : null;
    }

    /** Da chiamare quando i domini cambiano, per non aspettare la scadenza. */
    public static void invalida() {
        scadenza = 0;
    }
}
