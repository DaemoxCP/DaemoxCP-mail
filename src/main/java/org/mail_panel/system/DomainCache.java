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
public class DomainCache {

    private static final long VALIDITY_MS = 30_000;

    private static volatile Set<String> list = null;
    private static volatile long expiry = 0;

    private DomainCache() {}

    /** I domini gestiti, in minuscolo. Rilegge dal database solo quando la copia e' scaduta. */
    public static Set<String> domains() {
        long now = System.currentTimeMillis();
        Set<String> copy = list;
        if (copy != null && now < expiry) return copy;

        Set<String> fresh = new LinkedHashSet<>();
        try {
            for (var d : Main.mailDatabase.getDomains())
                if (d.domain != null && !d.domain.isBlank())
                    fresh.add(d.domain.trim().toLowerCase(Locale.ROOT));
        } catch (Exception e) {
            // Se il database non risponde si tiene la copia vecchia invece di svuotare
            // l'elenco: rispondere con dati di trenta secondi fa e' meglio che rispondere
            // "questo dominio non esiste" a un server mittente per un problema nostro.
            if (copy != null) {
                expiry = now + VALIDITY_MS;
                return copy;
            }
            return Set.of();
        }
        list = fresh;
        expiry = now + VALIDITY_MS;
        return fresh;
    }

    /** Il nome come sta nel database, se il dominio e' gestito. Altrimenti null. */
    public static String managed(String required) {
        if (required == null) return null;
        String r = required.trim().toLowerCase(Locale.ROOT);
        int p = r.indexOf(':');
        if (p > 0) r = r.substring(0, p);
        if (r.isEmpty()) return null;
        return domains().contains(r) ? r : null;
    }

    /** Da chiamare quando i domini cambiano, per non aspettare la scadenza. */
    public static void invalidate() {
        expiry = 0;
    }
}
