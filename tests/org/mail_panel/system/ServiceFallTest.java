package org.mail_panel.system;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Un servizio che non era attivo nemmeno prima non e' un servizio caduto.
 *
 * Quattro lavori chiudevano con un quadro dei servizi, e tre di loro contavano come guasto
 * QUALUNQUE servizio non attivo in quel momento, senza sapere come stava prima.
 *
 * Misurato sulla VM FreeBSD 15.1 il 23/10/2026: un aggiornamento guidato di nginx riuscito
 * in ogni passo — piano rispettato (firma 24ddf05e8623c1d2), nginx 1.30.5_2,3 -> 1.30.6,3,
 * configurazione accettata, servizio riavviato con il pid cambiato (68238 -> 16297),
 * vulnerabilita' richieste, pacchetto riprotetto — e' finito in "error" con "Aggiornamento
 * eseguito, ma un servizio non e' ripartito come doveva". I due servizi: local_unbound, che
 * su quella macchina non e' nemmeno abilitato, e ntpd, che non parte da prima.
 *
 * Un allarme che suona sempre insegna a ignorarlo, e quando suona per davvero non lo
 * distingue nessuno. Per questo le prove qui sotto misurano le DUE direzioni: che un guasto
 * vero venga ancora preso, e che un servizio fermo da prima non lo diventi.
 */
public class ServiceFallTest {

    private static int failures = 0;

    public static void main(String[] args) {

        // --- Il caso misurato sulla VM: 13 servizi, due fermi da prima ---
        Map<String, Boolean> before = vmServices(), now = vmServices();
        UpdateManager.Job j = new UpdateManager.Job("prova", "prova");
        boolean fallen = UpdateManager.fallenServices(j, before, now);
        String log = j.toJson().optString("consoleLog", "");
        check("la macchina della misura: nessun servizio e' caduto", !fallen);
        check("  local_unbound compare comunque nel quadro", log.contains("local_unbound"));
        check("  e ntpd anche", log.contains("ntpd"));
        check("  nessun allarme nel log", !log.toUpperCase().contains("ALLARME")
                                      && !log.toUpperCase().contains("ALARM"));

        // --- Un guasto vero si vede ancora: era attivo, adesso no ---
        Map<String, Boolean> afterFault = vmServices();
        afterFault.put("dovecot", false);
        UpdateManager.Job j2 = new UpdateManager.Job("prova2", "prova");
        check("un servizio che era attivo e adesso no: caduto",
             UpdateManager.fallenServices(j2, before, afterFault));
        String log2 = j2.toJson().optString("consoleLog", "");
        check("  e il log lo nomina", log2.contains("dovecot"));
        check("  con un allarme", log2.toUpperCase().contains("ALLARME") || log2.toUpperCase().contains("ALARM"));

        // --- Un servizio che l'aggiornamento ha ACCESO non e' un guasto ---
        Map<String, Boolean> turnedOn = vmServices();
        turnedOn.put("ntpd", true);
        UpdateManager.Job j3 = new UpdateManager.Job("prova3", "prova");
        check("un servizio che prima era fermo e adesso e' attivo: nessun guasto",
             !UpdateManager.fallenServices(j3, before, turnedOn));
        check("  e non si dice che non era attivo nemmeno prima, perche' adesso lo e'",
             !j3.toJson().optString("consoleLog", "").contains("ntpd: attivo (")
             && !j3.toJson().optString("consoleLog", "").contains("ntpd: running ("));

        // --- Un servizio SPARITO (il pacchetto se n'e' andato) mentre era attivo ---
        Map<String, Boolean> vanished = vmServices();
        vanished.remove("rspamd");
        UpdateManager.Job j4 = new UpdateManager.Job("prova4", "prova");
        check("un servizio attivo che non esiste piu': caduto",
             UpdateManager.fallenServices(j4, before, vanished));
        check("  e il log lo nomina", j4.toJson().optString("consoleLog", "").contains("rspamd"));

        // --- Un servizio comparso adesso si vede nel quadro ---
        Map<String, Boolean> appeared = vmServices();
        appeared.put("opendkim", true);
        UpdateManager.Job j5 = new UpdateManager.Job("prova5", "prova");
        check("un servizio comparso con l'aggiornamento non e' un guasto",
             !UpdateManager.fallenServices(j5, before, appeared));
        check("  ma compare nel quadro", j5.toJson().optString("consoleLog", "").contains("opendkim"));

        // --- Tutto attivo prima e dopo ---
        Map<String, Boolean> all = new LinkedHashMap<>();
        all.put("postfix", true); all.put("dovecot", true);
        UpdateManager.Job j6 = new UpdateManager.Job("prova6", "prova");
        check("tutto attivo prima e dopo: nessun guasto",
             !UpdateManager.fallenServices(j6, all, new LinkedHashMap<>(all)));

        // --- Nessuno stato di partenza: non si inventa un guasto ---
        // Succede se statoServizi() non ha trovato nessuno script rc.d. Senza un "prima" non
        // si puo' dire che qualcosa e' caduto, e dire di si' sarebbe un allarme inventato.
        UpdateManager.Job j7 = new UpdateManager.Job("prova7", "prova");
        check("senza stato di partenza non si dichiara nessun guasto",
             !UpdateManager.fallenServices(j7, new LinkedHashMap<>(), vmServices()));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /** I servizi della VM come li ha visti la misura del 23/10/2026. */
    private static Map<String, Boolean> vmServices() {
        Map<String, Boolean> m = new LinkedHashMap<>();
        for (String s : new String[]{"postfix", "dovecot", "rspamd", "redis", "clamav_clamd",
                                     "clamav_freshclam", "mysql-server", "nginx", "php_fpm",
                                     "fail2ban", "pf"}) m.put(s, true);
        m.put("local_unbound", false);   // non e' nemmeno abilitato su quella macchina
        m.put("ntpd", false);            // abilitato ma non parte, da prima dell'aggiornamento
        return m;
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
