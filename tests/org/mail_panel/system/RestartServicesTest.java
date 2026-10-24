package org.mail_panel.system;

import java.util.List;

/**
 * I servizi che si riavviano dopo aver aggiornato un pacchetto.
 *
 * Misurato su latest il 24/10/2026: aggiornamento guidato di clamav 1.5.4_1,1 -> 1.5.4_2,1,
 * «clamav in servizio», ma riavviato solo clamd. freshclam, che viene dallo stesso pacchetto e
 * carica la stessa libclamav, girava ancora col programma di prima: avviato alle 10:48, pacchetto
 * aggiornato alle 14:58, e procstat non trovava piu' il suo eseguibile. La tabella pacchetto ->
 * servizio dava un servizio solo per pacchetto.
 *
 * La parte diretta della tabella non chiede niente a pkg, quindi questa prova gira ovunque.
 */
public class RestartServicesTest {

    private static int failures = 0;

    public static void main(String[] args) {
        List<String> clamav = UpdateManager.serviziDaRiavviare("clamav");
        check("clamav: si riavvia clamd " + clamav, clamav.contains("clamav_clamd"));
        check("clamav: e anche freshclam", clamav.contains("clamav_freshclam"));
        check("clamav: una volta ciascuno", clamav.stream().distinct().count() == clamav.size());
        check("nginx: solo nginx " + UpdateManager.serviziDaRiavviare("nginx"),
                UpdateManager.serviziDaRiavviare("nginx").contains("nginx")
                && !UpdateManager.serviziDaRiavviare("nginx").contains("clamav_freshclam"));
        check("un pacchetto che non fa girare niente: nessun servizio diretto",
                !UpdateManager.serviziDaRiavviare("xorgproto").contains("clamav_clamd"));
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
