package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Un lavoro alla volta sui pacchetti, e l'elenco per riproteggerli scritto davvero.
 *
 * Revisione sul PR degli aggiornamenti: due aggiornamenti approvati da due schede
 * partivano insieme e si sovrascrivevano l'elenco su disco; e se l'elenco non si poteva scrivere
 * (disco pieno, /var/db non scrivibile) il lavoro sbloccava lo stesso. Qui si prova che il turno
 * lo prende uno solo anche con molti che ci provano nello stesso istante, che si libera anche se
 * il lavoro fallisce, e che l'elenco non sovrascrive quello di un lavoro interrotto e, se non si
 * scrive, lo dice.
 */
public class PackageQueueTest {

    private static int falliti = 0;

    public static void main(String[] args) throws Exception {
        // L'elenco in una cartella di prova, non in /var/db.
        Path d = Files.createTempDirectory("prova-turno");
        Path f = d.resolve("mail-panel-maintenance-locks");
        PackageJobLock.elenco = f;

        // --- Il turno ---
        vero("libero all'inizio", PackageJobLock.chi() == null);
        vero("il primo lo prende", PackageJobLock.prendi("a", "manutenzione") == null);
        String no = PackageJobLock.prendi("b", "aggiornamento di kafka");
        vero("il secondo no, e il messaggio dice chi lo tiene", no != null && no.contains("(manutenzione"));
        vero("nemmeno per le protezioni, mentre un lavoro gira",
            PackageJobLock.prendiPerLeProtezioni("c", "protezione dei pacchetti") != null);
        PackageJobLock.rilascia("b");
        vero("chi non lo tiene non puo' liberarlo", PackageJobLock.chi() != null);
        PackageJobLock.rilascia("a");
        vero("chi lo tiene lo libera", PackageJobLock.chi() == null);

        // Molti nello stesso istante: uno solo lo prende.
        int n = 64;
        CountDownLatch via = new CountDownLatch(1), finiti = new CountDownLatch(n);
        AtomicInteger presi = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            final String id = "t" + i;
            Thread.ofPlatform().start(() -> {
                try {
                    via.await();
                    if (PackageJobLock.prendi(id, "lavoro " + id) == null) presi.incrementAndGet();
                } catch (InterruptedException ignored) {
                } finally { finiti.countDown(); }
            });
        }
        via.countDown();
        finiti.await(10, TimeUnit.SECONDS);
        vero(n + " insieme: uno solo prende il turno", presi.get() == 1);
        String tiene = PackageJobLock.chi();
        PackageJobLock.rilascia(tiene.substring("lavoro ".length(), tiene.indexOf(',')));
        vero("e poi lo libera", PackageJobLock.chi() == null);

        // avvia: il turno si libera quando il lavoro finisce, anche se fallisce.
        CountDownLatch dentro = new CountDownLatch(1), esci = new CountDownLatch(1);
        vero("lavoro lungo: prende il turno", PackageJobLock.prendi("lungo", "lavoro lungo") == null);
        PackageJobLock.avvia("lungo", "prova-lungo", () -> {
            dentro.countDown();
            try { esci.await(); } catch (InterruptedException ignored) { }
        });
        dentro.await(5, TimeUnit.SECONDS);
        vero("mentre gira, il turno resta suo", PackageJobLock.prendi("altro", "altro") != null);
        esci.countDown();
        vero("finito il lavoro, il turno si libera", attendiLibero());

        Thread.setDefaultUncaughtExceptionHandler((t, x) -> { });   // l'eccezione voluta non sporca l'uscita
        vero("lavoro che fallisce: prende il turno", PackageJobLock.prendi("rotto", "lavoro rotto") == null);
        PackageJobLock.avvia("rotto", "prova-rotto", () -> { throw new IllegalStateException("prova"); });
        vero("anche se fallisce, il turno si libera", attendiLibero());

        // --- L'elenco su disco ---
        vero("elenco nuovo: scritto", PackageJobLock.scriviStato(List.of("kafka", "librdkafka")) == null);
        vero("elenco nuovo: contenuto giusto", "kafka\nlibrdkafka\n".equals(Files.readString(f)));
        String e = PackageJobLock.scriviStato(f, List.of("nginx"));
        vero("elenco gia' presente: rifiutato", e != null && e.contains("esiste già"));
        vero("elenco gia' presente: NON sovrascritto", "kafka\nlibrdkafka\n".equals(Files.readString(f)));
        Path senzaCartella = d.resolve("non-esiste").resolve("mail-panel-maintenance-locks");
        e = PackageJobLock.scriviStato(senzaCartella, List.of("nginx"));
        vero("cartella che non c'e': rifiutato, e dice perche'", e != null && e.startsWith("non riesco a scrivere"));
        vero("cartella che non c'e': nessun file lasciato", !Files.exists(senzaCartella));

        // Con l'elenco di un lavoro non chiuso su disco, quei pacchetti potrebbero essere ancora
        // sbloccati: nessun lavoro che installa o aggiorna parte. Rimettere le protezioni si',
        // perche' e' proprio il rimedio.
        String e2 = PackageJobLock.prendi("upd", "aggiornamento dei pacchetti non protetti");
        vero("elenco aperto: un aggiornamento non parte", e2 != null && e2.contains("non si è chiuso"));
        vero("elenco aperto: e il turno non resta preso", PackageJobLock.chi() == null);
        vero("elenco aperto: le protezioni si possono rimettere",
            PackageJobLock.prendiPerLeProtezioni("lock", "protezione dei pacchetti") == null);
        PackageJobLock.rilascia("lock");
        PackageJobLock.cancellaStato();
        vero("elenco chiuso: l'aggiornamento parte", PackageJobLock.prendi("upd", "aggiornamento") == null);
        PackageJobLock.rilascia("upd");

        Files.delete(d);
        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static boolean attendiLibero() throws InterruptedException {
        for (int i = 0; i < 100 && PackageJobLock.chi() != null; i++) Thread.sleep(50);
        return PackageJobLock.chi() == null;
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
