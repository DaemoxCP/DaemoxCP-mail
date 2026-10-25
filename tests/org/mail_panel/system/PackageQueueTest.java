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

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        // L'elenco in una cartella di prova, non in /var/db.
        Path d = Files.createTempDirectory("prova-turno");
        Path f = d.resolve("mail-panel-maintenance-locks");
        PackageQueue.list = f;

        // --- Il turno ---
        real("libero all'inizio", PackageQueue.holder() == null);
        real("il primo lo prende", PackageQueue.take("a", "manutenzione") == null);
        String no = PackageQueue.take("b", "aggiornamento di kafka");
        real("il secondo no, e il messaggio dice chi lo tiene", no != null && no.contains("(manutenzione"));
        real("nemmeno per le protezioni, mentre un lavoro gira",
            PackageQueue.takeForLocks("c", "protezione dei pacchetti") != null);
        PackageQueue.release("b");
        real("chi non lo tiene non puo' liberarlo", PackageQueue.holder() != null);
        PackageQueue.release("a");
        real("chi lo tiene lo libera", PackageQueue.holder() == null);

        // Molti nello stesso istante: uno solo lo prende.
        int n = 64;
        CountDownLatch via = new CountDownLatch(1), finished = new CountDownLatch(n);
        AtomicInteger taken = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            final String id = "t" + i;
            Thread.ofPlatform().start(() -> {
                try {
                    via.await();
                    if (PackageQueue.take(id, "lavoro " + id) == null) taken.incrementAndGet();
                } catch (InterruptedException ignored) {
                } finally { finished.countDown(); }
            });
        }
        via.countDown();
        finished.await(10, TimeUnit.SECONDS);
        real(n + " insieme: uno solo prende il turno", taken.get() == 1);
        String keeps = PackageQueue.holder();
        PackageQueue.release(keeps.substring("lavoro ".length(), keeps.indexOf(',')));
        real("e poi lo libera", PackageQueue.holder() == null);

        // avvia: il turno si libera quando il lavoro finisce, anche se fallisce.
        CountDownLatch inside = new CountDownLatch(1), leave = new CountDownLatch(1);
        real("lavoro lungo: prende il turno", PackageQueue.take("lungo", "lavoro lungo") == null);
        PackageQueue.start("lungo", "prova-lungo", () -> {
            inside.countDown();
            try { leave.await(); } catch (InterruptedException ignored) { }
        });
        inside.await(5, TimeUnit.SECONDS);
        real("mentre gira, il turno resta suo", PackageQueue.take("other", "other") != null);
        leave.countDown();
        real("finito il lavoro, il turno si libera", waitUntilFree());

        Thread.setDefaultUncaughtExceptionHandler((t, x) -> { });   // l'eccezione voluta non sporca l'uscita
        real("lavoro che fallisce: prende il turno", PackageQueue.take("broken", "lavoro rotto") == null);
        PackageQueue.start("broken", "prova-rotto", () -> { throw new IllegalStateException("prova"); });
        real("anche se fallisce, il turno si libera", waitUntilFree());

        // --- L'elenco su disco ---
        real("elenco nuovo: scritto", PackageQueue.writeState(List.of("kafka", "librdkafka")) == null);
        real("elenco nuovo: contenuto giusto", "kafka\nlibrdkafka\n".equals(Files.readString(f)));
        String e = PackageQueue.writeState(f, List.of("nginx"));
        real("elenco gia' presente: rifiutato", e != null && e.contains("esiste già"));
        real("elenco gia' presente: NON sovrascritto", "kafka\nlibrdkafka\n".equals(Files.readString(f)));
        Path withoutFolder = d.resolve("non-esiste").resolve("mail-panel-maintenance-locks");
        e = PackageQueue.writeState(withoutFolder, List.of("nginx"));
        real("cartella che non c'e': rifiutato, e dice perche'", e != null && e.startsWith("non riesco a scrivere"));
        real("cartella che non c'e': nessun file lasciato", !Files.exists(withoutFolder));

        // Con l'elenco di un lavoro non chiuso su disco, quei pacchetti potrebbero essere ancora
        // unlockedPackages: nessun lavoro che installa o aggiorna parte. Rimettere le protezioni si',
        // perche' e' proprio il rimedio.
        String e2 = PackageQueue.take("upd", "aggiornamento dei pacchetti non protetti");
        real("elenco aperto: un aggiornamento non parte", e2 != null && e2.contains("non si è chiuso"));
        real("elenco aperto: e il turno non resta preso", PackageQueue.holder() == null);
        real("elenco aperto: le protezioni si possono rimettere",
            PackageQueue.takeForLocks("lock", "protezione dei pacchetti") == null);
        PackageQueue.release("lock");
        PackageQueue.deleteState();
        real("elenco chiuso: l'aggiornamento parte", PackageQueue.take("upd", "aggiornamento") == null);
        PackageQueue.release("upd");

        Files.delete(d);
        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }

    private static boolean waitUntilFree() throws InterruptedException {
        for (int i = 0; i < 100 && PackageQueue.holder() != null; i++) Thread.sleep(50);
        return PackageQueue.holder() == null;
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
