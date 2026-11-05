package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * La reinstallazione completa con i pacchetti protetti (InstallLocks), con un pkg finto.
 *
 * Il pkg vero non sa dare i guasti che contano qui: uno sblocco che dice di si' e non sblocca,
 * una lettura delle protezioni che non risponde, una riprotezione che fallisce. Con il finto si
 * provano tutti, e per ognuno si guarda la stessa cosa che conta sulla macchina: se lo script
 * puo' partire, che cosa resta protetto, se l'elenco su disco si chiude o resta, se il turno si
 * libera. L'elenco e il file del turno stanno in una cartella di prova, non in /var/db.
 *
 * Il caso vero (il pannello acceso, 39 protetti, la reinstallazione dal menu) lo prova
 * MenuReinstall sulla VM; questa prova gira ovunque, ma va lanciata sulla VM come le altre.
 */
public class InstallLocksTest {

    private static int failed = 0;

    /** pkg finto: chi e' protetto, chi e' installato, e i guasti da piantare. */
    static final class FakePkg implements InstallLocks.Pkg {
        final Map<String, Boolean> locked = new LinkedHashMap<>();   // nome -> protetto
        final Set<String> installed = new TreeSet<>();
        final List<String> calls = new ArrayList<>();
        Set<String> unlockLies = Set.of();      // pkg unlock dice si', ma resta protetto
        Set<String> lockFails = Set.of();       // pkg lock fallisce
        int lockListNullFrom = Integer.MAX_VALUE; // dalla n-esima lettura, pkg non risponde
        Runnable onFirstRead = null;            // qualcosa che succede durante la prima lettura
        String explodeAt = null;                // pkg esplode sbloccando questo pacchetto
        boolean stateExistedAtFirstUnlock = false;
        int reads = 0;

        FakePkg with(String... names) {
            for (String n : names) { locked.put(n, true); installed.add(n); }
            return this;
        }

        public String lockList() {
            reads++;
            calls.add("list");
            if (reads == 1 && onFirstRead != null) onFirstRead.run();
            if (reads >= lockListNullFrom) return null;
            StringBuilder sb = new StringBuilder();
            for (var e : locked.entrySet()) if (e.getValue()) sb.append(e.getKey()).append("-1.0_1\n");
            return sb.toString().trim();
        }
        public boolean unlock(String n) {
            calls.add("unlock " + n);
            if (!calls.contains("unlocked-once")) {
                calls.add("unlocked-once");
                stateExistedAtFirstUnlock = PackageQueue.statePresent();
            }
            if (n.equals(explodeAt)) throw new IllegalStateException("prova: pkg esplode su " + n);
            if (unlockLies.contains(n)) return true;
            if (!locked.containsKey(n)) return false;
            locked.put(n, false);
            return true;
        }
        public boolean lock(String n) {
            calls.add("lock " + n);
            if (lockFails.contains(n) || !installed.contains(n)) return false;
            locked.put(n, true);
            return true;
        }
        public boolean installed(String n) { return installed.contains(n); }

        int unlockCalls() { return (int) calls.stream().filter(c -> c.startsWith("unlock ")).count(); }
        long lockedCount() { return locked.values().stream().filter(b -> b).count(); }
    }

    public static void main(String[] args) throws Exception {
        Path d = Files.createTempDirectory("install-locks");
        PackageQueue.list = d.resolve("mail-panel-maintenance-locks");
        Path list = PackageQueue.list;

        System.out.println("== Nessun pacchetto protetto ==");
        FakePkg p = new FakePkg();
        InstallLocks.Start s = InstallLocks.prepare("prova", p);
        check("parte", s.refusal() == null && s.held() != null);
        check("non sblocca niente e non scrive l'elenco", p.unlockCalls() == 0 && !Files.exists(list));
        check("tiene il turno", PackageQueue.holder() != null);
        InstallLocks.finish(s.held(), p, false);
        check("alla fine il turno e' libero", PackageQueue.holder() == null);

        System.out.println("\n== Tre protetti, tutto bene ==");
        p = new FakePkg().with("mysql84-server", "dovecot-mysql", "nginx");
        s = InstallLocks.prepare("prova", p);
        check("parte", s.refusal() == null && s.held() != null);
        check("l'elenco era su disco PRIMA del primo sblocco", p.stateExistedAtFirstUnlock);
        check("l'elenco nomina i tre pacchetti, senza versione",
                Files.readString(list).equals("dovecot-mysql\nmysql84-server\nnginx\n"));
        check("tutti e tre sbloccati", p.lockedCount() == 0);
        check("il rapporto dice quanti e dove sta l'elenco",
                s.report().contains("3") && s.report().contains(list.toString()));
        check("un altro lavoro non prende il turno", PackageQueue.take("other", "altro") != null);
        // Lo script ha reinstallato i pacchetti: vanno riprotetti tutti, l'elenco si chiude.
        String back = InstallLocks.finish(s.held(), p, false);
        check("riprotetti tutti e tre", p.lockedCount() == 3);
        check("l'elenco e' chiuso", !Files.exists(list));
        check("il turno e' libero", PackageQueue.holder() == null);
        check("il rapporto dice 3 di nuovo protetti", back.contains("3"));
        check("una seconda chiusura non fa niente", InstallLocks.finish(s.held(), p, false).isEmpty());

        System.out.println("\n== Lo script ha tolto un pacchetto ==");
        p = new FakePkg().with("mysql84-server", "dovecot");
        s = InstallLocks.prepare("prova", p);
        p.installed.remove("dovecot");
        p.locked.remove("dovecot");
        back = InstallLocks.finish(s.held(), p, false);
        check("l'altro e' di nuovo protetto", p.locked.get("mysql84-server"));
        check("l'elenco si chiude lo stesso (come il ripristino all'avvio)", !Files.exists(list));
        check("e il rapporto nomina quello sparito", back.contains("dovecot"));

        System.out.println("\n== Una riprotezione fallisce ==");
        p = new FakePkg().with("mysql84-server", "nginx");
        s = InstallLocks.prepare("prova", p);
        p.lockFails = Set.of("nginx");
        back = InstallLocks.finish(s.held(), p, false);
        check("l'elenco RESTA, cosi' il prossimo avvio riprova", Files.exists(list));
        check("il rapporto nomina nginx come non protetto", back.contains("nginx") && back.contains(list.toString()));
        check("il turno si libera comunque", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== Dopo lo script pkg non risponde ==");
        p = new FakePkg().with("mysql84-server");
        s = InstallLocks.prepare("prova", p);
        p.lockListNullFrom = p.reads + 1;
        back = InstallLocks.finish(s.held(), p, false);
        check("non si sa se e' protetto: l'elenco resta", Files.exists(list));
        check("e il rapporto lo dice", back.contains(list.toString()));
        check("il turno si libera", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== Uno sblocco dice si' e non sblocca ==");
        p = new FakePkg().with("mysql84-server", "nginx", "redis");
        p.unlockLies = Set.of("mysql84-server");
        s = InstallLocks.prepare("prova", p);
        check("NON parte", s.refusal() != null && s.held() == null);
        check("il rifiuto nomina il pacchetto rimasto protetto", s.refusal().contains("mysql84-server"));
        check("gli altri sono di nuovo protetti: come prima", p.lockedCount() == 3);
        check("l'elenco e' chiuso", !Files.exists(list));
        check("il turno e' libero", PackageQueue.holder() == null);

        System.out.println("\n== pkg non dice chi e' protetto ==");
        p = new FakePkg().with("mysql84-server");
        p.lockListNullFrom = 1;
        s = InstallLocks.prepare("prova", p);
        check("NON parte", s.refusal() != null && s.held() == null);
        check("non ha sbloccato niente e non ha scritto l'elenco", p.unlockCalls() == 0 && !Files.exists(list));
        check("il turno e' libero", PackageQueue.holder() == null);

        System.out.println("\n== Dopo lo sblocco pkg non risponde ==");
        p = new FakePkg().with("mysql84-server", "nginx");
        p.lockListNullFrom = 2;
        s = InstallLocks.prepare("prova", p);
        check("NON parte: non si sa se lo sblocco e' riuscito", s.refusal() != null && s.held() == null);
        check("ha provato a riproteggere entrambi", p.calls.contains("lock mysql84-server") && p.calls.contains("lock nginx"));
        check("e, senza poterlo verificare, l'elenco resta per il prossimo avvio", Files.exists(list));
        check("il turno e' libero", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== L'elenco non si puo' scrivere ==");
        // Compare l'elenco di un altro lavoro mentre si leggono le protezioni: writeState lo
        // rifiuta (CREATE_NEW), e allora non si deve sbloccare niente.
        p = new FakePkg().with("mysql84-server", "nginx");
        p.onFirstRead = () -> {
            try { Files.writeString(list, "kafka\n"); } catch (Exception e) { throw new RuntimeException(e); }
        };
        s = InstallLocks.prepare("prova", p);
        check("NON parte", s.refusal() != null && s.held() == null);
        check("non ha sbloccato niente", p.unlockCalls() == 0 && p.lockedCount() == 2);
        check("l'elenco dell'altro e' intatto", Files.readString(list).equals("kafka\n"));
        check("il turno e' libero", PackageQueue.holder() == null);
        Files.delete(list);

        System.out.println("\n== pkg esplode a meta' sblocco ==");
        p = new FakePkg().with("mysql84-server", "nginx");
        p.explodeAt = "nginx";   // il secondo in ordine: mysql84-server e' gia' sbloccato
        s = InstallLocks.prepare("prova", p);
        check("NON parte", s.refusal() != null && s.held() == null);
        check("il primo era stato sbloccato davvero", p.calls.contains("unlock mysql84-server"));
        check("ha riprotetto quello che c'era", p.lockedCount() == 2);
        check("l'elenco e' chiuso", !Files.exists(list));
        check("il turno e' libero", PackageQueue.holder() == null);

        System.out.println("\n== Il turno e' gia' preso ==");
        check("un altro lavoro prende il turno", PackageQueue.take("maint", "manutenzione") == null);
        p = new FakePkg().with("mysql84-server");
        s = InstallLocks.prepare("prova", p);
        check("NON parte, e dice chi lo tiene", s.refusal() != null && s.refusal().contains("manutenzione"));
        check("e non ha chiesto niente a pkg", p.calls.isEmpty());
        PackageQueue.release("maint");

        System.out.println("\n== C'e' l'elenco di un lavoro interrotto ==");
        Files.writeString(list, "kafka\n");
        p = new FakePkg().with("mysql84-server");
        s = InstallLocks.prepare("prova", p);
        check("NON parte", s.refusal() != null && s.held() == null);
        check("e non ha chiesto niente a pkg", p.calls.isEmpty());
        Files.delete(list);

        Files.deleteIfExists(PackageQueue.turnFile());
        Files.delete(d);
        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failed++;
    }
}
