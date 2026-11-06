package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Il turno dei lavori sui pacchetti fra due PROCESSI del pannello.
 *
 * Il servizio (--web) e il menu a schermo sono due JVM. Con il turno solo in memoria il menu non
 * vedeva una manutenzione in corso nel servizio (e viceversa una reinstallazione dal menu), e
 * ogni avvio del jar riproteggeva come "interrotto" l'elenco di un lavoro vivo in un altro
 * processo, cancellandoglielo. Qui un secondo processo vero (TurnHolder) tiene il turno, e si
 * guarda che questo processo:
 *   - non lo prenda, e sappia da chi e' tenuto;
 *   - all'avvio lasci stare l'elenco di quel lavoro (restoreLocksAfterCrash);
 *   - non applichi la regola dei blocchi mentre l'altro lavora (applyLockPolicy);
 * e che, ucciso l'altro con kill -9, il turno torni libero e l'elenco rimasto si riprotegga.
 *
 * L'elenco e il file del turno stanno in una cartella di prova. Il ripristino chiede a pkg di
 * due pacchetti che non esistono (pkg info -e), quindi non cambia niente sulla macchina; va
 * lanciata sulla VM come le altre.
 */
public class PackageTurnAcrossProcessesTest {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        Path d = Files.createTempDirectory("turn-across");
        PackageQueue.list = d.resolve("mail-panel-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        Path list = PackageQueue.list;

        System.out.println("== Un altro processo tiene il turno, senza elenco ==");
        Holder h = Holder.start(list, "manutenzione di prova");
        check("l'altro processo ha il turno", h.pid > 0);
        String r = PackageQueue.take("here", "aggiornamento guidato");
        check("qui non si prende", r != null);
        check("e il motivo dice il pid e il lavoro dell'altro",
                r != null && r.contains("pid " + h.pid) && r.contains("manutenzione di prova"));
        check("il rifiuto non lascia preso il turno in memoria", PackageQueue.holder() == null);
        check("nemmeno per le protezioni", PackageQueue.takeForLocks("here", "protezione") != null);
        // La regola dei blocchi all'avvio: con il database del pannello "presente" (non collegato:
        // il rifiuto arriva prima di qualunque domanda), non deve bloccare niente adesso.
        Main.mailDatabase = new MailDatabase();
        String policy = UpdateManager.applyLockPolicy();
        Main.mailDatabase = null;
        check("la regola dei blocchi non si applica mentre l'altro lavora", policy.contains("not applied"));
        h.release();
        check("rilasciato dall'altro, qui si prende", PackageQueue.take("here", "aggiornamento guidato") == null);
        check("e il file del turno dice chi lo tiene adesso",
                Files.readString(PackageQueue.turnLock).contains("pid " + ProcessHandle.current().pid()));
        PackageQueue.release("here");

        System.out.println("\n== Un altro processo lavora con i pacchetti sbloccati (elenco su disco) ==");
        h = Holder.start(list, "reinstallazione di prova", "e2e-turn-probe-a", "e2e-turn-probe-b");
        check("l'altro ha il turno e l'elenco", h.pid > 0 && Files.exists(list));
        String restore = UpdateManager.restoreLocksAfterCrash();
        check("l'avvio di questo processo lascia stare l'elenco", restore.contains("left alone"));
        check("e l'elenco e' ancora quello dell'altro",
                Files.readString(list).equals("e2e-turn-probe-a\ne2e-turn-probe-b\n"));
        check("con l'elenco di un lavoro vivo, qui non si parte", PackageQueue.take("here", "manutenzione") != null);

        System.out.println("\n== L'altro processo muore (kill -9) ==");
        h.kill();
        check("l'elenco resta: e' quello che sopravvive", Files.exists(list));
        restore = UpdateManager.restoreLocksAfterCrash();
        check("adesso l'avvio lo riconosce come interrotto e lo chiude",
                restore.contains("Interrupted") && !Files.exists(list));
        check("e il turno e' libero", PackageQueue.take("here", "manutenzione") == null);
        PackageQueue.release("here");

        Files.deleteIfExists(PackageQueue.turnLock);
        Files.delete(d);
        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Il secondo processo: TurnHolder, con lo stesso classpath. */
    static final class Holder {
        final Process p;
        final long pid;

        private Holder(Process p, long pid) { this.p = p; this.pid = pid; }

        static Holder start(Path list, String description, String... packages) throws Exception {
            String java = ProcessHandle.current().info().command().orElse("java");
            List<String> cmd = new ArrayList<>(List.of(java, "-cp", System.getProperty("java.class.path"),
                    "org.mail_panel.system.TurnHolder", list.toString(), description));
            cmd.addAll(List.of(packages));
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            BufferedReader out = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
            String line = out.readLine();
            System.out.println("    (altro processo: " + line + ")");
            long pid = line != null && line.startsWith("HELD ") ? Long.parseLong(line.substring(5).trim()) : -1;
            return new Holder(p, pid);
        }

        void release() throws Exception {
            p.getOutputStream().close();
            p.waitFor();
        }

        void kill() throws Exception {
            p.destroyForcibly();   // SIGKILL: niente finally, niente shutdown hook
            p.waitFor();
        }
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failed++;
    }
}
