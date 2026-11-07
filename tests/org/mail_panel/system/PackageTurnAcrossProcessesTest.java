package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.Main;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.scripts.FullMailServerScript;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Il turno dei lavori sui pacchetti fra PROCESSI: due pannelli, e il pannello contro lo script
 * dell'installazione completa lanciato a mano.
 *
 * Il servizio (--web) e il menu a schermo sono due JVM, e lo script install_mail_server.sh si
 * puo' lanciare anche da una shell. Il turno e' un lock su PackageQueue.turnLock (fcntl dal
 * pannello, lockf(1) dallo script). Qui un secondo processo vero (TurnHolder) tiene il turno, e si
 * guarda che questo processo:
 *   - non lo prenda, e sappia da chi e' tenuto;
 *   - all'avvio lasci stare l'elenco di quel lavoro (restoreLocksAfterCrash);
 *   - non applichi la regola dei blocchi mentre l'altro lavora, e lo dica (applyLockPolicy);
 * che, ucciso l'altro con kill -9, il turno torni libero e l'elenco rimasto si riprotegga con
 * l'avviso che nomina il lavoro interrotto; che lockf e il pannello si escludano in tutte e due le
 * direzioni (reperto 153); e che la parte del turno dello script vero (presa dal testo che il
 * pannello scrive, fino ai controlli sui pacchetti protetti, prima di fermare qualunque cosa)
 * parta solo quando deve.
 *
 * Elenco, record del lavoro, avviso e lock stanno in una cartella di prova. Il ripristino chiede
 * a pkg di due pacchetti che non esistono (pkg info -e), quindi non cambia niente sulla macchina;
 * va lanciata sulla VM come le altre, da root (lo script lo controlla):
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageTurnAcrossProcessesTest
 */
public class PackageTurnAcrossProcessesTest {

    private static int failed = 0;
    private static Path d;

    public static void main(String[] args) throws Exception {
        d = Files.createTempDirectory(Path.of("/var/tmp"), "turn-across");
        PackageQueue.list = d.resolve("mail-panel-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        PackageRecovery.notice = d.resolve("package-job-interrupted.json");
        Path list = PackageQueue.list;
        long me = ProcessHandle.current().pid();

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
        // il rifiuto arriva prima di qualunque domanda), non deve bloccare niente adesso, e dirlo.
        Main.mailDatabase = new MailDatabase();
        String policy = UpdateManager.applyLockPolicy();
        Main.mailDatabase = null;
        check("la regola dei blocchi non si applica mentre l'altro lavora, e lo dice",
                policy.contains("not applied") && policy.contains("manutenzione di prova"));
        h.release();
        check("rilasciato dall'altro, qui si prende", PackageQueue.take("here", "aggiornamento guidato") == null);
        check("e il lock dice chi lo tiene adesso", Files.readString(PackageQueue.turnLock).startsWith("pid " + me + ", "));
        PackageQueue.release("here");

        System.out.println("\n== Un altro processo lavora con i pacchetti sbloccati (elenco su disco) ==");
        h = Holder.start(list, "reinstallazione di prova", "e2e-turn-probe-a", "e2e-turn-probe-b");
        check("l'altro ha il turno e l'elenco", h.pid > 0 && Files.exists(list));
        check("il record del lavoro accanto all'elenco e' dell'altro",
                PackageQueue.jobRecord().optLong("pid") == h.pid
                && "reinstallazione di prova".equals(PackageQueue.jobRecord().optString("description")));
        String restore = UpdateManager.restoreLocksAfterCrash();
        check("l'avvio di questo processo lascia stare l'elenco", restore.contains("the list is not touched"));
        check("e l'elenco e' ancora quello dell'altro",
                Files.readString(list).equals("e2e-turn-probe-a\ne2e-turn-probe-b\n"));
        check("e nessun avviso di lavoro interrotto", !Files.exists(PackageRecovery.notice));
        check("con l'elenco di un lavoro vivo, qui non si parte", PackageQueue.take("here", "manutenzione") != null);

        System.out.println("\n== L'altro processo muore (kill -9) ==");
        h.kill();
        check("l'elenco resta: e' quello che sopravvive", Files.exists(list));
        restore = UpdateManager.restoreLocksAfterCrash();
        check("adesso l'avvio lo riconosce come interrotto e lo chiude",
                restore.contains("Interrupted") && !Files.exists(list));
        JSONObject notice = PackageRecovery.notice();
        check("e l'avviso nomina il lavoro interrotto", "reinstallazione di prova".equals(notice.optString("description")));
        check("e il turno e' libero", PackageQueue.take("here", "manutenzione") == null);
        PackageQueue.release("here");
        Files.deleteIfExists(PackageRecovery.notice);

        lockfAgainstThePanel();
        scriptTurn();

        for (String f : new String[]{"package-turn.lock", "mail-panel-maintenance-locks",
                "mail-panel-maintenance-locks.job.json", "package-job-interrupted.json", "stop", "turn-part.sh"})
            Files.deleteIfExists(d.resolve(f));
        Files.delete(d);
        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** lockf(1) (flock) e il pannello (fcntl): si escludono? Misurato nel reperto 153, qui ripetuto. */
    static void lockfAgainstThePanel() throws Exception {
        System.out.println("\n== lockf(1) contro il pannello ==");
        if (!Files.isExecutable(Path.of("/usr/bin/lockf"))) { check("lockf(1) c'e' (FreeBSD)", false); return; }
        Path lock = PackageQueue.turnLock, stop = d.resolve("stop");
        Files.writeString(stop, "");
        Process p = new ProcessBuilder("lockf", "-k", "-t", "0", lock.toString(), "sh", "-c",
                "echo \"pid $$, prova con lockf\" > " + lock + "; echo HELD; while [ -e " + stop + " ]; do sleep 0.2; done")
                .redirectErrorStream(true).start();
        String first = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8)).readLine();
        check("lockf ha il turno", "HELD".equals(first));
        String r = PackageQueue.take("here", "aggiornamento guidato");
        check("con lockf che lo tiene, il pannello non prende il turno", r != null);
        check("e sa chi lo tiene, da quello che c'e' scritto", r != null && r.contains("prova con lockf"));
        Files.delete(stop);
        p.waitFor();
        check("finito lockf -k, il file del lock resta", Files.exists(lock));
        check("finito lockf, il pannello lo prende", PackageQueue.take("here", "aggiornamento guidato") == null);
        int rc = sh("lockf -k -s -t 0 " + lock + " true");
        check("col turno al pannello, lockf -t 0 esce 75 (gia' preso)", rc == 75);
        PackageQueue.release("here");
        check("rilasciato dal pannello, lockf lo prende", sh("lockf -k -s -t 0 " + lock + " true") == 0);
        check("con -k il file resta (il pannello lo apre per nome)", Files.exists(lock));
    }

    /**
     * La parte del turno dello script vero: il testo di FullMailServerScript fino ai controlli sui
     * pacchetti protetti, con il lock della cartella di prova; al posto del resto, "TURN-OK" e
     * un'attesa finche' c'e' il file stop. Non arriva mai alla fase 1, qualunque cosa succeda.
     */
    static void scriptTurn() throws Exception {
        System.out.println("\n== La parte del turno dello script dell'installazione completa ==");
        String full = new FullMailServerScript().getScriptContent();
        String cut = "# Prima di fermare qualunque cosa: i pacchetti protetti";
        int at = full.indexOf(cut);
        check("lo script ha il controllo dei protetti dopo il turno", at > 0 && full.indexOf("PACKAGE_TURN_LOCK=") > 0
                && full.indexOf("PACKAGE_TURN_LOCK=") < at && at < full.indexOf("PHASE 1: CLEANUP"));
        if (at < 0) return;
        Path lock = PackageQueue.turnLock, stop = d.resolve("stop"), part = d.resolve("turn-part.sh");
        String body = full.substring(0, at).replace(PackageQueue.TURN_LOCK_PATH, lock.toString());
        check("e prende il lock del pannello, non un altro file", !body.equals(full.substring(0, at)));
        Files.writeString(part, body + "\necho TURN-OK\nwhile [ -e " + stop + " ]; do sleep 0.2; done\nexit 0\n");
        long me = ProcessHandle.current().pid();

        // Dal menu: il pannello (noi) tiene il turno e lo dice allo script.
        PackageQueue.take("menu", "complete mail server installation");
        Run s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", String.valueOf(me)));
        check("dal menu, col turno al pannello: lo script passa", s.rc == 0 && s.out.contains("TURN-OK"));
        // Lanciato a mano mentre il pannello lavora.
        s = Run.script(part, Map.of());
        check("a mano, col turno al pannello: lo script si ferma prima di tutto", s.rc != 0 && !s.out.contains("TURN-OK"));
        check("e dice chi lo tiene", s.out.contains("another job is working on the packages") && s.out.contains("pid " + me + ","));
        // Un pid che non e' il padre.
        s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", "1"));
        check("col pid di un altro processo: si ferma", s.rc != 0 && !s.out.contains("TURN-OK"));
        // Il rilancio sotto lockf finto mentre il pannello lavora: il lock e' preso (dal pannello),
        // quindi solo il controllo che il padre sia lockf lo ferma.
        s = Run.script(part, Map.of("MAIL_PANEL_TURN_BY_LOCKF", "1"));
        check("a mano con MAIL_PANEL_TURN_BY_LOCKF, col turno al pannello: si ferma", s.rc != 0 && !s.out.contains("TURN-OK"));
        PackageQueue.release("menu");
        // Il pannello dice di tenerlo, ma non lo tiene.
        s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", String.valueOf(me)));
        check("col pid giusto ma il turno libero: si ferma", s.rc != 0 && !s.out.contains("TURN-OK") && s.out.contains("does not hold"));
        // Il turno e' preso, ma da un altro processo: dentro c'e' scritto il suo pid, non il nostro.
        Holder h = Holder.start(PackageQueue.list, "manutenzione di prova");
        s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", String.valueOf(me)));
        check("col turno preso da un altro processo del pannello: si ferma", s.rc != 0 && !s.out.contains("TURN-OK"));
        h.release();
        // Il rilancio sotto lockf finto: la variabile messa a mano.
        s = Run.script(part, Map.of("MAIL_PANEL_TURN_BY_LOCKF", "1"));
        check("con MAIL_PANEL_TURN_BY_LOCKF messo a mano, senza lockf: si ferma", s.rc != 0 && !s.out.contains("TURN-OK"));

        // A mano, con il turno libero: si rilancia sotto lockf e lo tiene finche' lavora.
        Files.writeString(stop, "");
        Process p = Run.start(part, Map.of());
        StringBuilder out = new StringBuilder();
        BufferedReader rd = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
        for (String l; (l = rd.readLine()) != null; ) { out.append(l).append('\n'); if (l.contains("TURN-OK")) break; }
        check("a mano, col turno libero: lo script passa", out.toString().contains("TURN-OK"));
        String r = PackageQueue.take("here", "manutenzione");
        check("e mentre lavora il pannello non prende il turno", r != null);
        check("e sa che e' lo script lanciato a mano", r != null && r.contains("install_mail_server.sh started by hand"));
        Run second = Run.script(part, Map.of());
        check("e un secondo script a mano si ferma", second.rc != 0 && !second.out.contains("TURN-OK"));
        check("la riga del lock nomina il processo che lavora, non lockf",
                Files.readString(lock).startsWith("pid ") && !Files.readString(lock).startsWith("pid " + p.pid() + ","));
        Files.delete(stop);
        rd.transferTo(java.io.Writer.nullWriter());
        int rc = p.waitFor();
        check("lo script finisce con 0", rc == 0);
        // Prima di qualunque take: take crea il file se manca, e il controllo non vedrebbe piu'
        // niente (e' successo: con lockf senza -k questo controllo, messo dopo, restava verde).
        check("finito lo script, il file del lock c'e' ancora (lockf -k)", Files.exists(lock));
        check("finito lo script, il pannello prende il turno", PackageQueue.take("here", "manutenzione") == null);
        PackageQueue.release("here");
    }

    /** Uno script lanciato come lo lancia il pannello: sh <percorso> <argomenti>, stdin /dev/null. */
    static final class Run {
        int rc;
        String out;

        static final List<String> ARGS = List.of("127.0.0.1", "3306", "mailpanel", "mailserver", "mail.turn.test",
                "webmail.turn.test", "8443", "", "", "");

        static Process start(Path script, Map<String, String> env) throws Exception {
            List<String> cmd = new ArrayList<>(List.of("sh", script.toString()));
            cmd.addAll(ARGS);
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true)
                    .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
            pb.environment().remove("MAIL_PANEL_PACKAGE_TURN");
            pb.environment().remove("MAIL_PANEL_TURN_BY_LOCKF");
            pb.environment().put("MYSQL_PASSWORD", "turn-test");
            pb.environment().put("MYSQL_ROOT_PASSWORD", "turn-test");
            // Lo script della #91 (la webmail col suo utente MySQL) vuole anche questa, e si ferma
            // prima del turno se manca; quello di prima la ignora. Trovato sul ramo d'integrazione.
            pb.environment().put("ROUNDCUBE_DB_PASSWORD", "turn-test");
            pb.environment().putAll(env);
            return pb.start();
        }

        static Run script(Path script, Map<String, String> env) throws Exception {
            Process p = start(script, env);
            Run r = new Run();
            r.out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            r.rc = p.waitFor();
            String last = r.out.strip();
            int nl = last.lastIndexOf('\n');
            System.out.println("    (script " + env + ": rc=" + r.rc + ", " + (nl < 0 ? last : last.substring(nl + 1)) + ")");
            return r;
        }
    }

    private static int sh(String cmd) throws Exception {
        return new ProcessBuilder("sh", "-c", cmd).inheritIO().start().waitFor();
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
