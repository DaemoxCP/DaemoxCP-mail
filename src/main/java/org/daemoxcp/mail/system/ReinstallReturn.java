package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Tornare al server com'era prima di una reinstallazione completa, senza perdere la posta arrivata
 * dopo. Lo usano il menu da console (voce 6) e la pagina Aggiornamenti (l'avviso della
 * reinstallazione interrotta), con lo stesso codice.
 *
 * <p>Perche' esiste (reperto 169): la via di ritorno della reinstallazione e' un boot environment, e
 * /var/vmail ci sta dentro. Attivarlo e basta riportava la posta al momento in cui era stato creato:
 * i messaggi arrivati dopo si perdevano. E l'unico modo di sceglierla era leggere l'avviso e scrivere
 * bectl activate in una shell.
 *
 * <p>Qui, prima di attivarlo: Postfix e Dovecot si fermano (la posta non cambia mentre si copia), il
 * boot environment si monta, e i file della posta di adesso che li' MANCANO si aggiungono (tar -k: un
 * file che c'e' gia' non si tocca). Maildir e' un file per messaggio, quindi i messaggi di prima
 * restano e quelli nuovi si aggiungono; Dovecot li vede alla prima lettura. Non e' rollback-panel.sh,
 * che SOSTITUISCE la posta: dopo una reinstallazione la posta di adesso e' quella che la
 * reinstallazione ha svuotato, e sostituirla perderebbe proprio quella di prima. Poi bectl activate.
 * Non si riavvia qui: lo fa chi chiama, quando lo decide l'amministratore.
 *
 * <p>Cosa NON torna in pari: il database MySQL e' quello di prima (caselle, domini, alias e
 * amministratori creati dopo vanno rifatti: dopo una reinstallazione e' comunque quello ricreato
 * vuoto); la coda di Postfix e' quella di prima (lo si dice se adesso non e' vuota).
 */
public final class ReinstallReturn {

    private static final Logger LOGGER = Logger.getLogger(ReinstallReturn.class.getName());

    private ReinstallReturn() {}

    static String vmail = "/var/vmail";

    private static Shell.Result run(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd);
    }

    /** La via di ritorno della reinstallazione piu' recente, o "" se non ce n'e'. */
    public static String latest() {
        return PackageWayBack.newestReinstallWayBack();
    }

    /** Quello che serve per decidere: nome, quando, se ci stanno posta e database, il boot environment in uso. */
    public static JSONObject describe() {
        JSONObject r = new JSONObject().put("success", true);
        String name = latest();
        r.put("wayBack", name);
        if (name.isEmpty()) return r;
        r.put("createdUtc", name.substring(PackageWayBack.REINSTALL_PREFIX.length()));
        r.put("dataInside", new org.json.JSONArray(PackageWayBack.dataInside()));
        return r;
    }

    /**
     * Torna a 'name': la posta di adesso fusa dentro, poi bectl activate. Se qualcosa va storto prima
     * dell'attivazione, non e' cambiato niente e la posta riparte. Non riavvia.
     */
    public static JSONObject goBack(String name, Consumer<String> log) {
        JSONObject r = new JSONObject();
        if (name == null || !PackageWayBack.REINSTALL_OWN.matcher(name).matches())
            return r.put("success", false).put("error", I18n.tr("server.wayBack.notReinstall", Map.of("name", String.valueOf(name))));
        String state = null;
        for (String line : run("bectl list -H 2>/dev/null", 60).outputTrim().split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && f[0].trim().equals(name)) state = f[1].trim();
        }
        if (state == null)
            return r.put("success", false).put("error", I18n.tr("server.wayBack.missing", Map.of("name", name)));
        if (state.contains("N"))
            return r.put("success", false).put("error", I18n.tr("server.wayBack.alreadyRunning", Map.of("name", name)));

        // Il turno dei pacchetti: tornare indietro cambia pacchetti e configurazioni insieme, e un
        // lavoro sui pacchetti a meta' (in questo processo o in un altro) ne verrebbe rotto.
        String refusal = PackageQueue.takeForLocks("way-back", I18n.tr("server.wayBack.turn"));
        if (refusal != null) return r.put("success", false).put("error", refusal);
        String mnt = "", mntDir = "";
        List<String> stopped = new ArrayList<>();
        boolean activated = false;
        try {
            mntDir = run("mktemp -d /var/tmp/daemoxcp-mail-way-back.XXXXXX", 30).outputTrim();
            if (!mntDir.matches("/var/tmp/daemoxcp-mail-way-back\\.[A-Za-z0-9]+")) {
                String err = mntDir;
                mntDir = "";
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotMount", Map.of("name", name, "err", err)));
            }
            mnt = mntDir;
            Shell.Result m = run("bectl mount " + name + " " + mnt + " 2>&1", 120);
            if (!m.success())
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotMount", Map.of("name", name, "err", m.outputTrim())));

            int merged = 0;
            if (PackageWayBack.dataInside().contains(vmail) && new java.io.File(vmail).isDirectory()) {
                for (String svc : List.of("postfix", "dovecot"))
                    if (run("service " + svc + " status >/dev/null 2>&1", 30).success()) {
                        run("service " + svc + " stop >/dev/null 2>&1", 120);
                        stopped.add(svc);
                    }
                String parent = vmail.substring(0, vmail.lastIndexOf('/'));
                String base = vmail.substring(vmail.lastIndexOf('/') + 1);
                long before = count(mnt + vmail);
                // -k: un file che nel boot environment c'e' gia' non si sovrascrive. -p: proprietari e permessi.
                Shell.Result c = run("tar -cpf - -C " + parent + " " + base + " | tar -xpkf - -C " + mnt + parent + " 2>&1", 3600);
                long after = count(mnt + vmail);
                if (!c.success() || after < before) {
                    return r.put("success", false).put("error", I18n.tr("server.wayBack.mergeFailed",
                            Map.of("name", name, "err", c.outputTrim().isEmpty() ? "exit " + c.exitCode() : c.outputTrim())));
                }
                merged = (int) (after - before);
                log.accept(I18n.tr("server.wayBack.merged", Map.of("n", String.valueOf(merged), "name", name)));
            }
            String queued = run("postqueue -j 2>/dev/null | wc -l", 30).outputTrim();
            if (queued.matches("[0-9]+") && !queued.equals("0"))
                log.accept(I18n.tr("server.wayBack.queued", Map.of("n", queued)));

            Shell.Result u = run("bectl umount " + name + " 2>&1", 120);
            if (!u.success())
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotMount", Map.of("name", name, "err", u.outputTrim())));
            mnt = "";
            Shell.Result a = run("bectl activate " + name + " 2>&1", 120);
            if (!a.success())
                return r.put("success", false).put("error", I18n.tr("server.wayBack.cannotActivate", Map.of("name", name, "err", a.outputTrim())));
            activated = true;
            log.accept(I18n.tr("server.wayBack.activated", Map.of("name", name)));
            LOGGER.warning("Way back of a reinstallation activated for the next boot: " + name + ", " + merged + " mail files merged in");
            return r.put("success", true).put("name", name).put("merged", merged)
                    .put("note", I18n.tr("server.wayBack.rebootNeeded", Map.of("name", name)));
        } finally {
            if (!mnt.isEmpty()) run("bectl umount " + name + " >/dev/null 2>&1", 120);
            if (!mntDir.isEmpty()) run("rmdir " + mntDir + " 2>/dev/null", 30);
            // Fino all'attivazione niente e' cambiato: la posta riparte. Dopo, resta ferma fino al riavvio.
            if (!activated) for (String svc : stopped) run("service " + svc + " start >/dev/null 2>&1", 120);
            PackageQueue.release("way-back");
        }
    }

    private static long count(String dir) {
        String n = run("find " + dir + " -type f 2>/dev/null | wc -l", 600).outputTrim();
        return n.matches("[0-9]+") ? Long.parseLong(n) : -1;
    }
}
