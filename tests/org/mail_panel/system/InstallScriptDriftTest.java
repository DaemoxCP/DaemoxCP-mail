package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Il reperto 42: lo script di installazione di un pacchetto cambia la configurazione viva, e
 * l'aggiornamento si dichiara riuscito.
 *
 * Misurato sulla VM FreeBSD 15.1 il 24/10/2026: aggiornando postfix-mysql 3.11.7_1,1 ->
 * 3.11.7_3,1 lo script ha scritto {@code inet_protocols = ipv4} in main.cf mentre postfix
 * ascoltava in IPv4 e IPv6. Al riavvio IPv6 sparisce, e ogni controllo dell'aggiornamento
 * guidato passa: configurazione valida, servizio attivo, pid cambiato. E il filtro dei
 * messaggi, sull'uscita vera di quell'aggiornamento, restituiva zero messaggi.
 *
 * Due parti.
 *
 * A. Il filtro dei messaggi sull'uscita VERA di quell'aggiornamento, 61 righe copiate da
 *    /tmp/agg.log della VM. Gira ovunque.
 *
 * B. I tre lavori veri — aggiornamento guidato, aggiornamento dei non protetti, manutenzione
 *    completa — su un pacchetto finto, nginx-drift-probe, costruito qui con {@code pkg create}.
 *    La sua versione 1.1 fa quello che ha fatto lo script di postfix: stampa un «COMPATIBILITY:
 *    editing», aggiunge {@code protocols = ipv4} alla configurazione viva, e il servizio
 *    smette di ascoltare in IPv6; e scrive anche un file in /etc, che prima nessuno guardava.
 *    La versione 1.2 cambia solo i file suoi e crea il suo utente, come fanno i port: deve
 *    passare pulita, ed e' la direzione che dice che il controllo non grida al lupo.
 *
 *    Il nome comincia con «nginx» apposta: il pannello lo prende per un pezzo di nginx, quindi
 *    l'aggiornamento guidato ha un servizio vero da riavviare — innocuo da riavviare sulla VM.
 *    Nel caso sporco NON lo deve riavviare (il riavvio metterebbe in vigore una configurazione
 *    che nessuno ha letto); nel caso pulito si'. Lo dice il pid di nginx.
 *
 *    Il servizio e' un nc in ascolto su 127.0.0.1 e ::1, porta 47425. Lo script della 1.1
 *    non lo riavvia: spegne il lato IPv6, che e' l'effetto del riavvio. Il motivo e' misurato:
 *    un servizio rilanciato dallo script di installazione non sopravvive all'installazione
 *    (dopo l'aggiornamento non c'era piu' niente in ascolto, nemmeno in IPv4).
 *
 *    Per tenere fuori i pacchetti veri, durante la prova i repository FreeBSD-ports e
 *    FreeBSD-ports-kmods sono spenti (un file in /usr/local/etc/pkg/repos, tolto alla fine),
 *    e prima di ogni lavoro si controlla che il piano contenga SOLO drift-probe. La
 *    manutenzione sblocca e riprotegge davvero i pacchetti protetti della macchina, come
 *    sempre. Tocca il sistema e rimette tutto com'era, e lo controlla: si accende solo con
 *    -De2e.vm=yes, da root, su FreeBSD. Solo su una macchina di prova.
 *
 * Con il jar senza la correzione la parte A trova zero messaggi e i casi «sporchi» della
 * parte B finiscono «completed»: questa e' la prova che fallisce senza e passa con.
 */
public class InstallScriptDriftTest {

    private static int failures = 0, skipped = 0;

    /** L'uscita di pkg dell'aggiornamento di postfix-mysql, 24/10/2026, riga per riga. */
    static final String POSTFIX_UPGRADE_OUTPUT = """
            Checking integrity... done (1 conflicting)
              - lmdb0-0.9.35 [FreeBSD-ports] conflicts with lmdb-1.0.2,1 [installed] on /usr/local/bin/mdb_copy
            Checking integrity... done (0 conflicting)
            The following 3 package(s) will be affected (of 0 checked):

            New packages to be INSTALLED:
            \tlmdb0: 0.9.35 [FreeBSD-ports]

            Installed packages to be UPGRADED:
            \tpostfix-mysql: 3.11.7_1,1 -> 3.11.7_3,1 [FreeBSD-ports]

            Installed packages to be REMOVED:
            \tlmdb: 1.0.2,1

            Number of packages to be removed: 1
            Number of packages to be installed: 1
            Number of packages to be upgraded: 1
            [1/4] Deinstalling postfix-mysql-3.11.7_1,1...
            [1/4] Deleting files for postfix-mysql-3.11.7_1,1: .......... done
            ==> You should manually remove the "postfix" user
            ==> You should manually remove the "maildrop" group
            ==> You should manually remove the "postfix" group
            [2/4] Deinstalling lmdb-1.0.2,1...
            [2/4] Deleting files for lmdb-1.0.2,1: .......... done
            [3/4] Installing lmdb0-0.9.35...
            [3/4] Extracting lmdb0-0.9.35: .......... done
            [4/4] Installing postfix-mysql-3.11.7_3,1...
            ===> Creating groups
            Using existing group 'mail'
            Using existing group 'maildrop'
            Using existing group 'postfix'
            ===> Creating users
            Using existing user 'postfix'
            ===> Creating homedir(s)
            [4/4] Extracting postfix-mysql-3.11.7_3,1: .......... done
            postfix: Postfix is using backwards-compatible default settings
            postfix: See https://www.postfix.org/COMPATIBILITY_README.html for details
            postfix: To disable backwards compatibility use "postconf compatibility_level=3.11" and "postfix reload"
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for postscreen TCP service
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for smtpd unix-domain service
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for dnsblog unix-domain service
            Editing /usr/local/etc/postfix/master.cf, adding missing entry for tlsproxy unix-domain service
                COMPATIBILITY: editing /usr/local/etc/postfix/main.cf, setting
                inet_protocols=ipv4.  Specify inet_protocols explicitly if you
                want to enable IPv6.  In a future release IPv6 will be enabled
                by default.

            ===============================================================
            Postfix was *not* activated in //usr/local/etc/mail/mailer.conf!\s

            To finish installation run the following commands:

              mkdir -p //usr/local/etc/mail
              install -m 0644 //usr/local/share/postfix/mailer.conf.postfix //usr/local/etc/mail/mailer.conf
            ===============================================================

            You may need to manually remove /usr/local/etc/postfix/main.cf if it is no longer needed.
            You may need to manually remove /usr/local/etc/postfix/master.cf if it is no longer needed.
            Message from postfix-mysql-3.11.7_1,1:
            If you remove postfix permanent, adjust / remove the the following file:
              - /usr/local/etc/mail/mailer.conf
            """;

    public static void main(String[] args) throws Exception {
        messages();
        if ("yes".equals(System.getProperty("e2e.vm"))) {
            if (onFreeBsdAsRoot()) endToEnd();
            else { skipped++; System.out.println("\n  SALTATA  parte B: serve FreeBSD e root"); }
        } else {
            skipped++;
            System.out.println("\n  SALTATA  parte B: tocca il sistema, si accende con -De2e.vm=yes (solo su una VM di prova)");
        }
        System.out.println(failures == 0 ? "\nTUTTO OK" + (skipped > 0 ? " (" + skipped + " parti saltate, dette sopra)" : "")
                                         : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    // ===================== A. il filtro dei messaggi =====================

    private static void messages() {
        System.out.println("A. Il filtro dei messaggi sull'uscita vera dell'aggiornamento di postfix-mysql");
        List<String> m = UpdateManager.messaggiCheChiedonoAzione(POSTFIX_UPGRADE_OUTPUT);
        System.out.println("     messaggi trovati: " + m.size());
        check("l'avviso COMPATIBILITY, fuori da ogni blocco «Message from», viene ripescato",
                any(m, "COMPATIBILITY: editing /usr/local/etc/postfix/main.cf") && any(m, "inet_protocols=ipv4"));
        check("  intero: anche la riga che dice che IPv6 si perde", any(m, "want to enable IPv6"));
        check("le modifiche a master.cf annunciate dallo script anche",
                any(m, "Editing /usr/local/etc/postfix/master.cf, adding missing entry"));
        check("il riquadro di mailer.conf, con i comandi da eseguire",
                any(m, "Postfix was *not* activated") && any(m, "install -m 0644"));
        check("la frase di pkg sui file diversi dall'esempio non e' un'azione",
                !any(m, "You may need to manually remove"));
        check("nemmeno quella dei port sull'utente di un pacchetto che si reinstalla",
                !any(m, "You should manually remove the \"postfix\" user"));
        check("il messaggio della versione VECCHIA, che si disinstalla, non chiede niente",
                !any(m, "If you remove postfix permanent"));

        // Quello che il filtro sapeva gia' fare non si deve perdere.
        String rspamd = "[1/1] Upgrading rspamd from 3.12 to 4.1...\n[1/1] Extracting rspamd-4.1: .... done\n"
                + "=====\nMessage from rspamd-4.1:\n\n--\nThe statistics format changed.\nIt is recommended to remove\nthe old cache files:\n  rm /var/db/rspamd/*.hs*\n";
        List<String> r = UpdateManager.messaggiCheChiedonoAzione(rspamd);
        check("un blocco «Message from» che chiede un'azione resta ripescato, intero",
                r.size() == 1 && r.get(0).contains("It is recommended") && r.get(0).contains("rm /var/db/rspamd"));
        check("un'uscita senza niente da fare non da' messaggi",
                UpdateManager.messaggiCheChiedonoAzione("[1/1] Upgrading nginx from 1.30.5_2,3 to 1.30.6,3...\n"
                        + "[1/1] Extracting nginx-1.30.6,3: .......... done\n"
                        + "You may need to manually remove /usr/local/etc/nginx/nginx.conf if it is no longer needed.\n").isEmpty());
    }

    private static boolean any(List<String> messages, String text) {
        for (String s : messages) if (s.contains(text)) return true;
        return false;
    }

    // ===================== B. i tre lavori veri =====================

    static final String PKG = "nginx-drift-probe";
    static final String ETC_FILE = "/etc/drift-probe.conf";
    static final String USER = "driftprobe";
    static final String NGINX_PID = "/var/run/nginx.pid";
    static final String CONF = "/usr/local/etc/drift-probe/drift-probe.conf";
    static final String RESTART = "/usr/local/libexec/drift-probe/restart";
    static final String REPO_CONF = "/usr/local/etc/pkg/repos/zzz-drift-probe.conf";
    static final String REPO_DB = "/var/db/pkg/repos/" + PKG;
    static final String PID4 = "/var/run/drift-probe.4.pid", PID6 = "/var/run/drift-probe.6.pid";
    static final int PORT = 47425;
    static Path work;

    private static boolean onFreeBsdAsRoot() {
        return sh("uname -s").trim().equals("FreeBSD") && sh("id -u").trim().equals("0");
    }

    private static void endToEnd() throws Exception {
        System.out.println("\nB. I tre lavori veri, con un pacchetto il cui script cambia la configurazione");
        // I resti di un giro interrotto falserebbero il confronto finale: via prima di misurare.
        removePackage();
        sh("rm -f " + REPO_CONF + "; rm -rf " + REPO_DB);
        String packagesBefore = sh("pkg query %n-%v | sort | sha256");
        String savedBefore = sh("ls " + InstallSideEffects.BEFORE_UPDATE_DIR + " 2>/dev/null");
        Set<String> lockedBefore = locked();
        work = Files.createTempDirectory(Path.of("/var/tmp"), "drift-probe");
        try {
            buildPackage("1.0", false);
            buildPackage("1.1", true);    // lo script sporco
            buildPackage("1.2", false);   // cambia solo i file suoi
            Files.writeString(Path.of(REPO_CONF),
                    "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
                  + PKG + ": { url: \"file://" + work.resolve("repo") + "\", signature_type: \"none\", enabled: yes }\n");
            String repos = sh("pkg -vv 2>/dev/null | sed -n '/^Repositories/,$p'");
            if (!enabledOnly(repos, PKG)) {
                check("i repository veri sono spenti per la prova (altrimenti non si parte)", false);
                System.out.println(repos);
                return;
            }
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) {
                runCase(flow, "1.1", true);
                runCase(flow, "1.2", false);
            }
        } finally {
            removePackage();
            sh("rm -f " + REPO_CONF + "; rm -rf " + REPO_DB + " " + work);
            // Le copie «di prima» che i casi sporchi hanno messo da parte: sono della prova.
            for (String d : sh("ls " + InstallSideEffects.BEFORE_UPDATE_DIR + " 2>/dev/null").split("\n"))
                if (!d.isBlank() && !savedBefore.contains(d.trim())) sh("rm -rf " + InstallSideEffects.BEFORE_UPDATE_DIR + "/" + d.trim());
            // E la nota e i cartelli dei pacchetti bloccati, che dopo il pacchetto tolto vanno riallineati.
            UpdateManager.refreshLockTrace();
            String after = sh("pkg query %n-%v | sort | sha256");
            check("alla fine: gli stessi pacchetti di prima, alle stesse versioni", after.equals(packagesBefore));
            check("alla fine: gli stessi pacchetti protetti di prima", locked().equals(lockedBefore));
            check("alla fine: FreeBSD-ports di nuovo acceso",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("alla fine: niente in ascolto sulla porta della prova",
                    sh("sockstat -46lq -P tcp -p " + PORT).trim().isEmpty());
            check("alla fine: niente file di prova in /etc, nessun utente di prova",
                    !Files.exists(Path.of(ETC_FILE)) && !sh("pw usershow " + USER + " 2>&1").startsWith(USER + ":"));
            check("alla fine: le copie «di prima» sono quelle che c'erano",
                    sh("ls " + InstallSideEffects.BEFORE_UPDATE_DIR + " 2>/dev/null").equals(savedBefore));
        }
    }

    /** Un caso: drift-probe 1.0 installato e in ascolto, nel catalogo la versione data, e il lavoro. */
    private static void runCase(String flow, String version, boolean dirty) throws Exception {
        System.out.println("\n  --- " + flow + ", 1.0 -> " + version + (dirty ? " (lo script cambia la configurazione)" : " (pulito)") + " ---");
        removePackage();
        sh("pkg add " + work.resolve("pkgs/" + PKG + "-1.0.pkg") + " 2>&1");
        // La configurazione di un amministratore: diversa dal suo esempio, come main.cf.
        Files.writeString(Path.of(CONF), Files.readString(Path.of(CONF)) + "banner = drift probe\n", StandardCharsets.UTF_8);
        sh(RESTART);
        if (!waitListening(true)) { check(flow + " " + version + ": il servizio di prova ascolta in IPv4 e IPv6 prima del lavoro", false); return; }
        String nginxPidBefore = sh("cat " + NGINX_PID + " 2>/dev/null").trim();
        Path repo = work.resolve("repo");
        sh("rm -rf " + repo + " && mkdir -p " + repo + " && cp " + work.resolve("pkgs/" + PKG + "-" + version + ".pkg") + " " + repo
                + " && pkg repo " + repo + " >/dev/null 2>&1 && pkg update -f -r " + PKG + " >/dev/null 2>&1");
        if (!flow.equals("unprotected")) sh("pkg lock -y " + PKG);

        JSONObject plan, start;
        String signature;
        switch (flow) {
            case "guided" -> {
                JSONObject pf = UpdateManager.packagePreflight(PKG);
                plan = pf.optJSONObject("piano");
                signature = pf.optString("signature");
                if (!pf.optBoolean("canProceed")) {
                    check(flow + " " + version + ": il preflight lascia partire", false);
                    System.out.println("     " + pf.optJSONArray("checks"));
                    return;
                }
            }
            case "unprotected" -> {
                JSONObject st = UpdateManager.updatesStatus();
                plan = st.optJSONObject("piano");
                signature = st.optString("signature");
            }
            default -> {
                JSONObject pv = UpdateManager.maintenancePreview();
                plan = pv.optJSONObject("piano");
                signature = pv.optString("signature");
            }
        }
        Set<String> inPlan = new TreeSet<>();
        JSONArray ch = plan == null ? new JSONArray() : plan.optJSONArray("changes");
        for (int i = 0; ch != null && i < ch.length(); i++) inPlan.add(ch.getJSONObject(i).optString("nome"));
        if (!inPlan.equals(Set.of(PKG))) {
            // Un piano con altri pacchetti cambierebbe la macchina per davvero: non si parte.
            check(flow + " " + version + ": il piano contiene solo " + PKG + " (trovato " + inPlan + ")", false);
            return;
        }
        start = switch (flow) {
            case "guided" -> UpdateManager.startGuidedUpdate(PKG, signature);
            case "unprotected" -> UpdateManager.startUnlockedPackagesUpdate(signature);
            default -> UpdateManager.startMaintenance(signature);
        };
        String id = start.optString("jobId");
        if (id.isEmpty()) { check(flow + " " + version + ": il lavoro parte (" + start + ")", false); return; }
        // La fine e' il turno libero, non lo stato: la manutenzione dice «completed» prima dei
        // suoi controlli finali (reperto 43), e chi si fermasse li' guarderebbe un lavoro a meta'.
        long deadline = System.currentTimeMillis() + 600_000;
        while (PackageQueue.chi() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = UpdateManager.jobStatus(id).getJSONObject("job");
        // -De2e.dump=<cartella>: il JSON del lavoro com'e', quello che la pagina riceve da
        // job_status. Serve a far vedere a un browser l'esito vero, non uno scritto a mano.
        String dump = System.getProperty("e2e.dump");
        if (dump != null) Files.writeString(Path.of(dump, flow + "-" + version + ".json"),
                new JSONObject().put("success", true).put("job", job).toString(2));
        String log = job.optString("consoleLog"), error = job.optString("errorMessage"), status = job.optString("status");
        System.out.println("     esito: " + status + " in " + job.optLong("elapsedSeconds") + " s"
                + (error.isEmpty() ? "" : "\n     errore: " + error));
        for (String l : log.split("\n")) System.out.println("       | " + l);

        String nginxPidAfter = sh("cat " + NGINX_PID + " 2>/dev/null").trim();
        String label = flow + " 1.0 -> " + version + ": ";
        if (dirty) {
            check(label + "il lavoro NON si dichiara riuscito", "error".equals(status));
            check(label + "l'esito nomina il file che lo script ha cambiato", error.contains(CONF));
            check(label + "  e quello che ha scritto in /etc", error.contains(ETC_FILE));
            check(label + "l'esito nomina l'indirizzo perso", error.contains("[::1]:" + PORT));
            check(label + "il log mostra la riga che lo script ha aggiunto", log.contains("+ protocols = ipv4"));
            String header = I18n.tr("server.um.runAggiornamentoGuidato.33");
            int h = log.lastIndexOf(header);
            check(label + "e ristampa alla fine l'avviso COMPATIBILITY dello script",
                    h >= 0 && log.indexOf("COMPATIBILITY: editing", h) > h);
            // La versione di prima, messa da parte: il percorso lo dice il log, il contenuto lo
            // sa la prova, perche' e' quello che ha scritto lei prima del lavoro.
            String saved = null;
            for (String l : log.split("\n")) {
                int c = l.indexOf("cp -p ");
                if (c >= 0 && l.trim().endsWith(" " + CONF)) saved = l.substring(c + 6, l.lastIndexOf(" " + CONF)).trim();
            }
            check(label + "la versione di prima di " + CONF + " e' messa da parte, ed e' quella giusta",
                    saved != null && Files.exists(Path.of(saved))
                    && Files.readString(Path.of(saved)).equals("port = " + PORT + "\nbanner = drift probe\n"));
            check(label + "  e il log dice che " + ETC_FILE + " prima non c'era",
                    log.contains(I18n.tr("server.drift.savedCreated", java.util.Map.of("path", ETC_FILE))));
            if (flow.equals("guided")) {
                check(label + "nginx NON e' stato riavviato (pid " + nginxPidBefore + " -> " + nginxPidAfter + ")",
                        !nginxPidBefore.isEmpty() && nginxPidBefore.equals(nginxPidAfter));
                check(label + "  e l'esito lo dice, col comando per farlo dopo",
                        error.contains(I18n.tr("server.drift.restartHeldProblem", java.util.Map.of("list", "nginx")))
                        && log.contains("service nginx restart"));
            }
        } else {
            check(label + "riuscito, senza allarmi", "completed".equals(status) && error.isEmpty());
            check(label + "  e il controllo della configurazione c'e' stato", log.contains(I18n.tr("server.drift.configHeader")));
            check(label + "  e quello degli indirizzi pure", log.contains(I18n.tr("server.drift.listenHeader")));
            check(label + "  l'utente creato dal pacchetto si dice, senza allarme",
                    log.contains("/etc/passwd: ") && log.contains(I18n.tr("server.drift.kind.accounts")));
            if (flow.equals("guided"))
                check(label + "nginx riavviato come sempre (pid " + nginxPidBefore + " -> " + nginxPidAfter + ")",
                        !nginxPidAfter.isEmpty() && !nginxPidBefore.equals(nginxPidAfter));
        }
    }

    /** Il pacchetto di prova: un .sample, lo script che fa partire il servizio, e i due script di pkg. */
    private static void buildPackage(String version, boolean dirty) throws Exception {
        Path root = work.resolve("root-" + version);
        Path etc = Files.createDirectories(root.resolve("usr/local/etc/drift-probe"));
        Path libexec = Files.createDirectories(root.resolve("usr/local/libexec/drift-probe"));
        Files.writeString(etc.resolve("drift-probe.conf.sample"),
                "port = " + PORT + "\n" + ("1.2".equals(version) ? "# esempio della 1.2\n" : ""));
        Files.writeString(libexec.resolve("restart"), String.join("\n",
                "#!/bin/sh",
                "# drift-probe " + version + ": in ascolto in IPv4, e in IPv6 se la configurazione non lo toglie",
                "C=" + CONF,
                "for f in " + PID4 + " " + PID6 + "; do [ -f $f ] && kill $(cat $f) 2>/dev/null; rm -f $f; done",
                "sleep 1",
                "daemon -f -p " + PID4 + " nc -dkl 127.0.0.1 " + PORT,
                "grep -q '^protocols *= *ipv4' $C 2>/dev/null || daemon -f -p " + PID6 + " nc -6 -dkl ::1 " + PORT,
                "exit 0", ""));
        sh("chmod 755 " + libexec.resolve("restart"));
        String postInstall = "C=" + CONF + "\n[ -f $C ] || cp $C.sample $C\n";
        if (dirty) postInstall += String.join("\n",
                "echo 'daily_drift_probe_enable=\"YES\"' > " + ETC_FILE,
                "echo \"    COMPATIBILITY: editing $C, setting\"",
                "echo \"    protocols=ipv4.  Specify protocols explicitly if you want to enable IPv6.\"",
                "grep -q '^protocols' $C || echo 'protocols = ipv4' >> $C",
                "[ -f " + PID6 + " ] && kill $(cat " + PID6 + ") 2>/dev/null",
                "rm -f " + PID6, "");
        postInstall += "exit 0\n";
        // Come lo fanno i port con USERS e GROUPS: il gruppo e l'utente, se non ci sono.
        String preInstall = "1.2".equals(version)
                ? "pw groupshow " + USER + " >/dev/null 2>&1 || pw groupadd " + USER + "\n"
                + "pw usershow " + USER + " >/dev/null 2>&1 || pw useradd " + USER + " -g " + USER
                + " -d /nonexistent -s /usr/sbin/nologin -c 'drift probe'\nexit 0\n"
                : "exit 0\n";
        String preDeinstall = "C=" + CONF + "\nif cmp -s $C $C.sample; then rm -f $C; else "
                + "echo \"You may need to manually remove $C if it is no longer needed.\"; fi\nexit 0\n";
        Path manifest = work.resolve("manifest-" + version);
        Files.writeString(manifest, "name: " + PKG + "\nversion: \"" + version + "\"\norigin: misc/" + PKG
                + "\ncomment: \"prova del reperto 42\"\ndesc: \"prova del reperto 42\"\nmaintainer: root@localhost\n"
                + "www: https://localhost/\nprefix: /usr/local\nscripts: {\n"
                + "  pre-install: <<EOD\n" + preInstall + "EOD\n"
                + "  post-install: <<EOD\n" + postInstall + "EOD\n"
                + "  pre-deinstall: <<EOD\n" + preDeinstall + "EOD\n}\n");
        Path plist = work.resolve("plist-" + version);
        Files.writeString(plist, "/usr/local/etc/drift-probe/drift-probe.conf.sample\n/usr/local/libexec/drift-probe/restart\n");
        Files.createDirectories(work.resolve("pkgs"));
        String out = sh("pkg create -M " + manifest + " -r " + root + " -p " + plist + " -o " + work.resolve("pkgs") + " 2>&1");
        if (!Files.exists(work.resolve("pkgs/" + PKG + "-" + version + ".pkg")))
            throw new IllegalStateException("pkg create " + version + ": " + out);
    }

    private static void removePackage() {
        sh("for f in " + PID4 + " " + PID6 + "; do [ -f $f ] && kill $(cat $f) 2>/dev/null; rm -f $f; done; "
         + "pkill -f 'nc -dkl 127.0.0.1 " + PORT + "'; pkill -f 'nc -6 -dkl ::1 " + PORT + "'; "
         + "pkg unlock -y " + PKG + " >/dev/null 2>&1; pkg delete -y " + PKG + " >/dev/null 2>&1; "
         + "rm -rf /usr/local/etc/drift-probe /usr/local/libexec/drift-probe " + ETC_FILE + "; "
         + "pw userdel " + USER + " >/dev/null 2>&1; pw groupdel " + USER + " >/dev/null 2>&1; true");
    }

    private static boolean waitListening(boolean both) throws Exception {
        for (int i = 0; i < 10; i++) {
            String s = sh("sockstat -46lq -P tcp -p " + PORT);
            if (s.contains("127.0.0.1:" + PORT) && (!both || s.contains("[::1]:" + PORT))) return true;
            Thread.sleep(500);
        }
        return false;
    }

    /** Nel blocco Repositories di pkg -vv, il solo repository acceso e' quello dato. */
    private static boolean enabledOnly(String repos, String name) {
        String current = null;
        Set<String> enabled = new TreeSet<>();
        for (String l : repos.split("\n")) {
            String t = l.trim();
            if (t.endsWith(": {")) current = t.substring(0, t.length() - 3).trim();
            else if (current != null && t.matches("enabled\\s*:\\s*yes,?")) enabled.add(current);
        }
        return enabled.equals(Set.of(name));
    }

    private static Set<String> locked() {
        Set<String> r = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n"))
            if (!l.trim().isEmpty() && !l.trim().endsWith(":")) r.add(l.trim());
        return r;
    }

    private static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(300), cmd).output();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
