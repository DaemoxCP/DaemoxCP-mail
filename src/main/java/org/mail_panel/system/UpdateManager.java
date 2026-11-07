package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Protezione dei pacchetti, aggiornamenti e vulnerabilita' per lo stack di posta.
 *
 * Il senso di questa classe non e' "mostrare che ci sono aggiornamenti": quello lo fa
 * gia' pkg. Il senso e' rispondere alla domanda che pkg NON puo' porsi — *questo*
 * aggiornamento rompe *questo* server di posta? — e impedire materialmente quelli che
 * lo romperebbero.
 *
 * Il caso che ha motivato tutto: il pannello genera la configurazione di Dovecot con
 * la sintassi 2.3 (mail_location, passdb/userdb senza nome, variabili %u %d %n).
 * Dovecot 2.4 non degrada su quella configurazione: si RIFIUTA di partire. Un banale
 * "pkg upgrade" fermerebbe la posta, e nessun numero di versione lo direbbe.
 */
public final class UpdateManager {

    private static final Logger LOGGER = Logger.getLogger(UpdateManager.class.getName());
    private static final Map<String, Job> JOBS = new ConcurrentHashMap<>();

    /** Elenco dei pacchetti sbloccati durante una manutenzione, per rimetterli a posto dopo un crash. */
    private static final String MAINTENANCE_STATE = PackageQueue.STATE_PATH;

    private UpdateManager() {}

    // ===================== esecuzione comandi =====================

    /** Comando shell, output completo. Timeout esplicito: un pkg che non torna bloccherebbe un thread HTTP. */
    private static String sh(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).outputTrim();
    }

    private static String sh(String cmd) { return sh(cmd, 60); }

    private static boolean ok(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).success();
    }

    private static boolean ok(String cmd) { return ok(cmd, 30); }

    /**
     * Un nome di pacchetto finisce dentro una riga di comando: si accettano solo nomi
     * plausibili. Non e' teoria — "roundcube-php84" e "py311-fail2ban" contengono cifre
     * e trattini, quindi la regola dev'essere precisa senza essere permissiva.
     */
    public static boolean isValidName(String n) {
        return n != null && n.matches("[A-Za-z0-9._+-]{1,64}");
    }

    /**
     * Un pacchetto risulta protetto solo se compare come RIGA INTERA in `pkg lock -l`.
     * Con un contains() ingenuo, "curl" combacerebbe dentro "php84-curl-8.4.19" e il
     * pannello dichiarerebbe protetto un pacchetto che non lo e'.
     */
    private static boolean locked(String lockList, String name) {
        for (String line : lockList.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.endsWith(":")) continue;   // "Currently locked packages:"
            if (t.equals(name)) return true;
            // In "nome-versione" il taglio e' UNO SOLO: l'ultimo trattino, e cio' che segue
            // dev'essere una versione, cioe' cominciare con una cifra. Provando ogni trattino
            // "php84-curl-8.4.24" produceva anche il prefisso "php84", e il pannello
            // dichiarava protetto php84 per colpa di una sua estensione. Le versioni dei port
            // FreeBSD non contengono trattini (8.4.24, 1.7.2,1, 1.1.0_8, 25.0.3+9.f.1),
            // quindi un taglio solo basta ed e' esatto.
            int d = t.lastIndexOf('-');
            if (d > 0 && d + 1 < t.length() && Character.isDigit(t.charAt(d + 1))
                    && t.substring(0, d).equals(name)) return true;
        }
        return false;
    }

    // ===================== quali pacchetti riguardano la posta =====================

    /**
     * I pacchetti si RICONOSCONO, non si elencano. Cablare "mysql80-server" o "php84"
     * significa dover riscrivere questa classe al primo cambio di versione — ed e'
     * esattamente l'errore che gli script di installazione di questo pannello contengono
     * gia'. Qui si parte da cio' che e' davvero installato e lo si classifica.
     */
    private static final String[][] ROLES = {
        {"^postfix(-.*)?$",            "SMTP (Postfix)"},
        // Con i sapori del port: dovecot-mysql E' Dovecot, non un suo componente, ed e' il
        // pacchetto che l'installazione mette. Lo stesso per dovecot24-mysql della 2.4.
        {"^dovecot[0-9]*(-(mysql|pgsql|sqlite3|ldap|cdb))?$", "IMAP/POP3 (Dovecot)"},
        {"^dovecot[0-9]*-pigeonhole(-.*)?$", "server.um.role.sieve"},
        {"^dovecot[0-9]*-.*$",         "server.um.role.dovecotPart"},
        {"^rspamd$",                   "server.um.role.rspamd"},
        {"^redis(-.*)?$",              "server.um.locked.1"},
        {"^clamav(-.*)?$",             "Antivirus"},
        {"^roundcube(-php[0-9]+)?$",   "Webmail (Roundcube)"},
        {"^nginx(-.*)?$",              "server.um.locked.2"},
        {"^php[0-9]+$",                "PHP"},
        {"^php[0-9]+-.+$",             "server.um.role.phpExt"},
        {"^mysql[0-9]+-server$",       "Database (server)"},
        {"^mysql[0-9]+-client$",       "Database (client)"},
        {"^py[0-9]+-fail2ban$",        "server.um.role.fail2ban"},
        {"^(py[0-9]+-)?certbot$",      "server.um.locked.3"},
        {"^unbound$",                  "server.um.role.unbound"},
        {"^opendkim$",                 "server.um.role.opendkim"},
        {"^openssl[0-9]*$",            "server.um.role.openssl"},
        {"^openjdk[0-9]*$",            "server.um.locked.4"},
    };

    /** Ruolo del pacchetto nello stack di posta, o null se non lo riguarda. */
    private static String roleOf(String name) {
        for (String[] r : ROLES) if (name.matches(r[0])) return I18n.tr(r[1]);
        return null;
    }

    /**
     * Servizi che questo pannello governa. Ogni riga elenca i nomi POSSIBILI dello stesso
     * servizio, perche' lo script rc.d puo' chiamarsi in modi diversi: PHP-FPM e' "php_fpm"
     * (con il trattino basso, come lo chiama il resto del pannello) e il resolver puo' essere
     * "unbound" del port oppure "local_unbound" del sistema base.
     *
     * Non e' un dettaglio: un nome sbagliato non produce un errore, produce un SILENZIO. Il
     * servizio semplicemente non compare fra quelli controllati, e un aggiornamento che lo
     * spegnesse verrebbe dichiarato riuscito. E' successo: php-fpm con il trattino non e' mai
     * stato trovato, quindi la webmail non era sorvegliata affatto.
     */
    public static final String[][] SERVICES = {
        {"postfix"}, {"dovecot"}, {"rspamd"}, {"redis"},
        // Entrambe le grafie: il pannello stesso, in Main.java, prova "clamav_clamd" e poi
        // "clamav-clamd", segno che il nome dello script rc.d cambia fra le versioni del port.
        {"clamav_clamd", "clamav-clamd"}, {"clamav_freshclam", "clamav-freshclam"},
        {"mysql-server"}, {"nginx"},
        {"php_fpm", "php-fpm"},
        {"fail2ban"},
        {"unbound", "local_unbound"},
        // pf e ntpd sono del sistema base e pkg non li aggiorna, ma se erano attivi prima e
        // non lo sono dopo qualcosa e' successo comunque, e vale la pena accorgersene:
        // senza firewall il server e' esposto, senza orario giusto saltano DKIM e TLS.
        {"pf"},
        {"ntpd"},
        // NON si aggiungono, e il motivo va scritto perche' sembrano mancanze:
        //  - sendmail: il pannello lo SPEGNE apposta, va in conflitto con Postfix. Metterlo
        //    qui vorrebbe dire dichiarare guasto uno stato corretto.
        //  - roundcube: non e' un demone, non esiste nessuno script rc.d. Il riferimento a
        //    "service roundcube" altrove nel pannello e' verosimilmente uno sbaglio.
    };

    /**
     * Che fine hanno fatto i servizi, confrontati con com'erano PRIMA del lavoro.
     *
     * "Non attivo adesso" non vuol dire "caduto". Su questa macchina local_unbound non e'
     * nemmeno abilitato e ntpd non parte: un controllo che guarda solo l'adesso dichiara
     * guasto OGNI aggiornamento. Misurato sulla VM FreeBSD 15.1 il 23/10/2026: un
     * aggiornamento guidato di nginx riuscito in ogni singolo passo — piano rispettato,
     * servizio riavviato, pid cambiato, pacchetto riprotetto — e' finito in "error" con
     * "un servizio non e' ripartito come doveva", per due servizi che non erano attivi
     * nemmeno prima.
     *
     * Un allarme che suona sempre insegna a ignorarlo, e quando suona per davvero non lo
     * distingue nessuno. Che non fosse attivo nemmeno prima si dice comunque: e' una cosa
     * da sapere, non un guasto di questo lavoro.
     *
     * Sta in un punto solo perche' lo chiedono quattro lavori (manutenzione, aggiornamento
     * guidato, aggiornamento dei non protetti, migrazione di MySQL) e la stessa decisione
     * scritta quattro volte e' diventata quattro decisioni diverse: una giusta e tre no.
     *
     * @param prima lo stato dei servizi all'inizio del lavoro, da {@link #servicesState()}
     * @return true se almeno un servizio che era attivo adesso non lo e' piu'
     */
    private static boolean fallenServices(Job job, Map<String, Boolean> before) {
        return fallenServices(job, before, servicesState());
    }

    /** Il confronto in se', senza chiedere niente al sistema: cosi' si prova. */
    static boolean fallenServices(Job job, Map<String, Boolean> before, Map<String, Boolean> now) {
        java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<>(before.keySet());
        names.addAll(now.keySet());   // un servizio comparso con l'aggiornamento si vede
        boolean fallen = false;
        for (String s : names) {
            boolean wasActive = Boolean.TRUE.equals(before.get(s));
            boolean active = Boolean.TRUE.equals(now.get(s));
            if (wasActive && !active) {
                fallen = true;
                job.write(I18n.tr("server.um.runMaintenanceJob.21", java.util.Map.of("key", String.valueOf(s))));
                continue;
            }
            job.write("    " + s + ": "
                    + (active ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMaintenanceJob.22"))
                    + (!active && !wasActive ? I18n.tr("server.um.runMaintenanceJob.23") : ""));
        }
        return fallen;
    }

    /** Quali servizi risultano attivi adesso. Solo quelli davvero presenti sul sistema. */
    private static Map<String, Boolean> servicesState() {
        Map<String, Boolean> m = new LinkedHashMap<>();
        for (String[] candidates : SERVICES) {
            // Un servizio non installato non e' "caduto": va distinto, altrimenti la verifica
            // finale segnalerebbe come guasto qualcosa che non c'e' mai stato. La presenza si
            // decide dallo script rc.d, non dall'esito di "status": quello e' diverso da zero
            // sia per un servizio spento sia per uno inesistente, e confonderebbe i due casi.
            for (String s : candidates) {
                if (!isValidName(s)) continue;
                if (!ok("test -f /usr/local/etc/rc.d/" + s + " -o -f /etc/rc.d/" + s, 10)) continue;
                m.put(s, ok("service " + s + " status", 15));
                break;   // trovato il nome giusto: gli altri sono lo stesso servizio
            }
        }
        return m;
    }

    public static JSONObject packagesStatus() {
        JSONObject r = new JSONObject();
        String lock = sh("pkg lock -l 2>/dev/null");

        // Nome e versione di TUTTI i pacchetti in una query sola: interrogarli uno per uno
        // significherebbe decine di fork+exec a ogni click.
        Map<String, String> versions = new LinkedHashMap<>();
        for (String line : sh("pkg query '%n %v' 2>/dev/null", 30).split("\n")) {
            int sp = line.indexOf(' ');
            if (sp > 0) versions.put(line.substring(0, sp).trim(), line.substring(sp + 1).trim());
        }

        JSONArray arr = new JSONArray();
        int protectedNames = 0, totals = 0;
        for (Map.Entry<String, String> e : versions.entrySet()) {
            String name = e.getKey();
            if (!isValidName(name)) continue;
            String role = roleOf(name);
            if (role == null) continue;
            boolean lk = locked(lock, name);
            totals++;
            if (lk) protectedNames++;
            arr.put(new JSONObject()
                    .put("name", name).put("role", role)
                    .put("version", e.getValue()).put("locked", lk).put("installed", true));
        }
        r.put("success", true).put("packages", arr)
         .put("installedCount", totals).put("lockedCount", protectedNames);
        return r;
    }

    /**
     * Protegge o sblocca i pacchetti. Aspetta il turno dei lavori sui pacchetti: cambiare le
     * protezioni mentre un lavoro le ha tolte e le deve rimettere falserebbe il suo ripristino.
     * Con l'elenco di un lavoro interrotto su disco invece si puo': rimettere le protezioni e'
     * proprio il rimedio.
     */
    public static JSONObject packagesLock(boolean lock, String onlyThis) {
        String id = "lock-" + System.nanoTime();
        String refusal = PackageQueue.takeForLocks(id, I18n.tr("server.um.packagesLock.1"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        try {
            JSONObject outcome = changeLocks(lock, onlyThis);
            // La traccia sulla macchina dice lo stato di adesso: se un amministratore sblocca
            // dal pannello, ne' la nota ne' l'annotazione devono continuare a dirlo bloccato.
            refreshLockTrace();
            return outcome;
        }
        finally { PackageQueue.release(id); }
    }

    private static JSONObject changeLocks(boolean lock, String onlyThis) {
        if (!onlyThis.isEmpty() && !isValidName(onlyThis)) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
        }
        StringBuilder log = new StringBuilder();
        int changedCount = 0;
        boolean found = false;
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            String name = p.getString("name");
            if (!onlyThis.isEmpty() && !onlyThis.equals(name)) continue;
            found = true;
            if (p.getBoolean("locked") == lock) {
                log.append("  ").append(name).append(": ").append(I18n.tr("server.um.x.lockAlready")).append("\n");
                continue;
            }
            boolean done = ok("pkg " + (lock ? "lock" : "unlock") + " -y " + name);
            log.append("  ").append(name).append(": ")
               .append(done ? (lock ? I18n.tr("server.um.x.lockDone") : I18n.tr("server.um.x.unlockDone")) : I18n.tr("server.um.x.lockFailed")).append("\n");
            if (done) { changedCount++; rememberUnlock(name, !lock); }
        }
        // Un pacchetto che non e' dello stack (una dipendenza vulnerabile, uno bloccato a mano):
        // la tabella pacchetti lo mostra con il suo pulsante, quindi si blocca o sblocca come gli altri.
        if (!onlyThis.isEmpty() && !found) {
            String[] iv = PackagePlan.installed().get(onlyThis);
            if (iv == null) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.ov.notInstalled", java.util.Map.of("name", onlyThis)));
            if ("1".equals(iv[1]) == lock) log.append("  ").append(onlyThis).append(": ").append(I18n.tr("server.um.x.lockAlready")).append("\n");
            else {
                boolean done = ok("pkg " + (lock ? "lock" : "unlock") + " -y " + onlyThis);
                log.append("  ").append(onlyThis).append(": ")
                   .append(done ? (lock ? I18n.tr("server.um.x.lockDone") : I18n.tr("server.um.x.unlockDone")) : I18n.tr("server.um.x.lockFailed")).append("\n");
                if (done) { changedCount++; rememberUnlock(onlyThis, !lock); }
            }
        }
        return new JSONObject().put("success", true).put("changed", changedCount).put("output", log.toString());
    }

    // ===================== la regola dei blocchi =====================

    /**
     * I pacchetti dello stack di posta restano bloccati: e' cosi' che un pkg upgrade, da qui o
     * da SSH, non li sostituisce senza i controlli dell'aggiornamento guidato. Fanno eccezione
     * solo quelli che un amministratore ha sbloccato con il pannello: quella scelta si ricorda
     * (impostazione pkg.unlocked_by_admin) e si rispetta.
     */
    static final String UNLOCKED_BY_HAND = "pkg.unlocked_by_admin";

    static Set<String> unlockedByHand() {
        Set<String> r = new TreeSet<>();
        if (org.mail_panel.Main.mailDatabase == null) return r;
        for (String n : org.mail_panel.Main.mailDatabase.getSetting(UNLOCKED_BY_HAND, "").split(","))
            if (isValidName(n.trim())) r.add(n.trim());
        return r;
    }

    /** Ricorda (o dimentica) che un amministratore ha sbloccato questo pacchetto apposta. */
    static synchronized void rememberUnlock(String name, boolean unlocked) {
        if (org.mail_panel.Main.mailDatabase == null) return;
        Set<String> r = unlockedByHand();
        if (unlocked) r.add(name); else r.remove(name);
        if (r.isEmpty()) org.mail_panel.Main.mailDatabase.deleteSetting(UNLOCKED_BY_HAND);
        else org.mail_panel.Main.mailDatabase.setSetting(UNLOCKED_BY_HAND, String.join(",", r));
    }

    /**
     * All'avvio: blocca ogni pacchetto dello stack installato e non bloccato, tranne quelli
     * sbloccati apposta da un amministratore. Non fa niente se c'e' lo stato di un lavoro
     * interrotto (prima va ripristinato quello) o se il database del pannello non risponde:
     * senza l'elenco degli sblocchi voluti bloccherebbe anche quelli.
     */
    public static String applyLockPolicy() {
        if (PackageQueue.statePresent() || org.mail_panel.Main.mailDatabase == null) return "";
        // Anche questa passa all'avvio di ogni processo: se un altro pannello sta lavorando sui
        // pacchetti, le protezioni che ha tolto sono sue (reperto 147). Per esempio la
        // reinstallazione completa dal menu, che li ha sbloccati apposta: bloccarli adesso le
        // fermerebbe pkg a meta' (reperto 154). Lo si dice nel log: tornando "" come quando non
        // c'e' niente da fare, chi legge il log del servizio non sapeva che la regola era saltata.
        String refusal = PackageQueue.takeForLocks("startup-lock-policy", I18n.tr("server.recovery.turnLockPolicy"));
        if (refusal != null) {
            String msg = "Package lock rule not applied at this start (it is applied at the next one): " + refusal;
            LOGGER.info(msg);
            return msg;
        }
        try {
            // Col turno in mano si riguarda: l'elenco di un lavoro puo' essere comparso fra il
            // primo sguardo e il turno, e allora prima va ripristinato quello.
            if (PackageQueue.statePresent()) return "";
            return applyLockPolicyOnTurn();
        }
        finally { PackageQueue.release("startup-lock-policy"); }
    }

    private static String applyLockPolicyOnTurn() {
        Set<String> unlockedByHand = unlockedByHand();
        List<String> lockedPackages = new ArrayList<>(), failed = new ArrayList<>();
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            String n = p.getString("name");
            if (p.getBoolean("locked") || unlockedByHand.contains(n) || !isValidName(n)) continue;
            if (ok("pkg lock -y " + n)) lockedPackages.add(n); else failed.add(n);
        }
        // La traccia si rimette in pari a ogni avvio, anche quando non c'era niente da bloccare:
        // dice lo stato di ADESSO, e una traccia che resta indietro e' peggio di nessuna traccia.
        // E' anche il punto che ripara cio' che e' rimasto indietro fuori dal pannello: lo
        // script che aggiorna Java riprotegge con pkg lock e poi riavvia il pannello.
        refreshLockTrace();
        if (lockedPackages.isEmpty() && failed.isEmpty()) return "";
        String msg = "Mail stack packages locked at startup: " + (lockedPackages.isEmpty() ? "none" : String.join(", ", lockedPackages))
                + (failed.isEmpty() ? "" : "; could not lock: " + String.join(", ", failed));
        LOGGER.info(msg);
        return msg;
    }

    // ===================== la traccia dei blocchi sulla macchina =====================

    /**
     * Dove il pannello spiega, sulla macchina, perche' quei pacchetti sono bloccati.
     *
     * Il blocco non scade e nessuno lo toglie allo spegnimento: e' la regola, ed e' giusta
     * finche' il pannello c'e'. Ma se il pannello viene disinstallato, o semplicemente non
     * riparte piu', quei pacchetti restano bloccati per sempre — e un pacchetto bloccato non
     * riceve nemmeno le correzioni di sicurezza.
     *
     * Chi se ne accorgerebbe? Misurato sulla VM FreeBSD 15.1 il 23/10/2026, con 40 pacchetti
     * bloccati: `pkg upgrade` nomina i bloccati in una riga di passaggio, non li mette nel
     * riepilogo e termina con uscita ZERO. Dal sistema non si capisce ne' chi li ha bloccati,
     * ne' perche', ne' come liberarli: `pkg lock -l` elenca i nomi e basta.
     *
     * Questo file e' la risposta a quelle tre domande, e sopravvive al pannello.
     */
    static final String LOCK_NOTE = "/var/db/mailpanel/locked-packages.txt";

    /** Dove sta la nota. E' una variabile solo perche' le prove non scrivano in /var/db. */
    static Path lockNotePath = Paths.get(LOCK_NOTE);

    /** Il comando che libera tutto, scritto in un punto solo perche' compare in piu' testi. */
    static final String UNLOCK_ALL_COMMAND = "pkg unlock -a -y";

    /**
     * Il testo della nota. Funzione pura: riceve l'elenco e il momento, cosi' si prova.
     *
     * I commenti in italiano come negli altri file che il pannello genera sulla macchina
     * (l'override del ramo di pkg, il filtro di fail2ban, la lista permaban): li legge chi
     * amministra il server, non il programma. La firma in inglese, come in tutti (PanelMarker).
     */
    static String lockNoteText(java.util.Collection<String> locked, String when) {
        StringBuilder sb = new StringBuilder();
        sb.append("# ").append(PanelMarker.WRITTEN).append(" on ").append(when).append(" (UTC).\n")
          .append("# Pacchetti bloccati dal pannello mail FreeBSD. NON modificare a mano:\n")
          .append("# viene riscritto a ogni avvio del pannello e a ogni cambio di protezione.\n")
          .append("#\n")
          .append("# PERCHE': i pacchetti dello stack di posta restano bloccati (pkg lock) perche' un\n")
          .append("# \"pkg upgrade\", da qui o da SSH, non li sostituisca senza i controlli\n")
          .append("# dell'aggiornamento guidato: la configurazione generata dal pannello puo' non\n")
          .append("# essere accettata dalla versione nuova, e il servizio si rifiuterebbe di partire.\n")
          .append("#\n")
          .append("# COME SI AGGIORNANO: dal pannello, pagina Aggiornamenti. Li' si vede, per ogni\n")
          .append("# pacchetto, se c'e' una versione nuova e se chiude una vulnerabilita'; il pannello\n")
          .append("# sblocca, aggiorna, riprotegge e riavvia i servizi.\n")
          .append("#\n")
          .append("# ATTENZIONE, se il pannello non c'e' piu' o non riparte: questi pacchetti restano\n")
          .append("# bloccati, cioe' NON riceveranno piu' nemmeno le correzioni di sicurezza, e\n")
          .append("# \"pkg upgrade\" li salta uscendo con codice 0, come se non ci fosse niente da fare.\n")
          .append("# Per liberarli tutti:\n")
          .append("#\n")
          .append("#     ").append(UNLOCK_ALL_COMMAND).append("\n")
          .append("#\n")
          .append("# Uno solo:  pkg unlock -y <nome>\n")
          .append("# Lo stato vero lo dice sempre: pkg lock -l\n")
          .append("\n");
        if (locked.isEmpty()) sb.append("# (nessun pacchetto bloccato)\n");
        for (String n : locked) sb.append(n).append('\n');
        return sb.toString();
    }

    /**
     * Scrive la nota con i pacchetti bloccati ADESSO. Se non ce n'e' nessuno, la cancella:
     * una nota che elenca blocchi che non esistono piu' manderebbe a cercare un problema
     * che non c'e'.
     */
    static synchronized void writeLockNote() {
        try {
            Set<String> locked = new TreeSet<>();
            for (String n : lockedNames()) if (roleOf(n) != null) locked.add(n);
            Path f = lockNotePath;
            if (locked.isEmpty()) { Files.deleteIfExists(f); return; }
            if (f.getParent() != null) Files.createDirectories(f.getParent());
            String when = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
            // Scrittura atomica: un file letto a meta' da chi indaga su un server fermo
            // sarebbe un modo di sbagliare proprio nel momento peggiore.
            Path tmp = f.resolveSibling(f.getFileName() + ".tmp");
            Files.writeString(tmp, lockNoteText(locked, when), StandardCharsets.UTF_8);
            Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            // La nota e' una spiegazione, non un meccanismo: se non si scrive, il pannello
            // funziona comunque. Ma lo si dice, perche' senza di lei la macchina non spiega
            // piu' i propri blocchi.
            LOGGER.log(Level.WARNING, "Cannot write " + lockNotePath, e);
        }
    }

    /**
     * L'avviso sui pacchetti che resterebbero bloccati senza il pannello, o "" se non ce
     * n'e' nessuno.
     *
     * Serve dove qualcuno sta togliendo il pannello di mezzo: e' l'unico momento in cui la
     * domanda "e i blocchi?" si pone da se', ed e' il momento in cui nessuno la faceva.
     */
    static String locksStayWarning() {
        Set<String> locked = new TreeSet<>();
        for (String n : lockedNames()) if (roleOf(n) != null) locked.add(n);
        if (locked.isEmpty()) return "";
        return I18n.tr("server.um.x.locksStayWarning", java.util.Map.of(
                "n", String.valueOf(locked.size()), "cmd", UNLOCK_ALL_COMMAND, "file", LOCK_NOTE));
    }

    /**
     * La traccia dei blocchi rimessa in pari con la macchina: la nota e le annotazioni.
     *
     * Si chiama dove le protezioni possono essere cambiate: all'avvio, dal pulsante delle
     * protezioni e alla fine di ogni lavoro sul turno dei pacchetti (withLockTrace). Non
     * lancia mai: la traccia e' una spiegazione, non un meccanismo, e un suo guasto non deve
     * far fallire il lavoro che l'ha chiamata.
     */
    static void refreshLockTrace() {
        writeLockNote();
        try {
            int[] done = syncLockMarks();
            if (done[0] + done[1] + done[2] > 0)
                LOGGER.info("Lock marks: " + done[0] + " added, " + done[1] + " removed, " + done[2] + " rewritten");
        } catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Cannot update the lock marks", e);
        }
    }

    /**
     * Il lavoro sul turno dei pacchetti, con la traccia dei blocchi rimessa in pari quando
     * finisce, anche con un errore. Avvolge TUTTI i lavori del turno, quindi un lavoro nuovo
     * che riprotegge non deve ricordarsene.
     */
    static Runnable withLockTrace(Runnable work) {
        return () -> {
            try { work.run(); }
            finally { refreshLockTrace(); }
        };
    }

    /**
     * Il lavoro sul turno dei pacchetti, con la proprieta' dei file della webmail riaffermata
     * quando finisce: il post-install di roundcube-php84 fa "chown www:www" di logs e temp a ogni
     * installazione e aggiornamento (misurato sulla VM FreeBSD 15.1 il 31/10/2026), e il PHP di
     * Roundcube, che gira come roundcube, non potrebbe piu' scriverci. Avvolge tutti i lavori del
     * turno, come withLockTrace: anche quelli che aggiornano Roundcube senza dirlo.
     */
    static Runnable withWebmailOwnership(Runnable work) {
        return () -> {
            try { work.run(); }
            finally {
                try {
                    java.util.List<String> changed = RoundcubeUser.repairOwnership();
                    if (!changed.isEmpty()) LOGGER.info("Webmail files given back to " + RoundcubeUser.USER + ": " + changed);
                } catch (RuntimeException e) {
                    LOGGER.log(Level.WARNING, "Cannot give the webmail files back to " + RoundcubeUser.USER, e);
                }
            }
        };
    }

    /**
     * Mette l'annotazione su ogni pacchetto bloccato dal pannello che non ce l'ha, e la toglie
     * da quelli che non lo sono piu'. Restituisce {aggiunte, tolte}.
     *
     * L'annotazione e' il cartello nel punto in cui qualcuno si fa la domanda: chi vede
     * "nginx-1.30.6,3 is locked and may not be modified" e indaga con `pkg info -A nginx`
     * trova la riga, e la riga rimanda alla nota.
     *
     * Prima si annotava solo il pacchetto appena bloccato all'avvio. Misurato sulla VM
     * FreeBSD 15.1 il 24/10/2026: reinstallare un pacchetto — quindi anche aggiornarlo —
     * cancella le sue annotazioni, e nessuna riprotezione le riscriveva. Su 39 pacchetti
     * protetti dal pannello l'annotazione stava su uno, redis: il cartello spariva proprio dai
     * pacchetti che il pannello aveva aggiornato.
     *
     * Costa due letture (pkg lock -l, pkg query) e un comando per ogni cartello da cambiare,
     * quindi a regime nessuno. Se una delle due letture fallisce non si tocca niente: con
     * l'elenco dei blocchi vuoto per un errore, i cartelli si toglierebbero da tutti.
     */
    static int[] syncLockMarks() {
        Shell.Result lock = Shell.runShell(Duration.ofSeconds(30), "pkg lock -l");
        Shell.Result annotations = Shell.runShell(Duration.ofSeconds(60), "pkg query -a '%n %At %Av'");
        if (!lock.success() || !annotations.success()) {
            LOGGER.warning("Lock marks not updated: cannot read the locks or the annotations");
            return new int[]{0, 0, 0};
        }
        Set<String> locked = new TreeSet<>();
        for (String n : lockedNames(lock.outputTrim())) if (roleOf(n) != null) locked.add(n);
        String out = annotations.outputTrim();
        int added = 0, removed = 0, rewritten = 0;
        for (String cmd : lockMarkCommands(locked, markedIn(out), staleMarksIn(out))) {
            if (!ok(cmd, 20)) continue;
            if (cmd.contains(" -A ")) added++; else if (cmd.contains(" -M ")) rewritten++; else removed++;
        }
        return new int[]{added, removed, rewritten};
    }

    /**
     * I pacchetti che portano l'annotazione del pannello, da un'uscita di
     * `pkg query -a '%n %At %Av'` (o '%n %At'): una riga per annotazione, "nome chiave valore".
     * Funzione pura.
     */
    static Set<String> markedIn(String output) {
        Set<String> r = new TreeSet<>();
        for (String line : output.split("\n")) {
            String[] c = line.trim().split(" ", 3);
            if (c.length >= 2 && MARK_KEY.equals(c[1]) && isValidName(c[0])) r.add(c[0]);
        }
        return r;
    }

    /**
     * Quelli il cui cartello non dice piu' quello che il pannello scrive adesso: il testo di
     * prima, in italiano, sui server installati prima della fine di ottobre 2026. Il cartello e'
     * solo una spiegazione per chi lo legge con pkg info -A, quindi non serve riconoscerlo: basta
     * che non sia quello di adesso. Funzione pura, sull'uscita di `pkg query -a '%n %At %Av'`.
     */
    static Set<String> staleMarksIn(String output) {
        Set<String> r = new TreeSet<>();
        for (String line : output.split("\n")) {
            String[] c = line.trim().split(" ", 3);
            if (c.length >= 2 && MARK_KEY.equals(c[1]) && isValidName(c[0])
                    && !(c.length == 3 && MARK_VALUE.equals(c[2]))) r.add(c[0]);
        }
        return r;
    }

    /**
     * I comandi che portano i cartelli dallo stato annotati a quello bloccati: aggiungere
     * dove manca, togliere dove il blocco non c'e' piu'. Funzione pura, quindi si prova.
     *
     * La regola e' la stessa della nota (lo stack di posta, bloccato adesso): le due tracce
     * devono dire la stessa cosa.
     */
    static java.util.List<String> lockMarkCommands(Set<String> locked, Set<String> marked) {
        return lockMarkCommands(locked, marked, Set.of());
    }

    /** Come sopra, e in piu' riscrive i cartelli rimasti col testo di prima sui pacchetti ancora bloccati. */
    static java.util.List<String> lockMarkCommands(Set<String> locked, Set<String> marked, Set<String> stale) {
        java.util.List<String> r = new ArrayList<>();
        for (String n : new TreeSet<>(stale)) {
            if (!locked.contains(n) || !marked.contains(n)) continue;
            String cmd = rewriteMarkCommand(n);
            if (cmd != null) r.add(cmd);
        }
        for (String n : new TreeSet<>(locked)) {
            if (marked.contains(n)) continue;
            String cmd = markCommand(n);
            if (cmd != null) r.add(cmd);
        }
        for (String n : new TreeSet<>(marked)) {
            if (locked.contains(n)) continue;
            String cmd = removeMarkCommand(n);
            if (cmd != null) r.add(cmd);
        }
        return r;
    }

    /** Il comando che toglie l'annotazione, o null se il nome non passa il filtro. */
    static String removeMarkCommand(String name) {
        if (!isValidName(name)) return null;
        return "pkg annotate -y -D " + name + " " + MARK_KEY;
    }

    /** La chiave dell'annotazione nel database di pkg. */
    static final String MARK_KEY = "mail_panel_lock";

    /** Il valore: rimanda alla nota e al comando che libera tutto. */
    static final String MARK_VALUE = "locked by the mail panel: see " + LOCK_NOTE
            + " - unlock with " + UNLOCK_ALL_COMMAND;

    /**
     * Il comando che scrive l'annotazione, o null se il nome non passa il filtro.
     *
     * Sta in una funzione sua perche' il valore contiene spazi, un percorso e un trattino
     * lungo: e' una riga di comando, e una riga di comando si prova eseguendola, non
     * leggendola. In questo progetto un apice dentro un testo e' gia' passato intatto
     * attraverso un here-document per rompere piu' in la'.
     */
    static String markCommand(String name) {
        if (!isValidName(name)) return null;
        return "pkg annotate -y -A " + name + " " + MARK_KEY + " '" + MARK_VALUE + "'";
    }

    /** Il comando che riscrive il valore di un cartello che c'e' gia', o null se il nome non passa il filtro. */
    static String rewriteMarkCommand(String name) {
        if (!isValidName(name)) return null;
        return "pkg annotate -y -M " + name + " " + MARK_KEY + " '" + MARK_VALUE + "'";
    }

    // ===================== il quadro dei pacchetti =====================

    /**
     * Il quadro unico dei pacchetti per la pagina Aggiornamenti: per ognuno versione
     * installata e del catalogo, blocco, vulnerabilita' con il verdetto sulla correzione, e se
     * si puo' aggiornare da qui. Sola lettura e senza rete. Dentro: i pacchetti dello stack di
     * posta, piu' ogni altro pacchetto vulnerabile o bloccato; gli altri con un aggiornamento
     * (librerie, dipendenze) solo elencati a parte.
     */
    public static JSONObject packagesOverview() {
        JSONObject r = new JSONObject();
        Map<String, String[]> inst = PackagePlan.installed();
        if (inst.isEmpty()) return r.put("success", false).put("error", I18n.tr("server.um.ov.noPkgDb"));
        Shell.Result ev = PackagePlan.readToUpdate();
        Map<String, String> update = PackagePlan.toUpdate(ev.output());
        if (ev.exitCode() != 0 && update.isEmpty())
            r.put("catalogError", "pkg version -U -vRL= (" + ev.exitCode() + ")" + (ev.output().isBlank() ? "" : ": " + ev.output().trim()));
        JSONObject fixes = PackagePlan.fixes();
        JSONObject vuln = fixes.optBoolean("success") ? fixes.getJSONObject("packages") : new JSONObject();
        if (!fixes.optBoolean("success")) r.put("vulnError", fixes.optString("error"));

        String jvm = jvmPackage();
        java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<>();
        for (Map.Entry<String, String[]> e : inst.entrySet())
            if (roleOf(e.getKey()) != null) names.add(e.getKey());
        for (Map.Entry<String, String[]> e : inst.entrySet())
            if (vuln.has(e.getKey()) || "1".equals(e.getValue()[1])) names.add(e.getKey());

        JSONArray rows = new JSONArray();
        int updatable = 0, vulnerable = 0, resolvable = 0, lockedPackages = 0, unlockedStack = 0;
        boolean panelRestart = false;
        for (String n : names) {
            String[] iv = inst.get(n);
            String role = roleOf(n);
            boolean locked = "1".equals(iv[1]);
            String available = update.getOrDefault(n, "");
            JSONObject row = new JSONObject().put("name", n).put("installed", iv[0]).put("available", available)
                    .put("update", !available.isEmpty()).put("locked", locked).put("stack", role != null)
                    .put("role", role == null ? "" : role);
            if (locked) lockedPackages++;
            if (role != null && !locked) unlockedStack++;
            String why = "";
            boolean eJvm = n.equals(jvm);
            if (!available.isEmpty()) {
                updatable++;
                boolean jump = significantJump(n, iv[0], available);
                row.put("majorJump", jump);
                JSONObject ad = warningFor(n, jump);
                if (ad != null) {
                    row.put("advisory", ad);
                    if ("wait".equals(ad.optString("level"))) why = ad.optString("text");
                }
            }
            if (eJvm) {
                row.put("panelRuntime", true).put("inUse", I18n.tr("server.um.ov.panelRuns"));
                // Il JDK del pannello ha la sua procedura: ferma il pannello, aggiorna, riaccende.
                if (!available.isEmpty()) { why = I18n.tr("server.um.ov.javaFlow"); row.put("javaFlow", true); }
                String inUse = System.getProperty("java.version", "");
                String pkgName = iv[0].replaceAll("[+_].*$", "");
                if (!inUse.isEmpty() && !pkgName.isEmpty() && !pkgName.equals(inUse)) {
                    panelRestart = true;
                    row.put("panelRestart", I18n.tr("server.um.ov.panelRestart", java.util.Map.of("running", inUse, "installed", iv[0])));
                }
            }
            row.put("canUpdate", !available.isEmpty() && why.isEmpty()).put("whyNot", why);
            JSONObject v = vuln.optJSONObject(n);
            if (v != null) {
                vulnerable++;
                if ("fixed-by-upgrade".equals(v.optString("verdict"))) resolvable++;
                row.put("vuln", v);
            }
            rows.put(row);
        }
        JSONArray others = new JSONArray();
        for (Map.Entry<String, String> e : update.entrySet()) {
            if (names.contains(e.getKey()) || !inst.containsKey(e.getKey())) continue;
            others.put(new JSONObject().put("name", e.getKey()).put("installed", inst.get(e.getKey())[0]).put("available", e.getValue()));
        }
        return r.put("success", true).put("packages", rows).put("others", others)
                .put("summary", new JSONObject().put("updates", updatable + others.length()).put("stackUpdates", updatable)
                        .put("vulnerable", vulnerable).put("fixable", resolvable).put("locked", lockedPackages)
                        .put("stackUnlocked", unlockedStack).put("panelRestart", panelRestart));
    }

    // ===================== avvertenze specifiche dello stack di posta =====================

    /**
     * Colonne: espressione del nome, livello su salto di versione maggiore, testo.
     *
     * Il livello "attendi" non e' decorativo: la manutenzione automatica NON sblocca i
     * pacchetti che lo portano. Un'avvertenza che si limita a comparire mentre il bottone
     * accanto aggiorna lo stesso non e' un'avvertenza.
     */
    private static final String[][] WARNINGS = {
        {"^dovecot.*", "wait",
         "server.um.changeLocks.2"},
        {"^roundcube.*", "wait",
         "server.um.changeLocks.3"},
        {"^php[0-9]+.*", "wait",
         "server.um.changeLocks.4"},
        {"^mysql[0-9]+-server$", "wait",
         "server.um.changeLocks.5"},
        {"^mysql[0-9]+-client$", "wait",
         "server.um.changeLocks.6"},
        {"^postfix.*", "review",
         "server.um.changeLocks.7"},
        {"^rspamd$", "review",
         "server.um.changeLocks.8"},
        {"^redis.*", "review",
         "server.um.changeLocks.9"},
        {"^clamav.*", "review",
         "server.um.changeLocks.10"},
        {"^nginx.*", "review",
         "server.um.changeLocks.11"},
        {"^py[0-9]+-fail2ban$", "review",
         "server.um.changeLocks.12"},
        {"^(py[0-9]+-)?certbot$", "review",
         "server.um.changeLocks.13"},
        {"^unbound$", "review",
         "server.um.changeLocks.14"},
        {"^openjdk[0-9]*$", "wait",
         "server.um.changeLocks.15"},
        {"^openssl[0-9]*$", "review",
         "server.um.changeLocks.16"},
    };

    /**
     * Quante cifre della versione delimitano una rottura, per pacchetto.
     *
     * Guardare solo la prima cifra e' l'errore che rende inutile tutto il resto: Dovecot
     * 2.3 -> 2.4 riscrive il formato della configurazione e PHP 8.4 -> 8.5 cambia percorsi
     * e socket, ma per entrambi la prima cifra non si muove. Trattarli da "aggiornamenti
     * minori normalmente sicuri" sarebbe falso proprio sui due casi piu' pericolosi.
     */
    private static final String[][] VERSION_DEPTH = {
        {"^dovecot.*",           "2"},   // 2.3 -> 2.4: configurazione incompatibile
        {"^php[0-9]+.*",         "2"},   // 8.4 -> 8.5: percorsi, socket, nome dei pacchetti
        {"^mysql[0-9]+-.*",      "2"},   // 8.0 -> 8.4: data dictionary, opzioni rimosse
        {"^roundcube.*",         "2"},   // 1.5 -> 1.6: schema del database
        {"^rspamd$",             "2"},   // le minori cambiano opzioni e chiavi in Redis
        {"^postfix.*",           "2"},   // 3.10 -> 3.11 cambia i predefiniti del compatibility_level
    };

    /** Confronta le prime N cifre di due versioni: true se sono cambiate. */
    static boolean significantJump(String name, String from, String to) {
        int digits = 1;
        for (String[] r : VERSION_DEPTH) if (name.matches(r[0])) { digits = Integer.parseInt(r[1]); break; }
        return !versionPrefix(from, digits).equals(versionPrefix(to, digits));
    }

    /** Le prime n componenti numeriche di una versione, es. ("2.3.21", 2) -> "2.3". */
    static String versionPrefix(String v, int n) {
        if (v == null) return "";
        String[] parts = v.split("[._,+~]");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n && i < parts.length; i++) {
            if (i > 0) sb.append('.');
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    /**
     * Pacchetti il cui rischio NON dipende dal numero di versione, e per cui quindi
     * l'avvertenza vale sempre, anche su un aggiornamento di sole cifre finali.
     *
     * Il caso e' openjdk: il problema non e' cosa cambia fra due versioni, e' che il pannello
     * ci sta girando sopra. Appena i file della JVM vengono sostituiti, il processo in memoria
     * non riesce piu' ad avviare comandi: il job che sta facendo l'aggiornamento non puo'
     * nemmeno ribloccare il pacchetto e si ferma a meta', lasciando tutto scoperto.
     * Trattarlo con la regola generale "i salti minori sono sicuri" significa annullare la
     * protezione proprio nel caso per cui e' stata scritta.
     */
    private static final String[] ALWAYS_WAIT = { "^openjdk[0-9]*$" };

    private static boolean versionIndependentRisk(String name) {
        for (String r : ALWAYS_WAIT) if (name.matches(r)) return true;
        return false;
    }

    /** Avvertenza per un pacchetto, o null se non ne ha una specifica. */
    private static JSONObject warningFor(String name, boolean majorJump) {
        for (String[] a : WARNINGS) {
            if (!name.matches(a[0])) continue;
            if (!majorJump && "wait".equals(a[1]) && !versionIndependentRisk(name)) {
                return new JSONObject().put("level", "ok").put("text",
                        I18n.tr("server.um.warningFor.1"));
            }
            // Un'avvertenza scritta per il caso peggiore, mostrata su un aggiornamento di
            // sole cifre finali, dice il falso: parla di "cambio maggiore" quando il salto
            // non c'e'. Chi legge o si allarma per niente, o smette di fidarsi del testo.
            String text = majorJump ? I18n.tr(a[2])
                    : I18n.tr("server.um.warningFor.2", java.util.Map.of("p", I18n.tr(a[2])));
            return new JSONObject().put("level", a[1]).put("text", text);
        }
        if (majorJump) {
            return new JSONObject().put("level", "review").put("text",
                    I18n.tr("server.um.warningFor.3"));
        }
        return null;
    }

    /**
     * Versioni disponibili per i pacchetti BLOCCATI. Serve un comando diverso da
     * `pkg upgrade -n`: quello i bloccati li salta e non dice a che versione andrebbero,
     * quindi da solo lascerebbe credere che non abbiano aggiornamenti.
     */
    public static JSONArray lockedUpdates() {
        String v = sh("pkg version -U -vRL= 2>/dev/null", 60);
        String lock = sh("pkg lock -l 2>/dev/null");
        JSONArray arr = new JSONArray();
        Pattern p = Pattern.compile("^(\\S+)-([^\\s-]+)\\s+<\\s+.*\\(.*has ([^)]+)\\)");
        for (String line : v.split("\n")) {
            Matcher m = p.matcher(line.trim());
            if (!m.find()) continue;
            String name = m.group(1), current = m.group(2), available = m.group(3);
            if (roleOf(name) == null) continue;
            if (!locked(lock, name)) continue;
            boolean major = significantJump(name, current, available);
            JSONObject row = new JSONObject().put("name", name).put("current", current)
                    .put("available", available).put("majorJump", major)
                    .put("role", roleOf(name));
            JSONObject a = warningFor(name, major);
            if (a != null) row.put("advisory", a);
            arr.put(row);
        }
        return arr;
    }

    /**
     * Stato aggiornamenti e vulnerabilita'. Tutto in sola lettura: `pkg upgrade -n` e'
     * una simulazione e `pkg audit` interroga soltanto il database delle vulnerabilita'.
     */
    public static JSONObject updatesStatus() {
        JSONObject r = new JSONObject();
        ok("pkg update -q", 120);

        // La simulazione va letta INTERA. Le righe "is locked" dei pacchetti protetti ne
        // occupano decine, e un taglio anticipato cadrebbe in mezzo all'elenco facendo
        // risultare "senza aggiornamenti" pacchetti che invece ne hanno. Si taglia solo
        // cio' che si mostra a video, mai cio' che si analizza.
        // Il piano dell'aggiornamento dei NON protetti, con la sua firma. Prima qui c'era un
        // "pkg upgrade -n" grezzo e il testo finiva in pagina cosi' com'era: chi premeva
        // "Aggiorna non protetti" approvava un testo, non un piano, e niente legava quel
        // testo a cio' che sarebbe stato eseguito. Era l'unico dei tre lavori sui pacchetti
        // senza piano ne' firma — e l'unico che non confrontava niente alla fine.
        //
        // Nessuno sblocco: e' il senso di questo aggiornamento, quindi la regola rifiuta
        // sempre, e i protetti restano nel piano con il loro motivo (pkg li salta). E nessun
        // gemello di famiglia da sbloccare, per la stessa ragione: qui non si sblocca niente.
        JSONObject unprotectedPlan = judged(PackagePlan.fullPlan(java.util.Set.of(), lockedNames(),
                b -> I18n.tr("server.um.x.staysLockedHere")));
        String blocked = destructivePlanReason(unprotectedPlan);
        r.put("plan", planForCard(unprotectedPlan))
         .put("signature", unprotectedPlan.optString("signature"))
         .put("blockedReason", blocked == null ? "" : blocked);
        String fullSimulation = unprotectedPlan.optString("output");
        StringBuilder shown = new StringBuilder();
        int omitted = 0;
        for (String l : fullSimulation.split("\n")) {
            if (l.contains("is locked and may not be modified") || l.startsWith("Checking for upgrades")) { omitted++; continue; }
            shown.append(l).append("\n");
        }
        r.put("dryRun", shown.toString().trim()
                + (omitted > 0 ? I18n.tr("server.um.updatesStatus.1", java.util.Map.of("omitted", String.valueOf(omitted))) : ""));
        r.put("upToDate", fullSimulation.contains("Your packages are up to date"));

        // Quali pacchetti DELLA POSTA verrebbero toccati, e se sono protetti.
        JSONArray involved = new JSONArray();
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            if (fullSimulation.contains(p.getString("name") + ":")) {
                involved.put(new JSONObject().put("name", p.getString("name"))
                        .put("role", p.getString("role")).put("locked", p.getBoolean("locked")));
            }
        }
        r.put("affectedMailPackages", involved);
        r.put("lockedUpdates", lockedUpdates());

        // --- Vulnerabilita' note ---
        String audit = sh("pkg audit -F 2>&1", 180);
        r.put("audit", audit.length() > 4000 ? audit.substring(audit.length() - 4000) : audit);

        // Incrocio vulnerabilita' <-> protezione. E' il punto: un pacchetto bloccato NON
        // riceve le correzioni di sicurezza. Il lock protegge da cambiamenti inattesi, non
        // e' uno stato in cui restare per sempre, e chi lo mette deve poterlo vedere.
        JSONArray vulnerable = new JSONArray();
        String lock = sh("pkg lock -l 2>/dev/null");

        // Quali pacchetti hanno una versione piu' recente nel catalogo, PROTETTI COMPRESI.
        //
        // Serve perche' "pkg upgrade -n" i protetti li salta: dalla simulazione non si puo'
        // sapere se per un pacchetto protetto esista una correzione. "pkg version" invece
        // confronta le versioni e del lock non si occupa, quindi risponde anche per quelli.
        Set<String> updatable = new java.util.LinkedHashSet<>();
        for (String line : sh("pkg version -U -vRL= 2>/dev/null", 60).split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            // "nome-1.2.3    <   needs updating (index has 1.2.4)"
            //
            // Solo "<" vuol dire che esiste una versione piu' recente. ">" (installato piu'
            // nuovo del catalogo), "?" (non nel catalogo) e "!" (confronto fallito) sono
            // differenze, non aggiornamenti: prenderle per tali direbbe a chi legge che per
            // un pacchetto vulnerabile esiste una correzione che non esiste.
            String[] fields = t.split("\\s+");
            if (fields.length < 2 || !"<".equals(fields[1])) continue;
            String pv = fields[0];
            int dash = pv.lastIndexOf('-');
            if (dash > 0) updatable.add(pv.substring(0, dash));
        }
        Matcher m = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        Set<String> seen = new java.util.LinkedHashSet<>();
        while (m.find()) seen.add(m.group(1));
        for (String name : seen) {
            boolean lk = locked(lock, name);
            String role = roleOf(name);
            // Esiste una versione piu' recente? E' una domanda diversa da "l'aggiornamento
            // la applicherebbe", e va tenuta separata: per un pacchetto protetto la seconda
            // e' sempre no, ma la prima puo' essere si'.
            boolean hasUpdate = updatable.contains(name);
            JSONObject v = new JSONObject().put("name", name).put("locked", lk)
                    .put("mailPackage", role != null).put("role", role == null ? "" : role)
                    .put("updateAvailable", hasUpdate)
                    // Prima qui c'era "!lk && simulazione.contains(nome)", e per un pacchetto
                    // protetto veniva sempre falso — mentre la scheda scriveva "protetto,
                    // quindi NON riceve la correzione", cioe' affermava che una correzione
                    // esistesse. Nessuno l'aveva verificato: la simulazione i protetti li
                    // salta, quindi da li' quell'informazione non si ricava proprio.
                    .put("fixedByUpgrade", !lk && (hasUpdate
                            || fullSimulation.contains(name + ":")));
            // Il dettaglio serve per decidere: "ha una vulnerabilita'" non dice se e' una
            // esecuzione di codice da remoto o un rifiuto di servizio che non ti riguarda.
            JSONObject d = vulnerabilityDetail(audit, name);
            v.put("cve", d.getJSONArray("cve"));
            v.put("description", d.getString("description"));
            v.put("references", d.getJSONArray("references"));
            vulnerable.put(v);
        }
        // "C'e' una versione piu' recente" non risponde a "la correzione c'e'?": la versione
        // piu' recente puo' essere ancora vulnerabile, e la correzione puo' esistere in una
        // versione che il tuo catalogo non ha. Lo dicono gli intervalli di VuXML.
        if (vulnerable.length() > 0) {
            JSONObject fixes = PackagePlan.fixes();
            if (fixes.optBoolean("success")) {
                JSONObject per = fixes.getJSONObject("packages");
                for (int i = 0; i < vulnerable.length(); i++) {
                    JSONObject v = vulnerable.getJSONObject(i);
                    if (per.has(v.getString("name"))) v.put("fix", per.getJSONObject(v.getString("name")));
                }
            } else {
                r.put("fixesError", fixes.optString("error"));
            }
        }
        r.put("vulnerable", vulnerable);
        // Lezione pagata sull'altro server il 30/08: mysql80-server era stato aggiornato a
        // 8.0.46 ma il processo continuava a girare sui binari 8.0.45, quindi la correzione
        // non era in servizio pur risultando installata. Vale per ogni libreria condivisa.
        r.put("restartNote",
            I18n.tr("server.um.updatesStatus.2"));

        // --- Sistema base: kernel e userland a confronto. Se differiscono manca un riavvio. ---
        String k = sh("freebsd-version -k", 15), run = sh("freebsd-version -r", 15), u = sh("freebsd-version -u", 15);
        r.put("kernel", k).put("running", run).put("userland", u);
        r.put("rebootPending", !k.isEmpty() && !run.isEmpty() && !k.equals(run));

        r.put("success", true);
        return r;
    }

    /**
     * Estrae dal referto di `pkg audit` il blocco che riguarda un pacchetto: descrizione,
     * identificativi CVE e riferimenti. Senza questo il pannello direbbe soltanto "e'
     * vulnerabile", che non basta per decidere se valga la pena sbloccare e aggiornare.
     */
    /** La riga con cui pkg audit chiude il referto. E' la prova che il controllo e' avvenuto. */
    private static final Pattern FULL_AUDIT = Pattern.compile(
            "(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found");

    /**
     * Il referto di pkg audit per UNA versione precisa di un pacchetto.
     *
     * Due trappole, misurate sulla VM FreeBSD 15.1 il 23/10/2026, che insieme rendevano
     * questo controllo incapace di dire qualunque cosa.
     *
     * 1. `pkg audit nome`, col solo nome, non risponde "la versione installata e'
     *    vulnerabile?" ma "VuXML ha voci per questo nome?". Su nginx 1.30.6,3, appena
     *    aggiornato e non vulnerabile, rispondeva "nginx is vulnerable" con 25 problemi,
     *    elencando intervalli come "< 1.8.1_3,2" che non c'entrano niente; `pkg audit` senza
     *    argomenti, che guarda le versioni installate, nello stesso momento non lo nominava
     *    affatto. E l'intestazione di quel referto e' "nginx is vulnerable:", SENZA la
     *    versione, quindi vulnerabilityDetail — che cerca "nome-versione is vulnerable:"
     *    — non entrava mai nel blocco: zero CVE sempre, in entrambe le direzioni.
     *    Su php84 8.4.26, vulnerabile per davvero, il referto del pannello era "[ok] Nessuna
     *    vulnerabilita' nota registrata per questo pacchetto", mentre pkg diceva
     *    "php84 is vulnerable" e PackagePlan.fixes, che la domanda la pone giusta,
     *    trovava la fix nella 8.4.27.
     *    La forma che risponde alla domanda giusta e' `pkg audit nome-versione`: con
     *    "nginx-1.30.6,3" dice "0 problem(s)", con "php84-8.4.26" trova l'unico problema vero.
     *
     * 2. Se il database delle vulnerabilita' non c'e', pkg risponde "vulnxml file vuln.xml
     *    does not exist" e chi cerca solo le righe "is vulnerable" conclude "nessuna
     *    vulnerabilita'". E' il caso peggiore: una rassicurazione al posto di un "non ho
     *    potuto controllare". Il codice di uscita non aiuta a distinguere — misurato: 1
     *    senza il database, 0 sia con problemi trovati sia senza. Quello che distingue un
     *    referto fatto da uno non fatto e' la riga finale "N problem(s) in M package(s)
     *    found.", e quella si pretende.
     *
     * Il conto che si mostra e' quello della riga finale, non il numero di CVE: una voce di
     * VuXML puo' non avere nessun identificativo CVE, e contare i CVE la perderebbe.
     */
    static JSONObject auditReport(String name, String version) {
        JSONObject r = emptyAuditReport(name, version);
        if (!isValidName(name) || !PackagePlan.validVersion(version))
            return r.put("done", false).put("problems", 0)
                    .put("error", I18n.tr("server.um.x.auditNoVersion"));
        return readAuditReport(sh("pkg audit '" + name + "-" + version + "' 2>&1", 120), name, r);
    }

    /** La lettura del referto, separata dal comando: funzione pura, si prova con uscite vere. */
    static JSONObject readAuditReport(String out, String name, JSONObject r) {
        Matcher m = FULL_AUDIT.matcher(out == null ? "" : out);
        if (!m.find())
            return r.put("done", false).put("problems", 0)
                    .put("error", I18n.tr("server.um.x.auditNotDone", java.util.Map.of("out", String.valueOf(summarizeOutput(out)))));
        JSONObject detail = vulnerabilityDetail(out, name);
        int problems;
        try { problems = Integer.parseInt(m.group(1)); } catch (NumberFormatException e) { problems = 0; }
        return r.put("done", true).put("problems", problems)
                .put("cve", detail.getJSONArray("cve")).put("description", detail.getString("description"))
                .put("references", detail.getJSONArray("references"));
    }

    /** Un referto vuoto da riempire, per chi legge un'uscita gia' in mano. */
    static JSONObject emptyAuditReport(String name, String version) {
        return new JSONObject().put("name", name == null ? "" : name)
                .put("version", version == null ? "" : version)
                .put("cve", new JSONArray()).put("references", new JSONArray()).put("description", "");
    }

    static JSONObject vulnerabilityDetail(String audit, String pkgName) {
        JSONArray cve = new JSONArray();
        JSONArray references = new JSONArray();
        StringBuilder description = new StringBuilder();
        boolean inside = false;
        java.util.LinkedHashSet<String> seenCves = new java.util.LinkedHashSet<>();
        for (String line : audit.split("\n")) {
            String t = line.trim();
            // Inizio del blocco: "<nome>-<versione> is vulnerable:"
            if (t.matches("^" + java.util.regex.Pattern.quote(pkgName) + "-[0-9]\\S* is vulnerable:.*")) {
                inside = true;
                continue;
            }
            if (!inside) continue;
            // Il blocco finisce quando ne inizia un altro o alla prima riga vuota dopo il testo.
            if (t.endsWith("is vulnerable:") || (t.isEmpty() && description.length() > 0)) break;
            if (t.startsWith("CVE:")) {
                for (String c : t.substring(4).trim().split("[\\s,]+")) {
                    if (c.matches("CVE-[0-9]{4}-[0-9]+")) seenCves.add(c);
                }
            } else if (t.startsWith("WWW:")) {
                String u = t.substring(4).trim();
                if (u.startsWith("https://") || u.startsWith("http://")) references.put(u);
            } else if (!t.isEmpty()) {
                if (description.length() > 0) description.append(' ');
                description.append(t);
            }
        }
        for (String c : seenCves) cve.put(c);
        String desc = description.toString();
        if (desc.length() > 600) desc = desc.substring(0, 600) + "...";
        return new JSONObject().put("cve", cve).put("references", references).put("description", desc);
    }

    public static JSONObject maintenancePreview() {
        ok("pkg update -q", 120);
        JSONArray arr = lockedUpdates();
        int majors = 0, expectedOnes = 0;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            if (o.getBoolean("majorJump")) majors++;
            if (o.has("advisory") && "wait".equals(o.getJSONObject("advisory").getString("level"))) expectedOnes++;
        }
        // Il piano esatto dell'intera manutenzione, calcolato su una copia del database di pkg
        // con gli stessi sblocchi che fara' il lavoro vero. La tabella qui sopra dice i pacchetti
        // protetti; questo dice TUTTO cio' che cambiera', dipendenze comprese.
        JSONObject plan = judged(maintenancePlan(arr).getJSONObject("plan"));
        String blocked = destructivePlanReason(plan);
        return new JSONObject().put("success", true).put("packages", arr)
                .put("blockedReason", blocked == null ? "" : blocked)
                .put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""))
                .put("majorCount", majors).put("waitCount", expectedOnes)
                .put("generalNote",
                    I18n.tr("server.um.maintenancePreview.1"));
    }

    // ===================== compatibilita' della configurazione viva =====================

    private static final String DOVECOT_DIR = "/usr/local/etc/dovecot";
    private static final String MYCNF = "/usr/local/etc/mysql/my.cnf";

    /**
     * Costrutti che Dovecot 2.4 non accetta piu'. Colonne: espressione regolare da cercare
     * nei file di configurazione, descrizione, cosa mettere al suo posto.
     *
     * Presi dalle note ufficiali di aggiornamento 2.3 -> 2.4, non dalla memoria: qui una voce
     * sbagliata significa dire a un amministratore che puo' aggiornare quando non puo'.
     */
    private static final String[][] DOVECOT_24_BREAKS = {
        {"^[[:space:]]*mail_location[[:space:]]*=", "mail_location",
         "server.um.maintenancePreview.2"},
        {"^[[:space:]]*passdb[[:space:]]*\\{", "server.um.dovecot24.passdbNoName",
         "server.um.maintenancePreview.3"},
        {"^[[:space:]]*userdb[[:space:]]*\\{", "server.um.dovecot24.userdbNoName",
         "server.um.maintenancePreview.4"},
        {"^[[:space:]]*ssl_dh[[:space:]]*=", "ssl_dh",
         "server.um.maintenancePreview.5"},
        {"^[[:space:]]*default_fields[[:space:]]*=", "default_fields",
         "server.um.maintenancePreview.6"},
        {"^[[:space:]]*override_fields[[:space:]]*=", "override_fields",
         "server.um.maintenancePreview.6"},
        {"^[[:space:]]*service_count[[:space:]]*=", "service_count",
         "server.um.maintenancePreview.7"},
        {"^[[:space:]]*idle_kill[[:space:]]*=", "idle_kill",
         "server.um.dovecot24.idleKill"},
        {"fts[-_]lucene|fts[-_]squat", "server.um.maintenancePreview.8",
         "server.um.maintenancePreview.9"},
        {"imap[-_]zlib", "server.um.dovecot24.imapZlib",
         "server.um.maintenancePreview.10"},
        {"old[-_]stats", "server.um.dovecot24.oldStats", "server.um.dovecot24.removed"},
        {"^[[:space:]]*(director|replicator)[[:space:]]*\\{|director_servers", "director / replicator",
         "server.um.maintenancePreview.11"},
        {"driver[[:space:]]*=[[:space:]]*checkpassword", "passdb checkpassword", "server.um.maintenancePreview.12"},
    };

    /**
     * I file che Dovecot legge DAVVERO. La differenza non e' un dettaglio: sotto
     * /usr/local/etc/dovecot il port lascia anche example-config/, un albero di
     * configurazioni di esempio che Dovecot non apre mai. Scansionarlo significa
     * segnalare problemi in file che nessuno usa — e far sembrare bloccante un
     * aggiornamento per colpa di un esempio di LDAP che non e' nemmeno attivo.
     *
     * L'insieme si ricostruisce come lo costruisce Dovecot: si parte da dovecot.conf e si
     * seguono le direttive !include NON commentate, piu' i .conf.ext nominati negli args.
     */
    private static List<String> fileDovecot() { return fileDovecotIn(DOVECOT_DIR); }

    /** Come sopra, ma su una cartella qualsiasi: e' l'unico modo di provarlo senza un Dovecot installato. */
    static List<String> fileDovecotIn(String dir) {
        java.util.LinkedHashSet<String> alive = new java.util.LinkedHashSet<>();
        String root = dir + "/dovecot.conf";
        if (!ok("test -f " + root, 10)) return new ArrayList<>();
        alive.add(root);

        // I conf.d/*.conf entrano solo se dovecot.conf li include davvero: una riga
        // "#!include" commentata non fa entrare niente, e trattarla come attiva
        // reintrodurrebbe lo stesso errore degli esempi.
        if (ok("grep -qE '^[[:space:]]*!include[[:space:]]+conf\\.d/\\*\\.conf' " + root, 10)) {
            for (String f : sh("ls -1 " + dir + "/conf.d/*.conf 2>/dev/null", 15).split("\n")) {
                if (validDovecotPath(dir, f.trim())) alive.add(f.trim());
            }
        }

        // I .conf.ext non sono inclusi da un glob: entrano solo se nominati esplicitamente,
        // da un !include attivo oppure da un args = di passdb/userdb.
        for (int round = 0; round < 3; round++) {   // tre livelli bastano e impediscono un ciclo infinito
            int before = alive.size();
            String list = String.join(" ", alive);
            // -H e non -h: serve sapere DA QUALE file arriva ogni riferimento, perche' un
            // include relativo si risolve rispetto alla cartella del file che lo contiene.
            // "!include auth-sql.conf.ext" dentro conf.d/10-auth.conf indica
            // conf.d/auth-sql.conf.ext, non un file nella radice: risolverlo dalla radice
            // significa non trovarlo, e non trovarlo significa dichiarare compatibile una
            // configurazione che non lo e' — proprio il file che contiene i passdb.
            // Le righe commentate restano fuori: un include disattivato non porta dentro nulla.
            // Il grep prende largo e il filtro dei commenti si fa qui: esprimere "riga non
            // commentata che contiene args" in una sola espressione POSIX e' possibile ma
            // fragile, e una svista li' significa non seguire un riferimento — cioe' dichiarare
            // compatibile una configurazione che non lo e'.
            String references = sh("grep -HE '^[[:space:]]*(!include(_try)?[[:space:]]|.*args[[:space:]]*=)' "
                    + list + " 2>/dev/null", 20);
            for (String line : references.split("\n")) {
                int c = line.indexOf(':');
                if (c <= 0) continue;
                String source = line.substring(0, c);
                String content = line.substring(c + 1);
                if (content.trim().startsWith("#")) continue;   // include o args disattivato
                String base = source.contains("/") ? source.substring(0, source.lastIndexOf('/')) : dir;
                Matcher m = Pattern.compile("([A-Za-z0-9._/-]*[A-Za-z0-9._-]+\\.conf(\\.ext)?)").matcher(content);
                while (m.find()) {
                    String ref = m.group(1);
                    String absolute = ref.startsWith("/") ? ref : base + "/" + ref;
                    if (validDovecotPath(dir, absolute) && ok("test -f " + absolute, 10)) alive.add(absolute);
                }
            }
            if (alive.size() == before) break;
        }
        return new ArrayList<>(alive);
    }

    /**
     * Un percorso finisce dentro un comando: deve stare sotto la cartella di Dovecot, avere
     * una forma innocua, e NON provenire dall'albero degli esempi.
     */
    static boolean validDovecotPath(String dir, String p) {
        return p.startsWith(dir + "/")
                && !p.contains("/example-config/")
                && p.matches("[A-Za-z0-9._/-]{1,256}");
    }

    /**
     * La verifica che conta davvero: non "che versione ho" ma "la MIA configurazione
     * sopravvive alla prossima versione?". La stessa domanda che un numero di versione
     * non puo' rappresentare.
     */
    public static JSONObject dovecotCompatibility() {
        JSONObject r = new JSONObject();
        // Il pacchetto puo' chiamarsi dovecot, dovecot-mysql o dovecot-pgsql a seconda del
        // sapore scelto: sono lo stesso port e si escludono a vicenda, quindi su un sistema
        // con il sapore MySQL il nome "dovecot" NON e' installato e la query darebbe vuoto.
        // Il binario e' la risposta piu' diretta; l'origine del port e' il ripiego esatto.
        // Prima il PACCHETTO, poi il binario. Non e' indifferente: "dovecot --version" da' la
        // versione a monte (2.3.21.1) mentre pkg da' quella del port con la revisione FreeBSD
        // (2.3.21.1_3). Mettendo il binario per primo si finisce per confrontare due numeri di
        // natura diversa, e la scheda mostra un aggiornamento disponibile che non esiste.
        // L'interrogazione per ORIGINE funziona anche con i sapori, dove il nome "dovecot" non
        // e' installato affatto: e' quella la ragione per cui il binario era diventato il primo.
        String installed = sh("pkg query -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 20);
        if (installed.isEmpty()) {
            installed = sh("dovecot --version 2>/dev/null | awk '{print $1}'", 20);
        }
        String available = sh("pkg rquery -U -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 30);
        if (available.isEmpty()) available = sh("pkg rquery -U %v dovecot 2>/dev/null", 30);
        r.put("installed", installed).put("available", available);

        // Quali pacchetti Dovecot offre il repository. Non e' curiosita': se la 2.4 fosse un
        // PACCHETTO DIVERSO (come mysql80 e mysql84) allora nessun pkg upgrade potrebbe mai
        // portarci, e il rischio non sarebbe "un aggiornamento rompe la posta" ma "una
        // migrazione deliberata". Sono due scenari opposti e cambiano cosa va costruito.
        JSONArray offered = new JSONArray();
        for (String line : sh("pkg rquery -U -g '%n %v' 'dovecot*' 2>/dev/null", 30).split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            offered.put(new JSONObject().put("name", t.substring(0, sp)).put("version", t.substring(sp + 1).trim()));
        }
        r.put("repoPackages", offered);

        // Il giudizio di Dovecot stesso sulla configurazione. Finora il pannello scriveva i
        // file e riavviava senza mai chiedere al server se li accettasse: un errore di sintassi
        // si sarebbe scoperto a servizio gia' fermo. doveconf -n e' l'equivalente di
        // "mysqld --validate-config", e vale oggi, a prescindere dalla 2.4.
        Shell.Result dc = Shell.runShell(Duration.ofSeconds(30), "doveconf -n 2>&1 >/dev/null");
        r.put("doveconfAvailable", !dc.outputTrim().contains("not found"));
        String errors = dc.outputTrim();
        r.put("doveconfOk", dc.success() && errors.isEmpty());
        r.put("doveconfOutput", errors.length() > 3000 ? errors.substring(0, 3000) : errors);

        int majorInstalled = majorVersion(installed), majorAvailable = majorVersion(available);
        int minInst = minorVersion(installed), minorAvailable = minorVersion(available);
        // 2.3 -> 2.4 e' un salto di versione MINORE nei numeri ma una rottura totale nei fatti:
        // confrontare solo la cifra maggiore lo lascerebbe passare per innocuo.
        boolean jumpTo24 = majorAvailable > majorInstalled || (majorAvailable == majorInstalled && minorAvailable > minInst);
        r.put("breakingUpgradeAvailable", jumpTo24 && !installed.isEmpty() && !available.isEmpty());

        List<String> file = fileDovecot();
        r.put("configFilesScanned", file.size());
        JSONArray issues = new JSONArray();
        if (file.isEmpty()) {
            r.put("scanned", false);
            r.put("note", I18n.tr("server.um.dovecotCompatibility.1", java.util.Map.of("dovecotDir", String.valueOf(DOVECOT_DIR))));
        } else {
            r.put("scanned", true);
            String list = String.join(" ", file);
            for (String[] rot : DOVECOT_24_BREAKS) {
                String found = sh("grep -lE \"" + rot[0] + "\" " + list + " 2>/dev/null", 20);
                if (found.isEmpty()) continue;
                List<String> where = new ArrayList<>();
                for (String f : found.split("\n")) if (!f.trim().isEmpty()) where.add(f.trim());
                issues.put(new JSONObject().put("construct", I18n.tr(rot[1])).put("replacement", I18n.tr(rot[2]))
                        .put("files", new JSONArray(where)));
            }
            // Variabili a lettera singola: %u %d %n %h e le forme con modificatori (%2.256Nu).
            // La sintassi nuova e' %{...}, che non combacia con questa espressione.
            String var = sh("grep -lE '%[0-9.]*[A-Za-z]([^{A-Za-z]|$)' " + list + " 2>/dev/null", 20);
            if (!var.isEmpty()) {
                List<String> where = new ArrayList<>();
                for (String f : var.split("\n")) if (!f.trim().isEmpty()) where.add(f.trim());
                issues.put(new JSONObject()
                        .put("construct", I18n.tr("server.um.x.singleLetterVars"))
                        .put("replacement", I18n.tr("server.um.dovecotCompatibility.4"))
                        .put("files", new JSONArray(where)));
            }
            // Nella 2.4 questa direttiva e' obbligatoria e deve essere la prima: la sua assenza
            // e' di per se' la prova che la configurazione e' ancora in formato 2.3.
            if (sh("grep -lE '^[[:space:]]*dovecot_config_version' " + list + " 2>/dev/null", 20).isEmpty()) {
                issues.put(new JSONObject()
                        .put("construct", I18n.tr("server.um.x.noConfigVersion"))
                        .put("replacement", I18n.tr("server.um.dovecotCompatibility.6"))
                        .put("files", new JSONArray()));
            }
            if (sh("grep -lE '^[[:space:]]*dovecot_storage_version' " + list + " 2>/dev/null", 20).isEmpty()) {
                issues.put(new JSONObject()
                        .put("construct", I18n.tr("server.um.x.noStorageVersion"))
                        .put("replacement", I18n.tr("server.um.dovecotCompatibility.8"))
                        .put("files", new JSONArray()));
            }
        }
        r.put("issues", issues);
        r.put("compatible24", issues.length() == 0);
        r.put("source", I18n.tr("server.um.dovecotCompatibility.9"));
        r.put("success", true);
        return r;
    }

    private static int majorVersion(String v) {
        Matcher m = Pattern.compile("^([0-9]+)").matcher(v == null ? "" : v);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    private static int minorVersion(String v) {
        Matcher m = Pattern.compile("^[0-9]+\\.([0-9]+)").matcher(v == null ? "" : v);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** Opzioni del my.cnf vivo che MySQL 8.4 ha rimosso: con una sola di queste il server non parte. */
    private static final String[][] MYCNF_REMOVED_84 = {
        {"default_authentication_plugin", "authentication_policy"},
        {"expire_logs_days",              "server.um.minorVersion.1"},
        {"master_info_repository",        "server.um.minorVersion.2"},
        {"relay_log_info_repository",     "server.um.minorVersion.2"},
        {"slave_rows_search_algorithms",  "server.um.minorVersion.2"},
        {"transaction_write_set_extraction", "server.um.minorVersion.2"},
        {"binlog_transaction_dependency_tracking", "server.um.minorVersion.3"},
        {"log_bin_use_v1_events",         "server.um.minorVersion.2"},
        {"skip_host_cache",               "host_cache_size = 0"},
        {"character_set_client_handshake", "server.um.minorVersion.2"},
    };

    public static JSONObject mysqlCompatibility() {
        JSONObject r = new JSONObject();
        String pkgServer = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        r.put("package", pkgServer);
        if (pkgServer.isEmpty()) {
            return r.put("success", true).put("present", false)
                    .put("note", I18n.tr("server.um.mysqlCompatibility.1"));
        }
        if (!isValidName(pkgServer)) {
            return r.put("success", false).put("error", I18n.tr("server.um.mysqlCompatibility.2"));
        }
        r.put("present", true).put("version", sh("pkg query %v " + pkgServer, 20));
        // La 8.0 e' a fine vita: va detto anche quando tutto funziona, perche' il momento in cui
        // smetterebbe di funzionare non arriva con un preavviso.
        r.put("eol", pkgServer.startsWith("mysql80"));
        JSONArray issues = new JSONArray();
        if (Files.exists(Paths.get(MYCNF))) {
            for (String[] o : MYCNF_REMOVED_84) {
                // Nel my.cnf '_' e '-' sono equivalenti, e alcune opzioni sono interruttori
                // scritti senza '=': cercare solo "nome =" ne mancherebbe una parte.
                String v = o[0].replaceAll("[_-]", "[_-]");
                if (ok("grep -qE '^[[:space:]]*" + v + "[[:space:]]*(=|$)' " + MYCNF + " 2>/dev/null", 15)) {
                    issues.put(new JSONObject().put("option", o[0]).put("replacement", I18n.tr(o[1])));
                }
            }
            r.put("mycnfPresent", true);
        } else {
            r.put("mycnfPresent", false);
        }
        r.put("issues", issues);
        return r.put("success", true);
    }

    /**
     * PHP, webmail e pannello devono nominare la stessa versione di PHP. E' un accoppiamento
     * che non si vede da nessuna parte finche' non si rompe: il pacchetto roundcube porta la
     * versione nel nome, gli script del pannello la scrivono nei percorsi e nel socket php-fpm.
     */
    public static JSONObject webmailCompatibility() {
        JSONObject r = new JSONObject();
        String php = sh("pkg query %n 2>/dev/null | grep -E '^php[0-9]+$' | head -1", 20);
        String roundcube = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20);
        if (!php.isEmpty() && !isValidName(php)) php = "";
        if (!roundcube.isEmpty() && !isValidName(roundcube)) roundcube = "";
        r.put("php", php).put("roundcube", roundcube);
        r.put("phpVersion", php.isEmpty() ? "" : sh("pkg query %v " + php, 20));
        r.put("roundcubeVersion", roundcube.isEmpty() ? "" : sh("pkg query %v " + roundcube, 20));

        JSONArray note = new JSONArray();
        Matcher mp = Pattern.compile("^php([0-9]+)$").matcher(php);
        Matcher mr = Pattern.compile("^roundcube-php([0-9]+)$").matcher(roundcube);
        String vPhp = mp.find() ? mp.group(1) : "";
        String vRc = mr.find() ? mr.group(1) : "";
        if (!vPhp.isEmpty() && !vRc.isEmpty() && !vPhp.equals(vRc)) {
            note.put(I18n.tr("server.um.webmailCompatibility.1", java.util.Map.of("vRc", String.valueOf(vRc), "vPhp", String.valueOf(vPhp))));
        }
        // Cosa nomina il pannello nei propri script: se diverge da cio' che e' installato, il
        // prossimo script generato punterebbe a un percorso che non esiste.
        if (!vPhp.isEmpty() && !("84".equals(vPhp))) {
            note.put(I18n.tr("server.um.webmailCompatibility.2", java.util.Map.of("vPhp", String.valueOf(vPhp))));
        }
        r.put("notes", note);
        r.put("consistent", note.length() == 0);
        return r.put("success", true);
    }

    /**
     * Contenuto dei file di configurazione che Dovecot legge davvero, in sola lettura.
     *
     * Serve per una ragione precisa: il pannello ha TRE generatori di configurazione Dovecot
     * che nel tempo sono divergiti fra loro (userdb static contro userdb sql, Sieve presente
     * o assente, protocolli diversi). Per unificarli bisogna sapere quale variante e'
     * davvero in servizio, e l'unico modo onesto e' leggerla, non dedurla dal codice.
     *
     * Le credenziali vengono oscurate PRIMA di uscire da qui: dovecot-sql.conf contiene la
     * password del database delle caselle, e questo testo finisce in una pagina web.
     */
    public static JSONObject dumpDovecotConfig() {
        JSONArray files = new JSONArray();
        for (String f : fileDovecot()) {
            String content = sh("cat " + f + " 2>/dev/null", 20);
            content = maskCredentials(content);
            if (content.length() > 20000) content = content.substring(0, 20000) + "\n... " + I18n.tr("server.um.x.truncated");
            files.put(new JSONObject().put("path", f).put("content", content)
                    .put("lines", content.isEmpty() ? 0 : content.split("\n").length));
        }
        return new JSONObject().put("success", true).put("files", files).put("count", files.length());
    }

    /**
     * Toglie ogni password dal testo. Volutamente grossolana: meglio oscurare qualcosa di
     * innocuo che lasciar passare una credenziale in una pagina web.
     */
    static String maskCredentials(String text) {
        if (text == null) return "";
        return text
                .replaceAll("(?i)(password\\s*=\\s*)\\S+", "$1********")
                .replaceAll("(?i)(password=)[^\\s;]+", "$1********")
                .replaceAll("(?i)(pass\\s*=\\s*)\\S+", "$1********")
                .replaceAll("(?i)(secret\\s*=\\s*)\\S+", "$1********");
    }

    /**
     * Postfix non ha una rottura annunciata come Dovecot 2.4: ha un meccanismo diverso, e
     * dichiarato, che si chiama compatibility_level.
     *
     * Dalla 3.0 Postfix, quando cambia un valore predefinito in modo incompatibile, NON lo
     * applica: continua a usare quello vecchio e scrive nel log "using backwards-compatible
     * default setting nome=valore". La rete di sicurezza si toglie alzando
     * compatibility_level al numero della versione. Quindi la domanda giusta per Postfix non
     * e' "cosa si rompera'?" ma "su quali impostazioni vecchie mi sto appoggiando adesso?",
     * e la risposta la scrive Postfix stesso.
     *
     * Fonte: https://www.postfix.org/COMPATIBILITY_README.html e postconf(5).
     */
    /**
     * Cosa cambia salendo di livello di compatibilita'. Non e' un elenco decorativo: e'
     * l'unica cosa che permette di decidere se alzarlo. Dire "sei indietro, alzalo" senza
     * dire cosa cambia significa far premere un pulsante alla cieca.
     *
     * Fonte: COMPATIBILITY_README di Postfix (postfix.org), letto il 01/09/2026.
     */
    private static final String[][] POSTFIX_LEVELS = {
        {"1", "server.um.maskCredentials.1",
         "append_dot_mydomain smtpd_relay_restrictions smtputf8_enable"},
        {"2", "server.um.maskCredentials.2",
         "mynetworks_style relay_domains"},
        {"3.6", "server.um.maskCredentials.3",
         "smtpd_tls_fingerprint_digest smtp_tls_fingerprint_digest lmtp_tls_fingerprint_digest respectful_logging"},
        {"3.11", "server.um.maskCredentials.4",
         "smtp_tlsrpt_skip_reused_handshakes@smtp_tlsrpt_enable=yes smtp_tls_security_level"},
    };

    /**
     * Postfix non ha una rottura annunciata come Dovecot 2.4: ha un meccanismo diverso, e
     * dichiarato, che si chiama compatibility_level.
     *
     * Dalla 3.0, quando cambia un valore predefinito in modo incompatibile, Postfix NON lo
     * applica: continua a usare quello vecchio finche' l'amministratore non alza il livello.
     * Quindi la domanda giusta non e' "cosa si rompera'?" ma "di quanto sono indietro, e cosa
     * cambierebbe ad allinearmi?".
     *
     * La prima versione di questo controllo decideva in base al fatto che "postfix check"
     * stampasse qualcosa, e produceva la frase assurda "sta usando 0 impostazioni vecchie,
     * elencate qui sotto" senza elenco. Il confronto giusto e' fra il livello impostato e
     * quello che Postfix stesso indica nel proprio messaggio.
     */
    public static JSONObject postfixCompatibility() {
        JSONObject r = new JSONObject().put("success", true);
        String pkg = sh("pkg query %n 2>/dev/null | grep -E '^postfix(-[a-z]+)?$' | head -1", 20).trim();
        if (pkg.isEmpty() || !isValidName(pkg))
            return r.put("present", false).put("note", I18n.tr("server.um.postfixCompatibility.1"));
        r.put("present", true).put("package", pkg)
         .put("version", sh("pkg query %v " + pkg, 20))
         .put("repoVersion", sh("pkg rquery -U %v " + pkg + " 2>/dev/null", 30));

        if (!ok("command -v postconf >/dev/null 2>&1", 15))
            return r.put("readable", false)
                    .put("note", I18n.tr("server.um.postfixCompatibility.2"));
        r.put("readable", true);

        String set = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        r.put("level", set)
         .put("explicitLevel", ok("postconf -n 2>/dev/null | grep -q '^compatibility_level'", 20));

        String check = sh("postfix check 2>&1", 60);
        // Il campo si era perso nella riscrittura, e l'interfaccia mostrava l'intestazione
        // "postfix check:" seguita dal nulla: un titolo senza contenuto sembra un guasto.
        r.put("check", check.isBlank() ? "" : check).put("cleanCheck", check.isBlank());

        // Il livello a cui Postfix stesso dice di salire, preso dal suo messaggio.
        String recommended = "";
        Matcher mc = Pattern.compile("compatibility_level=([0-9.]+)").matcher(check);
        if (mc.find()) recommended = mc.group(1);
        r.put("recommended", recommended);

        // Cosa cambierebbe: solo i livelli STRETTAMENTE fra quello impostato e quello indicato.
        JSONArray changes = new JSONArray();
        double from = levelNumber(set), to = levelNumber(recommended);
        if (to > from) {
            String written = sh("postconf -n 2>/dev/null | sed -E 's/[[:space:]]*=.*//'", 30);
            java.util.Set<String> decided = new java.util.HashSet<>();
            for (String x : written.split("\n")) if (!x.isBlank()) decided.add(x.trim());
            for (String[] l : POSTFIX_LEVELS) {
                double n = levelNumber(l[0]);
                if (!(n > from && n <= to)) continue;
                JSONArray pieces = new JSONArray();
                int open = 0;
                for (String entry : l[2].split("\\s+")) {
                    if (entry.isBlank()) continue;
                    // "nome@gate=valore": il parametro conta solo se il gate ha quel valore.
                    String name = entry, gate = "", expected = "";
                    int at = entry.indexOf('@');
                    if (at > 0) {
                        name = entry.substring(0, at);
                        String g = entry.substring(at + 1);
                        int eq = g.indexOf('=');
                        if (eq > 0) { gate = g.substring(0, eq); expected = g.substring(eq + 1); }
                    }
                    if (!isValidName(name)) continue;
                    boolean already = decided.contains(name);
                    String gateValue = gate.isEmpty() || !isValidName(gate) ? ""
                            : sh("postconf -h " + gate + " 2>/dev/null", 15).trim();
                    boolean relevant = gate.isEmpty() || expected.equalsIgnoreCase(gateValue);
                    if (!already && relevant) open++;
                    JSONObject o = new JSONObject().put("name", name).put("alreadyDecided", already)
                            .put("value", already ? sh("postconf -h " + name + " 2>/dev/null", 15).trim() : "")
                            .put("relevant", relevant);
                    if (!gate.isEmpty())
                        o.put("gate", gate).put("gateValue", gateValue).put("expectedGate", expected);
                    pieces.put(o);
                }
                changes.put(new JSONObject().put("level", l[0]).put("change", l[1])
                        .put("parameters", pieces).put("openHere", open));
            }
        }
        r.put("changes", changes);

        String warnings = sh("grep -hE 'using backwards-compatible default setting [a-z0-9_]+=' "
                + "/var/log/maillog /var/log/maillog.[0-9] 2>/dev/null "
                + "| sed -E 's/.*using backwards-compatible default setting //' "
                + "| sed -E 's/[[:space:]]*(to|;).*//' | sort -u | head -40", 60);
        JSONArray lines = new JSONArray();
        for (String l : warnings.split("\n")) if (!l.isBlank()) lines.put(l.trim());
        r.put("supports", lines);

        boolean back = to > from;
        r.put("back", back);
        r.put("verdict", back ? "LEVEL_BEHIND" : "ALIGNED");
        r.put("explanation", back
                ? I18n.tr("server.um.postfixCompatibility.4", java.util.Map.of("configured", String.valueOf(set), "recommended", String.valueOf(recommended)))
                : (set.isBlank()
                   ? I18n.tr("server.um.postfixCompatibility.5")
                   : I18n.tr("server.um.postfixCompatibility.6", java.util.Map.of("configured", String.valueOf(set)))));
        int openTotal = 0;
        for (int i = 0; i < changes.length(); i++) openTotal += changes.getJSONObject(i).getInt("openHere");
        r.put("openHere", openTotal);
        r.put("effectHere", !back ? ""
                : (openTotal == 0
                   ? I18n.tr("server.um.postfixCompatibility.7")
                   : (openTotal == 1
                      ? I18n.tr("server.um.x.pfOpen.one")
                      : I18n.tr("server.um.x.pfOpen.other", java.util.Map.of("n", String.valueOf(openTotal))))));
        r.put("howToRaise", back
                ? I18n.tr("server.um.postfixCompatibility.10", java.util.Map.of("recommended", String.valueOf(recommended)))
                : "");
        r.put("source", I18n.tr("server.um.postfixCompatibility.11"));
        return r;
    }

    /**
     * Il tempo massimo di analisi di un messaggio, e se quel limite sia mai stato raggiunto.
     *
     * rspamadm configtest avverte che task_timeout (8s) e' inferiore al massimo teorico della
     * cache dei simboli (10s). E' un controllo di coerenza AGGIUNTO nella 4.1.0, non un
     * guasto comparso adesso, e la documentazione lo definisce informativo. Quei 10 secondi
     * sono la somma dei limiti dei singoli simboli: perche' si raggiungano davvero, ognuno
     * dovrebbe esaurire il proprio tempo nello stesso messaggio.
     *
     * Alzare un timeout perche' un avviso lo nomina sarebbe una scelta presa su una teoria.
     * Qui si guarda se e' MAI successo: se rspamd non ha mai interrotto un'analisi, non c'e'
     * niente da correggere; se l'ha fatto, si vede quante volte e quando.
     */
    public static JSONObject rspamdTimeoutDiagnostics() {
        JSONObject r = new JSONObject().put("success", true);
        if (!ok("pkg info -e rspamd", 20))
            return r.put("present", false).put("note", I18n.tr("server.um.rspamdTimeoutDiagnostics.1"));
        r.put("present", true);

        String ct = ok("command -v rspamadm >/dev/null 2>&1", 15)
                ? sh("rspamadm configtest 2>&1", 60) : "";
        r.put("configtest", ct);
        Matcher m = Pattern.compile("task_timeout ([0-9.]+) is less than maximum symbols cache timeout ([0-9.]+)")
                .matcher(ct);
        if (m.find()) r.put("taskTimeout", m.group(1)).put("theoreticalMax", m.group(2)).put("warns", true);
        else r.put("warns", false);

        JSONArray symbols = new JSONArray();
        Matcher ms = Pattern.compile("([A-Z0-9_]+)\\(([0-9.]+)\\)").matcher(ct);
        while (ms.find())
            symbols.put(new JSONObject().put("name", ms.group(1)).put("seconds", ms.group(2)));
        r.put("symbols", symbols);

        // La prova, se c'e', sta nel log. Non cerco una frase precisa — non la conosco e
        // inventarla darebbe zero risultati che sembrerebbero una buona notizia. Cerco la
        // parola e mostro cosa c'e', raggruppato.
        String log = "/var/log/rspamd/rspamd.log";
        boolean logC = ok("test -r " + log, 15);
        r.put("log", log).put("logReadable", logC);
        // Un solo lettore per tutto lo storico, compresse comprese.
        String reader = "for f in " + log + " /var/log/rspamd/rspamd.log.*; do "
                + "[ -f \"$f\" ] || continue; case \"$f\" in "
                + "*.bz2) bzip2 -dc \"$f\" 2>/dev/null;; *.gz) gzip -dc \"$f\" 2>/dev/null;; "
                + "*.xz) xz -dc \"$f\" 2>/dev/null;; *.zst) zstd -dc \"$f\" 2>/dev/null;; "
                + "*) cat \"$f\" 2>/dev/null;; esac; done";
        if (logC) {
            // La prima riga nel formato di rspamd, non il marcatore di newsyslog.
            r.put("since", sh("(" + reader + ") | grep -m1 -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' "
                    + "| cut -c1-19", 120).trim());
            r.put("until", sh("grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' " + log
                    + " 2>/dev/null | tail -1 | cut -c1-19", 60).trim());
            String rot = sh("ls /var/log/rspamd/rspamd.log.* 2>/dev/null | wc -l", 30).trim().replaceAll("[^0-9]", "");
            int rotations = rot.isEmpty() ? 0 : Integer.parseInt(rot);
            String compressed = sh("ls /var/log/rspamd/rspamd.log.*.[bg]z* 2>/dev/null | wc -l", 30)
                    .trim().replaceAll("[^0-9]", "");
            r.put("rotations", rotations)
             .put("compressedRotations", compressed.isEmpty() ? 0 : Integer.parseInt(compressed));
            String lines = sh("(" + reader + ") | grep -i 'timeout' "
                    + "| sed -E 's/^[^;]*; //' | sed -E 's/[0-9a-f]{8,}/<id>/g' "
                    + "| sed -E 's/[0-9]+\\.[0-9]+/<n>/g' | sort | uniq -c | sort -rn | head -15", 300);
            JSONArray groups = new JSONArray();
            int realOnes = 0, warning = 0;
            for (String l : lines.split("\n")) {
                String t = l.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                try {
                    int times = Integer.parseInt(t.substring(0, sp));
                    String msg = t.substring(sp + 1).trim();
                    // rspamd_worker_check_and_adjust_timeout e' il controllo di coerenza che
                    // rspamd esegue all'avvio: e' l'avviso, non un suo effetto.
                    boolean isWarning = msg.contains("check_and_adjust_timeout")
                            || msg.contains("symbols cache timeout")
                            || msg.contains("symbols by execution time");
                    if (isWarning) warning += times; else realOnes += times;
                    groups.put(new JSONObject().put("times", times).put("messageText", msg)
                            .put("isWarning", isWarning));
                } catch (NumberFormatException ignored) { }
            }
            r.put("inLog", groups).put("interruptions", realOnes).put("warningRepeats", warning);
            String tot = sh("(" + reader + ") | grep -ci 'timeout'", 300).trim().replaceAll("[^0-9]", "");
            r.put("occurrences", tot.isEmpty() ? 0 : Integer.parseInt(tot));
            String totalLines = sh("(" + reader + ") | wc -l", 300).trim().replaceAll("[^0-9]", "");
            r.put("logLines2", totalLines.isEmpty() ? 0 : Integer.parseInt(totalLines));
            String onlyCurrent = sh("wc -l < " + log + " 2>/dev/null", 60).trim().replaceAll("[^0-9]", "");
            r.put("currentLines", onlyCurrent.isEmpty() ? 0 : Integer.parseInt(onlyCurrent));
        }

        int occ = r.optInt("occurrences", -1);
        int logLines2 = r.optInt("logLines2", 0);
        // Un campione piccolo non autorizza a dire "mai". La soglia non e' un numero magico:
        // sotto le mille righe un log di posta copre tipicamente poche ore, e in poche ore
        // puo' semplicemente non essere passato il messaggio lento che farebbe scattare il caso.
        boolean wideSample = logLines2 >= 1000;
        String period = r.optString("since", "").isEmpty() ? ""
                : " " + I18n.tr("server.um.x.rsLogSpan", java.util.Map.of("since", String.valueOf(r.optString("since")), "until", String.valueOf(r.optString("until"))));
        String rotate = r.optInt("rotations", 0) > 0
                ? " " + (r.optInt("compressedRotations", 0) > 0
                     ? I18n.tr("server.um.x.rsRotZ", java.util.Map.of("n", String.valueOf(r.optInt("rotations")), "z", String.valueOf(r.optInt("compressedRotations")), "lines", String.valueOf(r.optInt("currentLines", 0))))
                     : I18n.tr("server.um.x.rsRot", java.util.Map.of("n", String.valueOf(r.optInt("rotations")), "lines", String.valueOf(r.optInt("currentLines", 0)))))
                : I18n.tr("server.um.rspamdTimeoutDiagnostics.2");
        r.put("wideSample", wideSample);
        int interruptions = r.optInt("interruptions", occ);
        r.put("verdict", !logC ? "LOG_UNREADABLE"
                : (interruptions > 0 ? "SCANS_INTERRUPTED"
                                    : (wideSample ? "NO_SCAN_INTERRUPTED"
                                                     : "NO_TRACE_SHORT_LOG")));
        String decomposition = occ == 0 ? ""
                : " " + I18n.tr("server.um.x.rsSplit", java.util.Map.of("occurrences", String.valueOf(occ), "warnings", String.valueOf(r.optInt("warningRepeats", 0)), "interruptions", String.valueOf(interruptions)));
        r.put("explanation", !logC
                ? I18n.tr("server.um.rspamdTimeoutDiagnostics.7", java.util.Map.of("log", String.valueOf(log)))
                : (interruptions == 0
                   ? (occ == 0
                        ? I18n.tr("server.um.rspamdTimeoutDiagnostics.8", java.util.Map.of("logLines", String.valueOf(logLines2)))
                        : I18n.tr("server.um.rspamdTimeoutDiagnostics.9", java.util.Map.of("logLines", String.valueOf(logLines2), "breakdown", String.valueOf(decomposition))))
                     + period + rotate
                     + (wideSample
                        ? I18n.tr("server.um.rspamdTimeoutDiagnostics.10")
                        : I18n.tr("server.um.rspamdTimeoutDiagnostics.11", java.util.Map.of("logLines", String.valueOf(logLines2))))
                     + " " + I18n.tr("server.um.x.rsTheoretical")
                   : I18n.tr("server.um.rspamdTimeoutDiagnostics.12", java.util.Map.of("interruptions", String.valueOf(interruptions), "logLines", String.valueOf(logLines2), "breakdown", String.valueOf(decomposition), "period", String.valueOf(period), "rotate", String.valueOf(rotate)))));
        r.put("ifNeeded", I18n.tr("server.um.rspamdTimeoutDiagnostics.13"));
        r.put("source", I18n.tr("server.um.rspamdTimeoutDiagnostics.14"));
        return r;
    }

    /**
     * Alza il livello di compatibilita' di Postfix, dal pannello.
     *
     * Non e' un comando incollato in un pulsante: e' la stessa cosa che si farebbe a mano,
     * piu' le tre cose che a mano si dimenticano — la copia di main.cf prima di toccarlo, la
     * verifica che il valore sia DAVVERO cambiato, e il ritorno indietro automatico se
     * qualcosa non torna.
     *
     * L'esito lo dice il sistema, non il codice di uscita di postconf: si rilegge il valore,
     * si richiede a Postfix se e' ancora in piedi, e si riesegue "postfix check" per vedere
     * se l'avviso e' effettivamente sparito.
     */
    public static JSONObject raisePostfixCompatibilityLevel(String target) {
        JSONObject r = new JSONObject().put("pkgName", "postfix");
        if (target == null || !target.matches("[0-9]+(\\.[0-9]+)?"))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.1", java.util.Map.of("target", String.valueOf(target))));
        if (!ok("command -v postconf >/dev/null 2>&1", 15))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.2"));

        StringBuilder log = new StringBuilder();
        String before = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        log.append(I18n.tr("server.um.x.pfLevelBefore", java.util.Map.of("v", String.valueOf(before)))).append("\n");
        if (before.equals(target))
            return r.put("success", true).put("alreadyAtLevel", true).put("before", before).put("after", before)
                    .put("log", log.toString())
                    .put("note", I18n.tr("server.um.raisePostfixCompatibilityLevel.3", java.util.Map.of("target", String.valueOf(target))));

        if (levelNumber(target) < levelNumber(before))
            return r.put("success", false).put("before", before)
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.4", java.util.Map.of("before", String.valueOf(before), "target", String.valueOf(target))));

        // La copia viene prima di tutto: e' cio' che rende reversibile il resto.
        String mainCf = sh("postconf -h config_directory 2>/dev/null", 20).trim();
        if (mainCf.isEmpty()) mainCf = "/usr/local/etc/postfix";
        mainCf = mainCf + "/main.cf";
        if (!ok("test -f " + mainCf, 15))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.5", java.util.Map.of("mainCf", String.valueOf(mainCf))));
        String copy = "/var/db/mailpanel/main.cf-" + sh("date '+%Y%m%d-%H%M%S'", 15).trim();
        sh("mkdir -p /var/db/mailpanel && cp -p " + mainCf + " " + copy, 30);
        boolean copyOk = ok("test -s " + copy, 15);
        r.put("copy", copy).put("copyOk", copyOk);
        log.append(copyOk ? I18n.tr("server.um.raisePostfixCompatibilityLevel.6", java.util.Map.of("copy", String.valueOf(copy)))
                           : I18n.tr("server.um.raisePostfixCompatibilityLevel.7"));
        if (!copyOk)
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.8"));

        log.append("--- ").append(I18n.tr("server.um.x.pfWrite")).append(" ---\n")
           .append(sh("postconf -e compatibility_level=" + target + " 2>&1", 60)).append("\n");

        String after = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        log.append(I18n.tr("server.um.x.pfLevelAfter", java.util.Map.of("v", String.valueOf(after)))).append("\n");
        r.put("before", before).put("after", after);
        if (!after.equals(target)) {
            sh("cp -p " + copy + " " + mainCf, 30);
            log.append(I18n.tr("server.um.x.pfUnchanged")).append("\n");
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.9", java.util.Map.of("after", String.valueOf(after))));
        }

        log.append("--- ").append(I18n.tr("server.um.x.pfReload")).append(" ---\n")
           .append(sh("postfix reload 2>&1", 60)).append("\n");

        // Postfix e' ancora in piedi? La domanda non e' retorica: una main.cf accettata da
        // postconf puo' comunque non piacere al master.
        boolean active = ok("service postfix status", 30);
        r.put("active", active);
        log.append(active ? I18n.tr("server.um.x.pfUpAfter") : I18n.tr("server.um.x.pfDownAfter")).append("\n");
        if (!active) {
            sh("cp -p " + copy + " " + mainCf, 30);
            sh("service postfix start 2>&1 || postfix start 2>&1", 60);
            boolean climbed = ok("service postfix status", 30);
            log.append(I18n.tr("server.um.x.pfRestored", java.util.Map.of("outcome", String.valueOf(climbed ? I18n.tr("server.um.x.pfBackUp") : I18n.tr("server.um.raisePostfixCompatibilityLevel.10"))))).append("\n");
            return r.put("success", false).put("log", log.toString())
                    .put("error", climbed
                            ? I18n.tr("server.um.x.pfDownBack")
                            : I18n.tr("server.um.x.pfDownStill"));
        }

        String check = sh("postfix check 2>&1", 60);
        boolean warningVia = !check.contains("backwards-compatible");
        r.put("check", check).put("warningVia", warningVia);
        log.append("--- postfix check ---\n").append(check.isBlank() ? I18n.tr("server.um.x.noMessage") : check).append("\n");

        return r.put("success", true).put("log", log.toString())
                .put("note", warningVia
                        ? I18n.tr("server.um.x.pfRaisedClean", java.util.Map.of("before", String.valueOf(before), "after", String.valueOf(after), "copy", String.valueOf(copy)))
                        : I18n.tr("server.um.x.pfRaisedWarn", java.util.Map.of("before", String.valueOf(before), "after", String.valueOf(after), "copy", String.valueOf(copy))));
    }

    /** "3.11" -> 3.11, "2" -> 2. Serve solo a ordinare i livelli fra loro. */
    private static double levelNumber(String v) {
        if (v == null) return -1;
        Matcher m = Pattern.compile("^([0-9]+)(?:\\.([0-9]+))?").matcher(v.trim());
        if (!m.find()) return -1;
        double n = Double.parseDouble(m.group(1));
        if (m.group(2) != null) n += Double.parseDouble(m.group(2)) / 100.0;
        return n;
    }

    /**
     * Rspamd cambia per gradi, e i cambiamenti che contano non sono di sintassi ma di
     * COMPORTAMENTO: un'opzione che sparisce, un predefinito che si rovescia, un simbolo che
     * cambia nome. Un file che resta valido puo' quindi produrre risultati diversi.
     *
     * Le voci qui sotto vengono una per una dalle note ufficiali di rilascio 4.0 e 4.1.
     */
    private static final String[][] RSPAMD_CONSTRUCTS = {
        {"(^|[^A-Za-z0-9_])ssl[[:space:]]*=[[:space:]]*true", "server.um.levelNumber.1",
         "server.um.levelNumber.2", "broken"},
        {"include_content_urls", "include_content_urls",
         "server.um.levelNumber.3", "behavior"},
        {"token_bucket", "server.um.levelNumber.4",
         "server.um.levelNumber.5", "behavior"},
        {"senderscore_reputation", "senderscore_reputation",
         "server.um.levelNumber.6", "behavior"},
        {"MX_NXDOMAIN|MX_MISSING", "server.um.rspamd4.mxSymbols",
         "server.um.levelNumber.7", "behavior"},
    };

    public static JSONObject rspamdCompatibility() {
        JSONObject r = new JSONObject().put("success", true);
        if (!ok("pkg info -e rspamd", 20))
            return r.put("present", false).put("note", I18n.tr("server.um.rspamdTimeoutDiagnostics.1"));
        r.put("present", true)
         .put("version", sh("pkg query %v rspamd", 20))
         .put("repoVersion", sh("pkg rquery -U %v rspamd 2>/dev/null", 30));

        String etc = "/usr/local/etc/rspamd";
        boolean c = ok("test -d " + etc, 15);
        r.put("configPresent", c);
        JSONArray issues = new JSONArray();
        int filesRead = 0;
        if (c) {
            String n = sh("grep -rIl '' " + etc + " 2>/dev/null | wc -l", 60).trim().replaceAll("[^0-9]", "");
            filesRead = n.isEmpty() ? 0 : Integer.parseInt(n);
            for (String[] k : RSPAMD_CONSTRUCTS) {
                String where = sh("grep -rIlE '" + k[0] + "' " + etc + " 2>/dev/null | head -20", 60);
                if (where.isBlank()) continue;
                JSONArray yours = new JSONArray(), ofPackage = new JSONArray();
                for (String f : where.split("\n")) {
                    String t = f.trim();
                    if (t.isEmpty()) continue;
                    if (!t.matches("[A-Za-z0-9_./+-]{1,256}")) continue;
                    boolean ownedByPkg = !sh("pkg which -q " + t + " 2>/dev/null", 20).trim().isEmpty();
                    (ownedByPkg ? ofPackage : yours).put(t);
                }
                if (yours.length() == 0 && ofPackage.length() == 0) continue;
                issues.put(new JSONObject().put("construct", I18n.tr(k[1])).put("whatChanges", I18n.tr(k[2]))
                        .put("type", yours.length() > 0 ? k[3] : "default")
                        .put("files", yours).put("packageFiles", ofPackage));
            }
        }
        r.put("filesRead", filesRead).put("issues", issues);

        // rspamadm configtest e' l'equivalente di doveconf -n: lo dice rspamd, non io.
        if (ok("command -v rspamadm >/dev/null 2>&1", 15)) {
            String t = sh("rspamadm configtest 2>&1", 60);
            r.put("configtest", t).put("configtestOk", t.toLowerCase().contains("syntax ok"));
        } else {
            r.put("configtest", I18n.tr("server.um.rspamdCompatibility.1")).put("configtestOk", false);
        }

        // Il ricalcolo dei Bayes riguarda SOLO le installazioni con Redis suddiviso su piu'
        // server: dirlo evita di spaventare chi non e' in quel caso.
        int redis = 0;
        if (c) {
            String rr = sh("grep -rhoE 'servers[[:space:]]*=[[:space:]]*\"[^\"]+\"' " + etc
                    + "/local.d/redis.conf 2>/dev/null | head -1", 20);
            redis = rr.isBlank() ? 1 : rr.split(",").length;
        }
        r.put("redisServer", redis)
         .put("bayes", redis > 1
                ? I18n.tr("server.um.rspamdCompatibility.2")
                : I18n.tr("server.um.rspamdCompatibility.3"));

        int broken = 0, yoursTotal = 0, packageOnly = 0;
        for (int i = 0; i < issues.length(); i++) {
            JSONObject q = issues.getJSONObject(i);
            int nYours = q.getJSONArray("files").length();
            yoursTotal += nYours;
            if (nYours == 0) packageOnly++;
            if (nYours > 0 && "broken".equals(q.getString("type"))) broken++;
        }
        r.put("yours", yoursTotal).put("packageOnly", packageOnly);
        r.put("verdict", broken > 0 ? "INVALID_CONSTRUCT"
                : (yoursTotal > 0 ? "BEHAVIOR_DIFFS"
                               : "NOTHING_TO_REPORT"));
        r.put("explanation", broken > 0
                ? I18n.tr("server.um.rspamdCompatibility.7", java.util.Map.of("broken", String.valueOf(broken)))
                : (yoursTotal > 0
                   ? I18n.tr("server.um.rspamdCompatibility.8")
                   : I18n.tr("server.um.x.rsClean")
                     + (packageOnly > 0
                        ? " " + I18n.tr("server.um.x.rsOnlyPkg", java.util.Map.of("n", String.valueOf(packageOnly)))
                        : "")));
        r.put("source", I18n.tr("server.um.rspamdCompatibility.9"));
        return r;
    }

    /** Le verifiche insieme: e' cio' che si guarda prima di premere "aggiorna". */
    public static JSONObject compatibilityReport() {
        return new JSONObject().put("success", true)
                .put("dovecot", dovecotCompatibility())
                .put("postfix", postfixCompatibility())
                .put("rspamd", rspamdCompatibility())
                .put("mysql", mysqlCompatibility())
                .put("webmail", webmailCompatibility());
    }

    // ===================== lavori in corso =====================

    /** Un'operazione lunga che il pannello segue mentre avviene. */
    public static final class Job {
        public final String id;
        public final String type;
        public volatile String status = "pending";
        public volatile String errorMessage = "";
        /** Il messaggio finale di un lavoro riuscito, da mostrare cosi' com'e' (es. il cambio di ramo). */
        public volatile String outcome = "";
        public volatile int step, total;
        public final long startedAt = System.currentTimeMillis();
        public volatile long finishedAt;
        private final StringBuilder log = new StringBuilder();

        Job(String id, String type) { this.id = id; this.type = type; }

        public synchronized void write(String line) {
            log.append('[')
               .append(new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date()))
               .append("] ").append(line).append('\n');
            // Un pkg upgrade di cento pacchetti produce migliaia di righe: senza un tetto il
            // job terrebbe in memoria tutto l'output e la pagina diventerebbe illeggibile.
            if (log.length() > 200_000) log.delete(0, log.length() - 150_000);
        }

        public void advance(int s, int t) { this.step = s; this.total = t; }

        /** Scrive la fine, se il lavoro non l'ha gia' scritta da se': vedi withEndMarked. */
        void markFinished() { if (finishedAt == 0) finishedAt = System.currentTimeMillis(); }

        /**
         * Lo stato come lo deve vedere chi aspetta il lavoro.
         *
         * Un lavoro scrive "completed" o "error" quando ha un esito, ma spesso ha ancora da
         * fare: la manutenzione completa scrive "completed" appena pkg upgrade esce con 0, e
         * DOPO confronta con il piano e con l'inventario, riprotegge i pacchetti, controlla
         * protezioni e servizi — e ognuno di questi passi puo' cambiare l'esito in "error".
         * La pagina smette di chiedere al primo esito che vede: un lavoro andato male poteva
         * comparire come riuscito, e le righe della verifica finale non arrivavano a schermo.
         * Misurato sulla VM il 23/10/2026: una sonda fermata al primo "completed" ha trovato 14
         * pacchetti su 39 ancora da riproteggere.
         *
         * Quindi un esito e' visibile solo quando la fine e' scritta, cioe' quando il lavoro ha
         * finito davvero. Fino ad allora il lavoro e' "running", come e'.
         *
         * L'ordine delle due letture conta: prima la fine, poi lo stato. Sono campi volatile e
         * il lavoro scrive lo stato PRIMA della fine, quindi chi vede la fine vede anche lo stato
         * che c'era a quel punto. Nell'ordine opposto si potrebbe leggere lo stato di prima del
         * finally e la fine di dopo, e mostrare come definitivo un "completed" gia' superato.
         */
        String visibleStatus() {
            long f = finishedAt;
            String s = status;
            return f == 0 && ("completed".equals(s) || "error".equals(s)) ? "running" : s;
        }

        public synchronized JSONObject toJson() {
            return new JSONObject()
                    .put("id", id).put("type", type).put("status", visibleStatus())
                    .put("step", step).put("total", total)
                    .put("percent", total > 0 ? (step * 100 / total) : 0)
                    .put("errorMessage", errorMessage)
                    .put("result", outcome)
                    .put("elapsedSeconds", ((finishedAt > 0 ? finishedAt : System.currentTimeMillis()) - startedAt) / 1000)
                    .put("consoleLog", log.toString());
        }
    }

    public static JSONObject jobStatus(String id) {
        Job j = JOBS.get(id);
        return j == null ? new JSONObject().put("success", false).put("error", I18n.tr("server.um.jobStatus.1"))
                         : new JSONObject().put("success", true).put("job", j.toJson());
    }

    /**
     * Esegue un comando lungo scrivendo l'output nel log del lavoro mentre arriva.
     * Shell.run raccoglie tutto e restituisce alla fine: per un pkg upgrade da minuti
     * significherebbe una pagina ferma senza sapere se sta funzionando.
     */
    static int runLogged(Job job, String command, int timeoutSeconds) throws Exception {
        return runLogged(job, command, timeoutSeconds, null);
    }

    static int runLogged(Job job, String command, int timeoutSeconds, StringBuilder capture) throws Exception {
        return runLogged(job, command, timeoutSeconds, capture, null);
    }

    /** Il codice d'uscita di un comando fermato allo scadere del tempo, come timeout(1). */
    static final int TIMED_OUT = 124;

    /**
     * Un comando che cambia i pacchetti o il sistema, che allo scadere del tempo NON si ferma.
     *
     * Misurato sulla VM il 06/11/2026 (reperto 147): allo scadere il log diceva «termino il
     * processo», ma il processo terminato era la shell; pkg, suo figlio, continuava e finiva, e
     * runLogged tornava solo alla fine di pkg con IOException invece di un codice. Il lavoro
     * finiva in errore mentre pkg stava ancora installando. Fermarlo davvero non e' la cura:
     * un pkg ucciso a meta' di un'installazione lascia pacchetti installati a meta'. Quindi per
     * questi comandi il tempo diventa una soglia di avviso: si dice che sta ancora lavorando e si
     * aspetta. Scaricare (-F) e simulare (-n) invece si possono fermare.
     */
    static boolean mustNotBeKilled(String command) {
        for (String part : command.split("[;&|]")) {
            String c = part.trim();
            String[] w = c.split("\\s+");
            if (w.length == 0) continue;
            String cmd = w[0].substring(w[0].lastIndexOf('/') + 1);
            if (cmd.equals("pkg") || cmd.equals("pkg-static")) {
                String sub = null;
                for (int i = 1; i < w.length; i++) if (!w[i].startsWith("-")) { sub = w[i]; break; }
                if (sub == null || !Set.of("upgrade", "install", "delete", "remove", "autoremove", "add").contains(sub)) continue;
                List<String> words = List.of(w);
                if (words.contains("-n") || words.contains("--dry-run") || words.contains("-F") || words.contains("--fetch-only")) continue;
                return true;
            }
            if (cmd.equals("freebsd-update") && (List.of(w).contains("install") || List.of(w).contains("rollback"))) return true;
        }
        return false;
    }

    /** Ferma il processo e TUTTI i suoi discendenti: prima con le buone, dopo 10 secondi con le cattive. */
    static void stopTree(Process p) {
        List<ProcessHandle> tree = p.descendants().toList();
        tree.forEach(ProcessHandle::destroy);
        p.destroy();
        long until = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < until && (p.isAlive() || tree.stream().anyMatch(ProcessHandle::isAlive))) {
            try { Thread.sleep(200); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
        }
        tree.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
        if (p.isAlive()) p.destroyForcibly();
    }

    static int runLogged(Job job, String command, int timeoutSeconds,
                            StringBuilder capture, Map<String, String> environment) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        org.mail_panel.util.Shell.applyPath(pb);
        if (environment != null) pb.environment().putAll(environment);
        // Lo standard input e' /dev/null, come in Shell: la pipe predefinita di
        // ProcessBuilder non arriva mai a EOF, quindi un comando che legge resterebbe
        // fermo per tutto il timeout — qui 1800 o 3600 secondi. Il motivo per esteso sta
        // sul campo NO_STDIN di Shell.
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
        pb.redirectErrorStream(true);
        Process p = pb.start();

        // Il timeout va sorvegliato da FUORI. Metterlo solo sulla waitFor finale non
        // servirebbe a niente: se il processo si blocca senza chiudere lo standard output,
        // readLine resta in attesa per sempre e la waitFor non viene mai raggiunta.
        boolean keepWaiting = mustNotBeKilled(command);
        java.util.concurrent.atomic.AtomicBoolean stopped = new java.util.concurrent.atomic.AtomicBoolean(false);
        Thread guard = localizedThread(() -> {
            try {
                long waited = 0;
                while (!p.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS)) {
                    waited += timeoutSeconds;
                    if (keepWaiting) {
                        job.write(I18n.tr("server.um.runLogged.pkgStillRunning", java.util.Map.of(
                                "cmd", command.trim().split("\\s+")[0], "minutes", String.valueOf(Math.max(1, waited / 60)))));
                        continue;
                    }
                    stopped.set(true);
                    job.write(I18n.tr("server.um.runLogged.stopped", java.util.Map.of("timeoutSeconds", String.valueOf(timeoutSeconds))));
                    stopTree(p);
                    return;
                }
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }, "update-watchdog");
        guard.setDaemon(true);
        guard.start();

        // L'uscita si legge in un thread a parte, e la fine la decide il PROCESSO, non l'uscita.
        // Un processo che il comando ha lanciato e lasciato andare (una subshell con "&", un demone
        // che non chiude lo standard output) esce dall'albero e tiene aperta la pipe: leggendola
        // qui fino in fondo, runLogged avrebbe aspettato lui, timeout o no. Misurato sulla VM il
        // 06/11/2026: "(sleep 71 &); sleep 63" con 3 secondi di timeout tornava dopo 71.
        java.util.concurrent.CountDownLatch drained = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<java.io.IOException> readError = new java.util.concurrent.atomic.AtomicReference<>();
        Thread reader = localizedThread(() -> {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = br.readLine()) != null) {
                    job.write(l);
                    if (capture != null) synchronized (capture) { capture.append(l).append('\n'); }
                }
            } catch (java.io.IOException e) {
                // Dopo stopTree lo stream si chiude sotto la lettura: quello che e' arrivato e' tutto.
                if (!stopped.get()) readError.set(e);
            } finally {
                drained.countDown();
            }
        }, "update-output");
        reader.setDaemon(true);
        reader.start();
        int code = p.waitFor();
        guard.interrupt();
        if (!drained.await(stopped.get() ? 5 : OUTPUT_GRACE_SECONDS, java.util.concurrent.TimeUnit.SECONDS))
            job.write(I18n.tr("server.um.runLogged.outputHeld"));
        if (readError.get() != null) throw readError.get();
        return stopped.get() ? TIMED_OUT : code;
    }

    /** Quanto si aspetta l'uscita dopo la fine del comando, prima di non aspettarla piu'. */
    static int OUTPUT_GRACE_SECONDS = 30;

    // ===================== stato su disco, per sopravvivere a un crash =====================

    /**
     * Il blocco finale di runMaintenanceJob non viene eseguito se il processo muore
     * (riavvio del pannello, kill, crash della JVM): i pacchetti resterebbero sbloccati e
     * nessuno se ne accorgerebbe finche' un aggiornamento successivo non porta via un
     * servizio. Questo file e' l'unica cosa che sopravvive.
     *
     * Si scrive con PackageQueue.writeState, che dice se c'e' riuscito: prima un errore di
     * scrittura finiva in un avviso e il lavoro sbloccava lo stesso. Chi non riesce a scriverlo
     * non sblocca niente.
     */
    private static void clearState() {
        PackageQueue.deleteState();
    }

    /**
     * Da chiamare all'avvio del pannello. Se il file di stato esiste, un lavoro sui pacchetti non
     * e' arrivato in fondo: i pacchetti elencati vanno riprotetti subito. Riproteggere qualcosa di
     * gia' protetto non ha effetti, quindi e' sicuro anche se in realta' era andato tutto bene.
     *
     * Tre cose misurate sulla VM il 06/11/2026 (reperto 147), e la risposta a ognuna:
     *  - ogni avvio del jar passa di qui, anche il menu da console aperto mentre il pannello web
     *    aggiorna: senza il turno fra processi riproteggeva i pacchetti del lavoro in corso e ne
     *    cancellava l'elenco. Adesso si prende il turno, e se lo tiene un altro processo non si
     *    tocca niente;
     *  - se pkg sta ancora lavorando (il pannello e' stato ucciso, non pkg), "pkg lock" fallisce e il
     *    pacchetto restava sbloccato fino al riavvio SUCCESSIVO. Adesso si riprova da soli ogni
     *    mezzo minuto, finche' pkg non ha finito;
     *  - l'interruzione si annotava solo nel log. Adesso c'e' un avviso (PackageRecovery) che la
     *    pagina Aggiornamenti e il rapporto mostrano finche' qualcuno non controlla.
     */
    public static String restoreLocksAfterCrash() {
        // PackageQueue.list, non il percorso scritto qui: e' lo stesso file, ma e' quello che
        // leggono PackageRecovery.statePackages e le prove, che lo spostano in una cartella loro.
        Path f = PackageQueue.list;
        if (!Files.exists(f)) return "";
        String refusal = PackageQueue.takeForLocks("startup-restore", I18n.tr("server.recovery.turnAtStartup"));
        if (refusal != null) {
            String msg = "A list of unlocked packages is on disk, but another panel process holds the package turn "
                    + "(a job is running there): the list is not touched. " + refusal;
            LOGGER.info(msg);
            return msg;
        }
        try {
            JSONObject job = PackageQueue.jobRecord();
            List<String> names = PackageRecovery.statePackages();
            Set<String> lockedNow = lockedNames();
            List<String> unlockedNow = new ArrayList<>();
            for (String n : names) if (!lockedNow.contains(n) && ok("pkg info -e " + n, 15)) unlockedNow.add(n);
            String pkgNow = PackageRecovery.pkgRunning();
            // L'aggiornamento della JVM lascia l'elenco apposta e si fa riavviare dal suo script:
            // se lo script ha gia' riprotetto tutto e pkg non lavora piu', non e' un'interruzione.
            boolean expected = job.optBoolean("expectsRestart") && unlockedNow.isEmpty() && pkgNow.isEmpty();
            if (!expected) PackageRecovery.recordInterruption(job, names, unlockedNow, pkgNow);
            StringBuilder log = new StringBuilder();
            boolean done = relockFromState(f, log);
            String msg = "Interrupted maintenance detected at startup: " + log;
            if (!done) {
                msg += (pkgNow.isEmpty() ? "" : "pkg is still working (" + pkgNow.replace("\n", "; ") + "): ")
                        + "retrying every " + PackageRecovery.retrySeconds + " seconds until they are protected again.\n";
                PackageRecovery.retryInBackground(UpdateManager::retryRelock);
            } else if (!expected) {
                PackageRecovery.markRelocked();
            }
            LOGGER.warning(msg);
            return msg;
        } finally {
            PackageQueue.release("startup-restore");
        }
    }

    /**
     * Riprotegge i pacchetti dell'elenco. Vero se alla fine sono tutti protetti (o non piu'
     * installati) e l'elenco e' stato tolto; falso se qualcuno non si e' riprotetto, e allora
     * l'elenco resta.
     */
    static boolean relockFromState(Path f, StringBuilder log) {
        int done = 0, totals = 0, skipped = 0;
        try {
            for (String line : Files.readString(f).split("\n")) {
                String n = line.trim();
                if (n.isEmpty()) continue;
                if (!isValidName(n)) { log.append("  name ignored: ").append(n).append('\n'); continue; }
                totals++;
                if (!ok("pkg info -e " + n, 15)) { skipped++; log.append("  ").append(n).append(": not installed, skipped\n"); continue; }
                if (ok("pkg lock -y " + n, 30)) { done++; log.append("  ").append(n).append(": protected again\n"); }
                else log.append("  ").append(n).append(": PROTECTING AGAIN FAILED\n");
            }
            log.insert(0, done + "/" + totals + " packages protected again.\n");
            if (done + skipped == totals) { clearState(); log.append("State cleared.\n"); return true; }
            log.append("Some were not protected again: the state stays.\n");
        } catch (Exception e) {
            log.append("Restore ERROR: ").append(e.getMessage()).append('\n');
        }
        return false;
    }

    /**
     * Un tentativo del ripristino in background (PackageRecovery.retryInBackground): vero quando
     * l'elenco non c'e' piu', cioe' quando non resta niente da fare. Prende il turno a ogni
     * tentativo, per non pestare un lavoro partito nel frattempo.
     */
    static boolean retryRelock() {
        Path f = PackageQueue.list;
        if (!Files.exists(f)) return true;
        if (PackageQueue.takeForLocks("relock-retry", I18n.tr("server.recovery.turnRetry")) != null) return false;
        try {
            StringBuilder log = new StringBuilder();
            if (!relockFromState(f, log)) return false;
            PackageRecovery.markRelocked();
            refreshLockTrace();
            LOGGER.warning("Packages of the interrupted job protected again in the background: " + log);
            return true;
        } finally {
            PackageQueue.release("relock-retry");
        }
    }

    /** Insieme dei pacchetti protetti adesso, nomi senza versione. */
    private static Set<String> lockedNames() {
        return lockedNames(sh("pkg lock -l 2>/dev/null"));
    }

    // ===================== i due lavori =====================

    /**
     * Riscrive la SOLA configurazione di Dovecot dalla sorgente unica, senza toccare i
     * pacchetti. Serviva: prima, per applicare una correzione alla configurazione bisognava
     * passare dalla reinstallazione del pacchetto — `pkg delete` e reinstallazione — che e'
     * sproporzionato per riscrivere dei file di testo e introduce rischi che non c'entrano.
     *
     * Il ricaricamento avviene solo se doveconf ha accettato: se rifiuta, il frammento ha
     * gia' rimesso la configurazione precedente ed esce diverso da zero, quindi qui non si
     * ricarica nulla e il servizio prosegue com'era.
     */
    /**
     * L'attivazione MTA-STS come lavoro in background.
     *
     * L'emissione del certificato dura piu' del limite di tempo di un proxy: tenuta dentro
     * una richiesta HTTP, il browser riceve una pagina di errore mentre sul server
     * l'operazione prosegue, e chi guarda resta senza sapere cosa sia successo a un
     * certificato di produzione. Qui la richiesta torna subito con un identificativo e la
     * pagina segue l'avanzamento, come per gli aggiornamenti dei pacchetti.
     */
    public static JSONObject startMtaStsActivation() {
        String id = "mtasts-" + System.currentTimeMillis();
        Job j = new Job(id, "mtasts");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                org.json.JSONObject outcome = org.mail_panel.system.MtaStsSetup.run(j);
                j.write("");
                j.write(outcome.optString("note", outcome.optString("error", "")));
                j.write("");
                j.write("--- " + I18n.tr("server.um.x.fullResult") + " ---");
                j.write(outcome.toString(2));
                j.status = outcome.optBoolean("success", false) ? "completed" : "error";
                if (!outcome.optBoolean("success", false))
                    j.errorMessage = outcome.optString("error", I18n.tr("server.um.x.seqInterrupted"));
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = String.valueOf(e.getMessage());
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.finishedAt = System.currentTimeMillis();
            }
        }, "mtasts-enable");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * "Configura tutto" per un dominio, come lavoro in background.
     *
     * Prima era una chiamata sincrona, e andava bene finche' la sequenza si limitava a
     * scrivere qualche record. Ora include l'attesa della propagazione DNS e l'eventuale
     * emissione del certificato: minuti, non secondi. Dietro un proxy quella richiesta
     * scadrebbe, e chi guarda resterebbe senza sapere cosa e' successo.
     */
    public static JSONObject startDomainSetup(int domainId) {
        String id = "domain-" + domainId + "-" + System.currentTimeMillis();
        Job j = new Job(id, "configure_domain");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                org.json.JSONObject outcome =
                        org.mail_panel.system.DomainSetup.run(domainId, j);
                j.write("");
                j.write(outcome.optString("note", outcome.optString("error", "")));
                j.write("");
                j.write("--- " + I18n.tr("server.um.x.fullResult") + " ---");
                j.write(outcome.toString(2));
                j.status = outcome.optBoolean("success", false) ? "completed" : "error";
                if (!outcome.optBoolean("success", false))
                    j.errorMessage = outcome.optString("error", I18n.tr("server.um.x.confInterrupted"));
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = String.valueOf(e.getMessage());
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.finishedAt = System.currentTimeMillis();
            }
        }, "configure-domain");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    public static JSONObject startDovecotRegeneration() {
        String id = "dovecot-cfg-" + System.currentTimeMillis();
        Job j = new Job(id, "dovecot_config");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> runDovecotRegeneration(j), "dovecot-config");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    private static void runDovecotRegeneration(Job job) {
        job.status = "running";
        java.nio.file.Path script = null;
        try {
            job.advance(1, 3);
            job.write(I18n.tr("server.um.runDovecotRegeneration.1"));
            job.write("");

            boolean activeBefore = ok("service dovecot status", 15);
            job.write(activeBefore ? I18n.tr("server.um.x.dcBeforeUp") : I18n.tr("server.um.x.dcBeforeDown"));

            String fragment = org.mail_panel.scripts.DovecotConfig.fromPanelConfig().scriptFragment();
            script = java.nio.file.Files.createTempFile("dovecot-config-", ".sh");
            java.nio.file.Files.writeString(script, "#!/bin/sh\nset -e\n" + fragment + "\n");
            java.nio.file.Files.setPosixFilePermissions(script,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));

            job.advance(2, 3);
            job.write("");
            job.write(I18n.tr("server.um.runDovecotRegeneration.2"));
            // La password passa dall'AMBIENTE: non nel testo dello script (che finisce su
            // disco) ne' sulla riga di comando (visibile nell'elenco dei processi).
            Map<String, String> environment = new LinkedHashMap<>();
            try (java.sql.ResultSet rs = org.mail_panel.Main.dbManager.get_data_config()) {
                if (rs.next()) {
                    String pw = org.mail_panel.Main.dbManager.mysqlPassword();
                    if (pw != null && !pw.isEmpty()) environment.put("DB_PASS", pw);
                }
            } catch (Exception ignored) {}
            job.write("    " + (environment.containsKey("DB_PASS")
                    ? I18n.tr("server.um.x.dbPassFromPanel")
                    : I18n.tr("server.um.x.dbPassScript")));
            int code = runLogged(job, "sh " + script, 300, null, environment);
            if (code != 0) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runDovecotRegeneration.3");
                job.write("");
                job.write(job.errorMessage);
                return;
            }

            job.advance(3, 3);
            job.write("");
            job.write(I18n.tr("server.um.x.dcReload33"));
            if (!activeBefore) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.4"));
                job.status = "completed";
                return;
            }
            boolean ok1 = ok("service dovecot reload", 60);
            job.write("    reload: " + (ok1 ? I18n.tr("server.um.x.done") : I18n.tr("server.um.runDovecotRegeneration.5")));
            if (!ok1) ok("service dovecot restart", 60);

            boolean activeAfter = ok("service dovecot status", 20);
            job.write("    " + (activeAfter ? I18n.tr("server.um.x.dcAfterUp") : I18n.tr("server.um.x.dcAfterDown")));
            if (!activeAfter) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runDovecotRegeneration.6");
                return;
            }

            // === Prova funzionale: l'autenticazione funziona ancora? ===
            // Questo passo riscrive dovecot-sql.conf, cioe' il file con cui Dovecot interroga
            // il database per autenticare. "Il servizio e' attivo" non dice niente al riguardo:
            // Dovecot resta attivo anche con credenziali sbagliate, e se ne accorgono gli utenti.
            // Si esegue la STESSA query che il pannello ha appena scritto nella configurazione,
            // con le STESSE credenziali, su una casella vera.
            job.write("");
            job.write(I18n.tr("server.um.x.authTest"));
            String mailbox = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
            if (mailbox.isEmpty()) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.7"));
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runDovecotRegeneration.8"));
                return;
            }
            if (!mailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.9"));
                job.status = "completed";
                return;
            }
            // La stessa condizione della password_query scritta nel file, senza estrarre la
            // password: interessa che la riga ci sia e sia raggiungibile, non il suo contenuto.
            String found = mysqlOut("SELECT COUNT(*) FROM mailboxes WHERE email='" + mailbox + "' AND active=1;").trim();
            if ("1".equals(found)) {
                job.write(I18n.tr("server.um.runDovecotRegeneration.10", java.util.Map.of("mailbox", String.valueOf(mailbox))));
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runDovecotRegeneration.11"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runDovecotRegeneration.12", java.util.Map.of("mailbox", String.valueOf(mailbox), "foundOnes", String.valueOf(found)));
                job.write("    " + I18n.tr("server.um.x.alarm", java.util.Map.of("m", String.valueOf(job.errorMessage))));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (script != null) try { java.nio.file.Files.deleteIfExists(script); } catch (Exception ignored) {}
            job.finishedAt = System.currentTimeMillis();
        }
    }

    /**
     * Esegue una query con le credenziali del pannello, prese dalla configurazione.
     * La password passa dall'ambiente, non dalla riga di comando: altrimenti comparirebbe
     * nell'elenco dei processi visibile a chiunque sul server.
     */
    private static String mysqlOut(String sql) {
        String user = "mailpanel", pass = "", db = "mailserver", host = "127.0.0.1", port = "3306";
        try (java.sql.ResultSet rs = org.mail_panel.Main.dbManager.get_data_config()) {
            if (rs.next()) {
                String u = rs.getString("mysql_user"), p2 = org.mail_panel.Main.dbManager.mysqlPassword();
                String d = rs.getString("mysql_database"), h = rs.getString("mysql_host"), po = rs.getString("mysql_port");
                if (u != null && !u.isBlank()) user = u.trim();
                if (p2 != null) pass = p2;
                if (d != null && !d.isBlank()) db = d.trim();
                if (h != null && !h.isBlank()) host = h.trim();
                if (po != null && po.matches("[0-9]{1,5}")) port = po.trim();
            }
        } catch (Exception ignored) {}
        if (!user.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !host.matches("[A-Za-z0-9._-]{1,128}")) return "";
        String q = sql.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$").replace("`", "\\`");
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c",
                    "mysql -u " + user + " -h " + host + " -P " + port + " -N -B " + db
                    + " -e \"" + q + "\" 2>/dev/null");
            org.mail_panel.util.Shell.applyPath(pb);
            pb.environment().put("MYSQL_PWD", pass);
            Process pr = pb.start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(pr.getInputStream(), StandardCharsets.UTF_8))) {
                String l; while ((l = br.readLine()) != null) sb.append(l).append('\n');
            }
            pr.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            return sb.toString().trim();
        } catch (Exception e) { return ""; }
    }

    /**
     * Query privilegiata come root attraverso il socket unix.
     *
     * Su FreeBSD l'utente root del sistema entra in MySQL dal socket senza password, ed e' il
     * modo con cui il pannello ha creato database e utenti al primo avvio. Serve per leggere
     * mysql.user, che l'utente applicativo non puo' vedere: l'alternativa sarebbe chiedere di
     * eseguire una GRANT a mano, cioe' esattamente il dettare comandi che si vuole evitare.
     */
    private static String mysqlRootOut(String sql) {
        String q = sql.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$").replace("`", "\\`");
        return sh("mysql -u root -N -B -e \"" + q + "\" 2>/dev/null", 30);
    }

    /**
     * Il pannello si collega come utente applicativo, non come root: potrebbe non avere il
     * permesso di leggere mysql.user. La differenza e' decisiva — "nessun account usa
     * mysql_native_password" e "non ho potuto guardare" producono lo stesso vuoto ma
     * significano l'opposto, e prendere il secondo per il primo vuol dire migrare convinti
     * che non ci sia nessuno da salvare.
     */
    private static boolean canReadMysqlUsers() {
        if (!mysqlRootOut("SELECT 1 FROM mysql.user LIMIT 1;").trim().isEmpty()) return true;
        return !mysqlOut("SELECT 1 FROM mysql.user LIMIT 1;").trim().isEmpty();
    }

    /** La lettura di mysql.user, con l'utenza che riesce a farla. */
    private static String usersWithNativePlugin() {
        String q = "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE plugin='mysql_native_password';";
        String r = mysqlRootOut(q);
        return r.isEmpty() ? mysqlOut(q) : r;
    }

    /**
     * Quali plugin di autenticazione sono in uso, con quanti account ciascuno.
     *
     * Dire "nessuno usa mysql_native_password" e' dimostrare un'assenza, e un'assenza si
     * confonde con un errore silenzioso. Elencare i plugin presenti e' una prova positiva:
     * se la somma degli account torna e i nomi sono quelli attesi, la lettura e' avvenuta
     * davvero. Serve anche a vedere sha256_password, deprecato anche lui.
     */
    private static JSONArray pluginInUse() {
        String q = "SELECT CONCAT(plugin,' ',COUNT(*)) FROM mysql.user GROUP BY plugin;";
        String out = mysqlRootOut(q);
        if (out.isEmpty()) out = mysqlOut(q);
        JSONArray arr = new JSONArray();
        for (String line : out.split("\n")) {
            String t = line.trim();
            int sp = t.lastIndexOf(' ');
            if (sp <= 0) continue;
            arr.put(new JSONObject().put("plugin", t.substring(0, sp).trim())
                    .put("accounts", (int) number(t.substring(sp + 1))));
        }
        return arr;
    }

    /** I plugin trovati, in forma leggibile. */
    private static String describePlugin(JSONArray a) {
        if (a.length() == 0) return I18n.tr("server.um.describePlugin.1");
        StringBuilder sb = new StringBuilder();
        int tot = 0;
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.getJSONObject(i);
            if (sb.length() > 0) sb.append(", ");
            sb.append(o.getString("plugin")).append(' ').append(o.getInt("accounts"));
            tot += o.getInt("accounts");
        }
        return I18n.tr("server.um.describePlugin.2", java.util.Map.of("sb", String.valueOf(sb), "tot", String.valueOf(tot)));
    }

    /** Numero da output di comando; 0 se non contiene cifre. */
    private static long number(String v) {
        try { return Long.parseLong(v == null ? "" : v.trim().replaceAll("[^0-9]", "")); }
        catch (Exception e) { return 0L; }
    }

    /** Due frasi in una nota, senza righe vuote se la seconda non c'e'. */
    private static String joinNotes(String a, String b) {
        return b == null || b.isEmpty() ? a : a + "\n\n" + b;
    }

    /**
     * Scarica i pacchetti che l'aggiornamento installera' e ricalcola il piano: il piano
     * dipende da cio' che e' nella CACHE di pkg.
     *
     * Misurato sulla VM FreeBSD 15.1 il 23/10/2026, due volte sullo stesso pacchetto e sullo
     * stesso catalogo, a due minuti di distanza:
     *
     *   senza i file in /var/cache/pkg -> 3 cambi: installa lmdb0, installa mysql97-client,
     *                                     aggiorna postfix-mysql
     *   con i file in /var/cache/pkg   -> 4 cambi: gli stessi PIU' "rimuove lmdb 1.0.2,1"
     *
     * Il controllo di integrita' di pkg trova i conflitti sui file solo quando i pacchetti
     * sono scaricati: senza, `pkg upgrade -n` non puo' vedere che lmdb0 e lmdb si contendono
     * /usr/local/bin/mdb_copy, e la rimozione che ne segue non compare nel piano. Compare
     * durante l'esecuzione, quando il solver rifa' il conto.
     *
     * Non e' un dettaglio: il pannello RIFIUTA i piani che rimuovono pacchetti ("Il piano
     * rimuove pacchetti: pkg rimuoverebbe lmdb 1.0.2,1. Il pannello non esegue aggiornamenti
     * che tolgono pacchetti dal server"), e quel rifiuto veniva scavalcato ogni volta che i
     * pacchetti non erano ancora stati scaricati — cioe' al primo tentativo, sempre. E' la
     * spiegazione del reperto 14: il piano firmato 465385a9d669def8 non conteneva rimozioni e
     * l'esecuzione ha rimosso lmdb.
     *
     * Lo scaricamento non aggiunge lavoro: sono gli stessi byte che servirebbero un istante
     * dopo. Quello che aggiunge e' la possibilita' di fermarsi prima.
     *
     * @return null se pkg farebbe le stesse cose, altrimenti il motivo per fermarsi
     */
    /** Cosa ha deciso fetchAndRecheck: fermarsi (stop non nullo) o andare avanti col piano dato. */
    record Recheck(String stop, JSONObject plan) {}

    private static Recheck fetchAndRecheck(Job job, String fetchCommand, JSONObject approved,
                                              java.util.function.Supplier<JSONObject> recompute) throws Exception {
        job.write("  " + I18n.tr("server.um.x.fetchFirst"));
        int fetchCode = runLogged(job, fetchCommand, 1800);
        if (fetchCode != 0) {
            // Senza i file, il piano resta quello incompleto: lo si dice, non si prosegue
            // facendo finta che il controllo sia stato fatto.
            job.write("  " + I18n.tr("server.um.x.fetchFailed", java.util.Map.of("code", String.valueOf(fetchCode))));
            return new Recheck(I18n.tr("server.um.x.fetchFailed", java.util.Map.of("code", String.valueOf(fetchCode))), approved);
        }
        JSONObject now = recompute.get();
        if (!now.optBoolean("measured")) {
            job.write("  " + I18n.tr("server.um.x.replanFailed"));
            return new Recheck(I18n.tr("server.um.x.replanFailed"), approved);
        }
        String before = PackagePlan.changesSignature(approved), after = PackagePlan.changesSignature(now);
        if (before.equals(after)) {
            job.write("  " + I18n.tr("server.um.x.planUnchanged", java.util.Map.of("f", String.valueOf(after))));
            return new Recheck(null, approved);
        }
        // Cresciuto di sole rimozioni: e' il caso di lmdb -> lmdb0, dove pkg vede il conflitto sui
        // file solo dopo aver scaricato. Se ognuna e' una sostituzione innocua si va avanti col
        // piano nuovo, e le prove si scrivono qui, nel registro del lavoro.
        java.util.List<String> added = onlyAddedRemovals(approved, now);
        if (added != null && !added.isEmpty()) {
            judged(now);
            String mapsNow = PostfixMaps.planBlocker(now);
            if (mapsNow != null) {
                job.write("  " + mapsNow);
                return new Recheck(mapsNow, approved);
            }
            if (removalsRefused(now).isEmpty()) {
                job.write("  " + I18n.tr("server.um.x.planGrewReplacement", java.util.Map.of("list", String.join(", ", added))));
                JSONArray v = now.getJSONArray("replacements");
                for (int i = 0; i < v.length(); i++) {
                    JSONObject x = v.getJSONObject(i);
                    job.write("    " + x.optString("name") + " " + x.optString("version"));
                    for (String e : jsonArrayToList(x.optJSONArray("evidence"))) job.write("      ok  " + e);
                    for (String e : jsonArrayToList(x.optJSONArray("problems"))) job.write("      !!  " + e);
                }
                LOGGER.info("Plan grew after fetching only by replacements, going on: " + before + " -> " + after
                        + "; " + v);
                return new Recheck(null, now);
            }
            // Il motivo dell'arresto e' questo, non il generico «il piano e' cambiato»: dice a chi
            // legge quali rimozioni il pannello non esegue.
            String why = removalsReason(now);
            job.write("  " + why);
            LOGGER.warning("Plan grew after fetching by removals the panel refuses: " + before + " -> " + after + "; " + now.getJSONArray("replacements"));
            return new Recheck(why, approved);
        }
        job.write("  " + I18n.tr("server.um.x.planGrew", java.util.Map.of("before", String.valueOf(before), "after", String.valueOf(after))));
        job.write("  " + I18n.tr("server.um.x.planApproved"));
        for (String r : PackagePlan.changesInLines(approved)) job.write("      " + r);
        job.write("  " + I18n.tr("server.um.x.planNow"));
        for (String r : PackagePlan.changesInLines(now)) job.write("      " + r);
        LOGGER.warning("Plan changed after fetching the packages: " + before + " -> " + after
                + "; approved=" + PackagePlan.changesInLines(approved) + "; now=" + PackagePlan.changesInLines(now));
        return new Recheck(I18n.tr("server.um.x.planGrewStop"), approved);
    }

    /**
     * "nome versione" delle rimozioni che il piano nuovo aggiunge a quello approvato; null se
     * cambia anche altro (un'installazione o un aggiornamento in piu', una versione diversa).
     */
    static java.util.List<String> onlyAddedRemovals(JSONObject approved, JSONObject now) {
        java.util.Set<String> a = changeKeys(approved);
        if (!changeKeys(now).containsAll(a)) return null;
        java.util.List<String> added = new ArrayList<>();
        JSONArray c = now == null ? null : now.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            if (a.contains(changeKey(x))) continue;
            if (!"remove".equals(x.optString("type"))) return null;
            added.add(x.optString("name") + " " + x.optString("from"));
        }
        return added;
    }

    private static java.util.Set<String> changeKeys(JSONObject plan) {
        java.util.Set<String> keys = new java.util.HashSet<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) keys.add(changeKey(c.getJSONObject(i)));
        return keys;
    }

    private static String changeKey(JSONObject x) {
        return x.optString("type") + "|" + x.optString("name") + "|" + x.optString("from") + "|" + x.optString("to");
    }

    /** JSONArray di stringhe -> lista Java, per poterle unire e ciclare. */
    private static java.util.List<String> jsonArrayToList(JSONArray a) {
        java.util.List<String> l = new ArrayList<>();
        for (int i = 0; a != null && i < a.length(); i++) {
            String v = a.optString(i, "");
            if (!v.isEmpty()) l.add(v);
        }
        return l;
    }

    /**
     * I cambiamenti che il pannello NON esegue: rimozioni e retrocessioni.
     *
     * E' una regola del pannello, non un fatto di pkg: un aggiornamento che toglie un
     * pacchetto da un server di posta, o che ne riporta indietro la versione, va deciso da
     * una persona che sa chi lo usa. Stava scritta in un punto solo — la scheda di un
     * pacchetto protetto — e mancava negli altri due lavori che eseguono un piano.
     *
     * Misurato sulla VM FreeBSD 15.1 il 23/10/2026, sulla stessa macchina e sullo stesso
     * pacchetto: l'aggiornamento guidato di postfix-mysql si ferma («Il piano rimuove
     * pacchetti: pkg rimuoverebbe lmdb 1.0.2,1»), mentre la manutenzione completa dava
     * runnable=true su un piano che conteneva «rimuove lmdb 1.0.2,1» e nessun impedimento.
     * Due risposte opposte alla stessa domanda, e quella permissiva stava sul pulsante
     * «Manutenzione completa», cioe' su quello che si preme per aggiornare tutto.
     *
     * @return {@code removes} e {@code downgrades}: i cambiamenti, gia' in forma leggibile
     */
    static JSONObject destructiveChanges(JSONObject plan) {
        JSONArray removed = new JSONArray(), downgrades = new JSONArray();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String n = x.optString("name");
            switch (x.optString("type")) {
                case "remove" -> removed.put(n + " " + x.optString("from"));
                case "downgrade" -> downgrades.put(n + " " + x.optString("from") + " -> " + x.optString("to"));
                default -> { }
            }
        }
        return new JSONObject().put("removes", removed).put("downgrades", downgrades);
    }

    /**
     * Il piano col giudizio su ogni rimozione (PackageReplacement), messo una volta sola nella
     * chiave "replacements": lo leggono la regola qui sotto, la pagina e il registro del lavoro.
     */
    static JSONObject judged(JSONObject plan) {
        if (plan == null || plan.has("replacements")) return plan;
        if (destructiveChanges(plan).getJSONArray("removes").isEmpty()) return plan.put("replacements", new JSONArray());
        return plan.put("replacements", PackageReplacement.judgePlan(plan));
    }

    /** Il giudizio su ogni rimozione del piano, per "nome versione". */
    private static Map<String, JSONObject> verdictsByKey(JSONObject plan) {
        Map<String, JSONObject> m = new LinkedHashMap<>();
        JSONArray v = plan == null ? null : plan.optJSONArray("replacements");
        for (int i = 0; v != null && i < v.length(); i++) {
            JSONObject x = v.getJSONObject(i);
            m.put(x.optString("name") + " " + x.optString("version"), x);
        }
        return m;
    }

    /**
     * "nome versione" delle rimozioni del piano che il pannello non esegue: tutte quelle che non
     * sono una sostituzione innocua. Qualcosa che resta installato sparirebbe o smetterebbe di
     * funzionare, o non si e' potuto misurare (una rimozione senza giudizio conta cosi'). Non c'e'
     * modo di confermarle: vedi PackageReplacement.
     */
    static java.util.List<String> removalsRefused(JSONObject plan) {
        Map<String, JSONObject> v = verdictsByKey(plan);
        java.util.List<String> refused = new ArrayList<>();
        for (String r : jsonArrayToList(destructiveChanges(plan).getJSONArray("removes"))) {
            JSONObject x = v.get(r);
            if (x == null || !x.optBoolean("safe")) refused.add(r);
        }
        return refused;
    }

    /** Il motivo per le rimozioni che fermano il piano, o null se non ce ne sono. */
    static String removalsReason(JSONObject plan) {
        java.util.List<String> refused = removalsRefused(plan);
        return refused.isEmpty() ? null
                : I18n.tr("server.um.x.planRemovesNever", java.util.Map.of("list", String.join(", ", refused)));
    }

    /**
     * Il motivo per cui un piano non si esegue, o null se non tocca niente in quel modo.
     * Lo chiedono i tre lavori che eseguono un piano, cosi' la regola e' una sola.
     *
     * Una rimozione passa solo se e' una sostituzione innocua (il giudizio sta nel piano, vedi
     * judged); le retrocessioni non passano mai.
     */
    static String destructivePlanReason(JSONObject plan) {
        JSONObject d = destructiveChanges(plan);
        java.util.List<String> reasons = new ArrayList<>();
        String removals = removalsReason(plan);
        if (removals != null) reasons.add(removals);
        // Un piano che puo' cambiare la libreria di un tipo di mappa di Postfix, se una mappa di quel
        // tipo non si potrebbe rigenerare uguale a prima (PostfixMaps).
        String maps = PostfixMaps.planBlocker(plan);
        if (maps != null) reasons.add(maps);
        if (!d.getJSONArray("downgrades").isEmpty())
            reasons.add(I18n.tr("server.um.x.planDowngrades", java.util.Map.of("list",
                    String.valueOf(String.join(", ", jsonArrayToList(d.getJSONArray("downgrades")))))));
        return reasons.isEmpty() ? null : String.join(" ", reasons);
    }

    /** I nomi delle divergenze, per il messaggio d'errore di un lavoro. */
    private static String divergenceList(JSONArray divergences) {
        java.util.List<String> names = new ArrayList<>();
        for (int i = 0; i < divergences.length(); i++) names.add(divergences.getJSONObject(i).optString("name"));
        return String.join(", ", names);
    }

    /** Il messaggio d'errore di un lavoro che ha trovato cambiamenti fuori dal piano. */
    private static String divergenceMessage(JSONArray d) {
        return d.length() == 1
            ? I18n.tr("server.um.x.divergenceFound.one", java.util.Map.of("list", String.valueOf(divergenceList(d))))
            : I18n.tr("server.um.x.divergenceFound.other", java.util.Map.of(
                    "n", String.valueOf(d.length()), "list", String.valueOf(divergenceList(d))));
    }

    /**
     * Confronta l'inventario dei pacchetti con quello di prima dell'aggiornamento e scrive
     * nel log del lavoro che cosa e' cambiato DAVVERO.
     *
     * Sta in un punto solo perche' la fanno due lavori (l'aggiornamento guidato e la
     * manutenzione completa) e una decisione scritta due volte diventa due decisioni.
     *
     * @param chi per il registro del pannello: quale lavoro ha trovato la divergenza
     * @return le divergenze, vuote se tutto cio' che e' cambiato era nel piano
     */
    private static JSONArray compareWithInventory(Job job, Map<String, String> before,
                                                     JSONObject plan, String who) {
        JSONArray outside = PackagePlan.divergences(before,
                PackagePlan.versionsOnly(PackagePlan.installed()), plan);
        job.write("  " + I18n.tr("server.um.x.divergenceHeader"));
        if (outside.isEmpty()) {
            job.write("    ok  " + I18n.tr("server.plan.d.none"));
            return outside;
        }
        for (int i = 0; i < outside.length(); i++)
            job.write("    NO  " + PackagePlan.divergenceInLine(outside.getJSONObject(i)));
        job.write("  " + I18n.tr("server.um.x.divergenceNote"));
        // Fuori dal log del lavoro, che vive in memoria e se ne va col pannello: un
        // cambiamento che nessuno ha approvato su un server di posta deve restare scritto.
        // Solo nomi di pacchetto e versioni, nessun segreto (r19).
        LOGGER.warning(who + ": " + outside.length() + " change(s) outside the signed plan: " + outside);
        return outside;
    }

    /**
     * La famiglia MySQL che la versione NEL REPOSITORY di un pacchetto pretende, quando e'
     * diversa da quella installata; null se non c'e' conflitto.
     *
     * Sta in un metodo solo perche' lo usano sia il preflight sia il piano: se il vincolo
     * vivesse in un posto solo, il piano proporrebbe un passo che il preflight poi rifiuta,
     * e una guida che propone cio' che poi nega non guida niente.
     */
    static String mysqlFamilyConflict(String name) {
        if (!isValidName(name)) return null;
        String installed = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        if (installed.isEmpty()) return null;
        // Si guarda TUTTA la famiglia, non il solo pacchetto nominato: php84 non dipende da
        // MySQL, ma php84-mysqli e php84-pdo_mysql si', e vengono aggiornati insieme a lui.
        // Controllare solo il nome scritto nel passo lascerebbe passare esattamente la stessa
        // trappola di postfix, con la differenza che qui nessuno la vedrebbe arrivare.
        for (String member : familyMembers(name)) {
            if (!isValidName(member)) continue;
            String deps = sh("pkg rquery -U %dn " + member + " 2>/dev/null", 30);
            Matcher m = Pattern.compile("mysql([0-9]+)-client").matcher(deps);
            if (!m.find()) continue;
            String required = "mysql" + m.group(1) + "-client";
            if (!required.equals(installed)) return required;
        }
        return null;
    }

    /** Una riga del referto di controlli: esito, cosa si e' controllato, perche' conta. */
    private static void addCheck(JSONArray a, String id, String label, String level, String detail) {
        a.put(new JSONObject().put("id", id).put("label", label)
                .put("level", level).put("detail", detail));
    }

    // ===================== migrazione MySQL 8.0 -> 8.4 =====================

    /**
     * Controlli preliminari per il passaggio a MySQL 8.4, tutti in SOLA LETTURA.
     *
     * Su questa macchina la migrazione ha un ostacolo che sul pannello web non esisteva:
     * Postfix e Dovecot leggono le caselle virtuali dal database attraverso la LIBRERIA di
     * mysql80-client. Se i pacchetti che il repository fornisce sono compilati contro la 8.0,
     * sostituire quella libreria li lascerebbe senza, e il server di posta non ripartirebbe.
     * Non e' una cosa da scoprire a meta' migrazione: si chiede a pkg prima.
     */
    public static JSONObject mysql84Preflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean block = false;

        // --- 1. Da dove si parte ---
        String srvPkg = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        String cliPkg = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        r.put("srvPkg", srvPkg).put("cliPkg", cliPkg);
        if (srvPkg.isEmpty()) {
            addCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "block",
                    I18n.tr("server.um.mysql84Preflight.2"));
            block = true;
        } else if (srvPkg.startsWith("mysql84")) {
            addCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "ok",
                    I18n.tr("server.um.mysql84Preflight.3", java.util.Map.of("srvPkg", String.valueOf(srvPkg))));
            r.put("alreadyDone", true);
        } else {
            String v = sh("pkg query %v " + srvPkg, 20);
            addCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "ok",
                    I18n.tr("server.um.mysql84Preflight.4", java.util.Map.of("srvPkg", String.valueOf(srvPkg), "v", String.valueOf(v), "cliPkg", String.valueOf(cliPkg))));
        }

        // --- 2. La destinazione esiste ---
        String srv84 = sh("pkg rquery -U %v mysql84-server 2>/dev/null", 30);
        String cli84 = sh("pkg rquery -U %v mysql84-client 2>/dev/null", 30);
        r.put("target", srv84);
        if (srv84.isEmpty() || cli84.isEmpty()) {
            addCheck(checks, "target", I18n.tr("server.um.mysql84Preflight.5"), "block",
                    I18n.tr("server.um.mysql84Preflight.6"));
            block = true;
        } else {
            addCheck(checks, "target", I18n.tr("server.um.mysql84Preflight.5"), "ok",
                    I18n.tr("server.um.x.my84Avail", java.util.Map.of("s", String.valueOf(srv84), "c", String.valueOf(cli84))));
        }

        // --- 3. IL PUNTO CRITICO: chi usa la libreria del client, e cosa pretende dal repository ---
        JSONArray dependents = new JSONArray();
        boolean conflict = false;
        if (!cliPkg.isEmpty()) {
            for (String line : sh("pkg query %rn " + cliPkg + " 2>/dev/null", 30).split("\n")) {
                String d = line.trim();
                if (!isValidName(d) || d.equals(srvPkg)) continue;
                // Cosa pretende la versione del repository di questo dipendente: se nomina
                // ancora mysql80-client, la 8.4 non lo soddisfa e il pacchetto va ricostruito.
                String deps = sh("pkg rquery -U %dn " + d + " 2>/dev/null", 30);
                boolean wants80 = deps.contains(cliPkg);
                boolean wants84 = deps.contains("mysql84-client");
                if (wants80 && !wants84) conflict = true;
                dependents.put(new JSONObject().put("name", d)
                        .put("requires", wants84 ? "mysql84-client" : (wants80 ? cliPkg : I18n.tr("server.um.mysql84Preflight.7")))
                        .put("compatible", !wants80 || wants84));
            }
        }
        r.put("dependents", dependents).put("libraryConflict", conflict);
        if (conflict) {
            addCheck(checks, "library", I18n.tr("server.um.mysql84Preflight.8"), "block",
                    I18n.tr("server.um.mysql84Preflight.9", java.util.Map.of("cliPkg", String.valueOf(cliPkg))));
            block = true;
        } else {
            addCheck(checks, "library", I18n.tr("server.um.mysql84Preflight.8"),
                    dependents.length() == 0 ? "ok" : "review",
                    dependents.length() == 0
                        ? I18n.tr("server.um.mysql84Preflight.10", java.util.Map.of("cliPkg", String.valueOf(cliPkg)))
                        : I18n.tr("server.um.mysql84Preflight.11", java.util.Map.of("length", String.valueOf(dependents.length()))));
        }

        // --- 4. Il processo in esecuzione e' quello del pacchetto? ---
        boolean su = ok("service mysql-server status", 15);
        String runVer = su ? mysqlOut("SELECT VERSION();") : "";
        if (!su) {
            addCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), "block",
                    I18n.tr("server.um.mysql84Preflight.12"));
            block = true;
        } else if (runVer.isEmpty()) {
            addCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), "block",
                    I18n.tr("server.um.mysql84Preflight.13"));
            block = true;
        } else {
            String pkgVer = sh("pkg query %v " + srvPkg, 20).split("[_,]")[0];
            boolean matches = pkgVer.isEmpty() || runVer.startsWith(pkgVer);
            addCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), matches ? "ok" : "block",
                    matches ? I18n.tr("server.um.mysql84Preflight.14", java.util.Map.of("runVer", String.valueOf(runVer)))
                             : I18n.tr("server.um.mysql84Preflight.15", java.util.Map.of("runVer", String.valueOf(runVer), "pkgVer", String.valueOf(pkgVer))));
            if (!matches) block = true;
            r.put("runningVersion", runVer);
        }

        // --- 5. my.cnf: opzioni rimosse nella 8.4 ---
        JSONObject cm = mysqlCompatibility();
        JSONArray issues = cm.optJSONArray("issues");
        if (issues != null && issues.length() > 0) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < issues.length(); i++) sb.append(issues.getJSONObject(i).getString("option")).append(' ');
            addCheck(checks, "mycnf", I18n.tr("server.um.mysql84Preflight.16"), "block",
                    I18n.tr("server.um.mysql84Preflight.17", java.util.Map.of("p", String.valueOf(sb.toString().trim()))));
            block = true;
        } else {
            addCheck(checks, "mycnf", I18n.tr("server.um.mysql84Preflight.16"), "ok",
                    I18n.tr("server.um.mysql84Preflight.18"));
        }

        // --- 6. Account con il plugin che la 8.4 non attiva piu' ---
        JSONArray nativeOnes = new JSONArray();
        boolean readable = su && !runVer.isEmpty() && canReadMysqlUsers();
        if (readable) {
            for (String l : usersWithNativePlugin().split("\n")) {
                if (!l.trim().isEmpty()) nativeOnes.put(l.trim());
            }
        }
        r.put("nativePasswordUsers", nativeOnes).put("userTableReadable", readable);
        if (readable) r.put("authPlugins", pluginInUse());
        if (!readable) {
            addCheck(checks, "auth", I18n.tr("server.um.mysql84Preflight.19"), "block",
                    I18n.tr("server.um.mysql84Preflight.20"));
            block = true;
        } else {
            addCheck(checks, "auth", I18n.tr("server.um.mysql84Preflight.19"), nativeOnes.length() > 0 ? "review" : "ok",
                    nativeOnes.length() == 0
                        ? I18n.tr("server.um.mysql84Preflight.21", java.util.Map.of("p", String.valueOf(describePlugin(pluginInUse()))))
                        : I18n.tr("server.um.x.nativeUsers", java.util.Map.of("n", String.valueOf(nativeOnes.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(nativeOnes))))));
        }

        // --- 7. Spazio per la copia fredda ---
        String dataDir = sh("grep -E '^[[:space:]]*datadir[[:space:]]*=' /usr/local/etc/mysql/my.cnf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' '", 15);
        if (dataDir.isEmpty()) dataDir = "/var/db/mysql";
        long dirKb = number(sh("du -sk " + dataDir + " 2>/dev/null | awk '{print $1}'", 120));
        long freeKb = number(sh("df -k /var/db 2>/dev/null | tail -1 | awk '{print $4}'", 20));
        long needed = (long) (dirKb * 1.15) + 512L * 1024L;
        r.put("dataDir", dataDir).put("dataDirMb", dirKb / 1024).put("freeMb", freeKb / 1024);
        if (dirKb <= 0 || freeKb < needed) {
            addCheck(checks, "space", I18n.tr("server.um.mysql84Preflight.22"), "block",
                    I18n.tr("server.um.mysql84Preflight.23", java.util.Map.of("p", String.valueOf((needed / 1024)), "p2", String.valueOf((freeKb / 1024)))));
            block = true;
        } else {
            addCheck(checks, "space", I18n.tr("server.um.mysql84Preflight.22"), "ok",
                    I18n.tr("server.um.x.dataDirSpace", java.util.Map.of("dir", String.valueOf(dataDir), "mb", String.valueOf((dirKb / 1024)), "free", String.valueOf((freeKb / 1024)))));
        }

        // --- 8. Inventario, per riconfrontare a fine migrazione ---
        long schemes = 0, tables = 0, mailboxes = 0;
        if (su && !runVer.isEmpty()) {
            schemes = number(mysqlOut("SELECT COUNT(*) FROM information_schema.schemata;"));
            tables = number(mysqlOut("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');"));
            mailboxes = number(mysqlOut("SELECT COUNT(*) FROM mailboxes;"));
        }
        r.put("schemaCount", schemes).put("tableCount", tables).put("mailboxCount", mailboxes);
        addCheck(checks, "inventory", I18n.tr("server.um.mysql84Preflight.24"), schemes > 0 ? "ok" : "review",
                schemes > 0 ? I18n.tr("server.um.mysql84Preflight.25", java.util.Map.of("schemas", String.valueOf(schemes), "tables", String.valueOf(tables), "mailboxes", String.valueOf(mailboxes)))
                           : I18n.tr("server.um.mysql84Preflight.26"));

        // --- 9. Cosa si ferma, e per quanto ---
        addCheck(checks, "services", I18n.tr("server.um.x.servicesInvolved"), "review",
                I18n.tr("server.um.mysql84Preflight.27"));

        r.put("success", true).put("checks", checks)
         .put("canProceed", !block && !r.optBoolean("alreadyDone", false)).put("blocked", block);
        return r;
    }

    private static final String MYSQL84_BACKUP = "/var/db/mailpanel/mysql84";

    /** Inserisce una direttiva subito dopo [mysqld], se non c'e' gia'. Scrittura atomica. */
    private static boolean addMysqldDirective(String line) {
        java.nio.file.Path f = Paths.get("/usr/local/etc/mysql/my.cnf");
        try {
            java.util.List<String> lines = Files.readAllLines(f);
            String key = line.split("=")[0].trim();
            for (String r : lines) if (!r.trim().startsWith("#") && r.trim().startsWith(key)) return true;
            java.util.List<String> fresh = new ArrayList<>();
            boolean put = false;
            for (String r : lines) {
                fresh.add(r);
                if (!put && r.trim().equalsIgnoreCase("[mysqld]")) {
                    fresh.add("# aggiunta dal pannello: nella 8.4 mysql_native_password non e' attivo di default");
                    fresh.add(line);
                    put = true;
                }
            }
            if (!put) return false;
            java.nio.file.Path tmp = Paths.get("/tmp/my.cnf.mailpanel-84");
            Files.write(tmp, fresh);
            return ok("mv " + tmp + " /usr/local/etc/mysql/my.cnf", 30)
                && ok("chmod 644 /usr/local/etc/mysql/my.cnf", 15);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not add " + line + " to my.cnf", e);
            return false;
        }
    }

    /** File e byte logici di un albero: si misura con stat, MAI con du. */
    private static long[] measure(String dir) {
        long file = number(sh("find " + dir + " -type f 2>/dev/null | wc -l", 120));
        long logicalBytes = number(sh("find " + dir + " -type f -exec stat -f %z {} + 2>/dev/null "
                + "| awk '{s+=$1} END {print s+0}'", 120));
        return new long[]{file, logicalBytes};
    }

    /**
     * Avvia un lavoro sui pacchetti nel suo thread, dopo aver preso il turno: uno alla volta
     * (vedi PackageQueue). Se il turno e' di un altro, o c'e' l'elenco di un lavoro che non si
     * e' chiuso, il lavoro non parte e la risposta dice perche'.
     */
    /**
     * Un thread di lavoro che scrive nella lingua di chi l'ha avviato: il ThreadLocal di I18n non
     * passa da solo ai thread nuovi, e senza questo il log di un lavoro uscirebbe sempre in italiano.
     */
    private static Thread localizedThread(Runnable work, String name) {
        return new Thread(I18n.withCurrent(work), name);
    }

    /** Il thread di un Job: come sopra, e con la fine scritta comunque (withEndMarked). */
    private static Thread localizedThread(Job j, Runnable work, String name) {
        return localizedThread(withEndMarked(j, work), name);
    }

    /**
     * Il lavoro di un Job, con la fine scritta comunque quando il thread esce.
     *
     * Un esito diventa visibile solo con la fine scritta (Job.visibleStatus): un lavoro che
     * desse un esito e uscisse senza scrivere la fine — per un ritorno dimenticato, o per
     * un'eccezione fuori dal suo try — resterebbe "running" per sempre agli occhi della
     * pagina. Ogni lavoro scrive gia' la propria fine come ultima cosa; questo e' il
     * pavimento, e non sposta la fine di chi l'ha scritta.
     */
    static Runnable withEndMarked(Job j, Runnable work) {
        return () -> {
            try { work.run(); }
            finally { j.markFinished(); }
        };
    }

    /**
     * Il lavoro con la sua via di ritorno (PackageWayBack): il boot environment prima, e dopo la
     * pulizia (tolto se nessun pacchetto e' cambiato, altrimenti i piu' vecchi). Se il boot
     * environment non si crea su un sistema che li ha, il lavoro finisce in errore senza partire.
     */
    static Runnable withWayBack(Job j, String kind, Runnable work) {
        return () -> {
            PackageWayBack.Prepared wb;
            try {
                wb = PackageWayBack.before(j::write, kind);
            } catch (IllegalStateException e) {
                j.status = "error";
                j.errorMessage = e.getMessage();
                j.write(e.getMessage());
                return;
            }
            j.write("");
            try { work.run(); }
            finally { PackageWayBack.after(j::write, wb); }
        };
    }

    private static JSONObject startOnTurn(String id, Job j, String description, String threadName, Runnable work) {
        String refusal = PackageQueue.take(id, description);
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        // Prima di tutto la via di ritorno: un boot environment, o il lavoro non tocca niente.
        work = withWayBack(j, threadName, work);
        // Ogni lavoro del turno puo' aver tolto e rimesso protezioni, o aggiornato pacchetti
        // protetti (che cosi' perdono l'annotazione): la traccia si rimette in pari alla fine.
        work = withLockTrace(work);
        work = withWebmailOwnership(work);
        JOBS.put(id, j);
        PackageQueue.start(id, threadName, withEndMarked(j, work));
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    public static JSONObject startMysql84Migration() {
        String id = "my84-" + System.currentTimeMillis();
        Job j = new Job(id, "mysql84_migration");
        return startOnTurn(id, j, I18n.tr("server.um.x.jobMy84"), "mysql84-migration", () -> runMigration84(j));
    }

    /**
     * Migrazione a MySQL 8.4.
     *
     * Rispetto alla stessa operazione sul pannello web ci sono due differenze che vengono
     * dalla natura di questa macchina: Postfix e Dovecot leggono le caselle dal database
     * attraverso la libreria client, quindi si fermano PRIMA e si riverificano DOPO; e la
     * verifica finale non si accontenta di "il servizio e' attivo" ma chiede a Postfix e a
     * Dovecot di risolvere davvero una casella. Un servizio avviato che non legge piu' gli
     * utenti e' il modo peggiore di sembrare a posto.
     */
    private static void runMigration84(Job job) {
        job.status = "running";
        final int TOT = 12;
        String backupDir = "", dataDir = "/var/db/mysql", srvPkg = "", cliPkg = "";
        boolean mysqlStopped = false, replacedPackages = false, reachedEnd = false;
        boolean postfixWasActive = false, dovecotWasActive = false;
        // Lo stato dei servizi PRIMA: senza questo, "non attivo adesso" verrebbe preso per
        // "caduto adesso" anche per chi non era mai partito.
        Map<String, Boolean> servicesBefore = servicesState();
        long schemesBefore = 0, tablesBefore = 0, mailboxesBefore = 0;
        String testMailbox = "";
        try {
            job.advance(1, TOT);
            job.write("=== " + I18n.tr("server.um.x.jobMy84Title") + " ===");
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = mysql84Preflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("alreadyDone", false)
                        ? I18n.tr("server.um.runMigration84.2") : I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.write("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            srvPkg = pf.optString("srvPkg", "");
            cliPkg = pf.optString("cliPkg", "");
            dataDir = pf.optString("dataDir", "/var/db/mysql");
            schemesBefore = pf.optLong("schemaCount", 0);
            tablesBefore = pf.optLong("tableCount", 0);
            mailboxesBefore = pf.optLong("mailboxCount", 0);
            testMailbox = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
            job.write("  " + srvPkg + " + " + cliPkg + " -> mysql84-server + mysql84-client");
            job.write(I18n.tr("server.um.runMigration84.5", java.util.Map.of("schemasBefore", String.valueOf(schemesBefore), "tablesBefore", String.valueOf(tablesBefore), "mailboxesBefore", String.valueOf(mailboxesBefore))));
            job.write("  " + (testMailbox.isEmpty()
                    ? I18n.tr("server.um.x.testBoxNone")
                    : I18n.tr("server.um.x.testBox", java.util.Map.of("mailbox", String.valueOf(testMailbox)))));

            job.advance(2, TOT);
            job.write("");
            job.write("[2/" + TOT + "] " + I18n.tr("server.um.x.stopPfDc"));
            postfixWasActive = ok("service postfix status", 20);
            dovecotWasActive = ok("service dovecot status", 20);
            if (postfixWasActive) { ok("service postfix stop", 60); job.write(I18n.tr("server.um.runMigration84.6")); }
            else job.write(I18n.tr("server.um.runMigration84.7"));
            if (dovecotWasActive) { ok("service dovecot stop", 60); job.write(I18n.tr("server.um.runMigration84.8")); }
            else job.write(I18n.tr("server.um.runMigration84.9"));

            job.advance(3, TOT);
            job.write("");
            job.write("[3/" + TOT + "] " + I18n.tr("server.um.x.stopMysql"));
            ok("service mysql-server stop", 120);
            boolean down = false;
            for (int i = 0; i < 120; i++) {
                if (!ok("service mysql-server status", 10) && !ok("pgrep -q mysqld", 10)) { down = true; break; }
                try { Thread.sleep(1000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            if (!down) throw new IllegalStateException("MySQL did not stop: a copy taken while the server is running could not be restored");
            mysqlStopped = true;
            job.write("    " + I18n.tr("server.um.x.stoppedConfirmed"));

            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.10", java.util.Map.of("total", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date for the copy");
            backupDir = MYSQL84_BACKUP + "/" + ts;
            if (!ok("mkdir -p " + backupDir + "/pkg", 30)) throw new IllegalStateException("cannot create " + backupDir);
            ok("cp -p /usr/local/etc/mysql/my.cnf " + backupDir + "/my.cnf", 30);
            ok("printf '%s\\n%s\\n' " + srvPkg + " " + cliPkg + " > " + backupDir + "/packages.txt", 20);
            job.write(I18n.tr("server.um.runMigration84.11"));
            ok("pkg fetch -y -o " + backupDir + "/pkg " + srvPkg + " " + cliPkg + " >/dev/null 2>&1", 600);
            job.write("    " + I18n.tr("server.um.x.pkgsKept", java.util.Map.of("n", String.valueOf(number(sh("find " + backupDir + "/pkg -name '*.pkg' | wc -l", 30))))));

            long[] before = measure(dataDir);
            job.write("    " + I18n.tr("server.um.x.copying", java.util.Map.of("dir", String.valueOf(dataDir), "n", String.valueOf(before[0]), "mb", String.valueOf((before[1] / 1024 / 1024)))));
            String cpOut = sh("cp -Rp " + dataDir + " " + backupDir + "/datadir 2>&1; echo EXIT=$?", 1800);
            int cpCode = -1;
            for (String l : cpOut.split("\n")) {
                if (l.startsWith("EXIT=")) { cpCode = (int) number(l); continue; }
                if (!l.trim().isEmpty()) job.write("      cp: " + l);
            }
            if (cpCode != 0) throw new IllegalStateException("cp exited with code " + cpCode);
            ok("sync", 120);
            long[] after = measure(backupDir + "/datadir");
            if (after[0] != before[0] || after[1] != before[1]) {
                throw new IllegalStateException("the copy does not match: " + after[0] + " files / " + after[1]
                        + " bytes against " + before[0] + " / " + before[1]);
            }
            if (!ok("test -f " + backupDir + "/datadir/ibdata1", 15)) {
                throw new IllegalStateException("ibdata1 is missing from the copy: it is not a data folder that can be restored");
            }
            ok("printf '%s\\n%s\\n' " + before[0] + " " + before[1] + " > " + backupDir + "/manifest.txt", 20);
            job.write(I18n.tr("server.um.runMigration84.12", java.util.Map.of("p", String.valueOf(after[0]), "p2", String.valueOf((after[1] / 1024 / 1024)))));
            job.write(I18n.tr("server.um.runMigration84.13", java.util.Map.of("backupDir", String.valueOf(backupDir))));

            job.advance(5, TOT);
            job.write("");
            job.write("[5/" + TOT + "] " + I18n.tr("server.um.x.replacingPkgs"));
            ok("pkg unlock -y " + srvPkg, 30);
            ok("pkg unlock -y " + cliPkg, 30);
            String del = sh("pkg delete -f -y " + srvPkg + " " + cliPkg + " 2>&1", 300);
            for (String l : del.split("\n")) if (!l.trim().isEmpty()) job.write("    " + l);
            replacedPackages = true;
            String ins = sh("pkg install -y mysql84-server mysql84-client 2>&1", 900);
            for (String l : ins.split("\n")) if (!l.trim().isEmpty()) job.write("    " + l);
            if (!ok("pkg info -e mysql84-server", 20) || !ok("pkg info -e mysql84-client", 20)) {
                throw new IllegalStateException("the 8.4 installation did not succeed: the data is intact, the copy is in " + backupDir);
            }

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.14", java.util.Map.of("total", String.valueOf(TOT))));
            boolean lost = false;
            for (String d : new String[]{"postfix-mysql", "dovecot-mysql"}) {
                boolean c = ok("pkg info -e " + d, 20);
                job.write("    " + d + ": " + (c ? I18n.tr("server.um.x.present") : I18n.tr("server.um.x.missing")));
                if (!c) lost = true;
            }
            if (lost) job.write(I18n.tr("server.um.runMigration84.15"));

            job.advance(7, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.16", java.util.Map.of("total", String.valueOf(TOT))));
            if (ok("test -f " + backupDir + "/my.cnf", 15)) {
                ok("cp -p " + backupDir + "/my.cnf /usr/local/etc/mysql/my.cnf", 30);
                ok("chmod 644 /usr/local/etc/mysql/my.cnf", 15);
                job.write("    " + I18n.tr("server.um.x.mycnfRestored"));
            }
            JSONArray nativeOnes = pf.optJSONArray("nativePasswordUsers");
            if (nativeOnes != null && nativeOnes.length() > 0) {
                job.write("    " + I18n.tr("server.um.x.nativeAdd", java.util.Map.of("n", String.valueOf(nativeOnes.length()))));
                // In Java riga per riga, NON con sed: il sed di BSD non interpreta \n nella
                // sostituzione e inserirebbe la lettera "n" al posto di un a capo, producendo
                // un my.cnf malformato proprio nel passo che serve a non far restare fuori
                // nessun account. Su questa macchina il ramo non scatta, ma un difetto che non
                // si vede oggi e' solo un difetto che aspetta.
                job.write("    " + (addMysqldDirective("mysql-native-password=ON")
                        ? I18n.tr("server.um.runMigration84.17") : I18n.tr("server.um.runMigration84.18")));
            }

            job.advance(8, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.19", java.util.Map.of("total", String.valueOf(TOT))));
            String bin = sh("which mysqld 2>/dev/null", 15);
            if (bin.isEmpty()) bin = "/usr/local/libexec/mysqld";
            String val = sh("su -m mysql -c '" + bin + " --validate-config' 2>&1", 120);
            if (!val.isEmpty()) {
                for (String l : val.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
                if (val.toLowerCase().matches("(?s).*(error|unknown variable|aborting).*")) {
                    throw new IllegalStateException("mysqld 8.4 does not accept my.cnf: the data was not touched, "
                            + "the copy is in " + backupDir);
                }
            } else job.write("    " + I18n.tr("server.um.x.acceptedClean"));

            job.advance(9, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.21", java.util.Map.of("total", String.valueOf(TOT))));
            ok("service mysql-server start", 120);
            String newVer = "";
            for (int i = 0; i < 200; i++) {
                newVer = mysqlOut("SELECT VERSION();").trim();
                if (!newVer.isEmpty()) break;
                try { Thread.sleep(3000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                if (i % 5 == 4) job.write(I18n.tr("server.um.runMigration84.22", java.util.Map.of("p", String.valueOf(((i + 1) * 3)))));
            }
            if (newVer.isEmpty()) throw new IllegalStateException("MySQL 8.4 does not answer: the copy is in " + backupDir);
            mysqlStopped = false;
            job.write("    SELECT VERSION() = " + newVer);
            if (!newVer.startsWith("8.4")) throw new IllegalStateException("the running version is " + newVer + ", not an 8.4");

            job.advance(10, TOT);
            job.write("");
            job.write("[10/" + TOT + "] " + I18n.tr("server.um.x.inventory"));
            long sd = number(mysqlOut("SELECT COUNT(*) FROM information_schema.schemata;"));
            long td = number(mysqlOut("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');"));
            long cd = number(mysqlOut("SELECT COUNT(*) FROM mailboxes;"));
            job.write(I18n.tr("server.um.runMigration84.23", java.util.Map.of("schemasBefore", String.valueOf(schemesBefore), "schemasAfter", String.valueOf(sd), "tablesBefore", String.valueOf(tablesBefore), "tablesAfter2", String.valueOf(td), "mailboxesBefore", String.valueOf(mailboxesBefore), "mailboxesAfter", String.valueOf(cd))));
            boolean inventoryOk = sd >= schemesBefore && td >= tablesBefore && cd >= mailboxesBefore;
            if (!inventoryOk) job.write(I18n.tr("server.um.runMigration84.24", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            else job.write("    " + I18n.tr("server.um.x.inventoryIntact"));

            job.advance(11, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.25", java.util.Map.of("total", String.valueOf(TOT))));
            boolean l1 = ok("pkg lock -y mysql84-server", 30), l2 = ok("pkg lock -y mysql84-client", 30);
            job.write("    " + I18n.tr("server.um.x.protect84", java.util.Map.of("s", String.valueOf(l1 ? "ok" : I18n.tr("server.um.x.failedF")), "c", String.valueOf(l2 ? "ok" : I18n.tr("server.um.x.failedF")))));
            if (postfixWasActive) { ok("service postfix start", 120); job.write("    postfix: " + (ok("service postfix status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26"))); }
            if (dovecotWasActive) { ok("service dovecot start", 120); job.write("    dovecot: " + (ok("service dovecot status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26"))); }

            job.advance(12, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.27", java.util.Map.of("total", String.valueOf(TOT))));
            // "Il servizio e' attivo" non basta: dopo aver sostituito la libreria client il
            // punto e' se Postfix e Dovecot RIESCONO ANCORA a interrogare il database.
            boolean testOk = true;
            // L'indirizzo finisce dentro un comando: si accetta solo cio' che e' davvero un
            // indirizzo. Viene dal database e non da fuori, ma la convalida costa una riga e
            // nel job di Dovecot c'era gia': trattare due volte la stessa cosa in due modi
            // diversi e' il modo in cui una svista sopravvive.
            if (!testMailbox.isEmpty()
                    && !testMailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.write(I18n.tr("server.um.runMigration84.28"));
                testMailbox = "";
            }
            if (testMailbox.isEmpty()) {
                job.write(I18n.tr("server.um.runMigration84.29"));
            } else {
                // QUESTA e' la prova che conta: postmap interroga MySQL attraverso la
                // libreria client appena sostituita. Se funziona, la sostituzione ha retto.
                String mapFile = "/usr/local/etc/postfix/mysql-virtual-mailboxes.cf";
                if (ok("test -f " + mapFile, 15)) {
                    String q = sh("postmap -q '" + testMailbox + "' mysql:" + mapFile + " 2>&1", 60);
                    // Cercare la sola parola "error" era sbagliato: postmap scrive "fatal:",
                    // e il controllo ha dichiarato riuscito un fallimento mentre ne stampava
                    // la prova. Si riconoscono tutte le forme, e soprattutto si pretende che
                    // la risposta SIA un risultato: un indirizzo, non un messaggio.
                    String ql = q.toLowerCase();
                    boolean pOk = !q.trim().isEmpty()
                            && !ql.contains("error") && !ql.contains("fatal")
                            && !ql.contains("warning") && !ql.contains("not found")
                            && !ql.contains("dlopen") && !ql.contains("unsupported")
                            && !ql.startsWith("postmap:");
                    job.write("    " + (pOk
                            ? I18n.tr("server.um.x.pfQueryYes", java.util.Map.of("mailbox", String.valueOf(testMailbox), "r", String.valueOf(q.trim())))
                            : I18n.tr("server.um.x.pfQueryNo", java.util.Map.of("mailbox", String.valueOf(testMailbox), "r", String.valueOf(q.trim())))));
                    if (!pOk) testOk = false;
                } else {
                    job.write(I18n.tr("server.um.runMigration84.30", java.util.Map.of("mapFile", String.valueOf(mapFile))));
                    testOk = false;
                }

                // Questa invece prova meno di quanto sembri, e va detto: lo userdb qui e'
                // "static", quindi doveadm risponde senza interrogare il database. Dimostra
                // che Dovecot e' vivo e risolve gli utenti, non che il suo passdb SQL funzioni.
                String du = sh("doveadm user '" + testMailbox + "' 2>&1 | head -5", 60);
                boolean dOk = du.toLowerCase().contains("uid") || du.toLowerCase().contains("home");
                job.write("    " + (dOk
                        ? I18n.tr("server.um.x.dcResolveYes", java.util.Map.of("mailbox", String.valueOf(testMailbox)))
                        : I18n.tr("server.um.x.dcResolveNo", java.util.Map.of("mailbox", String.valueOf(testMailbox), "r", String.valueOf(du.trim())))));
                if (!dOk) testOk = false;

                // Il percorso SQL di Dovecot si prova cosi': la stessa query che sta nel suo
                // dovecot-sql.conf, eseguita con le stesse credenziali.
                String lines = mysqlOut("SELECT COUNT(*) FROM mailboxes WHERE email='" + testMailbox
                        + "' AND active=1;").trim();
                boolean sOk = "1".equals(lines);
                job.write("    " + (sOk
                        ? I18n.tr("server.um.x.dcAuthYes", java.util.Map.of("mailbox", String.valueOf(testMailbox)))
                        : I18n.tr("server.um.x.dcAuthNo", java.util.Map.of("mailbox", String.valueOf(testMailbox), "lines", String.valueOf(lines)))));
                if (!sOk) testOk = false;
            }

            job.write("");
            job.write(I18n.tr("server.um.runMigration84.31"));
            boolean fallen = fallenServices(job, servicesBefore);

            reachedEnd = true;
            if (!inventoryOk || !testOk || fallen || lost || !l1 || !l2) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigration84.32", java.util.Map.of("backupDir", String.valueOf(backupDir)));
            } else {
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runMigration84.33", java.util.Map.of("newVer", String.valueOf(newVer))));
                job.write(I18n.tr("server.um.runMigration84.34", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.write("");
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (!reachedEnd) {
                if (mysqlStopped && !replacedPackages) {
                    job.write("");
                    job.write(I18n.tr("server.um.runMigration84.35"));
                    ok("service mysql-server start", 120);
                    if (postfixWasActive) ok("service postfix start", 120);
                    if (dovecotWasActive) ok("service dovecot start", 120);
                } else if (replacedPackages) {
                    job.write("");
                    job.write(I18n.tr("server.um.runMigration84.36"));
                    if (!backupDir.isEmpty()) job.write(I18n.tr("server.um.runMigration84.37", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                }
            }
            job.finishedAt = System.currentTimeMillis();
        }
    }

    // ===================== aggiornamento guidato di Roundcube =====================

    private static final String RC_DIR = "/usr/local/www/roundcube";

    /**
     * Credenziali del database della webmail, lette da config.inc.php.
     *
     * Non si indovinano: nel pannello compaiono due utenti diversi per lo stesso database
     * (mailpanel in un punto, roundcube in un altro), e quello autorevole e' cio' che
     * Roundcube usa davvero, cioe' il DSN nella sua configurazione. La lettura si fa in Java
     * e non con una catena di grep e sed: niente da proteggere in una shell, e la password
     * non passa mai da una riga di comando.
     */
    static JSONObject dsnRoundcube() {
        JSONObject r = new JSONObject().put("ok", false);
        try {
            java.nio.file.Path f = Paths.get(RC_DIR + "/config/config.inc.php");
            if (!Files.exists(f)) return r.put("error", I18n.tr("server.um.dsnRoundcube.1", java.util.Map.of("rcDir", String.valueOf(RC_DIR))));
            Pattern pat = Pattern.compile("db_dsnw'?\\]?\\s*=\\s*['\"]([a-z]+)://([^:]+):([^@]*)@([^/]+)/([A-Za-z0-9_]+)");
            // Riga per riga, non su tutto il testo, per due motivi che una ricerca globale
            // sbaglia entrambi: le righe COMMENTATE non contano — un DSN vecchio lasciato li'
            // farebbe fare copia e aggiornamento dello schema sul database sbagliato — e in PHP
            // vince l'ULTIMA assegnazione, non la prima, perche' i file di configurazione
            // spesso impostano un valore e poi lo sovrascrivono.
            JSONObject last = null;
            for (String line : Files.readAllLines(f)) {
                String t = line.trim();
                if (t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*")) continue;
                Matcher m = pat.matcher(t);
                if (m.find()) {
                    last = new JSONObject().put("ok", true).put("driver", m.group(1)).put("user", m.group(2))
                            .put("pass", m.group(3)).put("host", m.group(4)).put("db", m.group(5));
                }
            }
            if (last == null) return r.put("error", I18n.tr("server.um.dsnRoundcube.2"));
            return last;
        } catch (Exception e) {
            return r.put("error", e.getMessage());
        }
    }

    /** Query sul database della webmail, con le credenziali che usa Roundcube stesso. */
    private static String rcQuery(String sql) {
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok")) return "";
        String u = d.getString("user"), h = d.getString("host"), db = d.getString("db");
        if (!u.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !h.matches("[A-Za-z0-9._:-]{1,128}")) return "";
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        String q = sql.replace("\"", "");
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c",
                    "mysql -u " + u + " -h " + host + " -N -B " + db + " -e \"" + q + "\" 2>/dev/null");
            org.mail_panel.util.Shell.applyPath(pb);
            pb.environment().put("MYSQL_PWD", d.getString("pass"));
            Process pr = pb.start();
            StringBuilder sb = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(pr.getInputStream(), StandardCharsets.UTF_8))) {
                String l; while ((l = br.readLine()) != null) sb.append(l).append('\n');
            }
            pr.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            return sb.toString().trim();
        } catch (Exception e) { return ""; }
    }

    /**
     * Controlli preliminari per il salto di versione maggiore di Roundcube. Sola lettura.
     *
     * Il punto delicato non e' il pacchetto ma lo SCHEMA del database: la 1.7 lo cambia, e
     * finche' non si esegue bin/updatedb.sh la webmail non funziona. E l'aggiornamento dello
     * schema non si annulla, quindi serve una copia del database presa prima.
     */
    /**
     * Le righe "root ...roundcube" nelle configurazioni di nginx, con la posizione esatta.
     *
     * Dalla 1.7 Roundcube pretende che il server web punti alla sottocartella public_html:
     * tutto il resto dell'installazione smette di essere servibile, ed e' voluto — e' una
     * protezione. Ma su questo server nginx punta alla radice dell'applicazione (il pannello
     * stesso la scrive cosi' in cinque punti), quindi dopo l'aggiornamento la webmail
     * smetterebbe di funzionare. Va trovato PRIMA, non scoperto dopo.
     */
    private static JSONArray nginxRoundcubeRoots() {
        JSONArray outside = new JSONArray();
        String out = sh("grep -rn '^[[:space:]]*root[[:space:]].*roundcube' "
                + "/usr/local/etc/nginx/ 2>/dev/null", 60);
        for (String line : out.split("\n")) {
            Matcher m = Pattern.compile("^([^:]+):([0-9]+):\\s*root\\s+([^;]+);").matcher(line.trim());
            if (!m.find()) continue;
            String path = m.group(3).trim();
            outside.put(new JSONObject().put("file", m.group(1)).put("line", Integer.parseInt(m.group(2)))
                    .put("root", path)
                    .put("already", path.endsWith("/public_html") || path.endsWith("/public_html/")));
        }
        return outside;
    }

    /** Vero se la versione e' 1.7 o successiva, cioe' se pretende la radice public_html. */
    static boolean wantsPublicHtml(String version) {
        Matcher m = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(version == null ? "" : version);
        if (!m.find()) return false;
        int ma = Integer.parseInt(m.group(1)), mi = Integer.parseInt(m.group(2));
        return ma > 1 || (ma == 1 && mi >= 7);
    }

    public static JSONObject roundcubePreflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean block = false;

        String pkg = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20);
        String ver = pkg.isEmpty() ? "" : sh("pkg query %v " + pkg, 20);
        String available = pkg.isEmpty() ? "" : sh("pkg rquery -U %v " + pkg, 30);
        r.put("pkg", pkg).put("current", ver).put("available", available);
        if (pkg.isEmpty()) {
            addCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "block", I18n.tr("server.um.roundcubePreflight.2"));
            block = true;
        } else if (available.isEmpty() || available.equals(ver)) {
            // Non e' un impedimento da risolvere: non c'e' niente da fare. Chiamarlo "blocco"
            // e poi scrivere "risolvi le righe rosse" mette l'utente a cercare un guasto che
            // non esiste — ed e' il contrario di cio' che la riga vuole dire.
            addCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "ok",
                    available.isEmpty()
                        ? I18n.tr("server.um.roundcubePreflight.3", java.util.Map.of("pkg", String.valueOf(pkg), "ver", String.valueOf(ver)))
                        : I18n.tr("server.um.x.jvLatest", java.util.Map.of("pkg", String.valueOf(pkg), "cur", String.valueOf(ver))));
            r.put("already", !available.isEmpty()).put("unknown", available.isEmpty());
            block = true;
        } else {
            addCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "ok", pkg + " " + ver + " -> " + available);
        }

        // La famiglia PHP richiesta dalla versione nuova deve essere quella installata.
        String phpInst = sh("pkg query %n 2>/dev/null | grep -E '^php[0-9]+$' | head -1", 20);
        Matcher mp = Pattern.compile("roundcube-php([0-9]+)").matcher(pkg);
        String phpRc = mp.find() ? "php" + mp.group(1) : "";
        boolean phpOk = phpRc.isEmpty() || phpRc.equals(phpInst);
        addCheck(checks, "php", I18n.tr("server.um.roundcubePreflight.4"), phpOk ? "ok" : "block",
                phpOk ? I18n.tr("server.um.roundcubePreflight.5", java.util.Map.of("p", String.valueOf((phpRc.isEmpty() ? phpInst : phpRc))))
                      : I18n.tr("server.um.roundcubePreflight.6", java.util.Map.of("phpRc", String.valueOf(phpRc), "phpInst", String.valueOf(phpInst))));
        if (!phpOk) block = true;

        // Lo script che aggiorna lo schema: senza, il passo non si puo' completare.
        boolean updatedb = ok("test -x " + RC_DIR + "/bin/updatedb.sh", 15)
                        || ok("test -f " + RC_DIR + "/bin/updatedb.sh", 15);
        addCheck(checks, "updatedb", I18n.tr("server.um.roundcubePreflight.7"), updatedb ? "ok" : "block",
                updatedb ? I18n.tr("server.um.x.updatedbPresent", java.util.Map.of("file", String.valueOf(RC_DIR + "/bin/updatedb.sh")))
                         : I18n.tr("server.um.roundcubePreflight.8", java.util.Map.of("rcDir", String.valueOf(RC_DIR))));
        if (!updatedb) block = true;

        // Credenziali e stato del database, letti dalla configurazione di Roundcube.
        JSONObject dsn = dsnRoundcube();
        long tables = 0;
        if (!dsn.optBoolean("ok")) {
            addCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "block",
                    I18n.tr("server.um.x.rcNoCreds", java.util.Map.of("error", String.valueOf(dsn.optString("error", "")))));
            block = true;
        } else {
            tables = number(rcQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='"
                    + dsn.getString("db") + "';"));
            r.put("db", dsn.getString("db")).put("dbUser", dsn.getString("user")).put("tables", tables);
            if (tables == 0) {
                addCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "block",
                        I18n.tr("server.um.x.rcDbNoAnswer", java.util.Map.of("db", String.valueOf(dsn.getString("db")))));
                block = true;
            } else {
                addCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "ok",
                        I18n.tr("server.um.x.rcDbOk", java.util.Map.of("db", String.valueOf(dsn.getString("db")), "user", String.valueOf(dsn.getString("user")), "tables", String.valueOf(tables))));
            }
        }

        // Non si annuncia una via di ritorno: si prova, adesso, davvero.
        JSONObject test = testCopy();
        String dbName = dsn.optBoolean("ok") ? dsn.getString("db") : "roundcubemail";
        if (!test.optBoolean("ok")) {
            String inherited = inheritedOptions();
            String gtid = gtidState();
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "block",
                    I18n.tr("server.um.x.rcCopyFails", java.util.Map.of("db", String.valueOf(dbName), "error", String.valueOf(test.optString("error"))))
                    + (inherited.isEmpty() ? ""
                       : "  ||  " + I18n.tr("server.um.x.rcDumpOpts", java.util.Map.of("o", String.valueOf(inherited))))
                    + "  ||  " + (gtid.isEmpty() ? I18n.tr("server.um.x.gtidUnreadable")
                       : I18n.tr("server.um.x.serverState", java.util.Map.of("s", String.valueOf(gtid)))));
            block = true;
        } else if ("server.um.dumpMode.root".equals(test.optString("mode"))) {
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "wait",
                    I18n.tr("server.um.x.rcCopyRoot", java.util.Map.of("db", String.valueOf(dbName), "history", String.valueOf(test.optString("history")), "gtid", String.valueOf(gtidState()))));
        } else if (!"server.um.dumpMode.full".equals(test.optString("mode"))) {
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "wait",
                    I18n.tr("server.um.x.rcCopyReduced", java.util.Map.of("db", String.valueOf(dbName), "mode", String.valueOf(I18n.tr(test.getString("mode"))), "history", String.valueOf(test.optString("history")))));
        } else {
            addCheck(checks, "copy", I18n.tr("server.um.roundcubePreflight.10"), "ok",
                    I18n.tr("server.um.roundcubePreflight.11", java.util.Map.of("dbName", String.valueOf(dbName))));
        }

        // Non chiede niente a chi legge: dice cosa fa la procedura. Sotto l'etichetta gialla
        // "VERIFICA" sembrava una cosa rimasta da fare, in mezzo a righe tutte verdi.
        addCheck(checks, "opcache", I18n.tr("server.um.roundcubePreflight.12"), "note",
                I18n.tr("server.um.roundcubePreflight.13"));

        // Radice di nginx: dalla 1.7 deve puntare a public_html, altrimenti la webmail
        // smette di funzionare subito dopo l'aggiornamento.
        JSONArray roots = nginxRoundcubeRoots();
        // La domanda giusta non e' "sto passando alla 1.7?" ma "la versione che avro' pretende
        // public_html, e nginx ci punta?". Un server GIA' sulla 1.7 con la radice vecchia ha la
        // webmail gia' guasta adesso: chiedendo solo del passaggio non me ne accorgerei, e
        // direi "non va toccata" proprio nel caso in cui va toccata subito.
        java.util.List<String> toMove = new ArrayList<>();
        for (int i = 0; i < roots.length(); i++) {
            JSONObject x = roots.getJSONObject(i);
            if (!x.getBoolean("already"))
                toMove.add(x.getString("file") + ":" + x.getInt("line") + " -> " + x.getString("root") + "/public_html");
        }
        boolean demands = wantsPublicHtml(available);
        boolean already17 = wantsPublicHtml(ver);
        boolean serve = demands && !toMove.isEmpty();
        r.put("roots", roots).put("rootChange", serve);
        if (!demands) {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "ok",
                    I18n.tr("server.um.roundcubePreflight.15", java.util.Map.of("available", String.valueOf(available))));
        } else if (roots.length() == 0) {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "block",
                    I18n.tr("server.um.roundcubePreflight.16", java.util.Map.of("available", String.valueOf(available))));
            block = true;
        } else if (toMove.isEmpty()) {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "ok",
                    I18n.tr("server.um.roundcubePreflight.17"));
        } else {
            addCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "wait",
                    (already17
                     ? I18n.tr("server.um.roundcubePreflight.18", java.util.Map.of("ver", String.valueOf(ver)))
                     : I18n.tr("server.um.roundcubePreflight.19", java.util.Map.of("available", String.valueOf(available))))
                    + I18n.tr("server.um.x.rcRootFix", java.util.Map.of("n", String.valueOf(toMove.size()), "lines", String.valueOf(String.join(" ; ", toMove)))));
        }

        r.put("success", true).put("checks", checks).put("canProceed", !block).put("blocked", block);
        return r;
    }

    /**
     * Sposta la radice di nginx su public_html, come pretende Roundcube dalla 1.7.
     *
     * Riscrittura riga per riga e riscrittura atomica del file: niente sed, che su BSD si
     * comporta diversamente da come si e' abituati e ha gia' scritto una "n" letterale al
     * posto di un a capo in questo stesso progetto.
     */
    private static String moveNginxRoot(Job job, String backupDir) {
        JSONArray roots = nginxRoundcubeRoots();
        java.util.List<String> touched = new ArrayList<>();
        try {
            for (int i = 0; i < roots.length(); i++) {
                JSONObject x = roots.getJSONObject(i);
                if (x.getBoolean("already")) continue;
                String file = x.getString("file"), root = x.getString("root");
                if (!ok("test -f " + file, 10)) continue;
                // Se public_html non c'e', questa build non lo usa: non e' un guasto, e
                // dichiararlo tale bocciarebbe un aggiornamento riuscito — che e' il modo di
                // farsi tornare indietro senza motivo. Chi giudica resta la prova finale: se
                // la webmail non risponde, lo dice quella.
                if (!ok("test -d " + root + "/public_html", 10)) {
                    job.write(I18n.tr("server.um.moveNginxRoot.1", java.util.Map.of("root", String.valueOf(root))));
                    job.write(I18n.tr("server.um.moveNginxRoot.2"));
                    return "unneeded";
                }
                String name = file.replaceAll(".*/", "");
                ok("cp -p " + file + " " + backupDir + "/nginx-" + name, 30);
                java.util.List<String> lines = Files.readAllLines(Paths.get(file));
                int n = x.getInt("line") - 1;
                if (n < 0 || n >= lines.size()) { job.write(I18n.tr("server.um.moveNginxRoot.3", java.util.Map.of("file", String.valueOf(file), "p", String.valueOf((n + 1))))); return "failed"; }
                String old = lines.get(n);
                if (!old.contains(root)) { job.write("    " + I18n.tr("server.um.x.lineNoLonger", java.util.Map.of("file", String.valueOf(file), "line", String.valueOf((n + 1)), "root", String.valueOf(root)))); return "failed"; }
                // Puntare a una cartella che esiste non basta: dev'esserci cosa servire.
                if (!ok("test -f " + root + "/public_html/index.php", 10)) {
                    job.write(I18n.tr("server.um.moveNginxRoot.4", java.util.Map.of("root", String.valueOf(root))));
                    job.write(I18n.tr("server.um.moveNginxRoot.5"));
                    return "failed";
                }
                lines.set(n, old.replace(root + ";", root + "/public_html;"));
                Files.write(Paths.get(file), lines);
                touched.add(file);
                job.write("    " + file + ":" + (n + 1) + "  root -> " + root + "/public_html");
            }
            if (touched.isEmpty()) { job.write(I18n.tr("server.um.moveNginxRoot.6")); return "unneeded"; }

            // Prima di ricaricare: nginx accetta questa configurazione?
            String test = sh("nginx -t 2>&1", 60);
            boolean good = test.toLowerCase().contains("syntax is ok") && test.toLowerCase().contains("test is successful");
            if (!good) {
                for (String l : test.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
                for (String f : touched) {
                    String name = f.replaceAll(".*/", "");
                    ok("cp -p " + backupDir + "/nginx-" + name + " " + f, 30);
                }
                job.write(I18n.tr("server.um.moveNginxRoot.7"));
                return "failed";
            }
            job.write(I18n.tr("server.um.moveNginxRoot.8"));
            String svc = realServiceName("nginx");
            if (svc == null) { job.write(I18n.tr("server.um.moveNginxRoot.9")); return "failed"; }
            boolean reloadOutcome = ok("service " + svc + " reload", 60);
            job.write("    " + (reloadOutcome ? I18n.tr("server.um.x.reloadedYes") : I18n.tr("server.um.x.reloadedNo")));
            return reloadOutcome ? "done" : "failed";
        } catch (Exception e) {
            job.write(I18n.tr("server.um.moveNginxRoot.10", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            return "failed";
        }
    }

    /** Copia del database della webmail. Il marcatore finale di mysqldump prova che e' completa. */
    /**
     * Copia del database della webmail, con il motivo del fallimento quando fallisce.
     *
     * La versione precedente mandava stderr in /dev/null e tornava true/false: quando non
     * riusciva, il pannello sapeva soltanto che non era riuscita — cioe' esattamente niente di
     * utile. L'errore di mysqldump E' la diagnosi, buttarlo via era il difetto piu' grave qui.
     *
     * Due opzioni meritano una spiegazione, perche' sembrano dettagli e non lo sono:
     *  - --no-tablespaces: senza, mysqldump di MySQL 8 interroga le informazioni sui tablespace
     *    e per farlo pretende il privilegio PROCESS, che un utente di applicazione non ha e non
     *    deve avere. E' la causa piu' comune di un "Access denied" che non c'entra nulla con le
     *    tabelle da copiare.
     *  - --routines e --triggers chiedono altri privilegi ancora (SHOW_ROUTINE, TRIGGER). Sullo
     *    schema di Roundcube non c'e' niente di tutto cio', quindi se il primo tentativo cade li
     *    si riprova senza — e lo si SCRIVE, invece di consegnare una copia piu' povera di quella
     *    promessa facendo finta di niente.
     */
    /** I modi di copiare, dal piu' completo al meno esigente. Una lista sola per la prova e per la copia vera. */
    /**
     * I modi di copiare, dal meno privilegiato al piu' potente. Terza colonna: con quale utente.
     *
     * --no-tablespaces: senza, mysqldump di MySQL 8 legge le informazioni sui tablespace e per
     *   farlo pretende PROCESS, che un utente di applicazione non ha e non deve avere.
     * --set-gtid-purged=OFF: se il server ha i GTID attivi, mysqldump in modalita' AUTO (il
     *   default) vuole registrare quali GTID sono gia' applicati, e per prenderli coerenti fa
     *   FLUSH TABLES + FLUSH TABLES WITH READ LOCK, che pretendono RELOAD. Nessun file di
     *   opzioni c'entra: lo decide mysqldump guardando il server. Per una copia da rimettere
     *   sullo stesso server quell'informazione non serve, quindi si spegne.
     * --skip-lock-all-tables --skip-flush-logs: le altre due strade che portano allo stesso
     *   FLUSH. Spegnerle esplicitamente e' l'unico modo di sapere cosa si sta eseguendo.
     * --no-defaults: ignora ogni file di opzioni. Va per forza per prima sulla riga di comando.
     * root sul socket: ultima spiaggia, e funziona sempre perche' root ha tutti i privilegi.
     *   Sta per ultima apposta: una copia si fa col minimo necessario, non col massimo possibile.
     */
    private static final String[][] COPY_MODES = {
        {"--single-transaction --no-tablespaces --skip-lock-all-tables --skip-flush-logs "
         + "--set-gtid-purged=OFF --routines --triggers", "server.um.dumpMode.full", "app"},
        {"--single-transaction --no-tablespaces --skip-lock-all-tables --skip-flush-logs "
         + "--set-gtid-purged=OFF", "server.um.dumpMode.noRoutines", "app"},
        {"--no-defaults --single-transaction --no-tablespaces --skip-lock-all-tables "
         + "--skip-flush-logs --set-gtid-purged=OFF", "server.um.dumpMode.noDefaults", "app"},
        {"--single-transaction --no-tablespaces --set-gtid-purged=OFF --routines --triggers",
         "server.um.dumpMode.root", "root"},
    };

    /**
     * Il pannello riesce a entrare in MySQL come root dal socket unix?
     *
     * Si prova, non si presume: si esegue una domanda banale e si guarda se risponde. Presumerlo
     * significherebbe offrire come ultima spiaggia una strada che non c'e', e scoprirlo nel
     * momento in cui e' l'unica rimasta.
     */
    private static boolean mysqlRootAvailable() {
        return "1".equals(mysqlRootOut("SELECT 1;").trim());
    }

    /** La parte di connessione della riga, secondo l'utente scelto dal modo. */
    private static String copyConnection(String who, JSONObject dsn) {
        String h = dsn.getString("host");
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        return "root".equals(who)
                ? "-u root " + dsn.getString("db")                       // socket unix, nessuna password
                : "-u " + dsn.getString("user") + " -h " + host + " " + dsn.getString("db");
    }

    /** Perche' mysqldump fa quel FLUSH: si guarda il server, non si deduce. */
    private static String gtidState() {
        String r = mysqlRootOut("SELECT CONCAT('gtid_mode=', @@gtid_mode, "
                + "'  log_bin=', @@log_bin, '  enforce_gtid_consistency=', @@enforce_gtid_consistency);");
        return r == null ? "" : r.trim();
    }

    /**
     * Da dove arrivano le opzioni che non ho chiesto io.
     *
     * "--print-defaults" stampa la riga di comando che mysqldump si costruisce davvero, opzioni
     * dei file di configurazione comprese. Serve perche' un errore su un FLUSH TABLES che nessuno
     * ha chiesto e' incomprensibile finche' non si vede chi lo ha chiesto: e a quel punto smette
     * di essere un mistero e diventa una riga in un file.
     */
    private static String inheritedOptions() {
        String o = sh("mysqldump --print-defaults 2>&1 | tail -2", 30).replace("\n", " ").trim();
        return o.isEmpty() ? "" : o;
    }

    /**
     * Prova la copia PRIMA di averne bisogno, senza i dati.
     *
     * Una via di ritorno che non si e' mai percorsa non e' una via di ritorno: e' una speranza.
     * Qui si esegue davvero un mysqldump --no-data, che costa un istante e mette alla prova
     * esattamente cio' che conta — che il comando ci sia, che le credenziali entrino, che i
     * privilegi bastino e che il file arrivi in fondo. Se questo non passa, non ha senso
     * cominciare: e' quello che e' successo il 31/08/2026, scoperto al passo 2 invece che qui.
     */
    private static JSONObject testCopy() {
        String tmp = "/var/db/mailpanel/test-dump.sql";
        ok("mkdir -p /var/db/mailpanel", 20);
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok"))
            return new JSONObject().put("ok", false)
                    .put("error", I18n.tr("server.um.x.credsUnreadable", java.util.Map.of("reason", String.valueOf(d.optString("error", I18n.tr("server.um.x.reasonUnknown"))))));
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return new JSONObject().put("ok", false)
                    .put("error", I18n.tr("server.um.testCopy.1"));
        StringBuilder history = new StringBuilder();
        try {
            for (String[] m : COPY_MODES) {
                if ("root".equals(m[2]) && !mysqlRootAvailable()) {
                    history.append("[").append(I18n.tr(m[1])).append("] ").append(I18n.tr("server.um.x.notTriedRoot")).append("  ");
                    continue;
                }
                JSONObject e = rcDumpOneAttempt(m[0] + " --no-data",
                        copyConnection(m[2], d), "root".equals(m[2]) ? null : d.getString("pass"), tmp);
                if (e.optBoolean("ok"))
                    return new JSONObject().put("ok", true).put("mode", m[1])
                            .put("history", history.toString().trim());
                history.append("[").append(I18n.tr(m[1])).append("] ").append(e.optString("error")).append("  ");
            }
            return new JSONObject().put("ok", false).put("error", history.toString().trim());
        } finally {
            ok("rm -f " + tmp + " " + tmp + ".err", 20);
        }
    }

    private static JSONObject rcDump(String destination) {
        JSONObject r = new JSONObject().put("ok", false);
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok"))
            return r.put("error", I18n.tr("server.um.x.rcCredsUnreadable", java.util.Map.of("reason", String.valueOf(d.optString("error", I18n.tr("server.um.x.reasonUnknown"))))));
        String u = d.getString("user"), db = d.getString("db");
        String h = d.getString("host");
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        if (!u.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !host.matches("[A-Za-z0-9._-]{1,128}"))
            return r.put("error", I18n.tr("server.um.rcDump.1", java.util.Map.of("u", String.valueOf(u), "host", String.valueOf(host), "db", String.valueOf(db))));
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return r.put("error", I18n.tr("server.um.testCopy.1"));

        StringBuilder history = new StringBuilder();
        for (String[] t : COPY_MODES) {
            if ("root".equals(t[2]) && !mysqlRootAvailable()) {
                history.append("[").append(I18n.tr(t[1])).append("] ").append(I18n.tr("server.um.x.notTriedNoRoot")).append("  ");
                continue;
            }
            JSONObject e = rcDumpOneAttempt(t[0], copyConnection(t[2], d),
                    "root".equals(t[2]) ? null : d.getString("pass"), destination);
            if (e.optBoolean("ok")) {
                r.put("ok", true).put("mode", t[1]);
                if (!t[1].equals("server.um.dumpMode.full")) r.put("reduced", history.toString().trim());
                return r;
            }
            history.append("[").append(I18n.tr(t[1])).append("] ").append(e.optString("error")).append("  ");
        }
        return r.put("error", history.toString().trim());
    }

    private static JSONObject rcDumpOneAttempt(String options, String connection,
                                                String pass, String dest) {
        JSONObject r = new JSONObject().put("ok", false);
        String err = dest + ".err";
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c",
                    "mysqldump " + options + " " + connection + " > " + dest + " 2> " + err);
            org.mail_panel.util.Shell.applyPath(pb);
            // La password sta nell'ambiente e non nella riga di comando: cosi' non compare in ps.
            // Per il tentativo da root non c'e' password: entra dal socket unix.
            if (pass != null && !pass.isEmpty()) pb.environment().put("MYSQL_PWD", pass);
            Process pr = pb.start();
            if (!pr.waitFor(1800, java.util.concurrent.TimeUnit.SECONDS)) {
                pr.destroyForcibly();
                return r.put("error", I18n.tr("server.um.rcDumpOneAttempt.1"));
            }
            String message = sh("cat " + err + " 2>/dev/null", 30).replace("\n", " ").trim();
            if (pr.exitValue() != 0)
                return r.put("error", message.isEmpty()
                        ? I18n.tr("server.um.x.exitNoMsg", java.util.Map.of("c", String.valueOf(pr.exitValue())))
                        : I18n.tr("server.um.x.exitMsg", java.util.Map.of("c", String.valueOf(pr.exitValue()), "m", String.valueOf(message))));
            // mysqldump chiude con "Dump completed": senza quella riga il file e' troncato,
            // e un file troncato che sembra un backup e' peggio di nessun backup.
            if (!ok("tail -3 " + dest + " | grep -q 'Dump completed'", 60))
                return r.put("error", I18n.tr("server.um.x.dumpTruncated")
                        + (message.isEmpty() ? "" : " (" + message + ")"));
            ok("rm -f " + err, 15);
            return r.put("ok", true);
        } catch (Exception e) {
            return r.put("error", e.getMessage());
        }
    }

    /**
     * Perche' la webmail non risponde. Sola lettura.
     *
     * Un 403 non si indovina: nginx scrive nel suo log di errore la ragione esatta, e le due
     * ragioni possibili portano a rimedi opposti — "Permission denied" e' un problema di
     * permessi sul file, "directory index of ... is forbidden" vuol dire che nginx non trova
     * nessun file indice da servire. Confonderle significa aggiustare la cosa sbagliata.
     */
    /**
     * Interroga la webmail SULL'ORIGINE, non attraverso quello che sta davanti.
     *
     * Il 31/08/2026 la prova finale ha bocciato un aggiornamento riuscito perche' chiedeva alla
     * porta 443 mentre nginx ascolta sulla 8443: rispondeva Cloudflare, con un 403 suo, e nel
     * log di nginx non compariva nulla perche' la richiesta non era mai arrivata al server.
     * Qui la porta si legge dal blocco server vero, e ci si risolve su 127.0.0.1 per scavalcare
     * qualunque cosa stia davanti. Se malgrado tutto risponde una CDN, lo si dice invece di
     * scambiare la sua risposta per quella del server.
     */
    private static JSONObject testWebmailOrigin() {
        JSONObject r = new JSONObject().put("ok", false);
        JSONArray roots = nginxRoundcubeRoots();
        if (roots.length() == 0) return r.put("error", I18n.tr("server.um.testWebmailOrigin.1"));
        String file = roots.getJSONObject(0).getString("file");
        int line = roots.getJSONObject(0).getInt("line");
        // listen e server_name stanno nello stesso blocco, poche righe sopra la radice.
        int from = Math.max(1, line - 10);
        String head = sh("sed -n '" + from + "," + line + "p' " + file + " 2>/dev/null", 30);
        String port = "", name = "";
        for (String l : head.split("\n")) {
            Matcher mp = Pattern.compile("^\\s*listen\\s+([0-9]{1,5})\\b").matcher(l);
            if (mp.find()) port = mp.group(1);
            Matcher mn = Pattern.compile("^\\s*server_name\\s+([A-Za-z0-9._-]+)\\s*;").matcher(l);
            if (mn.find() && !"_".equals(mn.group(1))) name = mn.group(1);
        }
        if (port.isEmpty()) return r.put("error", I18n.tr("server.um.testWebmailOrigin.2"));
        if (name.isEmpty()) {
            try { name = org.mail_panel.Main.dbManager.getRoundcubeDomain(); } catch (Exception ignored) {}
        }
        if (name == null || !name.matches("[A-Za-z0-9._-]{1,255}"))
            return r.put("error", I18n.tr("server.um.testWebmailOrigin.3"));
        // --resolve mette a posto sia il nome nell'intestazione Host sia quello nel TLS,
        // ma manda la richiesta all'indirizzo locale: e' il modo di parlare col server e basta.
        String url = "https://" + name + ":" + port + "/";
        String out = sh("curl -sk -m 20 -D - -o /dev/null --resolve " + name + ":" + port
                + ":127.0.0.1 " + url + " 2>&1", 60);
        Matcher mc = Pattern.compile("HTTP/[0-9.]+\\s+([0-9]{3})").matcher(out);
        String code = mc.find() ? mc.group(1) : "";
        boolean cdn = out.toLowerCase().contains("cf-ray") || out.toLowerCase().contains("server: cloudflare");
        return r.put("ok", code.startsWith("2") || code.startsWith("3"))
                .put("code", code.isEmpty() ? I18n.tr("server.um.testWebmailOrigin.4") : code)
                .put("url", url).put("viaCdn", cdn).put("headers", out.trim());
    }

    /**
     * Cosa riceve DAVVERO PHP quando la richiesta passa da nginx.
     *
     * E' l'ultima incognita rimasta: static.php risolve il file con
     * realpath(INSTALL_PATH . PATH_INFO), il file c'e', i permessi ci sono, e risponde 404
     * lo stesso. Quindi o PATH_INFO non arriva come credo, o arriva vuoto — e "vuoto" non e'
     * la stessa cosa di "assente", perche' l'operatore ?? di PHP non ripiega su una stringa
     * vuota e static.php si ritroverebbe con un percorso nullo.
     *
     * Si scrive una sonda con un nome imprevedibile, le si fa una sola richiesta e la si
     * elimina subito, anche se qualcosa va storto. Stampa solo le sei variabili che servono,
     * non tutto l'ambiente.
     */
    public static JSONObject probePathInfo() {
        String name = "rc-probe-" + Long.toHexString(System.nanoTime()) + ".php";
        String file = RC_DIR + "/public_html/" + name;
        try {
            Files.writeString(Paths.get(file),
                "<?php header('Content-Type: text/plain');\n"
              + "foreach (['PATH_INFO','PATH_TRANSLATED','ORIG_PATH_INFO','SCRIPT_FILENAME',\n"
              + "          'SCRIPT_NAME','REQUEST_URI'] as $k) {\n"
              + "    echo $k, ' = ', array_key_exists($k, $_SERVER)\n"
              + "        ? '[' . $_SERVER[$k] . ']' : '(NON IMPOSTATA)', \"\\n\";\n"
              + "}\n"
              + "echo 'cgi.fix_pathinfo = ', ini_get('cgi.fix_pathinfo'), \"\\n\";\n");
            ok("chmod 644 " + file, 15);
            JSONObject pw = testWebmailOrigin();
            String url = pw.optString("url", "");
            if (url.isEmpty()) return new JSONObject().put("ok", false).put("error", I18n.tr("server.um.probePathInfo.2"));
            String n = url.replaceAll("^https://", "").replaceAll(":.*$", "");
            String port = url.replaceAll(".*:", "").replaceAll("/.*$", "");
            String res = "--resolve " + n + ":" + port + ":127.0.0.1 ";
            String u = "https://" + n + ":" + port + "/" + name + "/skins/elastic/deps/bootstrap.min.css";
            String out = sh("curl -sk -m 20 " + res + "'" + u + "' 2>&1 | head -c 1200", 60);
            return new JSONObject().put("ok", true).put("url", u).put("output", out.trim());
        } catch (Exception e) {
            return new JSONObject().put("ok", false).put("error", e.getMessage());
        } finally {
            // La sonda sparisce comunque: non deve restare un file PHP nella radice del web.
            ok("rm -f " + file, 20);
        }
    }

    /**
     * Un CSS in uscita e' 160 KB di testo: stamparlo per intero nasconde la risposta invece di
     * mostrarla. Qui si dice cosa e' uscito, non lo si riversa.
     */
    private static String summarizeOutput(String out) {
        if (out == null) return I18n.tr("server.um.x.nothing");
        String t = out.trim();
        if (t.isEmpty()) return I18n.tr("server.um.summarizeOutput.1");
        String first = t.length() > 200 ? t.substring(0, 200) : t;
        boolean looksLikeCss = t.contains("{") && (t.contains(";") || t.contains("}"));
        boolean looksLikeError = t.toLowerCase().contains("not found") || t.toLowerCase().contains("404")
                || t.toLowerCase().contains("fatal") || t.toLowerCase().contains("warning");
        return (looksLikeError ? I18n.tr("server.um.summarizeOutput.2") : looksLikeCss ? I18n.tr("server.um.summarizeOutput.3") : I18n.tr("server.um.x.output"))
                + " " + I18n.tr("server.um.x.charsPlus", java.util.Map.of("n", String.valueOf(t.length()))) + "\n" + first.replace("\n", " ");
    }

    /**
     * Scarica davvero un foglio di stile e guarda com'e' fatto.
     *
     * E' l'unica prova che distingue "la webmail risponde" da "la webmail si vede": nella 1.7
     * gli asset passano da static.php con il percorso DENTRO l'URI, e se nginx non se ne accorge
     * ogni CSS torna come pagina HTML — la pagina si apre, e non c'e' niente.
     */
    private static JSONObject testCssAsset(String name, String port) {
        JSONObject r = new JSONObject().put("ok", false);
        String base = "https://" + name + ":" + port;
        String res = "--resolve " + name + ":" + port + ":127.0.0.1 ";
        String html = sh("curl -sk -m 20 " + res + base + "/ 2>/dev/null | head -80", 60);
        Matcher m = Pattern.compile("href=\"([^\"]*\\.css[^\"]*)\"").matcher(html);
        if (!m.find()) return r.put("error", I18n.tr("server.um.testCssAsset.1"));
        String css = m.group(1).replace("&amp;", "&");
        // Il link e' relativo ("static.php/skins/..."): va reso assoluto, altrimenti curl
        // non ha un URL da chiamare e risponde 000 — che sembrerebbe un guasto del server.
        String url = css.startsWith("http") ? css
                   : css.startsWith("/") ? base + css
                   : base + "/" + css;
        String out = sh("curl -sk -m 20 -o /dev/null -w '%{http_code} %{content_type}' " + res
                + "'" + url + "' 2>&1", 60).trim();
        // Le intestazioni intere dicono CHI ha risposto: "X-Powered-By: PHP" vuol dire che la
        // richiesta e' arrivata a PHP e il problema e' dentro l'applicazione; la sua assenza
        // vuol dire che l'ha fermata nginx, e allora il problema e' nell'instradamento.
        String head = sh("curl -sk -m 20 -D - -o /dev/null " + res + "'" + url + "' 2>&1", 60).trim();
        boolean good = out.startsWith("200") && out.contains("text/css");
        return r.put("ok", good).put("url", url).put("answer", out)
                .put("headers", head)
                .put("fromPhp", head.toLowerCase().contains("x-powered-by: php"));
    }

    /**
     * Insegna a nginx a servire gli asset di Roundcube 1.7.
     *
     * Il problema in una riga: la 1.7 chiede i fogli di stile come
     *   /static.php/skins/elastic/deps/bootstrap.min.css
     * cioe' uno script PHP seguito da un percorso. Un "location ~ \.php$" non lo intercetta,
     * perche' quell'URI finisce in .css e non in .php: finisce in "location /", che lo manda a
     * index.php, che risponde HTML. La pagina si apre e non ha ne' grafica ne' JavaScript.
     *
     * La cura e' un location che riconosce lo script anche quando ha un percorso attaccato, e
     * che passa a PHP il percorso separato (PATH_INFO), che e' come static.php sa quale file
     * servire. Niente altro: la configurazione e' quella del wiki ufficiale, senza aggiunte.
     * Ci avevo messo un "try_files $fastcgi_script_name =404" per fermare i sondaggi automatici
     * prima di PHP, e quella riga era la causa del guasto: la sua redirezione interna riscrive
     * l'URI al solo nome dello script, PATH_INFO arriva vuota e ogni asset diventa un 404.
     * Se un giorno si volesse quella protezione, la forma che NON rompe il percorso e'
     *   if (!-f $document_root$fastcgi_script_name) { return 404; }
     * verificata con nginx e PHP veri. Ma non e' nella documentazione, quindi non e' qui.
     *
     * fastcgi_pass NON viene inventato: si riprende dal blocco che c'e', perche' su un'altra
     * installazione potrebbe essere un indirizzo TCP invece di un socket.
     */
    public static JSONObject repairNginxPathInfo(boolean run) {
        JSONObject r = new JSONObject();
        try {
            JSONArray roots = nginxRoundcubeRoots();
            if (roots.length() == 0)
                return r.put("success", false).put("error", I18n.tr("server.um.testWebmailOrigin.1"));
            String file = roots.getJSONObject(0).getString("file");
            int rootLine = roots.getJSONObject(0).getInt("line");
            java.util.List<String> lines = Files.readAllLines(Paths.get(file));

            // Il location del PHP dentro questo blocco server.
            int start = -1;
            for (int i = rootLine; i < Math.min(lines.size(), rootLine + 60); i++) {
                String t = lines.get(i);
                if (t.contains("location") && t.contains(".php") && t.contains("{")) { start = i; break; }
            }
            if (start < 0)
                return r.put("success", false).put("error",
                        I18n.tr("server.um.repairNginxPathInfo.1"));
            // Gia' a posto? Si guarda TUTTO il blocco, non la riga dopo: dopo una riparazione
            // precedente la seconda riga puo' essere il rewrite degli URL sicuri, e cercando
            // solo li' il pannello riparerebbe una seconda volta cio' che e' gia' riparato.
            boolean haSplit = false, haTryFiles = false;
            for (int i = start; i < Math.min(lines.size(), start + 25); i++) {
                if (lines.get(i).contains("fastcgi_split_path_info")) haSplit = true;
                // Questa riga ANNULLA la precedente: c'e' ma non basta, anzi rompe.
                if (lines.get(i).contains("try_files") && lines.get(i).contains("fastcgi_script_name"))
                    haTryFiles = true;
                if (lines.get(i).trim().equals("}")) break;
            }
            if (haSplit && !haTryFiles)
                return r.put("success", true).put("alreadyOk", true)
                        .put("note", I18n.tr("server.um.repairNginxPathInfo.2"));
            if (haSplit && haTryFiles)
                r.put("reason", I18n.tr("server.um.repairNginxPathInfo.3"));

            // Le graffe dentro le virgolette NON sono blocchi: la riga di rewrite per gli URL
            // sicuri contiene "{16}", e contarla chiuderebbe il blocco nel punto sbagliato,
            // riscrivendo mezza configurazione. Anche il testo dopo # e' commento, non codice.
            int braces = 0, end = -1;
            for (int i = start; i < lines.size(); i++) {
                boolean quotes = false;
                for (char c : lines.get(i).toCharArray()) {
                    if (c == '"') { quotes = !quotes; continue; }
                    if (quotes) continue;
                    if (c == '#') break;
                    if (c == '{') braces++;
                    else if (c == '}') braces--;
                }
                if (braces == 0) { end = i; break; }
            }
            if (end < 0)
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.4"));

            // use_secure_urls mette un prefisso di 16 caratteri davanti a ogni URL: se e' attivo
            // serve la riga di rewrite, in ENTRAMBI i blocchi, altrimenti nulla combacia piu'.
            // Non si presume: si legge dalla configurazione di Roundcube.
            boolean safeUrls = ok("grep -qE \"^[^/]*.use_secure_urls.*=.*(true|1)\" "
                    + RC_DIR + "/config/config.inc.php", 20);
            r.put("safeUrls", safeUrls);

            String passes = "";
            for (int i = start; i <= end; i++) {
                Matcher mp = Pattern.compile("fastcgi_pass\\s+([^;]+);").matcher(lines.get(i));
                if (mp.find()) passes = mp.group(1).trim();
            }
            if (passes.isEmpty())
                return r.put("success", false).put("error",
                        I18n.tr("server.um.repairNginxPathInfo.5"));

            String ind = lines.get(start).replaceAll("[^ \t].*$", "");
            String i2 = ind + "    ";
            // Ricalcata sull'esempio del wiki ufficiale di Roundcube (pagina Installation),
            // SENZA aggiunte. Ci avevo messo un "try_files $fastcgi_script_name =404" per
            // impedire che i sondaggi automatici arrivassero a PHP: quella riga fa una
            // redirezione interna che riscrive l'URI al solo nome dello script, e da quel
            // momento $fastcgi_path_info si ricalcola su un URI che il percorso non ce l'ha
            // piu'. Risultato: PATH_INFO arriva a static.php VUOTA, e siccome l'operatore ??
            // di PHP non ripiega su una stringa vuota, ogni foglio di stile diventa un 404.
            // Riprodotto con nginx e un PHP veri: e' esattamente il guasto del 31/08/2026.
            java.util.List<String> fresh = new ArrayList<>(java.util.List.of(
                ind + "# Roundcube 1.7 serve gli asset come /static.php/percorso/al/file.css:",
                ind + "# uno script PHP con un percorso attaccato. Un location che chiede .php",
                ind + "# in fondo all'URI non lo prende, e il foglio di stile torna come HTML.",
                ind + "# Configurazione dal wiki ufficiale di Roundcube (pagina Installation).",
                ind + "location ~ \\.php {"));
            if (safeUrls) fresh.add(i2 + "rewrite \"^/[a-zA-Z0-9]{16}/(.*)$\" /$1;");
            fresh.addAll(java.util.List.of(
                i2 + "include fastcgi_params;",
                i2 + "fastcgi_index index.php;",
                i2 + "fastcgi_split_path_info ^(.+\\.php)(/.+)$;",
                i2 + "fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
                i2 + "fastcgi_param PATH_INFO $fastcgi_path_info;",
                i2 + "fastcgi_pass " + passes + ";",
                ind + "}"));

            r.put("success", true).put("file", file).put("from", start + 1).put("to", end + 1)
             .put("current", String.join("\n", lines.subList(start, end + 1)))
             .put("proposed", String.join("\n", fresh));
            if (!run) return r.put("executed", false);

            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}"))
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.10"));
            String bk = "/var/db/mailpanel/nginx/" + ts;
            ok("mkdir -p " + bk, 30);
            if (!ok("cp -p " + file + " " + bk + "/nginx.conf", 30))
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.11", java.util.Map.of("file", String.valueOf(file))));

            java.util.List<String> out = new ArrayList<>(lines.subList(0, start));
            out.addAll(fresh);
            out.addAll(lines.subList(end + 1, lines.size()));
            Files.write(Paths.get(file), out);

            String test = sh("nginx -t 2>&1", 60).toLowerCase();
            if (!(test.contains("syntax is ok") && test.contains("test is successful"))) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                return r.put("success", false).put("executed", false)
                        .put("error", I18n.tr("server.um.x.nginxRejected", java.util.Map.of("out", String.valueOf(sh("nginx -t 2>&1", 60).replace("\n", " ")))));
            }
            String svc = realServiceName("nginx");
            if (svc == null || !ok("service " + svc + " reload", 60)) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                if (svc != null) ok("service " + svc + " reload", 60);
                return r.put("success", false).put("executed", false)
                        .put("error", I18n.tr("server.um.repairNginxPathInfo.12"));
            }

            // La prova che conta: il CSS torna come CSS?
            JSONObject pw = testWebmailOrigin();
            String name = pw.optString("url", "").replaceAll("^https://", "").replaceAll(":.*$", "");
            String port = pw.optString("url", "").replaceAll(".*:", "").replaceAll("/.*$", "");
            JSONObject css = name.isEmpty() ? new JSONObject().put("ok", false).put("error", I18n.tr("server.um.probePathInfo.2"))
                                            : testCssAsset(name, port);
            r.put("executed", true).put("backup", bk + "/nginx.conf").put("css", css);
            if (!css.optBoolean("ok")) {
                r.put("caution", I18n.tr("server.um.x.cssStillWrong", java.util.Map.of("r", String.valueOf(css.optString("answer", css.optString("error"))), "file", String.valueOf(bk + "/nginx.conf"))));
            }
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject roundcubeDiagnostics() {
        JSONObject r = new JSONObject();
        JSONArray entries = new JSONArray();
        try {
            // 1. Dove punta nginx adesso
            JSONArray roots = nginxRoundcubeRoots();
            String root = roots.length() > 0 ? roots.getJSONObject(0).getString("root") : RC_DIR;
            String file = roots.length() > 0 ? roots.getJSONObject(0).getString("file") : "?";
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.1"))
                    .put("text", I18n.tr("server.um.roundcubeDiagnostics.2", java.util.Map.of("root", String.valueOf(root), "file", String.valueOf(file)))));

            // 2. Il log di errore: e' li' che nginx dice PERCHE'
            String logPath = sh("grep -hE '^[[:space:]]*error_log' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 30).trim();
            if (!logPath.matches("/[A-Za-z0-9._/-]{1,200}")) logPath = "/var/log/nginx/error.log";
            String log = sh("tail -25 " + logPath + " 2>&1", 30);
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.3", java.util.Map.of("logPath", String.valueOf(logPath))))
                    .put("text", log.isEmpty() ? I18n.tr("server.um.x.empty") : log));

            // 3. Permessi lungo tutto il cammino: basta una cartella non attraversabile
            StringBuilder perm = new StringBuilder();
            String[] pieces = root.split("/");
            StringBuilder acc = new StringBuilder();
            for (String piece : pieces) {
                if (piece.isEmpty()) continue;
                acc.append('/').append(piece);
                perm.append(sh("ls -ld " + acc + " 2>&1", 20)).append('\n');
            }
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.4"))
                    .put("text", perm.toString().trim()));

            // 4. Cosa c'e' davvero nella cartella servita
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.5", java.util.Map.of("root", String.valueOf(root))))
                    .put("text", sh("ls -la " + root + " 2>&1 | head -25", 30)));

            // 5. Con quale utente gira nginx: e' lui che deve poter leggere
            String user = sh("grep -hE '^[[:space:]]*user[[:space:]]' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 20).trim();
            String proc = sh("ps -axo user,command 2>/dev/null | grep '[n]ginx: worker' | head -2", 30);
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.7"))
                    .put("text", I18n.tr("server.um.x.nginxUserDeclared", java.util.Map.of("u", String.valueOf(user.isEmpty() ? I18n.tr("server.um.x.nginxUserNobody") : user)))
                            + "\n" + (proc.isEmpty() ? I18n.tr("server.um.x.noWorker") : proc)));

            // 6. La risposta del SERVER, scavalcando qualunque cosa stia davanti
            JSONObject pw = testWebmailOrigin();
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.8"))
                    .put("text", pw.optBoolean("ok")
                            ? I18n.tr("server.um.x.urlAnswers", java.util.Map.of("url", String.valueOf(pw.optString("url")), "code", String.valueOf(pw.optString("code")))) + "\n\n"
                              + pw.optString("headers")
                            : I18n.tr("server.um.x.noAnswer", java.util.Map.of("r", String.valueOf(pw.optString("code", pw.optString("error")))))
                              + (pw.optBoolean("viaCdn") ? "  " + I18n.tr("server.um.x.cdnAnswered") : "")
                              + "\n\n" + pw.optString("headers")));

            // 6b. Il .htaccess dice come Roundcube vuole essere servita: e' la fonte autorevole
            entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.9", java.util.Map.of("root", String.valueOf(root))))
                    .put("text", sh("cat " + root + "/.htaccess 2>&1", 30)));

            // 6c. Gli asset: nella 1.7 passano da static.php, ed e' li' che nginx sbaglia di solito.
            if (pw.optBoolean("ok")) {
                String u = pw.optString("url");
                String hName = u.replaceAll("^https://", "").replaceAll(":.*$", "");
                String hPort = u.replaceAll(".*:", "").replaceAll("/.*$", "");
                JSONObject css = testCssAsset(hName, hPort);
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.10"))
                        .put("text", css.optString("url", I18n.tr("server.um.x.noLinkFound")) + "\n  -> "
                            + css.optString("answer", css.optString("error"))
                            + (css.optBoolean("ok") ? "   " + I18n.tr("server.um.x.correct")
                               : I18n.tr("server.um.roundcubeDiagnostics.11"))
                            + "\n\n" + I18n.tr("server.um.x.whoAnswered") + " " + (css.optBoolean("fromPhp")
                                ? I18n.tr("server.um.roundcubeDiagnostics.12")
                                : I18n.tr("server.um.roundcubeDiagnostics.13"))
                            + "\n\n" + css.optString("headers", "")));

                // Il file che static.php dovrebbe servire esiste davvero sul disco?
                String pathInfo = css.optString("url", "").replaceAll(".*/static\\.php", "").replaceAll("\\?.*$", "");
                if (!pathInfo.isEmpty() && pathInfo.matches("/[A-Za-z0-9._/-]{1,200}")) {
                    String expected = RC_DIR + pathInfo;
                    entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.14"))
                            .put("text", "PATH_INFO: " + pathInfo + "\n"
                                + sh("ls -l " + expected + " 2>&1", 20) + "\n"
                                + sh("ls -d " + RC_DIR + "/skins/*/ 2>&1 | head -5", 20)));
                }

                // L'esperimento che separa le due possibilita': static.php eseguito a mano,
                // con un PATH_INFO noto e senza web server di mezzo. Se qui il file esce,
                // l'applicazione funziona e il problema e' in cio' che nginx le manda; se
                // fallisce anche qui, il problema e' dentro static.php o nei suoi percorsi.
                if (!pathInfo.isEmpty() && pathInfo.matches("/[A-Za-z0-9._/-]{1,200}")) {
                    String cd = "cd " + RC_DIR + "/public_html && ";
                    String reqUri = "/static.php" + pathInfo;
                    String withPathInfo = sh(cd + "env PATH_INFO='" + pathInfo + "' REQUEST_URI='" + reqUri
                            + "' REQUEST_METHOD=GET php static.php 2>&1 | head -c 400", 60);
                    String withoutPathInfo = sh(cd + "env -u PATH_INFO REQUEST_URI='" + reqUri
                            + "' REQUEST_METHOD=GET php static.php 2>&1 | head -c 400", 60);
                    entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.15"))
                            .put("text",
                                "--- " + I18n.tr("server.um.x.withPathInfo", java.util.Map.of("v", String.valueOf(pathInfo))) + " ---\n"
                                + summarizeOutput(withPathInfo)
                                + "\n\n--- " + I18n.tr("server.um.x.withoutPathInfo", java.util.Map.of("v", String.valueOf(reqUri))) + " ---\n"
                                + summarizeOutput(withoutPathInfo)));
                }

                // Cosa riceve PHP passando da nginx: e' l'altra meta' della bisezione.
                JSONObject probe = probePathInfo();
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.16"))
                        .put("text", probe.optBoolean("ok")
                            ? I18n.tr("server.um.x.testRequest", java.util.Map.of("url", String.valueOf(probe.optString("url")))) + "\n\n"
                              + probe.optString("output")
                            : I18n.tr("server.um.x.notSucceeded", java.util.Map.of("e", String.valueOf(probe.optString("error"))))));

                // Il codice vero installato su QUESTO server, non quello del repository a monte.
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.17"))
                        .put("text", sh("head -45 " + RC_DIR + "/public_html/static.php 2>&1", 30)));

                // PHP puo' essere confinato: se non gli e' permesso uscire da public_html,
                // static.php non raggiunge le skin e risponde 404 pur funzionando.
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.18"))
                        .put("text", sh("grep -rhnE '^[^;]*(open_basedir|chroot|chdir)' "
                            + "/usr/local/etc/php.ini /usr/local/etc/php-fpm.conf "
                            + "/usr/local/etc/php-fpm.d/ /usr/local/etc/php/ 2>/dev/null | head -12", 30)
                            .trim().isEmpty()
                            ? I18n.tr("server.um.roundcubeDiagnostics.19")
                            : sh("grep -rhnE '^[^;]*(open_basedir|chroot|chdir)' "
                                + "/usr/local/etc/php.ini /usr/local/etc/php-fpm.conf "
                                + "/usr/local/etc/php-fpm.d/ /usr/local/etc/php/ 2>/dev/null | head -12", 30)));
            }

            // 7. Il blocco server, come sta adesso sul disco
            if (!"?".equals(file)) {
                int line = roots.getJSONObject(0).getInt("line");
                int from = Math.max(1, line - 12), a2 = line + 22;
                entries.put(new JSONObject().put("title", I18n.tr("server.um.roundcubeDiagnostics.20", java.util.Map.of("line", String.valueOf(line))))
                        .put("text", sh("sed -n '" + from + "," + a2 + "p' " + file + " 2>&1", 30)));
            }
            return r.put("success", true).put("entries", entries);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject startRoundcubeUpdate() {
        String id = "rc-" + System.currentTimeMillis();
        Job j = new Job(id, "roundcube");
        return startOnTurn(id, j, I18n.tr("server.um.startRoundcubeUpdate.1"), "roundcube-update", () -> runRoundcubeUpdate(j));
    }

    /**
     * Salto di versione maggiore di Roundcube.
     *
     * Il pacchetto e' la parte facile. La parte che rompe e' lo SCHEMA del database: la 1.7 lo
     * cambia, e finche' non si esegue bin/updatedb.sh la webmail non funziona. E quel cambio
     * non si annulla, quindi la copia del database viene prima di tutto.
     * L'altra insidia e' OPcache: aggiornati i file PHP, php-fpm continuerebbe a servire il
     * codice vecchio gia' compilato in memoria — aggiornato sul disco, non in servizio.
     */
    private static void runRoundcubeUpdate(Job job) {
        job.status = "running";
        final int TOT = 8;
        boolean unlocked = false;
        String pkg = "", backupDir = "";
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runRoundcubeUpdate.1"));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = roundcubePreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.write("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            pkg = pf.optString("pkg", "");
            long tablesBefore = pf.optLong("tables", 0);
            job.write("  " + pkg + " " + pf.optString("current") + " -> " + pf.optString("available"));
            job.write("  " + I18n.tr("server.um.x.dbTables", java.util.Map.of("db", String.valueOf(pf.optString("db")), "n", String.valueOf(tablesBefore))));

            job.advance(2, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.2", java.util.Map.of("total", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            backupDir = "/var/db/mailpanel/roundcube/" + ts;
            if (!ok("mkdir -p " + backupDir, 30)) throw new IllegalStateException("cannot create " + backupDir);
            ok("cp -p " + RC_DIR + "/config/config.inc.php " + backupDir + "/config.inc.php", 30);
            JSONObject cp = rcDump(backupDir + "/roundcube.sql");
            if (!cp.optBoolean("ok")) {
                job.write("    " + cp.optString("error"));
                throw new IllegalStateException("the database copy did not succeed: I do not go ahead "
                        + "without a way back. The reason is the line above.");
            }
            if (cp.has("reduced")) {
                job.write("    " + I18n.tr("server.um.x.copyReduced", java.util.Map.of("mode", String.valueOf(I18n.tr(cp.optString("mode"))))));
                job.write("    " + I18n.tr("server.um.x.didNotPass", java.util.Map.of("r", String.valueOf(cp.getString("reduced")))));
                job.write(I18n.tr("server.um.runRoundcubeUpdate.3"));
            }
            job.write("    " + I18n.tr("server.um.x.copyVerified", java.util.Map.of("file", String.valueOf(backupDir + "/roundcube.sql"), "kb", String.valueOf(number(sh("wc -c < " + backupDir + "/roundcube.sql", 30)) / 1024))));
            job.write(I18n.tr("server.um.runRoundcubeUpdate.4"));

            job.advance(3, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.5", java.util.Map.of("total", String.valueOf(TOT))));
            if (locked(sh("pkg lock -l 2>/dev/null"), pkg)) {
                // Prima l'elenco su disco, poi lo sblocco: se l'elenco non si scrive, non si sblocca.
                String stateError = PackageQueue.writeState(java.util.List.of(pkg));
                if (stateError != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I do not unlock " + pkg + ": " + stateError);
                // Da qui il finally riprotegge e chiude l'elenco, anche se lo sblocco fallisse a meta'.
                unlocked = true;
                if (!ok("pkg unlock -y " + pkg, 30)) throw new IllegalStateException("I could not unlock " + pkg);
                job.write("    " + I18n.tr("server.um.x.unlockedTemp"));
            }
            String sim = sh("pkg upgrade -n " + pkg + " 2>&1", 300);
            if (sim.toLowerCase().contains("conflicts with")) {
                for (String l : sim.split("\n")) if (l.toLowerCase().contains("conflict")) job.write("      " + l.trim());
                throw new IllegalStateException("the update would overwrite files of another package: I stop.");
            }
            StringBuilder cat = new StringBuilder();
            int code = runLogged(job, "pkg upgrade -y " + pkg + " 2>&1", 1800, cat);
            if (code != 0) throw new IllegalStateException("pkg upgrade exited with code " + code);
            for (String m : messagesAskingForAction(cat.toString())) {
                job.write("    " + I18n.tr("server.um.x.pkgAsks", java.util.Map.of("m", String.valueOf(m.replace("\n", " | ")))));
            }

            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.6", java.util.Map.of("total", String.valueOf(TOT))));
            // Il pacchetto puo' aver messo un config di esempio al posto del tuo.
            JSONObject dsnAfter = dsnRoundcube();
            if (!dsnAfter.optBoolean("ok")) {
                ok("cp -p " + backupDir + "/config.inc.php " + RC_DIR + "/config/config.inc.php", 30);
                job.write(I18n.tr("server.um.runRoundcubeUpdate.7"));
            } else job.write("    " + I18n.tr("server.um.x.confIntact"));

            job.advance(5, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.8", java.util.Map.of("total", String.valueOf(TOT))));
            String out = sh("cd " + RC_DIR + " && php bin/updatedb.sh --package=roundcube --dir=SQL 2>&1", 900);
            for (String l : out.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
            String ol = out.toLowerCase();
            if (ol.contains("error") || ol.contains("fatal") || ol.contains("failed")) {
                throw new IllegalStateException("updatedb.sh reported an error: the database copy is in "
                        + backupDir + "/roundcube.sql");
            }

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.9", java.util.Map.of("total", String.valueOf(TOT))));
            String rootOutcome = "unneeded";
            if (pf.optBoolean("rootChange", false)) {
                rootOutcome = moveNginxRoot(job, backupDir);
                if ("failed".equals(rootOutcome))
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.10", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            } else job.write(I18n.tr("server.um.runRoundcubeUpdate.11"));
            boolean rootOk = !"failed".equals(rootOutcome);

            job.advance(7, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.12", java.util.Map.of("total", String.valueOf(TOT))));
            // Il pacchetto ha appena rimesso logs e temp a www:www: tornano alla webmail prima che
            // php-fpm riparta, non alla fine del lavoro, perche' la prova qui sotto li usa gia'.
            java.util.List<String> given = RoundcubeUser.repairOwnership();
            if (!given.isEmpty())
                job.write(I18n.tr("server.um.runRoundcubeUpdate.ownership", java.util.Map.of("user", RoundcubeUser.USER,
                        "n", String.valueOf(given.size()))));
            String svc = realServiceName("php_fpm");
            if (svc != null) {
                ok("service " + svc + " restart", 120);
                job.write("    " + svc + ": " + (ok("service " + svc + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26")));
            } else job.write(I18n.tr("server.um.runRoundcubeUpdate.13"));

            job.advance(8, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runRoundcubeUpdate.14", java.util.Map.of("total", String.valueOf(TOT))));
            long tablesAfter = number(rcQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='"
                    + pf.optString("db") + "';"));
            job.write(I18n.tr("server.um.runRoundcubeUpdate.15", java.util.Map.of("tablesBefore", String.valueOf(tablesBefore), "tablesAfter", String.valueOf(tablesAfter))));
            boolean tabOk = tablesAfter >= tablesBefore;
            if (!tabOk) job.write(I18n.tr("server.um.runRoundcubeUpdate.16"));

            // La webmail risponde davvero? Non basta che i file siano aggiornati.
            //
            // E bisogna chiederlo AL SERVER. Chiedendolo al nome pubblico si finisce a parlare
            // con cio' che sta davanti — una CDN, un proxy — e a prendere la sua risposta per
            // quella del server: e' successo qui, con un 403 di Cloudflare scambiato per un
            // guasto della webmail mentre nginx non aveva nemmeno visto la richiesta.
            JSONObject pw = testWebmailOrigin();
            boolean testedWeb = !pw.has("error") || pw.has("code");
            boolean webOk = pw.optBoolean("ok");
            if (!testedWeb) {
                job.write("    " + I18n.tr("server.um.x.webTestNotRun", java.util.Map.of("e", String.valueOf(pw.optString("error")))));
                webOk = true;   // non provata non vuol dire guasta: non boccio cio' che non ho misurato
            } else if (webOk) {
                job.write("    " + I18n.tr("server.um.x.urlAnswersOrigin", java.util.Map.of("url", String.valueOf(pw.optString("url")), "code", String.valueOf(pw.optString("code")))));
            } else {
                job.write("    " + I18n.tr("server.um.x.urlAnswersBad", java.util.Map.of("url", String.valueOf(pw.optString("url")), "code", String.valueOf(pw.optString("code")))));
                if (pw.optBoolean("viaCdn"))
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.17"));
            }

            if (tabOk && webOk && rootOk) {
                job.status = "completed";
                job.write("");
                // "In servizio" si puo' dire solo se qualcuno l'ha visto rispondere. Senza quella
                // prova il lavoro puo' essere andato benissimo, ma il verdetto sarebbe piu' verde
                // delle prove che ho: allora lo dico, e la verifica la fai tu.
                job.write(testedWeb
                        ? I18n.tr("server.um.runRoundcubeUpdate.18")
                        : I18n.tr("server.um.runRoundcubeUpdate.19"));
                if (!testedWeb)
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.20"));
                if ("unneeded".equals(rootOutcome) && pf.optBoolean("rootChange", false))
                    job.write(I18n.tr("server.um.runRoundcubeUpdate.21"));
                job.write(I18n.tr("server.um.runRoundcubeUpdate.22", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                job.write(I18n.tr("server.um.runRoundcubeUpdate.23"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRoundcubeUpdate.24", java.util.Map.of("backupDir", String.valueOf(backupDir)));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (unlocked && !pkg.isEmpty()) {
                boolean r = ok("pkg info -e " + pkg, 15) && ok("pkg lock -y " + pkg, 30);
                job.write("");
                job.write(r ? I18n.tr("server.um.x.reprotectOk", java.util.Map.of("pkg", String.valueOf(pkg))) : I18n.tr("server.um.x.reprotectFail", java.util.Map.of("pkg", String.valueOf(pkg))));
                if (r) clearState();
            }
            job.finishedAt = System.currentTimeMillis();
        }
    }

    // ===================== aggiornamento della JVM del pannello =====================

    private static final String JDK_DIR = "/var/db/mailpanel/jdk";
    /** Dove finisce cio' che il pannello scrive quando riparte staccato dal terminale. */
    private static final String PANEL_LOG = "/var/db/mailpanel/panel.log";

    /**
     * La riga di comando che riavvia QUESTO pannello, ricostruita dal processo vivo.
     *
     * Non si legge da uno script sul disco: quello potrebbe essere vecchio, assente, o non
     * essere quello con cui il pannello e' stato davvero acceso. Si prende la java in uso,
     * le opzioni con cui questa macchina virtuale e' partita e il file jar da cui questa
     * classe e' stata caricata. Se il pannello e' stato avviato con "java -jar x.jar" e basta,
     * la riga ricostruita e' altrettanto spoglia — ed e' giusto cosi': si riparte come si era.
     */
    public static String startCommand(boolean webOnly) {
        StringBuilder c = new StringBuilder(System.getProperty("java.home", "") + "/bin/java");
        for (String a : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            // Le opzioni di misurazione non si riportano: appartengono a chi stava osservando.
            if (a.startsWith("-agentlib") || a.startsWith("-javaagent") || a.startsWith("-Xdebug")) continue;
            c.append(' ').append(a);
        }
        String jar = jarPath();
        if (!jar.isEmpty()) c.append(" -jar ").append(jar);
        return webOnly ? c.append(" --web").toString() : c.toString();
    }

    /** Il file jar da cui gira questo pannello, o stringa vuota se non e' un jar. */
    public static String jarPath() {
        try {
            java.io.File f = new java.io.File(
                    UpdateManager.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return f.isFile() ? f.getAbsolutePath() : "";
        } catch (Exception e) { return ""; }
    }

    /**
     * Scrive run.sh accanto al jar, se non c'e' gia'.
     *
     * Non e' un file da distribuire: e' una comodita' che il pannello si crea da solo, e per
     * questo rispecchia l'avvio VERO invece di una riga scritta a mano mesi fa. Se esiste gia'
     * non lo tocca: potrebbe essere stato adattato, e sovrascriverlo cancellerebbe l'adattamento
     * senza dire niente.
     */
    public static String createRunSh() {
        try {
            String jar = jarPath();
            if (jar.isEmpty()) return "";
            Path f = Paths.get(jar).getParent().resolve("run.sh");
            if (Files.exists(f)) return "";
            Files.writeString(f, "#!/bin/sh\n"
                + "# Creato dal pannello: rispecchia come e' stato avviato davvero.\n"
                + "# Senza argomenti: menu a schermo (serve un terminale).\n"
                + "# Con --web: solo il server web, senza menu e senza terminale.\n"
                // La cartella non e' quella del jar ma quella da cui il pannello e' PARTITO:
                // "./database" e "./install_scripts" sono relativi a quella. Nel caso normale
                // coincidono, ma se non coincidessero un run.sh che entra nella cartella del jar
                // farebbe nascere un secondo database vuoto accanto al primo, senza dire niente.
                + "cd '" + System.getProperty("user.dir", ".") + "' || exit 1\n"
                + "exec " + startCommand(false) + " \"$@\"\n");
            ok("chmod 700 " + f, 15);
            return I18n.tr("server.um.createRunSh.1", java.util.Map.of("f", String.valueOf(f)));
        } catch (Exception e) { return ""; }
    }

    /**
     * Come si rilancia il pannello dopo averlo fermato.
     *
     * Non si indovina: si ricostruisce la riga di comando di QUESTO processo — stessa java,
     * stesse opzioni della macchina virtuale, stesso file jar — e le si aggiunge --web.
     *
     * Il --web e' la chiave di tutto. Il pannello ha un'interfaccia a schermo che pretende un
     * terminale, e uno script staccato non ne ha uno: rilanciarlo normalmente lo farebbe morire
     * un istante dopo, lasciando il pannello web spento. In modalita' solo-web il terminale non
     * serve, quindi il ritorno e' certo. Si perde il MENU a schermo, non il pannello: per
     * riaverlo basta fermare il processo e riavviarlo da SSH senza --web.
     */
    private static JSONObject restartStrategy() {
        String dir = System.getProperty("user.dir", "");
        String binJava = System.getProperty("java.home", "") + "/bin/java";
        String jar = "";
        try {
            java.net.URL u = UpdateManager.class.getProtectionDomain().getCodeSource().getLocation();
            java.io.File f = new java.io.File(u.toURI());
            if (f.isFile()) jar = f.getAbsolutePath();
        } catch (Exception ignored) { }

        String command = startCommand(true);

        return new JSONObject()
                .put("dir", dir)
                .put("menuCommand", startCommand(false))
                .put("jar", jar)
                .put("command", command)
                // -f manda i tre descrittori a /dev/null, e da solo butta via TUTTO cio' che il
                // pannello scrive: e' successo il 31/08/2026, pannello riacceso e muto, senza
                // nessun modo di sapere cosa stesse facendo. -o riporta stdout e stderr in un
                // file, e per daemon(8) le due opzioni si combinano proprio cosi': prima
                // /dev/null, poi la redirezione al file. -t da' al processo un nome riconoscibile
                // in ps, cosi' si trova senza cercare "java" fra tutti i java.
                .put("log", PANEL_LOG)
                .put("line", "/usr/sbin/daemon -f -o " + PANEL_LOG + " -t mailpanel"
                        + " -- /bin/sh -c \"cd '" + dir + "' && exec " + command + "\"")
                .put("note", jar.isEmpty()
                        ? I18n.tr("server.um.restartStrategy.1")
                        : I18n.tr("server.um.restartStrategy.2", java.util.Map.of("p", String.valueOf(startCommand(false)))))
                .put("ok", !jar.isEmpty());
    }

    /**
     * La porta su cui il pannello sta ascoltando ADESSO, chiesta al sistema operativo.
     *
     * Si potrebbe leggerla dalla configurazione, ma la configurazione dice cosa era stato
     * chiesto, non cosa sta succedendo. Qui serve sapere su cosa ribussare dopo il riavvio,
     * quindi vale solo il fatto: quale porta ha aperto questo PID. Se non si riesce a
     * stabilirlo si torna 0, e lo script salta la verifica invece di controllare la porta
     * sbagliata e dichiarare un guasto che non c'e'.
     */
    private static int listeningPort(long pid) {
        for (String line : sh("sockstat -46l 2>/dev/null").split("\n")) {
            String[] c = line.trim().split("\\s+");
            if (c.length < 6 || !c[2].equals(String.valueOf(pid))) continue;
            String address = c[5];
            int i = Math.max(address.lastIndexOf(':'), address.lastIndexOf('.'));
            if (i < 0) continue;
            try {
                int port = Integer.parseInt(address.substring(i + 1));
                if (port > 0 && port < 65536) return port;
            } catch (NumberFormatException ignored) { }
        }
        return 0;
    }

    /** Il pacchetto che possiede la JVM su cui gira QUESTO processo. Non si deduce dal nome. */
    private static String jvmPackage() {
        String home = System.getProperty("java.home", "");
        if (home.isEmpty()) return "";
        // "pkg which -q" risponde NOME-VERSIONE (openjdk25-25.0.2+10.f.1_2), non il nome.
        // Con quello "pkg rquery" non trova niente, e una risposta vuota sembra "sei a posto".
        // La normalizzazione la fa pkg stesso: e' l'unico che sa dove finisce il nome, visto
        // che le versioni contengono + . _ e i nomi contengono cifre e trattini.
        String nv = sh("pkg which -q " + home + "/bin/java 2>/dev/null").trim();
        if (!nv.matches("[A-Za-z0-9._+-]{1,80}")) return "";
        // Non do per buona nemmeno la risposta di pkg: la accetto solo se il pacchetto
        // con quel nome esiste davvero. E' cio' che distingue un nome da una stringa.
        String name = sh("pkg query %n " + nv + " 2>/dev/null").trim();
        if (name.matches("[A-Za-z0-9._+-]{1,64}") && ok("pkg info -e " + name, 15)) return name;
        // Ripiego: taglio all'ultimo trattino seguito da una cifra, dove inizia la versione,
        // e accetto il risultato solo se pkg conferma che quel pacchetto esiste davvero.
        Matcher m = Pattern.compile("^(.+)-[0-9][^-]*$").matcher(nv);
        return m.find() && ok("pkg info -e " + m.group(1), 15) ? m.group(1) : "";
    }

    /**
     * Controlli preliminari per l'aggiornamento della JVM. Tutti in sola lettura.
     *
     * Questo aggiornamento e' diverso da tutti gli altri per un motivo solo: il pannello CI GIRA
     * SOPRA. Sostituire i file della JVM sotto un processo vivo rompe l'avvio dei sottoprocessi
     * (jspawnhelper smette di combaciare con la JVM in memoria), quindi da quel momento ogni
     * comando fallirebbe e ogni stato riportato dal pannello sarebbe falso. Per questo il lavoro
     * lo fa uno script staccato: prima il pannello si ferma, poi si aggiorna, poi si riparte.
     */
    public static JSONObject javaPreflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean lock = false;
        try {
            String pkg = jvmPackage();
            String home = System.getProperty("java.home", "");
            if (pkg.isEmpty()) {
                addCheck(checks, "pkg", I18n.tr("server.um.x.jvmInUse"), "block",
                        I18n.tr("server.um.javaPreflight.1", java.util.Map.of("home", String.valueOf(home))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", true).put("canProceed", false);
            }
            r.put("pkg", pkg);
            String vIns = sh("pkg query %v " + pkg + " 2>/dev/null").trim();
            String vRepo = sh("pkg rquery -U %v " + pkg + " 2>/dev/null").trim();
            r.put("current", vIns).put("available", vRepo).put("home", home);
            addCheck(checks, "pkg", I18n.tr("server.um.x.jvmInUse"), "ok",
                    I18n.tr("server.um.javaPreflight.2", java.util.Map.of("pkg", String.valueOf(pkg), "vIns", String.valueOf(vIns), "home", String.valueOf(home))));
            if (vRepo.isEmpty()) {
                addCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "block",
                        I18n.tr("server.um.javaPreflight.3", java.util.Map.of("pkg", String.valueOf(pkg))));
                lock = true;
            } else if (vRepo.equals(vIns)) {
                addCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "ok",
                        I18n.tr("server.um.javaPreflight.4", java.util.Map.of("vIns", String.valueOf(vIns))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", false).put("canProceed", false).put("already", true);
            } else {
                addCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "wait",
                        I18n.tr("server.um.javaPreflight.5", java.util.Map.of("vIns", String.valueOf(vIns), "vRepo", String.valueOf(vRepo), "home", String.valueOf(home))));
            }

            JSONObject st = restartStrategy();
            r.put("restart", st);
            if (!st.optBoolean("ok")) {
                addCheck(checks, "start", I18n.tr("server.um.javaPreflight.6"), "block", st.getString("note"));
                lock = true;
            } else {
                addCheck(checks, "start", I18n.tr("server.um.javaPreflight.6"), "wait", st.getString("note"));
                addCheck(checks, "cmd", I18n.tr("server.um.javaPreflight.7"), "ok",
                        "in " + st.getString("dir") + ":  " + st.getString("command"));
            }

            if (!ok("test -x /usr/sbin/daemon", 10)) {
                addCheck(checks, "daemon", I18n.tr("server.um.x.scriptDetach"), "block",
                        I18n.tr("server.um.javaPreflight.8"));
                lock = true;
            } else {
                addCheck(checks, "daemon", I18n.tr("server.um.x.scriptDetach"), "ok",
                        I18n.tr("server.um.javaPreflight.9"));
            }

            // Via di ritorno: un pacchetto ricostruito dai file INSTALLATI, non scaricato dal
            // repository. Se il repository non ha piu' la versione vecchia, e' l'unico modo.
            long free = number(sh("df -k /var/db | tail -1 | awk '{print $4}'", 30)) / 1024;
            long large = number(sh("pkg query %sb " + pkg + " 2>/dev/null", 30)) / 1024 / 1024;
            r.put("spaceMb", free).put("jdkMb", large);
            if (large > 0 && free < large * 2) {
                addCheck(checks, "space", I18n.tr("server.um.javaPreflight.10"), "block",
                        I18n.tr("server.um.javaPreflight.11", java.util.Map.of("p", String.valueOf((large * 2)), "free", String.valueOf(free))));
                lock = true;
            } else {
                addCheck(checks, "space", I18n.tr("server.um.javaPreflight.10"), "ok",
                        I18n.tr("server.um.javaPreflight.12", java.util.Map.of("size", String.valueOf(large), "jdkDir", String.valueOf(JDK_DIR), "free", String.valueOf(free))));
            }

            addCheck(checks, "down", I18n.tr("server.um.x.downtime"), "wait",
                    I18n.tr("server.um.javaPreflight.13"));

            r.put("success", true).put("checks", checks)
             .put("blocked", lock).put("canProceed", !lock);
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * Prepara lo script, lo verifica e lo lancia staccato. Poi il pannello muore: da quel
     * momento in poi l'unico testimone e' il file di log, che si rilegge alla riaccensione.
     */
    public static JSONObject startJavaUpdate() {
        // Il turno vale per la preparazione e il lancio. Poi lo script lavora fuori dal pannello:
        // da li' in avanti lo copre l'elenco su disco, che ferma ogni altro lavoro sui pacchetti
        // finche' il pannello riacceso non lo chiude.
        String id = "jdk-" + System.nanoTime();
        String refusal = PackageQueue.take(id, I18n.tr("server.um.startJavaUpdate.1"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        try { return startJavaUpdateNow(); }
        finally { PackageQueue.release(id); }
    }

    private static JSONObject startJavaUpdateNow() {
        try {
            JSONObject pf = javaPreflight();
            if (!pf.optBoolean("canProceed", false))
                return new JSONObject().put("success", false)
                        .put("error", pf.optBoolean("already", false)
                                ? I18n.tr("server.um.x.alreadyLatest") : I18n.tr("server.um.startJavaUpdateNow.1"));
            String pkg = pf.getString("pkg");
            if (!isValidName(pkg)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
            JSONObject st = pf.getJSONObject("restart");
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.10"));
            String bk = JDK_DIR + "/" + ts;
            String log = bk + ".log";
            if (!ok("mkdir -p " + bk, 30))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startJavaUpdateNow.2", java.util.Map.of("backup", String.valueOf(bk))));

            long pid = ProcessHandle.current().pid();
            int port = listeningPort(pid);

            String script = javaUpdateScript(pkg, pf.optString("home"), bk, log, pid,
                    st.getString("line"), st.getString("dir"), port);
            String path = bk + "/upgrade-jdk.sh";
            Files.writeString(Paths.get(path), script);
            ok("chmod 700 " + path, 15);

            // Uno script che non si legge non si esegue: meglio scoprirlo adesso che a pannello spento.
            String syntaxCheck = sh("sh -n " + path + " 2>&1", 30);
            if (!syntaxCheck.trim().isEmpty())
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.startJavaUpdateNow.4", java.util.Map.of("trim", String.valueOf(syntaxCheck.trim()))));

            // Il pannello segna i pacchetti sbloccati: se lo script morisse a meta', al prossimo
            // avvio restoreLocksAfterCrash() li riprotegge da solo. Se l'elenco non si scrive,
            // lo script non parte. Finche' l'elenco c'e', nessun altro lavoro sui pacchetti parte:
            // lo script lavora fuori dal pannello, e il turno del pannello non lo vede.
            String stateError = PackageQueue.writeStateForRestart(java.util.List.of(pkg));
            if (stateError != null)
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.startJavaUpdateNow.5", java.util.Map.of("stateError", String.valueOf(stateError))));
            if (!ok("/usr/sbin/daemon -f -- /bin/sh " + path, 30)) {
                clearState();
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.startJavaUpdateNow.6", java.util.Map.of("path", String.valueOf(path))));
            }
            return new JSONObject().put("success", true).put("log", log)
                    .put("note", st.getString("note"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /** L'ultimo resoconto lasciato dallo script, da rileggere quando il pannello e' tornato su. */
    public static JSONObject javaUpdateStatus() {
        try {
            String last = sh("ls -1t " + JDK_DIR + "/*.log 2>/dev/null | head -1").trim();
            if (last.isEmpty())
                return new JSONObject().put("success", true).put("present", false);
            String text = sh("cat " + last + " 2>/dev/null", 30);
            // Il registro di uno script scritto prima del 29/10/2026 ha i marcatori di prima:
            // si portano ai nomi di adesso (file di dati), poi si guarda solo quelli.
            for (String[] m : LegacyNames.pairs("javaScriptOutcomes")) text = text.replace(m[0], m[1]);
            boolean finished = text.contains("=== OUTCOME:");
            boolean succeeded = text.contains("=== OUTCOME: SUCCEEDED");
            // I marcatori restano fissi nel file (si rileggono qui sopra); a chi legge si mostrano
            // nella sua lingua
            String shown = text.replace("=== OUTCOME: SUCCEEDED", "=== " + I18n.tr("server.um.jvs.outcomeOk"))
                    .replace("=== OUTCOME: CANCELLED", "=== " + I18n.tr("server.um.jvs.outcomeCancelled"))
                    .replace("=== OUTCOME: TO CHECK", "=== " + I18n.tr("server.um.jvs.outcomeCheck"));
            return new JSONObject().put("success", true).put("present", true)
                    .put("file", last).put("text", shown).put("finished", finished)
                    .put("succeeded", succeeded);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    private static String javaUpdateScript(String pkg, String home, String bk, String log,
                                                  long pid, String startLine, String dir, int port) {
        // Le righe che lo script stampa sono nella lingua di chi ha avviato l'aggiornamento; le
        // righe "=== OUTCOME: ... ===" restano fisse, perche' javaUpdateStatus le rilegge.
        return "#!/bin/sh\n"
          + "# Generated by the panel: it updates the JVM the panel itself runs on.\n"
          + "exec >> '" + log + "' 2>&1\n"
          + "echo \"=== $(date) ===\"\n"
          + echo(I18n.tr("server.um.jvs.title")) + "\n"
          + "PKG='" + pkg + "'\n"
          + "BK='" + bk + "'\n"
          + "JAVA='" + home + "/bin/java'\n"
          + "\n"
          + echo(I18n.tr("server.um.jvs.s1")) + "\n"
          + "if pkg create -o \"$BK\" \"$PKG\"; then\n"
          + "  # pkg create makes .pkg on recent versions and .txz on older ones: the way back is not\n"
          + "  # tied to an extension, otherwise it would disappear for no reason.\n"
          + "  WAY_BACK=$(ls -1 \"$BK\"/${PKG}-* 2>/dev/null | head -1)\n"
          + "  if [ -n \"$WAY_BACK\" ]; then " + echo(I18n.tr("server.um.jvs.wayBack")) + "; else\n"
          + "    " + echo(I18n.tr("server.um.jvs.noFile")) + "\n"
          + "    " + echo(I18n.tr("server.um.jvs.cancelled")) + "\n"
          + "    echo '=== OUTCOME: CANCELLED ==='; exit 1; fi\n"
          + "else\n"
          + "  " + echo(I18n.tr("server.um.jvs.createFailed")) + "\n"
          + "  " + echo(I18n.tr("server.um.jvs.cancelled")) + "\n"
          + "  echo '=== OUTCOME: CANCELLED ==='; exit 1\n"
          + "fi\n"
          + "\n"
          + echo(I18n.tr("server.um.jvs.s2")) + "\n"
          + "kill " + pid + " 2>/dev/null\n"
          + "i=0\n"
          + "while kill -0 " + pid + " 2>/dev/null; do\n"
          + "  i=$((i+1)); [ $i -ge 45 ] && break; sleep 1\n"
          + "done\n"
          + "if kill -0 " + pid + " 2>/dev/null; then\n"
          + "  " + echo(I18n.tr("server.um.jvs.forceKill")) + "\n"
          + "  kill -9 " + pid + " 2>/dev/null; sleep 2\n"
          + "fi\n"
          + echo(I18n.tr("server.um.jvs.stopped")) + "\n"
          + "\n"
          + echo(I18n.tr("server.um.jvs.s3")) + "\n"
          + "pkg unlock -y \"$PKG\"\n"
          + "if pkg upgrade -y \"$PKG\"; then UPGRADE_RC=0; else UPGRADE_RC=1; " + echo(I18n.tr("server.um.jvs.upgradeFailed")) + "; fi\n"
          + "\n"
          + echo(I18n.tr("server.um.jvs.s4")) + "\n"
          + "if \"$JAVA\" -version 2>&1; then\n"
          + "  " + echo(I18n.tr("server.um.jvs.javaOk")) + "\n"
          + "else\n"
          + "  " + echo(I18n.tr("server.um.jvs.javaKo")) + "\n"
          + "  pkg add -f \"$WAY_BACK\" && " + echo(I18n.tr("server.um.jvs.prevBack")) + " || " + echo(I18n.tr("server.um.jvs.restoreFailed")) + "\n"
          + "  \"$JAVA\" -version 2>&1 || " + echo(I18n.tr("server.um.jvs.javaStillKo")) + "\n"
          + "fi\n"
          + "\n"
          + echo(I18n.tr("server.um.jvs.s5")) + "\n"
          + "pkg lock -y \"$PKG\" && " + echo(I18n.tr("server.um.jvs.relocked")) + " || " + echo(I18n.tr("server.um.jvs.relockFailed")) + "\n"
          + "mkdir -p /var/db/mailpanel\n"
          + "# The log is appended forever: above 10 MB it is set aside, so it does not grow\n"
          + "# without end and a copy of what was there before still remains.\n"
          + "if [ -f '" + PANEL_LOG + "' ] && [ $(stat -f %z '" + PANEL_LOG + "') -gt 10485760 ]; then\n"
          + "  mv '" + PANEL_LOG + "' '" + PANEL_LOG + ".1'\n"
          + "fi\n"
          + "cd " + shellQuote(dir) + " || " + echo(I18n.tr("server.um.jvs.noCd", java.util.Map.of("d", String.valueOf(dir)))) + "\n"
          + startLine + "\n"
          + "\n"
          + echo(I18n.tr("server.um.jvs.s6")) + "\n"
          + "PANEL_UP=1\n"
          + (port > 0
             ? "j=0\n"
             + "while [ $j -lt 90 ]; do\n"
             + "  # -46l and not -4l: the JVM can open the socket in IPv6, and with -4l the panel would\n"
             + "  # look off while it is up. The grep skips the header line. The final boundary is not\n"
             + "  # the end of the line: sockstat prints another column after the local address, so\n"
             + "  # with '$' it would never match. The boundary is a space or the end of the line.\n"
             + "  if sockstat -46l -p " + port + " 2>/dev/null | grep -qE '[:.]" + port + "([[:space:]]|$)'; then PANEL_UP=0; break; fi\n"
             + "  j=$((j+1)); sleep 1\n"
             + "done\n"
             + "[ $PANEL_UP -eq 0 ] && " + echo(I18n.tr("server.um.jvs.listening", java.util.Map.of("port", String.valueOf(port))))
             + " || " + echo(I18n.tr("server.um.jvs.notListening", java.util.Map.of("port", String.valueOf(port)))) + "\n"
             : echo(I18n.tr("server.um.jvs.noPort")) + "\nPANEL_UP=0\n")
          + "\n"
          + "if [ $UPGRADE_RC -eq 0 ] && [ $PANEL_UP -eq 0 ]; then\n"
          + "  echo \"=== OUTCOME: SUCCEEDED ($(date)) ===\"\n"
          + "  " + echo(I18n.tr("server.um.jvs.keepBack")) + "\n"
          + "  " + echo(I18n.tr("server.um.jvs.panelLog", java.util.Map.of("f", String.valueOf(PANEL_LOG)))) + "\n"
          + "else\n"
          + "  echo \"=== OUTCOME: TO CHECK ($(date)) ===\"\n"
          + "  echo \"upgrade=$UPGRADE_RC  panel_up=$PANEL_UP  way_back=$WAY_BACK\"\n"
          + "fi\n";
    }

    /**
     * Una riga "echo" per uno script: il testo fra apici singoli, quindi la shell non espande
     * niente di cio' che c'e' dentro; i segnaposto {MAIUSCOLO} diventano variabili della shell.
     */
    private static String echo(String text) {
        StringBuilder sb = new StringBuilder("echo ");
        Matcher m = Pattern.compile("\\{([A-Z_]{1,20})\\}").matcher(text);
        int last = 0;
        while (m.find()) {
            sb.append(shellQuote(text.substring(last, m.start()))).append("\"$").append(m.group(1)).append('"');
            last = m.end();
        }
        return sb.append(shellQuote(text.substring(last))).toString();
    }

    private static String shellQuote(String s) {
        return "'" + s.replace("'", "'\\''") + "'";
    }

    // ===================== passaggio py311 -> py312 =====================

    /**
     * Legge l'elenco di cio' che "pkg autoremove" toglierebbe.
     *
     * Il punto non e' contare: e' poter dire NO. autoremove ragiona su tutto il sistema, non
     * solo su Python, e una volta lanciato non chiede altro. Quindi o l'elenco si legge per
     * intero e si riconosce ogni nome, oppure la pulizia si salta. "leggibile" e' falso anche
     * quando i nomi letti sono meno di quelli che pkg dichiara: vorrebbe dire che qualcosa
     * sfugge alla lettura, ed e' proprio la riga sfuggita quella che farebbe danno.
     */
    static JSONObject analyzeAutoremove(String out, String expectedPrefix) {
        // Il prefisso arriva come "py311-": se ne ricava la versione per riconoscere anche
        // l'interprete "python311", che della famiglia fa parte quanto gli altri.
        final String verPy = expectedPrefix != null && expectedPrefix.startsWith("py")
                ? expectedPrefix.replaceAll("[^0-9]", "") : "";
        JSONObject r = new JSONObject();
        java.util.List<String> removed = new ArrayList<>(), foreign = new ArrayList<>();
        String o = out == null ? "" : out;
        if (o.toLowerCase().contains("nothing to do")) {
            return r.put("readable", true).put("howMany", 0)
                    .put("removed", new JSONArray()).put("foreign", new JSONArray());
        }
        int declared = -1;
        java.util.regex.Matcher mn = Pattern.compile(
                "(?i)number of packages to be removed:\\s*([0-9]+)").matcher(o);
        if (mn.find()) declared = Integer.parseInt(mn.group(1));

        boolean inside = false;
        for (String line : o.split("\n")) {
            if (line.matches("(?i).*packages to be REMOVED:\\s*")) { inside = true; continue; }
            if (!inside) continue;
            if (line.trim().isEmpty()) { inside = false; continue; }
            java.util.regex.Matcher m = Pattern.compile(
                    "^[ \\t]+([A-Za-z0-9._+-]+):[ \\t]").matcher(line);
            if (!m.find()) { inside = false; continue; }
            removed.add(m.group(1));
            if (!(m.group(1).startsWith(expectedPrefix)
                    || (!verPy.isEmpty() && m.group(1).equals("python" + verPy))))
                foreign.add(m.group(1));
        }
        boolean readable = declared >= 0 && removed.size() == declared;
        return r.put("readable", readable)
                .put("howMany", declared < 0 ? removed.size() : declared)
                .put("removed", new JSONArray(removed))
                .put("foreign", new JSONArray(foreign));
    }


    /** Versione predefinita di Python secondo bsd.default-versions.mk, senza il punto: "312". */
    private static String pyDefault() {
        // Una sola fonte: la stessa tabella che alimenta la scheda "Coerenza predefiniti".
        // Se domani il predefinito dei port passa a 3.13, questa procedura lo segue da sola.
        for (String[] line : DEFAULTS) {
            if ("Python".equals(line[0])) return line[1].replace(".", "");
        }
        return "312";
    }

    /**
     * Un pacchetto appartiene alla vecchia famiglia Python?
     *
     * Non basta il prefisso "py311-": l'interprete si chiama "python311", senza trattino, e
     * cercando solo il prefisso il pannello lo ha dichiarato "estraneo a Python" — una frase
     * assurda letta da chiunque, e sintomo di una classificazione sbagliata. La famiglia sono
     * entrambi.
     */
    static boolean pythonFamily(String name, String version) {
        return name != null && (name.startsWith("py" + version + "-") || name.equals("python" + version));
    }

    /** I py3XX-* installati su richiesta (non tirati dentro come dipendenza). Sono quelli da spostare. */
    private static java.util.List<String> pythonToMove(String old) {
        java.util.List<String> l = new ArrayList<>();
        for (String r : sh("pkg query '%n %a' 2>/dev/null").split("\n")) {
            String[] c = r.trim().split("\\s+");
            if (c.length != 2) continue;
            if (c[0].startsWith("py" + old + "-") && "0".equals(c[1])) l.add(c[0]);
        }
        java.util.Collections.sort(l);
        return l;
    }

    /**
     * Controlli preliminari, tutti in sola lettura.
     *
     * py311 e py312 non sono due versioni dello stesso pacchetto: sono pacchetti DIVERSI, quindi
     * "pkg upgrade" non li tocchera' mai e resterebbero su un Python che prima o poi esce dal
     * supporto. Il passaggio si fa a mano, e ha due punti dove si rompe qualcosa:
     *  - i comandi in /usr/local/bin (certbot, fail2ban-server) appartengono a UNO dei due, quindi
     *    collidono: vanno visti PRIMA, con una simulazione;
     *  - "pkg autoremove" alla fine puo' portarsi via piu' del previsto, perche' ragiona su tutto
     *    il sistema e non solo su Python. Qui si guarda l'elenco prima di eseguirlo.
     */
    public static JSONObject pythonPreflight() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean lock = false;
        try {
            String fresh = pyDefault();
            String old = null;
            for (String r2 : sh("pkg query %n 2>/dev/null").split("\n")) {
                java.util.regex.Matcher m = Pattern.compile("^py(3[0-9]{2})-").matcher(r2.trim());
                if (m.find() && !m.group(1).equals(fresh)) {
                    if (old == null || m.group(1).compareTo(old) < 0) old = m.group(1);
                }
            }
            r.put("newVersion", fresh);
            if (old == null) {
                addCheck(checks, "ver", I18n.tr("server.um.pythonPreflight.1"), "ok",
                        I18n.tr("server.um.pythonPreflight.2", java.util.Map.of("newer", String.valueOf(fresh))));
                return r.put("success", true).put("checks", checks)
                        .put("canProceed", false).put("blocked", false).put("already", true);
            }
            r.put("old", old);
            addCheck(checks, "ver", I18n.tr("server.um.pythonPreflight.1"), "wait",
                    I18n.tr("server.um.pythonPreflight.3", java.util.Map.of("old", String.valueOf(old), "newer", String.valueOf(fresh))));

            final String vec = old;
            java.util.List<String> leaf = pythonToMove(vec);
            long tot = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + vec + "-")).count();
            if (leaf.isEmpty()) {
                addCheck(checks, "leaf", I18n.tr("server.um.pythonPreflight.4"), "block",
                        I18n.tr("server.um.pythonPreflight.5", java.util.Map.of("tot", String.valueOf(tot), "old", String.valueOf(old))));
                lock = true;
            } else {
                addCheck(checks, "leaf", I18n.tr("server.um.pythonPreflight.4"), "ok",
                        String.join(", ", leaf) + "  " + I18n.tr("server.um.x.pyDepsFollow", java.util.Map.of("n", String.valueOf((tot - leaf.size())))));
            }
            r.put("leaf", new JSONArray(leaf));

            // Esiste il corrispondente py312 per ognuno? Senza, il passaggio lascerebbe un buco.
            java.util.List<String> newOnes = new ArrayList<>(), missing = new ArrayList<>();
            for (String v : leaf) {
                String n = "py" + fresh + "-" + v.substring(("py" + old + "-").length());
                if (!isValidName(n)) continue;
                if (sh("pkg rquery -U %n " + n + " 2>/dev/null").trim().isEmpty()) missing.add(n);
                else newOnes.add(n);
            }
            r.put("newPackages", new JSONArray(newOnes));
            if (!missing.isEmpty()) {
                addCheck(checks, "repo", I18n.tr("server.um.pythonPreflight.6"), "block",
                        I18n.tr("server.um.x.pyNoCounterpart", java.util.Map.of("newer", String.valueOf(fresh), "list", String.valueOf(String.join(", ", missing)))));
                lock = true;
            } else if (!newOnes.isEmpty()) {
                addCheck(checks, "repo", I18n.tr("server.um.pythonPreflight.6"), "ok",
                        I18n.tr("server.um.x.pyAllCounterparts", java.util.Map.of("list", String.valueOf(String.join(", ", newOnes)))));
            }

            // Chi dipende dai pacchetti che sto per togliere? Se qualcuno dipende, toglierli
            // porterebbe via anche lui: e' esattamente il caso da non scoprire a cose fatte.
            // Attenzione all'ovvio che non e' ovvio: py311-certbot-nginx DIPENDE da py311-certbot,
            // e si spostano insieme. Un dipendente che fa parte della stessa famiglia py<vecchio>
            // non e' un problema, perche' sparisce e rinasce anche lui. Il problema e' solo un
            // dipendente ESTERNO, che resterebbe senza cio' da cui dipende.
            java.util.List<String> withDependents = new ArrayList<>();
            for (String v : leaf) {
                if (!isValidName(v)) continue;
                java.util.List<String> external = new ArrayList<>();
                for (String d : sh("pkg query %rn " + v + " 2>/dev/null").split("\n")) {
                    String t = d.trim();
                    if (t.isEmpty() || t.startsWith("py" + vec + "-")) continue;
                    external.add(t);
                }
                if (!external.isEmpty()) withDependents.add(v + " <- " + String.join(", ", external));
            }
            if (!withDependents.isEmpty()) {
                addCheck(checks, "dependents", I18n.tr("server.um.pythonPreflight.7"), "block",
                        I18n.tr("server.um.x.rmPullsOthers", java.util.Map.of("list", String.valueOf(String.join(" ; ", withDependents)))));
                lock = true;
            } else {
                addCheck(checks, "dependents", I18n.tr("server.um.pythonPreflight.7"), "ok",
                        I18n.tr("server.um.pythonPreflight.8"));
            }

            // Simulazione vera: e' l'unico modo di sapere quali file collidono.
            if (!newOnes.isEmpty()) {
                String sim = sh("pkg install -n " + String.join(" ", newOnes) + " 2>&1", 300);
                boolean conflicts = sim.toLowerCase().contains("conflicts with");
                r.put("conflict", conflicts);
                if (conflicts) {
                    java.util.List<String> lines = new ArrayList<>();
                    for (String l2 : sim.split("\n")) if (l2.toLowerCase().contains("conflict")) lines.add(l2.trim());
                    addCheck(checks, "sim", I18n.tr("server.um.pythonPreflight.9"), "wait",
                            I18n.tr("server.um.x.pyCollide", java.util.Map.of("lines", String.valueOf(String.join(" | ", lines)), "old", String.valueOf(old))));
                } else {
                    addCheck(checks, "sim", I18n.tr("server.um.pythonPreflight.9"), "ok",
                            I18n.tr("server.um.pythonPreflight.10"));
                }
            }

            // Servizi coinvolti: quelli vanno fermati e riavviati, e verificati dopo.
            java.util.List<String> touchedServices = new ArrayList<>();
            for (String v : leaf) {
                String base = v.substring(("py" + old + "-").length());
                String svc = realServiceName(base);
                if (svc != null) touchedServices.add(svc);
            }
            r.put("services", new JSONArray(touchedServices));
            addCheck(checks, "svc", I18n.tr("server.um.x.servicesInvolved"), "ok", touchedServices.isEmpty()
                    ? I18n.tr("server.um.pythonPreflight.11")
                    : I18n.tr("server.um.x.svcStopStart", java.util.Map.of("list", String.valueOf(String.join(", ", touchedServices)))));

            // Cosa toglierebbe autoremove. Se tocca roba che non e' py<vecchio>, non lo si esegue.
            JSONObject an = analyzeAutoremove(sh("pkg autoremove -n 2>&1", 180), "py" + vec + "-");
            java.util.List<String> foreign = jsonArrayToList(an.optJSONArray("foreign"));
            r.put("autoremoveForeign", new JSONArray(foreign));
            if (!an.optBoolean("readable", false)) {
                addCheck(checks, "auto", I18n.tr("server.um.x.autoremoveTitle"), "wait",
                        I18n.tr("server.um.pythonPreflight.12"));
            } else {
                addCheck(checks, "auto", I18n.tr("server.um.x.autoremoveTitle"), foreign.isEmpty() ? "ok" : "wait",
                        foreign.isEmpty()
                        ? (an.optInt("howMany", 0) == 0 ? I18n.tr("server.um.x.noOrphans")
                           : I18n.tr("server.um.x.onlyPyOrphans", java.util.Map.of("oldVer", String.valueOf(vec), "n", String.valueOf(an.optInt("howMany", 0)))))
                        : I18n.tr("server.um.x.foreignOrphans", java.util.Map.of("list", String.valueOf(String.join(", ", foreign)))));
            }

            addCheck(checks, "backup", I18n.tr("server.um.pythonPreflight.13"), "ok",
                    I18n.tr("server.um.pythonPreflight.14"));

            r.put("success", true).put("checks", checks)
             .put("blocked", lock).put("canProceed", !lock && !newOnes.isEmpty());
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * I resti della vecchia famiglia Python, rimossi uno per uno invece che con autoremove.
     *
     * autoremove ragiona su tutto il sistema: qui vorrebbe portare via anche capstone, che con
     * Python non c'entra, e per questo viene giustamente saltato. Ma cosi' l'interprete vecchio
     * resta installato con le sue vulnerabilita'. La via d'uscita non e' eseguire autoremove
     * chiudendo un occhio: e' togliere SOLO i pacchetti della famiglia, uno alla volta, ognuno
     * dopo aver verificato che nessuno lo richieda piu'. Cosi' l'elenco di cio' che sparisce e'
     * scritto per intero prima di cominciare, e non contiene sorprese.
     *
     * A passaggi ripetuti perche' le dipendenze si liberano a catena: finche' py311-pyinotify
     * c'e', python311 ha un dipendente e non e' togliibile; tolto quello, lo diventa.
     */
    /**
     * Chi fa riferimento al vecchio interprete, fra le cose che RESTERANNO.
     *
     * pkg conosce le dipendenze fra pacchetti, non un file scritto a mano con
     * "#!/usr/local/bin/python3.11" in cima. Quella e' l'unica cosa che la rimozione potrebbe
     * rompere senza che nessun controllo automatico se ne accorga, ed e' il motivo per cui
     * questo controllo esiste.
     *
     * La domanda giusta non e' "qualcuno nomina python3.11?" — lo fanno i py311 stessi, che
     * stanno per sparire — ma "qualcosa che sopravvivera' lo nomina?". Per ogni file trovato si
     * chiede a pkg di chi e': se appartiene alla famiglia che si sta togliendo, sparisce con
     * lei e non e' un problema; se appartiene a un ALTRO pacchetto, o a nessuno perche' l'ha
     * scritto una persona, allora e' esattamente il caso da segnalare.
     */
    static JSONObject interpreterReferences(String old) {
        JSONObject r = new JSONObject();
        JSONArray issues = new JSONArray(), harmless = new JSONArray(), quotes = new JSONArray();
        // 311 -> 3\.11 : il punto va protetto, altrimenti nel regex combacia con qualunque
        // carattere e "python3x11" verrebbe contato come riferimento.
        String escapedOld = old.length() == 3
                ? old.charAt(0) + "\\." + old.substring(1) : old;

        // Cerco chi ESEGUE l'interprete, non chi lo nomina. La differenza non e' teorica: la
        // prima versione di questo controllo trovava /home/panel/admin/updates.html, cioe' la
        // pagina del pannello — e la riga che la faceva scattare era l'avvertenza che ho scritto
        // io, che contiene "#!/usr/local/bin/python3.11" come esempio. Un testo che parla
        // dell'interprete non lo esegue.
        //
        // Le tre forme che eseguono davvero:
        //   - la riga #! in cima a uno script
        //   - il percorso pieno del binario, che e' come lo invocano cron e gli script rc
        //   - "env python3.11", l'altra forma comune di shebang
        String[] modes = {
            "^#!.*python" + escapedOld,
            "/usr/local/bin/python" + escapedOld,
            "env[[:space:]]+python" + escapedOld,
        };
        StringBuilder e = new StringBuilder();
        for (String m : modes) e.append("-e '").append(m).append("' ");

        String where = "/etc /usr/local/etc /usr/local/bin /usr/local/sbin /usr/local/libexec "
                + "/usr/local/www /root /var/cron /var/spool/cron /home";
        // Fuori: i file dei pacchetti Python (spariscono con loro) e le pagine che il pannello
        // genera da se'. Quelle non sono script di nessuno: le scrivo io a ogni avvio.
        String mineOutside = "";
        try {
            String jar = jarPath();
            if (!jar.isEmpty()) {
                String dirJar = Paths.get(jar).getParent().toString();
                mineOutside = " | grep -v '^" + dirJar + "/admin/'";
            }
        } catch (Exception ignored) { }

        String cmd = "grep -rIl " + e.toString().trim() + " " + where
                + " 2>/dev/null | grep -v '^/usr/local/lib/python'"
                + " | grep -viE '\\.(html?|md|log|bak|orig|sample)$'" + mineOutside + " | head -300";
        String out = sh(cmd, 300);
        int reviewed = 0;
        for (String f : out.split("\n")) {
            String file = f.trim();
            if (file.isEmpty()) continue;
            reviewed++;
            String prop = sh("pkg which -q " + file + " 2>/dev/null", 20).trim();
            String name = prop.isEmpty() ? "" : sh("pkg query %n " + prop + " 2>/dev/null", 20).trim();
            boolean ofFamily = !name.isEmpty() && pythonFamily(name, old);

            // Un file che NOMINA il percorso dell'interprete non lo esegue per forza: un testo
            // che lo cita combacia come uno script che lo lancia, e grep non sa distinguerli.
            // La differenza la fanno due fatti verificabili: il file e' eseguibile, oppure sta
            // dove il sistema va a prendere cose da eseguire (cron, rc.d). Tutto il resto e'
            // molto probabilmente prosa, e non deve sbarrare una rimozione legittima — ma
            // finisce comunque in un elenco a parte, perche' "probabile" non e' "certo".
            boolean runnable = ok("test -x " + file, 10);
            boolean executionPlace = file.startsWith("/var/cron/") || file.startsWith("/var/spool/cron/")
                    || file.startsWith("/usr/local/etc/rc.d/") || file.startsWith("/etc/rc.d/")
                    || file.startsWith("/etc/periodic/") || file.startsWith("/usr/local/etc/periodic/")
                    || file.equals("/etc/crontab") || file.startsWith("/etc/rc.conf");
            // La riga che ha fatto scattare il controllo: senza, chi legge non puo' giudicare
            // se sia un'esecuzione vera o una citazione.
            String line = sh("grep -m1 -hIE " + e.toString().trim().replace("-e ", "-e ")
                    + " " + file + " 2>/dev/null | head -c 160", 20).trim();
            JSONObject v = new JSONObject().put("file", file).put("line", line)
                    .put("owner", name.isEmpty()
                            ? (prop.isEmpty() ? I18n.tr("server.um.interpreterReferences.1") : prop) : name);
            v.put("runnable", runnable).put("executionPlace", executionPlace);
            if (ofFamily) harmless.put(v);
            else if (runnable || executionPlace) issues.put(v);
            else quotes.put(v);
        }
        return r.put("reviewed", reviewed).put("issues", issues).put("harmless", harmless)
                .put("quotes", quotes).put("command", cmd);
    }

    /** I resti del vecchio Python; con esegui, li toglie, sul turno dei lavori sui pacchetti. */
    public static JSONObject pythonLeftovers(boolean run) {
        if (!run) return pythonLeftoversNow(false);
        String id = "restipy-" + System.nanoTime();
        String refusal = PackageQueue.take(id, I18n.tr("server.um.pythonLeftovers.1"));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        try { return pythonLeftoversNow(true); }
        finally { refreshLockTrace(); PackageQueue.release(id); }
    }

    private static JSONObject pythonLeftoversNow(boolean run) {
        JSONObject r = new JSONObject();
        try {
            String fresh = pyDefault();
            java.util.LinkedHashSet<String> old = new java.util.LinkedHashSet<>();
            for (String n : sh("pkg query %n 2>/dev/null").split("\n")) {
                Matcher m = Pattern.compile("^(?:py|python)(3[0-9]{2})(?:-|$)").matcher(n.trim());
                if (m.find() && !m.group(1).equals(fresh)) old.add(m.group(1));
            }
            if (old.isEmpty())
                return r.put("success", true).put("nothing", true)
                        .put("note", I18n.tr("server.um.pythonLeftoversNow.1", java.util.Map.of("newer", String.valueOf(fresh))));
            r.put("old", new JSONArray(old));

            java.util.List<String> family = new ArrayList<>();
            for (String v : old)
                for (String n : sh("pkg query %n 2>/dev/null").split("\n"))
                    if (pythonFamily(n.trim(), v)) family.add(n.trim());

            JSONArray detail = new JSONArray();
            java.util.List<String> removable = new ArrayList<>(), heldBack = new ArrayList<>();
            for (String n : family) {
                if (!isValidName(n)) continue;
                String ver = sh("pkg query %v " + n + " 2>/dev/null", 20).trim();
                long kb = number(sh("pkg query %sb " + n + " 2>/dev/null", 20)) / 1024;
                java.util.List<String> who = new ArrayList<>();
                for (String d : sh("pkg query %rn " + n + " 2>/dev/null").split("\n")) {
                    String t = d.trim();
                    if (!t.isEmpty()) who.add(t);
                }
                // Un dipendente che e' anch'esso della famiglia sparira' prima: non trattiene.
                java.util.List<String> external = new ArrayList<>();
                for (String c : who) if (!family.contains(c)) external.add(c);
                boolean free = external.isEmpty();
                (free ? removable : heldBack).add(n);
                detail.put(new JSONObject().put("name", n).put("version", ver).put("kb", kb)
                        .put("free", free).put("heldBackBy", new JSONArray(external)));
            }
            r.put("detail", detail).put("removable", new JSONArray(removable))
             .put("heldBack", new JSONArray(heldBack));

            // Chi nomina il vecchio interprete fra cio' che resta: pkg non lo sa, va cercato.
            JSONObject ref = interpreterReferences(old.iterator().next());
            r.put("references", ref);
            if (!run || removable.isEmpty()) return r.put("success", true).put("executed", false);
            if (ref.getJSONArray("issues").length() > 0)
                return r.put("success", false).put("executed", false)
                        .put("error", I18n.tr("server.um.x.pyRefsLeft", java.util.Map.of("n", String.valueOf(ref.getJSONArray("issues").length()))));

            // Passaggi ripetuti: a ogni giro si tolgono quelli che in QUEL momento non hanno
            // piu' nessuno che li richieda.
            JSONArray removed = new JSONArray(), failed = new JSONArray();
            java.util.List<String> remaining = new ArrayList<>(family);
            for (int round = 0; round < 6 && !remaining.isEmpty(); round++) {
                boolean something = false;
                for (String n : new ArrayList<>(remaining)) {
                    if (!isValidName(n) || !ok("pkg info -e " + n, 15)) { remaining.remove(n); continue; }
                    String dependents = sh("pkg query %rn " + n + " 2>/dev/null").trim();
                    if (!dependents.isEmpty()) continue;                      // ancora richiesto: al prossimo giro
                    boolean wasLocked = locked(sh("pkg lock -l 2>/dev/null"), n);
                    if (wasLocked) ok("pkg unlock -y " + n, 30);
                    if (ok("pkg delete -y " + n, 300)) { removed.put(n); something = true; }
                    else {
                        failed.put(n);
                        // Se la rimozione non riesce, il pacchetto resta: e allora deve restare
                        // com'era, protetto. Sbloccarlo e lasciarlo cosi' sarebbe peggio che non
                        // averci provato, perche' il prossimo aggiornamento potrebbe toccarlo.
                        if (wasLocked) ok("pkg lock -y " + n, 30);
                    }
                    remaining.remove(n);
                }
                if (!something) break;
            }
            r.put("executed", true).put("removed", removed).put("failed", failed)
             .put("remain", new JSONArray(remaining));
            // Verifica: quanti pacchetti della vecchia famiglia sono ancora installati.
            long still = 0;
            for (String v : old)
                still += sh("pkg query %n 2>/dev/null").lines().filter(x -> pythonFamily(x, v)).count();
            r.put("stillPresent", still);
            return r.put("success", true);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject startPythonTransition() {
        String id = "py-" + System.currentTimeMillis();
        Job j = new Job(id, "python");
        return startOnTurn(id, j, I18n.tr("server.um.startPythonTransition.1"), "python-move", () -> runPythonTransition(j));
    }

    private static void runPythonTransition(Job job) {
        job.status = "running";
        final int TOT = 7;
        java.util.List<String> unlockedPackages = new ArrayList<>();
        java.util.List<String> toRelock = new ArrayList<>();
        // L'elenco scritto su disco da questa esecuzione: vuoto finche' non e' scritto.
        java.util.List<String> listOnDisk = new ArrayList<>();
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runPythonTransition.1"));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = pythonPreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("already", false)
                        ? I18n.tr("server.um.runPythonTransition.2") : I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.write("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            String old = pf.getString("old"), fresh = pf.getString("newVersion");
            java.util.List<String> leaf = jsonArrayToList(pf.optJSONArray("leaf"));
            java.util.List<String> newOnes = jsonArrayToList(pf.optJSONArray("newPackages"));
            java.util.List<String> services = jsonArrayToList(pf.optJSONArray("services"));
            job.write("  py" + old + " -> py" + fresh);
            job.write("  " + String.join(", ", leaf));

            job.advance(2, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.3", java.util.Map.of("total", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            String bk = "/var/db/mailpanel/python/" + ts;
            if (!ok("mkdir -p " + bk, 30)) throw new IllegalStateException("cannot create " + bk);
            sh("pkg query '%n %v' > " + bk + "/packages-before.txt 2>/dev/null", 60);
            for (String d : new String[]{"/usr/local/etc/fail2ban", "/usr/local/etc/letsencrypt"}) {
                if (!ok("test -d " + d, 10)) { job.write(I18n.tr("server.um.runPythonTransition.5", java.util.Map.of("d", String.valueOf(d)))); continue; }
                String name = d.substring(d.lastIndexOf('/') + 1);
                if (!ok("tar -cf " + bk + "/" + name + ".tar -C " + d + " . 2>/dev/null", 300))
                    throw new IllegalStateException("copy of " + d + " failed");
                long n = number(sh("tar -tf " + bk + "/" + name + ".tar 2>/dev/null | wc -l", 60));
                if (n < 1) throw new IllegalStateException("the copy of " + d + " is empty");
                job.write("    " + d + " -> " + name + ".tar " + I18n.tr("server.um.x.entries", java.util.Map.of("n", String.valueOf(n))));
            }
            job.write("    " + I18n.tr("server.um.x.copiesIn", java.util.Map.of("dir", String.valueOf(bk))));

            job.advance(3, TOT);
            job.write("");
            job.write("[3/" + TOT + "] " + I18n.tr("server.um.x.stoppingSvcs"));
            if (services.isEmpty()) job.write("    " + I18n.tr("server.um.x.none"));
            for (String s : services) {
                boolean wasActive = ok("service " + s + " status", 20);
                if (wasActive) { ok("service " + s + " stop", 120); job.write(I18n.tr("server.um.runPythonTransition.6", java.util.Map.of("s", String.valueOf(s)))); }
                else job.write("    " + s + ": " + I18n.tr("server.um.x.wasStopped"));
            }

            job.advance(4, TOT);
            job.write("");
            job.write("[4/" + TOT + "] " + I18n.tr("server.um.x.pySwap", java.util.Map.of("old", String.valueOf(old), "newer", String.valueOf(fresh))));
            String list = sh("pkg lock -l 2>/dev/null");
            java.util.List<String> toUnlock = new ArrayList<>();
            for (String v : leaf) if (locked(list, v)) toUnlock.add(v);
            // L'elenco su disco PRIMA di sbloccare (prima lo si scriveva dopo): i vecchi, che vanno
            // riprotetti se restano, e i nuovi, che alla fine vanno protetti. Se il pannello muore
            // in mezzo, l'avvio protegge quelli che trova installati. Se l'elenco non si scrive,
            // non si tocca niente.
            java.util.List<String> toList = new ArrayList<>(toUnlock);
            for (String n : newOnes) if (isValidName(n) && !toList.contains(n)) toList.add(n);
            String stateError = PackageQueue.writeState(toList);
            if (stateError != null)
                throw new IllegalStateException("I could not save the list for the restore, so I did not touch anything: " + stateError);
            listOnDisk.addAll(toList);
            for (String v : toUnlock) { ok("pkg unlock -y " + v, 30); unlockedPackages.add(v); }
            if (!unlockedPackages.isEmpty()) job.write("    " + I18n.tr("server.um.x.unlockedList", java.util.Map.of("list", String.valueOf(String.join(", ", unlockedPackages)))));
            // L'ordine conta: prima togliere, poi installare. Cosi' nessun file va forzato,
            // ed e' esattamente l'errore che ha rotto il client MySQL.
            StringBuilder catDel = new StringBuilder();
            int cd = runLogged(job, "pkg delete -y " + String.join(" ", leaf) + " 2>&1", 900, catDel);
            if (cd != 0) throw new IllegalStateException("pkg delete exited with code " + cd);
            StringBuilder catIns = new StringBuilder();
            int ci = runLogged(job, "pkg install -y " + String.join(" ", newOnes) + " 2>&1", 1800, catIns);
            if (ci != 0) {
                job.write("");
                job.write(I18n.tr("server.um.runPythonTransition.7"));
                job.write(I18n.tr("server.um.x.toGoBack", java.util.Map.of("cmd", String.valueOf("pkg install -y " + String.join(" ", leaf)))));
                throw new IllegalStateException("pkg install exited with code " + ci);
            }
            toRelock.addAll(newOnes);
            for (String m : messagesAskingForAction(catIns.toString()))
                job.write("    " + I18n.tr("server.um.x.pkgAsks", java.util.Map.of("m", String.valueOf(m.replace("\n", " | ")))));

            job.advance(5, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.8", java.util.Map.of("total", String.valueOf(TOT))));
            String ar = sh("pkg autoremove -n 2>&1", 180);
            JSONObject an = analyzeAutoremove(ar, "py" + old + "-");
            java.util.List<String> foreign = jsonArrayToList(an.optJSONArray("foreign"));
            if (!an.optBoolean("readable", false)) {
                job.write(I18n.tr("server.um.runPythonTransition.9"));
                job.write(I18n.tr("server.um.runPythonTransition.10"));
                for (String l2 : ar.split("\n")) if (!l2.trim().isEmpty()) job.write("      " + l2);
            } else if (!foreign.isEmpty()) {
                job.write("    " + I18n.tr("server.um.x.skippedForeign", java.util.Map.of("list", String.valueOf(String.join(", ", foreign)))));
                job.write(I18n.tr("server.um.runPythonTransition.11", java.util.Map.of("old", String.valueOf(old))));
            } else if (an.optInt("howMany", 0) == 0) {
                job.write(I18n.tr("server.um.runPythonTransition.12"));
            } else {
                job.write("    " + I18n.tr("server.um.x.toRemove", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(an.optJSONArray("removed")))))));
                runLogged(job, "pkg autoremove -y 2>&1", 900);
            }

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.13", java.util.Map.of("total", String.valueOf(TOT))));
            boolean servicesOk = true;
            for (String s : services) {
                ok("service " + s + " start", 120);
                boolean su = ok("service " + s + " status", 30);
                job.write("    " + s + ": " + (su ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runPythonTransition.14")));
                if (!su) servicesOk = false;
            }
            if (services.isEmpty()) job.write("    " + I18n.tr("server.um.x.none"));

            job.advance(7, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runPythonTransition.15", java.util.Map.of("total", String.valueOf(TOT))));
            // Che il pacchetto sia installato non dice che il comando parta: e' la lezione
            // del client MySQL, dove tutto risultava a posto e postmap non trovava la libreria.
            // Non indovino il nome del comando dal nome del pacchetto: per py311-fail2ban
            // sbaglierei (i comandi sono fail2ban-server e fail2ban-client, non "fail2ban").
            // Chiedo a pkg quali file eseguibili ha installato davvero.
            boolean commandsOk = true;
            for (String n : newOnes) {
                if (!isValidName(n)) continue;
                int tested = 0;
                for (String f : sh("pkg query %Fp " + n + " 2>/dev/null").split("\n")) {
                    String t = f.trim();
                    if (!t.startsWith("/usr/local/bin/") && !t.startsWith("/usr/local/sbin/")) continue;
                    if (t.contains("test")) continue;   // niente suite di test lanciate per sbaglio
                    if (!ok("test -x " + t, 10)) continue;
                    if (++tested > 4) break;
                    String o = sh(t + " --version 2>&1", 120);
                    String ol = o.toLowerCase();
                    boolean good = !o.trim().isEmpty() && !ol.contains("not found") && !ol.contains("traceback")
                            && !ol.contains("importerror") && !ol.contains("modulenotfound")
                            && !ol.contains("no module named");
                    job.write("    " + t + " --version: "
                            + (good ? o.split("\n")[0].trim() : I18n.tr("server.um.x.failedArrow", java.util.Map.of("o", String.valueOf(o.trim())))));
                    if (!good) commandsOk = false;
                }
                if (tested == 0) job.write(I18n.tr("server.um.runPythonTransition.16", java.util.Map.of("n", String.valueOf(n))));
            }
            long left = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + old + "-")).count();
            job.write(I18n.tr("server.um.runPythonTransition.17", java.util.Map.of("old", String.valueOf(old), "left", String.valueOf(left))));

            if (servicesOk && commandsOk) {
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runPythonTransition.18", java.util.Map.of("newer", String.valueOf(fresh))));
                job.write(I18n.tr("server.um.runPythonTransition.19", java.util.Map.of("backup", String.valueOf(bk))));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runPythonTransition.20", java.util.Map.of("backup", String.valueOf(bk)));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // Si protegge ogni pacchetto dell'elenco che e' installato adesso: i nuovi arrivati e,
            // se il passaggio si e' fermato prima di toglierli, i vecchi. Prima, con un pkg delete
            // fallito, i vecchi restavano installati e sbloccati, con solo un avviso.
            if (!listOnDisk.isEmpty()) {
                java.util.List<String> failed = new ArrayList<>();
                int done = 0;
                for (String n : listOnDisk) {
                    if (!ok("pkg info -e " + n, 15)) continue;   // tolto, o mai arrivato
                    if (ok("pkg lock -y " + n, 30)) done++; else failed.add(n);
                }
                job.write("");
                job.write(failed.isEmpty()
                        ? I18n.tr("server.um.x.reprotectAll", java.util.Map.of("n", String.valueOf(done)))
                        : I18n.tr("server.um.x.reprotectSome", java.util.Map.of("list", String.valueOf(String.join(", ", failed)))));
                if (failed.isEmpty()) clearState();
                else job.write(I18n.tr("server.um.runPythonTransition.21", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
                if (toRelock.isEmpty() && !unlockedPackages.isEmpty()) {
                    job.write(I18n.tr("server.um.x.unlockedNotReplaced", java.util.Map.of("list", String.valueOf(String.join(", ", unlockedPackages)))));
                }
            }
            job.finishedAt = System.currentTimeMillis();
        }
    }

    // ===================== piano di manutenzione guidato =====================

    /** Le opzioni di grep per la firma di dovecot.conf, di adesso e di prima: " -e 'firma' ...". */
    static String dovecotSignatureOptions() {
        StringBuilder b = new StringBuilder();
        for (String f : PanelMarker.forms("dovecotSignature", org.mail_panel.scripts.DovecotConfig.SIGNATURE))
            b.append(" -e '").append(f).append('\'');
        return b.toString();
    }

    /**
     * Il piano: cosa va fatto su QUESTA macchina, in quale ordine, e a che punto sei.
     *
     * Lo stato di ogni passo non e' memorizzato da nessuna parte: viene RICAVATO ogni volta
     * dallo stato reale del sistema. Un flag salvato su disco potrebbe dire "fatto" per un
     * passo che qualcuno ha disfatto, o restare indietro dopo un ripristino; un controllo
     * ricavato dai fatti non puo' mentire. Costa qualche secondo in piu' e vale la pena.
     */
    public static JSONObject maintenancePlan() {
        ok("pkg update -q", 120);
        JSONArray steps = new JSONArray();

        // Dati raccolti UNA volta sola: pkg audit e la simulazione sono lente, e ripeterle
        // per ogni passo trasformerebbe il piano in un'attesa di minuti.
        String audit = sh("pkg audit -F 2>&1", 180);
        String dry = sh("pkg upgrade -n 2>&1", 180);
        String lock = sh("pkg lock -l 2>/dev/null");
        JSONObject state = packagesStatus();
        JSONArray packages = state.getJSONArray("packages");

        // Chi ha gia' una procedura dedicata (fasi F, G, H) non deve comparire ANCHE come passo
        // pacchetto: sarebbe la stessa operazione scritta due volte con parole diverse, e chi
        // legge non puo' sapere se sono una o due. Si decidono qui, una volta, e valgono per
        // entrambi gli elenchi piu' sotto e per le fasi.
        final String rcPkg = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20).trim();
        final String jvmPkg = jvmPackage();
        final String pyNew = pyDefault();
        java.util.function.Predicate<String> covered = n ->
                   (!rcPkg.isEmpty() && rcPkg.equals(n))
                || (!jvmPkg.isEmpty() && jvmPkg.equals(n))
                || (n.matches("^py3[0-9]{2}-.*") && !n.startsWith("py" + pyNew + "-"));

        // --- Passo 1: tutto lo stack protetto ---
        int installed = state.getInt("installedCount"), protectedNames = state.getInt("lockedCount");
        boolean allLocked = installed > 0 && protectedNames == installed;
        steps.put(repeatable(step("phase-protection", "phase", I18n.tr("server.um.x.stepProtect"),
                allLocked ? "done" : "todo",
                I18n.tr("server.um.maintenancePlan.1", java.util.Map.of("lockedNames", String.valueOf(protectedNames), "installedNames", String.valueOf(installed))),
                I18n.tr("server.um.maintenancePlan.2"),
                allLocked ? null : new JSONObject().put("type", "packages_lock_all")),
                new JSONObject().put("type", "packages_lock_all")));

        // --- Passo 2: aggiornare cio' che non e' protetto ---
        Matcher mUp = Pattern.compile("Number of packages to be upgraded:\\s*([0-9]+)").matcher(dry);
        int toUpdate = mUp.find() ? Integer.parseInt(mUp.group(1)) : 0;
        Matcher mIn = Pattern.compile("Number of packages to be installed:\\s*([0-9]+)").matcher(dry);
        int toInstall = mIn.find() ? Integer.parseInt(mIn.group(1)) : 0;
        boolean updatedContext = (toUpdate + toInstall) == 0;
        steps.put(step("phase-unprotected", "phase", I18n.tr("server.um.maintenancePlan.3"),
                updatedContext ? "done" : "todo",
                updatedContext ? I18n.tr("server.um.maintenancePlan.4")
                        : I18n.tr("server.um.maintenancePlan.5", java.util.Map.of("toUpdate", String.valueOf(toUpdate), "toInstall", String.valueOf(toInstall))),
                I18n.tr("server.um.maintenancePlan.6"),
                updatedContext ? null : new JSONObject().put("type", "updates_apply")));

        // --- Passi 3..N: un passo per ogni pacchetto protetto vulnerabile con correzione ---
        // L'ordine e' per numero di CVE chiuse: prima cio' che porta piu' beneficio.
        java.util.List<JSONObject> vulnerable = new ArrayList<>();
        Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
        while (mv.find()) seen.add(mv.group(1));
        for (String name : seen) {
            if (roleOf(name) == null) continue;              // non e' dello stack di posta
            if (covered.test(name)) continue;                 // ha gia' la sua fase dedicata
            String cur = sh("pkg query %v " + name + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + name + " 2>/dev/null", 20);
            if (cur.isEmpty() || av.isEmpty() || av.equals(cur)) continue;   // nessuna correzione disponibile
            boolean major = significantJump(name, cur, av);
            JSONObject warning = warningFor(name, major);
            int nCve = vulnerabilityDetail(audit, name).getJSONArray("cve").length();
            JSONObject o = new JSONObject().put("name", name).put("cur", cur).put("av", av)
                    .put("cve", nCve).put("major", major);
            if (warning != null) o.put("warning", warning);
            vulnerable.add(o);
        }
        vulnerable.sort((x, y) -> Integer.compare(y.getInt("cve"), x.getInt("cve")));
        // Un solo passo per famiglia: proporre "aggiorna mysql80-server" e poi "aggiorna
        // mysql80-client" significherebbe proporre due volte la stessa operazione, e la prima
        // non riuscirebbe nemmeno perche' l'altra meta' resta protetta.
        java.util.LinkedHashSet<String> seenFamilies = new java.util.LinkedHashSet<>();
        java.util.List<JSONObject> unique = new ArrayList<>();
        for (JSONObject v : vulnerable) {
            String fam = familyOf(v.getString("name"));
            String key = fam == null ? v.getString("name") : fam;
            if (seenFamilies.add(key)) unique.add(v);
        }
        vulnerable = unique;
        for (JSONObject v : vulnerable) {
            String name = v.getString("name");
            boolean wait = v.has("warning") && "wait".equals(v.getJSONObject("warning").getString("level"));
            java.util.List<String> mem = familyMembers(name);
            String title = mem.size() > 1
                    ? I18n.tr("server.um.x.updLinkedCve", java.util.Map.of("name", String.valueOf(name), "n", String.valueOf((mem.size() - 1)), "cve", String.valueOf(v.getInt("cve"))))
                    : I18n.tr("server.um.x.updCve", java.util.Map.of("name", String.valueOf(name), "cve", String.valueOf(v.getInt("cve"))));
            steps.put(step("pkg-" + name, "package", title,
                    wait ? "manual" : "todo",
                    name + " " + v.getString("cur") + " -> " + v.getString("av")
                        + (v.getBoolean("major") ? I18n.tr("server.um.maintenancePlan.7") : I18n.tr("server.um.maintenancePlan.8")),
                    wait ? v.getJSONObject("warning").getString("text")
                            : I18n.tr("server.um.maintenancePlan.9"),
                    wait ? null : new JSONObject().put("type", "package_update").put("package", name)));
        }

        // --- Migrazione MySQL, se serve: sta QUI perche' e' un prerequisito di alcuni passi
        //     successivi (Postfix pretende la libreria della 8.4) e perche' viene dopo gli
        //     aggiornamenti di sicurezza indipendenti, che sono piu' urgenti e meno invasivi.
        //     Un piano che dice "prima fai X" senza contenere X non guida: manda a cercare.
        String srvMysql = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        if (!srvMysql.isEmpty()) {
            boolean already84 = srvMysql.startsWith("mysql84");
            String available84 = already84 ? "" : sh("pkg rquery -U %v mysql84-server 2>/dev/null", 30);
            if (already84) {
                steps.put(step("phase-mysql84", "phase", I18n.tr("server.um.maintenancePlan.10"), "done",
                        I18n.tr("server.um.maintenancePlan.11", java.util.Map.of("srvMysql", String.valueOf(srvMysql))),
                        I18n.tr("server.um.maintenancePlan.12"), null));
            } else if (!available84.isEmpty()) {
                steps.put(step("phase-mysql84", "phase", I18n.tr("server.um.maintenancePlan.10"), "manual",
                        I18n.tr("server.um.maintenancePlan.13", java.util.Map.of("srvMysql", String.valueOf(srvMysql), "available84", String.valueOf(available84))),
                        I18n.tr("server.um.maintenancePlan.14"), null));
            }
        }

        // --- Passi per i pacchetti protetti che hanno un aggiornamento ma nessuna CVE ---
        // Non sono urgenti, ma "aggiornare tutto l'aggiornabile" e' una richiesta legittima e
        // il piano deve poterla rappresentare, altrimenti resterebbero invisibili per sempre.
        for (int i = 0; i < packages.length(); i++) {
            JSONObject p = packages.getJSONObject(i);
            String name = p.getString("name");
            if (seen.contains(name)) continue;               // gia' coperto come vulnerabile
            if (covered.test(name)) continue;                 // ha gia' la sua fase dedicata
            String fam = familyOf(name);
            String key = fam == null ? name : fam;
            if (!seenFamilies.add(key)) continue;         // gia' coperto dalla sua famiglia
            String cur = p.optString("version", "");
            String av = sh("pkg rquery -U %v " + name + " 2>/dev/null", 20);
            if (cur.isEmpty() || av.isEmpty() || av.equals(cur)) continue;
            boolean major = significantJump(name, cur, av);
            JSONObject warning = warningFor(name, major);
            boolean wait = warning != null && "wait".equals(warning.getString("level"));
            // Se il pacchetto nuovo pretende un'altra famiglia MySQL, il passo non e' "da fare":
            // e' bloccato finche' MySQL non e' stato migrato. Offrirlo sarebbe proporre
            // un'operazione che il preflight rifiuta un secondo dopo.
            String conflict = mysqlFamilyConflict(name);
            if (conflict != null) {
                java.util.List<String> memC = familyMembers(name);
                steps.put(step("pkg-" + name, "package", memC.size() > 1
                            ? I18n.tr("server.um.maintenancePlan.17", java.util.Map.of("name", String.valueOf(name), "p", String.valueOf(memC.size() - 1)))
                            : I18n.tr("server.um.maintenancePlan.18", java.util.Map.of("name", String.valueOf(name))),
                        "manual",
                        I18n.tr("server.um.maintenancePlan.15", java.util.Map.of("name", String.valueOf(name), "cur", String.valueOf(cur), "av", String.valueOf(av))),
                        I18n.tr("server.um.maintenancePlan.16", java.util.Map.of("conflict", String.valueOf(conflict))),
                        null));
                continue;
            }
            java.util.List<String> mem = familyMembers(name);
            String title = mem.size() > 1
                    ? I18n.tr("server.um.maintenancePlan.17", java.util.Map.of("name", String.valueOf(name), "p", String.valueOf((mem.size() - 1))))
                    : I18n.tr("server.um.maintenancePlan.18", java.util.Map.of("name", String.valueOf(name)));
            steps.put(step("pkg-" + name, "package", title, wait ? "manual" : "todo",
                    name + " " + cur + " -> " + av
                        + (major ? I18n.tr("server.um.maintenancePlan.7") : I18n.tr("server.um.maintenancePlan.8"))
                        + " " + I18n.tr("server.um.x.noKnownVuln"),
                    wait ? warning.getString("text")
                            : (warning != null ? warning.getString("text")
                                           : I18n.tr("server.um.maintenancePlan.19")),
                    wait ? null : new JSONObject().put("type", "package_update").put("package", name)));
        }

        // --- Cache di rspamd rimaste da un aggiornamento precedente ---
        // Esiste come passo solo finche' quei file ci sono: e' lo stesso principio dello
        // stato ricavato, e sparisce da solo quando non serve piu'.
        // Un "zero file trovati" puo' significare due cose opposte: che sono gia' stati
        // eliminati, oppure che ho guardato nel posto sbagliato. Si distingue guardando se la
        // cartella esiste e contiene qualcosa: un'assenza si dimostra, non si presume.
        boolean rspamdPresent = ok("pkg info -e rspamd", 20);
        boolean rspamdFolder = ok("test -d /var/db/rspamd", 15);
        long fileRspamd = rspamdFolder
                ? number(sh("find /var/db/rspamd -type f 2>/dev/null | wc -l", 60)) : 0;
        long unser = rspamdFolder
                ? number(sh("find /var/db/rspamd -type f -name '*.unser' 2>/dev/null | wc -l", 60)) : 0;
        if (rspamdPresent && !rspamdFolder) {
            steps.put(step("phase-rspamd-cache", "phase", I18n.tr("server.um.maintenancePlan.20"), "manual",
                    I18n.tr("server.um.maintenancePlan.21"),
                    I18n.tr("server.um.maintenancePlan.22"), null));
        } else if (unser > 0) {
            steps.put(step("phase-rspamd-cache", "phase", I18n.tr("server.um.maintenancePlan.23"), "todo",
                    I18n.tr("server.um.maintenancePlan.24", java.util.Map.of("unser", String.valueOf(unser))),
                    I18n.tr("server.um.maintenancePlan.25"),
                    new JSONObject().put("type", "rspamd_clean_cache")));
        } else if (rspamdPresent && rspamdFolder) {
            steps.put(step("phase-rspamd-cache", "phase", I18n.tr("server.um.maintenancePlan.26"), "done",
                    I18n.tr("server.um.maintenancePlan.27", java.util.Map.of("rspamdFile", String.valueOf(fileRspamd))),
                    I18n.tr("server.um.maintenancePlan.28"), null));
        }

        // --- Passo finale: configurazione Dovecot dalla sorgente unica ---
        // Lo stato si ricava dal file vivo: l'intestazione la scrive solo il generatore nuovo.
        // Anche quella di prima: un server che non ha ancora cambiato firma e' gia' rigenerato.
        boolean regenerated = ok("grep -qF" + dovecotSignatureOptions() + " "
                + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        boolean sieveActive = ok("grep -qE '^protocols.*sieve' " + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        steps.put(repeatable(step("phase-dovecot", "phase", I18n.tr("server.um.maintenancePlan.30"),
                regenerated ? "done" : "todo",
                regenerated ? (sieveActive
                        ? I18n.tr("server.um.x.dcSingleSieve")
                        : I18n.tr("server.um.x.dcSingleNoSieve"))
                    : I18n.tr("server.um.maintenancePlan.31"),
                I18n.tr("server.um.maintenancePlan.32"),
                regenerated ? null : new JSONObject().put("type", "dovecot_config_regen")),
                new JSONObject().put("type", "dovecot_config_regen")));

        // --- Le tre operazioni che un semplice "pkg upgrade" non sa fare ---
        // Stanno nel piano anche se l'azione vive in una scheda dedicata: un piano che tace su
        // cio' che resta da fare dice implicitamente "sei a posto", e non e' vero. Lo stato e'
        // ricavato con interrogazioni leggere — niente simulazioni, che qui costerebbero minuti.

        // Roundcube: il pacchetto si aggiornerebbe da solo, ma il salto di versione maggiore
        // cambia lo SCHEMA del database, e senza bin/updatedb.sh la webmail non funziona.
        if (!rcPkg.isEmpty() && isValidName(rcPkg)) {
            String cur = sh("pkg query %v " + rcPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + rcPkg + " 2>/dev/null", 20);
            boolean rcUnknown = cur.isEmpty() || av.isEmpty();
            boolean toDoRc = !rcUnknown && !av.equals(cur);
            // Una webmail gia' sulla 1.7 con la radice vecchia e' guasta ADESSO: se il piano
            // guardasse solo la versione direbbe "fatto" mentre la webmail non risponde.
            String crookedRoot = null;
            if (wantsPublicHtml(cur) || wantsPublicHtml(av)) {
                JSONArray rd = nginxRoundcubeRoots();
                for (int i = 0; i < rd.length(); i++)
                    if (!rd.getJSONObject(i).getBoolean("already"))
                        crookedRoot = rd.getJSONObject(i).getString("file");
            }
            if (crookedRoot != null) { toDoRc = true; rcUnknown = false; }
            int cveRc = vulnerabilityDetail(audit, rcPkg).getJSONArray("cve").length();
            steps.put(step("phase-roundcube", "phase", I18n.tr("server.um.x.stepRoundcube")
                        + (cveRc > 0 ? " (" + cveRc + " CVE)" : ""),
                    (toDoRc || rcUnknown) ? "manual" : "done",
                    rcUnknown ? I18n.tr("server.um.x.rcRepoUnknown", java.util.Map.of("pkg", String.valueOf(rcPkg), "cur", String.valueOf(cur.isEmpty() ? I18n.tr("server.um.x.unknownF") : cur)))
                        : !toDoRc ? I18n.tr("server.um.x.rcLatest", java.util.Map.of("pkg", String.valueOf(rcPkg), "cur", String.valueOf(cur)))
                        : (av.equals(cur)
                           ? I18n.tr("server.um.maintenancePlan.33", java.util.Map.of("rcPkg", String.valueOf(rcPkg), "cur", String.valueOf(cur), "crookedRoot", String.valueOf(crookedRoot)))
                           : rcPkg + " " + cur + " -> " + av
                             + (crookedRoot != null ? I18n.tr("server.um.maintenancePlan.34") : "")),
                    toDoRc
                    ? I18n.tr("server.um.maintenancePlan.35")
                    : I18n.tr("server.um.maintenancePlan.36"), null));
        }

        // Python: py311 e py312 sono pacchetti diversi, non due versioni dello stesso.
        java.util.LinkedHashSet<String> pyOld = new java.util.LinkedHashSet<>();
        for (String n : sh("pkg query %n 2>/dev/null").split("\n")) {
            Matcher m = Pattern.compile("^py(3[0-9]{2})-").matcher(n.trim());
            if (m.find() && !m.group(1).equals(pyNew)) pyOld.add(m.group(1));
        }
        if (!pyOld.isEmpty()) {
            String list = String.join(", ", pythonToMove(pyOld.iterator().next()));
            steps.put(step("phase-python", "phase", I18n.tr("server.um.maintenancePlan.37"),
                    "manual",
                    I18n.tr("server.um.x.pyInstalled", java.util.Map.of("oldOnes", String.valueOf(String.join("/py", pyOld)), "newer", String.valueOf(pyNew)))
                    + (list.isEmpty() ? "." : ": " + list),
                    I18n.tr("server.um.maintenancePlan.38", java.util.Map.of("p", String.valueOf(pyOld.iterator().next()), "pyNew", String.valueOf(pyNew))), null));
        } else {
            steps.put(step("phase-python", "phase", I18n.tr("server.um.maintenancePlan.37"),
                    "done", I18n.tr("server.um.maintenancePlan.39", java.util.Map.of("pyNew", String.valueOf(pyNew))),
                    I18n.tr("server.um.runPythonTransition.2"), null));
        }

        // JVM: il pannello ci gira sopra, quindi non puo' aggiornarla restando acceso.
        if (!jvmPkg.isEmpty()) {
            String cur = sh("pkg query %v " + jvmPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + jvmPkg + " 2>/dev/null", 20);
            // Tre stati, non due. Il repository che non risponde NON vuol dire "sei a posto":
            // vuol dire che non lo so, e dirlo e' l'unica risposta onesta.
            boolean unknownJv = cur.isEmpty() || av.isEmpty();
            boolean toDoJv = !unknownJv && !av.equals(cur);
            int cveJv = vulnerabilityDetail(audit, jvmPkg).getJSONArray("cve").length();
            steps.put(step("phase-jvm", "phase", I18n.tr("server.um.x.stepJvm")
                        + (cveJv > 0 ? " (" + cveJv + " CVE)" : ""),
                    (toDoJv || unknownJv) ? "manual" : "done",
                    unknownJv ? I18n.tr("server.um.x.jvRepoUnknown", java.util.Map.of("pkg", String.valueOf(jvmPkg), "cur", String.valueOf(cur.isEmpty() ? I18n.tr("server.um.x.unknownF") : cur)))
                        : toDoJv ? jvmPkg + " " + cur + " -> " + av
                             : I18n.tr("server.um.x.jvLatest", java.util.Map.of("pkg", String.valueOf(jvmPkg), "cur", String.valueOf(cur))),
                    unknownJv
                    ? I18n.tr("server.um.maintenancePlan.40")
                    : toDoJv
                    ? I18n.tr("server.um.maintenancePlan.41")
                    : I18n.tr("server.um.maintenancePlan.42"), null));
        }

        // Vulnerabilita' senza correzione disponibile: non sono un passo, ma vanno sapute.
        JSONArray withoutRemedy = new JSONArray();
        for (String name : seen) {
            String cur = sh("pkg query %v " + name + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + name + " 2>/dev/null", 20);
            if (!cur.isEmpty() && (av.isEmpty() || av.equals(cur))) withoutRemedy.put(name);
        }

        int toDo = 0;
        for (int i = 0; i < steps.length(); i++) if ("todo".equals(steps.getJSONObject(i).getString("state"))) toDo++;
        return new JSONObject().put("success", true).put("steps", steps)
                .put("toDo", toDo).put("total", steps.length())
                .put("withoutRemedy", withoutRemedy);
    }

    /**
     * Un passo del piano, identificato da una CHIAVE stabile e non da un numero.
     *
     * I numeri scorrevano: i passi sui singoli pacchetti spariscono quando il pacchetto non ha
     * piu' niente da fare — e' la conseguenza dello stato ricavato invece che memorizzato — e
     * quello che era "il 3" diventava un altro. Chi segue una guida deve poter dire "ho fatto
     * openssl", non "ho fatto il tre" e scoprire che il tre adesso e' nginx.
     */
    /**
     * La lettera di ogni fase, legata alla sua CHIAVE e non all'ordine di apparizione.
     *
     * Assegnarle scorrendo l'elenco sembrava stabile finche' le fasi erano sempre le stesse
     * quattro. Ma una fase che compare solo quando serve — come la pulizia delle cache di
     * rspamd — farebbe scorrere tutte quelle dopo, e "Fase C" tornerebbe a significare cose
     * diverse in momenti diversi: esattamente il difetto dei numeri, solo piu' lento a farsi
     * vedere.
     */
    private static final java.util.Map<String, String> PHASE_LETTER = java.util.Map.of(
        "phase-protection",   "A",
        "phase-unprotected",  "B",
        "phase-mysql84",      "C",
        "phase-dovecot",      "D",
        "phase-rspamd-cache", "E",
        "phase-roundcube",    "F",
        "phase-python",       "G",
        "phase-jvm",          "H"
    );

    /**
     * Segna un passo come RIFACIBILE: gia' fatto, ma ripetibile senza danno.
     *
     * Vale solo per i passi che riscrivono qualcosa in modo idempotente — la configurazione
     * Dovecot, la protezione dei pacchetti — e serve perche' lo stato ricavato, da solo,
     * rende impossibile ripetere cio' che risulta gia' fatto. Dopo un miglioramento del
     * generatore si vuole rigenerare, e non poterlo fare e' una limitazione, non una tutela.
     *
     * NON si applica agli aggiornamenti di pacchetto (rifarli non significa niente) ne' alla
     * migrazione MySQL, che riscrive il data dictionary e non e' ripetibile per definizione.
     */
    private static JSONObject repeatable(JSONObject step, JSONObject action) {
        if ("done".equals(step.optString("state")) && action != null) step.put("redoAction", action);
        return step;
    }

    private static JSONObject step(String key, String group, String title, String state,
                                    String situation, String why, JSONObject action) {
        JSONObject o = new JSONObject().put("key", key).put("group", group)
                .put("title", title).put("state", state)
                .put("situation", situation).put("why", why);
        if ("phase".equals(group)) o.put("letter", PHASE_LETTER.getOrDefault(key, "?"));
        if (action != null) o.put("action", action);
        return o;
    }

    // ===================== aggiornamento guidato di un singolo pacchetto =====================

    /**
     * Pacchetti che devono muoversi INSIEME.
     *
     * Non e' una preferenza estetica: mysql80-server dipende da mysql80-client, e se il
     * client resta protetto un "pkg upgrade mysql80-server" trova una dipendenza bloccata e
     * non conclude. Lo stesso vale per php84 con le sue ventotto estensioni, che portano il
     * numero di versione nel nome. Trattarli come passi separati significa proporre
     * un'operazione che non puo' riuscire.
     */
    private static final String[][] FAMILIES = {
        {"^mysql[0-9]+-(server|client)$",  "server.um.step.1"},
        {"^php[0-9]+(-.+)?$",              "server.um.step.2"},
        {"^dovecot[0-9]*(-.+)?$",          "server.um.family.dovecot"},
    };

    /** L'espressione della famiglia a cui appartiene il pacchetto, o null se sta da solo. */
    static String familyOf(String name) {
        for (String[] f : FAMILIES) if (name.matches(f[0])) return f[0];
        return null;
    }

    static String familyReason(String name) {
        for (String[] f : FAMILIES) if (name.matches(f[0])) return I18n.tr(f[1]);
        return "";
    }

    /**
     * Un pacchetto GIA' installato che e' "la stessa cosa a un'altra versione" di 'nome', o
     * null. Serve a PackagePlan per riconoscere quando pkg gira attorno a un blocco
     * installando un altro membro della famiglia: il perche' sta su PackagePlan.familyAddition.
     *
     * Due condizioni, entrambe necessarie, perche' una sola sbaglia:
     *
     *  - **la stessa famiglia dichiarata** (FAMIGLIE). Senza questa, python311 e python312
     *    sembrerebbero gemelli, e invece convivono benissimo.
     *  - **lo stesso scheletro**, cioe' lo stesso nome a cifre sostituite: mysql97-client e
     *    mysql84-client diventano entrambi "mysql#-client", mentre mysql84-server diventa
     *    "mysql#-server". Senza questa, il gemello di mysql97-client potrebbe risultare
     *    mysql84-server, che e' della stessa famiglia ma non occupa lo stesso posto.
     */
    static String installedFamilyTwin(String name) {
        if (!isValidName(name)) return null;
        String family = familyOf(name);
        if (family == null) return null;
        String skeleton = nameSkeleton(name);
        for (String line : sh("pkg query %n 2>/dev/null", 30).split("\n")) {
            String t = line.trim();
            if (!isValidName(t) || t.equals(name) || !t.matches(family)) continue;
            if (skeleton.equals(nameSkeleton(t))) return t;
        }
        return null;
    }

    /** Il nome con le cifre sostituite: "mysql84-client" -> "mysql#-client". */
    static String nameSkeleton(String name) {
        return name == null ? "" : name.replaceAll("[0-9]+", "#");
    }

    /** Tutti i pacchetti INSTALLATI che appartengono alla stessa famiglia. Almeno il pacchetto stesso. */
    static java.util.List<String> familyMembers(String name) {
        java.util.List<String> members = new ArrayList<>();
        String fam = familyOf(name);
        if (fam == null) { members.add(name); return members; }
        for (String line : sh("pkg query %n 2>/dev/null", 30).split("\n")) {
            String t = line.trim();
            if (isValidName(t) && t.matches(fam)) members.add(t);
        }
        if (members.isEmpty()) members.add(name);
        return members;
    }

    /**
     * Quale servizio dipende da quale pacchetto. Serve per la parte che ieri e' costata cara:
     * aggiornare un pacchetto NON aggiorna il processo in esecuzione, che continua a usare i
     * file gia' caricati in memoria. Senza riavviare, la vulnerabilita' resta aperta pur
     * risultando corretta.
     */
    private static final String[][] SERVICE_OF = {
        {"^postfix.*",                        "postfix"},
        {"^dovecot[0-9]*(-[a-z]+)?$",         "dovecot"},
        {"^dovecot[0-9]*-pigeonhole.*",       "dovecot"},
        {"^rspamd$",                          "rspamd"},
        {"^redis.*",                          "redis"},
        // Lo stesso pacchetto fa girare due demoni, e tutti e due caricano libclamav. Con la
        // sola riga di clamd, misurato su latest il 24/10/2026: clamav 1.5.4_1,1 -> 1.5.4_2,1,
        // clamd riavviato, e freshclam ancora col programma di prima (procstat non trovava piu'
        // il suo eseguibile) sotto un «clamav in servizio».
        {"^clamav.*",                         "clamav_clamd"},
        {"^clamav.*",                         "clamav_freshclam"},
        {"^nginx.*",                          "nginx"},
        {"^php[0-9]+.*",                      "php_fpm"},
        {"^mysql[0-9]+-server$",              "mysql-server"},
        {"^py[0-9]+-fail2ban$",               "fail2ban"},
        {"^unbound$",                         "unbound"},
    };

    /** Pacchetti che sono librerie condivise: qui un "nessun dipendente" va preso con cautela. */
    private static final String SHARED_LIBRARIES =
            "^(openssl[0-9]*|expat|libxml2|zlib|libiconv|pcre2?|curl|libssh2|nghttp2|icu|libsodium)$";

    /** Tutti i servizi di un pacchetto: un pacchetto puo' farne girare piu' d'uno (clamav). */
    private static java.util.List<String> directServices(String pkgName) {
        java.util.List<String> r = new ArrayList<>();
        for (String[] row : SERVICE_OF) if (pkgName.matches(row[0])) r.add(row[1]);
        return r;
    }

    /**
     * I servizi da riavviare dopo aver aggiornato un pacchetto. Per una libreria condivisa
     * come openssl non basta guardare il pacchetto stesso: si chiede a pkg CHI dipende da lui
     * e si traducono quei pacchetti in servizi. Un elenco scritto a mano invecchierebbe in
     * silenzio, e un servizio dimenticato significa una vulnerabilita' che resta aperta.
     */
    static java.util.List<String> servicesToRestart(String pkgName) {
        java.util.LinkedHashSet<String> services = new java.util.LinkedHashSet<>();
        services.addAll(directServices(pkgName));
        if (!isValidName(pkgName)) return new ArrayList<>(services);
        for (String line : sh("pkg query %rn " + pkgName + " 2>/dev/null", 30).split("\n")) {
            String dependents = line.trim();
            if (!isValidName(dependents)) continue;
            services.addAll(directServices(dependents));
        }
        return new ArrayList<>(services);
    }

    /** Nome effettivo dello script rc.d fra i candidati, o null se il servizio non c'e'. */
    private static String realServiceName(String logical) {
        for (String[] candidates : SERVICES) {
            boolean belongs = false;
            for (String c : candidates) if (c.equals(logical)) belongs = true;
            if (!belongs) continue;
            for (String c : candidates) {
                if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) return c;
            }
            return null;
        }
        return ok("test -f /usr/local/etc/rc.d/" + logical + " -o -f /etc/rc.d/" + logical, 10) ? logical : null;
    }

    /**
     * Ripesca dai messaggi post-installazione quelli che CHIEDONO un'azione.
     *
     * pkg li stampa in mezzo a centinaia di righe e poi si prosegue: un "e' consigliato
     * rimuovere i file di cache" scorre via e nessuno lo fa. Rspamd 4.1 ne aveva uno che
     * riguardava la classificazione dello spam, ed e' passato inosservato proprio cosi'.
     * Qui si riconoscono le formule imperative e il messaggio si ristampa ALLA FINE, dove
     * si guarda davvero.
     */
    static java.util.List<String> messagesAskingForAction(String outputPkg) {
        java.util.List<String> outside = new ArrayList<>();
        // Il rientro comune si toglie, non solo quello della prima riga: uno script che
        // scrive tutto rientrato di quattro spazi, ristampato con trim(), avrebbe la prima
        // riga a sinistra e le altre spostate.
        for (String block : outputBlocks(outputPkg))
            if (asksForAction(block)) outside.add(block.stripTrailing().stripIndent().strip());
        return outside;
    }

    /** "[4/4] Installing postfix-mysql-3.11.7_3,1...": pkg che dice a che punto e'. */
    private static final Pattern PKG_PROGRESS = Pattern.compile("^\\[\\d+/\\d+\\] .*");

    /** Le righe con cui pkg ricomincia a parlare, per esempio quando un aggiornamento si rilancia. */
    private static final Pattern PKG_RESTARTS = Pattern.compile(
            "^(Checking integrity|Checking for upgrades|Updating .* repository catalogue).*");

    /** Il bordo di un riquadro: «=====...» da solo sulla riga. */
    private static final Pattern BOX_EDGE = Pattern.compile("^={10,}\\s*$");

    /**
     * Due frasi che pkg e i port stampano a OGNI aggiornamento e che durante un aggiornamento
     * non chiedono niente. La prima e' di pkg per ogni file di configurazione diverso dal suo
     * esempio; la seconda dei port per ogni utente o gruppo del pacchetto che si disinstalla,
     * e qui il pacchetto si reinstalla subito dopo. Misurate nell'uscita vera
     * dell'aggiornamento di postfix-mysql del 24/10/2026: tenerle vorrebbe dire ristampare
     * come «da fare» due cose sbagliate da fare.
     */
    private static final Pattern[] NOTICES_NOT_ACTIONS = {
        Pattern.compile("^You may need to manually remove \\S+ if it is no longer needed\\.?\\s*$"),
        Pattern.compile("^==> You should manually remove the \"[^\"]+\" (user|group)\\s*$"),
    };

    /**
     * L'uscita di pkg divisa nei pezzi che chi la legge prenderebbe per un messaggio.
     *
     * Prima si leggevano solo i blocchi «Message from». Ma uno script di installazione scrive
     * mentre gira, e pkg stampa quelle righe dove capitano, FUORI da ogni blocco. Misurato
     * sull'aggiornamento di postfix-mysql del 24/10/2026 (reperto 42): 61 righe, e le due cose
     * che contavano erano entrambe fuori — «COMPATIBILITY: editing main.cf, setting
     * inet_protocols=ipv4», cioe' IPv6 tolto al prossimo riavvio, e il riquadro «Postfix was
     * *not* activated in mailer.conf». L'unico blocco «Message from» era quello della versione
     * VECCHIA, che si stava disinstallando. Risultato: zero messaggi.
     *
     * I pezzi:
     *  - un blocco «Message from», fino al successivo o a quando pkg ricomincia a parlare;
     *  - un riquadro fra due righe di «=====», con le sue righe vuote dentro;
     *  - fuori da questi, un paragrafo: righe consecutive fra due righe vuote o due righe di
     *    avanzamento di pkg. Le righe di uno script stanno fra l'avanzamento del suo
     *    pacchetto e quello del successivo.
     */
    static java.util.List<String> outputBlocks(String outputPkg) {
        java.util.List<String> blocks = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        String mode = "paragraph";   // "paragraph", "message", "box"
        for (String line : (outputPkg == null ? "" : outputPkg).split("\n")) {
            if (line.startsWith("Message from ")) {
                closeBlock(blocks, current);
                mode = "message";
                current.append(line).append('\n');
                continue;
            }
            boolean pkgSpeaks = PKG_PROGRESS.matcher(line).matches() || PKG_RESTARTS.matcher(line).matches();
            if ("message".equals(mode)) {
                if (!pkgSpeaks) { current.append(line).append('\n'); continue; }
                closeBlock(blocks, current);
                mode = "paragraph";
            }
            if (BOX_EDGE.matcher(line).matches()) {
                closeBlock(blocks, current);
                mode = "box".equals(mode) ? "paragraph" : "box";
                continue;
            }
            if (pkgSpeaks) {
                closeBlock(blocks, current);
                mode = "paragraph";
                continue;
            }
            boolean notice = false;
            for (Pattern p : NOTICES_NOT_ACTIONS) if (p.matcher(line).matches()) notice = true;
            if (notice) continue;
            if (line.trim().isEmpty() && "paragraph".equals(mode)) { closeBlock(blocks, current); continue; }
            current.append(line).append('\n');
        }
        closeBlock(blocks, current);
        return blocks;
    }

    private static void closeBlock(java.util.List<String> blocks, StringBuilder current) {
        if (!current.toString().trim().isEmpty()) blocks.add(current.toString());
        current.setLength(0);
    }

    /** «Editing /usr/local/etc/postfix/master.cf, adding...», «COMPATIBILITY: editing .../main.cf». */
    private static final Pattern SCRIPT_EDITS_A_FILE = Pattern.compile("(?s).*\\bediting /.*");

    private static boolean asksForAction(String text) {
        String t = text.toLowerCase();
        return t.contains("it is recommended") || t.contains("you should") || t.contains("you may need")
            || t.contains("you need to") || t.contains("remember to")
            || t.contains("following command") || t.contains("action is needed")
            // Uno script che dice di aver modificato un file, o di aver cambiato un valore
            // predefinito per compatibilita', non chiede niente a parole: ha gia' fatto. E'
            // la prima cosa da leggere, perche' quello che ha fatto entra in vigore al
            // riavvio (reperto 42: «Specify inet_protocols explicitly if you want to enable
            // IPv6»).
            || t.contains("compatibility:") || t.contains("explicitly")
            || SCRIPT_EDITS_A_FILE.matcher(t).matches();
    }

    /**
     * Ristampa alla fine del log i messaggi che chiedono un'azione o dicono di aver cambiato
     * qualcosa. La chiedono i tre lavori che aggiornano pacchetti: prima lo faceva solo
     * l'aggiornamento guidato, e la manutenzione completa — quella che aggiorna tutto —
     * lasciava scorrere i messaggi di tutti i pacchetti in mezzo all'uscita di pkg.
     */
    private static void writeActionMessages(Job job, String pkgOutput) {
        java.util.List<String> messages = messagesAskingForAction(pkgOutput);
        if (messages.isEmpty()) return;
        job.write("");
        job.write(I18n.tr("server.um.runGuidedUpdate.33"));
        job.write(I18n.tr("server.um.runGuidedUpdate.34"));
        for (String m : messages) {
            for (String l : m.split("\n")) if (!l.trim().isEmpty()) job.write("  " + l);
            job.write("");
        }
    }

    /**
     * Comando che chiede a un servizio se la sua configurazione e' valida, PRIMA di riavviarlo.
     *
     * Riavviare alla cieca dopo un aggiornamento e' il modo di scoprire un errore di sintassi
     * a servizio gia' fermo. Su Dovecot questo controllo esisteva gia'; non c'era per gli altri,
     * ed e' una disparita' senza motivo: nginx fra la 1.28 e la 1.30 puo' cambiare direttive,
     * e Postfix cambia i predefiniti fra versioni.
     */
    private static final String[][] CONFIG_TEST = {
        {"nginx",        "nginx -t"},
        {"postfix",      "postfix check"},
        {"dovecot",      "doveconf -n >/dev/null"},
        {"rspamd",       "rspamadm configtest"},
        {"mysql-server", "su -m mysql -c '$(which mysqld 2>/dev/null || echo /usr/local/libexec/mysqld) --validate-config'"},
    };

    private static String testConfigOf(String service) {
        for (String[] r : CONFIG_TEST) if (r[0].equals(service)) return r[1];
        return null;
    }

    /**
     * Prove da fare DOPO il riavvio, per vedere se il servizio ha ritrovato i propri dati.
     *
     * "Il processo e' ripartito" non dice se ha ripreso a fare il suo mestiere. Redis riavviato
     * con il dump non riletto riparte vuoto: rspamd continua a funzionare, ma senza
     * addestramento bayesiano, senza greylisting e senza limiti — e non se ne accorge nessuno
     * finche' lo spam non ricomincia a passare. Era scritto nella mia avvertenza e non lo
     * controllava niente: un'avvertenza che non verifica e' solo una frase.
     */
    private static final String[][] TEST_AFTER = {
        {"redis", "redis-cli DBSIZE 2>/dev/null", "server.um.testConfigOf.1"},
    };

    private static String[] testAfterOf(String service) {
        for (String[] r : TEST_AFTER) if (r[0].equals(service)) return r;
        return null;
    }

    /** Il pid di un servizio, o stringa vuota. Confrontarlo prima e dopo prova che e' ripartito davvero. */
    private static String servicePid(String service) {
        if (!isValidName(service)) return "";
        String o = sh("service " + service + " status 2>/dev/null", 15);
        Matcher m = Pattern.compile("pid[s]?[: ]+([0-9]+)").matcher(o.toLowerCase());
        return m.find() ? m.group(1) : "";
    }

    /**
     * Controlli preliminari per l'aggiornamento di UN pacchetto protetto. Tutto in sola
     * lettura: dice cosa succederebbe, quali vulnerabilita' si chiuderebbero e quali servizi
     * andranno riavviati, prima che qualcuno prema qualcosa.
     */
    public static JSONObject packagePreflight(String name) {
        JSONObject r = new JSONObject();
        if (!isValidName(name)) return r.put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
        JSONArray checks = new JSONArray();
        boolean block = false;

        // I pacchetti che devono muoversi insieme si sbloccano e si aggiornano insieme:
        // altrimenti una dipendenza rimasta protetta blocca tutta l'operazione. Serve saperlo
        // subito, perche' da questo dipendono anche i servizi da riavviare.
        java.util.List<String> family = familyMembers(name);

        String version = sh("pkg query %v " + name + " 2>/dev/null", 20);
        if (version.isEmpty()) {
            addCheck(checks, "installed", I18n.tr("server.um.packagePreflight.1"), "block",
                    I18n.tr("server.um.packagePreflight.2", java.util.Map.of("name", String.valueOf(name))));
            block = true;
        } else {
            addCheck(checks, "installed", I18n.tr("server.um.packagePreflight.1"), "ok", name + " " + version);
        }
        r.put("name", name).put("current", version).put("role", roleOf(name) == null ? "" : roleOf(name));

        String available = sh("pkg rquery -U %v " + name + " 2>/dev/null", 30);
        r.put("available", available);
        boolean major = !version.isEmpty() && !available.isEmpty()
                && significantJump(name, version, available);
        r.put("majorJump", major);
        if (available.isEmpty() || available.equals(version)) {
            addCheck(checks, "update", I18n.tr("server.um.packagePreflight.3"), "block",
                    I18n.tr("server.um.packagePreflight.4"));
            block = true;
        } else {
            addCheck(checks, "update", I18n.tr("server.um.packagePreflight.3"), "ok",
                    version + " -> " + available + (major ? I18n.tr("server.um.packagePreflight.5") : I18n.tr("server.um.packagePreflight.6")));
        }

        JSONObject warning = warningFor(name, major);
        if (warning != null) {
            r.put("advisory", warning);
            if ("wait".equals(warning.getString("level"))) {
                addCheck(checks, "warning", I18n.tr("server.um.packagePreflight.7"), "block", warning.getString("text"));
                block = true;
            } else {
                addCheck(checks, "warning", I18n.tr("server.um.packagePreflight.7"), warning.getString("level"), warning.getString("text"));
            }
        }

        // Il pacchetto nuovo pretende una famiglia MySQL diversa da quella installata?
        // E' il caso di postfix-mysql 3.11, che nel repository dipende da mysql84-client: sul
        // sistema c'e' ancora mysql80-client, e i due sono in conflitto. Aggiornarlo prima di
        // aver migrato MySQL significa o un fallimento o una sostituzione di libreria non
        // voluta, con mysql80-server che ci dipende ancora.
        String mysqlInstalled = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        if (!available.isEmpty()) {
            String required = mysqlFamilyConflict(name);
            if (required != null) {
                StringBuilder who = new StringBuilder();
                for (String member : family) {
                    if (!isValidName(member)) continue;
                    if (sh("pkg rquery -U %dn " + member + " 2>/dev/null", 30).contains(required)) {
                        if (who.length() > 0) who.append(", ");
                        who.append(member);
                    }
                }
                addCheck(checks, "mysqlfamily", I18n.tr("server.um.packagePreflight.8"), "block",
                        I18n.tr("server.um.x.mysqlFamilyBlock", java.util.Map.of("who", String.valueOf(who.length() > 0 ? who.toString() : name), "required", String.valueOf(required), "installedValue", String.valueOf(mysqlInstalled), "version", String.valueOf(required.replace("-client", "")))));
                block = true;
                r.put("mysqlFamilyConflict", required);
            }
        }

        // Vulnerabilita' che questo aggiornamento chiuderebbe: e' il motivo per farlo. Si
        // chiede per la versione INSTALLATA, e si pretende un referto: il perche' delle due
        // cose sta su auditReport.
        JSONObject report = auditReport(name, version);
        r.put("cve", report.getJSONArray("cve")).put("vulnDescription", report.getString("description"))
         .put("references", report.getJSONArray("references")).put("vulnChecked", report.optBoolean("done"));
        int problems = report.optInt("problems");
        if (!report.optBoolean("done"))
            addCheck(checks, "vulnerabilities", I18n.tr("server.um.x.knownVulns"), "review",
                    report.optString("error"));
        else
            addCheck(checks, "vulnerabilities", I18n.tr("server.um.x.knownVulns"), problems > 0 ? "review" : "ok",
                    problems > 0 ? I18n.tr("server.um.x.openCves", java.util.Map.of("n", String.valueOf(problems), "d", String.valueOf(report.getString("description"))))
                                 : I18n.tr("server.um.packagePreflight.9"));

        // Servizi da riavviare. Il punto dolente: senza riavvio la correzione non entra in
        // servizio. E vanno calcolati su TUTTA la famiglia, non sul solo pacchetto nominato:
        // aggiornando mysql80-server insieme a mysql80-client, sono i programmi collegati al
        // CLIENT (Postfix, Dovecot, php-fpm) a tenersi in memoria la libreria vecchia. Guardare
        // il solo nome scritto nel passo li lascerebbe fuori, ed e' esattamente il caso in cui
        // la correzione risulta installata senza essere in servizio.
        java.util.LinkedHashSet<String> logicalNames = new java.util.LinkedHashSet<>();
        for (String member : family) logicalNames.addAll(servicesToRestart(member));
        JSONArray services = new JSONArray();
        for (String logical : logicalNames) {
            String real = realServiceName(logical);
            if (real == null) continue;
            services.put(new JSONObject().put("name", real)
                    .put("running", ok("service " + real + " status", 15))
                    .put("pid", servicePid(real)));
        }
        r.put("services", services);
        // Cosa ha risposto pkg, per esteso: un "nessuno" senza le prove non e' un'informazione,
        // e su una libreria condivisa e' l'errore che vanifica l'aggiornamento.
        JSONArray foundDeps = new JSONArray();
        for (String member : family) {
            for (String line : sh("pkg query %rn " + member + " 2>/dev/null", 30).split("\n")) {
                String d = line.trim();
                if (isValidName(d) && !family.contains(d)) foundDeps.put(d);
            }
        }
        r.put("reverseDeps", foundDeps);
        addCheck(checks, "services", I18n.tr("server.um.packagePreflight.10"), "review",
                services.length() == 0
                    ? (foundDeps.length() == 0
                       ? I18n.tr("server.um.x.noSvcZero")
                       : I18n.tr("server.um.x.noSvcSome", java.util.Map.of("n", String.valueOf(foundDeps.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(foundDeps))))))
                    : I18n.tr("server.um.packagePreflight.11", java.util.Map.of("length", String.valueOf(services.length()))));

        if (Files.exists(Paths.get(MAINTENANCE_STATE))) {
            addCheck(checks, "state", I18n.tr("server.um.packagePreflight.12"), "block",
                    I18n.tr("server.um.packagePreflight.13", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
            block = true;
        }

        r.put("family", new JSONArray(family));
        if (family.size() > 1) {
            addCheck(checks, "family", I18n.tr("server.um.packagePreflight.14"), "review",
                    I18n.tr("server.um.x.familyTogether", java.util.Map.of("n", String.valueOf(family.size()), "reason", String.valueOf(familyReason(name)), "list", String.valueOf(String.join(", ", family)))));
        }

        String lockList = sh("pkg lock -l 2>/dev/null");
        java.util.List<String> lockedNow = new ArrayList<>();
        for (String m : family) if (locked(lockList, m)) lockedNow.add(m);
        r.put("wasLocked", !lockedNow.isEmpty());
        r.put("lockedMembers", new JSONArray(lockedNow));

        // Il piano ESATTO. Fin qui c'era soltanto "nome versione -> versione del catalogo", ma
        // pkg per aggiornare puo' cambiare anche dipendenze, installarne di nuove, rimuoverne:
        // si chiede a pkg, su una copia del suo database in cui si tolgono le stesse protezioni
        // che togliera' l'aggiornamento vero. Il database vero non viene toccato.
        JSONObject plan = judged(PackagePlan.planFor(family, lockedNames(lockList),
                UpdateManager::reasonNotToUnlock, UpdateManager::installedFamilyTwin));
        if (!plan.optBoolean("success") || !plan.optBoolean("measured")) {
            addCheck(checks, "plan", I18n.tr("server.um.packagePreflight.15"), "block",
                    I18n.tr("server.um.x.noPlan", java.util.Map.of("e", String.valueOf(plan.optString("error", "?")))));
            block = true;
        } else {
            JSONArray changes = plan.getJSONArray("changes");
            // Rimozioni e retrocessioni dalla funzione condivisa: la regola e' la stessa dei
            // due lavori, e scritta due volte diventerebbe due regole (e lo era).
            JSONObject destructive = destructiveChanges(plan);
            java.util.List<String> removed = jsonArrayToList(destructive.getJSONArray("removes"));
            java.util.List<String> downgrades = jsonArrayToList(destructive.getJSONArray("downgrades"));
            java.util.List<String> stillVulnerable = new ArrayList<>(), lines = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                String n = c.getString("name");
                if (c.optBoolean("stillVulnerable")) stillVulnerable.add(n + " " + c.getString("to"));
                lines.add(n + " " + (c.getString("from").isEmpty() ? I18n.tr("server.um.x.newPkg") : c.getString("from"))
                        + (c.getString("to").isEmpty() ? " " + I18n.tr("server.um.x.removedPkg") : " -> " + c.getString("to")));
            }
            JSONArray blockerList = plan.getJSONArray("blockers");
            for (int i = 0; i < blockerList.length(); i++) {
                JSONObject x = blockerList.getJSONObject(i);
                addCheck(checks, "plan-blocker", I18n.tr("server.um.packagePreflight.16"), "block",
                        I18n.tr("server.um.x.blockedBy", java.util.Map.of("name", String.valueOf(x.getString("name")), "reason", String.valueOf(x.getString("reason")))));
                block = true;
            }
            JSONArray err = plan.getJSONArray("pkgErrors");
            if (err.length() > 0 || plan.optBoolean("hasConflicts")) {
                addCheck(checks, "plan-errors", I18n.tr("server.um.packagePreflight.17"), "block",
                        String.join(" | ", jsonArrayToList(err)) + (plan.optBoolean("hasConflicts") ? " " + I18n.tr("server.um.x.pkgConflicts") : ""));
                block = true;
            }
            if (!removed.isEmpty()) {
                // Una sostituzione innocua e' un avviso; le altre fermano, e la pagina mostra le prove.
                if (removalsRefused(plan).isEmpty()) {
                    addCheck(checks, "plan-removals", I18n.tr("server.um.packagePreflight.18"), "review",
                            I18n.tr("server.um.x.removalsAccepted", java.util.Map.of("list", String.join(", ", removed))));
                } else {
                    addCheck(checks, "plan-removals", I18n.tr("server.um.packagePreflight.18"), "block",
                            removalsReason(plan));
                    block = true;
                }
            }
            String mapsBlocker = PostfixMaps.planBlocker(plan);
            if (mapsBlocker != null) {
                addCheck(checks, "plan-maps", I18n.tr("server.um.x.mapsCheck"), "block", mapsBlocker);
                block = true;
            }
            if (!downgrades.isEmpty()) {
                addCheck(checks, "plan-downgrades", I18n.tr("server.um.packagePreflight.19"), "block",
                        I18n.tr("server.um.x.planDowngrades", java.util.Map.of("list", String.valueOf(String.join(", ", downgrades)))));
                block = true;
            }
            if (jsonArrayToList(plan.getJSONArray("unchangedPackages")).contains(name)) {
                addCheck(checks, "plan-stopped", I18n.tr("server.um.packagePreflight.20"), "block",
                        I18n.tr("server.um.packagePreflight.21", java.util.Map.of("name", String.valueOf(name))));
                block = true;
            }
            if (!stillVulnerable.isEmpty()) {
                addCheck(checks, "plan-vulnerable", I18n.tr("server.um.packagePreflight.22"), "review",
                        I18n.tr("server.um.x.stillVulnerable", java.util.Map.of("list", String.valueOf(String.join(", ", stillVulnerable)))));
            }
            java.util.List<String> extra = new ArrayList<>(jsonArrayToList(plan.getJSONArray("unlockedPackages")));
            extra.removeAll(family);
            if (!extra.isEmpty()) {
                addCheck(checks, "plan-dependencies", I18n.tr("server.um.packagePreflight.23"), "review",
                        I18n.tr("server.um.x.depsProtected", java.util.Map.of("list", String.valueOf(String.join(", ", extra)))));
            }
            if (!block) {
                addCheck(checks, "plan", I18n.tr("server.um.packagePreflight.15"), "ok",
                        (changes.length() == 1
                         ? I18n.tr("server.um.x.pkgChanges.one", java.util.Map.of("lines", String.valueOf(String.join("; ", lines))))
                         : I18n.tr("server.um.x.pkgChanges.other", java.util.Map.of("n", String.valueOf(changes.length()), "lines", String.valueOf(String.join("; ", lines))))));
            }
            // I servizi da riavviare si calcolano su tutto cio' che il piano cambia, non solo
            // sulla famiglia: una dipendenza come openssl tiene in memoria i suoi utenti.
            java.util.LinkedHashSet<String> serviceNames = new java.util.LinkedHashSet<>();
            for (int i = 0; i < services.length(); i++) serviceNames.add(services.getJSONObject(i).getString("name"));
            java.util.List<String> forDependencies = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                if ("remove".equals(c.getString("type")) || family.contains(c.getString("name"))) continue;
                for (String logical : servicesToRestart(c.getString("name"))) {
                    String real = realServiceName(logical);
                    if (real == null || !serviceNames.add(real)) continue;
                    services.put(new JSONObject().put("name", real)
                            .put("running", ok("service " + real + " status", 15))
                            .put("pid", servicePid(real)));
                    forDependencies.add(real + " " + I18n.tr("server.um.x.forPkg", java.util.Map.of("name", String.valueOf(c.getString("name")))));
                }
            }
            if (!forDependencies.isEmpty()) {
                addCheck(checks, "plan-services", I18n.tr("server.um.packagePreflight.24"), "review",
                        I18n.tr("server.um.x.depsServices", java.util.Map.of("list", String.valueOf(String.join(", ", forDependencies)))));
            }
        }
        r.put("plan", planForCard(plan)).put("signature", plan.optString("signature", ""));

        java.util.List<String> toUnlock = jsonArrayToList(plan.optJSONArray("unlockedPackages") == null
                ? new JSONArray() : plan.getJSONArray("unlockedPackages"));
        addCheck(checks, "protection", I18n.tr("server.um.packagePreflight.25"), "ok",
                toUnlock.isEmpty()
                    ? I18n.tr("server.um.packagePreflight.26")
                    : I18n.tr("server.um.x.willUnlock", java.util.Map.of("list", String.valueOf(String.join(", ", toUnlock)))));

        // Se fra quelli da sbloccare c'e' un pacchetto che nessuno ha chiesto, il perche' va
        // detto: sta li' perche' altrimenti pkg installerebbe un altro membro della sua
        // famiglia al suo posto (PackagePlan.familyAddition).
        JSONArray family2 = plan.optJSONArray("familyUnlocked");
        for (int i = 0; family2 != null && i < family2.length(); i++) {
            JSONObject f = family2.getJSONObject(i);
            addCheck(checks, "unlockedfamily", I18n.tr("server.um.x.familyUnlockedLabel"), "review",
                    I18n.tr("server.um.x.familyUnlockedWhy", java.util.Map.of(
                            "twin", String.valueOf(f.optString("installed")),
                            "version", String.valueOf(f.optString("version")),
                            "newer", String.valueOf(f.optString("wouldInstall")))));
        }

        r.put("success", true).put("checks", checks).put("canProceed", !block).put("blocked", block);
        return r;
    }

    /** I pacchetti protetti adesso, per nome, da un'uscita di "pkg lock -l". */
    static Set<String> lockedNames(String lockOutput) {
        Set<String> r = new java.util.TreeSet<>();
        for (String line : lockOutput.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.endsWith(":")) continue;
            int d = t.lastIndexOf('-');
            String n = d > 0 && d + 1 < t.length() && Character.isDigit(t.charAt(d + 1)) ? t.substring(0, d) : t;
            if (isValidName(n)) r.add(n);
        }
        return r;
    }

    /**
     * Si puo' togliere la protezione a un pacchetto che pkg deve cambiare per far posto a quello
     * scelto? No se la sua avvertenza dice di aspettare: e' la regola che lo tiene fuori dalla
     * manutenzione completa, e deve valere anche quando entra dalla porta di servizio, come
     * dipendenza di un altro.
     */
    static String reasonNotToUnlock(JSONObject isProtected) {
        String n = isProtected.optString("name"), from = isProtected.optString("version"), to = isProtected.optString("destination");
        // Se pkg non dice a che versione andrebbe, si suppone il caso peggiore.
        boolean major = to.isEmpty() || significantJump(n, from, to);
        JSONObject av = warningFor(n, major);
        if (av != null && "wait".equals(av.optString("level")))
            return I18n.tr("server.um.x.protectedWait", java.util.Map.of("t", String.valueOf(av.optString("text"))));
        return null;
    }

    /** Il piano come lo mostra la scheda: l'uscita di pkg si accorcia, il resto resta com'e'. */
    private static JSONObject planForCard(JSONObject plan) {
        JSONObject p = new JSONObject(plan.toString());
        String u = p.optString("output", "");
        if (u.length() > 6000) p.put("output", "...\n" + u.substring(u.length() - 6000));
        return p;
    }

    /**
     * @param approvedSignature l'impronta del piano che chi preme ha letto nella scheda. Il job
     *                          ricalcola il piano e parte solo se e' lo stesso: fra la lettura e il
     *                          click il catalogo puo' essere cambiato, e allora si eseguirebbe un
     *                          piano che nessuno ha visto.
     */
    public static JSONObject startGuidedUpdate(String name, String approvedSignature) {
        if (!isValidName(name)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.changeLocks.1"));
        if (approvedSignature == null || !approvedSignature.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startGuidedUpdate.1"));
        String id = "guid-" + System.currentTimeMillis();
        Job j = new Job(id, "guided_update");
        // Il turno si prende qui, prima dei controlli e di ogni sblocco: due aggiornamenti
        // approvati da due schede non possono partire insieme.
        final String pkgName2 = name;
        return startOnTurn(id, j, I18n.tr("server.um.startGuidedUpdate.2", java.util.Map.of("name", String.valueOf(name))), "guided-update",
                () -> runGuidedUpdate(j, pkgName2, approvedSignature));
    }

    /**
     * Aggiorna UN pacchetto protetto e rimette in servizio cio' che ne dipende.
     *
     * L'ordine e' quello che ieri, sull'altro server, abbiamo imparato a nostre spese:
     * sbloccare, aggiornare, RIPROTEGGERE SEMPRE (anche in caso di errore), poi riavviare i
     * servizi e verificare che siano ripartiti DAVVERO confrontando il pid. Un pacchetto
     * aggiornato con il processo ancora sui file vecchi e' una vulnerabilita' aperta che
     * risulta chiusa: il modo peggiore di stare fermi.
     */
    private static void runGuidedUpdate(Job job, String name, String approvedSignature) {
        job.status = "running";
        final int TOT = 6;
        boolean planNotFollowed = false;
        JSONArray outsidePlan = new JSONArray();
        JSONObject plan;
        java.util.List<String> toRelock2 = new ArrayList<>();
        java.util.List<String> pkgFamily = new ArrayList<>();
        boolean manualRecheck = false;
        java.util.List<String> services = new ArrayList<>();
        Map<String, String> pidBefore = new LinkedHashMap<>();
        Map<String, Boolean> activeBefore = new LinkedHashMap<>();
        // activeBefore riguarda i soli servizi che si riavvieranno; per il quadro finale
        // serve lo stato di TUTTI, preso prima di toccare qualunque cosa.
        Map<String, Boolean> servicesBefore = servicesState();
        // Cio' che il piano non puo' dire: che cosa fanno gli script di installazione alla
        // configurazione viva e agli indirizzi in ascolto (vedi InstallSideEffects).
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        // I servizi che questo lavoro NON ha riavviato perche' uno script ha cambiato la
        // configurazione: vanno nell'esito, con il comando per riavviarli dopo averla guardata.
        java.util.List<String> heldRestarts = new ArrayList<>();
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runGuidedUpdate.1", java.util.Map.of("name", String.valueOf(name))));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = packagePreflight(name);
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level"))) {
                        job.write("  [" + c.optString("level").toUpperCase() + "] "
                                + c.optString("label") + ": " + c.optString("detail"));
                    }
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            String versionBefore = pf.optString("current", "");
            String wait = pf.optString("available", "");
            pkgFamily = jsonArrayToList(pf.optJSONArray("family") == null
                    ? new JSONArray().put(name) : pf.getJSONArray("family"));

            // Si esegue il piano che e' stato letto, o niente. Il preflight qui sopra l'ha appena
            // ricalcolato: se l'impronta non e' quella approvata, qualcosa e' cambiato nel
            // frattempo (di solito il catalogo) e il piano che partirebbe non l'ha visto nessuno.
            plan = pf.getJSONObject("plan");
            String currentSignature = pf.optString("signature", "");
            if (!currentSignature.equals(approvedSignature)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runGuidedUpdate.2");
                job.write(I18n.tr("server.um.runGuidedUpdate.3", java.util.Map.of("approvedSignature", String.valueOf(approvedSignature), "currentSignature", String.valueOf(currentSignature))));
                job.write(I18n.tr("server.um.runGuidedUpdate.4"));
                return;
            }
            job.write("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(currentSignature))));
            JSONArray planChanges = plan.getJSONArray("changes");
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                job.write("    " + PackagePlan.typeName(c.getString("type")) + " " + c.getString("name") + " "
                        + (c.getString("from").isEmpty() ? "" : c.getString("from"))
                        + (c.getString("to").isEmpty() || c.getString("to").equals(c.getString("from")) ? "" : " -> " + c.getString("to")));
            }
            // Si sblocca esattamente cio' che il piano ha sbloccato nella copia: ne' uno in meno
            // (pkg si fermerebbe), ne' uno in piu' (resterebbe scoperto senza motivo).
            java.util.List<String> protectedNames = jsonArrayToList(plan.getJSONArray("unlockedPackages"));
            JSONArray sv = pf.optJSONArray("services");
            for (int i = 0; sv != null && i < sv.length(); i++) {
                JSONObject o = sv.getJSONObject(i);
                String n = o.getString("name");
                services.add(n);
                pidBefore.put(n, o.optString("pid", ""));
                activeBefore.put(n, o.optBoolean("running", false));
            }
            job.write("  " + name + " " + versionBefore + " -> " + wait);
            if (pkgFamily.size() > 1) {
                job.write(I18n.tr("server.um.runGuidedUpdate.5", java.util.Map.of("p", String.valueOf((pkgFamily.size() - 1)), "p2", String.valueOf(familyReason(name)))));
            }
            job.write("  " + I18n.tr("server.um.x.svcInvolvedList", java.util.Map.of("list", String.valueOf(services.isEmpty() ? I18n.tr("server.um.x.none") : String.join(", ", services)))));

            job.advance(2, TOT);
            job.write("");
            job.write("[2/" + TOT + "] " + I18n.tr("server.um.x.tempUnlock"));
            if (protectedNames.isEmpty()) {
                job.write(I18n.tr("server.um.runGuidedUpdate.6"));
            } else {
                // L'elenco si salva PRIMA di sbloccare: se il pannello muore adesso, il
                // ripristino all'avvio sa cosa riproteggere. Se non si scrive, non si sblocca
                // niente: un'interruzione li lascerebbe sbloccati senza traccia.
                for (String m : protectedNames)
                    if (!isValidName(m)) throw new IllegalStateException("invalid package name in the plan: " + m);
                String stateError = PackageQueue.writeState(protectedNames);
                if (stateError != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I did not unlock anything: " + stateError);
                job.write(I18n.tr("server.um.runGuidedUpdate.7", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
                // Da riproteggere tutti, anche uno sblocco fallito o scaduto a meta': pkg lock su un
                // pacchetto gia' protetto non cambia niente, e cosi' l'elenco su disco si chiude
                // solo quando tutti risultano protetti.
                toRelock2.addAll(protectedNames);
                for (String m : protectedNames) {
                    boolean u = ok("pkg unlock -y " + m, 30);
                    job.write("    " + m + ": " + (u ? I18n.tr("server.um.x.unlocked") : I18n.tr("server.um.runGuidedUpdate.8")));
                    if (!u) throw new IllegalStateException("I could not unlock " + m);
                }
            }

            job.advance(3, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.9", java.util.Map.of("total", String.valueOf(TOT))));
            StringBuilder list = new StringBuilder();
            for (String m : pkgFamily) if (isValidName(m)) list.append(' ').append(m);

            // Prima si scaricano i pacchetti e si ricalcola: finche' non sono scaricati, pkg
            // non vede i conflitti sui file e il piano puo' crescere durante l'esecuzione.
            // Il perche' per esteso, con la misura, sta su fetchAndRecheck.
            final java.util.List<String> family = pkgFamily;
            Recheck grown = fetchAndRecheck(job, "pkg upgrade -F -y -U" + list + " 2>&1", plan,
                    () -> PackagePlan.planFor(family, lockedNames(), UpdateManager::reasonNotToUnlock,
                            UpdateManager::installedFamilyTwin));
            if (grown.stop() != null) throw new IllegalStateException(grown.stop());
            plan = grown.plan();
            // L'output serve due volte: mostrato mentre scorre, e riletto alla fine per
            // ripescare i messaggi che chiedono un'azione.
            StringBuilder captured = new StringBuilder();
            // L'inventario PRIMA: e' l'unico modo di accorgersi di un pacchetto che cambia
            // senza essere nel piano. Il confronto riga per riga del piano non puo' vederlo.
            Map<String, String> inventoryBefore = PackagePlan.versionsOnly(PackagePlan.installed());
            // E la configurazione con gli indirizzi in ascolto, nello stesso istante: il piano
            // dice quali pacchetti cambiano, non che cosa i loro script riscrivono.
            sideEffects.takeBefore();
            // Chi legge ogni tipo di mappa di Postfix, e il contenuto delle mappe che non si rigenerano
            // dal testo, prima: se dopo la libreria e' cambiata, le mappe si rigenerano uguali a prima.
            PostfixMaps.Before mapsBefore = PostfixMaps.before();
            // -U: stesso catalogo su cui e' stato calcolato il piano. Riscaricarlo adesso potrebbe
            // portare versioni diverse da quelle approvate.
            int code = runLogged(job, "pkg upgrade -y -U" + list + " 2>&1", 1800, captured);
            // 4 = EX_NEEDRESTART: pkg ha aggiornato se stesso. Le versioni recenti si rilanciano
            // da sole e fanno il resto; se questa si e' fermata li', la si rilancia una volta, uguale.
            if (code == 4) {
                job.write(I18n.tr("server.um.runGuidedUpdate.10"));
                code = runLogged(job, "pkg upgrade -y -U" + list + " 2>&1", 1800, captured);
            }

            // Il confronto con l'inventario si fa SUBITO, prima di decidere se fermarsi: un
            // pkg che esce diverso da zero e' proprio il caso in cui la macchina puo' essere
            // rimasta a meta', e allora sapere che cosa e' cambiato conta di piu', non di
            // meno. Misurato sulla VM il 23/10/2026: un aggiornamento guidato di
            // postfix-mysql si e' fermato a meta' con uscita 3 (mysql97-client in conflitto
            // con mysql84-client sugli stessi file) dopo che il solver aveva aggiunto al
            // piano una rimozione che il piano firmato non aveva.
            outsidePlan = compareWithInventory(job, inventoryBefore, plan,
                    "Guided update of " + name);
            // Anche questo prima di decidere se fermarsi, per la stessa ragione. Il riavvio dei
            // servizi qui sotto mette in vigore quello che uno script ha scritto.
            sideEffects.checkConfig(job, plan, outsidePlan, !services.isEmpty());
            // Le mappe prima del riavvio dei servizi, e anche se pkg e' uscito con un errore: e'
            // proprio quando la macchina puo' essere rimasta a meta'.
            String mapsProblem = PostfixMaps.afterUpgrade(mapsBefore, l -> job.write("  " + l)).problem();

            if (code != 0) throw new IllegalStateException("pkg upgrade exited with code " + code);
            if (mapsProblem != null) throw new IllegalStateException(mapsProblem);

            String versionAfter = sh("pkg query %v " + name + " 2>/dev/null", 20);
            job.write(I18n.tr("server.um.runGuidedUpdate.11", java.util.Map.of("versionAfter", String.valueOf(versionAfter))));
            if (versionAfter.equals(versionBefore)) {
                throw new IllegalStateException("the version did not change: the update had no effect");
            }
            // Ogni riga del piano, controllata: non "pkg e' uscito con 0", ma "ogni pacchetto e'
            // alla versione che il piano diceva".
            job.write(I18n.tr("server.um.runGuidedUpdate.12"));
            JSONArray verification = PackagePlan.verifyOutcome(plan);
            for (int i = 0; i < verification.length(); i++) {
                JSONObject v = verification.getJSONObject(i);
                job.write("    " + (v.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("name", String.valueOf(v.getString("name")), "expected", String.valueOf(v.getString("expected")), "found", String.valueOf(v.getString("found")))));
                if (!v.getBoolean("ok")) planNotFollowed = true;
            }
            if (planNotFollowed) job.write(I18n.tr("server.um.runGuidedUpdate.13"));


            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.14", java.util.Map.of("total", String.valueOf(TOT), "name", String.valueOf(name))));
            job.write(I18n.tr("server.um.runGuidedUpdate.15"));
            boolean servicesProblem = false;
            if (services.isEmpty()) {
                JSONArray rd = pf.optJSONArray("reverseDeps");
                job.write("  " + (rd == null || rd.length() == 0
                        ? I18n.tr("server.um.x.noRestartZero")
                        : I18n.tr("server.um.x.noRestartSome", java.util.Map.of("n", String.valueOf(rd.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(rd)))))));
                if (name.matches(SHARED_LIBRARIES)) {
                    job.write(I18n.tr("server.um.runGuidedUpdate.16", java.util.Map.of("name", String.valueOf(name))));
                    job.write(I18n.tr("server.um.runGuidedUpdate.17"));
                    job.write(I18n.tr("server.um.runGuidedUpdate.18"));
                    job.write(I18n.tr("server.um.runGuidedUpdate.19"));
                    job.write(I18n.tr("server.um.runGuidedUpdate.20"));
                    manualRecheck = true;
                }
            }
            // Uno script ha cambiato la configurazione e il piano non lo diceva: riavviare
            // metterebbe in vigore una modifica che nessuno ha letto. E' il reperto 42 —
            // inet_protocols = ipv4 scritto in main.cf, e il riavvio che toglie IPv6 a un server
            // di posta che risultava «in servizio». Allora non si riavvia: i servizi restano con
            // la configurazione di prima, ancora in memoria, e chi legge decide. Il costo e'
            // scritto qui sotto, ed e' lo stesso stato in cui la manutenzione completa lascia
            // sempre la macchina: aggiornata, con i processi vecchi finche' qualcuno non li
            // riavvia.
            boolean holdRestarts = sideEffects.configChangedByScript() && !services.isEmpty();
            if (holdRestarts) {
                job.write(I18n.tr("server.drift.restartHeld", java.util.Map.of("list", String.join(", ", services))));
                job.write(I18n.tr("server.drift.restartHeldCost"));
            }
            for (String s : services) {
                if (holdRestarts) {
                    heldRestarts.add(s);
                    job.write("      service " + s + " restart");
                    continue;
                }
                if (!Boolean.TRUE.equals(activeBefore.get(s))) {
                    job.write(I18n.tr("server.um.runGuidedUpdate.21", java.util.Map.of("s", String.valueOf(s))));
                    continue;
                }
                // Si chiede al servizio se accetta la propria configurazione PRIMA di
                // riavviarlo: se non la accetta, riavviarlo lo spegnerebbe e basta. Meglio
                // lasciarlo in piedi con quella vecchia e dirlo.
                String test = testConfigOf(s);
                if (test != null) {
                    Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), test + " 2>&1");
                    if (!pr.success()) {
                        job.write(I18n.tr("server.um.runGuidedUpdate.22", java.util.Map.of("s", String.valueOf(s))));
                        for (String l : pr.outputTrim().split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
                        job.write(I18n.tr("server.um.runGuidedUpdate.23"));
                        servicesProblem = true;
                        continue;
                    }
                    job.write(I18n.tr("server.um.runGuidedUpdate.24", java.util.Map.of("s", String.valueOf(s))));
                }
                boolean r1 = ok("service " + s + " restart", 120);
                boolean active = ok("service " + s + " status", 20);
                String pidAfter = servicePid(s);
                String pidP = pidBefore.getOrDefault(s, "");
                String note = "";
                if (!pidP.isEmpty() && !pidAfter.isEmpty()) {
                    note = pidP.equals(pidAfter)
                        ? I18n.tr("server.um.runGuidedUpdate.25", java.util.Map.of("pidAfter", String.valueOf(pidAfter)))
                        : "  (pid " + pidP + " -> " + pidAfter + ")";
                    if (pidP.equals(pidAfter)) servicesProblem = true;
                }
                job.write("    " + s + ": " + (r1 ? I18n.tr("server.um.x.restarted") : I18n.tr("server.um.runGuidedUpdate.26"))
                        + ", " + (active ? I18n.tr("server.um.x.nowRunning") : I18n.tr("server.um.x.nowNotRunning")) + note);
                if (!active) servicesProblem = true;

                // Ha ritrovato i suoi dati, o e' ripartito vuoto?
                String[] after = testAfterOf(s);
                if (after != null && active) {
                    String out = sh(after[1], 30).trim();
                    long n = number(out);
                    job.write("      " + I18n.tr(after[2]) + ": " + (out.isEmpty() ? I18n.tr("server.um.runGuidedUpdate.27") : String.valueOf(n)));
                    if (n == 0) {
                        job.write(I18n.tr("server.um.runGuidedUpdate.28"));
                        job.write(I18n.tr("server.um.runGuidedUpdate.29"));
                        job.write("      " + I18n.tr("server.um.x.rsGreyLimits"));
                        servicesProblem = true;
                    }
                }
            }

            job.advance(5, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.30", java.util.Map.of("total", String.valueOf(TOT))));
            // Sulla versione NUOVA, quella appena installata: chiedere col solo nome
            // risponderebbe a un'altra domanda (vedi auditReport).
            JSONObject reportAfter = auditReport(name, versionAfter);
            if (!reportAfter.optBoolean("done")) {
                // "Non ho potuto controllare" non e' "non ci sono vulnerabilita'".
                job.write("  " + reportAfter.optString("error"));
                job.write("  " + I18n.tr("server.um.x.auditUncertain"));
            } else if (reportAfter.optInt("problems") == 0) {
                job.write(I18n.tr("server.um.runGuidedUpdate.31", java.util.Map.of("name", String.valueOf(name))));
            } else {
                job.write("  " + I18n.tr("server.um.x.cvesLeft", java.util.Map.of("n", String.valueOf(reportAfter.optInt("problems")), "name", String.valueOf(name), "d", String.valueOf(reportAfter.getString("description")))));
                job.write(I18n.tr("server.um.runGuidedUpdate.32"));
            }

            writeActionMessages(job, captured.toString());

            job.advance(6, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runGuidedUpdate.35", java.util.Map.of("total", String.valueOf(TOT))));
            boolean fallen = fallenServices(job, servicesBefore);
            sideEffects.checkListening(job);
            java.util.List<String> effects = sideEffects.problems();
            if (!heldRestarts.isEmpty())
                effects.add(I18n.tr("server.drift.restartHeldProblem", java.util.Map.of("list", String.join(", ", heldRestarts))));

            if (planNotFollowed || !outsidePlan.isEmpty()) {
                // Due guasti diversi, e il messaggio li distingue: "piano non rispettato" e'
                // un pacchetto del piano che non e' arrivato dove doveva, la divergenza e'
                // qualcosa che e' cambiato senza essere nel piano. Possono presentarsi
                // insieme, quindi si dicono entrambi.
                job.status = "error";
                java.util.List<String> problems = new ArrayList<>();
                if (planNotFollowed) problems.add(I18n.tr("server.um.runGuidedUpdate.36"));
                if (!outsidePlan.isEmpty()) problems.add(divergenceMessage(outsidePlan));
                problems.addAll(effects);
                job.errorMessage = String.join(" ", problems);
            } else if (servicesProblem || fallen) {
                job.status = "error";
                java.util.List<String> problems = new ArrayList<>();
                problems.add(I18n.tr("server.um.runGuidedUpdate.37"));
                problems.addAll(effects);
                job.errorMessage = String.join(" ", problems);
            } else if (!effects.isEmpty()) {
                // Ogni passo e' riuscito — piano, riavvio, pid, servizi — ed e' proprio il caso
                // del reperto 42: il pacchetto e' in servizio, ma con una configurazione che
                // nessuno ha approvato, o senza un indirizzo che prima rispondeva.
                job.status = "error";
                job.errorMessage = String.join(" ", effects);
            } else if (manualRecheck) {
                // Non e' un errore, ma nemmeno un "fatto e verificato": dirlo completato
                // sarebbe affermare una cosa che il pannello non ha potuto controllare.
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runGuidedUpdate.38", java.util.Map.of("name", String.valueOf(name), "versionAfter", String.valueOf(versionAfter))));
                job.write(I18n.tr("server.um.runGuidedUpdate.39"));
                job.write(I18n.tr("server.um.runGuidedUpdate.40"));
            } else {
                job.status = "completed";
                job.write("");
                job.write("=== " + I18n.tr("server.um.x.inService", java.util.Map.of("name", String.valueOf(name), "v", String.valueOf(versionAfter))) + " ===");
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            // pkg fermo a meta' dopo che uno script ha gia' scritto: si dicono tutte e due.
            for (String p : sideEffects.problems()) job.errorMessage += " " + p;
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // La riprotezione avviene SEMPRE, qualunque cosa sia andata storta sopra.
            if (!toRelock2.isEmpty()) {
                job.write("");
                job.write(I18n.tr("server.um.x.reprotecting", java.util.Map.of("n", String.valueOf(toRelock2.size()))));
                int relockedCount = 0;
                for (String m : toRelock2) {
                    boolean relocked = ok("pkg info -e " + m, 15) && ok("pkg lock -y " + m, 30);
                    if (relocked) relockedCount++;
                    else job.write(I18n.tr("server.um.runGuidedUpdate.41", java.util.Map.of("m", String.valueOf(m))));
                }
                job.write("  " + I18n.tr("server.um.x.reprotectedCount", java.util.Map.of("n", String.valueOf(relockedCount), "tot", String.valueOf(toRelock2.size()))));
                if (relockedCount == toRelock2.size()) clearState();
                else {
                    job.write(I18n.tr("server.um.runPythonTransition.21", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
                    if ("completed".equals(job.status)) {
                        job.status = "error";
                        job.errorMessage = I18n.tr("server.um.runGuidedUpdate.42");
                    }
                }
            }
            job.finishedAt = System.currentTimeMillis();
        }
    }

    /**
     * Elimina SOLO le cache Hyperscan di rspamd e riavvia il servizio.
     *
     * E' una cancellazione, cioe' la categoria di operazione che puo' far sparire qualcosa:
     * il percorso e il criterio sono scritti qui e non arrivano dalla richiesta, e alla fine
     * il pannello DIMOSTRA di non aver toccato altro contando i file rimanenti prima e dopo.
     * "Ho cancellato solo quelli" e' un'affermazione, e le affermazioni si verificano.
     */
    public static JSONObject startRspamdCacheCleanup() {
        String id = "rspamd-cache-" + System.currentTimeMillis();
        Job j = new Job(id, "rspamd_cache");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                final String DIR = "/var/db/rspamd";
                j.advance(1, 4);
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.1"));
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.2"));
                long unserBefore = number(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long othersBefore = number(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.3", java.util.Map.of("unserBefore", String.valueOf(unserBefore))));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.4", java.util.Map.of("othersBefore", String.valueOf(othersBefore))));
                if (unserBefore == 0) {
                    j.status = "completed";
                    j.write(I18n.tr("server.um.startRspamdCacheCleanup.5"));
                    return;
                }
                for (String f : sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null", 60).split("\n")) {
                    if (!f.trim().isEmpty()) j.write("      " + f.trim());
                }

                j.advance(2, 4);
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.6"));
                ok("find " + DIR + " -type f -name '*.unser' -delete", 120);

                j.advance(3, 4);
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.7"));
                long unserAfter = number(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long othersAfter = number(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.8", java.util.Map.of("unserAfter", String.valueOf(unserAfter))));
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.9", java.util.Map.of("othersBefore", String.valueOf(othersBefore), "othersAfter", String.valueOf(othersAfter))));
                if (othersAfter != othersBefore) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.10", java.util.Map.of("othersBefore", String.valueOf(othersBefore), "othersAfter", String.valueOf(othersAfter)));
                    j.write("    " + I18n.tr("server.um.x.alarm", java.util.Map.of("m", String.valueOf(j.errorMessage))));
                    return;
                }
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.11"));

                j.advance(4, 4);
                j.write("");
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.12"));
                Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), "rspamadm configtest 2>&1");
                if (!pr.success()) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.13");
                    j.write("    " + pr.outputTrim());
                    return;
                }
                j.write(I18n.tr("server.um.startRspamdCacheCleanup.14"));
                String pidBefore = servicePid("rspamd");
                ok("service rspamd restart", 120);
                boolean active = ok("service rspamd status", 30);
                String pidAfter = servicePid("rspamd");
                j.write("    rspamd: " + (active ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26"))
                        + (pidBefore.isEmpty() || pidAfter.isEmpty() ? "" : "  (pid " + pidBefore + " -> " + pidAfter + ")"));
                if (!active) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.15");
                } else {
                    j.status = "completed";
                    j.write("");
                    j.write(I18n.tr("server.um.startRspamdCacheCleanup.16"));
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = e.getMessage();
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.finishedAt = System.currentTimeMillis();
            }
        }, "rspamd-cache");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Pacchetti che pretendono una libreria condivisa che sul disco NON c'e' piu'.
     *
     * E' il buco che ha fermato la posta: dopo aver sostituito mysql80-client con
     * mysql84-client, postfix-mysql e dovecot-mysql restavano compilati contro
     * libmysqlclient.so.21 e non caricavano piu'. Il preflight aveva verificato che il
     * REPOSITORY li fornisse compatibili con la 8.4 — ed era vero — ma non che quelli
     * INSTALLATI lo fossero. Sono due cose diverse e le avevo trattate come una sola.
     *
     * Qui non si indovina: si chiede a pkg quali librerie ogni pacchetto richiede (%B) e si
     * guarda se esistono davvero.
     */
    public static JSONObject packagesWithMissingLibraries() {
        JSONArray broken = new JSONArray();
        java.util.LinkedHashSet<String> missingLibraries = new java.util.LinkedHashSet<>();
        for (String line : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            String name = t.substring(0, sp).trim();
            String lib = t.substring(sp + 1).trim();
            if (!isValidName(name) || lib.isEmpty()) continue;
            if (!lib.matches("[A-Za-z0-9._+-]{1,128}")) continue;
            if (missingLibraries.contains(lib)) { broken.put(new JSONObject().put("name", name).put("lib", lib)); continue; }
            // Una libreria c'e' se il linker riesce a trovarla fra quelle note al sistema.
            if (!ok("ldconfig -r 2>/dev/null | grep -q ' " + lib + "$' || " +
                    "find /lib /usr/lib /usr/local/lib -name '" + lib + "' -maxdepth 3 2>/dev/null | grep -q .", 30)) {
                missingLibraries.add(lib);
                broken.put(new JSONObject().put("name", name).put("lib", lib));
            }
        }
        return new JSONObject().put("success", true).put("packages", broken)
                .put("missingLibs", new JSONArray(new ArrayList<>(missingLibraries)));
    }

    /**
     * "openssl: nessun pacchetto lo richiede, si puo' togliere" era una conclusione troppo
     * sicura per come veniva calcolata. `pkg query %rn` dice chi lo DICHIARA nel registro di
     * pkg; non dice chi lo sta davvero aprendo.
     *
     * La differenza conta perche' sul disco ci sono DUE OpenSSL: quella del sistema base in
     * /usr/lib, che non e' un pacchetto, non compare in pkg e non si tocca, e il port in
     * /usr/local/lib. Se le due copie portano lo stesso soname, nessuna lettura del registro
     * puo' dire quale delle due venga aperta, perche' i due nomi sono identici.
     *
     * Si misurano quindi tre cose distinte, e la terza e' l'unica che decide:
     *   1. chi dichiara il pacchetto                       -> pkg query %rn
     *   2. chi richiede i suoi soname                      -> pkg query %B  (ambiguo se i
     *      soname del port e quelli del base coincidono)
     *   3. quali processi VIVI hanno mappato una libreria in /usr/local/lib -> procstat -v
     *
     * procstat(1) mostra "process virtual memory mappings, including [...] mapped object
     * information": e' cio' che e' aperto adesso, non cio' che qualcuno ha dichiarato quando
     * il pacchetto e' stato compilato. Richiede pero' di essere il proprietario del processo
     * o root; se non lo si e', l'elenco torna vuoto e sembrerebbe "non lo usa nessuno".
     * Per questo si conta anche quanti processi mappano una qualsiasi libssl/libcrypto: se
     * quel totale e' zero su un server di posta con TLS attivo, la misura non ha funzionato
     * e va detto, invece di spacciare il silenzio per una risposta.
     */
    /**
     * Il caso openssl e' venuto fuori per intuizione di Pietro, non perche' il pannello
     * sapesse cercarlo: il port non lo dichiarava nessuno, ma lo installa uno script del
     * pannello e il pannello ne esegue il comando. Chiedere all'intuizione di ripetersi a
     * ogni rimozione e' esattamente il modo di sbagliare la volta che non ci si pensa.
     *
     * Qui la domanda diventa una misura, e vale per QUALSIASI pacchetto: prima di toglierlo,
     * il pannello lo usa nei propri script?
     *
     * Non si consulta un elenco scritto a mano, che invecchierebbe alla prima modifica:
     * si legge il jar CHE STA GIRANDO. I nomi dei comandi che il pannello invoca sono
     * costanti di stringa dentro le sue classi, quindi si estraggono le classi del pannello
     * dal jar e si cercano dentro i nomi degli eseguibili che il pacchetto installa.
     *
     * Due cautele, perche' una ricerca puo' fallire in modi che sembrano una risposta:
     *  - si contano i byte letti dal jar: se sono zero, la lettura non e' riuscita e va
     *    detto, invece di concludere "non lo usa";
     *  - i nomi cortissimi (tr, cut, ls) comparirebbero ovunque per caso, quindi sotto i
     *    quattro caratteri non si decide e lo si dichiara.
     */
    /**
     * Quali pacchetti sono anche solo CANDIDATI a essere tolti: quelli installati
     * esplicitamente (non tirati dentro come dipendenza) e che nessun altro pacchetto
     * dichiara. Sono gli unici su cui abbia senso porsi la domanda, ed e' l'elenco su cui
     * il controllo "il pannello lo usa?" va passato prima di rimuovere qualsiasi cosa.
     *
     * Si ricava con due letture invece che con una interrogazione per pacchetto:
     * l'elenco degli espliciti, e l'insieme di tutti i nomi che compaiono come dipendenza
     * di qualcuno. La differenza fra i due e' la risposta.
     */
    public static JSONObject removalCandidates() {
        java.util.LinkedHashSet<String> explicit = new java.util.LinkedHashSet<>();
        for (String n : sh("pkg query -e '%a = 0' '%n' 2>/dev/null", 60).split("\n"))
            if (isValidName(n.trim())) explicit.add(n.trim());

        java.util.HashSet<String> required = new java.util.HashSet<>();
        for (String line : sh("pkg query '%n %dn' 2>/dev/null", 120).split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp > 0) required.add(t.substring(sp + 1).trim());
        }

        String lock = sh("pkg lock -l 2>/dev/null", 30);

        JSONArray outside = new JSONArray();
        int withRole = 0;
        for (String n : explicit) {
            if (required.contains(n)) continue;
            String role = roleOf(n);
            if (role != null) withRole++;
            boolean essential = n.equals("pkg") || n.equals("pkg-devel");
            outside.put(new JSONObject().put("name", n)
                    .put("version", sh("pkg query %v " + n + " 2>/dev/null", 20))
                    .put("isProtected", locked(lock, n))
                    .put("role", role == null ? "" : role)
                    .put("essential", essential)
                    .put("warning", essential
                            ? I18n.tr("server.um.removalCandidates.1")
                            : (role == null ? "" : I18n.tr("server.um.removalCandidates.2"))));
        }
        return new JSONObject().put("success", true).put("candidates", outside)
                .put("explicitTotal", explicit.size()).put("withRole", withRole)
                .put("caution", I18n.tr("server.um.removalCandidates.3"))
                .put("explanation", I18n.tr("server.um.removalCandidates.4"));
    }

    /**
     * I luoghi in cui il pannello, i pacchetti e l'amministratore lasciano cose che vengono
     * eseguite DOPO: script di rinnovo, cron, rc.d, periodic, configurazioni. Il jar non li
     * contiene, quindi cercarli solo li' dentro non basta.
     */
    private static final String[][] PLACES = {
        {"/etc",                    "server.um.removalCandidates.5"},
        {"/usr/local/etc",          "server.um.removalCandidates.6"},
        {"/var/cron/tabs",          "server.um.place.userCrontabs"},
        {"/var/db/mailpanel",       "server.um.removalCandidates.7"},
        {"/root",                   "server.um.place.root"},
        {"/usr/local/bin",          "server.um.removalCandidates.8"},
        {"/usr/local/sbin",         "server.um.removalCandidates.9"},
        {"/usr/local/www/roundcube","server.um.removalCandidates.10"},
    };

    /**
     * L'analisi approfondita prima di togliere un pacchetto. Nasce da una richiesta precisa:
     * "non voglio che poi script o altro smettano di funzionare".
     *
     * Il controllo sul jar rispondeva a una domanda sola — il pannello ne invoca i comandi? —
     * e quella domanda e' la meno pericolosa, perche' un comando invocato col nome nudo
     * ripiega da solo sull'altra copia nel PATH. Cio' che rompe davvero e' un riferimento che
     * NON puo' ripiegare:
     *
     *   - un percorso assoluto dentro il pacchetto (/usr/local/bin/openssl): sparisce il file,
     *     e chi lo nomina fallisce;
     *   - un soname fornito dal pacchetto (libssl.so.12): sparisce la libreria, e chi ci si
     *     collega non parte piu'.
     *
     * Quindi si separano nettamente due elenchi: i riferimenti che ROMPONO e quelli che
     * REGGONO. E si cerca in tre posti diversi, perche' bastano due su tre per ingannarsi:
     * dentro il jar, fra i pacchetti installati (chi dichiara quei soname), e sui file di
     * testo del sistema, dove vivono gli script che girano piu' tardi.
     *
     * Ogni ricerca dichiara quanti file di testo ha esaminato. Una ricerca che non trova
     * nulla perche' non ha guardato da nessuna parte e' indistinguibile, nel risultato, da
     * una che ha guardato e non ha trovato: il conteggio e' cio' che le distingue.
     */
    public static JSONObject deepAnalysis(String pkgName) {
        if (!isValidName(pkgName))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        if (!ok("pkg info -e " + pkgName, 20))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.2", java.util.Map.of("pkg", String.valueOf(pkgName))));

        JSONObject r = new JSONObject().put("success", true).put("pkgName", pkgName);

        // --- cosa il pacchetto mette sul disco: percorsi assoluti e soname ---
        String list = sh("pkg query '%Fp' " + pkgName + " 2>/dev/null", 60);
        if (list.isBlank()) list = sh("pkg info -l " + pkgName + " 2>/dev/null", 60);
        java.util.LinkedHashSet<String> paths = new java.util.LinkedHashSet<>();
        java.util.LinkedHashSet<String> bases = new java.util.LinkedHashSet<>();
        for (String line : list.split("\n")) {
            String f = line.trim();
            if (!f.matches("(/usr)?(/local)?/(s?bin|libexec)(/[A-Za-z0-9._+-]{1,64}){1,2}")) continue;
            paths.add(f);
            bases.add(f.substring(f.lastIndexOf('/') + 1));
        }
        java.util.LinkedHashSet<String> soname = new java.util.LinkedHashSet<>();
        for (String l : sh("pkg query %b " + pkgName + " 2>/dev/null", 30).split("\n"))
            if (l.trim().matches("[A-Za-z0-9._+-]{1,128}")) soname.add(l.trim());
        r.put("paths", new JSONArray(new ArrayList<>(paths)))
         .put("soname", new JSONArray(new ArrayList<>(soname)));

        // I motivi per cui una rimozione rompe: percorso assoluto, o soname.
        java.util.LinkedHashSet<String> breakOnes = new java.util.LinkedHashSet<>(paths);
        breakOnes.addAll(soname);
        for (String sn : soname) { breakOnes.add("/usr/local/lib/" + sn); }
        r.put("searched", new JSONArray(new ArrayList<>(breakOnes)));

        // --- 1. chi, fra i pacchetti installati, dichiara quei soname ---
        JSONArray declareSoname = new JSONArray();
        if (!soname.isEmpty()) {
            for (String line : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
                String t = line.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                String n = t.substring(0, sp).trim(), lib = t.substring(sp + 1).trim();
                if (!n.equals(pkgName) && soname.contains(lib))
                    declareSoname.put(new JSONObject().put("pkgName", n).put("library", lib));
            }
        }
        r.put("declareSoname", declareSoname);

        // --- 2. il jar in esecuzione: percorsi assoluti e soname, non solo i nomi nudi ---
        String jar = jarPath();
        JSONArray inJar = new JSONArray();
        long jarBytes = 0;
        int blockingJars = 0;
        String myFile = UpdateManager.class.getSimpleName();
        if (jar != null && !jar.isBlank() && ok("test -r " + jar, 15)) {
            String n = sh("tar -xOf " + jar + " 'org/mail_panel/*' 2>/dev/null | wc -c", 120)
                    .trim().replaceAll("[^0-9]", "");
            if (!n.isEmpty()) jarBytes = Long.parseLong(n);
            if (jarBytes > 0) {
                StringBuilder pat = new StringBuilder();
                for (String x : breakOnes) pat.append(" -e '").append(x).append("'");
                // Estrazione in una cartella temporanea: solo cosi' grep puo' dire QUALE classe.
                String output = sh("d=$(mktemp -d) && tar -xf " + jar + " -C \"$d\" 'org/mail_panel/*' "
                        + "2>/dev/null; grep -rlaF" + pat + " \"$d\" 2>/dev/null "
                        + "| sed \"s|^$d/||\"; rm -rf \"$d\"", 240);
                for (String line : output.split("\n")) {
                    String f = line.trim();
                    if (f.isEmpty() || !f.endsWith(".class")) continue;
                    String className = f.substring(f.lastIndexOf('/') + 1).replace(".class", "");
                    boolean mine = className.equals(myFile) || className.startsWith(myFile + "$");
                    if (!mine) blockingJars++;
                    inJar.put(new JSONObject().put("className", className).put("file", f)
                            .put("selfReference", mine));
                }
            }
        }
        r.put("jar", jar == null ? "" : jar).put("jarBytes", jarBytes)
         .put("jarRead", jarBytes > 0).put("inJar", inJar).put("blockingJars", blockingJars)
         .put("checkClass", myFile);

        // --- 3. i file di testo del sistema: dove vivono gli script che girano dopo ---
        JSONArray places = new JSONArray();
        int totalBreak = 0, totalHold = 0;
        StringBuilder patternsBreak = new StringBuilder();
        for (String x : breakOnes) patternsBreak.append(" -e '").append(x).append("'");
        StringBuilder patternsHold = new StringBuilder();
        for (String b : bases) if (b.length() >= 4) patternsHold.append(" -e '").append(b).append("'");

        for (String[] L : PLACES) {
            if (!ok("test -d " + L[0], 15)) continue;
            JSONObject u = new JSONObject().put("where", L[0]).put("whatItContains", I18n.tr(L[1]));
            // Quanti file di testo esistono qui: e' la prova che la ricerca ha guardato.
            String cnt = sh("grep -rIl '' " + L[0] + " 2>/dev/null | wc -l", 180).trim().replaceAll("[^0-9]", "");
            int reviewed = cnt.isEmpty() ? 0 : Integer.parseInt(cnt);
            u.put("filesReviewed", reviewed);

            JSONArray breaks = new JSONArray();
            if (patternsBreak.length() > 0) {
                for (String line : sh("grep -rInIF" + patternsBreak + " " + L[0]
                        + " 2>/dev/null | head -40", 240).split("\n")) {
                    if (line.isBlank()) continue;
                    breaks.put(line.length() > 300 ? line.substring(0, 300) + "..." : line);
                }
            }
            int hold = 0;
            if (patternsHold.length() > 0) {
                String q = sh("grep -rIwoF" + patternsHold + " " + L[0] + " 2>/dev/null | wc -l", 240)
                        .trim().replaceAll("[^0-9]", "");
                if (!q.isEmpty()) hold = Integer.parseInt(q);
            }
            u.put("breakOnes", breaks).put("hold", hold);
            totalBreak += breaks.length();
            totalHold += hold;
            places.put(u);
        }
        r.put("places", places).put("totalBreak", totalBreak).put("totalHold", totalHold);

        // --- il giudizio ---
        // Il riferimento che sta nella classe che ESEGUE questo controllo non blocca: e'
        // l'analisi che nomina cio' che deve ispezionare, non un uso che si romperebbe.
        boolean blocking = totalBreak > 0 || blockingJars > 0 || declareSoname.length() > 0;
        r.put("blocking", blocking);
        r.put("verdict", blocking ? "REFS_WOULD_BREAK" : "NO_REF_BREAKS");
        int auto = inJar.length() - blockingJars;
        r.put("explanation", blocking
                ? I18n.tr("server.um.deepAnalysis.5", java.util.Map.of("pkg", String.valueOf(pkgName)))
                : I18n.tr("server.um.x.deepClean", java.util.Map.of("pkg", String.valueOf(pkgName), "n", String.valueOf(totalHold)))
                  + (auto > 0
                     ? " " + (auto == 1
                        ? I18n.tr("server.um.x.deepSelf.one", java.util.Map.of("file", String.valueOf(myFile)))
                        : I18n.tr("server.um.x.deepSelf.other", java.util.Map.of("n", String.valueOf(auto), "file", String.valueOf(myFile))))
                     : ""));
        r.put("caveat", I18n.tr("server.um.deepAnalysis.6"));
        return r;
    }

    /**
     * Il verdetto del jar lascia procedere la rimozione: il pannello non ne usa i comandi (anche
     * se e' una libreria: chi la richiede lo dice pkg query %rn, controllato prima, e i file sul
     * disco li guarda deepAnalysis, dopo), oppure li nomina ma non sono i suoi. Il 25/10/2026 i
     * verdetti sono passati all'inglese, e qui era rimasto il prefisso italiano di quello delle
     * librerie: la rimozione di una libreria non usata veniva rifiutata. Funzione pura.
     */
    static boolean removableByJarVerdict(String v) {
        return "PANEL_DOES_NOT_USE".equals(v) || "NAMES_NOT_THEIRS".equals(v) || "LIBRARY_ONLY".equals(v);
    }

    /**
     * La rimozione di un pacchetto, fatta dal pannello e non dettata come comando da SSH.
     *
     * Non e' un pulsante che esegue "pkg delete": e' il controllo che decide se eseguirlo.
     * Rifiuta da solo nei casi in cui la rimozione farebbe danno, e in quelli in cui non ha
     * potuto stabilire che non ne farebbe — che e' la stessa cosa. Poi verifica l'esito
     * guardando il sistema, non il codice di uscita di pkg: il pacchetto e' sparito davvero,
     * nessun altro pacchetto e' rimasto senza una libreria, i servizi sono ancora su.
     *
     * Aspetta il turno dei lavori sui pacchetti (vedi PackageQueue).
     */
    public static JSONObject removePackage(String name) {
        String id = "remove-" + System.nanoTime();
        String refusal = PackageQueue.take(id, I18n.tr("server.um.removePackage.1", java.util.Map.of("name", String.valueOf(name))));
        if (refusal != null) return new JSONObject().put("success", false).put("error", refusal);
        StringBuilder wayBack = new StringBuilder();
        PackageWayBack.Prepared wb;
        try { wb = PackageWayBack.before(l -> wayBack.append(l).append('\n'), "remove-" + name); }
        catch (IllegalStateException e) {
            PackageQueue.release(id);
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
        JSONObject r = null;
        try { return r = removePackageNow(name); }
        finally {
            PackageWayBack.after(l -> wayBack.append(l).append('\n'), wb);
            if (r != null) r.put("log", wayBack + r.optString("log", ""));
            refreshLockTrace();
            PackageQueue.release(id);
        }
    }

    private static JSONObject removePackageNow(String name) {
        if (!isValidName(name))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        StringBuilder log = new StringBuilder();
        JSONObject r = new JSONObject().put("pkgName", name);

        if (!ok("pkg info -e " + name, 20)) {
            log.append(I18n.tr("server.um.x.rmNotInstalled", java.util.Map.of("name", String.valueOf(name)))).append("\n")
               .append(I18n.tr("server.um.x.rmChecksAnyway")).append("\n");
            JSONObject lib0 = packagesWithMissingLibraries();
            JSONArray broken0 = lib0.optJSONArray("packages");
            boolean fault0 = broken0 != null && broken0.length() > 0;
            r.put("missingLibraries", lib0).put("services", servicesJson())
             .put("removed", true).put("alreadyAbsent", true).put("fault", fault0)
             .put("after", countLines(sh("pkg query %n 2>/dev/null", 60)));
            log.append("--- ").append(I18n.tr("server.um.x.check")).append(" ---\n")
               .append(fault0 ? I18n.tr("server.um.removePackageNow.1", java.util.Map.of("length", String.valueOf(broken0.length())))
                               : I18n.tr("server.um.removePackageNow.2")).append("\n");
            return r.put("success", true).put("log", log.toString())
                    .put("note", fault0
                            ? I18n.tr("server.um.removePackageNow.3", java.util.Map.of("name", String.valueOf(name), "name2", String.valueOf(name)))
                            : I18n.tr("server.um.removePackageNow.4", java.util.Map.of("name", String.valueOf(name))));
        }

        // --- chi lo dichiara: se qualcuno lo fa, non si tocca ---
        String declare = sh("pkg query %rn " + name + " 2>/dev/null", 30).trim();
        if (!declare.isEmpty())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.x.rmDeclaredDep", java.util.Map.of("list", String.valueOf(declare.replace("\n", ", ")))));

        // --- e il pannello? la stessa misura della scheda, rifatta adesso ---
        JSONObject use = panelUsage(name);
        r.put("use", use);
        String v = use.optString("verdict", "");
        if (!removableByJarVerdict(v))
            return new JSONObject().put("success", false).put("use", use)
                    .put("error", I18n.tr("server.um.x.rmJarSays", java.util.Map.of("v", String.valueOf(v))) + " "
                            + use.optString("explanation", ""));

        // --- e i riferimenti sul disco? il jar e' solo uno dei tre posti ---
        JSONObject deepResult = deepAnalysis(name);
        r.put("deep", deepResult);
        if (deepResult.optBoolean("blocking"))
            return new JSONObject().put("success", false).put("deep", deepResult)
                    .put("error", I18n.tr("server.um.removePackageNow.5", java.util.Map.of("name", String.valueOf(name))));

        // --- fotografia prima, per poter confrontare dopo ---
        int before = countLines(sh("pkg query %n 2>/dev/null", 60));
        log.append(I18n.tr("server.um.x.pkgsBefore", java.util.Map.of("n", String.valueOf(before)))).append("\n");

        boolean isProtected = locked(sh("pkg lock -l 2>/dev/null", 30), name);
        log.append(isProtected ? I18n.tr("server.um.x.protBeforeYes") : I18n.tr("server.um.x.protBeforeNo")).append("\n");
        if (isProtected) {
            log.append("--- ").append(I18n.tr("server.um.x.unlockSection")).append(" ---\n")
               .append(sh("pkg unlock -y " + name + " 2>&1", 60)).append("\n");
            if (locked(sh("pkg lock -l 2>/dev/null", 30), name)) {
                log.append(I18n.tr("server.um.x.stillProtected")).append("\n");
                return r.put("success", false).put("log", log.toString())
                        .put("error", I18n.tr("server.um.removePackageNow.6", java.util.Map.of("name", String.valueOf(name))));
            }
            log.append(I18n.tr("server.um.x.protRemoved")).append("\n");
        }

        String deleteOutput = sh("pkg delete -y " + name + " 2>&1", 180);
        log.append("--- ").append(I18n.tr("server.um.x.removalSection")).append(" ---\n").append(deleteOutput).append("\n");

        // L'esito lo dice il sistema, non il codice di uscita.
        boolean via = !ok("pkg info -e " + name, 20);
        int after = countLines(sh("pkg query %n 2>/dev/null", 60));
        log.append(I18n.tr("server.um.x.pkgsAfter", java.util.Map.of("n", String.valueOf(after)))).append("\n");
        r.put("before", before).put("after", after).put("removed", via);

        if (!via) {
            if (isProtected) log.append("--- riprotezione ---\n").append(sh("pkg lock -y " + name + " 2>&1", 60));
            // Il motivo lo dice pkg nella sua uscita: riportarlo invece di lasciare
            // l'utente a leggersi il log per capire perche'.
            String why = deleteOutput.contains("locked")
                    ? I18n.tr("server.um.removePackageNow.7")
                    : (deleteOutput.contains("vital") ? I18n.tr("server.um.x.markedVital") : "");
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.x.stillInstalled")
                            + why + (isProtected ? ". " + I18n.tr("server.um.x.reprotectedAsBefore") : "."));
        }

        // --- la verifica che conta: qualcuno e' rimasto senza una libreria? ---
        JSONObject lib = packagesWithMissingLibraries();
        JSONArray broken = lib.optJSONArray("packages");
        r.put("missingLibraries", lib);
        r.put("services", servicesJson());

        boolean fault = broken != null && broken.length() > 0;
        log.append("--- ").append(I18n.tr("server.um.x.check")).append(" ---\n")
           .append(fault ? I18n.tr("server.um.removePackageNow.1", java.util.Map.of("length", String.valueOf(broken.length())))
                          : I18n.tr("server.um.removePackageNow.2")).append("\n");
        return r.put("success", true).put("log", log.toString()).put("fault", fault)
                .put("note", fault
                        ? I18n.tr("server.um.removePackageNow.8", java.util.Map.of("name", String.valueOf(name), "name2", String.valueOf(name)))
                        : I18n.tr("server.um.removePackageNow.9"));
    }

    /**
     * Strumenti esterni da cui il pannello dipende, con la cartella in cui il port li mette.
     * Non e' un elenco decorativo: se uno di questi non si raggiunge, la funzione che lo usa
     * fallisce lontano da qui e con un messaggio che parla d'altro.
     */
    private static final String[][] TOOLS = {
        {"mysqldump",       "/usr/local/bin",  "server.um.removePackageNow.10"},
        {"mysql",           "/usr/local/bin",  "server.um.removePackageNow.11"},
        {"doveadm",         "/usr/local/bin",  "server.um.removePackageNow.12"},
        {"postmap",         "/usr/local/sbin", "server.um.removePackageNow.13"},
        {"postconf",        "/usr/local/sbin", "server.um.removePackageNow.14"},
        {"rspamadm",        "/usr/local/bin",  "server.um.removePackageNow.15"},
        {"fail2ban-client", "/usr/local/bin",  "server.um.tool.fail2ban"},
        {"nginx",           "/usr/local/sbin", "server.um.removePackageNow.16"},
        {"pkg",             "/usr/local/sbin", "server.um.removePackageNow.17"},
        {"openssl",         "/usr/bin",        "server.um.removePackageNow.18"},
        {"procstat",        "/usr/bin",        "server.um.removePackageNow.19"},
        {"bectl",           "/sbin",           "server.um.removePackageNow.20"},
    };

    /**
     * L'ambiente in cui il pannello esegue i comandi. Nasce da un guasto che ha impiegato
     * mezz'ora a essere capito: il preflight di Roundcube diceva "mysqldump non e' installato
     * o non e' nel PATH del pannello" mentre mysql84-client era regolarmente installato.
     * Le due cose che quel messaggio metteva insieme sono diversissime, e distinguerle e'
     * banale: si guarda se il file c'e' sul disco, e separatamente se il PATH lo raggiunge.
     */
    public static JSONObject panelBootEnvironment() {
        JSONObject r = new JSONObject().put("success", true)
                .put("inheritedPath", org.mail_panel.util.Shell.inheritedPath())
                .put("pathUsed", org.mail_panel.util.Shell.fullPath());
        JSONArray a = new JSONArray();
        int unreachable = 0, absent = 0;
        for (String[] t : TOOLS) {
            String resolved = sh("command -v " + t[0] + " 2>/dev/null", 15).trim();
            String expected = t[1] + "/" + t[0];
            boolean onDisk = ok("test -x " + expected, 15);
            String state;
            if (!resolved.isEmpty()) state = "reachable";
            else if (onDisk) { state = "NOT_IN_PATH"; unreachable++; }
            else { state = "not-installed"; absent++; }
            a.put(new JSONObject().put("command", t[0]).put("expectedIn", t[1]).put("purpose", t[2])
                    .put("resolved", resolved).put("onDisk", onDisk).put("state", state));
        }
        return r.put("tools", a).put("unreachable", unreachable).put("absent", absent)
                .put("explanation", unreachable > 0
                        ? I18n.tr("server.um.panelBootEnvironment.3", java.util.Map.of("unreachable", String.valueOf(unreachable)))
                        : (absent > 0
                           ? I18n.tr("server.um.panelBootEnvironment.4", java.util.Map.of("absent", String.valueOf(absent)))
                           : I18n.tr("server.um.panelBootEnvironment.5")));
    }

    /**
     * L'anteprima della configurazione che il pannello scriverebbe su un Dovecot 2.4.
     *
     * Serve a poterla leggere ORA, mentre il repository non ha ancora la 2.4 e non c'e'
     * nessuna fretta. Un template che si vede per la prima volta il giorno in cui il
     * pacchetto arriva e' un template che si legge di corsa.
     *
     * Non scrive niente: prende gli stessi file che scriverebbe lo script, sostituisce i
     * valori veri del database e nasconde la password.
     */
    public static JSONObject dovecot24Preview() {
        JSONObject r = new JSONObject().put("success", true);
        try {
            org.mail_panel.scripts.DovecotConfig c = org.mail_panel.scripts.DovecotConfig.fromPanelConfig();
            boolean pigeonhole = ok("pkg info -e dovecot-pigeonhole", 15)
                    || ok("pkg info -e dovecot-pigeonhole-mysql", 15)
                    || ok("pkg info -e dovecot-pigeonhole-pgsql", 15);
            JSONArray file = new JSONArray();
            for (var f : org.mail_panel.scripts.DovecotConfig.file24()) {
                String text = f.content()
                        .replace("${DB_USER}", c.getDbUser())
                        .replace("${DB_NAME}", c.getDbName())
                        .replace("${DB_PASS}", "«" + I18n.tr("server.um.x.dbPassHidden") + "»")
                        .replace("${SIEVE_PROTO}", pigeonhole ? " sieve" : "");
                file.put(new JSONObject().put("path", "/usr/local/etc/dovecot/" + f.path())
                        .put("content", text));
            }
            JSONArray ver = new JSONArray();
            for (String[] v : org.mail_panel.scripts.DovecotConfig.checks24())
                ver.put(new JSONObject().put("state", v[0]).put("setting", v[1]).put("note", v[2]));
            return r.put("file", file).put("checks", ver)
                    .put("dbName", c.getDbName()).put("dbUser", c.getDbUser())
                    .put("pigeonhole", pigeonhole)
                    .put("installedVersion", sh("pkg query -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 20))
                    .put("caveat", I18n.tr("server.um.dovecot24Preview.1"));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.dovecot24Preview.2", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Tutto cio' che un rapporto periodico deve poter dire, raccolto in una lettura sola.
     *
     * Sta qui e non nella classe che manda l'email per un motivo preciso: qui vivono gli
     * strumenti che interrogano il sistema, e duplicarli altrove significherebbe averne due
     * versioni che col tempo divergono. La classe del rapporto compone il testo, questa
     * raccoglie i fatti.
     *
     * La chiave "toDo" e' la ragione d'essere del rapporto: un elenco di cose da fare,
     * ordinate per urgenza, gia' scritte in italiano. Se e' vuoto, non c'e' niente da fare —
     * e anche quello va detto, altrimenti un'email che arriva ogni settimana diventa rumore
     * che si smette di leggere.
     */
    /**
     * Con updateDatabase = false non tocca la rete: e' la forma per l'anteprima.
     *
     * "pkg audit -F" scarica il database delle vulnerabilita'. L'anteprima lo chiamava, quindi
     * premere "guarda il rapporto" poteva restare appeso su una rete lenta mentre la scheda
     * prometteva una lettura. Chi guarda vede il numero e, accanto, quanto e' vecchio il
     * database: cosi' sa cosa sta guardando invece di crederlo aggiornato.
     */
    public static JSONObject reportData() { return reportData(true); }

    /**
     * Quanti pacchetti dello stack hanno una versione piu' recente nel catalogo, quanti di
     * quelli sono protetti — cioe' trattenuti dal blocco — e l'elenco da mostrare.
     *
     * Funzione pura: riceve le righe di {@link #packagesStatus()} e la mappa nome ->
     * versione del catalogo, cosi' si prova senza pkg. Le chiavi che legge sono quelle che
     * packagesStatus mette DAVVERO ("name", "version", "locked"), e la prova le verifica una
     * per una contro una riga vera: era proprio una chiave sbagliata a rendere muto questo
     * conto, e una chiave sbagliata non la vede ne' il compilatore ne' una prova scritta su
     * righe inventate.
     */
    static JSONObject countUpdates(JSONArray lines, Map<String, String> available) {
        int totals = 0, protectedNames = 0, withUpdate = 0, heldBack = 0;
        JSONArray toUpdate = new JSONArray();
        for (int i = 0; lines != null && i < lines.length(); i++) {
            JSONObject x = lines.getJSONObject(i);
            totals++;
            boolean isProtected = x.optBoolean("locked");
            if (isProtected) protectedNames++;
            String name = x.optString("name", "");
            String installed = x.optString("version", "");
            String catalog = available == null ? "" : available.getOrDefault(name, "");
            if (catalog.isEmpty() || catalog.equals(installed)) continue;
            withUpdate++;
            if (isProtected) heldBack++;
            if (toUpdate.length() < 25)
                toUpdate.put(name + " " + installed + " -> " + catalog
                        + (isProtected ? " " + I18n.tr("server.um.x.heldSuffix") : ""));
        }
        return new JSONObject().put("totals", totals).put("protectedNames", protectedNames)
                .put("withUpdate", withUpdate).put("heldBack", heldBack)
                .put("toUpdate", toUpdate);
    }

    public static JSONObject reportData(boolean updateDatabase) {
        JSONObject r = new JSONObject();
        JSONArray toDo = new JSONArray();

        // L'invio automatico aggiorna il catalogo, l'anteprima no.
        //
        // Tutte le interrogazioni al repository ora hanno "-U", cioe' NON scaricano il catalogo
        // da sole: e' giusto, perche' una lettura non deve andare in rete a sorpresa. Ma senza
        // qualcuno che lo aggiorni, la riga "N pacchetti hanno una versione piu' recente" viene
        // calcolata su un catalogo fermo a chissa' quando, e un rapporto che dice "niente da
        // aggiornare" perche' guarda dati vecchi e' peggio di un rapporto che non arriva.
        //
        // Quindi l'aggiornamento del catalogo sta QUI, esplicito, e solo nell'invio vero — dove
        // andare in rete e' previsto. L'anteprima resta una lettura, e la sua riga sull'eta' del
        // catalogo dice a chi guarda quanto sono vecchi i dati che sta vedendo.
        // L'esito si tiene: un "pkg update" fallito lascia il catalogo di prima, e il rapporto
        // deve poterlo dire invece di presentare quel catalogo come appena rinfrescato.
        boolean refreshedCatalog = updateDatabase && ok("pkg update -q", 120);
        r.put("refreshedCatalog", refreshedCatalog);

        // --- sistema ---
        JSONObject os = operatingSystem();
        r.put("system", os);
        String kernel = os.optString("installedKernel", ""), running = os.optString("runningKernel", "");
        if (!kernel.isEmpty() && !running.isEmpty() && !kernel.equals(running))
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.tr("mail.report.title.restart"))
                    .put("what", I18n.tr("server.um.reportData.1", java.util.Map.of("kernel", String.valueOf(kernel), "running", String.valueOf(running))))
                    .put("where", I18n.tr("server.um.reportData.2")));
        String end = os.optString("endOfSupport", "");
        long eolDays = daysToDate(end);
        r.put("daysToEndOfSupport", eolDays);
        if (eolDays >= 0 && eolDays < 120)
            toDo.put(new JSONObject().put("urgency", eolDays < 45 ? 1 : 3)
                    .put("title", I18n.tr("mail.report.title.endOfSupport"))
                    .put("what", I18n.tr("server.um.reportData.3", java.util.Map.of("eolDays", String.valueOf(eolDays), "end", String.valueOf(end))))
                    .put("where", I18n.tr("server.um.reportData.4")));

        // --- pacchetti ---
        //
        // Le versioni del catalogo si chiedono a pkg: nelle righe di packagesStatus non ci
        // sono, e la riga del rapporto le leggeva da due chiavi che quelle righe non hanno
        // mai avuto ("current" e "available"), quindi era SEMPRE zero. Misurato sulla VM il
        // 23/10/2026: "con aggiornamento: 0" mentre nello stesso istante packagesOverview,
        // che le versioni le chiede, ne contava 2 dello stack e 5 in tutto. Una riga che non
        // puo' dire nient'altro che zero e' peggio di una riga che manca: rassicura.
        JSONObject pk = packagesStatus();
        r.put("packages", pk);
        JSONObject count = countUpdates(pk.optJSONArray("packages"),
                PackagePlan.toUpdate(PackagePlan.readToUpdate().output()));
        int withUpdate = count.getInt("withUpdate");
        int heldBack = count.getInt("heldBack");
        JSONArray toUpdate = count.getJSONArray("toUpdate");
        r.put("totalPackages", count.getInt("totals")).put("lockedPackageCount", count.getInt("protectedNames"))
         .put("packagesWithUpdate", withUpdate).put("toUpdate", toUpdate)
         .put("heldBackPackages", heldBack);
        // Quelli che il blocco trattiene hanno la loro voce qui sotto, con il posto giusto dove
        // applicarli: contarli anche qui faceva dire due volte la stessa cosa ("aggiorna 1
        // pacchetto" e "applica 1 aggiornamento trattenuto", per lo stesso openjdk25 sulla VM il
        // 06/11/2026), con due indicazioni diverse su dove farlo.
        int freeUpdates = withUpdate - heldBack;
        if (freeUpdates > 0)
            toDo.put(new JSONObject().put("urgency", 2)
                    .put("title", I18n.trn("mail.report.title.updates", freeUpdates, java.util.Map.of()))
                    .put("what", freeUpdates == 1
                            ? I18n.tr("server.um.x.newerInRepo.one")
                            : I18n.tr("server.um.x.newerInRepo.other", java.util.Map.of("n", String.valueOf(freeUpdates))))
                    .put("where", I18n.tr("server.um.reportData.5")));
        // Un aggiornamento che esiste e che il blocco trattiene e' una notizia diversa da un
        // aggiornamento disponibile: `pkg upgrade`, da qui o da SSH, lo salta ed esce 0.
        // Misurato sulla VM il 23/10/2026: con nginx e postfix-mysql bloccati, `pkg upgrade -n`
        // li nomina in una riga di passaggio, non li mette nel riepilogo e termina con uscita
        // ZERO. Chi legge solo il codice di uscita conclude che non c'era niente da fare.
        if (heldBack > 0)
            toDo.put(new JSONObject().put("urgency", 2)
                    .put("title", I18n.trn("mail.report.title.held", heldBack, java.util.Map.of()))
                    .put("what", heldBack == 1
                            ? I18n.tr("server.um.x.heldByLock.one")
                            : I18n.tr("server.um.x.heldByLock.other", java.util.Map.of("n", String.valueOf(heldBack))))
                    .put("where", I18n.tr("server.um.reportData.8")));

        // --- vulnerabilita', separando quelle a cui si puo' rimediare ---
        //
        // Niente "tail": c'era, ed era una perdita silenziosa. Ogni blocco di pkg audit occupa
        // quattro o cinque righe, quindi oltre le ~8 vulnerabilita' le prime uscivano dalla
        // finestra e sparivano da ENTRAMBE le liste — quella con rimedio e quella senza. Il
        // rapporto risultava piu' tranquillo di com'era il server, e niente lo segnalava.
        //
        // "-F" scarica il database delle vulnerabilita' dalla rete, quindi lo fa solo l'invio
        // vero: l'anteprima promette una lettura e deve restare una lettura.
        String audit = sh("pkg audit" + (updateDatabase ? " -F" : "") + " 2>&1", 180);
        r.put("audit", audit);
        r.put("vulnDbDays", daysSince("/var/db/pkg/vuln.xml"));
        r.put("vulnDbUpdatedNow", updateDatabase);
        // Con "-U" le interrogazioni al repository leggono il catalogo che c'e': la sua eta'
        // fa parte del risultato, altrimenti "nel repository c'e' la versione X" suona come
        // una verifica appena fatta sui server di pkg, che non e'.
        //
        // La data la da' PkgCatalog, ed e' quella di pubblicazione sul server. Prima qui si
        // guardava /var/db/pkg/repo-FreeBSD.sqlite, che su FreeBSD 15 non esiste: ogni
        // rapporto diceva "eta' sconosciuta".
        JSONObject cat = PkgCatalog.read();
        long catalogDays = cat.optLong("days", -1);
        r.put("catalog", cat).put("catalogDays", catalogDays).put("catalogDate", cat.optString("data"));
        if (updateDatabase && !refreshedCatalog)
            toDo.put(new JSONObject().put("urgency", 2)
                    .put("title", I18n.tr("mail.report.title.catalogNotRefreshed"))
                    .put("what", catalogDays < 0
                            ? I18n.tr("server.um.x.pkgUpdateFailed")
                            : I18n.tr("server.um.x.pkgUpdateFailedDated", java.util.Map.of("howMuch", String.valueOf(PkgCatalog.howMuch(catalogDays)), "data", String.valueOf(cat.optString("data")))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));
        else if (catalogDays < 0)
            toDo.put(new JSONObject().put("urgency", 3)
                    .put("title", I18n.tr("mail.report.title.catalogUnknown"))
                    .put("what", cat.optString("note") + " " + I18n.tr("server.um.x.noCatalogDate"))
                    .put("where", I18n.tr("server.um.x.updatesPage")));
        else if (catalogDays >= 7 && !refreshedCatalog)
            // Dopo un "pkg update" riuscito, un catalogo vecchio e' l'ultimo che il server offre:
            // non c'e' niente da fare. Senza (l'anteprima), puo' esserci un catalogo piu' nuovo.
            toDo.put(new JSONObject().put("urgency", catalogDays >= 28 ? 2 : 3)
                    .put("title", I18n.tr("mail.report.title.catalogOld"))
                    .put("what", I18n.tr("server.um.x.catalogOld", java.util.Map.of("howMuch", String.valueOf(PkgCatalog.howMuch(catalogDays)), "data", String.valueOf(cat.optString("data")))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));

        JSONArray withRemedy = new JSONArray(), withoutRemedy = new JSONArray();
        JSONArray notUnderstood = new JSONArray();
        int found = 0;
        // "C'e' il rimedio" senza dire che il pacchetto e' protetto e' una falsa
        // rassicurazione: il rimedio esiste nel catalogo e nessun `pkg upgrade` lo applichera'
        // mai, perche' il blocco lo salta. Sulla VM, il 23/10/2026, era proprio il caso di
        // nginx: catalogo 1.30.6,3, cioe' la versione da cui VuXML considera corretto il
        // problema, e il pacchetto bloccato dal pannello.
        Set<String> lockedNow = lockedNames();
        for (String line : audit.split("\n")) {
            Matcher m = Pattern.compile("^([A-Za-z0-9._+-]+)-([0-9][^\\s]*) is vulnerable").matcher(line.trim());
            if (!m.find()) continue;
            found++;
            String name = m.group(1), installed = m.group(2);
            if (!isValidName(name)) {
                // Un nome che il filtro non accetta non deve sparire: sparendo non finirebbe
                // ne' fra quelli con rimedio ne' fra quelli senza, e il conto tornerebbe lo
                // stesso. Oggi i nomi di pkg stanno tutti dentro il filtro e questo ramo non
                // scatta mai — ma un elemento che il programma non capisce si conta e si dice.
                notUnderstood.put(line.trim());
                continue;
            }
            String inRepo = sh("pkg rquery -U %v " + name + " 2>/dev/null", 30).trim();
            if (!inRepo.isEmpty() && !inRepo.equals(installed))
                withRemedy.put(name + ": " + installed + " -> " + inRepo
                        + (lockedNow.contains(name) ? " " + I18n.tr("server.um.x.heldSuffixFix") : ""));
            else
                withoutRemedy.put(name + " " + installed);
        }

        // Il controllo incrociato che pkg audit regala: in fondo stampa "N problem(s) in M
        // package(s) found.". Se cio' che abbiamo letto non combacia con quei totali, il
        // risultato non si mostra come se fosse completo — si dice che non torna. Un elenco
        // parziale spacciato per intero e' peggio di nessun elenco.
        Matcher tot = Pattern.compile("(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found")
                .matcher(audit);
        if (tot.find()) {
            int declaredPackages = Integer.parseInt(tot.group(2));
            r.put("vulnDeclaredPackages", declaredPackages);
            if (declaredPackages != found)
                r.put("vulnCountMismatch", I18n.tr("server.um.reportData.6", java.util.Map.of("declaredPackages", String.valueOf(declaredPackages), "foundCount", String.valueOf(found))));
        } else {
            r.put("vulnCountMismatch", I18n.tr("server.um.reportData.7"));
        }
        if (notUnderstood.length() > 0) r.put("vulnNotUnderstood", notUnderstood);

        r.put("vulnWithRemedy", withRemedy).put("vulnWithoutRemedy", withoutRemedy);
        if (withRemedy.length() > 0)
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.trn("mail.report.title.securityFixes", withRemedy.length(), java.util.Map.of()))
                    .put("what", withRemedy.length() == 1
                            ? I18n.tr("server.um.x.vulnFix.one", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(withRemedy)))))
                            : I18n.tr("server.um.x.vulnFix.other", java.util.Map.of("n", String.valueOf(withRemedy.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(withRemedy))))))
                    .put("where", I18n.tr("server.um.reportData.8")));

        // --- librerie mancanti ---
        JSONArray broken = packagesWithMissingLibraries().optJSONArray("packages");
        r.put("missingLibraries", broken == null ? new JSONArray() : broken);
        if (broken != null && broken.length() > 0)
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.tr("mail.report.title.missingLibraries"))
                    .put("what", I18n.tr("server.um.reportData.9", java.util.Map.of("length", String.valueOf(broken.length()))))
                    .put("where", I18n.tr("server.um.reportData.10")));

        // --- servizi ---
        JSONArray services = servicesJson();
        r.put("services", services);
        JSONArray down = new JSONArray();
        for (int i = 0; i < services.length(); i++)
            if (!services.getJSONObject(i).getBoolean("active")) down.put(services.getJSONObject(i).getString("name"));
        r.put("inactiveServices", down);
        if (down.length() > 0)
            toDo.put(new JSONObject().put("urgency", 0)
                    .put("title", I18n.tr("mail.report.title.servicesDown", java.util.Map.of("list", String.join(", ", jsonArrayToList(down)))))
                    .put("what", I18n.tr("server.um.x.svcDown", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(down))))))
                    .put("where", I18n.tr("server.um.reportData.11")));

        // --- un lavoro sui pacchetti interrotto, e i pacchetti dello stack rimasti senza protezione ---
        //
        // Il rapporto e' l'unico canale che raggiunge chi non apre il pannello. Misurato sulla VM
        // il 06/11/2026 (reperto 147): con un pacchetto dello stack sbloccato e l'elenco di un
        // lavoro interrotto su disco, le cose da fare non ne parlavano.
        List<String> stillUnprotected = PackageRecovery.statePackages();
        if (PackageQueue.statePresent())
            toDo.put(new JSONObject().put("urgency", 0)
                    .put("title", I18n.tr("server.recovery.unprotectedTitle"))
                    .put("what", I18n.tr("server.recovery.unprotected", java.util.Map.of(
                            "n", String.valueOf(stillUnprotected.size()),
                            "list", String.join(" ", stillUnprotected))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));
        JSONObject interrupted = PackageRecovery.notice();
        if (!interrupted.isEmpty())
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.tr("server.recovery.title"))
                    .put("what", PackageRecovery.text(interrupted))
                    .put("where", I18n.tr("server.um.x.updatesPage")));
        Set<String> byHand = unlockedByHand();
        List<String> loose = new ArrayList<>();
        JSONArray stack = pk.optJSONArray("packages");
        for (int i = 0; stack != null && i < stack.length(); i++) {
            JSONObject x = stack.getJSONObject(i);
            String n = x.optString("name");
            if (!x.optBoolean("locked") && !byHand.contains(n) && !stillUnprotected.contains(n)) loose.add(n);
        }
        if (!loose.isEmpty())
            toDo.put(new JSONObject().put("urgency", 1)
                    .put("title", I18n.tr("server.recovery.looseTitle"))
                    .put("what", I18n.tr("server.recovery.loose", java.util.Map.of(
                            "n", String.valueOf(loose.size()), "list", String.join(" ", loose))))
                    .put("where", I18n.tr("server.um.x.updatesPage")));

        // --- spazio ---
        String df = sh("df -h / 2>/dev/null | tail -1", 30);
        r.put("space", df);
        Matcher mp = Pattern.compile("([0-9]+)%").matcher(df);
        if (mp.find()) {
            int used = Integer.parseInt(mp.group(1));
            r.put("usedPercent", used);
            if (used >= 85)
                toDo.put(new JSONObject().put("urgency", used >= 92 ? 0 : 2)
                        .put("title", I18n.tr("mail.report.title.disk", java.util.Map.of("used", String.valueOf(used))))
                        .put("what", I18n.tr("server.um.reportData.12", java.util.Map.of("used", String.valueOf(used))))
                        .put("where", I18n.tr("server.um.reportData.13")));
        }

        // --- ambienti di avvio ---
        JSONObject be = bootEnvironments();
        r.put("environments", be);

        r.put("branch", branchRepositories());
        r.put("toDo", sortByUrgency(toDo));
        return r;
    }

    /** Giorni da oggi a una data scritta come gg/mm/aaaa; -1 se non leggibile. */
    private static long daysToDate(String dd_mm_yyyy) {
        Matcher m = Pattern.compile("([0-9]{2})/([0-9]{2})/([0-9]{4})").matcher(dd_mm_yyyy == null ? "" : dd_mm_yyyy);
        if (!m.find()) return -1;
        try {
            java.time.LocalDate d = java.time.LocalDate.of(Integer.parseInt(m.group(3)),
                    Integer.parseInt(m.group(2)), Integer.parseInt(m.group(1)));
            return java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.now(), d);
        } catch (Exception e) { return -1; }
    }

    /** Le cose da fare, dalla piu' urgente. 0 = un servizio e' giu', 3 = da pianificare. */
    private static JSONArray sortByUrgency(JSONArray a) {
        java.util.List<JSONObject> l = new ArrayList<>();
        for (int i = 0; i < a.length(); i++) l.add(a.getJSONObject(i));
        l.sort(java.util.Comparator.comparingInt(x -> x.optInt("urgency", 9)));
        JSONArray out = new JSONArray();
        for (JSONObject x : l) out.put(x);
        return out;
    }

    /** servicesState() in forma di elenco JSON, per le schede che lo mostrano. */
    private static JSONArray servicesJson() {
        JSONArray a = new JSONArray();
        for (var e : servicesState().entrySet())
            a.put(new JSONObject().put("name", e.getKey()).put("active", e.getValue()));
        return a;
    }

    private static int countLines(String s) {
        int n = 0;
        for (String l : s.split("\n")) if (!l.isBlank()) n++;
        return n;
    }

    /** Legge l'uscita di "sort | uniq -c": conteggio, spazio, valore. */
    private static void countIn(String output, java.util.Map<String, Integer> where) {
        for (String line : output.split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            try { where.put(t.substring(sp + 1).trim(), Integer.parseInt(t.substring(0, sp))); }
            catch (NumberFormatException ignored) { }
        }
    }

    public static JSONObject panelUsage(String pkgName) {
        JSONObject r = new JSONObject().put("success", true).put("pkgName", pkgName);
        if (!isValidName(pkgName))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        if (!ok("pkg info -e " + pkgName, 20))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.panelUsage.1", java.util.Map.of("pkg", String.valueOf(pkgName))));

        // --- 1. quali eseguibili installa il pacchetto ---
        String list = sh("pkg query '%Fp' " + pkgName + " 2>/dev/null", 60);
        String asListed = "pkg query %Fp";
        if (list.isBlank()) {   // formato non disponibile: si ripiega su pkg info -l
            list = sh("pkg info -l " + pkgName + " 2>/dev/null", 60);
            asListed = "pkg info -l";
        }
        java.util.LinkedHashMap<String, String> runnables = new java.util.LinkedHashMap<>();
        for (String line : list.split("\n")) {
            String f = line.trim();
            if (!f.startsWith("/")) continue;
            if (!f.matches("(/usr)?(/local)?/(s?bin|libexec)(/[A-Za-z0-9._+-]{1,64}){1,2}")) continue;
            String name = f.substring(f.lastIndexOf('/') + 1);
            runnables.putIfAbsent(name, f);
        }
        r.put("asListed", asListed).put("runnablesFound", runnables.size());

        // --- 2. le classi del pannello, dal jar in esecuzione ---
        String jar = jarPath();
        r.put("jar", jar == null ? "" : jar);
        long bytesRead = 0;
        String extract = null;
        if (jar != null && !jar.isBlank() && ok("test -r " + jar, 15)) {
            // bsdtar (libarchive) e' nel sistema base e legge gli archivi zip, quindi anche i jar.
            extract = "tar -xOf " + jar + " 'org/mail_panel/*' 2>/dev/null";
            String n = sh(extract + " | wc -c", 120).trim().replaceAll("[^0-9]", "");
            if (!n.isEmpty()) bytesRead = Long.parseLong(n);
            if (bytesRead == 0 && ok("command -v unzip >/dev/null 2>&1", 15)) {
                extract = "unzip -p " + jar + " 'org/mail_panel/*' 2>/dev/null";
                n = sh(extract + " | wc -c", 120).trim().replaceAll("[^0-9]", "");
                if (!n.isEmpty()) bytesRead = Long.parseLong(n);
            }
        }
        boolean readSucceeded = bytesRead > 0;
        r.put("bytesRead", bytesRead).put("readSucceeded", readSucceeded);

        // --- 3. una sola passata: quali di quei nomi compaiono nelle classi ---
        // Due conteggi, non uno. La ricerca per SOTTOSTRINGA e' inservibile: "gif" compare 127
        // volte nelle classi del pannello, ma dentro JSON.stringify e writeNewsyslogIfMissing,
        // mai come comando. Con la ricerca per PAROLA INTERA scende a zero, che e' la verita'.
        // Il secondo conteggio e' piu' stretto ancora: il nome seguito da uno spazio, cioe' un
        // comando con argomenti. Serve a distinguere "openssl x509 -in ..." dal nome che compare
        // per caso. Il giudizio si basa sulla parola intera; l'altro numero e' li' per farsi
        // un'idea, perche' un nome come "test" resta ambiguo per natura.
        java.util.Map<String, Integer> counts = new java.util.HashMap<>();
        java.util.Map<String, Integer> withArguments = new java.util.HashMap<>();
        java.util.List<String> tooShort = new ArrayList<>();
        if (readSucceeded && !runnables.isEmpty()) {
            StringBuilder whole = new StringBuilder(), withSpace = new StringBuilder();
            for (String name : runnables.keySet()) {
                if (name.length() < 4) { tooShort.add(name); continue; }
                whole.append(" -e '").append(name).append("'");
                withSpace.append(" -e '").append(name).append(" '");
            }
            if (whole.length() > 0) {
                countIn(sh(extract + " | grep -aowF" + whole + " | sort | uniq -c", 180), counts);
                countIn(sh(extract + " | grep -aoF" + withSpace + " | sort | uniq -c", 180), withArguments);
            }
        }

        // --- 4. per ogni comando usato: esiste un'altra copia che resterebbe? ---
        JSONArray used = new JSONArray();
        for (var e : runnables.entrySet()) {
            Integer c = counts.get(e.getKey());
            if (c == null || c == 0) continue;
            String elsewhere = "";
            for (String d : new String[]{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}) {
                String cand = d + "/" + e.getKey();
                if (cand.equals(e.getValue())) continue;
                if (ok("test -x " + cand, 15)) { elsewhere = cand; break; }
            }
            // Non basta sapere che una seconda copia esiste: bisogna sapere QUALE delle due
            // gira adesso. Se il PATH gia' sceglie l'altra, togliere il pacchetto non cambia
            // nulla — dire "diventerebbe un altro binario" sarebbe falso, e contraddirebbe il
            // riquadro qui sopra che ha appena misurato chi vince nel PATH.
            String inUseNow = sh("command -v " + e.getKey() + " 2>/dev/null", 15).trim();
            boolean isItsOwn = inUseNow.equals(e.getValue());
            used.put(new JSONObject().put("command", e.getKey()).put("path", e.getValue())
                    .put("occurrences", c)
                    .put("withArguments", withArguments.getOrDefault(e.getKey(), 0))
                    .put("otherCopy", elsewhere)
                    .put("inUseNow", inUseNow).put("isItsOwn", isItsOwn)
                    .put("wouldStay", !elsewhere.isEmpty())
                    .put("effect", isItsOwn
                            ? (elsewhere.isEmpty()
                               ? I18n.tr("server.um.panelUsage.2")
                               : I18n.tr("server.um.panelUsage.3", java.util.Map.of("elsewhere", String.valueOf(elsewhere))))
                            : (inUseNow.isEmpty()
                               ? I18n.tr("server.um.panelUsage.4")
                               : I18n.tr("server.um.panelUsage.5", java.util.Map.of("inUseNow", String.valueOf(inUseNow))))));
        }
        // Un pacchetto puo' non avere nessun comando e servire lo stesso, perche' e' una
        // LIBRERIA: nessuno la digita, ma qualcuno ci si collega. giflib e' esattamente
        // questo. Dirlo qui evita che "non ne uso i comandi" venga letto come "si puo'
        // togliere": per una libreria la domanda giusta e' un'altra, ed e' quella che
        // pone la scheda dei pacchetti senza la libreria che richiedono.
        JSONArray libraries = new JSONArray();
        for (String l : sh("pkg query %b " + pkgName + " 2>/dev/null", 30).split("\n"))
            if (l.trim().matches("[A-Za-z0-9._+-]{1,128}")) libraries.put(l.trim());
        r.put("providesLibraries", libraries);
        r.put("commandsUsed", used).put("namesTooShort", new JSONArray(tooShort));

        String verdict, explanation;
        if (!readSucceeded) {
            verdict = "UNDETERMINED";
            explanation = I18n.tr("server.um.x.jarUnreadable", java.util.Map.of("jar", String.valueOf(jar == null || jar.isBlank() ? I18n.tr("server.um.x.jarUnknown") : jar)));
        } else if (used.length() == 0) {
            verdict = libraries.length() > 0 ? "LIBRARY_ONLY"
                                             : "PANEL_DOES_NOT_USE";
            explanation = I18n.tr("server.um.x.jarNoUse", java.util.Map.of("byte", String.valueOf(bytesRead), "n", String.valueOf(runnables.size()), "pkg", String.valueOf(pkgName)))
                    + (libraries.length() > 0
                       ? " " + I18n.tr("server.um.x.jarLibs", java.util.Map.of("n", String.valueOf(libraries.length()), "list", String.valueOf(String.join(", ", jsonArrayToList(libraries)))))
                       : "")
                    + (tooShort.isEmpty() ? ""
                       : " " + I18n.tr("server.um.x.jarShortNames", java.util.Map.of("n", String.valueOf(tooShort.size()), "list", String.valueOf(String.join(", ", tooShort)))));
        } else {
            int withoutReplacement = 0, reallyItsOwn = 0;
            for (int i = 0; i < used.length(); i++) {
                JSONObject u = used.getJSONObject(i);
                if (u.getBoolean("isItsOwn")) {
                    reallyItsOwn++;
                    if (!u.getBoolean("wouldStay")) withoutReplacement++;
                }
            }
            if (reallyItsOwn == 0) {
                // Li nomina, ma non e' questo pacchetto a fornire i binari che girano.
                verdict = "NAMES_NOT_THEIRS";
                explanation = used.length() == 1
                        ? I18n.tr("server.um.x.namesOther.one", java.util.Map.of("pkg", String.valueOf(pkgName)))
                        : I18n.tr("server.um.x.namesOther.other", java.util.Map.of("n", String.valueOf(used.length()), "pkg", String.valueOf(pkgName)));
                return r.put("verdict", verdict).put("explanation", explanation)
                        .put("why", I18n.tr("server.um.panelUsage.10"));
            }
            verdict = withoutReplacement > 0 ? "USES_NO_SPARE" : "USES";
            explanation = (used.length() == 1
                    ? I18n.tr("server.um.x.usesCmds.one")
                    : I18n.tr("server.um.x.usesCmds.other", java.util.Map.of("n", String.valueOf(used.length()))))
                    + " " + (withoutReplacement > 0
                       ? (withoutReplacement == 1
                          ? I18n.tr("server.um.x.noSpare.one")
                          : I18n.tr("server.um.x.noSpare.other", java.util.Map.of("n", String.valueOf(withoutReplacement))))
                       : I18n.tr("server.um.x.allSpare"));
        }
        return r.put("verdict", verdict).put("explanation", explanation)
                .put("why", I18n.tr("server.um.panelUsage.10"));
    }

    /**
     * L'analisi dell'uscita dello scan, staccata dal comando che la produce: cosi' si puo'
     * provare senza FreeBSD, che e' l'unico modo di sapere che legge davvero cio' che crede.
     * Una riga e' "pid TAB comando TAB percorso [percorso ...]". Il percorso in /usr/local
     * e' il port; quello in /usr/lib e' il sistema base.
     */
    static JSONArray analyzeMappings(String scan) {
        JSONArray processes = new JSONArray();
        if (scan == null) return processes;
        for (String line : scan.split("\n")) {
            String[] c = line.split("\t");
            if (c.length < 3 || c[0].trim().isEmpty()) continue;
            JSONArray libs = new JSONArray();
            boolean port = false;
            for (String v : c[2].trim().split("\\s+")) {
                if (v.isEmpty()) continue;
                libs.put(v);
                if (v.startsWith("/usr/local/")) port = true;
            }
            processes.put(new JSONObject().put("pid", c[0].trim())
                    .put("command", c[1].trim()).put("libraries", libs).put("usesThePort", port));
        }
        return processes;
    }

    public static JSONObject opensslUsage() {
        JSONObject r = new JSONObject().put("success", true);
        if (!ok("pkg info -e openssl", 20)) {
            return r.put("installed", false).put("verdict", "absent")
                    .put("explanation", I18n.tr("server.um.opensslUsage.1"));
        }
        r.put("installed", true).put("version", sh("pkg query %v openssl", 20));

        // --- 1. chi lo dichiara nel registro ---
        JSONArray declare = new JSONArray();
        for (String s : sh("pkg query %rn openssl 2>/dev/null", 30).split("\n"))
            if (isValidName(s.trim())) declare.put(s.trim());
        r.put("declare", declare);

        // --- 2. i soname delle due copie, e se si sovrappongono ---
        java.util.LinkedHashSet<String> sonPort = new java.util.LinkedHashSet<>();
        for (String s : sh("pkg query %b openssl 2>/dev/null", 30).split("\n")) {
            String t = s.trim();
            if (t.matches("lib(ssl|crypto)\\.so(\\.[0-9]+)*")) sonPort.add(t);
        }
        java.util.LinkedHashSet<String> sonBase = new java.util.LinkedHashSet<>();
        for (String s : sh("ls /usr/lib/libssl.so.* /usr/lib/libcrypto.so.* 2>/dev/null", 20).split("\n")) {
            String t = s.trim();
            int sl = t.lastIndexOf('/');
            if (sl >= 0 && sl + 1 < t.length()) sonBase.add(t.substring(sl + 1));
        }
        java.util.LinkedHashSet<String> common = new java.util.LinkedHashSet<>(sonPort);
        common.retainAll(sonBase);
        r.put("portSoname", new JSONArray(new ArrayList<>(sonPort)))
         .put("baseSoname", new JSONArray(new ArrayList<>(sonBase)))
         .put("sharedSoname", new JSONArray(new ArrayList<>(common)))
         .put("ambiguous", !common.isEmpty());

        // --- 2b. chi richiede quei soname (vale solo se NON sono in comune col base) ---
        JSONArray require = new JSONArray();
        if (!sonPort.isEmpty()) {
            for (String line : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
                String t = line.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                String name = t.substring(0, sp).trim(), lib = t.substring(sp + 1).trim();
                if (isValidName(name) && sonPort.contains(lib))
                    require.put(new JSONObject().put("pkgName", name).put("library", lib));
            }
        }
        r.put("requireTheSoname", require);

        // --- 3. la misura che decide: cosa e' mappato ADESSO dai processi vivi ---
        JSONArray processes = new JSONArray();
        JSONArray useThePort = new JSONArray();
        boolean hasProcstat = ok("command -v procstat >/dev/null 2>&1", 15);
        int withLibssl = 0;
        if (hasProcstat) {
            String scan = sh("for p in $(ps -axo pid=); do "
                    + "m=$(procstat -v $p 2>/dev/null | awk '/lib(ssl|crypto)\\.so/ {print $NF}' | sort -u | tr '\\n' ' '); "
                    + "[ -n \"$m\" ] && printf '%s\\t%s\\t%s\\n' \"$p\" \"$(ps -o comm= -p $p 2>/dev/null)\" \"$m\"; "
                    + "done", 240);
            processes = analyzeMappings(scan);
            withLibssl = processes.length();
            for (int i = 0; i < processes.length(); i++)
                if (processes.getJSONObject(i).getBoolean("usesThePort")) useThePort.put(processes.getJSONObject(i));
        }
        boolean reliableMeasure = hasProcstat && withLibssl > 0;

        // --- 4. il comando, non solo le librerie. procstat vede i processi VIVI: un
        // "openssl x509" dura millisecondi e non si fa quasi mai cogliere. Ma il pannello
        // lo invoca eccome (AcmeManager legge i certificati cosi', e gli script di
        // installazione generano password e chiavi con "openssl rand"), e lo invoca SENZA
        // percorso assoluto. Nel PATH di FreeBSD /usr/local/bin viene prima di /usr/bin,
        // quindi con il port installato e' il suo binario a vincere. Ignorarlo vorrebbe
        // dire dire "non lo usa nessuno" di un programma che gira ogni volta che il
        // pannello guarda un certificato.
        JSONArray binaries = new JSONArray();
        for (String path : new String[]{"/usr/local/bin/openssl", "/usr/bin/openssl"}) {
            if (!ok("test -x " + path, 15)) continue;
            binaries.put(new JSONObject().put("path", path)
                    .put("version", sh(path + " version 2>&1 | head -1", 20))
                    .put("pkgName", sh("pkg which -q " + path + " 2>/dev/null", 20))
                    .put("fromPort", path.startsWith("/usr/local/")));
        }
        String winner = sh("command -v openssl 2>/dev/null", 15).trim();
        boolean portCommand = winner.startsWith("/usr/local/");
        boolean baseHasCommand = ok("test -x /usr/bin/openssl", 15);
        r.put("binaries", binaries).put("commandInPath", winner)
         .put("portCommand", portCommand).put("baseHasCommand", baseHasCommand)
         .put("explicit", "0".equals(sh("pkg query %a openssl 2>/dev/null", 20).trim()))
         .put("whoInvokesIt", I18n.tr("server.um.opensslUsage.2"));

        r.put("processes", processes).put("useThePort", useThePort)
         .put("processesWithTls", withLibssl).put("reliableMeasure", reliableMeasure)
         .put("howMeasured", hasProcstat
                 ? I18n.tr("server.um.opensslUsage.3", java.util.Map.of("withLibssl", String.valueOf(withLibssl)))
                 : I18n.tr("server.um.opensslUsage.4"));

        // --- il verdetto, nell'ordine in cui le prove pesano ---
        String verdict, explanation;
        if (useThePort.length() > 0) {
            verdict = "IN_USE_NOW";
            explanation = useThePort.length() == 1
                    ? I18n.tr("server.um.x.portLibOpen.one")
                    : I18n.tr("server.um.x.portLibOpen.other", java.util.Map.of("n", String.valueOf(useThePort.length())));
        } else if (declare.length() > 0) {
            verdict = "REQUIRED";
            explanation = I18n.tr("server.um.x.declaredBy", java.util.Map.of("list", String.valueOf(String.join(", ", jsonArrayToList(declare)))));
        } else if (portCommand) {
            verdict = "COMMAND_IS_ITS";
            explanation = I18n.tr("server.um.x.cmdIsPort", java.util.Map.of("winner", String.valueOf(winner))) + " "
                    + (baseHasCommand
                       ? I18n.tr("server.um.x.baseHasCmd")
                       : I18n.tr("server.um.x.baseNoCmd"));
        } else if (!reliableMeasure) {
            verdict = "UNDETERMINED";
            explanation = I18n.tr("server.um.opensslUsage.7");
        } else {
            verdict = "NOBODY_USES";
            explanation = I18n.tr("server.um.opensslUsage.9", java.util.Map.of("withLibssl", String.valueOf(withLibssl)));
        }
        r.put("verdict", verdict).put("explanation", explanation);

        r.put("note", I18n.tr("server.um.opensslUsage.10"));
        r.put("whyItIsHere", I18n.tr("server.um.opensslUsage.11"));
        r.put("panel", panelUsage("openssl"));
        // Questo testo diceva di digitare "pkg unlock" e "pkg delete" da riga di comando.
        // Da quando la rimozione e' un pulsante, dettare i comandi e' peggio che inutile:
        // il pulsante rifa' i controlli e verifica dopo, una mano no.
        r.put("howToRemove", I18n.tr("server.um.opensslUsage.12"));
        return r;
    }

    /**
     * Chi dichiara cosa, sui client MySQL. Serve a rispondere con i fatti a una domanda che
     * altrimenti si risponde a intuito: perche' e' stato installato un client 9.7 quando il
     * predefinito dei port FreeBSD (Mk/bsd.default-versions.mk, rami main e 2026Q3) e' 8.4?
     *
     * Si guardano tre cose distinte, che e' facile confondere in una sola:
     *  - cosa dichiara il pacchetto INSTALLATO
     *  - cosa dichiara la versione nel REPOSITORY
     *  - quali pacchetti forniscono davvero la libreria contesa
     */
    public static JSONObject mysqlClientDiagnostics() {
        JSONObject r = new JSONObject();
        JSONArray client = new JSONArray();
        for (String line : sh("pkg query '%n %v' 2>/dev/null | grep -E '^mysql[0-9]+-(client|server) '", 30).split("\n")) {
            String t = line.trim();
            int sp = t.indexOf(' ');
            if (sp > 0) client.put(new JSONObject().put("name", t.substring(0, sp)).put("version", t.substring(sp + 1).trim()));
        }
        r.put("mysqlPackages", client);

        JSONArray dependents = new JSONArray();
        for (String pk : new String[]{"postfix-mysql", "dovecot-mysql"}) {
            if (!ok("pkg info -e " + pk, 20)) continue;
            dependents.put(new JSONObject().put("name", pk)
                    .put("version", sh("pkg query %v " + pk, 20))
                    .put("installedDependencies", sh("pkg query %dn " + pk + " 2>/dev/null | tr '\n' ' '", 30))
                    .put("repositoryDependencies", sh("pkg rquery -U %dn " + pk + " 2>/dev/null | tr '\n' ' '", 30))
                    .put("requiredLibraries", sh("pkg query %B " + pk + " 2>/dev/null | tr '\n' ' '", 30)));
        }
        r.put("dependents", dependents);

        // Chi fornisce la libreria contesa, e da quale pacchetto proviene il file sul disco.
        r.put("provideLib", sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20));
        r.put("fileLib", sh("ls -l /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20));
        // File che i due pacchetti si contendono: quanti ne ha persi la 8.4.
        r.put("hasConflicts", sh("pkg check -s mysql84-client 2>&1 | head -20", 180));
        return r.put("success", true);
    }

    /**
     * I predefiniti dei port FreeBSD, letti dalla fonte ufficiale.
     *
     * Colonne: componente, valore predefinito, come si rileva cio' che e' installato,
     * cosa comporta discostarsene.
     *
     * FONTE: Mk/bsd.default-versions.mk del repository ufficiale dei port
     * (cgit.freebsd.org), rami main e 2026Q3 — coincidono. Verificato il 31/08/2026.
     *
     * E' una fotografia datata, non una lettura dal vivo: il pannello non va su internet.
     * Va riverificata quando cambia il trimestre, e la scheda lo dice invece di far credere
     * che sia sempre aggiornata. Serve a rispondere alla domanda che oggi ci e' mancata —
     * "cio' che ho installato e' quello che il sistema si aspetta?" — prima di una
     * migrazione, non dopo.
     */
    private static final String[][] DEFAULTS = {
        {"MySQL", "8.4",
         "pkg query %n | grep -E '^mysql[0-9]+-server$'",
         "server.um.mysqlClientDiagnostics.1"},
        {"PHP", "8.4",
         "pkg query %n | grep -E '^php[0-9]+$'",
         "server.um.mysqlClientDiagnostics.2"},
        {"Python", "3.12",
         "pkg query %n | grep -E '^py[0-9]+-' | sed 's/-.*//' | sort -u | tr '\n' ' '",
         "server.um.mysqlClientDiagnostics.3"},
        {"OpenSSL", "base",
         "pkg query %n | grep -E '^openssl[0-9]*$' | tr '\n' ' '",
         "server.um.mysqlClientDiagnostics.4"},
        {"Perl", "5.42",
         "pkg query %v perl5 2>/dev/null",
         "server.um.mysqlClientDiagnostics.5"},
        {"Java", "25",
         "pkg query %n | grep -E '^openjdk[0-9]+$' | tr '\n' ' '",
         "server.um.mysqlClientDiagnostics.6"},
    };

    /**
     * Confronta i predefiniti ufficiali con cio' che e' davvero installato.
     * La colonna "installato" viene dal sistema, quella "predefinito" dalla fonte ufficiale:
     * il confronto e' il punto, perche' e' la divergenza a rompere le cose.
     */
    /**
     * Da quale ramo dei pacchetti si serve questo sistema.
     *
     * Cambia quanto ci mette una correzione ad arrivare, ed e' la risposta alla domanda "perche'
     * il repository non ha ancora la versione che chiude questa vulnerabilita'". Non si legge da
     * un file scelto a occhio: pkg fonde /etc/pkg/FreeBSD.conf con gli eventuali file in
     * /usr/local/etc/pkg/repos/, e solo lui sa quale ha vinto. "pkg -vv" stampa la
     * configurazione EFFICACE, quella davvero in uso.
     *
     * Nota sul significato, dall'Handbook di FreeBSD: quarterly viene tagliato da HEAD a
     * gennaio, aprile, luglio e ottobre, e riceve comunque le correzioni di sicurezza — anche
     * come aggiornamento di versione. Cio' che tiene fuori sono le novita', non le correzioni.
     */
    /**
     * Un rapporto unico, in testo, da copiare e incollare.
     *
     * I dati ci sono gia' tutti, ma sparsi in sei schede: quando serve mandarli a qualcuno si
     * finisce a copiare pezzi a mano, e i pezzi che si dimenticano sono sempre quelli che
     * servivano. Qui stanno insieme, nell'ordine in cui uno li chiederebbe.
     *
     * Due scelte deliberate:
     *  - le versioni installate e quelle del repository si leggono con DUE interrogazioni sole
     *    (pkg query e pkg rquery -U su tutto) e si uniscono qui: interrogare pkg 41 volte per 41
     *    pacchetti ci metterebbe minuti per la stessa informazione.
     *  - non entra NIENTE di segreto: nomi, versioni, stati e avvisi. Nessun file di
     *    configurazione, nessuna password, nessuna chiave. Un rapporto fatto per essere
     *    incollato deve poter essere incollato senza rileggerlo riga per riga.
     */
    /**
     * Fine supporto delle release di FreeBSD, dalla pagina ufficiale della sicurezza.
     *
     * Fotografia datata come PREDEFINITI, per lo stesso motivo: il pannello non va su internet.
     * Fonte: https://www.FreeBSD.org/security/ — letta il 31/08/2026.
     * Da rileggere quando esce una release nuova: una data di fine supporto sbagliata e' peggio
     * di nessuna data, perche' rassicura invece di far controllare.
     */
    private static final String[][] END_OF_SUPPORT = {
        {"15.1", "31/03/2027", "server.um.mysqlClientDiagnostics.7"},
        {"15.0", "30/09/2026", "server.um.mysqlClientDiagnostics.8"},
        {"14.4", "31/12/2026", "server.um.mysqlClientDiagnostics.9"},
    };
    private static final String SUPPORT_SOURCE =
        "server.um.mysqlClientDiagnostics.10";

    /**
     * Quando la tabella qui sopra e' stata copiata, in forma leggibile da un programma.
     *
     * La stessa informazione e' gia' dentro FONTE_SUPPORTO, ma dentro una frase: per mostrarla
     * accanto alla data di fine supporto bisognerebbe estrarla dal testo con un'espressione
     * regolare. Un dato che serve a un programma si mette in un campo, non lo si va a pescare
     * da una prosa scritta per un essere umano — e' lo stesso errore per cui il piano MTA-STS
     * cercava la parola "Cloudflare" dentro un motivo.
     */
    private static final String SUPPORT_SOURCE_READ = "31/08/2026";

    /**
     * Stato del sistema operativo di base: versione, livello di patch, riavvio necessario,
     * fine del supporto, aggiornamenti gia' scaricati.
     *
     * I pacchetti sono una meta' del server; l'altra e' il sistema sotto, che pkg non tocca e
     * che nessuna delle schede finora guardava. Tutto in sola lettura: "freebsd-update fetch"
     * SCARICA, quindi sta in un'azione separata e dichiarata, non qui dentro.
     */
    public static JSONObject operatingSystem() {
        JSONObject r = new JSONObject();
        try {
            String kernel = sh("freebsd-version -k 2>/dev/null", 20).trim();     // kernel installato
            String running = sh("freebsd-version -r 2>/dev/null", 20).trim();     // kernel in esecuzione
            String userland = sh("freebsd-version -u 2>/dev/null", 20).trim();   // userland
            String uname = sh("uname -r 2>/dev/null", 20).trim();
            String arch = sh("uname -mi 2>/dev/null", 20).trim();
            r.put("installedKernel", kernel).put("runningKernel", running)
             .put("userland", userland).put("uname", uname).put("arch", arch);

            // L'Handbook: se freebsd-version -k e uname -r differiscono, il kernel installato
            // non e' quello in esecuzione — cioe' manca un riavvio.
            boolean restart = !kernel.isEmpty() && !uname.isEmpty() && !kernel.equals(uname);
            r.put("restartNeeded", restart);

            // Fine supporto: si confronta la parte X.Y della userland con la tabella ufficiale.
            Matcher m = Pattern.compile("^([0-9]+\\.[0-9]+)").matcher(userland);
            String series = m.find() ? m.group(1) : "";
            String eol = "", eolNotes = "";
            for (String[] e : END_OF_SUPPORT)
                if (e[0].equals(series)) { eol = e[1]; eolNotes = I18n.tr(e[2]); }
            // "Non conosco questa serie" e' un'informazione, e va detta.
            //
            // Prima, se la serie non era in tabella, eol restava vuoto e la scheda non mostrava
            // nulla: un silenzio che si legge come "niente da segnalare". Ma il caso in cui la
            // serie manca e' esattamente quello in cui il sistema e' PIU' NUOVO della fotografia,
            // cioe' quello in cui la tabella andrebbe riletta. Il difetto si nascondeva proprio
            // dove voleva farsi notare.
            r.put("series", series).put("endOfSupport", eol).put("supportNotes", eolNotes)
             .put("knownSeries", !eol.isEmpty())
             .put("supportSourceRead", SUPPORT_SOURCE_READ)
             .put("supportSource", I18n.tr(SUPPORT_SOURCE));

            boolean release = userland.contains("-RELEASE");
            r.put("updatableWithFreebsdUpdate", release);
            if (!release) {
                r.put("updatesNote", I18n.tr("server.um.operatingSystem.1", java.util.Map.of("userland", String.valueOf(userland))));
            } else {
                // updatesready NON scarica: dice solo se c'e' gia' qualcosa di pronto da installare.
                String ready = sh("freebsd-update updatesready 2>&1", 60).trim();
                r.put("alreadyReady", ready);
                r.put("readyExist", !ready.toLowerCase().contains("no updates are available"));
            }
            return r.put("success", true);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * Cerca gli aggiornamenti del sistema di base. SCARICA, non installa.
     *
     * Sta in un'azione a parte proprio perche' scrive: "freebsd-update fetch" scarica le patch
     * in /var/db/freebsd-update e le lascia li'. Installarle e' un altro comando, e comporta un
     * riavvio se tocca il kernel: quello non lo faccio partire da un pulsante senza che sia una
     * decisione presa guardando cosa cambierebbe.
     */
    public static JSONObject startSystemUpdateSearch() {
        String id = "osf-" + System.currentTimeMillis();
        Job j = new Job(id, "os-fetch");
        JOBS.put(id, j);
        Thread t = localizedThread(j, () -> {
            j.status = "running";
            try {
                j.advance(1, 1);
                j.write(I18n.tr("server.um.startSystemUpdateSearch.1"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.2"));
                j.write("");
                JSONObject os = operatingSystem();
                if (!os.optBoolean("updatableWithFreebsdUpdate", false)) {
                    j.status = "error";
                    j.errorMessage = os.optString("updatesNote", I18n.tr("server.um.findSystemUpdates.1"));
                    j.write(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(j.errorMessage))));
                    return;
                }
                j.write(I18n.tr("server.um.x.youAreAt", java.util.Map.of("uname", String.valueOf(os.optString("uname")))));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.4"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.5"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.6"));
                j.write("");

                // Battito: senza, un comando che scarica per minuti senza andare a capo sembra
                // bloccato. Non e' un abbellimento — e' la differenza fra "sta lavorando" e
                // "e' morto", che dal registro non si distinguerebbe altrimenti.
                final long start = System.currentTimeMillis();
                final java.util.concurrent.atomic.AtomicBoolean finished =
                        new java.util.concurrent.atomic.AtomicBoolean(false);
                Thread heartbeat = localizedThread(() -> {
                    try {
                        while (!finished.get()) {
                            Thread.sleep(30000);
                            if (finished.get()) break;
                            j.write(I18n.tr("server.um.startSystemUpdateSearch.7", java.util.Map.of("p", String.valueOf(((System.currentTimeMillis() - start) / 1000)))));
                        }
                    } catch (InterruptedException ignored) { }
                }, "os-fetch-heartbeat");
                heartbeat.setDaemon(true);
                heartbeat.start();

                StringBuilder cat = new StringBuilder();
                int code;
                try {
                    code = runLogged(j, "freebsd-update --not-running-from-cron fetch 2>&1", 1800, cat);
                } finally {
                    finished.set(true);
                    heartbeat.interrupt();
                }
                String b2 = cat.toString().toLowerCase();
                boolean nobody = b2.contains("no updates needed") || b2.contains("has no updates available");
                j.write("");
                if (code != 0 && !nobody) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startSystemUpdateSearch.8", java.util.Map.of("code", String.valueOf(code)));
                    j.write(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(j.errorMessage))));
                    return;
                }
                j.write(nobody
                        ? I18n.tr("server.um.startSystemUpdateSearch.9")
                        : I18n.tr("server.um.startSystemUpdateSearch.10"));
                j.write(I18n.tr("server.um.startSystemUpdateSearch.11", java.util.Map.of("p", String.valueOf(((System.currentTimeMillis() - start) / 1000)))));
                j.status = "completed";
            } catch (Exception e) {
                j.status = "error"; j.errorMessage = e.getMessage();
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally { j.finishedAt = System.currentTimeMillis(); }
        }, "os-fetch");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Cerca gli aggiornamenti del sistema di base. SCARICA, non installa.
     *
     * Gira dentro un lavoro asincrono e non dentro la richiesta HTTP: su un sistema a p0
     * "freebsd-update fetch" deve scaricare mesi di patch e ci mette minuti, e il 31/08/2026
     * il browser ha mollato la connessione prima che il server rispondesse — lavoro fatto,
     * risposta persa, e a video solo un "Broken pipe". Le operazioni che durano si seguono
     * con il polling, come tutte le altre qui dentro.
     */
    private static JSONObject findSystemUpdates() {
        try {
            JSONObject os = operatingSystem();
            if (!os.optBoolean("updatableWithFreebsdUpdate", false))
                return new JSONObject().put("success", false)
                        .put("error", os.optString("updatesNote", I18n.tr("server.um.findSystemUpdates.1")));
            String out = sh("freebsd-update --not-running-from-cron fetch 2>&1", 900);
            String b = out.toLowerCase();
            boolean nobody = b.contains("no updates needed") || b.contains("has no updates available");
            return new JSONObject().put("success", true).put("output", out.trim())
                    .put("noUpdate", nobody)
                    .put("note", nobody
                        ? I18n.tr("server.um.startSystemUpdateSearch.9")
                        : I18n.tr("server.um.findSystemUpdates.2"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * Controlli preliminari per il salto di release del sistema di base. Tutti in sola lettura.
     *
     * Fonti: Handbook di FreeBSD, capitolo "Updating and Upgrading FreeBSD" (procedura
     * freebsd-update upgrade), manuale di bectl(8) per gli ambienti di avvio, e la pagina
     * https://www.FreeBSD.org/security/ per le date di fine supporto.
     *
     * Il punto che decide tutto: 15.0 e 15.1 hanno la STESSA ABI dei pacchetti
     * (FreeBSD:15:arch), perche' l'ABI porta solo il numero maggiore. L'Handbook impone
     * "pkg-static upgrade -f" solo per i salti di versione MAGGIORE, proprio a causa del
     * cambio di ABI. Qui l'ABI non cambia: i 41 pacchetti protetti non vanno toccati. Fosse
     * un salto maggiore, sarebbe un'altra procedura.
     */
    /**
     * Lo script rc.d del pannello: contenuto, e installazione su richiesta.
     *
     * Serve perche' oggi, se il server si riavvia per un qualsiasi motivo, il pannello resta
     * spento e nessuno lo segnala. Con questo torna su da solo, in modalita' --web.
     *
     * Struttura presa dall'articolo ufficiale "Practical rc.d scripting in BSD" della
     * documentazione FreeBSD: le righe PROVIDE/REQUIRE/KEYWORD per rcorder, l'inclusione di
     * /etc/rc.subr, name, rcvar, load_rc_config e run_rc_command.
     *
     * Due scelte che la documentazione stessa suggerisce:
     *  - il pannello NON e' un demone: sta in primo piano. La documentazione dice che in questi
     *    casi si definisce un start_cmd proprio, e qui si usa daemon(8) per staccarlo, con -p
     *    per il pidfile e -o per il registro.
     *  - procname e' il percorso della java, non /usr/sbin/daemon: rc.subr confronta il pid del
     *    pidfile con procname, e daemon -p scrive il pid del FIGLIO — che dopo l'exec e' java.
     *    Sbagliando questo, "service mailpanel status" direbbe sempre che non gira.
     *
     * REQUIRE resta LOGIN e basta: il pannello tollera MySQL spento (lo segnala e prosegue),
     * quindi legarlo a mysql lo renderebbe piu' fragile senza guadagnarci niente.
     */
    /**
     * Riavvio del server dal pannello.
     *
     * E' l'azione piu' irreversibile che il pannello possa fare, e ha senso solo da quando il
     * pannello torna su da solo: senza lo script rc.d, premere questo pulsante significherebbe
     * spegnere l'unica interfaccia da cui lo stai usando. Per questo, senza rc.d abilitato,
     * si rifiuta invece di avvisare.
     *
     * Il riavvio e' PROGRAMMATO, non immediato, per due motivi. Il primo e' tecnico: shutdown
     * con un tempo futuro resta in esecuzione fino al momento indicato (manuale di shutdown(8)),
     * quindi va lanciato staccato o la risposta HTTP non arriverebbe mai. Il secondo e' umano:
     * un minuto e' la finestra per ripensarci, e il pannello ha un pulsante per annullarlo.
     * (Su FreeBSD si annulla terminando il processo shutdown: "-c" e' power cycle, non cancel.)
     */
    /**
     * Annulla un riavvio programmato.
     *
     * Su FreeBSD non c'e' un'opzione per annullare: il manuale di shutdown(8) dice
     * "A scheduled shutdown can be canceled by killing the shutdown process (a SIGTERM should
     * suffice)". Attenzione a "shutdown -c": su Linux annulla, su FreeBSD e' POWER CYCLE —
     * spegne e riaccende la macchina. Il 31/08/2026 l'ho scritto a memoria e l'ho detto
     * sbagliato: e' esattamente il genere di ricordo che va verificato prima di usarlo.
     */
    /**
     * Dove sta davvero un comando, chiesto al sistema invece che ricordato.
     *
     * Il 31/08/2026 il pulsante di riavvio non ha riavviato niente perche' avevo scritto
     * /usr/sbin/shutdown a memoria. "daemon" fa fork e poi exec: se l'exec fallisce, il
     * fallimento avviene nel figlio e il padre esce comunque con successo — quindi nemmeno il
     * codice di uscita lo rivelava. Il manuale non dichiara il percorso, e allora la risposta
     * non e' scegliere fra /sbin e /usr/sbin: e' chiederlo.
     */
    private static String commandPath(String name, String... candidates) {
        if (!name.matches("[a-z0-9_-]{1,32}")) return "";
        String v = sh("command -v " + name + " 2>/dev/null", 20).trim();
        if (v.startsWith("/") && ok("test -x " + v, 10)) return v;
        for (String c : candidates) if (ok("test -x " + c, 10)) return c;
        return "";
    }

    public static JSONObject cancelReboot() {
        try {
            String pid = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            if (!pid.matches("[0-9]{1,7}")) pid = sh("pgrep -f '/shutdown -r' 2>/dev/null | head -1", 20).trim();
            if (!pid.matches("[0-9]{1,7}"))
                return new JSONObject().put("success", true).put("existedBefore", false)
                        .put("note", I18n.tr("server.um.cancelReboot.1"));
            String line = sh("ps -o command= -p " + pid + " 2>/dev/null", 20).trim();
            boolean done = ok("kill " + pid, 20);
            // La prova che conta: il processo e' davvero sparito?
            String still = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            boolean via = still.isEmpty();
            return new JSONObject().put("success", via).put("existedBefore", true)
                    .put("pid", pid).put("command", line)
                    .put("note", via
                        ? I18n.tr("server.um.cancelReboot.2", java.util.Map.of("pid", String.valueOf(pid), "line", String.valueOf(line)))
                        : I18n.tr("server.um.cancelReboot.3", java.util.Map.of("still", String.valueOf(still), "still2", String.valueOf(still))))
                    .put("error", via ? "" : I18n.tr("server.um.cancelReboot.4"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject restartServer(boolean run, int minutes) {
        JSONObject r = new JSONObject();
        try {
            if (minutes < 0 || minutes > 60) minutes = 1;
            JSONObject os = operatingSystem();
            r.put("installedKernel", os.optString("installedKernel"))
             .put("runningKernel", os.optString("uname"))
             .put("restartNeeded", os.optBoolean("restartNeeded"))
             .put("minutes", minutes);

            JSONObject startup = autoStart();
            boolean rc = startup.optBoolean("installed", false);
            boolean enabled = startup.optBoolean("enabled", false);
            r.put("rcActive", startup.optBoolean("active", false));
            r.put("autoStart", startup);
            if (!(rc && enabled)) {
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.restartServer.1"));
            }

            // Cosa si ferma: elencarlo prima e' meglio che scoprirlo dopo.
            JSONArray services = new JSONArray();
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                if (ok("service " + svc + " status", 20)) services.put(svc);
            }
            r.put("services", services);
            r.put("effect", I18n.tr("server.um.restartServer.2", java.util.Map.of("length", String.valueOf(services.length()))));

            String pending = sh("ps -axo command | grep '^shutdown ' | head -1", 20).trim();
            r.put("gaScheduled", pending);
            // Il manuale: "-f  Ignore the presence of the /var/run/noshutdown file". Se quel
            // file c'e', shutdown si rifiuta — ed e' meglio saperlo prima di premere.
            boolean noshutdown = ok("test -f /var/run/noshutdown", 10);
            r.put("noshutdown", noshutdown);
            String shPrev = commandPath("shutdown", "/sbin/shutdown", "/usr/sbin/shutdown");
            String dmPrev = commandPath("daemon", "/usr/sbin/daemon", "/sbin/daemon");
            r.put("shutdownPath", shPrev.isEmpty() ? I18n.tr("server.um.restartServer.3") : shPrev)
             .put("daemonPath", dmPrev.isEmpty() ? I18n.tr("server.um.restartServer.3") : dmPrev);
            if (noshutdown)
                r.put("noshutdownWarning", I18n.tr("server.um.restartServer.4"));
            if (!run) return r.put("success", true).put("executed", false);

            String msg = "Restart requested by the mail panel";
            String shutdown = commandPath("shutdown", "/sbin/shutdown", "/usr/sbin/shutdown");
            String daemon = commandPath("daemon", "/usr/sbin/daemon", "/sbin/daemon");
            if (shutdown.isEmpty() || daemon.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.x.noShutdownCmd", java.util.Map.of("cmd", String.valueOf(shutdown.isEmpty() ? "shutdown" : "daemon"))));
            String logR = "/var/db/mailpanel/reboot.log";
            ok("mkdir -p /var/db/mailpanel", 20);
            ok("rm -f " + logR, 15);
            // Staccato: shutdown con un tempo futuro non torna finche' non e' ora. E con -o
            // invece del solo -f, se rifiuta lo dice a qualcuno: la prima versione mandava la
            // sua uscita in /dev/null e il 31/08/2026 il riavvio non e' avvenuto senza che
            // nessuno sapesse perche'.
            ok(daemon + " -f -o " + logR + " " + shutdown + " -r +" + minutes + " '" + msg + "'", 30);

            // "daemon" esce subito e con successo comunque: il suo codice di uscita non dice
            // niente su shutdown. L'unica prova e' che il processo shutdown ESISTA.
            ok("sleep 2", 15);
            String pidS = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            String output = sh("cat " + logR + " 2>/dev/null", 20).trim();
            if (!pidS.matches("[0-9]{1,7}")) {
                boolean nosh = ok("test -f /var/run/noshutdown", 10);
                return r.put("success", false).put("executed", false)
                        .put("output", output)
                        .put("error", I18n.tr("server.um.x.restartNotScheduled")
                            + (nosh ? "  " + I18n.tr("server.um.x.noshutdownCause")
                                    : "")
                            + "  " + (output.isEmpty() ? I18n.tr("server.um.x.shutdownSilent")
                                             : I18n.tr("server.um.x.shutdownWrote", java.util.Map.of("u", String.valueOf(output)))));
            }
            return r.put("success", true).put("executed", true).put("pid", pidS)
                    .put("output", output)
                    .put("note", minutes == 1
                        ? I18n.tr("server.um.x.restartIn.one")
                        : I18n.tr("server.um.x.restartIn.other", java.util.Map.of("n", String.valueOf(minutes))))
                    .put("cancel", I18n.tr("server.um.restartServer.6"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * Il pannello torna su da solo dopo un riavvio del server?
     *
     * La risposta esisteva gia', ma solo DENTRO restartServer(): serviva a rifiutare un
     * riavvio, e non veniva mai detta a nessuno. Cosi' il fatto piu' importante — se il
     * pannello si riaccende o no — si scopriva soltanto provando a riavviare, cioe' nel
     * momento peggiore per scoprirlo.
     *
     * Conta piu' di quanto sembri: dentro il server web vivono lo scheduler della rotazione
     * DKIM, il rinnovo automatico dei certificati e il rapporto periodico. Se il pannello non
     * riparte, quelle cose non si rompono — si fermano dove sono, e nessuno lo segnala.
     */
    /**
     * La lista degli intervalli Cloudflare compilata nel pannello e' ancora quella ufficiale?
     *
     * Perche' serve. Il pannello si fida di CF-Connecting-IP soltanto se la richiesta arriva da
     * un indirizzo che riconosce come Cloudflare; l'elenco di quegli indirizzi e' scritto a mano
     * dentro TrustedProxy e va tenuto uguale a cloudflare.com/ips-v4 e ips-v6.
     *
     * Se Cloudflare aggiunge un intervallo e comincia a servire da li', il pannello smette di
     * riconoscerlo: da quel momento TUTTI i visitatori diventano un indirizzo solo — quello
     * dell'edge — e il limite dei tentativi di accesso si applica a tutti insieme. Cinque
     * tentativi sbagliati di chiunque chiuderebbero fuori anche te. Non e' un buco, e' un
     * blocco: fallisce diventando piu' severo, che e' il modo piu' silenzioso di rompersi.
     *
     * Questa funzione LEGGE e basta: scarica le due liste ufficiali e le confronta. Non
     * aggiorna niente da sola — una lista di chi e' degno di fiducia non si riscrive senza
     * che un essere umano l'abbia guardata.
     */
    public static JSONObject cloudflareRanges() {
        JSONObject r = new JSONObject().put("updatedOn", org.mail_panel.security.TrustedProxy.UPDATED_ON);
        // Cio' che il pannello CREDE si mostra sempre, anche se la rete non risponde: e' una
        // conoscenza sua, non dipende da cloudflare.com. Una lista che decide di chi fidarsi e
        // che nessuno puo' leggere e' una regola segreta; e nel momento in cui il confronto
        // fallisce e' proprio quando serve poter guardare cosa c'e' scritto.
        r.put("listV4", new JSONArray(org.mail_panel.security.TrustedProxy.cloudflareV4()));
        r.put("listV6", new JSONArray(org.mail_panel.security.TrustedProxy.cloudflareV6()));
        r.put("localList", new JSONArray(org.mail_panel.security.TrustedProxy.localIntervals()));
        try {
            java.util.List<String> v4 = downloadIntervals("https://www.cloudflare.com/ips-v4", true);
            java.util.List<String> v6 = downloadIntervals("https://www.cloudflare.com/ips-v6", false);

            // Una soglia minima, non il solo "non vuoto".
            //
            // Senza, una risposta parziale o una pagina di errore da cui si salvano due righe
            // darebbe una lista ufficiale corta. Nessun intervallo "mancante" — quindi niente
            // rosso — e invece una dozzina di "non piu' ufficiali": il pannello consiglierebbe
            // di TOGLIERE dalla lista di fiducia intervalli che Cloudflare usa eccome. Un
            // consiglio sbagliato e' peggio di un verde sbagliato, perche' chi lo segue rompe
            // qualcosa di suo con le proprie mani.
            //
            // Cloudflare pubblica da anni almeno 15 intervalli IPv4 e 7 IPv6. La soglia sta
            // sotto apposta: deve scattare su una risposta rotta, non su un aggiornamento
            // legittimo della lista.
            final int MIN_V4 = 10, MIN_V6 = 5;
            if (v4.size() < MIN_V4 || v6.size() < MIN_V6)
                return r.put("success", false).put("verified", false)
                        .put("officialV4", v4.size()).put("officialV6", v6.size())
                        .put("error", I18n.tr("server.um.cloudflareRanges.1", java.util.Map.of("size", String.valueOf(v4.size()), "size2", String.valueOf(v6.size()), "minimumV4", String.valueOf(MIN_V4), "minimumV6", String.valueOf(MIN_V6))));

            java.util.List<String> myV4 = org.mail_panel.security.TrustedProxy.cloudflareV4();
            java.util.List<String> myV6 = org.mail_panel.security.TrustedProxy.cloudflareV6();

            // Mancanti = presenti da Cloudflare e NON nel pannello. Sono quelli che contano:
            // sono gli indirizzi da cui il pannello non riconoscerebbe il proxy.
            JSONArray missing = new JSONArray();
            for (String c : v4) if (!myV4.contains(c)) missing.put(c);
            for (String c : v6) if (!myV6.contains(c)) missing.put(c);

            // In piu' = nel pannello e non piu' ufficiali. Non fanno danno diretto, ma sono
            // fiducia concessa a indirizzi che Cloudflare non usa piu'.
            JSONArray extra = new JSONArray();
            for (String c : myV4) if (!v4.contains(c)) extra.put(c);
            for (String c : myV6) if (!v6.contains(c)) extra.put(c);

            r.put("success", true).put("verified", true)
             .put("officialV4", v4.size()).put("officialV6", v6.size())
             .put("compiledV4", myV4.size()).put("compiledV6", myV6.size())
             .put("missing", missing).put("extra", extra)
             .put("aligned", missing.length() == 0 && extra.length() == 0);

            r.put("note", missing.length() > 0
                ? I18n.tr("server.um.cloudflareRanges.2", java.util.Map.of("length", String.valueOf(missing.length())))
                : extra.length() > 0
                  ? I18n.tr("server.um.cloudflareRanges.3", java.util.Map.of("length", String.valueOf(extra.length())))
                  : I18n.tr("server.um.cloudflareRanges.4"));
            return r;
        } catch (Exception e) {
            return r.put("success", false).put("verified", false)
                    .put("error", I18n.tr("server.um.cloudflareRanges.5", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Una riga per intervallo, righe vuote e commenti scartati.
     *
     * @param ipv4 la famiglia attesa: una riga della famiglia sbagliata viene scartata. Il
     *             controllo di forma da solo non distingue un CIDR IPv6 da uno IPv4, e una
     *             lista arrivata sul file sbagliato falserebbe il confronto.
     */
    private static java.util.List<String> downloadIntervals(String url, boolean ipv4) {
        java.util.List<String> out = new java.util.ArrayList<>();
        try {
            var http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(8)).build();
            var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(15)).GET().build();
            var resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return out;
            for (String line : resp.body().split("\n")) {
                String c = line.trim();
                // Si accetta solo cio' che ha la forma di un CIDR: da una pagina di errore o da
                // una risposta inattesa non deve entrare niente in una lista di fiducia.
                if (c.isEmpty() || c.startsWith("#")) continue;
                // Due filtri, non uno. La forma deve valere per la riga INTERA — cosi' una riga
                // di HTML che contenga un CIDR non passa — e la riga dev'essere un CIDR vero
                // della famiglia giusta.
                if (!c.matches("[0-9a-fA-F:.]+/[0-9]{1,3}")) continue;
                boolean looksLikeV4 = c.indexOf(':') < 0;
                if (looksLikeV4 != ipv4) continue;
                if (!validCidr(c, ipv4)) continue;
                out.add(c);
            }
        } catch (Exception ignore) { }
        return out;
    }

    /** Il CIDR e' scrivibile davvero: indirizzo letterale valido e prefisso nella scala giusta. */
    private static boolean validCidr(String cidr, boolean ipv4) {
        try {
            int i = cidr.indexOf('/');
            int prefix = Integer.parseInt(cidr.substring(i + 1));
            if (prefix < 0 || prefix > (ipv4 ? 32 : 128)) return false;
            byte[] b = java.net.InetAddress.getByName(cidr.substring(0, i)).getAddress();
            return b.length == (ipv4 ? 4 : 16);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Il riepilogo per la Home: versioni, riavvio necessario, quanti aggiornamenti, quante
     * vulnerabilita'. VELOCE — e la velocita' qui e' un requisito, non un vezzo.
     *
     * updatesStatus() risponde alle stesse domande ma esegue "pkg update" e "pkg upgrade -n":
     * fino a cinque minuti, e con la rete di mezzo. In una pagina che si apre di continuo
     * sarebbe una Home che gira. Qui si legge il catalogo GIA' scaricato e il database delle
     * vulnerabilita' GIA' presente: nessuna richiesta di rete.
     *
     * Il prezzo di quella scelta e' che i numeri possono essere vecchi, e va detto invece che
     * nascosto: si riporta anche l'ETA' del catalogo e del database. Un conteggio preciso
     * ricavato da dati di tre settimane fa e' un numero che sembra una misura e non lo e' —
     * per la simulazione vera resta la pagina Aggiornamenti, che la fa apposta.
     */
    public static JSONObject systemSummary() {
        JSONObject r = new JSONObject();
        try {
            r.put("os", operatingSystem());

            // Quanti pacchetti differiscono dal catalogo locale, DIVISI PER MOTIVO.
            //
            // "pkg version -L=" mostra tutto cio' che non e' "=" , e il manuale (pkg-version(8))
            // elenca quattro casi diversi: "<" installato piu' vecchio, ">" installato piu'
            // recente del catalogo, "?" non presente nel catalogo, "!" confronto non riuscito.
            // Solo il primo vuol dire "c'e' un aggiornamento".
            //
            // Contarli tutti insieme e chiamarli "versione piu' recente disponibile" dava un
            // numero che non corrispondeva a niente: qui diceva 5 mentre "pkg upgrade -n"
            // rispondeva "Your packages are up to date", cioe' zero. Un numero che nessuna
            // altra schermata conferma fa dubitare di tutte le altre.
            String list = sh("pkg version -U -vRL= 2>/dev/null", 60);
            int toUpdate = 0, mostRecent = 0, outsideCatalog = 0, notComparable = 0;
            for (String line : list.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                String[] fields = t.split("\\s+");
                String state = fields.length > 1 ? fields[1] : "";
                switch (state) {
                    case "<" -> toUpdate++;
                    case ">" -> mostRecent++;
                    case "?" -> outsideCatalog++;
                    case "!" -> notComparable++;
                    default -> { }
                }
            }
            r.put("toUpdate", toUpdate)
             .put("newerThanCatalog", mostRecent)
             .put("outsideCatalog", outsideCatalog)
             .put("notComparable", notComparable);

            // L'eta' del catalogo: senza, il numero qui sopra sembra piu' preciso di quanto sia.
            // E' la data di pubblicazione sul server (vedi PkgCatalog).
            JSONObject cat = PkgCatalog.read();
            r.put("catalogDays", cat.optLong("days", -1)).put("catalogDate", cat.optString("data"))
             .put("catalogNote", cat.optString("note"));

            // Vulnerabilita' dal database locale: "pkg audit" senza -F non scarica.
            String audit = sh("pkg audit -q 2>/dev/null", 60);
            int vuln = 0;
            for (String line : audit.split("\n")) if (!line.trim().isEmpty()) vuln++;
            r.put("vulnerable", vuln);
            r.put("vulnDbDays", daysSince("/var/db/pkg/vuln.xml"));

            return r.put("success", true);
        } catch (Exception e) {
            return r.put("success", false).put("error", e.getMessage());
        }
    }

    /** Da quanti giorni non viene toccato un file. -1 se non c'e' o non si riesce a leggerlo. */
    private static long daysSince(String path) {
        try {
            String m = sh("stat -f %m " + path + " 2>/dev/null", 15).trim();
            if (m.isEmpty()) return -1;
            long epoch = Long.parseLong(m);
            return (System.currentTimeMillis() / 1000L - epoch) / 86400L;
        } catch (Exception e) {
            return -1;
        }
    }

    public static JSONObject autoStart() {
        JSONObject r = new JSONObject();
        try {
            String path = ok("test -f /usr/local/etc/rc.d/mailpanel", 10)
                    ? "/usr/local/etc/rc.d/mailpanel"
                    : (ok("test -f /etc/rc.d/mailpanel", 10) ? "/etc/rc.d/mailpanel" : null);
            boolean installed = path != null;
            String enabledBy = sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim();
            boolean enabled = "YES".equalsIgnoreCase(enabledBy) || "yes".equalsIgnoreCase(enabledBy)
                    || "true".equalsIgnoreCase(enabledBy) || "1".equals(enabledBy);
            r.put("success", true)
             .put("installed", installed)
             .put("enabled", enabled)
             .put("active", installed && enabled)
             .put("path", path == null ? "" : path)
             .put("sysrcValue", enabledBy);
            r.put("reason", installed && enabled
                ? I18n.tr("server.um.autoStart.1")
                : !installed
                  ? I18n.tr("server.um.autoStart.2")
                  : I18n.tr("server.um.x.rcNotEnabled", java.util.Map.of("v", String.valueOf(enabledBy.isEmpty() ? I18n.tr("server.um.x.notSet") : enabledBy))));
            return r;
        } catch (Exception e) {
            // "Non ho potuto controllare" non e' "va bene": chi legge deve vederlo.
            return r.put("success", false).put("active", false)
                    .put("reason", I18n.tr("server.um.autoStart.3", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Toglie l'avvio automatico: disabilita mailpanel_enable e rimuove lo script rc.d.
     *
     * NON ferma il pannello. Se stai leggendo queste righe da un pannello avviato dal
     * servizio, quel processo continua a girare: chiudergli la porta in faccia mentre premi
     * il pulsante sarebbe assurdo. Cambia solo che al prossimo riavvio non torna su — e con
     * lui non tornano su lo scheduler della rotazione DKIM, il rinnovo dei certificati e il
     * rapporto periodico.
     *
     * Tre cautele, tutte imparate a spese di qualcun altro:
     *
     *  - Prima di cancellare si fa una COPIA, e se la copia non riesce non si cancella. Uno
     *    script rc.d cancellato senza copia si riscrive solo reinstallandolo.
     *  - "sysrc -x" su una variabile che non esiste ha un esito non documentato: in quel caso
     *    non lo si chiama nemmeno. Non si danno comandi al buio a un file di configurazione
     *    del boot.
     *  - Il verdetto NON si legge dai codici di uscita: si rilegge "sysrc -n" e si ricontrolla
     *    il file. Un comando che "riesce" senza aver fatto la cosa e' il modo piu' comune di
     *    raccontarsi che e' andata bene.
     *
     * @param esegui false = anteprima, non tocca niente.
     */
    public static JSONObject removePanelRcScript(boolean run) {
        JSONObject r = new JSONObject();
        try {
            JSONObject before = autoStart();
            r.put("before", before);
            String path = before.optString("path", "");
            boolean installed = before.optBoolean("installed", false);
            String value = before.optString("sysrcValue", "").trim();
            boolean variableExists = !value.isEmpty();

            String copy = "/var/db/mailpanel/mailpanel.rc.removed";
            r.put("path", path).put("copy", copy)
             .put("installed", installed).put("variableExists", variableExists);

            // Chi sta togliendo l'avvio automatico del pannello deve sapere che i blocchi
            // restano: e' l'unico punto in cui la domanda si pone da se'.
            String locksWarning = locksStayWarning();
            if (!locksWarning.isEmpty()) r.put("locksStay", locksWarning);

            if (!installed && !variableExists)
                return r.put("success", true).put("executed", false).put("nothingToDo", true)
                        .put("note", joinNotes(I18n.tr("server.um.removePanelRcScript.1"), locksWarning));

            if (!run)
                return r.put("success", true).put("executed", false)
                        .put("note", joinNotes(I18n.tr("server.um.x.rcRmPreview", java.util.Map.of("actions", String.valueOf((variableExists ? I18n.tr("server.um.x.rcRmVar") : "")
                                + (variableExists && installed ? " " + I18n.tr("server.um.x.and") + " " : "")
                                + (installed ? I18n.tr("server.um.x.rcRmFile", java.util.Map.of("file", String.valueOf(path), "copy", String.valueOf(copy))) : "")))), locksWarning));

            ok("mkdir -p /var/db/mailpanel", 20);

            // 1. La copia PRIMA di tutto: se non riesce, non si prosegue.
            if (installed) {
                ok("cp -p " + path + " " + copy, 20);
                if (!ok("test -s " + copy, 10))
                    return r.put("success", false)
                            .put("error", I18n.tr("server.um.removePanelRcScript.2", java.util.Map.of("path", String.valueOf(path), "copy", String.valueOf(copy))));
                r.put("copyDone", true);
            }

            // 2. La variabile, solo se c'e' davvero.
            if (variableExists) ok("sysrc -x mailpanel_enable", 30);

            // 3. Lo script.
            if (installed) ok("rm -f " + path, 20);

            // 4. Il verdetto: si RILEGGE, non si deduce dai codici di uscita.
            JSONObject after = autoStart();
            r.put("after", after);
            boolean fileStays = after.optBoolean("installed", false);
            boolean varStays = !after.optString("sysrcValue", "").trim().isEmpty();
            if (fileStays || varStays) {
                java.util.List<String> stays = new java.util.ArrayList<>();
                if (fileStays) stays.add(I18n.tr("server.um.removePanelRcScript.3", java.util.Map.of("path", String.valueOf(path))));
                if (varStays) stays.add(I18n.tr("server.um.x.rcVarStill", java.util.Map.of("v", String.valueOf(after.optString("sysrcValue", "")))));
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.x.rcRmIncomplete", java.util.Map.of("stays", String.valueOf(String.join("; ", stays)), "copy", String.valueOf(copy))));
            }

            return r.put("success", true).put("executed", true)
                    .put("note", joinNotes(I18n.tr("server.um.removePanelRcScript.4", java.util.Map.of("copy", String.valueOf(copy))), locksWarning));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.um.removePanelRcScript.5", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        }
    }

    public static JSONObject panelRcScript(boolean run) {
        JSONObject r = new JSONObject();
        try {
            String dir = System.getProperty("user.dir", "");
            String jar = jarPath();
            String binJava = System.getProperty("java.home", "") + "/bin/java";
            if (jar.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.panelRcScript.1"));
            StringBuilder option = new StringBuilder();
            for (String o : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
                if (o.startsWith("-agentlib") || o.startsWith("-javaagent") || o.startsWith("-Xdebug")) continue;
                option.append(' ').append(o);
            }
            String path = "/usr/local/etc/rc.d/mailpanel";
            r.put("path", path).put("dir", dir).put("jar", jar).put("java", binJava);

            String text =
                "#!/bin/sh\n"
              + "#\n"
              + "# PROVIDE: mailpanel\n"
              + "# REQUIRE: LOGIN\n"
              + "# KEYWORD: shutdown\n"
              + "#\n"
              + "# " + RcScriptRepair.MARKER + ". Avvia il pannello in\n"
              + "# modalita' solo-web (--web): niente menu a schermo, nessun terminale richiesto.\n"
              + "# Per riavere il menu: service mailpanel stop, poi lancialo a mano senza --web.\n"
              + "#\n"
              + "# Abilitazione:  sysrc mailpanel_enable=YES\n"
              + "\n"
              + ". /etc/rc.subr\n"
              + "\n"
              + "# Misurato il 31/08/2026 su questo server: avviato da rc.d il pannello riceveva\n"
              + "# PATH=/sbin:/bin:/usr/sbin:/usr/bin, cioe' senza /usr/local. Meta' degli strumenti\n"
              + "# da cui dipende (mysqldump, mysql, doveadm, postmap, rspamadm, fail2ban-client,\n"
              + "# nginx) sta in /usr/local: risultavano \"non installati\" pur essendoci. Il pannello\n"
              + "# ora completa da solo il PATH dei sottoprocessi, ma impostarlo anche qui non costa\n"
              + "# nulla e rende l'ambiente esplicito a chi legge questo file.\n"
              + "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin\n"
              + "export PATH\n"
              + "\n"
              + "name=mailpanel\n"
              + "rcvar=mailpanel_enable\n"
              + "\n"
              + "load_rc_config $name\n"
              + "\n"
              + ": ${mailpanel_enable:=\"NO\"}\n"
              + ": ${mailpanel_dir:=\"" + dir + "\"}\n"
              + ": ${mailpanel_java:=\"" + binJava + "\"}\n"
              + ": ${mailpanel_jar:=\"" + jar + "\"}\n"
              + ": ${mailpanel_opts:=\"" + option.toString().trim() + "\"}\n"
              + ": ${mailpanel_log:=\"" + PANEL_LOG + "\"}\n"
              + "\n"
              + "pidfile=\"/var/run/${name}.pid\"\n"
              + "# rc.subr confronta il pid del pidfile con procname: daemon -p scrive il pid del\n"
              + "# figlio, che dopo l'exec e' java. Mettendo /usr/sbin/daemon, status direbbe\n"
              + "# sempre che il pannello non gira.\n"
              + "procname=\"${mailpanel_java}\"\n"
              + "\n"
              + "start_cmd=\"${name}_start\"\n"
              + "stop_postcmd=\"${name}_poststop\"\n"
              + "\n"
              + "mailpanel_start()\n"
              + "{\n"
              + "\t# kill -0 invece di pgrep -F: e' POSIX, si comporta uguale ovunque e si puo'\n"
              + "\t# mettere alla prova. Un controllo che non si riesce a provare non protegge.\n"
              + "\tif [ -f \"${pidfile}\" ] && kill -0 \"$(cat \"${pidfile}\")\" 2>/dev/null; then\n"
              + "\t\techo \"${name}: gia' in esecuzione (pid $(cat ${pidfile}))\"\n"
              + "\t\treturn 1\n"
              + "\tfi\n"
              + "\tmkdir -p \"$(dirname \"${mailpanel_log}\")\"\n"
              + "\t# Il registro si accoda: oltre i 10 MB lo si mette da parte.\n"
              + "\tif [ -f \"${mailpanel_log}\" ] && [ $(stat -f %z \"${mailpanel_log}\") -gt 10485760 ]; then\n"
              + "\t\tmv \"${mailpanel_log}\" \"${mailpanel_log}.1\"\n"
              + "\tfi\n"
              + "\techo \"Avvio ${name} (solo web). Registro: ${mailpanel_log}\"\n"
              + "\t/usr/sbin/daemon -f -o \"${mailpanel_log}\" -p \"${pidfile}\" -t \"${name}\" \\\n"
              + "\t\t/bin/sh -c \"cd '${mailpanel_dir}' && exec '${mailpanel_java}' ${mailpanel_opts} -jar '${mailpanel_jar}' --web\"\n"
              + "}\n"
              + "\n"
              + "mailpanel_poststop()\n"
              + "{\n"
              + "\trm -f \"${pidfile}\"\n"
              + "}\n"
              + "\n"
              + "run_rc_command \"$1\"\n";
            r.put("text", text);

            boolean exists = ok("test -f " + path, 10);
            String enabled = sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim();
            r.put("exists", exists).put("enabled", enabled);
            if (!run) return r.put("success", true).put("executed", false);

            // Verifica la sintassi PRIMA di metterlo dove il sistema lo eseguira' all'avvio:
            // uno script rc.d rotto puo' fermare la sequenza di boot.
            String tmp = "/var/db/mailpanel/mailpanel.rc.test";
            ok("mkdir -p /var/db/mailpanel", 20);
            Files.writeString(Paths.get(tmp), text);
            String syntaxCheck = sh("sh -n " + tmp + " 2>&1", 30).trim();
            if (!syntaxCheck.isEmpty()) {
                ok("rm -f " + tmp, 15);
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.panelRcScript.3", java.util.Map.of("syntax", String.valueOf(syntaxCheck))));
            }
            if (exists) ok("cp -p " + path + " /var/db/mailpanel/mailpanel.rc.previous", 20);
            Files.writeString(Paths.get(path), text);
            ok("chmod 755 " + path, 15);
            ok("rm -f " + tmp, 15);
            boolean sysrc = ok("sysrc mailpanel_enable=YES", 30);

            // La prova che conta: rc.subr lo carica senza errori?
            String test = sh("service mailpanel rcvar 2>&1", 30).trim();
            boolean loaded = test.contains("mailpanel_enable");
            return r.put("success", true).put("executed", true)
                    .put("enabledNow", sysrc ? sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim() : "?")
                    .put("loaded", loaded).put("rcvar", test)
                    .put("note", I18n.tr("server.um.panelRcScript.4"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * Verso quali versioni ha senso andare, partendo da quella installata.
     *
     * Un campo di testo libero lasciava scrivere 16.0 (salto maggiore, tutti i pacchetti da
     * ricostruire), 15.9 (non esiste), o 14.4 (indietro). Il pannello sa quali release sono
     * supportate e sa da dove parte: puo' proporre le sole scelte sensate invece di accettare
     * qualunque cosa e poi lamentarsene.
     */
    /**
     * Che rapporto c'e' fra la versione installata e quella scelta.
     *
     * Funzione a se' perche' dev'essere PROVABILE. Dentro il preflight era irraggiungibile da
     * qualunque test: il primo controllo guarda se il sistema e' una -RELEASE, e su una
     * macchina che FreeBSD non e' si ferma li'. Un test che non arriva a esercitare cio' che
     * deve verificare passa e non dimostra niente.
     *
     * Restituisce: "indietro", "stessa", "minore", "maggiore", "illeggibile".
     */
    static String updateDirection(String current, String target) {
        Matcher a = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(current == null ? "" : current);
        Matcher b = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(target == null ? "" : target);
        if (!a.find() || !b.find()) return "unreadable";
        int a1 = Integer.parseInt(a.group(1)), a2 = Integer.parseInt(a.group(2));
        int b1 = Integer.parseInt(b.group(1)), b2 = Integer.parseInt(b.group(2));
        if (b1 < a1 || (b1 == a1 && b2 < a2)) return "backward";
        if (b1 == a1 && b2 == a2) return "same";
        return b1 == a1 ? "minor" : "major";
    }

    public static JSONObject targetVersions() {
        try {
            JSONObject os = operatingSystem();
            String series = os.optString("series");
            Matcher m = Pattern.compile("^([0-9]+)\\.([0-9]+)$").matcher(series);
            if (!m.find())
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.targetVersions.1", java.util.Map.of("series", String.valueOf(series))));
            int majorExpected = Integer.parseInt(m.group(1)), minorExpected = Integer.parseInt(m.group(2));
            JSONArray outside = new JSONArray();
            for (String[] e : END_OF_SUPPORT) {
                Matcher m2 = Pattern.compile("^([0-9]+)\\.([0-9]+)$").matcher(e[0]);
                if (!m2.find()) continue;
                int ma = Integer.parseInt(m2.group(1)), mi = Integer.parseInt(m2.group(2));
                if (ma != majorExpected) continue;          // i salti maggiori non passano di qui
                if (mi <= minorExpected) continue;          // se stessa o indietro: non e' un aggiornamento
                outside.put(new JSONObject().put("version", e[0])
                        .put("endOfSupport", e[1]).put("note", I18n.tr(e[2])));
            }
            return new JSONObject().put("success", true).put("current", series)
                    .put("versions", outside)
                    .put("source", I18n.tr(SUPPORT_SOURCE))
                    .put("note", outside.length() == 0
                        ? I18n.tr("server.um.targetVersions.2", java.util.Map.of("series", String.valueOf(series)))
                        : I18n.tr("server.um.targetVersions.3", java.util.Map.of("majorNow", String.valueOf(majorExpected), "p", String.valueOf((majorExpected + 1)))));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject systemUpgradePreflight(String targetVersion) {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean lock = false;
        try {
            if (targetVersion == null || !targetVersion.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
                return r.put("success", false).put("error", I18n.tr("server.um.systemUpgradePreflight.1"));
            String target = targetVersion + "-RELEASE";
            r.put("target", target);

            JSONObject os = operatingSystem();
            String userland = os.optString("userland"), uname = os.optString("uname");
            r.put("current", userland).put("uname", uname).put("arch", os.optString("arch"));

            if (!userland.contains("-RELEASE")) {
                addCheck(checks, "kind", I18n.tr("server.um.systemUpgradePreflight.2"), "block",
                        I18n.tr("server.um.systemUpgradePreflight.3", java.util.Map.of("userland", String.valueOf(userland))));
                return r.put("success", true).put("checks", checks).put("blocked", true).put("canProceed", false);
            }
            addCheck(checks, "current", I18n.tr("server.um.x.currentVersion"), "ok",
                    I18n.tr("server.um.x.userlandKernel", java.util.Map.of("u", String.valueOf(userland), "k", String.valueOf(uname)))
                    + (os.optBoolean("restartNeeded")
                       ? I18n.tr("server.um.systemUpgradePreflight.4") : ""));
            if (os.optBoolean("restartNeeded")) {
                addCheck(checks, "restartPending", I18n.tr("server.um.systemUpgradePreflight.5"), "block",
                        I18n.tr("server.um.systemUpgradePreflight.6"));
                lock = true;
            }

            // Salto minore o maggiore? Cambia se i pacchetti vanno ricostruiti.
            String majorExpected = userland.replaceAll("[^0-9.].*$", "").replaceAll("\\..*$", "");
            String majorNew = targetVersion.replaceAll("\\..*$", "");
            boolean minor = majorExpected.equals(majorNew);

            // Direzione: la decide una funzione a parte, che si puo' mettere alla prova.
            String direction = updateDirection(os.optString("series"), targetVersion);
            r.put("direction", direction);
            if ("backward".equals(direction) || "same".equals(direction)) {
                addCheck(checks, "direction", I18n.tr("server.um.systemUpgradePreflight.7"), "block",
                        "same".equals(direction)
                        ? I18n.tr("server.um.systemUpgradePreflight.8", java.util.Map.of("target", String.valueOf(targetVersion)))
                        : I18n.tr("server.um.x.targetOlder", java.util.Map.of("target", String.valueOf(targetVersion), "series", String.valueOf(os.optString("series")))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", true).put("canProceed", false);
            }
            r.put("minorJump", minor);
            String abiName = sh("pkg config abi 2>/dev/null", 20).trim();
            r.put("abiName", abiName);
            if (!minor) lock = true;
            addCheck(checks, "abi", I18n.tr("server.um.systemUpgradePreflight.9"), minor ? "ok" : "block",
                    minor
                    ? I18n.tr("server.um.systemUpgradePreflight.10", java.util.Map.of("abi", String.valueOf(abiName), "majorNow", String.valueOf(majorExpected), "majorNew", String.valueOf(majorNew)))
                    : I18n.tr("server.um.systemUpgradePreflight.11", java.util.Map.of("majorNow", String.valueOf(majorExpected), "majorNew", String.valueOf(majorNew))));

            // Fine supporto della versione di arrivo: passare a qualcosa che scade fra poco
            // non risolve niente.
            String eolNew = "", noteNew = "";
            for (String[] e : END_OF_SUPPORT) if (e[0].equals(targetVersion)) { eolNew = e[1]; noteNew = I18n.tr(e[2]); }
            r.put("targetEndOfSupport", eolNew);
            addCheck(checks, "eol", I18n.tr("server.um.systemUpgradePreflight.12"), eolNew.isEmpty() ? "wait" : "ok",
                    eolNew.isEmpty()
                    ? I18n.tr("server.um.systemUpgradePreflight.13", java.util.Map.of("target", String.valueOf(targetVersion)))
                    : I18n.tr("server.um.x.supportedUntil", java.util.Map.of("target", String.valueOf(target), "eol", String.valueOf(eolNew), "note", String.valueOf(noteNew), "series", String.valueOf(os.optString("series")), "end", String.valueOf(os.optString("endOfSupport")))));

            // Kernel personalizzato: l'Handbook avverte che non viene aggiornato.
            String kconf = sh("sysctl -n kern.conftxt 2>/dev/null | head -1", 20).trim();
            boolean generic = os.optString("arch").contains("GENERIC");
            addCheck(checks, "kernel", "Kernel", generic ? "ok" : "wait",
                    generic
                    ? I18n.tr("server.um.systemUpgradePreflight.14")
                    : I18n.tr("server.um.x.notGeneric", java.util.Map.of("arch", String.valueOf(os.optString("arch")))));

            // Ambienti di avvio: e' la vera via di ritorno di un aggiornamento di base.
            boolean be = ok("bectl check", 30);
            r.put("bootEnvironment", be);
            if (be) {
                String list = sh("bectl list -H 2>/dev/null | awk '{print $1\" (\"$2\") \"$4}'", 30);
                r.put("existingBes", list);
                addCheck(checks, "be", I18n.tr("server.um.systemUpgradePreflight.15"), "ok",
                        I18n.tr("server.um.x.beSupported", java.util.Map.of("list", String.valueOf(list.replace("\n", " | ")))));
            } else {
                addCheck(checks, "be", I18n.tr("server.um.systemUpgradePreflight.15"), "wait",
                        I18n.tr("server.um.systemUpgradePreflight.16"));
            }

            // Spazio: l'ambiente di avvio e' un clone, ma i file scaricati e le vecchie librerie
            // occupano comunque.
            long freeMb = number(sh("df -m / | tail -1 | awk '{print $4}'", 30));
            r.put("freeMb", freeMb);
            addCheck(checks, "space", I18n.tr("server.um.x.spaceRoot"), freeMb > 5000 ? "ok" : "block",
                    I18n.tr("server.um.x.mbFreeRoot", java.util.Map.of("n", String.valueOf(freeMb))) + " " + (freeMb > 5000
                        ? I18n.tr("server.um.systemUpgradePreflight.17")
                        : I18n.tr("server.um.systemUpgradePreflight.18")));
            if (freeMb <= 5000) lock = true;

            // Il pannello stesso: due riavvii, e lui non torna su da solo.
            // Attenzione a cosa si afferma. Il file c'e' e sysrc dice YES: sono fatti. Che il
            // pannello TORNI SU e' una previsione, e l'unica prova e' averlo avviato una volta
            // con "service mailpanel start". Dire "tornera' su da solo" perche' esiste un file
            // e' la stessa distanza fra "installato" e "funziona" su cui sbaglio di continuo.
            boolean rc = ok("test -f /usr/local/etc/rc.d/mailpanel -o -f /etc/rc.d/mailpanel", 10);
            String enabledBy = sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim();
            boolean enabled = "YES".equalsIgnoreCase(enabledBy) || "yes".equalsIgnoreCase(enabledBy)
                    || "true".equalsIgnoreCase(enabledBy) || "1".equals(enabledBy);
            boolean tested = ok("test -f /var/run/mailpanel.pid", 10);
            r.put("rcPanel", rc).put("rcEnabled", enabled).put("rcTested", tested);
            addCheck(checks, "panel", I18n.tr("server.um.systemUpgradePreflight.19"),
                    (rc && enabled && tested) ? "ok" : "wait",
                    !rc
                    ? I18n.tr("server.um.systemUpgradePreflight.20")
                    : !enabled
                    ? I18n.tr("server.um.systemUpgradePreflight.21", java.util.Map.of("enabled", String.valueOf(enabledBy)))
                    : tested
                    ? I18n.tr("server.um.systemUpgradePreflight.22")
                    : I18n.tr("server.um.systemUpgradePreflight.23"));

            // I servizi che devono tornare su: si annotano ORA per poterli confrontare DOPO.
            JSONArray services = new JSONArray();
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                services.put(new JSONObject().put("name", svc).put("active", ok("service " + svc + " status", 20)));
            }
            r.put("services", services);
            addCheck(checks, "services", I18n.tr("server.um.systemUpgradePreflight.24"), "ok",
                    I18n.tr("server.um.systemUpgradePreflight.25", java.util.Map.of("length", String.valueOf(services.length()))));

            // Patch di sicurezza arretrate: l'Handbook dice di applicarle PRIMA di aggiornare.
            String pl = uname.contains("-p") ? uname.replaceAll(".*-p", "p") : "p0 " + I18n.tr("server.um.x.noPatch");
            addCheck(checks, "patch", I18n.tr("server.um.systemUpgradePreflight.26"), "wait",
                    I18n.tr("server.um.systemUpgradePreflight.27", java.util.Map.of("pl", String.valueOf(pl))));

            r.put("success", true).put("checks", checks)
             .put("blocked", lock).put("canProceed", !lock);
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject startSystemPreparation(String target) {
        if (target == null || !target.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.systemUpgradePreflight.1"));
        String id = "sys-" + System.currentTimeMillis();
        Job j = new Job(id, "system");
        JOBS.put(id, j);
        final String b = target;
        Thread t = localizedThread(j, () -> runSystemPreparation(j, b), "system-prep");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Prepara il salto di release: copia di /etc, ambiente di avvio, patch arretrate.
     *
     * Non aggiorna la release: mette il sistema nelle condizioni in cui l'Handbook dice che
     * deve essere prima di cominciare, e crea la via di ritorno. Il salto vero e' interattivo
     * (chiede conferma, puo' aprire un editor per fondere i file di /etc) e comporta due
     * riavvii durante i quali questa pagina non esiste: quella parte la fa una persona, con le
     * istruzioni che il pannello genera sui valori veri di questo server.
     */
    private static void runSystemPreparation(Job job, String target) {
        job.status = "running";
        final int TOT = 4;
        try {
            job.advance(1, TOT);
            job.write(I18n.tr("server.um.runSystemPreparation.1", java.util.Map.of("target", String.valueOf(target))));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.1", java.util.Map.of("total", String.valueOf(TOT))));
            JSONObject pf = systemUpgradePreflight(target);
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigration84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if ("block".equals(c.optString("level")))
                        job.write("  [" + I18n.tr("server.um.x.blockTag") + "] " + c.optString("label") + ": " + c.optString("detail"));
                }
                job.write(I18n.tr("server.um.runMigration84.4"));
                return;
            }
            job.write("  " + pf.optString("current") + " -> " + pf.optString("target")
                    + "   " + (pf.optBoolean("minorJump") ? I18n.tr("server.um.x.jumpMinor")
                                                          : I18n.tr("server.um.x.jumpMajor")));

            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            String bk = "/var/db/mailpanel/system/" + ts;
            if (!ok("mkdir -p " + bk, 30)) throw new IllegalStateException("cannot create " + bk);

            job.advance(2, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runSystemPreparation.2", java.util.Map.of("total", String.valueOf(TOT))));
            if (!ok("tar -cf " + bk + "/etc.tar -C /etc . 2>/dev/null", 600))
                throw new IllegalStateException("copy of /etc failed");
            long entries = number(sh("tar -tf " + bk + "/etc.tar 2>/dev/null | wc -l", 120));
            if (entries < 50) throw new IllegalStateException("the copy of /etc has only " + entries
                    + " entries: not credible, I stop");
            job.write("    /etc -> " + bk + "/etc.tar " + I18n.tr("server.um.x.entries", java.util.Map.of("n", String.valueOf(entries))));
            sh("pkg query '%n %v' > " + bk + "/packages.txt 2>/dev/null", 120);
            sh("freebsd-version -kru > " + bk + "/version.txt 2>/dev/null", 30);
            StringBuilder el = new StringBuilder();
            JSONArray sv = pf.optJSONArray("services");
            for (int i = 0; sv != null && i < sv.length(); i++)
                el.append(sv.getJSONObject(i).getString("name")).append(' ')
                  .append(sv.getJSONObject(i).getBoolean("active") ? "active" : "stopped").append('\n');
            Files.writeString(Paths.get(bk + "/services.txt"), el.toString());
            job.write(I18n.tr("server.um.runSystemPreparation.3"));

            job.advance(3, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runSystemPreparation.4", java.util.Map.of("total", String.valueOf(TOT))));
            String beName = BE_PREFIX + target.replace(".", "") + "-" + ts;
            if (!pf.optBoolean("bootEnvironment", false)) {
                job.write(I18n.tr("server.um.runSystemPreparation.5"));
                job.write(I18n.tr("server.um.runSystemPreparation.6"));
            } else if (ok("bectl create " + beName, 300)) {
                boolean c1 = ok("bectl list -H 2>/dev/null | grep -q '^" + beName + "'", 30);
                job.write("    " + (c1 ? I18n.tr("server.um.x.beCreatedOk", java.util.Map.of("be", String.valueOf(beName))) : I18n.tr("server.um.x.beCreatedMissing", java.util.Map.of("be", String.valueOf(beName)))));
                if (!c1) throw new IllegalStateException("the boot environment does not appear to have been created: I stop");
                job.write(I18n.tr("server.um.runSystemPreparation.8", java.util.Map.of("beName", String.valueOf(beName))));
                job.write("");
                for (String l : sh("bectl list 2>/dev/null", 60).split("\n")) job.write("      " + l);
            } else throw new IllegalStateException("bectl create failed: without a way back I do not go on");

            job.advance(4, TOT);
            job.write("");
            job.write(I18n.tr("server.um.runSystemPreparation.9", java.util.Map.of("total", String.valueOf(TOT))));
            job.write(I18n.tr("server.um.runSystemPreparation.10"));
            String fetch = sh("freebsd-update --not-running-from-cron fetch 2>&1", 1800);
            for (String l : fetch.split("\n")) if (!l.trim().isEmpty()) job.write("      " + l);
            boolean none = fetch.toLowerCase().contains("no updates needed")
                    || fetch.toLowerCase().contains("has no updates available");
            if (none) {
                job.write(I18n.tr("server.um.runSystemPreparation.11"));
            } else {
                StringBuilder cat = new StringBuilder();
                runLogged(job, "freebsd-update install 2>&1", 1800, cat);
                // Il criterio e' quello dell'Handbook: kernel INSTALLATO contro kernel IN
                // ESECUZIONE. Cercare la parola "kernel" nell'output era una supposizione, e
                // il 31/08/2026 non ha visto un caso in cui il riavvio serviva davvero: il
                // pannello ha stampato "p13 / p0 / p13" e non ha detto niente. Avere il dato
                // e non trarne la conclusione e' come non averlo.
                JSONObject afterJ = operatingSystem();
                job.write("    " + I18n.tr("server.um.x.kernelInstalled", java.util.Map.of("k", String.valueOf(afterJ.optString("installedKernel")))));
                job.write("    " + I18n.tr("server.um.x.kernelRunning", java.util.Map.of("k", String.valueOf(afterJ.optString("uname")))));
                job.write("    userland:             " + afterJ.optString("userland"));
                if (afterJ.optBoolean("restartNeeded")) {
                    job.write("");
                    job.write(I18n.tr("server.um.runSystemPreparation.12"));
                    job.write(I18n.tr("server.um.runSystemPreparation.13"));
                    job.write(I18n.tr("server.um.runSystemPreparation.14"));
                    job.write(I18n.tr("server.um.runSystemPreparation.15"));
                    job.write(I18n.tr("server.um.runSystemPreparation.16"));
                } else {
                    job.write(I18n.tr("server.um.runSystemPreparation.17"));
                }
            }

            job.status = "completed";
            job.write("");
            job.write("=== " + I18n.tr("server.um.x.prepDone") + " ===");
            job.write(I18n.tr("server.um.runSystemPreparation.18", java.util.Map.of("backup", String.valueOf(bk), "beName", String.valueOf(beName))));
            job.write(I18n.tr("server.um.runSystemPreparation.19"));
            job.write(I18n.tr("server.um.runSystemPreparation.20"));
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.finishedAt = System.currentTimeMillis();
        }
    }

    /**
     * Le istruzioni per la parte che una persona deve fare da SSH, sui valori veri.
     *
     * Non e' un rinvio: e' il riconoscimento che quella parte chiede decisioni. freebsd-update
     * puo' aprire un editor per fondere file di /etc — su questo server sono master.passwd,
     * rc.conf, i file di Postfix — e una fusione decisa da un automatismo e' il modo di rompere
     * qualcosa senza che nessuno se ne accorga. La sequenza e' quella dell'Handbook, capitolo
     * "Updating and Upgrading FreeBSD".
     */
    public static JSONObject systemUpgradeInstructions(String target) {
        try {
            if (target == null || !target.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.systemUpgradeInstructions.1"));
            JSONObject pf = systemUpgradePreflight(target);
            String be = lastPanelBootEnvironment(sh("bectl list -H 2>/dev/null", 30));
            String startup = startCommand(false);
            String dir = System.getProperty("user.dir", "/home/panel");
            boolean minor = pf.optBoolean("minorJump", true);

            // Le istruzioni devono sapere se il pannello torna su da solo, altrimenti dicono
            // il contrario della scheda accanto. Tre stati, non due: c'e' lo script, e' abilitato,
            // ed e' stato provato almeno una volta (il pidfile lo dimostra).
            boolean rcC = pf.optBoolean("rcPanel", false);
            boolean rcA = pf.optBoolean("rcEnabled", false);
            boolean rcP = pf.optBoolean("rcTested", false);
            boolean returnsOnly = rcC && rcA;

            JSONArray steps = new JSONArray();
            steps.put(new JSONObject().put("n", 1)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.3"))
                .put("cmd", "freebsd-update -r " + target + "-RELEASE upgrade")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.4")));
            steps.put(new JSONObject().put("n", 2)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.5"))
                .put("cmd", "freebsd-update install")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.6")));
            steps.put(new JSONObject().put("n", 3)
                .put("title", I18n.tr("server.um.x.restart"))
                .put("cmd", "shutdown -r now")
                .put("note", returnsOnly
                    ? (rcP
                       ? I18n.tr("server.um.x.rcBackTested")
                       : I18n.tr("server.um.x.rcBackUntested", java.util.Map.of("dir", String.valueOf(dir), "startup", String.valueOf(startup))))
                    : I18n.tr("server.um.systemUpgradeInstructions.7")));
            steps.put(new JSONObject().put("n", 4)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.8"))
                .put("cmd", "freebsd-update install")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.9")));
            if (minor) {
                steps.put(new JSONObject().put("n", 5)
                    .put("title", I18n.tr("server.um.systemUpgradeInstructions.10"))
                    .put("cmd", I18n.tr("server.um.systemUpgradeInstructions.11"))
                    .put("note", I18n.tr("server.um.x.abiStays", java.util.Map.of("abi", String.valueOf(pf.optString("abiName"))))));
            } else {
                steps.put(new JSONObject().put("n", 5)
                    .put("title", I18n.tr("server.um.x.reinstallAll"))
                    .put("cmd", "pkg-static upgrade -f")
                    .put("note", I18n.tr("server.um.systemUpgradeInstructions.12")));
            }
            steps.put(new JSONObject().put("n", 6)
                .put("title", I18n.tr("server.um.x.lastFuCall"))
                .put("cmd", "freebsd-update install")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.13")));
            steps.put(new JSONObject().put("n", 7)
                .put("title", I18n.tr("server.um.systemUpgradeInstructions.14"))
                .put("cmd", "shutdown -r now")
                .put("note", I18n.tr("server.um.systemUpgradeInstructions.15", java.util.Map.of("target", String.valueOf(target)))));
            steps.put(new JSONObject().put("n", 8)
                .put("title", returnsOnly ? I18n.tr("server.um.x.checkTitle") : I18n.tr("server.um.systemUpgradeInstructions.16"))
                .put("cmd", returnsOnly ? I18n.tr("server.um.systemUpgradeInstructions.17") : "cd " + dir + " && " + startup)
                .put("note", returnsOnly
                    ? I18n.tr("server.um.systemUpgradeInstructions.18", java.util.Map.of("dir", String.valueOf(dir), "startup", String.valueOf(startup)))
                    : I18n.tr("server.um.systemUpgradeInstructions.19")));

            return new JSONObject().put("success", true).put("steps", steps)
                .put("target", target)
                .put("rcActive", returnsOnly).put("rcTested", rcP)
                .put("returnInfo", be.isEmpty()
                    ? I18n.tr("server.um.systemUpgradeInstructions.20")
                    : I18n.tr("server.um.systemUpgradeInstructions.21", java.util.Map.of("be", String.valueOf(be))))
                .put("source", I18n.tr("server.um.systemUpgradeInstructions.22"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * Verifica dopo il salto di release, confrontando con cio' che era stato annotato PRIMA.
     *
     * "Il sistema si e' acceso" non e' una verifica: un servizio puo' non essere ripartito e
     * nessuno accorgersene finche' qualcuno non prova a mandare una mail. Qui si confronta con
     * l'inventario preso dalla preparazione — versione, pacchetti, servizi — perche' un
     * confronto ha bisogno di due termini, e il primo va preso quando le cose funzionavano.
     */
    // ===================== proseguimento guidato del salto di release =====================

    /** Dove il pannello ricorda a che punto e' del salto, per ritrovarlo dopo un riavvio. */
    private static final String VERSION_JUMP_STATE = "/var/db/mailpanel/system/version-jump.json";

    /**
     * Cosa dice di fare freebsd-update, letto da chi lo esegue invece che dall'utente.
     *
     * freebsd-update non ha un codice di uscita che distingua "finito" da "riavvia e richiamami":
     * lo scrive in inglese, in fondo all'output, e finora quella riga la leggeva Pietro. Le tre
     * frasi qui sotto sono quelle che stampa davvero, viste sul server il 31/08/2026:
     *   - "Kernel updates have been installed.  Please reboot and run ... again"
     *   - "No updates are available to install."
     *   - "Installing updates... done."
     * Nel dubbio si torna "again", cioe' si riesegue: rieseguire quando non serve costa un
     * comando e non fa danni, fermarsi troppo presto lascia il sistema a meta'.
     */
    static String whatFreebsdUpdateAsks(String output) {
        String u = output == null ? "" : output.toLowerCase();
        if (u.contains("please reboot")) return "restart";
        // Questa e' una richiesta DIVERSA dal "rieseguimi", e sta nello stesso messaggio:
        // "Completing this upgrade requires removing old shared object files. Please rebuild
        // all installed 3rd party software ... and then run 'freebsd-update install' again."
        // Il 31/08/2026 il pannello ha visto solo la seconda meta' e ha proseguito in silenzio,
        // mentre la prima meta' chiedeva di ricostruire i pacchetti. Due istruzioni in una
        // frase: leggerne una sola e' peggio che non leggerne nessuna.
        if (u.contains("rebuild all installed 3rd party software")
                || u.contains("removing old shared object files")) return "rebuild";
        if (u.contains("no updates are available to install")
                || u.contains("no updates needed")) return "finished";
        if (u.contains("run '/usr/sbin/freebsd-update install'")
                || u.contains("run 'freebsd-update")) return "again";
        return "again";
    }

    private static JSONObject readJumpState() {
        try {
            if (!ok("test -f " + VERSION_JUMP_STATE, 10)) return new JSONObject();
            return upgradeOldJumpState(new JSONObject(Files.readString(Paths.get(VERSION_JUMP_STATE))));
        } catch (Exception e) { return new JSONObject(); }
    }

    // Le chiavi e i valori che lo stato del salto aveva prima del 24 e del 29/10/2026 stanno nel
    // file di dati (LegacyNames: jumpKeys, jumpStepKeys, jumpAsks, jumpPhases), non qui.

    /** Il prefisso dei boot environment che il pannello crea prima di un salto di release. */
    static final String BE_PREFIX = "before-";

    /**
     * Un boot environment creato dal pannello: col prefisso di adesso o con quello delle versioni
     * di prima (file di dati), che sui server gia' avviati c'e' ancora.
     */
    static boolean panelBootEnvironment(String name) {
        if (name.startsWith(BE_PREFIX)) return true;
        for (String old : LegacyNames.oldNamesOf("bootEnvironmentPrefix", BE_PREFIX))
            if (!old.isEmpty() && name.startsWith(old)) return true;
        return false;
    }

    /**
     * La via di ritorno piu' recente, da "bectl list -H": l'ultimo creato col prefisso di adesso
     * e, solo se non ce n'e', l'ultimo col prefisso di prima. Un nome di adesso e' sempre piu'
     * recente di uno di prima, anche se nell'elenco alfabetico viene prima.
     */
    static String lastPanelBootEnvironment(String bectlList) {
        String now = "", before = "";
        for (String line : bectlList == null ? new String[0] : bectlList.split("\n")) {
            String name = line.split("\t")[0].trim();
            if (name.startsWith(BE_PREFIX)) now = name;
            else if (panelBootEnvironment(name)) before = name;
        }
        return now.isEmpty() ? before : now;
    }

    /**
     * "cat" di un file dell'inventario preso prima di un salto: il nome di adesso e, se manca,
     * quelli delle copie fatte dalle versioni di prima (file di dati).
     */
    static String inventoryCat(String dir, String name) {
        StringBuilder c = new StringBuilder("cat " + dir + "/" + name + " 2>/dev/null");
        for (String old : LegacyNames.oldNamesOf("inventoryFiles", name))
            c.append(" || cat ").append(dir).append('/').append(old).append(" 2>/dev/null");
        return c.toString();
    }

    /**
     * Lo stato di un salto scritto dal pannello di prima, letto con i nomi di adesso.
     *
     * Un salto di versione attraversa un riavvio, e il pannello puo' essere aggiornato proprio
     * in mezzo: il file l'ha scritto il codice vecchio, con le chiavi italiane, e lo rilegge il
     * codice nuovo. Senza questa traduzione la fase sembrerebbe vuota, e il salto si
     * dichiarerebbe mai cominciato. Una chiave nuova gia' presente vince: non si sovrascrive.
     */
    static JSONObject upgradeOldJumpState(JSONObject st) {
        for (String[] k : LegacyNames.pairs("jumpKeys"))
            if (st.has(k[0]) && !st.has(k[1])) st.put(k[1], st.remove(k[0]));
        if (st.has("phase")) st.put("phase", LegacyNames.current("jumpPhases", st.optString("phase")));
        JSONArray steps = st.optJSONArray("steps");
        for (int i = 0; steps != null && i < steps.length(); i++) {
            JSONObject s = steps.optJSONObject(i);
            if (s == null) continue;
            for (String[] k : LegacyNames.pairs("jumpStepKeys"))
                if (s.has(k[0]) && !s.has(k[1])) s.put(k[1], s.remove(k[0]));
            if (s.has("asks")) s.put("asks", LegacyNames.current("jumpAsks", s.optString("asks")));
        }
        return st;
    }

    private static void writeJumpState(JSONObject st) {
        try {
            ok("mkdir -p /var/db/mailpanel/system", 20);
            Files.writeString(Paths.get(VERSION_JUMP_STATE), st.toString(2));
        } catch (Exception ignored) { }
    }

    /** Lo stato del salto, per la scheda: a che punto siamo e cosa serve adesso. */
    public static JSONObject versionJumpStatus() {
        JSONObject st = readJumpState();
        JSONObject os = operatingSystem();
        JSONObject r = new JSONObject()
                .put("success", true)
                .put("inProgress", st.has("phase"))
                .put("phase", st.optString("phase", ""))
                .put("target", st.optString("target", ""))
                .put("steps", st.optJSONArray("steps") == null ? new JSONArray() : st.getJSONArray("steps"))
                .put("installedKernel", os.optString("installedKernel"))
                .put("runningKernel", os.optString("uname"))
                .put("userland", os.optString("userland"))
                .put("restartNeeded", os.optBoolean("restartNeeded"));
        // Se aspettavamo un riavvio e il kernel adesso combacia, il riavvio c'e' stato.
        if ("awaiting-restart".equals(st.optString("phase")) && !os.optBoolean("restartNeeded"))
            r.put("restartHappened", true);
        return r;
    }

    public static JSONObject startResumeVersionJump(String target) {
        String id = "jump-" + System.currentTimeMillis();
        Job j = new Job(id, "jump");
        JOBS.put(id, j);
        final String b = target == null || target.isEmpty()
                ? readJumpState().optString("target", "") : target;
        Thread t = localizedThread(j, () -> runJumpContinuation(j, b), "jump-release");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Esegue "freebsd-update install" quante volte serve, leggendo cosa chiede di fare.
     *
     * Non e' un ciclo cieco: dopo ogni esecuzione guarda cosa freebsd-update ha scritto e si
     * comporta di conseguenza — se chiede un riavvio, si ferma, lo annota su disco e programma
     * il riavvio; se dice che non c'e' altro, finisce; altrimenti riesegue. Il tetto di sei giri
     * e' una rete, non una previsione: se ci arriva vuol dire che sta succedendo qualcosa che
     * non avevo previsto, e a quel punto e' giusto fermarsi e mostrarlo.
     */
    private static void runJumpContinuation(Job job, String target) {
        job.status = "running";
        try {
            boolean rebuildRequested = false;
            JSONObject st = readJumpState();
            JSONArray steps = st.optJSONArray("steps") == null ? new JSONArray() : st.getJSONArray("steps");
            if (!target.isEmpty()) st.put("target", target);

            job.write(I18n.tr("server.um.runJumpContinuation.1"));
            JSONObject before = operatingSystem();
            job.write(I18n.tr("server.um.x.kernelLine", java.util.Map.of("k", String.valueOf(before.optString("installedKernel")), "u", String.valueOf(before.optString("uname")), "l", String.valueOf(before.optString("userland")))));
            job.write("");

            if (before.optBoolean("restartNeeded")) {
                job.write(I18n.tr("server.um.runJumpContinuation.2"));
                job.write(I18n.tr("server.um.runJumpContinuation.3"));
                st.put("phase", "awaiting-restart").put("steps", steps);
                writeJumpState(st);
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runJumpContinuation.4");
                return;
            }

            for (int round = 1; round <= 6; round++) {
                job.advance(round, 6);
                job.write("--- freebsd-update install " + I18n.tr("server.um.x.round", java.util.Map.of("n", String.valueOf(round))) + " ---");
                StringBuilder cat = new StringBuilder();
                int code = runLogged(job, "freebsd-update install 2>&1", 3600, cat);
                String asks = whatFreebsdUpdateAsks(cat.toString());
                JSONObject after = operatingSystem();
                steps.put(new JSONObject().put("round", round).put("code", code)
                        .put("asks", asks).put("kernel", after.optString("installedKernel"))
                        .put("userland", after.optString("userland")));
                job.write("");
                job.write("    " + I18n.tr("server.um.x.fuAsks") + " " + (
                        "restart".equals(asks) ? I18n.tr("server.um.x.fuAsksRestart")
                      : "finished".equals(asks)  ? I18n.tr("server.um.x.fuAsksNothing")
                      : "rebuild".equals(asks)
                        ? I18n.tr("server.um.runJumpContinuation.5")
                      : I18n.tr("server.um.runJumpContinuation.6")));
                if ("rebuild".equals(asks)) {
                    rebuildRequested = true;
                    job.write("");
                    job.write(I18n.tr("server.um.runJumpContinuation.7"));
                    job.write(I18n.tr("server.um.runJumpContinuation.8"));
                    job.write(I18n.tr("server.um.runJumpContinuation.9"));
                    job.write(I18n.tr("server.um.runJumpContinuation.10"));
                }
                job.write("    " + I18n.tr("server.um.x.kernelNow", java.util.Map.of("k", String.valueOf(after.optString("installedKernel")), "u", String.valueOf(after.optString("uname")), "l", String.valueOf(after.optString("userland")))));

                if (code != 0 && !"finished".equals(asks)) {
                    st.put("phase", "error").put("steps", steps);
                    writeJumpState(st);
                    job.status = "error";
                    job.errorMessage = I18n.tr("server.um.runJumpContinuation.11", java.util.Map.of("code", String.valueOf(code)));
                    job.write(I18n.tr("server.um.runJumpContinuation.12", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                    return;
                }
                if ("restart".equals(asks)) {
                    st.put("phase", "awaiting-restart").put("steps", steps);
                    writeJumpState(st);
                    job.write("");
                    job.write(I18n.tr("server.um.runJumpContinuation.13"));
                    job.write(I18n.tr("server.um.runJumpContinuation.14"));
                    job.write(I18n.tr("server.um.runJumpContinuation.15"));
                    job.status = "completed";
                    return;
                }
                if ("finished".equals(asks)) {
                    st.put("phase", "finished").put("steps", steps);
                    writeJumpState(st);
                    job.write("");
                    job.write(I18n.tr("server.um.runJumpContinuation.16"));
                    if (after.optBoolean("restartNeeded")) {
                        job.write(I18n.tr("server.um.runJumpContinuation.17"));
                        job.write(I18n.tr("server.um.runJumpContinuation.18"));
                        st.put("phase", "awaiting-final-restart");
                        writeJumpState(st);
                    } else {
                        job.write(I18n.tr("server.um.x.youAreOn", java.util.Map.of("v", String.valueOf(after.optString("userland")))));
                    }
                    // La domanda "vanno ricostruiti i pacchetti?" non si risponde con un'opinione
                    // sull'ABI: si chiede a pkg quali librerie ogni pacchetto pretende e si guarda
                    // se esistono. E' l'unica prova diretta.
                    if (rebuildRequested) {
                        job.write("");
                        job.write("--- " + I18n.tr("server.um.x.fuRebuildCheck") + " ---");
                        JSONObject lib = packagesWithMissingLibraries();
                        JSONArray broken = lib.optJSONArray("packages");
                        int howMany = broken == null ? 0 : broken.length();
                        if (howMany == 0) {
                            job.write(I18n.tr("server.um.runJumpContinuation.19"));
                            job.write(I18n.tr("server.um.runJumpContinuation.20"));
                            job.write(I18n.tr("server.um.runJumpContinuation.21"));
                        } else {
                            job.write(I18n.tr("server.um.runJumpContinuation.22", java.util.Map.of("howMany", String.valueOf(howMany))));
                            for (int i = 0; i < Math.min(howMany, 20); i++)
                                job.write("      " + broken.getJSONObject(i).optString("name")
                                        + "  ->  " + broken.getJSONObject(i).optString("missing"));
                            job.write(I18n.tr("server.um.runJumpContinuation.23"));
                            job.write(I18n.tr("server.um.runJumpContinuation.24"));
                        }
                        st.put("rebuild", howMany == 0 ? I18n.tr("server.um.runJumpContinuation.25") : I18n.tr("server.um.x.neededN", java.util.Map.of("n", String.valueOf(howMany))));
                    }
                    job.write(I18n.tr("server.um.runJumpContinuation.26"));
                    job.status = "completed";
                    return;
                }
            }
            st.put("phase", "too-many-rounds").put("steps", steps);
            writeJumpState(st);
            job.status = "error";
            job.errorMessage = I18n.tr("server.um.runJumpContinuation.27");
            job.write(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.finishedAt = System.currentTimeMillis();
        }
    }

    /**
     * Gli ambienti di avvio, spiegati invece che elencati.
     *
     * "bectl list" e' una tabella per chi sa gia' cosa sta guardando: una colonna Active con
     * sigle (N, R, NR), nomi generati da programmi diversi, e nessuna indicazione di cosa si
     * possa toccare. Rovesciarla in una riga con dei trattini in mezzo, come faceva il pannello,
     * non e' informare: e' spostare il lavoro di capire dall'altra parte.
     *
     * Le sigle, dal manuale di bectl(8): N = quello avviato adesso, R = quello che si avviera'
     * al prossimo riavvio, NR = entrambi. Un trattino vuol dire che sta li' e basta.
     */
    public static JSONObject bootEnvironments() {
        JSONObject r = new JSONObject();
        try {
            if (!ok("bectl check", 20))
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.bootEnvironments.1"));
            JSONArray outside = new JSONArray();
            for (String line : sh("bectl list -H 2>/dev/null", 60).split("\n")) {
                String[] c = line.split("\t");
                if (c.length < 5) continue;
                String name = c[0].trim(), active = c[1].trim(), space = c[3].trim(), created = c[4].trim();
                boolean inUse = active.contains("N");
                boolean atRestart = active.contains("R");

                // Chi l'ha creato si capisce dal nome: il pannello usa BE_PREFIX (o il prefisso
                // delle versioni di prima), e freebsd-update usa <versione>_<data>. Saperlo cambia
                // cosa significa tenerlo.
                String origin, explain;
                if (PackageWayBack.REINSTALL_OWN.matcher(name).matches()) {
                    // La via di ritorno di una reinstallazione completa dal menu: il server di prima,
                    // configurazioni, caselle e database compresi.
                    origin = I18n.tr("server.um.bootEnvironments.reinstallOrigin");
                    explain = I18n.tr("server.um.bootEnvironments.reinstallExplain");
                } else if (PackageWayBack.OWN.matcher(name).matches()) {
                    // La via di ritorno di un lavoro sui pacchetti (PackageWayBack): senza questo
                    // ramo cadeva in "origine non riconosciuta, guardalo prima di toccarlo".
                    origin = I18n.tr("server.um.bootEnvironments.packagesOrigin");
                    explain = I18n.tr("server.um.bootEnvironments.packagesExplain");
                } else if (panelBootEnvironment(name)) {
                    origin = I18n.tr("server.um.bootEnvironments.2");
                    explain = I18n.tr("server.um.bootEnvironments.3");
                } else if (name.matches("^[0-9]+\\.[0-9].*_[0-9]{4}-[0-9]{2}-[0-9]{2}.*")) {
                    origin = I18n.tr("server.um.bootEnvironments.4");
                    explain = I18n.tr("server.um.bootEnvironments.5");
                } else if ("default".equals(name)) {
                    origin = I18n.tr("server.um.bootEnvironments.6");
                    explain = I18n.tr("server.um.bootEnvironments.7");
                } else {
                    origin = I18n.tr("server.um.bootEnvironments.8");
                    explain = I18n.tr("server.um.bootEnvironments.9");
                }

                outside.put(new JSONObject()
                        .put("name", name).put("space", space).put("created", created)
                        .put("inUse", inUse).put("atRestart", atRestart).put("shortName", active)
                        .put("origin", origin).put("explanation", explain)
                        .put("state", inUse && atRestart ? I18n.tr("server.um.bootEnvironments.10")
                                    : inUse ? I18n.tr("server.um.bootEnvironments.11")
                                    : atRestart ? I18n.tr("server.um.bootEnvironments.12")
                                    : I18n.tr("server.um.bootEnvironments.13"))
                        .put("deletable", !inUse && !atRestart)
                        .put("why", inUse || atRestart
                                ? I18n.tr("server.um.bootEnvironments.14")
                                : I18n.tr("server.um.bootEnvironments.15")));
            }
            return r.put("success", true).put("environments", outside)
                    .put("whatTheyAre", I18n.tr("server.um.bootEnvironments.16"))
                    .put("howToGoBack", I18n.tr("server.um.bootEnvironments.17"))
                    .put("whenToDelete", I18n.tr("server.um.bootEnvironments.18"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /**
     * Elimina un ambiente di avvio, ma solo uno che si puo' eliminare.
     *
     * Tre protezioni, e nessuna e' teorica: non si tocca quello in uso (spegneresti il sistema
     * sotto i tuoi piedi), non si tocca quello che partirebbe al prossimo riavvio (il server non
     * si rialzerebbe), e il nome dev'essere uno di quelli che esistono davvero — non una stringa
     * arrivata da fuori. Il controllo non si fida di cio' che chiede il pulsante: rilegge la
     * lista e decide su quella.
     */
    public static JSONObject deleteBootEnvironment(String name) {
        try {
            if (name == null || !name.matches("[A-Za-z0-9._:-]{1,128}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deleteBootEnvironment.1"));
            JSONObject el = bootEnvironments();
            if (!el.optBoolean("success")) return el;
            JSONArray environment = el.getJSONArray("environments");
            JSONObject found = null;
            for (int i = 0; i < environment.length(); i++)
                if (name.equals(environment.getJSONObject(i).getString("name"))) found = environment.getJSONObject(i);
            if (found == null)
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.deleteBootEnvironment.2", java.util.Map.of("name", String.valueOf(name))));
            if (!found.getBoolean("deletable"))
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.x.beNoDelete", java.util.Map.of("name", String.valueOf(name), "state", String.valueOf(found.getString("state")), "why", String.valueOf(found.getString("why")))));

            String output = sh("bectl destroy -F " + name + " 2>&1", 300).trim();
            // La prova e' che non compaia piu' nella lista, non che il comando sia uscito con zero.
            boolean via = !ok("bectl list -H 2>/dev/null | cut -f1 | grep -qx '" + name + "'", 30);
            return new JSONObject().put("success", via).put("name", name)
                    .put("space", found.getString("space"))
                    .put("output", output)
                    .put("note", via
                        ? I18n.tr("server.um.x.beDeleted", java.util.Map.of("name", String.valueOf(name), "space", String.valueOf(found.getString("space"))))
                        : I18n.tr("server.um.deleteBootEnvironment.3"))
                    .put("error", via ? "" : I18n.tr("server.um.deleteBootEnvironment.4", java.util.Map.of("output", String.valueOf(output))));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject verifyAfterUpdate() {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        try {
            String dir = sh("ls -1dt /var/db/mailpanel/system/*/ 2>/dev/null | head -1", 30).trim();
            if (dir.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.verifyAfterUpdate.1"));
            r.put("inventory", dir);

            JSONObject os = operatingSystem();
            String before = sh("(" + inventoryCat(dir, "version.txt") + ") | tr '\n' ' '", 30).trim();
            addCheck(checks, "ver", I18n.tr("server.um.x.version"), "ok",
                    I18n.tr("server.um.x.versionBeforeNow", java.util.Map.of("before", String.valueOf(before), "k", String.valueOf(os.optString("installedKernel")), "l", String.valueOf(os.optString("userland")))));
            if (os.optBoolean("restartNeeded")) {
                addCheck(checks, "restart", I18n.tr("server.um.x.restartTitle"), "wait",
                        I18n.tr("server.um.x.restartMissing", java.util.Map.of("k", String.valueOf(os.optString("installedKernel")), "u", String.valueOf(os.optString("uname")))));
            } else {
                addCheck(checks, "restart", I18n.tr("server.um.x.restartTitle"), "ok",
                        I18n.tr("server.um.verifyAfterUpdate.2"));
            }

            // Servizi: quelli che erano attivi prima devono esserlo adesso.
            java.util.List<String> off = new ArrayList<>(), absent = new ArrayList<>();
            int checked = 0;
            // Una copia fatta prima del 24/10/2026 ha il file e lo stato coi nomi di prima.
            for (String line : sh(inventoryCat(dir, "services.txt"), 30).split("\n")) {
                String[] c = line.trim().split("\\s+");
                if (c.length != 2 || !"active".equals(LegacyNames.current("inventoryServiceStates", c[1]))) continue;
                checked++;
                if (!ok("test -f /usr/local/etc/rc.d/" + c[0] + " -o -f /etc/rc.d/" + c[0], 10)) { absent.add(c[0]); continue; }
                if (!ok("service " + c[0] + " status", 20)) off.add(c[0]);
            }
            addCheck(checks, "services", I18n.tr("server.um.verifyAfterUpdate.3"),
                    (off.isEmpty() && absent.isEmpty()) ? "ok" : "block",
                    (off.isEmpty() && absent.isEmpty())
                    ? I18n.tr("server.um.verifyAfterUpdate.4", java.util.Map.of("checked", String.valueOf(checked)))
                    : I18n.tr("server.um.x.svcMissing", java.util.Map.of("n", String.valueOf(checked))) + " "
                      + (off.isEmpty() ? "" : I18n.tr("server.um.x.svcOff", java.util.Map.of("list", String.valueOf(String.join(", ", off)))) + "  ")
                      + (absent.isEmpty() ? "" : I18n.tr("server.um.x.svcGone", java.util.Map.of("list", String.valueOf(String.join(", ", absent))))));

            // Pacchetti: nessuno deve essere sparito.
            java.util.Map<String, String> now = new java.util.HashMap<>();
            for (String line : sh("pkg query '%n %v' 2>/dev/null", 120).split("\n")) {
                String[] c = line.trim().split("\\s+");
                if (c.length == 2) now.put(c[0], c[1]);
            }
            java.util.List<String> missing = new ArrayList<>(), different = new ArrayList<>();
            int totalBefore = 0;
            // Una copia fatta prima del 29/10/2026 ha il file col nome di prima.
            for (String line : sh(inventoryCat(dir, "packages.txt"), 60).split("\n")) {
                String[] c = line.trim().split("\\s+");
                if (c.length != 2) continue;
                totalBefore++;
                String v = now.get(c[0]);
                if (v == null) missing.add(c[0]);
                else if (!v.equals(c[1])) different.add(c[0] + " " + c[1] + " -> " + v);
            }
            addCheck(checks, "pkg", I18n.tr("server.um.x.packages"), missing.isEmpty() ? "ok" : "block",
                    missing.isEmpty()
                    ? I18n.tr("server.um.x.pkgsNoneGone", java.util.Map.of("before", String.valueOf(totalBefore), "now", String.valueOf(now.size())))
                      + (different.isEmpty() ? "" : ". " + I18n.tr("server.um.x.pkgsChanged", java.util.Map.of("list", String.valueOf(String.join(", ", different)))))
                    : I18n.tr("server.um.x.pkgsGone", java.util.Map.of("n", String.valueOf(missing.size()), "list", String.valueOf(String.join(", ", missing)))));

            // Protezione: dopo un'operazione di questa portata va riconfermata.
            JSONObject st = packagesStatus();
            int inst = st.optInt("installedCount"), lock = st.optInt("lockedCount");
            addCheck(checks, "lock", I18n.tr("server.um.packagePreflight.25"), inst == lock ? "ok" : "wait",
                    I18n.tr("server.um.x.lockOfInst", java.util.Map.of("lock", String.valueOf(lock), "inst", String.valueOf(inst)))
                    + (inst == lock ? "" : ": " + I18n.tr("server.um.x.someUnlocked")));

            // Gli ambienti di avvio: quello vecchio va tenuto finche' non sei sicuro.
            JSONObject be = bootEnvironments();
            if (be.optBoolean("success")) {
                r.put("environments", be);
                JSONArray el = be.getJSONArray("environments");
                int free = 0;
                for (int i = 0; i < el.length(); i++) if (el.getJSONObject(i).getBoolean("deletable")) free++;
                addCheck(checks, "be", I18n.tr("server.um.verifyAfterUpdate.5"), "ok",
                        I18n.tr("server.um.verifyAfterUpdate.6", java.util.Map.of("length", String.valueOf(el.length()), "free", String.valueOf(free))));
            }

            boolean fault = false;
            for (int i = 0; i < checks.length(); i++)
                if ("block".equals(checks.getJSONObject(i).getString("level"))) fault = true;
            return r.put("success", true).put("checks", checks).put("allGood", !fault);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject systemReport() {
        StringBuilder t = new StringBuilder();
        try {
            ok("pkg update -q", 180);
            t.append("=== ").append(I18n.tr("server.um.x.repTitle")).append(" ===\n");
            t.append("data: ").append(sh("date '+%Y-%m-%d %H:%M:%S %Z'", 15)).append('\n');
            t.append("host: ").append(sh("hostname", 15)).append('\n');
            t.append("FreeBSD: ").append(sh("freebsd-version -kru 2>/dev/null | tr '\n' ' '", 20)).append('\n');
            t.append("ABI pkg: ").append(sh("pkg config abi 2>/dev/null", 20)).append('\n');

            JSONObject branch = branchRepositories();
            JSONObject os = operatingSystem();
            t.append("\n--- ").append(I18n.tr("server.um.x.repOs")).append(" ---\n");
            t.append(I18n.tr("server.um.x.repKernel", java.util.Map.of("k", String.valueOf(os.optString("installedKernel")), "u", String.valueOf(os.optString("uname"))))).append('\n');
            t.append(I18n.tr("server.um.x.repUserland", java.util.Map.of("u", String.valueOf(os.optString("userland")), "a", String.valueOf(os.optString("arch"))))).append('\n');
            if (os.optBoolean("restartNeeded"))
                t.append(I18n.tr("server.um.x.repRestartNeeded")).append('\n');
            if (!os.optString("endOfSupport").isEmpty())
                t.append(I18n.tr("server.um.x.repEol", java.util.Map.of("series", String.valueOf(os.optString("series")), "end", String.valueOf(os.optString("endOfSupport")), "note", String.valueOf(os.optString("supportNotes"))))).append('\n');
            else
                t.append(I18n.tr("server.um.x.repEolUnknown")).append('\n');
            t.append(I18n.tr("server.um.x.repSource", java.util.Map.of("f", String.valueOf(os.optString("supportSource"))))).append('\n');
            if (os.has("alreadyReady"))
                t.append(I18n.tr("server.um.x.repFetched", java.util.Map.of("v", String.valueOf(os.optString("alreadyReady"))))).append('\n');
            if (os.has("updatesNote"))
                t.append(os.optString("updatesNote")).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repBranch")).append(" ---\n");
            t.append(branch.optString("branch")).append("   ").append(branch.optString("url")).append('\n');
            t.append(branch.optString("explanation")).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repDefaults")).append(" ---\n");
            JSONArray lines = defaultsConsistency().optJSONArray("lines");
            for (int i = 0; lines != null && i < lines.length(); i++) {
                JSONObject x = lines.getJSONObject(i);
                t.append(String.format(I18n.tr("server.um.systemReport.1"),
                        x.optString("component"), x.optString("defaultValue"),
                        x.optString("installed"), x.optString("outcome")));
                if (x.has("outsideDefault"))
                    t.append("           ").append(I18n.tr("server.um.x.repOutside", java.util.Map.of("v", String.valueOf(x.getString("outsideDefault"))))).append('\n');
            }

            // Due interrogazioni sole, poi si uniscono: e' l'unico modo di non metterci minuti.
            java.util.Map<String, String> inst = new java.util.LinkedHashMap<>(), repo = new java.util.HashMap<>();
            for (String r2 : sh("pkg query '%n %v' 2>/dev/null", 120).split("\n")) {
                String[] c = r2.trim().split("\\s+");
                if (c.length == 2) inst.put(c[0], c[1]);
            }
            for (String r2 : sh("pkg rquery -U '%n %v' 2>/dev/null", 180).split("\n")) {
                String[] c = r2.trim().split("\\s+");
                if (c.length == 2) repo.put(c[0], c[1]);
            }
            String lock = sh("pkg lock -l 2>/dev/null");

            t.append("\n--- ").append(I18n.tr("server.um.x.repStack")).append(" ---\n");
            t.append(String.format("%-28s %-22s %-22s %-9s %s%n",
                    I18n.tr("server.um.x.colPackage"), I18n.tr("server.um.x.colInstalled"), I18n.tr("server.um.systemReport.2"), I18n.tr("server.um.x.colProtected"), I18n.tr("server.um.x.colRole")));
            int different = 0;
            for (java.util.Map.Entry<String, String> e : inst.entrySet()) {
                String role = roleOf(e.getKey());
                if (role == null) continue;
                String available = repo.getOrDefault(e.getKey(), I18n.tr("server.um.x.absentInRepo"));
                boolean diff = !available.equals(e.getValue()) && !I18n.tr("server.um.x.absentInRepo").equals(available);
                if (diff) different++;
                t.append(String.format("%-28s %-22s %-22s %-9s %s%s%n",
                        e.getKey(), e.getValue(), available,
                        locked(lock, e.getKey()) ? I18n.tr("server.um.x.yes") : "NO", role, diff ? I18n.tr("server.um.systemReport.3") : ""));
            }
            t.append(I18n.tr("server.um.x.repNewer", java.util.Map.of("n", String.valueOf(different)))).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repVulns")).append(" ---\n");
            String audit = sh("pkg audit -F 2>&1", 240);
            t.append(audit.isEmpty() ? I18n.tr("server.um.systemReport.4") : audit + "\n");
            t.append("\n").append(I18n.tr("server.um.x.repFixPerPkg")).append('\n');
            Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
            java.util.LinkedHashSet<String> seen = new java.util.LinkedHashSet<>();
            while (mv.find()) seen.add(mv.group(1));
            if (seen.isEmpty()) t.append("  ").append(I18n.tr("server.um.x.repNoPkg")).append('\n');
            for (String n : seen) {
                String cur = inst.getOrDefault(n, "?"), av = repo.getOrDefault(n, I18n.tr("server.um.x.absentInRepo"));
                t.append(String.format(I18n.tr("server.um.systemReport.5"), n, cur, av,
                        I18n.tr("server.um.x.absentInRepo").equals(av) ? I18n.tr("server.um.x.repoUnknownPkg")
                        : av.equals(cur) ? I18n.tr("server.um.x.noFixSameVersion")
                        : I18n.tr("server.um.systemReport.6", java.util.Map.of("av", String.valueOf(av)))));
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repMissingLibs")).append(" ---\n");
            JSONObject lib = packagesWithMissingLibraries();
            JSONArray broken = lib.optJSONArray("packages");
            if (broken == null || broken.length() == 0) {
                t.append(I18n.tr("server.um.x.repLibsOk")).append('\n');
            } else {
                t.append(I18n.tr("server.um.x.repLibsLost", java.util.Map.of("n", String.valueOf(broken.length())))).append('\n');
                for (int i = 0; i < broken.length(); i++)
                    t.append("  ").append(broken.getJSONObject(i).optString("name"))
                     .append("  ->  ").append(broken.getJSONObject(i).optString("missing")).append('\n');
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repBe")).append(" ---\n");
            JSONObject be2 = bootEnvironments();
            if (!be2.optBoolean("success")) t.append(I18n.tr("server.um.x.notAvailable")).append('\n');
            else {
                JSONArray aa = be2.getJSONArray("environments");
                for (int i = 0; i < aa.length(); i++) {
                    JSONObject x = aa.getJSONObject(i);
                    t.append(String.format("  %-40s %-12s %-8s %s%n", x.getString("name"),
                            x.getBoolean("inUse") ? I18n.tr("server.um.x.inUseCaps") : x.getBoolean("atRestart") ? I18n.tr("server.um.systemReport.7") : I18n.tr("server.um.systemReport.8"),
                            x.getString("space"), x.getString("origin")));
                }
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repServices")).append(" ---\n");
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                t.append(String.format("  %-18s %s%n", svc, ok("service " + svc + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runPythonTransition.14")));
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repSpace")).append(" ---\n");
            t.append(sh("df -h / /var /usr 2>/dev/null | sort -u", 30)).append('\n');
            t.append("\n=== ").append(I18n.tr("server.um.x.repEnd")).append(" ===\n");
            return new JSONObject().put("success", true).put("text", t.toString());
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage())
                    .put("partial", t.toString());
        }
    }

    /**
     * Il ramo per la scheda dei predefiniti: lo legge PkgBranch, come la scheda "Ramo dei pacchetti".
     * Prima qui si prendeva il primo indirizzo di pkg.FreeBSD.org, che poteva essere quello dei
     * moduli del kernel, e un ramo misto non si vedeva.
     */
    public static JSONObject branchRepositories() {
        JSONObject st = PkgBranch.state(PkgBranch.real());
        if (!st.optBoolean("success"))
            return new JSONObject().put("success", true).put("branch", I18n.tr("server.um.branchRepositories.1")).put("url", "")
                    .put("explanation", st.optString("error")).put("where", "");
        String url = "";
        JSONArray repo = st.getJSONArray("repository");
        for (int i = 0; i < repo.length(); i++) {
            JSONObject x = repo.getJSONObject(i);
            if (x.optBoolean("enabled") && "packages".equals(x.optString("type"))) { url = x.optString("url"); break; }
        }
        return new JSONObject().put("success", true).put("branch", st.getString("branch")).put("url", url)
                .put("explanation", st.getString("explanation"))
                .put("where", I18n.tr("server.um.branchRepositories.2"));
    }

    public static JSONObject branchStatus() { return PkgBranch.state(PkgBranch.real()); }

    public static JSONObject branchPreview(String target) {
        if (!PkgBranch.BRANCHES.contains(target)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.branchPreview.1"));
        return PkgBranch.preview(PkgBranch.real(), target);
    }

    /**
     * Il cambio di ramo, sul turno dei lavori sui pacchetti: riscrivere da dove pkg prende i
     * pacchetti mentre un altro lavoro li sta installando cambierebbe i pacchetti sotto i suoi piedi.
     */
    public static JSONObject startBranchChange(String target, String fingerprint) {
        if (!PkgBranch.BRANCHES.contains(target)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.branchPreview.1"));
        if (fingerprint == null || !fingerprint.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startBranchChange.1"));
        String id = "branch-" + System.currentTimeMillis();
        Job j = new Job(id, "pkg_branch");
        return startOnTurn(id, j, I18n.tr("server.um.startBranchChange.2", java.util.Map.of("destination", String.valueOf(target))), "pkg-branch", () -> {
            j.status = "running";
            try {
                JSONObject r = PkgBranch.change(PkgBranch.real(), j::write, target, fingerprint);
                if (r.optBoolean("success")) {
                    j.outcome = r.optString("messageText");
                    j.status = "completed";
                } else {
                    j.errorMessage = r.optString("error");
                    j.status = "error";
                }
            } catch (RuntimeException e) {
                j.errorMessage = I18n.tr("server.um.startBranchChange.3", java.util.Map.of("message", String.valueOf(e.getMessage())));
                j.status = "error";
            } finally {
                j.finishedAt = System.currentTimeMillis();
            }
        });
    }

    public static JSONObject defaultsConsistency() {
        JSONArray lines = new JSONArray();
        for (String[] d : DEFAULTS) {
            String installed = sh(d[2], 60).trim().replace("\n", " ");
            String outcome, outside = "";
            if (installed.isEmpty()) {
                outcome = "absent";
            } else if ("base".equals(d[1])) {
                // Il predefinito e' il sistema base: il port installato e' l'anomalia.
                outcome = "port-beside-base";
            } else {
                // Si confrontano TUTTI i valori installati, uno per uno. Cercare se il
                // predefinito compare "da qualche parte" nella stringa era sbagliato: con
                // py311 e py312 insieme trovava py312 e dichiarava tutto coerente, nascondendo
                // proprio la divergenza che la scheda esiste per mostrare. La presenza del
                // predefinito non dimostra l'assenza di altro.
                String expectedDigits = d[1].replaceAll("[^0-9]", "");
                java.util.List<String> nonconforming = new ArrayList<>();
                int conforming = 0;
                for (String tok : installed.split("\\s+")) {
                    if (tok.isBlank()) continue;
                    if (tok.replaceAll("[^0-9]", "").contains(expectedDigits)) conforming++;
                    else nonconforming.add(tok);
                }
                if (nonconforming.isEmpty() && conforming > 0) outcome = "consistent";
                else if (conforming == 0) outcome = "DIVERGES";
                else { outcome = "MIXED"; outside = String.join(", ", nonconforming); }
            }
            JSONObject line = new JSONObject().put("component", d[0]).put("defaultValue", d[1])
                    .put("installed", installed).put("outcome", outcome).put("why", I18n.tr(d[3]));
            if (!outside.isEmpty()) line.put("outsideDefault", outside);

            // "Port installato accanto al sistema base" descrive, non risponde. La domanda che
            // uno si fa leggendola e' una sola: lo posso togliere? Dipende da chi lo richiede,
            // e quello il pannello puo' chiederlo invece di lasciarlo indovinare.
            // Solo per le righe non coerenti, e solo per i valori che sono davvero nomi di
            // pacchetto: per Python la colonna contiene prefissi (py311), non pacchetti, e
            // interrogarli darebbe un vuoto che sembrerebbe "non lo richiede nessuno".
            if (!"consistent".equals(outcome) && !"absent".equals(outcome)) {
                JSONArray who = new JSONArray();
                for (String tok : installed.split("\\s+")) {
                    if (tok.isBlank() || !isValidName(tok)) continue;
                    if (!ok("pkg info -e " + tok, 15)) continue;   // e' un prefisso, non un pacchetto
                    String dependents = sh("pkg query %rn " + tok + " 2>/dev/null", 30).trim();
                    who.put(new JSONObject().put("pkgName", tok)
                            .put("requiredBy", dependents.isEmpty() ? new JSONArray()
                                    : new JSONArray(java.util.List.of(dependents.split("\n")))));
                }
                if (who.length() > 0) line.put("dependents", who);
            }
            lines.put(line);
        }
        return new JSONObject().put("success", true).put("lines", lines)
                .put("branch", branchRepositories())
                .put("source", I18n.tr("server.um.defaultsConsistency.2"))
                .put("caveat", I18n.tr("server.um.defaultsConsistency.3"));
    }

    /**
     * Toglie un client MySQL estraneo e ripristina i file del client corretto.
     *
     * Situazione che lo rende necessario: un "pkg install -f" ha tirato dentro mysql97-client
     * e ne ha sovrascritto 19 file di mysql84-client — i comandi e gli header, NON la libreria
     * condivisa, che infatti e' rimasta quella della 8.4 ed e' il motivo per cui la posta ha
     * continuato a funzionare.
     *
     * L'ordine e' deliberato: prima si rimuove l'estraneo, poi si reinstalla quello giusto.
     * Cosi' qualunque file la rimozione porti via viene rimesso subito dopo. L'ordine inverso
     * lascerebbe la rimozione libera di cancellare cio' che si era appena ripristinato.
     */
    public static JSONObject startForeignClientCleanup(String foreign, String correct) {
        if (!isValidName(foreign) || !isValidName(correct)
                || !foreign.matches("mysql[0-9]+-client") || !correct.matches("mysql[0-9]+-client")) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startForeignClientCleanup.1"));
        }
        String id = "cleanclient-" + System.currentTimeMillis();
        Job j = new Job(id, "clean_client");
        return startOnTurn(id, j, I18n.tr("server.um.startForeignClientCleanup.2"), "clean-client", () -> {
            j.status = "running";
            boolean unlocked = false;
            try {
                j.advance(1, 5);
                j.write(I18n.tr("server.um.startForeignClientCleanup.3", java.util.Map.of("foreign", String.valueOf(foreign), "correct", String.valueOf(correct))));
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.4", java.util.Map.of("foreign", String.valueOf(foreign))));
                String dependents = sh("pkg query %rn " + foreign + " 2>/dev/null", 30).trim();
                if (!dependents.isEmpty()) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.x.someoneDepends", java.util.Map.of("pkg", String.valueOf(foreign), "dependents", String.valueOf(dependents.replace("\n", " "))));
                    j.write("    " + j.errorMessage);
                    return;
                }
                j.write(I18n.tr("server.um.startForeignClientCleanup.5", java.util.Map.of("foreign", String.valueOf(foreign))));
                String libBefore = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.write("    " + I18n.tr("server.um.x.libOwner", java.util.Map.of("p", String.valueOf(libBefore.isEmpty() ? I18n.tr("server.um.x.nobodyP") : libBefore))));

                j.advance(2, 5);
                j.write("");
                j.write("[2/5] " + I18n.tr("server.um.x.removingPkg", java.util.Map.of("pkg", String.valueOf(foreign))));
                for (String l : sh("pkg delete -y " + foreign + " 2>&1", 300).split("\n")) {
                    if (!l.trim().isEmpty()) j.write("    " + l);
                }

                j.advance(3, 5);
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.6", java.util.Map.of("correct", String.valueOf(correct))));
                if (locked(sh("pkg lock -l 2>/dev/null"), correct)) {
                    // Prima l'elenco su disco, poi lo sblocco: se l'elenco non si scrive, non si sblocca.
                    String stateError = PackageQueue.writeState(java.util.List.of(correct));
                    if (stateError != null)
                        throw new IllegalStateException("I could not save the list for the restore, so I do not unlock " + correct + ": " + stateError);
                    // Da qui il finally riprotegge e chiude l'elenco, anche se lo sblocco fallisse a meta'.
                    unlocked = true;
                    if (!ok("pkg unlock -y " + correct, 30)) throw new IllegalStateException("I could not unlock " + correct);
                    j.write("    " + I18n.tr("server.um.x.unlockedTemp"));
                }
                int code = runLogged(j, "pkg install -f -y " + correct + " 2>&1", 900);
                if (code != 0) throw new IllegalStateException("pkg install exited with code " + code);

                j.advance(4, 5);
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.7"));
                String chk = sh("pkg check -s " + correct + " 2>&1", 300);
                long nonconforming = 0;
                for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) nonconforming++;
                j.write(I18n.tr("server.um.startForeignClientCleanup.8", java.util.Map.of("nonconforming", String.valueOf(nonconforming))));
                if (nonconforming > 0) {
                    for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) j.write("      " + l.trim());
                }

                j.advance(5, 5);
                j.write("");
                j.write(I18n.tr("server.um.startForeignClientCleanup.9"));
                String libAfter = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.write("    " + I18n.tr("server.um.x.libOwner", java.util.Map.of("p", String.valueOf(libAfter.isEmpty() ? I18n.tr("server.um.x.nobodyMissing") : libAfter))));
                JSONArray broken = packagesWithMissingLibraries().getJSONArray("packages");
                j.write(I18n.tr("server.um.startForeignClientCleanup.10", java.util.Map.of("length", String.valueOf(broken.length()))));
                String mailbox = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
                boolean postfixOk = true;
                if (mailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                    String q = sh("postmap -q '" + mailbox + "' mysql:/usr/local/etc/postfix/mysql-virtual-mailboxes.cf 2>&1", 60);
                    String ql = q.toLowerCase();
                    postfixOk = !q.trim().isEmpty() && !ql.contains("error") && !ql.contains("fatal")
                            && !ql.contains("not found") && !ql.contains("dlopen") && !ql.startsWith("postmap:");
                    j.write("    " + (postfixOk
                            ? I18n.tr("server.um.x.pfResolveYes", java.util.Map.of("mailbox", String.valueOf(mailbox), "r", String.valueOf(q.trim())))
                            : I18n.tr("server.um.x.pfResolveNo", java.util.Map.of("mailbox", String.valueOf(mailbox), "r", String.valueOf(q.trim())))));
                }
                if (nonconforming == 0 && broken.length() == 0 && !libAfter.isEmpty() && postfixOk) {
                    j.status = "completed";
                    j.write("");
                    j.write(I18n.tr("server.um.startForeignClientCleanup.11"));
                } else {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startForeignClientCleanup.12");
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = e.getMessage();
                j.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                if (unlocked) {
                    boolean r = ok("pkg info -e " + correct, 15) && ok("pkg lock -y " + correct, 30);
                    j.write("");
                    j.write(r ? I18n.tr("server.um.x.reprotectOk", java.util.Map.of("pkg", String.valueOf(correct))) : I18n.tr("server.um.x.reprotectFail", java.util.Map.of("pkg", String.valueOf(correct))));
                    if (r) clearState();
                }
                j.finishedAt = System.currentTimeMillis();
            }
        });
    }

    public static JSONObject startRelinking() {
        String id = "relink-" + System.currentTimeMillis();
        Job j = new Job(id, "relink");
        return startOnTurn(id, j, I18n.tr("server.um.startRelinking.1"), "relink", () -> runRelinking(j));
    }

    /**
     * Reinstalla dal repository i pacchetti rimasti senza la libreria che pretendono, cosi'
     * tornano collegati a quella presente, e rimette in servizio cio' che ne dipende.
     */
    private static void runRelinking(Job job) {
        job.status = "running";
        java.util.List<String> unlockedPackages = new ArrayList<>();
        try {
            job.advance(1, 5);
            job.write(I18n.tr("server.um.runRelinking.1"));
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.2"));
            JSONObject d = packagesWithMissingLibraries();
            JSONArray broken = d.getJSONArray("packages");
            if (broken.length() == 0) {
                job.write(I18n.tr("server.um.runRelinking.3"));
                job.status = "completed";
                return;
            }
            java.util.LinkedHashSet<String> names = new java.util.LinkedHashSet<>();
            for (int i = 0; i < broken.length(); i++) {
                JSONObject o = broken.getJSONObject(i);
                job.write("    " + I18n.tr("server.um.x.requiresMissing", java.util.Map.of("name", String.valueOf(o.getString("name")), "lib", String.valueOf(o.getString("lib")))));
                names.add(o.getString("name"));
            }

            job.advance(2, 5);
            job.write("");
            job.write("[2/5] " + I18n.tr("server.um.x.tempUnlock"));
            String lock = sh("pkg lock -l 2>/dev/null");
            java.util.List<String> toUnlock = new ArrayList<>();
            for (String n : names) if (locked(lock, n)) toUnlock.add(n);
            if (!toUnlock.isEmpty()) {
                // Prima l'elenco su disco, poi lo sblocco: se l'elenco non si scrive, non si sblocca.
                String stateError = PackageQueue.writeState(toUnlock);
                if (stateError != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I did not unlock anything: " + stateError);
                // Da riproteggere tutti, anche uno sblocco fallito: cosi' l'elenco su disco si chiude.
                unlockedPackages.addAll(toUnlock);
                for (String n : toUnlock)
                    job.write("    " + n + ": " + (ok("pkg unlock -y " + n, 30) ? I18n.tr("server.um.x.unlocked") : I18n.tr("server.um.runRelinking.4")));
            } else job.write(I18n.tr("server.um.runRelinking.5"));

            job.advance(3, 5);
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.6"));
            StringBuilder el = new StringBuilder();
            for (String n : names) el.append(' ').append(n);
            // PRIMA una simulazione: se pkg segnala conflitti di file, ci si ferma.
            // "-f" serve a forzare la REINSTALLAZIONE, ma forza anche il passare sopra ai
            // conflitti — e sono due cose diverse. Averle confuse ha fatto sovrascrivere i
            // file del client MySQL 8.4 con quelli di un altro pacchetto.
            String simulation = sh("pkg install -f -n" + el + " 2>&1", 600);
            if (simulation.toLowerCase().contains("conflicts with")) {
                job.write(I18n.tr("server.um.runRelinking.7"));
                for (String l : simulation.split("\n")) {
                    if (l.toLowerCase().contains("conflict")) job.write("      " + l.trim());
                }
                throw new IllegalStateException("the operation would overwrite files of another package: "
                        + "which package must stay has to be decided by hand, not forced.");
            }
            int code = runLogged(job, "pkg install -f -y" + el + " 2>&1", 1800);
            if (code != 0) throw new IllegalStateException("pkg install exited with code " + code);

            job.advance(4, 5);
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.8"));
            java.util.LinkedHashSet<String> services = new java.util.LinkedHashSet<>();
            for (String n : names) services.addAll(servicesToRestart(n));
            for (String logical : services) {
                String real = realServiceName(logical);
                if (real == null) continue;
                String test = testConfigOf(real);
                if (test != null && !Shell.runShell(Duration.ofSeconds(60), test + " 2>&1").success()) {
                    job.write(I18n.tr("server.um.runRelinking.9", java.util.Map.of("real", String.valueOf(real))));
                    continue;
                }
                ok("service " + real + " restart", 120);
                job.write("    " + real + ": " + (ok("service " + real + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigration84.26")));
            }

            job.advance(5, 5);
            job.write("");
            job.write(I18n.tr("server.um.runRelinking.10"));
            JSONArray still = packagesWithMissingLibraries().getJSONArray("packages");
            if (still.length() == 0) {
                job.write(I18n.tr("server.um.runRelinking.11"));
                job.status = "completed";
                job.write("");
                job.write(I18n.tr("server.um.runRelinking.12"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRelinking.13", java.util.Map.of("length", String.valueOf(still.length())));
                for (int i = 0; i < still.length(); i++) {
                    JSONObject o = still.getJSONObject(i);
                    job.write("    " + I18n.tr("server.um.x.stillBroken", java.util.Map.of("name", String.valueOf(o.getString("name")), "lib", String.valueOf(o.getString("lib")))));
                }
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (!unlockedPackages.isEmpty()) {
                job.write("");
                job.write(I18n.tr("server.um.x.reprotecting", java.util.Map.of("n", String.valueOf(unlockedPackages.size()))));
                int n = 0;
                for (String p2 : unlockedPackages) if (ok("pkg info -e " + p2, 15) && ok("pkg lock -y " + p2, 30)) n++;
                job.write("  " + I18n.tr("server.um.x.reprotectedCount", java.util.Map.of("n", String.valueOf(n), "tot", String.valueOf(unlockedPackages.size()))));
                if (n == unlockedPackages.size()) clearState();
            }
            job.finishedAt = System.currentTimeMillis();
        }
    }

    /** @param approvedSignature l'impronta del piano mostrato dall'anteprima: si esegue quello o niente. */
    public static JSONObject startMaintenance(String approvedSignature) {
        if (approvedSignature == null || !approvedSignature.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startMaintenance.1"));
        String id = "maint-" + System.currentTimeMillis();
        Job j = new Job(id, "maintenance");
        return startOnTurn(id, j, I18n.tr("server.um.x.turnMaintenance"), "update-maintenance", () -> runMaintenanceJob(j, approvedSignature));
    }

    /** @param approvedSignature la firma del piano letto nella scheda: si esegue quello o niente. */
    public static JSONObject startUnlockedPackagesUpdate(String approvedSignature) {
        if (approvedSignature == null || !approvedSignature.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startUnlockedPackagesUpdate.2"));
        String id = "upd-" + System.currentTimeMillis();
        Job j = new Job(id, "update");
        return startOnTurn(id, j, I18n.tr("server.um.startUnlockedPackagesUpdate.1"), "update-plain",
                () -> runUpdateJob(j, approvedSignature));
    }

    /** Aggiorna solo cio' che non e' protetto: e' pkg stesso a saltare i pacchetti bloccati. */
    private static void runUpdateJob(Job job, String approvedSignature) {
        job.status = "running";
        // Lo stato dei servizi PRIMA dell'aggiornamento: e' l'unico modo di distinguere un
        // servizio caduto da uno che non era attivo nemmeno prima.
        Map<String, Boolean> servicesBefore = servicesState();
        // Come negli altri due: cio' che gli script fanno a configurazione e indirizzi.
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        final int TOTAL_STEPS = 4;
        job.advance(1, TOTAL_STEPS);
        job.write(I18n.tr("server.um.runUpdateJob.1"));
        job.write(I18n.tr("server.um.runUpdateJob.2"));
        job.write("");
        try {
            // Si esegue il piano che e' stato letto, o niente: come gli altri due lavori.
            JSONObject plan = PackagePlan.fullPlan(java.util.Set.of(), lockedNames(),
                    b -> I18n.tr("server.um.x.staysLockedHere"));
            if (!plan.optBoolean("measured"))
                throw new IllegalStateException("I could not work out the exact plan: "
                        + plan.optString("error", "?"));
            String currentSignature = plan.optString("signature");
            if (!currentSignature.equals(approvedSignature)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runUpdateJob.7");
                job.write(I18n.tr("server.um.runGuidedUpdate.3", java.util.Map.of("approvedSignature", String.valueOf(approvedSignature), "currentSignature", String.valueOf(currentSignature))));
                job.write(I18n.tr("server.um.runUpdateJob.8"));
                job.finishedAt = System.currentTimeMillis();
                return;
            }
            // Come la manutenzione: un piano che non si puo' eseguire non si esegue, e si
            // dice perche'. Senza questo, premere il pulsante su una macchina aggiornata
            // lanciava un pkg upgrade che non faceva niente e si dichiarava riuscito.
            if (!plan.optBoolean("runnable")) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.x.planNotRunnable", java.util.Map.of("errors", String.valueOf(String.join(" | ", jsonArrayToList(plan.getJSONArray("pkgErrors"))))))
                        + (plan.getJSONArray("changes").isEmpty() ? " " + I18n.tr("server.um.x.nothingToUpdate") : "");
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                job.finishedAt = System.currentTimeMillis();
                return;
            }
            // La stessa regola degli altri due: niente rimozioni, niente retrocessioni.
            String destructive = destructivePlanReason(judged(plan));
            if (destructive != null) {
                job.status = "error";
                job.errorMessage = destructive;
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(destructive))));
                job.write(I18n.tr("server.um.x.destructiveByHand"));
                job.finishedAt = System.currentTimeMillis();
                return;
            }
            job.write("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(currentSignature))));
            JSONArray planChanges = plan.getJSONArray("changes");
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                job.write("    " + PackagePlan.typeName(c.getString("type")) + " " + c.getString("name") + " " + c.getString("from")
                        + (c.getString("to").isEmpty() || c.getString("to").equals(c.getString("from")) ? "" : " -> " + c.getString("to")));
            }

            job.advance(2, TOTAL_STEPS);
            job.write("");
            // Come negli altri due: prima si scarica e si ricalcola, perche' il piano dipende
            // da cio' che e' nella cache di pkg (vedi fetchAndRecheck).
            Recheck grown = fetchAndRecheck(job, "pkg upgrade -F -y -U 2>&1", plan,
                    () -> PackagePlan.fullPlan(java.util.Set.of(), lockedNames(),
                            b -> I18n.tr("server.um.x.staysLockedHere")));
            if (grown.stop() != null) throw new IllegalStateException(grown.stop());
            plan = grown.plan();

            Map<String, String> inventoryBefore = PackagePlan.versionsOnly(PackagePlan.installed());
            sideEffects.takeBefore();

            job.advance(3, TOTAL_STEPS);
            job.write("");
            // L'uscita si tiene anche qui, per ripescare alla fine i messaggi degli script.
            StringBuilder captured = new StringBuilder();
            // Chi legge ogni tipo di mappa di Postfix, e il contenuto delle mappe che non si rigenerano
            // dal testo, prima: se dopo la libreria e' cambiata, le mappe si rigenerano uguali a prima.
            PostfixMaps.Before mapsBefore = PostfixMaps.before();
            // -U: lo stesso catalogo su cui e' stato calcolato il piano. Prima era senza, cioe'
            // riscaricava il catalogo e poteva installare versioni diverse da quelle mostrate.
            int code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            // 4 = EX_NEEDRESTART: pkg ha aggiornato se stesso. Le versioni recenti si rilanciano
            // da sole e fanno il resto; se questa si e' fermata li', la si rilancia una volta, uguale.
            if (code == 4) {
                job.write(I18n.tr("server.um.runUpdateJob.3"));
                code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            }

            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.13"));
            boolean planNotFollowed = false;
            JSONArray verification = PackagePlan.verifyOutcome(plan);
            for (int i = 0; i < verification.length(); i++) {
                JSONObject v2 = verification.getJSONObject(i);
                job.write("    " + (v2.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("name", String.valueOf(v2.getString("name")), "expected", String.valueOf(v2.getString("expected")), "found", String.valueOf(v2.getString("found")))));
                if (!v2.getBoolean("ok")) planNotFollowed = true;
            }
            JSONArray outsidePlan = compareWithInventory(job, inventoryBefore, plan,
                    "Update of the unprotected packages");
            // Questo lavoro non riavvia niente: quello che uno script ha scritto entra in
            // vigore al prossimo riavvio del servizio, e va detto prima.
            sideEffects.checkConfig(job, plan, outsidePlan, false);
            // Le mappe DOPO il controllo della configurazione, come nell'aggiornamento guidato: una mappa
            // che il pannello ricostruisce dal contenuto, senza il suo testo accanto, il controllo la
            // prenderebbe per un file cambiato da uno script (misurato sulla VM il 31/10/2026). E anche
            // se pkg e' uscito con un errore: e' proprio quando la macchina puo' essere rimasta a meta'.
            String mapsProblem = PostfixMaps.afterUpgrade(mapsBefore, l -> job.write("  " + l)).problem();
            writeActionMessages(job, captured.toString());

            job.advance(4, TOTAL_STEPS);
            job.write("");
            job.write(I18n.tr("server.um.runUpdateJob.4", java.util.Map.of("code", String.valueOf(code))));
            job.write("");
            job.write(I18n.tr("server.um.runMigration84.31"));
            boolean fallen = fallenServices(job, servicesBefore);
            sideEffects.checkListening(job);
            java.util.List<String> problems = new ArrayList<>();
            if (code != 0) problems.add(I18n.tr("server.um.runUpdateJob.5", java.util.Map.of("code", String.valueOf(code))));
            if (planNotFollowed) problems.add(I18n.tr("server.um.runMaintenanceJob.14"));
            if (!outsidePlan.isEmpty()) problems.add(divergenceMessage(outsidePlan));
            if (fallen) problems.add(I18n.tr("server.um.runUpdateJob.6"));
            if (mapsProblem != null) problems.add(mapsProblem);
            problems.addAll(sideEffects.problems());
            job.status = problems.isEmpty() ? "completed" : "error";
            job.errorMessage = String.join(" ", problems);
        } catch (Exception e) {
            job.status = "error"; job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.finishedAt = System.currentTimeMillis();
        }
    }

    /**
     * Sblocca -> aggiorna -> riprotegge ESATTAMENTE cio' che era protetto.
     * La riprotezione sta in un finally: deve avvenire anche se l'aggiornamento fallisce o
     * solleva un'eccezione. Lasciare i pacchetti sbloccati dopo un errore e' lo scenario
     * peggiore, perche' nessuno se ne accorge finche' un upgrade successivo non porta via
     * un servizio.
     */
    /**
     * Chi resta protetto durante la manutenzione completa, e perche'; e il piano esatto che ne
     * risulta. L'anteprima e il lavoro vero chiamano QUESTA funzione: se la decisione fosse
     * scritta due volte, prima o poi diventerebbe due decisioni diverse, e l'anteprima
     * mostrerebbe un piano che il lavoro non esegue.
     */
    private static JSONObject maintenancePlan(JSONArray lockedPackages) {
        Map<String, String> why = new LinkedHashMap<>();
        for (int i = 0; i < lockedPackages.length(); i++) {
            JSONObject o = lockedPackages.getJSONObject(i);
            if (o.has("advisory") && "wait".equals(o.getJSONObject("advisory").getString("level")))
                why.put(o.getString("name"), I18n.tr("server.um.x.waitAdvisory"));
        }
        // La prova sul campo batte l'avvertenza generica: se la configurazione Dovecot
        // VIVA contiene costrutti che la versione nuova non accetta, quel pacchetto non
        // si sblocca, punto. Non e' un'ipotesi sulla versione, e' cio' che c'e' sul disco.
        JSONObject dc = dovecotCompatibility();
        if (dc.optBoolean("scanned", false) && !dc.optBoolean("compatible24", true)) {
            for (String n : sh("pkg query %n 2>/dev/null | grep -E '^dovecot' ", 20).split("\n")) {
                String t = n.trim();
                if (isValidName(t))
                    why.put(t, I18n.tr("server.um.x.diskConfConstructs", java.util.Map.of("n", String.valueOf(dc.optJSONArray("issues").length()))));
            }
        }
        Set<String> protectedNames = lockedNames();
        Set<String> toUnlock = new TreeSet<>(protectedNames);
        toUnlock.removeAll(why.keySet());
        JSONObject plan = PackagePlan.fullPlan(toUnlock, protectedNames,
                b -> why.containsKey(b.optString("name"))
                        ? I18n.tr("server.um.x.staysProtected", java.util.Map.of("reason", String.valueOf(why.get(b.optString("name")))))
                        : reasonNotToUnlock(b),
                UpdateManager::installedFamilyTwin);
        return new JSONObject().put("plan", plan).put("heldBack", new JSONObject(why))
                .put("protectedNames", new JSONArray(new ArrayList<>(protectedNames)));
    }

    private static void runMaintenanceJob(Job job, String approvedSignature) {
        job.status = "running";
        List<String> toRelock = new ArrayList<>();
        JSONObject plan = null;
        boolean planNotFollowed = false;
        // Il file di stato si cancella solo se l'ha scritto QUESTA esecuzione. Prima si cancellava
        // quando "tutti i pacchetti da riproteggere" erano riprotetti — e con l'elenco vuoto di un
        // rifiuto a partire lo erano sempre: una manutenzione che si rifiutava perche' ne esisteva
        // una interrotta ne cancellava lo stato, cioe' l'elenco che l'avvio usa per riproteggere.
        boolean stateWritten = false;
        Set<String> lockedBefore = new TreeSet<>();
        Map<String, Boolean> servicesBefore = new LinkedHashMap<>();
        // Come negli altri due: cio' che gli script fanno a configurazione e indirizzi. Se il
        // lavoro si ferma prima di pkg upgrade non fotografa niente, e alla fine non dice niente.
        InstallSideEffects.Watch sideEffects = new InstallSideEffects.Watch();
        // La fine la scrive SOLO il finally, come sua ultima riga. Anche i rifiuti a partire qui
        // sotto escono passando dal finally, che scrive ancora la riprotezione e la verifica:
        // con la fine scritta prima del return, il loro esito diventava visibile (vedi
        // Job.visibleStatus) mentre il lavoro stava ancora scrivendo.
        try {
            if (Files.exists(Paths.get(MAINTENANCE_STATE))) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMaintenanceJob.1", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE)));
                job.write(I18n.tr("server.um.runMaintenanceJob.2", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                job.write(I18n.tr("server.um.runMaintenanceJob.3"));
                return;
            }

            job.advance(1, 4);
            job.write(I18n.tr("server.um.runMaintenanceJob.4"));
            job.write("");
            lockedBefore = lockedNames();
            servicesBefore = servicesState();
            job.write(I18n.tr("server.um.x.initialState", java.util.Map.of("n", String.valueOf(lockedBefore.size()))));
            job.write(I18n.tr("server.um.x.svcRunningList", java.util.Map.of("list", String.valueOf(servicesBefore.entrySet().stream()
                    .filter(Map.Entry::getValue).map(Map.Entry::getKey)
                    .collect(java.util.stream.Collectors.joining(", "))))));
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.5"));

            // --- Chi resta protetto, e perche': la stessa funzione dell'anteprima ---
            JSONObject decision = maintenancePlan(lockedUpdates());
            plan = decision.getJSONObject("plan");
            JSONObject why = decision.getJSONObject("heldBack");
            for (String n : new TreeSet<>(why.keySet()))
                job.write("    " + n + "  -> " + I18n.tr("server.um.x.heldBack", java.util.Map.of("reason", String.valueOf(why.getString(n)))));

            // Si esegue il piano che e' stato letto, o niente.
            if (!plan.optBoolean("measured")) {
                throw new IllegalStateException("I could not work out the exact plan: "
                        + plan.optString("error", "?"));
            }
            if (!plan.optString("signature", "").equals(approvedSignature)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMaintenanceJob.6");
                job.write(I18n.tr("server.um.runGuidedUpdate.3", java.util.Map.of("approvedSignature", String.valueOf(approvedSignature), "currentSignature", String.valueOf(plan.optString("signature")))));
                job.write(I18n.tr("server.um.runMaintenanceJob.7"));
                return;
            }
            if (!plan.optBoolean("runnable")) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.x.planNotRunnable", java.util.Map.of("errors", String.valueOf(String.join(" | ", jsonArrayToList(plan.getJSONArray("pkgErrors"))))))
                        + (plan.getJSONArray("changes").isEmpty() ? " " + I18n.tr("server.um.x.nothingToUpdate") : "");
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                return;
            }
            // La stessa regola della scheda di un pacchetto: il pannello non esegue piani
            // che rimuovono o retrocedono pacchetti. Qui mancava, e questo e' il lavoro che
            // si preme per aggiornare tutto.
            String destructive = destructivePlanReason(judged(plan));
            if (destructive != null) {
                job.status = "error";
                job.errorMessage = destructive;
                job.write(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(destructive))));
                job.write(I18n.tr("server.um.x.destructiveByHand"));
                return;
            }
            toRelock.addAll(jsonArrayToList(plan.getJSONArray("unlockedPackages")));
            job.write("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(plan.getString("signature")))));
            JSONArray planChanges = plan.getJSONArray("changes");
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                job.write("    " + PackagePlan.typeName(c.getString("type")) + " " + c.getString("name") + " " + c.getString("from")
                        + (c.getString("to").isEmpty() || c.getString("to").equals(c.getString("from")) ? "" : " -> " + c.getString("to")));
            }
            job.write("  " + I18n.tr("server.um.x.willRelock", java.util.Map.of("n", String.valueOf(toRelock.size()))));
            if (why.length() > 0) {
                job.write("  " + I18n.tr("server.um.x.heldBackN", java.util.Map.of("n", String.valueOf(why.length()))));
                job.write(I18n.tr("server.um.runMaintenanceJob.9"));
            }

            job.advance(2, 4);
            job.write("");
            job.write("[2/4] " + I18n.tr("server.um.x.tempUnlock"));
            // L'elenco si salva PRIMA di sbloccare: se il pannello muore adesso, il ripristino
            // all'avvio sa cosa riproteggere. Se non si scrive, non si sblocca niente.
            if (!toRelock.isEmpty()) {
                String stateError = PackageQueue.writeState(toRelock);
                if (stateError != null) {
                    toRelock.clear();   // non si e' sbloccato niente: niente da riproteggere
                    job.status = "error";
                    job.errorMessage = I18n.tr("server.um.runMaintenanceJob.10", java.util.Map.of("stateError", String.valueOf(stateError)));
                    job.write(I18n.tr("server.um.runMaintenanceJob.11", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                    return;
                }
                stateWritten = true;
                job.write(I18n.tr("server.um.runGuidedUpdate.7", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
            }
            for (String n : toRelock) ok("pkg unlock -y " + n, 30);

            job.advance(3, 4);
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.12"));
            // Come nell'aggiornamento guidato: prima si scarica e si ricalcola, perche' il
            // piano dipende da cio' che e' nella cache di pkg (vedi fetchAndRecheck).
            Recheck grown = fetchAndRecheck(job, "pkg upgrade -F -y -U 2>&1", plan,
                    () -> maintenancePlan(lockedUpdates()).getJSONObject("plan"));
            if (grown.stop() != null) throw new IllegalStateException(grown.stop());
            plan = grown.plan();

            // L'inventario PRIMA, per accorgersi di cio' che cambia senza essere nel piano.
            // Si prende dopo lo scaricamento, a ridosso dell'aggiornamento: lo scaricamento
            // non installa niente, ma l'inventario deve fotografare il momento esatto.
            Map<String, String> inventoryBefore = PackagePlan.versionsOnly(PackagePlan.installed());
            sideEffects.takeBefore();
            // L'uscita si tiene anche qui, per ripescare alla fine i messaggi degli script.
            StringBuilder captured = new StringBuilder();
            // Chi legge ogni tipo di mappa di Postfix, e il contenuto delle mappe che non si rigenerano
            // dal testo, prima: se dopo la libreria e' cambiata, le mappe si rigenerano uguali a prima.
            PostfixMaps.Before mapsBefore = PostfixMaps.before();
            // -U: lo stesso catalogo su cui e' stato calcolato il piano.
            int code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            // 4 = EX_NEEDRESTART: pkg ha aggiornato se stesso. Le versioni recenti si rilanciano
            // da sole e fanno il resto; se questa si e' fermata li', la si rilancia una volta, uguale.
            if (code == 4) {
                job.write(I18n.tr("server.um.runUpdateJob.3"));
                code = runLogged(job, "pkg upgrade -y -U 2>&1", 3600, captured);
            }
            job.write(I18n.tr("server.um.runUpdateJob.4", java.util.Map.of("code", String.valueOf(code))));
            if (code != 0) { job.status = "error"; job.errorMessage = I18n.tr("server.um.runUpdateJob.5", java.util.Map.of("code", String.valueOf(code))); }
            else job.status = "completed";

            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.13"));
            JSONArray verification = PackagePlan.verifyOutcome(plan);
            for (int i = 0; i < verification.length(); i++) {
                JSONObject v = verification.getJSONObject(i);
                job.write("    " + (v.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("name", String.valueOf(v.getString("name")), "expected", String.valueOf(v.getString("expected")), "found", String.valueOf(v.getString("found")))));
                if (!v.getBoolean("ok")) planNotFollowed = true;
            }

            // E dall'altra direzione: ogni differenza fra l'inventario di prima e quello di
            // adesso che il piano non spiega. Il confronto qui sopra scorre il PIANO e non
            // puo' vedere un pacchetto cambiato che nel piano non c'era.
            JSONArray outsidePlan = compareWithInventory(job, inventoryBefore, plan, "Maintenance");
            // La manutenzione non riavvia niente: cio' che uno script ha scritto entra in vigore
            // al prossimo riavvio, ed e' quello che chi legge la lista qui sotto sta per fare.
            sideEffects.checkConfig(job, plan, outsidePlan, false);
            // Le mappe DOPO il controllo della configurazione, come nell'aggiornamento guidato: una mappa
            // che il pannello ricostruisce dal contenuto, senza il suo testo accanto, il controllo la
            // prenderebbe per un file cambiato da uno script (misurato sulla VM il 31/10/2026). E anche
            // se pkg e' uscito con un errore: e' proprio quando la macchina puo' essere rimasta a meta'.
            String mapsProblem = PostfixMaps.afterUpgrade(mapsBefore, l -> job.write("  " + l)).problem();

            // I problemi si sommano al messaggio che c'e' gia' (per esempio l'uscita di pkg
            // diversa da zero): nessuno dei tre deve coprire gli altri.
            java.util.List<String> problems = new ArrayList<>();
            if (planNotFollowed) problems.add(I18n.tr("server.um.runMaintenanceJob.14"));
            if (!outsidePlan.isEmpty()) problems.add(divergenceMessage(outsidePlan));
            if (mapsProblem != null) problems.add(mapsProblem);
            if (!problems.isEmpty()) {
                job.status = "error";
                job.errorMessage = (job.errorMessage == null || job.errorMessage.isEmpty()
                        ? "" : job.errorMessage + " ") + String.join(" ", problems);
            }

            // Aggiornare un pacchetto non aggiorna il processo che lo usa: finche' non riparte gira
            // sui file vecchi, e la correzione risulta installata senza essere in servizio. La
            // manutenzione completa non riavvia niente da sola (lo fa l'aggiornamento guidato, un
            // pacchetto alla volta), ma dice esattamente chi va riavviato.
            java.util.LinkedHashSet<String> toRestart = new java.util.LinkedHashSet<>();
            for (int i = 0; i < planChanges.length(); i++) {
                JSONObject c = planChanges.getJSONObject(i);
                if ("remove".equals(c.getString("type"))) continue;
                for (String logical : servicesToRestart(c.getString("name"))) {
                    String real = realServiceName(logical);
                    if (real != null) toRestart.add(real);
                }
            }
            if (!toRestart.isEmpty()) {
                job.write("");
                job.write(I18n.tr("server.um.x.toRestart", java.util.Map.of("list", String.valueOf(String.join(", ", toRestart)))));
                job.write(I18n.tr("server.um.runMaintenanceJob.15"));
            }
            writeActionMessages(job, captured.toString());

        } catch (Exception e) {
            job.status = "error"; job.errorMessage = e.getMessage();
            job.write(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // La riprotezione avviene SEMPRE, qualunque cosa sia andata storta sopra.
            job.advance(4, 4);
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.16"));
            int done = 0;
            for (String n : toRelock) {
                if (ok("pkg info -e " + n, 15) && ok("pkg lock -y " + n, 30)) done++;
                else job.write(I18n.tr("server.um.runMaintenanceJob.17", java.util.Map.of("n", String.valueOf(n))));
            }
            job.write("  " + I18n.tr("server.um.x.reprotectedCount", java.util.Map.of("n", String.valueOf(done), "tot", String.valueOf(toRelock.size()))));
            if (done == toRelock.size()) { if (stateWritten) clearState(); }
            else {
                job.write(I18n.tr("server.um.runMaintenanceJob.18"));
                job.write(I18n.tr("server.um.runPythonTransition.21", java.util.Map.of("stateFile", String.valueOf(MAINTENANCE_STATE))));
            }

            // === Verifica del proprio operato: non basta aver eseguito i passi. ===
            job.write("");
            job.write(I18n.tr("server.um.runMaintenanceJob.19"));
            boolean alarm = false;

            Set<String> lockedAfter = lockedNames();
            Set<String> missing = new TreeSet<>(lockedBefore);
            missing.removeAll(lockedAfter);
            if (missing.isEmpty()) {
                job.write(I18n.tr("server.um.runMaintenanceJob.20", java.util.Map.of("size", String.valueOf(lockedAfter.size()))));
            } else {
                alarm = true;
                job.write("  " + I18n.tr("server.um.x.protLost", java.util.Map.of("list", String.valueOf(String.join(", ", missing)))));
            }

            // Questo confronto era giusto solo qui, e scritto a mano: adesso e' lo stesso
            // che usano gli altri tre lavori.
            if (fallenServices(job, servicesBefore)) alarm = true;

            // E la configurazione e gli indirizzi: nessuno dei due conti sopra li vede.
            sideEffects.checkListening(job);
            java.util.List<String> effects = sideEffects.problems();
            if (!effects.isEmpty()) {
                alarm = true;
                job.errorMessage = (job.errorMessage == null || job.errorMessage.isEmpty()
                        ? "" : job.errorMessage + " ") + String.join(" ", effects);
            }

            if (alarm) {
                job.status = "error";
                if (job.errorMessage == null || job.errorMessage.isEmpty()) {
                    job.errorMessage = I18n.tr("server.um.runMaintenanceJob.24");
                }
            } else if ("completed".equals(job.status)) {
                job.write("");
                job.write(I18n.tr("server.um.runMaintenanceJob.25"));
            }
            job.finishedAt = System.currentTimeMillis();
        }
    }
}
