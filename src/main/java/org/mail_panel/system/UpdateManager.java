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

    /** Elenco dei pacchetti unlockedPackages durante una manutenzione, per rimetterli a posto dopo un crash. */
    private static final String MAINTENANCE_STATE = PackageQueue.STATE_PATH;

    private UpdateManager() {}

    // ===================== esecuzione comandi =====================

    /** Comando shell, output completo. Timeout esplicito: un pkg che non torna bloccherebbe un thread HTTP. */
    private static String sh(String cmd, int secondi) {
        return Shell.runShell(Duration.ofSeconds(secondi), cmd).outputTrim();
    }

    private static String sh(String cmd) { return sh(cmd, 60); }

    private static boolean ok(String cmd, int secondi) {
        return Shell.runShell(Duration.ofSeconds(secondi), cmd).success();
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
    private static boolean bloccato(String elencoLock, String nome) {
        for (String riga : elencoLock.split("\n")) {
            String t = riga.trim();
            if (t.isEmpty() || t.endsWith(":")) continue;   // "Currently locked packages:"
            if (t.equals(nome)) return true;
            // In "nome-versione" il taglio e' UNO SOLO: l'ultimo trattino, e cio' che segue
            // dev'essere una versione, cioe' cominciare con una cifra. Provando ogni trattino
            // "php84-curl-8.4.24" produceva anche il prefisso "php84", e il pannello
            // dichiarava protetto php84 per colpa di una sua estensione. Le versioni dei port
            // FreeBSD non contengono trattini (8.4.24, 1.7.2,1, 1.1.0_8, 25.0.3+9.f.1),
            // quindi un taglio solo basta ed e' esatto.
            int d = t.lastIndexOf('-');
            if (d > 0 && d + 1 < t.length() && Character.isDigit(t.charAt(d + 1))
                    && t.substring(0, d).equals(nome)) return true;
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
        {"^dovecot[0-9]*$",            "IMAP/POP3 (Dovecot)"},
        {"^dovecot[0-9]*-pigeonhole(-.*)?$", "server.um.role.sieve"},
        {"^dovecot[0-9]*-.*$",         "server.um.role.dovecotPart"},
        {"^rspamd$",                   "server.um.role.rspamd"},
        {"^redis(-.*)?$",              "server.um.bloccato.1"},
        {"^clamav(-.*)?$",             "Antivirus"},
        {"^roundcube(-php[0-9]+)?$",   "Webmail (Roundcube)"},
        {"^nginx(-.*)?$",              "server.um.bloccato.2"},
        {"^php[0-9]+$",                "PHP"},
        {"^php[0-9]+-.+$",             "server.um.role.phpExt"},
        {"^mysql[0-9]+-server$",       "Database (server)"},
        {"^mysql[0-9]+-client$",       "Database (client)"},
        {"^py[0-9]+-fail2ban$",        "server.um.role.fail2ban"},
        {"^(py[0-9]+-)?certbot$",      "server.um.bloccato.3"},
        {"^unbound$",                  "server.um.role.unbound"},
        {"^opendkim$",                 "server.um.role.opendkim"},
        {"^openssl[0-9]*$",            "server.um.role.openssl"},
        {"^openjdk[0-9]*$",            "server.um.bloccato.4"},
    };

    /** Ruolo del pacchetto nello stack di posta, o null se non lo riguarda. */
    private static String ruoloDi(String nome) {
        for (String[] r : ROLES) if (nome.matches(r[0])) return I18n.tr(r[1]);
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

    /** Quali servizi risultano attivi adesso. Solo quelli davvero presenti sul sistema. */
    private static Map<String, Boolean> statoServizi() {
        Map<String, Boolean> m = new LinkedHashMap<>();
        for (String[] candidati : SERVICES) {
            // Un servizio non installato non e' "caduto": va distinto, altrimenti la verifica
            // finale segnalerebbe come guasto qualcosa che non c'e' mai stato. La presenza si
            // decide dallo script rc.d, non dall'esito di "status": quello e' diverso da zero
            // sia per un servizio spento sia per uno inesistente, e confonderebbe i due casi.
            for (String s : candidati) {
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
        Map<String, String> versioni = new LinkedHashMap<>();
        for (String riga : sh("pkg query '%n %v' 2>/dev/null", 30).split("\n")) {
            int sp = riga.indexOf(' ');
            if (sp > 0) versioni.put(riga.substring(0, sp).trim(), riga.substring(sp + 1).trim());
        }

        JSONArray arr = new JSONArray();
        int protetti = 0, totali = 0;
        for (Map.Entry<String, String> e : versioni.entrySet()) {
            String nome = e.getKey();
            if (!isValidName(nome)) continue;
            String ruolo = ruoloDi(nome);
            if (ruolo == null) continue;
            boolean lk = bloccato(lock, nome);
            totali++;
            if (lk) protetti++;
            arr.put(new JSONObject()
                    .put("name", nome).put("role", ruolo)
                    .put("version", e.getValue()).put("locked", lk).put("installed", true));
        }
        r.put("success", true).put("packages", arr)
         .put("installedCount", totali).put("lockedCount", protetti);
        return r;
    }

    /**
     * Protegge o sblocca i pacchetti. Aspetta il turno dei lavori sui pacchetti: cambiare le
     * protezioni mentre un lavoro le ha tolte e le deve rimettere falserebbe il suo ripristino.
     * Con l'elenco di un lavoro interrotto su disco invece si puo': rimettere le protezioni e'
     * proprio il rimedio.
     */
    public static JSONObject packagesLock(boolean blocca, String soloQuesto) {
        String id = "lock-" + System.nanoTime();
        String rifiuto = PackageQueue.prendiPerLeProtezioni(id, I18n.tr("server.um.packagesLock.1"));
        if (rifiuto != null) return new JSONObject().put("success", false).put("error", rifiuto);
        try {
            JSONObject esito = cambiaProtezioni(blocca, soloQuesto);
            // La nota sulla macchina dice lo stato di adesso: se un amministratore sblocca
            // dal pannello, la nota non deve continuare a elencare quel pacchetto.
            scriviNotaDeiBlocchi();
            return esito;
        }
        finally { PackageQueue.rilascia(id); }
    }

    private static JSONObject cambiaProtezioni(boolean blocca, String soloQuesto) {
        if (!soloQuesto.isEmpty() && !isValidName(soloQuesto)) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.cambiaProtezioni.1"));
        }
        StringBuilder log = new StringBuilder();
        int fatti = 0;
        boolean trovato = false;
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            String nome = p.getString("name");
            if (!soloQuesto.isEmpty() && !soloQuesto.equals(nome)) continue;
            trovato = true;
            if (p.getBoolean("locked") == blocca) {
                log.append("  ").append(nome).append(": ").append(I18n.tr("server.um.x.lockAlready")).append("\n");
                continue;
            }
            boolean fatto = ok("pkg " + (blocca ? "lock" : "unlock") + " -y " + nome);
            log.append("  ").append(nome).append(": ")
               .append(fatto ? (blocca ? I18n.tr("server.um.x.lockDone") : I18n.tr("server.um.x.unlockDone")) : I18n.tr("server.um.x.lockFailed")).append("\n");
            if (fatto) { fatti++; ricordaSblocco(nome, !blocca); }
        }
        // Un pacchetto che non e' dello stack (una dipendenza vulnerabile, uno bloccato a mano):
        // la tabella pacchetti lo mostra con il suo pulsante, quindi si blocca o sblocca come gli altri.
        if (!soloQuesto.isEmpty() && !trovato) {
            String[] iv = PackagePlan.installati().get(soloQuesto);
            if (iv == null) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.ov.notInstalled", java.util.Map.of("name", soloQuesto)));
            if ("1".equals(iv[1]) == blocca) log.append("  ").append(soloQuesto).append(": ").append(I18n.tr("server.um.x.lockAlready")).append("\n");
            else {
                boolean fatto = ok("pkg " + (blocca ? "lock" : "unlock") + " -y " + soloQuesto);
                log.append("  ").append(soloQuesto).append(": ")
                   .append(fatto ? (blocca ? I18n.tr("server.um.x.lockDone") : I18n.tr("server.um.x.unlockDone")) : I18n.tr("server.um.x.lockFailed")).append("\n");
                if (fatto) { fatti++; ricordaSblocco(soloQuesto, !blocca); }
            }
        }
        return new JSONObject().put("success", true).put("changed", fatti).put("output", log.toString());
    }

    // ===================== la regola dei blocchi =====================

    /**
     * I pacchetti dello stack di posta restano lockedPackages: e' cosi' che un pkg upgrade, da qui o
     * da SSH, non li sostituisce senza i controlli dell'aggiornamento guidato. Fanno eccezione
     * solo quelli che un amministratore ha sbloccato con il pannello: quella scelta si ricorda
     * (impostazione pkg.unlocked_by_admin) e si rispetta.
     */
    static final String SBLOCCATI_A_MANO = "pkg.unlocked_by_admin";

    static Set<String> sbloccatiAMano() {
        Set<String> r = new TreeSet<>();
        if (org.mail_panel.Main.mailDatabase == null) return r;
        for (String n : org.mail_panel.Main.mailDatabase.getSetting(SBLOCCATI_A_MANO, "").split(","))
            if (isValidName(n.trim())) r.add(n.trim());
        return r;
    }

    /** Ricorda (o dimentica) che un amministratore ha sbloccato questo pacchetto apposta. */
    static synchronized void ricordaSblocco(String nome, boolean sbloccato) {
        if (org.mail_panel.Main.mailDatabase == null) return;
        Set<String> r = sbloccatiAMano();
        if (sbloccato) r.add(nome); else r.remove(nome);
        if (r.isEmpty()) org.mail_panel.Main.mailDatabase.deleteSetting(SBLOCCATI_A_MANO);
        else org.mail_panel.Main.mailDatabase.setSetting(SBLOCCATI_A_MANO, String.join(",", r));
    }

    /**
     * All'avvio: blocca ogni pacchetto dello stack installato e non bloccato, tranne quelli
     * unlockedPackages apposta da un amministratore. Non fa niente se c'e' lo stato di un lavoro
     * interrotto (prima va ripristinato quello) o se il database del pannello non risponde:
     * senza l'elenco degli sblocchi voluti bloccherebbe anche quelli.
     */
    public static String applicaPoliticaBlocchi() {
        if (Files.exists(Paths.get(MAINTENANCE_STATE)) || org.mail_panel.Main.mailDatabase == null) return "";
        Set<String> aMano = sbloccatiAMano();
        List<String> lockedPackages = new ArrayList<>(), falliti = new ArrayList<>();
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            String n = p.getString("name");
            if (p.getBoolean("locked") || aMano.contains(n) || !isValidName(n)) continue;
            if (ok("pkg lock -y " + n)) { lockedPackages.add(n); annotaBlocco(n); } else falliti.add(n);
        }
        // La nota si riscrive a ogni avvio, anche quando non c'era niente da bloccare: dice lo
        // stato di ADESSO, e una nota che resta indietro e' peggio di nessuna nota.
        scriviNotaDeiBlocchi();
        if (lockedPackages.isEmpty() && falliti.isEmpty()) return "";
        String msg = "Mail stack packages locked at startup: " + (lockedPackages.isEmpty() ? "none" : String.join(", ", lockedPackages))
                + (falliti.isEmpty() ? "" : "; could not lock: " + String.join(", ", falliti));
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
    static Path notaBlocchi = Paths.get(LOCK_NOTE);

    /** Il comando che libera tutto, scritto in un punto solo perche' compare in piu' testi. */
    static final String COMANDO_SBLOCCO = "pkg unlock -a -y";

    /**
     * Il testo della nota. Funzione pura: riceve l'elenco e il momento, cosi' si prova.
     *
     * In italiano come gli altri file che il pannello genera sulla macchina (l'override del
     * ramo di pkg, il filtro di fail2ban, la lista permaban): li legge chi amministra il
     * server, non il programma.
     */
    static String notaDeiBlocchi(java.util.Collection<String> bloccati, String quando) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Pacchetti bloccati dal pannello mail FreeBSD\n")
          .append("# Scritto dal pannello il ").append(quando).append(" (UTC). NON modificare a mano:\n")
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
          .append("#     ").append(COMANDO_SBLOCCO).append("\n")
          .append("#\n")
          .append("# Uno solo:  pkg unlock -y <nome>\n")
          .append("# Lo stato vero lo dice sempre: pkg lock -l\n")
          .append("\n");
        if (bloccati.isEmpty()) sb.append("# (nessun pacchetto bloccato)\n");
        for (String n : bloccati) sb.append(n).append('\n');
        return sb.toString();
    }

    /**
     * Scrive la nota con i pacchetti bloccati ADESSO. Se non ce n'e' nessuno, la cancella:
     * una nota che elenca blocchi che non esistono piu' manderebbe a cercare un problema
     * che non c'e'.
     */
    static synchronized void scriviNotaDeiBlocchi() {
        try {
            Set<String> bloccati = new TreeSet<>();
            for (String n : insiemeProtetti()) if (ruoloDi(n) != null) bloccati.add(n);
            Path f = notaBlocchi;
            if (bloccati.isEmpty()) { Files.deleteIfExists(f); return; }
            if (f.getParent() != null) Files.createDirectories(f.getParent());
            String quando = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
            // Scrittura atomica: un file letto a meta' da chi indaga su un server fermo
            // sarebbe un modo di sbagliare proprio nel momento peggiore.
            Path tmp = f.resolveSibling(f.getFileName() + ".tmp");
            Files.writeString(tmp, notaDeiBlocchi(bloccati, quando), StandardCharsets.UTF_8);
            Files.move(tmp, f, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            // La nota e' una spiegazione, non un meccanismo: se non si scrive, il pannello
            // funziona comunque. Ma lo si dice, perche' senza di lei la macchina non spiega
            // piu' i propri blocchi.
            LOGGER.log(Level.WARNING, "Cannot write " + notaBlocchi, e);
        }
    }

    /**
     * L'avviso sui pacchetti che resterebbero bloccati senza il pannello, o "" se non ce
     * n'e' nessuno.
     *
     * Serve dove qualcuno sta togliendo il pannello di mezzo: e' l'unico momento in cui la
     * domanda "e i blocchi?" si pone da se', ed e' il momento in cui nessuno la faceva.
     */
    static String avvisoBlocchiRimasti() {
        Set<String> bloccati = new TreeSet<>();
        for (String n : insiemeProtetti()) if (ruoloDi(n) != null) bloccati.add(n);
        if (bloccati.isEmpty()) return "";
        return I18n.tr("server.um.x.locksStayWarning", java.util.Map.of(
                "n", String.valueOf(bloccati.size()), "cmd", COMANDO_SBLOCCO, "file", LOCK_NOTE));
    }

    /**
     * Annota sul pacchetto, nel database di pkg, chi l'ha bloccato e dove sta scritto il
     * perche'. E' il cartello nel punto in cui qualcuno si fa la domanda: chi vede
     * "nginx-1.30.6,3 is locked and may not be modified" e indaga con `pkg info -A nginx`
     * trova la riga, e la riga rimanda alla nota.
     *
     * Misurato sulla VM il 23/10/2026: `pkg annotate -y -A` scrive e `pkg info -A` mostra.
     * Si annota solo cio' che si e' appena bloccato, quindi a regime non costa niente.
     */
    private static void annotaBlocco(String nome) {
        String cmd = comandoAnnotazione(nome);
        if (cmd != null) ok(cmd, 20);
    }

    /** La chiave dell'annotazione nel database di pkg. */
    static final String CHIAVE_ANNOTAZIONE = "mail_panel_lock";

    /**
     * Il comando che scrive l'annotazione, o null se il nome non passa il filtro.
     *
     * Sta in una funzione sua perche' il valore contiene spazi, un percorso e un trattino
     * lungo: e' una riga di comando, e una riga di comando si prova eseguendola, non
     * leggendola. In questo progetto un apice dentro un testo e' gia' passato intatto
     * attraverso un here-document per rompere piu' in la'.
     */
    static String comandoAnnotazione(String nome) {
        if (!isValidName(nome)) return null;
        return "pkg annotate -y -A " + nome + " " + CHIAVE_ANNOTAZIONE
             + " 'bloccato dal pannello mail: vedi " + LOCK_NOTE
             + " - si libera con " + COMANDO_SBLOCCO + "'";
    }

    // ===================== il quadro dei pacchetti =====================

    /**
     * Il quadro unico dei pacchetti per la pagina Aggiornamenti: per ognuno versione
     * installata e del catalogo, blocco, vulnerabilita' con il verdict sulla fix, e se
     * si puo' aggiornare da qui. Sola lettura e senza rete. Dentro: i pacchetti dello stack di
     * posta, piu' ogni altro pacchetto vulnerabile o bloccato; gli altri con un aggiornamento
     * (librerie, dipendenze) solo elencati a parte.
     */
    public static JSONObject packagesOverview() {
        JSONObject r = new JSONObject();
        Map<String, String[]> inst = PackagePlan.installati();
        if (inst.isEmpty()) return r.put("success", false).put("error", I18n.tr("server.um.ov.noPkgDb"));
        Shell.Result ev = PackagePlan.leggiDaAggiornare();
        Map<String, String> agg = PackagePlan.daAggiornare(ev.output());
        if (ev.exitCode() != 0 && agg.isEmpty())
            r.put("catalogError", "pkg version -U -vRL= (" + ev.exitCode() + ")" + (ev.output().isBlank() ? "" : ": " + ev.output().trim()));
        JSONObject corr = PackagePlan.correzioni();
        JSONObject vul = corr.optBoolean("success") ? corr.getJSONObject("pacchetti") : new JSONObject();
        if (!corr.optBoolean("success")) r.put("vulnError", corr.optString("error"));

        String jvm = pacchettoDellaJvm();
        java.util.LinkedHashSet<String> nomi = new java.util.LinkedHashSet<>();
        for (Map.Entry<String, String[]> e : inst.entrySet())
            if (ruoloDi(e.getKey()) != null) nomi.add(e.getKey());
        for (Map.Entry<String, String[]> e : inst.entrySet())
            if (vul.has(e.getKey()) || "1".equals(e.getValue()[1])) nomi.add(e.getKey());

        JSONArray rows = new JSONArray();
        int aggiornabili = 0, vulnerabili = 0, risolvibili = 0, lockedPackages = 0, stackSbloccati = 0;
        boolean riavvioPannello = false;
        for (String n : nomi) {
            String[] iv = inst.get(n);
            String ruolo = ruoloDi(n);
            boolean locked = "1".equals(iv[1]);
            String disp = agg.getOrDefault(n, "");
            JSONObject row = new JSONObject().put("name", n).put("installed", iv[0]).put("available", disp)
                    .put("update", !disp.isEmpty()).put("locked", locked).put("stack", ruolo != null)
                    .put("role", ruolo == null ? "" : ruolo);
            if (locked) lockedPackages++;
            if (ruolo != null && !locked) stackSbloccati++;
            String perche = "";
            boolean eJvm = n.equals(jvm);
            if (!disp.isEmpty()) {
                aggiornabili++;
                boolean salto = saltoSignificativo(n, iv[0], disp);
                row.put("majorJump", salto);
                JSONObject ad = avvertenzaPer(n, salto);
                if (ad != null) {
                    row.put("advisory", ad);
                    if ("attendi".equals(ad.optString("level"))) perche = ad.optString("text");
                }
            }
            if (eJvm) {
                row.put("panelRuntime", true).put("inUse", I18n.tr("server.um.ov.panelRuns"));
                // Il JDK del pannello ha la sua procedura: ferma il pannello, aggiorna, riaccende.
                if (!disp.isEmpty()) { perche = I18n.tr("server.um.ov.javaFlow"); row.put("javaFlow", true); }
                String inUso = System.getProperty("java.version", "");
                String pacchetto = iv[0].replaceAll("[+_].*$", "");
                if (!inUso.isEmpty() && !pacchetto.isEmpty() && !pacchetto.equals(inUso)) {
                    riavvioPannello = true;
                    row.put("panelRestart", I18n.tr("server.um.ov.panelRestart", java.util.Map.of("running", inUso, "installed", iv[0])));
                }
            }
            row.put("canUpdate", !disp.isEmpty() && perche.isEmpty()).put("whyNot", perche);
            JSONObject v = vul.optJSONObject(n);
            if (v != null) {
                vulnerabili++;
                if ("si-risolve-aggiornando".equals(v.optString("verdict"))) risolvibili++;
                row.put("vuln", v);
            }
            rows.put(row);
        }
        JSONArray altri = new JSONArray();
        for (Map.Entry<String, String> e : agg.entrySet()) {
            if (nomi.contains(e.getKey()) || !inst.containsKey(e.getKey())) continue;
            altri.put(new JSONObject().put("name", e.getKey()).put("installed", inst.get(e.getKey())[0]).put("available", e.getValue()));
        }
        return r.put("success", true).put("packages", rows).put("others", altri)
                .put("summary", new JSONObject().put("updates", aggiornabili + altri.length()).put("stackUpdates", aggiornabili)
                        .put("vulnerable", vulnerabili).put("fixable", risolvibili).put("locked", lockedPackages)
                        .put("stackUnlocked", stackSbloccati).put("panelRestart", riavvioPannello));
    }

    // ===================== avvertenze specifiche dello stack di posta =====================

    /**
     * Colonne: espressione del nome, livello su salto di versione maggiore, testo.
     *
     * Il livello "attendi" non e' decorativo: la manutenzione automatica NON sblocca i
     * pacchetti che lo portano. Un'avvertenza che si limita a comparire mentre il bottone
     * accanto aggiorna lo stesso non e' un'avvertenza.
     */
    private static final String[][] AVVERTENZE = {
        {"^dovecot.*", "attendi",
         "server.um.cambiaProtezioni.2"},
        {"^roundcube.*", "attendi",
         "server.um.cambiaProtezioni.3"},
        {"^php[0-9]+.*", "attendi",
         "server.um.cambiaProtezioni.4"},
        {"^mysql[0-9]+-server$", "attendi",
         "server.um.cambiaProtezioni.5"},
        {"^mysql[0-9]+-client$", "attendi",
         "server.um.cambiaProtezioni.6"},
        {"^postfix.*", "verifica",
         "server.um.cambiaProtezioni.7"},
        {"^rspamd$", "verifica",
         "server.um.cambiaProtezioni.8"},
        {"^redis.*", "verifica",
         "server.um.cambiaProtezioni.9"},
        {"^clamav.*", "verifica",
         "server.um.cambiaProtezioni.10"},
        {"^nginx.*", "verifica",
         "server.um.cambiaProtezioni.11"},
        {"^py[0-9]+-fail2ban$", "verifica",
         "server.um.cambiaProtezioni.12"},
        {"^(py[0-9]+-)?certbot$", "verifica",
         "server.um.cambiaProtezioni.13"},
        {"^unbound$", "verifica",
         "server.um.cambiaProtezioni.14"},
        {"^openjdk[0-9]*$", "attendi",
         "server.um.cambiaProtezioni.15"},
        {"^openssl[0-9]*$", "verifica",
         "server.um.cambiaProtezioni.16"},
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
    static boolean saltoSignificativo(String nome, String da, String a) {
        int cifre = 1;
        for (String[] r : VERSION_DEPTH) if (nome.matches(r[0])) { cifre = Integer.parseInt(r[1]); break; }
        return !prefissoVersione(da, cifre).equals(prefissoVersione(a, cifre));
    }

    /** Le prime n componenti numeriche di una versione, es. ("2.3.21", 2) -> "2.3". */
    static String prefissoVersione(String v, int n) {
        if (v == null) return "";
        String[] parti = v.split("[._,+~]");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n && i < parti.length; i++) {
            if (i > 0) sb.append('.');
            sb.append(parti[i]);
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

    private static boolean rischioIndipendenteDallaVersione(String nome) {
        for (String r : ALWAYS_WAIT) if (nome.matches(r)) return true;
        return false;
    }

    /** Avvertenza per un pacchetto, o null se non ne ha una specifica. */
    private static JSONObject avvertenzaPer(String nome, boolean saltoMaggiore) {
        for (String[] a : AVVERTENZE) {
            if (!nome.matches(a[0])) continue;
            if (!saltoMaggiore && "attendi".equals(a[1]) && !rischioIndipendenteDallaVersione(nome)) {
                return new JSONObject().put("level", "ok").put("text",
                        I18n.tr("server.um.avvertenzaPer.1"));
            }
            // Un'avvertenza scritta per il caso peggiore, mostrata su un aggiornamento di
            // sole cifre finali, dice il falso: parla di "cambio maggiore" quando il salto
            // non c'e'. Chi legge o si allarma per niente, o smette di fidarsi del testo.
            String testo = saltoMaggiore ? I18n.tr(a[2])
                    : I18n.tr("server.um.avvertenzaPer.2", java.util.Map.of("p", I18n.tr(a[2])));
            return new JSONObject().put("level", a[1]).put("text", testo);
        }
        if (saltoMaggiore) {
            return new JSONObject().put("level", "verifica").put("text",
                    I18n.tr("server.um.avvertenzaPer.3"));
        }
        return null;
    }

    /**
     * Versioni disponibili per i pacchetti BLOCCATI. Serve un comando diverso da
     * `pkg upgrade -n`: quello i lockedPackages li salta e non dice a che versione andrebbero,
     * quindi da solo lascerebbe credere che non abbiano aggiornamenti.
     */
    public static JSONArray lockedUpdates() {
        String v = sh("pkg version -U -vRL= 2>/dev/null", 60);
        String lock = sh("pkg lock -l 2>/dev/null");
        JSONArray arr = new JSONArray();
        Pattern p = Pattern.compile("^(\\S+)-([^\\s-]+)\\s+<\\s+.*\\(.*has ([^)]+)\\)");
        for (String riga : v.split("\n")) {
            Matcher m = p.matcher(riga.trim());
            if (!m.find()) continue;
            String nome = m.group(1), attuale = m.group(2), disponibile = m.group(3);
            if (ruoloDi(nome) == null) continue;
            if (!bloccato(lock, nome)) continue;
            boolean maggiore = saltoSignificativo(nome, attuale, disponibile);
            JSONObject row = new JSONObject().put("name", nome).put("current", attuale)
                    .put("available", disponibile).put("majorJump", maggiore)
                    .put("role", ruoloDi(nome));
            JSONObject a = avvertenzaPer(nome, maggiore);
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
        String simulazioneCompleta = sh("pkg upgrade -n 2>&1", 180);
        StringBuilder mostrata = new StringBuilder();
        int omesse = 0;
        for (String l : simulazioneCompleta.split("\n")) {
            if (l.contains("is locked and may not be modified") || l.startsWith("Checking for upgrades")) { omesse++; continue; }
            mostrata.append(l).append("\n");
        }
        r.put("dryRun", mostrata.toString().trim()
                + (omesse > 0 ? I18n.tr("server.um.updatesStatus.1", java.util.Map.of("omesse", String.valueOf(omesse))) : ""));
        r.put("upToDate", simulazioneCompleta.contains("Your packages are up to date"));

        // Quali pacchetti DELLA POSTA verrebbero toccati, e se sono protetti.
        JSONArray coinvolti = new JSONArray();
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            if (simulazioneCompleta.contains(p.getString("name") + ":")) {
                coinvolti.put(new JSONObject().put("name", p.getString("name"))
                        .put("role", p.getString("role")).put("locked", p.getBoolean("locked")));
            }
        }
        r.put("affectedMailPackages", coinvolti);
        r.put("lockedUpdates", lockedUpdates());

        // --- Vulnerabilita' note ---
        String audit = sh("pkg audit -F 2>&1", 180);
        r.put("audit", audit.length() > 4000 ? audit.substring(audit.length() - 4000) : audit);

        // Incrocio vulnerabilita' <-> protezione. E' il punto: un pacchetto bloccato NON
        // riceve le correzioni di sicurezza. Il lock protegge da cambiamenti inattesi, non
        // e' uno stato in cui restare per sempre, e chi lo mette deve poterlo vedere.
        JSONArray vulnerabili = new JSONArray();
        String lock = sh("pkg lock -l 2>/dev/null");

        // Quali pacchetti hanno una versione piu' recente nel catalogo, PROTETTI COMPRESI.
        //
        // Serve perche' "pkg upgrade -n" i protetti li salta: dalla simulazione non si puo'
        // sapere se per un pacchetto protetto esista una fix. "pkg version" invece
        // confronta le versioni e del lock non si occupa, quindi risponde anche per quelli.
        Set<String> aggiornabili = new java.util.LinkedHashSet<>();
        for (String riga : sh("pkg version -U -vRL= 2>/dev/null", 60).split("\n")) {
            String t = riga.trim();
            if (t.isEmpty()) continue;
            // "nome-1.2.3    <   needs updating (index has 1.2.4)"
            //
            // Solo "<" vuol dire che esiste una versione piu' recente. ">" (installato piu'
            // nuovo del catalogo), "?" (non nel catalogo) e "!" (confronto fallito) sono
            // differenze, non aggiornamenti: prenderle per tali direbbe a chi legge che per
            // un pacchetto vulnerabile esiste una fix che non esiste.
            String[] campi = t.split("\\s+");
            if (campi.length < 2 || !"<".equals(campi[1])) continue;
            String pv = campi[0];
            int trattino = pv.lastIndexOf('-');
            if (trattino > 0) aggiornabili.add(pv.substring(0, trattino));
        }
        Matcher m = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        Set<String> visti = new java.util.LinkedHashSet<>();
        while (m.find()) visti.add(m.group(1));
        for (String nome : visti) {
            boolean lk = bloccato(lock, nome);
            String ruolo = ruoloDi(nome);
            // Esiste una versione piu' recente? E' una domanda diversa da "l'aggiornamento
            // la applicherebbe", e va tenuta separata: per un pacchetto protetto la seconda
            // e' sempre no, ma la prima puo' essere si'.
            boolean cEAggiornamento = aggiornabili.contains(nome);
            JSONObject v = new JSONObject().put("name", nome).put("locked", lk)
                    .put("mailPackage", ruolo != null).put("role", ruolo == null ? "" : ruolo)
                    .put("aggiornamentoDisponibile", cEAggiornamento)
                    // Prima qui c'era "!lk && simulazione.contains(nome)", e per un pacchetto
                    // protetto veniva sempre falso — mentre la scheda scriveva "protetto,
                    // quindi NON riceve la fix", cioe' affermava che una fix
                    // esistesse. Nessuno l'aveva verificato: la simulazione i protetti li
                    // salta, quindi da li' quell'informazione non si ricava proprio.
                    .put("fixedByUpgrade", !lk && (cEAggiornamento
                            || simulazioneCompleta.contains(nome + ":")));
            // Il dettaglio serve per decidere: "ha una vulnerabilita'" non dice se e' una
            // esecuzione di codice da remoto o un rifiuto di servizio che non ti riguarda.
            JSONObject d = dettaglioVulnerabilita(audit, nome);
            v.put("cve", d.getJSONArray("cve"));
            v.put("description", d.getString("description"));
            v.put("references", d.getJSONArray("references"));
            vulnerabili.put(v);
        }
        // "C'e' una versione piu' recente" non risponde a "la fix c'e'?": la versione
        // piu' recente puo' essere ancora vulnerabile, e la fix puo' esistere in una
        // versione che il tuo catalogo non ha. Lo dicono gli ranges di VuXML.
        if (vulnerabili.length() > 0) {
            JSONObject corr = PackagePlan.correzioni();
            if (corr.optBoolean("success")) {
                JSONObject per = corr.getJSONObject("pacchetti");
                for (int i = 0; i < vulnerabili.length(); i++) {
                    JSONObject v = vulnerabili.getJSONObject(i);
                    if (per.has(v.getString("name"))) v.put("fix", per.getJSONObject(v.getString("name")));
                }
            } else {
                r.put("correzioniErrore", corr.optString("error"));
            }
        }
        r.put("vulnerable", vulnerabili);
        // Lezione pagata sull'altro server il 30/08: mysql80-server era stato aggiornato a
        // 8.0.46 ma il processo continuava a girare sui binari 8.0.45, quindi la fix
        // non era in servizio pur risultando installata. Vale per ogni libreria condivisa.
        r.put("notaRiavvio",
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
     * identificativi CVE e references. Senza questo il pannello direbbe soltanto "e'
     * vulnerabile", che non basta per decidere se valga la pena sbloccare e aggiornare.
     */
    static JSONObject dettaglioVulnerabilita(String audit, String pacchetto) {
        JSONArray cve = new JSONArray();
        JSONArray references = new JSONArray();
        StringBuilder description = new StringBuilder();
        boolean dentro = false;
        java.util.LinkedHashSet<String> cveVisti = new java.util.LinkedHashSet<>();
        for (String riga : audit.split("\n")) {
            String t = riga.trim();
            // Inizio del blocco: "<nome>-<versione> is vulnerable:"
            if (t.matches("^" + java.util.regex.Pattern.quote(pacchetto) + "-[0-9]\\S* is vulnerable:.*")) {
                dentro = true;
                continue;
            }
            if (!dentro) continue;
            // Il blocco finisce quando ne inizia un altro o alla prima riga vuota dopo il testo.
            if (t.endsWith("is vulnerable:") || (t.isEmpty() && description.length() > 0)) break;
            if (t.startsWith("CVE:")) {
                for (String c : t.substring(4).trim().split("[\\s,]+")) {
                    if (c.matches("CVE-[0-9]{4}-[0-9]+")) cveVisti.add(c);
                }
            } else if (t.startsWith("WWW:")) {
                String u = t.substring(4).trim();
                if (u.startsWith("https://") || u.startsWith("http://")) references.put(u);
            } else if (!t.isEmpty()) {
                if (description.length() > 0) description.append(' ');
                description.append(t);
            }
        }
        for (String c : cveVisti) cve.put(c);
        String desc = description.toString();
        if (desc.length() > 600) desc = desc.substring(0, 600) + "...";
        return new JSONObject().put("cve", cve).put("references", references).put("description", desc);
    }

    public static JSONObject maintenancePreview() {
        ok("pkg update -q", 120);
        JSONArray arr = lockedUpdates();
        int maggiori = 0, attese = 0;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            if (o.getBoolean("majorJump")) maggiori++;
            if (o.has("advisory") && "attendi".equals(o.getJSONObject("advisory").getString("level"))) attese++;
        }
        // Il piano esatto dell'intera manutenzione, calcolato su una copia del database di pkg
        // con gli stessi sblocchi che fara' il lavoro vero. La tabella qui sopra dice i pacchetti
        // protetti; questo dice TUTTO cio' che cambiera', dipendenze comprese.
        JSONObject piano = pianoDellaManutenzione(arr).getJSONObject("piano");
        return new JSONObject().put("success", true).put("packages", arr)
                .put("piano", pianoPerLaScheda(piano)).put("signature", piano.optString("signature", ""))
                .put("majorCount", maggiori).put("waitCount", attese)
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
    private static final String[][] DOVECOT_24_ROTTURE = {
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
        java.util.LinkedHashSet<String> vivi = new java.util.LinkedHashSet<>();
        String radice = dir + "/dovecot.conf";
        if (!ok("test -f " + radice, 10)) return new ArrayList<>();
        vivi.add(radice);

        // I conf.d/*.conf entrano solo se dovecot.conf li include davvero: una riga
        // "#!include" commentata non fa entrare niente, e trattarla come attiva
        // reintrodurrebbe lo stesso errore degli esempi.
        if (ok("grep -qE '^[[:space:]]*!include[[:space:]]+conf\\.d/\\*\\.conf' " + radice, 10)) {
            for (String f : sh("ls -1 " + dir + "/conf.d/*.conf 2>/dev/null", 15).split("\n")) {
                if (percorsoDovecotValido(dir, f.trim())) vivi.add(f.trim());
            }
        }

        // I .conf.ext non sono inclusi da un glob: entrano solo se nominati esplicitamente,
        // da un !include attivo oppure da un args = di passdb/userdb.
        for (int giro = 0; giro < 3; giro++) {   // tre livelli bastano e impediscono un ciclo infinito
            int prima = vivi.size();
            String list = String.join(" ", vivi);
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
            for (String riga : references.split("\n")) {
                int c = riga.indexOf(':');
                if (c <= 0) continue;
                String sorgente = riga.substring(0, c);
                String contenuto = riga.substring(c + 1);
                if (contenuto.trim().startsWith("#")) continue;   // include o args disattivato
                String base = sorgente.contains("/") ? sorgente.substring(0, sorgente.lastIndexOf('/')) : dir;
                Matcher m = Pattern.compile("([A-Za-z0-9._/-]*[A-Za-z0-9._-]+\\.conf(\\.ext)?)").matcher(contenuto);
                while (m.find()) {
                    String rif = m.group(1);
                    String assoluto = rif.startsWith("/") ? rif : base + "/" + rif;
                    if (percorsoDovecotValido(dir, assoluto) && ok("test -f " + assoluto, 10)) vivi.add(assoluto);
                }
            }
            if (vivi.size() == prima) break;
        }
        return new ArrayList<>(vivi);
    }

    /**
     * Un percorso finisce dentro un comando: deve stare sotto la cartella di Dovecot, avere
     * una forma innocua, e NON provenire dall'albero degli esempi.
     */
    static boolean percorsoDovecotValido(String dir, String p) {
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
        String installata = sh("pkg query -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 20);
        if (installata.isEmpty()) {
            installata = sh("dovecot --version 2>/dev/null | awk '{print $1}'", 20);
        }
        String disponibile = sh("pkg rquery -U -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 30);
        if (disponibile.isEmpty()) disponibile = sh("pkg rquery -U %v dovecot 2>/dev/null", 30);
        r.put("installed", installata).put("available", disponibile);

        // Quali pacchetti Dovecot offre il repository. Non e' curiosita': se la 2.4 fosse un
        // PACCHETTO DIVERSO (come mysql80 e mysql84) allora nessun pkg upgrade potrebbe mai
        // portarci, e il rischio non sarebbe "un aggiornamento rompe la posta" ma "una
        // migrazione deliberata". Sono due scenari opposti e cambiano cosa va costruito.
        JSONArray offerti = new JSONArray();
        for (String riga : sh("pkg rquery -U -g '%n %v' 'dovecot*' 2>/dev/null", 30).split("\n")) {
            String t = riga.trim();
            if (t.isEmpty()) continue;
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            offerti.put(new JSONObject().put("name", t.substring(0, sp)).put("version", t.substring(sp + 1).trim()));
        }
        r.put("repoPackages", offerti);

        // Il giudizio di Dovecot stesso sulla configurazione. Finora il pannello scriveva i
        // file e riavviava senza mai chiedere al server se li accettasse: un errore di sintassi
        // si sarebbe scoperto a servizio gia' fermo. doveconf -n e' l'equivalente di
        // "mysqld --validate-config", e vale oggi, a prescindere dalla 2.4.
        Shell.Result dc = Shell.runShell(Duration.ofSeconds(30), "doveconf -n 2>&1 >/dev/null");
        r.put("doveconfAvailable", !dc.outputTrim().contains("not found"));
        String errori = dc.outputTrim();
        r.put("doveconfOk", dc.success() && errori.isEmpty());
        r.put("doveconfOutput", errori.length() > 3000 ? errori.substring(0, 3000) : errori);

        int magInst = versioneMaggiore(installata), magDisp = versioneMaggiore(disponibile);
        int minInst = versioneMinore(installata), minDisp = versioneMinore(disponibile);
        // 2.3 -> 2.4 e' un salto di versione MINORE nei numeri ma una rottura totale nei fatti:
        // confrontare solo la cifra maggiore lo lascerebbe passare per innocuo.
        boolean saltoVerso24 = magDisp > magInst || (magDisp == magInst && minDisp > minInst);
        r.put("breakingUpgradeAvailable", saltoVerso24 && !installata.isEmpty() && !disponibile.isEmpty());

        List<String> file = fileDovecot();
        r.put("configFilesScanned", file.size());
        JSONArray issues = new JSONArray();
        if (file.isEmpty()) {
            r.put("scanned", false);
            r.put("note", I18n.tr("server.um.dovecotCompatibility.1", java.util.Map.of("dOVECOT_DIR", String.valueOf(DOVECOT_DIR))));
        } else {
            r.put("scanned", true);
            String list = String.join(" ", file);
            for (String[] rot : DOVECOT_24_ROTTURE) {
                String trovati = sh("grep -lE \"" + rot[0] + "\" " + list + " 2>/dev/null", 20);
                if (trovati.isEmpty()) continue;
                List<String> dove = new ArrayList<>();
                for (String f : trovati.split("\n")) if (!f.trim().isEmpty()) dove.add(f.trim());
                issues.put(new JSONObject().put("costrutto", I18n.tr(rot[1])).put("sostituto", I18n.tr(rot[2]))
                        .put("files", new JSONArray(dove)));
            }
            // Variabili a lettera singola: %u %d %n %h e le forme con modificatori (%2.256Nu).
            // La sintassi nuova e' %{...}, che non combacia con questa espressione.
            String var = sh("grep -lE '%[0-9.]*[A-Za-z]([^{A-Za-z]|$)' " + list + " 2>/dev/null", 20);
            if (!var.isEmpty()) {
                List<String> dove = new ArrayList<>();
                for (String f : var.split("\n")) if (!f.trim().isEmpty()) dove.add(f.trim());
                issues.put(new JSONObject()
                        .put("costrutto", I18n.tr("server.um.x.singleLetterVars"))
                        .put("sostituto", I18n.tr("server.um.dovecotCompatibility.4"))
                        .put("files", new JSONArray(dove)));
            }
            // Nella 2.4 questa direttiva e' obbligatoria e deve essere la prima: la sua assenza
            // e' di per se' la prova che la configurazione e' ancora in formato 2.3.
            if (sh("grep -lE '^[[:space:]]*dovecot_config_version' " + list + " 2>/dev/null", 20).isEmpty()) {
                issues.put(new JSONObject()
                        .put("costrutto", I18n.tr("server.um.x.noConfigVersion"))
                        .put("sostituto", I18n.tr("server.um.dovecotCompatibility.6"))
                        .put("files", new JSONArray()));
            }
            if (sh("grep -lE '^[[:space:]]*dovecot_storage_version' " + list + " 2>/dev/null", 20).isEmpty()) {
                issues.put(new JSONObject()
                        .put("costrutto", I18n.tr("server.um.x.noStorageVersion"))
                        .put("sostituto", I18n.tr("server.um.dovecotCompatibility.8"))
                        .put("files", new JSONArray()));
            }
        }
        r.put("issues", issues);
        r.put("compatible24", issues.length() == 0);
        r.put("fonte", I18n.tr("server.um.dovecotCompatibility.9"));
        r.put("success", true);
        return r;
    }

    private static int versioneMaggiore(String v) {
        Matcher m = Pattern.compile("^([0-9]+)").matcher(v == null ? "" : v);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    private static int versioneMinore(String v) {
        Matcher m = Pattern.compile("^[0-9]+\\.([0-9]+)").matcher(v == null ? "" : v);
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    /** Opzioni del my.cnf vivo che MySQL 8.4 ha rimosso: con una sola di queste il server non parte. */
    private static final String[][] MYCNF_RIMOSSE_84 = {
        {"default_authentication_plugin", "authentication_policy"},
        {"expire_logs_days",              "server.um.versioneMinore.1"},
        {"master_info_repository",        "server.um.versioneMinore.2"},
        {"relay_log_info_repository",     "server.um.versioneMinore.2"},
        {"slave_rows_search_algorithms",  "server.um.versioneMinore.2"},
        {"transaction_write_set_extraction", "server.um.versioneMinore.2"},
        {"binlog_transaction_dependency_tracking", "server.um.versioneMinore.3"},
        {"log_bin_use_v1_events",         "server.um.versioneMinore.2"},
        {"skip_host_cache",               "host_cache_size = 0"},
        {"character_set_client_handshake", "server.um.versioneMinore.2"},
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
            for (String[] o : MYCNF_RIMOSSE_84) {
                // Nel my.cnf '_' e '-' sono equivalenti, e alcune opzioni sono interruttori
                // scritti senza '=': cercare solo "nome =" ne mancherebbe una parte.
                String v = o[0].replaceAll("[_-]", "[_-]");
                if (ok("grep -qE '^[[:space:]]*" + v + "[[:space:]]*(=|$)' " + MYCNF + " 2>/dev/null", 15)) {
                    issues.put(new JSONObject().put("opzione", o[0]).put("sostituto", I18n.tr(o[1])));
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
            String contenuto = sh("cat " + f + " 2>/dev/null", 20);
            contenuto = oscuraCredenziali(contenuto);
            if (contenuto.length() > 20000) contenuto = contenuto.substring(0, 20000) + "\n... " + I18n.tr("server.um.x.truncated");
            files.put(new JSONObject().put("path", f).put("content", contenuto)
                    .put("lines", contenuto.isEmpty() ? 0 : contenuto.split("\n").length));
        }
        return new JSONObject().put("success", true).put("files", files).put("count", files.length());
    }

    /**
     * Toglie ogni password dal testo. Volutamente grossolana: meglio oscurare qualcosa di
     * innocuo che lasciar passare una credenziale in una pagina web.
     */
    static String oscuraCredenziali(String testo) {
        if (testo == null) return "";
        return testo
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
    private static final String[][] LIVELLI_POSTFIX = {
        {"1", "server.um.oscuraCredenziali.1",
         "append_dot_mydomain smtpd_relay_restrictions smtputf8_enable"},
        {"2", "server.um.oscuraCredenziali.2",
         "mynetworks_style relay_domains"},
        {"3.6", "server.um.oscuraCredenziali.3",
         "smtpd_tls_fingerprint_digest smtp_tls_fingerprint_digest lmtp_tls_fingerprint_digest respectful_logging"},
        {"3.11", "server.um.oscuraCredenziali.4",
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
            return r.put("leggibile", false)
                    .put("note", I18n.tr("server.um.postfixCompatibility.2"));
        r.put("leggibile", true);

        String impostato = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        r.put("livello", impostato)
         .put("livelloEsplicito", ok("postconf -n 2>/dev/null | grep -q '^compatibility_level'", 20));

        String check = sh("postfix check 2>&1", 60);
        // Il campo si era perso nella riscrittura, e l'interfaccia mostrava l'intestazione
        // "postfix check:" seguita dal nulla: un titolo senza contenuto sembra un guasto.
        r.put("check", check.isBlank() ? "" : check).put("checkPulito", check.isBlank());

        // Il livello a cui Postfix stesso dice di salire, preso dal suo messaggio.
        String consigliato = "";
        Matcher mc = Pattern.compile("compatibility_level=([0-9.]+)").matcher(check);
        if (mc.find()) consigliato = mc.group(1);
        r.put("consigliato", consigliato);

        // Cosa cambierebbe: solo i livelli STRETTAMENTE fra quello impostato e quello indicato.
        JSONArray changes = new JSONArray();
        double da = numeroLivello(impostato), a = numeroLivello(consigliato);
        if (a > da) {
            String scritti = sh("postconf -n 2>/dev/null | sed -E 's/[[:space:]]*=.*//'", 30);
            java.util.Set<String> decisi = new java.util.HashSet<>();
            for (String x : scritti.split("\n")) if (!x.isBlank()) decisi.add(x.trim());
            for (String[] l : LIVELLI_POSTFIX) {
                double n = numeroLivello(l[0]);
                if (!(n > da && n <= a)) continue;
                JSONArray par = new JSONArray();
                int aperti = 0;
                for (String voce : l[2].split("\\s+")) {
                    if (voce.isBlank()) continue;
                    // "nome@gate=valore": il parametro conta solo se il gate ha quel valore.
                    String nome = voce, gate = "", atteso = "";
                    int at = voce.indexOf('@');
                    if (at > 0) {
                        nome = voce.substring(0, at);
                        String g = voce.substring(at + 1);
                        int eq = g.indexOf('=');
                        if (eq > 0) { gate = g.substring(0, eq); atteso = g.substring(eq + 1); }
                    }
                    if (!isValidName(nome)) continue;
                    boolean gia = decisi.contains(nome);
                    String valoreGate = gate.isEmpty() || !isValidName(gate) ? ""
                            : sh("postconf -h " + gate + " 2>/dev/null", 15).trim();
                    boolean rilevante = gate.isEmpty() || atteso.equalsIgnoreCase(valoreGate);
                    if (!gia && rilevante) aperti++;
                    JSONObject o = new JSONObject().put("nome", nome).put("giaDeciso", gia)
                            .put("valore", gia ? sh("postconf -h " + nome + " 2>/dev/null", 15).trim() : "")
                            .put("rilevante", rilevante);
                    if (!gate.isEmpty())
                        o.put("gate", gate).put("gateValore", valoreGate).put("gateAtteso", atteso);
                    par.put(o);
                }
                changes.put(new JSONObject().put("livello", l[0]).put("cambia", l[1])
                        .put("parametri", par).put("apertiQui", aperti));
            }
        }
        r.put("changes", changes);

        String warnings = sh("grep -hE 'using backwards-compatible default setting [a-z0-9_]+=' "
                + "/var/log/maillog /var/log/maillog.[0-9] 2>/dev/null "
                + "| sed -E 's/.*using backwards-compatible default setting //' "
                + "| sed -E 's/[[:space:]]*(to|;).*//' | sort -u | head -40", 60);
        JSONArray righe = new JSONArray();
        for (String l : warnings.split("\n")) if (!l.isBlank()) righe.put(l.trim());
        r.put("appoggi", righe);

        boolean indietro = a > da;
        r.put("indietro", indietro);
        r.put("verdict", indietro ? "IL LIVELLO E' INDIETRO" : "ALLINEATO");
        r.put("explanation", indietro
                ? I18n.tr("server.um.postfixCompatibility.4", java.util.Map.of("impostato", String.valueOf(impostato), "consigliato", String.valueOf(consigliato)))
                : (impostato.isBlank()
                   ? I18n.tr("server.um.postfixCompatibility.5")
                   : I18n.tr("server.um.postfixCompatibility.6", java.util.Map.of("impostato", String.valueOf(impostato)))));
        int apertiTot = 0;
        for (int i = 0; i < changes.length(); i++) apertiTot += changes.getJSONObject(i).getInt("apertiQui");
        r.put("apertiQui", apertiTot);
        r.put("effettoQui", !indietro ? ""
                : (apertiTot == 0
                   ? I18n.tr("server.um.postfixCompatibility.7")
                   : (apertiTot == 1
                      ? I18n.tr("server.um.x.pfOpen.one")
                      : I18n.tr("server.um.x.pfOpen.other", java.util.Map.of("n", String.valueOf(apertiTot))))));
        r.put("comeSiAlza", indietro
                ? I18n.tr("server.um.postfixCompatibility.10", java.util.Map.of("consigliato", String.valueOf(consigliato)))
                : "");
        r.put("fonte", I18n.tr("server.um.postfixCompatibility.11"));
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
        if (m.find()) r.put("taskTimeout", m.group(1)).put("massimoTeorico", m.group(2)).put("avvisa", true);
        else r.put("avvisa", false);

        JSONArray simboli = new JSONArray();
        Matcher ms = Pattern.compile("([A-Z0-9_]+)\\(([0-9.]+)\\)").matcher(ct);
        while (ms.find())
            simboli.put(new JSONObject().put("nome", ms.group(1)).put("secondi", ms.group(2)));
        r.put("simboli", simboli);

        // La prova, se c'e', sta nel log. Non cerco una frase precisa — non la conosco e
        // inventarla darebbe zero risultati che sembrerebbero una buona notizia. Cerco la
        // parola e mostro cosa c'e', raggruppato.
        String log = "/var/log/rspamd/rspamd.log";
        boolean logC = ok("test -r " + log, 15);
        r.put("log", log).put("logLeggibile", logC);
        // Un solo lettore per tutto lo storico, compresse comprese.
        String lettore = "for f in " + log + " /var/log/rspamd/rspamd.log.*; do "
                + "[ -f \"$f\" ] || continue; case \"$f\" in "
                + "*.bz2) bzip2 -dc \"$f\" 2>/dev/null;; *.gz) gzip -dc \"$f\" 2>/dev/null;; "
                + "*.xz) xz -dc \"$f\" 2>/dev/null;; *.zst) zstd -dc \"$f\" 2>/dev/null;; "
                + "*) cat \"$f\" 2>/dev/null;; esac; done";
        if (logC) {
            // La prima riga nel formato di rspamd, non il marcatore di newsyslog.
            r.put("dal", sh("(" + lettore + ") | grep -m1 -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' "
                    + "| cut -c1-19", 120).trim());
            r.put("al", sh("grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' " + log
                    + " 2>/dev/null | tail -1 | cut -c1-19", 60).trim());
            String rot = sh("ls /var/log/rspamd/rspamd.log.* 2>/dev/null | wc -l", 30).trim().replaceAll("[^0-9]", "");
            int rotazioni = rot.isEmpty() ? 0 : Integer.parseInt(rot);
            String compresse = sh("ls /var/log/rspamd/rspamd.log.*.[bg]z* 2>/dev/null | wc -l", 30)
                    .trim().replaceAll("[^0-9]", "");
            r.put("rotazioni", rotazioni)
             .put("rotazioniCompresse", compresse.isEmpty() ? 0 : Integer.parseInt(compresse));
            String righe = sh("(" + lettore + ") | grep -i 'timeout' "
                    + "| sed -E 's/^[^;]*; //' | sed -E 's/[0-9a-f]{8,}/<id>/g' "
                    + "| sed -E 's/[0-9]+\\.[0-9]+/<n>/g' | sort | uniq -c | sort -rn | head -15", 300);
            JSONArray gruppi = new JSONArray();
            int veri = 0, avviso = 0;
            for (String l : righe.split("\n")) {
                String t = l.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                try {
                    int volte = Integer.parseInt(t.substring(0, sp));
                    String msg = t.substring(sp + 1).trim();
                    // rspamd_worker_check_and_adjust_timeout e' il controllo di coerenza che
                    // rspamd esegue all'avvio: e' l'avviso, non un suo effetto.
                    boolean eAvviso = msg.contains("check_and_adjust_timeout")
                            || msg.contains("symbols cache timeout")
                            || msg.contains("symbols by execution time");
                    if (eAvviso) avviso += volte; else veri += volte;
                    gruppi.put(new JSONObject().put("volte", volte).put("messaggio", msg)
                            .put("eAvviso", eAvviso));
                } catch (NumberFormatException ignored) { }
            }
            r.put("nelLog", gruppi).put("interruzioni", veri).put("ripetizioniAvviso", avviso);
            String tot = sh("(" + lettore + ") | grep -ci 'timeout'", 300).trim().replaceAll("[^0-9]", "");
            r.put("occorrenze", tot.isEmpty() ? 0 : Integer.parseInt(tot));
            String righeTot = sh("(" + lettore + ") | wc -l", 300).trim().replaceAll("[^0-9]", "");
            r.put("righeLog", righeTot.isEmpty() ? 0 : Integer.parseInt(righeTot));
            String soloCorrente = sh("wc -l < " + log + " 2>/dev/null", 60).trim().replaceAll("[^0-9]", "");
            r.put("righeCorrente", soloCorrente.isEmpty() ? 0 : Integer.parseInt(soloCorrente));
        }

        int occ = r.optInt("occorrenze", -1);
        int righeLog = r.optInt("righeLog", 0);
        // Un campione piccolo non autorizza a dire "mai". La soglia non e' un numero magico:
        // sotto le mille righe un log di posta copre tipicamente poche ore, e in poche ore
        // puo' semplicemente non essere passato il messaggio lento che farebbe scattare il caso.
        boolean campioneAmpio = righeLog >= 1000;
        String periodo = r.optString("dal", "").isEmpty() ? ""
                : " " + I18n.tr("server.um.x.rsLogSpan", java.util.Map.of("dal", String.valueOf(r.optString("dal")), "al", String.valueOf(r.optString("al"))));
        String rotate = r.optInt("rotazioni", 0) > 0
                ? " " + (r.optInt("rotazioniCompresse", 0) > 0
                     ? I18n.tr("server.um.x.rsRotZ", java.util.Map.of("n", String.valueOf(r.optInt("rotazioni")), "z", String.valueOf(r.optInt("rotazioniCompresse")), "righe", String.valueOf(r.optInt("righeCorrente", 0))))
                     : I18n.tr("server.um.x.rsRot", java.util.Map.of("n", String.valueOf(r.optInt("rotazioni")), "righe", String.valueOf(r.optInt("righeCorrente", 0)))))
                : I18n.tr("server.um.rspamdTimeoutDiagnostics.2");
        r.put("campioneAmpio", campioneAmpio);
        int interruzioni = r.optInt("interruzioni", occ);
        r.put("verdict", !logC ? "LOG NON LEGGIBILE"
                : (interruzioni > 0 ? "CI SONO ANALISI INTERROTTE"
                                    : (campioneAmpio ? "NESSUNA ANALISI INTERROTTA"
                                                     : "NESSUNA TRACCIA, MA IL LOG E' CORTO")));
        String scomposizione = occ == 0 ? ""
                : " " + I18n.tr("server.um.x.rsSplit", java.util.Map.of("occ", String.valueOf(occ), "warnings", String.valueOf(r.optInt("ripetizioniAvviso", 0)), "interruzioni", String.valueOf(interruzioni)));
        r.put("explanation", !logC
                ? I18n.tr("server.um.rspamdTimeoutDiagnostics.7", java.util.Map.of("log", String.valueOf(log)))
                : (interruzioni == 0
                   ? (occ == 0
                        ? I18n.tr("server.um.rspamdTimeoutDiagnostics.8", java.util.Map.of("righeLog", String.valueOf(righeLog)))
                        : I18n.tr("server.um.rspamdTimeoutDiagnostics.9", java.util.Map.of("righeLog", String.valueOf(righeLog), "scomposizione", String.valueOf(scomposizione))))
                     + periodo + rotate
                     + (campioneAmpio
                        ? I18n.tr("server.um.rspamdTimeoutDiagnostics.10")
                        : I18n.tr("server.um.rspamdTimeoutDiagnostics.11", java.util.Map.of("righeLog", String.valueOf(righeLog))))
                     + " " + I18n.tr("server.um.x.rsTheoretical")
                   : I18n.tr("server.um.rspamdTimeoutDiagnostics.12", java.util.Map.of("interruzioni", String.valueOf(interruzioni), "righeLog", String.valueOf(righeLog), "scomposizione", String.valueOf(scomposizione), "periodo", String.valueOf(periodo), "rotate", String.valueOf(rotate)))));
        r.put("seServisse", I18n.tr("server.um.rspamdTimeoutDiagnostics.13"));
        r.put("fonte", I18n.tr("server.um.rspamdTimeoutDiagnostics.14"));
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
    public static JSONObject raisePostfixCompatibilityLevel(String bersaglio) {
        JSONObject r = new JSONObject().put("pacchetto", "postfix");
        if (bersaglio == null || !bersaglio.matches("[0-9]+(\\.[0-9]+)?"))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.1", java.util.Map.of("bersaglio", String.valueOf(bersaglio))));
        if (!ok("command -v postconf >/dev/null 2>&1", 15))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.2"));

        StringBuilder log = new StringBuilder();
        String prima = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        log.append(I18n.tr("server.um.x.pfLevelBefore", java.util.Map.of("v", String.valueOf(prima)))).append("\n");
        if (prima.equals(bersaglio))
            return r.put("success", true).put("giaAlLivello", true).put("prima", prima).put("dopo", prima)
                    .put("log", log.toString())
                    .put("nota", I18n.tr("server.um.raisePostfixCompatibilityLevel.3", java.util.Map.of("bersaglio", String.valueOf(bersaglio))));

        if (numeroLivello(bersaglio) < numeroLivello(prima))
            return r.put("success", false).put("prima", prima)
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.4", java.util.Map.of("prima", String.valueOf(prima), "bersaglio", String.valueOf(bersaglio))));

        // La copia viene prima di tutto: e' cio' che rende reversibile il resto.
        String mainCf = sh("postconf -h config_directory 2>/dev/null", 20).trim();
        if (mainCf.isEmpty()) mainCf = "/usr/local/etc/postfix";
        mainCf = mainCf + "/main.cf";
        if (!ok("test -f " + mainCf, 15))
            return r.put("success", false).put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.5", java.util.Map.of("mainCf", String.valueOf(mainCf))));
        String copia = "/var/db/mailpanel/main.cf-" + sh("date '+%Y%m%d-%H%M%S'", 15).trim();
        sh("mkdir -p /var/db/mailpanel && cp -p " + mainCf + " " + copia, 30);
        boolean copiaOk = ok("test -s " + copia, 15);
        r.put("copia", copia).put("copiaOk", copiaOk);
        log.append(copiaOk ? I18n.tr("server.um.raisePostfixCompatibilityLevel.6", java.util.Map.of("copia", String.valueOf(copia)))
                           : I18n.tr("server.um.raisePostfixCompatibilityLevel.7"));
        if (!copiaOk)
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.8"));

        log.append("--- ").append(I18n.tr("server.um.x.pfWrite")).append(" ---\n")
           .append(sh("postconf -e compatibility_level=" + bersaglio + " 2>&1", 60)).append("\n");

        String dopo = sh("postconf -h compatibility_level 2>/dev/null", 20).trim();
        log.append(I18n.tr("server.um.x.pfLevelAfter", java.util.Map.of("v", String.valueOf(dopo)))).append("\n");
        r.put("prima", prima).put("dopo", dopo);
        if (!dopo.equals(bersaglio)) {
            sh("cp -p " + copia + " " + mainCf, 30);
            log.append(I18n.tr("server.um.x.pfUnchanged")).append("\n");
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.raisePostfixCompatibilityLevel.9", java.util.Map.of("dopo", String.valueOf(dopo))));
        }

        log.append("--- ").append(I18n.tr("server.um.x.pfReload")).append(" ---\n")
           .append(sh("postfix reload 2>&1", 60)).append("\n");

        // Postfix e' ancora in piedi? La domanda non e' retorica: una main.cf accettata da
        // postconf puo' comunque non piacere al master.
        boolean attivo = ok("service postfix status", 30);
        r.put("attivo", attivo);
        log.append(attivo ? I18n.tr("server.um.x.pfUpAfter") : I18n.tr("server.um.x.pfDownAfter")).append("\n");
        if (!attivo) {
            sh("cp -p " + copia + " " + mainCf, 30);
            sh("service postfix start 2>&1 || postfix start 2>&1", 60);
            boolean risalito = ok("service postfix status", 30);
            log.append(I18n.tr("server.um.x.pfRestored", java.util.Map.of("esito", String.valueOf(risalito ? I18n.tr("server.um.x.pfBackUp") : I18n.tr("server.um.raisePostfixCompatibilityLevel.10"))))).append("\n");
            return r.put("success", false).put("log", log.toString())
                    .put("error", risalito
                            ? I18n.tr("server.um.x.pfDownBack")
                            : I18n.tr("server.um.x.pfDownStill"));
        }

        String check = sh("postfix check 2>&1", 60);
        boolean avvisoVia = !check.contains("backwards-compatible");
        r.put("check", check).put("avvisoVia", avvisoVia);
        log.append("--- postfix check ---\n").append(check.isBlank() ? I18n.tr("server.um.x.noMessage") : check).append("\n");

        return r.put("success", true).put("log", log.toString())
                .put("nota", avvisoVia
                        ? I18n.tr("server.um.x.pfRaisedClean", java.util.Map.of("prima", String.valueOf(prima), "dopo", String.valueOf(dopo), "copia", String.valueOf(copia)))
                        : I18n.tr("server.um.x.pfRaisedWarn", java.util.Map.of("prima", String.valueOf(prima), "dopo", String.valueOf(dopo), "copia", String.valueOf(copia))));
    }

    /** "3.11" -> 3.11, "2" -> 2. Serve solo a ordinare i livelli fra loro. */
    private static double numeroLivello(String v) {
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
    private static final String[][] RSPAMD_COSTRUTTI = {
        {"(^|[^A-Za-z0-9_])ssl[[:space:]]*=[[:space:]]*true", "server.um.numeroLivello.1",
         "server.um.numeroLivello.2", "rotto"},
        {"include_content_urls", "include_content_urls",
         "server.um.numeroLivello.3", "comportamento"},
        {"token_bucket", "server.um.numeroLivello.4",
         "server.um.numeroLivello.5", "comportamento"},
        {"senderscore_reputation", "senderscore_reputation",
         "server.um.numeroLivello.6", "comportamento"},
        {"MX_NXDOMAIN|MX_MISSING", "server.um.rspamd4.mxSymbols",
         "server.um.numeroLivello.7", "comportamento"},
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
        r.put("configPresente", c);
        JSONArray issues = new JSONArray();
        int fileLetti = 0;
        if (c) {
            String n = sh("grep -rIl '' " + etc + " 2>/dev/null | wc -l", 60).trim().replaceAll("[^0-9]", "");
            fileLetti = n.isEmpty() ? 0 : Integer.parseInt(n);
            for (String[] k : RSPAMD_COSTRUTTI) {
                String dove = sh("grep -rIlE '" + k[0] + "' " + etc + " 2>/dev/null | head -20", 60);
                if (dove.isBlank()) continue;
                JSONArray tuoi = new JSONArray(), delPacchetto = new JSONArray();
                for (String f : dove.split("\n")) {
                    String t = f.trim();
                    if (t.isEmpty()) continue;
                    if (!t.matches("[A-Za-z0-9_./+-]{1,256}")) continue;
                    boolean diPkg = !sh("pkg which -q " + t + " 2>/dev/null", 20).trim().isEmpty();
                    (diPkg ? delPacchetto : tuoi).put(t);
                }
                if (tuoi.length() == 0 && delPacchetto.length() == 0) continue;
                issues.put(new JSONObject().put("costrutto", I18n.tr(k[1])).put("cosaCambia", I18n.tr(k[2]))
                        .put("tipo", tuoi.length() > 0 ? k[3] : "predefinito")
                        .put("files", tuoi).put("filesPacchetto", delPacchetto));
            }
        }
        r.put("fileLetti", fileLetti).put("issues", issues);

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

        int rotti = 0, tuoiTot = 0, soloPacchetto = 0;
        for (int i = 0; i < issues.length(); i++) {
            JSONObject q = issues.getJSONObject(i);
            int nTuoi = q.getJSONArray("files").length();
            tuoiTot += nTuoi;
            if (nTuoi == 0) soloPacchetto++;
            if (nTuoi > 0 && "rotto".equals(q.getString("tipo"))) rotti++;
        }
        r.put("tuoi", tuoiTot).put("soloPacchetto", soloPacchetto);
        r.put("verdict", rotti > 0 ? "C'E' UN COSTRUTTO NON PIU' VALIDO"
                : (tuoiTot > 0 ? "DIFFERENZE DI COMPORTAMENTO NELLA TUA CONFIGURAZIONE"
                               : "NIENTE DA SEGNALARE"));
        r.put("explanation", rotti > 0
                ? I18n.tr("server.um.rspamdCompatibility.7", java.util.Map.of("rotti", String.valueOf(rotti)))
                : (tuoiTot > 0
                   ? I18n.tr("server.um.rspamdCompatibility.8")
                   : I18n.tr("server.um.x.rsClean")
                     + (soloPacchetto > 0
                        ? " " + I18n.tr("server.um.x.rsOnlyPkg", java.util.Map.of("n", String.valueOf(soloPacchetto)))
                        : "")));
        r.put("fonte", I18n.tr("server.um.rspamdCompatibility.9"));
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
        public final String tipo;
        public volatile String status = "pending";
        public volatile String errorMessage = "";
        /** Il messaggio finale di un lavoro riuscito, da mostrare cosi' com'e' (es. il cambio di ramo). */
        public volatile String esito = "";
        public volatile int step, total;
        public final long inizio = System.currentTimeMillis();
        public volatile long fine;
        private final StringBuilder log = new StringBuilder();

        Job(String id, String tipo) { this.id = id; this.tipo = tipo; }

        public synchronized void scrivi(String riga) {
            log.append('[')
               .append(new java.text.SimpleDateFormat("HH:mm:ss").format(new java.util.Date()))
               .append("] ").append(riga).append('\n');
            // Un pkg upgrade di cento pacchetti produce migliaia di righe: senza un tetto il
            // job terrebbe in memoria tutto l'output e la pagina diventerebbe illeggibile.
            if (log.length() > 200_000) log.delete(0, log.length() - 150_000);
        }

        public void avanza(int s, int t) { this.step = s; this.total = t; }

        public synchronized JSONObject toJson() {
            return new JSONObject()
                    .put("id", id).put("type", tipo).put("status", status)
                    .put("step", step).put("total", total)
                    .put("percent", total > 0 ? (step * 100 / total) : 0)
                    .put("errorMessage", errorMessage)
                    .put("result", esito)
                    .put("elapsedSeconds", ((fine > 0 ? fine : System.currentTimeMillis()) - inizio) / 1000)
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
    private static int eseguiConLog(Job job, String comando, int timeoutSecondi) throws Exception {
        return eseguiConLog(job, comando, timeoutSecondi, null);
    }

    private static int eseguiConLog(Job job, String comando, int timeoutSecondi, StringBuilder cattura) throws Exception {
        return eseguiConLog(job, comando, timeoutSecondi, cattura, null);
    }

    private static int eseguiConLog(Job job, String comando, int timeoutSecondi,
                                    StringBuilder cattura, Map<String, String> ambiente) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", comando);
        org.mail_panel.util.Shell.applicaPath(pb);
        if (ambiente != null) pb.environment().putAll(ambiente);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        // Il timeout va sorvegliato da FUORI. Metterlo solo sulla waitFor finale non
        // servirebbe a niente: se il processo si blocca senza chiudere lo standard output,
        // readLine resta in attesa per sempre e la waitFor non viene mai raggiunta. Un pkg
        // piantato terrebbe il lock del database dei pacchetti a tempo indefinito.
        Thread guardia = lavoroInLingua(() -> {
            try {
                if (!p.waitFor(timeoutSecondi, java.util.concurrent.TimeUnit.SECONDS)) {
                    job.scrivi(I18n.tr("server.um.eseguiConLog.1", java.util.Map.of("timeoutSecondi", String.valueOf(timeoutSecondi))));
                    p.destroyForcibly();
                }
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }, "update-watchdog");
        guardia.setDaemon(true);
        guardia.start();

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = br.readLine()) != null) {
                job.scrivi(l);
                if (cattura != null) cattura.append(l).append('\n');
            }
        }
        int code = p.waitFor();
        guardia.interrupt();
        return code;
    }

    // ===================== stato su disco, per sopravvivere a un crash =====================

    /**
     * Il blocco finale di runMaintenanceJob non viene eseguito se il processo muore
     * (riavvio del pannello, kill, crash della JVM): i pacchetti resterebbero unlockedPackages e
     * nessuno se ne accorgerebbe finche' un aggiornamento successivo non porta via un
     * servizio. Questo file e' l'unica cosa che sopravvive.
     *
     * Si scrive con PackageQueue.scriviStato, che dice se c'e' riuscito: prima un errore di
     * scrittura finiva in un avviso e il lavoro sbloccava lo stesso. Chi non riesce a scriverlo
     * non sblocca niente.
     */
    private static void pulisciStato() {
        PackageQueue.cancellaStato();
    }

    /**
     * Da chiamare all'avvio del pannello. Se il file di stato esiste, una manutenzione non e'
     * arrivata in fondo: i pacchetti elencati vanno riprotetti subito. Riproteggere qualcosa di
     * gia' protetto non ha effetti, quindi e' sicuro anche se in realta' era andato tutto bene.
     */
    public static String restoreLocksAfterCrash() {
        Path f = Paths.get(MAINTENANCE_STATE);
        if (!Files.exists(f)) return "";
        StringBuilder log = new StringBuilder();
        int fatti = 0, totali = 0, saltati = 0;
        try {
            for (String riga : Files.readString(f).split("\n")) {
                String n = riga.trim();
                if (n.isEmpty()) continue;
                if (!isValidName(n)) { log.append("  name ignored: ").append(n).append('\n'); continue; }
                totali++;
                if (!ok("pkg info -e " + n, 15)) { saltati++; log.append("  ").append(n).append(": not installed, skipped\n"); continue; }
                if (ok("pkg lock -y " + n, 30)) { fatti++; log.append("  ").append(n).append(": protected again\n"); }
                else log.append("  ").append(n).append(": PROTECTING AGAIN FAILED\n");
            }
            if (fatti + saltati == totali) { pulisciStato(); log.append("State cleared.\n"); }
            else log.append("Some were not protected again: the state stays, it is retried at the next start.\n");
        } catch (Exception e) {
            log.append("Restore ERROR: ").append(e.getMessage()).append('\n');
        }
        String msg = "Interrupted maintenance detected at startup: " + fatti + "/" + totali
                + " packages protected again.\n" + log;
        LOGGER.warning(msg);
        return msg;
    }

    /** Insieme dei pacchetti protetti adesso, nomi senza versione. */
    private static Set<String> insiemeProtetti() {
        return insiemeProtetti(sh("pkg lock -l 2>/dev/null"));
    }

    // ===================== i due lavori =====================

    /**
     * Riscrive la SOLA configurazione di Dovecot dalla sorgente unica, senza toccare i
     * pacchetti. Serviva: prima, per applicare una fix alla configurazione bisognava
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
        Thread t = lavoroInLingua(() -> {
            j.status = "running";
            try {
                org.json.JSONObject esito = org.mail_panel.system.MtaStsSetup.esegui(j);
                j.scrivi("");
                j.scrivi(esito.optString("nota", esito.optString("error", "")));
                j.scrivi("");
                j.scrivi("--- " + I18n.tr("server.um.x.fullResult") + " ---");
                j.scrivi(esito.toString(2));
                j.status = esito.optBoolean("success", false) ? "completed" : "error";
                if (!esito.optBoolean("success", false))
                    j.errorMessage = esito.optString("error", I18n.tr("server.um.x.seqInterrupted"));
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = String.valueOf(e.getMessage());
                j.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.fine = System.currentTimeMillis();
            }
        }, "mtasts-attiva");
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
        String id = "dominio-" + domainId + "-" + System.currentTimeMillis();
        Job j = new Job(id, "configura_dominio");
        JOBS.put(id, j);
        Thread t = lavoroInLingua(() -> {
            j.status = "running";
            try {
                org.json.JSONObject esito =
                        org.mail_panel.system.DomainSetup.esegui(domainId, j);
                j.scrivi("");
                j.scrivi(esito.optString("nota", esito.optString("error", "")));
                j.scrivi("");
                j.scrivi("--- " + I18n.tr("server.um.x.fullResult") + " ---");
                j.scrivi(esito.toString(2));
                j.status = esito.optBoolean("success", false) ? "completed" : "error";
                if (!esito.optBoolean("success", false))
                    j.errorMessage = esito.optString("error", I18n.tr("server.um.x.confInterrupted"));
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = String.valueOf(e.getMessage());
                j.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.fine = System.currentTimeMillis();
            }
        }, "configura-dominio");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    public static JSONObject startDovecotRegeneration() {
        String id = "dovecot-cfg-" + System.currentTimeMillis();
        Job j = new Job(id, "dovecot_config");
        JOBS.put(id, j);
        Thread t = lavoroInLingua(() -> runRigenerazioneDovecot(j), "dovecot-config");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    private static void runRigenerazioneDovecot(Job job) {
        job.status = "running";
        java.nio.file.Path script = null;
        try {
            job.avanza(1, 3);
            job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.1"));
            job.scrivi("");

            boolean attivoPrima = ok("service dovecot status", 15);
            job.scrivi(attivoPrima ? I18n.tr("server.um.x.dcBeforeUp") : I18n.tr("server.um.x.dcBeforeDown"));

            String frammento = org.mail_panel.scripts.DovecotConfig.fromPanelConfig().scriptFragment();
            script = java.nio.file.Files.createTempFile("dovecot-config-", ".sh");
            java.nio.file.Files.writeString(script, "#!/bin/sh\nset -e\n" + frammento + "\n");
            java.nio.file.Files.setPosixFilePermissions(script,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));

            job.avanza(2, 3);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.2"));
            // La password passa dall'AMBIENTE: non nel testo dello script (che finisce su
            // disco) ne' sulla riga di comando (visibile nell'elenco dei processi).
            Map<String, String> amb = new LinkedHashMap<>();
            try (java.sql.ResultSet rs = org.mail_panel.Main.dbManager.get_data_config()) {
                if (rs.next()) {
                    String pw = org.mail_panel.Main.dbManager.mysqlPassword();
                    if (pw != null && !pw.isEmpty()) amb.put("DB_PASS", pw);
                }
            } catch (Exception ignored) {}
            job.scrivi("    " + (amb.containsKey("DB_PASS")
                    ? I18n.tr("server.um.x.dbPassFromPanel")
                    : I18n.tr("server.um.x.dbPassScript")));
            int code = eseguiConLog(job, "sh " + script, 300, null, amb);
            if (code != 0) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRigenerazioneDovecot.3");
                job.scrivi("");
                job.scrivi(job.errorMessage);
                return;
            }

            job.avanza(3, 3);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.x.dcReload33"));
            if (!attivoPrima) {
                job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.4"));
                job.status = "completed";
                return;
            }
            boolean ok1 = ok("service dovecot reload", 60);
            job.scrivi("    reload: " + (ok1 ? I18n.tr("server.um.x.done") : I18n.tr("server.um.runRigenerazioneDovecot.5")));
            if (!ok1) ok("service dovecot restart", 60);

            boolean attivoDopo = ok("service dovecot status", 20);
            job.scrivi("    " + (attivoDopo ? I18n.tr("server.um.x.dcAfterUp") : I18n.tr("server.um.x.dcAfterDown")));
            if (!attivoDopo) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRigenerazioneDovecot.6");
                return;
            }

            // === Prova funzionale: l'autenticazione funziona ancora? ===
            // Questo passo riscrive dovecot-sql.conf, cioe' il file con cui Dovecot interroga
            // il database per autenticare. "Il servizio e' attivo" non dice niente al riguardo:
            // Dovecot resta attivo anche con credenziali sbagliate, e se ne accorgono gli utenti.
            // Si esegue la STESSA query che il pannello ha appena scritto nella configurazione,
            // con le STESSE credenziali, su una casella vera.
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.x.authTest"));
            String mailbox = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
            if (mailbox.isEmpty()) {
                job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.7"));
                job.status = "completed";
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.8"));
                return;
            }
            if (!mailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.9"));
                job.status = "completed";
                return;
            }
            // La stessa condizione della password_query scritta nel file, senza estrarre la
            // password: interessa che la riga ci sia e sia raggiungibile, non il suo contenuto.
            String trovate = mysqlOut("SELECT COUNT(*) FROM mailboxes WHERE email='" + mailbox + "' AND active=1;").trim();
            if ("1".equals(trovate)) {
                job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.10", java.util.Map.of("casella", String.valueOf(mailbox))));
                job.status = "completed";
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runRigenerazioneDovecot.11"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRigenerazioneDovecot.12", java.util.Map.of("casella", String.valueOf(mailbox), "trovate", String.valueOf(trovate)));
                job.scrivi("    " + I18n.tr("server.um.x.alarm", java.util.Map.of("m", String.valueOf(job.errorMessage))));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (script != null) try { java.nio.file.Files.deleteIfExists(script); } catch (Exception ignored) {}
            job.fine = System.currentTimeMillis();
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
            org.mail_panel.util.Shell.applicaPath(pb);
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
    private static boolean puoLeggereUtentiMysql() {
        if (!mysqlRootOut("SELECT 1 FROM mysql.user LIMIT 1;").trim().isEmpty()) return true;
        return !mysqlOut("SELECT 1 FROM mysql.user LIMIT 1;").trim().isEmpty();
    }

    /** La lettura di mysql.user, con l'utenza che riesce a farla. */
    private static String utentiConPluginNativo() {
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
    private static JSONArray pluginInUso() {
        String q = "SELECT CONCAT(plugin,' ',COUNT(*)) FROM mysql.user GROUP BY plugin;";
        String out = mysqlRootOut(q);
        if (out.isEmpty()) out = mysqlOut(q);
        JSONArray arr = new JSONArray();
        for (String riga : out.split("\n")) {
            String t = riga.trim();
            int sp = t.lastIndexOf(' ');
            if (sp <= 0) continue;
            arr.put(new JSONObject().put("plugin", t.substring(0, sp).trim())
                    .put("accounts", (int) number(t.substring(sp + 1))));
        }
        return arr;
    }

    /** I plugin trovati, in forma leggibile. */
    private static String descriviPlugin(JSONArray a) {
        if (a.length() == 0) return I18n.tr("server.um.descriviPlugin.1");
        StringBuilder sb = new StringBuilder();
        int tot = 0;
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.getJSONObject(i);
            if (sb.length() > 0) sb.append(", ");
            sb.append(o.getString("plugin")).append(' ').append(o.getInt("accounts"));
            tot += o.getInt("accounts");
        }
        return I18n.tr("server.um.descriviPlugin.2", java.util.Map.of("sb", String.valueOf(sb), "tot", String.valueOf(tot)));
    }

    /** Numero da output di comando; 0 se non contiene cifre. */
    private static long number(String v) {
        try { return Long.parseLong(v == null ? "" : v.trim().replaceAll("[^0-9]", "")); }
        catch (Exception e) { return 0L; }
    }

    /** Due frasi in una nota, senza righe vuote se la seconda non c'e'. */
    private static String unisci(String a, String b) {
        return b == null || b.isEmpty() ? a : a + "\n\n" + b;
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
     * La famiglia MySQL che la versione NEL REPOSITORY di un pacchetto pretende, quando e'
     * diversa da quella installata; null se non c'e' conflitto.
     *
     * Sta in un metodo solo perche' lo usano sia il preflight sia il piano: se il vincolo
     * vivesse in un posto solo, il piano proporrebbe un passo che il preflight poi rifiuta,
     * e una guida che propone cio' che poi nega non guida niente.
     */
    static String conflittoFamigliaMysql(String nome) {
        if (!isValidName(nome)) return null;
        String installato = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        if (installato.isEmpty()) return null;
        // Si guarda TUTTA la famiglia, non il solo pacchetto nominato: php84 non dipende da
        // MySQL, ma php84-mysqli e php84-pdo_mysql si', e vengono aggiornati insieme a lui.
        // Controllare solo il nome scritto nel passo lascerebbe passare esattamente la stessa
        // trappola di postfix, con la differenza che qui nessuno la vedrebbe arrivare.
        for (String membro : membriFamiglia(nome)) {
            if (!isValidName(membro)) continue;
            String deps = sh("pkg rquery -U %dn " + membro + " 2>/dev/null", 30);
            Matcher m = Pattern.compile("mysql([0-9]+)-client").matcher(deps);
            if (!m.find()) continue;
            String richiesto = "mysql" + m.group(1) + "-client";
            if (!richiesto.equals(installato)) return richiesto;
        }
        return null;
    }

    /** Una riga del referto di controlli: esito, cosa si e' controllato, perche' conta. */
    private static void aggiungiCheck(JSONArray a, String id, String label, String level, String detail) {
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
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "block",
                    I18n.tr("server.um.mysql84Preflight.2"));
            block = true;
        } else if (srvPkg.startsWith("mysql84")) {
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "ok",
                    I18n.tr("server.um.mysql84Preflight.3", java.util.Map.of("srvPkg", String.valueOf(srvPkg))));
            r.put("alreadyDone", true);
        } else {
            String v = sh("pkg query %v " + srvPkg, 20);
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.mysql84Preflight.1"), "ok",
                    I18n.tr("server.um.mysql84Preflight.4", java.util.Map.of("srvPkg", String.valueOf(srvPkg), "v", String.valueOf(v), "cliPkg", String.valueOf(cliPkg))));
        }

        // --- 2. La destinazione esiste ---
        String srv84 = sh("pkg rquery -U %v mysql84-server 2>/dev/null", 30);
        String cli84 = sh("pkg rquery -U %v mysql84-client 2>/dev/null", 30);
        r.put("target", srv84);
        if (srv84.isEmpty() || cli84.isEmpty()) {
            aggiungiCheck(checks, "target", I18n.tr("server.um.mysql84Preflight.5"), "block",
                    I18n.tr("server.um.mysql84Preflight.6"));
            block = true;
        } else {
            aggiungiCheck(checks, "target", I18n.tr("server.um.mysql84Preflight.5"), "ok",
                    I18n.tr("server.um.x.my84Avail", java.util.Map.of("s", String.valueOf(srv84), "c", String.valueOf(cli84))));
        }

        // --- 3. IL PUNTO CRITICO: chi usa la libreria del client, e cosa pretende dal repository ---
        JSONArray dipendenti = new JSONArray();
        boolean conflitto = false;
        if (!cliPkg.isEmpty()) {
            for (String riga : sh("pkg query %rn " + cliPkg + " 2>/dev/null", 30).split("\n")) {
                String d = riga.trim();
                if (!isValidName(d) || d.equals(srvPkg)) continue;
                // Cosa pretende la versione del repository di questo dipendente: se nomina
                // ancora mysql80-client, la 8.4 non lo soddisfa e il pacchetto va ricostruito.
                String deps = sh("pkg rquery -U %dn " + d + " 2>/dev/null", 30);
                boolean vuole80 = deps.contains(cliPkg);
                boolean vuole84 = deps.contains("mysql84-client");
                if (vuole80 && !vuole84) conflitto = true;
                dipendenti.put(new JSONObject().put("name", d)
                        .put("richiede", vuole84 ? "mysql84-client" : (vuole80 ? cliPkg : I18n.tr("server.um.mysql84Preflight.7")))
                        .put("compatibile", !vuole80 || vuole84));
            }
        }
        r.put("dependents", dipendenti).put("libraryConflict", conflitto);
        if (conflitto) {
            aggiungiCheck(checks, "libreria", I18n.tr("server.um.mysql84Preflight.8"), "block",
                    I18n.tr("server.um.mysql84Preflight.9", java.util.Map.of("cliPkg", String.valueOf(cliPkg))));
            block = true;
        } else {
            aggiungiCheck(checks, "libreria", I18n.tr("server.um.mysql84Preflight.8"),
                    dipendenti.length() == 0 ? "ok" : "verifica",
                    dipendenti.length() == 0
                        ? I18n.tr("server.um.mysql84Preflight.10", java.util.Map.of("cliPkg", String.valueOf(cliPkg)))
                        : I18n.tr("server.um.mysql84Preflight.11", java.util.Map.of("length", String.valueOf(dipendenti.length()))));
        }

        // --- 4. Il processo in esecuzione e' quello del pacchetto? ---
        boolean su = ok("service mysql-server status", 15);
        String runVer = su ? mysqlOut("SELECT VERSION();") : "";
        if (!su) {
            aggiungiCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), "block",
                    I18n.tr("server.um.mysql84Preflight.12"));
            block = true;
        } else if (runVer.isEmpty()) {
            aggiungiCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), "block",
                    I18n.tr("server.um.mysql84Preflight.13"));
            block = true;
        } else {
            String pkgVer = sh("pkg query %v " + srvPkg, 20).split("[_,]")[0];
            boolean combacia = pkgVer.isEmpty() || runVer.startsWith(pkgVer);
            aggiungiCheck(checks, "running", I18n.tr("server.um.x.mysqlRunning"), combacia ? "ok" : "block",
                    combacia ? I18n.tr("server.um.mysql84Preflight.14", java.util.Map.of("runVer", String.valueOf(runVer)))
                             : I18n.tr("server.um.mysql84Preflight.15", java.util.Map.of("runVer", String.valueOf(runVer), "pkgVer", String.valueOf(pkgVer))));
            if (!combacia) block = true;
            r.put("runningVersion", runVer);
        }

        // --- 5. my.cnf: opzioni rimosse nella 8.4 ---
        JSONObject cm = mysqlCompatibility();
        JSONArray issues = cm.optJSONArray("issues");
        if (issues != null && issues.length() > 0) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < issues.length(); i++) sb.append(issues.getJSONObject(i).getString("opzione")).append(' ');
            aggiungiCheck(checks, "mycnf", I18n.tr("server.um.mysql84Preflight.16"), "block",
                    I18n.tr("server.um.mysql84Preflight.17", java.util.Map.of("p", String.valueOf(sb.toString().trim()))));
            block = true;
        } else {
            aggiungiCheck(checks, "mycnf", I18n.tr("server.um.mysql84Preflight.16"), "ok",
                    I18n.tr("server.um.mysql84Preflight.18"));
        }

        // --- 6. Account con il plugin che la 8.4 non attiva piu' ---
        JSONArray nativi = new JSONArray();
        boolean leggibile = su && !runVer.isEmpty() && puoLeggereUtentiMysql();
        if (leggibile) {
            for (String l : utentiConPluginNativo().split("\n")) {
                if (!l.trim().isEmpty()) nativi.put(l.trim());
            }
        }
        r.put("nativePasswordUsers", nativi).put("userTableReadable", leggibile);
        if (leggibile) r.put("authPlugins", pluginInUso());
        if (!leggibile) {
            aggiungiCheck(checks, "auth", I18n.tr("server.um.mysql84Preflight.19"), "block",
                    I18n.tr("server.um.mysql84Preflight.20"));
            block = true;
        } else {
            aggiungiCheck(checks, "auth", I18n.tr("server.um.mysql84Preflight.19"), nativi.length() > 0 ? "verifica" : "ok",
                    nativi.length() == 0
                        ? I18n.tr("server.um.mysql84Preflight.21", java.util.Map.of("p", String.valueOf(descriviPlugin(pluginInUso()))))
                        : I18n.tr("server.um.x.nativeUsers", java.util.Map.of("n", String.valueOf(nativi.length()), "elenco", String.valueOf(String.join(", ", jsonArrayToList(nativi))))));
        }

        // --- 7. Spazio per la copia fredda ---
        String dataDir = sh("grep -E '^[[:space:]]*datadir[[:space:]]*=' /usr/local/etc/mysql/my.cnf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' '", 15);
        if (dataDir.isEmpty()) dataDir = "/var/db/mysql";
        long dirKb = number(sh("du -sk " + dataDir + " 2>/dev/null | awk '{print $1}'", 120));
        long freeKb = number(sh("df -k /var/db 2>/dev/null | tail -1 | awk '{print $4}'", 20));
        long servono = (long) (dirKb * 1.15) + 512L * 1024L;
        r.put("dataDir", dataDir).put("dataDirMb", dirKb / 1024).put("freeMb", freeKb / 1024);
        if (dirKb <= 0 || freeKb < servono) {
            aggiungiCheck(checks, "spazio", I18n.tr("server.um.mysql84Preflight.22"), "block",
                    I18n.tr("server.um.mysql84Preflight.23", java.util.Map.of("p", String.valueOf((servono / 1024)), "p2", String.valueOf((freeKb / 1024)))));
            block = true;
        } else {
            aggiungiCheck(checks, "spazio", I18n.tr("server.um.mysql84Preflight.22"), "ok",
                    I18n.tr("server.um.x.dataDirSpace", java.util.Map.of("dir", String.valueOf(dataDir), "mb", String.valueOf((dirKb / 1024)), "liberi", String.valueOf((freeKb / 1024)))));
        }

        // --- 8. Inventario, per riconfrontare a fine migrazione ---
        long schemi = 0, tabelle = 0, caselle = 0;
        if (su && !runVer.isEmpty()) {
            schemi = number(mysqlOut("SELECT COUNT(*) FROM information_schema.schemata;"));
            tabelle = number(mysqlOut("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');"));
            caselle = number(mysqlOut("SELECT COUNT(*) FROM mailboxes;"));
        }
        r.put("schemaCount", schemi).put("tableCount", tabelle).put("mailboxCount", caselle);
        aggiungiCheck(checks, "inventario", I18n.tr("server.um.mysql84Preflight.24"), schemi > 0 ? "ok" : "verifica",
                schemi > 0 ? I18n.tr("server.um.mysql84Preflight.25", java.util.Map.of("schemi", String.valueOf(schemi), "tabelle", String.valueOf(tabelle), "caselle", String.valueOf(caselle)))
                           : I18n.tr("server.um.mysql84Preflight.26"));

        // --- 9. Cosa si ferma, e per quanto ---
        aggiungiCheck(checks, "servizi", I18n.tr("server.um.x.servicesInvolved"), "verifica",
                I18n.tr("server.um.mysql84Preflight.27"));

        r.put("success", true).put("checks", checks)
         .put("canProceed", !block && !r.optBoolean("alreadyDone", false)).put("blocked", block);
        return r;
    }

    private static final String MYSQL84_BACKUP = "/var/db/mailpanel/mysql84";

    /** Inserisce una direttiva subito dopo [mysqld], se non c'e' gia'. Scrittura atomica. */
    private static boolean aggiungiDirettivaMysqld(String riga) {
        java.nio.file.Path f = Paths.get("/usr/local/etc/mysql/my.cnf");
        try {
            java.util.List<String> righe = Files.readAllLines(f);
            String chiave = riga.split("=")[0].trim();
            for (String r : righe) if (!r.trim().startsWith("#") && r.trim().startsWith(chiave)) return true;
            java.util.List<String> nuove = new ArrayList<>();
            boolean messo = false;
            for (String r : righe) {
                nuove.add(r);
                if (!messo && r.trim().equalsIgnoreCase("[mysqld]")) {
                    nuove.add("# aggiunta dal pannello: nella 8.4 mysql_native_password non e' attivo di default");
                    nuove.add(riga);
                    messo = true;
                }
            }
            if (!messo) return false;
            java.nio.file.Path tmp = Paths.get("/tmp/my.cnf.mailpanel-84");
            Files.write(tmp, nuove);
            return ok("mv " + tmp + " /usr/local/etc/mysql/my.cnf", 30)
                && ok("chmod 644 /usr/local/etc/mysql/my.cnf", 15);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Could not add " + riga + " to my.cnf", e);
            return false;
        }
    }

    /** File e byte logici di un albero: si misura con stat, MAI con du. */
    private static long[] misura(String dir) {
        long file = number(sh("find " + dir + " -type f 2>/dev/null | wc -l", 120));
        long byteLogici = number(sh("find " + dir + " -type f -exec stat -f %z {} + 2>/dev/null "
                + "| awk '{s+=$1} END {print s+0}'", 120));
        return new long[]{file, byteLogici};
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
    private static Thread lavoroInLingua(Runnable lavoro, String nome) {
        return new Thread(I18n.withCurrent(lavoro), nome);
    }

    private static JSONObject avviaSulTurno(String id, Job j, String description, String nomeThread, Runnable lavoro) {
        String rifiuto = PackageQueue.prendi(id, description);
        if (rifiuto != null) return new JSONObject().put("success", false).put("error", rifiuto);
        JOBS.put(id, j);
        PackageQueue.avvia(id, nomeThread, lavoro);
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    public static JSONObject startMysql84Migration() {
        String id = "my84-" + System.currentTimeMillis();
        Job j = new Job(id, "mysql84_migration");
        return avviaSulTurno(id, j, I18n.tr("server.um.x.jobMy84"), "mysql84-migration", () -> runMigrazione84(j));
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
    private static void runMigrazione84(Job job) {
        job.status = "running";
        final int TOT = 12;
        String backupDir = "", dataDir = "/var/db/mysql", srvPkg = "", cliPkg = "";
        boolean mysqlFermo = false, pacchettiSostituiti = false, arrivatoInFondo = false;
        boolean postfixEra = false, dovecotEra = false;
        long schemiPrima = 0, tabellePrima = 0, casellePrima = 0;
        String casellaProva = "";
        try {
            job.avanza(1, TOT);
            job.scrivi("=== " + I18n.tr("server.um.x.jobMy84Title") + " ===");
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.1", java.util.Map.of("tOT", String.valueOf(TOT))));
            JSONObject pf = mysql84Preflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("alreadyDone", false)
                        ? I18n.tr("server.um.runMigrazione84.2") : I18n.tr("server.um.runMigrazione84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.scrivi(I18n.tr("server.um.runMigrazione84.4"));
                return;
            }
            srvPkg = pf.optString("srvPkg", "");
            cliPkg = pf.optString("cliPkg", "");
            dataDir = pf.optString("dataDir", "/var/db/mysql");
            schemiPrima = pf.optLong("schemaCount", 0);
            tabellePrima = pf.optLong("tableCount", 0);
            casellePrima = pf.optLong("mailboxCount", 0);
            casellaProva = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
            job.scrivi("  " + srvPkg + " + " + cliPkg + " -> mysql84-server + mysql84-client");
            job.scrivi(I18n.tr("server.um.runMigrazione84.5", java.util.Map.of("schemiPrima", String.valueOf(schemiPrima), "tabellePrima", String.valueOf(tabellePrima), "casellePrima", String.valueOf(casellePrima))));
            job.scrivi("  " + (casellaProva.isEmpty()
                    ? I18n.tr("server.um.x.testBoxNone")
                    : I18n.tr("server.um.x.testBox", java.util.Map.of("casella", String.valueOf(casellaProva)))));

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi("[2/" + TOT + "] " + I18n.tr("server.um.x.stopPfDc"));
            postfixEra = ok("service postfix status", 20);
            dovecotEra = ok("service dovecot status", 20);
            if (postfixEra) { ok("service postfix stop", 60); job.scrivi(I18n.tr("server.um.runMigrazione84.6")); }
            else job.scrivi(I18n.tr("server.um.runMigrazione84.7"));
            if (dovecotEra) { ok("service dovecot stop", 60); job.scrivi(I18n.tr("server.um.runMigrazione84.8")); }
            else job.scrivi(I18n.tr("server.um.runMigrazione84.9"));

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi("[3/" + TOT + "] " + I18n.tr("server.um.x.stopMysql"));
            ok("service mysql-server stop", 120);
            boolean giu = false;
            for (int i = 0; i < 120; i++) {
                if (!ok("service mysql-server status", 10) && !ok("pgrep -q mysqld", 10)) { giu = true; break; }
                try { Thread.sleep(1000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            if (!giu) throw new IllegalStateException("MySQL did not stop: a copy taken while the server is running could not be restored");
            mysqlFermo = true;
            job.scrivi("    " + I18n.tr("server.um.x.stoppedConfirmed"));

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.10", java.util.Map.of("tOT", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date for the copy");
            backupDir = MYSQL84_BACKUP + "/" + ts;
            if (!ok("mkdir -p " + backupDir + "/pkg", 30)) throw new IllegalStateException("cannot create " + backupDir);
            ok("cp -p /usr/local/etc/mysql/my.cnf " + backupDir + "/my.cnf", 30);
            ok("printf '%s\\n%s\\n' " + srvPkg + " " + cliPkg + " > " + backupDir + "/pacchetti.txt", 20);
            job.scrivi(I18n.tr("server.um.runMigrazione84.11"));
            ok("pkg fetch -y -o " + backupDir + "/pkg " + srvPkg + " " + cliPkg + " >/dev/null 2>&1", 600);
            job.scrivi("    " + I18n.tr("server.um.x.pkgsKept", java.util.Map.of("n", String.valueOf(number(sh("find " + backupDir + "/pkg -name '*.pkg' | wc -l", 30))))));

            long[] prima = misura(dataDir);
            job.scrivi("    " + I18n.tr("server.um.x.copying", java.util.Map.of("dir", String.valueOf(dataDir), "n", String.valueOf(prima[0]), "mb", String.valueOf((prima[1] / 1024 / 1024)))));
            String cpOut = sh("cp -Rp " + dataDir + " " + backupDir + "/datadir 2>&1; echo EXIT=$?", 1800);
            int cpCode = -1;
            for (String l : cpOut.split("\n")) {
                if (l.startsWith("EXIT=")) { cpCode = (int) number(l); continue; }
                if (!l.trim().isEmpty()) job.scrivi("      cp: " + l);
            }
            if (cpCode != 0) throw new IllegalStateException("cp exited with code " + cpCode);
            ok("sync", 120);
            long[] dopo = misura(backupDir + "/datadir");
            if (dopo[0] != prima[0] || dopo[1] != prima[1]) {
                throw new IllegalStateException("the copy does not match: " + dopo[0] + " files / " + dopo[1]
                        + " bytes against " + prima[0] + " / " + prima[1]);
            }
            if (!ok("test -f " + backupDir + "/datadir/ibdata1", 15)) {
                throw new IllegalStateException("ibdata1 is missing from the copy: it is not a data folder that can be restored");
            }
            ok("printf '%s\\n%s\\n' " + prima[0] + " " + prima[1] + " > " + backupDir + "/manifest.txt", 20);
            job.scrivi(I18n.tr("server.um.runMigrazione84.12", java.util.Map.of("p", String.valueOf(dopo[0]), "p2", String.valueOf((dopo[1] / 1024 / 1024)))));
            job.scrivi(I18n.tr("server.um.runMigrazione84.13", java.util.Map.of("backupDir", String.valueOf(backupDir))));

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi("[5/" + TOT + "] " + I18n.tr("server.um.x.replacingPkgs"));
            ok("pkg unlock -y " + srvPkg, 30);
            ok("pkg unlock -y " + cliPkg, 30);
            String del = sh("pkg delete -f -y " + srvPkg + " " + cliPkg + " 2>&1", 300);
            for (String l : del.split("\n")) if (!l.trim().isEmpty()) job.scrivi("    " + l);
            pacchettiSostituiti = true;
            String ins = sh("pkg install -y mysql84-server mysql84-client 2>&1", 900);
            for (String l : ins.split("\n")) if (!l.trim().isEmpty()) job.scrivi("    " + l);
            if (!ok("pkg info -e mysql84-server", 20) || !ok("pkg info -e mysql84-client", 20)) {
                throw new IllegalStateException("the 8.4 installation did not succeed: the data is intact, the copy is in " + backupDir);
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.14", java.util.Map.of("tOT", String.valueOf(TOT))));
            boolean persi = false;
            for (String d : new String[]{"postfix-mysql", "dovecot-mysql"}) {
                boolean c = ok("pkg info -e " + d, 20);
                job.scrivi("    " + d + ": " + (c ? I18n.tr("server.um.x.present") : I18n.tr("server.um.x.missing")));
                if (!c) persi = true;
            }
            if (persi) job.scrivi(I18n.tr("server.um.runMigrazione84.15"));

            job.avanza(7, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.16", java.util.Map.of("tOT", String.valueOf(TOT))));
            if (ok("test -f " + backupDir + "/my.cnf", 15)) {
                ok("cp -p " + backupDir + "/my.cnf /usr/local/etc/mysql/my.cnf", 30);
                ok("chmod 644 /usr/local/etc/mysql/my.cnf", 15);
                job.scrivi("    " + I18n.tr("server.um.x.mycnfRestored"));
            }
            JSONArray nativi = pf.optJSONArray("nativePasswordUsers");
            if (nativi != null && nativi.length() > 0) {
                job.scrivi("    " + I18n.tr("server.um.x.nativeAdd", java.util.Map.of("n", String.valueOf(nativi.length()))));
                // In Java riga per riga, NON con sed: il sed di BSD non interpreta \n nella
                // sostituzione e inserirebbe la lettera "n" al posto di un a capo, producendo
                // un my.cnf malformato proprio nel passo che serve a non far restare fuori
                // nessun account. Su questa macchina il ramo non scatta, ma un difetto che non
                // si vede oggi e' solo un difetto che aspetta.
                job.scrivi("    " + (aggiungiDirettivaMysqld("mysql-native-password=ON")
                        ? I18n.tr("server.um.runMigrazione84.17") : I18n.tr("server.um.runMigrazione84.18")));
            }

            job.avanza(8, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.19", java.util.Map.of("tOT", String.valueOf(TOT))));
            String bin = sh("which mysqld 2>/dev/null", 15);
            if (bin.isEmpty()) bin = "/usr/local/libexec/mysqld";
            String val = sh("su -m mysql -c '" + bin + " --validate-config' 2>&1", 120);
            if (!val.isEmpty()) {
                for (String l : val.split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
                if (val.toLowerCase().matches("(?s).*(error|unknown variable|aborting).*")) {
                    throw new IllegalStateException("mysqld 8.4 does not accept my.cnf: the data was not touched, "
                            + "the copy is in " + backupDir);
                }
            } else job.scrivi("    " + I18n.tr("server.um.x.acceptedClean"));

            job.avanza(9, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.21", java.util.Map.of("tOT", String.valueOf(TOT))));
            ok("service mysql-server start", 120);
            String nuovaVer = "";
            for (int i = 0; i < 200; i++) {
                nuovaVer = mysqlOut("SELECT VERSION();").trim();
                if (!nuovaVer.isEmpty()) break;
                try { Thread.sleep(3000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                if (i % 5 == 4) job.scrivi(I18n.tr("server.um.runMigrazione84.22", java.util.Map.of("p", String.valueOf(((i + 1) * 3)))));
            }
            if (nuovaVer.isEmpty()) throw new IllegalStateException("MySQL 8.4 does not answer: the copy is in " + backupDir);
            mysqlFermo = false;
            job.scrivi("    SELECT VERSION() = " + nuovaVer);
            if (!nuovaVer.startsWith("8.4")) throw new IllegalStateException("the running version is " + nuovaVer + ", not an 8.4");

            job.avanza(10, TOT);
            job.scrivi("");
            job.scrivi("[10/" + TOT + "] " + I18n.tr("server.um.x.inventory"));
            long sd = number(mysqlOut("SELECT COUNT(*) FROM information_schema.schemata;"));
            long td = number(mysqlOut("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');"));
            long cd = number(mysqlOut("SELECT COUNT(*) FROM mailboxes;"));
            job.scrivi(I18n.tr("server.um.runMigrazione84.23", java.util.Map.of("schemiPrima", String.valueOf(schemiPrima), "sd", String.valueOf(sd), "tabellePrima", String.valueOf(tabellePrima), "td", String.valueOf(td), "casellePrima", String.valueOf(casellePrima), "cd", String.valueOf(cd))));
            boolean inventarioOk = sd >= schemiPrima && td >= tabellePrima && cd >= casellePrima;
            if (!inventarioOk) job.scrivi(I18n.tr("server.um.runMigrazione84.24", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            else job.scrivi("    " + I18n.tr("server.um.x.inventoryIntact"));

            job.avanza(11, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.25", java.util.Map.of("tOT", String.valueOf(TOT))));
            boolean l1 = ok("pkg lock -y mysql84-server", 30), l2 = ok("pkg lock -y mysql84-client", 30);
            job.scrivi("    " + I18n.tr("server.um.x.protect84", java.util.Map.of("s", String.valueOf(l1 ? "ok" : I18n.tr("server.um.x.failedF")), "c", String.valueOf(l2 ? "ok" : I18n.tr("server.um.x.failedF")))));
            if (postfixEra) { ok("service postfix start", 120); job.scrivi("    postfix: " + (ok("service postfix status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26"))); }
            if (dovecotEra) { ok("service dovecot start", 120); job.scrivi("    dovecot: " + (ok("service dovecot status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26"))); }

            job.avanza(12, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.27", java.util.Map.of("tOT", String.valueOf(TOT))));
            // "Il servizio e' attivo" non basta: dopo aver sostituito la libreria client il
            // punto e' se Postfix e Dovecot RIESCONO ANCORA a interrogare il database.
            boolean provaOk = true;
            // L'indirizzo finisce dentro un comando: si accetta solo cio' che e' davvero un
            // indirizzo. Viene dal database e non da fuori, ma la convalida costa una riga e
            // nel job di Dovecot c'era gia': trattare due volte la stessa cosa in due modi
            // diversi e' il modo in cui una svista sopravvive.
            if (!casellaProva.isEmpty()
                    && !casellaProva.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.scrivi(I18n.tr("server.um.runMigrazione84.28"));
                casellaProva = "";
            }
            if (casellaProva.isEmpty()) {
                job.scrivi(I18n.tr("server.um.runMigrazione84.29"));
            } else {
                // QUESTA e' la prova che conta: postmap interroga MySQL attraverso la
                // libreria client appena sostituita. Se funziona, la sostituzione ha retto.
                String mapFile = "/usr/local/etc/postfix/mysql-virtual-mailboxes.cf";
                if (ok("test -f " + mapFile, 15)) {
                    String q = sh("postmap -q '" + casellaProva + "' mysql:" + mapFile + " 2>&1", 60);
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
                    job.scrivi("    " + (pOk
                            ? I18n.tr("server.um.x.pfQueryYes", java.util.Map.of("casella", String.valueOf(casellaProva), "r", String.valueOf(q.trim())))
                            : I18n.tr("server.um.x.pfQueryNo", java.util.Map.of("casella", String.valueOf(casellaProva), "r", String.valueOf(q.trim())))));
                    if (!pOk) provaOk = false;
                } else {
                    job.scrivi(I18n.tr("server.um.runMigrazione84.30", java.util.Map.of("mapFile", String.valueOf(mapFile))));
                    provaOk = false;
                }

                // Questa invece prova meno di quanto sembri, e va detto: lo userdb qui e'
                // "static", quindi doveadm risponde senza interrogare il database. Dimostra
                // che Dovecot e' vivo e risolve gli utenti, non che il suo passdb SQL funzioni.
                String du = sh("doveadm user '" + casellaProva + "' 2>&1 | head -5", 60);
                boolean dOk = du.toLowerCase().contains("uid") || du.toLowerCase().contains("home");
                job.scrivi("    " + (dOk
                        ? I18n.tr("server.um.x.dcResolveYes", java.util.Map.of("casella", String.valueOf(casellaProva)))
                        : I18n.tr("server.um.x.dcResolveNo", java.util.Map.of("casella", String.valueOf(casellaProva), "r", String.valueOf(du.trim())))));
                if (!dOk) provaOk = false;

                // Il percorso SQL di Dovecot si prova cosi': la stessa query che sta nel suo
                // dovecot-sql.conf, eseguita con le stesse credenziali.
                String righe = mysqlOut("SELECT COUNT(*) FROM mailboxes WHERE email='" + casellaProva
                        + "' AND active=1;").trim();
                boolean sOk = "1".equals(righe);
                job.scrivi("    " + (sOk
                        ? I18n.tr("server.um.x.dcAuthYes", java.util.Map.of("casella", String.valueOf(casellaProva)))
                        : I18n.tr("server.um.x.dcAuthNo", java.util.Map.of("casella", String.valueOf(casellaProva), "righe", String.valueOf(righe)))));
                if (!sOk) provaOk = false;
            }

            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.31"));
            boolean caduto = false;
            for (Map.Entry<String, Boolean> e : statoServizi().entrySet()) {
                job.scrivi("    " + e.getKey() + ": " + (e.getValue() ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26")));
                if (!e.getValue()) caduto = true;
            }

            arrivatoInFondo = true;
            if (!inventarioOk || !provaOk || caduto || persi || !l1 || !l2) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigrazione84.32", java.util.Map.of("backupDir", String.valueOf(backupDir)));
            } else {
                job.status = "completed";
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runMigrazione84.33", java.util.Map.of("nuovaVer", String.valueOf(nuovaVer))));
                job.scrivi(I18n.tr("server.um.runMigrazione84.34", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (!arrivatoInFondo) {
                if (mysqlFermo && !pacchettiSostituiti) {
                    job.scrivi("");
                    job.scrivi(I18n.tr("server.um.runMigrazione84.35"));
                    ok("service mysql-server start", 120);
                    if (postfixEra) ok("service postfix start", 120);
                    if (dovecotEra) ok("service dovecot start", 120);
                } else if (pacchettiSostituiti) {
                    job.scrivi("");
                    job.scrivi(I18n.tr("server.um.runMigrazione84.36"));
                    if (!backupDir.isEmpty()) job.scrivi(I18n.tr("server.um.runMigrazione84.37", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                }
            }
            job.fine = System.currentTimeMillis();
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
            if (!Files.exists(f)) return r.put("errore", I18n.tr("server.um.dsnRoundcube.1", java.util.Map.of("rC_DIR", String.valueOf(RC_DIR))));
            Pattern pat = Pattern.compile("db_dsnw'?\\]?\\s*=\\s*['\"]([a-z]+)://([^:]+):([^@]*)@([^/]+)/([A-Za-z0-9_]+)");
            // Riga per riga, non su tutto il testo, per due motivi che una ricerca globale
            // sbaglia entrambi: le righe COMMENTATE non contano — un DSN vecchio lasciato li'
            // farebbe fare copia e aggiornamento dello schema sul database sbagliato — e in PHP
            // vince l'ULTIMA assegnazione, non la prima, perche' i file di configurazione
            // spesso impostano un valore e poi lo sovrascrivono.
            JSONObject ultimo = null;
            for (String riga : Files.readAllLines(f)) {
                String t = riga.trim();
                if (t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*")) continue;
                Matcher m = pat.matcher(t);
                if (m.find()) {
                    ultimo = new JSONObject().put("ok", true).put("driver", m.group(1)).put("user", m.group(2))
                            .put("pass", m.group(3)).put("host", m.group(4)).put("db", m.group(5));
                }
            }
            if (ultimo == null) return r.put("errore", I18n.tr("server.um.dsnRoundcube.2"));
            return ultimo;
        } catch (Exception e) {
            return r.put("errore", e.getMessage());
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
            org.mail_panel.util.Shell.applicaPath(pb);
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
    private static JSONArray radiciNginxRoundcube() {
        JSONArray fuori = new JSONArray();
        String out = sh("grep -rn '^[[:space:]]*root[[:space:]].*roundcube' "
                + "/usr/local/etc/nginx/ 2>/dev/null", 60);
        for (String riga : out.split("\n")) {
            Matcher m = Pattern.compile("^([^:]+):([0-9]+):\\s*root\\s+([^;]+);").matcher(riga.trim());
            if (!m.find()) continue;
            String percorso = m.group(3).trim();
            fuori.put(new JSONObject().put("file", m.group(1)).put("riga", Integer.parseInt(m.group(2)))
                    .put("root", percorso)
                    .put("gia", percorso.endsWith("/public_html") || percorso.endsWith("/public_html/")));
        }
        return fuori;
    }

    /** Vero se la versione e' 1.7 o successiva, cioe' se pretende la radice public_html. */
    static boolean vuolePublicHtml(String versione) {
        Matcher m = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(versione == null ? "" : versione);
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
        String disp = pkg.isEmpty() ? "" : sh("pkg rquery -U %v " + pkg, 30);
        r.put("pkg", pkg).put("current", ver).put("available", disp);
        if (pkg.isEmpty()) {
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "block", I18n.tr("server.um.roundcubePreflight.2"));
            block = true;
        } else if (disp.isEmpty() || disp.equals(ver)) {
            // Non e' un impedimento da risolvere: non c'e' niente da fare. Chiamarlo "blocco"
            // e poi scrivere "risolvi le righe rosse" mette l'utente a cercare un guasto che
            // non esiste — ed e' il contrario di cio' che la riga vuole dire.
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "ok",
                    disp.isEmpty()
                        ? I18n.tr("server.um.roundcubePreflight.3", java.util.Map.of("pkg", String.valueOf(pkg), "ver", String.valueOf(ver)))
                        : I18n.tr("server.um.x.jvLatest", java.util.Map.of("pkg", String.valueOf(pkg), "cur", String.valueOf(ver))));
            r.put("gia", !disp.isEmpty()).put("ignoto", disp.isEmpty());
            block = true;
        } else {
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.roundcubePreflight.1"), "ok", pkg + " " + ver + " -> " + disp);
        }

        // La famiglia PHP richiesta dalla versione nuova deve essere quella installata.
        String phpInst = sh("pkg query %n 2>/dev/null | grep -E '^php[0-9]+$' | head -1", 20);
        Matcher mp = Pattern.compile("roundcube-php([0-9]+)").matcher(pkg);
        String phpRc = mp.find() ? "php" + mp.group(1) : "";
        boolean phpOk = phpRc.isEmpty() || phpRc.equals(phpInst);
        aggiungiCheck(checks, "php", I18n.tr("server.um.roundcubePreflight.4"), phpOk ? "ok" : "block",
                phpOk ? I18n.tr("server.um.roundcubePreflight.5", java.util.Map.of("p", String.valueOf((phpRc.isEmpty() ? phpInst : phpRc))))
                      : I18n.tr("server.um.roundcubePreflight.6", java.util.Map.of("phpRc", String.valueOf(phpRc), "phpInst", String.valueOf(phpInst))));
        if (!phpOk) block = true;

        // Lo script che aggiorna lo schema: senza, il passo non si puo' completare.
        boolean updatedb = ok("test -x " + RC_DIR + "/bin/updatedb.sh", 15)
                        || ok("test -f " + RC_DIR + "/bin/updatedb.sh", 15);
        aggiungiCheck(checks, "updatedb", I18n.tr("server.um.roundcubePreflight.7"), updatedb ? "ok" : "block",
                updatedb ? I18n.tr("server.um.x.updatedbPresent", java.util.Map.of("file", String.valueOf(RC_DIR + "/bin/updatedb.sh")))
                         : I18n.tr("server.um.roundcubePreflight.8", java.util.Map.of("rC_DIR", String.valueOf(RC_DIR))));
        if (!updatedb) block = true;

        // Credenziali e stato del database, letti dalla configurazione di Roundcube.
        JSONObject dsn = dsnRoundcube();
        long tabelle = 0;
        if (!dsn.optBoolean("ok")) {
            aggiungiCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "block",
                    I18n.tr("server.um.x.rcNoCreds", java.util.Map.of("errore", String.valueOf(dsn.optString("errore", "")))));
            block = true;
        } else {
            tabelle = number(rcQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='"
                    + dsn.getString("db") + "';"));
            r.put("db", dsn.getString("db")).put("dbUser", dsn.getString("user")).put("tables", tabelle);
            if (tabelle == 0) {
                aggiungiCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "block",
                        I18n.tr("server.um.x.rcDbNoAnswer", java.util.Map.of("db", String.valueOf(dsn.getString("db")))));
                block = true;
            } else {
                aggiungiCheck(checks, "dsn", I18n.tr("server.um.roundcubePreflight.9"), "ok",
                        I18n.tr("server.um.x.rcDbOk", java.util.Map.of("db", String.valueOf(dsn.getString("db")), "user", String.valueOf(dsn.getString("user")), "tabelle", String.valueOf(tabelle))));
            }
        }

        // Non si annuncia una via di ritorno: si prova, adesso, davvero.
        JSONObject prova = provaCopia();
        String nomeDb = dsn.optBoolean("ok") ? dsn.getString("db") : "roundcubemail";
        if (!prova.optBoolean("ok")) {
            String ered = opzioniEreditate();
            String gtid = statoGtid();
            aggiungiCheck(checks, "copia", I18n.tr("server.um.roundcubePreflight.10"), "block",
                    I18n.tr("server.um.x.rcCopyFails", java.util.Map.of("db", String.valueOf(nomeDb), "errore", String.valueOf(prova.optString("errore"))))
                    + (ered.isEmpty() ? ""
                       : "  ||  " + I18n.tr("server.um.x.rcDumpOpts", java.util.Map.of("o", String.valueOf(ered))))
                    + "  ||  " + (gtid.isEmpty() ? I18n.tr("server.um.x.gtidUnreadable")
                       : I18n.tr("server.um.x.serverState", java.util.Map.of("s", String.valueOf(gtid)))));
            block = true;
        } else if ("server.um.dumpMode.root".equals(prova.optString("modo"))) {
            aggiungiCheck(checks, "copia", I18n.tr("server.um.roundcubePreflight.10"), "attendi",
                    I18n.tr("server.um.x.rcCopyRoot", java.util.Map.of("db", String.valueOf(nomeDb), "storia", String.valueOf(prova.optString("storia")), "gtid", String.valueOf(statoGtid()))));
        } else if (!"server.um.dumpMode.full".equals(prova.optString("modo"))) {
            aggiungiCheck(checks, "copia", I18n.tr("server.um.roundcubePreflight.10"), "attendi",
                    I18n.tr("server.um.x.rcCopyReduced", java.util.Map.of("db", String.valueOf(nomeDb), "modo", String.valueOf(I18n.tr(prova.getString("modo"))), "storia", String.valueOf(prova.optString("storia")))));
        } else {
            aggiungiCheck(checks, "copia", I18n.tr("server.um.roundcubePreflight.10"), "ok",
                    I18n.tr("server.um.roundcubePreflight.11", java.util.Map.of("nomeDb", String.valueOf(nomeDb))));
        }

        // Non chiede niente a chi legge: dice cosa fa la procedura. Sotto l'etichetta gialla
        // "VERIFICA" sembrava una cosa rimasta da fare, in mezzo a righe tutte verdi.
        aggiungiCheck(checks, "opcache", I18n.tr("server.um.roundcubePreflight.12"), "nota",
                I18n.tr("server.um.roundcubePreflight.13"));

        // Radice di nginx: dalla 1.7 deve puntare a public_html, altrimenti la webmail
        // smette di funzionare subito dopo l'aggiornamento.
        JSONArray radici = radiciNginxRoundcube();
        // La domanda giusta non e' "sto passando alla 1.7?" ma "la versione che avro' pretende
        // public_html, e nginx ci punta?". Un server GIA' sulla 1.7 con la radice vecchia ha la
        // webmail gia' guasta adesso: chiedendo solo del passaggio non me ne accorgerei, e
        // direi "non va toccata" proprio nel caso in cui va toccata subito.
        java.util.List<String> daSpostare = new ArrayList<>();
        for (int i = 0; i < radici.length(); i++) {
            JSONObject x = radici.getJSONObject(i);
            if (!x.getBoolean("gia"))
                daSpostare.add(x.getString("file") + ":" + x.getInt("riga") + " -> " + x.getString("root") + "/public_html");
        }
        boolean pretende = vuolePublicHtml(disp);
        boolean gia17 = vuolePublicHtml(ver);
        boolean serve = pretende && !daSpostare.isEmpty();
        r.put("radici", radici).put("cambioRadice", serve);
        if (!pretende) {
            aggiungiCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "ok",
                    I18n.tr("server.um.roundcubePreflight.15", java.util.Map.of("disp", String.valueOf(disp))));
        } else if (radici.length() == 0) {
            aggiungiCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "block",
                    I18n.tr("server.um.roundcubePreflight.16", java.util.Map.of("disp", String.valueOf(disp))));
            block = true;
        } else if (daSpostare.isEmpty()) {
            aggiungiCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "ok",
                    I18n.tr("server.um.roundcubePreflight.17"));
        } else {
            aggiungiCheck(checks, "root", I18n.tr("server.um.roundcubePreflight.14"), "attendi",
                    (gia17
                     ? I18n.tr("server.um.roundcubePreflight.18", java.util.Map.of("ver", String.valueOf(ver)))
                     : I18n.tr("server.um.roundcubePreflight.19", java.util.Map.of("disp", String.valueOf(disp))))
                    + I18n.tr("server.um.x.rcRootFix", java.util.Map.of("n", String.valueOf(daSpostare.size()), "righe", String.valueOf(String.join(" ; ", daSpostare)))));
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
    private static String spostaRadiceNginx(Job job, String backupDir) {
        JSONArray radici = radiciNginxRoundcube();
        java.util.List<String> toccati = new ArrayList<>();
        try {
            for (int i = 0; i < radici.length(); i++) {
                JSONObject x = radici.getJSONObject(i);
                if (x.getBoolean("gia")) continue;
                String file = x.getString("file"), root = x.getString("root");
                if (!ok("test -f " + file, 10)) continue;
                // Se public_html non c'e', questa build non lo usa: non e' un guasto, e
                // dichiararlo tale bocciarebbe un aggiornamento riuscito — che e' il modo di
                // farsi tornare indietro senza motivo. Chi giudica resta la prova finale: se
                // la webmail non risponde, lo dice quella.
                if (!ok("test -d " + root + "/public_html", 10)) {
                    job.scrivi(I18n.tr("server.um.spostaRadiceNginx.1", java.util.Map.of("root", String.valueOf(root))));
                    job.scrivi(I18n.tr("server.um.spostaRadiceNginx.2"));
                    return "nonserve";
                }
                String nome = file.replaceAll(".*/", "");
                ok("cp -p " + file + " " + backupDir + "/nginx-" + nome, 30);
                java.util.List<String> righe = Files.readAllLines(Paths.get(file));
                int n = x.getInt("riga") - 1;
                if (n < 0 || n >= righe.size()) { job.scrivi(I18n.tr("server.um.spostaRadiceNginx.3", java.util.Map.of("file", String.valueOf(file), "p", String.valueOf((n + 1))))); return "fallito"; }
                String vecchia = righe.get(n);
                if (!vecchia.contains(root)) { job.scrivi("    " + I18n.tr("server.um.x.lineNoLonger", java.util.Map.of("file", String.valueOf(file), "riga", String.valueOf((n + 1)), "root", String.valueOf(root)))); return "fallito"; }
                // Puntare a una cartella che esiste non basta: dev'esserci cosa servire.
                if (!ok("test -f " + root + "/public_html/index.php", 10)) {
                    job.scrivi(I18n.tr("server.um.spostaRadiceNginx.4", java.util.Map.of("root", String.valueOf(root))));
                    job.scrivi(I18n.tr("server.um.spostaRadiceNginx.5"));
                    return "fallito";
                }
                righe.set(n, vecchia.replace(root + ";", root + "/public_html;"));
                Files.write(Paths.get(file), righe);
                toccati.add(file);
                job.scrivi("    " + file + ":" + (n + 1) + "  root -> " + root + "/public_html");
            }
            if (toccati.isEmpty()) { job.scrivi(I18n.tr("server.um.spostaRadiceNginx.6")); return "nonserve"; }

            // Prima di ricaricare: nginx accetta questa configurazione?
            String prova = sh("nginx -t 2>&1", 60);
            boolean buona = prova.toLowerCase().contains("syntax is ok") && prova.toLowerCase().contains("test is successful");
            if (!buona) {
                for (String l : prova.split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
                for (String f : toccati) {
                    String nome = f.replaceAll(".*/", "");
                    ok("cp -p " + backupDir + "/nginx-" + nome + " " + f, 30);
                }
                job.scrivi(I18n.tr("server.um.spostaRadiceNginx.7"));
                return "fallito";
            }
            job.scrivi(I18n.tr("server.um.spostaRadiceNginx.8"));
            String svc = nomeServizioReale("nginx");
            if (svc == null) { job.scrivi(I18n.tr("server.um.spostaRadiceNginx.9")); return "fallito"; }
            boolean ric = ok("service " + svc + " reload", 60);
            job.scrivi("    " + (ric ? I18n.tr("server.um.x.reloadedYes") : I18n.tr("server.um.x.reloadedNo")));
            return ric ? "fatto" : "fallito";
        } catch (Exception e) {
            job.scrivi(I18n.tr("server.um.spostaRadiceNginx.10", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            return "fallito";
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
    private static final String[][] MODI_COPIA = {
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
    private static boolean mysqlRootDisponibile() {
        return "1".equals(mysqlRootOut("SELECT 1;").trim());
    }

    /** La parte di connessione della riga, secondo l'utente scelto dal modo. */
    private static String connessioneCopia(String chi, JSONObject dsn) {
        String h = dsn.getString("host");
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        return "root".equals(chi)
                ? "-u root " + dsn.getString("db")                       // socket unix, nessuna password
                : "-u " + dsn.getString("user") + " -h " + host + " " + dsn.getString("db");
    }

    /** Perche' mysqldump fa quel FLUSH: si guarda il server, non si deduce. */
    private static String statoGtid() {
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
    private static String opzioniEreditate() {
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
    private static JSONObject provaCopia() {
        String tmp = "/var/db/mailpanel/test-dump.sql";
        ok("mkdir -p /var/db/mailpanel", 20);
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok"))
            return new JSONObject().put("ok", false)
                    .put("errore", I18n.tr("server.um.x.credsUnreadable", java.util.Map.of("reason", String.valueOf(d.optString("errore", I18n.tr("server.um.x.reasonUnknown"))))));
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return new JSONObject().put("ok", false)
                    .put("errore", I18n.tr("server.um.provaCopia.1"));
        StringBuilder storia = new StringBuilder();
        try {
            for (String[] m : MODI_COPIA) {
                if ("root".equals(m[2]) && !mysqlRootDisponibile()) {
                    storia.append("[").append(I18n.tr(m[1])).append("] ").append(I18n.tr("server.um.x.notTriedRoot")).append("  ");
                    continue;
                }
                JSONObject e = rcDumpUnTentativo(m[0] + " --no-data",
                        connessioneCopia(m[2], d), "root".equals(m[2]) ? null : d.getString("pass"), tmp);
                if (e.optBoolean("ok"))
                    return new JSONObject().put("ok", true).put("modo", m[1])
                            .put("storia", storia.toString().trim());
                storia.append("[").append(I18n.tr(m[1])).append("] ").append(e.optString("errore")).append("  ");
            }
            return new JSONObject().put("ok", false).put("errore", storia.toString().trim());
        } finally {
            ok("rm -f " + tmp + " " + tmp + ".err", 20);
        }
    }

    private static JSONObject rcDump(String destinazione) {
        JSONObject r = new JSONObject().put("ok", false);
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok"))
            return r.put("errore", I18n.tr("server.um.x.rcCredsUnreadable", java.util.Map.of("reason", String.valueOf(d.optString("errore", I18n.tr("server.um.x.reasonUnknown"))))));
        String u = d.getString("user"), db = d.getString("db");
        String h = d.getString("host");
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        if (!u.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !host.matches("[A-Za-z0-9._-]{1,128}"))
            return r.put("errore", I18n.tr("server.um.rcDump.1", java.util.Map.of("u", String.valueOf(u), "host", String.valueOf(host), "db", String.valueOf(db))));
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return r.put("errore", I18n.tr("server.um.provaCopia.1"));

        StringBuilder storia = new StringBuilder();
        for (String[] t : MODI_COPIA) {
            if ("root".equals(t[2]) && !mysqlRootDisponibile()) {
                storia.append("[").append(I18n.tr(t[1])).append("] ").append(I18n.tr("server.um.x.notTriedNoRoot")).append("  ");
                continue;
            }
            JSONObject e = rcDumpUnTentativo(t[0], connessioneCopia(t[2], d),
                    "root".equals(t[2]) ? null : d.getString("pass"), destinazione);
            if (e.optBoolean("ok")) {
                r.put("ok", true).put("modo", t[1]);
                if (!t[1].equals("server.um.dumpMode.full")) r.put("ridotto", storia.toString().trim());
                return r;
            }
            storia.append("[").append(I18n.tr(t[1])).append("] ").append(e.optString("errore")).append("  ");
        }
        return r.put("errore", storia.toString().trim());
    }

    private static JSONObject rcDumpUnTentativo(String opzioni, String connessione,
                                                String pass, String dest) {
        JSONObject r = new JSONObject().put("ok", false);
        String err = dest + ".err";
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c",
                    "mysqldump " + opzioni + " " + connessione + " > " + dest + " 2> " + err);
            org.mail_panel.util.Shell.applicaPath(pb);
            // La password sta nell'ambiente e non nella riga di comando: cosi' non compare in ps.
            // Per il tentativo da root non c'e' password: entra dal socket unix.
            if (pass != null && !pass.isEmpty()) pb.environment().put("MYSQL_PWD", pass);
            Process pr = pb.start();
            if (!pr.waitFor(1800, java.util.concurrent.TimeUnit.SECONDS)) {
                pr.destroyForcibly();
                return r.put("errore", I18n.tr("server.um.rcDumpUnTentativo.1"));
            }
            String messaggio = sh("cat " + err + " 2>/dev/null", 30).replace("\n", " ").trim();
            if (pr.exitValue() != 0)
                return r.put("errore", messaggio.isEmpty()
                        ? I18n.tr("server.um.x.exitNoMsg", java.util.Map.of("c", String.valueOf(pr.exitValue())))
                        : I18n.tr("server.um.x.exitMsg", java.util.Map.of("c", String.valueOf(pr.exitValue()), "m", String.valueOf(messaggio))));
            // mysqldump chiude con "Dump completed": senza quella riga il file e' troncato,
            // e un file troncato che sembra un backup e' peggio di nessun backup.
            if (!ok("tail -3 " + dest + " | grep -q 'Dump completed'", 60))
                return r.put("errore", I18n.tr("server.um.x.dumpTruncated")
                        + (messaggio.isEmpty() ? "" : " (" + messaggio + ")"));
            ok("rm -f " + err, 15);
            return r.put("ok", true);
        } catch (Exception e) {
            return r.put("errore", e.getMessage());
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
    private static JSONObject provaWebmailOrigine() {
        JSONObject r = new JSONObject().put("ok", false);
        JSONArray radici = radiciNginxRoundcube();
        if (radici.length() == 0) return r.put("errore", I18n.tr("server.um.provaWebmailOrigine.1"));
        String file = radici.getJSONObject(0).getString("file");
        int riga = radici.getJSONObject(0).getInt("riga");
        // listen e server_name stanno nello stesso blocco, poche righe sopra la radice.
        int da = Math.max(1, riga - 10);
        String testa = sh("sed -n '" + da + "," + riga + "p' " + file + " 2>/dev/null", 30);
        String porta = "", nome = "";
        for (String l : testa.split("\n")) {
            Matcher mp = Pattern.compile("^\\s*listen\\s+([0-9]{1,5})\\b").matcher(l);
            if (mp.find()) porta = mp.group(1);
            Matcher mn = Pattern.compile("^\\s*server_name\\s+([A-Za-z0-9._-]+)\\s*;").matcher(l);
            if (mn.find() && !"_".equals(mn.group(1))) nome = mn.group(1);
        }
        if (porta.isEmpty()) return r.put("errore", I18n.tr("server.um.provaWebmailOrigine.2"));
        if (nome.isEmpty()) {
            try { nome = org.mail_panel.Main.dbManager.getRoundcubeDomain(); } catch (Exception ignored) {}
        }
        if (nome == null || !nome.matches("[A-Za-z0-9._-]{1,255}"))
            return r.put("errore", I18n.tr("server.um.provaWebmailOrigine.3"));
        // --resolve mette a posto sia il nome nell'intestazione Host sia quello nel TLS,
        // ma manda la richiesta all'indirizzo locale: e' il modo di parlare col server e basta.
        String url = "https://" + nome + ":" + porta + "/";
        String out = sh("curl -sk -m 20 -D - -o /dev/null --resolve " + nome + ":" + porta
                + ":127.0.0.1 " + url + " 2>&1", 60);
        Matcher mc = Pattern.compile("HTTP/[0-9.]+\\s+([0-9]{3})").matcher(out);
        String codice = mc.find() ? mc.group(1) : "";
        boolean cdn = out.toLowerCase().contains("cf-ray") || out.toLowerCase().contains("server: cloudflare");
        return r.put("ok", codice.startsWith("2") || codice.startsWith("3"))
                .put("codice", codice.isEmpty() ? I18n.tr("server.um.provaWebmailOrigine.4") : codice)
                .put("url", url).put("viaCdn", cdn).put("intestazioni", out.trim());
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
        String nome = "rc-sonda-" + Long.toHexString(System.nanoTime()) + ".php";
        String file = RC_DIR + "/public_html/" + nome;
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
            JSONObject pw = provaWebmailOrigine();
            String url = pw.optString("url", "");
            if (url.isEmpty()) return new JSONObject().put("ok", false).put("errore", I18n.tr("server.um.probePathInfo.2"));
            String n = url.replaceAll("^https://", "").replaceAll(":.*$", "");
            String porta = url.replaceAll(".*:", "").replaceAll("/.*$", "");
            String res = "--resolve " + n + ":" + porta + ":127.0.0.1 ";
            String u = "https://" + n + ":" + porta + "/" + nome + "/skins/elastic/deps/bootstrap.min.css";
            String out = sh("curl -sk -m 20 " + res + "'" + u + "' 2>&1 | head -c 1200", 60);
            return new JSONObject().put("ok", true).put("url", u).put("output", out.trim());
        } catch (Exception e) {
            return new JSONObject().put("ok", false).put("errore", e.getMessage());
        } finally {
            // La sonda sparisce comunque: non deve restare un file PHP nella radice del web.
            ok("rm -f " + file, 20);
        }
    }

    /**
     * Un CSS in uscita e' 160 KB di testo: stamparlo per intero nasconde la risposta invece di
     * mostrarla. Qui si dice cosa e' uscito, non lo si riversa.
     */
    private static String riassumiUscita(String out) {
        if (out == null) return I18n.tr("server.um.x.nothing");
        String t = out.trim();
        if (t.isEmpty()) return I18n.tr("server.um.riassumiUscita.1");
        String primo = t.length() > 200 ? t.substring(0, 200) : t;
        boolean sembraCss = t.contains("{") && (t.contains(";") || t.contains("}"));
        boolean sembraErrore = t.toLowerCase().contains("not found") || t.toLowerCase().contains("404")
                || t.toLowerCase().contains("fatal") || t.toLowerCase().contains("warning");
        return (sembraErrore ? I18n.tr("server.um.riassumiUscita.2") : sembraCss ? I18n.tr("server.um.riassumiUscita.3") : I18n.tr("server.um.x.output"))
                + " " + I18n.tr("server.um.x.charsPlus", java.util.Map.of("n", String.valueOf(t.length()))) + "\n" + primo.replace("\n", " ");
    }

    /**
     * Scarica davvero un foglio di stile e guarda com'e' fatto.
     *
     * E' l'unica prova che distingue "la webmail risponde" da "la webmail si vede": nella 1.7
     * gli asset passano da static.php con il percorso DENTRO l'URI, e se nginx non se ne accorge
     * ogni CSS torna come pagina HTML — la pagina si apre, e non c'e' niente.
     */
    private static JSONObject provaAssetCss(String nome, String porta) {
        JSONObject r = new JSONObject().put("ok", false);
        String base = "https://" + nome + ":" + porta;
        String res = "--resolve " + nome + ":" + porta + ":127.0.0.1 ";
        String html = sh("curl -sk -m 20 " + res + base + "/ 2>/dev/null | head -80", 60);
        Matcher m = Pattern.compile("href=\"([^\"]*\\.css[^\"]*)\"").matcher(html);
        if (!m.find()) return r.put("errore", I18n.tr("server.um.provaAssetCss.1"));
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
        String testa = sh("curl -sk -m 20 -D - -o /dev/null " + res + "'" + url + "' 2>&1", 60).trim();
        boolean bene = out.startsWith("200") && out.contains("text/css");
        return r.put("ok", bene).put("url", url).put("risposta", out)
                .put("intestazioni", testa)
                .put("daPhp", testa.toLowerCase().contains("x-powered-by: php"));
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
    public static JSONObject repairNginxPathInfo(boolean esegui) {
        JSONObject r = new JSONObject();
        try {
            JSONArray radici = radiciNginxRoundcube();
            if (radici.length() == 0)
                return r.put("success", false).put("error", I18n.tr("server.um.provaWebmailOrigine.1"));
            String file = radici.getJSONObject(0).getString("file");
            int rigaRoot = radici.getJSONObject(0).getInt("riga");
            java.util.List<String> righe = Files.readAllLines(Paths.get(file));

            // Il location del PHP dentro questo blocco server.
            int inizio = -1;
            for (int i = rigaRoot; i < Math.min(righe.size(), rigaRoot + 60); i++) {
                String t = righe.get(i);
                if (t.contains("location") && t.contains(".php") && t.contains("{")) { inizio = i; break; }
            }
            if (inizio < 0)
                return r.put("success", false).put("error",
                        I18n.tr("server.um.repairNginxPathInfo.1"));
            // Gia' a posto? Si guarda TUTTO il blocco, non la riga dopo: dopo una riparazione
            // precedente la seconda riga puo' essere il rewrite degli URL sicuri, e cercando
            // solo li' il pannello riparerebbe una seconda volta cio' che e' gia' riparato.
            boolean haSplit = false, haTryFiles = false;
            for (int i = inizio; i < Math.min(righe.size(), inizio + 25); i++) {
                if (righe.get(i).contains("fastcgi_split_path_info")) haSplit = true;
                // Questa riga ANNULLA la precedente: c'e' ma non basta, anzi rompe.
                if (righe.get(i).contains("try_files") && righe.get(i).contains("fastcgi_script_name"))
                    haTryFiles = true;
                if (righe.get(i).trim().equals("}")) break;
            }
            if (haSplit && !haTryFiles)
                return r.put("success", true).put("giaOk", true)
                        .put("nota", I18n.tr("server.um.repairNginxPathInfo.2"));
            if (haSplit && haTryFiles)
                r.put("reason", I18n.tr("server.um.repairNginxPathInfo.3"));

            // Le graffe dentro le virgolette NON sono blocchi: la riga di rewrite per gli URL
            // sicuri contiene "{16}", e contarla chiuderebbe il blocco nel punto sbagliato,
            // riscrivendo mezza configurazione. Anche il testo dopo # e' commento, non codice.
            int graffe = 0, fine = -1;
            for (int i = inizio; i < righe.size(); i++) {
                boolean virgolette = false;
                for (char c : righe.get(i).toCharArray()) {
                    if (c == '"') { virgolette = !virgolette; continue; }
                    if (virgolette) continue;
                    if (c == '#') break;
                    if (c == '{') graffe++;
                    else if (c == '}') graffe--;
                }
                if (graffe == 0) { fine = i; break; }
            }
            if (fine < 0)
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.4"));

            // use_secure_urls mette un prefisso di 16 caratteri davanti a ogni URL: se e' attivo
            // serve la riga di rewrite, in ENTRAMBI i blocchi, altrimenti nulla combacia piu'.
            // Non si presume: si legge dalla configurazione di Roundcube.
            boolean urlSicuri = ok("grep -qE \"^[^/]*.use_secure_urls.*=.*(true|1)\" "
                    + RC_DIR + "/config/config.inc.php", 20);
            r.put("urlSicuri", urlSicuri);

            String passa = "";
            for (int i = inizio; i <= fine; i++) {
                Matcher mp = Pattern.compile("fastcgi_pass\\s+([^;]+);").matcher(righe.get(i));
                if (mp.find()) passa = mp.group(1).trim();
            }
            if (passa.isEmpty())
                return r.put("success", false).put("error",
                        I18n.tr("server.um.repairNginxPathInfo.5"));

            String ind = righe.get(inizio).replaceAll("[^ \t].*$", "");
            String i2 = ind + "    ";
            // Ricalcata sull'esempio del wiki ufficiale di Roundcube (pagina Installation),
            // SENZA aggiunte. Ci avevo messo un "try_files $fastcgi_script_name =404" per
            // impedire che i sondaggi automatici arrivassero a PHP: quella riga fa una
            // redirezione interna che riscrive l'URI al solo nome dello script, e da quel
            // momento $fastcgi_path_info si ricalcola su un URI che il percorso non ce l'ha
            // piu'. Risultato: PATH_INFO arriva a static.php VUOTA, e siccome l'operatore ??
            // di PHP non ripiega su una stringa vuota, ogni foglio di stile diventa un 404.
            // Riprodotto con nginx e un PHP veri: e' esattamente il guasto del 31/08/2026.
            java.util.List<String> nuovo = new ArrayList<>(java.util.List.of(
                ind + "# Roundcube 1.7 serve gli asset come /static.php/percorso/al/file.css:",
                ind + "# uno script PHP con un percorso attaccato. Un location che chiede .php",
                ind + "# in fondo all'URI non lo prende, e il foglio di stile torna come HTML.",
                ind + "# Configurazione dal wiki ufficiale di Roundcube (pagina Installation).",
                ind + "location ~ \\.php {"));
            if (urlSicuri) nuovo.add(i2 + "rewrite \"^/[a-zA-Z0-9]{16}/(.*)$\" /$1;");
            nuovo.addAll(java.util.List.of(
                i2 + "include fastcgi_params;",
                i2 + "fastcgi_index index.php;",
                i2 + "fastcgi_split_path_info ^(.+\\.php)(/.+)$;",
                i2 + "fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
                i2 + "fastcgi_param PATH_INFO $fastcgi_path_info;",
                i2 + "fastcgi_pass " + passa + ";",
                ind + "}"));

            r.put("success", true).put("file", file).put("da", inizio + 1).put("a", fine + 1)
             .put("attuale", String.join("\n", righe.subList(inizio, fine + 1)))
             .put("proposto", String.join("\n", nuovo));
            if (!esegui) return r.put("eseguito", false);

            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}"))
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.10"));
            String bk = "/var/db/mailpanel/nginx/" + ts;
            ok("mkdir -p " + bk, 30);
            if (!ok("cp -p " + file + " " + bk + "/nginx.conf", 30))
                return r.put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.11", java.util.Map.of("file", String.valueOf(file))));

            java.util.List<String> out = new ArrayList<>(righe.subList(0, inizio));
            out.addAll(nuovo);
            out.addAll(righe.subList(fine + 1, righe.size()));
            Files.write(Paths.get(file), out);

            String prova = sh("nginx -t 2>&1", 60).toLowerCase();
            if (!(prova.contains("syntax is ok") && prova.contains("test is successful"))) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                return r.put("success", false).put("eseguito", false)
                        .put("error", I18n.tr("server.um.x.nginxRejected", java.util.Map.of("out", String.valueOf(sh("nginx -t 2>&1", 60).replace("\n", " ")))));
            }
            String svc = nomeServizioReale("nginx");
            if (svc == null || !ok("service " + svc + " reload", 60)) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                if (svc != null) ok("service " + svc + " reload", 60);
                return r.put("success", false).put("eseguito", false)
                        .put("error", I18n.tr("server.um.repairNginxPathInfo.12"));
            }

            // La prova che conta: il CSS torna come CSS?
            JSONObject pw = provaWebmailOrigine();
            String nome = pw.optString("url", "").replaceAll("^https://", "").replaceAll(":.*$", "");
            String porta = pw.optString("url", "").replaceAll(".*:", "").replaceAll("/.*$", "");
            JSONObject css = nome.isEmpty() ? new JSONObject().put("ok", false).put("errore", I18n.tr("server.um.probePathInfo.2"))
                                            : provaAssetCss(nome, porta);
            r.put("eseguito", true).put("backup", bk + "/nginx.conf").put("css", css);
            if (!css.optBoolean("ok")) {
                r.put("attenzione", I18n.tr("server.um.x.cssStillWrong", java.util.Map.of("r", String.valueOf(css.optString("risposta", css.optString("errore"))), "file", String.valueOf(bk + "/nginx.conf"))));
            }
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject roundcubeDiagnostics() {
        JSONObject r = new JSONObject();
        JSONArray voci = new JSONArray();
        try {
            // 1. Dove punta nginx adesso
            JSONArray radici = radiciNginxRoundcube();
            String root = radici.length() > 0 ? radici.getJSONObject(0).getString("root") : RC_DIR;
            String file = radici.length() > 0 ? radici.getJSONObject(0).getString("file") : "?";
            voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.1"))
                    .put("testo", I18n.tr("server.um.roundcubeDiagnostics.2", java.util.Map.of("root", String.valueOf(root), "file", String.valueOf(file)))));

            // 2. Il log di errore: e' li' che nginx dice PERCHE'
            String logPath = sh("grep -hE '^[[:space:]]*error_log' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 30).trim();
            if (!logPath.matches("/[A-Za-z0-9._/-]{1,200}")) logPath = "/var/log/nginx/error.log";
            String log = sh("tail -25 " + logPath + " 2>&1", 30);
            voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.3", java.util.Map.of("logPath", String.valueOf(logPath))))
                    .put("testo", log.isEmpty() ? I18n.tr("server.um.x.empty") : log));

            // 3. Permessi lungo tutto il cammino: basta una cartella non attraversabile
            StringBuilder perm = new StringBuilder();
            String[] pezzi = root.split("/");
            StringBuilder acc = new StringBuilder();
            for (String pz : pezzi) {
                if (pz.isEmpty()) continue;
                acc.append('/').append(pz);
                perm.append(sh("ls -ld " + acc + " 2>&1", 20)).append('\n');
            }
            voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.4"))
                    .put("testo", perm.toString().trim()));

            // 4. Cosa c'e' davvero nella cartella servita
            voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.5", java.util.Map.of("root", String.valueOf(root))))
                    .put("testo", sh("ls -la " + root + " 2>&1 | head -25", 30)));

            // 5. Con quale utente gira nginx: e' lui che deve poter leggere
            String user = sh("grep -hE '^[[:space:]]*user[[:space:]]' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 20).trim();
            String proc = sh("ps -axo user,command 2>/dev/null | grep '[n]ginx: worker' | head -2", 30);
            voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.7"))
                    .put("testo", I18n.tr("server.um.x.nginxUserDeclared", java.util.Map.of("u", String.valueOf(user.isEmpty() ? I18n.tr("server.um.x.nginxUserNobody") : user)))
                            + "\n" + (proc.isEmpty() ? I18n.tr("server.um.x.noWorker") : proc)));

            // 6. La risposta del SERVER, scavalcando qualunque cosa stia davanti
            JSONObject pw = provaWebmailOrigine();
            voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.8"))
                    .put("testo", pw.optBoolean("ok")
                            ? I18n.tr("server.um.x.urlAnswers", java.util.Map.of("url", String.valueOf(pw.optString("url")), "codice", String.valueOf(pw.optString("codice")))) + "\n\n"
                              + pw.optString("intestazioni")
                            : I18n.tr("server.um.x.noAnswer", java.util.Map.of("r", String.valueOf(pw.optString("codice", pw.optString("errore")))))
                              + (pw.optBoolean("viaCdn") ? "  " + I18n.tr("server.um.x.cdnAnswered") : "")
                              + "\n\n" + pw.optString("intestazioni")));

            // 6b. Il .htaccess dice come Roundcube vuole essere servita: e' la fonte autorevole
            voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.9", java.util.Map.of("root", String.valueOf(root))))
                    .put("testo", sh("cat " + root + "/.htaccess 2>&1", 30)));

            // 6c. Gli asset: nella 1.7 passano da static.php, ed e' li' che nginx sbaglia di solito.
            if (pw.optBoolean("ok")) {
                String u = pw.optString("url");
                String nomeH = u.replaceAll("^https://", "").replaceAll(":.*$", "");
                String portaH = u.replaceAll(".*:", "").replaceAll("/.*$", "");
                JSONObject css = provaAssetCss(nomeH, portaH);
                voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.10"))
                        .put("testo", css.optString("url", I18n.tr("server.um.x.noLinkFound")) + "\n  -> "
                            + css.optString("risposta", css.optString("errore"))
                            + (css.optBoolean("ok") ? "   " + I18n.tr("server.um.x.correct")
                               : I18n.tr("server.um.roundcubeDiagnostics.11"))
                            + "\n\n" + I18n.tr("server.um.x.whoAnswered") + " " + (css.optBoolean("daPhp")
                                ? I18n.tr("server.um.roundcubeDiagnostics.12")
                                : I18n.tr("server.um.roundcubeDiagnostics.13"))
                            + "\n\n" + css.optString("intestazioni", "")));

                // Il file che static.php dovrebbe servire esiste davvero sul disco?
                String pathInfo = css.optString("url", "").replaceAll(".*/static\\.php", "").replaceAll("\\?.*$", "");
                if (!pathInfo.isEmpty() && pathInfo.matches("/[A-Za-z0-9._/-]{1,200}")) {
                    String atteso = RC_DIR + pathInfo;
                    voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.14"))
                            .put("testo", "PATH_INFO: " + pathInfo + "\n"
                                + sh("ls -l " + atteso + " 2>&1", 20) + "\n"
                                + sh("ls -d " + RC_DIR + "/skins/*/ 2>&1 | head -5", 20)));
                }

                // L'esperimento che separa le due possibilita': static.php eseguito a mano,
                // con un PATH_INFO noto e senza web server di mezzo. Se qui il file esce,
                // l'applicazione funziona e il problema e' in cio' che nginx le manda; se
                // fallisce anche qui, il problema e' dentro static.php o nei suoi percorsi.
                if (!pathInfo.isEmpty() && pathInfo.matches("/[A-Za-z0-9._/-]{1,200}")) {
                    String cd = "cd " + RC_DIR + "/public_html && ";
                    String reqUri = "/static.php" + pathInfo;
                    String conPathInfo = sh(cd + "env PATH_INFO='" + pathInfo + "' REQUEST_URI='" + reqUri
                            + "' REQUEST_METHOD=GET php static.php 2>&1 | head -c 400", 60);
                    String senzaPathInfo = sh(cd + "env -u PATH_INFO REQUEST_URI='" + reqUri
                            + "' REQUEST_METHOD=GET php static.php 2>&1 | head -c 400", 60);
                    voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.15"))
                            .put("testo",
                                "--- " + I18n.tr("server.um.x.withPathInfo", java.util.Map.of("v", String.valueOf(pathInfo))) + " ---\n"
                                + riassumiUscita(conPathInfo)
                                + "\n\n--- " + I18n.tr("server.um.x.withoutPathInfo", java.util.Map.of("v", String.valueOf(reqUri))) + " ---\n"
                                + riassumiUscita(senzaPathInfo)));
                }

                // Cosa riceve PHP passando da nginx: e' l'altra meta' della bisezione.
                JSONObject sonda = probePathInfo();
                voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.16"))
                        .put("testo", sonda.optBoolean("ok")
                            ? I18n.tr("server.um.x.testRequest", java.util.Map.of("url", String.valueOf(sonda.optString("url")))) + "\n\n"
                              + sonda.optString("output")
                            : I18n.tr("server.um.x.notSucceeded", java.util.Map.of("e", String.valueOf(sonda.optString("errore"))))));

                // Il codice vero installato su QUESTO server, non quello del repository a monte.
                voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.17"))
                        .put("testo", sh("head -45 " + RC_DIR + "/public_html/static.php 2>&1", 30)));

                // PHP puo' essere confinato: se non gli e' permesso uscire da public_html,
                // static.php non raggiunge le skin e risponde 404 pur funzionando.
                voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.18"))
                        .put("testo", sh("grep -rhnE '^[^;]*(open_basedir|chroot|chdir)' "
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
                int riga = radici.getJSONObject(0).getInt("riga");
                int da = Math.max(1, riga - 12), a2 = riga + 22;
                voci.put(new JSONObject().put("titolo", I18n.tr("server.um.roundcubeDiagnostics.20", java.util.Map.of("riga", String.valueOf(riga))))
                        .put("testo", sh("sed -n '" + da + "," + a2 + "p' " + file + " 2>&1", 30)));
            }
            return r.put("success", true).put("voci", voci);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject startRoundcubeUpdate() {
        String id = "rc-" + System.currentTimeMillis();
        Job j = new Job(id, "roundcube");
        return avviaSulTurno(id, j, I18n.tr("server.um.startRoundcubeUpdate.1"), "roundcube-update", () -> runAggiornamentoRoundcube(j));
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
    private static void runAggiornamentoRoundcube(Job job) {
        job.status = "running";
        final int TOT = 8;
        boolean sbloccato = false;
        String pkg = "", backupDir = "";
        try {
            job.avanza(1, TOT);
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.1"));
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.1", java.util.Map.of("tOT", String.valueOf(TOT))));
            JSONObject pf = roundcubePreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigrazione84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.scrivi(I18n.tr("server.um.runMigrazione84.4"));
                return;
            }
            pkg = pf.optString("pkg", "");
            long tabellePrima = pf.optLong("tables", 0);
            job.scrivi("  " + pkg + " " + pf.optString("current") + " -> " + pf.optString("available"));
            job.scrivi("  " + I18n.tr("server.um.x.dbTables", java.util.Map.of("db", String.valueOf(pf.optString("db")), "n", String.valueOf(tabellePrima))));

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.2", java.util.Map.of("tOT", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            backupDir = "/var/db/mailpanel/roundcube/" + ts;
            if (!ok("mkdir -p " + backupDir, 30)) throw new IllegalStateException("cannot create " + backupDir);
            ok("cp -p " + RC_DIR + "/config/config.inc.php " + backupDir + "/config.inc.php", 30);
            JSONObject cp = rcDump(backupDir + "/roundcube.sql");
            if (!cp.optBoolean("ok")) {
                job.scrivi("    " + cp.optString("errore"));
                throw new IllegalStateException("the database copy did not succeed: I do not go ahead "
                        + "without a way back. The reason is the line above.");
            }
            if (cp.has("ridotto")) {
                job.scrivi("    " + I18n.tr("server.um.x.copyReduced", java.util.Map.of("modo", String.valueOf(I18n.tr(cp.optString("modo"))))));
                job.scrivi("    " + I18n.tr("server.um.x.didNotPass", java.util.Map.of("r", String.valueOf(cp.getString("ridotto")))));
                job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.3"));
            }
            job.scrivi("    " + I18n.tr("server.um.x.copyVerified", java.util.Map.of("file", String.valueOf(backupDir + "/roundcube.sql"), "kb", String.valueOf(number(sh("wc -c < " + backupDir + "/roundcube.sql", 30)) / 1024))));
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.4"));

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.5", java.util.Map.of("tOT", String.valueOf(TOT))));
            if (bloccato(sh("pkg lock -l 2>/dev/null"), pkg)) {
                // Prima l'elenco su disco, poi lo sblocco: se l'elenco non si scrive, non si sblocca.
                String errStato = PackageQueue.scriviStato(java.util.List.of(pkg));
                if (errStato != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I do not unlock " + pkg + ": " + errStato);
                // Da qui il finally riprotegge e chiude l'elenco, anche se lo sblocco fallisse a meta'.
                sbloccato = true;
                if (!ok("pkg unlock -y " + pkg, 30)) throw new IllegalStateException("I could not unlock " + pkg);
                job.scrivi("    " + I18n.tr("server.um.x.unlockedTemp"));
            }
            String sim = sh("pkg upgrade -n " + pkg + " 2>&1", 300);
            if (sim.toLowerCase().contains("conflicts with")) {
                for (String l : sim.split("\n")) if (l.toLowerCase().contains("conflict")) job.scrivi("      " + l.trim());
                throw new IllegalStateException("the update would overwrite files of another package: I stop.");
            }
            StringBuilder cat = new StringBuilder();
            int code = eseguiConLog(job, "pkg upgrade -y " + pkg + " 2>&1", 1800, cat);
            if (code != 0) throw new IllegalStateException("pkg upgrade exited with code " + code);
            for (String m : messaggiCheChiedonoAzione(cat.toString())) {
                job.scrivi("    " + I18n.tr("server.um.x.pkgAsks", java.util.Map.of("m", String.valueOf(m.replace("\n", " | ")))));
            }

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.6", java.util.Map.of("tOT", String.valueOf(TOT))));
            // Il pacchetto puo' aver messo un config di esempio al posto del tuo.
            JSONObject dsnDopo = dsnRoundcube();
            if (!dsnDopo.optBoolean("ok")) {
                ok("cp -p " + backupDir + "/config.inc.php " + RC_DIR + "/config/config.inc.php", 30);
                job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.7"));
            } else job.scrivi("    " + I18n.tr("server.um.x.confIntact"));

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.8", java.util.Map.of("tOT", String.valueOf(TOT))));
            String out = sh("cd " + RC_DIR + " && php bin/updatedb.sh --package=roundcube --dir=SQL 2>&1", 900);
            for (String l : out.split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
            String ol = out.toLowerCase();
            if (ol.contains("error") || ol.contains("fatal") || ol.contains("failed")) {
                throw new IllegalStateException("updatedb.sh reported an error: the database copy is in "
                        + backupDir + "/roundcube.sql");
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.9", java.util.Map.of("tOT", String.valueOf(TOT))));
            String esitoRadice = "nonserve";
            if (pf.optBoolean("cambioRadice", false)) {
                esitoRadice = spostaRadiceNginx(job, backupDir);
                if ("fallito".equals(esitoRadice))
                    job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.10", java.util.Map.of("backupDir", String.valueOf(backupDir))));
            } else job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.11"));
            boolean radiceOk = !"fallito".equals(esitoRadice);

            job.avanza(7, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.12", java.util.Map.of("tOT", String.valueOf(TOT))));
            String svc = nomeServizioReale("php_fpm");
            if (svc != null) {
                ok("service " + svc + " restart", 120);
                job.scrivi("    " + svc + ": " + (ok("service " + svc + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26")));
            } else job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.13"));

            job.avanza(8, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.14", java.util.Map.of("tOT", String.valueOf(TOT))));
            long tabelleDopo = number(rcQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='"
                    + pf.optString("db") + "';"));
            job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.15", java.util.Map.of("tabellePrima", String.valueOf(tabellePrima), "tabelleDopo", String.valueOf(tabelleDopo))));
            boolean tabOk = tabelleDopo >= tabellePrima;
            if (!tabOk) job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.16"));

            // La webmail risponde davvero? Non basta che i file siano aggiornati.
            //
            // E bisogna chiederlo AL SERVER. Chiedendolo al nome pubblico si finisce a parlare
            // con cio' che sta davanti — una CDN, un proxy — e a prendere la sua risposta per
            // quella del server: e' successo qui, con un 403 di Cloudflare scambiato per un
            // guasto della webmail mentre nginx non aveva nemmeno visto la richiesta.
            JSONObject pw = provaWebmailOrigine();
            boolean webProvata = !pw.has("errore") || pw.has("codice");
            boolean webOk = pw.optBoolean("ok");
            if (!webProvata) {
                job.scrivi("    " + I18n.tr("server.um.x.webTestNotRun", java.util.Map.of("e", String.valueOf(pw.optString("errore")))));
                webOk = true;   // non provata non vuol dire guasta: non boccio cio' che non ho measured
            } else if (webOk) {
                job.scrivi("    " + I18n.tr("server.um.x.urlAnswersOrigin", java.util.Map.of("url", String.valueOf(pw.optString("url")), "codice", String.valueOf(pw.optString("codice")))));
            } else {
                job.scrivi("    " + I18n.tr("server.um.x.urlAnswersBad", java.util.Map.of("url", String.valueOf(pw.optString("url")), "codice", String.valueOf(pw.optString("codice")))));
                if (pw.optBoolean("viaCdn"))
                    job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.17"));
            }

            if (tabOk && webOk && radiceOk) {
                job.status = "completed";
                job.scrivi("");
                // "In servizio" si puo' dire solo se qualcuno l'ha visto rispondere. Senza quella
                // prova il lavoro puo' essere andato benissimo, ma il verdict sarebbe piu' verde
                // delle prove che ho: allora lo dico, e la verifica la fai tu.
                job.scrivi(webProvata
                        ? I18n.tr("server.um.runAggiornamentoRoundcube.18")
                        : I18n.tr("server.um.runAggiornamentoRoundcube.19"));
                if (!webProvata)
                    job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.20"));
                if ("nonserve".equals(esitoRadice) && pf.optBoolean("cambioRadice", false))
                    job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.21"));
                job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.22", java.util.Map.of("backupDir", String.valueOf(backupDir))));
                job.scrivi(I18n.tr("server.um.runAggiornamentoRoundcube.23"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runAggiornamentoRoundcube.24", java.util.Map.of("backupDir", String.valueOf(backupDir)));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (sbloccato && !pkg.isEmpty()) {
                boolean r = ok("pkg info -e " + pkg, 15) && ok("pkg lock -y " + pkg, 30);
                job.scrivi("");
                job.scrivi(r ? I18n.tr("server.um.x.reprotectOk", java.util.Map.of("pkg", String.valueOf(pkg))) : I18n.tr("server.um.x.reprotectFail", java.util.Map.of("pkg", String.valueOf(pkg))));
                if (r) pulisciStato();
            }
            job.fine = System.currentTimeMillis();
        }
    }

    // ===================== aggiornamento della JVM del pannello =====================

    private static final String JDK_DIR = "/var/db/mailpanel/jdk";
    /** Dove finisce cio' che il pannello scrive quando riparte staccato dal terminale. */
    private static final String LOG_PANNELLO = "/var/db/mailpanel/panel.log";

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
    private static JSONObject strategiaRiavvio() {
        String dir = System.getProperty("user.dir", "");
        String binJava = System.getProperty("java.home", "") + "/bin/java";
        String jar = "";
        try {
            java.net.URL u = UpdateManager.class.getProtectionDomain().getCodeSource().getLocation();
            java.io.File f = new java.io.File(u.toURI());
            if (f.isFile()) jar = f.getAbsolutePath();
        } catch (Exception ignored) { }

        String comando = startCommand(true);

        return new JSONObject()
                .put("dir", dir)
                .put("comandoMenu", startCommand(false))
                .put("jar", jar)
                .put("comando", comando)
                // -f manda i tre descrittori a /dev/null, e da solo butta via TUTTO cio' che il
                // pannello scrive: e' successo il 31/08/2026, pannello riacceso e muto, senza
                // nessun modo di sapere cosa stesse facendo. -o riporta stdout e stderr in un
                // file, e per daemon(8) le due opzioni si combinano proprio cosi': prima
                // /dev/null, poi la redirezione al file. -t da' al processo un nome riconoscibile
                // in ps, cosi' si trova senza cercare "java" fra tutti i java.
                .put("log", LOG_PANNELLO)
                .put("riga", "/usr/sbin/daemon -f -o " + LOG_PANNELLO + " -t mailpanel"
                        + " -- /bin/sh -c \"cd '" + dir + "' && exec " + comando + "\"")
                .put("nota", jar.isEmpty()
                        ? I18n.tr("server.um.strategiaRiavvio.1")
                        : I18n.tr("server.um.strategiaRiavvio.2", java.util.Map.of("p", String.valueOf(startCommand(false)))))
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
    private static int portaInAscolto(long pid) {
        for (String riga : sh("sockstat -46l 2>/dev/null").split("\n")) {
            String[] c = riga.trim().split("\\s+");
            if (c.length < 6 || !c[2].equals(String.valueOf(pid))) continue;
            String indirizzo = c[5];
            int i = Math.max(indirizzo.lastIndexOf(':'), indirizzo.lastIndexOf('.'));
            if (i < 0) continue;
            try {
                int porta = Integer.parseInt(indirizzo.substring(i + 1));
                if (porta > 0 && porta < 65536) return porta;
            } catch (NumberFormatException ignored) { }
        }
        return 0;
    }

    /** Il pacchetto che possiede la JVM su cui gira QUESTO processo. Non si deduce dal nome. */
    private static String pacchettoDellaJvm() {
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
        String nome = sh("pkg query %n " + nv + " 2>/dev/null").trim();
        if (nome.matches("[A-Za-z0-9._+-]{1,64}") && ok("pkg info -e " + nome, 15)) return nome;
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
        boolean blocca = false;
        try {
            String pkg = pacchettoDellaJvm();
            String home = System.getProperty("java.home", "");
            if (pkg.isEmpty()) {
                aggiungiCheck(checks, "pkg", I18n.tr("server.um.x.jvmInUse"), "block",
                        I18n.tr("server.um.javaPreflight.1", java.util.Map.of("home", String.valueOf(home))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", true).put("canProceed", false);
            }
            r.put("pkg", pkg);
            String vIns = sh("pkg query %v " + pkg + " 2>/dev/null").trim();
            String vRepo = sh("pkg rquery -U %v " + pkg + " 2>/dev/null").trim();
            r.put("current", vIns).put("available", vRepo).put("home", home);
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.x.jvmInUse"), "ok",
                    I18n.tr("server.um.javaPreflight.2", java.util.Map.of("pkg", String.valueOf(pkg), "vIns", String.valueOf(vIns), "home", String.valueOf(home))));
            if (vRepo.isEmpty()) {
                aggiungiCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "block",
                        I18n.tr("server.um.javaPreflight.3", java.util.Map.of("pkg", String.valueOf(pkg))));
                blocca = true;
            } else if (vRepo.equals(vIns)) {
                aggiungiCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "ok",
                        I18n.tr("server.um.javaPreflight.4", java.util.Map.of("vIns", String.valueOf(vIns))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", false).put("canProceed", false).put("gia", true);
            } else {
                aggiungiCheck(checks, "ver", I18n.tr("server.um.x.versionAvail"), "attendi",
                        I18n.tr("server.um.javaPreflight.5", java.util.Map.of("vIns", String.valueOf(vIns), "vRepo", String.valueOf(vRepo), "home", String.valueOf(home))));
            }

            JSONObject st = strategiaRiavvio();
            r.put("riavvio", st);
            if (!st.optBoolean("ok")) {
                aggiungiCheck(checks, "start", I18n.tr("server.um.javaPreflight.6"), "block", st.getString("nota"));
                blocca = true;
            } else {
                aggiungiCheck(checks, "start", I18n.tr("server.um.javaPreflight.6"), "attendi", st.getString("nota"));
                aggiungiCheck(checks, "cmd", I18n.tr("server.um.javaPreflight.7"), "ok",
                        "in " + st.getString("dir") + ":  " + st.getString("comando"));
            }

            if (!ok("test -x /usr/sbin/daemon", 10)) {
                aggiungiCheck(checks, "daemon", I18n.tr("server.um.x.scriptDetach"), "block",
                        I18n.tr("server.um.javaPreflight.8"));
                blocca = true;
            } else {
                aggiungiCheck(checks, "daemon", I18n.tr("server.um.x.scriptDetach"), "ok",
                        I18n.tr("server.um.javaPreflight.9"));
            }

            // Via di ritorno: un pacchetto ricostruito dai file INSTALLATI, non scaricato dal
            // repository. Se il repository non ha piu' la versione vecchia, e' l'unico modo.
            long liberi = number(sh("df -k /var/db | tail -1 | awk '{print $4}'", 30)) / 1024;
            long grande = number(sh("pkg query %sb " + pkg + " 2>/dev/null", 30)) / 1024 / 1024;
            r.put("spazioMb", liberi).put("jdkMb", grande);
            if (grande > 0 && liberi < grande * 2) {
                aggiungiCheck(checks, "spazio", I18n.tr("server.um.javaPreflight.10"), "block",
                        I18n.tr("server.um.javaPreflight.11", java.util.Map.of("p", String.valueOf((grande * 2)), "liberi", String.valueOf(liberi))));
                blocca = true;
            } else {
                aggiungiCheck(checks, "spazio", I18n.tr("server.um.javaPreflight.10"), "ok",
                        I18n.tr("server.um.javaPreflight.12", java.util.Map.of("grande", String.valueOf(grande), "jDK_DIR", String.valueOf(JDK_DIR), "liberi", String.valueOf(liberi))));
            }

            aggiungiCheck(checks, "down", "Interruzione", "attendi",
                    I18n.tr("server.um.javaPreflight.13"));

            r.put("success", true).put("checks", checks)
             .put("blocked", blocca).put("canProceed", !blocca);
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
        String rifiuto = PackageQueue.prendi(id, I18n.tr("server.um.startJavaUpdate.1"));
        if (rifiuto != null) return new JSONObject().put("success", false).put("error", rifiuto);
        try { return avviaAggiornamentoJavaOra(); }
        finally { PackageQueue.rilascia(id); }
    }

    private static JSONObject avviaAggiornamentoJavaOra() {
        try {
            JSONObject pf = javaPreflight();
            if (!pf.optBoolean("canProceed", false))
                return new JSONObject().put("success", false)
                        .put("error", pf.optBoolean("gia", false)
                                ? I18n.tr("server.um.x.alreadyLatest") : I18n.tr("server.um.avviaAggiornamentoJavaOra.1"));
            String pkg = pf.getString("pkg");
            if (!isValidName(pkg)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.cambiaProtezioni.1"));
            JSONObject st = pf.getJSONObject("riavvio");
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.repairNginxPathInfo.10"));
            String bk = JDK_DIR + "/" + ts;
            String log = bk + ".log";
            if (!ok("mkdir -p " + bk, 30))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.avviaAggiornamentoJavaOra.2", java.util.Map.of("bk", String.valueOf(bk))));

            long pid = ProcessHandle.current().pid();
            int porta = portaInAscolto(pid);

            String script = scriptAggiornamentoJava(pkg, pf.optString("home"), bk, log, pid,
                    st.getString("riga"), st.getString("dir"), porta);
            String path = bk + "/aggiorna-jdk.sh";
            Files.writeString(Paths.get(path), script);
            ok("chmod 700 " + path, 15);

            // Uno script che non si legge non si esegue: meglio scoprirlo adesso che a pannello spento.
            String sint = sh("sh -n " + path + " 2>&1", 30);
            if (!sint.trim().isEmpty())
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.avviaAggiornamentoJavaOra.4", java.util.Map.of("trim", String.valueOf(sint.trim()))));

            // Il pannello segna i pacchetti unlockedPackages: se lo script morisse a meta', al prossimo
            // avvio restoreLocksAfterCrash() li riprotegge da solo. Se l'elenco non si scrive,
            // lo script non parte. Finche' l'elenco c'e', nessun altro lavoro sui pacchetti parte:
            // lo script lavora fuori dal pannello, e il turno del pannello non lo vede.
            String errStato = PackageQueue.scriviStato(java.util.List.of(pkg));
            if (errStato != null)
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.avviaAggiornamentoJavaOra.5", java.util.Map.of("errStato", String.valueOf(errStato))));
            if (!ok("/usr/sbin/daemon -f -- /bin/sh " + path, 30)) {
                pulisciStato();
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.avviaAggiornamentoJavaOra.6", java.util.Map.of("path", String.valueOf(path))));
            }
            return new JSONObject().put("success", true).put("log", log)
                    .put("nota", st.getString("nota"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /** L'ultimo resoconto lasciato dallo script, da rileggere quando il pannello e' tornato su. */
    public static JSONObject javaUpdateStatus() {
        try {
            String ultimo = sh("ls -1t " + JDK_DIR + "/*.log 2>/dev/null | head -1").trim();
            if (ultimo.isEmpty())
                return new JSONObject().put("success", true).put("presente", false);
            String testo = sh("cat " + ultimo + " 2>/dev/null", 30);
            boolean finito = testo.contains("=== ESITO:");
            boolean riuscito = testo.contains("=== ESITO: RIUSCITO");
            // I marcatori restano fissi nel file (si rileggono qui sopra); a chi legge si mostrano
            // nella sua lingua
            String mostrato = testo.replace("=== ESITO: RIUSCITO", "=== " + I18n.tr("server.um.jvs.outcomeOk"))
                    .replace("=== ESITO: ANNULLATO", "=== " + I18n.tr("server.um.jvs.outcomeCancelled"))
                    .replace("=== ESITO: DA CONTROLLARE", "=== " + I18n.tr("server.um.jvs.outcomeCheck"));
            return new JSONObject().put("success", true).put("presente", true)
                    .put("file", ultimo).put("testo", mostrato).put("finito", finito)
                    .put("riuscito", riuscito);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    private static String scriptAggiornamentoJava(String pkg, String home, String bk, String log,
                                                  long pid, String rigaAvvio, String dir, int porta) {
        // Le righe che lo script stampa sono nella lingua di chi ha avviato l'aggiornamento; le
        // righe "=== ESITO: ... ===" restano fisse, perche' javaUpdateStatus le rilegge.
        return "#!/bin/sh\n"
          + "# Generated by the panel: it updates the JVM the panel itself runs on.\n"
          + "exec >> '" + log + "' 2>&1\n"
          + "echo \"=== $(date) ===\"\n"
          + eco(I18n.tr("server.um.jvs.title")) + "\n"
          + "PKG='" + pkg + "'\n"
          + "BK='" + bk + "'\n"
          + "JAVA='" + home + "/bin/java'\n"
          + "\n"
          + eco(I18n.tr("server.um.jvs.s1")) + "\n"
          + "if pkg create -o \"$BK\" \"$PKG\"; then\n"
          + "  # pkg create makes .pkg on recent versions and .txz on older ones: the way back is not\n"
          + "  # tied to an extension, otherwise it would disappear for no reason.\n"
          + "  VIA=$(ls -1 \"$BK\"/${PKG}-* 2>/dev/null | head -1)\n"
          + "  if [ -n \"$VIA\" ]; then " + eco(I18n.tr("server.um.jvs.wayBack")) + "; else\n"
          + "    " + eco(I18n.tr("server.um.jvs.noFile")) + "\n"
          + "    " + eco(I18n.tr("server.um.jvs.cancelled")) + "\n"
          + "    echo '=== ESITO: ANNULLATO ==='; exit 1; fi\n"
          + "else\n"
          + "  " + eco(I18n.tr("server.um.jvs.createFailed")) + "\n"
          + "  " + eco(I18n.tr("server.um.jvs.cancelled")) + "\n"
          + "  echo '=== ESITO: ANNULLATO ==='; exit 1\n"
          + "fi\n"
          + "\n"
          + eco(I18n.tr("server.um.jvs.s2")) + "\n"
          + "kill " + pid + " 2>/dev/null\n"
          + "i=0\n"
          + "while kill -0 " + pid + " 2>/dev/null; do\n"
          + "  i=$((i+1)); [ $i -ge 45 ] && break; sleep 1\n"
          + "done\n"
          + "if kill -0 " + pid + " 2>/dev/null; then\n"
          + "  " + eco(I18n.tr("server.um.jvs.forceKill")) + "\n"
          + "  kill -9 " + pid + " 2>/dev/null; sleep 2\n"
          + "fi\n"
          + eco(I18n.tr("server.um.jvs.stopped")) + "\n"
          + "\n"
          + eco(I18n.tr("server.um.jvs.s3")) + "\n"
          + "pkg unlock -y \"$PKG\"\n"
          + "if pkg upgrade -y \"$PKG\"; then ESITO_UP=0; else ESITO_UP=1; " + eco(I18n.tr("server.um.jvs.upgradeFailed")) + "; fi\n"
          + "\n"
          + eco(I18n.tr("server.um.jvs.s4")) + "\n"
          + "if \"$JAVA\" -version 2>&1; then\n"
          + "  " + eco(I18n.tr("server.um.jvs.javaOk")) + "\n"
          + "else\n"
          + "  " + eco(I18n.tr("server.um.jvs.javaKo")) + "\n"
          + "  pkg add -f \"$VIA\" && " + eco(I18n.tr("server.um.jvs.prevBack")) + " || " + eco(I18n.tr("server.um.jvs.restoreFailed")) + "\n"
          + "  \"$JAVA\" -version 2>&1 || " + eco(I18n.tr("server.um.jvs.javaStillKo")) + "\n"
          + "fi\n"
          + "\n"
          + eco(I18n.tr("server.um.jvs.s5")) + "\n"
          + "pkg lock -y \"$PKG\" && " + eco(I18n.tr("server.um.jvs.relocked")) + " || " + eco(I18n.tr("server.um.jvs.relockFailed")) + "\n"
          + "mkdir -p /var/db/mailpanel\n"
          + "# The log is appended forever: above 10 MB it is set aside, so it does not grow\n"
          + "# without end and a copy of what was there before still remains.\n"
          + "if [ -f '" + LOG_PANNELLO + "' ] && [ $(stat -f %z '" + LOG_PANNELLO + "') -gt 10485760 ]; then\n"
          + "  mv '" + LOG_PANNELLO + "' '" + LOG_PANNELLO + ".1'\n"
          + "fi\n"
          + "cd " + apiciShell(dir) + " || " + eco(I18n.tr("server.um.jvs.noCd", java.util.Map.of("d", String.valueOf(dir)))) + "\n"
          + rigaAvvio + "\n"
          + "\n"
          + eco(I18n.tr("server.um.jvs.s6")) + "\n"
          + "SU=1\n"
          + (porta > 0
             ? "j=0\n"
             + "while [ $j -lt 90 ]; do\n"
             + "  # -46l and not -4l: the JVM can open the socket in IPv6, and with -4l the panel would\n"
             + "  # look off while it is up. The grep skips the header line. The final boundary is not\n"
             + "  # the end of the line: sockstat prints another column after the local address, so\n"
             + "  # with '$' it would never match. The boundary is a space or the end of the line.\n"
             + "  if sockstat -46l -p " + porta + " 2>/dev/null | grep -qE '[:.]" + porta + "([[:space:]]|$)'; then SU=0; break; fi\n"
             + "  j=$((j+1)); sleep 1\n"
             + "done\n"
             + "[ $SU -eq 0 ] && " + eco(I18n.tr("server.um.jvs.listening", java.util.Map.of("porta", String.valueOf(porta))))
             + " || " + eco(I18n.tr("server.um.jvs.notListening", java.util.Map.of("porta", String.valueOf(porta)))) + "\n"
             : eco(I18n.tr("server.um.jvs.noPort")) + "\nSU=0\n")
          + "\n"
          + "if [ $ESITO_UP -eq 0 ] && [ $SU -eq 0 ]; then\n"
          + "  echo \"=== ESITO: RIUSCITO ($(date)) ===\"\n"
          + "  " + eco(I18n.tr("server.um.jvs.keepBack")) + "\n"
          + "  " + eco(I18n.tr("server.um.jvs.panelLog", java.util.Map.of("f", String.valueOf(LOG_PANNELLO)))) + "\n"
          + "else\n"
          + "  echo \"=== ESITO: DA CONTROLLARE ($(date)) ===\"\n"
          + "  echo \"upgrade=$ESITO_UP  panel_up=$SU  way_back=$VIA\"\n"
          + "fi\n";
    }

    /**
     * Una riga "echo" per uno script: il testo fra apici singoli, quindi la shell non espande
     * niente di cio' che c'e' dentro; i segnaposto {MAIUSCOLO} diventano variabili della shell.
     */
    private static String eco(String testo) {
        StringBuilder sb = new StringBuilder("echo ");
        Matcher m = Pattern.compile("\\{([A-Z_]{1,20})\\}").matcher(testo);
        int ultimo = 0;
        while (m.find()) {
            sb.append(apiciShell(testo.substring(ultimo, m.start()))).append("\"$").append(m.group(1)).append('"');
            ultimo = m.end();
        }
        return sb.append(apiciShell(testo.substring(ultimo))).toString();
    }

    private static String apiciShell(String s) {
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
    static JSONObject analizzaAutoremove(String out, String prefissoAtteso) {
        // Il prefisso arriva come "py311-": se ne ricava la versione per riconoscere anche
        // l'interprete "python311", che della famiglia fa parte quanto gli altri.
        final String verPy = prefissoAtteso != null && prefissoAtteso.startsWith("py")
                ? prefissoAtteso.replaceAll("[^0-9]", "") : "";
        JSONObject r = new JSONObject();
        java.util.List<String> rimossi = new ArrayList<>(), estranei = new ArrayList<>();
        String o = out == null ? "" : out;
        if (o.toLowerCase().contains("nothing to do")) {
            return r.put("leggibile", true).put("quanti", 0)
                    .put("rimossi", new JSONArray()).put("estranei", new JSONArray());
        }
        int dichiarati = -1;
        java.util.regex.Matcher mn = Pattern.compile(
                "(?i)number of packages to be removed:\\s*([0-9]+)").matcher(o);
        if (mn.find()) dichiarati = Integer.parseInt(mn.group(1));

        boolean dentro = false;
        for (String riga : o.split("\n")) {
            if (riga.matches("(?i).*packages to be REMOVED:\\s*")) { dentro = true; continue; }
            if (!dentro) continue;
            if (riga.trim().isEmpty()) { dentro = false; continue; }
            java.util.regex.Matcher m = Pattern.compile(
                    "^[ \\t]+([A-Za-z0-9._+-]+):[ \\t]").matcher(riga);
            if (!m.find()) { dentro = false; continue; }
            rimossi.add(m.group(1));
            if (!(m.group(1).startsWith(prefissoAtteso)
                    || (!verPy.isEmpty() && m.group(1).equals("python" + verPy))))
                estranei.add(m.group(1));
        }
        boolean leggibile = dichiarati >= 0 && rimossi.size() == dichiarati;
        return r.put("leggibile", leggibile)
                .put("quanti", dichiarati < 0 ? rimossi.size() : dichiarati)
                .put("rimossi", new JSONArray(rimossi))
                .put("estranei", new JSONArray(estranei));
    }


    /** Versione predefinita di Python secondo bsd.default-versions.mk, senza il punto: "312". */
    private static String pyPredefinito() {
        // Una sola fonte: la stessa tabella che alimenta la scheda "Coerenza predefiniti".
        // Se domani il predefinito dei port passa a 3.13, questa procedura lo segue da sola.
        for (String[] riga : PREDEFINITI) {
            if ("Python".equals(riga[0])) return riga[1].replace(".", "");
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
    static boolean famigliaPython(String nome, String versione) {
        return nome != null && (nome.startsWith("py" + versione + "-") || nome.equals("python" + versione));
    }

    /** I py3XX-* installati su richiesta (non tirati dentro come dipendenza). Sono quelli da spostare. */
    private static java.util.List<String> pythonDaSpostare(String vecchio) {
        java.util.List<String> l = new ArrayList<>();
        for (String r : sh("pkg query '%n %a' 2>/dev/null").split("\n")) {
            String[] c = r.trim().split("\\s+");
            if (c.length != 2) continue;
            if (c[0].startsWith("py" + vecchio + "-") && "0".equals(c[1])) l.add(c[0]);
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
        boolean blocca = false;
        try {
            String nuovo = pyPredefinito();
            String vecchio = null;
            for (String r2 : sh("pkg query %n 2>/dev/null").split("\n")) {
                java.util.regex.Matcher m = Pattern.compile("^py(3[0-9]{2})-").matcher(r2.trim());
                if (m.find() && !m.group(1).equals(nuovo)) {
                    if (vecchio == null || m.group(1).compareTo(vecchio) < 0) vecchio = m.group(1);
                }
            }
            r.put("nuovo", nuovo);
            if (vecchio == null) {
                aggiungiCheck(checks, "ver", I18n.tr("server.um.pythonPreflight.1"), "ok",
                        I18n.tr("server.um.pythonPreflight.2", java.util.Map.of("nuovo", String.valueOf(nuovo))));
                return r.put("success", true).put("checks", checks)
                        .put("canProceed", false).put("blocked", false).put("gia", true);
            }
            r.put("vecchio", vecchio);
            aggiungiCheck(checks, "ver", I18n.tr("server.um.pythonPreflight.1"), "attendi",
                    I18n.tr("server.um.pythonPreflight.3", java.util.Map.of("vecchio", String.valueOf(vecchio), "nuovo", String.valueOf(nuovo))));

            final String vec = vecchio;
            java.util.List<String> leaf = pythonDaSpostare(vec);
            long tot = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + vec + "-")).count();
            if (leaf.isEmpty()) {
                aggiungiCheck(checks, "leaf", I18n.tr("server.um.pythonPreflight.4"), "block",
                        I18n.tr("server.um.pythonPreflight.5", java.util.Map.of("tot", String.valueOf(tot), "vecchio", String.valueOf(vecchio))));
                blocca = true;
            } else {
                aggiungiCheck(checks, "leaf", I18n.tr("server.um.pythonPreflight.4"), "ok",
                        String.join(", ", leaf) + "  " + I18n.tr("server.um.x.pyDepsFollow", java.util.Map.of("n", String.valueOf((tot - leaf.size())))));
            }
            r.put("leaf", new JSONArray(leaf));

            // Esiste il corrispondente py312 per ognuno? Senza, il passaggio lascerebbe un buco.
            java.util.List<String> nuovi = new ArrayList<>(), mancanti = new ArrayList<>();
            for (String v : leaf) {
                String n = "py" + nuovo + "-" + v.substring(("py" + vecchio + "-").length());
                if (!isValidName(n)) continue;
                if (sh("pkg rquery -U %n " + n + " 2>/dev/null").trim().isEmpty()) mancanti.add(n);
                else nuovi.add(n);
            }
            r.put("nuovi", new JSONArray(nuovi));
            if (!mancanti.isEmpty()) {
                aggiungiCheck(checks, "repo", I18n.tr("server.um.pythonPreflight.6"), "block",
                        I18n.tr("server.um.x.pyNoCounterpart", java.util.Map.of("nuovo", String.valueOf(nuovo), "elenco", String.valueOf(String.join(", ", mancanti)))));
                blocca = true;
            } else if (!nuovi.isEmpty()) {
                aggiungiCheck(checks, "repo", I18n.tr("server.um.pythonPreflight.6"), "ok",
                        I18n.tr("server.um.x.pyAllCounterparts", java.util.Map.of("elenco", String.valueOf(String.join(", ", nuovi)))));
            }

            // Chi dipende dai pacchetti che sto per togliere? Se qualcuno dipende, toglierli
            // porterebbe via anche lui: e' esattamente il caso da non scoprire a cose fatte.
            // Attenzione all'ovvio che non e' ovvio: py311-certbot-nginx DIPENDE da py311-certbot,
            // e si spostano insieme. Un dipendente che fa parte della stessa famiglia py<vecchio>
            // non e' un problema, perche' sparisce e rinasce anche lui. Il problema e' solo un
            // dipendente ESTERNO, che resterebbe senza cio' da cui dipende.
            java.util.List<String> conDipendenti = new ArrayList<>();
            for (String v : leaf) {
                if (!isValidName(v)) continue;
                java.util.List<String> esterni = new ArrayList<>();
                for (String d : sh("pkg query %rn " + v + " 2>/dev/null").split("\n")) {
                    String t = d.trim();
                    if (t.isEmpty() || t.startsWith("py" + vec + "-")) continue;
                    esterni.add(t);
                }
                if (!esterni.isEmpty()) conDipendenti.add(v + " <- " + String.join(", ", esterni));
            }
            if (!conDipendenti.isEmpty()) {
                aggiungiCheck(checks, "dip", I18n.tr("server.um.pythonPreflight.7"), "block",
                        I18n.tr("server.um.x.rmPullsOthers", java.util.Map.of("elenco", String.valueOf(String.join(" ; ", conDipendenti)))));
                blocca = true;
            } else {
                aggiungiCheck(checks, "dip", I18n.tr("server.um.pythonPreflight.7"), "ok",
                        I18n.tr("server.um.pythonPreflight.8"));
            }

            // Simulazione vera: e' l'unico modo di sapere quali file collidono.
            if (!nuovi.isEmpty()) {
                String sim = sh("pkg install -n " + String.join(" ", nuovi) + " 2>&1", 300);
                boolean coll = sim.toLowerCase().contains("conflicts with");
                r.put("conflitto", coll);
                if (coll) {
                    java.util.List<String> righe = new ArrayList<>();
                    for (String l2 : sim.split("\n")) if (l2.toLowerCase().contains("conflict")) righe.add(l2.trim());
                    aggiungiCheck(checks, "sim", I18n.tr("server.um.pythonPreflight.9"), "attendi",
                            I18n.tr("server.um.x.pyCollide", java.util.Map.of("righe", String.valueOf(String.join(" | ", righe)), "vecchio", String.valueOf(vecchio))));
                } else {
                    aggiungiCheck(checks, "sim", I18n.tr("server.um.pythonPreflight.9"), "ok",
                            I18n.tr("server.um.pythonPreflight.10"));
                }
            }

            // Servizi coinvolti: quelli vanno fermati e riavviati, e verificati dopo.
            java.util.List<String> serviziTocc = new ArrayList<>();
            for (String v : leaf) {
                String base = v.substring(("py" + vecchio + "-").length());
                String svc = nomeServizioReale(base);
                if (svc != null) serviziTocc.add(svc);
            }
            r.put("servizi", new JSONArray(serviziTocc));
            aggiungiCheck(checks, "svc", I18n.tr("server.um.x.servicesInvolved"), "ok", serviziTocc.isEmpty()
                    ? I18n.tr("server.um.pythonPreflight.11")
                    : I18n.tr("server.um.x.svcStopStart", java.util.Map.of("elenco", String.valueOf(String.join(", ", serviziTocc)))));

            // Cosa toglierebbe autoremove. Se tocca roba che non e' py<vecchio>, non lo si esegue.
            JSONObject an = analizzaAutoremove(sh("pkg autoremove -n 2>&1", 180), "py" + vec + "-");
            java.util.List<String> estranei = jsonArrayToList(an.optJSONArray("estranei"));
            r.put("autoremoveEstranei", new JSONArray(estranei));
            if (!an.optBoolean("leggibile", false)) {
                aggiungiCheck(checks, "auto", I18n.tr("server.um.x.autoremoveTitle"), "attendi",
                        I18n.tr("server.um.pythonPreflight.12"));
            } else {
                aggiungiCheck(checks, "auto", I18n.tr("server.um.x.autoremoveTitle"), estranei.isEmpty() ? "ok" : "attendi",
                        estranei.isEmpty()
                        ? (an.optInt("quanti", 0) == 0 ? I18n.tr("server.um.x.noOrphans")
                           : I18n.tr("server.um.x.onlyPyOrphans", java.util.Map.of("vec", String.valueOf(vec), "n", String.valueOf(an.optInt("quanti", 0)))))
                        : I18n.tr("server.um.x.foreignOrphans", java.util.Map.of("elenco", String.valueOf(String.join(", ", estranei)))));
            }

            aggiungiCheck(checks, "backup", I18n.tr("server.um.pythonPreflight.13"), "ok",
                    I18n.tr("server.um.pythonPreflight.14"));

            r.put("success", true).put("checks", checks)
             .put("blocked", blocca).put("canProceed", !blocca && !nuovi.isEmpty());
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
    static JSONObject riferimentiInterprete(String vecchia) {
        JSONObject r = new JSONObject();
        JSONArray issues = new JSONArray(), innocui = new JSONArray(), citazioni = new JSONArray();
        // 311 -> 3\.11 : il punto va protetto, altrimenti nel regex combacia con qualunque
        // carattere e "python3x11" verrebbe contato come riferimento.
        String punto = vecchia.length() == 3
                ? vecchia.charAt(0) + "\\." + vecchia.substring(1) : vecchia;

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
        String[] modi = {
            "^#!.*python" + punto,
            "/usr/local/bin/python" + punto,
            "env[[:space:]]+python" + punto,
        };
        StringBuilder e = new StringBuilder();
        for (String m : modi) e.append("-e '").append(m).append("' ");

        String dove = "/etc /usr/local/etc /usr/local/bin /usr/local/sbin /usr/local/libexec "
                + "/usr/local/www /root /var/cron /var/spool/cron /home";
        // Fuori: i file dei pacchetti Python (spariscono con loro) e le pagine che il pannello
        // genera da se'. Quelle non sono script di nessuno: le scrivo io a ogni avvio.
        String mieFuori = "";
        try {
            String jar = jarPath();
            if (!jar.isEmpty()) {
                String dirJar = Paths.get(jar).getParent().toString();
                mieFuori = " | grep -v '^" + dirJar + "/admin/'";
            }
        } catch (Exception ignored) { }

        String cmd = "grep -rIl " + e.toString().trim() + " " + dove
                + " 2>/dev/null | grep -v '^/usr/local/lib/python'"
                + " | grep -viE '\\.(html?|md|log|bak|orig|sample)$'" + mieFuori + " | head -300";
        String out = sh(cmd, 300);
        int esaminati = 0;
        for (String f : out.split("\n")) {
            String file = f.trim();
            if (file.isEmpty()) continue;
            esaminati++;
            String prop = sh("pkg which -q " + file + " 2>/dev/null", 20).trim();
            String nome = prop.isEmpty() ? "" : sh("pkg query %n " + prop + " 2>/dev/null", 20).trim();
            boolean dellaFamiglia = !nome.isEmpty() && famigliaPython(nome, vecchia);

            // Un file che NOMINA il percorso dell'interprete non lo esegue per forza: un testo
            // che lo cita combacia come uno script che lo lancia, e grep non sa distinguerli.
            // La differenza la fanno due fatti verificabili: il file e' runnable, oppure sta
            // dove il sistema va a prendere cose da eseguire (cron, rc.d). Tutto il resto e'
            // molto probabilmente prosa, e non deve sbarrare una rimozione legittima — ma
            // finisce comunque in un elenco a parte, perche' "probabile" non e' "certo".
            boolean runnable = ok("test -x " + file, 10);
            boolean postoDiEsecuzione = file.startsWith("/var/cron/") || file.startsWith("/var/spool/cron/")
                    || file.startsWith("/usr/local/etc/rc.d/") || file.startsWith("/etc/rc.d/")
                    || file.startsWith("/etc/periodic/") || file.startsWith("/usr/local/etc/periodic/")
                    || file.equals("/etc/crontab") || file.startsWith("/etc/rc.conf");
            // La riga che ha fatto scattare il controllo: senza, chi legge non puo' giudicare
            // se sia un'esecuzione vera o una citazione.
            String riga = sh("grep -m1 -hIE " + e.toString().trim().replace("-e ", "-e ")
                    + " " + file + " 2>/dev/null | head -c 160", 20).trim();
            JSONObject v = new JSONObject().put("file", file).put("riga", riga)
                    .put("proprietario", nome.isEmpty()
                            ? (prop.isEmpty() ? I18n.tr("server.um.riferimentiInterprete.1") : prop) : nome);
            v.put("runnable", runnable).put("postoDiEsecuzione", postoDiEsecuzione);
            if (dellaFamiglia) innocui.put(v);
            else if (runnable || postoDiEsecuzione) issues.put(v);
            else citazioni.put(v);
        }
        return r.put("esaminati", esaminati).put("issues", issues).put("innocui", innocui)
                .put("citazioni", citazioni).put("comando", cmd);
    }

    /** I resti del vecchio Python; con esegui, li toglie, sul turno dei lavori sui pacchetti. */
    public static JSONObject pythonLeftovers(boolean esegui) {
        if (!esegui) return restiPythonOra(false);
        String id = "restipy-" + System.nanoTime();
        String rifiuto = PackageQueue.prendi(id, I18n.tr("server.um.pythonLeftovers.1"));
        if (rifiuto != null) return new JSONObject().put("success", false).put("error", rifiuto);
        try { return restiPythonOra(true); }
        finally { PackageQueue.rilascia(id); }
    }

    private static JSONObject restiPythonOra(boolean esegui) {
        JSONObject r = new JSONObject();
        try {
            String nuovo = pyPredefinito();
            java.util.LinkedHashSet<String> vecchie = new java.util.LinkedHashSet<>();
            for (String n : sh("pkg query %n 2>/dev/null").split("\n")) {
                Matcher m = Pattern.compile("^(?:py|python)(3[0-9]{2})(?:-|$)").matcher(n.trim());
                if (m.find() && !m.group(1).equals(nuovo)) vecchie.add(m.group(1));
            }
            if (vecchie.isEmpty())
                return r.put("success", true).put("niente", true)
                        .put("nota", I18n.tr("server.um.restiPythonOra.1", java.util.Map.of("nuovo", String.valueOf(nuovo))));
            r.put("vecchie", new JSONArray(vecchie));

            java.util.List<String> famiglia = new ArrayList<>();
            for (String v : vecchie)
                for (String n : sh("pkg query %n 2>/dev/null").split("\n"))
                    if (famigliaPython(n.trim(), v)) famiglia.add(n.trim());

            JSONArray dettaglio = new JSONArray();
            java.util.List<String> togliibili = new ArrayList<>(), trattenuti = new ArrayList<>();
            for (String n : famiglia) {
                if (!isValidName(n)) continue;
                String ver = sh("pkg query %v " + n + " 2>/dev/null", 20).trim();
                long kb = number(sh("pkg query %sb " + n + " 2>/dev/null", 20)) / 1024;
                java.util.List<String> chi = new ArrayList<>();
                for (String d : sh("pkg query %rn " + n + " 2>/dev/null").split("\n")) {
                    String t = d.trim();
                    if (!t.isEmpty()) chi.add(t);
                }
                // Un dipendente che e' anch'esso della famiglia sparira' prima: non trattiene.
                java.util.List<String> esterni = new ArrayList<>();
                for (String c : chi) if (!famiglia.contains(c)) esterni.add(c);
                boolean libero = esterni.isEmpty();
                (libero ? togliibili : trattenuti).add(n);
                dettaglio.put(new JSONObject().put("nome", n).put("versione", ver).put("kb", kb)
                        .put("libero", libero).put("trattenutoDa", new JSONArray(esterni)));
            }
            r.put("dettaglio", dettaglio).put("togliibili", new JSONArray(togliibili))
             .put("trattenuti", new JSONArray(trattenuti));

            // Chi nomina il vecchio interprete fra cio' che resta: pkg non lo sa, va cercato.
            JSONObject rif = riferimentiInterprete(vecchie.iterator().next());
            r.put("references", rif);
            if (!esegui || togliibili.isEmpty()) return r.put("success", true).put("eseguito", false);
            if (rif.getJSONArray("issues").length() > 0)
                return r.put("success", false).put("eseguito", false)
                        .put("error", I18n.tr("server.um.x.pyRefsLeft", java.util.Map.of("n", String.valueOf(rif.getJSONArray("issues").length()))));

            // Passaggi ripetuti: a ogni giro si tolgono quelli che in QUEL momento non hanno
            // piu' nessuno che li richieda.
            JSONArray tolti = new JSONArray(), falliti = new JSONArray();
            java.util.List<String> restanti = new ArrayList<>(famiglia);
            for (int giro = 0; giro < 6 && !restanti.isEmpty(); giro++) {
                boolean qualcosa = false;
                for (String n : new ArrayList<>(restanti)) {
                    if (!isValidName(n) || !ok("pkg info -e " + n, 15)) { restanti.remove(n); continue; }
                    String dip = sh("pkg query %rn " + n + " 2>/dev/null").trim();
                    if (!dip.isEmpty()) continue;                      // ancora richiesto: al prossimo giro
                    boolean eraProtetto = bloccato(sh("pkg lock -l 2>/dev/null"), n);
                    if (eraProtetto) ok("pkg unlock -y " + n, 30);
                    if (ok("pkg delete -y " + n, 300)) { tolti.put(n); qualcosa = true; }
                    else {
                        falliti.put(n);
                        // Se la rimozione non riesce, il pacchetto resta: e allora deve restare
                        // com'era, protetto. Sbloccarlo e lasciarlo cosi' sarebbe peggio che non
                        // averci provato, perche' il prossimo aggiornamento potrebbe toccarlo.
                        if (eraProtetto) ok("pkg lock -y " + n, 30);
                    }
                    restanti.remove(n);
                }
                if (!qualcosa) break;
            }
            r.put("eseguito", true).put("tolti", tolti).put("falliti", falliti)
             .put("restano", new JSONArray(restanti));
            // Verifica: quanti pacchetti della vecchia famiglia sono ancora installati.
            long ancora = 0;
            for (String v : vecchie)
                ancora += sh("pkg query %n 2>/dev/null").lines().filter(x -> famigliaPython(x, v)).count();
            r.put("ancoraPresenti", ancora);
            return r.put("success", true);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject startPythonTransition() {
        String id = "py-" + System.currentTimeMillis();
        Job j = new Job(id, "python");
        return avviaSulTurno(id, j, I18n.tr("server.um.startPythonTransition.1"), "python-move", () -> runPassaggioPython(j));
    }

    private static void runPassaggioPython(Job job) {
        job.status = "running";
        final int TOT = 7;
        java.util.List<String> unlockedPackages = new ArrayList<>();
        java.util.List<String> daRibloccare = new ArrayList<>();
        // L'elenco scritto su disco da questa esecuzione: vuoto finche' non e' scritto.
        java.util.List<String> elencoSuDisco = new ArrayList<>();
        try {
            job.avanza(1, TOT);
            job.scrivi(I18n.tr("server.um.runPassaggioPython.1"));
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.1", java.util.Map.of("tOT", String.valueOf(TOT))));
            JSONObject pf = pythonPreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("gia", false)
                        ? I18n.tr("server.um.runPassaggioPython.2") : I18n.tr("server.um.runMigrazione84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.scrivi(I18n.tr("server.um.runMigrazione84.4"));
                return;
            }
            String vecchio = pf.getString("vecchio"), nuovo = pf.getString("nuovo");
            java.util.List<String> leaf = jsonArrayToList(pf.optJSONArray("leaf"));
            java.util.List<String> nuovi = jsonArrayToList(pf.optJSONArray("nuovi"));
            java.util.List<String> servizi = jsonArrayToList(pf.optJSONArray("servizi"));
            job.scrivi("  py" + vecchio + " -> py" + nuovo);
            job.scrivi("  " + String.join(", ", leaf));

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runPassaggioPython.3", java.util.Map.of("tOT", String.valueOf(TOT))));
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            String bk = "/var/db/mailpanel/python/" + ts;
            if (!ok("mkdir -p " + bk, 30)) throw new IllegalStateException("cannot create " + bk);
            sh("pkg query '%n %v' > " + bk + "/pacchetti-prima.txt 2>/dev/null", 60);
            for (String d : new String[]{"/usr/local/etc/fail2ban", "/usr/local/etc/letsencrypt"}) {
                if (!ok("test -d " + d, 10)) { job.scrivi(I18n.tr("server.um.runPassaggioPython.5", java.util.Map.of("d", String.valueOf(d)))); continue; }
                String nome = d.substring(d.lastIndexOf('/') + 1);
                if (!ok("tar -cf " + bk + "/" + nome + ".tar -C " + d + " . 2>/dev/null", 300))
                    throw new IllegalStateException("copy of " + d + " failed");
                long n = number(sh("tar -tf " + bk + "/" + nome + ".tar 2>/dev/null | wc -l", 60));
                if (n < 1) throw new IllegalStateException("the copy of " + d + " is empty");
                job.scrivi("    " + d + " -> " + nome + ".tar " + I18n.tr("server.um.x.entries", java.util.Map.of("n", String.valueOf(n))));
            }
            job.scrivi("    " + I18n.tr("server.um.x.copiesIn", java.util.Map.of("dir", String.valueOf(bk))));

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi("[3/" + TOT + "] " + I18n.tr("server.um.x.stoppingSvcs"));
            if (servizi.isEmpty()) job.scrivi("    " + I18n.tr("server.um.x.none"));
            for (String s : servizi) {
                boolean era = ok("service " + s + " status", 20);
                if (era) { ok("service " + s + " stop", 120); job.scrivi(I18n.tr("server.um.runPassaggioPython.6", java.util.Map.of("s", String.valueOf(s)))); }
                else job.scrivi("    " + s + ": " + I18n.tr("server.um.x.wasStopped"));
            }

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi("[4/" + TOT + "] " + I18n.tr("server.um.x.pySwap", java.util.Map.of("vecchio", String.valueOf(vecchio), "nuovo", String.valueOf(nuovo))));
            String list = sh("pkg lock -l 2>/dev/null");
            java.util.List<String> daSbloccare = new ArrayList<>();
            for (String v : leaf) if (bloccato(list, v)) daSbloccare.add(v);
            // L'elenco su disco PRIMA di sbloccare (prima lo si scriveva dopo): i vecchi, che vanno
            // riprotetti se restano, e i nuovi, che alla fine vanno protetti. Se il pannello muore
            // in mezzo, l'avvio protegge quelli che trova installati. Se l'elenco non si scrive,
            // non si tocca niente.
            java.util.List<String> daElencare = new ArrayList<>(daSbloccare);
            for (String n : nuovi) if (isValidName(n) && !daElencare.contains(n)) daElencare.add(n);
            String errStato = PackageQueue.scriviStato(daElencare);
            if (errStato != null)
                throw new IllegalStateException("I could not save the list for the restore, so I did not touch anything: " + errStato);
            elencoSuDisco.addAll(daElencare);
            for (String v : daSbloccare) { ok("pkg unlock -y " + v, 30); unlockedPackages.add(v); }
            if (!unlockedPackages.isEmpty()) job.scrivi("    " + I18n.tr("server.um.x.unlockedList", java.util.Map.of("elenco", String.valueOf(String.join(", ", unlockedPackages)))));
            // L'ordine conta: prima togliere, poi installare. Cosi' nessun file va forzato,
            // ed e' esattamente l'errore che ha rotto il client MySQL.
            StringBuilder catDel = new StringBuilder();
            int cd = eseguiConLog(job, "pkg delete -y " + String.join(" ", leaf) + " 2>&1", 900, catDel);
            if (cd != 0) throw new IllegalStateException("pkg delete exited with code " + cd);
            StringBuilder catIns = new StringBuilder();
            int ci = eseguiConLog(job, "pkg install -y " + String.join(" ", nuovi) + " 2>&1", 1800, catIns);
            if (ci != 0) {
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runPassaggioPython.7"));
                job.scrivi(I18n.tr("server.um.x.toGoBack", java.util.Map.of("cmd", String.valueOf("pkg install -y " + String.join(" ", leaf)))));
                throw new IllegalStateException("pkg install exited with code " + ci);
            }
            daRibloccare.addAll(nuovi);
            for (String m : messaggiCheChiedonoAzione(catIns.toString()))
                job.scrivi("    " + I18n.tr("server.um.x.pkgAsks", java.util.Map.of("m", String.valueOf(m.replace("\n", " | ")))));

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runPassaggioPython.8", java.util.Map.of("tOT", String.valueOf(TOT))));
            String ar = sh("pkg autoremove -n 2>&1", 180);
            JSONObject an = analizzaAutoremove(ar, "py" + vecchio + "-");
            java.util.List<String> estranei = jsonArrayToList(an.optJSONArray("estranei"));
            if (!an.optBoolean("leggibile", false)) {
                job.scrivi(I18n.tr("server.um.runPassaggioPython.9"));
                job.scrivi(I18n.tr("server.um.runPassaggioPython.10"));
                for (String l2 : ar.split("\n")) if (!l2.trim().isEmpty()) job.scrivi("      " + l2);
            } else if (!estranei.isEmpty()) {
                job.scrivi("    " + I18n.tr("server.um.x.skippedForeign", java.util.Map.of("elenco", String.valueOf(String.join(", ", estranei)))));
                job.scrivi(I18n.tr("server.um.runPassaggioPython.11", java.util.Map.of("vecchio", String.valueOf(vecchio))));
            } else if (an.optInt("quanti", 0) == 0) {
                job.scrivi(I18n.tr("server.um.runPassaggioPython.12"));
            } else {
                job.scrivi("    " + I18n.tr("server.um.x.toRemove", java.util.Map.of("elenco", String.valueOf(String.join(", ", jsonArrayToList(an.optJSONArray("rimossi")))))));
                eseguiConLog(job, "pkg autoremove -y 2>&1", 900);
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runPassaggioPython.13", java.util.Map.of("tOT", String.valueOf(TOT))));
            boolean serviziOk = true;
            for (String s : servizi) {
                ok("service " + s + " start", 120);
                boolean su = ok("service " + s + " status", 30);
                job.scrivi("    " + s + ": " + (su ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runPassaggioPython.14")));
                if (!su) serviziOk = false;
            }
            if (servizi.isEmpty()) job.scrivi("    " + I18n.tr("server.um.x.none"));

            job.avanza(7, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runPassaggioPython.15", java.util.Map.of("tOT", String.valueOf(TOT))));
            // Che il pacchetto sia installato non dice che il comando parta: e' la lezione
            // del client MySQL, dove tutto risultava a posto e postmap non trovava la libreria.
            // Non indovino il nome del comando dal nome del pacchetto: per py311-fail2ban
            // sbaglierei (i comandi sono fail2ban-server e fail2ban-client, non "fail2ban").
            // Chiedo a pkg quali file eseguibili ha installato davvero.
            boolean comandiOk = true;
            for (String n : nuovi) {
                if (!isValidName(n)) continue;
                int provati = 0;
                for (String f : sh("pkg query %Fp " + n + " 2>/dev/null").split("\n")) {
                    String t = f.trim();
                    if (!t.startsWith("/usr/local/bin/") && !t.startsWith("/usr/local/sbin/")) continue;
                    if (t.contains("test")) continue;   // niente suite di test lanciate per sbaglio
                    if (!ok("test -x " + t, 10)) continue;
                    if (++provati > 4) break;
                    String o = sh(t + " --version 2>&1", 120);
                    String ol = o.toLowerCase();
                    boolean bene = !o.trim().isEmpty() && !ol.contains("not found") && !ol.contains("traceback")
                            && !ol.contains("importerror") && !ol.contains("modulenotfound")
                            && !ol.contains("no module named");
                    job.scrivi("    " + t + " --version: "
                            + (bene ? o.split("\n")[0].trim() : I18n.tr("server.um.x.failedArrow", java.util.Map.of("o", String.valueOf(o.trim())))));
                    if (!bene) comandiOk = false;
                }
                if (provati == 0) job.scrivi(I18n.tr("server.um.runPassaggioPython.16", java.util.Map.of("n", String.valueOf(n))));
            }
            long rimasti = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + vecchio + "-")).count();
            job.scrivi(I18n.tr("server.um.runPassaggioPython.17", java.util.Map.of("vecchio", String.valueOf(vecchio), "rimasti", String.valueOf(rimasti))));

            if (serviziOk && comandiOk) {
                job.status = "completed";
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runPassaggioPython.18", java.util.Map.of("nuovo", String.valueOf(nuovo))));
                job.scrivi(I18n.tr("server.um.runPassaggioPython.19", java.util.Map.of("bk", String.valueOf(bk))));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runPassaggioPython.20", java.util.Map.of("bk", String.valueOf(bk)));
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // Si protegge ogni pacchetto dell'elenco che e' installato adesso: i nuovi arrivati e,
            // se il passaggio si e' fermato prima di toglierli, i vecchi. Prima, con un pkg delete
            // fallito, i vecchi restavano installati e unlockedPackages, con solo un avviso.
            if (!elencoSuDisco.isEmpty()) {
                java.util.List<String> falliti = new ArrayList<>();
                int fatti = 0;
                for (String n : elencoSuDisco) {
                    if (!ok("pkg info -e " + n, 15)) continue;   // tolto, o mai arrivato
                    if (ok("pkg lock -y " + n, 30)) fatti++; else falliti.add(n);
                }
                job.scrivi("");
                job.scrivi(falliti.isEmpty()
                        ? I18n.tr("server.um.x.reprotectAll", java.util.Map.of("n", String.valueOf(fatti)))
                        : I18n.tr("server.um.x.reprotectSome", java.util.Map.of("elenco", String.valueOf(String.join(", ", falliti)))));
                if (falliti.isEmpty()) pulisciStato();
                else job.scrivi(I18n.tr("server.um.runPassaggioPython.21", java.util.Map.of("sTATO_MANUTENZIONE", String.valueOf(MAINTENANCE_STATE))));
                if (daRibloccare.isEmpty() && !unlockedPackages.isEmpty()) {
                    job.scrivi(I18n.tr("server.um.x.unlockedNotReplaced", java.util.Map.of("elenco", String.valueOf(String.join(", ", unlockedPackages)))));
                }
            }
            job.fine = System.currentTimeMillis();
        }
    }

    // ===================== piano di manutenzione guidato =====================

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
        JSONArray passi = new JSONArray();

        // Dati raccolti UNA volta sola: pkg audit e la simulazione sono lente, e ripeterle
        // per ogni passo trasformerebbe il piano in un'attesa di minuti.
        String audit = sh("pkg audit -F 2>&1", 180);
        String dry = sh("pkg upgrade -n 2>&1", 180);
        String lock = sh("pkg lock -l 2>/dev/null");
        JSONObject stato = packagesStatus();
        JSONArray pacchetti = stato.getJSONArray("packages");

        // Chi ha gia' una procedura dedicata (fasi F, G, H) non deve comparire ANCHE come passo
        // pacchetto: sarebbe la stessa operazione scritta due volte con parole diverse, e chi
        // legge non puo' sapere se sono una o due. Si decidono qui, una volta, e valgono per
        // entrambi gli elenchi piu' sotto e per le fasi.
        final String rcPkg = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20).trim();
        final String jvmPkg = pacchettoDellaJvm();
        final String pyNuovo = pyPredefinito();
        java.util.function.Predicate<String> coperto = n ->
                   (!rcPkg.isEmpty() && rcPkg.equals(n))
                || (!jvmPkg.isEmpty() && jvmPkg.equals(n))
                || (n.matches("^py3[0-9]{2}-.*") && !n.startsWith("py" + pyNuovo + "-"));

        // --- Passo 1: tutto lo stack protetto ---
        int installati = stato.getInt("installedCount"), protetti = stato.getInt("lockedCount");
        boolean tuttoProtetto = installati > 0 && protetti == installati;
        passi.put(rifacibile(passo("fase-protezione", "fase", I18n.tr("server.um.x.stepProtect"),
                tuttoProtetto ? "fatto" : "dafare",
                I18n.tr("server.um.maintenancePlan.1", java.util.Map.of("protetti", String.valueOf(protetti), "installati", String.valueOf(installati))),
                I18n.tr("server.um.maintenancePlan.2"),
                tuttoProtetto ? null : new JSONObject().put("tipo", "packages_lock_all")),
                new JSONObject().put("tipo", "packages_lock_all")));

        // --- Passo 2: aggiornare cio' che non e' protetto ---
        Matcher mUp = Pattern.compile("Number of packages to be upgraded:\\s*([0-9]+)").matcher(dry);
        int daAggiornare = mUp.find() ? Integer.parseInt(mUp.group(1)) : 0;
        Matcher mIn = Pattern.compile("Number of packages to be installed:\\s*([0-9]+)").matcher(dry);
        int daInstallare = mIn.find() ? Integer.parseInt(mIn.group(1)) : 0;
        boolean contornoAggiornato = (daAggiornare + daInstallare) == 0;
        passi.put(passo("fase-nonprotetti", "fase", I18n.tr("server.um.maintenancePlan.3"),
                contornoAggiornato ? "fatto" : "dafare",
                contornoAggiornato ? I18n.tr("server.um.maintenancePlan.4")
                        : I18n.tr("server.um.maintenancePlan.5", java.util.Map.of("daAggiornare", String.valueOf(daAggiornare), "daInstallare", String.valueOf(daInstallare))),
                I18n.tr("server.um.maintenancePlan.6"),
                contornoAggiornato ? null : new JSONObject().put("tipo", "updates_apply")));

        // --- Passi 3..N: un passo per ogni pacchetto protetto vulnerabile con fix ---
        // L'ordine e' per numero di CVE chiuse: prima cio' che porta piu' beneficio.
        java.util.List<JSONObject> vulnerabili = new ArrayList<>();
        Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        java.util.LinkedHashSet<String> visti = new java.util.LinkedHashSet<>();
        while (mv.find()) visti.add(mv.group(1));
        for (String nome : visti) {
            if (ruoloDi(nome) == null) continue;              // non e' dello stack di posta
            if (coperto.test(nome)) continue;                 // ha gia' la sua fase dedicata
            String cur = sh("pkg query %v " + nome + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + nome + " 2>/dev/null", 20);
            if (cur.isEmpty() || av.isEmpty() || av.equals(cur)) continue;   // nessuna fix disponibile
            boolean maggiore = saltoSignificativo(nome, cur, av);
            JSONObject avv = avvertenzaPer(nome, maggiore);
            int nCve = dettaglioVulnerabilita(audit, nome).getJSONArray("cve").length();
            JSONObject o = new JSONObject().put("nome", nome).put("cur", cur).put("av", av)
                    .put("cve", nCve).put("maggiore", maggiore);
            if (avv != null) o.put("avv", avv);
            vulnerabili.add(o);
        }
        vulnerabili.sort((x, y) -> Integer.compare(y.getInt("cve"), x.getInt("cve")));
        // Un solo passo per famiglia: proporre "aggiorna mysql80-server" e poi "aggiorna
        // mysql80-client" significherebbe proporre due volte la stessa operazione, e la prima
        // non riuscirebbe nemmeno perche' l'altra meta' resta protetta.
        java.util.LinkedHashSet<String> famiglieViste = new java.util.LinkedHashSet<>();
        java.util.List<JSONObject> unici = new ArrayList<>();
        for (JSONObject v : vulnerabili) {
            String fam = famigliaDi(v.getString("nome"));
            String chiave = fam == null ? v.getString("nome") : fam;
            if (famiglieViste.add(chiave)) unici.add(v);
        }
        vulnerabili = unici;
        for (JSONObject v : vulnerabili) {
            String nome = v.getString("nome");
            boolean attendi = v.has("avv") && "attendi".equals(v.getJSONObject("avv").getString("level"));
            java.util.List<String> mem = membriFamiglia(nome);
            String titolo = mem.size() > 1
                    ? I18n.tr("server.um.x.updLinkedCve", java.util.Map.of("nome", String.valueOf(nome), "n", String.valueOf((mem.size() - 1)), "cve", String.valueOf(v.getInt("cve"))))
                    : I18n.tr("server.um.x.updCve", java.util.Map.of("nome", String.valueOf(nome), "cve", String.valueOf(v.getInt("cve"))));
            passi.put(passo("pkg-" + nome, "pacchetto", titolo,
                    attendi ? "manuale" : "dafare",
                    nome + " " + v.getString("cur") + " -> " + v.getString("av")
                        + (v.getBoolean("maggiore") ? I18n.tr("server.um.maintenancePlan.7") : I18n.tr("server.um.maintenancePlan.8")),
                    attendi ? v.getJSONObject("avv").getString("text")
                            : I18n.tr("server.um.maintenancePlan.9"),
                    attendi ? null : new JSONObject().put("tipo", "package_update").put("package", nome)));
        }

        // --- Migrazione MySQL, se serve: sta QUI perche' e' un prerequisito di alcuni passi
        //     successivi (Postfix pretende la libreria della 8.4) e perche' viene dopo gli
        //     aggiornamenti di sicurezza indipendenti, che sono piu' urgenti e meno invasivi.
        //     Un piano che dice "prima fai X" senza contenere X non guida: manda a cercare.
        String srvMysql = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        if (!srvMysql.isEmpty()) {
            boolean gia84 = srvMysql.startsWith("mysql84");
            String disp84 = gia84 ? "" : sh("pkg rquery -U %v mysql84-server 2>/dev/null", 30);
            if (gia84) {
                passi.put(passo("fase-mysql84", "fase", I18n.tr("server.um.maintenancePlan.10"), "fatto",
                        I18n.tr("server.um.maintenancePlan.11", java.util.Map.of("srvMysql", String.valueOf(srvMysql))),
                        I18n.tr("server.um.maintenancePlan.12"), null));
            } else if (!disp84.isEmpty()) {
                passi.put(passo("fase-mysql84", "fase", I18n.tr("server.um.maintenancePlan.10"), "manuale",
                        I18n.tr("server.um.maintenancePlan.13", java.util.Map.of("srvMysql", String.valueOf(srvMysql), "disp84", String.valueOf(disp84))),
                        I18n.tr("server.um.maintenancePlan.14"), null));
            }
        }

        // --- Passi per i pacchetti protetti che hanno un aggiornamento ma nessuna CVE ---
        // Non sono urgenti, ma "aggiornare tutto l'aggiornabile" e' una richiesta legittima e
        // il piano deve poterla rappresentare, altrimenti resterebbero invisibili per sempre.
        for (int i = 0; i < pacchetti.length(); i++) {
            JSONObject p = pacchetti.getJSONObject(i);
            String nome = p.getString("name");
            if (visti.contains(nome)) continue;               // gia' coperto come vulnerabile
            if (coperto.test(nome)) continue;                 // ha gia' la sua fase dedicata
            String fam = famigliaDi(nome);
            String chiave = fam == null ? nome : fam;
            if (!famiglieViste.add(chiave)) continue;         // gia' coperto dalla sua famiglia
            String cur = p.optString("version", "");
            String av = sh("pkg rquery -U %v " + nome + " 2>/dev/null", 20);
            if (cur.isEmpty() || av.isEmpty() || av.equals(cur)) continue;
            boolean maggiore = saltoSignificativo(nome, cur, av);
            JSONObject avv = avvertenzaPer(nome, maggiore);
            boolean attendi = avv != null && "attendi".equals(avv.getString("level"));
            // Se il pacchetto nuovo pretende un'altra famiglia MySQL, il passo non e' "da fare":
            // e' bloccato finche' MySQL non e' stato migrato. Offrirlo sarebbe proporre
            // un'operazione che il preflight rifiuta un secondo dopo.
            String confl = conflittoFamigliaMysql(nome);
            if (confl != null) {
                java.util.List<String> memC = membriFamiglia(nome);
                passi.put(passo("pkg-" + nome, "pacchetto", memC.size() > 1
                            ? I18n.tr("server.um.maintenancePlan.17", java.util.Map.of("nome", String.valueOf(nome), "p", String.valueOf(memC.size() - 1)))
                            : I18n.tr("server.um.maintenancePlan.18", java.util.Map.of("nome", String.valueOf(nome))),
                        "manuale",
                        I18n.tr("server.um.maintenancePlan.15", java.util.Map.of("nome", String.valueOf(nome), "cur", String.valueOf(cur), "av", String.valueOf(av))),
                        I18n.tr("server.um.maintenancePlan.16", java.util.Map.of("confl", String.valueOf(confl))),
                        null));
                continue;
            }
            java.util.List<String> mem = membriFamiglia(nome);
            String titolo = mem.size() > 1
                    ? I18n.tr("server.um.maintenancePlan.17", java.util.Map.of("nome", String.valueOf(nome), "p", String.valueOf((mem.size() - 1))))
                    : I18n.tr("server.um.maintenancePlan.18", java.util.Map.of("nome", String.valueOf(nome)));
            passi.put(passo("pkg-" + nome, "pacchetto", titolo, attendi ? "manuale" : "dafare",
                    nome + " " + cur + " -> " + av
                        + (maggiore ? I18n.tr("server.um.maintenancePlan.7") : I18n.tr("server.um.maintenancePlan.8"))
                        + " " + I18n.tr("server.um.x.noKnownVuln"),
                    attendi ? avv.getString("text")
                            : (avv != null ? avv.getString("text")
                                           : I18n.tr("server.um.maintenancePlan.19")),
                    attendi ? null : new JSONObject().put("tipo", "package_update").put("package", nome)));
        }

        // --- Cache di rspamd rimaste da un aggiornamento precedente ---
        // Esiste come passo solo finche' quei file ci sono: e' lo stesso principio dello
        // stato ricavato, e sparisce da solo quando non serve piu'.
        // Un "zero file trovati" puo' significare due cose opposte: che sono gia' stati
        // eliminati, oppure che ho guardato nel posto sbagliato. Si distingue guardando se la
        // cartella esiste e contiene qualcosa: un'assenza si dimostra, non si presume.
        boolean rspamdPresente = ok("pkg info -e rspamd", 20);
        boolean cartellaRspamd = ok("test -d /var/db/rspamd", 15);
        long fileRspamd = cartellaRspamd
                ? number(sh("find /var/db/rspamd -type f 2>/dev/null | wc -l", 60)) : 0;
        long unser = cartellaRspamd
                ? number(sh("find /var/db/rspamd -type f -name '*.unser' 2>/dev/null | wc -l", 60)) : 0;
        if (rspamdPresente && !cartellaRspamd) {
            passi.put(passo("fase-rspamd-cache", "fase", I18n.tr("server.um.maintenancePlan.20"), "manuale",
                    I18n.tr("server.um.maintenancePlan.21"),
                    I18n.tr("server.um.maintenancePlan.22"), null));
        } else if (unser > 0) {
            passi.put(passo("fase-rspamd-cache", "fase", I18n.tr("server.um.maintenancePlan.23"), "dafare",
                    I18n.tr("server.um.maintenancePlan.24", java.util.Map.of("unser", String.valueOf(unser))),
                    I18n.tr("server.um.maintenancePlan.25"),
                    new JSONObject().put("tipo", "rspamd_clean_cache")));
        } else if (rspamdPresente && cartellaRspamd) {
            passi.put(passo("fase-rspamd-cache", "fase", I18n.tr("server.um.maintenancePlan.26"), "fatto",
                    I18n.tr("server.um.maintenancePlan.27", java.util.Map.of("fileRspamd", String.valueOf(fileRspamd))),
                    I18n.tr("server.um.maintenancePlan.28"), null));
        }

        // --- Passo finale: configurazione Dovecot dalla sorgente unica ---
        // Lo stato si ricava dal file vivo: l'intestazione la scrive solo il generatore nuovo.
        boolean rigenerata = ok("grep -q 'generato dal FreeBSD Mail Panel' "
                + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        boolean sieveAttivo = ok("grep -qE '^protocols.*sieve' " + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        passi.put(rifacibile(passo("fase-dovecot", "fase", I18n.tr("server.um.maintenancePlan.30"),
                rigenerata ? "fatto" : "dafare",
                rigenerata ? (sieveAttivo
                        ? I18n.tr("server.um.x.dcSingleSieve")
                        : I18n.tr("server.um.x.dcSingleNoSieve"))
                    : I18n.tr("server.um.maintenancePlan.31"),
                I18n.tr("server.um.maintenancePlan.32"),
                rigenerata ? null : new JSONObject().put("tipo", "dovecot_config_regen")),
                new JSONObject().put("tipo", "dovecot_config_regen")));

        // --- Le tre operazioni che un semplice "pkg upgrade" non sa fare ---
        // Stanno nel piano anche se l'azione vive in una scheda dedicata: un piano che tace su
        // cio' che resta da fare dice implicitamente "sei a posto", e non e' vero. Lo stato e'
        // ricavato con interrogazioni leggere — niente simulazioni, che qui costerebbero minuti.

        // Roundcube: il pacchetto si aggiornerebbe da solo, ma il salto di versione maggiore
        // cambia lo SCHEMA del database, e senza bin/updatedb.sh la webmail non funziona.
        if (!rcPkg.isEmpty() && isValidName(rcPkg)) {
            String cur = sh("pkg query %v " + rcPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + rcPkg + " 2>/dev/null", 20);
            boolean rcIgnoto = cur.isEmpty() || av.isEmpty();
            boolean daFareRc = !rcIgnoto && !av.equals(cur);
            // Una webmail gia' sulla 1.7 con la radice vecchia e' guasta ADESSO: se il piano
            // guardasse solo la versione direbbe "fatto" mentre la webmail non risponde.
            String radiceStorta = null;
            if (vuolePublicHtml(cur) || vuolePublicHtml(av)) {
                JSONArray rd = radiciNginxRoundcube();
                for (int i = 0; i < rd.length(); i++)
                    if (!rd.getJSONObject(i).getBoolean("gia"))
                        radiceStorta = rd.getJSONObject(i).getString("file");
            }
            if (radiceStorta != null) { daFareRc = true; rcIgnoto = false; }
            int cveRc = dettaglioVulnerabilita(audit, rcPkg).getJSONArray("cve").length();
            passi.put(passo("fase-roundcube", "fase", I18n.tr("server.um.x.stepRoundcube")
                        + (cveRc > 0 ? " (" + cveRc + " CVE)" : ""),
                    (daFareRc || rcIgnoto) ? "manuale" : "fatto",
                    rcIgnoto ? I18n.tr("server.um.x.rcRepoUnknown", java.util.Map.of("pkg", String.valueOf(rcPkg), "cur", String.valueOf(cur.isEmpty() ? I18n.tr("server.um.x.unknownF") : cur)))
                        : !daFareRc ? I18n.tr("server.um.x.rcLatest", java.util.Map.of("pkg", String.valueOf(rcPkg), "cur", String.valueOf(cur)))
                        : (av.equals(cur)
                           ? I18n.tr("server.um.maintenancePlan.33", java.util.Map.of("rcPkg", String.valueOf(rcPkg), "cur", String.valueOf(cur), "radiceStorta", String.valueOf(radiceStorta)))
                           : rcPkg + " " + cur + " -> " + av
                             + (radiceStorta != null ? I18n.tr("server.um.maintenancePlan.34") : "")),
                    daFareRc
                    ? I18n.tr("server.um.maintenancePlan.35")
                    : I18n.tr("server.um.maintenancePlan.36"), null));
        }

        // Python: py311 e py312 sono pacchetti diversi, non due versioni dello stesso.
        java.util.LinkedHashSet<String> pyVecchie = new java.util.LinkedHashSet<>();
        for (String n : sh("pkg query %n 2>/dev/null").split("\n")) {
            Matcher m = Pattern.compile("^py(3[0-9]{2})-").matcher(n.trim());
            if (m.find() && !m.group(1).equals(pyNuovo)) pyVecchie.add(m.group(1));
        }
        if (!pyVecchie.isEmpty()) {
            String list = String.join(", ", pythonDaSpostare(pyVecchie.iterator().next()));
            passi.put(passo("fase-python", "fase", I18n.tr("server.um.maintenancePlan.37"),
                    "manuale",
                    I18n.tr("server.um.x.pyInstalled", java.util.Map.of("vecchie", String.valueOf(String.join("/py", pyVecchie)), "nuovo", String.valueOf(pyNuovo)))
                    + (list.isEmpty() ? "." : ": " + list),
                    I18n.tr("server.um.maintenancePlan.38", java.util.Map.of("p", String.valueOf(pyVecchie.iterator().next()), "pyNuovo", String.valueOf(pyNuovo))), null));
        } else {
            passi.put(passo("fase-python", "fase", I18n.tr("server.um.maintenancePlan.37"),
                    "fatto", I18n.tr("server.um.maintenancePlan.39", java.util.Map.of("pyNuovo", String.valueOf(pyNuovo))),
                    I18n.tr("server.um.runPassaggioPython.2"), null));
        }

        // JVM: il pannello ci gira sopra, quindi non puo' aggiornarla restando acceso.
        if (!jvmPkg.isEmpty()) {
            String cur = sh("pkg query %v " + jvmPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + jvmPkg + " 2>/dev/null", 20);
            // Tre stati, non due. Il repository che non risponde NON vuol dire "sei a posto":
            // vuol dire che non lo so, e dirlo e' l'unica risposta onesta.
            boolean jvIgnoto = cur.isEmpty() || av.isEmpty();
            boolean daFareJv = !jvIgnoto && !av.equals(cur);
            int cveJv = dettaglioVulnerabilita(audit, jvmPkg).getJSONArray("cve").length();
            passi.put(passo("fase-jvm", "fase", I18n.tr("server.um.x.stepJvm")
                        + (cveJv > 0 ? " (" + cveJv + " CVE)" : ""),
                    (daFareJv || jvIgnoto) ? "manuale" : "fatto",
                    jvIgnoto ? I18n.tr("server.um.x.jvRepoUnknown", java.util.Map.of("pkg", String.valueOf(jvmPkg), "cur", String.valueOf(cur.isEmpty() ? I18n.tr("server.um.x.unknownF") : cur)))
                        : daFareJv ? jvmPkg + " " + cur + " -> " + av
                             : I18n.tr("server.um.x.jvLatest", java.util.Map.of("pkg", String.valueOf(jvmPkg), "cur", String.valueOf(cur))),
                    jvIgnoto
                    ? I18n.tr("server.um.maintenancePlan.40")
                    : daFareJv
                    ? I18n.tr("server.um.maintenancePlan.41")
                    : I18n.tr("server.um.maintenancePlan.42"), null));
        }

        // Vulnerabilita' senza fix disponibile: non sono un passo, ma vanno sapute.
        JSONArray senzaRimedio = new JSONArray();
        for (String nome : visti) {
            String cur = sh("pkg query %v " + nome + " 2>/dev/null", 20);
            String av  = sh("pkg rquery -U %v " + nome + " 2>/dev/null", 20);
            if (!cur.isEmpty() && (av.isEmpty() || av.equals(cur))) senzaRimedio.put(nome);
        }

        int daFare = 0;
        for (int i = 0; i < passi.length(); i++) if ("dafare".equals(passi.getJSONObject(i).getString("stato"))) daFare++;
        return new JSONObject().put("success", true).put("passi", passi)
                .put("daFare", daFare).put("totale", passi.length())
                .put("senzaRimedio", senzaRimedio);
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
    private static final java.util.Map<String, String> LETTERA_FASE = java.util.Map.of(
        "fase-protezione",   "A",
        "fase-nonprotetti",  "B",
        "fase-mysql84",      "C",
        "fase-dovecot",      "D",
        "fase-rspamd-cache", "E",
        "fase-roundcube",    "F",
        "fase-python",       "G",
        "fase-jvm",          "H"
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
    private static JSONObject rifacibile(JSONObject passo, JSONObject azione) {
        if ("fatto".equals(passo.optString("stato")) && azione != null) passo.put("azioneRifai", azione);
        return passo;
    }

    private static JSONObject passo(String chiave, String gruppo, String titolo, String stato,
                                    String situazione, String perche, JSONObject azione) {
        JSONObject o = new JSONObject().put("chiave", chiave).put("gruppo", gruppo)
                .put("titolo", titolo).put("stato", stato)
                .put("situazione", situazione).put("perche", perche);
        if ("fase".equals(gruppo)) o.put("lettera", LETTERA_FASE.getOrDefault(chiave, "?"));
        if (azione != null) o.put("azione", azione);
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
    private static final String[][] FAMIGLIE = {
        {"^mysql[0-9]+-(server|client)$",  "server.um.passo.1"},
        {"^php[0-9]+(-.+)?$",              "server.um.passo.2"},
        {"^dovecot[0-9]*(-.+)?$",          "server.um.family.dovecot"},
    };

    /** L'espressione della famiglia a cui appartiene il pacchetto, o null se sta da solo. */
    static String famigliaDi(String nome) {
        for (String[] f : FAMIGLIE) if (nome.matches(f[0])) return f[0];
        return null;
    }

    static String motivoFamiglia(String nome) {
        for (String[] f : FAMIGLIE) if (nome.matches(f[0])) return I18n.tr(f[1]);
        return "";
    }

    /** Tutti i pacchetti INSTALLATI che appartengono alla stessa famiglia. Almeno il pacchetto stesso. */
    static java.util.List<String> membriFamiglia(String nome) {
        java.util.List<String> membri = new ArrayList<>();
        String fam = famigliaDi(nome);
        if (fam == null) { membri.add(nome); return membri; }
        for (String riga : sh("pkg query %n 2>/dev/null", 30).split("\n")) {
            String t = riga.trim();
            if (isValidName(t) && t.matches(fam)) membri.add(t);
        }
        if (membri.isEmpty()) membri.add(nome);
        return membri;
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
        {"^clamav.*",                         "clamav_clamd"},
        {"^nginx.*",                          "nginx"},
        {"^php[0-9]+.*",                      "php_fpm"},
        {"^mysql[0-9]+-server$",              "mysql-server"},
        {"^py[0-9]+-fail2ban$",               "fail2ban"},
        {"^unbound$",                         "unbound"},
    };

    /** Pacchetti che sono librerie condivise: qui un "nessun dipendente" va preso con cautela. */
    private static final String LIBRERIE_CONDIVISE =
            "^(openssl[0-9]*|expat|libxml2|zlib|libiconv|pcre2?|curl|libssh2|nghttp2|icu|libsodium)$";

    private static String servizioDiretto(String pacchetto) {
        for (String[] r : SERVICE_OF) if (pacchetto.matches(r[0])) return r[1];
        return null;
    }

    /**
     * I servizi da riavviare dopo aver aggiornato un pacchetto. Per una libreria condivisa
     * come openssl non basta guardare il pacchetto stesso: si chiede a pkg CHI dipende da lui
     * e si traducono quei pacchetti in servizi. Un elenco scritto a mano invecchierebbe in
     * silenzio, e un servizio dimenticato significa una vulnerabilita' che resta aperta.
     */
    static java.util.List<String> serviziDaRiavviare(String pacchetto) {
        java.util.LinkedHashSet<String> servizi = new java.util.LinkedHashSet<>();
        String diretto = servizioDiretto(pacchetto);
        if (diretto != null) servizi.add(diretto);
        if (!isValidName(pacchetto)) return new ArrayList<>(servizi);
        for (String riga : sh("pkg query %rn " + pacchetto + " 2>/dev/null", 30).split("\n")) {
            String dip = riga.trim();
            if (!isValidName(dip)) continue;
            String s = servizioDiretto(dip);
            if (s != null) servizi.add(s);
        }
        return new ArrayList<>(servizi);
    }

    /** Nome effettivo dello script rc.d fra i candidati, o null se il servizio non c'e'. */
    private static String nomeServizioReale(String logico) {
        for (String[] candidati : SERVICES) {
            boolean appartiene = false;
            for (String c : candidati) if (c.equals(logico)) appartiene = true;
            if (!appartiene) continue;
            for (String c : candidati) {
                if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) return c;
            }
            return null;
        }
        return ok("test -f /usr/local/etc/rc.d/" + logico + " -o -f /etc/rc.d/" + logico, 10) ? logico : null;
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
    static java.util.List<String> messaggiCheChiedonoAzione(String outputPkg) {
        java.util.List<String> fuori = new ArrayList<>();
        StringBuilder blocco = new StringBuilder();
        boolean dentro = false;
        for (String r : outputPkg.split("\n")) {
            if (r.startsWith("Message from ")) {
                if (dentro && chiedeAzione(blocco.toString())) fuori.add(blocco.toString().trim());
                blocco.setLength(0);
                dentro = true;
            }
            if (dentro) blocco.append(r).append('\n');
        }
        if (dentro && chiedeAzione(blocco.toString())) fuori.add(blocco.toString().trim());
        return fuori;
    }

    private static boolean chiedeAzione(String testo) {
        String t = testo.toLowerCase();
        return t.contains("it is recommended") || t.contains("you should") || t.contains("you may need")
            || t.contains("you need to") || t.contains("remember to")
            || t.contains("following command") || t.contains("action is needed");
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

    private static String provaConfigDi(String service) {
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
        {"redis", "redis-cli DBSIZE 2>/dev/null", "server.um.provaConfigDi.1"},
    };

    private static String[] provaDopoDi(String service) {
        for (String[] r : TEST_AFTER) if (r[0].equals(service)) return r;
        return null;
    }

    /** Il pid di un servizio, o stringa vuota. Confrontarlo prima e dopo prova che e' ripartito davvero. */
    private static String pidServizio(String service) {
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
    public static JSONObject packagePreflight(String nome) {
        JSONObject r = new JSONObject();
        if (!isValidName(nome)) return r.put("success", false).put("error", I18n.tr("server.um.cambiaProtezioni.1"));
        JSONArray checks = new JSONArray();
        boolean block = false;

        // I pacchetti che devono muoversi insieme si sbloccano e si aggiornano insieme:
        // altrimenti una dipendenza rimasta protetta blocca tutta l'operazione. Serve saperlo
        // subito, perche' da questo dipendono anche i servizi da riavviare.
        java.util.List<String> famiglia = membriFamiglia(nome);

        String versione = sh("pkg query %v " + nome + " 2>/dev/null", 20);
        if (versione.isEmpty()) {
            aggiungiCheck(checks, "installato", I18n.tr("server.um.packagePreflight.1"), "block",
                    I18n.tr("server.um.packagePreflight.2", java.util.Map.of("nome", String.valueOf(nome))));
            block = true;
        } else {
            aggiungiCheck(checks, "installato", I18n.tr("server.um.packagePreflight.1"), "ok", nome + " " + versione);
        }
        r.put("name", nome).put("current", versione).put("role", ruoloDi(nome) == null ? "" : ruoloDi(nome));

        String disponibile = sh("pkg rquery -U %v " + nome + " 2>/dev/null", 30);
        r.put("available", disponibile);
        boolean maggiore = !versione.isEmpty() && !disponibile.isEmpty()
                && saltoSignificativo(nome, versione, disponibile);
        r.put("majorJump", maggiore);
        if (disponibile.isEmpty() || disponibile.equals(versione)) {
            aggiungiCheck(checks, "aggiornamento", I18n.tr("server.um.packagePreflight.3"), "block",
                    I18n.tr("server.um.packagePreflight.4"));
            block = true;
        } else {
            aggiungiCheck(checks, "aggiornamento", I18n.tr("server.um.packagePreflight.3"), "ok",
                    versione + " -> " + disponibile + (maggiore ? I18n.tr("server.um.packagePreflight.5") : I18n.tr("server.um.packagePreflight.6")));
        }

        JSONObject avv = avvertenzaPer(nome, maggiore);
        if (avv != null) {
            r.put("advisory", avv);
            if ("attendi".equals(avv.getString("level"))) {
                aggiungiCheck(checks, "avvertenza", I18n.tr("server.um.packagePreflight.7"), "block", avv.getString("text"));
                block = true;
            } else {
                aggiungiCheck(checks, "avvertenza", I18n.tr("server.um.packagePreflight.7"), avv.getString("level"), avv.getString("text"));
            }
        }

        // Il pacchetto nuovo pretende una famiglia MySQL diversa da quella installata?
        // E' il caso di postfix-mysql 3.11, che nel repository dipende da mysql84-client: sul
        // sistema c'e' ancora mysql80-client, e i due sono in conflitto. Aggiornarlo prima di
        // aver migrato MySQL significa o un fallimento o una sostituzione di libreria non
        // voluta, con mysql80-server che ci dipende ancora.
        String mysqlInstallato = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        if (!disponibile.isEmpty()) {
            String richiesto = conflittoFamigliaMysql(nome);
            if (richiesto != null) {
                StringBuilder chi = new StringBuilder();
                for (String membro : famiglia) {
                    if (!isValidName(membro)) continue;
                    if (sh("pkg rquery -U %dn " + membro + " 2>/dev/null", 30).contains(richiesto)) {
                        if (chi.length() > 0) chi.append(", ");
                        chi.append(membro);
                    }
                }
                aggiungiCheck(checks, "mysqlfamiglia", I18n.tr("server.um.packagePreflight.8"), "block",
                        I18n.tr("server.um.x.mysqlFamilyBlock", java.util.Map.of("chi", String.valueOf(chi.length() > 0 ? chi.toString() : nome), "richiesto", String.valueOf(richiesto), "installato", String.valueOf(mysqlInstallato), "versione", String.valueOf(richiesto.replace("-client", "")))));
                block = true;
                r.put("mysqlFamilyConflict", richiesto);
            }
        }

        // Vulnerabilita' che questo aggiornamento chiuderebbe: e' il motivo per farlo.
        String audit = sh("pkg audit " + nome + " 2>&1", 120);
        JSONObject det = dettaglioVulnerabilita(audit, nome);
        r.put("cve", det.getJSONArray("cve")).put("vulnDescrizione", det.getString("description"))
         .put("references", det.getJSONArray("references"));
        int nCve = det.getJSONArray("cve").length();
        aggiungiCheck(checks, "vulnerabilita", I18n.tr("server.um.x.knownVulns"), nCve > 0 ? "verifica" : "ok",
                nCve > 0 ? I18n.tr("server.um.x.openCves", java.util.Map.of("n", String.valueOf(nCve), "d", String.valueOf(det.getString("description"))))
                         : I18n.tr("server.um.packagePreflight.9"));

        // Servizi da riavviare. Il punto dolente: senza riavvio la fix non entra in
        // servizio. E vanno calcolati su TUTTA la famiglia, non sul solo pacchetto nominato:
        // aggiornando mysql80-server insieme a mysql80-client, sono i programmi collegati al
        // CLIENT (Postfix, Dovecot, php-fpm) a tenersi in memoria la libreria vecchia. Guardare
        // il solo nome scritto nel passo li lascerebbe fuori, ed e' esattamente il caso in cui
        // la fix risulta installata senza essere in servizio.
        java.util.LinkedHashSet<String> logici = new java.util.LinkedHashSet<>();
        for (String membro : famiglia) logici.addAll(serviziDaRiavviare(membro));
        JSONArray servizi = new JSONArray();
        for (String logico : logici) {
            String reale = nomeServizioReale(logico);
            if (reale == null) continue;
            servizi.put(new JSONObject().put("name", reale)
                    .put("running", ok("service " + reale + " status", 15))
                    .put("pid", pidServizio(reale)));
        }
        r.put("services", servizi);
        // Cosa ha risposto pkg, per esteso: un "nessuno" senza le prove non e' un'informazione,
        // e su una libreria condivisa e' l'errore che vanifica l'aggiornamento.
        JSONArray dipTrovati = new JSONArray();
        for (String membro : famiglia) {
            for (String riga : sh("pkg query %rn " + membro + " 2>/dev/null", 30).split("\n")) {
                String d = riga.trim();
                if (isValidName(d) && !famiglia.contains(d)) dipTrovati.put(d);
            }
        }
        r.put("reverseDeps", dipTrovati);
        aggiungiCheck(checks, "servizi", I18n.tr("server.um.packagePreflight.10"), "verifica",
                servizi.length() == 0
                    ? (dipTrovati.length() == 0
                       ? I18n.tr("server.um.x.noSvcZero")
                       : I18n.tr("server.um.x.noSvcSome", java.util.Map.of("n", String.valueOf(dipTrovati.length()), "elenco", String.valueOf(String.join(", ", jsonArrayToList(dipTrovati))))))
                    : I18n.tr("server.um.packagePreflight.11", java.util.Map.of("length", String.valueOf(servizi.length()))));

        if (Files.exists(Paths.get(MAINTENANCE_STATE))) {
            aggiungiCheck(checks, "stato", I18n.tr("server.um.packagePreflight.12"), "block",
                    I18n.tr("server.um.packagePreflight.13", java.util.Map.of("sTATO_MANUTENZIONE", String.valueOf(MAINTENANCE_STATE))));
            block = true;
        }

        r.put("family", new JSONArray(famiglia));
        if (famiglia.size() > 1) {
            aggiungiCheck(checks, "famiglia", I18n.tr("server.um.packagePreflight.14"), "verifica",
                    I18n.tr("server.um.x.familyTogether", java.util.Map.of("n", String.valueOf(famiglia.size()), "reason", String.valueOf(motivoFamiglia(nome)), "elenco", String.valueOf(String.join(", ", famiglia)))));
        }

        String lockList = sh("pkg lock -l 2>/dev/null");
        java.util.List<String> protettiOra = new ArrayList<>();
        for (String m : famiglia) if (bloccato(lockList, m)) protettiOra.add(m);
        r.put("wasLocked", !protettiOra.isEmpty());
        r.put("lockedMembers", new JSONArray(protettiOra));

        // Il piano ESATTO. Fin qui c'era soltanto "nome versione -> versione del catalogo", ma
        // pkg per aggiornare puo' cambiare anche dipendenze, installarne di nuove, rimuoverne:
        // si chiede a pkg, su una copia del suo database in cui si tolgono le stesse protezioni
        // che togliera' l'aggiornamento vero. Il database vero non viene toccato.
        JSONObject piano = PackagePlan.pianoPer(famiglia, insiemeProtetti(lockList), UpdateManager::motivoPerNonSbloccare);
        if (!piano.optBoolean("success") || !piano.optBoolean("measured")) {
            aggiungiCheck(checks, "piano", I18n.tr("server.um.packagePreflight.15"), "block",
                    I18n.tr("server.um.x.noPlan", java.util.Map.of("e", String.valueOf(piano.optString("error", piano.optString("errore", "?"))))));
            block = true;
        } else {
            JSONArray changes = piano.getJSONArray("changes");
            java.util.List<String> rimossi = new ArrayList<>(), indietro = new ArrayList<>(),
                    ancoraVulnerabili = new ArrayList<>(), righe = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                String n = c.getString("nome");
                switch (c.getString("tipo")) {
                    case "rimuove" -> rimossi.add(n + " " + c.getString("da"));
                    case "retrocede" -> indietro.add(n + " " + c.getString("da") + " -> " + c.getString("a"));
                    default -> { }
                }
                if (c.optBoolean("stillVulnerable")) ancoraVulnerabili.add(n + " " + c.getString("a"));
                righe.add(n + " " + (c.getString("da").isEmpty() ? I18n.tr("server.um.x.newPkg") : c.getString("da"))
                        + (c.getString("a").isEmpty() ? " " + I18n.tr("server.um.x.removedPkg") : " -> " + c.getString("a")));
            }
            JSONArray imp = piano.getJSONArray("blockers");
            for (int i = 0; i < imp.length(); i++) {
                JSONObject x = imp.getJSONObject(i);
                aggiungiCheck(checks, "piano-impedimento", I18n.tr("server.um.packagePreflight.16"), "block",
                        I18n.tr("server.um.x.blockedBy", java.util.Map.of("nome", String.valueOf(x.getString("nome")), "reason", String.valueOf(x.getString("reason")))));
                block = true;
            }
            JSONArray err = piano.getJSONArray("erroriPkg");
            if (err.length() > 0 || piano.optBoolean("hasConflicts")) {
                aggiungiCheck(checks, "piano-errori", I18n.tr("server.um.packagePreflight.17"), "block",
                        String.join(" | ", jsonArrayToList(err)) + (piano.optBoolean("hasConflicts") ? " " + I18n.tr("server.um.x.pkgConflicts") : ""));
                block = true;
            }
            if (!rimossi.isEmpty()) {
                aggiungiCheck(checks, "piano-rimozioni", I18n.tr("server.um.packagePreflight.18"), "block",
                        I18n.tr("server.um.x.planRemoves", java.util.Map.of("elenco", String.valueOf(String.join(", ", rimossi)))));
                block = true;
            }
            if (!indietro.isEmpty()) {
                aggiungiCheck(checks, "piano-retrocede", I18n.tr("server.um.packagePreflight.19"), "block",
                        I18n.tr("server.um.x.planDowngrades", java.util.Map.of("elenco", String.valueOf(String.join(", ", indietro)))));
                block = true;
            }
            if (jsonArrayToList(piano.getJSONArray("unchangedPackages")).contains(nome)) {
                aggiungiCheck(checks, "piano-fermo", I18n.tr("server.um.packagePreflight.20"), "block",
                        I18n.tr("server.um.packagePreflight.21", java.util.Map.of("nome", String.valueOf(nome))));
                block = true;
            }
            if (!ancoraVulnerabili.isEmpty()) {
                aggiungiCheck(checks, "piano-vulnerabili", I18n.tr("server.um.packagePreflight.22"), "verifica",
                        I18n.tr("server.um.x.stillVulnerable", java.util.Map.of("elenco", String.valueOf(String.join(", ", ancoraVulnerabili)))));
            }
            java.util.List<String> extra = new ArrayList<>(jsonArrayToList(piano.getJSONArray("unlockedPackages")));
            extra.removeAll(famiglia);
            if (!extra.isEmpty()) {
                aggiungiCheck(checks, "piano-dipendenze", I18n.tr("server.um.packagePreflight.23"), "verifica",
                        I18n.tr("server.um.x.depsProtected", java.util.Map.of("elenco", String.valueOf(String.join(", ", extra)))));
            }
            if (!block) {
                aggiungiCheck(checks, "piano", I18n.tr("server.um.packagePreflight.15"), "ok",
                        (changes.length() == 1
                         ? I18n.tr("server.um.x.pkgChanges.one", java.util.Map.of("righe", String.valueOf(String.join("; ", righe))))
                         : I18n.tr("server.um.x.pkgChanges.other", java.util.Map.of("n", String.valueOf(changes.length()), "righe", String.valueOf(String.join("; ", righe))))));
            }
            // I servizi da riavviare si calcolano su tutto cio' che il piano cambia, non solo
            // sulla famiglia: una dipendenza come openssl tiene in memoria i suoi utenti.
            java.util.LinkedHashSet<String> nomiServizi = new java.util.LinkedHashSet<>();
            for (int i = 0; i < servizi.length(); i++) nomiServizi.add(servizi.getJSONObject(i).getString("name"));
            java.util.List<String> perDipendenze = new ArrayList<>();
            for (int i = 0; i < changes.length(); i++) {
                JSONObject c = changes.getJSONObject(i);
                if ("rimuove".equals(c.getString("tipo")) || famiglia.contains(c.getString("nome"))) continue;
                for (String logico : serviziDaRiavviare(c.getString("nome"))) {
                    String reale = nomeServizioReale(logico);
                    if (reale == null || !nomiServizi.add(reale)) continue;
                    servizi.put(new JSONObject().put("name", reale)
                            .put("running", ok("service " + reale + " status", 15))
                            .put("pid", pidServizio(reale)));
                    perDipendenze.add(reale + " " + I18n.tr("server.um.x.forPkg", java.util.Map.of("nome", String.valueOf(c.getString("nome")))));
                }
            }
            if (!perDipendenze.isEmpty()) {
                aggiungiCheck(checks, "piano-servizi", I18n.tr("server.um.packagePreflight.24"), "verifica",
                        I18n.tr("server.um.x.depsServices", java.util.Map.of("elenco", String.valueOf(String.join(", ", perDipendenze)))));
            }
        }
        r.put("piano", pianoPerLaScheda(piano)).put("signature", piano.optString("signature", ""));

        java.util.List<String> daSbloccare = jsonArrayToList(piano.optJSONArray("unlockedPackages") == null
                ? new JSONArray() : piano.getJSONArray("unlockedPackages"));
        aggiungiCheck(checks, "protezione", I18n.tr("server.um.packagePreflight.25"), "ok",
                daSbloccare.isEmpty()
                    ? I18n.tr("server.um.packagePreflight.26")
                    : I18n.tr("server.um.x.willUnlock", java.util.Map.of("elenco", String.valueOf(String.join(", ", daSbloccare)))));

        r.put("success", true).put("checks", checks).put("canProceed", !block).put("blocked", block);
        return r;
    }

    /** I pacchetti protetti adesso, per nome, da un'uscita di "pkg lock -l". */
    static Set<String> insiemeProtetti(String elencoLock) {
        Set<String> r = new java.util.TreeSet<>();
        for (String riga : elencoLock.split("\n")) {
            String t = riga.trim();
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
    static String motivoPerNonSbloccare(JSONObject protetto) {
        String n = protetto.optString("nome"), da = protetto.optString("versione"), a = protetto.optString("verso");
        // Se pkg non dice a che versione andrebbe, si suppone il caso peggiore.
        boolean maggiore = a.isEmpty() || saltoSignificativo(n, da, a);
        JSONObject av = avvertenzaPer(n, maggiore);
        if (av != null && "attendi".equals(av.optString("level")))
            return I18n.tr("server.um.x.protectedWait", java.util.Map.of("t", String.valueOf(av.optString("text"))));
        return null;
    }

    /** Il piano come lo mostra la scheda: l'uscita di pkg si accorcia, il resto resta com'e'. */
    private static JSONObject pianoPerLaScheda(JSONObject piano) {
        JSONObject p = new JSONObject(piano.toString());
        String u = p.optString("output", "");
        if (u.length() > 6000) p.put("output", "...\n" + u.substring(u.length() - 6000));
        return p;
    }

    /**
     * @param firmaApprovata l'fingerprint del piano che chi preme ha letto nella scheda. Il job
     *                       ricalcola il piano e parte solo se e' lo stesso: fra la lettura e il
     *                       click il catalogo puo' essere cambiato, e allora si eseguirebbe un
     *                       piano che nessuno ha visto.
     */
    public static JSONObject startGuidedUpdate(String nome, String firmaApprovata) {
        if (!isValidName(nome)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.cambiaProtezioni.1"));
        if (firmaApprovata == null || !firmaApprovata.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startGuidedUpdate.1"));
        String id = "guid-" + System.currentTimeMillis();
        Job j = new Job(id, "guided_update");
        // Il turno si prende qui, prima dei controlli e di ogni sblocco: due aggiornamenti
        // approvati da due schede non possono partire insieme.
        final String pkgNome = nome;
        return avviaSulTurno(id, j, I18n.tr("server.um.startGuidedUpdate.2", java.util.Map.of("nome", String.valueOf(nome))), "guided-update",
                () -> runAggiornamentoGuidato(j, pkgNome, firmaApprovata));
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
    private static void runAggiornamentoGuidato(Job job, String nome, String firmaApprovata) {
        job.status = "running";
        final int TOT = 6;
        boolean pianoNonRispettato = false;
        JSONObject piano;
        java.util.List<String> daRiproteggere = new ArrayList<>();
        java.util.List<String> famiglia = new ArrayList<>();
        java.util.List<String> messaggiAzione = new ArrayList<>();
        boolean ricontrolloManuale = false;
        java.util.List<String> servizi = new ArrayList<>();
        Map<String, String> pidPrima = new LinkedHashMap<>();
        Map<String, Boolean> attivoPrima = new LinkedHashMap<>();
        try {
            job.avanza(1, TOT);
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.1", java.util.Map.of("nome", String.valueOf(nome))));
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.1", java.util.Map.of("tOT", String.valueOf(TOT))));
            JSONObject pf = packagePreflight(nome);
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigrazione84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level"))) {
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] "
                                + c.optString("label") + ": " + c.optString("detail"));
                    }
                }
                job.scrivi(I18n.tr("server.um.runMigrazione84.4"));
                return;
            }
            String versionePrima = pf.optString("current", "");
            String attesa = pf.optString("available", "");
            famiglia = jsonArrayToList(pf.optJSONArray("family") == null
                    ? new JSONArray().put(nome) : pf.getJSONArray("family"));

            // Si esegue il piano che e' stato letto, o niente. Il preflight qui sopra l'ha appena
            // ricalcolato: se l'fingerprint non e' quella approvata, qualcosa e' cambiato nel
            // frattempo (di solito il catalogo) e il piano che partirebbe non l'ha visto nessuno.
            piano = pf.getJSONObject("piano");
            String firmaOra = pf.optString("signature", "");
            if (!firmaOra.equals(firmaApprovata)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runAggiornamentoGuidato.2");
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.3", java.util.Map.of("firmaApprovata", String.valueOf(firmaApprovata), "firmaOra", String.valueOf(firmaOra))));
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.4"));
                return;
            }
            job.scrivi("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(firmaOra))));
            JSONArray cambiPiano = piano.getJSONArray("changes");
            for (int i = 0; i < cambiPiano.length(); i++) {
                JSONObject c = cambiPiano.getJSONObject(i);
                job.scrivi("    " + PackagePlan.typeName(c.getString("tipo")) + " " + c.getString("nome") + " "
                        + (c.getString("da").isEmpty() ? "" : c.getString("da"))
                        + (c.getString("a").isEmpty() || c.getString("a").equals(c.getString("da")) ? "" : " -> " + c.getString("a")));
            }
            // Si sblocca esattamente cio' che il piano ha sbloccato nella copia: ne' uno in meno
            // (pkg si fermerebbe), ne' uno in piu' (resterebbe scoperto senza motivo).
            java.util.List<String> protetti = jsonArrayToList(piano.getJSONArray("unlockedPackages"));
            JSONArray sv = pf.optJSONArray("services");
            for (int i = 0; sv != null && i < sv.length(); i++) {
                JSONObject o = sv.getJSONObject(i);
                String n = o.getString("name");
                servizi.add(n);
                pidPrima.put(n, o.optString("pid", ""));
                attivoPrima.put(n, o.optBoolean("running", false));
            }
            job.scrivi("  " + nome + " " + versionePrima + " -> " + attesa);
            if (famiglia.size() > 1) {
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.5", java.util.Map.of("p", String.valueOf((famiglia.size() - 1)), "p2", String.valueOf(motivoFamiglia(nome)))));
            }
            job.scrivi("  " + I18n.tr("server.um.x.svcInvolvedList", java.util.Map.of("elenco", String.valueOf(servizi.isEmpty() ? I18n.tr("server.um.x.none") : String.join(", ", servizi)))));

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi("[2/" + TOT + "] " + I18n.tr("server.um.x.tempUnlock"));
            if (protetti.isEmpty()) {
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.6"));
            } else {
                // L'elenco si salva PRIMA di sbloccare: se il pannello muore adesso, il
                // ripristino all'avvio sa cosa riproteggere. Se non si scrive, non si sblocca
                // niente: un'interruzione li lascerebbe unlockedPackages senza traccia.
                for (String m : protetti)
                    if (!isValidName(m)) throw new IllegalStateException("invalid package name in the plan: " + m);
                String errStato = PackageQueue.scriviStato(protetti);
                if (errStato != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I did not unlock anything: " + errStato);
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.7", java.util.Map.of("sTATO_MANUTENZIONE", String.valueOf(MAINTENANCE_STATE))));
                // Da riproteggere tutti, anche uno sblocco fallito o scaduto a meta': pkg lock su un
                // pacchetto gia' protetto non cambia niente, e cosi' l'elenco su disco si chiude
                // solo quando tutti risultano protetti.
                daRiproteggere.addAll(protetti);
                for (String m : protetti) {
                    boolean u = ok("pkg unlock -y " + m, 30);
                    job.scrivi("    " + m + ": " + (u ? I18n.tr("server.um.x.unlocked") : I18n.tr("server.um.runAggiornamentoGuidato.8")));
                    if (!u) throw new IllegalStateException("I could not unlock " + m);
                }
            }

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.9", java.util.Map.of("tOT", String.valueOf(TOT))));
            StringBuilder list = new StringBuilder();
            for (String m : famiglia) if (isValidName(m)) list.append(' ').append(m);
            // L'output serve due volte: mostrato mentre scorre, e riletto alla fine per
            // ripescare i messaggi che chiedono un'azione.
            StringBuilder catturato = new StringBuilder();
            // -U: stesso catalogo su cui e' stato calcolato il piano. Riscaricarlo adesso potrebbe
            // portare versioni diverse da quelle approvate.
            int code = eseguiConLog(job, "pkg upgrade -y -U" + list + " 2>&1", 1800, catturato);
            // 4 = EX_NEEDRESTART: pkg ha aggiornato se stesso. Le versioni recenti si rilanciano
            // da sole e fanno il resto; se questa si e' fermata li', la si rilancia una volta, uguale.
            if (code == 4) {
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.10"));
                code = eseguiConLog(job, "pkg upgrade -y -U" + list + " 2>&1", 1800, catturato);
            }
            messaggiAzione = messaggiCheChiedonoAzione(catturato.toString());
            if (code != 0) throw new IllegalStateException("pkg upgrade exited with code " + code);

            String versioneDopo = sh("pkg query %v " + nome + " 2>/dev/null", 20);
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.11", java.util.Map.of("versioneDopo", String.valueOf(versioneDopo))));
            if (versioneDopo.equals(versionePrima)) {
                throw new IllegalStateException("the version did not change: the update had no effect");
            }
            // Ogni riga del piano, controllata: non "pkg e' uscito con 0", ma "ogni pacchetto e'
            // alla versione che il piano diceva".
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.12"));
            JSONArray verifica = PackagePlan.verificaEsito(piano);
            for (int i = 0; i < verifica.length(); i++) {
                JSONObject v = verifica.getJSONObject(i);
                job.scrivi("    " + (v.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("nome", String.valueOf(v.getString("nome")), "atteso", String.valueOf(v.getString("atteso")), "trovato", String.valueOf(v.getString("trovato")))));
                if (!v.getBoolean("ok")) pianoNonRispettato = true;
            }
            if (pianoNonRispettato) job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.13"));

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.14", java.util.Map.of("tOT", String.valueOf(TOT), "nome", String.valueOf(nome))));
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.15"));
            boolean problemaServizi = false;
            if (servizi.isEmpty()) {
                JSONArray rd = pf.optJSONArray("reverseDeps");
                job.scrivi("  " + (rd == null || rd.length() == 0
                        ? I18n.tr("server.um.x.noRestartZero")
                        : I18n.tr("server.um.x.noRestartSome", java.util.Map.of("n", String.valueOf(rd.length()), "elenco", String.valueOf(String.join(", ", jsonArrayToList(rd)))))));
                if (nome.matches(LIBRERIE_CONDIVISE)) {
                    job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.16", java.util.Map.of("nome", String.valueOf(nome))));
                    job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.17"));
                    job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.18"));
                    job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.19"));
                    job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.20"));
                    ricontrolloManuale = true;
                }
            }
            for (String s : servizi) {
                if (!Boolean.TRUE.equals(attivoPrima.get(s))) {
                    job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.21", java.util.Map.of("s", String.valueOf(s))));
                    continue;
                }
                // Si chiede al servizio se accetta la propria configurazione PRIMA di
                // riavviarlo: se non la accetta, riavviarlo lo spegnerebbe e basta. Meglio
                // lasciarlo in piedi con quella vecchia e dirlo.
                String prova = provaConfigDi(s);
                if (prova != null) {
                    Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), prova + " 2>&1");
                    if (!pr.success()) {
                        job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.22", java.util.Map.of("s", String.valueOf(s))));
                        for (String l : pr.outputTrim().split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
                        job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.23"));
                        problemaServizi = true;
                        continue;
                    }
                    job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.24", java.util.Map.of("s", String.valueOf(s))));
                }
                boolean r1 = ok("service " + s + " restart", 120);
                boolean attivo = ok("service " + s + " status", 20);
                String pidDopo = pidServizio(s);
                String pidP = pidPrima.getOrDefault(s, "");
                String nota = "";
                if (!pidP.isEmpty() && !pidDopo.isEmpty()) {
                    nota = pidP.equals(pidDopo)
                        ? I18n.tr("server.um.runAggiornamentoGuidato.25", java.util.Map.of("pidDopo", String.valueOf(pidDopo)))
                        : "  (pid " + pidP + " -> " + pidDopo + ")";
                    if (pidP.equals(pidDopo)) problemaServizi = true;
                }
                job.scrivi("    " + s + ": " + (r1 ? I18n.tr("server.um.x.restarted") : I18n.tr("server.um.runAggiornamentoGuidato.26"))
                        + ", " + (attivo ? I18n.tr("server.um.x.nowRunning") : I18n.tr("server.um.x.nowNotRunning")) + nota);
                if (!attivo) problemaServizi = true;

                // Ha ritrovato i suoi dati, o e' ripartito vuoto?
                String[] dopo = provaDopoDi(s);
                if (dopo != null && attivo) {
                    String out = sh(dopo[1], 30).trim();
                    long n = number(out);
                    job.scrivi("      " + I18n.tr(dopo[2]) + ": " + (out.isEmpty() ? I18n.tr("server.um.runAggiornamentoGuidato.27") : String.valueOf(n)));
                    if (n == 0) {
                        job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.28"));
                        job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.29"));
                        job.scrivi("      " + I18n.tr("server.um.x.rsGreyLimits"));
                        problemaServizi = true;
                    }
                }
            }

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.30", java.util.Map.of("tOT", String.valueOf(TOT))));
            String audit = sh("pkg audit " + nome + " 2>&1", 120);
            JSONObject det = dettaglioVulnerabilita(audit, nome);
            int rimaste = det.getJSONArray("cve").length();
            if (rimaste == 0) {
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.31", java.util.Map.of("nome", String.valueOf(nome))));
            } else {
                job.scrivi("  " + I18n.tr("server.um.x.cvesLeft", java.util.Map.of("n", String.valueOf(rimaste), "nome", String.valueOf(nome), "d", String.valueOf(det.getString("description")))));
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.32"));
            }

            if (!messaggiAzione.isEmpty()) {
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.33"));
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.34"));
                for (String m : messaggiAzione) {
                    for (String l : m.split("\n")) if (!l.trim().isEmpty()) job.scrivi("  " + l);
                    job.scrivi("");
                }
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.35", java.util.Map.of("tOT", String.valueOf(TOT))));
            boolean caduto = false;
            for (Map.Entry<String, Boolean> e : statoServizi().entrySet()) {
                job.scrivi("    " + e.getKey() + ": " + (e.getValue() ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26")));
                if (!e.getValue()) caduto = true;
            }

            if (pianoNonRispettato) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runAggiornamentoGuidato.36");
            } else if (problemaServizi || caduto) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runAggiornamentoGuidato.37");
            } else if (ricontrolloManuale) {
                // Non e' un errore, ma nemmeno un "fatto e verificato": dirlo completato
                // sarebbe affermare una cosa che il pannello non ha potuto controllare.
                job.status = "completed";
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.38", java.util.Map.of("nome", String.valueOf(nome), "versioneDopo", String.valueOf(versioneDopo))));
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.39"));
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.40"));
            } else {
                job.status = "completed";
                job.scrivi("");
                job.scrivi("=== " + I18n.tr("server.um.x.inService", java.util.Map.of("nome", String.valueOf(nome), "v", String.valueOf(versioneDopo))) + " ===");
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // La riprotezione avviene SEMPRE, qualunque cosa sia andata storta sopra.
            if (!daRiproteggere.isEmpty()) {
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.x.reprotecting", java.util.Map.of("n", String.valueOf(daRiproteggere.size()))));
                int rip = 0;
                for (String m : daRiproteggere) {
                    boolean ril = ok("pkg info -e " + m, 15) && ok("pkg lock -y " + m, 30);
                    if (ril) rip++;
                    else job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.41", java.util.Map.of("m", String.valueOf(m))));
                }
                job.scrivi("  " + rip + "/" + daRiproteggere.size() + " riprotetti");
                if (rip == daRiproteggere.size()) pulisciStato();
                else {
                    job.scrivi(I18n.tr("server.um.runPassaggioPython.21", java.util.Map.of("sTATO_MANUTENZIONE", String.valueOf(MAINTENANCE_STATE))));
                    if ("completed".equals(job.status)) {
                        job.status = "error";
                        job.errorMessage = I18n.tr("server.um.runAggiornamentoGuidato.42");
                    }
                }
            }
            job.fine = System.currentTimeMillis();
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
        Thread t = lavoroInLingua(() -> {
            j.status = "running";
            try {
                final String DIR = "/var/db/rspamd";
                j.avanza(1, 4);
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.1"));
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.2"));
                long unserPrima = number(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long altriPrima = number(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.3", java.util.Map.of("unserPrima", String.valueOf(unserPrima))));
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.4", java.util.Map.of("altriPrima", String.valueOf(altriPrima))));
                if (unserPrima == 0) {
                    j.status = "completed";
                    j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.5"));
                    return;
                }
                for (String f : sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null", 60).split("\n")) {
                    if (!f.trim().isEmpty()) j.scrivi("      " + f.trim());
                }

                j.avanza(2, 4);
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.6"));
                ok("find " + DIR + " -type f -name '*.unser' -delete", 120);

                j.avanza(3, 4);
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.7"));
                long unserDopo = number(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long altriDopo = number(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.8", java.util.Map.of("unserDopo", String.valueOf(unserDopo))));
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.9", java.util.Map.of("altriPrima", String.valueOf(altriPrima), "altriDopo", String.valueOf(altriDopo))));
                if (altriDopo != altriPrima) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.10", java.util.Map.of("altriPrima", String.valueOf(altriPrima), "altriDopo", String.valueOf(altriDopo)));
                    j.scrivi("    " + I18n.tr("server.um.x.alarm", java.util.Map.of("m", String.valueOf(j.errorMessage))));
                    return;
                }
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.11"));

                j.avanza(4, 4);
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.12"));
                Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), "rspamadm configtest 2>&1");
                if (!pr.success()) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.13");
                    j.scrivi("    " + pr.outputTrim());
                    return;
                }
                j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.14"));
                String pidPrima = pidServizio("rspamd");
                ok("service rspamd restart", 120);
                boolean attivo = ok("service rspamd status", 30);
                String pidDopo = pidServizio("rspamd");
                j.scrivi("    rspamd: " + (attivo ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26"))
                        + (pidPrima.isEmpty() || pidDopo.isEmpty() ? "" : "  (pid " + pidPrima + " -> " + pidDopo + ")"));
                if (!attivo) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startRspamdCacheCleanup.15");
                } else {
                    j.status = "completed";
                    j.scrivi("");
                    j.scrivi(I18n.tr("server.um.startRspamdCacheCleanup.16"));
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = e.getMessage();
                j.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                j.fine = System.currentTimeMillis();
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
        JSONArray rotti = new JSONArray();
        java.util.LinkedHashSet<String> librerieAssenti = new java.util.LinkedHashSet<>();
        for (String riga : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
            String t = riga.trim();
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            String nome = t.substring(0, sp).trim();
            String lib = t.substring(sp + 1).trim();
            if (!isValidName(nome) || lib.isEmpty()) continue;
            if (!lib.matches("[A-Za-z0-9._+-]{1,128}")) continue;
            if (librerieAssenti.contains(lib)) { rotti.put(new JSONObject().put("name", nome).put("lib", lib)); continue; }
            // Una libreria c'e' se il linker riesce a trovarla fra quelle note al sistema.
            if (!ok("ldconfig -r 2>/dev/null | grep -q ' " + lib + "$' || " +
                    "find /lib /usr/lib /usr/local/lib -name '" + lib + "' -maxdepth 3 2>/dev/null | grep -q .", 30)) {
                librerieAssenti.add(lib);
                rotti.put(new JSONObject().put("name", nome).put("lib", lib));
            }
        }
        return new JSONObject().put("success", true).put("packages", rotti)
                .put("missingLibs", new JSONArray(new ArrayList<>(librerieAssenti)));
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
        java.util.LinkedHashSet<String> espliciti = new java.util.LinkedHashSet<>();
        for (String n : sh("pkg query -e '%a = 0' '%n' 2>/dev/null", 60).split("\n"))
            if (isValidName(n.trim())) espliciti.add(n.trim());

        java.util.HashSet<String> richiesti = new java.util.HashSet<>();
        for (String riga : sh("pkg query '%n %dn' 2>/dev/null", 120).split("\n")) {
            String t = riga.trim();
            int sp = t.indexOf(' ');
            if (sp > 0) richiesti.add(t.substring(sp + 1).trim());
        }

        String lock = sh("pkg lock -l 2>/dev/null", 30);

        JSONArray fuori = new JSONArray();
        int conRuolo = 0;
        for (String n : espliciti) {
            if (richiesti.contains(n)) continue;
            String ruolo = ruoloDi(n);
            if (ruolo != null) conRuolo++;
            boolean essenziale = n.equals("pkg") || n.equals("pkg-devel");
            fuori.put(new JSONObject().put("nome", n)
                    .put("versione", sh("pkg query %v " + n + " 2>/dev/null", 20))
                    .put("protetto", bloccato(lock, n))
                    .put("ruolo", ruolo == null ? "" : ruolo)
                    .put("essenziale", essenziale)
                    .put("avviso", essenziale
                            ? I18n.tr("server.um.removalCandidates.1")
                            : (ruolo == null ? "" : I18n.tr("server.um.removalCandidates.2"))));
        }
        return new JSONObject().put("success", true).put("candidati", fuori)
                .put("esplicitiTotali", espliciti.size()).put("conRuolo", conRuolo)
                .put("attenzione", I18n.tr("server.um.removalCandidates.3"))
                .put("explanation", I18n.tr("server.um.removalCandidates.4"));
    }

    /**
     * I luoghi in cui il pannello, i pacchetti e l'amministratore lasciano cose che vengono
     * eseguite DOPO: script di rinnovo, cron, rc.d, periodic, configurazioni. Il jar non li
     * contiene, quindi cercarli solo li' dentro non basta.
     */
    private static final String[][] LUOGHI = {
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
     * Quindi si separano nettamente due elenchi: i references che ROMPONO e quelli che
     * REGGONO. E si cerca in tre posti diversi, perche' bastano due su tre per ingannarsi:
     * dentro il jar, fra i pacchetti installati (chi dichiara quei soname), e sui file di
     * testo del sistema, dove vivono gli script che girano piu' tardi.
     *
     * Ogni ricerca dichiara quanti file di testo ha esaminato. Una ricerca che non trova
     * nulla perche' non ha guardato da nessuna parte e' indistinguibile, nel risultato, da
     * una che ha guardato e non ha trovato: il conteggio e' cio' che le distingue.
     */
    public static JSONObject deepAnalysis(String pacchetto) {
        if (!isValidName(pacchetto))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        if (!ok("pkg info -e " + pacchetto, 20))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.2", java.util.Map.of("pacchetto", String.valueOf(pacchetto))));

        JSONObject r = new JSONObject().put("success", true).put("pacchetto", pacchetto);

        // --- cosa il pacchetto mette sul disco: percorsi assoluti e soname ---
        String list = sh("pkg query '%Fp' " + pacchetto + " 2>/dev/null", 60);
        if (list.isBlank()) list = sh("pkg info -l " + pacchetto + " 2>/dev/null", 60);
        java.util.LinkedHashSet<String> percorsi = new java.util.LinkedHashSet<>();
        java.util.LinkedHashSet<String> basi = new java.util.LinkedHashSet<>();
        for (String riga : list.split("\n")) {
            String f = riga.trim();
            if (!f.matches("(/usr)?(/local)?/(s?bin|libexec)(/[A-Za-z0-9._+-]{1,64}){1,2}")) continue;
            percorsi.add(f);
            basi.add(f.substring(f.lastIndexOf('/') + 1));
        }
        java.util.LinkedHashSet<String> soname = new java.util.LinkedHashSet<>();
        for (String l : sh("pkg query %b " + pacchetto + " 2>/dev/null", 30).split("\n"))
            if (l.trim().matches("[A-Za-z0-9._+-]{1,128}")) soname.add(l.trim());
        r.put("percorsi", new JSONArray(new ArrayList<>(percorsi)))
         .put("soname", new JSONArray(new ArrayList<>(soname)));

        // I motivi per cui una rimozione rompe: percorso assoluto, o soname.
        java.util.LinkedHashSet<String> rompono = new java.util.LinkedHashSet<>(percorsi);
        rompono.addAll(soname);
        for (String sn : soname) { rompono.add("/usr/local/lib/" + sn); }
        r.put("cercati", new JSONArray(new ArrayList<>(rompono)));

        // --- 1. chi, fra i pacchetti installati, dichiara quei soname ---
        JSONArray dichiaranoSoname = new JSONArray();
        if (!soname.isEmpty()) {
            for (String riga : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
                String t = riga.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                String n = t.substring(0, sp).trim(), lib = t.substring(sp + 1).trim();
                if (!n.equals(pacchetto) && soname.contains(lib))
                    dichiaranoSoname.put(new JSONObject().put("pacchetto", n).put("libreria", lib));
            }
        }
        r.put("dichiaranoSoname", dichiaranoSoname);

        // --- 2. il jar in esecuzione: percorsi assoluti e soname, non solo i nomi nudi ---
        String jar = jarPath();
        JSONArray nelJar = new JSONArray();
        long byteJar = 0;
        int jarBloccanti = 0;
        String mioFile = UpdateManager.class.getSimpleName();
        if (jar != null && !jar.isBlank() && ok("test -r " + jar, 15)) {
            String n = sh("tar -xOf " + jar + " 'org/mail_panel/*' 2>/dev/null | wc -c", 120)
                    .trim().replaceAll("[^0-9]", "");
            if (!n.isEmpty()) byteJar = Long.parseLong(n);
            if (byteJar > 0) {
                StringBuilder pat = new StringBuilder();
                for (String x : rompono) pat.append(" -e '").append(x).append("'");
                // Estrazione in una cartella temporanea: solo cosi' grep puo' dire QUALE classe.
                String output = sh("d=$(mktemp -d) && tar -xf " + jar + " -C \"$d\" 'org/mail_panel/*' "
                        + "2>/dev/null; grep -rlaF" + pat + " \"$d\" 2>/dev/null "
                        + "| sed \"s|^$d/||\"; rm -rf \"$d\"", 240);
                for (String riga : output.split("\n")) {
                    String f = riga.trim();
                    if (f.isEmpty() || !f.endsWith(".class")) continue;
                    String classe = f.substring(f.lastIndexOf('/') + 1).replace(".class", "");
                    boolean mio = classe.equals(mioFile) || classe.startsWith(mioFile + "$");
                    if (!mio) jarBloccanti++;
                    nelJar.put(new JSONObject().put("classe", classe).put("file", f)
                            .put("autoRiferimento", mio));
                }
            }
        }
        r.put("jar", jar == null ? "" : jar).put("byteJar", byteJar)
         .put("jarLetto", byteJar > 0).put("nelJar", nelJar).put("jarBloccanti", jarBloccanti)
         .put("classeDelControllo", mioFile);

        // --- 3. i file di testo del sistema: dove vivono gli script che girano dopo ---
        JSONArray luoghi = new JSONArray();
        int totaleRompono = 0, totaleReggono = 0;
        StringBuilder patRompono = new StringBuilder();
        for (String x : rompono) patRompono.append(" -e '").append(x).append("'");
        StringBuilder patReggono = new StringBuilder();
        for (String b : basi) if (b.length() >= 4) patReggono.append(" -e '").append(b).append("'");

        for (String[] L : LUOGHI) {
            if (!ok("test -d " + L[0], 15)) continue;
            JSONObject u = new JSONObject().put("dove", L[0]).put("cosaContiene", I18n.tr(L[1]));
            // Quanti file di testo esistono qui: e' la prova che la ricerca ha guardato.
            String cnt = sh("grep -rIl '' " + L[0] + " 2>/dev/null | wc -l", 180).trim().replaceAll("[^0-9]", "");
            int esaminati = cnt.isEmpty() ? 0 : Integer.parseInt(cnt);
            u.put("fileEsaminati", esaminati);

            JSONArray rotture = new JSONArray();
            if (patRompono.length() > 0) {
                for (String riga : sh("grep -rInIF" + patRompono + " " + L[0]
                        + " 2>/dev/null | head -40", 240).split("\n")) {
                    if (riga.isBlank()) continue;
                    rotture.put(riga.length() > 300 ? riga.substring(0, 300) + "..." : riga);
                }
            }
            int reggono = 0;
            if (patReggono.length() > 0) {
                String q = sh("grep -rIwoF" + patReggono + " " + L[0] + " 2>/dev/null | wc -l", 240)
                        .trim().replaceAll("[^0-9]", "");
                if (!q.isEmpty()) reggono = Integer.parseInt(q);
            }
            u.put("rompono", rotture).put("reggono", reggono);
            totaleRompono += rotture.length();
            totaleReggono += reggono;
            luoghi.put(u);
        }
        r.put("luoghi", luoghi).put("totaleRompono", totaleRompono).put("totaleReggono", totaleReggono);

        // --- il giudizio ---
        // Il riferimento che sta nella classe che ESEGUE questo controllo non blocca: e'
        // l'analisi che nomina cio' che deve ispezionare, non un uso che si romperebbe.
        boolean bloccante = totaleRompono > 0 || jarBloccanti > 0 || dichiaranoSoname.length() > 0;
        r.put("bloccante", bloccante);
        r.put("verdict", bloccante ? "CI SONO RIFERIMENTI CHE SI ROMPEREBBERO" : "NESSUN RIFERIMENTO CHE SI ROMPA");
        int auto = nelJar.length() - jarBloccanti;
        r.put("explanation", bloccante
                ? I18n.tr("server.um.deepAnalysis.5", java.util.Map.of("pacchetto", String.valueOf(pacchetto)))
                : I18n.tr("server.um.x.deepClean", java.util.Map.of("pacchetto", String.valueOf(pacchetto), "n", String.valueOf(totaleReggono)))
                  + (auto > 0
                     ? " " + (auto == 1
                        ? I18n.tr("server.um.x.deepSelf.one", java.util.Map.of("file", String.valueOf(mioFile)))
                        : I18n.tr("server.um.x.deepSelf.other", java.util.Map.of("n", String.valueOf(auto), "file", String.valueOf(mioFile))))
                     : ""));
        r.put("avvertenza", I18n.tr("server.um.deepAnalysis.6"));
        return r;
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
    public static JSONObject removePackage(String nome) {
        String id = "rimuovi-" + System.nanoTime();
        String rifiuto = PackageQueue.prendi(id, I18n.tr("server.um.removePackage.1", java.util.Map.of("nome", String.valueOf(nome))));
        if (rifiuto != null) return new JSONObject().put("success", false).put("error", rifiuto);
        try { return rimuoviPacchettoOra(nome); }
        finally { PackageQueue.rilascia(id); }
    }

    private static JSONObject rimuoviPacchettoOra(String nome) {
        if (!isValidName(nome))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        StringBuilder log = new StringBuilder();
        JSONObject r = new JSONObject().put("pacchetto", nome);

        if (!ok("pkg info -e " + nome, 20)) {
            log.append(I18n.tr("server.um.x.rmNotInstalled", java.util.Map.of("nome", String.valueOf(nome)))).append("\n")
               .append(I18n.tr("server.um.x.rmChecksAnyway")).append("\n");
            JSONObject lib0 = packagesWithMissingLibraries();
            JSONArray rotti0 = lib0.optJSONArray("packages");
            boolean guasto0 = rotti0 != null && rotti0.length() > 0;
            r.put("librerieMancanti", lib0).put("servizi", serviziJson())
             .put("rimosso", true).put("giaAssente", true).put("guasto", guasto0)
             .put("dopo", contaRighe(sh("pkg query %n 2>/dev/null", 60)));
            log.append("--- ").append(I18n.tr("server.um.x.check")).append(" ---\n")
               .append(guasto0 ? I18n.tr("server.um.rimuoviPacchettoOra.1", java.util.Map.of("length", String.valueOf(rotti0.length())))
                               : I18n.tr("server.um.rimuoviPacchettoOra.2")).append("\n");
            return r.put("success", true).put("log", log.toString())
                    .put("nota", guasto0
                            ? I18n.tr("server.um.rimuoviPacchettoOra.3", java.util.Map.of("nome", String.valueOf(nome), "nome2", String.valueOf(nome)))
                            : I18n.tr("server.um.rimuoviPacchettoOra.4", java.util.Map.of("nome", String.valueOf(nome))));
        }

        // --- chi lo dichiara: se qualcuno lo fa, non si tocca ---
        String dichiarano = sh("pkg query %rn " + nome + " 2>/dev/null", 30).trim();
        if (!dichiarano.isEmpty())
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.x.rmDeclaredDep", java.util.Map.of("elenco", String.valueOf(dichiarano.replace("\n", ", ")))));

        // --- e il pannello? la stessa misura della scheda, rifatta adesso ---
        JSONObject uso = panelUsage(nome);
        r.put("uso", uso);
        String v = uso.optString("verdict", "");
        if (!v.equals("IL PANNELLO NON LO USA") && !v.equals("LI NOMINA, MA NON SONO I SUOI")
                && !v.startsWith("NON NE USA I COMANDI"))
            return new JSONObject().put("success", false).put("uso", uso)
                    .put("error", I18n.tr("server.um.x.rmJarSays", java.util.Map.of("v", String.valueOf(v))) + " "
                            + uso.optString("explanation", ""));

        // --- e i references sul disco? il jar e' solo uno dei tre posti ---
        JSONObject prof = deepAnalysis(nome);
        r.put("profonda", prof);
        if (prof.optBoolean("bloccante"))
            return new JSONObject().put("success", false).put("profonda", prof)
                    .put("error", I18n.tr("server.um.rimuoviPacchettoOra.5", java.util.Map.of("nome", String.valueOf(nome))));

        // --- fotografia prima, per poter confrontare dopo ---
        int prima = contaRighe(sh("pkg query %n 2>/dev/null", 60));
        log.append(I18n.tr("server.um.x.pkgsBefore", java.util.Map.of("n", String.valueOf(prima)))).append("\n");

        boolean protetto = bloccato(sh("pkg lock -l 2>/dev/null", 30), nome);
        log.append(protetto ? I18n.tr("server.um.x.protBeforeYes") : I18n.tr("server.um.x.protBeforeNo")).append("\n");
        if (protetto) {
            log.append("--- ").append(I18n.tr("server.um.x.unlockSection")).append(" ---\n")
               .append(sh("pkg unlock -y " + nome + " 2>&1", 60)).append("\n");
            if (bloccato(sh("pkg lock -l 2>/dev/null", 30), nome)) {
                log.append(I18n.tr("server.um.x.stillProtected")).append("\n");
                return r.put("success", false).put("log", log.toString())
                        .put("error", I18n.tr("server.um.rimuoviPacchettoOra.6", java.util.Map.of("nome", String.valueOf(nome))));
            }
            log.append(I18n.tr("server.um.x.protRemoved")).append("\n");
        }

        String uscitaDelete = sh("pkg delete -y " + nome + " 2>&1", 180);
        log.append("--- ").append(I18n.tr("server.um.x.removalSection")).append(" ---\n").append(uscitaDelete).append("\n");

        // L'esito lo dice il sistema, non il codice di uscita.
        boolean via = !ok("pkg info -e " + nome, 20);
        int dopo = contaRighe(sh("pkg query %n 2>/dev/null", 60));
        log.append(I18n.tr("server.um.x.pkgsAfter", java.util.Map.of("n", String.valueOf(dopo)))).append("\n");
        r.put("prima", prima).put("dopo", dopo).put("rimosso", via);

        if (!via) {
            if (protetto) log.append("--- riprotezione ---\n").append(sh("pkg lock -y " + nome + " 2>&1", 60));
            // Il motivo lo dice pkg nella sua uscita: riportarlo invece di lasciare
            // l'utente a leggersi il log per capire perche'.
            String perche = uscitaDelete.contains("locked")
                    ? I18n.tr("server.um.rimuoviPacchettoOra.7")
                    : (uscitaDelete.contains("vital") ? I18n.tr("server.um.x.markedVital") : "");
            return r.put("success", false).put("log", log.toString())
                    .put("error", I18n.tr("server.um.x.stillInstalled")
                            + perche + (protetto ? ". " + I18n.tr("server.um.x.reprotectedAsBefore") : "."));
        }

        // --- la verifica che conta: qualcuno e' rimasto senza una libreria? ---
        JSONObject lib = packagesWithMissingLibraries();
        JSONArray rotti = lib.optJSONArray("packages");
        r.put("librerieMancanti", lib);
        r.put("servizi", serviziJson());

        boolean guasto = rotti != null && rotti.length() > 0;
        log.append("--- ").append(I18n.tr("server.um.x.check")).append(" ---\n")
           .append(guasto ? I18n.tr("server.um.rimuoviPacchettoOra.1", java.util.Map.of("length", String.valueOf(rotti.length())))
                          : I18n.tr("server.um.rimuoviPacchettoOra.2")).append("\n");
        return r.put("success", true).put("log", log.toString()).put("guasto", guasto)
                .put("nota", guasto
                        ? I18n.tr("server.um.rimuoviPacchettoOra.8", java.util.Map.of("nome", String.valueOf(nome), "nome2", String.valueOf(nome)))
                        : I18n.tr("server.um.rimuoviPacchettoOra.9"));
    }

    /**
     * Strumenti esterni da cui il pannello dipende, con la cartella in cui il port li mette.
     * Non e' un elenco decorativo: se uno di questi non si raggiunge, la funzione che lo usa
     * fallisce lontano da qui e con un messaggio che parla d'altro.
     */
    private static final String[][] STRUMENTI = {
        {"mysqldump",       "/usr/local/bin",  "server.um.rimuoviPacchettoOra.10"},
        {"mysql",           "/usr/local/bin",  "server.um.rimuoviPacchettoOra.11"},
        {"doveadm",         "/usr/local/bin",  "server.um.rimuoviPacchettoOra.12"},
        {"postmap",         "/usr/local/sbin", "server.um.rimuoviPacchettoOra.13"},
        {"postconf",        "/usr/local/sbin", "server.um.rimuoviPacchettoOra.14"},
        {"rspamadm",        "/usr/local/bin",  "server.um.rimuoviPacchettoOra.15"},
        {"fail2ban-client", "/usr/local/bin",  "server.um.tool.fail2ban"},
        {"nginx",           "/usr/local/sbin", "server.um.rimuoviPacchettoOra.16"},
        {"pkg",             "/usr/local/sbin", "server.um.rimuoviPacchettoOra.17"},
        {"openssl",         "/usr/bin",        "server.um.rimuoviPacchettoOra.18"},
        {"procstat",        "/usr/bin",        "server.um.rimuoviPacchettoOra.19"},
        {"bectl",           "/sbin",           "server.um.rimuoviPacchettoOra.20"},
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
                .put("pathEreditato", org.mail_panel.util.Shell.pathEreditato())
                .put("pathUsato", org.mail_panel.util.Shell.pathCompleto());
        JSONArray a = new JSONArray();
        int irraggiungibili = 0, assenti = 0;
        for (String[] t : STRUMENTI) {
            String risolto = sh("command -v " + t[0] + " 2>/dev/null", 15).trim();
            String atteso = t[1] + "/" + t[0];
            boolean suDisco = ok("test -x " + atteso, 15);
            String stato;
            if (!risolto.isEmpty()) stato = "raggiungibile";
            else if (suDisco) { stato = "C'E' MA IL PATH NON LO RAGGIUNGE"; irraggiungibili++; }
            else { stato = "non installato"; assenti++; }
            a.put(new JSONObject().put("comando", t[0]).put("attesoIn", t[1]).put("aCosaServe", t[2])
                    .put("risolto", risolto).put("suDisco", suDisco).put("stato", stato));
        }
        return r.put("strumenti", a).put("irraggiungibili", irraggiungibili).put("assenti", assenti)
                .put("explanation", irraggiungibili > 0
                        ? I18n.tr("server.um.panelBootEnvironment.3", java.util.Map.of("irraggiungibili", String.valueOf(irraggiungibili)))
                        : (assenti > 0
                           ? I18n.tr("server.um.panelBootEnvironment.4", java.util.Map.of("assenti", String.valueOf(assenti)))
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
                String testo = f.contenuto()
                        .replace("${DB_USER}", c.getDbUser())
                        .replace("${DB_NAME}", c.getDbName())
                        .replace("${DB_PASS}", "«" + I18n.tr("server.um.x.dbPassHidden") + "»")
                        .replace("${SIEVE_PROTO}", pigeonhole ? " sieve" : "");
                file.put(new JSONObject().put("percorso", "/usr/local/etc/dovecot/" + f.percorso())
                        .put("contenuto", testo));
            }
            JSONArray ver = new JSONArray();
            for (String[] v : org.mail_panel.scripts.DovecotConfig.verifiche24())
                ver.put(new JSONObject().put("stato", v[0]).put("impostazione", v[1]).put("nota", v[2]));
            return r.put("file", file).put("verifiche", ver)
                    .put("dbName", c.getDbName()).put("dbUser", c.getDbUser())
                    .put("pigeonhole", pigeonhole)
                    .put("installata", sh("pkg query -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 20))
                    .put("avvertenza", I18n.tr("server.um.dovecot24Preview.1"));
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
     * La chiave "daFare" e' la ragione d'essere del rapporto: un elenco di cose da fare,
     * ordinate per urgenza, gia' scritte in italiano. Se e' vuoto, non c'e' niente da fare —
     * e anche quello va detto, altrimenti un'email che arriva ogni settimana diventa rumore
     * che si smette di leggere.
     */
    /**
     * Con aggiornaDatabase = false non tocca la rete: e' la forma per l'anteprima.
     *
     * "pkg audit -F" scarica il database delle vulnerabilita'. L'anteprima lo chiamava, quindi
     * premere "guarda il rapporto" poteva restare appeso su una rete lenta mentre la scheda
     * prometteva una lettura. Chi guarda vede il numero e, accanto, quanto e' vecchio il
     * database: cosi' sa cosa sta guardando invece di crederlo aggiornato.
     */
    public static JSONObject reportData() { return reportData(true); }

    public static JSONObject reportData(boolean aggiornaDatabase) {
        JSONObject r = new JSONObject();
        JSONArray daFare = new JSONArray();

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
        boolean catalogoRinfrescato = aggiornaDatabase && ok("pkg update -q", 120);
        r.put("catalogoRinfrescato", catalogoRinfrescato);

        // --- sistema ---
        JSONObject so = operatingSystem();
        r.put("sistema", so);
        String kernel = so.optString("kernelInstallato", ""), inEsecuzione = so.optString("kernelInEsecuzione", "");
        if (!kernel.isEmpty() && !inEsecuzione.isEmpty() && !kernel.equals(inEsecuzione))
            daFare.put(new JSONObject().put("urgenza", 1)
                    .put("cosa", I18n.tr("server.um.reportData.1", java.util.Map.of("kernel", String.valueOf(kernel), "inEsecuzione", String.valueOf(inEsecuzione))))
                    .put("dove", I18n.tr("server.um.reportData.2")));
        String fine = so.optString("fineSupporto", "");
        long giorniEol = giorniAllaData(fine);
        r.put("giorniAllaFineSupporto", giorniEol);
        if (giorniEol >= 0 && giorniEol < 120)
            daFare.put(new JSONObject().put("urgenza", giorniEol < 45 ? 1 : 3)
                    .put("cosa", I18n.tr("server.um.reportData.3", java.util.Map.of("giorniEol", String.valueOf(giorniEol), "fine", String.valueOf(fine))))
                    .put("dove", I18n.tr("server.um.reportData.4")));

        // --- pacchetti ---
        JSONObject pk = packagesStatus();
        r.put("pacchetti", pk);
        int conAggiornamento = 0, protetti = 0, totali = 0;
        JSONArray list = pk.optJSONArray("packages");
        JSONArray daAggiornare = new JSONArray();
        if (list != null) {
            totali = list.length();
            for (int i = 0; i < list.length(); i++) {
                JSONObject x = list.getJSONObject(i);
                if (x.optBoolean("locked")) protetti++;
                String ins = x.optString("current", ""), rep = x.optString("available", "");
                if (!rep.isEmpty() && !rep.equals(ins) && !"-".equals(rep)) {
                    conAggiornamento++;
                    if (daAggiornare.length() < 25)
                        daAggiornare.put(x.optString("name") + " " + ins + " -> " + rep);
                }
            }
        }
        r.put("pacchettiTotali", totali).put("pacchettiProtetti", protetti)
         .put("pacchettiConAggiornamento", conAggiornamento).put("daAggiornare", daAggiornare);
        if (conAggiornamento > 0)
            daFare.put(new JSONObject().put("urgenza", 2)
                    .put("cosa", conAggiornamento == 1
                            ? I18n.tr("server.um.x.newerInRepo.one")
                            : I18n.tr("server.um.x.newerInRepo.other", java.util.Map.of("n", String.valueOf(conAggiornamento))))
                    .put("dove", I18n.tr("server.um.reportData.5")));

        // --- vulnerabilita', separando quelle a cui si puo' rimediare ---
        //
        // Niente "tail": c'era, ed era una perdita silenziosa. Ogni blocco di pkg audit occupa
        // quattro o cinque righe, quindi oltre le ~8 vulnerabilita' le prime uscivano dalla
        // finestra e sparivano da ENTRAMBE le liste — quella con rimedio e quella senza. Il
        // rapporto risultava piu' tranquillo di com'era il server, e niente lo segnalava.
        //
        // "-F" scarica il database delle vulnerabilita' dalla rete, quindi lo fa solo l'invio
        // vero: l'anteprima promette una lettura e deve restare una lettura.
        String audit = sh("pkg audit" + (aggiornaDatabase ? " -F" : "") + " 2>&1", 180);
        r.put("audit", audit);
        r.put("vulnDbGiorni", giorniDa("/var/db/pkg/vuln.xml"));
        r.put("vulnDbAggiornatoOra", aggiornaDatabase);
        // Con "-U" le interrogazioni al repository leggono il catalogo che c'e': la sua eta'
        // fa parte del risultato, altrimenti "nel repository c'e' la versione X" suona come
        // una verifica appena fatta sui server di pkg, che non e'.
        //
        // La data la da' PkgCatalog, ed e' quella di pubblicazione sul server. Prima qui si
        // guardava /var/db/pkg/repo-FreeBSD.sqlite, che su FreeBSD 15 non esiste: ogni
        // rapporto diceva "eta' sconosciuta".
        JSONObject cat = PkgCatalog.leggi();
        long giorniCat = cat.optLong("giorni", -1);
        r.put("catalogo", cat).put("catalogoGiorni", giorniCat).put("catalogoData", cat.optString("data"));
        if (aggiornaDatabase && !catalogoRinfrescato)
            daFare.put(new JSONObject().put("urgenza", 2)
                    .put("cosa", giorniCat < 0
                            ? I18n.tr("server.um.x.pkgUpdateFailed")
                            : I18n.tr("server.um.x.pkgUpdateFailedDated", java.util.Map.of("quanto", String.valueOf(PkgCatalog.quanto(giorniCat)), "data", String.valueOf(cat.optString("data")))))
                    .put("dove", I18n.tr("server.um.x.updatesPage")));
        else if (giorniCat < 0)
            daFare.put(new JSONObject().put("urgenza", 3)
                    .put("cosa", cat.optString("nota") + " " + I18n.tr("server.um.x.noCatalogDate"))
                    .put("dove", I18n.tr("server.um.x.updatesPage")));
        else if (giorniCat >= 7 && !catalogoRinfrescato)
            // Dopo un "pkg update" riuscito, un catalogo vecchio e' l'ultimo che il server offre:
            // non c'e' niente da fare. Senza (l'anteprima), puo' esserci un catalogo piu' nuovo.
            daFare.put(new JSONObject().put("urgenza", giorniCat >= 28 ? 2 : 3)
                    .put("cosa", I18n.tr("server.um.x.catalogOld", java.util.Map.of("quanto", String.valueOf(PkgCatalog.quanto(giorniCat)), "data", String.valueOf(cat.optString("data")))))
                    .put("dove", I18n.tr("server.um.x.updatesPage")));

        JSONArray conRimedio = new JSONArray(), senzaRimedio = new JSONArray();
        JSONArray nonCapiti = new JSONArray();
        int trovati = 0;
        for (String riga : audit.split("\n")) {
            Matcher m = Pattern.compile("^([A-Za-z0-9._+-]+)-([0-9][^\\s]*) is vulnerable").matcher(riga.trim());
            if (!m.find()) continue;
            trovati++;
            String nome = m.group(1), installata = m.group(2);
            if (!isValidName(nome)) {
                // Un nome che il filtro non accetta non deve sparire: sparendo non finirebbe
                // ne' fra quelli con rimedio ne' fra quelli senza, e il conto tornerebbe lo
                // stesso. Oggi i nomi di pkg stanno tutti dentro il filtro e questo ramo non
                // scatta mai — ma un elemento che il programma non capisce si conta e si dice.
                nonCapiti.put(riga.trim());
                continue;
            }
            String nelRepo = sh("pkg rquery -U %v " + nome + " 2>/dev/null", 30).trim();
            if (!nelRepo.isEmpty() && !nelRepo.equals(installata))
                conRimedio.put(nome + ": " + installata + " -> " + nelRepo);
            else
                senzaRimedio.put(nome + " " + installata);
        }

        // Il controllo incrociato che pkg audit regala: in fondo stampa "N problem(s) in M
        // package(s) found.". Se cio' che abbiamo letto non combacia con quei totali, il
        // risultato non si mostra come se fosse completo — si dice che non torna. Un elenco
        // parziale spacciato per intero e' peggio di nessun elenco.
        Matcher tot = Pattern.compile("(\\d+)\\s+problem\\(s\\)\\s+in\\s+(\\d+)\\s+[^\\n]*package\\(s\\)\\s+found")
                .matcher(audit);
        if (tot.find()) {
            int pacchettiDichiarati = Integer.parseInt(tot.group(2));
            r.put("vulnPacchettiDichiarati", pacchettiDichiarati);
            if (pacchettiDichiarati != trovati)
                r.put("vulnConteggioNonTorna", I18n.tr("server.um.reportData.6", java.util.Map.of("pacchettiDichiarati", String.valueOf(pacchettiDichiarati), "trovati", String.valueOf(trovati))));
        } else {
            r.put("vulnConteggioNonTorna", I18n.tr("server.um.reportData.7"));
        }
        if (nonCapiti.length() > 0) r.put("vulnNonCapiti", nonCapiti);

        r.put("vulnConRimedio", conRimedio).put("vulnSenzaRimedio", senzaRimedio);
        if (conRimedio.length() > 0)
            daFare.put(new JSONObject().put("urgenza", 1)
                    .put("cosa", conRimedio.length() == 1
                            ? I18n.tr("server.um.x.vulnFix.one", java.util.Map.of("elenco", String.valueOf(String.join(", ", jsonArrayToList(conRimedio)))))
                            : I18n.tr("server.um.x.vulnFix.other", java.util.Map.of("n", String.valueOf(conRimedio.length()), "elenco", String.valueOf(String.join(", ", jsonArrayToList(conRimedio))))))
                    .put("dove", I18n.tr("server.um.reportData.8")));

        // --- librerie mancanti ---
        JSONArray rotti = packagesWithMissingLibraries().optJSONArray("packages");
        r.put("librerieMancanti", rotti == null ? new JSONArray() : rotti);
        if (rotti != null && rotti.length() > 0)
            daFare.put(new JSONObject().put("urgenza", 1)
                    .put("cosa", I18n.tr("server.um.reportData.9", java.util.Map.of("length", String.valueOf(rotti.length()))))
                    .put("dove", I18n.tr("server.um.reportData.10")));

        // --- servizi ---
        JSONArray servizi = serviziJson();
        r.put("servizi", servizi);
        JSONArray giu = new JSONArray();
        for (int i = 0; i < servizi.length(); i++)
            if (!servizi.getJSONObject(i).getBoolean("attivo")) giu.put(servizi.getJSONObject(i).getString("nome"));
        r.put("serviziNonAttivi", giu);
        if (giu.length() > 0)
            daFare.put(new JSONObject().put("urgenza", 0)
                    .put("cosa", I18n.tr("server.um.x.svcDown", java.util.Map.of("elenco", String.valueOf(String.join(", ", jsonArrayToList(giu))))))
                    .put("dove", I18n.tr("server.um.reportData.11")));

        // --- spazio ---
        String df = sh("df -h / 2>/dev/null | tail -1", 30);
        r.put("spazio", df);
        Matcher mp = Pattern.compile("([0-9]+)%").matcher(df);
        if (mp.find()) {
            int usata = Integer.parseInt(mp.group(1));
            r.put("percentualeUsata", usata);
            if (usata >= 85)
                daFare.put(new JSONObject().put("urgenza", usata >= 92 ? 0 : 2)
                        .put("cosa", I18n.tr("server.um.reportData.12", java.util.Map.of("usata", String.valueOf(usata))))
                        .put("dove", I18n.tr("server.um.reportData.13")));
        }

        // --- ambienti di avvio ---
        JSONObject be = bootEnvironments();
        r.put("ambienti", be);

        r.put("branch", branchRepositories());
        r.put("daFare", ordinaPerUrgenza(daFare));
        return r;
    }

    /** Giorni da oggi a una data scritta come gg/mm/aaaa; -1 se non leggibile. */
    private static long giorniAllaData(String gg_mm_aaaa) {
        Matcher m = Pattern.compile("([0-9]{2})/([0-9]{2})/([0-9]{4})").matcher(gg_mm_aaaa == null ? "" : gg_mm_aaaa);
        if (!m.find()) return -1;
        try {
            java.time.LocalDate d = java.time.LocalDate.of(Integer.parseInt(m.group(3)),
                    Integer.parseInt(m.group(2)), Integer.parseInt(m.group(1)));
            return java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.now(), d);
        } catch (Exception e) { return -1; }
    }

    /** Le cose da fare, dalla piu' urgente. 0 = un servizio e' giu', 3 = da pianificare. */
    private static JSONArray ordinaPerUrgenza(JSONArray a) {
        java.util.List<JSONObject> l = new ArrayList<>();
        for (int i = 0; i < a.length(); i++) l.add(a.getJSONObject(i));
        l.sort(java.util.Comparator.comparingInt(x -> x.optInt("urgenza", 9)));
        JSONArray out = new JSONArray();
        for (JSONObject x : l) out.put(x);
        return out;
    }

    /** statoServizi() in forma di elenco JSON, per le schede che lo mostrano. */
    private static JSONArray serviziJson() {
        JSONArray a = new JSONArray();
        for (var e : statoServizi().entrySet())
            a.put(new JSONObject().put("nome", e.getKey()).put("attivo", e.getValue()));
        return a;
    }

    private static int contaRighe(String s) {
        int n = 0;
        for (String l : s.split("\n")) if (!l.isBlank()) n++;
        return n;
    }

    /** Legge l'uscita di "sort | uniq -c": conteggio, spazio, valore. */
    private static void contaIn(String output, java.util.Map<String, Integer> dove) {
        for (String riga : output.split("\n")) {
            String t = riga.trim();
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            try { dove.put(t.substring(sp + 1).trim(), Integer.parseInt(t.substring(0, sp))); }
            catch (NumberFormatException ignored) { }
        }
    }

    public static JSONObject panelUsage(String pacchetto) {
        JSONObject r = new JSONObject().put("success", true).put("pacchetto", pacchetto);
        if (!isValidName(pacchetto))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deepAnalysis.1"));
        if (!ok("pkg info -e " + pacchetto, 20))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.panelUsage.1", java.util.Map.of("pacchetto", String.valueOf(pacchetto))));

        // --- 1. quali eseguibili installa il pacchetto ---
        String list = sh("pkg query '%Fp' " + pacchetto + " 2>/dev/null", 60);
        String comeElencato = "pkg query %Fp";
        if (list.isBlank()) {   // formato non disponibile: si ripiega su pkg info -l
            list = sh("pkg info -l " + pacchetto + " 2>/dev/null", 60);
            comeElencato = "pkg info -l";
        }
        java.util.LinkedHashMap<String, String> eseguibili = new java.util.LinkedHashMap<>();
        for (String riga : list.split("\n")) {
            String f = riga.trim();
            if (!f.startsWith("/")) continue;
            if (!f.matches("(/usr)?(/local)?/(s?bin|libexec)(/[A-Za-z0-9._+-]{1,64}){1,2}")) continue;
            String nome = f.substring(f.lastIndexOf('/') + 1);
            eseguibili.putIfAbsent(nome, f);
        }
        r.put("comeElencato", comeElencato).put("eseguibiliTrovati", eseguibili.size());

        // --- 2. le classi del pannello, dal jar in esecuzione ---
        String jar = jarPath();
        r.put("jar", jar == null ? "" : jar);
        long byteLetti = 0;
        String estrai = null;
        if (jar != null && !jar.isBlank() && ok("test -r " + jar, 15)) {
            // bsdtar (libarchive) e' nel sistema base e legge gli archivi zip, quindi anche i jar.
            estrai = "tar -xOf " + jar + " 'org/mail_panel/*' 2>/dev/null";
            String n = sh(estrai + " | wc -c", 120).trim().replaceAll("[^0-9]", "");
            if (!n.isEmpty()) byteLetti = Long.parseLong(n);
            if (byteLetti == 0 && ok("command -v unzip >/dev/null 2>&1", 15)) {
                estrai = "unzip -p " + jar + " 'org/mail_panel/*' 2>/dev/null";
                n = sh(estrai + " | wc -c", 120).trim().replaceAll("[^0-9]", "");
                if (!n.isEmpty()) byteLetti = Long.parseLong(n);
            }
        }
        boolean letturaRiuscita = byteLetti > 0;
        r.put("byteLetti", byteLetti).put("letturaRiuscita", letturaRiuscita);

        // --- 3. una sola passata: quali di quei nomi compaiono nelle classi ---
        // Due conteggi, non uno. La ricerca per SOTTOSTRINGA e' inservibile: "gif" compare 127
        // volte nelle classi del pannello, ma dentro JSON.stringify e writeNewsyslogIfMissing,
        // mai come comando. Con la ricerca per PAROLA INTERA scende a zero, che e' la verita'.
        // Il secondo conteggio e' piu' stretto ancora: il nome seguito da uno spazio, cioe' un
        // comando con argomenti. Serve a distinguere "openssl x509 -in ..." dal nome che compare
        // per caso. Il giudizio si basa sulla parola intera; l'altro numero e' li' per farsi
        // un'idea, perche' un nome come "test" resta ambiguo per natura.
        java.util.Map<String, Integer> conteggi = new java.util.HashMap<>();
        java.util.Map<String, Integer> conArgomenti = new java.util.HashMap<>();
        java.util.List<String> troppoCorti = new ArrayList<>();
        if (letturaRiuscita && !eseguibili.isEmpty()) {
            StringBuilder intere = new StringBuilder(), conSpazio = new StringBuilder();
            for (String nome : eseguibili.keySet()) {
                if (nome.length() < 4) { troppoCorti.add(nome); continue; }
                intere.append(" -e '").append(nome).append("'");
                conSpazio.append(" -e '").append(nome).append(" '");
            }
            if (intere.length() > 0) {
                contaIn(sh(estrai + " | grep -aowF" + intere + " | sort | uniq -c", 180), conteggi);
                contaIn(sh(estrai + " | grep -aoF" + conSpazio + " | sort | uniq -c", 180), conArgomenti);
            }
        }

        // --- 4. per ogni comando usato: esiste un'altra copia che resterebbe? ---
        JSONArray usati = new JSONArray();
        for (var e : eseguibili.entrySet()) {
            Integer c = conteggi.get(e.getKey());
            if (c == null || c == 0) continue;
            String altrove = "";
            for (String d : new String[]{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"}) {
                String cand = d + "/" + e.getKey();
                if (cand.equals(e.getValue())) continue;
                if (ok("test -x " + cand, 15)) { altrove = cand; break; }
            }
            // Non basta sapere che una seconda copia esiste: bisogna sapere QUALE delle due
            // gira adesso. Se il PATH gia' sceglie l'altra, togliere il pacchetto non cambia
            // nulla — dire "diventerebbe un altro binario" sarebbe falso, e contraddirebbe il
            // riquadro qui sopra che ha appena measured chi vince nel PATH.
            String inUsoOra = sh("command -v " + e.getKey() + " 2>/dev/null", 15).trim();
            boolean eSuo = inUsoOra.equals(e.getValue());
            usati.put(new JSONObject().put("comando", e.getKey()).put("percorso", e.getValue())
                    .put("occorrenze", c)
                    .put("conArgomenti", conArgomenti.getOrDefault(e.getKey(), 0))
                    .put("altraCopia", altrove)
                    .put("inUsoOra", inUsoOra).put("eSuo", eSuo)
                    .put("resterebbe", !altrove.isEmpty())
                    .put("effetto", eSuo
                            ? (altrove.isEmpty()
                               ? I18n.tr("server.um.panelUsage.2")
                               : I18n.tr("server.um.panelUsage.3", java.util.Map.of("altrove", String.valueOf(altrove))))
                            : (inUsoOra.isEmpty()
                               ? I18n.tr("server.um.panelUsage.4")
                               : I18n.tr("server.um.panelUsage.5", java.util.Map.of("inUsoOra", String.valueOf(inUsoOra))))));
        }
        // Un pacchetto puo' non avere nessun comando e servire lo stesso, perche' e' una
        // LIBRERIA: nessuno la digita, ma qualcuno ci si collega. giflib e' esattamente
        // questo. Dirlo qui evita che "non ne uso i comandi" venga letto come "si puo'
        // togliere": per una libreria la domanda giusta e' un'altra, ed e' quella che
        // pone la scheda dei pacchetti senza la libreria che richiedono.
        JSONArray librerie = new JSONArray();
        for (String l : sh("pkg query %b " + pacchetto + " 2>/dev/null", 30).split("\n"))
            if (l.trim().matches("[A-Za-z0-9._+-]{1,128}")) librerie.put(l.trim());
        r.put("fornisceLibrerie", librerie);
        r.put("comandiUsati", usati).put("nomiTroppoCorti", new JSONArray(troppoCorti));

        String verdict, explanation;
        if (!letturaRiuscita) {
            verdict = "NON DETERMINABILE";
            explanation = I18n.tr("server.um.x.jarUnreadable", java.util.Map.of("jar", String.valueOf(jar == null || jar.isBlank() ? I18n.tr("server.um.x.jarUnknown") : jar)));
        } else if (usati.length() == 0) {
            verdict = librerie.length() > 0 ? "NON NE USA I COMANDI, MA E' UNA LIBRERIA"
                                             : "IL PANNELLO NON LO USA";
            explanation = I18n.tr("server.um.x.jarNoUse", java.util.Map.of("byte", String.valueOf(byteLetti), "n", String.valueOf(eseguibili.size()), "pacchetto", String.valueOf(pacchetto)))
                    + (librerie.length() > 0
                       ? " " + I18n.tr("server.um.x.jarLibs", java.util.Map.of("n", String.valueOf(librerie.length()), "elenco", String.valueOf(String.join(", ", jsonArrayToList(librerie)))))
                       : "")
                    + (troppoCorti.isEmpty() ? ""
                       : " " + I18n.tr("server.um.x.jarShortNames", java.util.Map.of("n", String.valueOf(troppoCorti.size()), "elenco", String.valueOf(String.join(", ", troppoCorti)))));
        } else {
            int senzaRicambio = 0, davveroSuoi = 0;
            for (int i = 0; i < usati.length(); i++) {
                JSONObject u = usati.getJSONObject(i);
                if (u.getBoolean("eSuo")) {
                    davveroSuoi++;
                    if (!u.getBoolean("resterebbe")) senzaRicambio++;
                }
            }
            if (davveroSuoi == 0) {
                // Li nomina, ma non e' questo pacchetto a fornire i binari che girano.
                verdict = "LI NOMINA, MA NON SONO I SUOI";
                explanation = usati.length() == 1
                        ? I18n.tr("server.um.x.namesOther.one", java.util.Map.of("pacchetto", String.valueOf(pacchetto)))
                        : I18n.tr("server.um.x.namesOther.other", java.util.Map.of("n", String.valueOf(usati.length()), "pacchetto", String.valueOf(pacchetto)));
                return r.put("verdict", verdict).put("explanation", explanation)
                        .put("perche", I18n.tr("server.um.panelUsage.10"));
            }
            verdict = senzaRicambio > 0 ? "LO USA, E NON C'E' RICAMBIO" : "LO USA";
            explanation = (usati.length() == 1
                    ? I18n.tr("server.um.x.usesCmds.one")
                    : I18n.tr("server.um.x.usesCmds.other", java.util.Map.of("n", String.valueOf(usati.length()))))
                    + " " + (senzaRicambio > 0
                       ? (senzaRicambio == 1
                          ? I18n.tr("server.um.x.noSpare.one")
                          : I18n.tr("server.um.x.noSpare.other", java.util.Map.of("n", String.valueOf(senzaRicambio))))
                       : I18n.tr("server.um.x.allSpare"));
        }
        return r.put("verdict", verdict).put("explanation", explanation)
                .put("perche", I18n.tr("server.um.panelUsage.10"));
    }

    /**
     * L'analisi dell'uscita dello scan, staccata dal comando che la produce: cosi' si puo'
     * provare senza FreeBSD, che e' l'unico modo di sapere che legge davvero cio' che crede.
     * Una riga e' "pid TAB comando TAB percorso [percorso ...]". Il percorso in /usr/local
     * e' il port; quello in /usr/lib e' il sistema base.
     */
    static JSONArray analizzaMappature(String scan) {
        JSONArray processi = new JSONArray();
        if (scan == null) return processi;
        for (String riga : scan.split("\n")) {
            String[] c = riga.split("\t");
            if (c.length < 3 || c[0].trim().isEmpty()) continue;
            JSONArray libs = new JSONArray();
            boolean port = false;
            for (String v : c[2].trim().split("\\s+")) {
                if (v.isEmpty()) continue;
                libs.put(v);
                if (v.startsWith("/usr/local/")) port = true;
            }
            processi.put(new JSONObject().put("pid", c[0].trim())
                    .put("comando", c[1].trim()).put("librerie", libs).put("usaIlPort", port));
        }
        return processi;
    }

    public static JSONObject opensslUsage() {
        JSONObject r = new JSONObject().put("success", true);
        if (!ok("pkg info -e openssl", 20)) {
            return r.put("installato", false).put("verdict", "assente")
                    .put("explanation", I18n.tr("server.um.opensslUsage.1"));
        }
        r.put("installato", true).put("versione", sh("pkg query %v openssl", 20));

        // --- 1. chi lo dichiara nel registro ---
        JSONArray dichiarano = new JSONArray();
        for (String s : sh("pkg query %rn openssl 2>/dev/null", 30).split("\n"))
            if (isValidName(s.trim())) dichiarano.put(s.trim());
        r.put("dichiarano", dichiarano);

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
        java.util.LinkedHashSet<String> comuni = new java.util.LinkedHashSet<>(sonPort);
        comuni.retainAll(sonBase);
        r.put("sonamePort", new JSONArray(new ArrayList<>(sonPort)))
         .put("sonameBase", new JSONArray(new ArrayList<>(sonBase)))
         .put("sonameInComune", new JSONArray(new ArrayList<>(comuni)))
         .put("ambiguo", !comuni.isEmpty());

        // --- 2b. chi richiede quei soname (vale solo se NON sono in comune col base) ---
        JSONArray richiedono = new JSONArray();
        if (!sonPort.isEmpty()) {
            for (String riga : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
                String t = riga.trim();
                int sp = t.indexOf(' ');
                if (sp <= 0) continue;
                String nome = t.substring(0, sp).trim(), lib = t.substring(sp + 1).trim();
                if (isValidName(nome) && sonPort.contains(lib))
                    richiedono.put(new JSONObject().put("pacchetto", nome).put("libreria", lib));
            }
        }
        r.put("richiedonoIlSoname", richiedono);

        // --- 3. la misura che decide: cosa e' mappato ADESSO dai processi vivi ---
        JSONArray processi = new JSONArray();
        JSONArray usanoIlPort = new JSONArray();
        boolean haProcstat = ok("command -v procstat >/dev/null 2>&1", 15);
        int conLibssl = 0;
        if (haProcstat) {
            String scan = sh("for p in $(ps -axo pid=); do "
                    + "m=$(procstat -v $p 2>/dev/null | awk '/lib(ssl|crypto)\\.so/ {print $NF}' | sort -u | tr '\\n' ' '); "
                    + "[ -n \"$m\" ] && printf '%s\\t%s\\t%s\\n' \"$p\" \"$(ps -o comm= -p $p 2>/dev/null)\" \"$m\"; "
                    + "done", 240);
            processi = analizzaMappature(scan);
            conLibssl = processi.length();
            for (int i = 0; i < processi.length(); i++)
                if (processi.getJSONObject(i).getBoolean("usaIlPort")) usanoIlPort.put(processi.getJSONObject(i));
        }
        boolean misuraAttendibile = haProcstat && conLibssl > 0;

        // --- 4. il comando, non solo le librerie. procstat vede i processi VIVI: un
        // "openssl x509" dura millisecondi e non si fa quasi mai cogliere. Ma il pannello
        // lo invoca eccome (AcmeManager legge i certificati cosi', e gli script di
        // installazione generano password e chiavi con "openssl rand"), e lo invoca SENZA
        // percorso assoluto. Nel PATH di FreeBSD /usr/local/bin viene prima di /usr/bin,
        // quindi con il port installato e' il suo binario a vincere. Ignorarlo vorrebbe
        // dire dire "non lo usa nessuno" di un programma che gira ogni volta che il
        // pannello guarda un certificato.
        JSONArray binari = new JSONArray();
        for (String percorso : new String[]{"/usr/local/bin/openssl", "/usr/bin/openssl"}) {
            if (!ok("test -x " + percorso, 15)) continue;
            binari.put(new JSONObject().put("percorso", percorso)
                    .put("versione", sh(percorso + " version 2>&1 | head -1", 20))
                    .put("pacchetto", sh("pkg which -q " + percorso + " 2>/dev/null", 20))
                    .put("delPort", percorso.startsWith("/usr/local/")));
        }
        String vincitore = sh("command -v openssl 2>/dev/null", 15).trim();
        boolean comandoDelPort = vincitore.startsWith("/usr/local/");
        boolean baseHaIlComando = ok("test -x /usr/bin/openssl", 15);
        r.put("binari", binari).put("comandoInPath", vincitore)
         .put("comandoDelPort", comandoDelPort).put("baseHaIlComando", baseHaIlComando)
         .put("esplicito", "0".equals(sh("pkg query %a openssl 2>/dev/null", 20).trim()))
         .put("chiLoInvoca", I18n.tr("server.um.opensslUsage.2"));

        r.put("processi", processi).put("usanoIlPort", usanoIlPort)
         .put("processiConTls", conLibssl).put("misuraAttendibile", misuraAttendibile)
         .put("comeHoMisurato", haProcstat
                 ? I18n.tr("server.um.opensslUsage.3", java.util.Map.of("conLibssl", String.valueOf(conLibssl)))
                 : I18n.tr("server.um.opensslUsage.4"));

        // --- il verdict, nell'ordine in cui le prove pesano ---
        String verdict, explanation;
        if (usanoIlPort.length() > 0) {
            verdict = "IN USO ADESSO";
            explanation = usanoIlPort.length() == 1
                    ? I18n.tr("server.um.x.portLibOpen.one")
                    : I18n.tr("server.um.x.portLibOpen.other", java.util.Map.of("n", String.valueOf(usanoIlPort.length())));
        } else if (dichiarano.length() > 0) {
            verdict = "RICHIESTO";
            explanation = I18n.tr("server.um.x.declaredBy", java.util.Map.of("elenco", String.valueOf(String.join(", ", jsonArrayToList(dichiarano)))));
        } else if (comandoDelPort) {
            verdict = "IL COMANDO E' SUO";
            explanation = I18n.tr("server.um.x.cmdIsPort", java.util.Map.of("vincitore", String.valueOf(vincitore))) + " "
                    + (baseHaIlComando
                       ? I18n.tr("server.um.x.baseHasCmd")
                       : I18n.tr("server.um.x.baseNoCmd"));
        } else if (!misuraAttendibile) {
            verdict = "NON DETERMINABILE";
            explanation = I18n.tr("server.um.opensslUsage.7");
        } else {
            verdict = "NESSUNO LO USA";
            explanation = I18n.tr("server.um.opensslUsage.9", java.util.Map.of("conLibssl", String.valueOf(conLibssl)));
        }
        r.put("verdict", verdict).put("explanation", explanation);

        r.put("nota", I18n.tr("server.um.opensslUsage.10"));
        r.put("percheEQui", I18n.tr("server.um.opensslUsage.11"));
        r.put("pannello", panelUsage("openssl"));
        // Questo testo diceva di digitare "pkg unlock" e "pkg delete" da riga di comando.
        // Da quando la rimozione e' un pulsante, dettare i comandi e' peggio che inutile:
        // il pulsante rifa' i controlli e verifica dopo, una mano no.
        r.put("comeSiToglie", I18n.tr("server.um.opensslUsage.12"));
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
        for (String riga : sh("pkg query '%n %v' 2>/dev/null | grep -E '^mysql[0-9]+-(client|server) '", 30).split("\n")) {
            String t = riga.trim();
            int sp = t.indexOf(' ');
            if (sp > 0) client.put(new JSONObject().put("name", t.substring(0, sp)).put("version", t.substring(sp + 1).trim()));
        }
        r.put("mysqlPackages", client);

        JSONArray dip = new JSONArray();
        for (String pk : new String[]{"postfix-mysql", "dovecot-mysql"}) {
            if (!ok("pkg info -e " + pk, 20)) continue;
            dip.put(new JSONObject().put("name", pk)
                    .put("versione", sh("pkg query %v " + pk, 20))
                    .put("dipendenzeInstallato", sh("pkg query %dn " + pk + " 2>/dev/null | tr '\n' ' '", 30))
                    .put("dipendenzeRepository", sh("pkg rquery -U %dn " + pk + " 2>/dev/null | tr '\n' ' '", 30))
                    .put("librerieRichieste", sh("pkg query %B " + pk + " 2>/dev/null | tr '\n' ' '", 30)));
        }
        r.put("dipendenti", dip);

        // Chi fornisce la libreria contesa, e da quale pacchetto proviene il file sul disco.
        r.put("fornisconoLib", sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20));
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
    private static final String[][] PREDEFINITI = {
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
     * Cambia quanto ci mette una fix ad arrivare, ed e' la risposta alla domanda "perche'
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
     *  - non entra NIENTE di segreto: nomi, versioni, stati e warnings. Nessun file di
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
    private static final String[][] FINE_SUPPORTO = {
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
            String inEsec = sh("freebsd-version -r 2>/dev/null", 20).trim();     // kernel in esecuzione
            String userland = sh("freebsd-version -u 2>/dev/null", 20).trim();   // userland
            String uname = sh("uname -r 2>/dev/null", 20).trim();
            String arch = sh("uname -mi 2>/dev/null", 20).trim();
            r.put("kernelInstallato", kernel).put("kernelInEsecuzione", inEsec)
             .put("userland", userland).put("uname", uname).put("arch", arch);

            // L'Handbook: se freebsd-version -k e uname -r differiscono, il kernel installato
            // non e' quello in esecuzione — cioe' manca un riavvio.
            boolean riavvio = !kernel.isEmpty() && !uname.isEmpty() && !kernel.equals(uname);
            r.put("riavvioNecessario", riavvio);

            // Fine supporto: si confronta la parte X.Y della userland con la tabella ufficiale.
            Matcher m = Pattern.compile("^([0-9]+\\.[0-9]+)").matcher(userland);
            String serie = m.find() ? m.group(1) : "";
            String eol = "", noteEol = "";
            for (String[] e : FINE_SUPPORTO)
                if (e[0].equals(serie)) { eol = e[1]; noteEol = I18n.tr(e[2]); }
            // "Non conosco questa serie" e' un'informazione, e va detta.
            //
            // Prima, se la serie non era in tabella, eol restava vuoto e la scheda non mostrava
            // nulla: un silenzio che si legge come "niente da segnalare". Ma il caso in cui la
            // serie manca e' esattamente quello in cui il sistema e' PIU' NUOVO della fotografia,
            // cioe' quello in cui la tabella andrebbe riletta. Il difetto si nascondeva proprio
            // dove voleva farsi notare.
            r.put("serie", serie).put("fineSupporto", eol).put("noteSupporto", noteEol)
             .put("serieConosciuta", !eol.isEmpty())
             .put("fonteSupportoLetta", SUPPORT_SOURCE_READ)
             .put("fonteSupporto", I18n.tr(SUPPORT_SOURCE));

            boolean release = userland.contains("-RELEASE");
            r.put("aggiornabileConFreebsdUpdate", release);
            if (!release) {
                r.put("notaAggiornamenti", I18n.tr("server.um.operatingSystem.1", java.util.Map.of("userland", String.valueOf(userland))));
            } else {
                // updatesready NON scarica: dice solo se c'e' gia' qualcosa di pronto da installare.
                String pronti = sh("freebsd-update updatesready 2>&1", 60).trim();
                r.put("giaPronti", pronti);
                r.put("cePronti", !pronti.toLowerCase().contains("no updates are available"));
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
        Thread t = lavoroInLingua(() -> {
            j.status = "running";
            try {
                j.avanza(1, 1);
                j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.1"));
                j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.2"));
                j.scrivi("");
                JSONObject so = operatingSystem();
                if (!so.optBoolean("aggiornabileConFreebsdUpdate", false)) {
                    j.status = "error";
                    j.errorMessage = so.optString("notaAggiornamenti", I18n.tr("server.um.cercaAggiornamentiSistema.1"));
                    j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(j.errorMessage))));
                    return;
                }
                j.scrivi(I18n.tr("server.um.x.youAreAt", java.util.Map.of("uname", String.valueOf(so.optString("uname")))));
                j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.4"));
                j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.5"));
                j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.6"));
                j.scrivi("");

                // Battito: senza, un comando che scarica per minuti senza andare a capo sembra
                // bloccato. Non e' un abbellimento — e' la differenza fra "sta lavorando" e
                // "e' morto", che dal registro non si distinguerebbe altrimenti.
                final long inizio = System.currentTimeMillis();
                final java.util.concurrent.atomic.AtomicBoolean finito =
                        new java.util.concurrent.atomic.AtomicBoolean(false);
                Thread battito = lavoroInLingua(() -> {
                    try {
                        while (!finito.get()) {
                            Thread.sleep(30000);
                            if (finito.get()) break;
                            j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.7", java.util.Map.of("p", String.valueOf(((System.currentTimeMillis() - inizio) / 1000)))));
                        }
                    } catch (InterruptedException ignored) { }
                }, "os-fetch-battito");
                battito.setDaemon(true);
                battito.start();

                StringBuilder cat = new StringBuilder();
                int codice;
                try {
                    codice = eseguiConLog(j, "freebsd-update --not-running-from-cron fetch 2>&1", 1800, cat);
                } finally {
                    finito.set(true);
                    battito.interrupt();
                }
                String b2 = cat.toString().toLowerCase();
                boolean nessuno = b2.contains("no updates needed") || b2.contains("has no updates available");
                j.scrivi("");
                if (codice != 0 && !nessuno) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startSystemUpdateSearch.8", java.util.Map.of("codice", String.valueOf(codice)));
                    j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(j.errorMessage))));
                    return;
                }
                j.scrivi(nessuno
                        ? I18n.tr("server.um.startSystemUpdateSearch.9")
                        : I18n.tr("server.um.startSystemUpdateSearch.10"));
                j.scrivi(I18n.tr("server.um.startSystemUpdateSearch.11", java.util.Map.of("p", String.valueOf(((System.currentTimeMillis() - inizio) / 1000)))));
                j.status = "completed";
            } catch (Exception e) {
                j.status = "error"; j.errorMessage = e.getMessage();
                j.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally { j.fine = System.currentTimeMillis(); }
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
    private static JSONObject cercaAggiornamentiSistema() {
        try {
            JSONObject so = operatingSystem();
            if (!so.optBoolean("aggiornabileConFreebsdUpdate", false))
                return new JSONObject().put("success", false)
                        .put("error", so.optString("notaAggiornamenti", I18n.tr("server.um.cercaAggiornamentiSistema.1")));
            String out = sh("freebsd-update --not-running-from-cron fetch 2>&1", 900);
            String b = out.toLowerCase();
            boolean nessuno = b.contains("no updates needed") || b.contains("has no updates available");
            return new JSONObject().put("success", true).put("output", out.trim())
                    .put("nessunAggiornamento", nessuno)
                    .put("nota", nessuno
                        ? I18n.tr("server.um.startSystemUpdateSearch.9")
                        : I18n.tr("server.um.cercaAggiornamentiSistema.2"));
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
    private static String percorsoComando(String nome, String... candidati) {
        if (!nome.matches("[a-z0-9_-]{1,32}")) return "";
        String v = sh("command -v " + nome + " 2>/dev/null", 20).trim();
        if (v.startsWith("/") && ok("test -x " + v, 10)) return v;
        for (String c : candidati) if (ok("test -x " + c, 10)) return c;
        return "";
    }

    public static JSONObject cancelReboot() {
        try {
            String pid = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            if (!pid.matches("[0-9]{1,7}")) pid = sh("pgrep -f '/shutdown -r' 2>/dev/null | head -1", 20).trim();
            if (!pid.matches("[0-9]{1,7}"))
                return new JSONObject().put("success", true).put("cera", false)
                        .put("nota", I18n.tr("server.um.cancelReboot.1"));
            String riga = sh("ps -o command= -p " + pid + " 2>/dev/null", 20).trim();
            boolean fatto = ok("kill " + pid, 20);
            // La prova che conta: il processo e' davvero sparito?
            String ancora = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            boolean via = ancora.isEmpty();
            return new JSONObject().put("success", via).put("cera", true)
                    .put("pid", pid).put("comando", riga)
                    .put("nota", via
                        ? I18n.tr("server.um.cancelReboot.2", java.util.Map.of("pid", String.valueOf(pid), "riga", String.valueOf(riga)))
                        : I18n.tr("server.um.cancelReboot.3", java.util.Map.of("ancora", String.valueOf(ancora), "ancora2", String.valueOf(ancora))))
                    .put("error", via ? "" : I18n.tr("server.um.cancelReboot.4"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject restartServer(boolean esegui, int minuti) {
        JSONObject r = new JSONObject();
        try {
            if (minuti < 0 || minuti > 60) minuti = 1;
            JSONObject so = operatingSystem();
            r.put("kernelInstallato", so.optString("kernelInstallato"))
             .put("kernelInEsecuzione", so.optString("uname"))
             .put("riavvioNecessario", so.optBoolean("riavvioNecessario"))
             .put("minuti", minuti);

            JSONObject avvio = autoStart();
            boolean rc = avvio.optBoolean("installato", false);
            boolean acceso = avvio.optBoolean("abilitato", false);
            r.put("rcAttivo", avvio.optBoolean("attivo", false));
            r.put("autoStart", avvio);
            if (!(rc && acceso)) {
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.restartServer.1"));
            }

            // Cosa si ferma: elencarlo prima e' meglio che scoprirlo dopo.
            JSONArray servizi = new JSONArray();
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                if (ok("service " + svc + " status", 20)) servizi.put(svc);
            }
            r.put("servizi", servizi);
            r.put("effetto", I18n.tr("server.um.restartServer.2", java.util.Map.of("length", String.valueOf(servizi.length()))));

            String pendente = sh("ps -axo command | grep '^shutdown ' | head -1", 20).trim();
            r.put("gaProgrammato", pendente);
            // Il manuale: "-f  Ignore the presence of the /var/run/noshutdown file". Se quel
            // file c'e', shutdown si rifiuta — ed e' meglio saperlo prima di premere.
            boolean noshutdown = ok("test -f /var/run/noshutdown", 10);
            r.put("noshutdown", noshutdown);
            String shPrev = percorsoComando("shutdown", "/sbin/shutdown", "/usr/sbin/shutdown");
            String dmPrev = percorsoComando("daemon", "/usr/sbin/daemon", "/sbin/daemon");
            r.put("percorsoShutdown", shPrev.isEmpty() ? I18n.tr("server.um.restartServer.3") : shPrev)
             .put("percorsoDaemon", dmPrev.isEmpty() ? I18n.tr("server.um.restartServer.3") : dmPrev);
            if (noshutdown)
                r.put("avvisoNoshutdown", I18n.tr("server.um.restartServer.4"));
            if (!esegui) return r.put("success", true).put("eseguito", false);

            String msg = "Restart requested by the mail panel";
            String shutdown = percorsoComando("shutdown", "/sbin/shutdown", "/usr/sbin/shutdown");
            String daemon = percorsoComando("daemon", "/usr/sbin/daemon", "/sbin/daemon");
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
            ok(daemon + " -f -o " + logR + " " + shutdown + " -r +" + minuti + " '" + msg + "'", 30);

            // "daemon" esce subito e con successo comunque: il suo codice di uscita non dice
            // niente su shutdown. L'unica prova e' che il processo shutdown ESISTA.
            ok("sleep 2", 15);
            String pidS = sh("pgrep -x shutdown 2>/dev/null | head -1", 20).trim();
            String usc = sh("cat " + logR + " 2>/dev/null", 20).trim();
            if (!pidS.matches("[0-9]{1,7}")) {
                boolean nosh = ok("test -f /var/run/noshutdown", 10);
                return r.put("success", false).put("eseguito", false)
                        .put("output", usc)
                        .put("error", I18n.tr("server.um.x.restartNotScheduled")
                            + (nosh ? "  " + I18n.tr("server.um.x.noshutdownCause")
                                    : "")
                            + "  " + (usc.isEmpty() ? I18n.tr("server.um.x.shutdownSilent")
                                             : I18n.tr("server.um.x.shutdownWrote", java.util.Map.of("u", String.valueOf(usc)))));
            }
            return r.put("success", true).put("eseguito", true).put("pid", pidS)
                    .put("output", usc)
                    .put("nota", minuti == 1
                        ? I18n.tr("server.um.x.restartIn.one")
                        : I18n.tr("server.um.x.restartIn.other", java.util.Map.of("n", String.valueOf(minuti))))
                    .put("annulla", I18n.tr("server.um.restartServer.6"));
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
     * La lista degli ranges Cloudflare compilata nel pannello e' ancora quella ufficiale?
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
        JSONObject r = new JSONObject().put("aggiornataIl", org.mail_panel.security.TrustedProxy.AGGIORNATA_IL);
        // Cio' che il pannello CREDE si mostra sempre, anche se la rete non risponde: e' una
        // conoscenza sua, non dipende da cloudflare.com. Una lista che decide di chi fidarsi e
        // che nessuno puo' leggere e' una regola segreta; e nel momento in cui il confronto
        // fallisce e' proprio quando serve poter guardare cosa c'e' scritto.
        r.put("listaV4", new JSONArray(org.mail_panel.security.TrustedProxy.cloudflareV4()));
        r.put("listaV6", new JSONArray(org.mail_panel.security.TrustedProxy.cloudflareV6()));
        r.put("listaLocali", new JSONArray(org.mail_panel.security.TrustedProxy.intervalliLocali()));
        try {
            java.util.List<String> v4 = scaricaIntervalli("https://www.cloudflare.com/ips-v4", true);
            java.util.List<String> v6 = scaricaIntervalli("https://www.cloudflare.com/ips-v6", false);

            // Una soglia minima, non il solo "non vuoto".
            //
            // Senza, una risposta parziale o una pagina di errore da cui si salvano due righe
            // darebbe una lista ufficiale corta. Nessun intervallo "mancante" — quindi niente
            // rosso — e invece una dozzina di "non piu' ufficiali": il pannello consiglierebbe
            // di TOGLIERE dalla lista di fiducia ranges che Cloudflare usa eccome. Un
            // consiglio sbagliato e' peggio di un verde sbagliato, perche' chi lo segue rompe
            // qualcosa di suo con le proprie mani.
            //
            // Cloudflare pubblica da anni almeno 15 ranges IPv4 e 7 IPv6. La soglia sta
            // sotto apposta: deve scattare su una risposta rotta, non su un aggiornamento
            // legittimo della lista.
            final int MIN_V4 = 10, MIN_V6 = 5;
            if (v4.size() < MIN_V4 || v6.size() < MIN_V6)
                return r.put("success", false).put("verificato", false)
                        .put("ufficialiV4", v4.size()).put("ufficialiV6", v6.size())
                        .put("error", I18n.tr("server.um.cloudflareRanges.1", java.util.Map.of("size", String.valueOf(v4.size()), "size2", String.valueOf(v6.size()), "mINIMO_V4", String.valueOf(MIN_V4), "mINIMO_V6", String.valueOf(MIN_V6))));

            java.util.List<String> miaV4 = org.mail_panel.security.TrustedProxy.cloudflareV4();
            java.util.List<String> miaV6 = org.mail_panel.security.TrustedProxy.cloudflareV6();

            // Mancanti = presenti da Cloudflare e NON nel pannello. Sono quelli che contano:
            // sono gli indirizzi da cui il pannello non riconoscerebbe il proxy.
            JSONArray mancanti = new JSONArray();
            for (String c : v4) if (!miaV4.contains(c)) mancanti.put(c);
            for (String c : v6) if (!miaV6.contains(c)) mancanti.put(c);

            // In piu' = nel pannello e non piu' ufficiali. Non fanno danno diretto, ma sono
            // fiducia concessa a indirizzi che Cloudflare non usa piu'.
            JSONArray inPiu = new JSONArray();
            for (String c : miaV4) if (!v4.contains(c)) inPiu.put(c);
            for (String c : miaV6) if (!v6.contains(c)) inPiu.put(c);

            r.put("success", true).put("verificato", true)
             .put("ufficialiV4", v4.size()).put("ufficialiV6", v6.size())
             .put("compilatiV4", miaV4.size()).put("compilatiV6", miaV6.size())
             .put("mancanti", mancanti).put("inPiu", inPiu)
             .put("allineata", mancanti.length() == 0 && inPiu.length() == 0);

            r.put("nota", mancanti.length() > 0
                ? I18n.tr("server.um.cloudflareRanges.2", java.util.Map.of("length", String.valueOf(mancanti.length())))
                : inPiu.length() > 0
                  ? I18n.tr("server.um.cloudflareRanges.3", java.util.Map.of("length", String.valueOf(inPiu.length())))
                  : I18n.tr("server.um.cloudflareRanges.4"));
            return r;
        } catch (Exception e) {
            return r.put("success", false).put("verificato", false)
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
    private static java.util.List<String> scaricaIntervalli(String url, boolean ipv4) {
        java.util.List<String> out = new java.util.ArrayList<>();
        try {
            var http = java.net.http.HttpClient.newBuilder()
                    .connectTimeout(java.time.Duration.ofSeconds(8)).build();
            var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(url))
                    .timeout(java.time.Duration.ofSeconds(15)).GET().build();
            var resp = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return out;
            for (String riga : resp.body().split("\n")) {
                String c = riga.trim();
                // Si accetta solo cio' che ha la forma di un CIDR: da una pagina di errore o da
                // una risposta inattesa non deve entrare niente in una lista di fiducia.
                if (c.isEmpty() || c.startsWith("#")) continue;
                // Due filtri, non uno. La forma deve valere per la riga INTERA — cosi' una riga
                // di HTML che contenga un CIDR non passa — e la riga dev'essere un CIDR vero
                // della famiglia giusta.
                if (!c.matches("[0-9a-fA-F:.]+/[0-9]{1,3}")) continue;
                boolean sembraV4 = c.indexOf(':') < 0;
                if (sembraV4 != ipv4) continue;
                if (!cidrValido(c, ipv4)) continue;
                out.add(c);
            }
        } catch (Exception ignora) { }
        return out;
    }

    /** Il CIDR e' scrivibile davvero: indirizzo letterale valido e prefisso nella scala giusta. */
    private static boolean cidrValido(String cidr, boolean ipv4) {
        try {
            int i = cidr.indexOf('/');
            int prefisso = Integer.parseInt(cidr.substring(i + 1));
            if (prefisso < 0 || prefisso > (ipv4 ? 32 : 128)) return false;
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
            r.put("so", operatingSystem());

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
            int daAggiornare = 0, piuRecenti = 0, fuoriCatalogo = 0, nonConfrontabili = 0;
            for (String riga : list.split("\n")) {
                String t = riga.trim();
                if (t.isEmpty()) continue;
                String[] campi = t.split("\\s+");
                String stato = campi.length > 1 ? campi[1] : "";
                switch (stato) {
                    case "<" -> daAggiornare++;
                    case ">" -> piuRecenti++;
                    case "?" -> fuoriCatalogo++;
                    case "!" -> nonConfrontabili++;
                    default -> { }
                }
            }
            r.put("daAggiornare", daAggiornare)
             .put("piuRecentiDelCatalogo", piuRecenti)
             .put("fuoriCatalogo", fuoriCatalogo)
             .put("nonConfrontabili", nonConfrontabili);

            // L'eta' del catalogo: senza, il numero qui sopra sembra piu' preciso di quanto sia.
            // E' la data di pubblicazione sul server (vedi PkgCatalog).
            JSONObject cat = PkgCatalog.leggi();
            r.put("catalogoGiorni", cat.optLong("giorni", -1)).put("catalogoData", cat.optString("data"))
             .put("catalogoNota", cat.optString("nota"));

            // Vulnerabilita' dal database locale: "pkg audit" senza -F non scarica.
            String audit = sh("pkg audit -q 2>/dev/null", 60);
            int vuln = 0;
            for (String riga : audit.split("\n")) if (!riga.trim().isEmpty()) vuln++;
            r.put("vulnerabili", vuln);
            r.put("vulnDbGiorni", giorniDa("/var/db/pkg/vuln.xml"));

            return r.put("success", true);
        } catch (Exception e) {
            return r.put("success", false).put("error", e.getMessage());
        }
    }

    /** Da quanti giorni non viene toccato un file. -1 se non c'e' o non si riesce a leggerlo. */
    private static long giorniDa(String percorso) {
        try {
            String m = sh("stat -f %m " + percorso + " 2>/dev/null", 15).trim();
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
            String percorso = ok("test -f /usr/local/etc/rc.d/mailpanel", 10)
                    ? "/usr/local/etc/rc.d/mailpanel"
                    : (ok("test -f /etc/rc.d/mailpanel", 10) ? "/etc/rc.d/mailpanel" : null);
            boolean installato = percorso != null;
            String abil = sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim();
            boolean abilitato = "YES".equalsIgnoreCase(abil) || "yes".equalsIgnoreCase(abil)
                    || "true".equalsIgnoreCase(abil) || "1".equals(abil);
            r.put("success", true)
             .put("installato", installato)
             .put("abilitato", abilitato)
             .put("attivo", installato && abilitato)
             .put("percorso", percorso == null ? "" : percorso)
             .put("valoreSysrc", abil);
            r.put("reason", installato && abilitato
                ? I18n.tr("server.um.autoStart.1")
                : !installato
                  ? I18n.tr("server.um.autoStart.2")
                  : I18n.tr("server.um.x.rcNotEnabled", java.util.Map.of("v", String.valueOf(abil.isEmpty() ? I18n.tr("server.um.x.notSet") : abil))));
            return r;
        } catch (Exception e) {
            // "Non ho potuto controllare" non e' "va bene": chi legge deve vederlo.
            return r.put("success", false).put("attivo", false)
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
     *  - Il verdict NON si legge dai codici di uscita: si rilegge "sysrc -n" e si ricontrolla
     *    il file. Un comando che "riesce" senza aver fatto la cosa e' il modo piu' comune di
     *    raccontarsi che e' andata bene.
     *
     * @param esegui false = anteprima, non tocca niente.
     */
    public static JSONObject removePanelRcScript(boolean esegui) {
        JSONObject r = new JSONObject();
        try {
            JSONObject prima = autoStart();
            r.put("prima", prima);
            String percorso = prima.optString("percorso", "");
            boolean installato = prima.optBoolean("installato", false);
            String valore = prima.optString("valoreSysrc", "").trim();
            boolean variabileEsiste = !valore.isEmpty();

            String copia = "/var/db/mailpanel/mailpanel.rc.removed";
            r.put("percorso", percorso).put("copia", copia)
             .put("installato", installato).put("variabileEsiste", variabileEsiste);

            // Chi sta togliendo l'avvio automatico del pannello deve sapere che i blocchi
            // restano: e' l'unico punto in cui la domanda si pone da se'.
            String avvisoBlocchi = avvisoBlocchiRimasti();
            if (!avvisoBlocchi.isEmpty()) r.put("locksStay", avvisoBlocchi);

            if (!installato && !variabileEsiste)
                return r.put("success", true).put("eseguito", false).put("nothingToDo", true)
                        .put("nota", unisci(I18n.tr("server.um.removePanelRcScript.1"), avvisoBlocchi));

            if (!esegui)
                return r.put("success", true).put("eseguito", false)
                        .put("nota", unisci(I18n.tr("server.um.x.rcRmPreview", java.util.Map.of("azioni", String.valueOf((variabileEsiste ? I18n.tr("server.um.x.rcRmVar") : "")
                                + (variabileEsiste && installato ? " " + I18n.tr("server.um.x.and") + " " : "")
                                + (installato ? I18n.tr("server.um.x.rcRmFile", java.util.Map.of("file", String.valueOf(percorso), "copia", String.valueOf(copia))) : "")))), avvisoBlocchi));

            ok("mkdir -p /var/db/mailpanel", 20);

            // 1. La copia PRIMA di tutto: se non riesce, non si prosegue.
            if (installato) {
                ok("cp -p " + percorso + " " + copia, 20);
                if (!ok("test -s " + copia, 10))
                    return r.put("success", false)
                            .put("error", I18n.tr("server.um.removePanelRcScript.2", java.util.Map.of("percorso", String.valueOf(percorso), "copia", String.valueOf(copia))));
                r.put("copiaFatta", true);
            }

            // 2. La variabile, solo se c'e' davvero.
            if (variabileEsiste) ok("sysrc -x mailpanel_enable", 30);

            // 3. Lo script.
            if (installato) ok("rm -f " + percorso, 20);

            // 4. Il verdict: si RILEGGE, non si deduce dai codici di uscita.
            JSONObject dopo = autoStart();
            r.put("dopo", dopo);
            boolean restaFile = dopo.optBoolean("installato", false);
            boolean restaVar = !dopo.optString("valoreSysrc", "").trim().isEmpty();
            if (restaFile || restaVar) {
                java.util.List<String> resta = new java.util.ArrayList<>();
                if (restaFile) resta.add(I18n.tr("server.um.removePanelRcScript.3", java.util.Map.of("percorso", String.valueOf(percorso))));
                if (restaVar) resta.add(I18n.tr("server.um.x.rcVarStill", java.util.Map.of("v", String.valueOf(dopo.optString("valoreSysrc", "")))));
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.x.rcRmIncomplete", java.util.Map.of("resta", String.valueOf(String.join("; ", resta)), "copia", String.valueOf(copia))));
            }

            return r.put("success", true).put("eseguito", true)
                    .put("nota", unisci(I18n.tr("server.um.removePanelRcScript.4", java.util.Map.of("copia", String.valueOf(copia))), avvisoBlocchi));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.um.removePanelRcScript.5", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        }
    }

    public static JSONObject panelRcScript(boolean esegui) {
        JSONObject r = new JSONObject();
        try {
            String dir = System.getProperty("user.dir", "");
            String jar = jarPath();
            String binJava = System.getProperty("java.home", "") + "/bin/java";
            if (jar.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.panelRcScript.1"));
            StringBuilder opz = new StringBuilder();
            for (String o : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
                if (o.startsWith("-agentlib") || o.startsWith("-javaagent") || o.startsWith("-Xdebug")) continue;
                opz.append(' ').append(o);
            }
            String percorso = "/usr/local/etc/rc.d/mailpanel";
            r.put("percorso", percorso).put("dir", dir).put("jar", jar).put("java", binJava);

            String testo =
                "#!/bin/sh\n"
              + "#\n"
              + "# PROVIDE: mailpanel\n"
              + "# REQUIRE: LOGIN\n"
              + "# KEYWORD: shutdown\n"
              + "#\n"
              + "# Generato dal pannello il giorno dell'installazione. Avvia il pannello in\n"
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
              + ": ${mailpanel_opts:=\"" + opz.toString().trim() + "\"}\n"
              + ": ${mailpanel_log:=\"" + LOG_PANNELLO + "\"}\n"
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
            r.put("testo", testo);

            boolean esiste = ok("test -f " + percorso, 10);
            String abilitato = sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim();
            r.put("esiste", esiste).put("abilitato", abilitato);
            if (!esegui) return r.put("success", true).put("eseguito", false);

            // Verifica la sintassi PRIMA di metterlo dove il sistema lo eseguira' all'avvio:
            // uno script rc.d rotto puo' fermare la sequenza di boot.
            String tmp = "/var/db/mailpanel/mailpanel.rc.test";
            ok("mkdir -p /var/db/mailpanel", 20);
            Files.writeString(Paths.get(tmp), testo);
            String sint = sh("sh -n " + tmp + " 2>&1", 30).trim();
            if (!sint.isEmpty()) {
                ok("rm -f " + tmp, 15);
                return r.put("success", false)
                        .put("error", I18n.tr("server.um.panelRcScript.3", java.util.Map.of("sint", String.valueOf(sint))));
            }
            if (esiste) ok("cp -p " + percorso + " /var/db/mailpanel/mailpanel.rc.precedente", 20);
            Files.writeString(Paths.get(percorso), testo);
            ok("chmod 755 " + percorso, 15);
            ok("rm -f " + tmp, 15);
            boolean sysrc = ok("sysrc mailpanel_enable=YES", 30);

            // La prova che conta: rc.subr lo carica senza errori?
            String prova = sh("service mailpanel rcvar 2>&1", 30).trim();
            boolean caricato = prova.contains("mailpanel_enable");
            return r.put("success", true).put("eseguito", true)
                    .put("abilitatoOra", sysrc ? sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim() : "?")
                    .put("caricato", caricato).put("rcvar", prova)
                    .put("nota", I18n.tr("server.um.panelRcScript.4"));
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
    static String direzioneAggiornamento(String attuale, String bersaglio) {
        Matcher a = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(attuale == null ? "" : attuale);
        Matcher b = Pattern.compile("^([0-9]+)\\.([0-9]+)").matcher(bersaglio == null ? "" : bersaglio);
        if (!a.find() || !b.find()) return "illeggibile";
        int a1 = Integer.parseInt(a.group(1)), a2 = Integer.parseInt(a.group(2));
        int b1 = Integer.parseInt(b.group(1)), b2 = Integer.parseInt(b.group(2));
        if (b1 < a1 || (b1 == a1 && b2 < a2)) return "indietro";
        if (b1 == a1 && b2 == a2) return "stessa";
        return b1 == a1 ? "minore" : "maggiore";
    }

    public static JSONObject targetVersions() {
        try {
            JSONObject so = operatingSystem();
            String serie = so.optString("serie");
            Matcher m = Pattern.compile("^([0-9]+)\\.([0-9]+)$").matcher(serie);
            if (!m.find())
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.targetVersions.1", java.util.Map.of("serie", String.valueOf(serie))));
            int magAtt = Integer.parseInt(m.group(1)), minAtt = Integer.parseInt(m.group(2));
            JSONArray fuori = new JSONArray();
            for (String[] e : FINE_SUPPORTO) {
                Matcher m2 = Pattern.compile("^([0-9]+)\\.([0-9]+)$").matcher(e[0]);
                if (!m2.find()) continue;
                int ma = Integer.parseInt(m2.group(1)), mi = Integer.parseInt(m2.group(2));
                if (ma != magAtt) continue;          // i salti maggiori non passano di qui
                if (mi <= minAtt) continue;          // se stessa o indietro: non e' un aggiornamento
                fuori.put(new JSONObject().put("versione", e[0])
                        .put("fineSupporto", e[1]).put("note", I18n.tr(e[2])));
            }
            return new JSONObject().put("success", true).put("attuale", serie)
                    .put("versioni", fuori)
                    .put("fonte", I18n.tr(SUPPORT_SOURCE))
                    .put("nota", fuori.length() == 0
                        ? I18n.tr("server.um.targetVersions.2", java.util.Map.of("serie", String.valueOf(serie)))
                        : I18n.tr("server.um.targetVersions.3", java.util.Map.of("magAtt", String.valueOf(magAtt), "p", String.valueOf((magAtt + 1)))));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject systemUpgradePreflight(String bersaglio) {
        JSONObject r = new JSONObject();
        JSONArray checks = new JSONArray();
        boolean blocca = false;
        try {
            if (bersaglio == null || !bersaglio.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
                return r.put("success", false).put("error", I18n.tr("server.um.systemUpgradePreflight.1"));
            String target = bersaglio + "-RELEASE";
            r.put("bersaglio", target);

            JSONObject so = operatingSystem();
            String userland = so.optString("userland"), uname = so.optString("uname");
            r.put("attuale", userland).put("uname", uname).put("arch", so.optString("arch"));

            if (!userland.contains("-RELEASE")) {
                aggiungiCheck(checks, "tipo", I18n.tr("server.um.systemUpgradePreflight.2"), "block",
                        I18n.tr("server.um.systemUpgradePreflight.3", java.util.Map.of("userland", String.valueOf(userland))));
                return r.put("success", true).put("checks", checks).put("blocked", true).put("canProceed", false);
            }
            aggiungiCheck(checks, "attuale", I18n.tr("server.um.x.currentVersion"), "ok",
                    I18n.tr("server.um.x.userlandKernel", java.util.Map.of("u", String.valueOf(userland), "k", String.valueOf(uname)))
                    + (so.optBoolean("riavvioNecessario")
                       ? I18n.tr("server.um.systemUpgradePreflight.4") : ""));
            if (so.optBoolean("riavvioNecessario")) {
                aggiungiCheck(checks, "riavvioPendente", I18n.tr("server.um.systemUpgradePreflight.5"), "block",
                        I18n.tr("server.um.systemUpgradePreflight.6"));
                blocca = true;
            }

            // Salto minore o maggiore? Cambia se i pacchetti vanno ricostruiti.
            String magAtt = userland.replaceAll("[^0-9.].*$", "").replaceAll("\\..*$", "");
            String magNew = bersaglio.replaceAll("\\..*$", "");
            boolean minore = magAtt.equals(magNew);

            // Direzione: la decide una funzione a parte, che si puo' mettere alla prova.
            String direzione = direzioneAggiornamento(so.optString("serie"), bersaglio);
            r.put("direzione", direzione);
            if ("indietro".equals(direzione) || "stessa".equals(direzione)) {
                aggiungiCheck(checks, "direzione", I18n.tr("server.um.systemUpgradePreflight.7"), "block",
                        "stessa".equals(direzione)
                        ? I18n.tr("server.um.systemUpgradePreflight.8", java.util.Map.of("bersaglio", String.valueOf(bersaglio)))
                        : I18n.tr("server.um.x.targetOlder", java.util.Map.of("bersaglio", String.valueOf(bersaglio), "serie", String.valueOf(so.optString("serie")))));
                return r.put("success", true).put("checks", checks)
                        .put("blocked", true).put("canProceed", false);
            }
            r.put("saltoMinore", minore);
            String abi = sh("pkg config abi 2>/dev/null", 20).trim();
            r.put("abi", abi);
            if (!minore) blocca = true;
            aggiungiCheck(checks, "abi", I18n.tr("server.um.systemUpgradePreflight.9"), minore ? "ok" : "block",
                    minore
                    ? I18n.tr("server.um.systemUpgradePreflight.10", java.util.Map.of("abi", String.valueOf(abi), "magAtt", String.valueOf(magAtt), "magNew", String.valueOf(magNew)))
                    : I18n.tr("server.um.systemUpgradePreflight.11", java.util.Map.of("magAtt", String.valueOf(magAtt), "magNew", String.valueOf(magNew))));

            // Fine supporto della versione di arrivo: passare a qualcosa che scade fra poco
            // non risolve niente.
            String eolNew = "", noteNew = "";
            for (String[] e : FINE_SUPPORTO) if (e[0].equals(bersaglio)) { eolNew = e[1]; noteNew = I18n.tr(e[2]); }
            r.put("fineSupportoBersaglio", eolNew);
            aggiungiCheck(checks, "eol", I18n.tr("server.um.systemUpgradePreflight.12"), eolNew.isEmpty() ? "attendi" : "ok",
                    eolNew.isEmpty()
                    ? I18n.tr("server.um.systemUpgradePreflight.13", java.util.Map.of("bersaglio", String.valueOf(bersaglio)))
                    : I18n.tr("server.um.x.supportedUntil", java.util.Map.of("target", String.valueOf(target), "eol", String.valueOf(eolNew), "note", String.valueOf(noteNew), "serie", String.valueOf(so.optString("serie")), "fine", String.valueOf(so.optString("fineSupporto")))));

            // Kernel personalizzato: l'Handbook avverte che non viene aggiornato.
            String kconf = sh("sysctl -n kern.conftxt 2>/dev/null | head -1", 20).trim();
            boolean generic = so.optString("arch").contains("GENERIC");
            aggiungiCheck(checks, "kernel", "Kernel", generic ? "ok" : "attendi",
                    generic
                    ? I18n.tr("server.um.systemUpgradePreflight.14")
                    : I18n.tr("server.um.x.notGeneric", java.util.Map.of("arch", String.valueOf(so.optString("arch")))));

            // Ambienti di avvio: e' la vera via di ritorno di un aggiornamento di base.
            boolean be = ok("bectl check", 30);
            r.put("bootEnvironment", be);
            if (be) {
                String list = sh("bectl list -H 2>/dev/null | awk '{print $1\" (\"$2\") \"$4}'", 30);
                r.put("beEsistenti", list);
                aggiungiCheck(checks, "be", I18n.tr("server.um.systemUpgradePreflight.15"), "ok",
                        I18n.tr("server.um.x.beSupported", java.util.Map.of("elenco", String.valueOf(list.replace("\n", " | ")))));
            } else {
                aggiungiCheck(checks, "be", I18n.tr("server.um.systemUpgradePreflight.15"), "attendi",
                        I18n.tr("server.um.systemUpgradePreflight.16"));
            }

            // Spazio: l'ambiente di avvio e' un clone, ma i file scaricati e le vecchie librerie
            // occupano comunque.
            long liberiMb = number(sh("df -m / | tail -1 | awk '{print $4}'", 30));
            r.put("liberiMb", liberiMb);
            aggiungiCheck(checks, "spazio", I18n.tr("server.um.x.spaceRoot"), liberiMb > 5000 ? "ok" : "block",
                    I18n.tr("server.um.x.mbFreeRoot", java.util.Map.of("n", String.valueOf(liberiMb))) + " " + (liberiMb > 5000
                        ? I18n.tr("server.um.systemUpgradePreflight.17")
                        : I18n.tr("server.um.systemUpgradePreflight.18")));
            if (liberiMb <= 5000) blocca = true;

            // Il pannello stesso: due riavvii, e lui non torna su da solo.
            // Attenzione a cosa si afferma. Il file c'e' e sysrc dice YES: sono fatti. Che il
            // pannello TORNI SU e' una previsione, e l'unica prova e' averlo avviato una volta
            // con "service mailpanel start". Dire "tornera' su da solo" perche' esiste un file
            // e' la stessa distanza fra "installato" e "funziona" su cui sbaglio di continuo.
            boolean rc = ok("test -f /usr/local/etc/rc.d/mailpanel -o -f /etc/rc.d/mailpanel", 10);
            String abil = sh("sysrc -n mailpanel_enable 2>/dev/null", 20).trim();
            boolean acceso = "YES".equalsIgnoreCase(abil) || "yes".equalsIgnoreCase(abil)
                    || "true".equalsIgnoreCase(abil) || "1".equals(abil);
            boolean provato = ok("test -f /var/run/mailpanel.pid", 10);
            r.put("rcPannello", rc).put("rcAbilitato", acceso).put("rcProvato", provato);
            aggiungiCheck(checks, "pannello", I18n.tr("server.um.systemUpgradePreflight.19"),
                    (rc && acceso && provato) ? "ok" : "attendi",
                    !rc
                    ? I18n.tr("server.um.systemUpgradePreflight.20")
                    : !acceso
                    ? I18n.tr("server.um.systemUpgradePreflight.21", java.util.Map.of("abil", String.valueOf(abil)))
                    : provato
                    ? I18n.tr("server.um.systemUpgradePreflight.22")
                    : I18n.tr("server.um.systemUpgradePreflight.23"));

            // I servizi che devono tornare su: si annotano ORA per poterli confrontare DOPO.
            JSONArray servizi = new JSONArray();
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                servizi.put(new JSONObject().put("nome", svc).put("attivo", ok("service " + svc + " status", 20)));
            }
            r.put("servizi", servizi);
            aggiungiCheck(checks, "servizi", I18n.tr("server.um.systemUpgradePreflight.24"), "ok",
                    I18n.tr("server.um.systemUpgradePreflight.25", java.util.Map.of("length", String.valueOf(servizi.length()))));

            // Patch di sicurezza arretrate: l'Handbook dice di applicarle PRIMA di aggiornare.
            String pl = uname.contains("-p") ? uname.replaceAll(".*-p", "p") : "p0 " + I18n.tr("server.um.x.noPatch");
            aggiungiCheck(checks, "patch", I18n.tr("server.um.systemUpgradePreflight.26"), "attendi",
                    I18n.tr("server.um.systemUpgradePreflight.27", java.util.Map.of("pl", String.valueOf(pl))));

            r.put("success", true).put("checks", checks)
             .put("blocked", blocca).put("canProceed", !blocca);
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject startSystemPreparation(String bersaglio) {
        if (bersaglio == null || !bersaglio.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.systemUpgradePreflight.1"));
        String id = "sys-" + System.currentTimeMillis();
        Job j = new Job(id, "sistema");
        JOBS.put(id, j);
        final String b = bersaglio;
        Thread t = lavoroInLingua(() -> runPreparazioneSistema(j, b), "sistema-prep");
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
    private static void runPreparazioneSistema(Job job, String bersaglio) {
        job.status = "running";
        final int TOT = 4;
        try {
            job.avanza(1, TOT);
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.1", java.util.Map.of("bersaglio", String.valueOf(bersaglio))));
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.1", java.util.Map.of("tOT", String.valueOf(TOT))));
            JSONObject pf = systemUpgradePreflight(bersaglio);
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMigrazione84.3");
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if ("block".equals(c.optString("level")))
                        job.scrivi("  [" + I18n.tr("server.um.x.blockTag") + "] " + c.optString("label") + ": " + c.optString("detail"));
                }
                job.scrivi(I18n.tr("server.um.runMigrazione84.4"));
                return;
            }
            job.scrivi("  " + pf.optString("attuale") + " -> " + pf.optString("bersaglio")
                    + "   " + (pf.optBoolean("saltoMinore") ? I18n.tr("server.um.x.jumpMinor")
                                                          : I18n.tr("server.um.x.jumpMajor")));

            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("invalid date");
            String bk = "/var/db/mailpanel/system/" + ts;
            if (!ok("mkdir -p " + bk, 30)) throw new IllegalStateException("cannot create " + bk);

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.2", java.util.Map.of("tOT", String.valueOf(TOT))));
            if (!ok("tar -cf " + bk + "/etc.tar -C /etc . 2>/dev/null", 600))
                throw new IllegalStateException("copy of /etc failed");
            long voci = number(sh("tar -tf " + bk + "/etc.tar 2>/dev/null | wc -l", 120));
            if (voci < 50) throw new IllegalStateException("the copy of /etc has only " + voci
                    + " entries: not credible, I stop");
            job.scrivi("    /etc -> " + bk + "/etc.tar " + I18n.tr("server.um.x.entries", java.util.Map.of("n", String.valueOf(voci))));
            sh("pkg query '%n %v' > " + bk + "/pacchetti.txt 2>/dev/null", 120);
            sh("freebsd-version -kru > " + bk + "/versione.txt 2>/dev/null", 30);
            StringBuilder el = new StringBuilder();
            JSONArray sv = pf.optJSONArray("servizi");
            for (int i = 0; sv != null && i < sv.length(); i++)
                el.append(sv.getJSONObject(i).getString("nome")).append(' ')
                  .append(sv.getJSONObject(i).getBoolean("attivo") ? "attivo" : "fermo").append('\n');
            Files.writeString(Paths.get(bk + "/servizi.txt"), el.toString());
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.3"));

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.4", java.util.Map.of("tOT", String.valueOf(TOT))));
            String nomeBe = "prima-di-" + bersaglio.replace(".", "") + "-" + ts;
            if (!pf.optBoolean("bootEnvironment", false)) {
                job.scrivi(I18n.tr("server.um.runPreparazioneSistema.5"));
                job.scrivi(I18n.tr("server.um.runPreparazioneSistema.6"));
            } else if (ok("bectl create " + nomeBe, 300)) {
                boolean c1 = ok("bectl list -H 2>/dev/null | grep -q '^" + nomeBe + "'", 30);
                job.scrivi("    " + (c1 ? I18n.tr("server.um.x.beCreatedOk", java.util.Map.of("be", String.valueOf(nomeBe))) : I18n.tr("server.um.x.beCreatedMissing", java.util.Map.of("be", String.valueOf(nomeBe)))));
                if (!c1) throw new IllegalStateException("the boot environment does not appear to have been created: I stop");
                job.scrivi(I18n.tr("server.um.runPreparazioneSistema.8", java.util.Map.of("nomeBe", String.valueOf(nomeBe))));
                job.scrivi("");
                for (String l : sh("bectl list 2>/dev/null", 60).split("\n")) job.scrivi("      " + l);
            } else throw new IllegalStateException("bectl create failed: without a way back I do not go on");

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.9", java.util.Map.of("tOT", String.valueOf(TOT))));
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.10"));
            String fetch = sh("freebsd-update --not-running-from-cron fetch 2>&1", 1800);
            for (String l : fetch.split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
            boolean nessuna = fetch.toLowerCase().contains("no updates needed")
                    || fetch.toLowerCase().contains("has no updates available");
            if (nessuna) {
                job.scrivi(I18n.tr("server.um.runPreparazioneSistema.11"));
            } else {
                StringBuilder cat = new StringBuilder();
                eseguiConLog(job, "freebsd-update install 2>&1", 1800, cat);
                // Il criterio e' quello dell'Handbook: kernel INSTALLATO contro kernel IN
                // ESECUZIONE. Cercare la parola "kernel" nell'output era una supposizione, e
                // il 31/08/2026 non ha visto un caso in cui il riavvio serviva davvero: il
                // pannello ha stampato "p13 / p0 / p13" e non ha detto niente. Avere il dato
                // e non trarne la conclusione e' come non averlo.
                JSONObject dopoJ = operatingSystem();
                job.scrivi("    " + I18n.tr("server.um.x.kernelInstalled", java.util.Map.of("k", String.valueOf(dopoJ.optString("kernelInstallato")))));
                job.scrivi("    " + I18n.tr("server.um.x.kernelRunning", java.util.Map.of("k", String.valueOf(dopoJ.optString("uname")))));
                job.scrivi("    userland:             " + dopoJ.optString("userland"));
                if (dopoJ.optBoolean("riavvioNecessario")) {
                    job.scrivi("");
                    job.scrivi(I18n.tr("server.um.runPreparazioneSistema.12"));
                    job.scrivi(I18n.tr("server.um.runPreparazioneSistema.13"));
                    job.scrivi(I18n.tr("server.um.runPreparazioneSistema.14"));
                    job.scrivi(I18n.tr("server.um.runPreparazioneSistema.15"));
                    job.scrivi(I18n.tr("server.um.runPreparazioneSistema.16"));
                } else {
                    job.scrivi(I18n.tr("server.um.runPreparazioneSistema.17"));
                }
            }

            job.status = "completed";
            job.scrivi("");
            job.scrivi("=== " + I18n.tr("server.um.x.prepDone") + " ===");
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.18", java.util.Map.of("bk", String.valueOf(bk), "nomeBe", String.valueOf(nomeBe))));
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.19"));
            job.scrivi(I18n.tr("server.um.runPreparazioneSistema.20"));
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.fine = System.currentTimeMillis();
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
    public static JSONObject systemUpgradeInstructions(String bersaglio) {
        try {
            if (bersaglio == null || !bersaglio.matches("[0-9]{1,2}\\.[0-9]{1,2}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.systemUpgradeInstructions.1"));
            JSONObject pf = systemUpgradePreflight(bersaglio);
            String be = sh("bectl list -H 2>/dev/null | grep '^prima-di-' | tail -1 | awk '{print $1}'", 30).trim();
            String avvio = startCommand(false);
            String dir = System.getProperty("user.dir", "/home/panel");
            boolean minore = pf.optBoolean("saltoMinore", true);

            // Le istruzioni devono sapere se il pannello torna su da solo, altrimenti dicono
            // il contrario della scheda accanto. Tre stati, non due: c'e' lo script, e' abilitato,
            // ed e' stato provato almeno una volta (il pidfile lo dimostra).
            boolean rcC = pf.optBoolean("rcPannello", false);
            boolean rcA = pf.optBoolean("rcAbilitato", false);
            boolean rcP = pf.optBoolean("rcProvato", false);
            boolean tornaSolo = rcC && rcA;

            JSONArray passi = new JSONArray();
            passi.put(new JSONObject().put("n", 1)
                .put("titolo", I18n.tr("server.um.systemUpgradeInstructions.3"))
                .put("cmd", "freebsd-update -r " + bersaglio + "-RELEASE upgrade")
                .put("nota", I18n.tr("server.um.systemUpgradeInstructions.4")));
            passi.put(new JSONObject().put("n", 2)
                .put("titolo", I18n.tr("server.um.systemUpgradeInstructions.5"))
                .put("cmd", "freebsd-update install")
                .put("nota", I18n.tr("server.um.systemUpgradeInstructions.6")));
            passi.put(new JSONObject().put("n", 3)
                .put("titolo", I18n.tr("server.um.x.restart"))
                .put("cmd", "shutdown -r now")
                .put("nota", tornaSolo
                    ? (rcP
                       ? I18n.tr("server.um.x.rcBackTested")
                       : I18n.tr("server.um.x.rcBackUntested", java.util.Map.of("dir", String.valueOf(dir), "avvio", String.valueOf(avvio))))
                    : I18n.tr("server.um.systemUpgradeInstructions.7")));
            passi.put(new JSONObject().put("n", 4)
                .put("titolo", I18n.tr("server.um.systemUpgradeInstructions.8"))
                .put("cmd", "freebsd-update install")
                .put("nota", I18n.tr("server.um.systemUpgradeInstructions.9")));
            if (minore) {
                passi.put(new JSONObject().put("n", 5)
                    .put("titolo", I18n.tr("server.um.systemUpgradeInstructions.10"))
                    .put("cmd", I18n.tr("server.um.systemUpgradeInstructions.11"))
                    .put("nota", I18n.tr("server.um.x.abiStays", java.util.Map.of("abi", String.valueOf(pf.optString("abi"))))));
            } else {
                passi.put(new JSONObject().put("n", 5)
                    .put("titolo", I18n.tr("server.um.x.reinstallAll"))
                    .put("cmd", "pkg-static upgrade -f")
                    .put("nota", I18n.tr("server.um.systemUpgradeInstructions.12")));
            }
            passi.put(new JSONObject().put("n", 6)
                .put("titolo", I18n.tr("server.um.x.lastFuCall"))
                .put("cmd", "freebsd-update install")
                .put("nota", I18n.tr("server.um.systemUpgradeInstructions.13")));
            passi.put(new JSONObject().put("n", 7)
                .put("titolo", I18n.tr("server.um.systemUpgradeInstructions.14"))
                .put("cmd", "shutdown -r now")
                .put("nota", I18n.tr("server.um.systemUpgradeInstructions.15", java.util.Map.of("bersaglio", String.valueOf(bersaglio)))));
            passi.put(new JSONObject().put("n", 8)
                .put("titolo", tornaSolo ? I18n.tr("server.um.x.checkTitle") : I18n.tr("server.um.systemUpgradeInstructions.16"))
                .put("cmd", tornaSolo ? I18n.tr("server.um.systemUpgradeInstructions.17") : "cd " + dir + " && " + avvio)
                .put("nota", tornaSolo
                    ? I18n.tr("server.um.systemUpgradeInstructions.18", java.util.Map.of("dir", String.valueOf(dir), "avvio", String.valueOf(avvio)))
                    : I18n.tr("server.um.systemUpgradeInstructions.19")));

            return new JSONObject().put("success", true).put("passi", passi)
                .put("bersaglio", bersaglio)
                .put("rcAttivo", tornaSolo).put("rcProvato", rcP)
                .put("ritorno", be.isEmpty()
                    ? I18n.tr("server.um.systemUpgradeInstructions.20")
                    : I18n.tr("server.um.systemUpgradeInstructions.21", java.util.Map.of("be", String.valueOf(be))))
                .put("fonte", I18n.tr("server.um.systemUpgradeInstructions.22"));
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
     * Nel dubbio si torna "ancora", cioe' si riesegue: rieseguire quando non serve costa un
     * comando e non fa danni, fermarsi troppo presto lascia il sistema a meta'.
     */
    static String cosaChiedeFreebsdUpdate(String output) {
        String u = output == null ? "" : output.toLowerCase();
        if (u.contains("please reboot")) return "riavvia";
        // Questa e' una richiesta DIVERSA dal "rieseguimi", e sta nello stesso messaggio:
        // "Completing this upgrade requires removing old shared object files. Please rebuild
        // all installed 3rd party software ... and then run 'freebsd-update install' again."
        // Il 31/08/2026 il pannello ha visto solo la seconda meta' e ha proseguito in silenzio,
        // mentre la prima meta' chiedeva di ricostruire i pacchetti. Due istruzioni in una
        // frase: leggerne una sola e' peggio che non leggerne nessuna.
        if (u.contains("rebuild all installed 3rd party software")
                || u.contains("removing old shared object files")) return "ancora-ricostruisci";
        if (u.contains("no updates are available to install")
                || u.contains("no updates needed")) return "finito";
        if (u.contains("run '/usr/sbin/freebsd-update install'")
                || u.contains("run 'freebsd-update")) return "ancora";
        return "ancora";
    }

    private static JSONObject leggiStatoSalto() {
        try {
            if (!ok("test -f " + VERSION_JUMP_STATE, 10)) return new JSONObject();
            return new JSONObject(Files.readString(Paths.get(VERSION_JUMP_STATE)));
        } catch (Exception e) { return new JSONObject(); }
    }

    private static void scriviStatoSalto(JSONObject st) {
        try {
            ok("mkdir -p /var/db/mailpanel/system", 20);
            Files.writeString(Paths.get(VERSION_JUMP_STATE), st.toString(2));
        } catch (Exception ignored) { }
    }

    /** Lo stato del salto, per la scheda: a che punto siamo e cosa serve adesso. */
    public static JSONObject versionJumpStatus() {
        JSONObject st = leggiStatoSalto();
        JSONObject so = operatingSystem();
        JSONObject r = new JSONObject()
                .put("success", true)
                .put("inCorso", st.has("fase"))
                .put("fase", st.optString("fase", ""))
                .put("bersaglio", st.optString("bersaglio", ""))
                .put("passi", st.optJSONArray("passi") == null ? new JSONArray() : st.getJSONArray("passi"))
                .put("kernelInstallato", so.optString("kernelInstallato"))
                .put("kernelInEsecuzione", so.optString("uname"))
                .put("userland", so.optString("userland"))
                .put("riavvioNecessario", so.optBoolean("riavvioNecessario"));
        // Se aspettavamo un riavvio e il kernel adesso combacia, il riavvio c'e' stato.
        if ("attende-riavvio".equals(st.optString("fase")) && !so.optBoolean("riavvioNecessario"))
            r.put("riavvioAvvenuto", true);
        return r;
    }

    public static JSONObject startResumeVersionJump(String bersaglio) {
        String id = "salto-" + System.currentTimeMillis();
        Job j = new Job(id, "salto");
        JOBS.put(id, j);
        final String b = bersaglio == null || bersaglio.isEmpty()
                ? leggiStatoSalto().optString("bersaglio", "") : bersaglio;
        Thread t = lavoroInLingua(() -> runProseguiSalto(j, b), "salto-release");
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
    private static void runProseguiSalto(Job job, String bersaglio) {
        job.status = "running";
        try {
            boolean ricostruzioneChiesta = false;
            JSONObject st = leggiStatoSalto();
            JSONArray passi = st.optJSONArray("passi") == null ? new JSONArray() : st.getJSONArray("passi");
            if (!bersaglio.isEmpty()) st.put("bersaglio", bersaglio);

            job.scrivi(I18n.tr("server.um.runProseguiSalto.1"));
            JSONObject prima = operatingSystem();
            job.scrivi(I18n.tr("server.um.x.kernelLine", java.util.Map.of("k", String.valueOf(prima.optString("kernelInstallato")), "u", String.valueOf(prima.optString("uname")), "l", String.valueOf(prima.optString("userland")))));
            job.scrivi("");

            if (prima.optBoolean("riavvioNecessario")) {
                job.scrivi(I18n.tr("server.um.runProseguiSalto.2"));
                job.scrivi(I18n.tr("server.um.runProseguiSalto.3"));
                st.put("fase", "attende-riavvio").put("passi", passi);
                scriviStatoSalto(st);
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runProseguiSalto.4");
                return;
            }

            for (int giro = 1; giro <= 6; giro++) {
                job.avanza(giro, 6);
                job.scrivi("--- freebsd-update install " + I18n.tr("server.um.x.round", java.util.Map.of("n", String.valueOf(giro))) + " ---");
                StringBuilder cat = new StringBuilder();
                int codice = eseguiConLog(job, "freebsd-update install 2>&1", 3600, cat);
                String chiede = cosaChiedeFreebsdUpdate(cat.toString());
                JSONObject dopo = operatingSystem();
                passi.put(new JSONObject().put("giro", giro).put("codice", codice)
                        .put("chiede", chiede).put("kernel", dopo.optString("kernelInstallato"))
                        .put("userland", dopo.optString("userland")));
                job.scrivi("");
                job.scrivi("    " + I18n.tr("server.um.x.fuAsks") + " " + (
                        "riavvia".equals(chiede) ? I18n.tr("server.um.x.fuAsksRestart")
                      : "finito".equals(chiede)  ? I18n.tr("server.um.x.fuAsksNothing")
                      : "ancora-ricostruisci".equals(chiede)
                        ? I18n.tr("server.um.runProseguiSalto.5")
                      : I18n.tr("server.um.runProseguiSalto.6")));
                if ("ancora-ricostruisci".equals(chiede)) {
                    ricostruzioneChiesta = true;
                    job.scrivi("");
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.7"));
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.8"));
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.9"));
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.10"));
                }
                job.scrivi("    " + I18n.tr("server.um.x.kernelNow", java.util.Map.of("k", String.valueOf(dopo.optString("kernelInstallato")), "u", String.valueOf(dopo.optString("uname")), "l", String.valueOf(dopo.optString("userland")))));

                if (codice != 0 && !"finito".equals(chiede)) {
                    st.put("fase", "errore").put("passi", passi);
                    scriviStatoSalto(st);
                    job.status = "error";
                    job.errorMessage = I18n.tr("server.um.runProseguiSalto.11", java.util.Map.of("codice", String.valueOf(codice)));
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.12", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                    return;
                }
                if ("riavvia".equals(chiede)) {
                    st.put("fase", "attende-riavvio").put("passi", passi);
                    scriviStatoSalto(st);
                    job.scrivi("");
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.13"));
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.14"));
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.15"));
                    job.status = "completed";
                    return;
                }
                if ("finito".equals(chiede)) {
                    st.put("fase", "finito").put("passi", passi);
                    scriviStatoSalto(st);
                    job.scrivi("");
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.16"));
                    if (dopo.optBoolean("riavvioNecessario")) {
                        job.scrivi(I18n.tr("server.um.runProseguiSalto.17"));
                        job.scrivi(I18n.tr("server.um.runProseguiSalto.18"));
                        st.put("fase", "attende-riavvio-finale");
                        scriviStatoSalto(st);
                    } else {
                        job.scrivi(I18n.tr("server.um.x.youAreOn", java.util.Map.of("v", String.valueOf(dopo.optString("userland")))));
                    }
                    // La domanda "vanno ricostruiti i pacchetti?" non si risponde con un'opinione
                    // sull'ABI: si chiede a pkg quali librerie ogni pacchetto pretende e si guarda
                    // se esistono. E' l'unica prova diretta.
                    if (ricostruzioneChiesta) {
                        job.scrivi("");
                        job.scrivi("--- " + I18n.tr("server.um.x.fuRebuildCheck") + " ---");
                        JSONObject lib = packagesWithMissingLibraries();
                        JSONArray rotti = lib.optJSONArray("pacchetti");
                        int quanti = rotti == null ? 0 : rotti.length();
                        if (quanti == 0) {
                            job.scrivi(I18n.tr("server.um.runProseguiSalto.19"));
                            job.scrivi(I18n.tr("server.um.runProseguiSalto.20"));
                            job.scrivi(I18n.tr("server.um.runProseguiSalto.21"));
                        } else {
                            job.scrivi(I18n.tr("server.um.runProseguiSalto.22", java.util.Map.of("quanti", String.valueOf(quanti))));
                            for (int i = 0; i < Math.min(quanti, 20); i++)
                                job.scrivi("      " + rotti.getJSONObject(i).optString("nome")
                                        + "  ->  " + rotti.getJSONObject(i).optString("mancanti"));
                            job.scrivi(I18n.tr("server.um.runProseguiSalto.23"));
                            job.scrivi(I18n.tr("server.um.runProseguiSalto.24"));
                        }
                        st.put("ricostruzione", quanti == 0 ? I18n.tr("server.um.runProseguiSalto.25") : I18n.tr("server.um.x.neededN", java.util.Map.of("n", String.valueOf(quanti))));
                    }
                    job.scrivi(I18n.tr("server.um.runProseguiSalto.26"));
                    job.status = "completed";
                    return;
                }
            }
            st.put("fase", "troppi-giri").put("passi", passi);
            scriviStatoSalto(st);
            job.status = "error";
            job.errorMessage = I18n.tr("server.um.runProseguiSalto.27");
            job.scrivi(I18n.tr("server.um.startSystemUpdateSearch.3", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.fine = System.currentTimeMillis();
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
            JSONArray fuori = new JSONArray();
            for (String riga : sh("bectl list -H 2>/dev/null", 60).split("\n")) {
                String[] c = riga.split("\t");
                if (c.length < 5) continue;
                String nome = c[0].trim(), attivo = c[1].trim(), spazio = c[3].trim(), creato = c[4].trim();
                boolean inUso = attivo.contains("N");
                boolean alRiavvio = attivo.contains("R");

                // Chi l'ha creato si capisce dal nome: il pannello usa "prima-di-", e
                // freebsd-update usa <versione>_<data>. Saperlo cambia cosa significa tenerlo.
                String origine, spiega;
                if (nome.startsWith("prima-di-")) {
                    origine = I18n.tr("server.um.bootEnvironments.2");
                    spiega = I18n.tr("server.um.bootEnvironments.3");
                } else if (nome.matches("^[0-9]+\\.[0-9].*_[0-9]{4}-[0-9]{2}-[0-9]{2}.*")) {
                    origine = I18n.tr("server.um.bootEnvironments.4");
                    spiega = I18n.tr("server.um.bootEnvironments.5");
                } else if ("default".equals(nome)) {
                    origine = I18n.tr("server.um.bootEnvironments.6");
                    spiega = I18n.tr("server.um.bootEnvironments.7");
                } else {
                    origine = I18n.tr("server.um.bootEnvironments.8");
                    spiega = I18n.tr("server.um.bootEnvironments.9");
                }

                fuori.put(new JSONObject()
                        .put("nome", nome).put("spazio", spazio).put("creato", creato)
                        .put("inUso", inUso).put("alRiavvio", alRiavvio).put("sigla", attivo)
                        .put("origine", origine).put("explanation", spiega)
                        .put("stato", inUso && alRiavvio ? I18n.tr("server.um.bootEnvironments.10")
                                    : inUso ? I18n.tr("server.um.bootEnvironments.11")
                                    : alRiavvio ? I18n.tr("server.um.bootEnvironments.12")
                                    : I18n.tr("server.um.bootEnvironments.13"))
                        .put("eliminabile", !inUso && !alRiavvio)
                        .put("perche", inUso || alRiavvio
                                ? I18n.tr("server.um.bootEnvironments.14")
                                : I18n.tr("server.um.bootEnvironments.15")));
            }
            return r.put("success", true).put("ambienti", fuori)
                    .put("cosaSono", I18n.tr("server.um.bootEnvironments.16"))
                    .put("comeTornare", I18n.tr("server.um.bootEnvironments.17"))
                    .put("quandoEliminare", I18n.tr("server.um.bootEnvironments.18"));
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
    public static JSONObject deleteBootEnvironment(String nome) {
        try {
            if (nome == null || !nome.matches("[A-Za-z0-9._:-]{1,128}"))
                return new JSONObject().put("success", false).put("error", I18n.tr("server.um.deleteBootEnvironment.1"));
            JSONObject el = bootEnvironments();
            if (!el.optBoolean("success")) return el;
            JSONArray amb = el.getJSONArray("ambienti");
            JSONObject trovato = null;
            for (int i = 0; i < amb.length(); i++)
                if (nome.equals(amb.getJSONObject(i).getString("nome"))) trovato = amb.getJSONObject(i);
            if (trovato == null)
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.deleteBootEnvironment.2", java.util.Map.of("nome", String.valueOf(nome))));
            if (!trovato.getBoolean("eliminabile"))
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.um.x.beNoDelete", java.util.Map.of("nome", String.valueOf(nome), "stato", String.valueOf(trovato.getString("stato")), "perche", String.valueOf(trovato.getString("perche")))));

            String output = sh("bectl destroy -F " + nome + " 2>&1", 300).trim();
            // La prova e' che non compaia piu' nella lista, non che il comando sia uscito con zero.
            boolean via = !ok("bectl list -H 2>/dev/null | cut -f1 | grep -qx '" + nome + "'", 30);
            return new JSONObject().put("success", via).put("nome", nome)
                    .put("spazio", trovato.getString("spazio"))
                    .put("output", output)
                    .put("nota", via
                        ? I18n.tr("server.um.x.beDeleted", java.util.Map.of("nome", String.valueOf(nome), "spazio", String.valueOf(trovato.getString("spazio"))))
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
            r.put("inventario", dir);

            JSONObject so = operatingSystem();
            String prima = sh("cat " + dir + "/versione.txt 2>/dev/null | tr '\n' ' '", 30).trim();
            aggiungiCheck(checks, "ver", I18n.tr("server.um.x.version"), "ok",
                    I18n.tr("server.um.x.versionBeforeNow", java.util.Map.of("prima", String.valueOf(prima), "k", String.valueOf(so.optString("kernelInstallato")), "l", String.valueOf(so.optString("userland")))));
            if (so.optBoolean("riavvioNecessario")) {
                aggiungiCheck(checks, "riavvio", I18n.tr("server.um.x.restartTitle"), "attendi",
                        I18n.tr("server.um.x.restartMissing", java.util.Map.of("k", String.valueOf(so.optString("kernelInstallato")), "u", String.valueOf(so.optString("uname")))));
            } else {
                aggiungiCheck(checks, "riavvio", I18n.tr("server.um.x.restartTitle"), "ok",
                        I18n.tr("server.um.verifyAfterUpdate.2"));
            }

            // Servizi: quelli che erano attivi prima devono esserlo adesso.
            java.util.List<String> spenti = new ArrayList<>(), assenti = new ArrayList<>();
            int controllati = 0;
            for (String riga : sh("cat " + dir + "/servizi.txt 2>/dev/null", 30).split("\n")) {
                String[] c = riga.trim().split("\\s+");
                if (c.length != 2 || !"attivo".equals(c[1])) continue;
                controllati++;
                if (!ok("test -f /usr/local/etc/rc.d/" + c[0] + " -o -f /etc/rc.d/" + c[0], 10)) { assenti.add(c[0]); continue; }
                if (!ok("service " + c[0] + " status", 20)) spenti.add(c[0]);
            }
            aggiungiCheck(checks, "servizi", I18n.tr("server.um.verifyAfterUpdate.3"),
                    (spenti.isEmpty() && assenti.isEmpty()) ? "ok" : "block",
                    (spenti.isEmpty() && assenti.isEmpty())
                    ? I18n.tr("server.um.verifyAfterUpdate.4", java.util.Map.of("controllati", String.valueOf(controllati)))
                    : I18n.tr("server.um.x.svcMissing", java.util.Map.of("n", String.valueOf(controllati))) + " "
                      + (spenti.isEmpty() ? "" : I18n.tr("server.um.x.svcOff", java.util.Map.of("elenco", String.valueOf(String.join(", ", spenti)))) + "  ")
                      + (assenti.isEmpty() ? "" : I18n.tr("server.um.x.svcGone", java.util.Map.of("elenco", String.valueOf(String.join(", ", assenti))))));

            // Pacchetti: nessuno deve essere sparito.
            java.util.Map<String, String> ora = new java.util.HashMap<>();
            for (String riga : sh("pkg query '%n %v' 2>/dev/null", 120).split("\n")) {
                String[] c = riga.trim().split("\\s+");
                if (c.length == 2) ora.put(c[0], c[1]);
            }
            java.util.List<String> mancanti = new ArrayList<>(), diversi = new ArrayList<>();
            int totPrima = 0;
            for (String riga : sh("cat " + dir + "/pacchetti.txt 2>/dev/null", 60).split("\n")) {
                String[] c = riga.trim().split("\\s+");
                if (c.length != 2) continue;
                totPrima++;
                String v = ora.get(c[0]);
                if (v == null) mancanti.add(c[0]);
                else if (!v.equals(c[1])) diversi.add(c[0] + " " + c[1] + " -> " + v);
            }
            aggiungiCheck(checks, "pkg", I18n.tr("server.um.x.packages"), mancanti.isEmpty() ? "ok" : "block",
                    mancanti.isEmpty()
                    ? I18n.tr("server.um.x.pkgsNoneGone", java.util.Map.of("prima", String.valueOf(totPrima), "ora", String.valueOf(ora.size())))
                      + (diversi.isEmpty() ? "" : ". " + I18n.tr("server.um.x.pkgsChanged", java.util.Map.of("elenco", String.valueOf(String.join(", ", diversi)))))
                    : I18n.tr("server.um.x.pkgsGone", java.util.Map.of("n", String.valueOf(mancanti.size()), "elenco", String.valueOf(String.join(", ", mancanti)))));

            // Protezione: dopo un'operazione di questa portata va riconfermata.
            JSONObject st = packagesStatus();
            int inst = st.optInt("installedCount"), lock = st.optInt("lockedCount");
            aggiungiCheck(checks, "lock", I18n.tr("server.um.packagePreflight.25"), inst == lock ? "ok" : "attendi",
                    I18n.tr("server.um.x.lockOfInst", java.util.Map.of("lock", String.valueOf(lock), "inst", String.valueOf(inst)))
                    + (inst == lock ? "" : ": " + I18n.tr("server.um.x.someUnlocked")));

            // Gli ambienti di avvio: quello vecchio va tenuto finche' non sei sicuro.
            JSONObject be = bootEnvironments();
            if (be.optBoolean("success")) {
                r.put("ambienti", be);
                JSONArray el = be.getJSONArray("ambienti");
                int liberi = 0;
                for (int i = 0; i < el.length(); i++) if (el.getJSONObject(i).getBoolean("eliminabile")) liberi++;
                aggiungiCheck(checks, "be", I18n.tr("server.um.verifyAfterUpdate.5"), "ok",
                        I18n.tr("server.um.verifyAfterUpdate.6", java.util.Map.of("length", String.valueOf(el.length()), "liberi", String.valueOf(liberi))));
            }

            boolean guasto = false;
            for (int i = 0; i < checks.length(); i++)
                if ("block".equals(checks.getJSONObject(i).getString("level"))) guasto = true;
            return r.put("success", true).put("checks", checks).put("tuttoBene", !guasto);
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

            JSONObject ramo = branchRepositories();
            JSONObject so = operatingSystem();
            t.append("\n--- ").append(I18n.tr("server.um.x.repOs")).append(" ---\n");
            t.append(I18n.tr("server.um.x.repKernel", java.util.Map.of("k", String.valueOf(so.optString("kernelInstallato")), "u", String.valueOf(so.optString("uname"))))).append('\n');
            t.append(I18n.tr("server.um.x.repUserland", java.util.Map.of("u", String.valueOf(so.optString("userland")), "a", String.valueOf(so.optString("arch"))))).append('\n');
            if (so.optBoolean("riavvioNecessario"))
                t.append(I18n.tr("server.um.x.repRestartNeeded")).append('\n');
            if (!so.optString("fineSupporto").isEmpty())
                t.append(I18n.tr("server.um.x.repEol", java.util.Map.of("serie", String.valueOf(so.optString("serie")), "fine", String.valueOf(so.optString("fineSupporto")), "note", String.valueOf(so.optString("noteSupporto"))))).append('\n');
            else
                t.append(I18n.tr("server.um.x.repEolUnknown")).append('\n');
            t.append(I18n.tr("server.um.x.repSource", java.util.Map.of("f", String.valueOf(so.optString("fonteSupporto"))))).append('\n');
            if (so.has("giaPronti"))
                t.append(I18n.tr("server.um.x.repFetched", java.util.Map.of("v", String.valueOf(so.optString("giaPronti"))))).append('\n');
            if (so.has("notaAggiornamenti"))
                t.append(so.optString("notaAggiornamenti")).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repBranch")).append(" ---\n");
            t.append(ramo.optString("branch")).append("   ").append(ramo.optString("url")).append('\n');
            t.append(ramo.optString("explanation")).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repDefaults")).append(" ---\n");
            JSONArray righe = defaultsConsistency().optJSONArray("righe");
            for (int i = 0; righe != null && i < righe.length(); i++) {
                JSONObject x = righe.getJSONObject(i);
                t.append(String.format(I18n.tr("server.um.systemReport.1"),
                        x.optString("componente"), x.optString("predefinito"),
                        x.optString("installato"), x.optString("esito")));
                if (x.has("fuoriPredefinito"))
                    t.append("           ").append(I18n.tr("server.um.x.repOutside", java.util.Map.of("v", String.valueOf(x.getString("fuoriPredefinito"))))).append('\n');
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
            int diversi = 0;
            for (java.util.Map.Entry<String, String> e : inst.entrySet()) {
                String ruolo = ruoloDi(e.getKey());
                if (ruolo == null) continue;
                String disp = repo.getOrDefault(e.getKey(), "(assente)");
                boolean diff = !disp.equals(e.getValue()) && !"(assente)".equals(disp);
                if (diff) diversi++;
                t.append(String.format("%-28s %-22s %-22s %-9s %s%s%n",
                        e.getKey(), e.getValue(), disp,
                        bloccato(lock, e.getKey()) ? I18n.tr("server.um.x.yes") : "NO", ruolo, diff ? I18n.tr("server.um.systemReport.3") : ""));
            }
            t.append(I18n.tr("server.um.x.repNewer", java.util.Map.of("n", String.valueOf(diversi)))).append('\n');

            t.append("\n--- ").append(I18n.tr("server.um.x.repVulns")).append(" ---\n");
            String audit = sh("pkg audit -F 2>&1", 240);
            t.append(audit.isEmpty() ? I18n.tr("server.um.systemReport.4") : audit + "\n");
            t.append("\n").append(I18n.tr("server.um.x.repFixPerPkg")).append('\n');
            Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
            java.util.LinkedHashSet<String> visti = new java.util.LinkedHashSet<>();
            while (mv.find()) visti.add(mv.group(1));
            if (visti.isEmpty()) t.append("  ").append(I18n.tr("server.um.x.repNoPkg")).append('\n');
            for (String n : visti) {
                String cur = inst.getOrDefault(n, "?"), av = repo.getOrDefault(n, "(assente)");
                t.append(String.format(I18n.tr("server.um.systemReport.5"), n, cur, av,
                        "(assente)".equals(av) ? I18n.tr("server.um.x.repoUnknownPkg")
                        : av.equals(cur) ? I18n.tr("server.um.x.noFixSameVersion")
                        : I18n.tr("server.um.systemReport.6", java.util.Map.of("av", String.valueOf(av)))));
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repMissingLibs")).append(" ---\n");
            JSONObject lib = packagesWithMissingLibraries();
            JSONArray rotti = lib.optJSONArray("pacchetti");
            if (rotti == null || rotti.length() == 0) {
                t.append(I18n.tr("server.um.x.repLibsOk")).append('\n');
            } else {
                t.append(I18n.tr("server.um.x.repLibsLost", java.util.Map.of("n", String.valueOf(rotti.length())))).append('\n');
                for (int i = 0; i < rotti.length(); i++)
                    t.append("  ").append(rotti.getJSONObject(i).optString("nome"))
                     .append("  ->  ").append(rotti.getJSONObject(i).optString("mancanti")).append('\n');
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repBe")).append(" ---\n");
            JSONObject be2 = bootEnvironments();
            if (!be2.optBoolean("success")) t.append(I18n.tr("server.um.x.notAvailable")).append('\n');
            else {
                JSONArray aa = be2.getJSONArray("ambienti");
                for (int i = 0; i < aa.length(); i++) {
                    JSONObject x = aa.getJSONObject(i);
                    t.append(String.format("  %-40s %-12s %-8s %s%n", x.getString("nome"),
                            x.getBoolean("inUso") ? I18n.tr("server.um.x.inUseCaps") : x.getBoolean("alRiavvio") ? I18n.tr("server.um.systemReport.7") : I18n.tr("server.um.systemReport.8"),
                            x.getString("spazio"), x.getString("origine")));
                }
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repServices")).append(" ---\n");
            for (String[] cand : SERVICES) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                t.append(String.format("  %-18s %s%n", svc, ok("service " + svc + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runPassaggioPython.14")));
            }

            t.append("\n--- ").append(I18n.tr("server.um.x.repSpace")).append(" ---\n");
            t.append(sh("df -h / /var /usr 2>/dev/null | sort -u", 30)).append('\n');
            t.append("\n=== ").append(I18n.tr("server.um.x.repEnd")).append(" ===\n");
            return new JSONObject().put("success", true).put("testo", t.toString());
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage())
                    .put("parziale", t.toString());
        }
    }

    /**
     * Il ramo per la scheda dei predefiniti: lo legge PkgBranch, come la scheda "Ramo dei pacchetti".
     * Prima qui si prendeva il primo indirizzo di pkg.FreeBSD.org, che poteva essere quello dei
     * moduli del kernel, e un ramo misto non si vedeva.
     */
    public static JSONObject branchRepositories() {
        JSONObject st = PkgBranch.stato(PkgBranch.reale());
        if (!st.optBoolean("success"))
            return new JSONObject().put("success", true).put("branch", I18n.tr("server.um.branchRepositories.1")).put("url", "")
                    .put("explanation", st.optString("error")).put("dove", "");
        String url = "";
        JSONArray repo = st.getJSONArray("repository");
        for (int i = 0; i < repo.length(); i++) {
            JSONObject x = repo.getJSONObject(i);
            if (x.optBoolean("acceso") && "pacchetti".equals(x.optString("tipo"))) { url = x.optString("url"); break; }
        }
        return new JSONObject().put("success", true).put("branch", st.getString("branch")).put("url", url)
                .put("explanation", st.getString("explanation"))
                .put("dove", I18n.tr("server.um.branchRepositories.2"));
    }

    public static JSONObject branchStatus() { return PkgBranch.stato(PkgBranch.reale()); }

    public static JSONObject branchPreview(String verso) {
        if (!PkgBranch.RAMI.contains(verso)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.branchPreview.1"));
        return PkgBranch.anteprima(PkgBranch.reale(), verso);
    }

    /**
     * Il cambio di ramo, sul turno dei lavori sui pacchetti: riscrivere da dove pkg prende i
     * pacchetti mentre un altro lavoro li sta installando cambierebbe i pacchetti sotto i suoi piedi.
     */
    public static JSONObject startBranchChange(String verso, String fingerprint) {
        if (!PkgBranch.RAMI.contains(verso)) return new JSONObject().put("success", false).put("error", I18n.tr("server.um.branchPreview.1"));
        if (fingerprint == null || !fingerprint.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startBranchChange.1"));
        String id = "ramo-" + System.currentTimeMillis();
        Job j = new Job(id, "pkg_branch");
        return avviaSulTurno(id, j, I18n.tr("server.um.startBranchChange.2", java.util.Map.of("verso", String.valueOf(verso))), "pkg-branch", () -> {
            j.status = "running";
            try {
                JSONObject r = PkgBranch.cambia(PkgBranch.reale(), j::scrivi, verso, fingerprint);
                if (r.optBoolean("success")) {
                    j.esito = r.optString("messaggio");
                    j.status = "completed";
                } else {
                    j.errorMessage = r.optString("error");
                    j.status = "error";
                }
            } catch (RuntimeException e) {
                j.errorMessage = I18n.tr("server.um.startBranchChange.3", java.util.Map.of("message", String.valueOf(e.getMessage())));
                j.status = "error";
            } finally {
                j.fine = System.currentTimeMillis();
            }
        });
    }

    public static JSONObject defaultsConsistency() {
        JSONArray righe = new JSONArray();
        for (String[] d : PREDEFINITI) {
            String installato = sh(d[2], 60).trim().replace("\n", " ");
            String esito, fuori = "";
            if (installato.isEmpty()) {
                esito = "assente";
            } else if ("base".equals(d[1])) {
                // Il predefinito e' il sistema base: il port installato e' l'anomalia.
                esito = "port installato accanto al sistema base";
            } else {
                // Si confrontano TUTTI i valori installati, uno per uno. Cercare se il
                // predefinito compare "da qualche parte" nella stringa era sbagliato: con
                // py311 e py312 insieme trovava py312 e dichiarava tutto coerente, nascondendo
                // proprio la divergenza che la scheda esiste per mostrare. La presenza del
                // predefinito non dimostra l'assenza di altro.
                String cifreAttese = d[1].replaceAll("[^0-9]", "");
                java.util.List<String> nonConformi = new ArrayList<>();
                int conformi = 0;
                for (String tok : installato.split("\\s+")) {
                    if (tok.isBlank()) continue;
                    if (tok.replaceAll("[^0-9]", "").contains(cifreAttese)) conformi++;
                    else nonConformi.add(tok);
                }
                if (nonConformi.isEmpty() && conformi > 0) esito = "coerente";
                else if (conformi == 0) esito = "DIVERGE";
                else { esito = "MISTO"; fuori = String.join(", ", nonConformi); }
            }
            JSONObject riga = new JSONObject().put("componente", d[0]).put("predefinito", d[1])
                    .put("installato", installato).put("esito", esito).put("perche", I18n.tr(d[3]));
            if (!fuori.isEmpty()) riga.put("fuoriPredefinito", fuori);

            // "Port installato accanto al sistema base" descrive, non risponde. La domanda che
            // uno si fa leggendola e' una sola: lo posso togliere? Dipende da chi lo richiede,
            // e quello il pannello puo' chiederlo invece di lasciarlo indovinare.
            // Solo per le righe non coerenti, e solo per i valori che sono davvero nomi di
            // pacchetto: per Python la colonna contiene prefissi (py311), non pacchetti, e
            // interrogarli darebbe un vuoto che sembrerebbe "non lo richiede nessuno".
            if (!"coerente".equals(esito) && !"assente".equals(esito)) {
                JSONArray chi = new JSONArray();
                for (String tok : installato.split("\\s+")) {
                    if (tok.isBlank() || !isValidName(tok)) continue;
                    if (!ok("pkg info -e " + tok, 15)) continue;   // e' un prefisso, non un pacchetto
                    String dip = sh("pkg query %rn " + tok + " 2>/dev/null", 30).trim();
                    chi.put(new JSONObject().put("pacchetto", tok)
                            .put("richiestoDa", dip.isEmpty() ? new JSONArray()
                                    : new JSONArray(java.util.List.of(dip.split("\n")))));
                }
                if (chi.length() > 0) riga.put("dipendenti", chi);
            }
            righe.put(riga);
        }
        return new JSONObject().put("success", true).put("righe", righe)
                .put("branch", branchRepositories())
                .put("fonte", I18n.tr("server.um.defaultsConsistency.2"))
                .put("avvertenza", I18n.tr("server.um.defaultsConsistency.3"));
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
    public static JSONObject startForeignClientCleanup(String estraneo, String corretto) {
        if (!isValidName(estraneo) || !isValidName(corretto)
                || !estraneo.matches("mysql[0-9]+-client") || !corretto.matches("mysql[0-9]+-client")) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.um.startForeignClientCleanup.1"));
        }
        String id = "cleanclient-" + System.currentTimeMillis();
        Job j = new Job(id, "clean_client");
        return avviaSulTurno(id, j, I18n.tr("server.um.startForeignClientCleanup.2"), "clean-client", () -> {
            j.status = "running";
            boolean sbloccato = false;
            try {
                j.avanza(1, 5);
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.3", java.util.Map.of("estraneo", String.valueOf(estraneo), "corretto", String.valueOf(corretto))));
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.4", java.util.Map.of("estraneo", String.valueOf(estraneo))));
                String dip = sh("pkg query %rn " + estraneo + " 2>/dev/null", 30).trim();
                if (!dip.isEmpty()) {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.x.someoneDepends", java.util.Map.of("pkg", String.valueOf(estraneo), "dip", String.valueOf(dip.replace("\n", " "))));
                    j.scrivi("    " + j.errorMessage);
                    return;
                }
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.5", java.util.Map.of("estraneo", String.valueOf(estraneo))));
                String libPrima = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.scrivi("    " + I18n.tr("server.um.x.libOwner", java.util.Map.of("p", String.valueOf(libPrima.isEmpty() ? I18n.tr("server.um.x.nobodyP") : libPrima))));

                j.avanza(2, 5);
                j.scrivi("");
                j.scrivi("[2/5] " + I18n.tr("server.um.x.removingPkg", java.util.Map.of("pkg", String.valueOf(estraneo))));
                for (String l : sh("pkg delete -y " + estraneo + " 2>&1", 300).split("\n")) {
                    if (!l.trim().isEmpty()) j.scrivi("    " + l);
                }

                j.avanza(3, 5);
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.6", java.util.Map.of("corretto", String.valueOf(corretto))));
                if (bloccato(sh("pkg lock -l 2>/dev/null"), corretto)) {
                    // Prima l'elenco su disco, poi lo sblocco: se l'elenco non si scrive, non si sblocca.
                    String errStato = PackageQueue.scriviStato(java.util.List.of(corretto));
                    if (errStato != null)
                        throw new IllegalStateException("I could not save the list for the restore, so I do not unlock " + corretto + ": " + errStato);
                    // Da qui il finally riprotegge e chiude l'elenco, anche se lo sblocco fallisse a meta'.
                    sbloccato = true;
                    if (!ok("pkg unlock -y " + corretto, 30)) throw new IllegalStateException("I could not unlock " + corretto);
                    j.scrivi("    " + I18n.tr("server.um.x.unlockedTemp"));
                }
                int code = eseguiConLog(j, "pkg install -f -y " + corretto + " 2>&1", 900);
                if (code != 0) throw new IllegalStateException("pkg install exited with code " + code);

                j.avanza(4, 5);
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.7"));
                String chk = sh("pkg check -s " + corretto + " 2>&1", 300);
                long difformi = 0;
                for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) difformi++;
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.8", java.util.Map.of("difformi", String.valueOf(difformi))));
                if (difformi > 0) {
                    for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) j.scrivi("      " + l.trim());
                }

                j.avanza(5, 5);
                j.scrivi("");
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.9"));
                String libDopo = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.scrivi("    " + I18n.tr("server.um.x.libOwner", java.util.Map.of("p", String.valueOf(libDopo.isEmpty() ? I18n.tr("server.um.x.nobodyMissing") : libDopo))));
                JSONArray rotti = packagesWithMissingLibraries().getJSONArray("packages");
                j.scrivi(I18n.tr("server.um.startForeignClientCleanup.10", java.util.Map.of("length", String.valueOf(rotti.length()))));
                String mailbox = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
                boolean postfixOk = true;
                if (mailbox.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                    String q = sh("postmap -q '" + mailbox + "' mysql:/usr/local/etc/postfix/mysql-virtual-mailboxes.cf 2>&1", 60);
                    String ql = q.toLowerCase();
                    postfixOk = !q.trim().isEmpty() && !ql.contains("error") && !ql.contains("fatal")
                            && !ql.contains("not found") && !ql.contains("dlopen") && !ql.startsWith("postmap:");
                    j.scrivi("    " + (postfixOk
                            ? I18n.tr("server.um.x.pfResolveYes", java.util.Map.of("casella", String.valueOf(mailbox), "r", String.valueOf(q.trim())))
                            : I18n.tr("server.um.x.pfResolveNo", java.util.Map.of("casella", String.valueOf(mailbox), "r", String.valueOf(q.trim())))));
                }
                if (difformi == 0 && rotti.length() == 0 && !libDopo.isEmpty() && postfixOk) {
                    j.status = "completed";
                    j.scrivi("");
                    j.scrivi(I18n.tr("server.um.startForeignClientCleanup.11"));
                } else {
                    j.status = "error";
                    j.errorMessage = I18n.tr("server.um.startForeignClientCleanup.12");
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = e.getMessage();
                j.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
            } finally {
                if (sbloccato) {
                    boolean r = ok("pkg info -e " + corretto, 15) && ok("pkg lock -y " + corretto, 30);
                    j.scrivi("");
                    j.scrivi(r ? I18n.tr("server.um.x.reprotectOk", java.util.Map.of("pkg", String.valueOf(corretto))) : I18n.tr("server.um.x.reprotectFail", java.util.Map.of("pkg", String.valueOf(corretto))));
                    if (r) pulisciStato();
                }
                j.fine = System.currentTimeMillis();
            }
        });
    }

    public static JSONObject startRelinking() {
        String id = "relink-" + System.currentTimeMillis();
        Job j = new Job(id, "relink");
        return avviaSulTurno(id, j, I18n.tr("server.um.startRelinking.1"), "relink", () -> runRicollegamento(j));
    }

    /**
     * Reinstalla dal repository i pacchetti rimasti senza la libreria che pretendono, cosi'
     * tornano collegati a quella presente, e rimette in servizio cio' che ne dipende.
     */
    private static void runRicollegamento(Job job) {
        job.status = "running";
        java.util.List<String> unlockedPackages = new ArrayList<>();
        try {
            job.avanza(1, 5);
            job.scrivi(I18n.tr("server.um.runRicollegamento.1"));
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runRicollegamento.2"));
            JSONObject d = packagesWithMissingLibraries();
            JSONArray rotti = d.getJSONArray("packages");
            if (rotti.length() == 0) {
                job.scrivi(I18n.tr("server.um.runRicollegamento.3"));
                job.status = "completed";
                return;
            }
            java.util.LinkedHashSet<String> nomi = new java.util.LinkedHashSet<>();
            for (int i = 0; i < rotti.length(); i++) {
                JSONObject o = rotti.getJSONObject(i);
                job.scrivi("    " + I18n.tr("server.um.x.requiresMissing", java.util.Map.of("name", String.valueOf(o.getString("name")), "lib", String.valueOf(o.getString("lib")))));
                nomi.add(o.getString("name"));
            }

            job.avanza(2, 5);
            job.scrivi("");
            job.scrivi("[2/5] " + I18n.tr("server.um.x.tempUnlock"));
            String lock = sh("pkg lock -l 2>/dev/null");
            java.util.List<String> daSbloccare = new ArrayList<>();
            for (String n : nomi) if (bloccato(lock, n)) daSbloccare.add(n);
            if (!daSbloccare.isEmpty()) {
                // Prima l'elenco su disco, poi lo sblocco: se l'elenco non si scrive, non si sblocca.
                String errStato = PackageQueue.scriviStato(daSbloccare);
                if (errStato != null)
                    throw new IllegalStateException("I could not save the list for the restore, so I did not unlock anything: " + errStato);
                // Da riproteggere tutti, anche uno sblocco fallito: cosi' l'elenco su disco si chiude.
                unlockedPackages.addAll(daSbloccare);
                for (String n : daSbloccare)
                    job.scrivi("    " + n + ": " + (ok("pkg unlock -y " + n, 30) ? I18n.tr("server.um.x.unlocked") : I18n.tr("server.um.runRicollegamento.4")));
            } else job.scrivi(I18n.tr("server.um.runRicollegamento.5"));

            job.avanza(3, 5);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runRicollegamento.6"));
            StringBuilder el = new StringBuilder();
            for (String n : nomi) el.append(' ').append(n);
            // PRIMA una simulazione: se pkg segnala hasConflicts di file, ci si ferma.
            // "-f" serve a forzare la REINSTALLAZIONE, ma forza anche il passare sopra ai
            // hasConflicts — e sono due cose diverse. Averle confuse ha fatto sovrascrivere i
            // file del client MySQL 8.4 con quelli di un altro pacchetto.
            String simulazione = sh("pkg install -f -n" + el + " 2>&1", 600);
            if (simulazione.toLowerCase().contains("conflicts with")) {
                job.scrivi(I18n.tr("server.um.runRicollegamento.7"));
                for (String l : simulazione.split("\n")) {
                    if (l.toLowerCase().contains("conflict")) job.scrivi("      " + l.trim());
                }
                throw new IllegalStateException("the operation would overwrite files of another package: "
                        + "which package must stay has to be decided by hand, not forced.");
            }
            int code = eseguiConLog(job, "pkg install -f -y" + el + " 2>&1", 1800);
            if (code != 0) throw new IllegalStateException("pkg install exited with code " + code);

            job.avanza(4, 5);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runRicollegamento.8"));
            java.util.LinkedHashSet<String> servizi = new java.util.LinkedHashSet<>();
            for (String n : nomi) servizi.addAll(serviziDaRiavviare(n));
            for (String logico : servizi) {
                String reale = nomeServizioReale(logico);
                if (reale == null) continue;
                String prova = provaConfigDi(reale);
                if (prova != null && !Shell.runShell(Duration.ofSeconds(60), prova + " 2>&1").success()) {
                    job.scrivi(I18n.tr("server.um.runRicollegamento.9", java.util.Map.of("reale", String.valueOf(reale))));
                    continue;
                }
                ok("service " + reale + " restart", 120);
                job.scrivi("    " + reale + ": " + (ok("service " + reale + " status", 20) ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26")));
            }

            job.avanza(5, 5);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runRicollegamento.10"));
            JSONArray ancora = packagesWithMissingLibraries().getJSONArray("packages");
            if (ancora.length() == 0) {
                job.scrivi(I18n.tr("server.um.runRicollegamento.11"));
                job.status = "completed";
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runRicollegamento.12"));
            } else {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runRicollegamento.13", java.util.Map.of("length", String.valueOf(ancora.length())));
                for (int i = 0; i < ancora.length(); i++) {
                    JSONObject o = ancora.getJSONObject(i);
                    job.scrivi("    " + I18n.tr("server.um.x.stillBroken", java.util.Map.of("name", String.valueOf(o.getString("name")), "lib", String.valueOf(o.getString("lib")))));
                }
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            if (!unlockedPackages.isEmpty()) {
                job.scrivi("");
                job.scrivi("Riproteggo...");
                int n = 0;
                for (String p2 : unlockedPackages) if (ok("pkg info -e " + p2, 15) && ok("pkg lock -y " + p2, 30)) n++;
                job.scrivi("  " + n + "/" + unlockedPackages.size() + " riprotetti");
                if (n == unlockedPackages.size()) pulisciStato();
            }
            job.fine = System.currentTimeMillis();
        }
    }

    /** @param firmaApprovata l'fingerprint del piano mostrato dall'anteprima: si esegue quello o niente. */
    public static JSONObject startMaintenance(String firmaApprovata) {
        if (firmaApprovata == null || !firmaApprovata.matches("[0-9a-f]{16}"))
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.um.startMaintenance.1"));
        String id = "maint-" + System.currentTimeMillis();
        Job j = new Job(id, "maintenance");
        return avviaSulTurno(id, j, "manutenzione", "update-maintenance", () -> runMaintenanceJob(j, firmaApprovata));
    }

    public static JSONObject startUnlockedPackagesUpdate() {
        String id = "upd-" + System.currentTimeMillis();
        Job j = new Job(id, "update");
        return avviaSulTurno(id, j, I18n.tr("server.um.startUnlockedPackagesUpdate.1"), "update-plain", () -> runUpdateJob(j));
    }

    /** Aggiorna solo cio' che non e' protetto: e' pkg stesso a saltare i pacchetti lockedPackages. */
    private static void runUpdateJob(Job job) {
        job.status = "running";
        job.avanza(1, 2);
        job.scrivi(I18n.tr("server.um.runUpdateJob.1"));
        job.scrivi(I18n.tr("server.um.runUpdateJob.2"));
        job.scrivi("");
        try {
            int code = eseguiConLog(job, "pkg upgrade -y 2>&1", 3600);
            // 4 = EX_NEEDRESTART: pkg ha aggiornato se stesso. Le versioni recenti si rilanciano
            // da sole e fanno il resto; se questa si e' fermata li', la si rilancia una volta, uguale.
            if (code == 4) {
                job.scrivi(I18n.tr("server.um.runUpdateJob.3"));
                code = eseguiConLog(job, "pkg upgrade -y 2>&1", 3600);
            }
            job.avanza(2, 2);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runUpdateJob.4", java.util.Map.of("code", String.valueOf(code))));
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMigrazione84.31"));
            boolean caduto = false;
            for (Map.Entry<String, Boolean> e : statoServizi().entrySet()) {
                job.scrivi("  " + e.getKey() + ": " + (e.getValue() ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMigrazione84.26")));
                if (!e.getValue()) caduto = true;
            }
            job.status = (code == 0 && !caduto) ? "completed" : "error";
            if (code != 0) job.errorMessage = I18n.tr("server.um.runUpdateJob.5", java.util.Map.of("code", String.valueOf(code)));
            else if (caduto) job.errorMessage = I18n.tr("server.um.runUpdateJob.6");
        } catch (Exception e) {
            job.status = "error"; job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            job.fine = System.currentTimeMillis();
        }
    }

    /**
     * Sblocca -> aggiorna -> riprotegge ESATTAMENTE cio' che era protetto.
     * La riprotezione sta in un finally: deve avvenire anche se l'aggiornamento fallisce o
     * solleva un'eccezione. Lasciare i pacchetti unlockedPackages dopo un errore e' lo scenario
     * peggiore, perche' nessuno se ne accorge finche' un upgrade successivo non porta via
     * un servizio.
     */
    /**
     * Chi resta protetto durante la manutenzione completa, e perche'; e il piano esatto che ne
     * risulta. L'anteprima e il lavoro vero chiamano QUESTA funzione: se la decisione fosse
     * scritta due volte, prima o poi diventerebbe due decisioni diverse, e l'anteprima
     * mostrerebbe un piano che il lavoro non esegue.
     */
    private static JSONObject pianoDellaManutenzione(JSONArray lockedPackages) {
        Map<String, String> perche = new LinkedHashMap<>();
        for (int i = 0; i < lockedPackages.length(); i++) {
            JSONObject o = lockedPackages.getJSONObject(i);
            if (o.has("advisory") && "attendi".equals(o.getJSONObject("advisory").getString("level")))
                perche.put(o.getString("name"), I18n.tr("server.um.x.waitAdvisory"));
        }
        // La prova sul campo batte l'avvertenza generica: se la configurazione Dovecot
        // VIVA contiene costrutti che la versione nuova non accetta, quel pacchetto non
        // si sblocca, punto. Non e' un'ipotesi sulla versione, e' cio' che c'e' sul disco.
        JSONObject dc = dovecotCompatibility();
        if (dc.optBoolean("scanned", false) && !dc.optBoolean("compatible24", true)) {
            for (String n : sh("pkg query %n 2>/dev/null | grep -E '^dovecot' ", 20).split("\n")) {
                String t = n.trim();
                if (isValidName(t))
                    perche.put(t, I18n.tr("server.um.x.diskConfConstructs", java.util.Map.of("n", String.valueOf(dc.optJSONArray("issues").length()))));
            }
        }
        Set<String> protetti = insiemeProtetti();
        Set<String> daSbloccare = new TreeSet<>(protetti);
        daSbloccare.removeAll(perche.keySet());
        JSONObject piano = PackagePlan.pianoTotale(daSbloccare, protetti,
                b -> perche.containsKey(b.optString("nome"))
                        ? I18n.tr("server.um.x.staysProtected", java.util.Map.of("reason", String.valueOf(perche.get(b.optString("nome")))))
                        : motivoPerNonSbloccare(b));
        return new JSONObject().put("piano", piano).put("trattenuti", new JSONObject(perche))
                .put("protetti", new JSONArray(new ArrayList<>(protetti)));
    }

    private static void runMaintenanceJob(Job job, String firmaApprovata) {
        job.status = "running";
        List<String> daRibloccare = new ArrayList<>();
        JSONObject piano = null;
        boolean pianoNonRispettato = false;
        // Il file di stato si cancella solo se l'ha scritto QUESTA esecuzione. Prima si cancellava
        // quando "tutti i pacchetti da riproteggere" erano riprotetti — e con l'elenco vuoto di un
        // rifiuto a partire lo erano sempre: una manutenzione che si rifiutava perche' ne esisteva
        // una interrotta ne cancellava lo stato, cioe' l'elenco che l'avvio usa per riproteggere.
        boolean statoScritto = false;
        Set<String> protettiPrima = new TreeSet<>();
        Map<String, Boolean> serviziPrima = new LinkedHashMap<>();
        try {
            if (Files.exists(Paths.get(MAINTENANCE_STATE))) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMaintenanceJob.1", java.util.Map.of("sTATO_MANUTENZIONE", String.valueOf(MAINTENANCE_STATE)));
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.2", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.3"));
                job.fine = System.currentTimeMillis();
                return;
            }

            job.avanza(1, 4);
            job.scrivi(I18n.tr("server.um.runMaintenanceJob.4"));
            job.scrivi("");
            protettiPrima = insiemeProtetti();
            serviziPrima = statoServizi();
            job.scrivi(I18n.tr("server.um.x.initialState", java.util.Map.of("n", String.valueOf(protettiPrima.size()))));
            job.scrivi(I18n.tr("server.um.x.svcRunningList", java.util.Map.of("elenco", String.valueOf(serviziPrima.entrySet().stream()
                    .filter(Map.Entry::getValue).map(Map.Entry::getKey)
                    .collect(java.util.stream.Collectors.joining(", "))))));
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMaintenanceJob.5"));

            // --- Chi resta protetto, e perche': la stessa funzione dell'anteprima ---
            JSONObject decisione = pianoDellaManutenzione(lockedUpdates());
            piano = decisione.getJSONObject("piano");
            JSONObject perche = decisione.getJSONObject("trattenuti");
            for (String n : new TreeSet<>(perche.keySet()))
                job.scrivi("    " + n + "  -> " + I18n.tr("server.um.x.heldBack", java.util.Map.of("reason", String.valueOf(perche.getString(n)))));

            // Si esegue il piano che e' stato letto, o niente.
            if (!piano.optBoolean("measured")) {
                throw new IllegalStateException("I could not work out the exact plan: "
                        + piano.optString("error", piano.optString("errore", "?")));
            }
            if (!piano.optString("signature", "").equals(firmaApprovata)) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMaintenanceJob.6");
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.3", java.util.Map.of("firmaApprovata", String.valueOf(firmaApprovata), "firmaOra", String.valueOf(piano.optString("signature")))));
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.7"));
                job.fine = System.currentTimeMillis();
                return;
            }
            if (!piano.optBoolean("runnable")) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.x.planNotRunnable", java.util.Map.of("errori", String.valueOf(String.join(" | ", jsonArrayToList(piano.getJSONArray("erroriPkg"))))))
                        + (piano.getJSONArray("changes").isEmpty() ? " " + I18n.tr("server.um.x.nothingToUpdate") : "");
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.8", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                job.fine = System.currentTimeMillis();
                return;
            }
            daRibloccare.addAll(jsonArrayToList(piano.getJSONArray("unlockedPackages")));
            job.scrivi("  " + I18n.tr("server.um.x.exactPlan", java.util.Map.of("f", String.valueOf(piano.getString("signature")))));
            JSONArray cambiPiano = piano.getJSONArray("changes");
            for (int i = 0; i < cambiPiano.length(); i++) {
                JSONObject c = cambiPiano.getJSONObject(i);
                job.scrivi("    " + PackagePlan.typeName(c.getString("tipo")) + " " + c.getString("nome") + " " + c.getString("da")
                        + (c.getString("a").isEmpty() || c.getString("a").equals(c.getString("da")) ? "" : " -> " + c.getString("a")));
            }
            job.scrivi("  " + I18n.tr("server.um.x.willRelock", java.util.Map.of("n", String.valueOf(daRibloccare.size()))));
            if (perche.length() > 0) {
                job.scrivi("  " + I18n.tr("server.um.x.heldBackN", java.util.Map.of("n", String.valueOf(perche.length()))));
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.9"));
            }

            job.avanza(2, 4);
            job.scrivi("");
            job.scrivi("[2/4] " + I18n.tr("server.um.x.tempUnlock"));
            // L'elenco si salva PRIMA di sbloccare: se il pannello muore adesso, il ripristino
            // all'avvio sa cosa riproteggere. Se non si scrive, non si sblocca niente.
            if (!daRibloccare.isEmpty()) {
                String errStato = PackageQueue.scriviStato(daRibloccare);
                if (errStato != null) {
                    daRibloccare.clear();   // non si e' sbloccato niente: niente da riproteggere
                    job.status = "error";
                    job.errorMessage = I18n.tr("server.um.runMaintenanceJob.10", java.util.Map.of("errStato", String.valueOf(errStato)));
                    job.scrivi(I18n.tr("server.um.runMaintenanceJob.11", java.util.Map.of("errorMessage", String.valueOf(job.errorMessage))));
                    return;
                }
                statoScritto = true;
                job.scrivi(I18n.tr("server.um.runAggiornamentoGuidato.7", java.util.Map.of("sTATO_MANUTENZIONE", String.valueOf(MAINTENANCE_STATE))));
            }
            for (String n : daRibloccare) ok("pkg unlock -y " + n, 30);

            job.avanza(3, 4);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMaintenanceJob.12"));
            // -U: lo stesso catalogo su cui e' stato calcolato il piano.
            int code = eseguiConLog(job, "pkg upgrade -y -U 2>&1", 3600);
            // 4 = EX_NEEDRESTART: pkg ha aggiornato se stesso. Le versioni recenti si rilanciano
            // da sole e fanno il resto; se questa si e' fermata li', la si rilancia una volta, uguale.
            if (code == 4) {
                job.scrivi(I18n.tr("server.um.runUpdateJob.3"));
                code = eseguiConLog(job, "pkg upgrade -y -U 2>&1", 3600);
            }
            job.scrivi(I18n.tr("server.um.runUpdateJob.4", java.util.Map.of("code", String.valueOf(code))));
            if (code != 0) { job.status = "error"; job.errorMessage = I18n.tr("server.um.runUpdateJob.5", java.util.Map.of("code", String.valueOf(code))); }
            else job.status = "completed";

            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMaintenanceJob.13"));
            JSONArray verifica = PackagePlan.verificaEsito(piano);
            for (int i = 0; i < verifica.length(); i++) {
                JSONObject v = verifica.getJSONObject(i);
                job.scrivi("    " + (v.getBoolean("ok") ? "ok  " : "NO  ") + I18n.tr("server.um.x.expectedFound", java.util.Map.of("nome", String.valueOf(v.getString("nome")), "atteso", String.valueOf(v.getString("atteso")), "trovato", String.valueOf(v.getString("trovato")))));
                if (!v.getBoolean("ok")) pianoNonRispettato = true;
            }
            if (pianoNonRispettato) {
                job.status = "error";
                job.errorMessage = I18n.tr("server.um.runMaintenanceJob.14");
            }

            // Aggiornare un pacchetto non aggiorna il processo che lo usa: finche' non riparte gira
            // sui file vecchi, e la fix risulta installata senza essere in servizio. La
            // manutenzione completa non riavvia niente da sola (lo fa l'aggiornamento guidato, un
            // pacchetto alla volta), ma dice esattamente chi va riavviato.
            java.util.LinkedHashSet<String> daRiavviare = new java.util.LinkedHashSet<>();
            for (int i = 0; i < cambiPiano.length(); i++) {
                JSONObject c = cambiPiano.getJSONObject(i);
                if ("rimuove".equals(c.getString("tipo"))) continue;
                for (String logico : serviziDaRiavviare(c.getString("nome"))) {
                    String reale = nomeServizioReale(logico);
                    if (reale != null) daRiavviare.add(reale);
                }
            }
            if (!daRiavviare.isEmpty()) {
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.x.toRestart", java.util.Map.of("elenco", String.valueOf(String.join(", ", daRiavviare)))));
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.15"));
            }

        } catch (Exception e) {
            job.status = "error"; job.errorMessage = e.getMessage();
            job.scrivi(I18n.tr("server.um.startMtaStsActivation.1", java.util.Map.of("message", String.valueOf(e.getMessage()))));
        } finally {
            // La riprotezione avviene SEMPRE, qualunque cosa sia andata storta sopra.
            job.avanza(4, 4);
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMaintenanceJob.16"));
            int fatti = 0;
            for (String n : daRibloccare) {
                if (ok("pkg info -e " + n, 15) && ok("pkg lock -y " + n, 30)) fatti++;
                else job.scrivi(I18n.tr("server.um.runMaintenanceJob.17", java.util.Map.of("n", String.valueOf(n))));
            }
            job.scrivi("  " + I18n.tr("server.um.x.reprotectedCount", java.util.Map.of("n", String.valueOf(fatti), "tot", String.valueOf(daRibloccare.size()))));
            if (fatti == daRibloccare.size()) { if (statoScritto) pulisciStato(); }
            else {
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.18"));
                job.scrivi(I18n.tr("server.um.runPassaggioPython.21", java.util.Map.of("sTATO_MANUTENZIONE", String.valueOf(MAINTENANCE_STATE))));
            }

            // === Verifica del proprio operato: non basta aver eseguito i passi. ===
            job.scrivi("");
            job.scrivi(I18n.tr("server.um.runMaintenanceJob.19"));
            boolean allarme = false;

            Set<String> protettiDopo = insiemeProtetti();
            Set<String> mancanti = new TreeSet<>(protettiPrima);
            mancanti.removeAll(protettiDopo);
            if (mancanti.isEmpty()) {
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.20", java.util.Map.of("size", String.valueOf(protettiDopo.size()))));
            } else {
                allarme = true;
                job.scrivi("  " + I18n.tr("server.um.x.protLost", java.util.Map.of("elenco", String.valueOf(String.join(", ", mancanti)))));
            }

            Map<String, Boolean> serviziDopo = statoServizi();
            for (Map.Entry<String, Boolean> e : serviziPrima.entrySet()) {
                boolean prima = e.getValue(), dopo = serviziDopo.getOrDefault(e.getKey(), false);
                if (prima && !dopo) {
                    allarme = true;
                    job.scrivi(I18n.tr("server.um.runMaintenanceJob.21", java.util.Map.of("key", String.valueOf(e.getKey()))));
                } else {
                    job.scrivi("  " + e.getKey() + ": " + (dopo ? I18n.tr("server.um.x.running") : I18n.tr("server.um.runMaintenanceJob.22"))
                            + (prima ? "" : I18n.tr("server.um.runMaintenanceJob.23")));
                }
            }

            if (allarme) {
                job.status = "error";
                if (job.errorMessage == null || job.errorMessage.isEmpty()) {
                    job.errorMessage = I18n.tr("server.um.runMaintenanceJob.24");
                }
            } else if ("completed".equals(job.status)) {
                job.scrivi("");
                job.scrivi(I18n.tr("server.um.runMaintenanceJob.25"));
            }
            job.fine = System.currentTimeMillis();
        }
    }
}
