package org.mail_panel.system;

import org.json.JSONArray;
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
    private static final String STATO_MANUTENZIONE = "/var/db/mail-panel-maintenance-locks";

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
    public static boolean nomeValido(String n) {
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
            if (t.isEmpty()) continue;
            if (t.equals(nome)) return true;
            int d = t.lastIndexOf('-');
            while (d > 0) {
                if (t.substring(0, d).equals(nome)) return true;
                d = t.lastIndexOf('-', d - 1);
            }
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
    private static final String[][] RUOLI = {
        {"^postfix(-.*)?$",            "SMTP (Postfix)"},
        {"^dovecot[0-9]*$",            "IMAP/POP3 (Dovecot)"},
        {"^dovecot[0-9]*-pigeonhole(-.*)?$", "Filtri Sieve (Pigeonhole)"},
        {"^dovecot[0-9]*-.*$",         "Componente Dovecot"},
        {"^rspamd$",                   "Antispam e firma DKIM"},
        {"^redis(-.*)?$",              "Archivio dati di rspamd"},
        {"^clamav(-.*)?$",             "Antivirus"},
        {"^roundcube(-php[0-9]+)?$",   "Webmail (Roundcube)"},
        {"^nginx(-.*)?$",              "Web server della webmail"},
        {"^php[0-9]+$",                "PHP"},
        {"^php[0-9]+-.+$",             "Estensione PHP"},
        {"^mysql[0-9]+-server$",       "Database (server)"},
        {"^mysql[0-9]+-client$",       "Database (client)"},
        {"^py[0-9]+-fail2ban$",        "Blocco intrusioni (fail2ban)"},
        {"^(py[0-9]+-)?certbot$",      "Certificati Let's Encrypt"},
        {"^unbound$",                  "Risolutore DNS locale"},
        {"^opendkim$",                 "Firma DKIM"},
        {"^openssl[0-9]*$",            "Libreria TLS"},
        {"^openjdk[0-9]*$",            "Runtime Java: ci gira questo pannello"},
    };

    /** Ruolo del pacchetto nello stack di posta, o null se non lo riguarda. */
    private static String ruoloDi(String nome) {
        for (String[] r : RUOLI) if (nome.matches(r[0])) return r[1];
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
    public static final String[][] SERVIZI = {
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
        for (String[] candidati : SERVIZI) {
            // Un servizio non installato non e' "caduto": va distinto, altrimenti la verifica
            // finale segnalerebbe come guasto qualcosa che non c'e' mai stato. La presenza si
            // decide dallo script rc.d, non dall'esito di "status": quello e' diverso da zero
            // sia per un servizio spento sia per uno inesistente, e confonderebbe i due casi.
            for (String s : candidati) {
                if (!nomeValido(s)) continue;
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
            if (!nomeValido(nome)) continue;
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

    public static JSONObject packagesLock(boolean blocca, String soloQuesto) {
        if (!soloQuesto.isEmpty() && !nomeValido(soloQuesto)) {
            return new JSONObject().put("success", false).put("error", "nome pacchetto non valido");
        }
        StringBuilder log = new StringBuilder();
        int fatti = 0;
        JSONArray st = packagesStatus().getJSONArray("packages");
        for (int i = 0; i < st.length(); i++) {
            JSONObject p = st.getJSONObject(i);
            String nome = p.getString("name");
            if (!soloQuesto.isEmpty() && !soloQuesto.equals(nome)) continue;
            if (p.getBoolean("locked") == blocca) {
                log.append("  ").append(nome).append(": gia' a posto\n");
                continue;
            }
            boolean fatto = ok("pkg " + (blocca ? "lock" : "unlock") + " -y " + nome);
            log.append("  ").append(nome).append(": ")
               .append(fatto ? (blocca ? "protetto" : "sbloccato") : "FALLITO").append("\n");
            if (fatto) fatti++;
        }
        return new JSONObject().put("success", true).put("changed", fatti).put("output", log.toString());
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
         "ROTTURA CERTA. Dovecot 2.4 non accetta le configurazioni 2.3: non parte affatto, non si limita a "
         + "segnalare avvisi. Servono due nuove direttive obbligatorie (dovecot_config_version e "
         + "dovecot_storage_version), passdb e userdb devono avere un nome, mail_location e' stato scomposto "
         + "in piu' impostazioni mail_*, e le variabili a lettera singola (%u %d %n %h) sono state eliminate. "
         + "QUESTO PANNELLO genera esattamente quella sintassi: dopo l'aggiornamento la posta si ferma e "
         + "rigenerare la configurazione dal pannello non la rimetterebbe in piedi. Prima va adeguato il "
         + "generatore di configurazione, poi il pacchetto."},
        {"^roundcube.*", "attendi",
         "Un cambio di versione maggiore di Roundcube richiede l'aggiornamento dello schema del database "
         + "(bin/updatedb.sh): finche' non lo esegui la webmail resta inutilizzabile. Inoltre il pacchetto e' "
         + "legato alla versione di PHP (roundcube-phpNN): cambiare PHP significa cambiare anche questo."},
        {"^php[0-9]+.*", "attendi",
         "Gli script di questo pannello nominano una versione precisa di PHP nei percorsi, nel socket php-fpm "
         + "e nella configurazione di nginx per la webmail. Aggiornando il pacchetto senza prima adeguare il "
         + "pannello, la webmail resta senza PHP. Va anche tenuto allineato roundcube-phpNN."},
        {"^mysql[0-9]+-server$", "attendi",
         "Su FreeBSD le versioni maggiori di MySQL sono pacchetti DIVERSI e in conflitto: nessun pkg upgrade "
         + "porta dalla 8.0 alla 8.4. E al primo avvio la nuova versione riscrive il data dictionary, cosa "
         + "che non si annulla. Va fatta come migrazione a se', con una copia fredda presa a database spento."},
        {"^mysql[0-9]+-client$", "attendi",
         "Va tenuto allineato al server MySQL: aggiornarlo da solo disallinea le versioni del protocollo."},
        {"^postfix.*", "verifica",
         "Gli aggiornamenti di Postfix sono normalmente indolori, ma il livello di compatibilita' "
         + "(compatibility_level) cambia i valori predefiniti fra le versioni maggiori: dopo l'aggiornamento "
         + "controlla i log all'avvio. Attenzione anche al sapore del pacchetto: senza il supporto MySQL, "
         + "Postfix non legge piu' le caselle virtuali e rifiuta la posta."},
        {"^rspamd$", "verifica",
         "Le versioni maggiori cambiano qualche opzione di configurazione e il formato di alcune chiavi in "
         + "Redis. Dopo l'aggiornamento verifica che la firma DKIM in uscita funzioni ancora."},
        {"^redis.*", "verifica",
         "E' la memoria di rspamd: statistiche bayesiane, greylisting e limiti. L'aggiornamento e' normalmente "
         + "compatibile, ma se il file di dump non venisse riletto, rspamd riparte senza addestramento."},
        {"^clamav.*", "verifica",
         "Dopo l'aggiornamento il demone va riavviato e le firme possono richiedere un freshclam completo. "
         + "Nel frattempo la posta viene consegnata senza analisi antivirus, oppure messa in coda: dipende da "
         + "come e' configurato il fallimento dello scanner."},
        {"^nginx.*", "verifica",
         "Serve la webmail. Su un cambio maggiore controlla il virtual host generato dal pannello prima di "
         + "riavviare: la sintassi di alcune direttive cambia."},
        {"^py[0-9]+-fail2ban$", "verifica",
         "Il nome del pacchetto contiene la versione di Python: quando il predefinito del sistema cambia, il "
         + "pacchetto cambia nome e quello vecchio smette di ricevere aggiornamenti senza che nulla lo segnali. "
         + "Verifica che le regole (jail) restino attive dopo l'aggiornamento."},
        {"^(py[0-9]+-)?certbot$", "verifica",
         "Vale lo stesso discorso sulla versione di Python. Dopo l'aggiornamento prova un rinnovo simulato "
         + "prima di scoprire il problema alla scadenza del certificato."},
        {"^unbound$", "verifica",
         "E' il risolutore usato per le liste di blocco e le verifiche DNS. Un aggiornamento puo' rigenerare "
         + "i file di inoltro: dopo, controlla che la risoluzione funzioni ancora."},
        {"^openjdk[0-9]*$", "attendi",
         "E' il runtime Java su cui gira QUESTO pannello. Aggiornandolo mentre e' in esecuzione, la JVM in "
         + "memoria non combacia piu' con i file su disco e il pannello NON riesce piu' ad avviare processi: "
         + "da quel momento ogni comando che lancia fallisce in silenzio, compreso il riblocco dei pacchetti, "
         + "e ogni stato che riporta diventa falso. MEGLIO ATTENDERE: aggiornalo da solo e riavvia subito il "
         + "pannello."},
        {"^openssl[0-9]*$", "verifica",
         "Tocca TLS di Postfix, Dovecot e nginx insieme. Un cambio maggiore puo' rendere non piu' accettati "
         + "protocolli o cifrari vecchi: i client datati potrebbero non collegarsi piu'."},
    };

    /**
     * Quante cifre della versione delimitano una rottura, per pacchetto.
     *
     * Guardare solo la prima cifra e' l'errore che rende inutile tutto il resto: Dovecot
     * 2.3 -> 2.4 riscrive il formato della configurazione e PHP 8.4 -> 8.5 cambia percorsi
     * e socket, ma per entrambi la prima cifra non si muove. Trattarli da "aggiornamenti
     * minori normalmente sicuri" sarebbe falso proprio sui due casi piu' pericolosi.
     */
    private static final String[][] PROFONDITA_VERSIONE = {
        {"^dovecot.*",           "2"},   // 2.3 -> 2.4: configurazione incompatibile
        {"^php[0-9]+.*",         "2"},   // 8.4 -> 8.5: percorsi, socket, nome dei pacchetti
        {"^mysql[0-9]+-.*",      "2"},   // 8.0 -> 8.4: data dictionary, opzioni rimosse
        {"^roundcube.*",         "2"},   // 1.5 -> 1.6: schema del database
        {"^rspamd$",             "2"},   // le minori cambiano opzioni e chiavi in Redis
    };

    /** Confronta le prime N cifre di due versioni: true se sono cambiate. */
    static boolean saltoSignificativo(String nome, String da, String a) {
        int cifre = 1;
        for (String[] r : PROFONDITA_VERSIONE) if (nome.matches(r[0])) { cifre = Integer.parseInt(r[1]); break; }
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

    /** Avvertenza per un pacchetto, o null se non ne ha una specifica. */
    private static JSONObject avvertenzaPer(String nome, boolean saltoMaggiore) {
        for (String[] a : AVVERTENZE) {
            if (!nome.matches(a[0])) continue;
            if (!saltoMaggiore && "attendi".equals(a[1])) {
                return new JSONObject().put("level", "ok").put("text",
                        "Aggiornamento minore: normalmente sicuro. Sono i salti di versione maggiore, su questo "
                        + "pacchetto, a dover essere coordinati.");
            }
            // Un'avvertenza scritta per il caso peggiore, mostrata su un aggiornamento di
            // sole cifre finali, dice il falso: parla di "cambio maggiore" quando il salto
            // non c'e'. Chi legge o si allarma per niente, o smette di fidarsi del testo.
            String testo = saltoMaggiore ? a[2]
                    : "Questo NON e' un salto di versione significativo: cambiano solo le cifre finali, "
                      + "quindi il rischio e' contenuto e in genere si tratta di correzioni. "
                      + "Resta comunque valido: " + a[2];
            return new JSONObject().put("level", a[1]).put("text", testo);
        }
        if (saltoMaggiore) {
            return new JSONObject().put("level", "verifica").put("text",
                    "Salto di versione maggiore su un pacchetto dello stack di posta: verifica cosa cambia "
                    + "prima di procedere.");
        }
        return null;
    }

    /**
     * Versioni disponibili per i pacchetti BLOCCATI. Serve un comando diverso da
     * `pkg upgrade -n`: quello i bloccati li salta e non dice a che versione andrebbero,
     * quindi da solo lascerebbe credere che non abbiano aggiornamenti.
     */
    public static JSONArray aggiornamentiBloccati() {
        String v = sh("pkg version -vRL= 2>/dev/null", 60);
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
                + (omesse > 0 ? "\n\n(" + omesse + " righe sui pacchetti protetti omesse per leggibilita')" : ""));
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
        r.put("lockedUpdates", aggiornamentiBloccati());

        // --- Vulnerabilita' note ---
        String audit = sh("pkg audit -F 2>&1", 180);
        r.put("audit", audit.length() > 4000 ? audit.substring(audit.length() - 4000) : audit);

        // Incrocio vulnerabilita' <-> protezione. E' il punto: un pacchetto bloccato NON
        // riceve le correzioni di sicurezza. Il lock protegge da cambiamenti inattesi, non
        // e' uno stato in cui restare per sempre, e chi lo mette deve poterlo vedere.
        JSONArray vulnerabili = new JSONArray();
        String lock = sh("pkg lock -l 2>/dev/null");
        Matcher m = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        Set<String> visti = new java.util.LinkedHashSet<>();
        while (m.find()) visti.add(m.group(1));
        for (String nome : visti) {
            boolean lk = bloccato(lock, nome);
            String ruolo = ruoloDi(nome);
            JSONObject v = new JSONObject().put("name", nome).put("locked", lk)
                    .put("mailPackage", ruolo != null).put("role", ruolo == null ? "" : ruolo)
                    .put("fixedByUpgrade", !lk && simulazioneCompleta.contains(nome + ":"));
            // Il dettaglio serve per decidere: "ha una vulnerabilita'" non dice se e' una
            // esecuzione di codice da remoto o un rifiuto di servizio che non ti riguarda.
            JSONObject d = dettaglioVulnerabilita(audit, nome);
            v.put("cve", d.getJSONArray("cve"));
            v.put("descrizione", d.getString("descrizione"));
            v.put("riferimenti", d.getJSONArray("riferimenti"));
            vulnerabili.put(v);
        }
        r.put("vulnerable", vulnerabili);
        // Lezione pagata sull'altro server il 30/08: mysql80-server era stato aggiornato a
        // 8.0.46 ma il processo continuava a girare sui binari 8.0.45, quindi la correzione
        // non era in servizio pur risultando installata. Vale per ogni libreria condivisa.
        r.put("notaRiavvio",
            "Aggiornare un pacchetto NON aggiorna il processo gia' in esecuzione: i servizi "
            + "continuano a usare i file caricati in memoria finche' non li riavvii. Dopo un "
            + "aggiornamento di openssl vanno riavviati Postfix, Dovecot e nginx; dopo uno di "
            + "MySQL va riavviato mysql-server. Finche' non lo fai, la vulnerabilita' resta "
            + "aperta anche se il pacchetto risulta corretto.");

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
    static JSONObject dettaglioVulnerabilita(String audit, String pacchetto) {
        JSONArray cve = new JSONArray();
        JSONArray riferimenti = new JSONArray();
        StringBuilder descrizione = new StringBuilder();
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
            if (t.endsWith("is vulnerable:") || (t.isEmpty() && descrizione.length() > 0)) break;
            if (t.startsWith("CVE:")) {
                for (String c : t.substring(4).trim().split("[\\s,]+")) {
                    if (c.matches("CVE-[0-9]{4}-[0-9]+")) cveVisti.add(c);
                }
            } else if (t.startsWith("WWW:")) {
                String u = t.substring(4).trim();
                if (u.startsWith("https://") || u.startsWith("http://")) riferimenti.put(u);
            } else if (!t.isEmpty()) {
                if (descrizione.length() > 0) descrizione.append(' ');
                descrizione.append(t);
            }
        }
        for (String c : cveVisti) cve.put(c);
        String desc = descrizione.toString();
        if (desc.length() > 600) desc = desc.substring(0, 600) + "...";
        return new JSONObject().put("cve", cve).put("riferimenti", riferimenti).put("descrizione", desc);
    }

    public static JSONObject maintenancePreview() {
        ok("pkg update -q", 120);
        JSONArray arr = aggiornamentiBloccati();
        int maggiori = 0, attese = 0;
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            if (o.getBoolean("majorJump")) maggiori++;
            if (o.has("advisory") && "attendi".equals(o.getJSONObject("advisory").getString("level"))) attese++;
        }
        return new JSONObject().put("success", true).put("packages", arr)
                .put("majorCount", maggiori).put("waitCount", attese)
                .put("generalNote",
                    "Prima di un salto di versione maggiore la domanda non e' se il servizio regge, ma se "
                    + "IL PANNELLO E LA CONFIGURAZIONE che ha generato sono gia' pensati per quella versione. "
                    + "Gli script di questo pannello scrivono nomi di pacchetto, percorsi e direttive della "
                    + "versione attualmente installata: vanno adeguati PRIMA di aggiornare, non dopo.");
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
         "scomposto in piu' impostazioni mail_* (mail_driver, mail_path, ...)"},
        {"^[[:space:]]*passdb[[:space:]]*\\{", "passdb senza nome",
         "nella 2.4 ogni passdb deve avere un nome: passdb sql { ... }"},
        {"^[[:space:]]*userdb[[:space:]]*\\{", "userdb senza nome",
         "nella 2.4 ogni userdb deve avere un nome: userdb sql { ... }"},
        {"^[[:space:]]*ssl_dh[[:space:]]*=", "ssl_dh",
         "rinominata in ssl_server_dh_file (e ssl-parameters.dat non viene piu' convertito da solo)"},
        {"^[[:space:]]*default_fields[[:space:]]*=", "default_fields",
         "sostituita da passdb_fields / userdb_fields"},
        {"^[[:space:]]*override_fields[[:space:]]*=", "override_fields",
         "sostituita da passdb_fields / userdb_fields"},
        {"^[[:space:]]*service_count[[:space:]]*=", "service_count",
         "rinominata in service_restart_request_count, e il valore predefinito e' cambiato"},
        {"^[[:space:]]*idle_kill[[:space:]]*=", "idle_kill",
         "rinominata in service_idle_kill_interval"},
        {"fts[-_]lucene|fts[-_]squat", "backend di ricerca fts-lucene / fts-squat",
         "rimossi: si usa fts-flatcurve o fts-solr"},
        {"imap[-_]zlib", "plugin imap-zlib",
         "rimosso: la compressione COMPRESS e' ora automatica"},
        {"old[-_]stats", "plugin old-stats", "rimosso"},
        {"^[[:space:]]*(director|replicator)[[:space:]]*\\{|director_servers", "director / replicator",
         "rimossi dalla 2.4"},
        {"driver[[:space:]]*=[[:space:]]*checkpassword", "passdb checkpassword", "rimosso dalla 2.4"},
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
            String elenco = String.join(" ", vivi);
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
            String riferimenti = sh("grep -HE '^[[:space:]]*(!include(_try)?[[:space:]]|.*args[[:space:]]*=)' "
                    + elenco + " 2>/dev/null", 20);
            for (String riga : riferimenti.split("\n")) {
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
    public static JSONObject compatibilitaDovecot() {
        JSONObject r = new JSONObject();
        // Il pacchetto puo' chiamarsi dovecot, dovecot-mysql o dovecot-pgsql a seconda del
        // sapore scelto: sono lo stesso port e si escludono a vicenda, quindi su un sistema
        // con il sapore MySQL il nome "dovecot" NON e' installato e la query darebbe vuoto.
        // Il binario e' la risposta piu' diretta; l'origine del port e' il ripiego esatto.
        String installata = sh("dovecot --version 2>/dev/null | awk '{print $1}'", 20);
        if (installata.isEmpty()) {
            installata = sh("pkg query -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 20);
        }
        String disponibile = sh("pkg rquery -e '%o = \"mail/dovecot\"' %v 2>/dev/null | head -1", 30);
        if (disponibile.isEmpty()) disponibile = sh("pkg rquery %v dovecot 2>/dev/null", 30);
        r.put("installed", installata).put("available", disponibile);

        // Quali pacchetti Dovecot offre il repository. Non e' curiosita': se la 2.4 fosse un
        // PACCHETTO DIVERSO (come mysql80 e mysql84) allora nessun pkg upgrade potrebbe mai
        // portarci, e il rischio non sarebbe "un aggiornamento rompe la posta" ma "una
        // migrazione deliberata". Sono due scenari opposti e cambiano cosa va costruito.
        JSONArray offerti = new JSONArray();
        for (String riga : sh("pkg rquery -g '%n %v' 'dovecot*' 2>/dev/null", 30).split("\n")) {
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
        JSONArray problemi = new JSONArray();
        if (file.isEmpty()) {
            r.put("scanned", false);
            r.put("note", "Nessun file di configurazione trovato in " + DOVECOT_DIR
                    + ": impossibile dire se sopravvivrebbe alla 2.4.");
        } else {
            r.put("scanned", true);
            String elenco = String.join(" ", file);
            for (String[] rot : DOVECOT_24_ROTTURE) {
                String trovati = sh("grep -lE \"" + rot[0] + "\" " + elenco + " 2>/dev/null", 20);
                if (trovati.isEmpty()) continue;
                List<String> dove = new ArrayList<>();
                for (String f : trovati.split("\n")) if (!f.trim().isEmpty()) dove.add(f.trim());
                problemi.put(new JSONObject().put("costrutto", rot[1]).put("sostituto", rot[2])
                        .put("files", new JSONArray(dove)));
            }
            // Variabili a lettera singola: %u %d %n %h e le forme con modificatori (%2.256Nu).
            // La sintassi nuova e' %{...}, che non combacia con questa espressione.
            String var = sh("grep -lE '%[0-9.]*[A-Za-z]([^{A-Za-z]|$)' " + elenco + " 2>/dev/null", 20);
            if (!var.isEmpty()) {
                List<String> dove = new ArrayList<>();
                for (String f : var.split("\n")) if (!f.trim().isEmpty()) dove.add(f.trim());
                problemi.put(new JSONObject()
                        .put("costrutto", "variabili a lettera singola (%u, %d, %n, %h)")
                        .put("sostituto", "sintassi nuova %{user}, %{user | domain}, %{home}")
                        .put("files", new JSONArray(dove)));
            }
            // Nella 2.4 questa direttiva e' obbligatoria e deve essere la prima: la sua assenza
            // e' di per se' la prova che la configurazione e' ancora in formato 2.3.
            if (sh("grep -lE '^[[:space:]]*dovecot_config_version' " + elenco + " 2>/dev/null", 20).isEmpty()) {
                problemi.put(new JSONObject()
                        .put("costrutto", "dovecot_config_version assente")
                        .put("sostituto", "obbligatoria nella 2.4 e deve essere la prima direttiva")
                        .put("files", new JSONArray()));
            }
        }
        r.put("issues", problemi);
        r.put("compatible24", problemi.length() == 0);
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
        {"expire_logs_days",              "binlog_expire_logs_seconds (in secondi)"},
        {"master_info_repository",        "nessun sostituto: va tolta"},
        {"relay_log_info_repository",     "nessun sostituto: va tolta"},
        {"slave_rows_search_algorithms",  "nessun sostituto: va tolta"},
        {"transaction_write_set_extraction", "nessun sostituto: va tolta"},
        {"binlog_transaction_dependency_tracking", "nessun sostituto: la funzione e' interna"},
        {"log_bin_use_v1_events",         "nessun sostituto: va tolta"},
        {"skip_host_cache",               "host_cache_size = 0"},
        {"character_set_client_handshake", "nessun sostituto: va tolta"},
    };

    public static JSONObject compatibilitaMysql() {
        JSONObject r = new JSONObject();
        String pkgServer = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        r.put("package", pkgServer);
        if (pkgServer.isEmpty()) {
            return r.put("success", true).put("present", false)
                    .put("note", "Nessun pacchetto mysqlNN-server installato su questa macchina.");
        }
        if (!nomeValido(pkgServer)) {
            return r.put("success", false).put("error", "nome pacchetto MySQL non riconosciuto");
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
                    issues.put(new JSONObject().put("opzione", o[0]).put("sostituto", o[1]));
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
    public static JSONObject compatibilitaWebmail() {
        JSONObject r = new JSONObject();
        String php = sh("pkg query %n 2>/dev/null | grep -E '^php[0-9]+$' | head -1", 20);
        String roundcube = sh("pkg query %n 2>/dev/null | grep -E '^roundcube' | head -1", 20);
        if (!php.isEmpty() && !nomeValido(php)) php = "";
        if (!roundcube.isEmpty() && !nomeValido(roundcube)) roundcube = "";
        r.put("php", php).put("roundcube", roundcube);
        r.put("phpVersion", php.isEmpty() ? "" : sh("pkg query %v " + php, 20));
        r.put("roundcubeVersion", roundcube.isEmpty() ? "" : sh("pkg query %v " + roundcube, 20));

        JSONArray note = new JSONArray();
        Matcher mp = Pattern.compile("^php([0-9]+)$").matcher(php);
        Matcher mr = Pattern.compile("^roundcube-php([0-9]+)$").matcher(roundcube);
        String vPhp = mp.find() ? mp.group(1) : "";
        String vRc = mr.find() ? mr.group(1) : "";
        if (!vPhp.isEmpty() && !vRc.isEmpty() && !vPhp.equals(vRc)) {
            note.put("Roundcube e' compilato per PHP " + vRc + " ma il PHP installato e' il " + vPhp
                    + ": la webmail non parte finche' non combaciano.");
        }
        // Cosa nomina il pannello nei propri script: se diverge da cio' che e' installato, il
        // prossimo script generato punterebbe a un percorso che non esiste.
        if (!vPhp.isEmpty() && !("84".equals(vPhp))) {
            note.put("Gli script di installazione di questo pannello nominano php84 (percorsi, socket php-fpm, "
                    + "configurazione nginx della webmail) mentre il PHP installato e' il " + vPhp
                    + ": vanno adeguati prima di rigenerare qualunque configurazione.");
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
    public static JSONObject dumpConfigDovecot() {
        JSONArray files = new JSONArray();
        for (String f : fileDovecot()) {
            String contenuto = sh("cat " + f + " 2>/dev/null", 20);
            contenuto = oscuraCredenziali(contenuto);
            if (contenuto.length() > 20000) contenuto = contenuto.substring(0, 20000) + "\n... (troncato)";
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

    /** Le tre verifiche insieme: e' cio' che si guarda prima di premere "aggiorna". */
    public static JSONObject compatibilityReport() {
        return new JSONObject().put("success", true)
                .put("dovecot", compatibilitaDovecot())
                .put("mysql", compatibilitaMysql())
                .put("webmail", compatibilitaWebmail());
    }

    // ===================== lavori in corso =====================

    /** Un'operazione lunga che il pannello segue mentre avviene. */
    public static final class Job {
        public final String id;
        public final String tipo;
        public volatile String status = "pending";
        public volatile String errorMessage = "";
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
                    .put("elapsedSeconds", ((fine > 0 ? fine : System.currentTimeMillis()) - inizio) / 1000)
                    .put("consoleLog", log.toString());
        }
    }

    public static JSONObject jobStatus(String id) {
        Job j = JOBS.get(id);
        return j == null ? new JSONObject().put("success", false).put("error", "lavoro non trovato")
                         : new JSONObject().put("success", true).put("job", j.toJson());
    }

    /**
     * Esegue un comando lungo scrivendo l'output nel log del lavoro mentre arriva.
     * Shell.run raccoglie tutto e restituisce alla fine: per un pkg upgrade da minuti
     * significherebbe una pagina ferma senza sapere se sta funzionando.
     */
    private static int eseguiConLog(Job job, String comando, int timeoutSecondi) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", comando);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        // Il timeout va sorvegliato da FUORI. Metterlo solo sulla waitFor finale non
        // servirebbe a niente: se il processo si blocca senza chiudere lo standard output,
        // readLine resta in attesa per sempre e la waitFor non viene mai raggiunta. Un pkg
        // piantato terrebbe il lock del database dei pacchetti a tempo indefinito.
        Thread guardia = new Thread(() -> {
            try {
                if (!p.waitFor(timeoutSecondi, java.util.concurrent.TimeUnit.SECONDS)) {
                    job.scrivi("TIMEOUT dopo " + timeoutSecondi + "s: termino il processo.");
                    p.destroyForcibly();
                }
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }, "update-watchdog");
        guardia.setDaemon(true);
        guardia.start();

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = br.readLine()) != null) job.scrivi(l);
        }
        int code = p.waitFor();
        guardia.interrupt();
        return code;
    }

    // ===================== stato su disco, per sopravvivere a un crash =====================

    /**
     * Il blocco finale di runMaintenanceJob non viene eseguito se il processo muore
     * (riavvio del pannello, kill, crash della JVM): i pacchetti resterebbero sbloccati e
     * nessuno se ne accorgerebbe finche' un aggiornamento successivo non porta via un
     * servizio. Questo file e' l'unica cosa che sopravvive.
     */
    private static void scriviStato(List<String> pacchetti) {
        try {
            Files.writeString(Paths.get(STATO_MANUTENZIONE), String.join("\n", pacchetti) + "\n");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Impossibile scrivere lo stato manutenzione", e);
        }
    }

    private static void pulisciStato() {
        try { Files.deleteIfExists(Paths.get(STATO_MANUTENZIONE)); }
        catch (Exception e) { LOGGER.log(Level.WARNING, "Impossibile rimuovere lo stato manutenzione", e); }
    }

    /**
     * Da chiamare all'avvio del pannello. Se il file di stato esiste, una manutenzione non e'
     * arrivata in fondo: i pacchetti elencati vanno riprotetti subito. Riproteggere qualcosa di
     * gia' protetto non ha effetti, quindi e' sicuro anche se in realta' era andato tutto bene.
     */
    public static String ripristinaLockDopoCrash() {
        Path f = Paths.get(STATO_MANUTENZIONE);
        if (!Files.exists(f)) return "";
        StringBuilder log = new StringBuilder();
        int fatti = 0, totali = 0, saltati = 0;
        try {
            for (String riga : Files.readString(f).split("\n")) {
                String n = riga.trim();
                if (n.isEmpty()) continue;
                if (!nomeValido(n)) { log.append("  nome ignorato: ").append(n).append('\n'); continue; }
                totali++;
                if (!ok("pkg info -e " + n, 15)) { saltati++; log.append("  ").append(n).append(": non installato, salto\n"); continue; }
                if (ok("pkg lock -y " + n, 30)) { fatti++; log.append("  ").append(n).append(": riprotetto\n"); }
                else log.append("  ").append(n).append(": RIPROTEZIONE FALLITA\n");
            }
            if (fatti + saltati == totali) { pulisciStato(); log.append("Stato ripulito.\n"); }
            else log.append("Alcuni non sono stati riprotetti: lo stato resta, si riprova al prossimo avvio.\n");
        } catch (Exception e) {
            log.append("ERRORE nel ripristino: ").append(e.getMessage()).append('\n');
        }
        String msg = "Manutenzione interrotta rilevata all'avvio: " + fatti + "/" + totali
                + " pacchetti riprotetti.\n" + log;
        LOGGER.warning(msg);
        return msg;
    }

    /** Insieme dei pacchetti protetti adesso, nomi senza versione. */
    private static Set<String> insiemeProtetti() {
        Set<String> r = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n")) {
            String n = l.trim();
            if (n.isEmpty() || n.endsWith(":")) continue;
            n = n.replaceAll("-[0-9][^\\s]*$", "");
            if (nomeValido(n)) r.add(n);
        }
        return r;
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
    public static JSONObject avviaRigenerazioneDovecot() {
        String id = "dovecot-cfg-" + System.currentTimeMillis();
        Job j = new Job(id, "dovecot_config");
        JOBS.put(id, j);
        Thread t = new Thread(() -> runRigenerazioneDovecot(j), "dovecot-config");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    private static void runRigenerazioneDovecot(Job job) {
        job.status = "running";
        java.nio.file.Path script = null;
        try {
            job.avanza(1, 3);
            job.scrivi("=== Rigenerazione della configurazione Dovecot ===");
            job.scrivi("");

            boolean attivoPrima = ok("service dovecot status", 15);
            job.scrivi("Dovecot prima dell'operazione: " + (attivoPrima ? "attivo" : "non attivo"));

            String frammento = org.mail_panel.scripts.DovecotConfig.fromPanelConfig().scriptFragment();
            script = java.nio.file.Files.createTempFile("dovecot-config-", ".sh");
            java.nio.file.Files.writeString(script, "#!/bin/sh\nset -e\n" + frammento + "\n");
            java.nio.file.Files.setPosixFilePermissions(script,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));

            job.avanza(2, 3);
            job.scrivi("");
            job.scrivi("[2/3] Scrivo e valido la configurazione...");
            int code = eseguiConLog(job, "sh " + script, 300);
            if (code != 0) {
                job.status = "error";
                job.errorMessage = "Dovecot non accetta la configurazione generata: e' stata ripristinata "
                        + "quella precedente e il servizio NON e' stato toccato.";
                job.scrivi("");
                job.scrivi(job.errorMessage);
                return;
            }

            job.avanza(3, 3);
            job.scrivi("");
            job.scrivi("[3/3] Ricarico Dovecot...");
            if (!attivoPrima) {
                job.scrivi("    Dovecot non era attivo: non lo avvio io, la configurazione e' pronta.");
                job.status = "completed";
                return;
            }
            boolean ok1 = ok("service dovecot reload", 60);
            job.scrivi("    reload: " + (ok1 ? "eseguito" : "fallito, provo un restart"));
            if (!ok1) ok("service dovecot restart", 60);

            boolean attivoDopo = ok("service dovecot status", 20);
            job.scrivi("    Dovecot dopo l'operazione: " + (attivoDopo ? "attivo" : "NON attivo"));
            if (!attivoDopo) {
                job.status = "error";
                job.errorMessage = "Dovecot non risulta attivo dopo il ricaricamento: guarda /var/log/maillog.";
            } else {
                job.status = "completed";
                job.scrivi("");
                job.scrivi("Configurazione rigenerata e in servizio.");
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            if (script != null) try { java.nio.file.Files.deleteIfExists(script); } catch (Exception ignored) {}
            job.fine = System.currentTimeMillis();
        }
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

    /** Una riga del referto di controlli: esito, cosa si e' controllato, perche' conta. */
    private static void aggiungiCheck(JSONArray a, String id, String label, String level, String detail) {
        a.put(new JSONObject().put("id", id).put("label", label)
                .put("level", level).put("detail", detail));
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
    public static JSONObject pianoManutenzione() {
        ok("pkg update -q", 120);
        JSONArray passi = new JSONArray();
        int n = 0;

        // Dati raccolti UNA volta sola: pkg audit e la simulazione sono lente, e ripeterle
        // per ogni passo trasformerebbe il piano in un'attesa di minuti.
        String audit = sh("pkg audit -F 2>&1", 180);
        String dry = sh("pkg upgrade -n 2>&1", 180);
        String lock = sh("pkg lock -l 2>/dev/null");
        JSONObject stato = packagesStatus();
        JSONArray pacchetti = stato.getJSONArray("packages");

        // --- Passo 1: tutto lo stack protetto ---
        int installati = stato.getInt("installedCount"), protetti = stato.getInt("lockedCount");
        boolean tuttoProtetto = installati > 0 && protetti == installati;
        passi.put(passo(++n, "Proteggere tutti i pacchetti dello stack",
                tuttoProtetto ? "fatto" : "dafare",
                protetti + " su " + installati + " pacchetti sono protetti.",
                "Senza il lock, un aggiornamento puo' sostituire o rimuovere un pezzo del server di posta "
                + "senza che nessuno lo decida. E' il primo passo perche' rende sicuri tutti quelli dopo.",
                tuttoProtetto ? null : new JSONObject().put("tipo", "packages_lock_all")));

        // --- Passo 2: aggiornare cio' che non e' protetto ---
        Matcher mUp = Pattern.compile("Number of packages to be upgraded:\\s*([0-9]+)").matcher(dry);
        int daAggiornare = mUp.find() ? Integer.parseInt(mUp.group(1)) : 0;
        Matcher mIn = Pattern.compile("Number of packages to be installed:\\s*([0-9]+)").matcher(dry);
        int daInstallare = mIn.find() ? Integer.parseInt(mIn.group(1)) : 0;
        boolean contornoAggiornato = (daAggiornare + daInstallare) == 0;
        passi.put(passo(++n, "Aggiornare i pacchetti non protetti",
                contornoAggiornato ? "fatto" : "dafare",
                contornoAggiornato ? "Nessun pacchetto non protetto ha aggiornamenti in sospeso."
                        : daAggiornare + " da aggiornare e " + daInstallare + " da installare.",
                "Sono le librerie e gli strumenti di contorno. Il lock tiene fuori lo stack di posta e il "
                + "runtime Java del pannello, quindi il rischio e' minimo ed e' il modo giusto per verificare "
                + "che il meccanismo funzioni prima di toccare cose delicate.",
                contornoAggiornato ? null : new JSONObject().put("tipo", "updates_apply")));

        // --- Passi 3..N: un passo per ogni pacchetto protetto vulnerabile con correzione ---
        // L'ordine e' per numero di CVE chiuse: prima cio' che porta piu' beneficio.
        java.util.List<JSONObject> vulnerabili = new ArrayList<>();
        Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
        java.util.LinkedHashSet<String> visti = new java.util.LinkedHashSet<>();
        while (mv.find()) visti.add(mv.group(1));
        for (String nome : visti) {
            if (ruoloDi(nome) == null) continue;              // non e' dello stack di posta
            String cur = sh("pkg query %v " + nome + " 2>/dev/null", 20);
            String av  = sh("pkg rquery %v " + nome + " 2>/dev/null", 20);
            if (cur.isEmpty() || av.isEmpty() || av.equals(cur)) continue;   // nessuna correzione disponibile
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
                    ? "Aggiornare " + nome + " e " + (mem.size() - 1) + " pacchetti collegati ("
                      + v.getInt("cve") + " CVE)"
                    : "Aggiornare " + nome + " (" + v.getInt("cve") + " CVE)";
            passi.put(passo(++n, titolo,
                    attendi ? "manuale" : "dafare",
                    nome + " " + v.getString("cur") + " -> " + v.getString("av")
                        + (v.getBoolean("maggiore") ? ", salto di versione significativo" : ", solo cifre finali"),
                    attendi ? v.getJSONObject("avv").getString("text")
                            : "Il pannello lo sblocca, lo aggiorna, riavvia i servizi che lo usano verificando "
                              + "che siano ripartiti davvero, e lo riprotegge.",
                    attendi ? null : new JSONObject().put("tipo", "package_update").put("package", nome)));
        }

        // --- Passo finale: configurazione Dovecot dalla sorgente unica ---
        // Lo stato si ricava dal file vivo: l'intestazione la scrive solo il generatore nuovo.
        boolean rigenerata = ok("grep -q 'generato dal FreeBSD Mail Panel' "
                + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        boolean sieveAttivo = ok("grep -qE '^protocols.*sieve' " + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        passi.put(passo(++n, "Rigenerare la configurazione Dovecot",
                rigenerata ? "fatto" : "dafare",
                rigenerata ? "La configurazione proviene gia' dalla sorgente unica del pannello."
                        + (sieveAttivo ? " ManageSieve attivo." : " ManageSieve non attivo.")
                    : "La configurazione attuale e' un misto di generatori diversi.",
                "Unifica i file con la sorgente unica, corregge il nome del database che due generatori "
                + "scrivevano sbagliato, e attiva ManageSieve se Pigeonhole e' installato. Prima di mettere "
                + "in servizio chiede a Dovecot se accetta la configurazione: se rifiuta, rimette quella "
                + "precedente senza riavviare.",
                rigenerata ? null : new JSONObject().put("tipo", "dovecot_config_regen")));

        // Vulnerabilita' senza correzione disponibile: non sono un passo, ma vanno sapute.
        JSONArray senzaRimedio = new JSONArray();
        for (String nome : visti) {
            String cur = sh("pkg query %v " + nome + " 2>/dev/null", 20);
            String av  = sh("pkg rquery %v " + nome + " 2>/dev/null", 20);
            if (!cur.isEmpty() && (av.isEmpty() || av.equals(cur))) senzaRimedio.put(nome);
        }

        int daFare = 0;
        for (int i = 0; i < passi.length(); i++) if ("dafare".equals(passi.getJSONObject(i).getString("stato"))) daFare++;
        return new JSONObject().put("success", true).put("passi", passi)
                .put("daFare", daFare).put("totale", passi.length())
                .put("senzaRimedio", senzaRimedio);
    }

    private static JSONObject passo(int n, String titolo, String stato, String situazione,
                                    String perche, JSONObject azione) {
        JSONObject o = new JSONObject().put("n", n).put("titolo", titolo).put("stato", stato)
                .put("situazione", situazione).put("perche", perche);
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
        {"^mysql[0-9]+-(server|client)$",  "MySQL: server e client vanno alla stessa versione"},
        {"^php[0-9]+(-.+)?$",              "PHP e le sue estensioni condividono il numero di versione"},
        {"^dovecot[0-9]*(-.+)?$",          "Dovecot e i suoi componenti"},
    };

    /** L'espressione della famiglia a cui appartiene il pacchetto, o null se sta da solo. */
    static String famigliaDi(String nome) {
        for (String[] f : FAMIGLIE) if (nome.matches(f[0])) return f[0];
        return null;
    }

    static String motivoFamiglia(String nome) {
        for (String[] f : FAMIGLIE) if (nome.matches(f[0])) return f[1];
        return "";
    }

    /** Tutti i pacchetti INSTALLATI che appartengono alla stessa famiglia. Almeno il pacchetto stesso. */
    static java.util.List<String> membriFamiglia(String nome) {
        java.util.List<String> membri = new ArrayList<>();
        String fam = famigliaDi(nome);
        if (fam == null) { membri.add(nome); return membri; }
        for (String riga : sh("pkg query %n 2>/dev/null", 30).split("\n")) {
            String t = riga.trim();
            if (nomeValido(t) && t.matches(fam)) membri.add(t);
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
    private static final String[][] SERVIZIO_DI = {
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

    private static String servizioDiretto(String pacchetto) {
        for (String[] r : SERVIZIO_DI) if (pacchetto.matches(r[0])) return r[1];
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
        if (!nomeValido(pacchetto)) return new ArrayList<>(servizi);
        for (String riga : sh("pkg query %rn " + pacchetto + " 2>/dev/null", 30).split("\n")) {
            String dip = riga.trim();
            if (!nomeValido(dip)) continue;
            String s = servizioDiretto(dip);
            if (s != null) servizi.add(s);
        }
        return new ArrayList<>(servizi);
    }

    /** Nome effettivo dello script rc.d fra i candidati, o null se il servizio non c'e'. */
    private static String nomeServizioReale(String logico) {
        for (String[] candidati : SERVIZI) {
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

    /** Il pid di un servizio, o stringa vuota. Confrontarlo prima e dopo prova che e' ripartito davvero. */
    private static String pidServizio(String servizio) {
        if (!nomeValido(servizio)) return "";
        String o = sh("service " + servizio + " status 2>/dev/null", 15);
        Matcher m = Pattern.compile("pid[s]?[: ]+([0-9]+)").matcher(o.toLowerCase());
        return m.find() ? m.group(1) : "";
    }

    /**
     * Controlli preliminari per l'aggiornamento di UN pacchetto protetto. Tutto in sola
     * lettura: dice cosa succederebbe, quali vulnerabilita' si chiuderebbero e quali servizi
     * andranno riavviati, prima che qualcuno prema qualcosa.
     */
    public static JSONObject preflightPacchetto(String nome) {
        JSONObject r = new JSONObject();
        if (!nomeValido(nome)) return r.put("success", false).put("error", "nome pacchetto non valido");
        JSONArray checks = new JSONArray();
        boolean block = false;

        String versione = sh("pkg query %v " + nome + " 2>/dev/null", 20);
        if (versione.isEmpty()) {
            aggiungiCheck(checks, "installato", "Pacchetto installato", "block",
                    nome + " non risulta installato su questa macchina.");
            block = true;
        } else {
            aggiungiCheck(checks, "installato", "Pacchetto installato", "ok", nome + " " + versione);
        }
        r.put("name", nome).put("current", versione).put("role", ruoloDi(nome) == null ? "" : ruoloDi(nome));

        String disponibile = sh("pkg rquery %v " + nome + " 2>/dev/null", 30);
        r.put("available", disponibile);
        boolean maggiore = !versione.isEmpty() && !disponibile.isEmpty()
                && saltoSignificativo(nome, versione, disponibile);
        r.put("majorJump", maggiore);
        if (disponibile.isEmpty() || disponibile.equals(versione)) {
            aggiungiCheck(checks, "aggiornamento", "Aggiornamento disponibile", "block",
                    "Il repository non offre una versione piu' recente: non c'e' niente da aggiornare.");
            block = true;
        } else {
            aggiungiCheck(checks, "aggiornamento", "Aggiornamento disponibile", "ok",
                    versione + " -> " + disponibile + (maggiore ? " (salto di versione significativo)" : " (solo cifre finali)"));
        }

        JSONObject avv = avvertenzaPer(nome, maggiore);
        if (avv != null) {
            r.put("advisory", avv);
            if ("attendi".equals(avv.getString("level"))) {
                aggiungiCheck(checks, "avvertenza", "Avvertenza sul pacchetto", "block", avv.getString("text"));
                block = true;
            } else {
                aggiungiCheck(checks, "avvertenza", "Avvertenza sul pacchetto", avv.getString("level"), avv.getString("text"));
            }
        }

        // Vulnerabilita' che questo aggiornamento chiuderebbe: e' il motivo per farlo.
        String audit = sh("pkg audit " + nome + " 2>&1", 120);
        JSONObject det = dettaglioVulnerabilita(audit, nome);
        r.put("cve", det.getJSONArray("cve")).put("vulnDescrizione", det.getString("descrizione"))
         .put("riferimenti", det.getJSONArray("riferimenti"));
        int nCve = det.getJSONArray("cve").length();
        aggiungiCheck(checks, "vulnerabilita", "Vulnerabilita' note", nCve > 0 ? "verifica" : "ok",
                nCve > 0 ? nCve + " CVE aperte su questo pacchetto: " + det.getString("descrizione")
                         : "Nessuna vulnerabilita' nota registrata per questo pacchetto.");

        // Servizi da riavviare. Il punto dolente: senza riavvio la correzione non entra in servizio.
        JSONArray servizi = new JSONArray();
        for (String logico : serviziDaRiavviare(nome)) {
            String reale = nomeServizioReale(logico);
            if (reale == null) continue;
            servizi.put(new JSONObject().put("name", reale)
                    .put("running", ok("service " + reale + " status", 15))
                    .put("pid", pidServizio(reale)));
        }
        r.put("services", servizi);
        aggiungiCheck(checks, "servizi", "Servizi da riavviare", "verifica",
                servizi.length() == 0
                    ? "Nessun servizio risulta dipendere da questo pacchetto: non serve riavviare nulla."
                    : servizi.length() + " servizi verranno riavviati dopo l'aggiornamento, uno alla volta. "
                      + "Senza il riavvio continuerebbero a usare i file gia' caricati in memoria e la "
                      + "correzione non sarebbe in servizio, pur risultando installata.");

        if (Files.exists(Paths.get(STATO_MANUTENZIONE))) {
            aggiungiCheck(checks, "stato", "Nessuna manutenzione in sospeso", "block",
                    "Esiste uno stato di manutenzione non concluso in " + STATO_MANUTENZIONE
                    + ": riavvia il pannello, che lo ripristina da solo, e riprova.");
            block = true;
        }

        // I pacchetti che devono muoversi insieme si sbloccano e si aggiornano insieme:
        // altrimenti una dipendenza rimasta protetta blocca tutta l'operazione.
        java.util.List<String> famiglia = membriFamiglia(nome);
        r.put("family", new JSONArray(famiglia));
        if (famiglia.size() > 1) {
            aggiungiCheck(checks, "famiglia", "Pacchetti che si muovono insieme", "verifica",
                    famiglia.size() + " pacchetti verranno aggiornati insieme (" + motivoFamiglia(nome) + "): "
                    + String.join(", ", famiglia) + ". Aggiornarne uno solo non riuscirebbe, perche' gli altri "
                    + "restano protetti e pkg si ferma sulla dipendenza bloccata.");
        }

        String lockList = sh("pkg lock -l 2>/dev/null");
        java.util.List<String> protettiOra = new ArrayList<>();
        for (String m : famiglia) if (bloccato(lockList, m)) protettiOra.add(m);
        r.put("wasLocked", !protettiOra.isEmpty());
        r.put("lockedMembers", new JSONArray(protettiOra));
        aggiungiCheck(checks, "protezione", "Protezione dei pacchetti", "ok",
                protettiOra.isEmpty()
                    ? "Nessuno di questi e' protetto: verranno aggiornati e poi protetti."
                    : protettiOra.size() + " protetti su " + famiglia.size()
                      + ": verranno sbloccati per l'aggiornamento e riprotetti subito dopo, "
                      + "anche se qualcosa andasse storto.");

        r.put("success", true).put("checks", checks).put("canProceed", !block).put("blocked", block);
        return r;
    }

    public static JSONObject avviaAggiornamentoGuidato(String nome) {
        if (!nomeValido(nome)) return new JSONObject().put("success", false).put("error", "nome pacchetto non valido");
        String id = "guid-" + System.currentTimeMillis();
        Job j = new Job(id, "guided_update");
        JOBS.put(id, j);
        final String pkgNome = nome;
        Thread t = new Thread(() -> runAggiornamentoGuidato(j, pkgNome), "guided-update");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
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
    private static void runAggiornamentoGuidato(Job job, String nome) {
        job.status = "running";
        final int TOT = 6;
        java.util.List<String> daRiproteggere = new ArrayList<>();
        java.util.List<String> famiglia = new ArrayList<>();
        java.util.List<String> servizi = new ArrayList<>();
        Map<String, String> pidPrima = new LinkedHashMap<>();
        Map<String, Boolean> attivoPrima = new LinkedHashMap<>();
        try {
            job.avanza(1, TOT);
            job.scrivi("=== Aggiornamento guidato di " + nome + " ===");
            job.scrivi("");
            job.scrivi("[1/" + TOT + "] Controlli preliminari...");
            JSONObject pf = preflightPacchetto(nome);
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = "I controlli preliminari hanno trovato un impedimento.";
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level"))) {
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] "
                                + c.optString("label") + ": " + c.optString("detail"));
                    }
                }
                job.scrivi("RIFIUTO DI PARTIRE.");
                return;
            }
            String versionePrima = pf.optString("current", "");
            String attesa = pf.optString("available", "");
            famiglia = jsonArrayToList(pf.optJSONArray("family") == null
                    ? new JSONArray().put(nome) : pf.getJSONArray("family"));
            java.util.List<String> protetti = jsonArrayToList(pf.optJSONArray("lockedMembers") == null
                    ? new JSONArray() : pf.getJSONArray("lockedMembers"));
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
                job.scrivi("  insieme a " + (famiglia.size() - 1) + " pacchetti della stessa famiglia: "
                        + motivoFamiglia(nome));
            }
            job.scrivi("  servizi coinvolti: " + (servizi.isEmpty() ? "nessuno" : String.join(", ", servizi)));

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi("[2/" + TOT + "] Sblocco temporaneo...");
            if (protetti.isEmpty()) {
                job.scrivi("  nessuno di questi era protetto: niente da sbloccare");
            } else {
                // L'elenco si salva PRIMA di sbloccare: se il pannello muore adesso, il
                // ripristino all'avvio sa cosa riproteggere.
                scriviStato(protetti);
                job.scrivi("  elenco salvato in " + STATO_MANUTENZIONE + " per il ripristino automatico");
                for (String m : protetti) {
                    if (!nomeValido(m)) continue;
                    boolean u = ok("pkg unlock -y " + m, 30);
                    job.scrivi("    " + m + ": " + (u ? "sbloccato" : "SBLOCCO FALLITO"));
                    if (!u) throw new IllegalStateException("non sono riuscito a sbloccare " + m);
                    daRiproteggere.add(m);
                }
            }

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi("[3/" + TOT + "] Aggiornamento...");
            StringBuilder elenco = new StringBuilder();
            for (String m : famiglia) if (nomeValido(m)) elenco.append(' ').append(m);
            int code = eseguiConLog(job, "pkg upgrade -y" + elenco + " 2>&1", 1800);
            if (code != 0) throw new IllegalStateException("pkg upgrade uscito con codice " + code);

            String versioneDopo = sh("pkg query %v " + nome + " 2>/dev/null", 20);
            job.scrivi("  versione installata adesso: " + versioneDopo);
            if (versioneDopo.equals(versionePrima)) {
                throw new IllegalStateException("la versione non e' cambiata: l'aggiornamento non ha avuto effetto");
            }

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi("[4/" + TOT + "] Riavvio dei servizi che usano " + nome + "...");
            job.scrivi("  (senza questo continuerebbero a usare i file gia' caricati in memoria)");
            boolean problemaServizi = false;
            for (String s : servizi) {
                if (!Boolean.TRUE.equals(attivoPrima.get(s))) {
                    job.scrivi("    " + s + ": non era attivo prima, non lo avvio io");
                    continue;
                }
                boolean r1 = ok("service " + s + " restart", 120);
                boolean attivo = ok("service " + s + " status", 20);
                String pidDopo = pidServizio(s);
                String pidP = pidPrima.getOrDefault(s, "");
                String nota = "";
                if (!pidP.isEmpty() && !pidDopo.isEmpty()) {
                    nota = pidP.equals(pidDopo)
                        ? "  ATTENZIONE: stesso pid " + pidDopo + ", NON e' ripartito"
                        : "  (pid " + pidP + " -> " + pidDopo + ")";
                    if (pidP.equals(pidDopo)) problemaServizi = true;
                }
                job.scrivi("    " + s + ": " + (r1 ? "riavviato" : "RIAVVIO FALLITO")
                        + ", ora " + (attivo ? "attivo" : "NON ATTIVO") + nota);
                if (!attivo) problemaServizi = true;
            }

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi("[5/" + TOT + "] Verifica delle vulnerabilita' residue...");
            String audit = sh("pkg audit " + nome + " 2>&1", 120);
            JSONObject det = dettaglioVulnerabilita(audit, nome);
            int rimaste = det.getJSONArray("cve").length();
            if (rimaste == 0) {
                job.scrivi("  pkg audit non segnala piu' vulnerabilita' per " + nome);
            } else {
                job.scrivi("  ATTENZIONE: restano " + rimaste + " CVE su " + nome + ": " + det.getString("descrizione"));
                job.scrivi("  Il repository potrebbe non avere ancora la correzione.");
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi("[6/" + TOT + "] Stato di tutti i servizi...");
            boolean caduto = false;
            for (Map.Entry<String, Boolean> e : statoServizi().entrySet()) {
                job.scrivi("    " + e.getKey() + ": " + (e.getValue() ? "attivo" : "NON attivo"));
                if (!e.getValue()) caduto = true;
            }

            if (problemaServizi || caduto) {
                job.status = "error";
                job.errorMessage = "Aggiornamento eseguito, ma un servizio non e' ripartito come doveva: leggi il log.";
            } else {
                job.status = "completed";
                job.scrivi("");
                job.scrivi("=== " + nome + " " + versioneDopo + " in servizio ===");
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            // La riprotezione avviene SEMPRE, qualunque cosa sia andata storta sopra.
            if (!daRiproteggere.isEmpty()) {
                job.scrivi("");
                job.scrivi("Riproteggo " + daRiproteggere.size() + " pacchetti...");
                int rip = 0;
                for (String m : daRiproteggere) {
                    boolean ril = ok("pkg info -e " + m, 15) && ok("pkg lock -y " + m, 30);
                    if (ril) rip++;
                    else job.scrivi("    " + m + ": RIPROTEZIONE FALLITA");
                }
                job.scrivi("  " + rip + "/" + daRiproteggere.size() + " riprotetti");
                if (rip == daRiproteggere.size()) pulisciStato();
                else {
                    job.scrivi("  Lo stato resta in " + STATO_MANUTENZIONE + ": il pannello riprovera' al prossimo avvio.");
                    if ("completed".equals(job.status)) {
                        job.status = "error";
                        job.errorMessage = "Aggiornamento riuscito ma non tutti i pacchetti sono stati riprotetti.";
                    }
                }
            }
            job.fine = System.currentTimeMillis();
        }
    }

    public static JSONObject avviaManutenzione() {
        String id = "maint-" + System.currentTimeMillis();
        Job j = new Job(id, "maintenance");
        JOBS.put(id, j);
        Thread t = new Thread(() -> runMaintenanceJob(j), "update-maintenance");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    public static JSONObject avviaAggiornamentoNonProtetti() {
        String id = "upd-" + System.currentTimeMillis();
        Job j = new Job(id, "update");
        JOBS.put(id, j);
        Thread t = new Thread(() -> runUpdateJob(j), "update-plain");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /** Aggiorna solo cio' che non e' protetto: e' pkg stesso a saltare i pacchetti bloccati. */
    private static void runUpdateJob(Job job) {
        job.status = "running";
        job.avanza(1, 2);
        job.scrivi("=== Aggiornamento dei pacchetti NON protetti ===");
        job.scrivi("I pacchetti bloccati non vengono toccati: e' il lock a difenderli.");
        job.scrivi("");
        try {
            int code = eseguiConLog(job, "pkg upgrade -y 2>&1", 3600);
            job.avanza(2, 2);
            job.scrivi("");
            job.scrivi("pkg upgrade terminato con codice " + code);
            job.scrivi("");
            job.scrivi("=== Stato dei servizi ===");
            boolean caduto = false;
            for (Map.Entry<String, Boolean> e : statoServizi().entrySet()) {
                job.scrivi("  " + e.getKey() + ": " + (e.getValue() ? "attivo" : "NON attivo"));
                if (!e.getValue()) caduto = true;
            }
            job.status = (code == 0 && !caduto) ? "completed" : "error";
            if (code != 0) job.errorMessage = "pkg upgrade uscito con codice " + code;
            else if (caduto) job.errorMessage = "Aggiornamento eseguito, ma un servizio non risulta attivo: leggi il log.";
        } catch (Exception e) {
            job.status = "error"; job.errorMessage = e.getMessage();
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            job.fine = System.currentTimeMillis();
        }
    }

    /**
     * Sblocca -> aggiorna -> riprotegge ESATTAMENTE cio' che era protetto.
     * La riprotezione sta in un finally: deve avvenire anche se l'aggiornamento fallisce o
     * solleva un'eccezione. Lasciare i pacchetti sbloccati dopo un errore e' lo scenario
     * peggiore, perche' nessuno se ne accorge finche' un upgrade successivo non porta via
     * un servizio.
     */
    private static void runMaintenanceJob(Job job) {
        job.status = "running";
        List<String> daRibloccare = new ArrayList<>();
        Set<String> protettiPrima = new TreeSet<>();
        Map<String, Boolean> serviziPrima = new LinkedHashMap<>();
        try {
            if (Files.exists(Paths.get(STATO_MANUTENZIONE))) {
                job.status = "error";
                job.errorMessage = "Esiste gia' uno stato di manutenzione non concluso in " + STATO_MANUTENZIONE;
                job.scrivi("RIFIUTO DI PARTIRE: " + job.errorMessage);
                job.scrivi("Riavvia il pannello (esegue il ripristino automatico) e riprova.");
                job.fine = System.currentTimeMillis();
                return;
            }

            job.avanza(1, 4);
            job.scrivi("=== Manutenzione: sblocca, aggiorna, riprotegge ===");
            job.scrivi("");
            protettiPrima = insiemeProtetti();
            serviziPrima = statoServizi();
            job.scrivi("Stato iniziale: " + protettiPrima.size() + " pacchetti protetti.");
            job.scrivi("Servizi attivi: " + serviziPrima.entrySet().stream()
                    .filter(Map.Entry::getValue).map(Map.Entry::getKey)
                    .collect(java.util.stream.Collectors.joining(", ")));
            job.scrivi("");
            job.scrivi("[1/4] Decido cosa si puo' aggiornare e cosa no...");

            // --- Chi resta protetto, e perche' ---
            Set<String> trattieni = new TreeSet<>();
            Map<String, String> perche = new LinkedHashMap<>();

            JSONArray bloccati = aggiornamentiBloccati();
            for (int i = 0; i < bloccati.length(); i++) {
                JSONObject o = bloccati.getJSONObject(i);
                if (o.has("advisory") && "attendi".equals(o.getJSONObject("advisory").getString("level"))) {
                    trattieni.add(o.getString("name"));
                    perche.put(o.getString("name"), "avvertenza di livello ATTENDI su un salto di versione maggiore");
                }
            }

            // La prova sul campo batte l'avvertenza generica: se la configurazione Dovecot
            // VIVA contiene costrutti che la versione nuova non accetta, quel pacchetto non
            // si sblocca, punto. Non e' un'ipotesi sulla versione, e' cio' che c'e' sul disco.
            JSONObject dc = compatibilitaDovecot();
            if (dc.optBoolean("scanned", false) && !dc.optBoolean("compatible24", true)) {
                for (String n : sh("pkg query %n 2>/dev/null | grep -E '^dovecot' ", 20).split("\n")) {
                    String t = n.trim();
                    if (nomeValido(t)) {
                        trattieni.add(t);
                        perche.put(t, "la configurazione sul disco usa " + dc.optJSONArray("issues").length()
                                + " costrutti che la versione nuova non accetta");
                    }
                }
            }

            for (String l : sh("pkg lock -l 2>/dev/null").split("\n")) {
                String n = l.trim();
                if (n.isEmpty() || n.endsWith(":")) continue;
                n = n.replaceAll("-[0-9][^\\s]*$", "");
                if (!nomeValido(n)) continue;
                if (trattieni.contains(n)) {
                    job.scrivi("    " + n + "  -> TRATTENUTO: " + perche.getOrDefault(n, "avvertenza attiva"));
                    continue;
                }
                daRibloccare.add(n);
            }
            job.scrivi("  " + daRibloccare.size() + " pacchetti verranno aggiornati e riprotetti");
            if (!trattieni.isEmpty()) {
                job.scrivi("  " + trattieni.size() + " trattenuti: restano protetti e pkg li salta.");
                job.scrivi("  Vanno aggiornati con la procedura dedicata, non da qui.");
            }

            job.avanza(2, 4);
            job.scrivi("");
            job.scrivi("[2/4] Sblocco temporaneo...");
            // L'elenco si salva PRIMA di sbloccare: se il pannello muore adesso, il ripristino
            // all'avvio sa cosa riproteggere.
            scriviStato(daRibloccare);
            job.scrivi("  elenco salvato in " + STATO_MANUTENZIONE + " per il ripristino automatico");
            for (String n : daRibloccare) ok("pkg unlock -y " + n, 30);

            job.avanza(3, 4);
            job.scrivi("");
            job.scrivi("[3/4] Aggiornamento...");
            int code = eseguiConLog(job, "pkg upgrade -y 2>&1", 3600);
            job.scrivi("pkg upgrade terminato con codice " + code);
            if (code != 0) { job.status = "error"; job.errorMessage = "pkg upgrade uscito con codice " + code; }
            else job.status = "completed";

        } catch (Exception e) {
            job.status = "error"; job.errorMessage = e.getMessage();
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            // La riprotezione avviene SEMPRE, qualunque cosa sia andata storta sopra.
            job.avanza(4, 4);
            job.scrivi("");
            job.scrivi("[4/4] Ripristino la protezione...");
            int fatti = 0;
            for (String n : daRibloccare) {
                if (ok("pkg info -e " + n, 15) && ok("pkg lock -y " + n, 30)) fatti++;
                else job.scrivi("    ATTENZIONE: non sono riuscito a riproteggere " + n);
            }
            job.scrivi("  " + fatti + "/" + daRibloccare.size() + " pacchetti riprotetti");
            if (fatti == daRibloccare.size()) pulisciStato();
            else {
                job.scrivi("  CONTROLLA A MANO lo stato delle protezioni prima di considerare chiusa l'operazione.");
                job.scrivi("  Lo stato resta in " + STATO_MANUTENZIONE + ": il pannello riprovera' al prossimo avvio.");
            }

            // === Verifica del proprio operato: non basta aver eseguito i passi. ===
            job.scrivi("");
            job.scrivi("=== Verifica finale ===");
            boolean allarme = false;

            Set<String> protettiDopo = insiemeProtetti();
            Set<String> mancanti = new TreeSet<>(protettiPrima);
            mancanti.removeAll(protettiDopo);
            if (mancanti.isEmpty()) {
                job.scrivi("  Protezione: " + protettiDopo.size() + " pacchetti, insieme identico a prima. OK");
            } else {
                allarme = true;
                job.scrivi("  ALLARME: erano protetti e adesso NON lo sono: " + String.join(", ", mancanti));
            }

            Map<String, Boolean> serviziDopo = statoServizi();
            for (Map.Entry<String, Boolean> e : serviziPrima.entrySet()) {
                boolean prima = e.getValue(), dopo = serviziDopo.getOrDefault(e.getKey(), false);
                if (prima && !dopo) {
                    allarme = true;
                    job.scrivi("  ALLARME: " + e.getKey() + " era attivo prima e adesso NON lo e'.");
                } else {
                    job.scrivi("  " + e.getKey() + ": " + (dopo ? "attivo" : "non attivo")
                            + (prima ? "" : " (non lo era nemmeno prima)"));
                }
            }

            if (allarme) {
                job.status = "error";
                if (job.errorMessage == null || job.errorMessage.isEmpty()) {
                    job.errorMessage = "Aggiornamento eseguito, ma la verifica finale ha rilevato problemi: leggi il log.";
                }
            } else if ("completed".equals(job.status)) {
                job.scrivi("");
                job.scrivi("Verifica superata: protezione ripristinata e nessun servizio caduto.");
            }
            job.fine = System.currentTimeMillis();
        }
    }
}
