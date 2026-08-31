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
         "NON aggiornarlo da qui: usa la scheda \"Aggiornamento Roundcube\", che fa anche lo schema. "
         + "Un cambio di versione maggiore di Roundcube richiede l'aggiornamento dello schema del database "
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
         + "e ogni stato che riporta diventa falso. NON aggiornarlo da qui: usa la scheda \"Aggiornamento "
         + "della JVM del pannello\", che lo fa con uno script staccato — impacchetta la Java attuale come "
         + "via di ritorno, spegne il pannello, aggiorna, controlla che java risponda e lo riaccende da solo."},
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
        {"^postfix.*",           "2"},   // 3.10 -> 3.11 cambia i predefiniti del compatibility_level
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
    private static final String[] SEMPRE_ATTENDI = { "^openjdk[0-9]*$" };

    private static boolean rischioIndipendenteDallaVersione(String nome) {
        for (String r : SEMPRE_ATTENDI) if (nome.matches(r)) return true;
        return false;
    }

    /** Avvertenza per un pacchetto, o null se non ne ha una specifica. */
    private static JSONObject avvertenzaPer(String nome, boolean saltoMaggiore) {
        for (String[] a : AVVERTENZE) {
            if (!nome.matches(a[0])) continue;
            if (!saltoMaggiore && "attendi".equals(a[1]) && !rischioIndipendenteDallaVersione(nome)) {
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
        return eseguiConLog(job, comando, timeoutSecondi, null);
    }

    private static int eseguiConLog(Job job, String comando, int timeoutSecondi, StringBuilder cattura) throws Exception {
        return eseguiConLog(job, comando, timeoutSecondi, cattura, null);
    }

    private static int eseguiConLog(Job job, String comando, int timeoutSecondi,
                                    StringBuilder cattura, Map<String, String> ambiente) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", comando);
        if (ambiente != null) pb.environment().putAll(ambiente);
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
            // La password passa dall'AMBIENTE: non nel testo dello script (che finisce su
            // disco) ne' sulla riga di comando (visibile nell'elenco dei processi).
            Map<String, String> amb = new LinkedHashMap<>();
            try (java.sql.ResultSet rs = org.mail_panel.Main.dbManager.get_data_config()) {
                if (rs.next()) {
                    String pw = rs.getString("mysql_password");
                    if (pw != null && !pw.isEmpty()) amb.put("DB_PASS", pw);
                }
            } catch (Exception ignored) {}
            job.scrivi("    password del database: " + (amb.containsKey("DB_PASS")
                    ? "presa dalla configurazione del pannello"
                    : "non disponibile qui, lo script la cerchera' da solo"));
            int code = eseguiConLog(job, "sh " + script, 300, null, amb);
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
                return;
            }

            // === Prova funzionale: l'autenticazione funziona ancora? ===
            // Questo passo riscrive dovecot-sql.conf, cioe' il file con cui Dovecot interroga
            // il database per autenticare. "Il servizio e' attivo" non dice niente al riguardo:
            // Dovecot resta attivo anche con credenziali sbagliate, e se ne accorgono gli utenti.
            // Si esegue la STESSA query che il pannello ha appena scritto nella configurazione,
            // con le STESSE credenziali, su una casella vera.
            job.scrivi("");
            job.scrivi("Prova funzionale dell'autenticazione...");
            String casella = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
            if (casella.isEmpty()) {
                job.scrivi("    nessuna casella attiva nel database: prova non eseguibile.");
                job.status = "completed";
                job.scrivi("");
                job.scrivi("Configurazione rigenerata e in servizio, ma l'autenticazione non e' stata provata.");
                return;
            }
            if (!casella.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.scrivi("    indirizzo non riconosciuto, non lo uso in una query: prova saltata.");
                job.status = "completed";
                return;
            }
            // La stessa condizione della password_query scritta nel file, senza estrarre la
            // password: interessa che la riga ci sia e sia raggiungibile, non il suo contenuto.
            String trovate = mysqlOut("SELECT COUNT(*) FROM mailboxes WHERE email='" + casella + "' AND active=1;").trim();
            if ("1".equals(trovate)) {
                job.scrivi("    la query di autenticazione trova " + casella + ": il percorso verso il database funziona.");
                job.status = "completed";
                job.scrivi("");
                job.scrivi("Configurazione rigenerata, in servizio e verificata.");
            } else {
                job.status = "error";
                job.errorMessage = "Dovecot e' attivo ma la query di autenticazione non trova " + casella
                        + " (risultato: '" + trovate + "'). Le caselle potrebbero non riuscire piu' ad "
                        + "accedere: la configurazione precedente e' in " + "/var/db/mailpanel.";
                job.scrivi("    ALLARME: " + job.errorMessage);
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

    /**
     * Esegue una query con le credenziali del pannello, prese dalla configurazione.
     * La password passa dall'ambiente, non dalla riga di comando: altrimenti comparirebbe
     * nell'elenco dei processi visibile a chiunque sul server.
     */
    private static String mysqlOut(String sql) {
        String user = "mailpanel", pass = "", db = "mailserver", host = "127.0.0.1", port = "3306";
        try (java.sql.ResultSet rs = org.mail_panel.Main.dbManager.get_data_config()) {
            if (rs.next()) {
                String u = rs.getString("mysql_user"), p2 = rs.getString("mysql_password");
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
                    .put("accounts", (int) numero(t.substring(sp + 1))));
        }
        return arr;
    }

    /** I plugin trovati, in forma leggibile. */
    private static String descriviPlugin(JSONArray a) {
        if (a.length() == 0) return "nessun plugin elencato (lettura non riuscita)";
        StringBuilder sb = new StringBuilder();
        int tot = 0;
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.getJSONObject(i);
            if (sb.length() > 0) sb.append(", ");
            sb.append(o.getString("plugin")).append(' ').append(o.getInt("accounts"));
            tot += o.getInt("accounts");
        }
        return sb + " (in tutto " + tot + " account)";
    }

    /** Numero da output di comando; 0 se non contiene cifre. */
    private static long numero(String v) {
        try { return Long.parseLong(v == null ? "" : v.trim().replaceAll("[^0-9]", "")); }
        catch (Exception e) { return 0L; }
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
        if (!nomeValido(nome)) return null;
        String installato = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-client$' | head -1", 20);
        if (installato.isEmpty()) return null;
        // Si guarda TUTTA la famiglia, non il solo pacchetto nominato: php84 non dipende da
        // MySQL, ma php84-mysqli e php84-pdo_mysql si', e vengono aggiornati insieme a lui.
        // Controllare solo il nome scritto nel passo lascerebbe passare esattamente la stessa
        // trappola di postfix, con la differenza che qui nessuno la vedrebbe arrivare.
        for (String membro : membriFamiglia(nome)) {
            if (!nomeValido(membro)) continue;
            String deps = sh("pkg rquery %dn " + membro + " 2>/dev/null", 30);
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
            aggiungiCheck(checks, "pkg", "Pacchetto MySQL installato", "block",
                    "Nessun mysqlNN-server installato: non c'e' niente da migrare.");
            block = true;
        } else if (srvPkg.startsWith("mysql84")) {
            aggiungiCheck(checks, "pkg", "Pacchetto MySQL installato", "ok",
                    srvPkg + ": sei gia' sulla 8.4.");
            r.put("alreadyDone", true);
        } else {
            String v = sh("pkg query %v " + srvPkg, 20);
            aggiungiCheck(checks, "pkg", "Pacchetto MySQL installato", "ok",
                    srvPkg + " " + v + " + " + cliPkg + " -> mysql84-server + mysql84-client. "
                    + "Il port mysql80 verra' RIMOSSO da FreeBSD dopo il 31/12/2026: dopo quella data "
                    + "non sarebbe piu' possibile nemmeno tornare indietro reinstallandolo.");
        }

        // --- 2. La destinazione esiste ---
        String srv84 = sh("pkg rquery %v mysql84-server 2>/dev/null", 30);
        String cli84 = sh("pkg rquery %v mysql84-client 2>/dev/null", 30);
        r.put("target", srv84);
        if (srv84.isEmpty() || cli84.isEmpty()) {
            aggiungiCheck(checks, "target", "Disponibilita' della 8.4", "block",
                    "Il repository non offre mysql84-server/mysql84-client.");
            block = true;
        } else {
            aggiungiCheck(checks, "target", "Disponibilita' della 8.4", "ok",
                    "mysql84-server " + srv84 + " e mysql84-client " + cli84 + " disponibili.");
        }

        // --- 3. IL PUNTO CRITICO: chi usa la libreria del client, e cosa pretende dal repository ---
        JSONArray dipendenti = new JSONArray();
        boolean conflitto = false;
        if (!cliPkg.isEmpty()) {
            for (String riga : sh("pkg query %rn " + cliPkg + " 2>/dev/null", 30).split("\n")) {
                String d = riga.trim();
                if (!nomeValido(d) || d.equals(srvPkg)) continue;
                // Cosa pretende la versione del repository di questo dipendente: se nomina
                // ancora mysql80-client, la 8.4 non lo soddisfa e il pacchetto va ricostruito.
                String deps = sh("pkg rquery %dn " + d + " 2>/dev/null", 30);
                boolean vuole80 = deps.contains(cliPkg);
                boolean vuole84 = deps.contains("mysql84-client");
                if (vuole80 && !vuole84) conflitto = true;
                dipendenti.put(new JSONObject().put("name", d)
                        .put("richiede", vuole84 ? "mysql84-client" : (vuole80 ? cliPkg : "non specificato"))
                        .put("compatibile", !vuole80 || vuole84));
            }
        }
        r.put("dependents", dipendenti).put("libraryConflict", conflitto);
        if (conflitto) {
            aggiungiCheck(checks, "libreria", "Pacchetti collegati alla libreria client", "block",
                    "Almeno un pacchetto che usa la libreria di " + cliPkg + " la pretende ancora dal "
                    + "repository nella versione 8.0. Sostituendola con la 8.4 resterebbe senza libreria e "
                    + "NON ripartirebbe: sul server di posta significa Postfix o Dovecot che non leggono piu' "
                    + "le caselle. Va risolto prima, non durante.");
            block = true;
        } else {
            aggiungiCheck(checks, "libreria", "Pacchetti collegati alla libreria client",
                    dipendenti.length() == 0 ? "ok" : "verifica",
                    dipendenti.length() == 0
                        ? "Nessun pacchetto esterno usa la libreria di " + cliPkg + "."
                        : dipendenti.length() + " pacchetti la usano e il repository li fornisce compatibili "
                          + "con la 8.4. Verranno comunque riavviati e ricontrollati a fine migrazione.");
        }

        // --- 4. Il processo in esecuzione e' quello del pacchetto? ---
        boolean su = ok("service mysql-server status", 15);
        String runVer = su ? mysqlOut("SELECT VERSION();") : "";
        if (!su) {
            aggiungiCheck(checks, "running", "MySQL in esecuzione", "block",
                    "MySQL e' fermo: i controlli su account e tabelle si fanno interrogandolo.");
            block = true;
        } else if (runVer.isEmpty()) {
            aggiungiCheck(checks, "running", "MySQL in esecuzione", "block",
                    "MySQL non risponde alla query di versione con le credenziali del pannello.");
            block = true;
        } else {
            String pkgVer = sh("pkg query %v " + srvPkg, 20).split("[_,]")[0];
            boolean combacia = pkgVer.isEmpty() || runVer.startsWith(pkgVer);
            aggiungiCheck(checks, "running", "MySQL in esecuzione", combacia ? "ok" : "block",
                    combacia ? "Versione attiva " + runVer + ", combacia con il pacchetto."
                             : "Il processo gira sulla " + runVer + " ma il pacchetto e' " + pkgVer
                               + ": riavvia MySQL prima di migrare.");
            if (!combacia) block = true;
            r.put("runningVersion", runVer);
        }

        // --- 5. my.cnf: opzioni rimosse nella 8.4 ---
        JSONObject cm = compatibilitaMysql();
        JSONArray issues = cm.optJSONArray("issues");
        if (issues != null && issues.length() > 0) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < issues.length(); i++) sb.append(issues.getJSONObject(i).getString("opzione")).append(' ');
            aggiungiCheck(checks, "mycnf", "Configurazione compatibile", "block",
                    "Il my.cnf contiene opzioni rimosse nella 8.4 (" + sb.toString().trim()
                    + "): con una sola di queste il server non parte, e a quel punto la 8.0 sarebbe gia' disinstallata.");
            block = true;
        } else {
            aggiungiCheck(checks, "mycnf", "Configurazione compatibile", "ok",
                    "Nessuna opzione rimossa nella 8.4 e' attiva nel my.cnf.");
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
            aggiungiCheck(checks, "auth", "Plugin di autenticazione", "block",
                    "Non riesco a leggere mysql.user con l'utente del pannello: non posso dire se qualche "
                    + "account usa mysql_native_password, che la 8.4 non attiva piu'. Non lo do per assente, "
                    + "perche' un silenzio non e' una conferma: se fra quelli ci fosse l'utente di Postfix o "
                    + "Dovecot, dopo la migrazione la posta si fermerebbe. Il pannello ha provato sia come "
                    + "utente applicativo sia come root dal socket unix: se nemmeno quello riesce, MySQL su "
                    + "questa macchina non consente l'accesso root dal socket e la verifica va fatta a parte.");
            block = true;
        } else {
            aggiungiCheck(checks, "auth", "Plugin di autenticazione", nativi.length() > 0 ? "verifica" : "ok",
                    nativi.length() == 0
                        ? "Nessun account usa mysql_native_password. Prova positiva della lettura: "
                          + descriviPlugin(pluginInUso()) + "."
                        : nativi.length() + " account lo usano (" + String.join(", ", jsonArrayToList(nativi))
                          + "): la migrazione aggiungera' mysql-native-password=ON al my.cnf perche' "
                          + "continuino a entrare.");
        }

        // --- 7. Spazio per la copia fredda ---
        String dataDir = sh("grep -E '^[[:space:]]*datadir[[:space:]]*=' /usr/local/etc/mysql/my.cnf 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' '", 15);
        if (dataDir.isEmpty()) dataDir = "/var/db/mysql";
        long dirKb = numero(sh("du -sk " + dataDir + " 2>/dev/null | awk '{print $1}'", 120));
        long freeKb = numero(sh("df -k /var/db 2>/dev/null | tail -1 | awk '{print $4}'", 20));
        long servono = (long) (dirKb * 1.15) + 512L * 1024L;
        r.put("dataDir", dataDir).put("dataDirMb", dirKb / 1024).put("freeMb", freeKb / 1024);
        if (dirKb <= 0 || freeKb < servono) {
            aggiungiCheck(checks, "spazio", "Spazio per la copia di sicurezza", "block",
                    "Servono circa " + (servono / 1024) + " MB liberi, disponibili " + (freeKb / 1024)
                    + ". La copia fredda e' l'unica via di ritorno: senza, il passaggio e' irreversibile.");
            block = true;
        } else {
            aggiungiCheck(checks, "spazio", "Spazio per la copia di sicurezza", "ok",
                    dataDir + " occupa " + (dirKb / 1024) + " MB, liberi " + (freeKb / 1024) + " MB.");
        }

        // --- 8. Inventario, per riconfrontare a fine migrazione ---
        long schemi = 0, tabelle = 0, caselle = 0;
        if (su && !runVer.isEmpty()) {
            schemi = numero(mysqlOut("SELECT COUNT(*) FROM information_schema.schemata;"));
            tabelle = numero(mysqlOut("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');"));
            caselle = numero(mysqlOut("SELECT COUNT(*) FROM mailboxes;"));
        }
        r.put("schemaCount", schemi).put("tableCount", tabelle).put("mailboxCount", caselle);
        aggiungiCheck(checks, "inventario", "Inventario di partenza", schemi > 0 ? "ok" : "verifica",
                schemi > 0 ? schemi + " schemi, " + tabelle + " tabelle, " + caselle
                             + " caselle di posta. A fine migrazione il pannello riconta e segnala differenze."
                           : "Inventario non leggibile: la verifica finale sarebbe meno stringente.");

        // --- 9. Cosa si ferma, e per quanto ---
        aggiungiCheck(checks, "servizi", "Servizi coinvolti", "verifica",
                "Postfix e Dovecot verranno fermati PRIMA di MySQL e riavviati dopo: fermarli e' piu' pulito "
                + "che lasciarli rispondere con errori mentre il database non c'e'. In quella finestra la posta "
                + "in arrivo viene rifiutata temporaneamente e i mittenti riprovano; le caselle non si collegano. "
                + "Il pannello resta utilizzabile perche' le sessioni stanno in memoria.");

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
            LOGGER.log(Level.WARNING, "Impossibile aggiungere " + riga + " al my.cnf", e);
            return false;
        }
    }

    /** File e byte logici di un albero: si misura con stat, MAI con du. */
    private static long[] misura(String dir) {
        long file = numero(sh("find " + dir + " -type f 2>/dev/null | wc -l", 120));
        long byteLogici = numero(sh("find " + dir + " -type f -exec stat -f %z {} + 2>/dev/null "
                + "| awk '{s+=$1} END {print s+0}'", 120));
        return new long[]{file, byteLogici};
    }

    public static JSONObject avviaMigrazione84() {
        String id = "my84-" + System.currentTimeMillis();
        Job j = new Job(id, "mysql84_migration");
        JOBS.put(id, j);
        Thread t = new Thread(() -> runMigrazione84(j), "mysql84-migration");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
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
            job.scrivi("=== Migrazione MySQL 8.0 -> 8.4 ===");
            job.scrivi("");
            job.scrivi("[1/" + TOT + "] Controlli preliminari...");
            JSONObject pf = mysql84Preflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("alreadyDone", false)
                        ? "Sei gia' sulla 8.4." : "I controlli preliminari hanno trovato un impedimento.";
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.scrivi("RIFIUTO DI PARTIRE.");
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
            job.scrivi("  inventario: " + schemiPrima + " schemi, " + tabellePrima + " tabelle, "
                    + casellePrima + " caselle");
            job.scrivi("  casella usata per la prova finale: "
                    + (casellaProva.isEmpty() ? "nessuna (verifica funzionale non possibile)" : casellaProva));

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi("[2/" + TOT + "] Fermo Postfix e Dovecot...");
            postfixEra = ok("service postfix status", 20);
            dovecotEra = ok("service dovecot status", 20);
            if (postfixEra) { ok("service postfix stop", 60); job.scrivi("    postfix: fermato"); }
            else job.scrivi("    postfix: non era attivo");
            if (dovecotEra) { ok("service dovecot stop", 60); job.scrivi("    dovecot: fermato"); }
            else job.scrivi("    dovecot: non era attivo");

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi("[3/" + TOT + "] Fermo MySQL...");
            ok("service mysql-server stop", 120);
            boolean giu = false;
            for (int i = 0; i < 120; i++) {
                if (!ok("service mysql-server status", 10) && !ok("pgrep -q mysqld", 10)) { giu = true; break; }
                try { Thread.sleep(1000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            }
            if (!giu) throw new IllegalStateException("MySQL non si e' fermato: una copia presa a server acceso non sarebbe ripristinabile");
            mysqlFermo = true;
            job.scrivi("    fermo e confermato tale");

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi("[4/" + TOT + "] Copia di sicurezza a freddo...");
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("data non valida per la copia");
            backupDir = MYSQL84_BACKUP + "/" + ts;
            if (!ok("mkdir -p " + backupDir + "/pkg", 30)) throw new IllegalStateException("non riesco a creare " + backupDir);
            ok("cp -p /usr/local/etc/mysql/my.cnf " + backupDir + "/my.cnf", 30);
            ok("printf '%s\\n%s\\n' " + srvPkg + " " + cliPkg + " > " + backupDir + "/pacchetti.txt", 20);
            job.scrivi("    my.cnf e nomi dei pacchetti salvati");
            ok("pkg fetch -y -o " + backupDir + "/pkg " + srvPkg + " " + cliPkg + " >/dev/null 2>&1", 600);
            job.scrivi("    " + numero(sh("find " + backupDir + "/pkg -name '*.pkg' | wc -l", 30))
                    + " pacchetti 8.0 conservati per l'eventuale ritorno");

            long[] prima = misura(dataDir);
            job.scrivi("    copio " + dataDir + ": " + prima[0] + " file, " + (prima[1] / 1024 / 1024) + " MB");
            String cpOut = sh("cp -Rp " + dataDir + " " + backupDir + "/datadir 2>&1; echo EXIT=$?", 1800);
            int cpCode = -1;
            for (String l : cpOut.split("\n")) {
                if (l.startsWith("EXIT=")) { cpCode = (int) numero(l); continue; }
                if (!l.trim().isEmpty()) job.scrivi("      cp: " + l);
            }
            if (cpCode != 0) throw new IllegalStateException("cp uscito con codice " + cpCode);
            ok("sync", 120);
            long[] dopo = misura(backupDir + "/datadir");
            if (dopo[0] != prima[0] || dopo[1] != prima[1]) {
                throw new IllegalStateException("la copia non corrisponde: " + dopo[0] + " file / " + dopo[1]
                        + " byte contro " + prima[0] + " / " + prima[1]);
            }
            if (!ok("test -f " + backupDir + "/datadir/ibdata1", 15)) {
                throw new IllegalStateException("nella copia manca ibdata1: non e' una cartella dati ripristinabile");
            }
            ok("printf '%s\\n%s\\n' " + prima[0] + " " + prima[1] + " > " + backupDir + "/manifest.txt", 20);
            job.scrivi("    copia verificata file per file: " + dopo[0] + " file, " + (dopo[1] / 1024 / 1024) + " MB");
            job.scrivi("    percorso della copia: " + backupDir);

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi("[5/" + TOT + "] Sostituisco i pacchetti...");
            ok("pkg unlock -y " + srvPkg, 30);
            ok("pkg unlock -y " + cliPkg, 30);
            String del = sh("pkg delete -f -y " + srvPkg + " " + cliPkg + " 2>&1", 300);
            for (String l : del.split("\n")) if (!l.trim().isEmpty()) job.scrivi("    " + l);
            pacchettiSostituiti = true;
            String ins = sh("pkg install -y mysql84-server mysql84-client 2>&1", 900);
            for (String l : ins.split("\n")) if (!l.trim().isEmpty()) job.scrivi("    " + l);
            if (!ok("pkg info -e mysql84-server", 20) || !ok("pkg info -e mysql84-client", 20)) {
                throw new IllegalStateException("l'installazione della 8.4 non e' riuscita: i dati sono intatti, la copia e' in " + backupDir);
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi("[6/" + TOT + "] Verifico che Postfix e Dovecot siano ancora installati...");
            boolean persi = false;
            for (String d : new String[]{"postfix-mysql", "dovecot-mysql"}) {
                boolean c = ok("pkg info -e " + d, 20);
                job.scrivi("    " + d + ": " + (c ? "presente" : "MANCANTE"));
                if (!c) persi = true;
            }
            if (persi) job.scrivi("    ATTENZIONE: un pacchetto e' stato rimosso dalla sostituzione. Reinstallalo prima di proseguire.");

            job.avanza(7, TOT);
            job.scrivi("");
            job.scrivi("[7/" + TOT + "] Configurazione...");
            if (ok("test -f " + backupDir + "/my.cnf", 15)) {
                ok("cp -p " + backupDir + "/my.cnf /usr/local/etc/mysql/my.cnf", 30);
                ok("chmod 644 /usr/local/etc/mysql/my.cnf", 15);
                job.scrivi("    my.cnf ripristinato dalla copia");
            }
            JSONArray nativi = pf.optJSONArray("nativePasswordUsers");
            if (nativi != null && nativi.length() > 0) {
                job.scrivi("    " + nativi.length() + " account usano mysql_native_password: aggiungo mysql-native-password=ON");
                // In Java riga per riga, NON con sed: il sed di BSD non interpreta \n nella
                // sostituzione e inserirebbe la lettera "n" al posto di un a capo, producendo
                // un my.cnf malformato proprio nel passo che serve a non far restare fuori
                // nessun account. Su questa macchina il ramo non scatta, ma un difetto che non
                // si vede oggi e' solo un difetto che aspetta.
                job.scrivi("    " + (aggiungiDirettivaMysqld("mysql-native-password=ON")
                        ? "aggiunta al my.cnf" : "NON aggiunta: controlla il my.cnf a mano"));
            }

            job.avanza(8, TOT);
            job.scrivi("");
            job.scrivi("[8/" + TOT + "] Il mysqld 8.4 accetta la configurazione?");
            String bin = sh("which mysqld 2>/dev/null", 15);
            if (bin.isEmpty()) bin = "/usr/local/libexec/mysqld";
            String val = sh("su -m mysql -c '" + bin + " --validate-config' 2>&1", 120);
            if (!val.isEmpty()) {
                for (String l : val.split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
                if (val.toLowerCase().matches("(?s).*(error|unknown variable|aborting).*")) {
                    throw new IllegalStateException("il mysqld 8.4 non accetta il my.cnf: i dati non sono stati toccati, "
                            + "la copia e' in " + backupDir);
                }
            } else job.scrivi("    accettata senza segnalazioni");

            job.avanza(9, TOT);
            job.scrivi("");
            job.scrivi("[9/" + TOT + "] Primo avvio della 8.4 (riscrive il data dictionary: punto di non ritorno)...");
            ok("service mysql-server start", 120);
            String nuovaVer = "";
            for (int i = 0; i < 200; i++) {
                nuovaVer = mysqlOut("SELECT VERSION();").trim();
                if (!nuovaVer.isEmpty()) break;
                try { Thread.sleep(3000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                if (i % 5 == 4) job.scrivi("    ...in avvio da " + ((i + 1) * 3) + "s");
            }
            if (nuovaVer.isEmpty()) throw new IllegalStateException("MySQL 8.4 non risponde: la copia e' in " + backupDir);
            mysqlFermo = false;
            job.scrivi("    SELECT VERSION() = " + nuovaVer);
            if (!nuovaVer.startsWith("8.4")) throw new IllegalStateException("la versione attiva e' " + nuovaVer + ", non una 8.4");

            job.avanza(10, TOT);
            job.scrivi("");
            job.scrivi("[10/" + TOT + "] Inventario...");
            long sd = numero(mysqlOut("SELECT COUNT(*) FROM information_schema.schemata;"));
            long td = numero(mysqlOut("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys');"));
            long cd = numero(mysqlOut("SELECT COUNT(*) FROM mailboxes;"));
            job.scrivi("    schemi " + schemiPrima + " -> " + sd + ", tabelle " + tabellePrima + " -> " + td
                    + ", caselle " + casellePrima + " -> " + cd);
            boolean inventarioOk = sd >= schemiPrima && td >= tabellePrima && cd >= casellePrima;
            if (!inventarioOk) job.scrivi("    ALLARME: mancano oggetti rispetto a prima. La copia e' in " + backupDir);
            else job.scrivi("    inventario integro");

            job.avanza(11, TOT);
            job.scrivi("");
            job.scrivi("[11/" + TOT + "] Riproteggo i pacchetti e riavvio Postfix e Dovecot...");
            boolean l1 = ok("pkg lock -y mysql84-server", 30), l2 = ok("pkg lock -y mysql84-client", 30);
            job.scrivi("    protezione: mysql84-server " + (l1 ? "ok" : "FALLITA")
                    + ", mysql84-client " + (l2 ? "ok" : "FALLITA"));
            if (postfixEra) { ok("service postfix start", 120); job.scrivi("    postfix: " + (ok("service postfix status", 20) ? "attivo" : "NON attivo")); }
            if (dovecotEra) { ok("service dovecot start", 120); job.scrivi("    dovecot: " + (ok("service dovecot status", 20) ? "attivo" : "NON attivo")); }

            job.avanza(12, TOT);
            job.scrivi("");
            job.scrivi("[12/" + TOT + "] Prova funzionale: leggono davvero le caselle?");
            // "Il servizio e' attivo" non basta: dopo aver sostituito la libreria client il
            // punto e' se Postfix e Dovecot RIESCONO ANCORA a interrogare il database.
            boolean provaOk = true;
            // L'indirizzo finisce dentro un comando: si accetta solo cio' che e' davvero un
            // indirizzo. Viene dal database e non da fuori, ma la convalida costa una riga e
            // nel job di Dovecot c'era gia': trattare due volte la stessa cosa in due modi
            // diversi e' il modo in cui una svista sopravvive.
            if (!casellaProva.isEmpty()
                    && !casellaProva.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                job.scrivi("    l'indirizzo letto dal database non ha una forma riconoscibile: prova saltata");
                casellaProva = "";
            }
            if (casellaProva.isEmpty()) {
                job.scrivi("    nessuna casella utilizzabile: prova funzionale non eseguibile");
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
                    job.scrivi("    postfix interroga MySQL per " + casellaProva + ": "
                            + (pOk ? "SI (" + q.trim() + ") -> la libreria client nuova funziona"
                                   : "NO -> " + q.trim()));
                    if (!pOk) provaOk = false;
                } else {
                    job.scrivi("    " + mapFile + " non trovato: la prova sulla libreria client NON e' stata fatta");
                    provaOk = false;
                }

                // Questa invece prova meno di quanto sembri, e va detto: lo userdb qui e'
                // "static", quindi doveadm risponde senza interrogare il database. Dimostra
                // che Dovecot e' vivo e risolve gli utenti, non che il suo passdb SQL funzioni.
                String du = sh("doveadm user '" + casellaProva + "' 2>&1 | head -5", 60);
                boolean dOk = du.toLowerCase().contains("uid") || du.toLowerCase().contains("home");
                job.scrivi("    dovecot risolve " + casellaProva + ": " + (dOk ? "SI" : "NO -> " + du.trim())
                        + "  (userdb static: non prova il passdb SQL)");
                if (!dOk) provaOk = false;

                // Il percorso SQL di Dovecot si prova cosi': la stessa query che sta nel suo
                // dovecot-sql.conf, eseguita con le stesse credenziali.
                String righe = mysqlOut("SELECT COUNT(*) FROM mailboxes WHERE email='" + casellaProva
                        + "' AND active=1;").trim();
                boolean sOk = "1".equals(righe);
                job.scrivi("    la query di autenticazione di Dovecot trova " + casellaProva + ": "
                        + (sOk ? "SI" : "NO (risultato '" + righe + "')"));
                if (!sOk) provaOk = false;
            }

            job.scrivi("");
            job.scrivi("=== Stato dei servizi ===");
            boolean caduto = false;
            for (Map.Entry<String, Boolean> e : statoServizi().entrySet()) {
                job.scrivi("    " + e.getKey() + ": " + (e.getValue() ? "attivo" : "NON attivo"));
                if (!e.getValue()) caduto = true;
            }

            arrivatoInFondo = true;
            if (!inventarioOk || !provaOk || caduto || persi || !l1 || !l2) {
                job.status = "error";
                job.errorMessage = "Migrazione completata ma la verifica finale ha rilevato problemi: leggi il log. "
                        + "La copia per tornare indietro e' in " + backupDir + ".";
            } else {
                job.status = "completed";
                job.scrivi("");
                job.scrivi("=== MySQL " + nuovaVer + " in servizio, Postfix e Dovecot leggono le caselle ===");
                job.scrivi("La copia della 8.0 resta in " + backupDir + ": tienila finche' non sei sicuro.");
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi("");
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            if (!arrivatoInFondo) {
                if (mysqlFermo && !pacchettiSostituiti) {
                    job.scrivi("");
                    job.scrivi("Ripristino: i pacchetti non sono stati toccati, riaccendo la 8.0 e i servizi.");
                    ok("service mysql-server start", 120);
                    if (postfixEra) ok("service postfix start", 120);
                    if (dovecotEra) ok("service dovecot start", 120);
                } else if (pacchettiSostituiti) {
                    job.scrivi("");
                    job.scrivi("La 8.0 e' gia' stata disinstallata: non posso riaccenderla da qui.");
                    if (!backupDir.isEmpty()) job.scrivi("La copia integra e' in " + backupDir + ".");
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
            if (!Files.exists(f)) return r.put("errore", "config.inc.php non trovato in " + RC_DIR + "/config");
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
            if (ultimo == null) return r.put("errore", "nessun db_dsnw attivo riconoscibile in config.inc.php");
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
        String disp = pkg.isEmpty() ? "" : sh("pkg rquery %v " + pkg, 30);
        r.put("pkg", pkg).put("current", ver).put("available", disp);
        if (pkg.isEmpty()) {
            aggiungiCheck(checks, "pkg", "Roundcube installato", "block", "Nessun pacchetto roundcube installato.");
            block = true;
        } else if (disp.isEmpty() || disp.equals(ver)) {
            // Non e' un impedimento da risolvere: non c'e' niente da fare. Chiamarlo "blocco"
            // e poi scrivere "risolvi le righe rosse" mette l'utente a cercare un guasto che
            // non esiste — ed e' il contrario di cio' che la riga vuole dire.
            aggiungiCheck(checks, "pkg", "Roundcube installato", "ok",
                    disp.isEmpty()
                        ? pkg + " " + ver + ": il repository non risponde sulla versione disponibile, "
                          + "quindi non posso dire se ce ne sia una piu' recente."
                        : pkg + " " + ver + ": e' gia' l'ultima versione disponibile.");
            r.put("gia", !disp.isEmpty()).put("ignoto", disp.isEmpty());
            block = true;
        } else {
            aggiungiCheck(checks, "pkg", "Roundcube installato", "ok", pkg + " " + ver + " -> " + disp);
        }

        // La famiglia PHP richiesta dalla versione nuova deve essere quella installata.
        String phpInst = sh("pkg query %n 2>/dev/null | grep -E '^php[0-9]+$' | head -1", 20);
        Matcher mp = Pattern.compile("roundcube-php([0-9]+)").matcher(pkg);
        String phpRc = mp.find() ? "php" + mp.group(1) : "";
        boolean phpOk = phpRc.isEmpty() || phpRc.equals(phpInst);
        aggiungiCheck(checks, "php", "Versione di PHP", phpOk ? "ok" : "block",
                phpOk ? "Roundcube e' compilato per " + (phpRc.isEmpty() ? phpInst : phpRc)
                        + ", che e' quello installato."
                      : "Roundcube e' per " + phpRc + " ma il PHP installato e' " + phpInst
                        + ": vanno allineati prima.");
        if (!phpOk) block = true;

        // Lo script che aggiorna lo schema: senza, il passo non si puo' completare.
        boolean updatedb = ok("test -x " + RC_DIR + "/bin/updatedb.sh", 15)
                        || ok("test -f " + RC_DIR + "/bin/updatedb.sh", 15);
        aggiungiCheck(checks, "updatedb", "Script di aggiornamento schema", updatedb ? "ok" : "block",
                updatedb ? RC_DIR + "/bin/updatedb.sh presente."
                         : "Manca " + RC_DIR + "/bin/updatedb.sh: senza, lo schema del database non si aggiorna "
                           + "e la webmail resterebbe inutilizzabile dopo l'aggiornamento del pacchetto.");
        if (!updatedb) block = true;

        // Credenziali e stato del database, letti dalla configurazione di Roundcube.
        JSONObject dsn = dsnRoundcube();
        long tabelle = 0;
        if (!dsn.optBoolean("ok")) {
            aggiungiCheck(checks, "dsn", "Database della webmail", "block",
                    "Non riesco a leggere le credenziali dal config.inc.php: " + dsn.optString("errore", "")
                    + ". Senza, non posso ne' fare la copia ne' aggiornare lo schema.");
            block = true;
        } else {
            tabelle = numero(rcQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='"
                    + dsn.getString("db") + "';"));
            r.put("db", dsn.getString("db")).put("dbUser", dsn.getString("user")).put("tables", tabelle);
            if (tabelle == 0) {
                aggiungiCheck(checks, "dsn", "Database della webmail", "block",
                        "Il database " + dsn.getString("db") + " non risponde o non ha tabelle con le "
                        + "credenziali di Roundcube: non procedo alla cieca.");
                block = true;
            } else {
                aggiungiCheck(checks, "dsn", "Database della webmail", "ok",
                        dsn.getString("db") + " raggiungibile come utente " + dsn.getString("user")
                        + ", " + tabelle + " tabelle. A fine aggiornamento il pannello riconta.");
            }
        }

        // Non si annuncia una via di ritorno: si prova, adesso, davvero.
        JSONObject prova = provaCopia();
        String nomeDb = dsn.optBoolean("ok") ? dsn.getString("db") : "roundcubemail";
        if (!prova.optBoolean("ok")) {
            String ered = opzioniEreditate();
            String gtid = statoGtid();
            aggiungiCheck(checks, "copia", "Copia del database", "block",
                    "la prova di copia di " + nomeDb + " NON riesce, quindi non ci sarebbe via di "
                    + "ritorno e non si parte. Motivo: " + prova.optString("errore")
                    + (ered.isEmpty() ? ""
                       : "  ||  Opzioni che mysqldump si costruisce da solo, file di configurazione "
                         + "compresi: " + ered)
                    + (gtid.isEmpty() ? "  ||  Stato GTID del server: non leggibile."
                       : "  ||  Stato del server: " + gtid));
            block = true;
        } else if ("come utente root del database".equals(prova.optString("modo"))) {
            aggiungiCheck(checks, "copia", "Copia del database", "attendi",
                    "la copia di " + nomeDb + " riesce, ma solo entrando come root dal socket unix: "
                    + "come utente dell'applicazione non passa. Motivo dei tentativi precedenti: "
                    + prova.optString("storia") + "  ||  Stato del server: " + statoGtid()
                    + "  — la copia e' comunque una via di ritorno valida e provata adesso, ma sappi "
                    + "che sta usando piu' privilegi del minimo necessario.");
        } else if (!"completa".equals(prova.optString("modo"))) {
            aggiungiCheck(checks, "copia", "Copia del database", "attendi",
                    "la copia di " + nomeDb + " riesce, ma solo in modo ridotto (" + prova.getString("modo")
                    + "). Il tentativo completo non passa: " + prova.optString("storia")
                    + " — sullo schema di Roundcube non c'e' nulla di cio' che verrebbe escluso, "
                    + "quindi la copia resta una via di ritorno valida. E' provata adesso, non promessa.");
        } else {
            aggiungiCheck(checks, "copia", "Copia del database", "ok",
                    "provata adesso per davvero: un mysqldump senza dati di " + nomeDb
                    + " arriva fino in fondo. Prima di toccare qualsiasi cosa verra' copiato tutto, "
                    + "con il config.inc.php. L'aggiornamento dello schema non si annulla: e' l'unica "
                    + "via di ritorno, quindi si prova prima di averne bisogno.");
        }

        aggiungiCheck(checks, "opcache", "Cache del codice PHP", "verifica",
                "Dopo l'aggiornamento php-fpm viene riavviato: con OPcache attivo continuerebbe a servire il "
                + "codice vecchio gia' compilato in memoria, e la webmail sembrerebbe non aggiornata.");

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
            aggiungiCheck(checks, "root", "Radice del server web", "ok",
                    "la versione di arrivo (" + disp + ") non richiede la radice public_html");
        } else if (radici.length() == 0) {
            aggiungiCheck(checks, "root", "Radice del server web", "block",
                    "la " + disp + " pretende che nginx punti a .../public_html, ma in "
                    + "/usr/local/etc/nginx/ non trovo nessuna riga \"root\" che nomini roundcube: "
                    + "non so quale configurazione serve la webmail, quindi non posso ne' correggerla "
                    + "ne' garantire che resti funzionante. Dimmi dove sta e la aggiungo.");
            block = true;
        } else if (daSpostare.isEmpty()) {
            aggiungiCheck(checks, "root", "Radice del server web", "ok",
                    "nginx punta gia' a public_html: niente da cambiare");
        } else {
            aggiungiCheck(checks, "root", "Radice del server web", "attendi",
                    (gia17
                     ? "ATTENZIONE: sei GIA' sulla " + ver + ", che pretende la radice public_html, ma nginx "
                       + "punta ancora alla radice dell'applicazione. Se la webmail non risponde, e' questo. "
                     : "la " + disp + " pretende che nginx punti a .../public_html, altrimenti la webmail "
                       + "smette di funzionare. ")
                    + "La procedura corregge " + daSpostare.size() + " riga/e, controlla la configurazione "
                    + "con \"nginx -t\" PRIMA di ricaricare e, se nginx la rifiuta, rimette quella di "
                    + "prima: " + String.join(" ; ", daSpostare));
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
                    job.scrivi("    " + root + "/public_html non esiste: questa versione non lo usa,");
                    job.scrivi("    lascio la radice dov'e'. La prova via web dira' se e' un problema.");
                    return "nonserve";
                }
                String nome = file.replaceAll(".*/", "");
                ok("cp -p " + file + " " + backupDir + "/nginx-" + nome, 30);
                java.util.List<String> righe = Files.readAllLines(Paths.get(file));
                int n = x.getInt("riga") - 1;
                if (n < 0 || n >= righe.size()) { job.scrivi("    " + file + ": riga " + (n + 1) + " non c'e' piu'"); return "fallito"; }
                String vecchia = righe.get(n);
                if (!vecchia.contains(root)) { job.scrivi("    " + file + ":" + (n + 1) + " non contiene piu' " + root); return "fallito"; }
                // Puntare a una cartella che esiste non basta: dev'esserci cosa servire.
                if (!ok("test -f " + root + "/public_html/index.php", 10)) {
                    job.scrivi("    " + root + "/public_html esiste ma non contiene index.php:");
                    job.scrivi("    non sposto la radice su una cartella che non ha nulla da servire.");
                    return "fallito";
                }
                righe.set(n, vecchia.replace(root + ";", root + "/public_html;"));
                Files.write(Paths.get(file), righe);
                toccati.add(file);
                job.scrivi("    " + file + ":" + (n + 1) + "  root -> " + root + "/public_html");
            }
            if (toccati.isEmpty()) { job.scrivi("    nessuna riga da cambiare"); return "nonserve"; }

            // Prima di ricaricare: nginx accetta questa configurazione?
            String prova = sh("nginx -t 2>&1", 60);
            boolean buona = prova.toLowerCase().contains("syntax is ok") && prova.toLowerCase().contains("test is successful");
            if (!buona) {
                for (String l : prova.split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
                for (String f : toccati) {
                    String nome = f.replaceAll(".*/", "");
                    ok("cp -p " + backupDir + "/nginx-" + nome + " " + f, 30);
                }
                job.scrivi("    nginx ha rifiutato la configurazione: rimessa quella di prima, non ricarico");
                return "fallito";
            }
            job.scrivi("    nginx accetta la configurazione");
            String svc = nomeServizioReale("nginx");
            if (svc == null) { job.scrivi("    nginx non risulta fra i servizi: ricaricalo tu"); return "fallito"; }
            boolean ric = ok("service " + svc + " reload", 60);
            job.scrivi("    ricaricato: " + (ric ? "si" : "NO"));
            return ric ? "fatto" : "fallito";
        } catch (Exception e) {
            job.scrivi("    errore nello spostamento della radice: " + e.getMessage());
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
         + "--set-gtid-purged=OFF --routines --triggers", "completa", "app"},
        {"--single-transaction --no-tablespaces --skip-lock-all-tables --skip-flush-logs "
         + "--set-gtid-purged=OFF", "senza routine e trigger", "app"},
        {"--no-defaults --single-transaction --no-tablespaces --skip-lock-all-tables "
         + "--skip-flush-logs --set-gtid-purged=OFF", "ignorando i file di opzioni", "app"},
        {"--single-transaction --no-tablespaces --set-gtid-purged=OFF --routines --triggers",
         "come utente root del database", "root"},
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
        String tmp = "/var/db/mailpanel/prova-copia.sql";
        ok("mkdir -p /var/db/mailpanel", 20);
        JSONObject d = dsnRoundcube();
        if (!d.optBoolean("ok"))
            return new JSONObject().put("ok", false)
                    .put("errore", "credenziali non leggibili: " + d.optString("errore", "motivo non noto"));
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return new JSONObject().put("ok", false)
                    .put("errore", "mysqldump non e' installato o non e' nel PATH del pannello");
        StringBuilder storia = new StringBuilder();
        try {
            for (String[] m : MODI_COPIA) {
                if ("root".equals(m[2]) && !mysqlRootDisponibile()) {
                    storia.append("[").append(m[1]).append("] non provato: il pannello non entra "
                            + "in MySQL come root dal socket  ");
                    continue;
                }
                JSONObject e = rcDumpUnTentativo(m[0] + " --no-data",
                        connessioneCopia(m[2], d), "root".equals(m[2]) ? null : d.getString("pass"), tmp);
                if (e.optBoolean("ok"))
                    return new JSONObject().put("ok", true).put("modo", m[1])
                            .put("storia", storia.toString().trim());
                storia.append("[").append(m[1]).append("] ").append(e.optString("errore")).append("  ");
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
            return r.put("errore", "non riesco a leggere le credenziali da config.inc.php: "
                    + d.optString("errore", "motivo non noto"));
        String u = d.getString("user"), db = d.getString("db");
        String h = d.getString("host");
        String host = h.contains(":") ? h.substring(0, h.indexOf(':')) : h;
        if (!u.matches("[A-Za-z0-9_]{1,64}") || !db.matches("[A-Za-z0-9_]{1,64}")
                || !host.matches("[A-Za-z0-9._-]{1,128}"))
            return r.put("errore", "utente, database o host non hanno una forma valida: "
                    + u + "@" + host + "/" + db);
        if (!ok("which mysqldump >/dev/null 2>&1", 20))
            return r.put("errore", "mysqldump non e' installato o non e' nel PATH del pannello");

        StringBuilder storia = new StringBuilder();
        for (String[] t : MODI_COPIA) {
            if ("root".equals(t[2]) && !mysqlRootDisponibile()) {
                storia.append("[").append(t[1]).append("] non provato: nessun accesso root dal socket  ");
                continue;
            }
            JSONObject e = rcDumpUnTentativo(t[0], connessioneCopia(t[2], d),
                    "root".equals(t[2]) ? null : d.getString("pass"), destinazione);
            if (e.optBoolean("ok")) {
                r.put("ok", true).put("modo", t[1]);
                if (!t[1].equals("completa")) r.put("ridotto", storia.toString().trim());
                return r;
            }
            storia.append("[").append(t[1]).append("] ").append(e.optString("errore")).append("  ");
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
            // La password sta nell'ambiente e non nella riga di comando: cosi' non compare in ps.
            // Per il tentativo da root non c'e' password: entra dal socket unix.
            if (pass != null && !pass.isEmpty()) pb.environment().put("MYSQL_PWD", pass);
            Process pr = pb.start();
            if (!pr.waitFor(1800, java.util.concurrent.TimeUnit.SECONDS)) {
                pr.destroyForcibly();
                return r.put("errore", "mysqldump non e' tornato entro 30 minuti");
            }
            String messaggio = sh("cat " + err + " 2>/dev/null", 30).replace("\n", " ").trim();
            if (pr.exitValue() != 0)
                return r.put("errore", "uscito con codice " + pr.exitValue()
                        + (messaggio.isEmpty() ? " e nessun messaggio" : ": " + messaggio));
            // mysqldump chiude con "Dump completed": senza quella riga il file e' troncato,
            // e un file troncato che sembra un backup e' peggio di nessun backup.
            if (!ok("tail -3 " + dest + " | grep -q 'Dump completed'", 60))
                return r.put("errore", "uscito senza errori ma il file non finisce con "
                        + "\"Dump completed\": e' troncato"
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
        if (radici.length() == 0) return r.put("errore", "non trovo il blocco server della webmail");
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
        if (porta.isEmpty()) return r.put("errore", "non riesco a leggere la porta dal blocco server");
        if (nome.isEmpty()) {
            try { nome = org.mail_panel.Main.dbManager.getRoundcubeDomain(); } catch (Exception ignored) {}
        }
        if (nome == null || !nome.matches("[A-Za-z0-9._-]{1,255}"))
            return r.put("errore", "non riesco a stabilire il nome della webmail");
        // --resolve mette a posto sia il nome nell'intestazione Host sia quello nel TLS,
        // ma manda la richiesta all'indirizzo locale: e' il modo di parlare col server e basta.
        String url = "https://" + nome + ":" + porta + "/";
        String out = sh("curl -sk -m 20 -D - -o /dev/null --resolve " + nome + ":" + porta
                + ":127.0.0.1 " + url + " 2>&1", 60);
        Matcher mc = Pattern.compile("HTTP/[0-9.]+\\s+([0-9]{3})").matcher(out);
        String codice = mc.find() ? mc.group(1) : "";
        boolean cdn = out.toLowerCase().contains("cf-ray") || out.toLowerCase().contains("server: cloudflare");
        return r.put("ok", codice.startsWith("2") || codice.startsWith("3"))
                .put("codice", codice.isEmpty() ? "nessuna risposta" : codice)
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
    public static JSONObject sondaPathInfo() {
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
            if (url.isEmpty()) return new JSONObject().put("ok", false).put("errore", "URL non ricavabile");
            String n = url.replaceAll("^https://", "").replaceAll(":.*$", "");
            String porta = url.replaceAll(".*:", "").replaceAll("/.*$", "");
            String res = "--resolve " + n + ":" + porta + ":127.0.0.1 ";
            String u = "https://" + n + ":" + porta + "/" + nome + "/skins/elastic/deps/bootstrap.min.css";
            String out = sh("curl -sk -m 20 " + res + "'" + u + "' 2>&1 | head -c 1200", 60);
            return new JSONObject().put("ok", true).put("url", u).put("uscita", out.trim());
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
        if (out == null) return "(niente)";
        String t = out.trim();
        if (t.isEmpty()) return "(nessuna uscita)";
        String primo = t.length() > 200 ? t.substring(0, 200) : t;
        boolean sembraCss = t.contains("{") && (t.contains(";") || t.contains("}"));
        boolean sembraErrore = t.toLowerCase().contains("not found") || t.toLowerCase().contains("404")
                || t.toLowerCase().contains("fatal") || t.toLowerCase().contains("warning");
        return (sembraErrore ? "SEMBRA UN ERRORE" : sembraCss ? "SEMBRA IL CONTENUTO DEL FILE" : "uscita")
                + " (" + t.length() + "+ caratteri):\n" + primo.replace("\n", " ");
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
        if (!m.find()) return r.put("errore", "nella pagina non c'e' nessun link a un .css");
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
    public static JSONObject riparaNginxPathInfo(boolean esegui) {
        JSONObject r = new JSONObject();
        try {
            JSONArray radici = radiciNginxRoundcube();
            if (radici.length() == 0)
                return r.put("success", false).put("error", "non trovo il blocco server della webmail");
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
                        "nel blocco server non trovo nessun \"location\" per i file .php");
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
                        .put("nota", "il location dei .php gestisce gia' il percorso: niente da cambiare");
            if (haSplit && haTryFiles)
                r.put("motivo", "c'e' fastcgi_split_path_info, ma anche un \"try_files "
                        + "$fastcgi_script_name\" che lo annulla: la redirezione interna riscrive l'URI "
                        + "e PATH_INFO arriva vuota. Va tolta.");

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
                return r.put("success", false).put("error", "il blocco location non si chiude: non lo tocco");

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
                        "nel blocco non c'e' nessun fastcgi_pass: non so a chi passare le richieste");

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
                return r.put("success", false).put("error", "data di sistema non leggibile");
            String bk = "/var/db/mailpanel/nginx/" + ts;
            ok("mkdir -p " + bk, 30);
            if (!ok("cp -p " + file + " " + bk + "/nginx.conf", 30))
                return r.put("success", false).put("error", "non riesco a copiare " + file);

            java.util.List<String> out = new ArrayList<>(righe.subList(0, inizio));
            out.addAll(nuovo);
            out.addAll(righe.subList(fine + 1, righe.size()));
            Files.write(Paths.get(file), out);

            String prova = sh("nginx -t 2>&1", 60).toLowerCase();
            if (!(prova.contains("syntax is ok") && prova.contains("test is successful"))) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                return r.put("success", false).put("eseguito", false)
                        .put("error", "nginx ha rifiutato la configurazione, ho rimesso quella di prima: "
                                + sh("nginx -t 2>&1", 60).replace("\n", " "));
            }
            String svc = nomeServizioReale("nginx");
            if (svc == null || !ok("service " + svc + " reload", 60)) {
                ok("cp -p " + bk + "/nginx.conf " + file, 30);
                if (svc != null) ok("service " + svc + " reload", 60);
                return r.put("success", false).put("eseguito", false)
                        .put("error", "il ricaricamento di nginx non e' riuscito: rimessa quella di prima");
            }

            // La prova che conta: il CSS torna come CSS?
            JSONObject pw = provaWebmailOrigine();
            String nome = pw.optString("url", "").replaceAll("^https://", "").replaceAll(":.*$", "");
            String porta = pw.optString("url", "").replaceAll(".*:", "").replaceAll("/.*$", "");
            JSONObject css = nome.isEmpty() ? new JSONObject().put("ok", false).put("errore", "URL non ricavabile")
                                            : provaAssetCss(nome, porta);
            r.put("eseguito", true).put("backup", bk + "/nginx.conf").put("css", css);
            if (!css.optBoolean("ok")) {
                r.put("attenzione", "la configurazione e' stata applicata e nginx l'ha accettata, ma il "
                        + "foglio di stile non torna ancora come CSS: " + css.optString("risposta",
                        css.optString("errore")) + ". La copia di prima e' in " + bk + "/nginx.conf");
            }
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject roundcubeDiagnosi() {
        JSONObject r = new JSONObject();
        JSONArray voci = new JSONArray();
        try {
            // 1. Dove punta nginx adesso
            JSONArray radici = radiciNginxRoundcube();
            String root = radici.length() > 0 ? radici.getJSONObject(0).getString("root") : RC_DIR;
            String file = radici.length() > 0 ? radici.getJSONObject(0).getString("file") : "?";
            voci.put(new JSONObject().put("titolo", "Radice di nginx")
                    .put("testo", root + "   (da " + file + ")"));

            // 2. Il log di errore: e' li' che nginx dice PERCHE'
            String logPath = sh("grep -hE '^[[:space:]]*error_log' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 30).trim();
            if (!logPath.matches("/[A-Za-z0-9._/-]{1,200}")) logPath = "/var/log/nginx/error.log";
            String log = sh("tail -25 " + logPath + " 2>&1", 30);
            voci.put(new JSONObject().put("titolo", "Ultime righe di " + logPath)
                    .put("testo", log.isEmpty() ? "(vuoto)" : log));

            // 3. Permessi lungo tutto il cammino: basta una cartella non attraversabile
            StringBuilder perm = new StringBuilder();
            String[] pezzi = root.split("/");
            StringBuilder acc = new StringBuilder();
            for (String pz : pezzi) {
                if (pz.isEmpty()) continue;
                acc.append('/').append(pz);
                perm.append(sh("ls -ld " + acc + " 2>&1", 20)).append('\n');
            }
            voci.put(new JSONObject().put("titolo", "Permessi dalla radice del filesystem in giu'")
                    .put("testo", perm.toString().trim()));

            // 4. Cosa c'e' davvero nella cartella servita
            voci.put(new JSONObject().put("titolo", "Contenuto di " + root)
                    .put("testo", sh("ls -la " + root + " 2>&1 | head -25", 30)));

            // 5. Con quale utente gira nginx: e' lui che deve poter leggere
            String utente = sh("grep -hE '^[[:space:]]*user[[:space:]]' /usr/local/etc/nginx/nginx.conf "
                    + "2>/dev/null | head -1 | awk '{print $2}' | tr -d ';'", 20).trim();
            String proc = sh("ps -axo user,command 2>/dev/null | grep '[n]ginx: worker' | head -2", 30);
            voci.put(new JSONObject().put("titolo", "Utente di nginx")
                    .put("testo", "dichiarato nella configurazione: " + (utente.isEmpty() ? "(non dichiarato: nobody)" : utente)
                            + "\n" + (proc.isEmpty() ? "(nessun worker trovato)" : proc)));

            // 6. La risposta del SERVER, scavalcando qualunque cosa stia davanti
            JSONObject pw = provaWebmailOrigine();
            voci.put(new JSONObject().put("titolo", "Risposta del server (non di cio' che sta davanti)")
                    .put("testo", pw.optBoolean("ok")
                            ? pw.optString("url") + " risponde " + pw.optString("codice") + "\n\n"
                              + pw.optString("intestazioni")
                            : "NON risponde: " + pw.optString("codice", pw.optString("errore"))
                              + (pw.optBoolean("viaCdn") ? "  (attenzione: ha risposto una CDN, non il server)" : "")
                              + "\n\n" + pw.optString("intestazioni")));

            // 6b. Il .htaccess dice come Roundcube vuole essere servita: e' la fonte autorevole
            voci.put(new JSONObject().put("titolo", "Come Roundcube chiede di essere servita (" + root + "/.htaccess)")
                    .put("testo", sh("cat " + root + "/.htaccess 2>&1", 30)));

            // 6c. Gli asset: nella 1.7 passano da static.php, ed e' li' che nginx sbaglia di solito.
            if (pw.optBoolean("ok")) {
                String u = pw.optString("url");
                String nomeH = u.replaceAll("^https://", "").replaceAll(":.*$", "");
                String portaH = u.replaceAll(".*:", "").replaceAll("/.*$", "");
                JSONObject css = provaAssetCss(nomeH, portaH);
                voci.put(new JSONObject().put("titolo", "Prova di un foglio di stile")
                        .put("testo", css.optString("url", "(nessun link trovato)") + "\n  -> "
                            + css.optString("risposta", css.optString("errore"))
                            + (css.optBoolean("ok") ? "   (corretto)"
                               : "   <- NON e' un CSS: la pagina si apre ma senza grafica")
                            + "\n\nChi ha risposto: " + (css.optBoolean("daPhp")
                                ? "PHP (c'e' X-Powered-By): la richiesta E' arrivata a static.php, "
                                  + "quindi l'instradamento funziona e il problema e' dentro l'applicazione"
                                : "nginx (nessun X-Powered-By): la richiesta NON e' arrivata a PHP, "
                                  + "quindi il problema e' nell'instradamento")
                            + "\n\n" + css.optString("intestazioni", "")));

                // Il file che static.php dovrebbe servire esiste davvero sul disco?
                String pathInfo = css.optString("url", "").replaceAll(".*/static\\.php", "").replaceAll("\\?.*$", "");
                if (!pathInfo.isEmpty() && pathInfo.matches("/[A-Za-z0-9._/-]{1,200}")) {
                    String atteso = RC_DIR + pathInfo;
                    voci.put(new JSONObject().put("titolo", "Il file che static.php dovrebbe servire")
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
                    voci.put(new JSONObject().put("titolo", "static.php eseguito a mano (senza nginx)")
                            .put("testo",
                                "--- con PATH_INFO=" + pathInfo + " ---\n"
                                + riassumiUscita(conPathInfo)
                                + "\n\n--- senza PATH_INFO, solo REQUEST_URI=" + reqUri + " ---\n"
                                + riassumiUscita(senzaPathInfo)));
                }

                // Cosa riceve PHP passando da nginx: e' l'altra meta' della bisezione.
                JSONObject sonda = sondaPathInfo();
                voci.put(new JSONObject().put("titolo", "Cosa riceve PHP quando passa da nginx")
                        .put("testo", sonda.optBoolean("ok")
                            ? "richiesta di prova: " + sonda.optString("url") + "\n\n"
                              + sonda.optString("uscita")
                            : "non riuscita: " + sonda.optString("errore")));

                // Il codice vero installato su QUESTO server, non quello del repository a monte.
                voci.put(new JSONObject().put("titolo", "Le prime righe dello static.php installato")
                        .put("testo", sh("head -45 " + RC_DIR + "/public_html/static.php 2>&1", 30)));

                // PHP puo' essere confinato: se non gli e' permesso uscire da public_html,
                // static.php non raggiunge le skin e risponde 404 pur funzionando.
                voci.put(new JSONObject().put("titolo", "Limiti di PHP (open_basedir, chroot)")
                        .put("testo", sh("grep -rhnE '^[^;]*(open_basedir|chroot|chdir)' "
                            + "/usr/local/etc/php.ini /usr/local/etc/php-fpm.conf "
                            + "/usr/local/etc/php-fpm.d/ /usr/local/etc/php/ 2>/dev/null | head -12", 30)
                            .trim().isEmpty()
                            ? "nessun open_basedir, chroot o chdir impostato: PHP non e' confinato"
                            : sh("grep -rhnE '^[^;]*(open_basedir|chroot|chdir)' "
                                + "/usr/local/etc/php.ini /usr/local/etc/php-fpm.conf "
                                + "/usr/local/etc/php-fpm.d/ /usr/local/etc/php/ 2>/dev/null | head -12", 30)));
            }

            // 7. Il blocco server, come sta adesso sul disco
            if (!"?".equals(file)) {
                int riga = radici.getJSONObject(0).getInt("riga");
                int da = Math.max(1, riga - 12), a2 = riga + 22;
                voci.put(new JSONObject().put("titolo", "Il blocco server attorno alla riga " + riga)
                        .put("testo", sh("sed -n '" + da + "," + a2 + "p' " + file + " 2>&1", 30)));
            }
            return r.put("success", true).put("voci", voci);
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject avviaAggiornamentoRoundcube() {
        String id = "rc-" + System.currentTimeMillis();
        Job j = new Job(id, "roundcube");
        JOBS.put(id, j);
        Thread t = new Thread(() -> runAggiornamentoRoundcube(j), "roundcube-update");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
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
            job.scrivi("=== Aggiornamento di Roundcube ===");
            job.scrivi("");
            job.scrivi("[1/" + TOT + "] Controlli preliminari...");
            JSONObject pf = roundcubePreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = "I controlli preliminari hanno trovato un impedimento.";
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.scrivi("RIFIUTO DI PARTIRE.");
                return;
            }
            pkg = pf.optString("pkg", "");
            long tabellePrima = pf.optLong("tables", 0);
            job.scrivi("  " + pkg + " " + pf.optString("current") + " -> " + pf.optString("available"));
            job.scrivi("  database " + pf.optString("db") + ", " + tabellePrima + " tabelle");

            job.avanza(2, TOT);
            job.scrivi("");
            job.scrivi("[2/" + TOT + "] Copia del database e della configurazione...");
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("data non valida");
            backupDir = "/var/db/mailpanel/roundcube/" + ts;
            if (!ok("mkdir -p " + backupDir, 30)) throw new IllegalStateException("non riesco a creare " + backupDir);
            ok("cp -p " + RC_DIR + "/config/config.inc.php " + backupDir + "/config.inc.php", 30);
            JSONObject cp = rcDump(backupDir + "/roundcube.sql");
            if (!cp.optBoolean("ok")) {
                job.scrivi("    " + cp.optString("errore"));
                throw new IllegalStateException("la copia del database non e' riuscita: non procedo "
                        + "senza via di ritorno. Il motivo e' la riga qui sopra.");
            }
            if (cp.has("ridotto")) {
                job.scrivi("    copia RIDOTTA (" + cp.optString("modo") + "): il tentativo completo");
                job.scrivi("    non e' passato -> " + cp.getString("ridotto"));
                job.scrivi("    Sullo schema di Roundcube non cambia nulla, ma devi saperlo.");
            }
            job.scrivi("    copia verificata: " + backupDir + "/roundcube.sql ("
                    + numero(sh("wc -c < " + backupDir + "/roundcube.sql", 30)) / 1024 + " KB)");
            job.scrivi("    config.inc.php salvato");

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi("[3/" + TOT + "] Aggiorno il pacchetto...");
            if (bloccato(sh("pkg lock -l 2>/dev/null"), pkg)) {
                scriviStato(java.util.List.of(pkg));
                sbloccato = ok("pkg unlock -y " + pkg, 30);
                job.scrivi("    sbloccato temporaneamente");
            }
            String sim = sh("pkg upgrade -n " + pkg + " 2>&1", 300);
            if (sim.toLowerCase().contains("conflicts with")) {
                for (String l : sim.split("\n")) if (l.toLowerCase().contains("conflict")) job.scrivi("      " + l.trim());
                throw new IllegalStateException("l'aggiornamento sovrascriverebbe file di un altro pacchetto: mi fermo.");
            }
            StringBuilder cat = new StringBuilder();
            int code = eseguiConLog(job, "pkg upgrade -y " + pkg + " 2>&1", 1800, cat);
            if (code != 0) throw new IllegalStateException("pkg upgrade uscito con codice " + code);
            for (String m : messaggiCheChiedonoAzione(cat.toString())) {
                job.scrivi("    IL PACCHETTO CHIEDE: " + m.replace("\n", " | "));
            }

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi("[4/" + TOT + "] Configurazione...");
            // Il pacchetto puo' aver messo un config di esempio al posto del tuo.
            JSONObject dsnDopo = dsnRoundcube();
            if (!dsnDopo.optBoolean("ok")) {
                ok("cp -p " + backupDir + "/config.inc.php " + RC_DIR + "/config/config.inc.php", 30);
                job.scrivi("    config.inc.php ripristinato dalla copia (il pacchetto lo aveva sostituito)");
            } else job.scrivi("    config.inc.php intatto");

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi("[5/" + TOT + "] Aggiorno lo schema del database...");
            String out = sh("cd " + RC_DIR + " && php bin/updatedb.sh --package=roundcube --dir=SQL 2>&1", 900);
            for (String l : out.split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
            String ol = out.toLowerCase();
            if (ol.contains("error") || ol.contains("fatal") || ol.contains("failed")) {
                throw new IllegalStateException("updatedb.sh ha segnalato un errore: la copia del database e' in "
                        + backupDir + "/roundcube.sql");
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi("[6/" + TOT + "] Radice del server web...");
            String esitoRadice = "nonserve";
            if (pf.optBoolean("cambioRadice", false)) {
                esitoRadice = spostaRadiceNginx(job, backupDir);
                if ("fallito".equals(esitoRadice))
                    job.scrivi("    ATTENZIONE: la webmail non sara' raggiungibile finche' "
                            + "nginx non punta a .../public_html. Le copie sono in " + backupDir + ".");
            } else job.scrivi("    non serve cambiarla per questa versione");
            boolean radiceOk = !"fallito".equals(esitoRadice);

            job.avanza(7, TOT);
            job.scrivi("");
            job.scrivi("[7/" + TOT + "] Riavvio php-fpm per svuotare OPcache...");
            String svc = nomeServizioReale("php_fpm");
            if (svc != null) {
                ok("service " + svc + " restart", 120);
                job.scrivi("    " + svc + ": " + (ok("service " + svc + " status", 20) ? "attivo" : "NON attivo"));
            } else job.scrivi("    php-fpm non trovato fra i servizi");

            job.avanza(8, TOT);
            job.scrivi("");
            job.scrivi("[8/" + TOT + "] Verifica...");
            long tabelleDopo = numero(rcQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='"
                    + pf.optString("db") + "';"));
            job.scrivi("    tabelle: " + tabellePrima + " prima, " + tabelleDopo + " adesso");
            boolean tabOk = tabelleDopo >= tabellePrima;
            if (!tabOk) job.scrivi("    ALLARME: ci sono meno tabelle di prima.");

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
                job.scrivi("    prova via web NON eseguita: " + pw.optString("errore"));
                webOk = true;   // non provata non vuol dire guasta: non boccio cio' che non ho misurato
            } else if (webOk) {
                job.scrivi("    " + pw.optString("url") + " risponde " + pw.optString("codice")
                        + "  (interrogato il server, non cio' che sta davanti)");
            } else {
                job.scrivi("    " + pw.optString("url") + " risponde " + pw.optString("codice")
                        + "  <- non e' una risposta valida");
                if (pw.optBoolean("viaCdn"))
                    job.scrivi("    ATTENZIONE: ha risposto una CDN e non il server: la prova non vale.");
            }

            if (tabOk && webOk && radiceOk) {
                job.status = "completed";
                job.scrivi("");
                // "In servizio" si puo' dire solo se qualcuno l'ha visto rispondere. Senza quella
                // prova il lavoro puo' essere andato benissimo, ma il verdetto sarebbe piu' verde
                // delle prove che ho: allora lo dico, e la verifica la fai tu.
                job.scrivi(webProvata
                        ? "=== Roundcube aggiornato e in servizio ==="
                        : "=== Roundcube aggiornato — NON ho potuto verificare che risponda ===");
                if (!webProvata)
                    job.scrivi("Non conosco il dominio della webmail, quindi non l'ho interrogata: "
                            + "aprila nel browser prima di considerare finita questa operazione.");
                if ("nonserve".equals(esitoRadice) && pf.optBoolean("cambioRadice", false))
                    job.scrivi("La radice di nginx e' rimasta dov'era: questa build non usa public_html.");
                job.scrivi("La copia del database resta in " + backupDir + ".");
                job.scrivi("Entra nella webmail e verifica di vedere i tuoi messaggi prima di eliminarla.");
            } else {
                job.status = "error";
                job.errorMessage = "Aggiornamento eseguito ma la verifica finale non torna: la copia e' in " + backupDir;
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            if (sbloccato && !pkg.isEmpty()) {
                boolean r = ok("pkg info -e " + pkg, 15) && ok("pkg lock -y " + pkg, 30);
                job.scrivi("");
                job.scrivi("Riprotezione di " + pkg + ": " + (r ? "fatta" : "FALLITA"));
                if (r) pulisciStato();
            }
            job.fine = System.currentTimeMillis();
        }
    }

    // ===================== aggiornamento della JVM del pannello =====================

    private static final String JDK_DIR = "/var/db/mailpanel/jdk";

    /**
     * La riga di comando che riavvia QUESTO pannello, ricostruita dal processo vivo.
     *
     * Non si legge da uno script sul disco: quello potrebbe essere vecchio, assente, o non
     * essere quello con cui il pannello e' stato davvero acceso. Si prende la java in uso,
     * le opzioni con cui questa macchina virtuale e' partita e il file jar da cui questa
     * classe e' stata caricata. Se il pannello e' stato avviato con "java -jar x.jar" e basta,
     * la riga ricostruita e' altrettanto spoglia — ed e' giusto cosi': si riparte come si era.
     */
    public static String comandoAvvio(boolean soloWeb) {
        StringBuilder c = new StringBuilder(System.getProperty("java.home", "") + "/bin/java");
        for (String a : java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments()) {
            // Le opzioni di misurazione non si riportano: appartengono a chi stava osservando.
            if (a.startsWith("-agentlib") || a.startsWith("-javaagent") || a.startsWith("-Xdebug")) continue;
            c.append(' ').append(a);
        }
        String jar = percorsoJar();
        if (!jar.isEmpty()) c.append(" -jar ").append(jar);
        return soloWeb ? c.append(" --web").toString() : c.toString();
    }

    /** Il file jar da cui gira questo pannello, o stringa vuota se non e' un jar. */
    public static String percorsoJar() {
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
    public static String creaRunSh() {
        try {
            String jar = percorsoJar();
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
                + "exec " + comandoAvvio(false) + " \"$@\"\n");
            ok("chmod 700 " + f, 15);
            return "Creato " + f + " (avvio col menu, oppure ./run.sh --web per il solo server web).";
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

        String comando = comandoAvvio(true);

        return new JSONObject()
                .put("dir", dir)
                .put("comandoMenu", comandoAvvio(false))
                .put("jar", jar)
                .put("comando", comando)
                .put("riga", "/usr/sbin/daemon -f -- /bin/sh -c \"cd '" + dir + "' && exec " + comando + "\"")
                .put("nota", jar.isEmpty()
                        ? "non riesco a stabilire da quale file jar sto girando: senza quello non "
                          + "posso ricostruire il comando di riavvio"
                        : "il pannello riparte in modalita' solo-web, cioe' senza il menu a schermo: "
                          + "l'interfaccia web torna esattamente com'e' adesso. Per riavere anche il "
                          + "menu, quando vuoi, fermalo da SSH e rilancialo senza --web:  "
                          + comandoAvvio(false))
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
                aggiungiCheck(checks, "pkg", "JVM in uso", "block",
                        "il java che sta eseguendo il pannello (" + home + ") non appartiene a nessun "
                        + "pacchetto: non e' stato installato con pkg e non posso aggiornarlo io");
                return r.put("success", true).put("checks", checks)
                        .put("blocked", true).put("canProceed", false);
            }
            r.put("pkg", pkg);
            String vIns = sh("pkg query %v " + pkg + " 2>/dev/null").trim();
            String vRepo = sh("pkg rquery %v " + pkg + " 2>/dev/null").trim();
            r.put("current", vIns).put("available", vRepo).put("home", home);
            aggiungiCheck(checks, "pkg", "JVM in uso", "ok",
                    pkg + " " + vIns + "  (" + home + ") — e' proprio quella che esegue il pannello");
            if (vRepo.isEmpty()) {
                aggiungiCheck(checks, "ver", "Versione disponibile", "block",
                        "il repository non conosce " + pkg + ": controlla pkg update");
                blocca = true;
            } else if (vRepo.equals(vIns)) {
                aggiungiCheck(checks, "ver", "Versione disponibile", "ok",
                        "sei gia' all'ultima versione disponibile (" + vIns + "): non c'e' niente da fare");
                return r.put("success", true).put("checks", checks)
                        .put("blocked", false).put("canProceed", false).put("gia", true);
            } else {
                aggiungiCheck(checks, "ver", "Versione disponibile", "attendi",
                        vIns + "  ->  " + vRepo + " (stesso pacchetto, quindi " + home + " non cambia posto)");
            }

            JSONObject st = strategiaRiavvio();
            r.put("riavvio", st);
            if (!st.optBoolean("ok")) {
                aggiungiCheck(checks, "start", "Come il pannello verra' riacceso", "block", st.getString("nota"));
                blocca = true;
            } else {
                aggiungiCheck(checks, "start", "Come il pannello verra' riacceso", "attendi", st.getString("nota"));
                aggiungiCheck(checks, "cmd", "Comando di riavvio", "ok",
                        "in " + st.getString("dir") + ":  " + st.getString("comando"));
            }

            if (!ok("test -x /usr/sbin/daemon", 10)) {
                aggiungiCheck(checks, "daemon", "Distacco dello script", "block",
                        "manca /usr/sbin/daemon: senza, lo script morirebbe insieme al pannello");
                blocca = true;
            } else {
                aggiungiCheck(checks, "daemon", "Distacco dello script", "ok",
                        "lo script viene lanciato con daemon(8), quindi sopravvive alla chiusura del pannello");
            }

            // Via di ritorno: un pacchetto ricostruito dai file INSTALLATI, non scaricato dal
            // repository. Se il repository non ha piu' la versione vecchia, e' l'unico modo.
            long liberi = numero(sh("df -k /var/db | tail -1 | awk '{print $4}'", 30)) / 1024;
            long grande = numero(sh("pkg query %sb " + pkg + " 2>/dev/null", 30)) / 1024 / 1024;
            r.put("spazioMb", liberi).put("jdkMb", grande);
            if (grande > 0 && liberi < grande * 2) {
                aggiungiCheck(checks, "spazio", "Spazio per la via di ritorno", "block",
                        "servono almeno " + (grande * 2) + " MB in /var/db e ce ne sono " + liberi);
                blocca = true;
            } else {
                aggiungiCheck(checks, "spazio", "Spazio per la via di ritorno", "ok",
                        "prima di aggiornare, la JVM attuale (" + grande + " MB) viene impacchettata in "
                        + JDK_DIR + ": se la nuova non partisse, lo script rimette quella. "
                        + "Liberi in /var/db: " + liberi + " MB");
            }

            aggiungiCheck(checks, "down", "Interruzione", "attendi",
                    "l'interfaccia web resta irraggiungibile per circa un minuto. La posta NON si ferma: "
                    + "Postfix, Dovecot e Rspamd non c'entrano con la JVM e continuano a lavorare.");

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
    public static JSONObject avviaAggiornamentoJava() {
        try {
            JSONObject pf = javaPreflight();
            if (!pf.optBoolean("canProceed", false))
                return new JSONObject().put("success", false)
                        .put("error", pf.optBoolean("gia", false)
                                ? "Sei gia' all'ultima versione." : "I controlli preliminari non lo permettono.");
            String pkg = pf.getString("pkg");
            if (!nomeValido(pkg)) return new JSONObject().put("success", false).put("error", "nome pacchetto non valido");
            JSONObject st = pf.getJSONObject("riavvio");
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}"))
                return new JSONObject().put("success", false).put("error", "data di sistema non leggibile");
            String bk = JDK_DIR + "/" + ts;
            String log = bk + ".log";
            if (!ok("mkdir -p " + bk, 30))
                return new JSONObject().put("success", false).put("error", "non riesco a creare " + bk);

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
                        .put("error", "lo script generato non e' valido, non lo lancio: " + sint.trim());

            // Il pannello segna i pacchetti sbloccati: se lo script morisse a meta', al prossimo
            // avvio ripristinaLockDopoCrash() li riprotegge da solo.
            scriviStato(java.util.List.of(pkg));
            ok("/usr/sbin/daemon -f -- /bin/sh " + path, 30);
            return new JSONObject().put("success", true).put("log", log)
                    .put("nota", st.getString("nota"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    /** L'ultimo resoconto lasciato dallo script, da rileggere quando il pannello e' tornato su. */
    public static JSONObject statoAggiornamentoJava() {
        try {
            String ultimo = sh("ls -1t " + JDK_DIR + "/*.log 2>/dev/null | head -1").trim();
            if (ultimo.isEmpty())
                return new JSONObject().put("success", true).put("presente", false);
            String testo = sh("cat " + ultimo + " 2>/dev/null", 30);
            boolean finito = testo.contains("=== ESITO:");
            return new JSONObject().put("success", true).put("presente", true)
                    .put("file", ultimo).put("testo", testo).put("finito", finito)
                    .put("riuscito", testo.contains("=== ESITO: RIUSCITO"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    private static String scriptAggiornamentoJava(String pkg, String home, String bk, String log,
                                                  long pid, String rigaAvvio, String dir, int porta) {
        return "#!/bin/sh\n"
          + "# Generato dal pannello. Aggiorna la JVM su cui il pannello stesso gira.\n"
          + "exec >> '" + log + "' 2>&1\n"
          + "echo \"=== Aggiornamento JVM: $(date) ===\"\n"
          + "PKG='" + pkg + "'\n"
          + "BK='" + bk + "'\n"
          + "JAVA='" + home + "/bin/java'\n"
          + "\n"
          + "echo '[1/6] Impacchetto la JVM attuale come via di ritorno...'\n"
          + "if pkg create -o \"$BK\" \"$PKG\"; then\n"
          + "  # pkg create produce .pkg sulle versioni recenti e .txz su quelle piu' vecchie:\n"
          + "  # non lego la via di ritorno a una estensione, altrimenti sparirebbe senza motivo.\n"
          + "  VIA=$(ls -1 \"$BK\"/${PKG}-* 2>/dev/null | head -1)\n"
          + "  if [ -n \"$VIA\" ]; then echo \"      via di ritorno: $VIA\"; else\n"
          + "    echo '      ERRORE: pkg create non ha prodotto nessun file. Mi fermo.'\n"
          + "    echo '=== ESITO: ANNULLATO (nessuna via di ritorno, niente e stato toccato) ==='; exit 1; fi\n"
          + "else\n"
          + "  echo '      ERRORE: pkg create fallito. Mi fermo senza toccare niente.'\n"
          + "  echo '=== ESITO: ANNULLATO (nessuna via di ritorno, niente e stato toccato) ==='; exit 1\n"
          + "fi\n"
          + "\n"
          + "echo '[2/6] Fermo il pannello...'\n"
          + "kill " + pid + " 2>/dev/null\n"
          + "i=0\n"
          + "while kill -0 " + pid + " 2>/dev/null; do\n"
          + "  i=$((i+1)); [ $i -ge 45 ] && break; sleep 1\n"
          + "done\n"
          + "if kill -0 " + pid + " 2>/dev/null; then\n"
          + "  echo '      non si e fermato da solo dopo 45s: lo chiudo di forza'\n"
          + "  kill -9 " + pid + " 2>/dev/null; sleep 2\n"
          + "fi\n"
          + "echo '      fermo'\n"
          + "\n"
          + "echo '[3/6] Aggiorno il pacchetto...'\n"
          + "pkg unlock -y \"$PKG\"\n"
          + "if pkg upgrade -y \"$PKG\"; then ESITO_UP=0; else ESITO_UP=1; echo '      pkg upgrade FALLITO'; fi\n"
          + "\n"
          + "echo '[4/6] Verifico che java funzioni...'\n"
          + "if \"$JAVA\" -version 2>&1; then\n"
          + "  echo '      java risponde'\n"
          + "else\n"
          + "  echo '      java NON risponde: rimetto la versione di prima'\n"
          + "  pkg add -f \"$VIA\" && echo '      versione precedente rimessa' || echo '      RIPRISTINO FALLITO'\n"
          + "  \"$JAVA\" -version 2>&1 || echo '      java non risponde nemmeno adesso'\n"
          + "fi\n"
          + "\n"
          + "echo '[5/6] Riproteggo il pacchetto e riaccendo il pannello...'\n"
          + "pkg lock -y \"$PKG\" && echo '      riprotetto' || echo '      RIPROTEZIONE FALLITA'\n"
          + "cd '" + dir + "' || echo '      ATTENZIONE: non riesco a entrare in " + dir + "'\n"
          + rigaAvvio + "\n"
          + "\n"
          + "echo '[6/6] Attendo che il pannello risponda...'\n"
          + "SU=1\n"
          + (porta > 0
             ? "j=0\n"
             + "while [ $j -lt 90 ]; do\n"
             + "  # -46l e non -4l: la JVM puo' aprire il socket in IPv6, e con -4l il pannello\n"
             + "  # risulterebbe spento mentre e' su. Il grep serve a non contare la riga di intestazione.\n"
             + "  # Il confine finale non e' la fine riga: sockstat stampa un'altra colonna dopo\n"
             + "  # l'indirizzo locale. Con '$' non combacerebbe mai e il pannello risulterebbe\n"
             + "  # spento anche da acceso. Il confine e' uno spazio oppure la fine riga.\n"
             + "  if sockstat -46l -p " + porta + " 2>/dev/null | grep -qE '[:.]" + porta + "([[:space:]]|$)'; then SU=0; break; fi\n"
             + "  j=$((j+1)); sleep 1\n"
             + "done\n"
             + "[ $SU -eq 0 ] && echo '      il pannello ascolta sulla porta " + porta + "' "
             + "|| echo '      dopo 90s la porta " + porta + " non risponde ancora'\n"
             : "echo '      porta del pannello non nota: salto questa verifica'\nSU=0\n")
          + "\n"
          + "if [ $ESITO_UP -eq 0 ] && [ $SU -eq 0 ]; then\n"
          + "  echo \"=== ESITO: RIUSCITO ($(date)) ===\"\n"
          + "  echo \"La via di ritorno resta in $BK: puoi cancellarla quando sei sicuro.\"\n"
          + "else\n"
          + "  echo \"=== ESITO: DA CONTROLLARE ($(date)) ===\"\n"
          + "  echo \"upgrade=$ESITO_UP  pannello_su=$SU  via_di_ritorno=$VIA\"\n"
          + "fi\n";
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
                aggiungiCheck(checks, "ver", "Versione di Python", "ok",
                        "tutti i pacchetti Python installati sono gia' py" + nuovo + ": non c'e' niente da spostare");
                return r.put("success", true).put("checks", checks)
                        .put("canProceed", false).put("blocked", false).put("gia", true);
            }
            r.put("vecchio", vecchio);
            aggiungiCheck(checks, "ver", "Versione di Python", "attendi",
                    "sono installati pacchetti py" + vecchio + ", il predefinito dei port e' py" + nuovo);

            final String vec = vecchio;
            java.util.List<String> leaf = pythonDaSpostare(vec);
            long tot = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + vec + "-")).count();
            if (leaf.isEmpty()) {
                aggiungiCheck(checks, "leaf", "Pacchetti da spostare", "block",
                        "ci sono " + tot + " pacchetti py" + vecchio + " ma nessuno risulta installato su richiesta: "
                        + "sono tutti dipendenze di qualcos'altro, e vanno seguite quelle");
                blocca = true;
            } else {
                aggiungiCheck(checks, "leaf", "Pacchetti da spostare", "ok",
                        String.join(", ", leaf) + "  (piu' " + (tot - leaf.size())
                        + " dipendenze che seguiranno da sole)");
            }
            r.put("leaf", new JSONArray(leaf));

            // Esiste il corrispondente py312 per ognuno? Senza, il passaggio lascerebbe un buco.
            java.util.List<String> nuovi = new ArrayList<>(), mancanti = new ArrayList<>();
            for (String v : leaf) {
                String n = "py" + nuovo + "-" + v.substring(("py" + vecchio + "-").length());
                if (!nomeValido(n)) continue;
                if (sh("pkg rquery %n " + n + " 2>/dev/null").trim().isEmpty()) mancanti.add(n);
                else nuovi.add(n);
            }
            r.put("nuovi", new JSONArray(nuovi));
            if (!mancanti.isEmpty()) {
                aggiungiCheck(checks, "repo", "Disponibilita' nel repository", "block",
                        "non esiste il corrispondente py" + nuovo + " per: " + String.join(", ", mancanti));
                blocca = true;
            } else if (!nuovi.isEmpty()) {
                aggiungiCheck(checks, "repo", "Disponibilita' nel repository", "ok",
                        "il repository ha tutti i corrispondenti: " + String.join(", ", nuovi));
            }

            // Chi dipende dai pacchetti che sto per togliere? Se qualcuno dipende, toglierli
            // porterebbe via anche lui: e' esattamente il caso da non scoprire a cose fatte.
            // Attenzione all'ovvio che non e' ovvio: py311-certbot-nginx DIPENDE da py311-certbot,
            // e si spostano insieme. Un dipendente che fa parte della stessa famiglia py<vecchio>
            // non e' un problema, perche' sparisce e rinasce anche lui. Il problema e' solo un
            // dipendente ESTERNO, che resterebbe senza cio' da cui dipende.
            java.util.List<String> conDipendenti = new ArrayList<>();
            for (String v : leaf) {
                if (!nomeValido(v)) continue;
                java.util.List<String> esterni = new ArrayList<>();
                for (String d : sh("pkg query %rn " + v + " 2>/dev/null").split("\n")) {
                    String t = d.trim();
                    if (t.isEmpty() || t.startsWith("py" + vec + "-")) continue;
                    esterni.add(t);
                }
                if (!esterni.isEmpty()) conDipendenti.add(v + " <- " + String.join(", ", esterni));
            }
            if (!conDipendenti.isEmpty()) {
                aggiungiCheck(checks, "dip", "Chi dipende da questi pacchetti", "block",
                        "rimuoverli si porterebbe dietro altro: " + String.join(" ; ", conDipendenti));
                blocca = true;
            } else {
                aggiungiCheck(checks, "dip", "Chi dipende da questi pacchetti", "ok",
                        "nessun altro pacchetto dipende da quelli da spostare: si possono togliere da soli");
            }

            // Simulazione vera: e' l'unico modo di sapere quali file collidono.
            if (!nuovi.isEmpty()) {
                String sim = sh("pkg install -n " + String.join(" ", nuovi) + " 2>&1", 300);
                boolean coll = sim.toLowerCase().contains("conflicts with");
                r.put("conflitto", coll);
                if (coll) {
                    java.util.List<String> righe = new ArrayList<>();
                    for (String l2 : sim.split("\n")) if (l2.toLowerCase().contains("conflict")) righe.add(l2.trim());
                    aggiungiCheck(checks, "sim", "Simulazione dell'installazione", "attendi",
                            "i due gruppi si contendono gli stessi file, come previsto: "
                            + String.join(" | ", righe) + ". La procedura toglie prima i py" + vecchio
                            + " e poi installa, cosi' non c'e' nulla da forzare.");
                } else {
                    aggiungiCheck(checks, "sim", "Simulazione dell'installazione", "ok",
                            "nessuna collisione di file: si possono installare accanto ai vecchi");
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
            aggiungiCheck(checks, "svc", "Servizi coinvolti", "ok", serviziTocc.isEmpty()
                    ? "nessuno dei pacchetti corrisponde a un servizio attivo"
                    : String.join(", ", serviziTocc) + ": vengono fermati prima e riavviati dopo, con verifica");

            // Cosa toglierebbe autoremove. Se tocca roba che non e' py<vecchio>, non lo si esegue.
            JSONObject an = analizzaAutoremove(sh("pkg autoremove -n 2>&1", 180), "py" + vec + "-");
            java.util.List<String> estranei = jsonArrayToList(an.optJSONArray("estranei"));
            r.put("autoremoveEstranei", new JSONArray(estranei));
            if (!an.optBoolean("leggibile", false)) {
                aggiungiCheck(checks, "auto", "Pulizia finale (pkg autoremove)", "attendi",
                        "pkg rimuoverebbe qualcosa ma non riesco a leggerne l'elenco: la pulizia verra' SALTATA "
                        + "invece di essere eseguita alla cieca");
            } else {
                aggiungiCheck(checks, "auto", "Pulizia finale (pkg autoremove)", estranei.isEmpty() ? "ok" : "attendi",
                        estranei.isEmpty()
                        ? (an.optInt("quanti", 0) == 0 ? "non c'e' niente di orfano da togliere"
                           : "toglierebbe solo dipendenze py" + vec + " rimaste orfane ("
                             + an.optInt("quanti", 0) + ")")
                        : "toglierebbe anche pacchetti che non c'entrano con Python (" + String.join(", ", estranei)
                          + "): la pulizia verra' SALTATA e te lo dico alla fine");
            }

            aggiungiCheck(checks, "backup", "Copia delle configurazioni", "ok",
                    "prima di toccare i pacchetti vengono copiati /usr/local/etc/fail2ban e "
                    + "/usr/local/etc/letsencrypt, che sono i dati che non si ricreano");

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
        JSONArray problemi = new JSONArray(), innocui = new JSONArray(), citazioni = new JSONArray();
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
            String jar = percorsoJar();
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
            // La differenza la fanno due fatti verificabili: il file e' eseguibile, oppure sta
            // dove il sistema va a prendere cose da eseguire (cron, rc.d). Tutto il resto e'
            // molto probabilmente prosa, e non deve sbarrare una rimozione legittima — ma
            // finisce comunque in un elenco a parte, perche' "probabile" non e' "certo".
            boolean eseguibile = ok("test -x " + file, 10);
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
                            ? (prop.isEmpty() ? "(nessun pacchetto: scritto a mano)" : prop) : nome);
            v.put("eseguibile", eseguibile).put("postoDiEsecuzione", postoDiEsecuzione);
            if (dellaFamiglia) innocui.put(v);
            else if (eseguibile || postoDiEsecuzione) problemi.put(v);
            else citazioni.put(v);
        }
        return r.put("esaminati", esaminati).put("problemi", problemi).put("innocui", innocui)
                .put("citazioni", citazioni).put("comando", cmd);
    }

    public static JSONObject restiPython(boolean esegui) {
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
                        .put("nota", "non e' rimasto nessun pacchetto Python fuori dal predefinito py" + nuovo);
            r.put("vecchie", new JSONArray(vecchie));

            java.util.List<String> famiglia = new ArrayList<>();
            for (String v : vecchie)
                for (String n : sh("pkg query %n 2>/dev/null").split("\n"))
                    if (famigliaPython(n.trim(), v)) famiglia.add(n.trim());

            JSONArray dettaglio = new JSONArray();
            java.util.List<String> togliibili = new ArrayList<>(), trattenuti = new ArrayList<>();
            for (String n : famiglia) {
                if (!nomeValido(n)) continue;
                String ver = sh("pkg query %v " + n + " 2>/dev/null", 20).trim();
                long kb = numero(sh("pkg query %sb " + n + " 2>/dev/null", 20)) / 1024;
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
            r.put("riferimenti", rif);
            if (!esegui || togliibili.isEmpty()) return r.put("success", true).put("eseguito", false);
            if (rif.getJSONArray("problemi").length() > 0)
                return r.put("success", false).put("eseguito", false)
                        .put("error", "NON rimuovo: " + rif.getJSONArray("problemi").length()
                            + " file che resterebbero fanno riferimento al vecchio interprete. "
                            + "Guardali nell'anteprima: se sono cose che non usi piu', vanno tolte o "
                            + "aggiornate prima, altrimenti smetterebbero di funzionare senza preavviso.");

            // Passaggi ripetuti: a ogni giro si tolgono quelli che in QUEL momento non hanno
            // piu' nessuno che li richieda.
            JSONArray tolti = new JSONArray(), falliti = new JSONArray();
            java.util.List<String> restanti = new ArrayList<>(famiglia);
            for (int giro = 0; giro < 6 && !restanti.isEmpty(); giro++) {
                boolean qualcosa = false;
                for (String n : new ArrayList<>(restanti)) {
                    if (!nomeValido(n) || !ok("pkg info -e " + n, 15)) { restanti.remove(n); continue; }
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

    public static JSONObject avviaPassaggioPython() {
        String id = "py-" + System.currentTimeMillis();
        Job j = new Job(id, "python");
        JOBS.put(id, j);
        Thread t = new Thread(() -> runPassaggioPython(j), "python-move");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    private static void runPassaggioPython(Job job) {
        job.status = "running";
        final int TOT = 7;
        java.util.List<String> sbloccati = new ArrayList<>();
        java.util.List<String> daRibloccare = new ArrayList<>();
        try {
            job.avanza(1, TOT);
            job.scrivi("=== Passaggio dei pacchetti Python alla versione predefinita ===");
            job.scrivi("");
            job.scrivi("[1/" + TOT + "] Controlli preliminari...");
            JSONObject pf = pythonPreflight();
            if (!pf.optBoolean("canProceed", false)) {
                job.status = "error";
                job.errorMessage = pf.optBoolean("gia", false)
                        ? "Non c'e' niente da spostare." : "I controlli preliminari hanno trovato un impedimento.";
                JSONArray ck = pf.optJSONArray("checks");
                for (int i = 0; ck != null && i < ck.length(); i++) {
                    JSONObject c = ck.getJSONObject(i);
                    if (!"ok".equals(c.optString("level")))
                        job.scrivi("  [" + c.optString("level").toUpperCase() + "] " + c.optString("label")
                                + ": " + c.optString("detail"));
                }
                job.scrivi("RIFIUTO DI PARTIRE.");
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
            job.scrivi("[2/" + TOT + "] Copia delle configurazioni...");
            String ts = sh("date '+%Y%m%d-%H%M%S'", 15);
            if (!ts.matches("[0-9]{8}-[0-9]{6}")) throw new IllegalStateException("data non valida");
            String bk = "/var/db/mailpanel/python/" + ts;
            if (!ok("mkdir -p " + bk, 30)) throw new IllegalStateException("non riesco a creare " + bk);
            sh("pkg query '%n %v' > " + bk + "/pacchetti-prima.txt 2>/dev/null", 60);
            for (String d : new String[]{"/usr/local/etc/fail2ban", "/usr/local/etc/letsencrypt"}) {
                if (!ok("test -d " + d, 10)) { job.scrivi("    " + d + ": non esiste, niente da copiare"); continue; }
                String nome = d.substring(d.lastIndexOf('/') + 1);
                if (!ok("tar -cf " + bk + "/" + nome + ".tar -C " + d + " . 2>/dev/null", 300))
                    throw new IllegalStateException("copia di " + d + " non riuscita");
                long n = numero(sh("tar -tf " + bk + "/" + nome + ".tar 2>/dev/null | wc -l", 60));
                if (n < 1) throw new IllegalStateException("la copia di " + d + " risulta vuota");
                job.scrivi("    " + d + " -> " + nome + ".tar (" + n + " voci)");
            }
            job.scrivi("    copie in " + bk);

            job.avanza(3, TOT);
            job.scrivi("");
            job.scrivi("[3/" + TOT + "] Fermo i servizi coinvolti...");
            if (servizi.isEmpty()) job.scrivi("    nessuno");
            for (String s : servizi) {
                boolean era = ok("service " + s + " status", 20);
                if (era) { ok("service " + s + " stop", 120); job.scrivi("    " + s + ": fermato"); }
                else job.scrivi("    " + s + ": era gia' fermo");
            }

            job.avanza(4, TOT);
            job.scrivi("");
            job.scrivi("[4/" + TOT + "] Rimuovo i py" + vecchio + " e installo i py" + nuovo + "...");
            String elenco = sh("pkg lock -l 2>/dev/null");
            for (String v : leaf) if (bloccato(elenco, v)) { ok("pkg unlock -y " + v, 30); sbloccati.add(v); }
            if (!sbloccati.isEmpty()) {
                scriviStato(sbloccati);
                job.scrivi("    sbloccati: " + String.join(", ", sbloccati));
            }
            // L'ordine conta: prima togliere, poi installare. Cosi' nessun file va forzato,
            // ed e' esattamente l'errore che ha rotto il client MySQL.
            StringBuilder catDel = new StringBuilder();
            int cd = eseguiConLog(job, "pkg delete -y " + String.join(" ", leaf) + " 2>&1", 900, catDel);
            if (cd != 0) throw new IllegalStateException("pkg delete uscito con codice " + cd);
            StringBuilder catIns = new StringBuilder();
            int ci = eseguiConLog(job, "pkg install -y " + String.join(" ", nuovi) + " 2>&1", 1800, catIns);
            if (ci != 0) {
                job.scrivi("");
                job.scrivi("L'installazione e' fallita e adesso i pacchetti NON ci sono piu'.");
                job.scrivi("Per tornare indietro: pkg install -y " + String.join(" ", leaf));
                throw new IllegalStateException("pkg install uscito con codice " + ci);
            }
            daRibloccare.addAll(nuovi);
            for (String m : messaggiCheChiedonoAzione(catIns.toString()))
                job.scrivi("    IL PACCHETTO CHIEDE: " + m.replace("\n", " | "));

            job.avanza(5, TOT);
            job.scrivi("");
            job.scrivi("[5/" + TOT + "] Pulizia delle dipendenze rimaste orfane...");
            String ar = sh("pkg autoremove -n 2>&1", 180);
            JSONObject an = analizzaAutoremove(ar, "py" + vecchio + "-");
            java.util.List<String> estranei = jsonArrayToList(an.optJSONArray("estranei"));
            if (!an.optBoolean("leggibile", false)) {
                job.scrivi("    SALTATA: pkg dice che rimuoverebbe qualcosa, ma non riesco a leggere");
                job.scrivi("    l'elenco per controllarlo. Non eseguo una rimozione che non so descrivere.");
                for (String l2 : ar.split("\n")) if (!l2.trim().isEmpty()) job.scrivi("      " + l2);
            } else if (!estranei.isEmpty()) {
                job.scrivi("    SALTATA: toglierebbe anche " + String.join(", ", estranei)
                        + ", che non c'entrano con Python.");
                job.scrivi("    Restano delle librerie py" + vecchio + " inutilizzate: occupano spazio, non fanno danno.");
            } else if (an.optInt("quanti", 0) == 0) {
                job.scrivi("    non e' rimasto niente di orfano");
            } else {
                job.scrivi("    da togliere: " + String.join(", ", jsonArrayToList(an.optJSONArray("rimossi"))));
                eseguiConLog(job, "pkg autoremove -y 2>&1", 900);
            }

            job.avanza(6, TOT);
            job.scrivi("");
            job.scrivi("[6/" + TOT + "] Riavvio i servizi...");
            boolean serviziOk = true;
            for (String s : servizi) {
                ok("service " + s + " start", 120);
                boolean su = ok("service " + s + " status", 30);
                job.scrivi("    " + s + ": " + (su ? "attivo" : "NON ATTIVO"));
                if (!su) serviziOk = false;
            }
            if (servizi.isEmpty()) job.scrivi("    nessuno");

            job.avanza(7, TOT);
            job.scrivi("");
            job.scrivi("[7/" + TOT + "] Verifica che i comandi funzionino davvero...");
            // Che il pacchetto sia installato non dice che il comando parta: e' la lezione
            // del client MySQL, dove tutto risultava a posto e postmap non trovava la libreria.
            // Non indovino il nome del comando dal nome del pacchetto: per py311-fail2ban
            // sbaglierei (i comandi sono fail2ban-server e fail2ban-client, non "fail2ban").
            // Chiedo a pkg quali file eseguibili ha installato davvero.
            boolean comandiOk = true;
            for (String n : nuovi) {
                if (!nomeValido(n)) continue;
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
                            + (bene ? o.split("\n")[0].trim() : "FALLITO -> " + o.trim()));
                    if (!bene) comandiOk = false;
                }
                if (provati == 0) job.scrivi("    " + n + ": nessun eseguibile da provare (e' una libreria)");
            }
            long rimasti = sh("pkg query %n 2>/dev/null").lines().filter(x -> x.startsWith("py" + vecchio + "-")).count();
            job.scrivi("    pacchetti py" + vecchio + " ancora presenti: " + rimasti);

            if (serviziOk && comandiOk) {
                job.status = "completed";
                job.scrivi("");
                job.scrivi("=== Fatto: i pacchetti sono su py" + nuovo + " e i comandi rispondono ===");
                job.scrivi("Le copie restano in " + bk + ".");
            } else {
                job.status = "error";
                job.errorMessage = "Passaggio eseguito ma la verifica finale non torna. Copie in " + bk;
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            if (!daRibloccare.isEmpty()) {
                java.util.List<String> falliti = new ArrayList<>();
                for (String n : daRibloccare)
                    if (!(ok("pkg info -e " + n, 15) && ok("pkg lock -y " + n, 30))) falliti.add(n);
                job.scrivi("");
                job.scrivi("Riprotezione: " + (falliti.isEmpty()
                        ? "fatta su " + daRibloccare.size() + " pacchetti"
                        : "FALLITA su " + String.join(", ", falliti)));
                if (falliti.isEmpty()) pulisciStato();
            } else if (!sbloccati.isEmpty()) {
                job.scrivi("");
                job.scrivi("ATTENZIONE: erano stati sbloccati " + String.join(", ", sbloccati)
                        + " ma non sono stati sostituiti: controlla la scheda Protezione pacchetti.");
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
    public static JSONObject pianoManutenzione() {
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
        passi.put(rifacibile(passo("fase-protezione", "fase", "Proteggere tutti i pacchetti dello stack",
                tuttoProtetto ? "fatto" : "dafare",
                protetti + " su " + installati + " pacchetti sono protetti.",
                "Senza il lock, un aggiornamento puo' sostituire o rimuovere un pezzo del server di posta "
                + "senza che nessuno lo decida. E' il primo passo perche' rende sicuri tutti quelli dopo.",
                tuttoProtetto ? null : new JSONObject().put("tipo", "packages_lock_all")),
                new JSONObject().put("tipo", "packages_lock_all")));

        // --- Passo 2: aggiornare cio' che non e' protetto ---
        Matcher mUp = Pattern.compile("Number of packages to be upgraded:\\s*([0-9]+)").matcher(dry);
        int daAggiornare = mUp.find() ? Integer.parseInt(mUp.group(1)) : 0;
        Matcher mIn = Pattern.compile("Number of packages to be installed:\\s*([0-9]+)").matcher(dry);
        int daInstallare = mIn.find() ? Integer.parseInt(mIn.group(1)) : 0;
        boolean contornoAggiornato = (daAggiornare + daInstallare) == 0;
        passi.put(passo("fase-nonprotetti", "fase", "Aggiornare i pacchetti non protetti",
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
            if (coperto.test(nome)) continue;                 // ha gia' la sua fase dedicata
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
            passi.put(passo("pkg-" + nome, "pacchetto", titolo,
                    attendi ? "manuale" : "dafare",
                    nome + " " + v.getString("cur") + " -> " + v.getString("av")
                        + (v.getBoolean("maggiore") ? ", salto di versione significativo" : ", solo cifre finali"),
                    attendi ? v.getJSONObject("avv").getString("text")
                            : "Il pannello lo sblocca, lo aggiorna, riavvia i servizi che lo usano verificando "
                              + "che siano ripartiti davvero, e lo riprotegge.",
                    attendi ? null : new JSONObject().put("tipo", "package_update").put("package", nome)));
        }

        // --- Migrazione MySQL, se serve: sta QUI perche' e' un prerequisito di alcuni passi
        //     successivi (Postfix pretende la libreria della 8.4) e perche' viene dopo gli
        //     aggiornamenti di sicurezza indipendenti, che sono piu' urgenti e meno invasivi.
        //     Un piano che dice "prima fai X" senza contenere X non guida: manda a cercare.
        String srvMysql = sh("pkg query %n 2>/dev/null | grep -E '^mysql[0-9]+-server$' | head -1", 20);
        if (!srvMysql.isEmpty()) {
            boolean gia84 = srvMysql.startsWith("mysql84");
            String disp84 = gia84 ? "" : sh("pkg rquery %v mysql84-server 2>/dev/null", 30);
            if (gia84) {
                passi.put(passo("fase-mysql84", "fase", "Migrare MySQL alla 8.4", "fatto",
                        srvMysql + ": la migrazione e' gia' avvenuta.",
                        "Il port mysql80 verra' rimosso da FreeBSD dopo il 31/12/2026.", null));
            } else if (!disp84.isEmpty()) {
                passi.put(passo("fase-mysql84", "fase", "Migrare MySQL alla 8.4", "manuale",
                        srvMysql + " -> mysql84-server " + disp84
                        + ". Il port attuale sara' RIMOSSO da FreeBSD dopo il 31/12/2026.",
                        "Non e' un aggiornamento ma una sostituzione di pacchetti in conflitto, con copia "
                        + "fredda a database spento. Serve anche come prerequisito: i pacchetti che nel "
                        + "repository pretendono la libreria della 8.4 restano bloccati finche' non e' fatta. "
                        + "Usa la scheda \"Migrazione MySQL 8.0 -> 8.4\" qui sotto: per ora esegue solo la "
                        + "verifica dei prerequisiti.", null));
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
            String av = sh("pkg rquery %v " + nome + " 2>/dev/null", 20);
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
                passi.put(passo("pkg-" + nome, "pacchetto", "Aggiornare " + nome
                            + (memC.size() > 1 ? " e " + (memC.size() - 1) + " pacchetti collegati" : ""),
                        "manuale",
                        nome + " " + cur + " -> " + av + " (nessuna vulnerabilita' nota)",
                        "BLOCCATO da un vincolo di ordine: la versione nel repository richiede " + confl
                        + " mentre qui c'e' ancora la famiglia precedente, e le due sono in conflitto. "
                        + "Va fatta PRIMA la migrazione di MySQL, altrimenti questo aggiornamento "
                        + "sostituirebbe la libreria client sotto un server che la sta usando.",
                        null));
                continue;
            }
            java.util.List<String> mem = membriFamiglia(nome);
            String titolo = mem.size() > 1
                    ? "Aggiornare " + nome + " e " + (mem.size() - 1) + " pacchetti collegati"
                    : "Aggiornare " + nome;
            passi.put(passo("pkg-" + nome, "pacchetto", titolo, attendi ? "manuale" : "dafare",
                    nome + " " + cur + " -> " + av
                        + (maggiore ? ", salto di versione significativo" : ", solo cifre finali")
                        + " (nessuna vulnerabilita' nota)",
                    attendi ? avv.getString("text")
                            : (avv != null ? avv.getString("text")
                                           : "Aggiornamento senza avvertenze particolari."),
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
                ? numero(sh("find /var/db/rspamd -type f 2>/dev/null | wc -l", 60)) : 0;
        long unser = cartellaRspamd
                ? numero(sh("find /var/db/rspamd -type f -name '*.unser' 2>/dev/null | wc -l", 60)) : 0;
        if (rspamdPresente && !cartellaRspamd) {
            passi.put(passo("fase-rspamd-cache", "fase", "Cache di rspamd: posizione da verificare", "manuale",
                    "rspamd e' installato ma /var/db/rspamd non esiste.",
                    "Il port di rspamd 4.1 chiede di eliminare le cache Hyperscan da quella cartella. Non "
                    + "trovandola, il pannello non puo' dire se ci siano file da togliere: non e' un'assenza "
                    + "verificata, e' una domanda senza risposta. Su questa installazione la cache potrebbe "
                    + "stare altrove.", null));
        } else if (unser > 0) {
            passi.put(passo("fase-rspamd-cache", "fase", "Eliminare le cache Hyperscan di rspamd", "dafare",
                    unser + " file .unser in /var/db/rspamd, generati dalla versione precedente.",
                    "Il port di rspamd 4.1 chiede espressamente di rimuoverli: sono cache di espressioni "
                    + "regolari compilate dalla versione vecchia e possono far sbagliare la classificazione, "
                    + "cioe' spam che passa o posta buona scartata, senza che nulla sembri guasto. "
                    + "Sono file rigenerati da solo al primo avvio: non sono dati ne' configurazione.",
                    new JSONObject().put("tipo", "rspamd_clean_cache")));
        } else if (rspamdPresente && cartellaRspamd) {
            passi.put(passo("fase-rspamd-cache", "fase", "Cache Hyperscan di rspamd", "fatto",
                    "Nessun file .unser in /var/db/rspamd, che contiene " + fileRspamd + " file in tutto.",
                    "La pulizia chiesta dal port di rspamd 4.1 non serve: la cartella e' stata guardata ed "
                    + "e' pulita. Il conteggio degli altri file e' la prova che la ricerca ha funzionato "
                    + "davvero, invece di non trovare nulla perche' cercava nel posto sbagliato.", null));
        }

        // --- Passo finale: configurazione Dovecot dalla sorgente unica ---
        // Lo stato si ricava dal file vivo: l'intestazione la scrive solo il generatore nuovo.
        boolean rigenerata = ok("grep -q 'generato dal FreeBSD Mail Panel' "
                + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        boolean sieveAttivo = ok("grep -qE '^protocols.*sieve' " + DOVECOT_DIR + "/dovecot.conf 2>/dev/null", 15);
        passi.put(rifacibile(passo("fase-dovecot", "fase", "Rigenerare la configurazione Dovecot",
                rigenerata ? "fatto" : "dafare",
                rigenerata ? "La configurazione proviene gia' dalla sorgente unica del pannello."
                        + (sieveAttivo ? " ManageSieve attivo." : " ManageSieve non attivo.")
                    : "La configurazione attuale e' un misto di generatori diversi.",
                "Unifica i file con la sorgente unica, corregge il nome del database che due generatori "
                + "scrivevano sbagliato, e attiva ManageSieve se Pigeonhole e' installato. Prima di mettere "
                + "in servizio chiede a Dovecot se accetta la configurazione: se rifiuta, rimette quella "
                + "precedente senza riavviare.",
                rigenerata ? null : new JSONObject().put("tipo", "dovecot_config_regen")),
                new JSONObject().put("tipo", "dovecot_config_regen")));

        // --- Le tre operazioni che un semplice "pkg upgrade" non sa fare ---
        // Stanno nel piano anche se l'azione vive in una scheda dedicata: un piano che tace su
        // cio' che resta da fare dice implicitamente "sei a posto", e non e' vero. Lo stato e'
        // ricavato con interrogazioni leggere — niente simulazioni, che qui costerebbero minuti.

        // Roundcube: il pacchetto si aggiornerebbe da solo, ma il salto di versione maggiore
        // cambia lo SCHEMA del database, e senza bin/updatedb.sh la webmail non funziona.
        if (!rcPkg.isEmpty() && nomeValido(rcPkg)) {
            String cur = sh("pkg query %v " + rcPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery %v " + rcPkg + " 2>/dev/null", 20);
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
            passi.put(passo("fase-roundcube", "fase", "Aggiornare Roundcube con lo schema del database"
                        + (cveRc > 0 ? " (" + cveRc + " CVE)" : ""),
                    (daFareRc || rcIgnoto) ? "manuale" : "fatto",
                    rcIgnoto ? rcPkg + ": non riesco a sapere quale versione offre il repository "
                             + "(installata: " + (cur.isEmpty() ? "sconosciuta" : cur) + "). "
                             + "Non e' una conferma che sei aggiornato."
                        : !daFareRc ? rcPkg + " " + cur + ": ultima versione, e nginx punta a public_html."
                        : (av.equals(cur)
                           ? rcPkg + " " + cur + ": versione a posto, ma nginx punta ancora alla radice "
                             + "vecchia (" + radiceStorta + ") e la webmail non puo' funzionare."
                           : rcPkg + " " + cur + " -> " + av
                             + (radiceStorta != null ? ", e nginx punta ancora alla radice vecchia." : "")),
                    daFareRc
                    ? "NON usare l'aggiornamento normale: cambierebbe due cose sotto il naso. Primo, lo "
                      + "schema del database resterebbe quello vecchio. Secondo, dalla 1.7 Roundcube pretende "
                      + "che nginx punti alla sottocartella public_html, e qui punta alla radice: cosi' com'e' "
                      + "la webmail smetterebbe di rispondere. Usa la scheda \"Aggiornamento Roundcube\" qui "
                      + "sotto: copia il database, aggiorna, esegue bin/updatedb.sh, sposta la radice di nginx "
                      + "controllandola con \"nginx -t\" prima di ricaricare, svuota OPcache riavviando "
                      + "php-fpm e verifica che la webmail risponda davvero."
                    : "Quando ci sara' un aggiornamento, passera' dalla scheda dedicata: il salto di versione "
                      + "maggiore cambia lo schema del database e va fatto insieme, non dopo.", null));
        }

        // Python: py311 e py312 sono pacchetti diversi, non due versioni dello stesso.
        java.util.LinkedHashSet<String> pyVecchie = new java.util.LinkedHashSet<>();
        for (String n : sh("pkg query %n 2>/dev/null").split("\n")) {
            Matcher m = Pattern.compile("^py(3[0-9]{2})-").matcher(n.trim());
            if (m.find() && !m.group(1).equals(pyNuovo)) pyVecchie.add(m.group(1));
        }
        if (!pyVecchie.isEmpty()) {
            String elenco = String.join(", ", pythonDaSpostare(pyVecchie.iterator().next()));
            passi.put(passo("fase-python", "fase", "Spostare i pacchetti Python alla versione predefinita",
                    "manuale",
                    "py" + String.join("/py", pyVecchie) + " installati, il predefinito dei port e' py" + pyNuovo
                    + (elenco.isEmpty() ? "." : ": " + elenco),
                    "pkg upgrade non li toccherebbe mai, perche' py" + pyVecchie.iterator().next()
                    + "-qualcosa e py" + pyNuovo + "-qualcosa sono pacchetti con nomi diversi. Restano "
                    + "fermi su un Python che prima o poi esce dal supporto, senza che nulla lo segnali. "
                    + "Usa la scheda \"Passaggio dei pacchetti Python\" qui sotto.", null));
        } else {
            passi.put(passo("fase-python", "fase", "Spostare i pacchetti Python alla versione predefinita",
                    "fatto", "Tutti i pacchetti Python installati sono gia' py" + pyNuovo + ".",
                    "Non c'e' niente da spostare.", null));
        }

        // JVM: il pannello ci gira sopra, quindi non puo' aggiornarla restando acceso.
        if (!jvmPkg.isEmpty()) {
            String cur = sh("pkg query %v " + jvmPkg + " 2>/dev/null", 20);
            String av  = sh("pkg rquery %v " + jvmPkg + " 2>/dev/null", 20);
            // Tre stati, non due. Il repository che non risponde NON vuol dire "sei a posto":
            // vuol dire che non lo so, e dirlo e' l'unica risposta onesta.
            boolean jvIgnoto = cur.isEmpty() || av.isEmpty();
            boolean daFareJv = !jvIgnoto && !av.equals(cur);
            int cveJv = dettaglioVulnerabilita(audit, jvmPkg).getJSONArray("cve").length();
            passi.put(passo("fase-jvm", "fase", "Aggiornare la Java su cui gira il pannello"
                        + (cveJv > 0 ? " (" + cveJv + " CVE)" : ""),
                    (daFareJv || jvIgnoto) ? "manuale" : "fatto",
                    jvIgnoto ? jvmPkg + ": non riesco a sapere quale versione offre il repository "
                             + "(installata: " + (cur.isEmpty() ? "sconosciuta" : cur)
                             + "). Non e' una conferma che sei aggiornato: e' una domanda senza risposta."
                        : daFareJv ? jvmPkg + " " + cur + " -> " + av
                             : jvmPkg + " " + cur + ": e' gia' l'ultima versione disponibile.",
                    jvIgnoto
                    ? "Premi di nuovo \"Ricalcola il piano\". Il piano lancia gia' \"pkg update\", "
                      + "ma se il repository non era raggiungibile la risposta resta vuota. Finche' "
                      + "non lo so, non ti dico ne' di aggiornare ne' che sei a posto."
                    : daFareJv
                    ? "E' l'unico aggiornamento che il pannello non puo' fare restando acceso: sostituire "
                      + "i file della JVM sotto il processo vivo rompe l'avvio dei sottoprocessi, e da quel "
                      + "momento ogni stato mostrato qui sarebbe falso. Usa la scheda \"Aggiornamento della "
                      + "JVM del pannello\": uno script staccato impacchetta la Java attuale come via di "
                      + "ritorno, spegne il pannello, aggiorna e lo riaccende da solo. La posta non si ferma."
                    : "Quando ci sara' un aggiornamento, passera' dalla scheda dedicata: il pannello deve "
                      + "spegnersi per farlo.", null));
        }

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

    /** Pacchetti che sono librerie condivise: qui un "nessun dipendente" va preso con cautela. */
    private static final String LIBRERIE_CONDIVISE =
            "^(openssl[0-9]*|expat|libxml2|zlib|libiconv|pcre2?|curl|libssh2|nghttp2|icu|libsodium)$";

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
    private static final String[][] PROVA_CONFIG = {
        {"nginx",        "nginx -t"},
        {"postfix",      "postfix check"},
        {"dovecot",      "doveconf -n >/dev/null"},
        {"rspamd",       "rspamadm configtest"},
        {"mysql-server", "su -m mysql -c '$(which mysqld 2>/dev/null || echo /usr/local/libexec/mysqld) --validate-config'"},
    };

    private static String provaConfigDi(String servizio) {
        for (String[] r : PROVA_CONFIG) if (r[0].equals(servizio)) return r[1];
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
    private static final String[][] PROVA_DOPO = {
        {"redis", "redis-cli DBSIZE 2>/dev/null", "chiavi presenti in Redis"},
    };

    private static String[] provaDopoDi(String servizio) {
        for (String[] r : PROVA_DOPO) if (r[0].equals(servizio)) return r;
        return null;
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

        // I pacchetti che devono muoversi insieme si sbloccano e si aggiornano insieme:
        // altrimenti una dipendenza rimasta protetta blocca tutta l'operazione. Serve saperlo
        // subito, perche' da questo dipendono anche i servizi da riavviare.
        java.util.List<String> famiglia = membriFamiglia(nome);

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
                    if (!nomeValido(membro)) continue;
                    if (sh("pkg rquery %dn " + membro + " 2>/dev/null", 30).contains(richiesto)) {
                        if (chi.length() > 0) chi.append(", ");
                        chi.append(membro);
                    }
                }
                aggiungiCheck(checks, "mysqlfamiglia", "Versione di MySQL richiesta", "block",
                        "Nel repository " + (chi.length() > 0 ? chi.toString() : nome) + " richiede " + richiesto
                        + ", ma su questa macchina c'e' " + mysqlInstallato + ", e i due sono in conflitto. "
                        + "Aggiornarlo adesso o fallirebbe o sostituirebbe la libreria client mentre il server "
                        + "MySQL installato ne dipende ancora: sul server di posta significa Postfix o Dovecot "
                        + "che non leggono piu' le caselle. Va fatta PRIMA la migrazione di MySQL alla versione "
                        + richiesto.replace("-client", "") + ".");
                block = true;
                r.put("mysqlFamilyConflict", richiesto);
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

        // Servizi da riavviare. Il punto dolente: senza riavvio la correzione non entra in
        // servizio. E vanno calcolati su TUTTA la famiglia, non sul solo pacchetto nominato:
        // aggiornando mysql80-server insieme a mysql80-client, sono i programmi collegati al
        // CLIENT (Postfix, Dovecot, php-fpm) a tenersi in memoria la libreria vecchia. Guardare
        // il solo nome scritto nel passo li lascerebbe fuori, ed e' esattamente il caso in cui
        // la correzione risulta installata senza essere in servizio.
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
                if (nomeValido(d) && !famiglia.contains(d)) dipTrovati.put(d);
            }
        }
        r.put("reverseDeps", dipTrovati);
        aggiungiCheck(checks, "servizi", "Servizi da riavviare", "verifica",
                servizi.length() == 0
                    ? "Nessun servizio risulta dipendere da questo pacchetto. Prova: pkg riporta "
                      + (dipTrovati.length() == 0 ? "ZERO pacchetti dipendenti"
                                                  : dipTrovati.length() + " pacchetti dipendenti ("
                                                    + String.join(", ", jsonArrayToList(dipTrovati))
                                                    + "), nessuno dei quali e' un servizio")
                      + ". ATTENZIONE se questo pacchetto e' una libreria condivisa: i programmi "
                      + "collegati alla versione del SISTEMA BASE non compaiono qui, e potrebbero "
                      + "comunque tenersi in memoria quella vecchia."
                    : servizi.length() + " servizi verranno riavviati dopo l'aggiornamento, uno alla volta. "
                      + "Senza il riavvio continuerebbero a usare i file gia' caricati in memoria e la "
                      + "correzione non sarebbe in servizio, pur risultando installata.");

        if (Files.exists(Paths.get(STATO_MANUTENZIONE))) {
            aggiungiCheck(checks, "stato", "Nessuna manutenzione in sospeso", "block",
                    "Esiste uno stato di manutenzione non concluso in " + STATO_MANUTENZIONE
                    + ": riavvia il pannello, che lo ripristina da solo, e riprova.");
            block = true;
        }

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
        java.util.List<String> messaggiAzione = new ArrayList<>();
        boolean ricontrolloManuale = false;
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
            // L'output serve due volte: mostrato mentre scorre, e riletto alla fine per
            // ripescare i messaggi che chiedono un'azione.
            StringBuilder catturato = new StringBuilder();
            int code = eseguiConLog(job, "pkg upgrade -y" + elenco + " 2>&1", 1800, catturato);
            messaggiAzione = messaggiCheChiedonoAzione(catturato.toString());
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
            if (servizi.isEmpty()) {
                JSONArray rd = pf.optJSONArray("reverseDeps");
                job.scrivi("  Nessun servizio da riavviare. pkg riporta "
                        + (rd == null || rd.length() == 0 ? "zero pacchetti dipendenti"
                           : rd.length() + " pacchetti dipendenti: " + String.join(", ", jsonArrayToList(rd))));
                if (nome.matches(LIBRERIE_CONDIVISE)) {
                    job.scrivi("  ATTENZIONE: " + nome + " e' una libreria condivisa. Il fatto che nessun");
                    job.scrivi("  pacchetto la dichiari come dipendenza NON garantisce che nessun processo la");
                    job.scrivi("  stia usando: chi si collega alla copia del sistema base non compare in pkg.");
                    job.scrivi("  Verifica a mano che TLS funzioni (una casella in IMAPS, la webmail in HTTPS),");
                    job.scrivi("  e se vuoi essere certo riavvia postfix, dovecot e nginx dalla pagina Servizi.");
                    ricontrolloManuale = true;
                }
            }
            for (String s : servizi) {
                if (!Boolean.TRUE.equals(attivoPrima.get(s))) {
                    job.scrivi("    " + s + ": non era attivo prima, non lo avvio io");
                    continue;
                }
                // Si chiede al servizio se accetta la propria configurazione PRIMA di
                // riavviarlo: se non la accetta, riavviarlo lo spegnerebbe e basta. Meglio
                // lasciarlo in piedi con quella vecchia e dirlo.
                String prova = provaConfigDi(s);
                if (prova != null) {
                    Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), prova + " 2>&1");
                    if (!pr.success()) {
                        job.scrivi("    " + s + ": CONFIGURAZIONE RIFIUTATA, NON lo riavvio");
                        for (String l : pr.outputTrim().split("\n")) if (!l.trim().isEmpty()) job.scrivi("      " + l);
                        job.scrivi("      resta in servizio con la configurazione precedente: correggila e riavvialo a mano");
                        problemaServizi = true;
                        continue;
                    }
                    job.scrivi("    " + s + ": configurazione accettata");
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

                // Ha ritrovato i suoi dati, o e' ripartito vuoto?
                String[] dopo = provaDopoDi(s);
                if (dopo != null && attivo) {
                    String out = sh(dopo[1], 30).trim();
                    long n = numero(out);
                    job.scrivi("      " + dopo[2] + ": " + (out.isEmpty() ? "non leggibile" : String.valueOf(n)));
                    if (n == 0) {
                        job.scrivi("      ATTENZIONE: e' ripartito senza dati. Se ne conteneva prima, il");
                        job.scrivi("      contenuto non e' stato riletto: rspamd perderebbe addestramento,");
                        job.scrivi("      greylisting e limiti, continuando a sembrare sano.");
                        problemaServizi = true;
                    }
                }
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

            if (!messaggiAzione.isEmpty()) {
                job.scrivi("");
                job.scrivi("=== IL PACCHETTO CHIEDE UN'AZIONE ===");
                job.scrivi("Erano in mezzo all'output dell'aggiornamento e sarebbero passati inosservati:");
                for (String m : messaggiAzione) {
                    for (String l : m.split("\n")) if (!l.trim().isEmpty()) job.scrivi("  " + l);
                    job.scrivi("");
                }
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
            } else if (ricontrolloManuale) {
                // Non e' un errore, ma nemmeno un "fatto e verificato": dirlo completato
                // sarebbe affermare una cosa che il pannello non ha potuto controllare.
                job.status = "completed";
                job.scrivi("");
                job.scrivi("=== " + nome + " " + versioneDopo + " installato ===");
                job.scrivi("ATTENZIONE: nessun servizio e' stato riavviato. Se qualche processo usava la");
                job.scrivi("versione vecchia della libreria, la sta ancora usando. Verifica TLS a mano.");
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

    /**
     * Elimina SOLO le cache Hyperscan di rspamd e riavvia il servizio.
     *
     * E' una cancellazione, cioe' la categoria di operazione che puo' far sparire qualcosa:
     * il percorso e il criterio sono scritti qui e non arrivano dalla richiesta, e alla fine
     * il pannello DIMOSTRA di non aver toccato altro contando i file rimanenti prima e dopo.
     * "Ho cancellato solo quelli" e' un'affermazione, e le affermazioni si verificano.
     */
    public static JSONObject avviaPuliziaCacheRspamd() {
        String id = "rspamd-cache-" + System.currentTimeMillis();
        Job j = new Job(id, "rspamd_cache");
        JOBS.put(id, j);
        Thread t = new Thread(() -> {
            j.status = "running";
            try {
                final String DIR = "/var/db/rspamd";
                j.avanza(1, 4);
                j.scrivi("=== Pulizia delle cache Hyperscan di rspamd ===");
                j.scrivi("");
                j.scrivi("[1/4] Conto cosa c'e' adesso...");
                long unserPrima = numero(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long altriPrima = numero(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.scrivi("    file .unser da eliminare: " + unserPrima);
                j.scrivi("    altri file, che NON devono essere toccati: " + altriPrima);
                if (unserPrima == 0) {
                    j.status = "completed";
                    j.scrivi("    niente da fare.");
                    return;
                }
                for (String f : sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null", 60).split("\n")) {
                    if (!f.trim().isEmpty()) j.scrivi("      " + f.trim());
                }

                j.avanza(2, 4);
                j.scrivi("");
                j.scrivi("[2/4] Elimino...");
                ok("find " + DIR + " -type f -name '*.unser' -delete", 120);

                j.avanza(3, 4);
                j.scrivi("");
                j.scrivi("[3/4] Verifico di non aver toccato altro...");
                long unserDopo = numero(sh("find " + DIR + " -type f -name '*.unser' 2>/dev/null | wc -l", 60));
                long altriDopo = numero(sh("find " + DIR + " -type f ! -name '*.unser' 2>/dev/null | wc -l", 60));
                j.scrivi("    file .unser rimasti: " + unserDopo + " (attesi 0)");
                j.scrivi("    altri file: " + altriPrima + " prima, " + altriDopo + " adesso");
                if (altriDopo != altriPrima) {
                    j.status = "error";
                    j.errorMessage = "Sono spariti file che non dovevano essere toccati: "
                            + altriPrima + " prima, " + altriDopo + " adesso.";
                    j.scrivi("    ALLARME: " + j.errorMessage);
                    return;
                }
                j.scrivi("    nessun altro file toccato.");

                j.avanza(4, 4);
                j.scrivi("");
                j.scrivi("[4/4] Riavvio rspamd...");
                Shell.Result pr = Shell.runShell(Duration.ofSeconds(60), "rspamadm configtest 2>&1");
                if (!pr.success()) {
                    j.status = "error";
                    j.errorMessage = "rspamd non accetta la configurazione: NON lo riavvio.";
                    j.scrivi("    " + pr.outputTrim());
                    return;
                }
                j.scrivi("    configurazione accettata");
                String pidPrima = pidServizio("rspamd");
                ok("service rspamd restart", 120);
                boolean attivo = ok("service rspamd status", 30);
                String pidDopo = pidServizio("rspamd");
                j.scrivi("    rspamd: " + (attivo ? "attivo" : "NON attivo")
                        + (pidPrima.isEmpty() || pidDopo.isEmpty() ? "" : "  (pid " + pidPrima + " -> " + pidDopo + ")"));
                if (!attivo) {
                    j.status = "error";
                    j.errorMessage = "rspamd non e' ripartito: guarda /var/log/maillog.";
                } else {
                    j.status = "completed";
                    j.scrivi("");
                    j.scrivi("Cache eliminate: rspamd le rigenerera' da solo mentre lavora.");
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = e.getMessage();
                j.scrivi("ERRORE: " + e.getMessage());
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
    public static JSONObject pacchettiConLibrerieMancanti() {
        JSONArray rotti = new JSONArray();
        java.util.LinkedHashSet<String> librerieAssenti = new java.util.LinkedHashSet<>();
        for (String riga : sh("pkg query '%n %B' 2>/dev/null", 120).split("\n")) {
            String t = riga.trim();
            int sp = t.indexOf(' ');
            if (sp <= 0) continue;
            String nome = t.substring(0, sp).trim();
            String lib = t.substring(sp + 1).trim();
            if (!nomeValido(nome) || lib.isEmpty()) continue;
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
     * Chi dichiara cosa, sui client MySQL. Serve a rispondere con i fatti a una domanda che
     * altrimenti si risponde a intuito: perche' e' stato installato un client 9.7 quando il
     * predefinito dei port FreeBSD (Mk/bsd.default-versions.mk, rami main e 2026Q3) e' 8.4?
     *
     * Si guardano tre cose distinte, che e' facile confondere in una sola:
     *  - cosa dichiara il pacchetto INSTALLATO
     *  - cosa dichiara la versione nel REPOSITORY
     *  - quali pacchetti forniscono davvero la libreria contesa
     */
    public static JSONObject diagnosiClientMysql() {
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
                    .put("dipendenzeRepository", sh("pkg rquery %dn " + pk + " 2>/dev/null | tr '\n' ' '", 30))
                    .put("librerieRichieste", sh("pkg query %B " + pk + " 2>/dev/null | tr '\n' ' '", 30)));
        }
        r.put("dipendenti", dip);

        // Chi fornisce la libreria contesa, e da quale pacchetto proviene il file sul disco.
        r.put("fornisconoLib", sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20));
        r.put("fileLib", sh("ls -l /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20));
        // File che i due pacchetti si contendono: quanti ne ha persi la 8.4.
        r.put("conflitti", sh("pkg check -s mysql84-client 2>&1 | head -20", 180));
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
         "Un server fuori dal predefinito riceve pacchetti collegati costruiti per un'altra versione."},
        {"PHP", "8.4",
         "pkg query %n | grep -E '^php[0-9]+$'",
         "Roundcube e le estensioni portano la versione nel nome: fuori dal predefinito smettono di combaciare."},
        {"Python", "3.12",
         "pkg query %n | grep -E '^py[0-9]+-' | sed 's/-.*//' | sort -u | tr '\n' ' '",
         "I pacchetti py3NN fuori dal predefinito smettono di ricevere aggiornamenti senza che nulla lo segnali."},
        {"OpenSSL", "base",
         "pkg query %n | grep -E '^openssl[0-9]*$' | tr '\n' ' '",
         "Con SSL_DEFAULT=base i programmi usano l'OpenSSL del sistema, non il port: se il port e' installato, con ogni probabilita' nessuno lo usa."},
        {"Perl", "5.42",
         "pkg query %v perl5 2>/dev/null",
         "Molti strumenti di contorno ne dipendono."},
        {"Java", "25",
         "pkg query %n | grep -E '^openjdk[0-9]+$' | tr '\n' ' '",
         "E' il runtime del pannello."},
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
     *    (pkg query e pkg rquery su tutto) e si uniscono qui: interrogare pkg 41 volte per 41
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
    private static final String[][] FINE_SUPPORTO = {
        {"15.1", "31/03/2027", "releng/15.1, rilasciata il 16/06/2026"},
        {"15.0", "30/09/2026", "releng/15.0, rilasciata il 02/12/2025"},
        {"14.4", "31/12/2026", "releng/14.4, rilasciata il 10/03/2026"},
    };
    private static final String FONTE_SUPPORTO =
        "https://www.FreeBSD.org/security/ (letta il 31/08/2026). I rami stable sono supportati piu' "
      + "a lungo: stable/15 fino al 31/12/2029, stable/14 fino al 30/11/2028.";

    /**
     * Stato del sistema operativo di base: versione, livello di patch, riavvio necessario,
     * fine del supporto, aggiornamenti gia' scaricati.
     *
     * I pacchetti sono una meta' del server; l'altra e' il sistema sotto, che pkg non tocca e
     * che nessuna delle schede finora guardava. Tutto in sola lettura: "freebsd-update fetch"
     * SCARICA, quindi sta in un'azione separata e dichiarata, non qui dentro.
     */
    public static JSONObject sistemaOperativo() {
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
                if (e[0].equals(serie)) { eol = e[1]; noteEol = e[2]; }
            r.put("serie", serie).put("fineSupporto", eol).put("noteSupporto", noteEol)
             .put("fonteSupporto", FONTE_SUPPORTO);

            boolean release = userland.contains("-RELEASE");
            r.put("aggiornabileConFreebsdUpdate", release);
            if (!release) {
                r.put("notaAggiornamenti", "La userland non e' una -RELEASE (" + userland + "): "
                        + "freebsd-update vale per le release binarie, un sistema compilato dai "
                        + "sorgenti si aggiorna in un altro modo. Non do indicazioni che non valgono qui.");
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
    public static JSONObject cercaAggiornamentiSistema() {
        try {
            JSONObject so = sistemaOperativo();
            if (!so.optBoolean("aggiornabileConFreebsdUpdate", false))
                return new JSONObject().put("success", false)
                        .put("error", so.optString("notaAggiornamenti", "sistema non aggiornabile con freebsd-update"));
            String out = sh("freebsd-update --not-running-from-cron fetch 2>&1", 900);
            String b = out.toLowerCase();
            boolean nessuno = b.contains("no updates needed") || b.contains("has no updates available");
            return new JSONObject().put("success", true).put("uscita", out.trim())
                    .put("nessunAggiornamento", nessuno)
                    .put("nota", nessuno
                        ? "Nessun aggiornamento del sistema di base da applicare."
                        : "Le patch sono state SCARICATE, non installate. Per applicarle serve "
                          + "\"freebsd-update install\", e se toccano il kernel serve un riavvio: "
                          + "leggi sopra cosa cambierebbe prima di decidere.");
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage());
        }
    }

    public static JSONObject rapportoSistema() {
        StringBuilder t = new StringBuilder();
        try {
            ok("pkg update -q", 180);
            t.append("=== RAPPORTO DEL SISTEMA ===\n");
            t.append("data: ").append(sh("date '+%Y-%m-%d %H:%M:%S %Z'", 15)).append('\n');
            t.append("host: ").append(sh("hostname", 15)).append('\n');
            t.append("FreeBSD: ").append(sh("freebsd-version -kru 2>/dev/null | tr '\n' ' '", 20)).append('\n');
            t.append("ABI pkg: ").append(sh("pkg config abi 2>/dev/null", 20)).append('\n');

            JSONObject ramo = ramoRepository();
            JSONObject so = sistemaOperativo();
            t.append("\n--- SISTEMA OPERATIVO ---\n");
            t.append("kernel installato: ").append(so.optString("kernelInstallato"))
             .append("   in esecuzione: ").append(so.optString("uname")).append('\n');
            t.append("userland: ").append(so.optString("userland"))
             .append("   architettura: ").append(so.optString("arch")).append('\n');
            if (so.optBoolean("riavvioNecessario"))
                t.append("RIAVVIO NECESSARIO: il kernel installato non e' quello in esecuzione.\n");
            if (!so.optString("fineSupporto").isEmpty())
                t.append("fine supporto della ").append(so.optString("serie")).append(": ")
                 .append(so.optString("fineSupporto")).append("   (").append(so.optString("noteSupporto")).append(")\n");
            else
                t.append("fine supporto: serie non presente nella tabella del pannello, da riverificare\n");
            t.append("fonte: ").append(so.optString("fonteSupporto")).append('\n');
            if (so.has("giaPronti"))
                t.append("aggiornamenti di base gia' scaricati: ").append(so.optString("giaPronti")).append('\n');
            if (so.has("notaAggiornamenti"))
                t.append(so.optString("notaAggiornamenti")).append('\n');

            t.append("\n--- RAMO DEI PACCHETTI ---\n");
            t.append(ramo.optString("ramo")).append("   ").append(ramo.optString("url")).append('\n');
            t.append(ramo.optString("spiegazione")).append('\n');

            t.append("\n--- COERENZA CON I PREDEFINITI DEI PORT ---\n");
            JSONArray righe = coerenzaPredefiniti().optJSONArray("righe");
            for (int i = 0; righe != null && i < righe.length(); i++) {
                JSONObject x = righe.getJSONObject(i);
                t.append(String.format("%-10s atteso %-8s installato %-28s %s%n",
                        x.optString("componente"), x.optString("predefinito"),
                        x.optString("installato"), x.optString("esito")));
                if (x.has("fuoriPredefinito"))
                    t.append("           fuori dal predefinito: ").append(x.getString("fuoriPredefinito")).append('\n');
            }

            // Due interrogazioni sole, poi si uniscono: e' l'unico modo di non metterci minuti.
            java.util.Map<String, String> inst = new java.util.LinkedHashMap<>(), repo = new java.util.HashMap<>();
            for (String r2 : sh("pkg query '%n %v' 2>/dev/null", 120).split("\n")) {
                String[] c = r2.trim().split("\\s+");
                if (c.length == 2) inst.put(c[0], c[1]);
            }
            for (String r2 : sh("pkg rquery '%n %v' 2>/dev/null", 180).split("\n")) {
                String[] c = r2.trim().split("\\s+");
                if (c.length == 2) repo.put(c[0], c[1]);
            }
            String lock = sh("pkg lock -l 2>/dev/null");

            t.append("\n--- PACCHETTI DELLO STACK DI POSTA ---\n");
            t.append(String.format("%-28s %-22s %-22s %-9s %s%n",
                    "pacchetto", "installato", "nel repository", "protetto", "ruolo"));
            int diversi = 0;
            for (java.util.Map.Entry<String, String> e : inst.entrySet()) {
                String ruolo = ruoloDi(e.getKey());
                if (ruolo == null) continue;
                String disp = repo.getOrDefault(e.getKey(), "(assente)");
                boolean diff = !disp.equals(e.getValue()) && !"(assente)".equals(disp);
                if (diff) diversi++;
                t.append(String.format("%-28s %-22s %-22s %-9s %s%s%n",
                        e.getKey(), e.getValue(), disp,
                        bloccato(lock, e.getKey()) ? "si" : "NO", ruolo, diff ? "   <- aggiornabile" : ""));
            }
            t.append("pacchetti dello stack con una versione piu' recente nel repository: ").append(diversi).append('\n');

            t.append("\n--- VULNERABILITA' NOTE (pkg audit) ---\n");
            String audit = sh("pkg audit -F 2>&1", 240);
            t.append(audit.isEmpty() ? "(nessuna uscita)\n" : audit + "\n");
            t.append("\nPer ciascun pacchetto segnalato, se il repository offre gia' la correzione:\n");
            Matcher mv = Pattern.compile("(?m)^(\\S+?)-[0-9][^\\s]* is vulnerable:").matcher(audit);
            java.util.LinkedHashSet<String> visti = new java.util.LinkedHashSet<>();
            while (mv.find()) visti.add(mv.group(1));
            if (visti.isEmpty()) t.append("  (nessun pacchetto segnalato)\n");
            for (String n : visti) {
                String cur = inst.getOrDefault(n, "?"), av = repo.getOrDefault(n, "(assente)");
                t.append(String.format("  %-24s installato %-18s repository %-18s -> %s%n", n, cur, av,
                        "(assente)".equals(av) ? "il repository non lo conosce"
                        : av.equals(cur) ? "NESSUNA CORREZIONE DISPONIBILE (stessa versione)"
                        : "aggiornabile a " + av));
            }

            t.append("\n--- SERVIZI ---\n");
            for (String[] cand : SERVIZI) {
                String svc = null;
                for (String c : cand)
                    if (ok("test -f /usr/local/etc/rc.d/" + c + " -o -f /etc/rc.d/" + c, 10)) { svc = c; break; }
                if (svc == null) continue;
                t.append(String.format("  %-18s %s%n", svc, ok("service " + svc + " status", 20) ? "attivo" : "NON ATTIVO"));
            }

            t.append("\n--- SPAZIO ---\n");
            t.append(sh("df -h / /var /usr 2>/dev/null | sort -u", 30)).append('\n');
            t.append("\n=== FINE RAPPORTO ===\n");
            return new JSONObject().put("success", true).put("testo", t.toString());
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", e.getMessage())
                    .put("parziale", t.toString());
        }
    }

    public static JSONObject ramoRepository() {
        JSONObject r = new JSONObject();
        String url = "";
        for (String riga : sh("pkg -vv 2>/dev/null", 60).split("\n")) {
            Matcher m = Pattern.compile("url\\s*:\\s*\"?([^\",]+)").matcher(riga);
            if (m.find() && m.group(1).contains("pkg.FreeBSD.org")) { url = m.group(1).trim(); break; }
        }
        String ramo = url.contains("/quarterly") ? "quarterly"
                    : url.contains("/latest") ? "latest" : "non riconosciuto";
        String spiega;
        if ("quarterly".equals(ramo))
            spiega = "Ramo trimestrale: tagliato da HEAD a gennaio, aprile, luglio e ottobre. Riceve "
                   + "comunque le correzioni di sicurezza, anche come aggiornamento di versione, ma "
                   + "arrivano dopo che qualcuno le ha portate sul ramo — quindi piu' tardi che su "
                   + "\"latest\". E' il motivo per cui una correzione gia' pubblicata a monte puo' "
                   + "non essere ancora qui.";
        else if ("latest".equals(ramo))
            spiega = "Ramo continuo: le versioni arrivano appena la modifica al port e' accettata e il "
                   + "cluster di compilazione ha finito. Se una correzione non c'e' ancora, non e' il "
                   + "ramo a trattenerla.";
        else
            spiega = "Non riesco a stabilire il ramo dalla configurazione efficace di pkg.";
        return r.put("success", true).put("ramo", ramo).put("url", url).put("spiegazione", spiega)
                .put("dove", "configurazione efficace letta con \"pkg -vv\"; l'eventuale scelta "
                        + "personale sta in /usr/local/etc/pkg/repos/FreeBSD.conf, il predefinito "
                        + "in /etc/pkg/FreeBSD.conf");
    }

    public static JSONObject coerenzaPredefiniti() {
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
                    .put("installato", installato).put("esito", esito).put("perche", d[3]);
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
                    if (tok.isBlank() || !nomeValido(tok)) continue;
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
                .put("ramo", ramoRepository())
                .put("fonte", "Mk/bsd.default-versions.mk del repository ufficiale dei port FreeBSD "
                        + "(cgit.freebsd.org), rami main e 2026Q3 — coincidono. Verificato il 31/08/2026.")
                .put("avvertenza", "E' una fotografia datata, non una lettura dal vivo: il pannello non "
                        + "va su internet. Va riverificata quando cambia il trimestre.");
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
    public static JSONObject avviaPuliziaClientEstraneo(String estraneo, String corretto) {
        if (!nomeValido(estraneo) || !nomeValido(corretto)
                || !estraneo.matches("mysql[0-9]+-client") || !corretto.matches("mysql[0-9]+-client")) {
            return new JSONObject().put("success", false).put("error", "nomi non validi");
        }
        String id = "cleanclient-" + System.currentTimeMillis();
        Job j = new Job(id, "clean_client");
        JOBS.put(id, j);
        Thread t = new Thread(() -> {
            j.status = "running";
            boolean sbloccato = false;
            try {
                j.avanza(1, 5);
                j.scrivi("=== Rimozione di " + estraneo + " e ripristino di " + corretto + " ===");
                j.scrivi("");
                j.scrivi("[1/5] Controllo che nessuno dipenda da " + estraneo + "...");
                String dip = sh("pkg query %rn " + estraneo + " 2>/dev/null", 30).trim();
                if (!dip.isEmpty()) {
                    j.status = "error";
                    j.errorMessage = "Qualcuno dipende da " + estraneo + ": " + dip.replace("\n", " ")
                            + ". Rimuoverlo li lascerebbe senza libreria: mi fermo.";
                    j.scrivi("    " + j.errorMessage);
                    return;
                }
                j.scrivi("    nessun pacchetto dipende da " + estraneo + ": si puo' rimuovere.");
                String libPrima = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.scrivi("    la libreria condivisa appartiene a: " + (libPrima.isEmpty() ? "(nessuno)" : libPrima));

                j.avanza(2, 5);
                j.scrivi("");
                j.scrivi("[2/5] Rimuovo " + estraneo + "...");
                for (String l : sh("pkg delete -y " + estraneo + " 2>&1", 300).split("\n")) {
                    if (!l.trim().isEmpty()) j.scrivi("    " + l);
                }

                j.avanza(3, 5);
                j.scrivi("");
                j.scrivi("[3/5] Ripristino i file di " + corretto + "...");
                if (bloccato(sh("pkg lock -l 2>/dev/null"), corretto)) {
                    scriviStato(java.util.List.of(corretto));
                    sbloccato = ok("pkg unlock -y " + corretto, 30);
                    j.scrivi("    sbloccato temporaneamente");
                }
                int code = eseguiConLog(j, "pkg install -f -y " + corretto + " 2>&1", 900);
                if (code != 0) throw new IllegalStateException("pkg install uscito con codice " + code);

                j.avanza(4, 5);
                j.scrivi("");
                j.scrivi("[4/5] Verifica dell'integrita' dei file...");
                String chk = sh("pkg check -s " + corretto + " 2>&1", 300);
                long difformi = 0;
                for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) difformi++;
                j.scrivi("    file con contenuto difforme: " + difformi + " (attesi 0)");
                if (difformi > 0) {
                    for (String l : chk.split("\n")) if (l.contains("checksum mismatch")) j.scrivi("      " + l.trim());
                }

                j.avanza(5, 5);
                j.scrivi("");
                j.scrivi("[5/5] La posta legge ancora le caselle?");
                String libDopo = sh("pkg which -q /usr/local/lib/mysql/libmysqlclient.so.24 2>/dev/null", 20).trim();
                j.scrivi("    la libreria condivisa appartiene a: " + (libDopo.isEmpty() ? "(NESSUNO: manca!)" : libDopo));
                JSONArray rotti = pacchettiConLibrerieMancanti().getJSONArray("packages");
                j.scrivi("    pacchetti senza libreria: " + rotti.length() + " (attesi 0)");
                String casella = mysqlOut("SELECT email FROM mailboxes WHERE active=1 LIMIT 1;").trim();
                boolean postfixOk = true;
                if (casella.matches("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}")) {
                    String q = sh("postmap -q '" + casella + "' mysql:/usr/local/etc/postfix/mysql-virtual-mailboxes.cf 2>&1", 60);
                    String ql = q.toLowerCase();
                    postfixOk = !q.trim().isEmpty() && !ql.contains("error") && !ql.contains("fatal")
                            && !ql.contains("not found") && !ql.contains("dlopen") && !ql.startsWith("postmap:");
                    j.scrivi("    postfix risolve " + casella + ": " + (postfixOk ? "SI (" + q.trim() + ")" : "NO -> " + q.trim()));
                }
                if (difformi == 0 && rotti.length() == 0 && !libDopo.isEmpty() && postfixOk) {
                    j.status = "completed";
                    j.scrivi("");
                    j.scrivi("=== Stato ripulito: un solo client MySQL, file integri, posta funzionante ===");
                } else {
                    j.status = "error";
                    j.errorMessage = "La pulizia ha lasciato qualcosa fuori posto: leggi il log.";
                }
            } catch (Exception e) {
                j.status = "error";
                j.errorMessage = e.getMessage();
                j.scrivi("ERRORE: " + e.getMessage());
            } finally {
                if (sbloccato) {
                    boolean r = ok("pkg info -e " + corretto, 15) && ok("pkg lock -y " + corretto, 30);
                    j.scrivi("");
                    j.scrivi("Riprotezione di " + corretto + ": " + (r ? "fatta" : "FALLITA"));
                    if (r) pulisciStato();
                }
                j.fine = System.currentTimeMillis();
            }
        }, "clean-client");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    public static JSONObject avviaRicollegamento() {
        String id = "relink-" + System.currentTimeMillis();
        Job j = new Job(id, "relink");
        JOBS.put(id, j);
        Thread t = new Thread(() -> runRicollegamento(j), "relink");
        t.setDaemon(true);
        t.start();
        return new JSONObject().put("success", true).put("jobId", id).put("async", true);
    }

    /**
     * Reinstalla dal repository i pacchetti rimasti senza la libreria che pretendono, cosi'
     * tornano collegati a quella presente, e rimette in servizio cio' che ne dipende.
     */
    private static void runRicollegamento(Job job) {
        job.status = "running";
        java.util.List<String> sbloccati = new ArrayList<>();
        try {
            job.avanza(1, 5);
            job.scrivi("=== Ricollegamento dei pacchetti alla libreria presente ===");
            job.scrivi("");
            job.scrivi("[1/5] Cerco chi pretende una libreria che non c'e'...");
            JSONObject d = pacchettiConLibrerieMancanti();
            JSONArray rotti = d.getJSONArray("packages");
            if (rotti.length() == 0) {
                job.scrivi("    nessuno: tutti i pacchetti trovano le librerie che richiedono.");
                job.status = "completed";
                return;
            }
            java.util.LinkedHashSet<String> nomi = new java.util.LinkedHashSet<>();
            for (int i = 0; i < rotti.length(); i++) {
                JSONObject o = rotti.getJSONObject(i);
                job.scrivi("    " + o.getString("name") + " richiede " + o.getString("lib") + ", assente");
                nomi.add(o.getString("name"));
            }

            job.avanza(2, 5);
            job.scrivi("");
            job.scrivi("[2/5] Sblocco temporaneo...");
            String lock = sh("pkg lock -l 2>/dev/null");
            java.util.List<String> daSbloccare = new ArrayList<>();
            for (String n : nomi) if (bloccato(lock, n)) daSbloccare.add(n);
            if (!daSbloccare.isEmpty()) {
                scriviStato(daSbloccare);
                for (String n : daSbloccare) {
                    if (ok("pkg unlock -y " + n, 30)) { sbloccati.add(n); job.scrivi("    " + n + ": sbloccato"); }
                }
            } else job.scrivi("    nessuno era protetto");

            job.avanza(3, 5);
            job.scrivi("");
            job.scrivi("[3/5] Reinstallo dal repository...");
            StringBuilder el = new StringBuilder();
            for (String n : nomi) el.append(' ').append(n);
            // PRIMA una simulazione: se pkg segnala conflitti di file, ci si ferma.
            // "-f" serve a forzare la REINSTALLAZIONE, ma forza anche il passare sopra ai
            // conflitti — e sono due cose diverse. Averle confuse ha fatto sovrascrivere i
            // file del client MySQL 8.4 con quelli di un altro pacchetto.
            String simulazione = sh("pkg install -f -n" + el + " 2>&1", 600);
            if (simulazione.toLowerCase().contains("conflicts with")) {
                job.scrivi("    pkg segnala CONFLITTI DI FILE: mi fermo senza installare nulla.");
                for (String l : simulazione.split("\n")) {
                    if (l.toLowerCase().contains("conflict")) job.scrivi("      " + l.trim());
                }
                throw new IllegalStateException("l'operazione sovrascriverebbe file di un altro pacchetto: "
                        + "va deciso a mano quale pacchetto deve restare, non forzato.");
            }
            int code = eseguiConLog(job, "pkg install -f -y" + el + " 2>&1", 1800);
            if (code != 0) throw new IllegalStateException("pkg install uscito con codice " + code);

            job.avanza(4, 5);
            job.scrivi("");
            job.scrivi("[4/5] Riavvio i servizi coinvolti...");
            java.util.LinkedHashSet<String> servizi = new java.util.LinkedHashSet<>();
            for (String n : nomi) servizi.addAll(serviziDaRiavviare(n));
            for (String logico : servizi) {
                String reale = nomeServizioReale(logico);
                if (reale == null) continue;
                String prova = provaConfigDi(reale);
                if (prova != null && !Shell.runShell(Duration.ofSeconds(60), prova + " 2>&1").success()) {
                    job.scrivi("    " + reale + ": configurazione rifiutata, NON lo riavvio");
                    continue;
                }
                ok("service " + reale + " restart", 120);
                job.scrivi("    " + reale + ": " + (ok("service " + reale + " status", 20) ? "attivo" : "NON attivo"));
            }

            job.avanza(5, 5);
            job.scrivi("");
            job.scrivi("[5/5] Verifica: le librerie ci sono tutte adesso?");
            JSONArray ancora = pacchettiConLibrerieMancanti().getJSONArray("packages");
            if (ancora.length() == 0) {
                job.scrivi("    nessun pacchetto senza libreria.");
                job.status = "completed";
                job.scrivi("");
                job.scrivi("=== Ricollegamento riuscito ===");
            } else {
                job.status = "error";
                job.errorMessage = ancora.length() + " pacchetti restano senza la libreria che richiedono.";
                for (int i = 0; i < ancora.length(); i++) {
                    JSONObject o = ancora.getJSONObject(i);
                    job.scrivi("    ANCORA ROTTO: " + o.getString("name") + " richiede " + o.getString("lib"));
                }
            }
        } catch (Exception e) {
            job.status = "error";
            job.errorMessage = e.getMessage();
            job.scrivi("ERRORE: " + e.getMessage());
        } finally {
            if (!sbloccati.isEmpty()) {
                job.scrivi("");
                job.scrivi("Riproteggo...");
                int n = 0;
                for (String p2 : sbloccati) if (ok("pkg info -e " + p2, 15) && ok("pkg lock -y " + p2, 30)) n++;
                job.scrivi("  " + n + "/" + sbloccati.size() + " riprotetti");
                if (n == sbloccati.size()) pulisciStato();
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
