package org.mail_panel.scripts;

import org.mail_panel.Main;

import java.sql.ResultSet;

/**
 * Sorgente UNICA della configurazione Dovecot.
 *
 * Perche' esiste: il pannello aveva tre generatori distinti (DovecotScript,
 * FullMailStackScript, FullMailServerScript) che nel tempo sono divergiti. A seconda di
 * quale si eseguiva si otteneva un server diverso — userdb static contro userdb sql,
 * Sieve presente o assente, elenco protocols diverso — e due dei tre scrivevano un nome
 * di database CABLATO e sbagliato (`mailpanel` invece di quello configurato), il che
 * significava togliere l'autenticazione a tutte le caselle con un clic.
 *
 * Il contenuto canonico qui sotto e' la configurazione VIVA del server, quella che
 * `doveconf -n` accetta e che sta funzionando: non una terza variante inventata.
 *
 * Tre principi, in ordine di importanza:
 *
 *  1. NIENTE VALORI CABLATI che appartengono alla configurazione. Il nome del database e
 *     l'utente arrivano dalla configurazione del pannello. E' lo stesso errore di
 *     "mysql80" e "php84": funziona finche' nessuno cambia niente.
 *  2. LE DECISIONI RISCHIOSE LE PRENDE IL SERVER, non questo file. La versione di Dovecot
 *     e la presenza di Pigeonhole si leggono al momento dell'esecuzione: scrivere "sieve"
 *     fra i protocolli senza Pigeonhole installato impedisce a Dovecot di avviarsi.
 *  3. SI VALIDA PRIMA DI METTERE IN SERVIZIO. Dopo aver scritto si esegue `doveconf -n`:
 *     se Dovecot rifiuta la configurazione si ripristina quella precedente e NON si
 *     riavvia il servizio. Finora il pannello scriveva e riavviava alla cieca, e un
 *     errore di sintassi si sarebbe scoperto a posta gia' ferma.
 */
public final class DovecotConfig {

    private final String dbName;
    private final String dbUser;

    private DovecotConfig(String dbName, String dbUser) {
        this.dbName = dbName;
        this.dbUser = dbUser;
    }

    /**
     * Valori presi dalla configurazione del pannello. Se non sono leggibili si usano i
     * valori predefiniti del pannello stesso (mailserver/mailpanel), NON quelli cablati
     * negli script vecchi: e' proprio quella differenza ad aver rotto dovecot-sql.conf.
     */
    public static DovecotConfig fromPanelConfig() {
        String db = "mailserver", user = "mailpanel";
        try (ResultSet rs = Main.dbManager.get_data_config()) {
            if (rs.next()) {
                String d = rs.getString("mysql_database");
                String u = rs.getString("mysql_user");
                if (d != null && !d.isBlank()) db = d.trim();
                if (u != null && !u.isBlank()) user = u.trim();
            }
        } catch (Exception ignored) {
            // Config non leggibile: restano i predefiniti, che sono quelli giusti.
        }
        return new DovecotConfig(sanitize(db, "mailserver"), sanitize(user, "mailpanel"));
    }

    /** Un identificatore MySQL finisce dentro un file di configurazione e un comando: va ristretto. */
    private static String sanitize(String v, String fallback) {
        return (v != null && v.matches("[A-Za-z0-9_]{1,64}")) ? v : fallback;
    }

    public String getDbName() { return dbName; }
    public String getDbUser() { return dbUser; }

    /**
     * Frammento di shell che scrive TUTTA la configurazione Dovecot, la valida e solo
     * allora la mette in servizio. Da includere negli script di installazione al posto
     * dei blocchi che ognuno aveva per conto suo.
     */
    public String scriptFragment() {
        return """
            # =====================================================================
            # Configurazione Dovecot — generata dal pannello (sorgente unica)
            # =====================================================================
            DOVECOT_ETC=/usr/local/etc/dovecot
            DB_NAME='__DBNAME__'
            DB_USER='__DBUSER__'

            # --- Password del database, in ordine di autorevolezza ---
            # Non sta scritta qui dentro e non passa dalla riga di comando. Le sorgenti sono
            # quattro perche' quattro sono le situazioni reali, verificate leggendo gli script:
            #   1. DB_PASS dall'ambiente: la mette il pannello dalla propria configurazione,
            #      cioe' la password con cui si collega davvero. E' la piu' attendibile.
            #   2. MYSQL_PASSWORD: la variabile di FullMailServerScript (definita prima di qui).
            #   3. il file creato da FullMailStackScript.
            #   4. la configurazione Dovecot GIA' IN SERVIZIO: su un sistema che funziona e'
            #      la prova provata di quale password vada bene.
            # Cercare solo il file era l'errore: questo server e' stato installato con
            # FullMailServerScript, che quel file non lo crea, e la rigenerazione si fermava.
            if [ -z "$DB_PASS" ] && [ -n "$MYSQL_PASSWORD" ]; then
                DB_PASS="$MYSQL_PASSWORD"
            fi
            if [ -z "$DB_PASS" ] && [ -f /usr/local/etc/mail/mysql_password ]; then
                DB_PASS=$(cat /usr/local/etc/mail/mysql_password)
            fi
            if [ -z "$DB_PASS" ]; then
                for f in "$DOVECOT_ETC/dovecot-sql.conf" "$DOVECOT_ETC/conf.d/auth-sql.conf.ext"; do
                    [ -f "$f" ] || continue
                    DB_PASS=$(grep -m1 -oE 'password[[:space:]]*=[[:space:]]*[^[:space:]]+' "$f" 2>/dev/null | sed 's/.*=[[:space:]]*//')
                    [ -n "$DB_PASS" ] && break
                done
                [ -n "$DB_PASS" ] && echo "[CONFIG] password ripresa dalla configurazione attualmente in servizio"
            fi
            if [ -z "$DB_PASS" ]; then
                echo "[ERRORE] Non trovo la password del database in nessuna delle sorgenti previste:"
                echo "         ambiente, MYSQL_PASSWORD, /usr/local/etc/mail/mysql_password,"
                echo "         configurazione Dovecot esistente. Senza, nessuna casella si autenticherebbe."
                exit 1
            fi

            # --- Versione di Dovecot: decide QUALE sintassi scrivere ---
            # La 2.4 non accetta le configurazioni 2.3 e viceversa: non esiste un formato
            # che vada bene per entrambe, quindi la scelta va fatta qui, sul server, in base
            # a cio' che e' davvero installato.
            # La versione si chiede al BINARIO, non al nome del pacchetto. Su FreeBSD il port
            # mail/dovecot ha dei sapori: con il supporto MySQL il pacchetto si chiama
            # "dovecot-mysql" e quello chiamato "dovecot" non e' installato affatto. Chiedere
            # `pkg query %v dovecot` restituisce vuoto proprio sui sistemi come questo.
            # Prima il pacchetto per ORIGINE (funziona con qualunque sapore: dovecot-mysql,
            # dovecot-pgsql...), poi il binario come ripiego. L'ordine conta perche' i due
            # numeri non sono la stessa cosa: pkg include la revisione del port, il binario no.
            DOVECOT_VER=$(pkg query -e '%o = "mail/dovecot"' %v 2>/dev/null | head -1)
            [ -z "$DOVECOT_VER" ] && DOVECOT_VER=$(dovecot --version 2>/dev/null | awk '{print $1}')
            # Solo cifre: se la versione non fosse riconoscibile, un confronto numerico su una
            # stringa qualsiasi fallirebbe in modo imprevedibile (e con "set -e" fermerebbe lo
            # script). Meglio ricadere sul 2.3, che e' il formato compatibile con l'installato.
            DOVECOT_MAJOR=$(echo "$DOVECOT_VER" | cut -d. -f1 | tr -cd '0-9')
            DOVECOT_MINOR=$(echo "$DOVECOT_VER" | cut -d. -f2 | tr -cd '0-9')
            [ -z "$DOVECOT_MAJOR" ] && DOVECOT_MAJOR=2
            [ -z "$DOVECOT_MINOR" ] && DOVECOT_MINOR=3
            echo "[CONFIG] Dovecot rilevato: ${DOVECOT_VER:-sconosciuto} (${DOVECOT_MAJOR}.${DOVECOT_MINOR})"

            # --- Pigeonhole: decide se ManageSieve puo' essere attivato ---
            # "sieve" fra i protocolli SENZA Pigeonhole installato impedisce a Dovecot di
            # avviarsi. Per questo non e' una costante: e' una domanda al sistema.
            if pkg info -e dovecot-pigeonhole >/dev/null 2>&1 || \\
               pkg info -e dovecot-pigeonhole-mysql >/dev/null 2>&1 || \\
               pkg info -e dovecot-pigeonhole-pgsql >/dev/null 2>&1; then
                SIEVE_PROTO=" sieve"
                echo "[CONFIG] Pigeonhole presente: ManageSieve verra' abilitato sulla porta 4190"
            else
                SIEVE_PROTO=""
                echo "[CONFIG] Pigeonhole assente: ManageSieve NON verra' abilitato"
            fi

            # --- Copia di sicurezza: e' cio' che rende reversibile tutto il resto ---
            DOVECOT_BAK="/var/db/mailpanel/dovecot-config-$(date '+%Y%m%d-%H%M%S')"
            if [ -d "$DOVECOT_ETC" ]; then
                mkdir -p "$DOVECOT_BAK"
                cp -Rp "$DOVECOT_ETC/." "$DOVECOT_BAK/" 2>/dev/null
                echo "[CONFIG] Configurazione precedente salvata in $DOVECOT_BAK"
            fi

            mkdir -p "$DOVECOT_ETC/conf.d"

            if [ "$DOVECOT_MAJOR" -ge 3 ] 2>/dev/null || \\
               { [ "$DOVECOT_MAJOR" -eq 2 ] && [ "$DOVECOT_MINOR" -ge 4 ] 2>/dev/null; }; then
            __CONFIG_24__
            else
            __CONFIG_23__
            fi

            # --- Permessi sul file che contiene la password del database ---
            # Quale file sia cambia fra le due versioni: nella 2.3 e' dovecot-sql.conf,
            # nella 2.4 la connessione sta dentro auth-sql.conf.ext. Si proteggono entrambi
            # se esistono, invece di dare per scontato quale sia.
            for f in "$DOVECOT_ETC/dovecot-sql.conf" "$DOVECOT_ETC/conf.d/auth-sql.conf.ext"; do
                if [ -f "$f" ]; then
                    chmod 600 "$f"
                    chown root:dovecot "$f" 2>/dev/null || true
                fi
            done

            # =====================================================================
            # Validazione PRIMA della messa in servizio
            # =====================================================================
            # Il punto di tutto: si chiede a Dovecot se accetta cio' che abbiamo scritto.
            # Se non lo accetta si torna indietro e NON si riavvia, cosi' il server continua
            # a girare con la configurazione di prima invece di fermarsi.
            if command -v doveconf >/dev/null 2>&1; then
                DOVECONF_ERR=$(doveconf -n 2>&1 >/dev/null)
                if [ -n "$DOVECONF_ERR" ]; then
                    echo "[ERRORE] Dovecot NON accetta la configurazione appena scritta:"
                    echo "$DOVECONF_ERR" | sed 's/^/         /'
                    if [ -d "$DOVECOT_BAK" ]; then
                        echo "[RIPRISTINO] Rimetto la configurazione precedente da $DOVECOT_BAK"
                        rm -rf "$DOVECOT_ETC"
                        mkdir -p "$DOVECOT_ETC"
                        cp -Rp "$DOVECOT_BAK/." "$DOVECOT_ETC/"
                        echo "[RIPRISTINO] Fatto. Il servizio NON e' stato riavviato: continua con la configurazione di prima."
                    else
                        echo "[ATTENZIONE] Nessuna copia disponibile: la configurazione scritta resta, ma NON avvio il servizio."
                    fi
                    exit 1
                fi
                echo "[CONFIG] doveconf accetta la configurazione."
            else
                echo "[ATTENZIONE] doveconf non disponibile: impossibile validare prima di riavviare."
            fi
            """
            .replace("__DBNAME__", dbName)
            .replace("__DBUSER__", dbUser)
            // I blocchi NON vanno rientrati: la shell riconosce il terminatore di un
            // heredoc solo se sta a inizio riga. Rientrarli per leggibilita' lascerebbe
            // ogni heredoc senza chiusura, e il file verrebbe scritto a meta' o per niente.
            .replace("__CONFIG_23__", config23())
            .replace("__CONFIG_24__", config24());
    }



    /**
     * Sintassi 2.3 — il contenuto CANONICO, copiato dalla configurazione viva del server,
     * quella che doveconf accetta e con cui la posta sta funzionando. Le uniche differenze
     * volute rispetto a quel file sono il nome del database e l'utente, che qui arrivano
     * dalla configurazione invece di essere cablati, e "sieve" fra i protocolli che viene
     * aggiunto solo se Pigeonhole e' installato.
     */
    private static String config23() {
        return """
            echo "[CONFIG] Scrivo la configurazione in formato Dovecot 2.3"

            cat > "$DOVECOT_ETC/dovecot.conf" <<DOVECOT_MAIN
            # Dovecot — generato dal FreeBSD Mail Panel
            protocols = imap pop3 lmtp${SIEVE_PROTO}
            listen = *, ::
            mail_privileged_group = mail
            first_valid_uid = 5000
            first_valid_gid = 5000
            sendmail_path = /usr/local/sbin/sendmail

            !include conf.d/*.conf
            DOVECOT_MAIN

            cat > "$DOVECOT_ETC/conf.d/10-auth.conf" <<'DOVECOT_AUTH'
            disable_plaintext_auth = yes
            auth_mechanisms = plain login

            # Utente master per l'accesso amministrativo (SSO del pannello)
            auth_master_user_separator = *
            !include auth-master.conf.ext
            !include auth-sql.conf.ext
            DOVECOT_AUTH

            cat > "$DOVECOT_ETC/conf.d/10-mail.conf" <<'DOVECOT_MAIL'
            mail_location = maildir:/var/vmail/%d/%n
            mail_uid = vmail
            mail_gid = vmail
            DOVECOT_MAIL

            cat > "$DOVECOT_ETC/conf.d/10-ssl.conf" <<'DOVECOT_SSL'
            # SSL — gestito dal pannello
            ssl = required
            ssl_cert = </usr/local/etc/ssl/mail/fullchain.pem
            ssl_key = </usr/local/etc/ssl/mail/privkey.pem
            ssl_min_protocol = TLSv1.2
            ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
            ssl_prefer_server_ciphers = yes
            DOVECOT_SSL

            cat > "$DOVECOT_ETC/conf.d/10-master.conf" <<'DOVECOT_MASTER'
            service imap-login {
              inet_listener imap {
                port = 143
              }
              inet_listener imaps {
                port = 993
                ssl = yes
              }
            }

            service pop3-login {
              inet_listener pop3 {
                port = 110
              }
              inet_listener pop3s {
                port = 995
                ssl = yes
              }
            }

            service lmtp {
              unix_listener lmtp {
                mode = 0666
                user = vmail
                group = vmail
              }
              # LMTP su porta 24 per Postfix (virtual_transport = lmtp:inet:127.0.0.1:24)
              inet_listener lmtp {
                address = 127.0.0.1
                port = 24
              }
            }

            service auth {
              # Autenticazione SASL per Postfix
              unix_listener /var/spool/postfix/private/auth {
                mode = 0660
                user = postfix
                group = postfix
              }

              unix_listener auth-userdb {
                mode = 0600
                user = vmail
                group = vmail
              }
            }

            service managesieve-login {
              inet_listener sieve {
                port = 4190
              }
            }

            service managesieve {
            }

            protocol lmtp {
              mail_plugins = sieve
            }

            plugin {
              sieve = /var/mail/sieve/%d/%n/.dovecot.sieve
              sieve_dir = /var/mail/sieve/%d/%n/
              sieve_global_dir = /var/mail/sieve/global/
              sieve_extensions = +fileinto +reject +envelope +vacation +copy +imap4flags +regex +relational +comparator-i;ascii-numeric +date +variables
            }
            DOVECOT_MASTER

            cat > "$DOVECOT_ETC/conf.d/auth-master.conf.ext" <<'DOVECOT_AUTH_MASTER'
            passdb {
              driver = passwd-file
              master = yes
              args = /usr/local/etc/dovecot/master-users
              result_success = continue
            }
            DOVECOT_AUTH_MASTER

            cat > "$DOVECOT_ETC/conf.d/auth-sql.conf.ext" <<'DOVECOT_AUTH_SQL'
            passdb {
              driver = sql
              args = /usr/local/etc/dovecot/dovecot-sql.conf
            }
            userdb {
              driver = static
              args = uid=vmail gid=vmail home=/var/vmail/%d/%n
            }
            DOVECOT_AUTH_SQL

            cat > "$DOVECOT_ETC/dovecot-sql.conf" <<DOVECOT_SQL
            driver = mysql
            connect = host=127.0.0.1 dbname=${DB_NAME} user=${DB_USER} password=${DB_PASS}
            default_pass_scheme = BLF-CRYPT
            password_query = SELECT email as user, password FROM mailboxes WHERE email='%u' AND active=1
            DOVECOT_SQL
            """;
    }

    /**
     * Sintassi 2.4 — traduzione della configurazione qui sopra, fatta sulle pagine
     * ufficiali di Dovecot 2.4 (una per una: mail_location, databases/sql,
     * databases/static, master_users, plugins/sieve, e la guida di migrazione 2.3->2.4).
     *
     * ATTENZIONE, ed e' importante saperlo: nel repository FreeBSD la 2.4 NON esiste
     * ancora, quindi questo blocco non e' mai stato eseguito su un Dovecot 2.4 vero.
     * Per questo il frammento chiamante lo sottopone SEMPRE a `doveconf -n` prima di
     * metterlo in servizio, e in caso di rifiuto ripristina la configurazione precedente
     * senza riavviare: se qualcosa qui e' sbagliato, il risultato e' un messaggio di
     * errore, non un server di posta fermo.
     */
    // =====================================================================
    // Dovecot 2.4 — contenuto dei file, sorgente unica
    // =====================================================================
    //
    // Il template esisteva ma non era mai stato confrontato con la documentazione. La
    // verifica del 31/08/2026 ha trovato quattro errori VERI, tutti confermati da un
    // esempio ufficiale:
    //
    //   disable_plaintext_auth    -> auth_allow_cleartext  (e il valore si INVERTE)
    //   ssl_prefer_server_ciphers -> ssl_server_prefer_ciphers
    //   mail_plugins = sieve      -> mail_plugins { sieve = yes }   (tipo "boollist")
    //   default_password_scheme   -> dentro il blocco passdb, non al livello globale
    //
    // E ha prodotto un errore mio, poi corretto: avevo dichiarato rimosse
    // mail_privileged_group, first_valid_uid, first_valid_gid e auth_master_user_separator
    // sulla base del RIASSUNTO di una pagina, non del suo testo. L'elenco vero delle
    // impostazioni rimosse e' un altro: auth_stats, dict_db_config, imap_id_log,
    // login_access_sockets, quota_set, sieve_dir, sieve_global_dir, sieve_global_path,
    // sieve_vacation_max_subject_codepoints. Di queste, la configurazione 2.3 del pannello
    // usa sieve_dir e sieve_global_dir, sostituite qui dai blocchi sieve_script.
    //
    // IL CRITERIO, che vale piu' dei singoli casi:
    //   si TIENE cio' che la 2.3 aveva, a meno che la documentazione dica positivamente che
    //   e' cambiato. Il motivo e' asimmetrico: un'impostazione che la 2.4 non conosce piu'
    //   fa fallire doveconf, quindi si scopre subito e la configurazione precedente torna al
    //   suo posto; un'impostazione GIUSTA ma non scritta non fa fallire niente e cambia il
    //   comportamento in silenzio. Fra i due errori possibili, si sceglie quello rumoroso.
    //
    // Il caso che lo dimostra: auth_master_user_separator. Toglierla avrebbe rotto l'accesso
    // unico a Roundcube, perche' RoundcubeSsoManager compone il login come "email*masteruser"
    // — e doveconf non avrebbe segnalato nulla.
    //
    // Fonti (lette il 31/08/2026):
    //   https://doc.dovecot.org/2.4.0/installation/upgrade/2.3-to-2.4.html
    //   https://doc.dovecot.org/2.4.1/core/config/auth/master_users.html
    //   https://doc.dovecot.org/main/core/config/auth/databases/sql.html
    //   https://doc.dovecot.org/main/core/config/auth/databases/static.html
    //   https://doc.dovecot.org/main/core/config/auth/databases/passwd_file.html
    //   https://doc.dovecot.org/2.4.1/core/plugins/sieve.html
    //   https://doc.dovecot.org/main/core/settings/variables.html
    //
    // I file si definiscono UNA volta sola qui: da questa mappa si genera sia lo script che
    // li scrive sul server, sia l'anteprima leggibile dal pannello.

    /** Un file di configurazione: percorso relativo a /usr/local/etc/dovecot, contenuto,
     *  e se il contenuto contiene variabili di shell da espandere (la password del database). */
    public record FileConf(String path, String content, boolean expand) {}

    public static java.util.List<FileConf> file24() {
        java.util.List<FileConf> f = new java.util.ArrayList<>();

        f.add(new FileConf("dovecot.conf", """
            # Dovecot 2.4 — generato dal FreeBSD Mail Panel
            # dovecot_config_version DEVE essere la prima direttiva del file.
            dovecot_config_version = 2.4.0
            dovecot_storage_version = 2.4.0

            # Nella 2.4 il valore predefinito di protocols e' VUOTO: senza questa riga non
            # verrebbe abilitato nessun protocollo.
            protocols = imap pop3 lmtp${SIEVE_PROTO}
            listen = *, ::
            sendmail_path = /usr/local/sbin/sendmail
            mail_privileged_group = mail

            # Il limite inferiore di uid e gid: senza, un utente di sistema potrebbe ricevere
            # posta. Non e' fra le impostazioni rimosse dalla 2.4.
            first_valid_uid = 5000
            first_valid_gid = 5000

            !include conf.d/*.conf
            """, true));

        f.add(new FileConf("conf.d/10-auth.conf", """
            # disable_plaintext_auth non esiste piu': si chiama auth_allow_cleartext e il
            # valore e' rovesciato. "no" qui significa cio' che "yes" significava prima.
            auth_allow_cleartext = no
            auth_mechanisms = plain login

            # Il separatore dei master user: il pannello ne dipende, perche' l'accesso unico
            # a Roundcube fa login come "email*masteruser". Non e' fra le rimosse, ed e' nel
            # esempio ufficiale della 2.4.
            auth_master_user_separator = *

            !include auth-master.conf.ext
            !include auth-sql.conf.ext
            """, false));

        f.add(new FileConf("conf.d/10-mail.conf", """
            # mail_location scomposto: il formato e il percorso sono due impostazioni.
            # Le variabili a lettera singola non esistono piu': %d -> %{user | domain},
            # %n -> %{user | username}.
            mail_driver = maildir
            mail_path = /var/vmail/%{user | domain}/%{user | username}
            mail_uid = vmail
            mail_gid = vmail
            """, false));

        f.add(new FileConf("conf.d/10-ssl.conf", """
            ssl = required
            # ssl_cert/ssl_key rinominate, e non si usa piu' il prefisso "<" per dire "e' un file".
            ssl_server_cert_file = /usr/local/etc/ssl/mail/fullchain.pem
            ssl_server_key_file = /usr/local/etc/ssl/mail/privkey.pem
            ssl_min_protocol = TLSv1.2
            ssl_server_prefer_ciphers = yes
            # Non e' fra le rimosse: si tiene l'elenco della 2.3 invece di affidarsi ai
            # predefiniti, cosi' il comportamento non cambia insieme alla sintassi.
            ssl_cipher_list = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
            """, false));

        f.add(new FileConf("conf.d/10-master.conf", """
            service imap-login {
              inet_listener imap {
                port = 143
              }
              inet_listener imaps {
                port = 993
                ssl = yes
              }
            }

            service pop3-login {
              inet_listener pop3 {
                port = 110
              }
              inet_listener pop3s {
                port = 995
                ssl = yes
              }
            }

            service lmtp {
              unix_listener lmtp {
                mode = 0666
                user = vmail
                group = vmail
              }
              inet_listener lmtp {
                address = 127.0.0.1
                port = 24
              }
            }

            service auth {
              unix_listener /var/spool/postfix/private/auth {
                mode = 0660
                user = postfix
                group = postfix
              }

              unix_listener auth-userdb {
                mode = 0600
                user = vmail
                group = vmail
              }
            }

            service managesieve-login {
              inet_listener sieve {
                port = 4190
              }
            }

            service managesieve {
            }

            # mail_plugins non e' piu' un elenco su una riga: e' un "boollist", cioe' un
            # blocco in cui ogni voce si accende singolarmente.
            protocol lmtp {
              mail_plugins {
                sieve = yes
              }
            }

            # I percorsi Sieve non sono piu' impostazioni singole ma blocchi di archivio.
            sieve_script personal {
              type = personal
              driver = file
              path = /var/mail/sieve/%{user | domain}/%{user | username}
              active_path = /var/mail/sieve/%{user | domain}/%{user | username}/.dovecot.sieve
            }

            sieve_script global {
              type = global
              driver = file
              path = /var/mail/sieve/global/
            }

            # sieve_extensions NON viene piu' elencato. Nella 2.4 tutte le estensioni
            # supportate sono attive per impostazione predefinita, tranne quelle deprecate,
            # quelle che modificano i messaggi e quelle che richiedono configurazione
            # esplicita. L'elenco della 2.3 (+fileinto +reject +envelope +vacation +copy
            # +imap4flags +regex +relational +date +variables) e' interamente compreso in
            # quel predefinito: riscriverlo aggiungerebbe solo occasioni di sbagliare un
            # nome, e un nome sbagliato impedisce l'avvio.
            """, false));

        f.add(new FileConf("conf.d/auth-master.conf.ext", """
            # Il nome del blocco e' obbligatorio nella 2.4, e "args" e' diventato
            # passwd_file_path.
            passdb passwd-file {
              passwd_file_path = /usr/local/etc/dovecot/master-users
              master = yes
              result_success = continue
            }
            """, false));

        f.add(new FileConf("conf.d/auth-sql.conf.ext", """
            # La connessione al database non sta piu' in un file a parte (dovecot-sql.conf
            # non esiste nella 2.4): si dichiara con un blocco del driver, e la query di
            # passdb si chiama "query", non "password_query".
            sql_driver = mysql

            mysql 127.0.0.1 {
              user = ${DB_USER}
              password = ${DB_PASS}
              dbname = ${DB_NAME}
            }

            passdb sql {
              # default_password_scheme sta DENTRO il blocco passdb, non al livello globale.
              default_password_scheme = BLF-CRYPT
              query = SELECT email AS user, password FROM mailboxes WHERE email = '%{user}' AND active = 1
            }

            userdb static {
              fields {
                uid = vmail
                gid = vmail
                home = /var/vmail/%{user | domain}/%{user | username}
              }
            }
            """, true));

        return f;
    }

    /**
     * Impostazioni che la documentazione ufficiale conferma, e quelle che invece restano da
     * confermare sul campo. Dichiararlo e' il punto: un template dato per buono e mai provato
     * e' esattamente cio' che ha prodotto i sei errori trovati oggi.
     */
    public static String[][] checks24() {
        return new String[][]{
            {"confirmed", "dovecot_config_version / dovecot_storage_version", "obbligatorie; la prima dev'essere in cima a dovecot.conf"},
            {"confirmed", "mail_driver + mail_path", "sostituiscono mail_location"},
            {"confirmed", "%{user}, %{user | username}, %{user | domain}", "sostituiscono %u, %n, %d"},
            {"confirmed", "auth_allow_cleartext", "sostituisce disable_plaintext_auth, e il valore si inverte"},
            {"confirmed", "ssl_server_cert_file / ssl_server_key_file", "sostituiscono ssl_cert / ssl_key, senza il prefisso <"},
            {"confirmed", "ssl_server_prefer_ciphers", "sostituisce ssl_prefer_server_ciphers"},
            {"confirmed", "passdb sql { query = ... }", "il blocco vuole un nome; password_query si chiama query"},
            {"confirmed", "userdb static { fields { ... } }", "esempio ufficiale identico"},
            {"confirmed", "passdb passwd-file { passwd_file_path = ... }", "args si chiama passwd_file_path"},
            {"confirmed", "sql_driver + blocco mysql <host> { ... }", "dovecot-sql.conf non esiste piu'"},
            {"confirmed", "mail_plugins { sieve = yes }", "non piu' un elenco su una riga: e' un boollist"},
            {"confirmed", "default_password_scheme dentro passdb", "non piu' al livello globale"},
            {"confirmed", "blocchi sieve_script al posto di sieve_dir e sieve_global_dir",
             "sieve_dir, sieve_global_dir e sieve_global_path sono nell'elenco ufficiale delle rimosse"},
            {"confirmed", "protocols va scritto esplicitamente",
             "nella 2.4 il valore predefinito e' vuoto: senza quella riga non si abilita nessun protocollo"},
            {"confirmed", "auth_master_user_separator = *",
             "NON e' rimossa: l'esempio ufficiale della 2.4 la mostra. Il pannello ne dipende, perche' "
             + "l'accesso unico a Roundcube fa login come email*masteruser"},
            {"confirmed", "first_valid_uid / first_valid_gid / mail_privileged_group / ssl_cipher_list",
             "non compaiono fra le impostazioni rimosse: si tengono come nella 2.3"},
            {"da confermare", "sieve_script { type = ... }",
             "la descrizione elenca 'type' fra le chiavi, l'esempio ufficiale non lo scrive. Qui c'e': se doveconf lo rifiuta, va tolto"},
            {"da confermare", "mail_uid / mail_gid",
             "non citate fra le modifiche, quindi tenute. Se la 2.4 le avesse tolte, doveconf lo direbbe: "
             + "uid e gid arrivano comunque anche da userdb static, quindi togliendole non cambia niente"},
            {"da confermare", "ssl = required, ssl_min_protocol, sendmail_path, !include",
             "non citate fra le modifiche, quindi presumibilmente invariate"},
            {"criterion", "si tiene cio' che la 2.3 aveva, salvo changes documentati",
             "i due errori possibili non pesano uguale: un'impostazione che la 2.4 non conosce piu' fa "
             + "fallire doveconf, quindi si scopre subito e la configurazione precedente torna al suo "
             + "posto; un'impostazione giusta ma non scritta non fa fallire niente e cambia il "
             + "comportamento in silenzio. Fra i due si sceglie l'errore rumoroso"},
        };
    }

    private static String config24() {
        StringBuilder sb = new StringBuilder();
        sb.append("""
            echo "[CONFIG] Scrivo la configurazione in formato Dovecot 2.4"
            echo "[CONFIG] Template verificato sulla documentazione ufficiale il 31/08/2026,"
            echo "[CONFIG] ma mai eseguito su un 2.4 reale: doveconf decide, e se rifiuta"
            echo "[CONFIG] la configurazione precedente torna al suo posto senza riavvii."
            """);
        for (FileConf f : file24()) {
            String delim = "DOVECOT_" + f.path().replaceAll("[^A-Za-z0-9]", "_").toUpperCase();
            // Heredoc quotato quando NON ci sono variabili da espandere: cosi' un $ nel
            // contenuto (le %{...} non ne hanno, ma le query potrebbero) resta letterale.
            sb.append("\ncat > \"$DOVECOT_ETC/").append(f.path()).append("\" <<")
              .append(f.expand() ? delim : "'" + delim + "'").append("\n");
            sb.append(f.content());
            sb.append(delim).append("\n");
        }
        sb.append("""

            # Nella 2.4 non esiste piu' dovecot-sql.conf: se e' rimasto da una 2.3 va tolto
            # di mezzo, altrimenti resterebbe sul disco un file con la password del database
            # che nessuno legge piu' e nessuno aggiorna.
            if [ -f "$DOVECOT_ETC/dovecot-sql.conf" ]; then
                mv "$DOVECOT_ETC/dovecot-sql.conf" "$DOVECOT_ETC/dovecot-sql.conf.pre-2.4"
                chmod 600 "$DOVECOT_ETC/dovecot-sql.conf.pre-2.4"
            fi
            """);
        return sb.toString();
    }
}
