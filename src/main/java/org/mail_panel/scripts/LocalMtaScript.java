package org.mail_panel.scripts;

/**
 * Postfix come MTA LOCALE: il pezzo di script che fa passare da Postfix la posta che nasce su
 * questa macchina — cron, periodic, mail(1), il mail() di PHP, chiunque chiami sendmail(8).
 * Lo usano tutti e tre gli script che installano Postfix (FullMailServerScript, PostfixScript,
 * FullMailStackScript), e sta qui per non scriverlo tre volte.
 *
 * Su FreeBSD /usr/sbin/sendmail e' mailwrapper(8): legge /usr/local/etc/mail/mailer.conf e, se
 * manca, /etc/mail/mailer.conf del sistema base, che da FreeBSD 14 passa tutto a dma(8). Il
 * pacchetto di Postfix quel file NON lo scrive: lo dice nel suo messaggio di installazione e
 * si ferma li'. Misurato sulla VM FreeBSD 15.1 il 23/10/2026, con l'installazione di main: un
 * `sendmail -t` locale e il mail() di PHP finivano entrambi in dma ("dma[...]: delivery
 * successful" nel maillog), e Postfix non ne vedeva nessuno. Per la posta verso fuori vuol dire
 * niente milter, quindi niente firma DKIM, e nessuna politica TLS: e' il difetto che il rapporto
 * periodico aveva gia' incontrato e aggirato da solo (PeriodicReport.sendmailDiPostfix).
 *
 * Questo pezzo da solo NON basta, e anche questo e' misurato: va insieme a "myorigin = localhost"
 * in main.cf, che ciascuno script scrive. Senza, "root" diventava root@<nome del server>, che non
 * e' in mydestination, e Postfix lo spediva via SMTP. Sulla VM, senza DNS, restava in coda; con
 * il nome del server che risolve sul server stesso, come in produzione, rimbalzava ("mail for
 * ... loops back to myself"), e il rimbalzo, indirizzato allo stesso root, rimbalzava a sua
 * volta e veniva scartato. Cioe' la posta di sistema che dma consegnava in /var/mail/root
 * sarebbe andata persa. Il perche' di localhost e non di $myhostname in mydestination e' scritto
 * accanto a myorigin, in FullMailServerScript.
 *
 * Si puo' ripetere: il secondo giro trova mailer.conf gia' giusto e non lo tocca, e sysrc
 * scrive ogni voce una volta sola.
 */
public final class LocalMtaScript {

    private LocalMtaScript() {}

    public static final String SHELL = """
        # --- Postfix come MTA locale (LocalMtaScript.java) ---
        # mailer.conf si installa solo se il sendmail di Postfix c'e' davvero: un mailer.conf
        # che punta a un programma assente farebbe fallire ogni invio locale, peggio di dma.
        LOCAL_MAILER_CONF=/usr/local/etc/mail/mailer.conf
        POSTFIX_MAILER_CONF=/usr/local/share/postfix/mailer.conf.postfix
        if [ -f "$POSTFIX_MAILER_CONF" ] && [ -x /usr/local/sbin/sendmail ]; then
            if ! cmp -s "$POSTFIX_MAILER_CONF" "$LOCAL_MAILER_CONF"; then
                # Un mailer.conf diverso non si butta: resta accanto, con data e ora UTC.
                if [ -f "$LOCAL_MAILER_CONF" ]; then
                    cp -p "$LOCAL_MAILER_CONF" "$LOCAL_MAILER_CONF.before-postfix.$(date -u +%Y%m%dT%H%M%SZ)"
                fi
                install -d -m 0755 /usr/local/etc/mail
                install -m 0644 "$POSTFIX_MAILER_CONF" "$LOCAL_MAILER_CONF"
            fi
            echo "  sendmail(8) hands over to Postfix ($LOCAL_MAILER_CONF)"
            # Il database degli alias. dma non ne aveva bisogno, legge /etc/mail/aliases cosi'
            # com'e'; Postfix si', e su una macchina appena installata non c'e': ogni consegna
            # locale restava in coda con "alias database unavailable" finche' il pannello, al
            # primo avvio, non lo costruiva da se'. Misurato sulla VM pulita il 29/10/2026. Lo
            # costruisce il newaliases di Postfix, nel formato che dice alias_database.
            /usr/local/bin/newaliases || echo "  WARNING: newaliases failed: local mail stays queued until the alias database exists"
        else
            echo "  ERROR: Postfix's sendmail not found: sendmail(8) still hands over to dma"
        fi

        # I quattro lavori giornalieri di sendmail che il messaggio del pacchetto di Postfix dice
        # di spegnere. Con Postfix non servono, e 440.status-mailq riporterebbe ogni giorno una
        # coda "submit" che con Postfix non esiste, chiudendo come se ci fosse qualcosa da dire.
        sysrc -f /etc/periodic.conf daily_clean_hoststat_enable="NO" daily_status_mail_rejects_enable="NO" daily_status_include_submit_mailq="NO" daily_submit_queuerun="NO"

        # dma resta nel sistema base e non ha un interruttore da spegnere: non e' un demone, parte
        # solo quando qualcuno lo chiama, e da qui in avanti mailwrapper non lo chiama piu'. Quello
        # che e' rimasto nella SUA coda pero' non partira' mai: lo si dice, e non lo si spedisce
        # da qui, perche' dma consegnerebbe proprio come non deve (senza DKIM, senza TLS).
        DMA_QUEUED=$(find /var/spool/dma -type f -name 'Q*' 2>/dev/null | wc -l | tr -d ' ')
        if [ "${DMA_QUEUED:-0}" -gt 0 ]; then
            echo "  WARNING: $DMA_QUEUED message(s) left in the dma queue (/var/spool/dma) will not be sent"
        fi
        """;
}
