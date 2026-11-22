package org.daemoxcp.mail.scripts;

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
 * periodico aveva gia' incontrato e aggirato da solo (PeriodicReport.postfixSendmail).
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
        # --- Postfix as the local MTA (LocalMtaScript.java) ---
        # mailer.conf is installed only if Postfix's sendmail is really there: a mailer.conf
        # pointing to a missing program would make every local send fail, worse than dma.
        LOCAL_MAILER_CONF=/usr/local/etc/mail/mailer.conf
        POSTFIX_MAILER_CONF=/usr/local/share/postfix/mailer.conf.postfix
        if [ -f "$POSTFIX_MAILER_CONF" ] && [ -x /usr/local/sbin/sendmail ]; then
            if ! cmp -s "$POSTFIX_MAILER_CONF" "$LOCAL_MAILER_CONF"; then
                # A different mailer.conf is not thrown away: it stays next to it, with the UTC date and time.
                if [ -f "$LOCAL_MAILER_CONF" ]; then
                    cp -p "$LOCAL_MAILER_CONF" "$LOCAL_MAILER_CONF.before-postfix.$(date -u +%Y%m%dT%H%M%SZ)"
                fi
                install -d -m 0755 /usr/local/etc/mail
                install -m 0644 "$POSTFIX_MAILER_CONF" "$LOCAL_MAILER_CONF"
            fi
            echo "  sendmail(8) hands over to Postfix ($LOCAL_MAILER_CONF)"
            # The alias database. dma did not need it, it reads /etc/mail/aliases as
            # it is; Postfix does, and on a freshly installed machine it is not there: every local
            # delivery stayed queued with "alias database unavailable" until the panel, at its
            # first start, built it by itself. Measured on the clean VM on 29/10/2026. Postfix's
            # newaliases builds it, in the format alias_database says.
            /usr/local/bin/newaliases || echo "  WARNING: newaliases failed: local mail stays queued until the alias database exists"
        else
            echo "  ERROR: Postfix's sendmail not found: sendmail(8) still hands over to dma"
        fi

        # The four daily sendmail jobs that the message of Postfix's package says to turn
        # off. With Postfix they are not needed, and 440.status-mailq would report every day a
        # "submit" queue that does not exist with Postfix, ending as if there were something to say.
        sysrc -f /etc/periodic.conf daily_clean_hoststat_enable="NO" daily_status_mail_rejects_enable="NO" daily_status_include_submit_mailq="NO" daily_submit_queuerun="NO"

        # dma stays in the base system and has no switch to turn off: it is not a daemon, it starts
        # only when someone calls it, and from here on mailwrapper no longer calls it. What
        # stayed in ITS queue will never leave, though: it is said, and not sent from
        # here, because dma would deliver exactly as it must not (without DKIM, without TLS).
        DMA_QUEUED=$(find /var/spool/dma -type f -name 'Q*' 2>/dev/null | wc -l | tr -d ' ')
        if [ "${DMA_QUEUED:-0}" -gt 0 ]; then
            echo "  WARNING: $DMA_QUEUED message(s) left in the dma queue (/var/spool/dma) will not be sent"
        fi
        """;
}
