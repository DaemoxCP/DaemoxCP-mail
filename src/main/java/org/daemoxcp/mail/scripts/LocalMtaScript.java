package org.daemoxcp.mail.scripts;

/**
 * Postfix as LOCAL MTA: the piece of script that makes the mail born on this machine go
 * through Postfix -- cron, periodic, mail(1), PHP's mail(), anyone who calls sendmail(8).
 * All three scripts that install Postfix use it (FullMailServerScript, PostfixScript,
 * FullMailStackScript), and it is here so as not to write it three times.
 *
 * On FreeBSD /usr/sbin/sendmail is mailwrapper(8): it reads /usr/local/etc/mail/mailer.conf and, if
 * it is missing, the base system's /etc/mail/mailer.conf, which since FreeBSD 14 passes everything to
 * dma(8). The Postfix package does NOT write that file: it says so in its installation message and
 * stops there. Measured on the FreeBSD 15.1 VM on 2026-10-23, with the installation from main: a
 * local `sendmail -t` and PHP's mail() both ended up in dma ("dma[...]: delivery
 * successful" in the maillog), and Postfix saw none of them. For outgoing mail this means
 * no milter, so no DKIM signature, and no TLS policy: it is the defect that the periodic
 * report had already met and worked around on its own (PeriodicReport.postfixSendmail).
 *
 * This piece alone is NOT enough, and this too is measured: it goes together with "myorigin = localhost"
 * in main.cf, which each script writes. Without it, "root" became root@<server name>, which is not
 * in mydestination, and Postfix sent it via SMTP. On the VM, without DNS, it stayed in the queue; with
 * the server name resolving to the server itself, as in production, it bounced ("mail for
 * ... loops back to myself"), and the bounce, addressed to the same root, bounced in its
 * turn and was discarded. That is, the system mail that dma delivered to /var/mail/root
 * would have been lost. The reason for localhost and not $myhostname in mydestination is written
 * next to myorigin, in FullMailServerScript.
 *
 * It can be repeated: the second run finds mailer.conf already right and does not touch it, and sysrc
 * writes each entry only once.
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
