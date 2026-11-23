package org.daemoxcp.mail.scripts;

/**
 * A local recursive DNS resolver, for rspamd: the piece of script that turns on the base system's local_unbound
 * without forwarding, and points /etc/resolv.conf at it. It is used by the three scripts that
 * install rspamd (FullMailServerScript, RspamdScript, FullMailStackScript), before rspamd
 * starts, because rspamd reads resolv.conf at startup.
 *
 * The reason, measured on the FreeBSD 15.1 VM on 2026-10-29 with rspamc and a message that
 * contains Spamhaus's test domain (dbltest.com):
 *  - with the DNS that the panel's "timezone" script sets (1.1.1.1), rspamd gets
 *    DBL_BLOCKED_OPENRESOLVER and URIBL_BLOCKED: Spamhaus does not answer queries that come
 *    from a public resolver (for dbltest.com it gives 127.255.255.254), so the lists are
 *    useless;
 *  - with the VM's DNS, DBL_FAIL "query timed out", and 5 seconds for every message;
 *  - with recursive local_unbound, dbltest.com gives 127.0.1.2, which is the right answer.
 * The panel already knows it is needed: the "Unbound" page (SSLMailServer.runUnboundFixAll) does the
 * same thing by hand, and checks precisely that there is no forwarding. The installer did not do it.
 *
 * local_unbound_forwarders="none" is the FreeBSD way: local-unbound-setup goes into recursive
 * mode, comments out the other servers in resolv.conf and writes a static resolvconf.conf
 * (libc="NO"), so a DHCP renewal does not bring the forwarders back. Measured: after
 * "service dhclient restart" resolv.conf stays on 127.0.0.1 and forward.conf is not created.
 *
 * It can be repeated: with a configuration that is already recursive the setup is not redone, it is
 * only restarted. And if the local resolver does not answer, everything goes back exactly as it was.
 */
public final class LocalResolverScript {

    private LocalResolverScript() {}

    public static final String SHELL = """
        # --- Local recursive DNS resolver for rspamd (LocalResolverScript.java) ---
        # Before touching DNS a copy is kept: if the local resolver does not answer, everything
        # goes back exactly as it was, because a mail server without DNS delivers nothing.
        RESOLV_SAVED=$(mktemp /tmp/daemoxcp-mail-resolv.XXXXXX)
        cp -p /etc/resolv.conf "$RESOLV_SAVED"
        RESOLVCONF_SAVED=""
        if [ -f /etc/resolvconf.conf ]; then
            RESOLVCONF_SAVED=$(mktemp /tmp/daemoxcp-mail-resolvconf.XXXXXX)
            cp -p /etc/resolvconf.conf "$RESOLVCONF_SAVED"
        fi
        LOCAL_UNBOUND_WAS=$(sysrc -n local_unbound_enable 2>/dev/null)
        sysrc local_unbound_enable="YES" local_unbound_forwarders="none"
        # A configuration that forwards (FreeBSD's default local_unbound forwards to the servers
        # of resolv.conf) is made recursive again; one already recursive is not touched.
        if [ ! -f /var/unbound/unbound.conf ] || grep -qs "forward-zone" /var/unbound/forward.conf; then
            service local_unbound setup
        fi
        # When recursive, the reverse zones of private addresses are resolved here (NXDOMAIN, RFC 6303).
        # local-unbound-setup writes unblock-lan-zones: yes, meant for forwarding to the LAN's DNS:
        # when recursive those queries go out to the Internet and never come back. Measured on the VM on
        # 29/10/2026: every ssh login from the LAN took 30 seconds (sshd looks up the client's
        # reverse name), with this file 0. conf.d is included after lan-zones.conf, and the setup does not touch it.
        mkdir -p /var/unbound/conf.d
        printf 'server:\\n\\tunblock-lan-zones: no\\n\\tinsecure-lan-zones: no\\n' > /var/unbound/conf.d/daemoxcp-mail.conf
        if service local_unbound status >/dev/null 2>&1; then
            service local_unbound restart
        else
            service local_unbound start
        fi
        # Just restarted, with an empty cache, the first query can fail: measured on the VM on
        # 30/10/2026, in the second installation Spamhaus gave SERVFAIL and this piece printed
        # a false warning (at the end of the installation the same check gave OK). So it
        # retries, up to 10 times 2 seconds apart: a false "does not answer" here would put the DNS
        # of before back for no reason.
        RESOLVER_ANSWERS=no
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if drill @127.0.0.1 freebsd.org A 2>/dev/null | grep -q "rcode: NOERROR"; then RESOLVER_ANSWERS=yes; break; fi
            sleep 2
        done
        if [ "$RESOLVER_ANSWERS" = "yes" ]; then
            # It answers. Spamhaus says whether it answers as a recursive resolver: to the test query it gives 127.0.0.x;
            # 127.255.255.x is the refusal reserved for public resolvers.
            SPAMHAUS_ANSWERS=no
            for attempt in 1 2 3 4 5 6 7 8 9 10; do
                if drill @127.0.0.1 2.0.0.127.zen.spamhaus.org A 2>/dev/null | grep -Eq "IN[[:space:]]+A[[:space:]]+127[.]0[.]0[.][0-9]+"; then SPAMHAUS_ANSWERS=yes; break; fi
                sleep 2
            done
            if [ "$SPAMHAUS_ANSWERS" = "yes" ]; then
                echo "  DNS: local recursive resolver on 127.0.0.1 (local_unbound), Spamhaus answers"
            else
                echo "  WARNING: the local resolver answers, but Spamhaus does not: DNS blocklists will not work"
            fi
        else
            echo "  ERROR: the local resolver (local_unbound) does not answer: DNS put back as it was"
            service local_unbound stop 2>/dev/null || true
            sysrc local_unbound_enable="${LOCAL_UNBOUND_WAS:-NO}"
            cp -p "$RESOLV_SAVED" /etc/resolv.conf
            if [ -n "$RESOLVCONF_SAVED" ]; then
                cp -p "$RESOLVCONF_SAVED" /etc/resolvconf.conf
            else
                rm -f /etc/resolvconf.conf
            fi
        fi
        rm -f "$RESOLV_SAVED" "$RESOLVCONF_SAVED"
        """;
}
