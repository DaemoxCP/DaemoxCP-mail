package org.daemoxcp.mail.scripts;

/**
 * Un risolutore DNS ricorsivo locale, per rspamd: il pezzo di script che accende local_unbound
 * del sistema base senza inoltro, e ci fa puntare /etc/resolv.conf. Lo usano i tre script che
 * installano rspamd (FullMailServerScript, RspamdScript, FullMailStackScript), prima che rspamd
 * parta, perche' rspamd legge resolv.conf all'avvio.
 *
 * Il perche', misurato sulla VM FreeBSD 15.1 il 29/10/2026 con rspamc e un messaggio che
 * contiene il dominio di prova di Spamhaus (dbltest.com):
 *  - con il DNS che lo script "timezone" del pannello imposta (1.1.1.1), rspamd riceve
 *    DBL_BLOCKED_OPENRESOLVER e URIBL_BLOCKED: Spamhaus non risponde alle domande che arrivano
 *    da un risolutore pubblico (per dbltest.com da' 127.255.255.254), quindi le liste non
 *    servono a niente;
 *  - con il DNS della VM, DBL_FAIL "query timed out", e 5 secondi per ogni messaggio;
 *  - con local_unbound ricorsivo, dbltest.com da' 127.0.1.2, che e' la risposta giusta.
 * Il pannello sa gia' che serve: la pagina «Unbound» (SSLMailServer.runUnboundFixAll) fa la
 * stessa cosa a mano, e controlla proprio che non ci sia inoltro. L'installatore non lo faceva.
 *
 * local_unbound_forwarders="none" e' il modo di FreeBSD: local-unbound-setup va in modo
 * ricorsivo, commenta in resolv.conf gli altri server e scrive un resolvconf.conf statico
 * (libc="NO"), quindi un rinnovo DHCP non rimette gli inoltri. Misurato: dopo
 * "service dhclient restart" resolv.conf resta su 127.0.0.1 e forward.conf non nasce.
 *
 * Si puo' ripetere: con una configurazione gia' ricorsiva non si rifa' il setup, si riavvia
 * soltanto. E se il risolutore locale non risponde, tutto torna esattamente com'era.
 */
public final class LocalResolverScript {

    private LocalResolverScript() {}

    public static final String SHELL = """
        # --- Risolutore DNS ricorsivo locale per rspamd (LocalResolverScript.java) ---
        # Prima di toccare il DNS se ne tiene una copia: se il risolutore locale non risponde si
        # torna esattamente com'era, perche' un server di posta senza DNS non consegna niente.
        RESOLV_SAVED=$(mktemp /tmp/daemoxcp-mail-resolv.XXXXXX)
        cp -p /etc/resolv.conf "$RESOLV_SAVED"
        RESOLVCONF_SAVED=""
        if [ -f /etc/resolvconf.conf ]; then
            RESOLVCONF_SAVED=$(mktemp /tmp/daemoxcp-mail-resolvconf.XXXXXX)
            cp -p /etc/resolvconf.conf "$RESOLVCONF_SAVED"
        fi
        LOCAL_UNBOUND_WAS=$(sysrc -n local_unbound_enable 2>/dev/null)
        sysrc local_unbound_enable="YES" local_unbound_forwarders="none"
        # Una configurazione che inoltra (il local_unbound predefinito di FreeBSD inoltra ai server
        # di resolv.conf) si rifa' ricorsiva; una gia' ricorsiva non si tocca.
        if [ ! -f /var/unbound/unbound.conf ] || grep -qs "forward-zone" /var/unbound/forward.conf; then
            service local_unbound setup
        fi
        # Da ricorsivo, le zone inverse degli indirizzi privati si risolvono qui (NXDOMAIN, RFC 6303).
        # local-unbound-setup scrive unblock-lan-zones: yes, pensato per chi inoltra al DNS della LAN:
        # da ricorsivo quelle domande vanno su Internet e non tornano. Misurato sulla VM il
        # 29/10/2026: ogni login ssh dalla LAN impiegava 30 secondi (sshd fa la ricerca inversa del
        # client), con questo file 0. conf.d si include dopo lan-zones.conf, e il setup non lo tocca.
        mkdir -p /var/unbound/conf.d
        printf 'server:\\n\\tunblock-lan-zones: no\\n\\tinsecure-lan-zones: no\\n' > /var/unbound/conf.d/mail-panel.conf
        if service local_unbound status >/dev/null 2>&1; then
            service local_unbound restart
        else
            service local_unbound start
        fi
        # Appena riavviato, con la cache vuota, la prima domanda puo' fallire: misurato sulla VM il
        # 30/10/2026, nella seconda installazione Spamhaus ha dato SERVFAIL e il pezzo ha stampato
        # un avviso falso (alla fine dell'installazione lo stesso controllo dava OK). Quindi si
        # riprova, fino a 10 volte a 2 secondi: un falso "non risponde" qui rimetterebbe il DNS di
        # prima senza motivo.
        RESOLVER_ANSWERS=no
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if drill @127.0.0.1 freebsd.org A 2>/dev/null | grep -q "rcode: NOERROR"; then RESOLVER_ANSWERS=yes; break; fi
            sleep 2
        done
        if [ "$RESOLVER_ANSWERS" = "yes" ]; then
            # Risponde. Che risponda da ricorsivo lo dice Spamhaus: alla domanda di prova da' 127.0.0.x;
            # 127.255.255.x e' il rifiuto riservato ai risolutori pubblici.
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
