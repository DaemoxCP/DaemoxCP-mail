
        // ---------- Il firewall del provider (reperto 245) ----------
        // Le regole da creare nel firewall del provider, dalle porte vere di questo server, e la lista ufficiale di
        // Cloudflare per il pannello e la webmail, pronta da incollare. «L'ho messa» ricorda la sua impronta: quando
        // Cloudflare cambia la lista, questa scheda e Diagnostica lo dicono finche' non si conferma di nuovo.
        let pfwFingerprint = '';

        function pfwPorts(list) { return (list || []).join(', '); }

        async function pfwLoad() {
            const state = document.getElementById('pfw-state');
            if (!state) return;
            state.innerHTML = '<span class="small text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                + escHtml(t('pfw.loading')) + '</span>';
            const r = await updApi('provider_firewall');
            const rules = r.rules || {};
            const body = document.getElementById('pfw-rules');
            const row = (what, ports, sources, plain) => '<tr><th scope="row" class="fw-normal">' + escHtml(what) + '</th><td>'
                + (plain ? escHtml(ports) : '<code>' + escHtml(ports) + '</code>') + '</td><td>' + escHtml(sources) + '</td></tr>';
            // ICMP: nessuna porta. Senza questa regola il firewall di Hetzner Cloud scarta ogni ping, in IPv4 e in IPv6
            // (visto sul server vero): non si puo' controllare se il server e' raggiungibile, e all'IPv6 mancano i suoi
            // messaggi di servizio. Non apre nessun servizio.
            body.innerHTML = row(t('pfw.rowSsh'), pfwPorts(rules.ssh), t('pfw.srcYourIp'))
                + row(t(rules.pop3 ? 'pfw.rowMailPop3' : 'pfw.rowMail'), pfwPorts(rules.open), t('pfw.srcAny'))
                + row(t('pfw.rowWeb'), pfwPorts(rules.cloudflare), t('pfw.srcCloudflare'))
                + row(t('pfw.rowIcmp'), t('pfw.icmpPorts'), t('pfw.srcAny'), true);
            const list = document.getElementById('pfw-list');
            list.value = r.commaList || '';
            pfwFingerprint = r.fingerprint || '';
            document.getElementById('pfw-ack').disabled = !pfwFingerprint || r.state === 'current';
            const at = r.acknowledged && r.acknowledged.at ? new Date(r.acknowledged.at).toLocaleString(window.I18N_LANG) : '';
            const box = (cls, icon, text) => '<div class="alert alert-' + cls + ' py-2 small mb-2"><i class="fas ' + icon
                + ' me-1" aria-hidden="true"></i>' + escHtml(text) + '</div>';
            if (r.state === 'current') state.innerHTML = box('success', 'fa-circle-check', t('pfw.stCurrent', { date: at }));
            else if (r.state === 'changed') state.innerHTML = box('warning', 'fa-triangle-exclamation', t('pfw.stChanged', { date: at }));
            else if (r.state === 'never') state.innerHTML = box('info', 'fa-circle-right', t('pfw.stNever'));
            else state.innerHTML = box('secondary', 'fa-circle-question', r.error || t('pfw.downloadFailed'));
        }

        async function pfwCopy() {
            const list = document.getElementById('pfw-list');
            try {
                await navigator.clipboard.writeText(list.value);
                panelSay('success', t('pfw.copied'));
            } catch (e) {
                list.focus();
                list.select();
                panelSay('warning', t('pfw.copyByHand'));
            }
        }

        async function pfwAck() {
            if (!pfwFingerprint) return;
            if (!await updConfirm(t('pfw.ackConfirm'), t('pfw.ackGo'))) return;
            const el = document.getElementById('pfw-outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('pfw.saving'));
            const r = await updApi('provider_firewall_ack', { fingerprint: pfwFingerprint, confirm: 'UPDATED' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                + escHtml(r.success ? t('pfw.saved') : (r.error || t('pfw.notSaved'))) + '</div>';
            pfwLoad();
        }

        document.addEventListener('DOMContentLoaded', pfwLoad);
