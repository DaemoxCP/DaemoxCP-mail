        // ========== Indirizzi del server: IPv4 e IPv6 (ServerAddresses, AddressGuide) ==========
        // Lo stato del server, l'obiettivo, e i passi numerati (fatto / adesso / dopo / bloccato) con UN pulsante per il
        // passo di adesso. Tutto costruito con il DOM: niente testo del server dentro innerHTML.

        let addrData = null;

        // Lo stato si chiede piu' volte (dopo un passo, cambiando obiettivo, il ricontrollo da solo) e ogni risposta ci mette
        // qualche secondo (le prove d'uscita vere): si disegna solo la risposta dell'ultima domanda. Prima una risposta lenta
        // per l'obiettivo di prima poteva arrivare dopo e coprire quello scelto dopo (visto nella prova nel browser).
        let addrSeq = 0;

        function addrFetchState() {
            const id = ++addrSeq;
            return fetch('/api/server-addresses?goal=' + encodeURIComponent(addrGoal())).then(r => r.json())
                .then(d => (id === addrSeq ? d : null));
        }

        // Ogni testo con la sua chiave scritta per intero: I18nTest le cerca cosi' in entrambe le lingue.
        function addrStatusText(s) {
            switch (s) {
                case 'done': return t('addr.status.done');
                case 'now': return t('addr.status.now');
                case 'next': return t('addr.status.next');
                default: return t('addr.status.blocked');
            }
        }

        function addrWhoText(w) { return w === 'you' ? t('addr.who.you') : t('addr.who.panel'); }

        function addrStepTitle(id) {
            switch (id) {
                case 'v4Address': return t('guide.step.v4Address');
                case 'v4Ptr': return t('guide.step.v4Ptr');
                case 'v4Dns': return t('guide.step.v4Dns');
                case 'v6Address': return t('guide.step.v6Address');
                case 'v6Firewall': return t('guide.step.v6Firewall');
                case 'v6Ptr': return t('guide.step.v6Ptr');
                case 'v6Dns': return t('guide.step.v6Dns');
                case 'webAaaa': return t('guide.step.webAaaa');
                case 'webA': return t('guide.step.webA');
                case 'mailBoth': return t('guide.step.mailBoth');
                case 'mailV4': return t('guide.step.mailV4');
                case 'mailV6': return t('guide.step.mailV6');
                case 'v6DnsRemove': return t('guide.step.v6DnsRemove');
                case 'v6AddressRemove': return t('guide.step.v6AddressRemove');
                case 'v4DnsRemove': return t('guide.step.v4DnsRemove');
                case 'v4Provider': return t('guide.step.v4Provider');
                case 'v4Clean': return t('guide.step.v4Clean');
                default: return '';
            }
        }

        function addrHow(id, p) {
            switch (id) {
                case 'v4Address': return t('guide.how.v4Address', p);
                case 'v4Ptr': return t('guide.how.v4Ptr', p);
                case 'v4Dns': return t('guide.how.v4Dns', p);
                case 'v6Address': return t('guide.how.v6Address', p);
                case 'v6Firewall': return t('guide.how.v6Firewall', p);
                case 'v6Ptr': return t('guide.how.v6Ptr', p);
                case 'v6Dns': return t('guide.how.v6Dns', p);
                case 'webAaaa': return t('guide.how.webAaaa', p);
                case 'webA': return t('guide.how.webA', p);
                case 'mailBoth': return t('guide.how.mailBoth', p);
                case 'mailV4': return t('guide.how.mailV4', p);
                case 'mailV6': return t('guide.how.mailV6', p);
                case 'v6DnsRemove': return t('guide.how.v6DnsRemove', p);
                case 'v6AddressRemove': return t('guide.how.v6AddressRemove', p);
                case 'v4DnsRemove': return t('guide.how.v4DnsRemove', p);
                case 'v4Provider': return t('guide.how.v4Provider', p);
                case 'v4Clean': return t('guide.how.v4Clean', p);
                default: return '';
            }
        }

        function addrHowManual(id, p) {
            switch (id) {
                case 'v4Dns': return t('guide.howManual.v4Dns', p);
                case 'v6Dns': return t('guide.howManual.v6Dns', p);
                case 'webAaaa': return t('guide.howManual.webAaaa', p);
                case 'webA': return t('guide.howManual.webA', p);
                case 'v6DnsRemove': return t('guide.howManual.v6DnsRemove', p);
                case 'v4DnsRemove': return t('guide.howManual.v4DnsRemove', p);
                default: return '';
            }
        }


        // I passi dal provider, quando il provider e' riconosciuto (oggi Hetzner Cloud).
        function addrHowHetzner(id, p) {
            switch (id) {
                case 'v4Ptr': return t('guide.howHetzner.v4Ptr', p);
                case 'v6Ptr': return t('guide.howHetzner.v6Ptr', p);
                default: return '';
            }
        }

        function addrGoal() {
            const r = document.querySelector('input[name="addrGoal"]:checked');
            return r ? r.value : 'both';
        }

        function addrEl(tag, cls, text) {
            const e = document.createElement(tag);
            if (cls) e.className = cls;
            if (text !== undefined && text !== null) e.textContent = text;
            return e;
        }

        // hidden: solo per gli screen reader (la riga e' un role=status sempre nella pagina), quando lo stesso esito si
        // vede gia' accanto al pulsante che l'ha chiesto, in fondo alla scheda e lontano da qui.
        function addrSay(text, kind, hidden) {
            const el = document.getElementById('addrStatus');
            el.className = hidden ? 'visually-hidden' : 'small mb-2 text-' + (kind || 'muted');
            el.textContent = text || '';
        }

        // L'ora di un controllo, nella lingua del pannello, coi secondi: due controlli nello stesso minuto si
        // distinguono, e lo screen reader legge di nuovo una frase che e' cambiata.
        function addrTime() {
            return new Date().toLocaleTimeString(window.I18N_LANG, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }

        function addrSetLast(text, cls) {
            const el = document.getElementById('addrLastCheck');
            if (!el) return false;
            el.className = 'small mt-2 mb-0 ' + (cls || 'text-muted');
            el.textContent = text;
            return true;
        }

        // Si o no o «non controllato»: la parola e un'icona che non e' l'unico segnale (r9: il colore non basta).
        function addrYesNo(v) {
            const span = addrEl('span', v === true ? 'text-success' : v === false ? 'text-danger' : 'text-muted');
            const icon = addrEl('i', 'fas me-1 ' + (v === true ? 'fa-check' : v === false ? 'fa-times' : 'fa-question'));
            icon.setAttribute('aria-hidden', 'true');
            span.append(icon, document.createTextNode(v === true ? t('addr.yes') : v === false ? t('addr.no') : t('addr.unknown')));
            return span;
        }

        function addrRow(family, side, dnsOk, ptrOk) {
            const tr = document.createElement('tr');
            tr.append(addrEl('th', '', family));
            tr.firstChild.setAttribute('scope', 'row');
            const list = side && side.addresses && side.addresses.length ? side.addresses.join(', ') : t('addr.none');
            tr.append(addrEl('td', 'text-break', list));
            const cells = [side && side.addresses && side.addresses.length ? side.internet : false, dnsOk, ptrOk];
            cells.forEach(v => { const td = document.createElement('td'); td.append(addrYesNo(v)); tr.append(td); });
            return tr;
        }

        // Il valore {ip} dei testi: l'IPv6 del server (o quello suggerito) per i passi IPv6, l'IPv4 pubblico per gli altri.
        function addrParams(id) {
            const d = addrData;
            const v6 = (d.state.v6.addresses && d.state.v6.addresses[0]) || (d.suggestion && d.suggestion.address) || '';
            const ip = /v6|Aaaa|AAAA/.test(id) || id === 'webAaaa' ? v6 : (d.state.v4.public || (d.state.v4.addresses || [])[0] || '');
            return { h: d.dns.host || '', ip: ip };
        }

        function addrButton(label, action, danger) {
            const b = addrEl('button', 'btn btn-sm touch-target ' + (danger ? 'btn-danger' : 'btn-primary'), label);
            b.type = 'button';
            b.setAttribute('data-on-click', action);
            return b;
        }

        function addrField(id, label, value, help) {
            const wrap = addrEl('div', 'mb-2');
            const l = addrEl('label', 'form-label small mb-1', label);
            l.htmlFor = id;
            const i = addrEl('input', 'form-control form-control-sm');
            i.id = id;
            i.type = 'text';
            i.value = value || '';
            i.autocomplete = 'off';
            i.spellcheck = false;
            i.setAttribute('autocorrect', 'off');
            i.setAttribute('autocapitalize', 'off');
            if (help) i.setAttribute('aria-describedby', help);
            wrap.append(l, i);
            return wrap;
        }

        // Il pannello del passo di adesso: la spiegazione e UN pulsante.
        // Un valore da scrivere altrove (la console del provider): l'etichetta, il valore, e «Copia».
        function addrCopyRow(label, value) {
            const row = addrEl('div', 'd-flex flex-wrap align-items-center gap-2 mb-2');
            const code = addrEl('code', 'text-break', value);
            const b = addrEl('button', 'btn btn-outline-secondary btn-sm touch-target', t('addr.copy'));
            b.type = 'button';
            b.dataset.copy = value;
            b.setAttribute('aria-label', t('addr.copy') + ': ' + label);
            b.setAttribute('data-on-click', 'addrCopy(this)');
            row.append(addrEl('span', 'small', label), code, b);
            return row;
        }

        function addrCopy(btn) {
            const value = btn.dataset.copy || '';
            const done = () => { btn.textContent = t('addr.copied'); setTimeout(() => { btn.textContent = t('addr.copy'); }, 2000); };
            if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(value).then(done).catch(() => {});
        }

        // Il pannello del passo di adesso: la spiegazione e UN pulsante.
        function addrNowPanel(step) {
            const d = addrData;
            const box = addrEl('div', 'border rounded p-2 mt-2');
            if (step.status === 'blocked') {
                const w = addrEl('div', 'alert alert-warning mb-0', step.blocked || '');
                w.setAttribute('role', 'alert');
                box.append(w);
                return box;
            }
            const params = addrParams(step.id);
            const manual = !d.dns.cloudflare && ['v4Dns', 'v6Dns', 'webAaaa', 'webA', 'v6DnsRemove', 'v4DnsRemove'].includes(step.id);
            const hetzner = d.provider === 'hetzner' && (step.id === 'v4Ptr' || step.id === 'v6Ptr');
            box.append(addrEl('p', 'small mb-2', manual ? addrHowManual(step.id, params) : hetzner ? addrHowHetzner(step.id, params) : addrHow(step.id, params)));

            // Il DNS inverso: i valori da scrivere nella console del provider, con «Copia», e cosa da' adesso.
            if (step.id === 'v4Ptr' || step.id === 'v6Ptr') {
                const v6 = step.id === 'v6Ptr';
                if (v6 && hetzner && d.state.v6.hostPart) box.append(addrCopyRow(t('addr.copyAddressField'), d.state.v6.hostPart));
                box.append(addrCopyRow(t('addr.copyFullAddress'), params.ip));
                box.append(addrCopyRow(t('addr.copyNameField'), params.h));
                const found = v6 ? d.dns.ptr6Found : d.dns.ptr4Found;
                box.append(addrEl('p', 'small mb-2', found ? t('addr.ptrNow', { name: found }) : t('addr.ptrNone')));
                box.append(addrEl('p', 'small text-muted mb-2', t('addr.waitMinutes')));
            }
            if (step.id === 'v6Firewall') {
                const a = addrEl('a', 'd-inline-block mb-2 small', t('addr.openFirewall'));
                a.href = '/firewall#provider-firewall';
                box.append(a);
                box.append(addrEl('div', 'mb-2'));
                box.append(addrButton(t('guide.do.v6Firewall'), "addrDo('confirm-firewall')", false));
                return box;
            }
            if (step.who === 'you' || manual) {
                box.append(addrEl('p', 'small text-muted mb-2', t('addr.recheck')));
                const again = addrButton(t('addr.checkAgain'), 'addrRecheck()', false);
                again.dataset.recheck = '1';
                box.append(again);
                // Quando e' stato l'ultimo controllo, da solo o col pulsante: si vede che il pannello sta guardando.
                const last = addrEl('p', 'small text-muted mt-2 mb-0', t('addr.lastCheck', { time: addrTime() }));
                last.id = 'addrLastCheck';
                box.append(last);
                return box;
            }
            switch (step.id) {
                case 'v6Address': {
                    const sg = d.suggestion;
                    const hint = addrEl('p', 'small text-muted mb-2', t('addr.fieldHint'));
                    hint.id = 'addrFieldHint';
                    const fields = [
                        addrField('addrV6Address', t('addr.fieldAddress'), sg ? sg.address : '', 'addrFieldHint'),
                        addrField('addrV6Prefix', t('addr.fieldPrefix'), sg ? String(sg.prefix) : '64', 'addrFieldHint'),
                        addrField('addrV6Gateway', t('addr.fieldGateway'), sg ? sg.gateway.replace(/%.*$/, '') : 'fe80::1', 'addrFieldHint'),
                        hint];
                    if (sg) {
                        // Il provider l'ha gia' detto: una frase e il pulsante; i campi solo dietro «Cambia».
                        box.append(addrEl('p', 'small mb-2', t('addr.suggested', { ip: sg.address, p: sg.prefix, gw: sg.gateway.replace(/%.*$/, '') })));
                        const det = addrEl('details', 'mb-2');
                        det.append(addrEl('summary', 'small', t('addr.change')));
                        fields.forEach(f => det.append(f));
                        box.append(det);
                    } else {
                        fields.forEach(f => box.append(f));
                    }
                    box.append(addrButton(t('guide.do.v6Address'), "addrDo('add-ipv6')", false));
                    break;
                }
                case 'v4Address': box.append(addrButton(t('guide.do.v4Address'), "addrDo('add-ipv4')", false)); break;
                case 'v4Dns': box.append(addrButton(t('guide.do.v4Dns'), "addrDns('A', 'add')", false)); break;
                case 'v6Dns': box.append(addrButton(t('guide.do.v6Dns'), "addrDns('AAAA', 'add')", false)); break;
                case 'webAaaa': box.append(addrButton(t('guide.do.webAaaa'), "addrDo('web-aaaa')", false)); break;
                case 'webA': box.append(addrButton(t('guide.do.webA'), "addrDo('web-a')", false)); break;
                case 'mailBoth': box.append(addrButton(t('guide.do.mailBoth'), "addrMail('both', false)", false)); break;
                case 'mailV4': box.append(addrButton(t('guide.do.mailV4'), "addrMail('ipv4', false)", false)); break;
                case 'mailV6': box.append(addrButton(t('guide.do.mailV6'), "addrMail('ipv6', false)", true)); break;
                case 'v6DnsRemove': box.append(addrButton(t('guide.do.v6DnsRemove'), "addrDns('AAAA', 'remove')", true)); break;
                case 'v4DnsRemove': box.append(addrButton(t('guide.do.v4DnsRemove'), "addrDns('A', 'remove')", true)); break;
                case 'v6AddressRemove': box.append(addrButton(t('guide.do.v6AddressRemove'), "addrDo('remove-ipv6')", true)); break;
                case 'v4Clean': box.append(addrButton(t('guide.do.v4Clean'), "addrDo('clean-ipv4')", true)); break;
            }
            return box;
        }

        // Quando il passo di adesso e' dell'amministratore (fuori dal pannello), il pannello ricontrolla da solo ogni 30
        // secondi, per 10 minuti; ridisegna solo se qualcosa e' cambiato, cosi' non toglie il fuoco a chi sta leggendo.
        let addrTimer = null, addrRechecks = 0, addrShown = '';

        function addrSchedule(d) {
            clearTimeout(addrTimer);
            const now = (d.steps || []).find(s => s.status === 'now');
            const waiting = now && (now.who === 'you' || (!d.dns.cloudflare && ['v4Dns', 'v6Dns', 'webAaaa', 'webA', 'v6DnsRemove', 'v4DnsRemove'].includes(now.id)));
            if (!waiting || now.id === 'v6Firewall' || addrRechecks >= 20) return;
            addrTimer = setTimeout(() => {
                addrRechecks++;
                addrFetchState().then(n => {
                    if (!n || !n.success) return;
                    if (JSON.stringify([n.steps, n.dns, n.state]) !== addrShown) addrRender(n);
                    else {
                        addrSetLast(t('addr.lastCheck', { time: addrTime() }));
                        addrSchedule(n);
                    }
                }).catch(() => {});
            }, 30000);
        }

        function addrRender(d) {
            addrData = d;
            addrShown = JSON.stringify([d.steps, d.dns, d.state]);
            addrSchedule(d);
            const rows = document.getElementById('addrRows');
            rows.replaceChildren(
                addrRow('IPv4', d.state.v4, d.dns.a, d.dns.ptr4),
                addrRow('IPv6', d.state.v6, d.dns.aaaa, d.dns.ptr6));
            document.getElementById('addrReached').classList.toggle('d-none', !d.reached);
            const ol = document.getElementById('addrSteps');
            ol.replaceChildren();
            if (d.reached) return;
            d.steps.forEach((s, i) => {
                const li = addrEl('li', 'mb-2' + (s.status === 'now' || s.status === 'blocked' ? '' : ' text-muted'));
                li.dataset.step = s.id;
                li.dataset.status = s.status;
                const head = addrEl('div', 'd-flex flex-wrap gap-2 align-items-baseline');
                const badge = addrEl('span', 'badge ' + (s.status === 'done' ? 'bg-success' : s.status === 'now' ? 'bg-primary'
                        : s.status === 'blocked' ? 'bg-warning text-dark' : 'bg-secondary'), (i + 1) + '. ' + addrStatusText(s.status));
                head.append(badge, addrEl('span', s.status === 'now' || s.status === 'blocked' ? 'fw-semibold' : '', addrStepTitle(s.id)),
                        addrEl('span', 'small text-muted', addrWhoText(s.who)));
                li.append(head);
                if (s.status === 'now' || s.status === 'blocked') {
                    li.setAttribute('aria-current', 'step');
                    li.append(addrNowPanel(s));
                }
                ol.append(li);
            });
        }

        function addrLoad() {
            addrRechecks = 0;
            addrSay(t('addr.loading'), 'muted');
            addrFetchState().then(d => {
                if (!d) return;
                if (!d.success) { addrSay(d.error || t('addr.failedGeneric'), 'danger'); return; }
                addrSay('', 'muted');
                addrRender(d);
            }).catch(() => addrSay(t('addr.failedGeneric'), 'danger'));
        }

        // «Controlla di nuovo»: dice sempre com'e' andata, accanto al pulsante. Prima, se non era cambiato niente, la
        // pagina si ridisegnava uguale e non diceva nulla: sembrava che il pulsante non facesse niente (visto sul server
        // vero, aspettando il DNS inverso). Se non e' cambiato niente la pagina non si ridisegna e il fuoco resta sul
        // pulsante; se e' cambiato, il fuoco torna sul pulsante del passo nuovo, se ce l'ha.
        function addrRecheck() {
            addrRechecks = 0;
            const btn = document.querySelector('#addrSteps button[data-recheck]');
            if (btn) btn.disabled = true;
            addrSetLast(t('addr.loading'));
            addrFetchState().then(d => {
                if (!d) return;
                if (btn) btn.disabled = false;
                if (!d.success) {
                    addrSetLast(d.error || t('addr.failedGeneric'), 'text-danger');
                    addrSay(d.error || t('addr.failedGeneric'), 'danger', true);
                    return;
                }
                const changed = JSON.stringify([d.steps, d.dns, d.state]) !== addrShown;
                const time = addrTime();
                const msg = changed ? t('addr.checkedChanged', { time: time }) : t('addr.checkedSame', { time: time });
                if (changed) addrRender(d);
                else addrSchedule(d);
                const near = addrSetLast(msg, changed ? 'text-success' : 'text-muted');
                addrSay(msg, changed ? 'success' : 'muted', near);
                const again = document.querySelector('#addrSteps button[data-recheck]');
                if (again) again.focus();
            }).catch(() => {
                if (btn) btn.disabled = false;
                addrSetLast(t('addr.failedGeneric'), 'text-danger');
                addrSay(t('addr.failedGeneric'), 'danger', true);
            });
        }

        function addrLock(locked) {
            document.querySelectorAll('#addrCard button, #addrCard input').forEach(e => { e.disabled = locked; });
        }

        // Un passo del pannello: POST, l'esito con il nome del registro, poi lo stato di nuovo (il passo dopo).
        function addrPost(body) {
            addrLock(true);
            addrSay(t('addr.working'), 'muted');
            body.csrf_token = csrfToken;
            return fetch('/api/server-addresses', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            }).then(r => r.json()).then(d => {
                addrLock(false);
                const msg = (d.success ? d.message : d.error) || (d.success ? '' : t('addr.failedGeneric'));
                addrSay(msg + (d.journal ? ' ' + t('addr.journal', { name: d.journal }) : ''), d.success ? 'success' : 'danger');
                return addrLoadKeepingStatus();
            }).catch(() => { addrLock(false); addrSay(t('addr.failedGeneric'), 'danger'); });
        }

        // Ricarica lo stato senza cancellare l'esito appena scritto.
        function addrLoadKeepingStatus() {
            return addrFetchState().then(d => {
                if (d && d.success) addrRender(d);
            }).catch(() => {});
        }

        async function addrDo(action) {
            const body = { action: action };
            if (action === 'add-ipv6') {
                body.address = document.getElementById('addrV6Address').value.trim();
                body.prefix = Number(document.getElementById('addrV6Prefix').value.trim());
                body.gateway = document.getElementById('addrV6Gateway').value.trim();
            }
            if (action === 'add-ipv6' && !body.address) {
                addrSay(t('addr.fieldMissing'), 'danger');
                return;
            }
            if (['remove-ipv6', 'clean-ipv4'].includes(action)) {
                const id = action === 'remove-ipv6' ? 'v6AddressRemove' : 'v4Clean';
                if (!await panelConfirm(addrHow(id, addrParams(id)), true)) return;
            }
            return addrPost(body);
        }

        async function addrDns(type, op) {
            if (op === 'remove') {
                const id = type === 'A' ? 'v4DnsRemove' : 'v6DnsRemove';
                if (!await panelConfirm(addrHow(id, addrParams(id)), true)) return;
            }
            return addrPost({ action: 'dns', type: type, op: op });
        }

        // La posta: la stessa scelta della scheda «IPv4 e IPv6» (IpFamily). Prima senza conferma: se IpFamily ha degli
        // avvisi (chi la sceglie da quale famiglia arriva, i record che restano) si mostrano, e solo dopo un «si'» si va.
        async function addrMail(family, confirmed) {
            addrLock(true);
            addrSay(t('set.ipfApplying'), 'muted');
            let d;
            try {
                const r = await fetch('/api/ip-family', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ family: family, confirmed: !!confirmed, csrf_token: csrfToken })
                });
                d = await r.json();
            } catch (e) {
                addrLock(false);
                addrSay(t('set.ipfFailed', { e: '' }), 'danger');
                return;
            }
            addrLock(false);
            if (d.confirm) {
                addrSay('', 'muted');
                if (await panelConfirm((d.warnings || []).join('\n'), true)) return addrMail(family, true);
                return;
            }
            if (d.success) addrSay(t('set.ipfDone', { f: ipfName(family) }), 'success');
            else addrSay(t('set.ipfFailed', { e: d.error || '' }), 'danger');
            ipfLoad();
            return addrLoadKeepingStatus();
        }

