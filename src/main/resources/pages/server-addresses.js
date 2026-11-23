        // ========== Server addresses: IPv4 and IPv6 (ServerAddresses, AddressGuide) ==========
        // The server's state, the goal, and the numbered steps (done / now / later / blocked) with ONE button for
        // the current step. All built with the DOM: no server text inside innerHTML.

        let addrData = null;

        // The state is requested several times (after a step, when changing goal, the automatic recheck) and
        // every answer takes a few seconds (the real outbound tests): only the answer to the last request is
        // drawn. Before, a slow answer for the previous goal could arrive later and cover the one chosen
        // afterwards (seen in the browser test).
        let addrSeq = 0;

        function addrFetchState() {
            const id = ++addrSeq;
            return fetch('/api/server-addresses?goal=' + encodeURIComponent(addrGoal())).then(r => r.json())
                .then(d => (id === addrSeq ? d : null));
        }

        // Every text with its key written in full: that is how I18nTest finds them in both languages.
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
                case 'mailSend6': return t('guide.step.mailSend6');
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
                case 'mailSend6': return t('guide.how.mailSend6', p);
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


        // The steps at the provider, when the provider is recognized (today Hetzner Cloud).
        function addrHowHetzner(id, p) {
            switch (id) {
                case 'v4Ptr': return t('guide.howHetzner.v4Ptr', p);
                case 'v6Ptr': return t('guide.howHetzner.v6Ptr', p);
                default: return '';
            }
        }

        // The goal: IPv4 and IPv6 with the "Mail also comes in over IPv6" box off is "send6", mail over IPv6
        // only outbound; the box applies only to IPv4 and IPv6.
        function addrGoal() {
            const r = document.querySelector('input[name="addrGoal"]:checked');
            const g = r ? r.value : 'both';
            const sw = document.getElementById('addrInbound6');
            if (sw) sw.disabled = g !== 'both';
            return g === 'both' && sw && !sw.checked ? 'send6' : g;
        }

        function addrEl(tag, cls, text) {
            const e = document.createElement(tag);
            if (cls) e.className = cls;
            if (text !== undefined && text !== null) e.textContent = text;
            return e;
        }

        // hidden: only for screen readers (the line is a role=status always in the page), when the same outcome
        // is already visible next to the button that asked for it, at the bottom of the card and far from here.
        function addrSay(text, kind, hidden) {
            const el = document.getElementById('addrStatus');
            el.className = hidden ? 'visually-hidden' : 'small mb-2 text-' + (kind || 'muted');
            el.textContent = text || '';
        }

        // The time of a check, in the panel's language, with seconds: two checks in the same minute can be
        // told apart, and the screen reader reads again a sentence that has changed.
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

        // Yes or no or "not checked": the word and an icon that is not the only signal (r9: color is not enough).
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

        // The {ip} value of the texts: the server's IPv6 (or the suggested one) for the IPv6 steps, the public
        // IPv4 for the others.
        function addrParams(id) {
            const d = addrData;
            const v6 = (d.state.v6.addresses && d.state.v6.addresses[0]) || (d.suggestion && d.suggestion.address) || '';
            const ip = /v6|Aaaa|AAAA|Send6/.test(id) ? v6 : (d.state.v4.public || (d.state.v4.addresses || [])[0] || '');
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

        // The panel of the current step: the explanation and ONE button.
        // A value to write elsewhere (the provider's console): the label, the value, and "Copy".
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

        // The panel of the current step: the explanation and ONE button.
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
            const manual = !d.dns.cloudflare && addrManualIds.includes(step.id);
            const hetzner = d.provider === 'hetzner' && ['v4Ptr', 'v6Ptr'].includes(step.id);
            box.append(addrEl('p', 'small mb-2', manual ? addrHowManual(step.id, params) : hetzner ? addrHowHetzner(step.id, params) : addrHow(step.id, params)));

            // The reverse DNS: the values to write in the provider's console, with "Copy", and what it gives now.
            if (['v4Ptr', 'v6Ptr'].includes(step.id)) {
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
                // When the last check was, automatic or by button: it shows that the panel is watching.
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
                        // The provider has already said so: a sentence and the button; the fields only behind "Change".
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
                case 'mailSend6': box.append(addrButton(t('guide.do.mailSend6'), "addrMail('ipv6out', false)", false)); break;
                case 'mailV4': box.append(addrButton(t('guide.do.mailV4'), "addrMail('ipv4', false)", false)); break;
                case 'mailV6': box.append(addrButton(t('guide.do.mailV6'), "addrMail('ipv6', false)", true)); break;
                case 'v6DnsRemove': box.append(addrButton(t('guide.do.v6DnsRemove'), "addrDns('AAAA', 'remove')", true)); break;
                case 'v4DnsRemove': box.append(addrButton(t('guide.do.v4DnsRemove'), "addrDns('A', 'remove')", true)); break;
                case 'v6AddressRemove': box.append(addrButton(t('guide.do.v6AddressRemove'), "addrDo('remove-ipv6')", true)); break;
                case 'v4Clean': box.append(addrButton(t('guide.do.v4Clean'), "addrDo('clean-ipv4')", true)); break;
            }
            return box;
        }

        // When the current step is the administrator's (outside the panel), the panel rechecks by itself every
        // 30 seconds, for 10 minutes; it redraws only if something has changed, so it does not take focus away
        // from whoever is reading.
        let addrTimer = null, addrRechecks = 0, addrShown = '';

        function addrSchedule(d) {
            clearTimeout(addrTimer);
            const now = (d.steps || []).find(s => s.status === 'now');
            const waiting = now && (now.who === 'you' || (!d.dns.cloudflare && addrManualIds.includes(now.id)));
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

        // The steps that, without a Cloudflare account that sees the zone, the administrator does by hand in
        // their DNS.
        const addrManualIds = ['v4Dns', 'v6Dns', 'webAaaa', 'webA', 'v6DnsRemove', 'v4DnsRemove'];
        // At the first answer the "Mail also comes in over IPv6" box takes the server's state: on if mail
        // already receives over IPv6. Otherwise, off: the recommended choice.
        let addrSynced = false;

        function addrLoad() {
            addrRechecks = 0;
            addrSay(t('addr.loading'), 'muted');
            addrFetchState().then(d => {
                if (!d) return;
                if (!d.success) { addrSay(d.error || t('addr.failedGeneric'), 'danger'); return; }
                const sw = document.getElementById('addrInbound6');
                if (!addrSynced) {
                    addrSynced = true;
                    if (sw && !sw.checked && d.mail === 'both' && d.goal === 'send6') { sw.checked = true; addrLoad(); return; }
                }
                addrSay('', 'muted');
                addrRender(d);
            }).catch(() => addrSay(t('addr.failedGeneric'), 'danger'));
        }

        // The "Mail also comes in over IPv6" box is a real on/off switch. If the other steps are already done
        // and only the mail one is missing, touching it applies the choice at once, after ONE confirmation:
        // what happens and the warnings IpFamily would give (whoever touches it, which family they arrive
        // from), asked for first without changing anything. If it is cancelled or does not succeed, the box
        // goes back to how it was: so it always says how the server is. If other steps are missing the box
        // only chooses, and the guide shows the missing steps. Before, it only chose, and the button of the
        // last step was also needed: two gestures for an on/off switch (asked by the administrator on
        // 19 November).
        async function addrSwitch() {
            const sw = document.getElementById('addrInbound6');
            const was = !sw.checked;
            addrRechecks = 0;
            addrSay(t('addr.loading'), 'muted');
            let d;
            try { d = await addrFetchState(); } catch (e) { addrSay(t('addr.failedGeneric'), 'danger'); return; }
            if (!d) return;
            if (!d.success) { addrSay(d.error || t('addr.failedGeneric'), 'danger'); return; }
            addrSay('', 'muted');
            addrRender(d);
            const open = (d.steps || []).filter(s => s.status !== 'done');
            const last = open.length === 1 && open[0].status === 'now' && ['mailBoth', 'mailSend6'].includes(open[0].id) ? open[0].id : '';
            if (!last) return;
            const family = last === 'mailBoth' ? 'both' : 'ipv6out';
            // The warnings of the choice, without making it. If they do not arrive the choice is requested
            // without `confirmed`: if there are any, IpFamily sends them back and addrMail shows them in a
            // second confirmation, before changing.
            let warnings = null;
            try {
                const w = await fetch('/api/ip-family?family=' + encodeURIComponent(family)).then(r => r.json());
                if (w && w.success && Array.isArray(w.warnings)) warnings = w.warnings;
            } catch (e) { warnings = null; }
            const said = [addrHow(last, addrParams(last))].concat(warnings || []).join('\n');
            if (await panelConfirm(said, !!(warnings && warnings.length)) && await addrMail(family, warnings !== null)) {
                sw.focus();
                return;
            }
            sw.checked = was;
            await addrLoadKeepingStatus();
            sw.focus();
        }

        // "Check again": it always says how it went, next to the button. Before, if nothing had changed, the
        // page was redrawn identical and said nothing: it looked as if the button did nothing (seen on the
        // production server, waiting for the reverse DNS). If nothing has changed the page is not redrawn and
        // focus stays on the button; if it has changed, focus goes back to the button of the new step, if it
        // has one.
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

        // A panel step: POST, the outcome with the log's name, then the state again (the next step).
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

        // Reloads the state without erasing the outcome just written.
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

        // Mail: the same choice as the "IPv4 and IPv6" card (IpFamily). Before, without confirmation: if
        // IpFamily has warnings (whoever chooses it, which family they arrive from, the records that
        // remain) they are shown, and only after a "yes" does it go ahead. Returns true only if the choice
        // has been applied (otherwise the box above goes back to how it was).
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
                return false;
            }
            addrLock(false);
            if (d.confirm) {
                addrSay('', 'muted');
                if (await panelConfirm((d.warnings || []).join('\n'), true)) return addrMail(family, true);
                return false;
            }
            if (d.success) addrSay(t('set.ipfDone', { f: ipfName(family) }), 'success');
            else addrSay(t('set.ipfFailed', { e: d.error || '' }), 'danger');
            ipfLoad();
            await addrLoadKeepingStatus();
            return !!d.success;
        }

