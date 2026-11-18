
        // ---------- la versione del pannello e le release di GitHub (ReleaseCheck) ----------
        // L'ultimo esito lo legge il server senza rete; «Controlla adesso» chiede a GitHub (al massimo una volta al
        // minuto). Della release si mostrano solo versione e data, e il link lo costruisce il server dal tag.
        // Gli istanti arrivano in UTC (r13) e si mostrano qui, nella lingua della pagina, col fuso accanto.
        // Le chiamate vanno dirette (updSend), non in fila dietro i lavori lenti di pkg (updApi): leggere l'esito non tocca
        // la rete, e il controllo ha il suo pulsante che non si ripreme mentre lavora.
        function relLang() {
            return window.I18N_LANG || document.documentElement.lang || undefined;
        }

        function relDate(iso, withTime) {
            const d = new Date(iso);
            if (!iso || isNaN(d.getTime())) return '';
            const o = withTime ? { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }
                               : { day: 'numeric', month: 'long', year: 'numeric' };
            try {
                return new Intl.DateTimeFormat(relLang(), o).format(d);
            } catch (e) {
                return d.toLocaleString(window.I18N_LANG);
            }
        }

        function relEl(tag, className, text) {
            const el = document.createElement(tag);
            if (className) el.className = className;
            if (text !== undefined) el.textContent = text;
            return el;
        }

        // Il link alla release: solo se e' davvero la pagina di una release del repository del pannello.
        function relLink(release, text) {
            const url = String(release && release.url || '');
            if (!/^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/releases\/tag\/[A-Za-z0-9._-]+$/.test(url)) return null;
            const a = relEl('a', 'alert-link', text);
            a.href = url;
            a.rel = 'noopener noreferrer';
            return a;
        }

        // Ogni testo con la sua chiave scritta per intero: I18nTest le cerca cosi' in entrambe le lingue.
        function relReason(r) {
            const code = String(r.error || '');
            if (/^http_\d{3}$/.test(code)) return t('rel.err.http', { code: code.slice(5) });
            switch (code) {
                case 'network': return t('rel.err.network');
                case 'no_ipv4': return t('rel.err.no_ipv4');
                case 'not_found': return t('rel.err.not_found', { repository: r.repository || '' });
                case 'rate_limited': return t('rel.err.rate_limited');
                case 'invalid': return t('rel.err.invalid');
                case 'too_large': return t('rel.err.too_large');
                case 'unknown_version': return t('rel.err.unknown_version');
                default: return code;
            }
        }

        function relRender(r, note) {
            const out = document.getElementById('relOutcome');
            if (!out) return;
            document.getElementById('relRunning').textContent = /^\d+\.\d+\.\d+/.test(r.current || '')
                ? t('rel.running', { version: r.current }) : t('rel.runningUnknown');
            const auto = document.getElementById('relAuto');
            auto.checked = !!r.enabled;
            auto.disabled = false;
            document.getElementById('relAutoHint').textContent = t('rel.autoHint', { repository: r.repository || '' });
            document.getElementById('relAutoState').textContent = r.enabled ? t('rel.autoOn') : t('rel.autoOff');

            out.replaceChildren();
            if (r.newest) {
                const box = relEl('div', 'alert alert-info mb-2');
                box.append(relEl('i', 'fas fa-gift me-2'));
                box.firstChild.setAttribute('aria-hidden', 'true');
                const said = { version: r.newest.version, date: relDate(r.newest.publishedAt, false) || '?' };
                box.append(relEl('span', '', r.newest.preRelease ? t('rel.availablePre', said) : t('rel.available', said)));
                const a = relLink(r.newest, t('rel.link'));
                if (a) box.append(' ', a);
                out.append(box);
            }
            if (!r.checkedAt) {
                out.append(relEl('p', 'small text-muted mb-2', t('rel.never')));
            } else if (r.ok === false) {
                out.append(relEl('p', 'small text-danger mb-2', t('rel.failed', { date: relDate(r.checkedAt, true), reason: relReason(r) })));
            } else if (!r.newest) {
                out.append(relEl('p', 'small text-success mb-2', t('rel.upToDate', { date: relDate(r.checkedAt, true) })));
            } else {
                out.append(relEl('p', 'small text-muted mb-2', t('rel.lastCheck', { date: relDate(r.checkedAt, true) })));
            }
            if (note) out.append(relEl('p', 'small text-muted mb-2', note));
        }

        function relError(message) {
            const out = document.getElementById('relOutcome');
            if (out) out.replaceChildren(relEl('p', 'small text-danger mb-2', t('rel.notRead', { error: message || '?' })));
        }

        async function relLoad() {
            const r = await updSend('panel_release');
            if (!r || !r.success) { relError(r && r.error); return; }
            relRender(r);
        }

        async function relCheckNow() {
            const button = document.getElementById('relCheckButton');
            const icon = document.getElementById('relCheckIcon');
            button.disabled = true;
            icon.className = 'fas fa-spinner fa-spin me-1';
            const out = document.getElementById('relOutcome');
            out.replaceChildren(relEl('p', 'small text-muted mb-2', t('rel.checking')));
            try {
                const r = await updSend('panel_release_check');
                // Senza repository la risposta non e' del controllo (un permesso che manca, la rete della pagina).
                if (!r || !r.repository) { relError(r && r.error); return; }
                relRender(r, r.justChecked ? t('rel.justChecked') : (!r.success ? relReason(r) : ''));
            } finally {
                button.disabled = false;
                icon.className = 'fas fa-magnifying-glass me-1';
            }
        }

        async function relSetAuto(input) {
            const wanted = !!input.checked;
            input.disabled = true;
            const r = await updSend('panel_release_auto', { enabled: wanted });
            if (!r || !r.success) {
                input.checked = !wanted;
                input.disabled = false;
                document.getElementById('relAutoState').textContent = r && r.error ? r.error : t('rel.notRead', { error: '?' });
                return;
            }
            relRender(r);
        }

        document.addEventListener('DOMContentLoaded', () => { if (document.getElementById('panelRelease')) relLoad(); });
