
        // ---------- il pannello stesso, in cima alla dashboard (reperto 183) ----------
        // Da quando gira lo vede chiunque apra la dashboard. Il resto (versione, build, commit,
        // impronta del jar, Java, sistema, processo) sta dietro l'occhio: lo vede solo chi ha
        // system.view, e si chiede al server solo quando lo si apre.
        //
        // Gli istanti arrivano in UTC (r13) e si mostrano qui, nella lingua della pagina, con il
        // fuso scritto accanto: un'ora senza fuso, letta da un altro paese, sbaglia senza dirlo.
        const panelInfo = { offsetMs: 0, startedMs: 0, details: null, tick: null, sync: null };

        async function panelInfoGet(action) {
            try {
                const res = await fetch('/api/panel_info?action=' + encodeURIComponent(action), { headers: { 'Accept': 'application/json' } });
                const body = await res.json().catch(() => ({}));
                if (res.status === 403) return { success: false, forbidden: true };
                if (!res.ok || !body.success) return { success: false, error: body.error || ('HTTP ' + res.status) };
                return body;
            } catch (e) {
                return { success: false, error: t('common.networkError', { message: e.message }) };
            }
        }

        function panelInfoLang() {
            return window.I18N_LANG || document.documentElement.lang || undefined;
        }

        function panelInfoJoin(parts) {
            try {
                return new Intl.ListFormat(panelInfoLang(), { style: 'long', type: 'conjunction' }).format(parts);
            } catch (e) {
                return parts.join(', ');
            }
        }

        // 3 giorni, 4 ore e 12 minuti: i secondi no, la pagina si aggiorna ogni quindici.
        function panelInfoDuration(seconds) {
            const s = Math.max(0, Math.floor(seconds));
            const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
            const parts = [];
            if (d) parts.push(tn('hp.days', d));
            if (h) parts.push(tn('hp.hours', h));
            if (m) parts.push(tn('hp.minutes', m));
            return parts.length ? panelInfoJoin(parts) : t('hp.underMinute');
        }

        function panelInfoDate(iso) {
            const d = new Date(iso);
            if (!iso || isNaN(d.getTime())) return '';
            try {
                return new Intl.DateTimeFormat(panelInfoLang(), { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
                    hour: '2-digit', minute: '2-digit', timeZoneName: 'short' }).format(d);
            } catch (e) {
                return d.toLocaleString(window.I18N_LANG);
            }
        }

        function panelInfoBytes(bytes) {
            const n = Number(bytes);
            if (!isFinite(n) || n <= 0) return t('hp.unavailable');
            const gb = n >= 1024 * 1024 * 1024;
            const value = gb ? n / (1024 * 1024 * 1024) : n / (1024 * 1024);
            try {
                return new Intl.NumberFormat(panelInfoLang(), { style: 'unit', unit: gb ? 'gigabyte' : 'megabyte',
                    maximumFractionDigits: gb ? 1 : 0 }).format(value);
            } catch (e) {
                return Math.round(value) + (gb ? ' GB' : ' MB');
            }
        }

        // L'ora di adesso secondo il server: l'orologio del browser puo' essere avanti o indietro.
        function panelInfoNow() {
            return Date.now() + panelInfo.offsetMs;
        }

        function panelInfoStatus(text) {
            const el = document.getElementById('panelInfoState');
            if (el) el.textContent = text || '';
        }

        function panelInfoTick() {
            const el = document.getElementById('panelInfoUptime');
            if (el && panelInfo.startedMs) el.textContent = panelInfoDuration((panelInfoNow() - panelInfo.startedMs) / 1000);
        }

        async function panelInfoLoad() {
            const r = await panelInfoGet('uptime');
            if (!r.success) {
                panelInfoStatus(t('hp.notRead', { error: r.error || t('hp.unavailable') }));
                return;
            }
            panelInfo.offsetMs = new Date(r.now).getTime() - Date.now();
            panelInfo.startedMs = new Date(r.startedAt).getTime();
            const started = document.getElementById('panelInfoStarted');
            started.textContent = panelInfoDate(r.startedAt);
            started.setAttribute('datetime', r.startedAt);
            started.title = r.startedAt;
            panelInfoTick();
            panelInfoStatus('');
            document.getElementById('panelInfoToggle').hidden = !r.details;
            panelReleaseShow(r.release);
            if (!panelInfo.tick) panelInfo.tick = setInterval(panelInfoTick, 15000);
            // Se il pannello riparte mentre la pagina e' aperta, l'inizio cambia: si rilegge ogni tanto.
            if (!panelInfo.sync) panelInfo.sync = setInterval(panelInfoLoad, 5 * 60 * 1000);
        }

        // Una versione nuova su GitHub (ReleaseCheck): il server la manda solo a chi vede le pagine del sistema. Il
        // link va alla pagina della release solo se e' davvero una release su GitHub.
        function panelReleaseShow(release) {
            const box = document.getElementById('panelReleaseNotice');
            if (!box) return;
            if (!release || !release.version) { box.hidden = true; return; }
            document.getElementById('panelReleaseText').textContent = t('hp.newRelease', { version: release.version, current: release.current || '?' });
            const link = document.getElementById('panelReleaseLink');
            if (/^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/releases\/tag\/[A-Za-z0-9._-]+$/.test(String(release.url || ''))) link.href = release.url;
            box.hidden = false;
        }

        async function panelInfoToggle() {
            const button = document.getElementById('panelInfoToggle');
            const box = document.getElementById('panelInfoDetails');
            const open = button.getAttribute('aria-expanded') !== 'true';
            button.setAttribute('aria-expanded', String(open));
            document.getElementById('panelInfoEye').className = 'fas ' + (open ? 'fa-eye-slash' : 'fa-eye') + ' me-1';
            document.getElementById('panelInfoToggleText').textContent = t(open ? 'hp.hide' : 'hp.show');
            box.hidden = !open;
            if (!open) return;
            const list = document.getElementById('panelInfoList');
            list.replaceChildren(panelInfoEl('dd', 'col-12 text-muted mb-0', t('hp.readingDetails')));
            // Ogni apertura rilegge: la memoria cambia, e un jar sostituito si vede subito.
            const r = await panelInfoGet('details');
            if (button.getAttribute('aria-expanded') !== 'true') return;
            if (!r.success) {
                panelInfo.details = null;
                list.replaceChildren(panelInfoEl('dd', 'col-12 mb-0', r.forbidden ? t('hp.forbidden')
                    : t('hp.detailsNotRead', { error: r.error || t('hp.unavailable') })));
                return;
            }
            panelInfo.details = r;
            panelInfoRender(list, r);
        }

        function panelInfoEl(tag, className, text) {
            const el = document.createElement(tag);
            if (className) el.className = className;
            if (text !== undefined) el.textContent = text;
            return el;
        }

        function panelInfoCode(text, id, title) {
            const code = panelInfoEl('code', 'text-break', text);
            if (id) code.id = id;
            if (title) code.title = title;
            return code;
        }

        function panelInfoCopyButton(which, label) {
            const b = panelInfoEl('button', 'btn btn-sm btn-link py-0 px-1 align-baseline touch-target');
            b.type = 'button';
            b.setAttribute('aria-label', label);
            b.title = label;
            b.setAttribute('data-on-click', "panelInfoCopy('" + which + "', this)");
            b.append(panelInfoEl('i', 'fas fa-copy'));
            b.firstChild.setAttribute('aria-hidden', 'true');
            return b;
        }

        // Una riga della lista: il nome a sinistra, il valore (testo o nodi) a destra; sotto lo
        // schermo stretto vanno uno sopra l'altro.
        function panelInfoRow(list, label, ...values) {
            list.append(panelInfoEl('dt', 'col-sm-4 col-lg-3 fw-semibold', label));
            const dd = panelInfoEl('dd', 'col-sm-8 col-lg-9');
            const shown = values.filter(v => v !== null && v !== undefined && v !== '');
            if (shown.length) dd.append(...shown);
            else dd.append(panelInfoEl('span', 'text-muted', t('hp.unavailable')));
            list.append(dd);
        }

        function panelInfoHint(text) {
            return panelInfoEl('div', 'text-muted', text);
        }

        function panelInfoRender(list, r) {
            list.replaceChildren();
            const recorded = !!(r.build && r.commit);
            const version = panelInfoEl('span', '', recorded ? t('hp.versionBuild', { version: r.version || '?', build: r.build })
                                                              : t('hp.buildNotRecorded', { version: r.version || '?' }));
            const extra = [];
            if (r.modified) {
                extra.push(' ', panelInfoEl('span', 'badge bg-warning text-dark', t('hp.modified')), panelInfoHint(t('hp.modifiedHint')));
            }
            if (!recorded) extra.push(panelInfoHint(t('hp.buildNotRecordedHint')));
            panelInfoRow(list, t('hp.version'), version, ...extra);

            panelInfoRow(list, t('hp.commit'), ...(r.commit
                ? [panelInfoCode(r.commit.slice(0, 12), 'panelInfoCommit', r.commit), panelInfoCopyButton('commit', t('hp.copyCommit'))]
                : []));
            panelInfoRow(list, t('hp.builtAt'), panelInfoDate(r.builtAt));
            panelInfoRow(list, t('hp.jar'), r.jarPath ? panelInfoCode(r.jarPath) : '');
            panelInfoRow(list, t('hp.sha256'), ...(r.jarSha256
                ? [panelInfoCode(r.jarSha256, 'panelInfoSha'), panelInfoCopyButton('jarSha256', t('hp.copySha')), panelInfoHint(t('hp.sha256Hint'))]
                : []));

            const j = r.java || {};
            panelInfoRow(list, t('hp.java'), j.version ? j.version + (j.vendor || j.vm ? ' (' + [j.vendor, j.vm].filter(Boolean).join(', ') + ')' : '') : '',
                j.home ? panelInfoHint(j.home) : '');

            const os = r.os || {};
            panelInfoRow(list, t('hp.system'), os.userland
                ? t('hp.systemLine', { userland: os.userland, kernel: os.kernel || '?', arch: os.arch || '?' }) : '');

            const machine = [];
            if (r.hostname) machine.push(panelInfoCode(r.hostname));
            if (r.bootedAt) {
                const up = panelInfoDuration((panelInfoNow() - new Date(r.bootedAt).getTime()) / 1000);
                machine.push(panelInfoEl('span', '', (r.hostname ? ', ' : '') + t('hp.machineUp', { uptime: up })),
                             panelInfoHint(t('hp.since', { date: panelInfoDate(r.bootedAt) })));
            }
            panelInfoRow(list, t('hp.machine'), ...machine);

            panelInfoRow(list, t('hp.process'), t('hp.processLine', { pid: r.pid, user: r.user || '?', port: r.port }));
            panelInfoRow(list, t('hp.memory'), t('hp.memoryLine', { used: panelInfoBytes(r.heapUsed), max: panelInfoBytes(r.heapMax) })
                + (r.processors ? ', ' + tn('hp.processors', r.processors) : ''));
        }

        async function panelInfoCopy(which, button) {
            const value = panelInfo.details && panelInfo.details[which];
            if (!value) return;
            try {
                await navigator.clipboard.writeText(value);
                panelInfoStatus(t('hp.copied'));
                setTimeout(() => panelInfoStatus(''), 4000);
                const icon = button && button.querySelector('i');
                if (icon) {
                    icon.className = 'fas fa-check';
                    setTimeout(() => { icon.className = 'fas fa-copy'; }, 1500);
                }
            } catch (e) {
                // Senza permesso per gli appunti: lo si seleziona, e lo si copia a mano.
                const code = document.getElementById(which === 'commit' ? 'panelInfoCommit' : 'panelInfoSha');
                if (code) {
                    if (which === 'commit') code.textContent = value;
                    window.getSelection().selectAllChildren(code);
                }
                panelInfoStatus(t('hp.copyFailed'));
            }
        }

        document.addEventListener('DOMContentLoaded', () => { panelInfoLoad(); });
