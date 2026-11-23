
        // ---------- Diagnostics: check everything (finding 199) ----------
        // One button: the checks that read, one after the other, and a list with the one to look at first. Each
        // entry states the outcome in words and has ONE button for the next step (fix it, go where it is fixed,
        // or open the card with the details). What is fine stays collapsed below. The verdict of each check
        // follows the same rules as its card (the same fields, the same colors): the cards below remain for the
        // details.

        // The level: problem (red), warn (yellow), todo (a step to take), info, ok. The order of the list.
        const DIAG_ORDER = { problem: 0, warn: 1, todo: 2, info: 3, ok: 4 };

        function diagOpen(key) { return { label: t('diag.all.open'), action: "diagOpenCard('" + key + "')" }; }

        // The card's compatibility rules (updCompat), the same ones: red where the card is red, yellow where it
        // is yellow. The text says what and whose, component by component; the details stay in the card.
        function diagCompat(r) {
            const bad = [], warn = [];
            const d = r.dovecot || {}, pf = r.postfix || {}, rs = r.rspamd || {}, m = r.mysql || {}, w = r.webmail || {};
            // The card's verdict is an uppercase title: here it sits inside a sentence.
            const verdict = v => String(typeof updVerdict === 'function' ? updVerdict(v) : v).toLocaleLowerCase();
            // Red only if the installed package would jump to 2.4; 2.4 as a separate package (dovecot24), which
            // nothing installs by itself, is something to look at, not a fault (finding 212).
            if (d.scanned && !d.compatible24) {
                if (d.breakingUpgradeAvailable) bad.push(t('diag.c.dovecot24'));
                else warn.push(t('diag.c.dovecot24Later'));
            }
            if (r.dovecot && d.doveconfAvailable !== false && !d.doveconfOk) warn.push(t('diag.c.doveconf'));
            if (pf.verdict && pf.verdict !== 'ALIGNED') warn.push(t('diag.c.postfix', { verdict: verdict(pf.verdict) }));
            if (rs.present && rs.verdict !== 'NOTHING_TO_REPORT' && rs.verdict !== 'BEHAVIOR_DIFFS') bad.push(t('diag.c.rspamd', { verdict: verdict(rs.verdict) }));
            if (m.present && (m.issues || []).length) bad.push(t('diag.c.mysqlOptions'));
            if (m.present && m.eol) warn.push(t('diag.c.mysqlEol'));
            if (r.webmail && !w.consistent) warn.push(t('diag.c.webmail'));
            if (bad.length) return ['problem', bad.concat(warn).join('; ') + '.', diagOpen('compat')];
            if (warn.length) return ['warn', warn.join('; ') + '.', diagOpen('compat')];
            return ['ok', t('diag.v.compatOk')];
        }

        // The checks, in the order they run: key, title (the card's), /api/updates action, verdict.
        // The verdict: [level, text, button?]; the button is { label, action } or nothing.
        const DIAG_CHECKS = [
            { key: 'os', title: 'up.os', api: 'os_status', verdict: r => {
                if (r.restartNeeded) return ['todo', t('osu.patchRestartRow', { now: r.userland, kernel: r.installedKernel }),
                    document.getElementById('panelRebootModal') ? { label: t('osu.restartGo'), action: 'panelRebootOpen()' } : null];
                if (r.readyExist) return ['todo', t('uc.osReady', { now: r.userland, target: r.readyTarget || '?' }),
                    { label: t('diag.all.toUpdates'), href: '/updates' }];
                return ['ok', t('diag.v.osOk', { now: r.userland })];
            } },
            { key: 'journal', title: 'jr.title', api: 'journal_list', verdict: r => {
                // An error followed by a successful job of the same type is not something to look at (finding 212).
                const ended = (r.journals || []).slice(0, 20).filter(j => j.status === 'error' || j.status === 'unfinished');
                const bad = ended.filter(j => !j.settled);
                if (!bad.length) return ['ok', ended.length ? tn('diag.v.jobsSettled', ended.length) : t('diag.v.jobsOk')];
                return ['warn', tn('diag.v.jobsBad', bad.length), { label: t('diag.all.showLog'), action: "diagShowJournal('" + bad[0].name + "')" }];
            } },
            { key: 'svc', title: 'up.svcUsers', api: 'service_users', verdict: r => (r.problems || []).length
                ? ['warn', t('su.warnings', { n: r.problems.length }), diagOpen('svc')] : ['ok', t('su.none')] },
            { key: 'watch', title: 'up.watch', api: 'watch', verdict: r => r.replaced > 0 ? ['problem', r.note, diagOpen('watch')]
                : r.updated > 0 ? ['warn', r.note, diagOpen('watch')] : ['ok', r.note] },
            { key: 'libs', title: 'up.libs', api: 'broken_libs', verdict: r => (r.packages || []).length
                ? ['problem', tn('up.libsMissing', r.packages.length), diagOpen('libs')] : ['ok', t('up.libsOk')] },
            { key: 'compat', title: 'up.compat', api: 'compatibility', verdict: diagCompat },
            { key: 'java', title: 'uc.java', api: 'java_status', verdict: r => !r.present ? ['ok', t('diag.v.javaNone')]
                : !r.finished ? ['info', t('up.stillRunning'), diagOpen('java')]
                : r.succeeded ? ['ok', t('diag.v.javaOk')] : ['warn', t('diag.v.javaCheck'), diagOpen('java')] },
            { key: 'web', title: 'up.web', api: 'web_diagnosis', verdict: r => r.plainContents
                ? ['problem', r.verdict, diagOpen('web')] : ['ok', r.verdict] },
            { key: 'defaults', title: 'up.defaults', api: 'defaults_check', verdict: r => {
                const n = (r.lines || []).filter(x => x.outcome === 'DIVERGES').length;
                return n ? ['warn', tn('diag.v.defaultsDiverge', n), diagOpen('defaults')] : ['ok', t('diag.v.defaultsOk')];
            } },
            { key: 'env', title: 'up.env', api: 'panel_env', verdict: r => r.unreachable ? ['problem', r.explanation, diagOpen('env')]
                : r.absent ? ['warn', r.explanation, diagOpen('env')] : ['ok', r.explanation] },
            // Outbound port 25 (finding 246): if the provider blocks it, outgoing mail stays in the queue.
            { key: 'smtpout', title: 'so.title', api: 'smtp_out', verdict: r => r.state === 'open' ? ['ok', t('so.v.open')]
                : r.state === 'blocked' ? ['problem', t('so.v.blocked')] : ['info', t('so.v.unknown')] },
            // The provider's firewall with Cloudflare's list for the panel and the webmail (finding 245).
            { key: 'pfw', title: 'pfw.title', api: 'provider_firewall', verdict: r => {
                const go = { label: t('pfw.open'), href: '/firewall#provider-firewall' };
                if (r.state === 'current') return ['ok', t('pfw.v.current')];
                if (r.state === 'changed') return ['warn', t('pfw.v.changed'), go];
                if (r.state === 'never') return ['todo', t('pfw.v.never'), go];
                return ['info', r.error || t('pfw.downloadFailed')];
            } },
        ];

        // The card of a check, with its details: it is filled by its check, and the page goes to it.
        const DIAG_CARDS = { os: ['diag-os', 'osState'], svc: ['diag-svc', 'svcUsersLoad'], watch: ['diag-watch', 'watchLoad'],
            libs: ['diag-libs', 'libsCheck'], compat: ['diag-compat', 'updCompat'], java: ['diag-java', 'jvState'],
            web: ['diag-web', 'webDiag'], defaults: ['diag-defaults', 'defCheck'], env: ['diag-env', 'envCheck'] };

        function diagOpenCard(key) {
            const c = DIAG_CARDS[key];
            if (!c) return;
            const card = document.getElementById(c[0]);
            if (typeof window[c[1]] === 'function') window[c[1]]();
            card.focus({ preventScroll: true });
            card.scrollIntoView({ block: 'start', behavior: 'smooth' });
        }

        function diagShowJournal(name) {
            const card = document.getElementById('jr-card');
            jrList();
            jrShow(name);
            card.scrollIntoView({ block: 'start', behavior: 'smooth' });
        }

        function diagItem(c, v) {
            const level = v[0], word = { problem: t('diag.lv.problem'), warn: t('diag.lv.warn'), todo: t('diag.lv.todo'),
                info: t('diag.lv.info'), ok: t('diag.lv.ok') }[level];
            const icon = { problem: 'fa-circle-xmark text-danger', warn: 'fa-triangle-exclamation text-warning', todo: 'fa-circle-right text-primary',
                info: 'fa-circle-info text-info', ok: 'fa-circle-check text-success' }[level];
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex flex-wrap align-items-start gap-2';
            li.dataset.diag = c.key;
            li.dataset.level = level;
            let h = '<i class="fas ' + icon + ' mt-1" aria-hidden="true"></i><div class="flex-grow-1"><div class="fw-semibold">'
                + escHtml(t(c.title)) + ' <span class="small fw-normal">(' + escHtml(word) + ')</span></div>'
                + '<div class="small">' + escHtml(v[1] || '') + '</div></div>';
            const b = v[2];
            if (b && b.href) h += '<a class="btn btn-sm btn-primary touch-target" href="' + escHtml(b.href) + '">' + escHtml(b.label) + '</a>';
            else if (b) h += '<button type="button" class="btn btn-sm btn-primary touch-target" data-on-click="' + escHtml(b.action) + '">' + escHtml(b.label) + '</button>';
            li.innerHTML = h;
            return li;
        }

        async function diagAll() {
            const go = document.getElementById('diagAllGo'), state = document.getElementById('diagAllState');
            const list = document.getElementById('diagAllList'), okList = document.getElementById('diagAllOk');
            const okBox = document.getElementById('diagAllOkBox');
            go.disabled = true;
            list.replaceChildren();
            okList.replaceChildren();
            okBox.hidden = true;
            const results = [];
            for (let i = 0; i < DIAG_CHECKS.length; i++) {
                const c = DIAG_CHECKS[i];
                state.textContent = t('diag.all.running', { n: i + 1, total: DIAG_CHECKS.length, what: t(c.title) });
                let v;
                try {
                    const r = await updApi(c.api);
                    v = r && r.success ? c.verdict(r) : ['problem', (r && r.error) || t('common.errorShort'), diagOpen(c.key)];
                } catch (e) {
                    v = ['problem', t('common.networkError', { message: e.message }), diagOpen(c.key)];
                }
                results.push([c, v]);
            }
            results.sort((a, b) => DIAG_ORDER[a[1][0]] - DIAG_ORDER[b[1][0]]);
            const attention = results.filter(x => x[1][0] !== 'ok');
            attention.forEach(x => list.append(diagItem(x[0], x[1])));
            const fine = results.filter(x => x[1][0] === 'ok');
            fine.forEach(x => okList.append(diagItem(x[0], x[1])));
            okBox.hidden = !fine.length;
            document.getElementById('diagAllOkTitle').textContent = tn('diag.all.fine', fine.length);
            state.textContent = attention.length ? tn('diag.all.attention', attention.length) : t('diag.all.allFine', { n: results.length });
            go.disabled = false;
        }
