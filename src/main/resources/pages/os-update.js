
        // ---------- FreeBSD guidato: le patch e il passaggio a una release nuova (reperto 196) ----------
        // Una frase sullo stato e UN pulsante per il passo che viene dopo. Le patch: installa, poi (se serve) riavvia.
        // Una release nuova compare solo quando c'e', ed e' una lista di quattro passi: si vede dove si e', e solo il
        // passo di adesso ha il suo pulsante. Il registro di quello che il server fa resta chiuso finche' non lo si apre.

        // Quale dei due pannelli della riga: le patch o la release nuova. Mai tutti e due insieme.
        function osShow(which) {
            const patch = document.getElementById('os-patch'), release = document.getElementById('os-release');
            if (patch) patch.hidden = which !== 'patch';
            if (release) release.hidden = which !== 'release';
        }

        // Il registro sotto un pannello: c'e' solo quando c'e' qualcosa da leggere, e resta chiuso.
        function osLogBox(id, show) {
            const box = document.getElementById(id);
            if (box) box.hidden = !show;
        }

        function osRestartButton(cls) {
            if (!document.getElementById('panelRebootModal')) return '';
            return '<button type="button" class="btn ' + (cls || 'btn-warning') + ' touch-target" data-on-click="panelRebootOpen()">'
                + '<i class="fas fa-rotate-right me-1" aria-hidden="true"></i>' + escHtml(t('osu.restartGo')) + '</button>';
        }

        // L'esito delle patch, letto dal sistema e non dal registro: cosa e' installato e cosa resta da fare.
        async function osPatchOutcome() {
            const el = document.getElementById('os-body');
            const r = await updApi('os_status');
            if (el && r.success) {
                el.innerHTML = r.restartNeeded
                    ? '<div class="alert alert-warning py-2 mb-0"><p class="mb-2"><strong>' + escHtml(t('osu.patchDone', { now: r.userland })) + '</strong> '
                      + escHtml(t('osu.patchRestart', { installed: r.installedKernel, running: r.uname })) + '</p>'
                      + osRestartButton() + '<p class="small mt-2 mb-0">' + escHtml(t('osu.wayBackNote')) + '</p></div>'
                    : '<div class="alert alert-success py-2 mb-0"><strong>' + escHtml(t('osu.patchDone', { now: r.userland })) + '</strong> '
                      + escHtml(t('osu.patchNothingElse')) + '</div>';
            }
            if (document.getElementById('ucList')) ucLoad(true);
            if (typeof panelRebootRefresh === 'function') panelRebootRefresh();
        }

        // ---------- la release nuova ----------

        // La release verso cui si va: quella del passaggio cominciato, altrimenti la piu' recente fra le supportate.
        function osRelTarget() {
            const jp = uc.jump || {};
            if (jp.inProgress && jp.target) return jp.target;
            const v = (uc.targets && uc.targets.versions) || [];
            return v.length ? v[v.length - 1].version : '';
        }

        // A che passo si e', dallo stato che il server tiene su disco e da quello che freebsd-update ha scaricato.
        function osRelStep() {
            const jp = uc.jump || {};
            if (jp.phase === 'finished') return 4;
            if (['awaiting-restart', 'awaiting-final-restart', 'error', 'too-many-rounds'].includes(jp.phase) || jp.upgradeFetched) return 3;
            if (jp.phase === 'prepared') return 2;
            return 1;
        }

        // Il passaggio e' in corso (preparato o cominciato) e non ancora finito.
        function osMoving() {
            const jp = uc.jump || {};
            return !!(jp.success && jp.inProgress && jp.phase !== 'finished');
        }

        function ucRelease() {
            ucOpen('os');
            osShow('release');
            osReleaseRender();
        }

        function osReleaseRender() {
            const list = document.getElementById('os-steps');
            if (!list) return;
            const target = osRelTarget(), now = osRelStep(), jp = uc.jump || {}, os = uc.os || {};
            const steps = [
                { title: t('osu.s1.title'), text: t('osu.s1.text') },
                { title: t('osu.s2.title'), text: t('osu.s2.text') },
                { title: t('osu.s3.title'), text: t('osu.s3.text') },
                { title: t('osu.s4.title'), text: t('osu.s4.text') },
            ];
            let h = '<h4 class="h6 mb-3">' + escHtml(t('osu.moveTitle', { target: target })) + '</h4>';
            steps.forEach((s, i) => {
                const n = i + 1, state = n < now ? 'done' : (n === now ? 'now' : 'later');
                const icon = { done: 'fa-circle-check text-success', now: 'fa-circle-right text-primary', later: 'fa-circle text-muted' }[state];
                const word = { done: t('osu.stepWord.done'), now: t('osu.stepWord.now'), later: t('osu.stepWord.later') }[state];
                h += '<li class="d-flex gap-2 mb-3' + (state === 'later' ? ' text-muted' : '') + '">'
                   + '<i class="fas ' + icon + ' mt-1" aria-hidden="true"></i><div class="flex-grow-1">'
                   + '<div class="fw-semibold">' + n + '. ' + escHtml(s.title) + ' <span class="small fw-normal">(' + escHtml(word) + ')</span></div>';
                if (state === 'now') h += '<p class="small mb-2">' + escHtml(s.text) + '</p>' + osRelAction(n, target, jp, os);
                h += '</div></li>';
            });
            list.innerHTML = h;
            // L'ultimo passo non ha pulsanti: il controllo parte da solo, una volta.
            if (now === 4 && !osReleaseRender.checked) { osReleaseRender.checked = true; upCheck(); }
        }

        // Il pulsante (o i pulsanti) del passo di adesso.
        function osRelAction(n, target, jp, os) {
            if (n === 1) {
                return '<button type="button" class="btn btn-primary touch-target" data-on-click="osRelPrepare()">'
                    + '<i class="fas fa-clipboard-check me-1" aria-hidden="true"></i>' + escHtml(t('osu.s1.go')) + '</button>';
            }
            if (n === 2) {
                const cmd = 'freebsd-update -r ' + target + '-RELEASE upgrade';
                return '<pre class="upd-log mb-2" id="os-cmd">' + escHtml(cmd) + '</pre>'
                    + '<div class="d-flex flex-wrap gap-2">'
                    + '<button type="button" class="btn btn-outline-secondary touch-target" data-on-click="osRelCopy()"><i class="fas fa-copy me-1" aria-hidden="true"></i>' + escHtml(t('osu.s2.copy')) + '</button>'
                    + '<button type="button" class="btn btn-primary touch-target" data-on-click="osRelFetched()"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('osu.s2.done')) + '</button>'
                    + '<span class="small align-self-center" id="os-cmd-copied" role="status"></span>'
                    + '</div><p class="small mt-3 mb-0"><button type="button" class="btn btn-link btn-sm p-0" data-on-click="osRelCancel()">' + escHtml(t('osu.cancel')) + '</button></p>';
            }
            if (n === 3) {
                if (os.restartNeeded)
                    return '<div class="alert alert-warning py-2 mb-2">' + escHtml(t('osu.s3.restart')) + '</div>' + osRestartButton();
                return (jp.phase === 'error' || jp.phase === 'too-many-rounds'
                        ? '<div class="alert alert-danger py-2 mb-2">' + escHtml(t('osu.s3.failed')) + '</div>' : '')
                    + '<button type="button" class="btn btn-primary touch-target" data-on-click="osRelInstall()">'
                    + '<i class="fas fa-download me-1" aria-hidden="true"></i>' + escHtml(t('osu.s3.go', { target: target })) + '</button>';
            }
            return '';
        }

        // Passo 1: i controlli e, se sono a posto, la preparazione con una sola conferma. Se qualcosa non va si
        // vedono solo le righe che fermano, con cosa fare.
        async function osRelPrepare() {
            const el = document.getElementById('up-body'), pre = document.getElementById('up-log'), target = osRelTarget();
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('osu.checking'));
            const r = await updApi('os_upgrade_preflight', { target: target });
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + updEsc(r.error) + '</div>'; return; }
            const stops = (r.checks || []).filter(c => c.level === 'block');
            if (r.blocked || stops.length) {
                let h = '<div class="alert alert-danger py-2 mb-0"><p class="mb-2"><strong>' + escHtml(t('osu.blocked')) + '</strong></p><ul class="mb-0">';
                stops.forEach(c => { h += '<li><strong>' + updEsc(c.label) + '</strong>: ' + updEsc(c.detail) + '</li>'; });
                el.innerHTML = h + '</ul></div>';
                return;
            }
            el.innerHTML = '';
            const yes = await panelAsk({ title: t('osu.prepAskTitle', { target: target }),
                text: t('osu.prepAskText', { n: (r.checks || []).length }), confirm: t('osu.prepAskGo') });
            if (!yes) return;
            const s = await updApi('os_upgrade_prepare', { confirm: 'PREPARE UPGRADE', target: target });
            if (!s.success) { el.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + updEsc(s.error) + '</div>'; return; }
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('osu.preparing'));
            osLogBox('up-log-box', true);
            planPoll(s.jobId, el, pre, () => { el.innerHTML = ''; ucLoad(true); });
        }

        async function osRelCopy() {
            const cmd = (document.getElementById('os-cmd') || {}).textContent || '';
            const said = document.getElementById('os-cmd-copied');
            try { await navigator.clipboard.writeText(cmd); if (said) said.textContent = t('osu.copied'); }
            catch (e) { if (said) said.textContent = t('osu.copyFailed'); }
        }

        // Passo 2 fatto? Lo dice freebsd-update, non la persona: si rilegge e si guarda se la release e' scaricata.
        async function osRelFetched() {
            await ucLoad(true);
            if (!(uc.jump || {}).upgradeFetched)
                document.getElementById('up-body').innerHTML = '<div class="alert alert-info py-2 mb-0">' + escHtml(t('osu.s2.notYet')) + '</div>';
        }

        async function osRelCancel() {
            const target = osRelTarget();
            const yes = await panelAsk({ title: t('osu.cancel'), text: t('osu.cancelAsk', { target: target }), confirm: t('osu.cancel') });
            if (!yes) return;
            const r = await updApi('jump_cancel', { confirm: 'CANCEL' });
            document.getElementById('up-body').innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 mb-0">'
                + updEsc(r.note || r.error || '') + '</div>';
            ucLoad(true);
        }

        // Passo 3: freebsd-update install a giri; si ferma quando serve un riavvio, e dopo il riavvio si riprende da qui.
        async function osRelInstall() {
            const target = osRelTarget();
            const yes = await panelAsk({ title: t('osu.installAskTitle', { target: target }), text: t('osu.installAskText'),
                confirm: t('osu.installAskGo') });
            if (!yes) return;
            const el = document.getElementById('up-body'), pre = document.getElementById('up-log');
            const r = await updApi('jump_continue', { confirm: 'CONTINUE', target: target });
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + updEsc(r.error) + '</div>'; return; }
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('osu.installing'));
            osLogBox('up-log-box', true);
            planPoll(r.jobId, el, pre, () => { el.innerHTML = ''; ucLoad(true); if (typeof panelRebootRefresh === 'function') panelRebootRefresh(); });
        }

        // ---------- i registri delle operazioni (Diagnostica) ----------
        // Ogni lavoro guidato scrive il suo registro anche su disco (JobJournal): qui l'elenco, dal piu' recente, e il
        // testo di quello scelto. Restano dopo un riavvio del pannello o del server, quando il registro della pagina non c'e' piu'.
        async function jrList() {
            const box = document.getElementById('jr-list');
            box.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('up.reading'));
            const r = await updApi('journal_list');
            if (!r.success) { box.innerHTML = '<span class="text-danger">' + updEsc(r.error) + '</span>'; return; }
            const list = r.journals || [];
            if (!list.length) { box.innerHTML = '<p class="small mb-0">' + escHtml(t('jr.none')) + '</p>'; return; }
            const kind = { 'os-patch': t('jr.type.osPatch'), 'os-fetch': t('jr.type.osFetch'), system: t('jr.type.system'), jump: t('jr.type.jump'),
                search: t('jr.type.search'), update: t('jr.type.update'), guided_update: t('jr.type.guidedUpdate'),
                maintenance: t('jr.type.maintenance'), roundcube: t('jr.type.roundcube'), python: t('jr.type.python'),
                mysql84_migration: t('jr.type.mysql84'), pkg_branch: t('jr.type.branch'), update_everything: t('jr.type.everything') };
            const outcome = { completed: t('jr.ok'), error: t('jr.error'), unfinished: t('jr.unfinished'), ended: t('jr.ended') };
            const badge = { completed: 'upd-badge-ok', error: 'upd-badge-warn', unfinished: 'upd-badge-warn', ended: 'upd-badge-info' };
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><caption class="visually-hidden">' + escHtml(t('jr.title')) + '</caption>'
                + '<thead><tr><th scope="col">' + escHtml(t('jr.colWhen')) + '</th><th scope="col">' + escHtml(t('jr.colWhat')) + '</th>'
                + '<th scope="col">' + escHtml(t('jr.colOutcome')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('jr.view')) + '</span></th></tr></thead><tbody>';
            list.forEach(j => {
                const when = new Date(j.startedUtc);
                h += '<tr class="upd-cell"><td class="small">' + escHtml(isNaN(when) ? j.startedUtc : when.toLocaleString()) + '</td>'
                   + '<td>' + escHtml(kind[j.type] || j.type) + '</td>'
                   + '<td><span class="badge ' + (badge[j.status] || 'upd-badge-info') + '">' + escHtml(outcome[j.status] || j.status) + '</span></td>'
                   + '<td class="text-end"><button type="button" class="btn btn-sm btn-outline-secondary touch-target" data-name="' + escHtml(j.name) + '" data-on-click="jrShow(this.dataset.name)">'
                   + escHtml(t('jr.view')) + '</button></td></tr>';
            });
            box.innerHTML = h + '</tbody></table></div><p class="small text-muted mb-0">' + escHtml(t('jr.where', { dir: r.dir })) + '</p>';
        }

        async function jrShow(name) {
            const pre = document.getElementById('jr-text');
            pre.hidden = false;
            pre.textContent = t('up.reading');
            const r = await updApi('journal_read', { name: name });
            pre.textContent = r.success ? (r.truncated ? t('jr.truncated') + '\n' : '') + r.text : (r.error || t('common.errorShort'));
            pre.focus({ preventScroll: true });
            pre.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
