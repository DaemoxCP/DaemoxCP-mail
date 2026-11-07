
        // ---------- Aggiorna il server (reperto 186) ----------
        // Un posto solo per sapere cosa c'e' da aggiornare e farlo: il sistema di base, i pacchetti, quelli
        // del server di posta (protetti, uno alla volta), la Java del pannello, il ramo e il riavvio. Legge
        // con le azioni delle schede qui sotto e fa le cose con i loro lavori: qui cambia solo il percorso.
        const uc = { os: null, pk: null, branch: null, reboot: null };

        function ucEl(tag, cls, text) {
            const e = document.createElement(tag);
            if (cls) e.className = cls;
            if (text !== undefined) e.textContent = text;
            return e;
        }

        function ucButton(cls, icon, label, action) {
            const b = ucEl('button', 'btn btn-sm touch-target ' + cls);
            b.type = 'button';
            const i = ucEl('i', 'fas ' + icon + ' me-1');
            i.setAttribute('aria-hidden', 'true');
            b.append(i, label);
            b.setAttribute('data-on-click', action);
            return b;
        }

        // Una riga: lo stato a parole (mai solo col colore), un'icona, e i pulsanti di quello che c'e' da fare.
        function ucRow(kind, title, text, buttons, extra) {
            const li = ucEl('li', 'list-group-item d-flex flex-wrap align-items-start gap-2');
            const icon = ucEl('i', 'fas mt-1 ' + ({ ok: 'fa-circle-check text-success', todo: 'fa-circle-exclamation text-warning',
                info: 'fa-circle-info text-primary', error: 'fa-circle-xmark text-danger' }[kind] || 'fa-circle-info'));
            icon.setAttribute('aria-hidden', 'true');
            const body = ucEl('div', 'flex-grow-1');
            const head = ucEl('div', 'fw-semibold', title);
            const state = ucEl('span', 'visually-hidden', ' (' + t('uc.kind.' + kind) + ')');
            head.append(state);
            body.append(head, ucEl('div', 'small', text));
            if (extra) body.append(extra);
            li.append(icon, body);
            if (buttons && buttons.length) {
                const box = ucEl('div', 'd-flex flex-wrap gap-2');
                buttons.forEach(b => box.append(b));
                li.append(box);
            }
            return li;
        }

        async function ucLoad() {
            const state = document.getElementById('ucState');
            state.textContent = t('uc.reading');
            [uc.os, uc.pk, uc.branch] = [await updApi('os_status'), await updApi('packages_overview'), await updApi('branch_status')];
            uc.reboot = typeof panelRebootRefresh === 'function' ? await panelRebootRefresh() : null;
            ucRender();
            state.textContent = '';
        }

        function ucRender() {
            const list = document.getElementById('ucList');
            list.replaceChildren();
            const os = uc.os || {}, pk = uc.pk || {}, br = uc.branch || {}, rb = uc.reboot || {};

            // 1. Il sistema di base
            if (!os.success) {
                list.append(ucRow('error', t('uc.os'), os.error || t('common.errorShort')));
            } else if (!os.updatableWithFreebsdUpdate) {
                list.append(ucRow('info', t('uc.os'), os.updatesNote || ''));
            } else if (os.readyExist) {
                list.append(ucRow('todo', t('uc.os'), t('uc.osReady', { now: os.userland, target: os.readyTarget || '?' })
                    + (os.readyKernel ? ' ' + t('osp.readyKernel') : ''),
                    [ucButton('btn-primary', 'fa-download', t('osp.install'), 'osInstall()')]));
            } else {
                list.append(ucRow('ok', t('uc.os'), t('uc.osOk', { now: os.userland })));
            }

            // 2. I pacchetti che non sono del server di posta: un piano, un pulsante
            const sum = pk.summary || {};
            const rows = pk.packages || [];
            const stack = rows.filter(p => p.update && p.locked);
            const plain = (sum.updates || 0) - stack.length;
            if (!pk.success) {
                list.append(ucRow('error', t('uc.packages'), pk.error || t('common.errorShort')));
            } else if (plain > 0) {
                list.append(ucRow('todo', t('uc.packages'), tn('uc.packagesTodo', plain)
                    + (sum.fixable ? ' ' + tn('uc.packagesFix', sum.fixable) : ''),
                    [ucButton('btn-primary', 'fa-arrow-up', t('uc.packagesGo'), 'ucPackages()')]));
            } else {
                list.append(ucRow('ok', t('uc.packages'), t('uc.packagesOk')));
            }

            // 3. Quelli del server di posta: protetti, uno alla volta, ognuno col suo controllo
            if (pk.success) {
                if (!stack.length) {
                    list.append(ucRow('ok', t('uc.stack'), t('uc.stackOk')));
                } else {
                    const items = ucEl('ul', 'list-unstyled small mb-0 mt-1');
                    const buttons = [];
                    stack.forEach(p => {
                        items.append(ucEl('li', '', p.name + ': ' + p.installed + ' \u2192 ' + p.available
                            + (p.canUpdate || p.javaFlow ? '' : ' (' + (p.whyNot || t('pkgs.heldBack')) + ')')));
                        if (p.canUpdate) {
                            const b = ucButton('btn-outline-primary', 'fa-arrow-up', t('pkgs.update', { v: p.available }) + ' (' + p.name + ')', 'pkUpdOpen(this.dataset.pkg)');
                            b.dataset.pkg = p.name;
                            buttons.push(b);
                        } else if (p.javaFlow) {
                            buttons.push(ucButton('btn-outline-primary', 'fa-mug-hot', t('pkgs.javaFlow'), 'pkGoJava()'));
                        }
                    });
                    list.append(ucRow('todo', t('uc.stack'), tn('uc.stackTodo', stack.length), buttons, items));
                }
            }

            // 4. Il ramo
            if (br.success) {
                const b = ucButton('btn-outline-secondary', 'fa-code-branch', t('uc.branchGo'), 'ucGoBranch()');
                list.append(ucRow('info', t('uc.branch'), t('uc.branchNow', { branch: br.branch || '?' }), [b]));
            }

            // 5. Il riavvio
            if (rb && rb.success) {
                if (rb.state === 'needed' || rb.state === 'advised') {
                    list.append(ucRow('todo', t('uc.reboot'), rb.state === 'needed'
                        ? t('rb.needed', { installed: rb.installedKernel, running: rb.runningKernel }) : t('rb.advised'),
                        document.getElementById('panelRebootModal') ? [ucButton('btn-warning', 'fa-rotate-right', t('rb.open'), 'panelRebootOpen()')] : []));
                } else {
                    list.append(ucRow('ok', t('uc.reboot'), rb.scheduled ? t('rb.scheduled') : t('uc.rebootNo')));
                }
            }
        }

        // Cerca: scarica cataloghi, vulnerabilita' e patch (non installa niente), poi rilegge tutto.
        async function ucSearch() {
            const pre = document.getElementById('uc-log');
            const state = document.getElementById('ucState');
            state.textContent = t('uc.searching');
            ucOutcome(true, '');
            pre.hidden = false;
            pre.textContent = '';
            const r = await updApi('updates_search', { confirm: 'SEARCH' });
            if (!r.success) { state.textContent = r.error || t('common.errorShort'); return; }
            ucFollow(r.jobId, () => { ucLoad(); osState(); pkOverview(); });
        }

        // L'esito di un lavoro: in un posto suo, che la rilettura della scheda non copre.
        function ucOutcome(ok, text) {
            const box = document.getElementById('ucOutcome');
            box.replaceChildren(text ? ucEl('div', 'alert py-2 small mb-2 ' + (ok ? 'alert-success' : 'alert-danger'), text) : '');
        }

        // Segue un lavoro nel registro della scheda, poi fa 'after'.
        async function ucFollow(id, after) {
            const pre = document.getElementById('uc-log');
            const state = document.getElementById('ucState');
            const s = await updApi('job_status', { jobId: id });
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed') {
                    state.textContent = '';
                    ucOutcome(true, s.job.result || t('up.opDone', { s: s.job.elapsedSeconds }));
                    after();
                    return;
                }
                if (s.job.status === 'error') {
                    state.textContent = '';
                    ucOutcome(false, t('up.opFailed') + ' ' + (s.job.errorMessage || ''));
                    return;
                }
            }
            setTimeout(() => ucFollow(id, after), 3000);
        }

        // I pacchetti fuori dal server di posta: il piano esatto (lo stesso di «Verifica»), una conferma che
        // lo mostra, e il lavoro che esegue quel piano o niente (la firma).
        async function ucPackages() {
            const state = document.getElementById('ucState');
            ucOutcome(true, '');
            state.textContent = t('uc.planning');
            const r = await updApi('updates_status');
            if (!r.success) { state.textContent = r.error || t('common.errorShort'); return; }
            const plan = r.plan || {};
            if (!plan.measured) { state.textContent = t('up.planUnavailable') + ' ' + (plan.error || ''); return; }
            const changes = plan.changes || [];
            if (!changes.length) { state.textContent = t('up.planNoChange'); return; }
            if (changes.some(c => c.type === 'remove' || c.type === 'downgrade')) {
                state.textContent = t('uc.planRemoves');
                document.getElementById('updates').scrollIntoView();
                updStatus();
                return;
            }
            state.textContent = '';
            const lines = changes.map(c => c.name + ': ' + (c.from || '-') + ' \u2192 ' + (c.to || '-')).join('\n');
            const yes = await panelAsk({ title: tn('uc.pkAskTitle', changes.length), text: t('uc.pkAskText') + '\n' + lines,
                confirm: tn('uc.pkAskGo', changes.length) });
            if (!yes) return;
            updUnprotectedSignature = r.signature;
            const a = await updApi('updates_apply', { confirm: 'UPDATE', signature: r.signature });
            if (!a.success) { state.textContent = a.error || t('common.errorShort'); return; }
            const pre = document.getElementById('uc-log');
            pre.hidden = false;
            ucOutcome(true, '');
            state.textContent = t('up.upgradingKeepOpen');
            ucFollow(a.jobId, () => { ucLoad(); pkOverview(); });
        }

        function ucShow() {
            const card = document.getElementById('update-center');
            if (card) { card.scrollIntoView({ behavior: 'smooth' }); document.getElementById('ucTitle').setAttribute('tabindex', '-1'); document.getElementById('ucTitle').focus({ preventScroll: true }); }
        }

        function ucGoBranch() {
            const card = document.getElementById('branch');
            if (card) { card.scrollIntoView({ behavior: 'smooth' }); card.querySelector('button, a') && card.querySelector('button, a').focus({ preventScroll: true }); }
        }

        document.addEventListener('DOMContentLoaded', () => { ucLoad(); });
