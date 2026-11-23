
        // ---------- Update the server (findings 186, 193) ----------
        // A single place to know what there is to update and to do it. Each row has its header (the state in
        // words and the buttons), which is redrawn when the data arrive, and its panel below, which stays where it
        // is: the button opens it in place, without sending to another card. The rows for Java, Roundcube, MySQL
        // and Python appear only when the server says they are needed (packages_overview, "procedures"). The jobs
        // are the usual ones.
        const uc = { os: null, pk: null, reboot: null, targets: null, jump: null, plainBlocked: false, turn: null };

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

        // A row's header: the state in words (never only with color), an icon, the buttons.
        function ucHead(key, kind, title, text, buttons, extra) {
            const li = document.getElementById('uc-' + key);
            if (!li) return;
            const head = li.querySelector('.uc-head');
            head.className = 'uc-head d-flex flex-wrap align-items-start gap-2';
            head.replaceChildren();
            const icon = ucEl('i', 'fas mt-1 ' + ({ ok: 'fa-circle-check text-success', todo: 'fa-circle-exclamation text-warning',
                info: 'fa-circle-info text-primary', error: 'fa-circle-xmark text-danger' }[kind] || 'fa-circle-info'));
            icon.setAttribute('aria-hidden', 'true');
            const body = ucEl('div', 'flex-grow-1');
            const name = ucEl('div', 'fw-semibold', title);
            // The keys written in full: I18nTest checks that every text used exists in both languages.
            const word = { ok: t('uc.kind.ok'), todo: t('uc.kind.todo'), info: t('uc.kind.info'), error: t('uc.kind.error') }[kind] || '';
            name.append(ucEl('span', 'visually-hidden', ' (' + word + ')'));
            body.append(name, ucEl('div', 'small', text));
            if (extra) body.append(extra);
            head.append(icon, body);
            if (buttons && buttons.length) {
                const box = ucEl('div', 'd-flex flex-wrap gap-2');
                buttons.forEach(b => box.append(b));
                head.append(box);
            }
            li.hidden = false;
        }

        function ucHide(key) {
            const li = document.getElementById('uc-' + key);
            if (li) li.hidden = true;
        }

        // Opens a row's panel, under the row. 'panel' is a piece that moves (the package plan, only one for
        // two rows). Focus goes to the panel, which can be seen without scrolling elsewhere.
        function ucOpen(key, panel) {
            const detail = document.getElementById('uc-' + key + '-detail');
            if (!detail) return;
            if (panel) {
                const p = document.getElementById(panel);
                if (p) { if (p.parentElement !== detail) detail.appendChild(p); p.hidden = false; }
            }
            detail.hidden = false;
            detail.setAttribute('tabindex', '-1');
            detail.focus({ preventScroll: true });
            detail.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }

        // The rows' actions: they open the panel under the row and start from there.
        // Once a row's panel is open, its button is in there: the header is redrawn without it (finding 197).
        function ucOpened(key) {
            const d = document.getElementById('uc-' + key + '-detail');
            return !!(d && !d.hidden);
        }
        function ucMysql() { ucOpen('mysql'); ucRender(); my84Pre(); }
        function ucPython() { ucOpen('python'); ucRender(); pyPre(); }
        function ucDovecot() { ucOpen('dovecot'); ucRender(); dc24Pre(); }
        function ucPythonLeftovers() { ucOpen('python'); pyLeftovers(); }

        // Reads the FreeBSD state; packages, branch and restart arrive from their own reads (events below):
        // rereading them here doubled the page's heaviest read. "Reread" redoes them all.
        async function ucLoad(all) {
            const state = document.getElementById('ucState');
            if (!state || !document.getElementById('ucList')) return;
            state.textContent = t('uc.reading');
            if (all) {
                // On rereading, the package plan is redone: if before it could not be run, now it will show.
                uc.plainBlocked = false;
                pkOverview();
                branchStatus();
                if (typeof panelRebootRefresh === 'function') panelRebootRefresh();
            }
            uc.os = await updApi('os_status');
            // The newest releases and the state of a move already started: they decide what the FreeBSD row says.
            uc.targets = await updApi('os_upgrade_targets');
            uc.jump = await updApi('jump_state');
            ucRender();
            state.textContent = '';
        }

        document.addEventListener('upd:packages', e => { uc.pk = e.detail; ucRender(); });
        document.addEventListener('panel:reboot', e => { uc.reboot = e.detail; ucRender(); });

        // The mail server's package steps. Those of the same family (php84 and its extensions, MySQL server
        // and client, Dovecot and its components) are updated TOGETHER: the server unlocks them and updates
        // them together anyway (UpdateManager, FAMILIES). So they are ONE step, with the name of the main
        // package. On the production server the row said "1 of 30", and 27 were PHP (finding 203). A step is
        // ready only if all its packages are.
        function ucSteps(stack) {
            const steps = [];
            stack.forEach(p => {
                const key = p.family || p.name;
                let s = steps.find(x => x.key === key);
                if (!s) steps.push(s = { key: key, members: [] });
                s.members.push(p);
            });
            steps.forEach(s => {
                s.members.sort((a, b) => a.name.length - b.name.length || a.name.localeCompare(b.name));
                s.head = s.members[0];
                s.held = s.members.filter(p => !p.canUpdate);
            });
            return steps;
        }

        function ucRender() {
            if (!document.getElementById('ucList')) return;
            const os = uc.os || {}, pk = uc.pk || {}, rb = uc.reboot || {};
            const proc = pk.procedures || {};
            const rows = pk.packages || [];
            const reading = (key, title) => ucHead(key, 'info', title, t('uc.reading'));

            // 0. "Update everything", at the top (finding 207): the list of what it will do, in order, and a single
            //    button. If a mail server package is not locked, it is locked first: the plan of the others would
            //    change it.
            if (uc.turn && uc.turn.java) ucHead('all', 'todo', t('uc.everythingTitle'), t('uc.everythingJavaRunning'));
            else if (!uc.os || !uc.pk) reading('all', t('uc.everythingTitle'));
            else {
                const planned = ucPlanned();
                const unlocked = ((uc.pk || {}).summary || {}).stackUnlocked || 0;
                if (unlocked > 0) {
                    ucHead('all', 'todo', t('uc.everythingTitle'), tn('pkgs.stackUnlocked', unlocked) + ' ' + t('uc.everythingProtectFirst'),
                        [ucButton('btn-primary', 'fa-lock', t('pkgs.bulk.lockAll'), 'updLockAll(true)')]);
                } else if (planned.length) {
                    const list = ucEl('ol', 'small mb-0 mt-1 ps-3');
                    planned.forEach(p => list.append(ucEl('li', '', p.label)));
                    // The button always stays: even with a job's outcome open below (it used to hide it, leaving a
                    // row without a button: "the possibility to update disappears altogether"). While a job runs,
                    // it waits.
                    ucHead('all', 'todo', t('uc.everythingTitle'), tn('uc.everythingSummary', planned.length),
                        [ucButton('btn-primary', 'fa-arrow-up', tn('uc.everything', planned.length), 'ucEverything()')], list);
                } else if (uc.plainBlocked) {
                    // The plan of the other packages would remove or downgrade something: it is not "nothing to
                    // update".
                    ucHead('all', 'todo', t('uc.everythingTitle'), t('uc.everythingPlainBlocked'));
                } else ucHead('all', 'ok', t('uc.everythingTitle'), gdDone.all || t('uc.everythingNone'));
            }

            // 1. The base system, guided (finding 196): a sentence and the button of the next step. First a release
            //    move already started, then a missing restart, then the ready patches. A new release only if there
            //    is one.
            // With the row's panel open, the next step's button is in there: in the header it would be a duplicate.
            const osDetail = document.getElementById('uc-os-detail');
            const osOpen = !!(osDetail && !osDetail.hidden);
            const restart = () => document.getElementById('panelRebootModal') && !osOpen
                ? [ucButton('btn-warning', 'fa-rotate-right', t('osu.restartGo'), 'panelRebootOpen()')] : [];
            const moving = osMoving();
            if (!uc.os) reading('os', t('uc.os'));
            else if (!os.success) ucHead('os', 'error', t('uc.os'), os.error || t('common.errorShort'));
            else if (moving) {
                ucHead('os', 'todo', t('uc.os'), t('osu.moving', { target: osRelTarget(), n: osRelStep() }),
                    osOpen ? [] : [ucButton('btn-primary', 'fa-list-check', t('osu.openMove'), 'ucRelease()')]);
            } else if (os.restartNeeded) {
                ucHead('os', 'todo', t('uc.os'), t('osu.patchRestartRow', { now: os.userland, kernel: os.installedKernel }), restart());
            } else if (!os.updatableWithFreebsdUpdate) ucHead('os', 'info', t('uc.os'), os.updatesNote || '');
            else if (os.readyExist) {
                ucHead('os', 'todo', t('uc.os'), t('uc.osReady', { now: os.userland, target: os.readyTarget || '?' })
                    + (os.readyKernel ? ' ' + t('osp.readyKernel') : ''));
            } else ucHead('os', 'ok', t('uc.os'), t('uc.osOk', { now: os.userland }));
            // A new release: one more row with its button, only when there is one and nothing else is in progress.
            const tv = (uc.targets && uc.targets.success && uc.targets.versions) || [];
            if (uc.os && os.success && !moving && !os.restartNeeded && tv.length) {
                const v = tv[tv.length - 1];
                const line = ucEl('div', 'd-flex flex-wrap align-items-center gap-2 mt-2 small');
                line.append(ucEl('span', '', t('osu.newRelease', { version: v.version, date: v.endOfSupport })),
                    ucButton('btn-outline-primary', 'fa-forward', t('osu.moveTo', { version: v.version }), 'ucRelease()'));
                document.querySelector('#uc-os .uc-head .flex-grow-1').append(line);
            }
            const releaseView = document.getElementById('os-release');
            if (releaseView && !releaseView.hidden) osReleaseRender();

            // The dedicated procedures have their own row: here below they are not counted twice.
            const own = p => p.javaFlow || (proc.roundcube && p.name === proc.roundcubePackage);

            // 2. The packages, in a single row (finding 202). Two ways of updating them, because two different
            //    risks: those outside the mail server all together in one plan; those of the mail server, locked,
            //    one at a time, each with its check and the restart of the services that use it (findings 42,
            //    197). The sentence says how many of each kind; the button is ONE, the next step: first the plan,
            //    then the next mail one. If the plan cannot be run (it would remove packages), the next step moves
            //    on to the mail ones.
            const sum = pk.summary || {};
            const stack = rows.filter(p => p.update && p.locked && !own(p));
            const plain = (sum.updates || 0) - rows.filter(p => p.update && p.locked).length;
            const steps = ucSteps(stack);
            const ready = steps.filter(s => !s.held.length);
            // What the "Update everything" list already shows is not repeated here (finding 207: the same counts
            // twice).
            const listed = uc.os && uc.pk && !(sum.stackUnlocked > 0) ? ucPlanned() : [];
            const plainListed = listed.some(p => p.kind === 'plain'), stackListed = listed.some(p => p.kind === 'package');
            // Java and Roundcube are packages too: with a step of theirs in the list (or Java being updated) the
            // row does not say "all up to date".
            const anyListed = listed.some(p => p.kind !== 'os') || !!(uc.turn && uc.turn.java);
            if (!uc.pk) reading('packages', t('uc.packages'));
            else if (!pk.success) ucHead('packages', 'error', t('uc.packages'), pk.error || t('common.errorShort'));
            else if (pk.catalogError) ucHead('packages', 'error', t('uc.packages'), t('pkgs.catalogError', { error: pk.catalogError }));
            else {
                const words = [];
                if (anyListed) words.push(t('uc.pkInAll'));
                if (plain > 0 && !plainListed) words.push(tn('uc.pkPlain', plain));
                // Several packages in a single step (a family) are not "in 1 steps": they have their own sentence.
                if (stack.length && !stackListed) words.push((steps.length === 1 && stack.length > 1 ? t('uc.pkStackFamily', { n: stack.length })
                    : tn('uc.pkStack', stack.length, { steps: steps.length })) + (ready.length ? '' : ' ' + t('uc.stackHeld')));
                if (sum.fixable) words.push(tn('uc.packagesFix', sum.fixable));
                const open = (sum.vulnerable || 0) - (sum.fixable || 0);
                if (open > 0) words.push(tn('uc.pkVulnOpen', open));
                // The steps to take are in the "Update everything" list, at the top (finding 207): here only the
                // held-back ones, with the reason, and the missing lock.
                const extra = ucEl('div');
                const held = steps.filter(x => x.held.length);
                if (held.length) {
                    const items = ucEl('ul', 'list-unstyled small mb-0 mt-1');
                    held.forEach(x => items.append(ucEl('li', '', x.head.name + ': ' + x.head.installed + ' → ' + x.head.available + ' ('
                        + x.held.map(p => (x.members.length > 1 ? p.name + ': ' : '') + (p.whyNot || t('pkgs.heldBack'))).join('; ') + ')')));
                    extra.append(items);
                }
                if (sum.stackUnlocked > 0)
                    extra.append(ucEl('div', 'mt-2 small text-warning-emphasis', tn('pkgs.stackUnlocked', sum.stackUnlocked)));
                if (words.length || sum.stackUnlocked > 0) ucHead('packages', 'todo', t('uc.packages'), words.join(' '), [], extra);
                else ucHead('packages', 'ok', t('uc.packages'), t('uc.pkOk'), [], extra);
            }

            // 3. The dedicated procedures, only when they are needed
            const doneRow = (key, title) => gdDone[key] ? ucHead(key, 'ok', title, gdDone[key]) : ucHide(key);
            // The panel's Java and Roundcube are steps of "Update everything" (finding 207): no rows of their own.
            ucHide('java');
            ucHide('roundcube');
            if (proc.mysql84) {
                ucHead('mysql', 'todo', t('uc.mysql'), t('uc.mysqlTodo'),
                    ucOpened('mysql') ? [] : [ucButton('btn-primary', 'fa-clipboard-check', t('uc.prepare'), 'ucMysql()')]);
            } else doneRow('mysql', t('uc.mysql'));
            // Dovecot 2.4 (finding 213): a separate package, nothing moves to it by itself; the row says it is
            // there and guides the move.
            if (proc.dovecot24) {
                ucHead('dovecot', 'todo', t('uc.dovecot'), t('uc.dovecotTodo'),
                    ucOpened('dovecot') ? [] : [ucButton('btn-primary', 'fa-clipboard-check', t('uc.prepare'), 'ucDovecot()')]);
            } else doneRow('dovecot', t('uc.dovecot'));
            if (proc.python) {
                ucHead('python', 'todo', t('uc.python'), t('uc.pythonTodo'),
                    ucOpened('python') ? [] : [ucButton('btn-primary', 'fa-clipboard-check', t('uc.prepare'), 'ucPython()')]);
            } else if (gdDone.python) {
                // The move done: the next step is removing the remains of the old family, with its button.
                ucHead('python', 'ok', t('uc.python'), gdDone.python + ' ' + t('gd.pyNext'),
                    [ucButton('btn-outline-primary', 'fa-broom', t('up.leftovers'), 'ucPythonLeftovers()')]);
            } else ucHide('python');

            // The package branch has its own card, below (finding 205).

            // 4. The restart: the panel's window, the same as on every page
            if (!uc.reboot) reading('reboot', t('uc.reboot'));
            else if (rb.success && rb.state === 'needed' && os.restartNeeded) ucHide('reboot');
            else if (rb.success) {
                if (rb.state === 'needed' || rb.state === 'advised') {
                    ucHead('reboot', 'todo', t('uc.reboot'), rb.state === 'needed'
                        ? t('rb.needed', { installed: rb.installedKernel, running: rb.runningKernel }) : t('rb.advised'),
                        document.getElementById('panelRebootModal') ? [ucButton('btn-warning', 'fa-rotate-right', t('rb.open'), 'panelRebootOpen()')] : []);
                } else ucHead('reboot', 'ok', t('uc.reboot'), rb.scheduled ? t('rb.scheduled') : t('uc.rebootNo'));
            }
            ucWaitForTurn();
        }

        // The package job in progress (finding 206). The owner, refused twice while a search for updates was
        // running: "it doesn't show what it is doing or anything". Now the card asks the server who holds
        // the turn, on opening and every 15 seconds (every 3 while it runs): it says so at the top, with what
        // it is doing, and meanwhile the step buttons and "Check for updates" wait. When it finishes, the
        // card reads itself again and says the next step. This applies to every panel job, started from
        // here, from another page or from another card.
        let ucTurnTimer = null;
        async function ucTurn() {
            clearTimeout(ucTurnTimer);
            let r = null;
            try { r = await updApi('package_turn'); } catch (e) { r = null; }
            const was = !!(uc.turn && uc.turn.running), wasJava = !!(uc.turn && uc.turn.java);
            uc.turn = r && r.success ? r : null;
            const now = !!(uc.turn && uc.turn.running), nowJava = !!(uc.turn && uc.turn.java);
            await ucRunningShow();
            // The panel's Java being updated (finding 210): the "Update everything" row says so, and the page
            // waits for the panel to come back before reloading, even if it was reloaded halfway.
            if (wasJava !== nowJava) ucRender();
            if (nowJava) ucAwaitPanel();
            ucWaitForTurn();
            if (was && !now) ucLoad(true);
            ucTurnTimer = setTimeout(ucTurn, now ? 3000 : 15000);
        }

        async function ucRunningShow() {
            const box = document.getElementById('ucRunning');
            if (!box) return;
            const turn = uc.turn;
            if (!turn || !turn.running) { box.hidden = true; return; }
            document.getElementById('ucRunningText').textContent = turn.java ? t('uc.runningJava') : t('uc.running', { who: turn.who || '' });
            box.hidden = false;
            const logBox = document.getElementById('ucRunningLogBox');
            // The Java script is not a panel job: its log arrives with the turn.
            if (turn.java) {
                ucRunningLogShow(turn.log || '');
                logBox.hidden = false;
                return;
            }
            if (!turn.jobId) { logBox.hidden = true; ucRunningNow(''); return; }
            const s = await updApi('job_status', { jobId: turn.jobId });
            if (!(s && s.success && s.job)) return;
            ucRunningLogShow(s.job.consoleLog || '');
            logBox.hidden = false;
        }

        // The log under the "In progress" row, and above it the current step (finding 210: "I don't
        // understand how far along it is").
        function ucRunningLogShow(text) {
            const pre = document.getElementById('ucRunningLog');
            pre.textContent = text;
            pre.scrollTop = pre.scrollHeight;
            ucRunningNow(text);
        }

        // The current step, from the log: the step of the "Update everything" chain ("=== Step 2 of 3: ... ===")
        // and, inside it, its last "[n/m] ...". Without the time in front, which the panel's log puts on every
        // line.
        function ucRunningNow(text) {
            const el = document.getElementById('ucRunningNow');
            if (!el) return;
            const lines = String(text).split('\n').map(l => l.replace(/^\[\d{2}:\d{2}:\d{2}\]\s*/, '').replace(/^\d{4}-\d{2}-\d{2}T[\d:]+Z\s*/, '').trim());
            let chain = '', step = '';
            lines.forEach(l => {
                const c = l.match(/^=== (.+ \d+ .+ \d+: .+) ===$/);
                if (c && /\d+/.test(c[1]) && !/^(end|job)\b/.test(c[1])) { chain = c[1]; step = ''; }
                if (/^\[\d+\/\d+\] /.test(l)) step = l;
            });
            const now = [chain, step].filter(Boolean).join(' — ');
            el.textContent = now ? t('uc.runningNow', { step: now }) : '';
            el.hidden = !now;
        }

        // The step buttons and "Check for updates" wait for the job in progress, and say so.
        function ucWaitForTurn() {
            const busy = !!(uc.turn && uc.turn.running);
            const buttons = [...document.querySelectorAll('#ucList .uc-head button')];
            const search = document.getElementById('ucSearchButton');
            if (search) buttons.push(search);
            buttons.forEach(b => {
                b.disabled = busy;
                if (busy) { b.title = t('uc.runningWait'); b.setAttribute('aria-describedby', 'ucRunningText'); }
                else { b.removeAttribute('title'); b.removeAttribute('aria-describedby'); }
            });
        }

        // Check: downloads catalogs, vulnerabilities and patches (installs nothing), then rereads everything.
        async function ucSearch() {
            const pre = document.getElementById('uc-log');
            const state = document.getElementById('ucState');
            state.textContent = t('uc.searching');
            ucOutcome(true, '');
            osLogBox('uc-log-box', true);
            pre.textContent = '';
            const r = await updApi('updates_search', { confirm: 'SEARCH' });
            ucTurn();
            if (!r.success) { state.textContent = r.error || t('common.errorShort'); return; }
            ucFollow(r.jobId, () => { ucLoad(true); });
        }

        // A job's outcome: in a place of its own, which the card's reread does not cover.
        function ucOutcome(ok, text) {
            const box = document.getElementById('ucOutcome');
            box.replaceChildren(text ? ucEl('div', 'alert py-2 small mb-2 ' + (ok ? 'alert-success' : 'alert-danger'), text) : '');
        }

        // Follows a job in the card's log, then does 'after'.
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

        // What "Update everything" would do now, in order (finding 207): the FreeBSD patches, the other packages
        // in one plan, the mail server steps (a package, or a family with its main one), Roundcube with its
        // procedure, and last the panel's Java, which stops and restarts it.
        function ucPlanned() {
            const os = uc.os || {}, pk = uc.pk || {}, proc = pk.procedures || {}, rows = pk.packages || [], sum = pk.summary || {};
            const own = p => p.javaFlow || (proc.roundcube && p.name === proc.roundcubePackage);
            const out = [];
            if (os.success && os.updatableWithFreebsdUpdate && os.readyExist && !os.restartNeeded && !osMoving())
                out.push({ kind: 'os', label: t('uc.allOs', { target: os.readyTarget || '?' }) });
            if (!pk.success || pk.catalogError) return out;
            const plain = (sum.updates || 0) - rows.filter(p => p.update && p.locked).length;
            if (plain > 0 && !uc.plainBlocked) out.push({ kind: 'plain', label: tn('uc.allPlain', plain) });
            ucSteps(rows.filter(p => p.update && p.locked && !own(p))).filter(x => !x.held.length).forEach(x => out.push({ kind: 'package', step: x,
                label: x.members.length > 1 ? t('uc.pkFamilyLine', { name: x.head.name, more: x.members.length - 1, from: x.head.installed, to: x.head.available })
                                            : x.head.name + ': ' + x.head.installed + ' → ' + x.head.available }));
            const rc = rows.find(p => p.name === proc.roundcubePackage);
            if (proc.roundcube && rc) out.push({ kind: 'roundcube', label: t('uc.allRoundcube', { from: rc.installed, to: rc.available }) });
            const jvm = rows.find(p => p.javaFlow);
            if (proc.java && jvm && !(uc.turn && uc.turn.java)) out.push({ kind: 'java', label: t('uc.allJava', { from: jvm.installed, to: jvm.available }) });
            return out;
        }

        // "Update everything" (finding 207). The owner: "there is still disorganization, then if I click cancel
        // on the update, the possibility to update disappears altogether, you must substantially rethink
        // everything in a logical and simple way".
        // First the checks of each step, the same as its procedure; then ONE confirmation that lists them; then
        // ONE job that runs them one after the other and stops at the first one that fails. Cancelling changes
        // nothing: the button stays where it is.
        async function ucEverything() {
            ucOpen('all');
            ucRender();
            const box = document.getElementById('all-run');
            const say = (cls, text) => { box.innerHTML = '<div class="alert ' + cls + ' py-2 mb-0">' + escHtml(text) + '</div>'; };
            const busy = text => { box.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(text); };
            const planned = ucPlanned();
            const go = [], out = [], approved = {}, waiting = [];
            const add = plan => ((plan && plan.changes) || []).forEach(c => { if (c.name && c.to) approved[c.name] = c.to; });
            // The new packages a step installs (a library the new version wants): they are stated in the
            // confirmation, because the confirmation shows what will be done (finding 208: lmdb0 for
            // postfix-mysql, on the production server).
            const installs = plan => {
                const list = ((plan && plan.changes) || []).filter(c => c.type === 'install' && c.name && c.to).map(c => c.name + ' ' + c.to);
                return list.length ? ' — ' + t('uc.allInstalls', { list: list.join(', ') }) : '';
            };
            const stopOf = r => { const c = (r.checks || []).find(x => x.level === 'block'); return c ? c.label + ' — ' + c.detail : (r.error || t('common.errorShort')); };
            for (let i = 0; i < planned.length; i++) {
                const p = planned[i];
                busy(t('uc.allChecking', { n: i + 1, total: planned.length, name: p.label }));
                if (p.kind === 'os') { go.push({ kind: 'os', label: p.label }); continue; }
                if (p.kind === 'plain') {
                    const r = await updApi('updates_status');
                    const plan = r.plan || {};
                    const changes = plan.changes || [];
                    if (!r.success || !plan.measured || !changes.length) { out.push(p.label + ': ' + (r.error || plan.error || t('up.planNoChange'))); continue; }
                    if (changes.some(c => c.type === 'remove' || c.type === 'downgrade')) { uc.plainBlocked = true; out.push(p.label + ': ' + t('uc.allPlanRemoves')); continue; }
                    // A reinstalled package (one it uses has changed) is not an update: it is stated separately,
                    // so the counts match the list (on the VM: 9 updates and cyrus-sasl reinstalled, not
                    // "10 packages").
                    const again = changes.filter(c => c.type === 'reinstall').length;
                    const label = again && again < changes.length ? tn('uc.allPlain', changes.length - again) + ' ' + tn('uc.allPlainReinstall', again)
                        : tn('uc.allPlain', changes.length);
                    go.push({ kind: 'plain', signature: r.signature, label: label });
                    add(plan);
                    continue;
                }
                const action = { package: 'package_preflight', roundcube: 'roundcube_preflight', java: 'java_preflight' }[p.kind];
                const r = await updApi(action, p.kind === 'package' ? { package: p.step.head.name } : {});
                if (!(r.success && r.canProceed && r.signature)) {
                    // Held by locked packages that have an update of their own: if an earlier step does it, this
                    // one is checked when its turn comes (below). On the VM: postfix-mysql behind mysql84-client.
                    const blockers = ((r.plan && r.plan.blockers) || []).map(b => b.name).filter(Boolean);
                    if (p.kind === 'package' && blockers.length) { waiting.push({ p: p, r: r, blockers: blockers }); continue; }
                    out.push(p.label + ': ' + stopOf(r));
                    continue;
                }
                const services = (r.services || []).map(x => x.name || x).filter(Boolean);
                go.push({ kind: p.kind, package: p.kind === 'package' ? p.step.head.name : '', signature: r.signature,
                    label: p.label + (services.length ? ' — ' + t('uc.allRestarts', { list: services.join(', ') }) : '') + installs(r.plan) });
                add(r.plan);
            }
            // The steps held only by a package that an earlier step updates: after the other packages, before
            // Roundcube and Java, without a fingerprint. The server checks them when their turn comes, and runs
            // them only if their plan stays within the changes shown here (finding 207).
            const deferred = [];
            waiting.forEach(w => {
                if (!w.blockers.every(b => Object.prototype.hasOwnProperty.call(approved, b))) { out.push(w.p.label + ': ' + stopOf(w.r)); return; }
                // What its plan, held, already knew (a new dependency, for example) is shown and counts as
                // shown; the step's members at the catalog version. The rest, if present at its turn, stops it.
                add(w.r.plan);
                w.p.step.members.forEach(m => { approved[m.name] = m.available; });
                deferred.push({ kind: 'package', package: w.p.step.head.name, signature: '',
                    label: w.p.label + ' — ' + t('uc.allDeferred', { after: w.blockers.join(', ') }) + installs(w.r.plan) });
            });
            if (deferred.length) {
                const late = go.findIndex(g => g.kind === 'roundcube' || g.kind === 'java');
                go.splice(late < 0 ? go.length : late, 0, ...deferred);
            }
            box.innerHTML = '';
            if (!go.length) { say('alert-warning', t('uc.allNone') + ' ' + out.join('; ')); return; }
            const lines = go.map((g, i) => (i + 1) + '. ' + g.label);
            const yes = await panelAsk({ title: tn('uc.everythingAskTitle', go.length),
                text: t('uc.everythingAskText') + '\n' + lines.join('\n')
                    + (out.length ? '\n' + t('uc.allLeftOut') + ' ' + out.join('; ') : '')
                    + (go.some(g => g.kind === 'java') ? '\n' + t('uc.everythingJavaNote') : ''),
                confirm: tn('uc.everythingGo', go.length) });
            if (!yes) {
                // Cancelled: everything as it was, with the button in its place.
                document.getElementById('uc-all-detail').hidden = true;
                ucRender();
                return;
            }
            const a = await updApi('update_everything', { confirm: 'UPDATE',
                steps: go.map(g => ({ kind: g.kind, package: g.package || '', signature: g.signature || '' })),
                approved: Object.keys(approved).map(n => ({ name: n, to: approved[n] })) });
            ucTurn();
            if (!a.success) { say('alert-danger', a.error || t('common.errorShort')); return; }
            gdFollow('all', 'all-run', 'all-log-box', 'all-log', a.jobId, t('uc.everythingRunning'));
            if (go.some(g => g.kind === 'java')) ucAwaitPanel();
        }

        // With the panel's Java last, the panel stops and restarts: it waits for it to answer again and
        // reloads the page. Only if it has really been gone for a while (the script starts at the end of the job).
        function ucAwaitPanel() {
            if (uc.awaitingPanel) return;
            uc.awaitingPanel = true;
            let wasDown = false, rounds = 0;
            const tick = async () => {
                rounds++;
                let up = false;
                try { up = (await fetch('/api/panel_info', { cache: 'no-store' })).status > 0; } catch (e) { up = false; }
                if (!up) wasDown = true;
                if (wasDown && up) { location.reload(); return; }
                if (rounds < 180) setTimeout(tick, 5000);
            };
            setTimeout(tick, 5000);
        }

        // After the branch change: back to the top of this card, to see what there is to update now.
        function ucShow() {
            const title = document.getElementById('ucTitle');
            if (title) { title.focus({ preventScroll: true }); title.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
        }

        document.addEventListener('DOMContentLoaded', () => { ucLoad(); if (document.getElementById('ucList')) ucTurn(); });
