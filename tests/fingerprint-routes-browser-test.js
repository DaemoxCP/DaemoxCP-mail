// The two features that send the root part a "fingerprint" the panel itself computed (reperto 204), on the real panel of
// the TEST VM, through the web part and the root part's closed list (RootGate). On the real server the branch change was
// refused with "The request does not have the shape the panel expects": the gate checked every "fingerprint" against
// the shape of an SSH key's.
//
//  1. The package branch: to latest and back to quarterly, each with its preview's fingerprint (16 hex digits), its
//     confirmation and its job followed to the end. The VM must be on quarterly when it starts, and is put back on it in
//     any case.
//  2. "Turn into mailbox": a test alias created for it, the preview's fingerprint (64 hex digits), the conversion, then
//     the mailbox deleted (and the alias, if anything went wrong).
//  3. The root part's log: no forwarded request refused while the test ran.
//
// Through an SSH tunnel to the VM's port 2096 (self-signed certificate: errors ignored, for this test machine only).
// Sign-in with a console code; the session's fresh confirmation with the "confirm" mode of tests/signed-jobs-setup.sh
// (copied to /root/signed on the VM).
//
// Usage:
//   ssh -i ~/.ssh/freebsd_test_vm -N -L 127.0.0.1:2096:127.0.0.1:2096 root@192.168.1.20 &
//   NODE_PATH=<playwright node_modules> node tests/fingerprint-routes-browser-test.js
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const BASE = 'https://127.0.0.1:2096';
const VM = 'ssh -i ' + process.env.HOME + '/.ssh/freebsd_test_vm -o IdentitiesOnly=yes -o ConnectTimeout=10 root@192.168.1.20';
let failed = 0;
const check = (what, ok) => { console.log((ok ? '  OK     ' : '  FAILED ') + what); if (!ok) failed++; };
const vm = cmd => execSync(VM + " '" + cmd + "'").toString().trim();
const refusals = () => Number(vm('grep -c "forwarded request refused" /var/db/mailpanel/panel.log || true'));

(async () => {
    const browser = await chromium.launch({ headless: true, channel: 'chrome' });
    const errors = [];
    let page;
    // A call from the page, as its scripts make it (the page adds the CSRF header itself): status and answer.
    const call = (url, method, body) => page.evaluate(async ([u, m, b]) => {
        const r = await fetch(u, { method: m, headers: { 'Content-Type': 'application/json' },
            body: b ? JSON.stringify(Object.assign({ csrf_token: document.getElementById('csrf_token').value }, b)) : undefined });
        return { status: r.status, body: await r.json().catch(() => ({})) };
    }, [url, method, body || null]);
    const updates = body => call('/api/updates', 'POST', body);
    const branch = async () => (await updates({ action: 'branch_status' })).body.branch;
    // Preview, change, follow the job: what the Package branch card does.
    async function changeBranch(to) {
        const pv = await updates({ action: 'branch_preview', destination: to });
        const fp = pv.body.fingerprint || '';
        const ch = await updates({ action: 'branch_change', destination: to, fingerprint: fp, confirm: to });
        let job = null;
        for (let i = 0; ch.body.jobId && i < 150; i++) {
            const s = await updates({ action: 'job_status', jobId: ch.body.jobId });
            job = s.body.job;
            if (job && (job.status === 'completed' || job.status === 'error')) break;
            await page.waitForTimeout(2000);
        }
        return { fp, ch, job };
    }
    const before = refusals();
    let startBranch = '';
    try {
        if (vm('pgrep -x shutdown || true') !== '') { console.error('A restart is scheduled on the VM: not starting.'); process.exit(2); }
        const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: 'en-US' });
        page = await context.newPage();
        page.on('pageerror', e => errors.push(String(e)));
        const code = vm('cd /home/panel && /usr/local/openjdk25/bin/java -jar freebsd-mail-panel-1.0.jar --access-code 2>/dev/null')
            .match(/([0-9]{4} [0-9]{4})/)[1];
        await page.goto(BASE + '/index');
        await page.click('#linkConsole');
        await page.fill('#consoleCode', code);
        await page.click('#btnConsole');
        await page.waitForURL(u => !String(u).includes('/index'), { timeout: 30000 });
        await page.goto(BASE + '/updates');
        console.log('    ' + vm('sh /root/signed/signed-jobs-setup.sh confirm'));

        console.log('\n== 1. The package branch, to latest and back ==');
        startBranch = await branch();
        check('the VM starts on quarterly (' + startBranch + ')', startBranch === 'quarterly');
        if (startBranch !== 'quarterly') throw new Error('not on quarterly: not touching the branch');
        const latest = await changeBranch('latest');
        check('the preview gives the fingerprint of 16 hex digits', /^[0-9a-f]{16}$/.test(latest.fp));
        check('the change is not refused by the root part (' + latest.ch.status + ')', latest.ch.status === 200 && latest.ch.body.success === true
            && !/shape the panel expects/.test(latest.ch.body.error || ''));
        check('  its job ends well (' + (latest.job && latest.job.status) + ')', latest.job && latest.job.status === 'completed');
        check('  and the branch is latest', await branch() === 'latest');
        const back = await changeBranch('quarterly');
        check('back to quarterly: not refused, the job ends well', back.ch.status === 200 && back.ch.body.success === true
            && back.job && back.job.status === 'completed');
        check('  and the branch is quarterly again', await branch() === 'quarterly');

        console.log('\n== 2. Turn into mailbox ==');
        const domains = (await call('/api/domains', 'GET')).body.domains || [];
        const domain = (domains.find(d => d.active) || domains[0] || {}).domain;
        check('a domain of the VM to try it on (' + domain + ')', !!domain);
        const source = 'gate-test-' + Date.now() % 100000 + '@' + domain;
        const made = await call('/api/aliases', 'POST', { source, destination: 'postmaster@' + domain });
        check('a test alias created', made.status === 200 && made.body.success === true);
        const info = await call('/api/aliases?transform=' + encodeURIComponent(source), 'GET');
        check('the preview gives the fingerprint of 64 hex digits', info.body.possible === true && /^[0-9a-f]{64}$/.test(info.body.fingerprint || ''));
        const pw = (await call('/api/mailboxes', 'POST', { action: 'generate_password' })).body.password;
        const tr = await call('/api/aliases', 'POST', { action: 'transform_to_mailbox', source, password: pw, name: 'Gate test',
            quota_mb: 10, keep_forwards: false, old_mail: '', fingerprint: info.body.fingerprint });
        check('the conversion is not refused by the root part (' + tr.status + ')', tr.status === 200 && tr.body.success === true
            && !/shape the panel expects/.test(tr.body.error || ''));
        const boxes = (await call('/api/mailboxes', 'GET')).body.mailboxes || [];
        const box = boxes.find(m => m.email === source);
        check('  the mailbox is there', !!box);
        if (box) check('  and it is deleted again', (await call('/api/mailboxes?id=' + box.id, 'DELETE', {})).body.success === true);
        const left = ((await call('/api/aliases', 'GET')).body.aliases || []).filter(a => a.source === source);
        for (const a of left) await call('/api/aliases?id=' + a.id, 'DELETE', {});
        check('  nothing left of the test address', !((await call('/api/mailboxes', 'GET')).body.mailboxes || []).some(m => m.email === source)
            && !((await call('/api/aliases', 'GET')).body.aliases || []).some(a => a.source === source));

        console.log('\n== 3. The root part\'s log ==');
        const after = refusals();
        check('no forwarded request refused while the test ran (' + before + ' before, ' + after + ' after)', after === before);
        check('no page error' + (errors.length ? ': ' + errors.join(' | ') : ''), errors.length === 0);
    } catch (e) {
        console.error(e);
        failed++;
    } finally {
        // Back on quarterly in any case, if the test moved it.
        try { if (page && startBranch === 'quarterly' && await branch() !== 'quarterly') { await changeBranch('quarterly'); console.log('    put back on quarterly'); } }
        catch (e) { console.error('COULD NOT PUT THE BRANCH BACK: ' + e); failed++; }
        await browser.close();
        vm('sh /root/signed/signed-jobs-setup.sh confirm-stop || true');
    }
    console.log('\n' + (failed === 0 ? 'ALL OK' : failed + ' CHECKS FAILED'));
    process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
