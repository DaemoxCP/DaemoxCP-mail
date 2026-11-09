// La striscia "il server va riavviato" in cima a ogni pagina, la finestra del riavvio e una finestra di
// conferma per tutto il pannello (reperto 185). Le mette la cornice (Layout.rebootFrame) a chi vede il
// sistema; il pulsante e le finestre solo a chi puo' cambiarlo.
//
// Prima il riavvio stava in fondo alla scheda del sistema, nella pagina Aggiornamenti, e chiedeva di
// scrivere una frase in una finestra del browser; che servisse lo diceva solo un cartellino nella stessa
// scheda. Le patch del kernel installate restavano senza effetto finche' qualcuno non ci passava.
var panelReboot = { state: null, poll: null, at: 0, sawDown: false };

function panelRebootApi(action, extra) {
    var token = document.getElementById('csrf_token');
    return fetch('/api/updates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ action: action, csrf_token: token ? token.value : '' }, extra || {}))
    }).then(function (r) {
        // Una risposta che non e' JSON (Cloudflare quando l'origine e' giu': 52x in HTML) vale come
        // il server che non risponde.
        return r.json().then(function (j) { j.status = r.status; return j; },
                             function () { return { success: false, network: true, status: r.status }; });
    }).catch(function (e) { return { success: false, network: true, error: t('common.networkError', { message: e.message }) }; });
}

function panelRebootEl(tag, className, text) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
}

function panelRebootButton(className, icon, label, action) {
    var b = panelRebootEl('button', className);
    b.type = 'button';
    var i = panelRebootEl('i', 'fas ' + icon + ' me-1');
    i.setAttribute('aria-hidden', 'true');
    b.append(i, label);
    b.setAttribute('data-on-click', action);
    return b;
}

// Quando il contenuto della finestra cambia, il pulsante premuto puo' sparire: il fuoco andrebbe fuori
// dalla finestra, ed Esc non la chiuderebbe piu' (Bootstrap ascolta i tasti sulla finestra). Si rimette
// sul pulsante di chiusura (r9: il fuoco non si perde mai).
function panelRebootKeepFocus() {
    var modal = document.getElementById('panelRebootModal');
    if (modal && modal.classList.contains('show') && !modal.contains(document.activeElement)) {
        var close = modal.querySelector('.btn-close');
        if (close) close.focus();
    }
}

function panelRebootWhy(r) {
    if (r.state === 'needed') return t('rb.needed', { installed: r.installedKernel, running: r.runningKernel });
    if (r.state === 'advised') return t('rb.advised');
    return '';
}

// La striscia: compare solo se serve (o se un riavvio e' gia' programmato), e si rilegge dopo ogni azione.
function panelRebootRefresh() {
    var box = document.getElementById('panelRebootBanner');
    if (!box) return Promise.resolve(null);
    return panelRebootApi('reboot_state').then(function (r) {
        panelReboot.state = r;
        document.dispatchEvent(new CustomEvent('panel:reboot', { detail: r }));
        if (!r || !r.success || (r.state === 'none' && !r.scheduled)) {
            box.hidden = true;
            box.replaceChildren();
            return r;
        }
        var alert = panelRebootEl('div', 'alert ' + (r.state === 'advised' && !r.scheduled ? 'alert-info' : 'alert-warning')
            + ' d-flex flex-wrap align-items-center gap-2 mb-0');
        alert.setAttribute('role', 'status');
        var icon = panelRebootEl('i', 'fas fa-rotate-right');
        icon.setAttribute('aria-hidden', 'true');
        var text = panelRebootEl('span', 'flex-grow-1', r.scheduled ? t('rb.scheduled') : panelRebootWhy(r));
        alert.append(icon, text);
        if (box.getAttribute('data-can-reboot') === 'true') {
            alert.append(r.scheduled
                ? panelRebootButton('btn btn-sm btn-outline-dark touch-target', 'fa-ban', t('rb.cancel'), 'panelRebootCancel()')
                : panelRebootButton('btn btn-sm btn-warning touch-target', 'fa-rotate-right', t('rb.open'), 'panelRebootOpen()'));
        } else {
            alert.append(panelRebootEl('span', 'small', t('rb.askSuperadmin')));
        }
        box.replaceChildren(alert);
        box.hidden = false;
        return r;
    });
}

// La finestra: perche', cosa si ferma, quando; poi il conto alla rovescia e il ritorno del server.
function panelRebootOpen() {
    var body = document.getElementById('panelRebootBody');
    var go = document.getElementById('panelRebootGo');
    var when = document.getElementById('panelRebootWhen');
    if (!body || !go) return;
    body.replaceChildren(panelRebootEl('p', 'text-muted mb-0', t('rb.reading')));
    go.disabled = true;
    go.hidden = false;
    when.hidden = false;
    bootstrap.Modal.getOrCreateInstance(document.getElementById('panelRebootModal')).show();
    panelRebootApi('reboot_preview').then(function (r) {
        body.replaceChildren();
        if (!r.success) {
            body.append(panelRebootEl('div', 'alert alert-danger mb-0', r.error || t('common.errorShort')));
            when.hidden = true;
            go.hidden = true;
            return;
        }
        var why = panelRebootWhy(panelReboot.state || {});
        if (why) body.append(panelRebootEl('p', '', why));
        var services = (r.services || []).join(', ');
        if (services) body.append(panelRebootEl('p', '', t('rb.stops', { list: services })));
        body.append(panelRebootEl('p', '', t('rb.mailDown')));
        body.append(panelRebootEl('p', '', t('rb.panelBack')));
        if (r.noshutdownWarning) body.append(panelRebootEl('div', 'alert alert-warning mb-0', r.noshutdownWarning));
        go.disabled = false;
    });
}

function panelRebootGo() {
    var go = document.getElementById('panelRebootGo');
    var body = document.getElementById('panelRebootBody');
    var picked = document.querySelector('input[name="panelRebootMinutes"]:checked');
    var minutes = picked ? Number(picked.value) : 1;
    go.disabled = true;
    panelRebootApi('reboot_now', { confirm: 'REBOOT THE SERVER', minutes: minutes }).then(function (r) {
        if (!r.success) {
            body.append(panelRebootEl('div', 'alert alert-danger mt-2 mb-0', r.error || t('common.errorShort')));
            go.disabled = false;
            return;
        }
        panelReboot.at = Date.now() + minutes * 60000;
        panelReboot.sawDown = false;
        window.panelRebootPending = true;
        var time = new Intl.DateTimeFormat(window.I18N_LANG || undefined, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })
            .format(new Date(panelReboot.at));
        body.replaceChildren(panelRebootEl('p', 'fw-semibold', t('rb.at', { time: time })),
            panelRebootButton('btn btn-outline-secondary touch-target', 'fa-ban', t('rb.cancel'), 'panelRebootCancel()'));
        go.hidden = true;
        document.getElementById('panelRebootWhen').hidden = true;
        panelRebootKeepFocus();
        panelRebootRefresh();
        panelRebootWatch();
    });
}

function panelRebootCancel() {
    panelRebootApi('reboot_cancel').then(function (r) {
        if (panelReboot.poll) { clearInterval(panelReboot.poll); panelReboot.poll = null; }
        window.panelRebootPending = false;
        var body = document.getElementById('panelRebootBody');
        if (body) body.replaceChildren(panelRebootEl('div', 'alert alert-' + (r.success ? 'success' : 'danger') + ' mb-0',
            r.success ? t('rb.cancelled') : (r.error || t('common.errorShort'))));
        panelRebootKeepFocus();
        panelRebootRefresh();
    });
}

// Dopo l'ora del riavvio: finche' il server si spegne (risponde ancora, ma senza sessione: MySQL si e'
// gia' fermato) o e' giu' (non risponde), si dice che si sta riavviando. Quando torna, dopo essere
// stato giu', la sessione non c'e' piu' (vale un avvio solo): si va all'accesso, che dice che il
// server e' stato riavviato. Se dopo dieci minuti non e' mai stato giu', il riavvio non c'e' stato.
function panelRebootWaiting() {
    var box = document.getElementById('panelRebootBanner');
    var line = panelRebootEl('div', 'alert alert-warning mb-0', t('rb.waiting'));
    line.setAttribute('role', 'status');
    if (box) { box.replaceChildren(line); box.hidden = false; }
    var body = document.getElementById('panelRebootBody');
    if (body) body.replaceChildren(panelRebootEl('p', 'mb-0', t('rb.waiting')));
}

function panelRebootWatch() {
    if (panelReboot.poll) clearInterval(panelReboot.poll);
    panelReboot.poll = setInterval(function () {
        if (Date.now() < panelReboot.at) return;
        panelRebootApi('reboot_state').then(function (r) {
            if (r && r.network) {
                panelReboot.sawDown = true;
                panelRebootWaiting();
            } else if (r && r.status === 401) {
                if (panelReboot.sawDown) {
                    clearInterval(panelReboot.poll);
                    location.replace('/index?session=rebooted');
                } else {
                    panelRebootWaiting();
                }
            } else if (Date.now() > panelReboot.at + 10 * 60000) {
                clearInterval(panelReboot.poll);
                window.panelRebootPending = false;
                panelRebootRefresh();
            }
        });
    }, 5000);
}

// Una conferma del pannello, al posto di prompt(): titolo, testo e il pulsante che fa la cosa.
// Restituisce una promessa: true se si e' premuto il pulsante, false altrimenti.
function panelAsk(options) {
    var modal = document.getElementById('panelAskModal');
    if (!modal) return Promise.resolve(window.confirm(options.text || ''));
    document.getElementById('panelAskTitle').textContent = options.title || '';
    var body = document.getElementById('panelAskBody');
    body.replaceChildren();
    String(options.text || '').split('\n').forEach(function (line) { if (line.trim()) body.append(panelRebootEl('p', '', line)); });
    var go = document.getElementById('panelAskGo');
    go.className = 'btn touch-target ' + (options.danger ? 'btn-danger' : 'btn-primary');
    go.textContent = options.confirm || t('common.confirm');
    return new Promise(function (resolve) {
        var answered = false;
        panelAsk.resolve = function (value) { if (!answered) { answered = true; resolve(value); } };
        modal.addEventListener('hidden.bs.modal', function () { panelAsk.resolve(false); }, { once: true });
        bootstrap.Modal.getOrCreateInstance(modal).show();
    });
}

// Una conferma di una frase, al posto di confirm() (reperto 198): «Procedere?», la frase, e il pulsante; rosso quando
// si toglie qualcosa. Restituisce una promessa, come panelAsk.
function panelConfirm(text, danger) {
    return panelAsk({ title: t('gd.confirmTitle'), text: text, confirm: t(danger ? 'gd.confirmDanger' : 'gd.confirmGo'), danger: !!danger });
}

// Un avviso del pannello, al posto di alert() (reperto 198): non ferma la pagina, lo leggono gli screen reader (role
// alert per errori e richieste, status per gli esiti), il colore dice cos'e' e lo dice anche la parola nascosta. Gli
// esiti riusciti spariscono da soli dopo 10 s; errori e richieste restano finche' non li si chiude.
function panelSay(kind, text) {
    var s = String(text === undefined || text === null ? '' : text);
    var k = { success: 1, danger: 1, warning: 1, info: 1 }[kind] ? kind : 'info';
    if (/^\u2713/.test(s)) k = 'success'; else if (/^\u2717/.test(s)) k = 'danger'; else if (/^\u26a0/.test(s)) k = 'warning';
    var box = document.getElementById('panelNotices');
    if (!box) {
        box = document.createElement('div');
        box.id = 'panelNotices';
        box.className = 'panel-notices';
        document.body.appendChild(box);
    }
    var n = panelRebootEl('div', 'alert alert-' + k + ' alert-dismissible shadow-sm mb-2');
    n.setAttribute('role', k === 'danger' || k === 'warning' ? 'alert' : 'status');
    n.append(panelRebootEl('span', 'visually-hidden', t('notice.' + k) + ': '));
    s.split('\n').forEach(function (line) { if (line.trim()) n.append(panelRebootEl('p', 'mb-1', line)); });
    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'btn-close';
    close.setAttribute('aria-label', t('common.close'));
    close.addEventListener('click', function () { n.remove(); });
    n.append(close);
    box.append(n);
    if (k === 'success' || k === 'info') setTimeout(function () { n.remove(); }, 10000);
}

// La stessa, col pulsante rosso: per quello che toglie, revoca o azzera.
function panelConfirmDanger(text) {
    return panelConfirm(text, true);
}

function panelAskYes() {
    if (panelAsk.resolve) panelAsk.resolve(true);
    bootstrap.Modal.getOrCreateInstance(document.getElementById('panelAskModal')).hide();
}

// Le finestre stanno in un <template> (Layout.rebootFrame) e si mettono in fondo alla pagina: dentro la
// pagina, prima del suo titolo, i loro <h2> venivano prima di quello della pagina.
document.addEventListener('DOMContentLoaded', function () {
    var tpl = document.getElementById('panelRebootTemplates');
    if (tpl) document.body.appendChild(tpl.content.cloneNode(true));
    panelRebootRefresh();
});
