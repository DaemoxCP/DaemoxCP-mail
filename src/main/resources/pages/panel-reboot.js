// The "the server needs a restart" strip at the top of every page, the restart window and a confirmation
// window for the whole panel (finding 185). The frame (Layout.rebootFrame) adds them for those who see the
// system; the button and the windows only for those who can change it.
//
// Before, the restart was at the bottom of the system card, on the Updates page, and asked to
// type a phrase in a browser window; that it was needed was said only by a tag in the same
// card. Installed kernel patches stayed without effect until someone happened to come by.
var panelReboot = { state: null, poll: null, at: 0, sawDown: false };

function panelRebootApi(action, extra) {
    var token = document.getElementById('csrf_token');
    return fetch('/api/updates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ action: action, csrf_token: token ? token.value : '' }, extra || {}))
    }).then(function (r) {
        // A response that is not JSON (Cloudflare when the origin is down: 52x in HTML) counts as
        // the server not answering.
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

// When the window's content changes, the pressed button may disappear: focus would go outside
// the window, and Esc would no longer close it (Bootstrap listens for keys on the window). It is put
// back on the close button (r9: focus is never lost).
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

// The strip: it appears only if needed (or if a restart is already scheduled), and it is reread after every action.
function panelRebootRefresh() {
    var box = document.getElementById('panelRebootBanner');
    if (!box) return Promise.resolve(null);
    return panelRebootApi('reboot_state').then(function (r) {
        panelReboot.state = r;
        panelRestartLock(!!(r && r.success && r.scheduled));
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
        var text = panelRebootEl('span', 'flex-grow-1', r.scheduled
            ? (r.at ? t('rb.lockedAt', { time: panelRebootTime(r.at) }) : t('rb.locked')) : panelRebootWhy(r));
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

// The restart time in the viewer's time zone (r13: it is converted only to show it).
function panelRebootTime(ms) {
    return new Intl.DateTimeFormat(window.I18N_LANG || undefined, { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })
        .format(new Date(ms));
}

// With the scheduled restart the panel is read-only (RestartLock on the server, which refuses anyway): the
// page's buttons look switched off and do nothing, and whoever presses one reads why and what they can do.
// The restart strip, its windows, the menu, the tabs and the parts to open and close remain: only the
// page's content (#main) is locked.
function panelRestartLock(on) {
    document.body.classList.toggle('panel-restart-locked', on);
}

function panelRestartBlocked(e) {
    if (!document.body.classList.contains('panel-restart-locked')) return;
    var el = e.type === 'submit' ? e.target
        : e.target.closest && e.target.closest('button, input[type="submit"], input[type="button"], input[type="checkbox"], input[type="radio"], [data-on-click]');
    if (!el || !el.closest('#main')) return;
    if (el.closest('#panelRebootBanner, .modal, .panel-notices, [data-bs-toggle], [data-bs-dismiss], summary, .btn-close')) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    if (!panelReboot.notice || !panelReboot.notice.isConnected) {
        panelSay('warning', t('rb.lockedClick'));
        var all = document.querySelectorAll('#panelNotices .alert');
        panelReboot.notice = all.length ? all[all.length - 1] : null;
    }
}
document.addEventListener('click', panelRestartBlocked, true);
document.addEventListener('submit', panelRestartBlocked, true);

// The window: why, what stops, when; then the countdown and the server's return.
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
        body.replaceChildren(panelRebootEl('p', 'fw-semibold', t('rb.at', { time: panelRebootTime(panelReboot.at) })),
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

// After the restart time: while the server is shutting down (it still answers, but without a session: MySQL
// has already stopped) or is down (it does not answer), it says that it is restarting. When it comes back,
// after having been down, the session is gone (it is valid for one run only): it goes to the login, which
// says that the server has been restarted. If after ten minutes it has never been down, the restart did
// not happen.
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

// A panel confirmation, instead of prompt(): title, text and the button that does the thing.
// Returns a promise: true if the button was pressed, false otherwise.
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

// A one-sentence confirmation, instead of confirm() (finding 198): "Go ahead?", the sentence, and the button;
// red when something is removed. Returns a promise, like panelAsk.
function panelConfirm(text, danger) {
    return panelAsk({ title: t('gd.confirmTitle'), text: text, confirm: t(danger ? 'gd.confirmDanger' : 'gd.confirmGo'), danger: !!danger });
}

// A panel notice, instead of alert() (finding 198): it does not stop the page, screen readers read it (role
// alert for errors and requests, status for outcomes), the color says what it is and so does the hidden word.
// Successful outcomes disappear by themselves after 10 s; errors and requests stay until they are closed.
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

// The same, with the red button: for what removes, revokes or resets.
function panelConfirmDanger(text) {
    return panelConfirm(text, true);
}

function panelAskYes() {
    if (panelAsk.resolve) panelAsk.resolve(true);
    bootstrap.Modal.getOrCreateInstance(document.getElementById('panelAskModal')).hide();
}

// Focus goes back to where it was when a window closes (r9). Bootstrap gives it back by itself only to windows
// opened with data-bs-toggle, and when a window opens on top of another it removes the latter's Tab trap without
// ever giving it back. The panel's windows opened by code on top of another ("Go ahead?", the recent
// confirmation: revealing a password, the keys) thus left focus on the body: the window below no longer heard
// Esc, and whoever uses the keyboard or a screen reader was left outside, behind (test from a clean server,
// 2026-11-18). On opening, it remembers who had focus; on closing, the window still open below takes back the
// trap, and focus returns to whoever had it or, if that is gone, to the window itself.
document.addEventListener('show.bs.modal', function (e) {
    var a = document.activeElement;
    e.target.panelFocusBefore = a && a !== document.body ? a : null;
});
// Opened on top of another, the new window did not even take focus: Bootstrap 5.3.0's trap moves it onto
// the new window BEFORE switching off the trap of the window below, which takes it back immediately. The
// question was not read, and Enter and Esc went to the window behind. Once fully open, if focus is not its
// own, its trap restarts (now it is the only one) and takes it.
document.addEventListener('shown.bs.modal', function (e) {
    if (e.target.contains(document.activeElement)) return;
    var inst = window.bootstrap && bootstrap.Modal.getInstance(e.target);
    var trap = inst && inst._focustrap;
    if (trap) { trap.deactivate(); trap.activate(); }
    if (!e.target.contains(document.activeElement)) e.target.focus();
});
document.addEventListener('hidden.bs.modal', function (e) {
    var open = Array.prototype.filter.call(document.querySelectorAll('.modal.show'), function (m) { return m !== e.target; });
    var top = open.length ? open[open.length - 1] : null;
    if (top && window.bootstrap) {
        var inst = bootstrap.Modal.getInstance(top);
        var trap = inst && inst._focustrap;
        if (trap) { trap.deactivate(); trap.activate(); }
    }
    var back = e.target.panelFocusBefore;
    e.target.panelFocusBefore = null;
    // Disabled (the button that asked for the confirmation and is now working) does not take focus: then the window.
    var usable = back && document.contains(back) && back.offsetParent !== null && !back.disabled && (!top || top.contains(back));
    if (usable) back.focus();
    if (top && !top.contains(document.activeElement)) top.focus();
});

// The windows are in a <template> (Layout.rebootFrame) and are put at the end of the page: inside the
// page, before its title, their <h2> came before the page's own.
document.addEventListener('DOMContentLoaded', function () {
    var tpl = document.getElementById('panelRebootTemplates');
    if (tpl) document.body.appendChild(tpl.content.cloneNode(true));
    panelRebootRefresh();
});
