// The confirmation for dangerous operations, the same on every page.
// The server asks for it with a 403 and the X-Panel-Confirmation: needed header; the fetch wrapper in the head
// of every page calls window.panelConfirmIdentity(), which opens this window and answers true when the root has
// verified the passkey or the code; then the request is repeated once. Whoever has a passkey chooses between
// the passkey and a code by email; whoever has none, only the code. Always, also a code from the server
// console (--access-code), for whoever has no passkey and does not receive the email. The confirmation lasts
// 5 minutes. The WebAuthn functions (webauthnGetOptions, webauthnCredentialJson) come from
// PanelContent.getWebAuthnScript, in the same file and in the same function (Layout.CONFIRM_SCRIPT): nothing
// global, except panelConfirmIdentity.

var pending = null;
var finish = null;

function confirmPost(action, body) {
    return fetch('/api/account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ action: action }, body || {}))
    }).then(function (r) { return r.json().catch(function () { return {}; }); });
}

function say(box, kind, text) {
    box.className = 'small mt-2' + (kind ? ' text-' + kind : '');
    box.textContent = text || '';
}

function tr(key, params) {
    return typeof window.t === 'function' ? window.t(key, params) : key;
}

/** The window, taken once from its template (Layout) and kept in the page; the buttons have their listeners. */
function dialog() {
    var modal = document.getElementById('panelConfirmModal');
    if (modal) return modal;
    var template = document.getElementById('panelConfirmTemplate');
    if (!template) return null;
    document.body.appendChild(template.content.cloneNode(true));
    modal = document.getElementById('panelConfirmModal');
    var part = function (name) { return modal.querySelector('[data-confirm="' + name + '"]'); };
    var msg = document.getElementById('panelConfirmMsg');
    var code = document.getElementById('panelConfirmCode');
    var done = function () {
        var f = finish;
        finish = null;
        window.bootstrap.Modal.getOrCreateInstance(modal).hide();
        if (f) f(true);
    };
    part('passkey').addEventListener('click', function () {
        say(msg, '', '');
        confirmPost('stepup_options').then(function (o) {
            if (!o.success) { say(msg, 'danger', o.error || tr('common.failed')); return; }
            return navigator.credentials.get(webauthnGetOptions(o.options)).then(function (cred) {
                return confirmPost('stepup_verify', { request: o.request, credential: webauthnCredentialJson(cred) }).then(function (r) {
                    if (r.success) done(); else say(msg, 'danger', r.error || tr('login.passkeyFailed'));
                });
            }, function (err) {
                say(msg, 'danger', err && err.name === 'NotAllowedError' ? tr('login.cancelled')
                    : tr('login.passkeyError', { message: err && err.message ? err.message : String(err) }));
            });
        }).catch(function (e) { say(msg, 'danger', tr('common.networkError', { message: e.message })); });
    });
    part('email').addEventListener('click', function () {
        say(msg, '', '');
        confirmPost('stepup_code_request').then(function (r) {
            if (!r.success) { say(msg, 'danger', r.error || tr('common.failed')); return; }
            part('code').hidden = false;
            say(msg, 'success', r.message || '');
            code.focus();
        }).catch(function (e) { say(msg, 'danger', tr('common.networkError', { message: e.message })); });
    });
    var verify = function () {
        var value = code.value.trim();
        if (!/^[0-9]{6}$/.test(value)) { say(msg, 'danger', tr('login.enterOtp')); code.focus(); return; }
        confirmPost('stepup_code_verify', { code: value }).then(function (r) {
            if (r.success) done(); else say(msg, 'danger', r.error || tr('common.failed'));
        }).catch(function (e) { say(msg, 'danger', tr('common.networkError', { message: e.message })); });
    };
    part('verify').addEventListener('click', verify);
    code.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); verify(); } });
    // The console's access code (--access-code): always possible, even without a passkey and without email.
    // Whoever reads it has a root shell on the server.
    var consoleCode = document.getElementById('panelConfirmConsoleCode');
    part('console').addEventListener('click', function () {
        say(msg, '', '');
        part('console-code').hidden = false;
        part('console').setAttribute('aria-expanded', 'true');
        consoleCode.focus();
    });
    var verifyConsole = function () {
        var value = consoleCode.value.replace(/[ -]/g, '');
        if (!/^[0-9]{8}$/.test(value)) { say(msg, 'danger', tr('login.consoleEnterValid')); consoleCode.focus(); return; }
        confirmPost('stepup_console_verify', { code: value }).then(function (r) {
            if (r.success) done(); else say(msg, 'danger', r.error || tr('common.failed'));
        }).catch(function (e) { say(msg, 'danger', tr('common.networkError', { message: e.message })); });
    };
    part('console-verify').addEventListener('click', verifyConsole);
    consoleCode.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); verifyConsole(); } });
    modal.addEventListener('hidden.bs.modal', function () {
        var f = finish;
        finish = null;
        if (f) f(false);
    });
    return modal;
}

/** Opens the window with the ways the account has, and answers true when the confirmation succeeded. */
function ask() {
    return fetch('/api/account').then(function (r) { return r.json(); }).catch(function () { return {}; }).then(function (state) {
        var modal = dialog();
        if (!modal || !window.bootstrap) return false;
        var part = function (name) { return modal.querySelector('[data-confirm="' + name + '"]'); };
        var passkey = !!state.passkeysAvailable && (state.passkeys || []).length > 0 && !!window.PublicKeyCredential;
        var email = !!state.email;
        part('choose').hidden = !(passkey && email);
        part('passkey-only').hidden = !(passkey && !email);
        part('email-only').hidden = !(!passkey && email);
        part('none').hidden = passkey || email;
        part('passkey').hidden = !passkey;
        part('email').hidden = !email;
        part('code').hidden = true;
        part('console-code').hidden = true;
        part('console').setAttribute('aria-expanded', 'false');
        document.getElementById('panelConfirmCode').value = '';
        document.getElementById('panelConfirmConsoleCode').value = '';
        // The command with the name of whoever is confirming: the code is valid only for them.
        document.getElementById('panelConfirmConsoleCommand').textContent =
            'java -jar daemoxcp-mail.jar --access-code' + (state.username ? ' ' + state.username : '');
        say(document.getElementById('panelConfirmMsg'), '', '');
        var before = document.activeElement;
        return new Promise(function (resolve) {
            finish = function (ok) {
                // Focus goes back to where it was before the window.
                if (before && typeof before.focus === 'function') before.focus();
                resolve(ok);
            };
            window.bootstrap.Modal.getOrCreateInstance(modal).show();
        });
    });
}

window.panelConfirmIdentity = function () {
    // Several requests that ask for it at the same time wait for the same window, and then are all repeated.
    if (!pending) pending = ask().finally(function () { pending = null; });
    return pending;
};
