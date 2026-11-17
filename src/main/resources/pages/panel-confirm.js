// La conferma per le operazioni pericolose, uguale in tutte le pagine.
// Il server la chiede con un 403 e l'intestazione X-Panel-Confirmation: needed; l'involucro di fetch nella testa di
// ogni pagina chiama window.panelConfirmIdentity(), che apre questa finestra e risponde true quando la root ha
// verificato la passkey o il codice; allora la richiesta si ripete una volta. Chi ha una passkey sceglie fra la
// passkey e un codice via email; chi non ne ha, solo il codice. La conferma vale 5 minuti.
// Le funzioni WebAuthn (webauthnGetOptions, webauthnCredentialJson) arrivano da PanelContent.getWebAuthnScript,
// nello stesso file e nella stessa funzione (Layout.CONFIRM_SCRIPT): niente di globale, salvo panelConfirmIdentity.

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

/** La finestra, presa una volta dal suo modello (Layout) e tenuta nella pagina; i pulsanti hanno i loro ascoltatori. */
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
    modal.addEventListener('hidden.bs.modal', function () {
        var f = finish;
        finish = null;
        if (f) f(false);
    });
    return modal;
}

/** Apre la finestra con le strade che l'account ha, e risponde true quando la conferma e' riuscita. */
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
        document.getElementById('panelConfirmCode').value = '';
        say(document.getElementById('panelConfirmMsg'), '', '');
        var before = document.activeElement;
        return new Promise(function (resolve) {
            finish = function (ok) {
                // Il fuoco torna dove era prima della finestra.
                if (before && typeof before.focus === 'function') before.focus();
                resolve(ok);
            };
            window.bootstrap.Modal.getOrCreateInstance(modal).show();
        });
    });
}

window.panelConfirmIdentity = function () {
    // Piu' richieste insieme che la chiedono aspettano la stessa finestra, e poi si ripetono tutte.
    if (!pending) pending = ask().finally(function () { pending = null; });
    return pending;
};
