// Le azioni e gli stili delle pagine senza codice in linea, per una Content-Security-Policy senza
// 'unsafe-inline' (reperto 178).
//
// Prima ogni pulsante portava il suo onclick="...", e ogni elemento il suo style="...": con
// 'unsafe-inline' nella CSP, una stringa iniettata in una pagina (un nome di casella, una riga di
// log) poteva eseguire codice qualunque. Adesso:
//
//  - data-on-<evento>="funzione(argomenti)" al posto di on<evento>="...": un solo ascoltatore per
//    tipo di evento, su document, legge l'attributo e lo esegue. Non e' eval: e' un linguaggio
//    minimo, che sa solo chiamare le funzioni DEL PANNELLO (dichiarate dagli script delle pagine,
//    mai quelle del browser come fetch o alert) con argomenti letterali ('testo', 12, true, null),
//    this e le sue proprieta' (this.value, this.dataset.id, this.closest('tr')), event,
//    Number(...), === e !==, e "return" (return false = preventDefault). Piu' istruzioni con ";".
//    Una forma che non conosce la scrive in console come errore e non fa niente.
//  - data-style="..." al posto di style="...": lo stesso stile, applicato con il CSSOM appena
//    l'elemento entra nella pagina (anche quelli creati dopo con innerHTML). Il CSSOM la CSP non lo
//    blocca, e cosi' lo stile resta uno stile dell'elemento: il codice che mostra e nasconde con
//    el.style.display = '' o 'none' continua a funzionare (con una classe non funzionerebbe).
//
// Si carica nella <head>, prima del corpo: l'osservatore vede ogni elemento mentre la pagina si
// costruisce, prima che venga disegnato, e prima che giri qualunque script della pagina.
(function () {
    'use strict';

    // Gli eventi che le pagine usano. Quelli che non risalgono (toggle di <details>) si prendono
    // nella fase di cattura e valgono solo per l'elemento stesso, come i gestori in linea.
    var EVENTS = ['click', 'change', 'input', 'submit', 'keyup', 'keydown'];
    var TARGET_ONLY = ['toggle'];
    // I soli metodi che un'azione puo' chiamare su un oggetto (this, event, un elemento).
    var METHODS = { closest: true, preventDefault: true, stopPropagation: true };

    // ---------- il linguaggio ----------

    function ActionError(message) { this.message = message; }

    function tokenize(src) {
        var tokens = [], i = 0, n = src.length;
        while (i < n) {
            var c = src.charAt(i);
            if (/\s/.test(c)) { i++; continue; }
            if (c === "'" || c === '"') {
                var quote = c, value = '';
                i++;
                while (i < n && src.charAt(i) !== quote) {
                    var ch = src.charAt(i);
                    if (ch === '\\') {
                        var next = src.charAt(i + 1);
                        if (next === 'n') value += '\n';
                        else if (next === 't') value += '\t';
                        else if (next === 'u' && /^[0-9a-fA-F]{4}$/.test(src.substr(i + 2, 4))) { value += String.fromCharCode(parseInt(src.substr(i + 2, 4), 16)); i += 4; }
                        else value += next;
                        i += 2;
                    } else { value += ch; i++; }
                }
                if (i >= n) throw new ActionError('unterminated string');
                i++;
                tokens.push({ t: 'str', v: value });
                continue;
            }
            if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(src.charAt(i + 1)))) {
                var m = /^[0-9]*\.?[0-9]+(?:[eE][+-]?[0-9]+)?/.exec(src.slice(i));
                tokens.push({ t: 'num', v: Number(m[0]) });
                i += m[0].length;
                continue;
            }
            if (/[A-Za-z_$]/.test(c)) {
                var id = /^[A-Za-z_$][A-Za-z0-9_$]*/.exec(src.slice(i))[0];
                tokens.push({ t: 'id', v: id });
                i += id.length;
                continue;
            }
            if (src.substr(i, 3) === '===' || src.substr(i, 3) === '!==') { tokens.push({ t: 'op', v: src.substr(i, 3) }); i += 3; continue; }
            if ('().,;!-'.indexOf(c) >= 0) { tokens.push({ t: 'op', v: c }); i++; continue; }
            throw new ActionError('unexpected character ' + c);
        }
        return tokens;
    }

    function parse(src) {
        var tokens = tokenize(src), pos = 0;
        function peek(v) { var t = tokens[pos]; return t && t.t === 'op' && t.v === v; }
        function take(v) { if (!peek(v)) throw new ActionError('expected ' + v); pos++; }
        function primary() {
            var t = tokens[pos++];
            if (!t) throw new ActionError('unexpected end');
            if (t.t === 'str' || t.t === 'num') return { k: 'lit', v: t.v };
            if (t.t === 'op' && t.v === '(') { var e = expr(); take(')'); return e; }
            if (t.t === 'id') {
                if (t.v === 'true') return { k: 'lit', v: true };
                if (t.v === 'false') return { k: 'lit', v: false };
                if (t.v === 'null') return { k: 'lit', v: null };
                if (t.v === 'this') return { k: 'this' };
                if (t.v === 'event') return { k: 'event' };
                return { k: 'name', v: t.v };
            }
            throw new ActionError('unexpected ' + t.v);
        }
        function postfix() {
            var node = primary();
            for (;;) {
                if (peek('.')) {
                    pos++;
                    var p = tokens[pos++];
                    if (!p || p.t !== 'id') throw new ActionError('expected a property');
                    node = { k: 'get', o: node, p: p.v };
                } else if (peek('(')) {
                    pos++;
                    var args = [];
                    if (!peek(')')) {
                        args.push(expr());
                        while (peek(',')) { pos++; args.push(expr()); }
                    }
                    take(')');
                    node = { k: 'call', f: node, a: args };
                } else {
                    return node;
                }
            }
        }
        function unary() {
            if (peek('!')) { pos++; return { k: 'not', e: unary() }; }
            if (peek('-')) { pos++; return { k: 'neg', e: unary() }; }
            return postfix();
        }
        function expr() {
            var left = unary();
            var t = tokens[pos];
            if (t && t.t === 'op' && (t.v === '===' || t.v === '!==')) {
                pos++;
                return { k: t.v === '===' ? 'eq' : 'ne', l: left, r: unary() };
            }
            return left;
        }
        var program = [];
        while (pos < tokens.length) {
            if (peek(';')) { pos++; continue; }
            var ret = tokens[pos].t === 'id' && tokens[pos].v === 'return';
            if (ret) pos++;
            program.push({ ret: ret, e: expr() });
            if (pos < tokens.length) take(';');
        }
        return program;
    }

    // Una funzione del pannello: dichiarata da uno script delle pagine, non del browser. Le funzioni
    // del browser (fetch, alert, eval, ...) hanno "[native code]" nel loro testo.
    function panelFunction(name) {
        if (!Object.prototype.hasOwnProperty.call(window, name)) return null;
        var f = window[name];
        if (typeof f !== 'function') return null;
        if (/\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(f))) return null;
        return f;
    }

    function evaluate(node, el, ev) {
        switch (node.k) {
            case 'lit': return node.v;
            case 'this': return el;
            case 'event': return ev;
            case 'not': return !evaluate(node.e, el, ev);
            case 'neg': return -evaluate(node.e, el, ev);
            case 'eq': return evaluate(node.l, el, ev) === evaluate(node.r, el, ev);
            case 'ne': return evaluate(node.l, el, ev) !== evaluate(node.r, el, ev);
            case 'get': {
                var o = evaluate(node.o, el, ev);
                if (o === null || o === undefined) throw new ActionError('no ' + node.p + ' on ' + o);
                return o[node.p];
            }
            case 'call': {
                var args = node.a.map(function (a) { return evaluate(a, el, ev); });
                if (node.f.k === 'name') {
                    if (node.f.v === 'Number') return Number(args[0]);
                    var f = panelFunction(node.f.v);
                    if (!f) throw new ActionError(node.f.v + ' is not a function of the panel');
                    return f.apply(window, args);
                }
                if (node.f.k === 'get' && METHODS[node.f.p]) {
                    var target = evaluate(node.f.o, el, ev);
                    if (target === null || target === undefined) throw new ActionError('no ' + node.f.p + ' on ' + target);
                    return target[node.f.p].apply(target, args);
                }
                throw new ActionError('this call is not allowed');
            }
            case 'name': throw new ActionError(node.v + ' can only be called');
        }
        throw new ActionError('unknown node');
    }

    var programs = new Map();

    function compile(src) {
        var p = programs.get(src);
        if (!p) {
            p = parse(src);
            programs.set(src, p);
        }
        return p;
    }

    function run(el, ev, attr) {
        var src = el.getAttribute(attr);
        try {
            var program = compile(src);
            for (var i = 0; i < program.length; i++) {
                var value = evaluate(program[i].e, el, ev);
                if (program[i].ret) {
                    if (value === false) ev.preventDefault();
                    return;
                }
            }
        } catch (e) {
            if (e instanceof ActionError) {
                console.error('[panel-actions] ' + attr + '="' + src + '": ' + e.message);
                return;
            }
            throw e;
        }
    }

    EVENTS.forEach(function (type) {
        var attr = 'data-on-' + type;
        var selector = '[' + attr + ']';
        document.addEventListener(type, function (ev) {
            var node = ev.target && ev.target.nodeType === 1 ? ev.target : ev.target && ev.target.parentElement;
            // Dal bersaglio verso l'alto, come risalgono i gestori in linea; stopPropagation() ferma.
            while (node) {
                var el = node.closest(selector);
                if (!el) return;
                run(el, ev, attr);
                if (ev.cancelBubble) return;
                node = el.parentElement;
            }
        });
    });
    TARGET_ONLY.forEach(function (type) {
        var attr = 'data-on-' + type;
        document.addEventListener(type, function (ev) {
            if (ev.target && ev.target.nodeType === 1 && ev.target.hasAttribute(attr)) run(ev.target, ev, attr);
        }, true);
    });

    // Per le prove: lo stesso linguaggio, senza eseguire niente. I problemi di un'espressione, in
    // questa pagina: non si analizza, chiama una funzione che non e' del pannello, o un metodo non
    // ammesso. Un elenco vuoto = va.
    window.panelActionsCheck = function (src) {
        var problems = [];
        var program;
        try { program = parse(src); } catch (e) { return [e instanceof ActionError ? e.message : String(e)]; }
        (function walk(node) {
            if (!node || typeof node !== 'object') return;
            if (node.k === 'call') {
                if (node.f.k === 'name' && node.f.v !== 'Number' && !panelFunction(node.f.v)) problems.push(node.f.v + ' is not a function of the panel');
                if (node.f.k === 'get' && !METHODS[node.f.p]) problems.push('method ' + node.f.p + ' is not allowed');
                if (node.f.k !== 'name' && node.f.k !== 'get') problems.push('this call is not allowed');
                if (node.f.k === 'get') walk(node.f.o);
                node.a.forEach(walk);
                return;
            }
            // Un nome che non e' chiamato (una variabile): evaluate lo rifiuta.
            if (node.k === 'name') problems.push(node.v + ' can only be called');
            ['e', 'l', 'r', 'o'].forEach(function (key) { walk(node[key]); });
            (node.a || []).forEach(walk);
        })({ a: program.map(function (s) { return s.e; }) });
        return problems;
    };

    // ---------- gli stili ----------

    var styled = new WeakMap();

    // Le dichiarazioni di data-style, una per una. Quelle che il codice ha gia' messo sull'elemento
    // (subito dopo averlo creato, prima che arrivasse l'osservatore) restano sue.
    function applyStyle(el) {
        var css = el.getAttribute('data-style');
        if (styled.get(el) === css) return;
        styled.set(el, css);
        var probe = document.createElement('div').style;
        probe.cssText = css;
        for (var i = 0; i < probe.length; i++) {
            var prop = probe[i];
            if (el.style.getPropertyValue(prop) === '') {
                el.style.setProperty(prop, probe.getPropertyValue(prop), probe.getPropertyPriority(prop));
            }
        }
    }

    // Per le prove: se data-style di questo elemento e' stato applicato (dopo, il codice della pagina
    // puo' averlo cambiato, ed e' giusto).
    window.panelStyleApplied = function (el) { return styled.get(el) === el.getAttribute('data-style'); };

    function applyStyles(node) {
        if (node.nodeType !== 1) return;
        if (node.hasAttribute('data-style')) applyStyle(node);
        var inner = node.querySelectorAll('[data-style]');
        for (var i = 0; i < inner.length; i++) applyStyle(inner[i]);
    }

    // Le pagine costruiscono i pezzi con innerHTML e subito dopo, nella stessa funzione, a volte
    // mostrano o nascondono qualcosa (el.style.display = ''): lo stile di data-style deve esserci
    // gia' in quel momento, non dopo, quando arriva l'osservatore. Quindi le tre vie con cui le
    // pagine scrivono HTML lo applicano subito; l'osservatore resta per tutto il resto (la pagina
    // mentre si costruisce, gli elementi spostati o clonati).
    function wrapSetter(proto, prop, after) {
        var d = Object.getOwnPropertyDescriptor(proto, prop);
        if (!d || !d.set) return;
        Object.defineProperty(proto, prop, {
            configurable: true, enumerable: d.enumerable, get: d.get,
            set: function (value) {
                var parent = this.parentNode;
                d.set.call(this, value);
                after(this, parent);
            }
        });
    }
    wrapSetter(Element.prototype, 'innerHTML', function (el) { applyStyles(el); });
    wrapSetter(Element.prototype, 'outerHTML', function (el, parent) { if (parent) applyStyles(parent.nodeType === 1 ? parent : document.documentElement); });
    var insertAdjacent = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (where, html) {
        var r = insertAdjacent.call(this, where, html);
        var w = String(where).toLowerCase();
        applyStyles((w === 'beforebegin' || w === 'afterend') && this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : this);
        return r;
    };

    new MutationObserver(function (records) {
        for (var r = 0; r < records.length; r++) {
            var rec = records[r];
            if (rec.type === 'attributes') {
                if (rec.target.hasAttribute('data-style')) applyStyle(rec.target);
            } else {
                for (var i = 0; i < rec.addedNodes.length; i++) applyStyles(rec.addedNodes[i]);
            }
        }
    }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-style'] });
    applyStyles(document.documentElement);
})();
