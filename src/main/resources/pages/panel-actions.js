// The page actions and styles without inline code, for a Content-Security-Policy without
// 'unsafe-inline' (finding 178).
//
// Before, every button carried its inline onclick handler, and every element its style attribute: with
// 'unsafe-inline' in the CSP, a string injected into a page (a mailbox name, a log
// line) could run arbitrary code. Now:
//
//  - data-on-<event>="function(arguments)" instead of on<event>="...": a single listener per
//    event type, on document, reads the attribute and runs it. It is not eval: it is a
//    minimal language, which can only call the PANEL's functions (declared by the pages' scripts,
//    never the browser's, like fetch or alert) with literal arguments ('text', 12, true, null),
//    this and its properties (this.value, this.dataset.id, this.closest('tr')), event,
//    Number(...), === and !==, and "return" (return false = preventDefault). Several statements with ";".
//    A form it does not know is written to the console as an error and nothing is done.
//  - data-style="..." instead of the style attribute: the same style, applied with the CSSOM as soon as
//    the element enters the page (also those created later with innerHTML). The CSP does not block the
//    CSSOM, and so the style remains a style of the element: the code that shows and hides with
//    el.style.display = '' or 'none' keeps working (with a class it would not).
//
// It is loaded in the <head>, before the body: the observer sees every element while the page is
// being built, before it is drawn, and before any script of the page runs.
(function () {
    'use strict';

    // The events the pages use. Those that do not bubble (toggle of <details>) are caught
    // in the capture phase and apply only to the element itself, like inline handlers.
    var EVENTS = ['click', 'change', 'input', 'submit', 'keyup', 'keydown'];
    var TARGET_ONLY = ['toggle'];
    // The only methods an action may call on an object (this, event, an element).
    var METHODS = { closest: true, preventDefault: true, stopPropagation: true };

    // ---------- the language ----------

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

    // A panel function: declared by a page script, not by the browser. The browser's functions
    // (fetch, alert, eval, ...) have "[native code]" in their text.
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
            // From the target upwards, as inline handlers bubble up; stopPropagation() stops it.
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

    // For the tests: the same language, without running anything. The problems of an expression, on
    // this page: it does not parse, it calls a function that is not the panel's, or a method that is
    // not allowed. An empty list = it is fine.
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
            // A name that is not called (a variable): evaluate rejects it.
            if (node.k === 'name') problems.push(node.v + ' can only be called');
            ['e', 'l', 'r', 'o'].forEach(function (key) { walk(node[key]); });
            (node.a || []).forEach(walk);
        })({ a: program.map(function (s) { return s.e; }) });
        return problems;
    };

    // ---------- the styles ----------

    var styled = new WeakMap();

    // The declarations of data-style, one by one. Those the code has already put on the element
    // (right after creating it, before the observer arrived) remain its own.
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

    // For the tests: whether this element's data-style has been applied (afterwards, the page's code
    // may have changed it, and that is fine).
    window.panelStyleApplied = function (el) { return styled.get(el) === el.getAttribute('data-style'); };

    function applyStyles(node) {
        if (node.nodeType !== 1) return;
        if (node.hasAttribute('data-style')) applyStyle(node);
        var inner = node.querySelectorAll('[data-style]');
        for (var i = 0; i < inner.length; i++) applyStyle(inner[i]);
    }

    // The pages build the pieces with innerHTML and right after, in the same function, they sometimes
    // show or hide something (el.style.display = ''): the data-style style must already be there at
    // that moment, not later, when the observer arrives. So the three ways in which the
    // pages write HTML apply it at once; the observer remains for everything else (the page
    // while it is being built, elements moved or cloned).
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
