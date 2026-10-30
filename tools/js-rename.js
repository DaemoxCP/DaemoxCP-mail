// Rinomina identificatori JavaScript con il parser di TypeScript.
//   NODE_PATH=$(npm root -g) node tools/js-rename.js <radice> <mappa.txt> [--dry]
// File: src/main/resources/pages/*.js|*.html, tests/*.js, e le stringhe Java che contengono
// JavaScript (decodificate dagli escape, analizzate, rimappate sulle posizioni del sorgente).
// Si cambiano: i nodi Identifier col nome nella mappa, e dentro le stringhe JavaScript i nomi di
// funzione negli attributi on*="..." (lo stesso nome chiamato dall'HTML generato).
const ts = require('typescript');
const fs = require('fs'), path = require('path');
const [root, mapFile] = process.argv.slice(2, 4), dry = process.argv.includes('--dry');
const map = new Map(fs.readFileSync(mapFile, 'utf8').trim().split('\n').map(l => l.trim().split(/\s+/)));
const names = [...map.keys()].sort((a, b) => b.length - a.length);
const wordRe = new RegExp('(?<![\\w$.])(' + names.map(n => n.replace(/[$]/g, '\\$')).join('|') + ')(?![\\w$])', 'g');
const counts = {};
function inc(k) { counts[k] = (counts[k] || 0) + 1; }

/** Le modifiche (posizione nel testo JS, lunghezza, nuovo) per un pezzo di JavaScript. */
function jsEdits(code, where) {
  const sf = ts.createSourceFile('x.js', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out = [];
  const visit = node => {
    if (ts.isIdentifier(node) && map.has(node.text)) {
      // non una chiave di proprieta' (obj.nome / { nome: ... }): quelle sono dati, fase 55
      const p = node.parent;
      const isPropName = (ts.isPropertyAccessExpression(p) && p.name === node)
        || (ts.isPropertyAssignment(p) && p.name === node)
        || (ts.isMethodDeclaration(p) && p.name === node);
      if (!isPropName) { out.push([node.getStart(sf), node.text.length, map.get(node.text)]); inc('identificatori ' + where); }
      else if (ts.isShorthandPropertyAssignment(p)) { /* gestito sotto */ }
    }
    if (ts.isShorthandPropertyAssignment(node) && map.has(node.name.text)) {
      // { nome } = { nome: nome }: la chiave resta, il valore cambia
      out.push([node.name.getStart(sf), node.name.text.length, node.name.text + ': ' + map.get(node.name.text)]);
      inc('abbreviate ' + where);
      return;
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      const raw = code.slice(node.getStart(sf), node.getEnd());
      const re = /\bon[a-z]+=\\?["']([^"'\\]*)/g; let m;
      while ((m = re.exec(raw))) {
        const base = node.getStart(sf) + m.index + m[0].length - m[1].length;
        let w; wordRe.lastIndex = 0;
        while ((w = wordRe.exec(m[1]))) { out.push([base + w.index, w[1].length, map.get(w[1])]); inc('in on*= ' + where); }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function apply(text, edits) {
  edits.sort((a, b) => b[0] - a[0]);
  let t = text, last = Infinity;
  for (const [p, l, n] of edits) { if (p + l > last) continue; t = t.slice(0, p) + n + t.slice(p + l); last = p; }
  return t;
}

/** Le stringhe Java (normali e text block) con il loro contenuto decodificato e la mappa delle posizioni. */
function javaStrings(src) {
  const out = []; let i = 0, n = src.length;
  while (i < n) {
    if (src.startsWith('"""', i)) {
      let j = src.indexOf('"""', i + 3); if (j < 0) j = n;
      const start = src.indexOf('\n', i) + 1; out.push(decode(src, start, j)); i = j + 3;
    } else if (src[i] === '"') {
      let j = i + 1; while (j < n && src[j] !== '"' && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      out.push(decode(src, i + 1, j)); i = j + 1;
    } else if (src[i] === "'") { let j = i + 1; while (j < n && src[j] !== "'" && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1; i = j + 1; }
    else if (src.startsWith('//', i)) { const j = src.indexOf('\n', i); i = j < 0 ? n : j; }
    else if (src.startsWith('/*', i)) { const j = src.indexOf('*/', i + 2); i = j < 0 ? n : j + 2; }
    else i++;
  }
  return out;
}
function decode(src, a, b) {
  let text = '', pos = [];
  for (let i = a; i < b; i++) {
    if (src[i] === '\\' && i + 1 < b) {
      const c = src[i + 1]; const d = { n: '\n', t: '\t', '"': '"', "'": "'", '\\': '\\', r: '\r' }[c];
      if (d !== undefined) { text += d; pos.push(i); i++; continue; }
    }
    text += src[i]; pos.push(i);
  }
  return { text, pos };
}
/**
 * Un frammento che mescola HTML e script (i text block della pagina): JavaScript solo fra
 * <script> e </script>, e altrove solo i nomi dentro gli attributi on*="...". Analizzato tutto
 * come JavaScript, TypeScript leggerebbe l'HTML come JSX e il codice che segue come testo.
 * Il frammento comincia in JavaScript, a meno che cominci con '<'.
 */
function mixedEdits(text, where) {
  const out = [];
  let mode = /^\s*</.test(text) ? 'html' : 'js', i = 0;
  while (i < text.length) {
    if (mode === 'js') {
      const r = /<\/script/ig; r.lastIndex = i; const m = r.exec(text);
      const stop = m ? m.index : text.length;
      for (const [p, l, n] of jsEdits(text.slice(i, stop), where)) out.push([i + p, l, n]);
      i = stop; mode = 'html';
      if (!m) break;
    } else {
      const r = /<script(?![^>]*\bsrc=)[^>]*>/ig; r.lastIndex = i; const m = r.exec(text);
      const stop = m ? m.index + m[0].length : text.length;
      const chunk = text.slice(i, stop);
      const ra = /\bon[a-z]+=\\?["']([^"'\\]*)/g; let a;
      while ((a = ra.exec(chunk))) { const base = i + a.index + a[0].length - a[1].length; let w; wordRe.lastIndex = 0;
        while ((w = wordRe.exec(a[1]))) { out.push([base + w.index, w[1].length, map.get(w[1])]); inc('in on*= markup ' + where); } }
      i = stop; mode = 'js';
      if (!m) break;
    }
  }
  return out;
}
// anche il pezzo che chiude uno <script> aperto in un altro pezzo: "loadMailboxes();\n</script>"
function looksJs(t) { return /\bfunction\b|=>|\bconst\b|\blet\b|document\.|\bon[a-z]+=|<\/script/.test(t); }

let files = 0;
const pages = path.join(root, 'src/main/resources/pages');
for (const f of fs.readdirSync(pages).filter(f => f.endsWith('.js')).map(f => path.join(pages, f)).concat(
     fs.readdirSync(path.join(root, 'tests')).filter(f => f.endsWith('.js')).map(f => path.join(root, 'tests', f)))) {
  const t = fs.readFileSync(f, 'utf8'); const e = jsEdits(t, 'file js');
  if (e.length) { files++; if (!dry) fs.writeFileSync(f, apply(t, e)); }
}
for (const f of fs.readdirSync(pages).filter(f => f.endsWith('.html')).map(f => path.join(pages, f))) {
  const t = fs.readFileSync(f, 'utf8'); const e = [];
  const re = /(<script(?![^>]*\bsrc=)[^>]*>)([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(t))) for (const [p, l, n] of jsEdits(m[2], 'html')) e.push([m.index + m[1].length + p, l, n]);
  const ra = /\bon[a-z]+="([^"]*)"/g;
  while ((m = ra.exec(t))) { let w; wordRe.lastIndex = 0; const base = m.index + m[0].length - 1 - m[1].length;
    while ((w = wordRe.exec(m[1]))) { e.push([base + w.index, w[1].length, map.get(w[1])]); inc('in on*= html'); } }
  if (e.length) { files++; if (!dry) fs.writeFileSync(f, apply(t, e)); }
}
const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(x => x.isDirectory() ? walk(path.join(d, x.name)) : (x.name.endsWith('.java') ? [path.join(d, x.name)] : []));
for (const f of walk(path.join(root, 'src/main/java'))) {
  const src = fs.readFileSync(f, 'utf8'); const e = [];
  for (const s of javaStrings(src)) {
    if (!looksJs(s.text)) continue;
    for (const [p, l, n] of mixedEdits(s.text, 'nel java')) {
      const a = s.pos[p], b = s.pos[p + l - 1] + 1;
      if (src.slice(a, b) === s.text.slice(p, p + l)) e.push([a, b - a, n]);
    }
  }
  if (e.length) { files++; if (!dry) fs.writeFileSync(f, apply(src, e)); }
}
console.log('file cambiati: ' + files + (dry ? ' (a secco)' : ''), JSON.stringify(counts));
