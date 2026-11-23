// Renames JavaScript identifiers with the TypeScript parser.
//   NODE_PATH=$(npm root -g) node tools/js-rename.js <root> <map.txt> [--dry]
// Files: src/main/resources/pages/*.js|*.html, tests/*.js, and the Java strings that contain
// JavaScript (decoded from the escapes, parsed, mapped back onto the positions of the source).
// What is changed: the Identifier nodes with the name in the map, and inside the JavaScript strings
// the function names in the on*="..." attributes (the same name called by the generated HTML).
const ts = require('typescript');
const fs = require('fs'), path = require('path');
const [root, mapFile] = process.argv.slice(2, 4), dry = process.argv.includes('--dry');
const map = new Map(fs.readFileSync(mapFile, 'utf8').trim().split('\n').map(l => l.trim().split(/\s+/)));
const names = [...map.keys()].sort((a, b) => b.length - a.length);
const wordRe = new RegExp('(?<![\\w$.])(' + names.map(n => n.replace(/[$]/g, '\\$')).join('|') + ')(?![\\w$])', 'g');
const counts = {};
function inc(k) { counts[k] = (counts[k] || 0) + 1; }

/** The changes (position in the JS text, length, new) for a piece of JavaScript. */
function jsEdits(code, where) {
  const sf = ts.createSourceFile('x.js', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out = [];
  const visit = node => {
    if (ts.isIdentifier(node) && map.has(node.text)) {
      // not a property key (obj.nome / { nome: ... }): those are data, phase 55
      const p = node.parent;
      const isPropName = (ts.isPropertyAccessExpression(p) && p.name === node)
        || (ts.isPropertyAssignment(p) && p.name === node)
        || (ts.isMethodDeclaration(p) && p.name === node);
      if (!isPropName) { out.push([node.getStart(sf), node.text.length, map.get(node.text)]); inc('identifiers ' + where); }
      else if (ts.isShorthandPropertyAssignment(p)) { /* handled below */ }
    }
    if (ts.isShorthandPropertyAssignment(node) && map.has(node.name.text)) {
      // { nome } = { nome: nome }: the key stays, the value changes
      out.push([node.name.getStart(sf), node.name.text.length, node.name.text + ': ' + map.get(node.name.text)]);
      inc('abbreviated ' + where);
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

/** The Java strings (normal ones and text blocks) with their decoded content and the map of the positions. */
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
 * A fragment that mixes HTML and script (the text blocks of the page): JavaScript only between
 * <script> and </script>, and elsewhere only the names inside the on*="..." attributes. Parsed entirely
 * as JavaScript, TypeScript would read the HTML as JSX and the code that follows as text.
 * The fragment starts in JavaScript, unless it starts with '<'.
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
// also the piece that closes a <script> opened in another piece: "loadMailboxes();\n</script>"
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
    for (const [p, l, n] of mixedEdits(s.text, 'in the java')) {
      const a = s.pos[p], b = s.pos[p + l - 1] + 1;
      if (src.slice(a, b) === s.text.slice(p, p + l)) e.push([a, b - a, n]);
    }
  }
  if (e.length) { files++; if (!dry) fs.writeFileSync(f, apply(src, e)); }
}
console.log('files changed: ' + files + (dry ? ' (a secco)' : ''), JSON.stringify(counts));
