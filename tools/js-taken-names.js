const ts = require('typescript'); const fs = require('fs'), path = require('path');
const [dir, mapFile, ...extra] = process.argv.slice(2);
const map = new Map(fs.readFileSync(mapFile, 'utf8').trim().split('\n').map(l => l.trim().split(/\s+/)));
const ids = new Set();
function scan(code) {
  const sf = ts.createSourceFile('x.js', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const v = n => { if (ts.isIdentifier(n)) { const p = n.parent;
      const prop = (ts.isPropertyAccessExpression(p) && p.name === n) || (ts.isPropertyAssignment(p) && p.name === n) || (ts.isMethodDeclaration(p) && p.name === n);
      if (!prop) ids.add(n.text); } ts.forEachChild(n, v); };
  v(sf);
}
for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.html'))) {
  const html = fs.readFileSync(path.join(dir, f), 'utf8'); const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(html))) scan(m[1]);
}
for (const f of extra) scan(fs.readFileSync(f, 'utf8'));
const targets = new Map(); for (const [a, b] of map) targets.set(b, (targets.get(b) || []).concat(a));
for (const [a, b] of map) {
  if (ids.has(b) && !map.has(b)) console.log('ESISTE GIA ' + a + ' -> ' + b);
  if (targets.get(b).length > 1) console.log('CONDIVISO ' + targets.get(b).join(',') + ' -> ' + b);
}
