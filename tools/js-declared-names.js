// The names declared in the JavaScript that the browser runs: the generated pages (inline scripts)
// and the browser tests. Output: name<TAB>kind<TAB>count
const ts = require('typescript');
const fs = require('fs'), path = require('path');
const dir = process.argv[2], extra = process.argv.slice(3);
const decl = new Map();
function add(n, k) { const key = n + '\t' + k; decl.set(key, (decl.get(key) || 0) + 1); }
function walk(sf) {
  const visit = node => {
    if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) && node.name) add(node.name.text, 'funzione');
    else if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) add(node.name.text, 'variabile');
    else if (ts.isParameter(node) && ts.isIdentifier(node.name)) add(node.name.text, 'parametro');
    else if (ts.isBindingElement(node) && ts.isIdentifier(node.name)) add(node.name.text, 'variabile');
    ts.forEachChild(node, visit);
  };
  visit(sf);
}
for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.html') && !f.endsWith('.en.html'))) {
  const html = fs.readFileSync(path.join(dir, f), 'utf8');
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g; let m, i = 0;
  while ((m = re.exec(html))) walk(ts.createSourceFile(f + '#' + (i++) + '.js', m[1], ts.ScriptTarget.Latest, true, ts.ScriptKind.JS));
}
for (const f of extra) walk(ts.createSourceFile(f, fs.readFileSync(f, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS));
for (const [k, v] of [...decl.entries()].sort()) console.log(k + '\t' + v);
