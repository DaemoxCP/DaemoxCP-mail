// The generated pages before and after: the same JavaScript except for a consistent rename.
//   NODE_PATH=$(npm root -g) node tools/js-rename-check.js <pages-before> <pages-after> <map.txt>
const ts = require('typescript');
const fs = require('fs'), path = require('path');
const [before, after, mapFile] = process.argv.slice(2);
const map = new Map(fs.readFileSync(mapFile, 'utf8').trim().split('\n').map(l => l.trim().split(/\s+/)));
const names = [...map.keys()].sort((a, b) => b.length - a.length);
const wordRe = new RegExp('(?<![\\w$.])(' + names.join('|') + ')(?![\\w$])', 'g');
const onRename = s => s.replace(/(\bon[a-z]+=\\?["'])([^"'\\]*)/g, (m, a, code) => a + code.replace(wordRe, w => map.get(w)));
function tokens(code) {
  const sf = ts.createSourceFile('x.js', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const out = [];
  const leaf = n => { const ch = n.getChildren(sf); if (!ch.length) { if (n.kind !== ts.SyntaxKind.EndOfFileToken) out.push([n.kind, n.getText(sf), n.parent]); } else ch.forEach(leaf); };
  leaf(sf);
  return out;
}
function scripts(html) { const r = []; const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g; let m; while ((m = re.exec(html))) r.push(m[1]); return r; }
let bad = 0, pages = 0, renamed = 0;
const problem = s => { if (bad++ < 25) console.log('DOES NOT MATCH ' + s); };
// the two folders must have the same pages, and at least one: with nothing in front nothing is checked
const listA = fs.readdirSync(before).filter(f => f.endsWith('.html')).sort(), listB = fs.readdirSync(after).filter(f => f.endsWith('.html')).sort();
if (!listA.length) problem('no page in ' + before);
if (listA.join() !== listB.join()) problem('the pages are not the same: ' + listA.length + ' before, ' + listB.length + ' after');
for (const f of listA.filter(f => listB.includes(f))) {
  const A = fs.readFileSync(path.join(before, f), 'utf8'), B = fs.readFileSync(path.join(after, f), 'utf8');
  pages++;
  const sa = scripts(A), sb = scripts(B);
  if (sa.length !== sb.length) { problem(f + ': number of scripts ' + sa.length + ' -> ' + sb.length); continue; }
  // the markup outside the scripts
  const ma = A.replace(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/g, '<script/>'), mb = B.replace(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/g, '<script/>');
  if (onRename(ma) !== mb) problem(f + ': the markup changed outside the on*=');
  for (let i = 0; i < sa.length; i++) {
    const ta = tokens(sa[i]), tb = tokens(sb[i]);
    if (ta.length !== tb.length) { problem(f + '#' + i + ': token ' + ta.length + ' -> ' + tb.length); continue; }
    const fwd = new Map(), back = new Map();
    // the variable and function names that were there: the property keys (obj.name, { name: })
    // are in another space, and naming a variable that way does not touch them
    const isPropKey = (pa, x) => (ts.isPropertyAccessExpression(pa) && pa.name.getText() === x) || (ts.isPropertyAssignment(pa) && pa.name.getText() === x) || (ts.isMethodDeclaration(pa) && pa.name.getText() === x);
    const oldIds = new Set(ta.filter(t => t[0] === ts.SyntaxKind.Identifier && !isPropKey(t[2], t[1])).map(t => t[1]));
    for (let k = 0; k < ta.length; k++) {
      const [ka, xa, pa] = ta[k], [kb, xb] = tb[k];
      if (ka !== kb) { problem(f + '#' + i + ' token ' + k + ': kind ' + ts.SyntaxKind[ka] + ' -> ' + ts.SyntaxKind[kb]); break; }
      if (ka === ts.SyntaxKind.Identifier) {
        if (xa !== xb) {
          renamed++;
          if (map.get(xa) !== xb) { problem(f + '#' + i + ': ' + xa + ' -> ' + xb + ' is not in the map'); break; }
          if (oldIds.has(xb) && !map.has(xb)) { problem(f + '#' + i + ': ' + xa + ' -> ' + xb + ' captures a name that already existed'); break; }
        } else if (map.has(xa)) {
          // left with the old name: it is fine only if it is a property key (data)
          const isProp = (ts.isPropertyAccessExpression(pa) && pa.name.getText() === xa) || ts.isPropertyAssignment(pa);
          if (!isProp) { problem(f + '#' + i + ': ' + xa + ' left with the old name'); break; }
        }
        if (!isPropKey(pa, xa)) {
          if (back.has(xb) && back.get(xb) !== xa) { problem(f + '#' + i + ': two different names become ' + xb); break; }
          back.set(xb, xa);
        }
      } else {
        const expect = (ka === ts.SyntaxKind.StringLiteral || ka === ts.SyntaxKind.NoSubstitutionTemplateLiteral || (ka >= ts.SyntaxKind.TemplateHead && ka <= ts.SyntaxKind.TemplateTail)) ? onRename(xa) : xa;
        if (expect !== xb) { problem(f + '#' + i + ' token ' + k + ': ' + JSON.stringify(xa).slice(0, 80) + ' -> ' + JSON.stringify(xb).slice(0, 80)); break; }
      }
    }
  }
}
console.log((bad ? 'CHECK FAILED: ' + bad + ' problems' : 'CHECK: ' + pages + ' pages, same JavaScript except for ' + renamed + ' identifiers renamed'));
process.exit(bad ? 1 : 0);
