// Le pagine generate prima e dopo: stesso JavaScript a meno di una rinomina coerente.
//   NODE_PATH=$(npm root -g) node tools/js-rename-check.js <pagine-prima> <pagine-dopo> <mappa.txt>
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
const problem = s => { if (bad++ < 25) console.log('NON TORNA ' + s); };
// le due cartelle devono avere le stesse pagine, e almeno una: con niente davanti non si verifica niente
const listA = fs.readdirSync(before).filter(f => f.endsWith('.html')).sort(), listB = fs.readdirSync(after).filter(f => f.endsWith('.html')).sort();
if (!listA.length) problem('nessuna pagina in ' + before);
if (listA.join() !== listB.join()) problem('le pagine non sono le stesse: ' + listA.length + ' prima, ' + listB.length + ' dopo');
for (const f of listA.filter(f => listB.includes(f))) {
  const A = fs.readFileSync(path.join(before, f), 'utf8'), B = fs.readFileSync(path.join(after, f), 'utf8');
  pages++;
  const sa = scripts(A), sb = scripts(B);
  if (sa.length !== sb.length) { problem(f + ': numero di script ' + sa.length + ' -> ' + sb.length); continue; }
  // il markup fuori dagli script
  const ma = A.replace(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/g, '<script/>'), mb = B.replace(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/g, '<script/>');
  if (onRename(ma) !== mb) problem(f + ': il markup e\' cambiato fuori dagli on*=');
  for (let i = 0; i < sa.length; i++) {
    const ta = tokens(sa[i]), tb = tokens(sb[i]);
    if (ta.length !== tb.length) { problem(f + '#' + i + ': token ' + ta.length + ' -> ' + tb.length); continue; }
    const fwd = new Map(), back = new Map();
    // i nomi di variabile e di funzione che c'erano: le chiavi di proprieta' (obj.name, { name: })
    // stanno in un altro spazio, e chiamare cosi' una variabile non le tocca
    const isPropKey = (pa, x) => (ts.isPropertyAccessExpression(pa) && pa.name.getText() === x) || (ts.isPropertyAssignment(pa) && pa.name.getText() === x) || (ts.isMethodDeclaration(pa) && pa.name.getText() === x);
    const oldIds = new Set(ta.filter(t => t[0] === ts.SyntaxKind.Identifier && !isPropKey(t[2], t[1])).map(t => t[1]));
    for (let k = 0; k < ta.length; k++) {
      const [ka, xa, pa] = ta[k], [kb, xb] = tb[k];
      if (ka !== kb) { problem(f + '#' + i + ' token ' + k + ': tipo ' + ts.SyntaxKind[ka] + ' -> ' + ts.SyntaxKind[kb]); break; }
      if (ka === ts.SyntaxKind.Identifier) {
        if (xa !== xb) {
          renamed++;
          if (map.get(xa) !== xb) { problem(f + '#' + i + ': ' + xa + ' -> ' + xb + ' non e\' nella mappa'); break; }
          if (oldIds.has(xb) && !map.has(xb)) { problem(f + '#' + i + ': ' + xa + ' -> ' + xb + ' cattura un nome che c\'era gia\''); break; }
        } else if (map.has(xa)) {
          // rimasto col nome vecchio: va bene solo se e' una chiave di proprieta' (dati)
          const isProp = (ts.isPropertyAccessExpression(pa) && pa.name.getText() === xa) || ts.isPropertyAssignment(pa);
          if (!isProp) { problem(f + '#' + i + ': ' + xa + ' rimasto col nome vecchio'); break; }
        }
        if (!isPropKey(pa, xa)) {
          if (back.has(xb) && back.get(xb) !== xa) { problem(f + '#' + i + ': due nomi diversi diventano ' + xb); break; }
          back.set(xb, xa);
        }
      } else {
        const expect = (ka === ts.SyntaxKind.StringLiteral || ka === ts.SyntaxKind.NoSubstitutionTemplateLiteral || (ka >= ts.SyntaxKind.TemplateHead && ka <= ts.SyntaxKind.TemplateTail)) ? onRename(xa) : xa;
        if (expect !== xb) { problem(f + '#' + i + ' token ' + k + ': ' + JSON.stringify(xa).slice(0, 80) + ' -> ' + JSON.stringify(xb).slice(0, 80)); break; }
      }
    }
  }
}
console.log((bad ? 'VERIFICA FALLITA: ' + bad + ' problemi' : 'VERIFICA: ' + pages + ' pagine, stesso JavaScript a meno di ' + renamed + ' identificatori rinominati'));
process.exit(bad ? 1 : 0);
