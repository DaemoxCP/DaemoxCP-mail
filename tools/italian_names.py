"""Which parts of a name are Italian.

Italian corpus: the texts of it.json and the comments of the code (they are in Italian by rule).
English corpus: the texts of en.json, plus the technical words. A part is Italian if it appears in
the Italian corpus and not in the English one, or if it is not in the English dictionary (as before)."""
import re, json, glob, os, sys
ROOT = sys.argv[1]
def words_of(s): return set(w.lower() for w in re.findall(r"[A-Za-zÀ-ÿ']+", s) for w in w.split("'") if w)
it = json.load(open(f"{ROOT}/src/main/resources/lang/it.json", encoding="utf-8"))
en = json.load(open(f"{ROOT}/src/main/resources/lang/en.json", encoding="utf-8"))
IT_WORDS = set().union(*(words_of(v) for v in it.values() if isinstance(v, str)))
EN_WORDS = set().union(*(words_of(v) for v in en.values() if isinstance(v, str)))
for f in glob.glob(f"{ROOT}/src/main/java/**/*.java", recursive=True) + glob.glob(f"{ROOT}/src/main/resources/pages/*") + glob.glob(f"{ROOT}/tests/**/*.java", recursive=True) + glob.glob(f"{ROOT}/tests/*.js") + glob.glob(f"{ROOT}/tests/*.py"):
    t = open(f, encoding="utf-8", errors="replace").read()
    for c in re.findall(r"(?m)//[^\n]*|/\*[\s\S]*?\*/|^\s*#[^\n]*", t): IT_WORDS |= words_of(c)
DICT = set(w.strip().lower() for w in open("/usr/share/dict/words", encoding="utf-8", errors="ignore"))
TECH = set(open(os.path.join(os.path.dirname(__file__), "technical-words.txt")).read().split()) if os.path.exists(os.path.join(os.path.dirname(__file__), "technical-words.txt")) else set()
# words that are in both corpora but here are Italian (or vice versa) are decided by hand
def parts(name):
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return [re.sub(r"\d+$", "", p.lower()) for p in re.split(r"[\s_\-]+", s) if p and not p.isdigit()]
def italian_parts(name):
    out = []
    for p in parts(name):
        if len(p) < 3 or p in TECH: continue
        if (p in IT_WORDS and p not in EN_WORDS) or (p not in DICT and p not in EN_WORDS and p not in TECH):
            out.append(p)
    return out
if __name__ == "__main__":
    for l in open(sys.argv[2], encoding="utf-8"):
        n = l.split("\t")[0]
        ip = italian_parts(n)
        if ip: print(n + "\t" + ",".join(ip) + "\t" + "\t".join(l.rstrip("\n").split("\t")[1:]))
