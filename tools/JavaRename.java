import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.LineMap;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;

import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.util.Elements;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Stream;

/**
 * Rinomina nomi Java con il compilatore, non con il testo (r26).
 *
 * javac analizza tutti i sorgenti del progetto insieme (src/main/java e tests), e ogni
 * occorrenza di un nome — dichiarazione, chiamata, accesso a un campo, riferimento a metodo —
 * viene risolta alla dichiarazione a cui punta. Si cambiano solo le occorrenze che puntano
 * alla dichiarazione scelta: un omonimo in un'altra classe, un parametro con lo stesso nome
 * in un altro metodo, una parola uguale in un commento restano come sono.
 *
 * Poi il controllo, che e' la parte che conta: si rianalizza tutto e OGNI occorrenza di OGNI
 * nome del progetto deve puntare alla stessa dichiarazione di prima. «Compila» non basta:
 * un nome nuovo uguale a un campo esistente compila, e cambia il significato in silenzio.
 * Se una sola occorrenza non torna, lo strumento lo dice e esce con 1.
 *
 * I commenti e le stringhe il compilatore non li vede: dopo la rinomina si cercano a parte i
 * nomi vecchi rimasti, e si decide uno per uno.
 *
 * Uso, dalla radice del progetto, con il jar costruito come classpath delle dipendenze:
 *
 *   java tools/JavaRename.java declarations target/freebsd-mail-panel-1.0.jar righe.txt
 *        elenca le dichiarazioni il cui nome sta su una delle righe (file:riga per riga)
 *   java tools/JavaRename.java rename target/freebsd-mail-panel-1.0.jar mappa.txt
 *        applica la mappa e controlla; una riga per nome:
 *          member:org.mail_panel.system.UpdateManager#avviaSulTurno startOnTurn
 *              tutti i membri con quel nome in quella classe (gli overload insieme)
 *          local:src/main/java/org/mail_panel/system/UpdateManager.java:2750:lavoro work
 *              il parametro o la variabile dichiarata su quella riga
 */
public class JavaRename {

    /** Una occorrenza di un nome: dove sta, e a quale dichiarazione punta. */
    record Occurrence(String file, int pos, String name, boolean declaration, String target) {}

    /** Una dichiarazione del progetto, con cio' che serve per sceglierla dalla mappa. */
    record Declaration(String file, int pos, int line, String name, String kind, String owner) {}

    static final class Analysis {
        final List<Occurrence> occurrences = new ArrayList<>();
        final List<Declaration> declarations = new ArrayList<>();
        final Map<String, String> sources = new HashMap<>();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("uso: declarations|rename <classpath> <file>");
            System.exit(2);
        }
        Path root = Path.of("").toAbsolutePath();
        switch (args[0]) {
            case "declarations" -> listDeclarations(root, args[1], Path.of(args[2]));
            case "rename" -> System.exit(rename(root, args[1], Path.of(args[2])));
            default -> { System.err.println("modo sconosciuto: " + args[0]); System.exit(2); }
        }
    }

    // ===================== l'analisi =====================

    static List<Path> sourceFiles(Path root) throws IOException {
        List<Path> files = new ArrayList<>();
        for (String dir : List.of("src/main/java", "tests")) {
            Path d = root.resolve(dir);
            if (!Files.isDirectory(d)) continue;
            try (Stream<Path> s = Files.walk(d)) {
                s.filter(p -> p.toString().endsWith(".java")).sorted().forEach(files::add);
            }
        }
        return files;
    }

    static Analysis analyze(Path root, String classpath) throws IOException {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager fm = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8);
        List<Path> files = sourceFiles(root);
        Iterable<? extends JavaFileObject> units = fm.getJavaFileObjectsFromPaths(files);
        List<String> options = List.of("-proc:none", "-nowarn", "-Xlint:none", "--release", "25",
                "-encoding", "UTF-8", "-cp", classpath);
        JavacTask task = (JavacTask) compiler.getTask(null, fm, diagnostics, options, null, units);
        Iterable<? extends CompilationUnitTree> trees = task.parse();
        task.analyze();
        List<String> errors = new ArrayList<>();
        for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
            if (d.getKind() == Diagnostic.Kind.ERROR) errors.add(d.toString());
        }
        if (!errors.isEmpty()) {
            errors.stream().limit(20).forEach(System.err::println);
            throw new IllegalStateException(errors.size() + " errori di compilazione: niente da fare finche' non compila");
        }
        Trees t = Trees.instance(task);
        Elements elements = task.getElements();
        Analysis a = new Analysis();
        Map<Element, String> keys = new IdentityHashMap<>();

        // Due giri: prima le dichiarazioni (cosi' ogni riferimento trova la sua chiave anche se
        // la dichiarazione sta in un file che viene dopo), poi i riferimenti.
        List<CompilationUnitTree> cus = new ArrayList<>();
        trees.forEach(cus::add);
        for (CompilationUnitTree cu : cus) {
            String file = root.relativize(Path.of(cu.getSourceFile().toUri())).toString();
            String text = cu.getSourceFile().getCharContent(true).toString();
            a.sources.put(file, text);
            new DeclarationScanner(t, elements, cu, file, text, keys, a).scan(cu, null);
        }
        for (CompilationUnitTree cu : cus) {
            String file = root.relativize(Path.of(cu.getSourceFile().toUri())).toString();
            new ReferenceScanner(t, cu, file, a.sources.get(file), keys, a).scan(cu, null);
        }
        return a;
    }

    /** La chiave di una dichiarazione fuori dal progetto: tipo, contenitore, nome, parametri. */
    static String externalKey(Element e) {
        String sig = e instanceof ExecutableElement x ? x.getParameters().stream()
                .map(p -> p.asType().toString()).toList().toString() : "";
        return "ext:" + e.getKind() + ":" + e.getEnclosingElement() + "." + e.getSimpleName() + sig;
    }

    /** Dove comincia il nome, cercandolo da 'from' come parola intera. -1 se non c'e'. */
    static int findName(String text, int from, String name) {
        if (from < 0) return -1;
        int i = text.indexOf(name, from);
        while (i >= 0) {
            boolean before = i > 0 && Character.isJavaIdentifierPart(text.charAt(i - 1));
            int end = i + name.length();
            boolean after = end < text.length() && Character.isJavaIdentifierPart(text.charAt(end));
            if (!before && !after) return i;
            i = text.indexOf(name, i + 1);
        }
        return -1;
    }

    static final class DeclarationScanner extends TreePathScanner<Void, Void> {
        final Trees trees; final Elements elements; final CompilationUnitTree cu; final String file, text;
        final Map<Element, String> keys; final Analysis a; final SourcePositions sp; final LineMap lines;

        DeclarationScanner(Trees trees, Elements elements, CompilationUnitTree cu, String file, String text,
                           Map<Element, String> keys, Analysis a) {
            this.trees = trees; this.elements = elements; this.cu = cu; this.file = file; this.text = text;
            this.keys = keys; this.a = a; this.sp = trees.getSourcePositions(); this.lines = cu.getLineMap();
        }

        void record(Tree tree, String name, int pos, String kind) {
            Element e = trees.getElement(getCurrentPath());
            if (e == null || pos < 0) return;
            if (!text.startsWith(name, pos)) throw new IllegalStateException(
                    "posizione sbagliata per " + name + " in " + file + ":" + lines.getLineNumber(Math.max(pos, 0)));
            String key = "src:" + file + "@" + pos;
            keys.put(e, key);
            String owner = e.getEnclosingElement() instanceof TypeElement te
                    ? elements.getBinaryName(te).toString()
                    : String.valueOf(e.getEnclosingElement());
            a.declarations.add(new Declaration(file, pos, (int) lines.getLineNumber(pos), name, kind, owner));
            a.occurrences.add(new Occurrence(file, pos, name, true, key));
        }

        @Override public Void visitClass(ClassTree node, Void v) {
            String name = node.getSimpleName().toString();
            if (!name.isEmpty()) {
                int from = (int) sp.getEndPosition(cu, node.getModifiers());
                if (from < 0) from = (int) sp.getStartPosition(cu, node);
                record(node, name, findName(text, from, name), "class");
            }
            return super.visitClass(node, v);
        }

        @Override public Void visitMethod(MethodTree node, Void v) {
            String name = node.getName().toString();
            if (!name.equals("<init>")) {
                int from = node.getReturnType() != null ? (int) sp.getEndPosition(cu, node.getReturnType()) : -1;
                if (from < 0) from = (int) sp.getStartPosition(cu, node);
                record(node, name, findName(text, from, name), "method");
            }
            return super.visitMethod(node, v);
        }

        @Override public Void visitVariable(VariableTree node, Void v) {
            String name = node.getName().toString();
            int from = node.getType() != null ? (int) sp.getEndPosition(cu, node.getType()) : -1;
            int start = (int) sp.getStartPosition(cu, node);
            // Un parametro di lambda senza tipo, o un tipo sintetizzato: il nome e' all'inizio.
            if (from < start) from = start;
            int pos = findName(text, from, name);
            if (pos < 0 || !text.startsWith(name, pos)) pos = findName(text, start, name);
            record(node, name, pos, "variable");
            return super.visitVariable(node, v);
        }
    }

    static final class ReferenceScanner extends TreePathScanner<Void, Void> {
        final Trees trees; final CompilationUnitTree cu; final String file, text;
        final Map<Element, String> keys; final Analysis a; final SourcePositions sp;

        ReferenceScanner(Trees trees, CompilationUnitTree cu, String file, String text,
                         Map<Element, String> keys, Analysis a) {
            this.trees = trees; this.cu = cu; this.file = file; this.text = text;
            this.keys = keys; this.a = a; this.sp = trees.getSourcePositions();
        }

        void reference(String name, int pos) {
            if (pos < 0 || name.equals("this") || name.equals("super") || name.equals("class")) return;
            Element e = trees.getElement(getCurrentPath());
            if (e == null) return;
            if (!text.startsWith(name, pos)) return;   // nomi sintetizzati dal compilatore
            String key = keys.getOrDefault(e, externalKey(e));
            a.occurrences.add(new Occurrence(file, pos, name, false, key));
        }

        @Override public Void visitIdentifier(IdentifierTree node, Void v) {
            reference(node.getName().toString(), (int) sp.getStartPosition(cu, node));
            return super.visitIdentifier(node, v);
        }

        @Override public Void visitMemberSelect(MemberSelectTree node, Void v) {
            String name = node.getIdentifier().toString();
            long end = sp.getEndPosition(cu, node);
            reference(name, end < 0 ? -1 : (int) end - name.length());
            return super.visitMemberSelect(node, v);
        }

        @Override public Void visitMemberReference(MemberReferenceTree node, Void v) {
            String name = node.getName().toString();
            long end = sp.getEndPosition(cu, node);
            if (!name.equals("<init>")) reference(name, end < 0 ? -1 : (int) end - name.length());
            return super.visitMemberReference(node, v);
        }
    }

    // ===================== elenco delle dichiarazioni =====================

    static void listDeclarations(Path root, String classpath, Path linesFile) throws IOException {
        Set<String> wanted = new TreeSet<>();
        for (String l : Files.readAllLines(linesFile)) if (!l.isBlank()) wanted.add(l.trim());
        Analysis a = analyze(root, classpath);
        for (Declaration d : a.declarations) {
            if (!wanted.contains(d.file() + ":" + d.line())) continue;
            System.out.println(d.kind() + "\t" + d.owner() + "\t" + d.name() + "\t" + d.file() + ":" + d.line());
        }
    }

    // ===================== rinomina e controllo =====================

    record Edit(String file, int pos, String oldName, String newName) {}

    static int rename(Path root, String classpath, Path mapFile) throws IOException {
        Map<String, String> map = new LinkedHashMap<>();
        for (String l : Files.readAllLines(mapFile)) {
            String s = l.strip();
            if (s.isEmpty() || s.startsWith("#")) continue;
            String[] p = s.split("\\s+");
            if (p.length != 2 || !p[1].matches("[A-Za-z_][A-Za-z0-9_]*")) throw new IllegalArgumentException("riga non valida: " + l);
            if (map.put(p[0], p[1]) != null) throw new IllegalArgumentException("selettore doppio: " + p[0]);
        }
        Analysis before = analyze(root, classpath);
        System.out.println("prima: " + before.occurrences.size() + " occorrenze, " + before.declarations.size() + " dichiarazioni");

        // Selettore -> chiavi delle dichiarazioni che sceglie. Ogni selettore deve sceglierne
        // almeno una: un selettore che non trova niente e' un errore di battitura, non un no-op.
        Map<String, String> targetToNew = new HashMap<>();
        int problems = 0;
        for (Map.Entry<String, String> m : map.entrySet()) {
            List<Declaration> chosen = new ArrayList<>();
            String sel = m.getKey();
            for (Declaration d : before.declarations) {
                if (sel.startsWith("member:")) {
                    String[] cm = sel.substring("member:".length()).split("#");
                    if (cm.length == 2 && d.owner().equals(cm[0]) && d.name().equals(cm[1])
                            && !d.kind().equals("class")) chosen.add(d);
                } else if (sel.startsWith("local:")) {
                    String rest = sel.substring("local:".length());
                    int c2 = rest.lastIndexOf(':'), c1 = rest.lastIndexOf(':', c2 - 1);
                    if (c1 < 0) continue;
                    if (d.file().equals(rest.substring(0, c1)) && String.valueOf(d.line()).equals(rest.substring(c1 + 1, c2))
                            && d.name().equals(rest.substring(c2 + 1)) && d.kind().equals("variable")) chosen.add(d);
                }
            }
            if (chosen.isEmpty()) { System.out.println("NESSUNA DICHIARAZIONE per " + sel); problems++; }
            for (Declaration d : chosen) targetToNew.put("src:" + d.file() + "@" + d.pos(), m.getValue());
        }
        if (problems > 0) return 1;

        List<Edit> edits = new ArrayList<>();
        for (Occurrence o : before.occurrences) {
            String nn = targetToNew.get(o.target());
            if (nn != null) edits.add(new Edit(o.file(), o.pos(), o.name(), nn));
        }
        Map<String, TreeMap<Integer, Edit>> byFile = new HashMap<>();
        for (Edit e : edits) byFile.computeIfAbsent(e.file(), k -> new TreeMap<>()).put(e.pos(), e);
        System.out.println("occorrenze da cambiare: " + edits.size() + " in " + byFile.size() + " file");

        for (Map.Entry<String, TreeMap<Integer, Edit>> f : byFile.entrySet()) {
            StringBuilder sb = new StringBuilder(before.sources.get(f.getKey()));
            for (Edit e : f.getValue().descendingMap().values()) {
                if (!sb.substring(e.pos(), e.pos() + e.oldName().length()).equals(e.oldName()))
                    throw new IllegalStateException("testo inatteso in " + e.file() + " a " + e.pos());
                sb.replace(e.pos(), e.pos() + e.oldName().length(), e.newName());
            }
            Files.writeString(root.resolve(f.getKey()), sb.toString(), StandardCharsets.UTF_8);
        }

        // --- il controllo ---
        Analysis after = analyze(root, classpath);
        Map<String, Occurrence> afterAt = new HashMap<>();
        for (Occurrence o : after.occurrences) afterAt.put(o.file() + "@" + o.pos(), o);
        int bad = 0;
        for (Occurrence o : before.occurrences) {
            int np = shift(byFile.get(o.file()), o.pos());
            Occurrence n = afterAt.get(o.file() + "@" + np);
            String expectedName = targetToNew.getOrDefault(o.target(), o.name());
            String expectedTarget = shiftKey(byFile, o.target());
            if (n == null || !n.name().equals(expectedName) || !n.target().equals(expectedTarget)) {
                if (bad++ < 30) System.out.println("NON TORNA: " + o.file() + "@" + o.pos() + " " + o.name()
                        + " -> " + (n == null ? "sparita" : n.name() + " punta a " + n.target()) + ", attesa " + expectedTarget);
            }
        }
        if (after.occurrences.size() != before.occurrences.size()) {
            System.out.println("NON TORNA: occorrenze " + before.occurrences.size() + " prima, " + after.occurrences.size() + " dopo");
            bad++;
        }
        System.out.println(bad == 0
                ? "CONTROLLO: tutte le " + after.occurrences.size() + " occorrenze puntano alla stessa dichiarazione di prima"
                : "CONTROLLO FALLITO: " + bad + " occorrenze non tornano");
        return bad == 0 ? 0 : 1;
    }

    /** La posizione di prima, dopo le sostituzioni fatte prima di lei nello stesso file. */
    static int shift(TreeMap<Integer, Edit> edits, int pos) {
        if (edits == null) return pos;
        int delta = 0;
        for (Edit e : edits.headMap(pos, false).values()) delta += e.newName().length() - e.oldName().length();
        return pos + delta;
    }

    static String shiftKey(Map<String, TreeMap<Integer, Edit>> byFile, String key) {
        if (!key.startsWith("src:")) return key;
        int at = key.lastIndexOf('@');
        String file = key.substring(4, at);
        return "src:" + file + "@" + shift(byFile.get(file), Integer.parseInt(key.substring(at + 1)));
    }
}
