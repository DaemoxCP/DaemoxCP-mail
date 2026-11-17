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
 *   java tools/JavaRename.java declarations target/daemoxcp-mail-1.0.jar righe.txt
 *        elenca le dichiarazioni il cui nome sta su una delle righe (file:riga per riga)
 *   java tools/JavaRename.java rename target/daemoxcp-mail-1.0.jar mappa.txt
 *        applica la mappa e controlla; una riga per nome:
 *          member:org.daemoxcp.mail.system.UpdateManager#avviaSulTurno startOnTurn
 *              tutti i membri con quel nome in quella classe (gli overload insieme)
 *          local:src/main/java/org/daemoxcp/mail/system/UpdateManager.java:2750:lavoro work
 *              il parametro o la variabile dichiarata su quella riga
 *          type:org.daemoxcp.mail.system.PackageQueue$Turno Turn
 *              un tipo annidato, con i suoi costruttori (i tipi in un giro a parte)
 *          enum:org.daemoxcp.mail.system.SubmissionPort$Outcome#AGGIUNTA ADDED
 *              una costante di enum; solo cosi', perche' il suo nome e' un valore che puo' uscire
 *              dal codice (name(), valueOf()) e chi lo legge fuori va cambiato nello stesso passo.
 *        Un componente di record si sceglie come un campo (member:), e porta con se' il suo
 *        accessore implicito.
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
        /** Per ogni metodo del progetto, i metodi di cui fa l'override (per chiave). */
        final Map<String, Set<String>> overrides = new HashMap<>();
        /** I nomi qualificati scritti come watchQualified (file -> posizioni d'inizio), per il modo package. */
        final Map<String, TreeSet<Integer>> qualifiedSpans = new HashMap<>();
    }

    /** Il nome qualificato di cui raccogliere le occorrenze scritte per intero (modo package), o null. */
    static String watchQualified = null;

    public static void main(String[] args) throws Exception {
        boolean pkg = args.length == 4 && args[0].equals("package");
        if (args.length != 3 && !pkg) {
            System.err.println("uso: declarations|rename <classpath> <file>  oppure  package <classpath> <vecchio> <nuovo>");
            System.exit(2);
        }
        Path root = Path.of("").toAbsolutePath();
        switch (args[0]) {
            case "declarations" -> listDeclarations(root, args[1], Path.of(args[2]));
            case "rename" -> System.exit(rename(root, args[1], Path.of(args[2])));
            case "package" -> System.exit(renamePackage(root, args[1], args[2], args[3]));
            default -> { System.err.println("modo sconosciuto: " + args[0]); System.exit(2); }
        }
    }

    // ===================== l'analisi =====================

    static List<Path> sourceFiles(Path root) throws IOException {
        List<Path> files = new ArrayList<>();
        for (String dir : List.of("src/main/java", "tests")) {
            Path d = root.resolve(dir);
            if (!Files.isDirectory(d)) continue;
            // tests/planted ha una copia guasta apposta di una classe del pannello (stesso nome, stesso
            // pacchetto): compilata insieme alle altre sarebbe una classe doppia.
            Path planted = root.resolve("tests/planted");
            try (Stream<Path> s = Files.walk(d)) {
                s.filter(p -> p.toString().endsWith(".java") && !p.startsWith(planted)).sorted().forEach(files::add);
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
            if (watchQualified != null) new QualifiedScanner(t, cu, file, a.sources.get(file), a).scan(cu, null);
        }
        // Gli override. La risoluzione dei riferimenti non li vede: un metodo rinominato come uno
        // della superclasse lo sostituisce a runtime senza che nessun riferimento cambi bersaglio.
        javax.lang.model.util.Types types = task.getTypes();
        for (Map.Entry<Element, String> en : keys.entrySet()) {
            if (!(en.getKey() instanceof ExecutableElement me) || me.getKind() != javax.lang.model.element.ElementKind.METHOD) continue;
            if (!(me.getEnclosingElement() instanceof TypeElement owner)) continue;
            Set<String> over = new TreeSet<>();
            java.util.ArrayDeque<javax.lang.model.type.TypeMirror> todo = new java.util.ArrayDeque<>(types.directSupertypes(owner.asType()));
            Set<String> seen = new java.util.HashSet<>();
            while (!todo.isEmpty()) {
                javax.lang.model.type.TypeMirror sup = todo.pop();
                Element se = types.asElement(sup);
                if (!(se instanceof TypeElement ste) || !seen.add(ste.getQualifiedName().toString())) continue;
                for (Element m2 : ste.getEnclosedElements()) {
                    if (m2 instanceof ExecutableElement x && m2.getKind() == javax.lang.model.element.ElementKind.METHOD
                            && x.getSimpleName().equals(me.getSimpleName()) && elements.overrides(me, x, owner))
                        over.add(keys.getOrDefault(m2, externalKey(m2)));
                }
                todo.addAll(types.directSupertypes(sup));
            }
            a.overrides.put(en.getValue(), over);
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
            kind = refine(e, kind);
            if (!text.startsWith(name, pos)) throw new IllegalStateException(
                    "posizione sbagliata per " + name + " in " + file + ":" + lines.getLineNumber(Math.max(pos, 0)));
            String key = "src:" + file + "@" + pos;
            keys.put(e, key);
            // Per un tipo il "proprietario" e' il tipo stesso: lo si sceglie per nome binario.
            // Per un costruttore e' la sua classe: si rinomina insieme a lei.
            Element ownerEl = kind.equals("type") ? e : e.getEnclosingElement();
            String owner = ownerEl instanceof TypeElement te
                    ? elements.getBinaryName(te).toString()
                    : String.valueOf(ownerEl);
            a.declarations.add(new Declaration(file, pos, (int) lines.getLineNumber(pos), name, kind, owner));
            a.occurrences.add(new Occurrence(file, pos, name, true, key));
        }

        /** Che cosa e' davvero la dichiarazione: decide cosa si puo' scegliere, e come. */
        String refine(Element e, String kind) {
            switch (e.getKind()) {
                case CLASS, INTERFACE, ENUM, RECORD, ANNOTATION_TYPE: return "type";
                case CONSTRUCTOR: return "ctor";
                case ENUM_CONSTANT: return "enumconst";
                case FIELD:
                    if (e.getEnclosingElement().getKind() == javax.lang.model.element.ElementKind.RECORD
                            && !e.getModifiers().contains(javax.lang.model.element.Modifier.STATIC)) return "component";
                    return "field";
                case METHOD: return "method";
                default: return kind;
            }
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
            } else if (sp.getStartPosition(cu, node) >= 0 && getCurrentPath().getParentPath().getLeaf() instanceof ClassTree ct
                       && !ct.getSimpleName().toString().isEmpty()) {
                // Un costruttore scritto nel sorgente (quelli impliciti non hanno testo).
                String cn = ct.getSimpleName().toString();
                int from = (int) sp.getEndPosition(cu, node.getModifiers());
                if (from < 0) from = (int) sp.getStartPosition(cu, node);
                int pos = findName(text, from, cn);
                if (pos >= 0 && pos < sp.getEndPosition(cu, node)) record(node, cn, pos, "ctor");
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

    /**
     * I punti in cui il nome qualificato del pacchetto e' scritto per intero: dichiarazione del
     * pacchetto, import, nomi scritti per intero nel codice. Un nome qualificato scritto come quello cercato che il compilatore
     * risolve a qualcos'altro che quel pacchetto e' un errore, non si tocca.
     */
    static final class QualifiedScanner extends TreePathScanner<Void, Void> {
        final Trees trees; final CompilationUnitTree cu; final String file, text; final Analysis a; final SourcePositions sp;

        QualifiedScanner(Trees trees, CompilationUnitTree cu, String file, String text, Analysis a) {
            this.trees = trees; this.cu = cu; this.file = file; this.text = text; this.a = a;
            this.sp = trees.getSourcePositions();
        }

        @Override public Void visitMemberSelect(MemberSelectTree node, Void v) {
            int s = (int) sp.getStartPosition(cu, node), e = (int) sp.getEndPosition(cu, node);
            if (s >= 0 && e > s && text.substring(s, e).equals(watchQualified)) {
                Element el = trees.getElement(getCurrentPath());
                if (el != null && !(el instanceof javax.lang.model.element.PackageElement pe
                                    && pe.getQualifiedName().contentEquals(watchQualified)))
                    throw new IllegalStateException(file + "@" + s + ": " + watchQualified + " risolto a " + el.getKind() + " " + el);
                a.qualifiedSpans.computeIfAbsent(file, k -> new TreeSet<>()).add(s);
                return null;   // dentro ci sono solo i pezzi del nome stesso
            }
            return super.visitMemberSelect(node, v);
        }
    }

    // ===================== il pacchetto =====================

    /**
     * Sposta un pacchetto, con i suoi sottopacchetti, sotto un nome nuovo (il 17/11/2026
     * org.mail_panel -> org.daemoxcp.mail): si cambiano i nomi qualificati che il compilatore risolve a quel pacchetto
     * (dichiarazioni, import, nomi scritti per intero) e i file passano nella cartella del pacchetto
     * nuovo. Il controllo e' quello della rinomina: rianalizzato tutto, ogni occorrenza di ogni nome
     * deve puntare alla stessa dichiarazione di prima, nel file spostato. I pezzi del nome del
     * pacchetto stesso ("mail_panel" che diventa "daemoxcp" e "mail") si controllano a parte.
     */
    static int renamePackage(Path root, String classpath, String oldPkg, String newPkg) throws IOException {
        String pkgName = "[a-z_][a-z0-9_]*(\\.[a-z_][a-z0-9_]*)+";
        if (!oldPkg.matches(pkgName) || !newPkg.matches(pkgName)) throw new IllegalArgumentException("nomi di pacchetto non validi");
        watchQualified = oldPkg;
        Analysis before = analyze(root, classpath);
        System.out.println("prima: " + before.occurrences.size() + " occorrenze, " + before.declarations.size()
                + " dichiarazioni, " + before.qualifiedSpans.values().stream().mapToInt(Set::size).sum() + " volte " + oldPkg);

        String oldDir = oldPkg.replace('.', '/') + "/", newDir = newPkg.replace('.', '/') + "/";
        Map<String, String> moves = new HashMap<>();
        for (String f : before.sources.keySet()) {
            for (String base : List.of("src/main/java/", "tests/")) {
                if (f.startsWith(base + oldDir)) moves.put(f, base + newDir + f.substring((base + oldDir).length()));
            }
        }
        Map<String, TreeMap<Integer, Edit>> byFile = new HashMap<>();
        for (Map.Entry<String, TreeSet<Integer>> q : before.qualifiedSpans.entrySet())
            for (int s : q.getValue()) byFile.computeIfAbsent(q.getKey(), k -> new TreeMap<>()).put(s, new Edit(q.getKey(), s, oldPkg, newPkg));
        System.out.println("nomi qualificati da cambiare in " + byFile.size() + " file, file da spostare: " + moves.size());

        for (String f : before.sources.keySet()) {
            StringBuilder sb = new StringBuilder(before.sources.get(f));
            TreeMap<Integer, Edit> ed = byFile.get(f);
            if (ed != null) for (Edit e : ed.descendingMap().values()) {
                if (!sb.substring(e.pos(), e.pos() + oldPkg.length()).equals(oldPkg))
                    throw new IllegalStateException("testo inatteso in " + f + " a " + e.pos());
                sb.replace(e.pos(), e.pos() + oldPkg.length(), newPkg);
            }
            String to = moves.getOrDefault(f, f);
            if (ed == null && to.equals(f)) continue;
            Path target = root.resolve(to);
            Files.createDirectories(target.getParent());
            Files.writeString(target, sb.toString(), StandardCharsets.UTF_8);
            if (!to.equals(f)) Files.delete(root.resolve(f));
        }
        for (String base : List.of("src/main/java/", "tests/")) deleteEmptyDirs(root.resolve(base + oldDir));

        // --- il controllo ---
        Analysis after = analyze(root, classpath);
        Map<String, Occurrence> afterAt = new HashMap<>();
        for (Occurrence o : after.occurrences) afterAt.put(o.file() + "@" + o.pos(), o);
        int bad = 0, insideBefore = 0, insideAfter = 0;
        String[] newParts = newPkg.split("\\.");
        for (Occurrence o : before.occurrences) {
            Integer span = spanContaining(before.qualifiedSpans.get(o.file()), o.pos(), oldPkg.length());
            if (span != null && o.pos() != span) { insideBefore++; continue; }   // i pezzi del nome vecchio
            String nf = moves.getOrDefault(o.file(), o.file());
            int np = shift(byFile.get(o.file()), o.pos());
            Occurrence n = afterAt.get(nf + "@" + np);
            String expectedTarget = moveKey(o.target(), moves, byFile, oldPkg, newPkg);
            if (n == null || !n.name().equals(o.name()) || !n.target().equals(expectedTarget)) {
                if (bad++ < 30) System.out.println("NON TORNA: " + o.file() + "@" + o.pos() + " " + o.name() + " -> "
                        + (n == null ? "sparita" : n.name() + " punta a " + n.target()) + ", attesa " + expectedTarget);
            }
        }
        // I pezzi del nome nuovo, dove prima c'era il nome vecchio: tutti, nell'ordine, al loro posto.
        for (Map.Entry<String, TreeSet<Integer>> q : before.qualifiedSpans.entrySet()) {
            String nf = moves.getOrDefault(q.getKey(), q.getKey());
            for (int s : q.getValue()) {
                int ns = shift(byFile.get(q.getKey()), s), at = ns;
                for (int i = 0; i < newParts.length; i++) {
                    Occurrence n = afterAt.get(nf + "@" + at);
                    if (i > 0) {
                        if (n != null && n.name().equals(newParts[i])) insideAfter++;
                        else if (n != null && bad++ < 30) System.out.println("NON TORNA: " + nf + "@" + at + " atteso " + newParts[i] + ", c'e' " + n.name());
                    }
                    at += newParts[i].length() + 1;
                }
            }
        }
        for (Map.Entry<String, Set<String>> ov : before.overrides.entrySet()) {
            String nk = moveKey(ov.getKey(), moves, byFile, oldPkg, newPkg);
            Set<String> expected = new TreeSet<>();
            for (String k : ov.getValue()) expected.add(moveKey(k, moves, byFile, oldPkg, newPkg));
            if (!after.overrides.getOrDefault(nk, Set.of()).equals(expected) && bad++ < 30)
                System.out.println("OVERRIDE CAMBIATO: " + nk);
        }
        int expectedCount = before.occurrences.size() - insideBefore + insideAfter;
        if (after.occurrences.size() != expectedCount) {
            System.out.println("NON TORNA: occorrenze " + after.occurrences.size() + " dopo, attese " + expectedCount
                    + " (" + insideBefore + " pezzi del nome vecchio, " + insideAfter + " del nome nuovo)");
            bad++;
        }
        if (after.declarations.size() != before.declarations.size()) {
            System.out.println("NON TORNA: dichiarazioni " + before.declarations.size() + " prima, " + after.declarations.size() + " dopo");
            bad++;
        }
        System.out.println(bad == 0
                ? "CONTROLLO: tutte le " + after.occurrences.size() + " occorrenze puntano alla stessa dichiarazione di prima ("
                  + insideBefore + " pezzi di " + oldPkg + " diventati " + insideAfter + " di " + newPkg + ")"
                : "CONTROLLO FALLITO: " + bad + " occorrenze non tornano");
        return bad == 0 ? 0 : 1;
    }

    /** L'inizio del nome qualificato che contiene pos, se pos sta dentro uno di quelli raccolti. */
    static Integer spanContaining(TreeSet<Integer> spans, int pos, int len) {
        if (spans == null) return null;
        Integer s = spans.floor(pos);
        return s != null && pos < s + len ? s : null;
    }

    /** La chiave di una dichiarazione dopo lo spostamento: file nuovo e posizione nuova, o il pacchetto nuovo nel nome. */
    static String moveKey(String key, Map<String, String> moves, Map<String, TreeMap<Integer, Edit>> byFile, String oldPkg, String newPkg) {
        if (key.startsWith("src:")) {
            int at = key.lastIndexOf('@');
            String file = key.substring(4, at);
            return "src:" + moves.getOrDefault(file, file) + "@" + shift(byFile.get(file), Integer.parseInt(key.substring(at + 1)));
        }
        return key.replaceAll(java.util.regex.Pattern.quote(oldPkg) + "(?=[.\\],>)\\s]|$)", java.util.regex.Matcher.quoteReplacement(newPkg));
    }

    static void deleteEmptyDirs(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) return;
        try (Stream<Path> s = Files.walk(dir)) {
            for (Path p : s.sorted(java.util.Comparator.reverseOrder()).toList()) {
                if (!Files.isDirectory(p)) continue;
                try (Stream<Path> c = Files.list(p)) { if (c.findAny().isEmpty()) Files.delete(p); }
            }
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
        // Chiavi di dichiarazioni senza testo (l'accessore implicito di un record) che cambiano
        // nome: nel controllo, la chiave attesa e' quella col nome nuovo.
        Map<String, String> externalRenames = new HashMap<>();
        // Tipi rinominati, per nome canonico: compaiono dentro le chiavi esterne (un accessore
        // implicito, values() di un enum) e vanno riscritti anche li'.
        Map<String, String> typeRenames = new LinkedHashMap<>();
        // Un tipo di primo livello da' il nome al suo file: rinominato lui, il file si sposta.
        Map<String, String> moves = new HashMap<>();
        int problems = 0;
        for (Map.Entry<String, String> m : map.entrySet()) {
            List<Declaration> chosen = new ArrayList<>();
            String sel = m.getKey();
            for (Declaration d : before.declarations) {
                if (sel.startsWith("member:")) {
                    String[] cm = sel.substring("member:".length()).split("#");
                    // Le costanti di enum no: il loro nome e' un valore (name(), valueOf()) che
                    // finisce nel JSON o su disco, e si cambia con chi lo legge.
                    if (cm.length == 2 && d.owner().equals(cm[0]) && d.name().equals(cm[1])
                            && (d.kind().equals("method") || d.kind().equals("field") || d.kind().equals("component"))) {
                        chosen.add(d);
                        if (d.kind().equals("component")) {
                            String canon = cm[0].replace('$', '.');
                            externalRenames.put("ext:METHOD:" + canon + "." + cm[1] + "[]",
                                                "ext:METHOD:" + canon + "." + m.getValue() + "[]");
                        }
                    }
                } else if (sel.startsWith("enum:")) {
                    // Una costante di enum, scelta apposta: il suo nome e' un valore che puo' uscire
                    // dal codice (name(), valueOf()), e chi lo legge fuori va cambiato insieme.
                    String[] cm = sel.substring("enum:".length()).split("#");
                    if (cm.length == 2 && d.owner().equals(cm[0]) && d.name().equals(cm[1]) && d.kind().equals("enumconst"))
                        chosen.add(d);
                } else if (sel.startsWith("type:")) {
                    String bin = sel.substring("type:".length());
                    if (d.owner().equals(bin) && d.kind().equals("type")) {
                        chosen.add(d);
                        String canon = bin.replace('$', '.');
                        typeRenames.put(canon, canon.substring(0, canon.lastIndexOf('.') + 1) + m.getValue());
                        String simple = canon.substring(canon.lastIndexOf('.') + 1);
                        if (!bin.contains("$") && d.file().endsWith("/" + simple + ".java"))
                            moves.put(d.file(), d.file().substring(0, d.file().length() - simple.length() - 5) + m.getValue() + ".java");
                    }
                    if (d.owner().equals(bin) && d.kind().equals("ctor")) chosen.add(d);
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
        for (Map.Entry<String, String> x : externalRenames.entrySet())
            targetToNew.put(x.getKey(), x.getValue().substring(x.getValue().lastIndexOf('.') + 1, x.getValue().length() - 2));
        if (!typeRenames.isEmpty() && (!externalRenames.isEmpty() || map.keySet().stream().anyMatch(k -> !k.startsWith("type:")))) {
            System.out.println("i tipi si rinominano in un giro a parte, prima dei membri");
            return 1;
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
            String to = moves.getOrDefault(f.getKey(), f.getKey());
            if (!to.equals(f.getKey()) && Files.exists(root.resolve(to)))
                throw new IllegalStateException("c'e' gia' " + to + ": il tipo rinominato non ha dove andare");
            Files.writeString(root.resolve(to), sb.toString(), StandardCharsets.UTF_8);
            if (!to.equals(f.getKey())) Files.delete(root.resolve(f.getKey()));
        }

        // --- il controllo ---
        Analysis after = analyze(root, classpath);
        Map<String, Occurrence> afterAt = new HashMap<>();
        for (Occurrence o : after.occurrences) afterAt.put(o.file() + "@" + o.pos(), o);
        int bad = 0;
        for (Occurrence o : before.occurrences) {
            int np = shift(byFile.get(o.file()), o.pos());
            Occurrence n = afterAt.get(moves.getOrDefault(o.file(), o.file()) + "@" + np);
            String expectedName = targetToNew.getOrDefault(o.target(), o.name());
            String expectedTarget = externalRenames.containsKey(o.target())
                    ? externalRenames.get(o.target()) : renameTypesIn(moveFile(shiftKey(byFile, o.target()), moves), typeRenames);
            if (n == null || !n.name().equals(expectedName) || !n.target().equals(expectedTarget)) {
                if (bad++ < 30) System.out.println("NON TORNA: " + o.file() + "@" + o.pos() + " " + o.name()
                        + " -> " + (n == null ? "sparita" : n.name() + " punta a " + n.target()) + ", attesa " + expectedTarget);
            }
        }
        // Gli override devono essere gli stessi: ne' persi ne' guadagnati.
        for (Map.Entry<String, Set<String>> ov : before.overrides.entrySet()) {
            String nk = moveFile(shiftKey(byFile, ov.getKey()), moves);
            Set<String> expected = new TreeSet<>();
            for (String k : ov.getValue()) expected.add(renameTypesIn(moveFile(shiftKey(byFile, k), moves), typeRenames));
            Set<String> got = after.overrides.getOrDefault(nk, Set.of());
            if (!got.equals(expected)) {
                if (bad++ < 30) System.out.println("OVERRIDE CAMBIATO: " + nk + " prima " + expected + ", dopo " + got);
            }
        }
        if (after.overrides.size() != before.overrides.size()) {
            System.out.println("NON TORNA: metodi " + before.overrides.size() + " prima, " + after.overrides.size() + " dopo");
            bad++;
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

    /** Una chiave esterna che nomina un tipo rinominato, scritta col nome nuovo. */
    static String renameTypesIn(String key, Map<String, String> typeRenames) {
        if (!key.startsWith("ext:")) return key;
        for (Map.Entry<String, String> r : typeRenames.entrySet())
            key = key.replaceAll(java.util.regex.Pattern.quote(r.getKey()) + "(?![A-Za-z0-9_$])",
                                 java.util.regex.Matcher.quoteReplacement(r.getValue()));
        return key;
    }

    /** Una chiave "src:" del file spostato (tipo di primo livello rinominato), col file nuovo. */
    static String moveFile(String key, Map<String, String> moves) {
        if (!key.startsWith("src:") || moves.isEmpty()) return key;
        int at = key.lastIndexOf('@');
        String file = key.substring(4, at);
        return "src:" + moves.getOrDefault(file, file) + key.substring(at);
    }

    static String shiftKey(Map<String, TreeMap<Integer, Edit>> byFile, String key) {
        if (!key.startsWith("src:")) return key;
        int at = key.lastIndexOf('@');
        String file = key.substring(4, at);
        return "src:" + file + "@" + shift(byFile.get(file), Integer.parseInt(key.substring(at + 1)));
    }
}
