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
 * Renames Java names with the compiler, not with the text (r26).
 *
 * javac analyses all the sources of the project together (src/main/java and tests), and every
 * occurrence of a name - declaration, call, field access, method reference - is resolved to
 * the declaration it points to. Only the occurrences that point to the chosen declaration are
 * changed: a namesake in another class, a parameter with the same name in another method, an
 * identical word in a comment stay as they are.
 *
 * Then the check, which is the part that matters: everything is analysed again and EVERY
 * occurrence of EVERY name of the project must point to the same declaration as before.
 * "It compiles" is not enough: a new name equal to an existing field compiles, and silently
 * changes the meaning. If a single occurrence does not match, the tool says so and exits with 1.
 *
 * The compiler does not see comments and strings: after the rename the old names that are left
 * are searched for separately, and decided one by one.
 *
 * Usage, from the project root, with the built jar as the classpath of the dependencies:
 *
 *   java tools/JavaRename.java declarations target/daemoxcp-mail.jar lines.txt
 *        lists the declarations whose name is on one of the lines (file:line per line)
 *   java tools/JavaRename.java rename target/daemoxcp-mail.jar map.txt
 *        applies the map and checks; one line per name:
 *          member:org.daemoxcp.mail.system.UpdateManager#avviaSulTurno startOnTurn
 *              all the members with that name in that class (the overloads together)
 *          local:src/main/java/org/daemoxcp/mail/system/UpdateManager.java:2750:lavoro work
 *              the parameter or the variable declared on that line
 *          type:org.daemoxcp.mail.system.PackageQueue$Turno Turn
 *              a nested type, with its constructors (the types in a separate pass)
 *          enum:org.daemoxcp.mail.system.SubmissionPort$Outcome#AGGIUNTA ADDED
 *              an enum constant; only this way, because its name is a value that can leave
 *              the code (name(), valueOf()) and whoever reads it outside must be changed in the
 *              same step.
 *        A record component is chosen like a field (member:), and brings its implicit
 *        accessor with it.
 */
public class JavaRename {

    /** An occurrence of a name: where it is, and which declaration it points to. */
    record Occurrence(String file, int pos, String name, boolean declaration, String target) {}

    /** A declaration of the project, with what is needed to choose it from the map. */
    record Declaration(String file, int pos, int line, String name, String kind, String owner) {}

    static final class Analysis {
        final List<Occurrence> occurrences = new ArrayList<>();
        final List<Declaration> declarations = new ArrayList<>();
        final Map<String, String> sources = new HashMap<>();
        /** For each method of the project, the methods it overrides (by key). */
        final Map<String, Set<String>> overrides = new HashMap<>();
        /** The qualified names written as watchQualified (file -> start positions), for the package mode. */
        final Map<String, TreeSet<Integer>> qualifiedSpans = new HashMap<>();
    }

    /** The qualified name whose occurrences written in full are to be collected (package mode), or null. */
    static String watchQualified = null;

    public static void main(String[] args) throws Exception {
        boolean pkg = args.length == 4 && args[0].equals("package");
        if (args.length != 3 && !pkg) {
            System.err.println("usage: declarations|rename <classpath> <file>  or  package <classpath> <old> <new>");
            System.exit(2);
        }
        Path root = Path.of("").toAbsolutePath();
        switch (args[0]) {
            case "declarations" -> listDeclarations(root, args[1], Path.of(args[2]));
            case "rename" -> System.exit(rename(root, args[1], Path.of(args[2])));
            case "package" -> System.exit(renamePackage(root, args[1], args[2], args[3]));
            default -> { System.err.println("unknown mode: " + args[0]); System.exit(2); }
        }
    }

    // ===================== the analysis =====================

    static List<Path> sourceFiles(Path root) throws IOException {
        List<Path> files = new ArrayList<>();
        for (String dir : List.of("src/main/java", "tests")) {
            Path d = root.resolve(dir);
            if (!Files.isDirectory(d)) continue;
            // tests/planted has a deliberately broken copy of a panel class (same name, same
            // package): compiled together with the others it would be a duplicate class.
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
            throw new IllegalStateException(errors.size() + " compilation errors: nothing to do until it compiles");
        }
        Trees t = Trees.instance(task);
        Elements elements = task.getElements();
        Analysis a = new Analysis();
        Map<Element, String> keys = new IdentityHashMap<>();

        // Two passes: first the declarations (so that every reference finds its key even if
        // the declaration is in a file that comes later), then the references.
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
        // The overrides. Reference resolution does not see them: a method renamed like one
        // of the superclass replaces it at runtime without any reference changing its target.
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

    /** The key of a declaration outside the project: kind, container, name, parameters. */
    static String externalKey(Element e) {
        String sig = e instanceof ExecutableElement x ? x.getParameters().stream()
                .map(p -> p.asType().toString()).toList().toString() : "";
        return "ext:" + e.getKind() + ":" + e.getEnclosingElement() + "." + e.getSimpleName() + sig;
    }

    /** Where the name begins, searching for it from 'from' as a whole word. -1 if it is not there. */
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
                    "wrong position for " + name + " in " + file + ":" + lines.getLineNumber(Math.max(pos, 0)));
            String key = "src:" + file + "@" + pos;
            keys.put(e, key);
            // For a type the "owner" is the type itself: it is chosen by binary name.
            // For a constructor it is its class: it is renamed together with it.
            Element ownerEl = kind.equals("type") ? e : e.getEnclosingElement();
            String owner = ownerEl instanceof TypeElement te
                    ? elements.getBinaryName(te).toString()
                    : String.valueOf(ownerEl);
            a.declarations.add(new Declaration(file, pos, (int) lines.getLineNumber(pos), name, kind, owner));
            a.occurrences.add(new Occurrence(file, pos, name, true, key));
        }

        /** What the declaration really is: it decides what can be chosen, and how. */
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
                // A constructor written in the source (the implicit ones have no text).
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
            // A lambda parameter without a type, or a synthesized type: the name is at the start.
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
            if (!text.startsWith(name, pos)) return;   // names synthesized by the compiler
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
     * The places where the qualified name of the package is written in full: the package
     * declaration, imports, names written in full in the code. A qualified name written like the one searched
     * for that the compiler resolves to something other than that package is an error, and is not touched.
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
                return null;   // only the pieces of the name itself are inside
            }
            return super.visitMemberSelect(node, v);
        }
    }

    // ===================== the package =====================

    /**
     * Moves a package, with its subpackages, under a new name (on 2026-11-17
     * org.mail_panel -> org.daemoxcp.mail): the qualified names that the compiler resolves to that package
     * are changed (declarations, imports, names written in full) and the files move into the folder of the
     * new package. The check is the one of the rename: everything analysed again, every occurrence of every
     * name must point to the same declaration as before, in the moved file. The pieces of the name of the
     * package itself ("mail_panel" that becomes "daemoxcp" and "mail") are checked separately.
     */
    static int renamePackage(Path root, String classpath, String oldPkg, String newPkg) throws IOException {
        String pkgName = "[a-z_][a-z0-9_]*(\\.[a-z_][a-z0-9_]*)+";
        if (!oldPkg.matches(pkgName) || !newPkg.matches(pkgName)) throw new IllegalArgumentException("invalid package names");
        watchQualified = oldPkg;
        Analysis before = analyze(root, classpath);
        System.out.println("before: " + before.occurrences.size() + " occurrences, " + before.declarations.size()
                + " declarations, " + before.qualifiedSpans.values().stream().mapToInt(Set::size).sum() + " times " + oldPkg);

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
        System.out.println("qualified names to change in " + byFile.size() + " files, files to move: " + moves.size());

        for (String f : before.sources.keySet()) {
            StringBuilder sb = new StringBuilder(before.sources.get(f));
            TreeMap<Integer, Edit> ed = byFile.get(f);
            if (ed != null) for (Edit e : ed.descendingMap().values()) {
                if (!sb.substring(e.pos(), e.pos() + oldPkg.length()).equals(oldPkg))
                    throw new IllegalStateException("unexpected text in " + f + " at " + e.pos());
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

        // --- the check ---
        Analysis after = analyze(root, classpath);
        Map<String, Occurrence> afterAt = new HashMap<>();
        for (Occurrence o : after.occurrences) afterAt.put(o.file() + "@" + o.pos(), o);
        int bad = 0, insideBefore = 0, insideAfter = 0;
        String[] newParts = newPkg.split("\\.");
        for (Occurrence o : before.occurrences) {
            Integer span = spanContaining(before.qualifiedSpans.get(o.file()), o.pos(), oldPkg.length());
            if (span != null && o.pos() != span) { insideBefore++; continue; }   // the pieces of the old name
            String nf = moves.getOrDefault(o.file(), o.file());
            int np = shift(byFile.get(o.file()), o.pos());
            Occurrence n = afterAt.get(nf + "@" + np);
            String expectedTarget = moveKey(o.target(), moves, byFile, oldPkg, newPkg);
            if (n == null || !n.name().equals(o.name()) || !n.target().equals(expectedTarget)) {
                if (bad++ < 30) System.out.println("DOES NOT MATCH: " + o.file() + "@" + o.pos() + " " + o.name() + " -> "
                        + (n == null ? "gone" : n.name() + " points to " + n.target()) + ", expected " + expectedTarget);
            }
        }
        // The pieces of the new name, where the old name used to be: all of them, in order, in their place. ALL
        // the occurrences recorded in there are counted, even the same position twice: the compiler sometimes
        // visits the same name twice (it did so before too, with the pieces of the old name), and counting them
        // only once here would give a total that does not match without anything having changed.
        Map<String, TreeMap<Integer, String>> expectedParts = new HashMap<>();
        for (Map.Entry<String, TreeSet<Integer>> q : before.qualifiedSpans.entrySet()) {
            String nf = moves.getOrDefault(q.getKey(), q.getKey());
            for (int s : q.getValue()) {
                int at = shift(byFile.get(q.getKey()), s);
                for (int i = 0; i < newParts.length; i++) {
                    if (i > 0) expectedParts.computeIfAbsent(nf, k -> new TreeMap<>()).put(at, newParts[i]);
                    at += newParts[i].length() + 1;
                }
            }
        }
        for (Occurrence o : after.occurrences) {
            TreeMap<Integer, String> parts = expectedParts.get(o.file());
            if (parts == null) continue;
            String want = parts.get(o.pos());
            if (want == null) continue;
            if (o.name().equals(want)) insideAfter++;
            else if (bad++ < 30) System.out.println("DOES NOT MATCH: " + o.file() + "@" + o.pos() + " expected " + want + ", found " + o.name());
        }
        for (Map.Entry<String, Set<String>> ov : before.overrides.entrySet()) {
            String nk = moveKey(ov.getKey(), moves, byFile, oldPkg, newPkg);
            Set<String> expected = new TreeSet<>();
            for (String k : ov.getValue()) expected.add(moveKey(k, moves, byFile, oldPkg, newPkg));
            if (!after.overrides.getOrDefault(nk, Set.of()).equals(expected) && bad++ < 30)
                System.out.println("OVERRIDE CHANGED: " + nk);
        }
        int expectedCount = before.occurrences.size() - insideBefore + insideAfter;
        if (after.occurrences.size() != expectedCount) {
            System.out.println("DOES NOT MATCH: occurrences " + after.occurrences.size() + " after, expected " + expectedCount
                    + " (" + insideBefore + " pieces of the old name, " + insideAfter + " of the new name)");
            bad++;
        }
        if (after.declarations.size() != before.declarations.size()) {
            System.out.println("DOES NOT MATCH: declarations " + before.declarations.size() + " before, " + after.declarations.size() + " after");
            bad++;
        }
        System.out.println(bad == 0
                ? "CHECK: all " + after.occurrences.size() + " occurrences point to the same declaration as before ("
                  + insideBefore + " pieces of " + oldPkg + " became " + insideAfter + " of " + newPkg + ")"
                : "CHECK FAILED: " + bad + " occurrences do not match");
        return bad == 0 ? 0 : 1;
    }

    /** The start of the qualified name that contains pos, if pos is inside one of those collected. */
    static Integer spanContaining(TreeSet<Integer> spans, int pos, int len) {
        if (spans == null) return null;
        Integer s = spans.floor(pos);
        return s != null && pos < s + len ? s : null;
    }

    /** The key of a declaration after the move: new file and new position, or the new package in the name. */
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

    // ===================== list of the declarations =====================

    static void listDeclarations(Path root, String classpath, Path linesFile) throws IOException {
        Set<String> wanted = new TreeSet<>();
        for (String l : Files.readAllLines(linesFile)) if (!l.isBlank()) wanted.add(l.trim());
        Analysis a = analyze(root, classpath);
        for (Declaration d : a.declarations) {
            if (!wanted.contains(d.file() + ":" + d.line())) continue;
            System.out.println(d.kind() + "\t" + d.owner() + "\t" + d.name() + "\t" + d.file() + ":" + d.line());
        }
    }

    // ===================== rename and check =====================

    record Edit(String file, int pos, String oldName, String newName) {}

    static int rename(Path root, String classpath, Path mapFile) throws IOException {
        Map<String, String> map = new LinkedHashMap<>();
        for (String l : Files.readAllLines(mapFile)) {
            String s = l.strip();
            if (s.isEmpty() || s.startsWith("#")) continue;
            String[] p = s.split("\\s+");
            if (p.length != 2 || !p[1].matches("[A-Za-z_][A-Za-z0-9_]*")) throw new IllegalArgumentException("invalid line: " + l);
            if (map.put(p[0], p[1]) != null) throw new IllegalArgumentException("duplicate selector: " + p[0]);
        }
        Analysis before = analyze(root, classpath);
        System.out.println("before: " + before.occurrences.size() + " occurrences, " + before.declarations.size() + " declarations");

        // Selector -> keys of the declarations it chooses. Every selector must choose
        // at least one: a selector that finds nothing is a typo, not a no-op.
        Map<String, String> targetToNew = new HashMap<>();
        // Keys of declarations without text (the implicit accessor of a record) that change
        // name: in the check, the expected key is the one with the new name.
        Map<String, String> externalRenames = new HashMap<>();
        // Renamed types, by canonical name: they appear inside the external keys (an implicit
        // accessor, values() of an enum) and must be rewritten there too.
        Map<String, String> typeRenames = new LinkedHashMap<>();
        // A top-level type gives its name to its file: once it is renamed, the file moves.
        Map<String, String> moves = new HashMap<>();
        int problems = 0;
        for (Map.Entry<String, String> m : map.entrySet()) {
            List<Declaration> chosen = new ArrayList<>();
            String sel = m.getKey();
            for (Declaration d : before.declarations) {
                if (sel.startsWith("member:")) {
                    String[] cm = sel.substring("member:".length()).split("#");
                    // Not the enum constants: their name is a value (name(), valueOf()) that
                    // ends up in the JSON or on disk, and is changed together with whoever reads it.
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
                    // An enum constant, chosen on purpose: its name is a value that can leave
                    // the code (name(), valueOf()), and whoever reads it outside must be changed with it.
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
            if (chosen.isEmpty()) { System.out.println("NO DECLARATION for " + sel); problems++; }
            for (Declaration d : chosen) targetToNew.put("src:" + d.file() + "@" + d.pos(), m.getValue());
        }
        for (Map.Entry<String, String> x : externalRenames.entrySet())
            targetToNew.put(x.getKey(), x.getValue().substring(x.getValue().lastIndexOf('.') + 1, x.getValue().length() - 2));
        if (!typeRenames.isEmpty() && (!externalRenames.isEmpty() || map.keySet().stream().anyMatch(k -> !k.startsWith("type:")))) {
            System.out.println("types are renamed in a pass of their own, before the members");
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
        System.out.println("occurrences to change: " + edits.size() + " in " + byFile.size() + " files");

        for (Map.Entry<String, TreeMap<Integer, Edit>> f : byFile.entrySet()) {
            StringBuilder sb = new StringBuilder(before.sources.get(f.getKey()));
            for (Edit e : f.getValue().descendingMap().values()) {
                if (!sb.substring(e.pos(), e.pos() + e.oldName().length()).equals(e.oldName()))
                    throw new IllegalStateException("unexpected text in " + e.file() + " at " + e.pos());
                sb.replace(e.pos(), e.pos() + e.oldName().length(), e.newName());
            }
            String to = moves.getOrDefault(f.getKey(), f.getKey());
            if (!to.equals(f.getKey()) && Files.exists(root.resolve(to)))
                throw new IllegalStateException("already there: " + to + ": the renamed type has nowhere to go");
            Files.writeString(root.resolve(to), sb.toString(), StandardCharsets.UTF_8);
            if (!to.equals(f.getKey())) Files.delete(root.resolve(f.getKey()));
        }

        // --- the check ---
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
                if (bad++ < 30) System.out.println("DOES NOT MATCH: " + o.file() + "@" + o.pos() + " " + o.name()
                        + " -> " + (n == null ? "gone" : n.name() + " points to " + n.target()) + ", expected " + expectedTarget);
            }
        }
        // The overrides must be the same: none lost and none gained.
        for (Map.Entry<String, Set<String>> ov : before.overrides.entrySet()) {
            String nk = moveFile(shiftKey(byFile, ov.getKey()), moves);
            Set<String> expected = new TreeSet<>();
            for (String k : ov.getValue()) expected.add(renameTypesIn(moveFile(shiftKey(byFile, k), moves), typeRenames));
            Set<String> got = after.overrides.getOrDefault(nk, Set.of());
            if (!got.equals(expected)) {
                if (bad++ < 30) System.out.println("OVERRIDE CHANGED: " + nk + " before " + expected + ", after " + got);
            }
        }
        if (after.overrides.size() != before.overrides.size()) {
            System.out.println("DOES NOT MATCH: methods " + before.overrides.size() + " before, " + after.overrides.size() + " after");
            bad++;
        }
        if (after.occurrences.size() != before.occurrences.size()) {
            System.out.println("DOES NOT MATCH: occurrences " + before.occurrences.size() + " before, " + after.occurrences.size() + " after");
            bad++;
        }
        System.out.println(bad == 0
                ? "CHECK: all " + after.occurrences.size() + " occurrences point to the same declaration as before"
                : "CHECK FAILED: " + bad + " occurrences do not match");
        return bad == 0 ? 0 : 1;
    }

    /** The position from before, after the replacements made before it in the same file. */
    static int shift(TreeMap<Integer, Edit> edits, int pos) {
        if (edits == null) return pos;
        int delta = 0;
        for (Edit e : edits.headMap(pos, false).values()) delta += e.newName().length() - e.oldName().length();
        return pos + delta;
    }

    /** An external key that names a renamed type, written with the new name. */
    static String renameTypesIn(String key, Map<String, String> typeRenames) {
        if (!key.startsWith("ext:")) return key;
        for (Map.Entry<String, String> r : typeRenames.entrySet())
            key = key.replaceAll(java.util.regex.Pattern.quote(r.getKey()) + "(?![A-Za-z0-9_$])",
                                 java.util.regex.Matcher.quoteReplacement(r.getValue()));
        return key;
    }

    /** A "src:" key of the moved file (renamed top-level type), with the new file. */
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
