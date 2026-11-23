import com.sun.source.tree.*;
import com.sun.source.util.*;

import javax.tools.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/**
 * The status codes written as strings in the Java: listing them and renaming them, with the compiler
 * telling where each string literal is and inside what.
 *
 * A value like "attendi" can be a code (level = "attendi", "attendi".equals(x),
 * case "attendi" ->) or the name of a placeholder in Map.of("attendi", ...) for I18n.tr. Only
 * the former are renamed: the strings inside a Map.of, Map.entry or I18n.tr call are not
 * touched (they belong to the translations phase), and neither is a whole excluded file
 * (PathMigration: there "sistema" is the name of the OLD folder, to be migrated).
 *
 * Usage:  java ValueRename.java list   <classpath> <values.txt>   lists by context
 *         java ValueRename.java rename <classpath> <map.txt>      applies (old new)
 */
public class ValueRename {
    record Hit(Path file, int pos, int end, String value, String context) {}

    public static void main(String[] a) throws Exception {
        Map<String, String> map = new LinkedHashMap<>();
        for (String l : Files.readAllLines(Path.of(a[2]))) {
            String[] p = l.trim().split("\\s+");
            if (p.length >= 1 && !p[0].isEmpty() && !p[0].startsWith("#")) map.put(p[0], p.length > 1 ? p[1] : p[0]);
        }
        List<Path> files = new ArrayList<>();
        for (String d : List.of("src/main/java", "tests")) try (Stream<Path> s = Files.walk(Path.of(d))) {
            s.filter(p -> p.toString().endsWith(".java")).forEach(files::add);
        }
        JavaCompiler c = ToolProvider.getSystemJavaCompiler();
        StandardJavaFileManager fm = c.getStandardFileManager(null, null, StandardCharsets.UTF_8);
        JavacTask task = (JavacTask) c.getTask(null, fm, d -> {}, List.of("-proc:none", "-nowarn", "--release", "25", "-cp", a[1]),
                null, fm.getJavaFileObjectsFromPaths(files));
        Iterable<? extends CompilationUnitTree> cus = task.parse();
        task.analyze();
        Trees trees = Trees.instance(task);
        SourcePositions sp = trees.getSourcePositions();
        List<Hit> hits = new ArrayList<>();
        Map<String, Map<String, Integer>> byCtx = new TreeMap<>();
        for (CompilationUnitTree cu : cus) {
            Path file = Path.of(cu.getSourceFile().toUri());
            if (file.getFileName().toString().equals("PathMigration.java")) continue;
            new TreePathScanner<Void, Void>() {
                @Override public Void visitLiteral(LiteralTree lt, Void v) {
                    if (lt.getValue() instanceof String s && map.containsKey(s)) {
                        String ctx = context(getCurrentPath());
                        byCtx.computeIfAbsent(s, k -> new TreeMap<>()).merge(ctx, 1, Integer::sum);
                        if (!ctx.startsWith("SKIP")) hits.add(new Hit(file, (int) sp.getStartPosition(cu, lt), (int) sp.getEndPosition(cu, lt), s, ctx));
                    }
                    return null;
                }
            }.scan(cu, null);
        }
        if (a[0].equals("list")) {
            for (var e : byCtx.entrySet()) System.out.println(e.getKey() + "\t" + e.getValue());
            return;
        }
        // rename: from bottom to top per file, checking the text
        Map<Path, List<Hit>> per = new TreeMap<>();
        for (Hit h : hits) per.computeIfAbsent(h.file(), k -> new ArrayList<>()).add(h);
        int n = 0;
        for (var e : per.entrySet()) {
            StringBuilder sb = new StringBuilder(Files.readString(e.getKey()));
            List<Hit> hs = e.getValue();
            hs.sort(Comparator.comparingInt(Hit::pos).reversed());
            for (Hit h : hs) {
                String lit = sb.substring(h.pos(), h.end());
                if (!lit.equals("\"" + h.value() + "\"")) throw new IllegalStateException("unexpected text " + e.getKey() + "@" + h.pos() + ": " + lit);
                sb.replace(h.pos(), h.end(), "\"" + map.get(h.value()) + "\"");
                n++;
            }
            Files.writeString(e.getKey(), sb.toString());
        }
        System.out.println("values changed: " + n + " in " + per.size() + " file");
    }

    /** What the string is inside: it decides whether it is a code or a placeholder name. */
    static String context(TreePath p) {
        Tree leaf = p.getLeaf();
        for (TreePath q = p.getParentPath(); q != null; leaf = q.getLeaf(), q = q.getParentPath()) {
            Tree t = q.getLeaf();
            if (t instanceof MethodInvocationTree mi) {
                String sel = mi.getMethodSelect().toString();
                if (sel.endsWith("Map.of") || sel.endsWith("Map.entry") || sel.endsWith("Map.ofEntries")) return "SKIP Map.of";
                if (sel.endsWith("I18n.tr") || sel.endsWith("I18n.trIn")) return "SKIP I18n.tr";
                if (leaf instanceof LiteralTree && mi.getArguments().contains(leaf)) {
                    String m = sel.substring(sel.lastIndexOf('.') + 1);
                    if (mi.getArguments().indexOf(leaf) == 0 && (m.equals("put") || m.startsWith("opt") || m.startsWith("get") || m.equals("has")))
                        return "SKIP JSON key";
                    if (m.equals("equals") || m.equals("equalsIgnoreCase")) return "comparison";
                    if (m.equals("put")) return "JSON value";
                    return "argument of " + m;
                }
                if (mi.getMethodSelect() instanceof MemberSelectTree ms && ms.getExpression() == leaf
                        && (ms.getIdentifier().contentEquals("equals") || ms.getIdentifier().contentEquals("equalsIgnoreCase"))) return "comparison";
            }
            if (t instanceof CaseTree) return "case";
            if (t instanceof ReturnTree) return "return";
            if (t instanceof VariableTree || t instanceof AssignmentTree) return "assignment";
            if (t instanceof ConditionalExpressionTree) continue;
            if (t instanceof NewArrayTree) return "array";
            if (t instanceof BinaryTree) return "concatenation";
            if (t instanceof NewClassTree) return "constructor";
            if (t instanceof MethodTree || t instanceof ClassTree) break;
        }
        return "other";
    }
}
