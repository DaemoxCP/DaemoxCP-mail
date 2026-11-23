import com.sun.source.tree.*;
import com.sun.source.util.*;

import javax.lang.model.element.Element;
import javax.tools.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/**
 * The JSON keys that would end up twice on the same object after a rename.
 *
 * For every put("key", ...) and opt*("key") with a literal key it goes back to the object:
 * the variable it is called on, or the root of a chain new JSONObject().put(...).put(...).
 * Then, with the map of the renames (old new, one per line), every object that after the
 * rename would have two equal keys is reported: an old one renamed and one that already
 * existed, or two old ones with the same translation.
 *
 * Usage: java JsonKeyCheck.java <classpath> <map>   (from the project root)
 */
public class JsonKeyCheck {
    static String shortText(Tree t) {
        String s = t.toString().replaceAll("\\s+", " ");
        return s.substring(0, Math.min(40, s.length()));
    }

    public static void main(String[] a) throws Exception {
        Map<String, String> map = new HashMap<>();
        for (String l : Files.readAllLines(Path.of(a[1]))) {
            String[] p = l.trim().split("\\s+");
            if (p.length == 2) map.put(p[0], p[1]);
        }
        List<Path> files = new ArrayList<>();
        for (String d : List.of("src/main/java", "tests")) try (Stream<Path> s = Files.walk(Path.of(d))) {
            s.filter(p -> p.toString().endsWith(".java")).forEach(files::add);
        }
        JavaCompiler c = ToolProvider.getSystemJavaCompiler();
        StandardJavaFileManager fm = c.getStandardFileManager(null, null, StandardCharsets.UTF_8);
        JavacTask task = (JavacTask) c.getTask(null, fm, d -> {}, List.of("-proc:none", "-nowarn", "--release", "25", "-cp", a[0]),
                null, fm.getJavaFileObjectsFromPaths(files));
        Iterable<? extends CompilationUnitTree> cus = task.parse();
        task.analyze();
        Trees trees = Trees.instance(task);
        // object -> (key -> where)
        Map<Object, Map<String, List<String>>> puts = new LinkedHashMap<>(), reads = new LinkedHashMap<>();
        Map<Object, String> label = new HashMap<>();
        for (CompilationUnitTree cu : cus) {
            String file = Path.of(cu.getSourceFile().toUri()).getFileName().toString();
            LineMap lm = cu.getLineMap();
            SourcePositions sp = trees.getSourcePositions();
            new TreePathScanner<Void, Void>() {
                @Override public Void visitMethodInvocation(MethodInvocationTree mi, Void v) {
                    if (mi.getMethodSelect() instanceof MemberSelectTree ms && !mi.getArguments().isEmpty()
                            && mi.getArguments().get(0) instanceof LiteralTree lt && lt.getValue() instanceof String key) {
                        String m = ms.getIdentifier().toString();
                        boolean put = m.equals("put") || m.equals("accumulate") || m.equals("append");
                        boolean read = m.startsWith("opt") || m.startsWith("get") || m.equals("has") || m.equals("remove") || m.equals("isNull");
                        if (put || read) {
                            ExpressionTree recv = ms.getExpression();
                            // goes back up the chain of puts: the object is the root
                            while (put && recv instanceof MethodInvocationTree inner && inner.getMethodSelect() instanceof MemberSelectTree ims
                                    && (ims.getIdentifier().contentEquals("put") || ims.getIdentifier().contentEquals("accumulate")))
                                recv = ims.getExpression();
                            Object id;
                            Element e = trees.getElement(new TreePath(getCurrentPath(), recv));
                            if (recv instanceof IdentifierTree && e != null) id = e;
                            else id = recv;   // the root of the chain, as a node
                            label.putIfAbsent(id, file + ":" + lm.getLineNumber(sp.getStartPosition(cu, mi)) + " " + shortText(recv));
                            (put ? puts : reads).computeIfAbsent(id, k -> new TreeMap<>()).computeIfAbsent(key, k -> new ArrayList<>())
                                    .add(file + ":" + lm.getLineNumber(sp.getStartPosition(cu, mi)));
                        }
                    }
                    return super.visitMethodInvocation(mi, v);
                }
            }.scan(cu, null);
        }
        int n = 0;
        for (Map.Entry<String, Map<Object, Map<String, List<String>>>> kind : Map.of("SCRITTE", puts, "LETTE", reads).entrySet()) {
            for (Map.Entry<Object, Map<String, List<String>>> o : kind.getValue().entrySet()) {
                Map<String, List<String>> after = new TreeMap<>();
                for (String k : o.getValue().keySet()) after.computeIfAbsent(map.getOrDefault(k, k), x -> new ArrayList<>()).add(k);
                for (Map.Entry<String, List<String>> x : after.entrySet()) {
                    if (x.getValue().size() > 1) {
                        n++;
                        System.out.println(kind.getKey() + " sullo stesso oggetto (" + label.get(o.getKey()) + "): " + x.getValue() + " -> " + x.getKey());
                    }
                }
            }
        }
        System.out.println(n == 0 ? "NESSUNA COLLISIONE" : n + " COLLISIONI");
        System.exit(n == 0 ? 0 : 1);
    }
}
