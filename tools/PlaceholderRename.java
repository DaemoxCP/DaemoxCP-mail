import com.sun.source.tree.*;
import com.sun.source.util.*;

import javax.tools.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/**
 * The names of the placeholders in the Java: the keys of the Map.of passed to I18n.tr / I18n.trIn.
 *
 * The compiler tells which string is in KEY position (even) inside a Map.of that is an
 * argument of I18n.tr: only those are renamed. If two keys of the same Map.of end up
 * with the same name, it stops: the text would lose one of the two values.
 *
 * Usage: java PlaceholderRename.java <classpath> <map.txt> [--dry]
 */
public class PlaceholderRename {
    record Edit(Path file, int pos, int end, String value) {}

    public static void main(String[] a) throws Exception {
        Map<String, String> map = new HashMap<>();
        for (String l : Files.readAllLines(Path.of(a[1]))) {
            String[] p = l.trim().split("\\s+");
            if (p.length == 2) map.put(p[0], p[1]);
        }
        boolean dry = a.length > 2 && a[2].equals("--dry");
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
        SourcePositions sp = Trees.instance(task).getSourcePositions();
        List<Edit> edits = new ArrayList<>();
        List<String> clashes = new ArrayList<>();
        int calls = 0;
        for (CompilationUnitTree cu : cus) {
            Path file = Path.of(cu.getSourceFile().toUri());
            LineMap lm = cu.getLineMap();
            int[] seen = {0};
            new TreeScanner<Void, Void>() {
                @Override public Void visitMethodInvocation(MethodInvocationTree mi, Void v) {
                    String sel = mi.getMethodSelect().toString();
                    if (sel.endsWith("I18n.tr") || sel.endsWith("I18n.trIn")) {
                        for (ExpressionTree arg : mi.getArguments()) {
                            if (arg instanceof MethodInvocationTree m2 && m2.getMethodSelect().toString().endsWith("Map.of")) {
                                seen[0]++;
                                Set<String> after = new HashSet<>();
                                List<? extends ExpressionTree> args = m2.getArguments();
                                for (int i = 0; i < args.size(); i += 2) {
                                    if (!(args.get(i) instanceof LiteralTree lt) || !(lt.getValue() instanceof String k)) continue;
                                    String nk = map.getOrDefault(k, k);
                                    if (!after.add(nk)) clashes.add(file.getFileName() + ":" + lm.getLineNumber(sp.getStartPosition(cu, lt)) + " " + nk);
                                    if (map.containsKey(k))
                                        edits.add(new Edit(file, (int) sp.getStartPosition(cu, lt), (int) sp.getEndPosition(cu, lt), k));
                                }
                            }
                        }
                    }
                    return super.visitMethodInvocation(mi, v);
                }
            }.scan(cu, null);
            calls += seen[0];
        }
        System.out.println("Map.of inside I18n.tr: " + calls + "; keys to rename: " + edits.size() + "; collisioni: " + clashes.size());
        clashes.forEach(x -> System.out.println("  COLLISIONE " + x));
        if (!clashes.isEmpty()) System.exit(1);
        if (dry) return;
        Map<Path, List<Edit>> per = new TreeMap<>();
        for (Edit e : edits) per.computeIfAbsent(e.file(), k -> new ArrayList<>()).add(e);
        for (var e : per.entrySet()) {
            StringBuilder sb = new StringBuilder(Files.readString(e.getKey()));
            e.getValue().sort(Comparator.comparingInt(Edit::pos).reversed());
            for (Edit x : e.getValue()) {
                if (!sb.substring(x.pos(), x.end()).equals("\"" + x.value() + "\"")) throw new IllegalStateException("unexpected text " + e.getKey() + "@" + x.pos());
                sb.replace(x.pos(), x.end(), "\"" + map.get(x.value()) + "\"");
            }
            Files.writeString(e.getKey(), sb.toString());
        }
        System.out.println("written " + per.size() + " file");
    }
}
