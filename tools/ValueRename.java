import com.sun.source.tree.*;
import com.sun.source.util.*;

import javax.tools.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

/**
 * I codici di stato scritti come stringhe nel Java: elencarli e rinominarli, con il compilatore
 * a dire dove sta ogni stringa letterale e dentro che cosa.
 *
 * Un valore come "attendi" puo' essere un codice (level = "attendi", "attendi".equals(x),
 * case "attendi" ->) o il nome di un segnaposto in Map.of("attendi", ...) per I18n.tr. Si
 * rinominano solo i primi: le stringhe dentro una chiamata Map.of, Map.entry o I18n.tr non si
 * toccano (sono della fase delle traduzioni), e nemmeno un intero file escluso (PathMigration:
 * li' "sistema" e' il nome della cartella VECCHIA, da migrare).
 *
 * Uso:  java ValueRename.java list   <classpath> <valori.txt>   elenca per contesto
 *       java ValueRename.java rename <classpath> <mappa.txt>    applica (vecchio nuovo)
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
        // rename: da fondo a cima per file, verificando il testo
        Map<Path, List<Hit>> per = new TreeMap<>();
        for (Hit h : hits) per.computeIfAbsent(h.file(), k -> new ArrayList<>()).add(h);
        int n = 0;
        for (var e : per.entrySet()) {
            StringBuilder sb = new StringBuilder(Files.readString(e.getKey()));
            List<Hit> hs = e.getValue();
            hs.sort(Comparator.comparingInt(Hit::pos).reversed());
            for (Hit h : hs) {
                String lit = sb.substring(h.pos(), h.end());
                if (!lit.equals("\"" + h.value() + "\"")) throw new IllegalStateException("testo inatteso " + e.getKey() + "@" + h.pos() + ": " + lit);
                sb.replace(h.pos(), h.end(), "\"" + map.get(h.value()) + "\"");
                n++;
            }
            Files.writeString(e.getKey(), sb.toString());
        }
        System.out.println("valori cambiati: " + n + " in " + per.size() + " file");
    }

    /** Dentro che cosa sta la stringa: decide se e' un codice o un nome di segnaposto. */
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
                        return "SKIP chiave JSON";
                    if (m.equals("equals") || m.equals("equalsIgnoreCase")) return "confronto";
                    if (m.equals("put")) return "valore JSON";
                    return "argomento di " + m;
                }
                if (mi.getMethodSelect() instanceof MemberSelectTree ms && ms.getExpression() == leaf
                        && (ms.getIdentifier().contentEquals("equals") || ms.getIdentifier().contentEquals("equalsIgnoreCase"))) return "confronto";
            }
            if (t instanceof CaseTree) return "case";
            if (t instanceof ReturnTree) return "return";
            if (t instanceof VariableTree || t instanceof AssignmentTree) return "assegnazione";
            if (t instanceof ConditionalExpressionTree) continue;
            if (t instanceof NewArrayTree) return "array";
            if (t instanceof BinaryTree) return "concatenazione";
            if (t instanceof NewClassTree) return "costruttore";
            if (t instanceof MethodTree || t instanceof ClassTree) break;
        }
        return "altro";
    }
}
