package org.mail_panel.system;

import java.util.ArrayList;
import java.util.List;

/**
 * "Update all" (reperto 205): the steps the page sends are checked before any job starts. One step per package or
 * family, its head's name and the signature of the plan the confirmation showed; from 1 to 20 steps. What runs each
 * step is the guided update of a single package, unchanged: this test says only what may start.
 *
 * Usage (from the project root, after mvn package):
 *   javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/system/UpdateAllTest.java
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.UpdateAllTest
 */
public class UpdateAllTest {

    private static int failed = 0;

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    private static boolean starts(List<String> names, List<String> signatures) {
        return UpdateManager.updateAllProblem(names, signatures) == null;
    }

    public static void main(String[] args) {
        String sig = "0123456789abcdef";
        System.out.println("== What may start ==");
        check("the four steps of the real server: nginx, the PHP family, postfix-mysql, redis",
                starts(List.of("nginx", "php84", "postfix-mysql", "redis"), List.of(sig, sig, sig, sig)));
        check("one step", starts(List.of("nginx"), List.of(sig)));

        System.out.println("\n== What does not ==");
        check("no step", !starts(List.of(), List.of()));
        check("missing lists", !starts(null, List.of(sig)) && !starts(List.of("nginx"), null));
        check("a step without its signature", !starts(List.of("nginx", "redis"), List.of(sig)));
        check("a signature that is not one (15 digits, capitals, empty)", !starts(List.of("nginx"), List.of("0123456789abcde"))
                && !starts(List.of("nginx"), List.of("0123456789ABCDEF")) && !starts(List.of("nginx"), List.of("")));
        check("a name that is not a package's (a space, an option)", !starts(List.of("ngi nx"), List.of(sig))
                && !starts(List.of("-oProxy"), List.of(sig)));
        check("the same family twice: php84 and php84-ctype are one step, not two",
                !starts(List.of("php84", "php84-ctype"), List.of(sig, sig)));
        check("the same package twice", !starts(List.of("redis", "redis"), List.of(sig, sig)));
        List<String> many = new ArrayList<>(), sigs = new ArrayList<>();
        for (int i = 0; i < 21; i++) { many.add("p" + i); sigs.add(sig); }
        check("more than 20 steps", !starts(many, sigs));
        check("  20 do", starts(many.subList(0, 20), sigs.subList(0, 20)));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
