package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * PackageWayBack.afterInstallation with real bectl: when the way back of the full reinstallation
 * stays and when it is removed.
 *
 *  - the script stopped before phase 1 and the packages are the same: the boot environment is
 *    removed, and with it the snapshot it was born from;
 *  - the script reached phase 1: it stays, and the message says how to go back to it;
 *  - the packages changed (even without phase 1): it stays;
 *  - it is called reinstall-before-<time> and has its own pruning (REINSTALL_KEEP stay): three
 *    reinstallations leave the last two, and the way back of a package job is not touched; the
 *    pruning of the package jobs, in turn, does not touch those of the reinstallation.
 * At the end nothing is left: the same boot environments and the same snapshots as before.
 *
 * It creates and removes real boot environments: ONLY on a test clone, and it refuses to start if
 * there are already ways back of package jobs (the pruning would remove them). It is switched on
 * with -De2e.vm=yes, as root, where bectl check succeeds:
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ReinstallWayBackE2ETest
 */
public class ReinstallWayBackE2ETest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(120), cmd).outputTrim();
    }

    static List<String> bootEnvironments() {
        List<String> r = new ArrayList<>();
        for (String l : sh("bectl list -H 2>/dev/null | cut -f1").split("\n")) if (!l.isBlank()) r.add(l.trim());
        return r;
    }

    static String snapshots() {
        return sh("zfs list -H -t snapshot -o name 2>/dev/null | sort");
    }

    static void sleepOverSecond() {
        try { Thread.sleep(1100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    public static void main(String[] args) {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes (a test clone on the FreeBSD VM, as root).");
            System.exit(0);
        }
        if (!Shell.runShell(Duration.ofSeconds(30), "bectl check").success()) {
            System.out.println("FAILED: bectl check does not succeed, there are no boot environments here.");
            System.exit(1);
        }
        I18n.setCurrent("en");
        List<String> beBefore = bootEnvironments();
        // The test calls afterInstallation, which prunes the older ways back (it keeps
        // PackageWayBack.KEEP). With real ways back already here it would remove one: measured on
        // the clone on 06/11/2026, the test started after three real reinstallations removed the
        // oldest. So it starts only where there are none.
        List<String> own = new ArrayList<>();
        for (String n : beBefore)
            if (PackageWayBack.OWN.matcher(n).matches() || PackageWayBack.REINSTALL_OWN.matcher(n).matches()) own.add(n);
        if (!own.isEmpty()) {
            System.out.println("STOPPED: there are already ways back of package jobs here " + own
                    + ", and the test would prune some. Remove them (or use a clone without them) and start again.");
            System.exit(2);
        }
        String snapBefore = snapshots();
        List<String> made = new ArrayList<>();
        try {
            System.out.println("== The script stops before phase 1, packages the same ==");
            List<String> log = new ArrayList<>();
            PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            check("created before the installation, with the reinstallation's name: " + p.name(), bootEnvironments().contains(p.name())
                    && p.name().matches("reinstall-before-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}"));
            PackageWayBack.afterInstallation(log::add, p, false);
            check("removed at the end", !bootEnvironments().contains(p.name()));
            check("and the snapshot it was born from", snapshots().equals(snapBefore));
            check("the message says it was not needed", String.join("\n", log).contains("not needed: removed"));

            System.out.println("\n== The script reaches phase 1 ==");
            log.clear();
            p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            PackageWayBack.afterInstallation(log::add, p, true);
            check("it stays", bootEnvironments().contains(p.name()));
            check("and the message says how to go back to it", String.join("\n", log).contains("bectl activate " + p.name()));
            String origin = "";
            org.json.JSONArray list = UpdateManager.bootEnvironments().optJSONArray("environments");
            for (int k = 0; list != null && k < list.length(); k++)
                if (p.name().equals(list.getJSONObject(k).optString("name"))) origin = list.getJSONObject(k).optString("origin");
            check("the boot environments card presents it as the way back of a reinstallation (" + origin + ")",
                    origin.contains("complete reinstallation"));
            check("removing it by hand leaves everything as before", PackageWayBack.destroy(p.name()) == null
                    && bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));

            System.out.println("\n== Packages changed, even without phase 1 ==");
            log.clear();
            p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            PackageWayBack.afterInstallation(log::add, new PackageWayBack.Prepared(p.name(), "another inventory"), false);
            check("it stays", bootEnvironments().contains(p.name()));
            check("removing it leaves everything as before", PackageWayBack.destroy(p.name()) == null
                    && bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));

            System.out.println("\n== Three reinstallations and a package job: separate prunings ==");
            log.clear();
            PackageWayBack.Prepared job = PackageWayBack.before(log::add, "e2e-job");
            made.add(job.name());
            List<String> three = new ArrayList<>();
            for (int k = 0; k < 3; k++) {
                sleepOverSecond();      // the name has the seconds
                PackageWayBack.Prepared r = PackageWayBack.beforeInstallation(log::add);
                made.add(r.name());
                three.add(r.name());
                PackageWayBack.afterInstallation(log::add, r, true);
            }
            List<String> now = bootEnvironments();
            check("of the three reinstallations the last " + PackageWayBack.REINSTALL_KEEP + " stay",
                    !now.contains(three.get(0)) && now.contains(three.get(1)) && now.contains(three.get(2)));
            check("and the pruning says so", String.join("\n", log).contains("older way back of a reinstallation " + three.get(0)));
            check("the way back of the package job is not touched", now.contains(job.name()));
            log.clear();
            PackageWayBack.prune(log::add, 0);      // a package job that prunes all of its own
            now = bootEnvironments();
            check("the pruning of the package jobs removes its own", !now.contains(job.name()));
            check("and not those of the reinstallation", now.contains(three.get(1)) && now.contains(three.get(2)));
            for (String n : List.of(three.get(1), three.get(2))) PackageWayBack.destroy(n);
            check("removed by hand: everything as before", bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));

            System.out.println("\n== The space (reperto 170) ==");
            long saved = PackageWayBack.reinstallMinFree;
            try {
                PackageWayBack.reinstallMinFree = Long.MAX_VALUE;
                log.clear();
                String refused = PackageWayBack.reinstallSpace(log::add);
                check("with little free space the reinstallation does not start, and says so", refused != null && refused.contains("MB free"));
            } finally {
                PackageWayBack.reinstallMinFree = saved;
            }
            log.clear();
            check("with enough space it starts", PackageWayBack.reinstallSpace(log::add) == null);
            check("and it says how much the way back will keep taken", String.join("\n", log).contains("The way back keeps the mail and the database"));
            Path probe = Path.of("/var/vmail/e2e-space-probe");
            sh("dd if=/dev/urandom of=" + probe + " bs=1m count=50 2>/dev/null");
            p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            sh("rm -f " + probe);       // like the reinstallation that empties /var/vmail
            // ZFS counts a snapshot's space when it closes the transaction: read right after the
            // deletion it gave 0 (measured). The close is forced and it waits up to 30 seconds.
            long pinned = -1;
            for (int k = 0; k < 15 && pinned < 45L * 1048576; k++) {
                sh("zpool sync 2>/dev/null; sleep 2");
                pinned = PackageWayBack.pinnedBytes(p.name());
            }
            check("the 50 MB deleted stay taken by the way back (" + PackageWayBack.mb(pinned) + " MB)", pinned >= 45L * 1048576);
            String explain = "";
            org.json.JSONArray list2 = UpdateManager.bootEnvironments().optJSONArray("environments");
            for (int k = 0; list2 != null && k < list2.length(); k++)
                if (p.name().equals(list2.getJSONObject(k).optString("name"))) explain = list2.getJSONObject(k).optString("explanation");
            check("and the card says so: " + explain.replaceAll(".*(It keeps [0-9]+ MB).*", "$1"), explain.matches(".*It keeps ([4-9][0-9]|[0-9]{3,}) MB taken.*"));
            check("removing it leaves everything as before", PackageWayBack.destroy(p.name()) == null
                    && bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));
        } finally {
            for (String n : made) if (bootEnvironments().contains(n)) PackageWayBack.destroy(n);
        }
        check("at the end: the same boot environments and snapshots as before", bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
