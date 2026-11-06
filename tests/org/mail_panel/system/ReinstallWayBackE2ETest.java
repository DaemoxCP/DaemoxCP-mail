package org.mail_panel.system;

import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * PackageWayBack.afterInstallation con bectl vero: quando la via di ritorno della reinstallazione
 * completa resta e quando si toglie.
 *
 *  - lo script si e' fermato prima della fase 1 e i pacchetti sono uguali: il boot environment si
 *    toglie, e con lui lo snapshot da cui era nato;
 *  - lo script e' arrivato alla fase 1: resta, e il messaggio dice come tornarci;
 *  - i pacchetti sono cambiati (anche senza fase 1): resta;
 *  - si chiama reinstall-before-<ora> e ha la sua potatura (ne restano REINSTALL_KEEP): tre
 *    reinstallazioni lasciano le ultime due, e la via di ritorno di un lavoro sui pacchetti non si
 *    tocca; la potatura dei lavori sui pacchetti, a sua volta, non tocca quelle della reinstallazione.
 * Alla fine non resta niente: gli stessi boot environment e gli stessi snapshot di prima.
 *
 * Crea e toglie boot environment veri: SOLO su un clone di prova, e si rifiuta di partire se ci sono
 * gia' vie di ritorno dei lavori sui pacchetti (la potatura le toglierebbe). Si accende con
 * -De2e.vm=yes, da root, dove bectl check riesce:
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReinstallWayBackE2ETest
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
            System.out.println("SALTATA: serve -De2e.vm=yes (un clone di prova sulla VM FreeBSD, da root).");
            System.exit(0);
        }
        if (!Shell.runShell(Duration.ofSeconds(30), "bectl check").success()) {
            System.out.println("FALLITA: bectl check non riesce, qui non ci sono boot environment.");
            System.exit(1);
        }
        I18n.setCurrent("en");
        List<String> beBefore = bootEnvironments();
        // La prova chiama afterInstallation, che pota le vie di ritorno piu' vecchie (ne tiene
        // PackageWayBack.KEEP). Con vie di ritorno vere gia' qui ne toglierebbe una: misurato sul
        // clone il 06/11/2026, la prova lanciata dopo tre reinstallazioni vere ha tolto la piu'
        // vecchia. Quindi parte solo dove non ce ne sono.
        List<String> own = new ArrayList<>();
        for (String n : beBefore)
            if (PackageWayBack.OWN.matcher(n).matches() || PackageWayBack.REINSTALL_OWN.matcher(n).matches()) own.add(n);
        if (!own.isEmpty()) {
            System.out.println("FERMATA: qui ci sono gia' vie di ritorno dei lavori sui pacchetti " + own
                    + ", e la prova ne poterebbe qualcuna. Toglierle (o usare un clone senza) e rilanciare.");
            System.exit(2);
        }
        String snapBefore = snapshots();
        List<String> made = new ArrayList<>();
        try {
            System.out.println("== Lo script si ferma prima della fase 1, pacchetti uguali ==");
            List<String> log = new ArrayList<>();
            PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            check("creato prima dell'installazione, col nome della reinstallazione: " + p.name(), bootEnvironments().contains(p.name())
                    && p.name().matches("reinstall-before-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}"));
            PackageWayBack.afterInstallation(log::add, p, false);
            check("tolto alla fine", !bootEnvironments().contains(p.name()));
            check("e lo snapshot da cui era nato", snapshots().equals(snapBefore));
            check("il messaggio dice che non serviva", String.join("\n", log).contains("not needed: removed"));

            System.out.println("\n== Lo script arriva alla fase 1 ==");
            log.clear();
            p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            PackageWayBack.afterInstallation(log::add, p, true);
            check("resta", bootEnvironments().contains(p.name()));
            check("e il messaggio dice come tornarci", String.join("\n", log).contains("bectl activate " + p.name()));
            String origin = "";
            org.json.JSONArray list = UpdateManager.bootEnvironments().optJSONArray("environments");
            for (int k = 0; list != null && k < list.length(); k++)
                if (p.name().equals(list.getJSONObject(k).optString("name"))) origin = list.getJSONObject(k).optString("origin");
            check("la scheda dei boot environment lo presenta come la via di ritorno di una reinstallazione (" + origin + ")",
                    origin.contains("complete reinstallation"));
            check("toglierlo a mano lascia tutto come prima", PackageWayBack.destroy(p.name()) == null
                    && bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));

            System.out.println("\n== Pacchetti cambiati, anche senza fase 1 ==");
            log.clear();
            p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            PackageWayBack.afterInstallation(log::add, new PackageWayBack.Prepared(p.name(), "un altro inventario"), false);
            check("resta", bootEnvironments().contains(p.name()));
            check("toglierlo lascia tutto come prima", PackageWayBack.destroy(p.name()) == null
                    && bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));

            System.out.println("\n== Tre reinstallazioni e un lavoro sui pacchetti: potature separate ==");
            log.clear();
            PackageWayBack.Prepared job = PackageWayBack.before(log::add, "e2e-job");
            made.add(job.name());
            List<String> three = new ArrayList<>();
            for (int k = 0; k < 3; k++) {
                sleepOverSecond();      // il nome ha i secondi
                PackageWayBack.Prepared r = PackageWayBack.beforeInstallation(log::add);
                made.add(r.name());
                three.add(r.name());
                PackageWayBack.afterInstallation(log::add, r, true);
            }
            List<String> now = bootEnvironments();
            check("delle tre reinstallazioni restano le ultime " + PackageWayBack.REINSTALL_KEEP,
                    !now.contains(three.get(0)) && now.contains(three.get(1)) && now.contains(three.get(2)));
            check("e la potatura lo dice", String.join("\n", log).contains("older way back of a reinstallation " + three.get(0)));
            check("la via di ritorno del lavoro sui pacchetti non si tocca", now.contains(job.name()));
            log.clear();
            PackageWayBack.prune(log::add, 0);      // un lavoro sui pacchetti che pota tutti i suoi
            now = bootEnvironments();
            check("la potatura dei lavori sui pacchetti toglie i suoi", !now.contains(job.name()));
            check("e non quelli della reinstallazione", now.contains(three.get(1)) && now.contains(three.get(2)));
            for (String n : List.of(three.get(1), three.get(2))) PackageWayBack.destroy(n);
            check("tolti a mano: tutto come prima", bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));

            System.out.println("\n== Lo spazio (reperto 170) ==");
            long saved = PackageWayBack.reinstallMinFree;
            try {
                PackageWayBack.reinstallMinFree = Long.MAX_VALUE;
                log.clear();
                String refused = PackageWayBack.reinstallSpace(log::add);
                check("con poco spazio libero la reinstallazione non parte, e lo dice", refused != null && refused.contains("MB free"));
            } finally {
                PackageWayBack.reinstallMinFree = saved;
            }
            log.clear();
            check("con spazio a sufficienza parte", PackageWayBack.reinstallSpace(log::add) == null);
            check("e dice quanto la via di ritorno terra' occupato", String.join("\n", log).contains("The way back keeps the mail and the database"));
            Path probe = Path.of("/var/vmail/e2e-space-probe");
            sh("dd if=/dev/urandom of=" + probe + " bs=1m count=50 2>/dev/null");
            p = PackageWayBack.beforeInstallation(log::add);
            made.add(p.name());
            sh("rm -f " + probe);       // come la reinstallazione che svuota /var/vmail
            // ZFS conta lo spazio di uno snapshot quando chiude la transazione: letto subito dopo la
            // cancellazione dava 0 (misurato). Si forza la chiusura e si aspetta fino a 30 secondi.
            long pinned = -1;
            for (int k = 0; k < 15 && pinned < 45L * 1048576; k++) {
                sh("zpool sync 2>/dev/null; sleep 2");
                pinned = PackageWayBack.pinnedBytes(p.name());
            }
            check("i 50 MB cancellati restano occupati dalla via di ritorno (" + PackageWayBack.mb(pinned) + " MB)", pinned >= 45L * 1048576);
            String explain = "";
            org.json.JSONArray list2 = UpdateManager.bootEnvironments().optJSONArray("environments");
            for (int k = 0; list2 != null && k < list2.length(); k++)
                if (p.name().equals(list2.getJSONObject(k).optString("name"))) explain = list2.getJSONObject(k).optString("explanation");
            check("e la scheda lo dice: " + explain.replaceAll(".*(It keeps [0-9]+ MB).*", "$1"), explain.matches(".*It keeps ([4-9][0-9]|[0-9]{3,}) MB taken.*"));
            check("toglierla lascia tutto come prima", PackageWayBack.destroy(p.name()) == null
                    && bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));
        } finally {
            for (String n : made) if (bootEnvironments().contains(n)) PackageWayBack.destroy(n);
        }
        check("alla fine: gli stessi boot environment e snapshot di prima", bootEnvironments().equals(beBefore) && snapshots().equals(snapBefore));
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
