package org.mail_panel.system;

import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * La via di ritorno di un lavoro sui pacchetti: un boot environment creato PRIMA di toccarli.
 *
 * Misurato sulla VM il 06/11/2026 (reperto 147): dopo un aggiornamento guidato non c'era nessun
 * boot environment nuovo, e il pacchetto di prima non c'era da nessuna parte. Un aggiornamento
 * che rompe un servizio si poteva solo inseguire in avanti. Il salto di release il suo boot
 * environment lo faceva gia' (e senza non partiva): adesso lo fanno tutti i lavori sui pacchetti.
 *
 * Le regole:
 *  - su un sistema con i boot environment (bectl check riesce) il lavoro NON parte se la
 *    creazione fallisce: e' la stessa scelta del salto di release;
 *  - su un sistema senza (UFS), si va avanti come prima, e il log lo dice;
 *  - se alla fine nessun pacchetto e' cambiato (un lavoro rifiutato, un piano vuoto), il boot
 *    environment appena creato si toglie: altrimenti i rifiuti spingerebbero fuori le vie di
 *    ritorno vere;
 *  - se qualcosa e' cambiato, si tengono gli ultimi KEEP creati prima di un lavoro sui pacchetti
 *    e si tolgono i piu' vecchi. Mai quello in uso ne' quello del prossimo avvio. Lo snapshot da
 *    cui era nato si toglie solo se nessun altro clone lo usa.
 *
 * Il prefisso e' diverso da quello del salto di release ("before-"): l'ultima via di ritorno del
 * salto (lastPanelBootEnvironment) non deve diventare quella di un aggiornamento dei pacchetti.
 */
public final class PackageWayBack {

    private PackageWayBack() {}

    private static final Logger LOGGER = Logger.getLogger(PackageWayBack.class.getName());

    static final String PREFIX = "packages-before-";
    static final int KEEP = 3;

    /** I nomi che questa classe crea e quindi puo' togliere: niente altro passa. */
    static final java.util.regex.Pattern OWN = java.util.regex.Pattern.compile(
            "^packages-before-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}-[a-z0-9-]{1,40}$");

    /** I dati che, se stanno dentro il boot environment, tornano indietro con lui. */
    static final List<String> DATA = List.of("/var/vmail", "/var/db/mysql");

    /** Cio' che si sa dopo before(): il nome creato ("" se nessuno) e l'impronta dei pacchetti. */
    public record Prepared(String name, String inventory) {}

    private static Shell.Result run(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd);
    }

    static String inventory() {
        return run("pkg query %n-%v 2>/dev/null | sort | sha256", 120).outputTrim();
    }

    /** Il nome di un nuovo boot environment per il lavoro 'kind', con l'ora UTC: in ordine alfabetico e' in ordine di tempo. */
    static String nameFor(String kind, ZonedDateTime when) {
        String k = (kind == null ? "job" : kind.toLowerCase(java.util.Locale.ROOT)).replaceAll("[^a-z0-9-]", "-");
        if (k.isEmpty()) k = "job";
        if (k.length() > 40) k = k.substring(0, 40);
        return PREFIX + when.withZoneSameInstant(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss")) + "-" + k;
    }

    /**
     * Prima del lavoro. Crea il boot environment e scrive come si torna indietro. Lancia
     * IllegalStateException se il sistema ha i boot environment ma la creazione non riesce: chi
     * chiama non deve toccare i pacchetti.
     */
    public static Prepared before(Consumer<String> log, String kind) {
        String inv = inventory();
        if (!run("bectl check", 30).success()) {
            log.accept(I18n.tr("server.um.x.wbUnsupported"));
            return new Prepared("", inv);
        }
        String name = nameFor(kind, ZonedDateTime.now());
        Shell.Result c = run("bectl create " + name + " 2>&1", 300);
        boolean listed = run("bectl list -H 2>/dev/null | cut -f1", 60).outputTrim().lines().anyMatch(name::equals);
        if (!c.success() || !listed) {
            String err = c.outputTrim().isEmpty() ? "exit " + c.exitCode() : c.outputTrim();
            throw new IllegalStateException(I18n.tr("server.um.x.wbFailed", Map.of("name", name, "err", err)));
        }
        log.accept(I18n.tr("server.um.x.wbCreated", Map.of("name", name)));
        log.accept(I18n.tr("server.um.x.wbHowBack", Map.of("name", name)));
        List<String> inside = dataInside();
        if (!inside.isEmpty())
            log.accept(I18n.tr("server.um.x.wbDataInside", Map.of("paths", String.join(", ", inside))));
        LOGGER.info("Way back created before a package job: " + name);
        return new Prepared(name, inv);
    }

    /**
     * Dopo il lavoro, comunque sia finito. Se nessun pacchetto e' cambiato, il boot environment
     * appena creato non serve e si toglie; altrimenti si potano i piu' vecchi.
     */
    public static void after(Consumer<String> log, Prepared p) {
        if (p == null || p.name().isEmpty()) return;
        if (p.inventory().equals(inventory()) && !p.inventory().isEmpty()) {
            String err = destroy(p.name());
            log.accept(err == null ? I18n.tr("server.um.x.wbNotNeeded", Map.of("name", p.name()))
                                   : I18n.tr("server.um.x.wbPruneFailed", Map.of("name", p.name(), "err", err)));
            return;
        }
        prune(log, KEEP);
    }

    /** Toglie i boot environment dei pacchetti piu' vecchi, tenendo gli ultimi 'keep'. */
    static void prune(Consumer<String> log, int keep) {
        List<String> own = new ArrayList<>();
        for (String line : run("bectl list -H 2>/dev/null", 60).outputTrim().split("\n")) {
            String[] f = line.split("\t");
            if (f.length < 2 || !OWN.matcher(f[0].trim()).matches()) continue;
            // N = in uso adesso, R = al prossimo avvio, T = solo al prossimo avvio: mai toccarli.
            if (f[1].contains("N") || f[1].contains("R") || f[1].contains("T")) continue;
            own.add(f[0].trim());
        }
        java.util.Collections.sort(own);
        for (int i = 0; i < own.size() - keep; i++) {
            String err = destroy(own.get(i));
            log.accept(err == null ? I18n.tr("server.um.x.wbPruned", Map.of("name", own.get(i), "keep", String.valueOf(keep)))
                                   : I18n.tr("server.um.x.wbPruneFailed", Map.of("name", own.get(i), "err", err)));
        }
    }

    /**
     * Toglie un boot environment creato da questa classe, e lo snapshot da cui era nato se nessun
     * altro clone lo usa. null se tolto, altrimenti il motivo. Non usa "bectl destroy -o": dopo una
     * promozione lo snapshot d'origine puo' essere quello di un altro boot environment.
     */
    static String destroy(String name) {
        if (!OWN.matcher(name).matches()) return "not a boot environment made before a package job";
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        String parent = root.contains("/") ? root.substring(0, root.lastIndexOf('/')) : "";
        String origin = parent.isEmpty() ? "" : run("zfs get -H -o value origin " + parent + "/" + name + " 2>/dev/null", 30).outputTrim();
        Shell.Result d = run("bectl destroy -F " + name + " 2>&1", 300);
        if (!d.success()) return d.outputTrim().isEmpty() ? "exit " + d.exitCode() : d.outputTrim();
        if (origin.matches("[A-Za-z0-9_./:-]+@[A-Za-z0-9_.:-]+")) {
            String clones = run("zfs get -H -o value clones " + origin + " 2>/dev/null", 30).outputTrim();
            if (clones.isEmpty() || "-".equals(clones)) run("zfs destroy " + origin + " 2>&1", 120);
        }
        return null;
    }

    /** Quali dei DATA stanno dentro il boot environment in uso (cioe' tornerebbero indietro con lui). */
    static List<String> dataInside() {
        List<String> r = new ArrayList<>();
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        if (root.isEmpty()) return r;
        for (String path : DATA) {
            if (!new java.io.File(path).isDirectory()) continue;
            String ds = run("zfs list -H -o name " + path + " 2>/dev/null", 30).outputTrim();
            if (ds.equals(root) || ds.startsWith(root + "/")) r.add(path);
        }
        return r;
    }
}
