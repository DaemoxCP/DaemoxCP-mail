package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

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

    /*
     * La via di ritorno della reinstallazione completa dal menu ha un nome e una potatura sua.
     * Prima era "packages-before-...-reinstall" e contava fra le KEEP dei lavori sui pacchetti:
     * tre aggiornamenti dopo una reinstallazione la toglievano (reperto 162), e una prova lanciata
     * sul clone dopo tre reinstallazioni ne aveva tolta una vera. Adesso i lavori sui pacchetti non
     * la vedono, e lei pota solo le sue: e' la sola copia del server di prima (configurazioni,
     * caselle, database), e una reinstallazione si fa di rado.
     */
    static final String REINSTALL_PREFIX = "reinstall-before-";
    static final int REINSTALL_KEEP = 2;
    public static final java.util.regex.Pattern REINSTALL_OWN = java.util.regex.Pattern.compile(
            "^reinstall-before-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}$");

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
        return create(log, nameFor(kind, ZonedDateTime.now()));
    }

    /** Il nome della via di ritorno di una reinstallazione, con l'ora UTC. */
    static String reinstallName(ZonedDateTime when) {
        return REINSTALL_PREFIX + when.withZoneSameInstant(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss"));
    }

    /**
     * Lo spazio libero che la reinstallazione vuole prima di partire. Misurato sulla VM: con i
     * pacchetti gia' installati la reinstallazione ha scritto 54 MB netti (06/11/2026, reperto 170);
     * con gli undici pacchetti principali da scaricare e reinstallare, e la cache di pkg vuota, 358 MB,
     * di cui 81 di cache (07/11/2026, reperto 174). 1 GB e' quasi tre volte il caso peggiore misurato,
     * per i picchi durante l'estrazione e per la posta che intanto arriva. Un disco che si riempie a
     * meta' lascia la posta spenta peggio di una reinstallazione che non parte.
     */
    static long reinstallMinFree = 1L << 30;

    /**
     * Prima della reinstallazione, sui sistemi coi boot environment: se il pool ha meno di
     * reinstallMinFree libero, il motivo del rifiuto; altrimenti null, e il log dice quanto la via di
     * ritorno terra' occupato. Misurato (reperto 170): la reinstallazione svuota /var/vmail e ricrea
     * MySQL, ma i blocchi di prima non si liberano, li tiene lo snapshot della via di ritorno. Con 500 MB
     * di posta, 516 MB. Finche' la via di ritorno c'e', la posta nuova riempie il disco accanto a
     * quella vecchia.
     */
    public static String reinstallSpace(Consumer<String> log) {
        if (!run("bectl check", 30).success()) return null;
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        String avail = root.isEmpty() ? "" : run("zfs get -Hp -o value available " + root + " 2>/dev/null", 30).outputTrim();
        if (!avail.matches("[0-9]+")) return null;      // non si sa: non si ferma niente per questo
        long free = Long.parseLong(avail);
        long data = 0;
        for (String path : dataInside()) {
            String kb = run("du -sk " + path + " 2>/dev/null | cut -f1", 600).outputTrim();
            if (kb.matches("[0-9]+")) data += Long.parseLong(kb) * 1024;
        }
        if (free < reinstallMinFree)
            return I18n.tr("server.reinstall.noSpace", Map.of("free", mb(free), "need", mb(reinstallMinFree)));
        log.accept(I18n.tr("server.reinstall.wayBackSpace", Map.of("data", mb(data), "free", mb(free))));
        return null;
    }

    static String mb(long bytes) {
        return String.valueOf(Math.round(bytes / 1048576.0));
    }

    /**
     * Lo spazio che una via di ritorno tiene occupato davvero: i blocchi che ha solo lei, cioe' quelli
     * dello snapshot da cui e' nata (zfs «used» dello snapshot). Il «used» del boot environment, appena
     * creato, e' 0: bectl list e la scheda dicevano «0 MB» per una via di ritorno che ne teneva 516
     * (misurato, reperto 170). -1 se non si sa.
     */
    static long pinnedBytes(String name) {
        String root = run("zfs list -H -o name / 2>/dev/null", 30).outputTrim();
        String parent = root.contains("/") ? root.substring(0, root.lastIndexOf('/')) : "";
        if (parent.isEmpty()) return -1;
        String origin = run("zfs get -H -o value origin " + parent + "/" + name + " 2>/dev/null", 30).outputTrim();
        if (!origin.contains("@")) return -1;
        String used = run("zfs get -Hp -o value used " + origin + " 2>/dev/null", 30).outputTrim();
        return used.matches("[0-9]+") ? Long.parseLong(used) : -1;
    }

    /** La via di ritorno di reinstallazione piu' recente su questo sistema, o "" se non ce n'e'. */
    static String newestReinstallWayBack() {
        String newest = "";
        for (String line : run("bectl list -H 2>/dev/null | cut -f1", 60).outputTrim().split("\n")) {
            String n = line.trim();
            if (REINSTALL_OWN.matcher(n).matches() && n.compareTo(newest) > 0) newest = n;
        }
        return newest;
    }

    /** Prima della reinstallazione completa: come {@link #before}, col nome della reinstallazione. */
    public static Prepared beforeInstallation(Consumer<String> log) {
        return create(log, reinstallName(ZonedDateTime.now()));
    }

    private static Prepared create(Consumer<String> log, String name) {
        String inv = inventory();
        if (!run("bectl check", 30).success()) {
            log.accept(I18n.tr("server.um.x.wbUnsupported"));
            return new Prepared("", inv);
        }
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

    /**
     * Dopo la reinstallazione completa dal menu. A differenza dei lavori sui pacchetti, li' i
     * pacchetti uguali non dicono che niente e' cambiato: lo script ferma i servizi, cancella e
     * riscrive le configurazioni, svuota /var/vmail e ricrea le tabelle di MySQL anche quando non
     * installa niente di nuovo. Quindi il boot environment si toglie solo se lo script si e'
     * fermato PRIMA di cambiare qualcosa ({@code systemTouched} falso: non e' arrivato alla fase 1)
     * e i pacchetti sono uguali; altrimenti resta, si dice come tornarci, e si potano i piu' vecchi.
     */
    public static void afterInstallation(Consumer<String> log, Prepared p, boolean systemTouched) {
        if (p == null || p.name().isEmpty()) return;
        if (!systemTouched && p.inventory().equals(inventory()) && !p.inventory().isEmpty()) {
            String err = destroy(p.name());
            log.accept(err == null ? I18n.tr("server.reinstall.wayBackNotNeeded", Map.of("name", p.name()))
                                   : I18n.tr("server.um.x.wbPruneFailed", Map.of("name", p.name(), "err", err)));
            return;
        }
        log.accept(I18n.tr("server.reinstall.wayBackKept", Map.of("name", p.name())));
        prune(log, REINSTALL_OWN, REINSTALL_KEEP, "server.reinstall.wayBackPruned");
    }

    /** Toglie i boot environment dei pacchetti piu' vecchi, tenendo gli ultimi 'keep'. */
    static void prune(Consumer<String> log, int keep) {
        prune(log, OWN, keep, "server.um.x.wbPruned");
    }

    /** Toglie i piu' vecchi fra quelli del modello 'own', tenendo gli ultimi 'keep'. */
    static void prune(Consumer<String> log, java.util.regex.Pattern ownNames, int keep, String prunedKey) {
        List<String> own = new ArrayList<>();
        for (String line : run("bectl list -H 2>/dev/null", 60).outputTrim().split("\n")) {
            String[] f = line.split("\t");
            if (f.length < 2 || !ownNames.matcher(f[0].trim()).matches()) continue;
            // N = in uso adesso, R = al prossimo avvio, T = solo al prossimo avvio: mai toccarli.
            if (f[1].contains("N") || f[1].contains("R") || f[1].contains("T")) continue;
            own.add(f[0].trim());
        }
        java.util.Collections.sort(own);
        for (int i = 0; i < own.size() - keep; i++) {
            String err = destroy(own.get(i));
            log.accept(err == null ? I18n.tr(prunedKey, Map.of("name", own.get(i), "keep", String.valueOf(keep)))
                                   : I18n.tr("server.um.x.wbPruneFailed", Map.of("name", own.get(i), "err", err)));
        }
    }

    /**
     * Toglie un boot environment creato da questa classe, e lo snapshot da cui era nato se nessun
     * altro clone lo usa. null se tolto, altrimenti il motivo. Non usa "bectl destroy -o": dopo una
     * promozione lo snapshot d'origine puo' essere quello di un altro boot environment.
     */
    static String destroy(String name) {
        if (!OWN.matcher(name).matches() && !REINSTALL_OWN.matcher(name).matches())
            return "not a boot environment made before a package job or a reinstallation";
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
