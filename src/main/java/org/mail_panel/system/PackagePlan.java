package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Il piano ESATTO di un aggiornamento di pacchetti, e se una vulnerabilita' ha davvero una
 * versione corretta.
 *
 * Due domande a cui il pannello rispondeva solo a meta'.
 *
 * 1. "Se aggiorno X, cosa cambia?" Il preflight leggeva dal catalogo "X 1.2 -> 1.3" e basta.
 *    Ma pkg, per aggiornare X, puo' aggiornare dipendenze, installarne di nuove, reinstallarne
 *    o rimuoverne: la riga di X e' una delle righe di un piano che nessuno mostrava. E per un
 *    pacchetto PROTETTO il piano non si poteva nemmeno chiedere, perche' pkg upgrade -n i
 *    protetti li salta.
 *
 *    Qui il piano si chiede a pkg su una COPIA del suo database, nella quale si tolgono le
 *    stesse protezioni che l'aggiornamento vero togliera'. La risposta e' quella che pkg
 *    darebbe davvero: ogni pacchetto, da quale versione a quale, e se la versione di arrivo e'
 *    ancora vulnerabile. Il database vero non viene toccato.
 *
 * 2. "La patch c'e' o no?" pkg audit dice "vulnerabile" e basta. Ma VuXML, il database da cui
 *    legge, per ogni problema dice QUALI versioni sono vulnerabili (per esempio "< 1.30.5,3"),
 *    cioe' da quale versione in poi il problema e' corretto. Messa accanto alla versione che il
 *    catalogo offre diventa una risposta esatta: si corregge aggiornando; oppure la fix
 *    esiste ma il tuo ramo non ce l'ha ancora; oppure una versione corretta non esiste.
 *
 * I formati letti qui sono quelli del sorgente di pkg (src/utils.c, src/audit.c,
 * src/version.c), non quelli ricordati: una riga interpretata male qui vuol dire promettere
 * un aggiornamento diverso da quello che avverra'.
 */
public final class PackagePlan {

    private PackagePlan() {}

    // ===================== leggere il piano di pkg =====================

    /** Le intestazioni che pkg stampa per ogni tipo di cambiamento, e il nome che usiamo qui. */
    private static final String[][] SECTIONS = {
        {"Installed packages to be UPGRADED:",    "upgrade"},
        {"Installed packages to be DOWNGRADED:",  "downgrade"},
        {"New packages to be INSTALLED:",         "install"},
        {"Installed packages to be REINSTALLED:", "reinstall"},
        {"Installed packages to be REMOVED:",     "remove"},
        {"Installed packages LOCKED:",            "locked"},
        {"New packages to be FETCHED:",           "download"},
        {"New groups to be UPGRADED:",            "group"},
        {"New groups to be INSTALLED:",           "group"},
    };

    /** I totali che pkg scrive in fondo al piano: il controllo incrociato del parser. */
    private static final String[][] TOTALS = {
        {"Number of packages to be upgraded: ",    "upgrade"},
        {"Number of packages to be downgraded: ",  "downgrade"},
        {"Number of packages to be installed: ",   "install"},
        {"Number of packages to be reinstalled: ", "reinstall"},
        {"Number of packages to be removed: ",     "remove"},
        {"Number of packages to be fetched: ",     "download"},
    };

    private static final String VULNERABLE = " (vulnerable!)";

    private static final Pattern FROM_TO = Pattern.compile("^(\\S+): (\\S+) -> (\\S+)(?: \\[([^\\]]+)\\])?$");
    private static final Pattern REPO_VERSION_NAME = Pattern.compile("^(\\S+): (\\S+)(?: \\[([^\\]]+)\\])?$");
    private static final Pattern REINSTALL = Pattern.compile("^(\\S+)-([^\\s-]+)(?: \\[([^\\]]+)\\])?(?: \\((.*)\\))?$");
    private static final Pattern REMOVES = Pattern.compile("^(\\S+): (\\S+)(?: \\((.*)\\))?$");
    private static final Pattern PROTECTED_IN_PLAN = Pattern.compile(
            "^Package (\\S+)-([^\\s-]+) is locked and may not be (\\S+)(?: to version (\\S+))?");
    private static final Pattern PROTECTED_EVENT = Pattern.compile("^(\\S+)-([^\\s-]+) is locked and may not be modified$");

    /**
     * Il piano come lo stampa {@code pkg upgrade -n}, letto sezione per sezione.
     *
     * Funzione pura: riceve il testo, non lancia niente, cosi' si prova con uscite vere. Se una
     * riga dentro una sezione non si lascia leggere, o i conti non tornano con i totali che pkg
     * stampa da solo, il piano esce con "measured" falso: un piano letto a meta' e presentato
     * come completo e' peggio di nessun piano.
     */
    static JSONObject readPlan(String output) {
        JSONArray changes = new JSONArray(), lockedPackages = new JSONArray();
        JSONArray errors = new JSONArray(), warnings = new JSONArray(), unreadable = new JSONArray();
        Map<String, Integer> counted = new HashMap<>(), declared = new HashMap<>();
        Set<String> alreadyLocked = new LinkedHashSet<>();
        boolean updated = false, hasConflicts = false;
        String section = null;

        for (String raw : (output == null ? "" : output).split("\n")) {
            String line = raw.replace("\r", "");
            String t = line.trim();

            String fresh = null;
            for (String[] s : SECTIONS) if (t.equals(s[0])) fresh = s[1];
            if (fresh != null) { section = fresh; continue; }

            if (section != null && line.startsWith("\t") && !t.isEmpty()) {
                if (!readEntry(section, t, changes, lockedPackages, alreadyLocked)) unreadable.put(t);
                else if (!"locked".equals(section) && !"group".equals(section))
                    counted.merge(section, 1, Integer::sum);
                continue;
            }
            section = null;   // una riga vuota o non rientrata chiude la sezione
            if (t.isEmpty()) continue;

            Matcher ev = PROTECTED_EVENT.matcher(t);
            if (ev.find()) {
                if (alreadyLocked.add(ev.group(1)))
                    lockedPackages.put(new JSONObject().put("name", ev.group(1)).put("version", ev.group(2))
                            .put("action", "modified").put("destination", ""));
                continue;
            }
            boolean total = false;
            for (String[] tt : TOTALS) {
                if (t.startsWith(tt[0])) {
                    try { declared.put(tt[1], Integer.parseInt(t.substring(tt[0].length()).trim())); }
                    catch (NumberFormatException e) { unreadable.put(t); }
                    total = true;
                }
            }
            if (total) continue;
            if (t.equals("Your packages are up to date.")) { updated = true; continue; }
            if (t.startsWith("Conflicts with the existing packages")) { hasConflicts = true; continue; }
            if (t.startsWith("pkg:")) {
                if (t.toLowerCase().contains("warning")) warnings.put(t); else errors.put(t);
            }
            // Il resto (dimensioni, "Checking for upgrades", "Updating ... repository catalogue")
            // non cambia il piano.
        }

        JSONObject r = new JSONObject().put("changes", changes).put("lockedPackages", lockedPackages)
                .put("pkgErrors", errors).put("pkgWarnings", warnings)
                .put("nothingToDo", updated || (changes.isEmpty() && lockedPackages.isEmpty() && errors.isEmpty()))
                .put("hasConflicts", hasConflicts);

        if (unreadable.length() > 0)
            return r.put("measured", false).put("unreadable", unreadable)
                    .put("error", I18n.tr("server.plan.unreadableLines", java.util.Map.of("n", String.valueOf(unreadable.length()), "first", String.valueOf(unreadable.getString(0)))));
        // pkg stampa un totale per ogni tipo che compare: i due conti devono coincidere, in
        // entrambe le direzioni. Un tipo contato senza totale e' un totale che non ho letto.
        Set<String> kinds = new LinkedHashSet<>(counted.keySet());
        kinds.addAll(declared.keySet());
        for (String type : kinds) {
            int a = counted.getOrDefault(type, 0), b = declared.getOrDefault(type, -1);
            if (a != b)
                return r.put("measured", false)
                        .put("error", I18n.tr("server.plan.countMismatch", java.util.Map.of("b", String.valueOf(b < 0 ? I18n.tr("server.plan.noTotal") : String.valueOf(b)), "kind", String.valueOf(type), "a", String.valueOf(a))));
        }
        return r.put("measured", true);
    }

    /** Una riga rientrata di una sezione. false se non ha la forma che la sezione prevede. */
    private static boolean readEntry(String section, String t, JSONArray changes, JSONArray lockedPackages, Set<String> alreadyLocked) {
        boolean vulnerable = t.endsWith(VULNERABLE);
        String s = vulnerable ? t.substring(0, t.length() - VULNERABLE.length()) : t;
        Matcher m;
        switch (section) {
            case "upgrade", "downgrade" -> {
                m = FROM_TO.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), m.group(2), m.group(3), "", m.group(4), vulnerable));
            }
            case "install" -> {
                m = REPO_VERSION_NAME.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), "", m.group(2), "", m.group(3), vulnerable));
            }
            case "reinstall" -> {
                m = REINSTALL.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), m.group(2), m.group(2), m.group(4), m.group(3), vulnerable));
            }
            case "remove" -> {
                m = REMOVES.matcher(s);
                if (!m.find()) return false;
                changes.put(entry(section, m.group(1), m.group(2), "", m.group(3), null, false));
            }
            case "locked" -> {
                m = PROTECTED_IN_PLAN.matcher(s);
                if (!m.find()) return false;
                if (alreadyLocked.add(m.group(1)))
                    lockedPackages.put(new JSONObject().put("name", m.group(1)).put("version", m.group(2))
                            .put("action", m.group(3)).put("destination", m.group(4) == null ? "" : m.group(4)));
            }
            case "download", "group" -> { /* non cambiano pacchetti installati */ }
            default -> { return false; }
        }
        return true;
    }

    private static JSONObject entry(String type, String name, String from, String to, String reason,
                                   String repo, boolean vulnerable) {
        return new JSONObject().put("type", type).put("name", name).put("from", from).put("to", to)
                .put("reason", reason == null ? "" : reason).put("repo", repo == null ? "" : repo)
                .put("stillVulnerable", vulnerable);
    }

    /**
     * L'fingerprint di un piano: cio' che e' stato approvato e cio' che si esegue devono coincidere.
     *
     * Dentro ci sono le protezioni da togliere e ogni cambiamento con le sue versioni, in ordine
     * fisso. Fra la lettura del piano e il click puo' passare un aggiornamento del catalogo: con
     * l'fingerprint, il pannello se ne accorge e si ferma invece di eseguire un piano diverso da
     * quello che e' stato letto.
     */
    static String signature(JSONObject plan) {
        List<String> lines = new ArrayList<>();
        JSONArray sb = plan.optJSONArray("unlockedPackages");
        for (int i = 0; sb != null && i < sb.length(); i++) lines.add("unlock " + sb.getString(i));
        JSONArray c = plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            lines.add(x.optString("type") + " " + x.optString("name") + " " + x.optString("from") + " " + x.optString("to"));
        }
        java.util.Collections.sort(lines);
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * L'fingerprint dei soli CAMBIAMENTI del piano, senza le protezioni da togliere.
     *
     * Serve per confrontare due piani calcolati in condizioni diverse: quello approvato,
     * dove il pacchetto era ancora protetto e andava sbloccato, e quello ricalcolato dopo lo
     * sblocco vero, dove non c'e' piu' niente da sbloccare. La firma intera differirebbe per
     * quella sola ragione; questa risponde alla domanda che conta, cioe' "pkg farebbe le
     * stesse cose?".
     */
    public static String changesSignature(JSONObject plan) {
        List<String> lines = new ArrayList<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            lines.add(x.optString("type") + " " + x.optString("name") + " " + x.optString("from") + " " + x.optString("to"));
        }
        java.util.Collections.sort(lines);
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /** I cambiamenti del piano in righe leggibili, per mostrare due piani a confronto. */
    public static List<String> changesInLines(JSONObject plan) {
        List<String> lines = new ArrayList<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String a = x.optString("to");
            lines.add(typeName(x.optString("type")) + " " + x.optString("name")
                    + (x.optString("from").isEmpty() ? "" : " " + x.optString("from"))
                    + (a.isEmpty() || a.equals(x.optString("from")) ? "" : " -> " + a));
        }
        java.util.Collections.sort(lines);
        return lines;
    }

    // ===================== chiedere il piano a pkg =====================

    /** Solo nomi di pacchetto plausibili: finiscono in una riga di comando. */
    /** Il tipo di cambiamento ("aggiorna", "rimuove"...) detto nella lingua di chi legge. */
    public static String typeName(String type) {
        return switch (type == null ? "" : type) {
            case "upgrade" -> I18n.tr("up.tUpgrade");
            case "install" -> I18n.tr("up.tInstall");
            case "reinstall" -> I18n.tr("up.tReinstall");
            case "remove" -> I18n.tr("up.tRemove");
            case "downgrade" -> I18n.tr("up.tDowngrade");
            default -> String.valueOf(type);
        };
    }

    static boolean isValidName(String n) {
        return n != null && n.matches("[A-Za-z0-9._+-]{1,64}");
    }

    private static String sh(String cmd, int seconds) {
        return Shell.runShell(Duration.ofSeconds(seconds), cmd).outputTrim();
    }

    /** La cartella del database di pkg: la si chiede a pkg invece di supporla. */
    static String dbFolder() {
        String d = sh("pkg config PKG_DBDIR 2>/dev/null", 30);
        return d.matches("/[A-Za-z0-9._/-]{1,200}") ? d : "/var/db/pkg";
    }

    /**
     * Cosa farebbe {@code pkg upgrade} su 'pacchetti' (tutti, se l'elenco e' vuoto) dopo aver
     * tolto la protezione a 'daSbloccare'.
     *
     * Se non c'e' niente da sbloccare, la simulazione gira sul database vero: {@code -n} non
     * scrive niente. Se c'e', gira su una copia completa della cartella di pkg (catalogo
     * compreso), fatta in /var/tmp e cancellata subito dopo: e' l'unico modo di sapere cosa
     * farebbe pkg su un pacchetto protetto senza togliergli davvero la protezione.
     *
     * {@code -U}: il catalogo non si riscarica, si usa quello che c'e'. Il pannello lo aggiorna
     * prima di mostrare lo stato; qui conta che la simulazione e l'esecuzione usino lo STESSO.
     */
    public static JSONObject simulate(List<String> toUnlock, List<String> packages) {
        for (String n : toUnlock) if (!isValidName(n)) return failed(I18n.tr("server.plan.badName", java.util.Map.of("n", String.valueOf(n))));
        for (String n : packages) if (!isValidName(n)) return failed(I18n.tr("server.plan.badName", java.util.Map.of("n", String.valueOf(n))));
        String list = packages.isEmpty() ? "" : " " + String.join(" ", packages);
        String prefix = "pkg";
        String copy = null;
        try {
            if (!toUnlock.isEmpty()) {
                String db = dbFolder();
                long kb = number(sh("du -sk " + db + " 2>/dev/null | cut -f1", 120));
                long free = number(sh("df -k /var/tmp 2>/dev/null | tail -1 | awk '{print $4}'", 30));
                if (kb <= 0) return failed(I18n.tr("server.plan.cannotMeasure", java.util.Map.of("db", String.valueOf(db))));
                if (free < kb * 2)
                    return failed(I18n.tr("server.plan.noSpace", java.util.Map.of("mb", String.valueOf(kb / 1024), "free", String.valueOf(free / 1024))));
                copy = sh("mktemp -d /var/tmp/panel-simulation.XXXXXX 2>/dev/null", 30);
                if (!copy.matches("/var/tmp/panel-simulation\\.[A-Za-z0-9]{6,}")) {
                    String oddFolder = copy;
                    copy = null;
                    return failed(I18n.tr("server.plan.mktempFailed", java.util.Map.of("d", String.valueOf(oddFolder))));
                }
                Shell.Result cp = Shell.runShell(Duration.ofSeconds(600), "cp -Rp " + db + "/. " + copy + "/ 2>&1");
                if (!cp.success()) return failed(I18n.tr("server.plan.copyFailed", java.util.Map.of("out", String.valueOf(cp.outputTrim()))));
                prefix = "pkg -o PKG_DBDIR=" + copy;
                for (String n : toUnlock) {
                    Shell.Result u = Shell.runShell(Duration.ofSeconds(60), prefix + " unlock -y " + n + " 2>&1");
                    if (!u.success()) return failed(I18n.tr("server.plan.unlockFailed", java.util.Map.of("n", String.valueOf(n), "out", String.valueOf(u.outputTrim()))));
                }
            }
            Shell.Result r = Shell.runShell(Duration.ofSeconds(600), prefix + " upgrade -n -U" + list + " 2>&1");
            JSONObject plan = readPlan(r.output());
            return plan.put("success", true).put("code", r.exitCode()).put("output", r.outputTrim())
                    .put("onBackup", copy != null)
                    .put("command", "pkg upgrade -n -U" + list);
        } finally {
            // La copia se ne va sempre. Il percorso e' quello creato da mktemp e verificato sopra.
            if (copy != null) Shell.runShell(Duration.ofSeconds(300), "rm -rf " + copy);
        }
    }

    /**
     * Il piano per aggiornare 'pacchetti' togliendo solo le protezioni necessarie.
     *
     * Si parte sbloccando, nella copia, i pacchetti richiesti che sono protetti. Se pkg trova
     * sulla sua strada altri pacchetti protetti — una dipendenza che deve cambiare anche lei —
     * li nomina: si aggiungono all'elenco e si rifa' il conto, ma solo se la regola del chiamante
     * permette di sbloccarli. Quelli che non si possono sbloccare restano come impedimento, con
     * il loro nome e il motivo: e' esattamente quello che serve sapere prima di premere.
     *
     * @param protetti          i pacchetti protetti adesso
     * @param reasonNotToUnlock riceve il pacchetto protetto che pkg ha nominato (nome, versione
     *                          e, se pkg la dice, la versione a cui andrebbe); restituisce null se
     *                          si puo' sbloccare, altrimenti il perche'
     */
    public static JSONObject planFor(List<String> packages, Set<String> protectedNames,
                                      Function<JSONObject, String> reasonNotToUnlock) {
        return planFor(packages, protectedNames, reasonNotToUnlock, n -> null);
    }

    /**
     * @param gemelloInstallato riceve il nome di un pacchetto che il piano INSTALLEREBBE e
     *                          restituisce il nome di un pacchetto GIA' installato della
     *                          stessa famiglia, o null. Serve a riconoscere quando pkg sta
     *                          girando attorno a un blocco: vedi il ciclo di planWith.
     */
    public static JSONObject planFor(List<String> packages, Set<String> protectedNames,
                                      Function<JSONObject, String> reasonNotToUnlock,
                                      Function<String, String> installedTwin) {
        LinkedHashSet<String> unlock = new LinkedHashSet<>();
        for (String p : packages) if (protectedNames.contains(p)) unlock.add(p);
        return planWith(packages, unlock, protectedNames, reasonNotToUnlock, installedTwin, true);
    }

    /**
     * Il piano della manutenzione completa: tutto cio' che pkg aggiornerebbe, con 'daSbloccare'
     * sbloccati. Qui un pacchetto protetto che pkg nomina e che non si puo' sbloccare non e' un
     * impedimento: e' uno di quelli trattenuti apposta, pkg lo salta e aggiorna il resto. Resta
     * nel piano, con il suo motivo, perche' chi legge sappia cosa NON verra' aggiornato.
     */
    public static JSONObject fullPlan(Set<String> toUnlock, Set<String> protectedNames,
                                         Function<JSONObject, String> reasonNotToUnlock) {
        return fullPlan(toUnlock, protectedNames, reasonNotToUnlock, n -> null);
    }

    public static JSONObject fullPlan(Set<String> toUnlock, Set<String> protectedNames,
                                         Function<JSONObject, String> reasonNotToUnlock,
                                         Function<String, String> installedTwin) {
        return planWith(List.of(), new LinkedHashSet<>(toUnlock), protectedNames, reasonNotToUnlock,
                installedTwin, false);
    }

    private static JSONObject planWith(List<String> packages, LinkedHashSet<String> unlock, Set<String> protectedNames,
                                       Function<JSONObject, String> reasonNotToUnlock,
                                       Function<String, String> installedTwin, boolean blockersBlock) {
        JSONObject plan = null;
        JSONArray blockers = new JSONArray();
        JSONArray unlockedFamily = new JSONArray();
        for (int round = 0; round < 6; round++) {
            plan = simulate(new ArrayList<>(unlock), packages);
            if (!plan.optBoolean("success") || !plan.optBoolean("measured")) break;
            blockers = new JSONArray();
            boolean added = false;
            JSONArray bl = plan.getJSONArray("lockedPackages");
            for (int i = 0; i < bl.length(); i++) {
                JSONObject block = bl.getJSONObject(i);
                String n = block.getString("name");
                if (unlock.contains(n)) continue;
                String no = !protectedNames.contains(n)
                        ? I18n.tr("server.plan.lockedUnknown")
                        : reasonNotToUnlock.apply(block);
                if (no != null) { blockers.put(new JSONObject().put("name", n).put("reason", no)); continue; }
                unlock.add(n);
                added = true;
            }
            if (familyAddition(plan, unlock, protectedNames, installedTwin, blockers, unlockedFamily))
                added = true;
            if (!added) break;
        }
        plan.put("unlockedPackages", new JSONArray(new ArrayList<>(unlock))).put("blockers", blockers)
             .put("familyUnlocked", unlockedFamily);

        // I pacchetti chiesti che il piano NON cambia: pkg li lascerebbe dove sono.
        JSONArray stopped = new JSONArray();
        JSONArray changes = plan.optJSONArray("changes");
        for (String p : packages) {
            boolean change = false;
            for (int i = 0; changes != null && i < changes.length(); i++)
                if (p.equals(changes.getJSONObject(i).optString("name"))) change = true;
            if (!change) stopped.put(p);
        }
        plan.put("unchangedPackages", stopped);

        // pkg aggiorna prima se stesso. In un aggiornamento vero, se il catalogo ha un pkg piu'
        // recente, pkg installa quello, si rilancia e poi fa il resto; con -n questo passo lo
        // salta, quindi la simulazione non lo mostra. Un piano "esatto" che tace un pacchetto
        // che cambiera' non lo e': si aggiunge in testa, entra nell'fingerprint e viene verificato.
        JSONObject before = plan.optBoolean("measured") ? pkgToUpdate() : null;
        if (before != null && changes != null) {
            boolean already = false;
            for (int i = 0; i < changes.length(); i++) if ("pkg".equals(changes.getJSONObject(i).optString("name"))) already = true;
            if (!already) {
                JSONArray withPkg = new JSONArray().put(entry("upgrade", "pkg", before.getString("from"), before.getString("to"),
                        I18n.tr("server.plan.pkgFirst"), "", false));
                for (int i = 0; i < changes.length(); i++) withPkg.put(changes.get(i));
                plan.put("changes", withPkg);
                changes = withPkg;
            }
        }

        boolean runnable = plan.optBoolean("success") && plan.optBoolean("measured")
                && (!blockersBlock || (blockers.isEmpty() && plan.optJSONArray("lockedPackages") != null
                                             && plan.getJSONArray("lockedPackages").length() == 0))
                && plan.getJSONArray("pkgErrors").length() == 0 && !plan.optBoolean("hasConflicts")
                && changes != null && changes.length() > 0
                // Se nessuno dei pacchetti chiesti cambia, non c'e' niente da eseguire: nemmeno
                // se nel piano c'e' pkg che aggiornerebbe se stesso.
                && (packages.isEmpty() || stopped.length() < packages.size());
        return plan.put("runnable", runnable).put("signature", plan.optBoolean("measured") ? signature(plan) : "");
    }

    /**
     * Un "installa" che e' della stessa famiglia di un pacchetto GIA' installato non e'
     * un'aggiunta: e' pkg che gira attorno a un blocco.
     *
     * Per pkg un pacchetto protetto non e' "da non cambiare": e' **non disponibile**. Se
     * serve una libreria che quel pacchetto fornisce, il solver cerca un altro fornitore — e
     * lo installa, anche se si contende i file con quello che c'e' gia'.
     *
     * Misurato sulla VM FreeBSD 15.1 il 23/10/2026. Con mysql84-client protetto, aggiornare
     * postfix-mysql produceva un piano con "installa mysql97-client 9.7.2"; i due forniscono
     * la stessa libmysqlclient.so.24 e si contendono /usr/local/bin/comp_err, quindi
     * l'esecuzione moriva a meta' con «mysql97-client conflicts with mysql84-client
     * (installs files into the same place)», uscita 3. Sbloccando ANCHE mysql84-client, nella
     * stessa simulazione mysql97-client **spariisce dal piano**: pkg torna a usare quello che
     * c'e'. Il piano diceva il vero su cio' che pkg avrebbe fatto; era pkg a essere stato
     * reso cieco dal blocco.
     *
     * Si sblocca solo quando il catalogo ha la STESSA versione installata, cioe' quando
     * sbloccare non puo' cambiare niente: lo scopo e' far vedere a pkg cio' che c'e' gia',
     * non aggiornarlo. Se il catalogo ne ha una piu' recente, sbloccare sarebbe un
     * aggiornamento che nessuno ha chiesto (e per i client MySQL l'avvertenza dice di
     * aspettare): allora e' un impedimento, col suo motivo. E se il gemello non e' nemmeno
     * protetto, il blocco non c'entra: e' un conflitto vero fra due membri della famiglia.
     *
     * @return true se ha allargato l'elenco da sbloccare, cioe' se il piano va rifatto
     */
    private static boolean familyAddition(JSONObject plan, LinkedHashSet<String> unlock,
                                            Set<String> protectedNames, Function<String, String> installedTwin,
                                            JSONArray blockers, JSONArray unlockedFamily) {
        boolean added = false;
        JSONArray changes = plan.optJSONArray("changes");
        for (int i = 0; changes != null && i < changes.length(); i++) {
            JSONObject c = changes.getJSONObject(i);
            if (!"install".equals(c.optString("type"))) continue;
            String newName = c.optString("name");
            String twin = installedTwin == null ? null : installedTwin.apply(newName);
            if (twin == null || twin.equals(newName) || unlock.contains(twin)
                    || !isValidName(twin)) continue;
            if (alreadyBlocked(blockers, twin)) continue;
            if (!protectedNames.contains(twin)) {
                blockers.put(new JSONObject().put("name", newName)
                        .put("reason", I18n.tr("server.plan.familyConflict",
                                java.util.Map.of("newer", String.valueOf(newName), "twin", String.valueOf(twin)))));
                continue;
            }
            String installed = sh("pkg query %v " + twin + " 2>/dev/null", 20).trim();
            String catalog = "";
            for (String line : sh("pkg rquery -U %v " + twin + " 2>/dev/null", 30).split("\n")) {
                String x = line.trim();
                if (validVersion(x)) { catalog = x; break; }
            }
            if (!validVersion(installed) || !installed.equals(catalog)) {
                blockers.put(new JSONObject().put("name", twin)
                        .put("reason", I18n.tr("server.plan.familyLockedNewer",
                                java.util.Map.of("newer", String.valueOf(newName), "twin", String.valueOf(twin),
                                        "installed", String.valueOf(installed.isEmpty() ? "?" : installed),
                                        "catalog", String.valueOf(catalog.isEmpty() ? "?" : catalog)))));
                continue;
            }
            unlock.add(twin);
            unlockedFamily.put(new JSONObject().put("installed", twin).put("wouldInstall", newName)
                    .put("version", installed));
            added = true;
        }
        return added;
    }

    private static boolean alreadyBlocked(JSONArray blockers, String name) {
        for (int i = 0; i < blockers.length(); i++)
            if (name.equals(blockers.getJSONObject(i).optString("name"))) return true;
        return false;
    }

    /** Il pkg installato e quello del catalogo, se il catalogo ne ha uno piu' recente; altrimenti null. */
    static JSONObject pkgToUpdate() {
        String from = sh("pkg query %v pkg 2>/dev/null", 30), to = "";
        for (String line : sh("pkg rquery -U %v pkg 2>/dev/null", 60).split("\n"))
            if (validVersion(line.trim())) { to = line.trim(); break; }
        if (!validVersion(from) || !validVersion(to)) return null;
        try {
            return pkgComparison().compare(to, from) > 0 ? new JSONObject().put("from", from).put("to", to) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Le versioni installate senza lo stato di blocco: {@code name -> versione}. */
    public static Map<String, String> versionsOnly(Map<String, String[]> installed) {
        Map<String, String> r = new java.util.TreeMap<>();
        if (installed != null)
            for (Map.Entry<String, String[]> e : installed.entrySet())
                if (e.getValue() != null && e.getValue().length > 0) r.put(e.getKey(), e.getValue()[0]);
        return r;
    }

    /**
     * Che cosa e' cambiato DAVVERO, messo a confronto con il piano firmato.
     *
     * {@link #verifyOutcome} scorre le righe del PIANO: vede un pacchetto del piano che non
     * e' arrivato dove doveva, e non puo' vedere un pacchetto cambiato che nel piano non
     * c'era. Il 18/10/2026, sulla VM, e' successo: il piano firmato (465385a9d669def8) aveva
     * dieci cambi e nessuna rimozione; durante l'esecuzione pkg ha trovato un conflitto
     * (lmdb0 contro lmdb su /usr/local/bin/mdb_copy), ha rifatto il calcolo e ha RIMOSSO
     * lmdb. Il confronto ha controllato i suoi dieci, li ha trovati tutti "ok" e ha concluso
     * "verifica superata". La rimozione stava nel log di pkg e in nessun verdetto.
     *
     * Qui si guarda dall'altra direzione: l'inventario dei pacchetti installati prima e
     * dopo. Ogni differenza che il piano non spiega e' una divergenza. La firma del piano
     * esiste per garantire che venga eseguito quello che e' stato mostrato, e su un server
     * di posta una rimozione non prevista e' precisamente il caso che deve intercettare.
     *
     * Una reinstallazione non lascia traccia nell'inventario (stessa versione) e quindi non
     * puo' comparire qui: quel caso lo copre {@link #verifyOutcome}. I due controlli sono
     * complementari e servono entrambi.
     *
     * Funzione pura: riceve i due inventari e il piano, cosi' si prova con uscite vere.
     *
     * @return una voce per divergenza: {@code name}, {@code happened}
     *         ("removed", "installed", "changed"), {@code from}, {@code to}, {@code why}
     */
    public static JSONArray divergences(Map<String, String> before, Map<String, String> after,
                                       JSONObject plan) {
        Map<String, String> a = before == null ? Map.of() : before;
        Map<String, String> b = after == null ? Map.of() : after;

        // Le righe del piano per nome. Un nome puo' comparire una volta sola: se comparisse
        // due volte il piano sarebbe ambiguo, e si tiene la prima perche' e' quella mostrata.
        Map<String, JSONObject> planned = new HashMap<>();
        JSONArray c = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            planned.putIfAbsent(x.optString("name"), x);
        }

        Set<String> names = new java.util.TreeSet<>(a.keySet());
        names.addAll(b.keySet());
        JSONArray outside = new JSONArray();
        for (String name : names) {
            String versionA = a.get(name), versionB = b.get(name);
            String happened = versionA == null ? "installed" : versionB == null ? "removed"
                            : versionA.equals(versionB) ? null : "changed";
            if (happened == null) continue;   // niente e' cambiato per questo pacchetto

            JSONObject p = planned.get(name);
            if (p == null) {
                outside.put(divergenceEntry(name, happened, versionA, versionB,
                        I18n.tr("server.plan.d.notInPlan")));
                continue;
            }
            // Nel piano c'era: il tipo e la versione di arrivo devono combaciare.
            String type = p.optString("type"), expected = p.optString("to");
            boolean matches = switch (happened) {
                case "removed" -> "remove".equals(type);
                case "installed" -> "install".equals(type) && expected.equals(versionB);
                default -> ("upgrade".equals(type) || "downgrade".equals(type)) && expected.equals(versionB);
            };
            if (matches) continue;
            outside.put(divergenceEntry(name, happened, versionA, versionB,
                    I18n.tr("server.plan.d.planSaid", java.util.Map.of(
                            "kind", String.valueOf(typeName(type)),
                            "expected", String.valueOf(expected.isEmpty() ? I18n.tr("server.plan.removed") : expected)))));
        }
        return outside;
    }

    private static JSONObject divergenceEntry(String name, String happened, String from, String a, String why) {
        return new JSONObject().put("name", name).put("happened", happened)
                .put("from", from == null ? "" : from).put("to", a == null ? "" : a)
                .put("why", why);
    }

    /** Una divergenza detta in una riga, nella lingua di chi legge. */
    public static String divergenceInLine(JSONObject d) {
        String name = d.optString("name");
        String text = switch (d.optString("happened")) {
            case "removed" -> I18n.tr("server.plan.d.removed", java.util.Map.of("name", name, "version", String.valueOf(d.optString("from"))));
            case "installed" -> I18n.tr("server.plan.d.installed", java.util.Map.of("name", name, "version", String.valueOf(d.optString("to"))));
            default -> I18n.tr("server.plan.d.changed", java.util.Map.of("name", name,
                    "from", String.valueOf(d.optString("from")), "to", String.valueOf(d.optString("to"))));
        };
        return text + " — " + d.optString("why");
    }

    /**
     * Dopo l'aggiornamento vero: ogni pacchetto del piano e' dove il piano diceva?
     * Una riga per cambiamento, con cio' che era atteso e cio' che c'e'.
     */
    public static JSONArray verifyOutcome(JSONObject plan) {
        JSONArray outcome = new JSONArray();
        JSONArray c = plan.optJSONArray("changes");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String name = x.optString("name");
            if (!isValidName(name)) continue;
            String now = sh("pkg query %v " + name + " 2>/dev/null", 30);
            String expected = "remove".equals(x.optString("type")) ? "" : x.optString("to");
            outcome.put(new JSONObject().put("name", name).put("type", x.optString("type"))
                    .put("expected", expected.isEmpty() ? I18n.tr("server.plan.removed") : expected)
                    .put("found", now.isEmpty() ? I18n.tr("server.plan.notInstalled") : now)
                    .put("ok", expected.equals(now)));
        }
        return outcome;
    }

    // ===================== la fix c'e'? =====================

    /** Confronto di due versioni, con le regole di pkg. Negativo, zero o positivo. */
    public interface VersionComparator { int compare(String a, String b); }

    /** Solo versioni plausibili: finiscono in una riga di comando. */
    static boolean validVersion(String v) {
        return v != null && v.matches("[A-Za-z0-9._,+~]{1,64}");
    }

    /**
     * Il confronto lo fa pkg stesso ({@code pkg version -t}), non una copia delle sue regole:
     * epoch dopo la virgola, revisione del port dopo il trattino basso, "p", "a", "b", "rc".
     * Riscriverle qui vorrebbe dire sbagliarle sul caso che conta. Le risposte si ricordano:
     * lo stesso confronto non si chiede due volte.
     */
    public static VersionComparator pkgComparison() {
        Map<String, Integer> already = new HashMap<>();
        return (a, b) -> {
            if (!validVersion(a) || !validVersion(b))
                throw new IllegalArgumentException("version not comparable: " + a + " / " + b);
            return already.computeIfAbsent(a + " " + b, k -> {
                String o = sh("pkg version -t '" + a + "' '" + b + "'", 15);
                return switch (o) {
                    case "<" -> -1;
                    case "=" -> 0;
                    case ">" -> 1;
                    default -> throw new IllegalStateException("pkg version -t answered \"" + o + "\"");
                };
            });
        };
    }

    /** Un estremo di un intervallo di VuXML, come lo scrive pkg: operatore e versione. */
    record Bound(String op, String version) {}

    private static final Pattern BOUND = Pattern.compile("^(<=|>=|<|>|=)\\s*(\\S+)$");

    /** "&gt;= 1.25.0 : &lt; 1.30.5,3" diventa due estremi; "&lt; 1.30.5,3" uno solo. */
    static List<Bound> bounds(String interval) {
        List<Bound> r = new ArrayList<>();
        for (String part : interval.split(":")) {
            Matcher m = BOUND.matcher(part.trim());
            if (m.find()) r.add(new Bound(m.group(1), m.group(2)));
        }
        return r;
    }

    static boolean inside(String v, List<Bound> es, VersionComparator c) {
        if (es.isEmpty()) return false;
        for (Bound e : es) {
            int x = c.compare(v, e.version());
            boolean ok = switch (e.op()) {
                case "<" -> x < 0;
                case "<=" -> x <= 0;
                case ">" -> x > 0;
                case ">=" -> x >= 0;
                case "=" -> x == 0;
                default -> false;
            };
            if (!ok) return false;
        }
        return true;
    }

    private static boolean insideAny(String v, JSONArray ranges, VersionComparator c) {
        for (int i = 0; ranges != null && i < ranges.length(); i++)
            if (inside(v, bounds(ranges.getString(i)), c)) return true;
        return false;
    }

    /**
     * {@code pkg audit -Rjson} ridotto a cio' che serve: per ogni pacchetto la versione e i
     * problemi, ognuno con gli ranges di versioni vulnerabili.
     *
     * Attenzione alla forma dell'opzione: e' {@code -Rjson}, attaccato. Con {@code -R json}
     * pkg prende "json" per il nome di un pacchetto e produce un altro formato.
     */
    static JSONObject readAudit(String json) {
        JSONObject outside = new JSONObject();
        int g = json == null ? -1 : json.indexOf('{');
        if (g < 0) return outside;
        JSONObject top = new JSONObject(json.substring(g));
        JSONObject pk = top.optJSONObject("packages");
        if (pk == null) return outside;
        for (String name : pk.keySet()) {
            JSONObject p = pk.getJSONObject(name);
            JSONArray issues = new JSONArray();
            JSONArray is = p.optJSONArray("issues");
            for (int i = 0; is != null && i < is.length(); i++) {
                JSONObject x = is.getJSONObject(i);
                issues.put(new JSONObject()
                        .put("ranges", x.optJSONArray("Affected versions") == null ? new JSONArray()
                                : x.getJSONArray("Affected versions"))
                        .put("description", x.optString("description", ""))
                        .put("cve", x.optJSONArray("cve") == null ? new JSONArray() : x.getJSONArray("cve"))
                        .put("url", x.optString("url", "")));
            }
            outside.put(name, new JSONObject().put("version", p.optString("version", "")).put("issues", issues));
        }
        return outside;
    }

    /**
     * La risposta a "la fix c'e'?" per un pacchetto: la versione installata, quella che
     * il catalogo offre, e gli ranges di VuXML di ogni problema.
     *
     * Verdetti, dal migliore al peggiore:
     *  - "fixed-by-upgrade": il catalogo ha una versione piu' recente che VuXML non
     *    considera vulnerabile per nessuno dei problemi;
     *  - "upgrade-not-enough": il catalogo ha una versione piu' recente, ma per almeno un
     *    problema e' ancora vulnerabile;
     *  - "fix-outside-branch": il catalogo non va oltre, ma VuXML indica da quale
     *    versione il problema e' corretto — esiste, non e' ancora nel tuo ramo;
     *  - "fix-not-stated": vulnerabile fino a una versione compresa, senza dire la prima
     *    corretta;
     *  - "no-fix": VuXML non mette un limite superiore, cioe' nessuna versione
     *    pubblicata e' corretta;
     *  - "unknown": un intervallo non si lascia leggere o il confronto non ha risposto.
     */
    static JSONObject assessFix(String installed, String catalog, JSONArray issues, VersionComparator c) {
        JSONObject r = new JSONObject().put("installedVersion", installed).put("catalog", catalog == null ? "" : catalog);
        try {
            boolean newerCatalog = catalog != null && !catalog.isEmpty() && c.compare(catalog, installed) > 0;
            JSONArray details = new JSONArray();
            String firstFixed = null;          // la piu' alta fra le prime versioni corrette
            String upTo = null;                  // un "<=": vulnerabile fino a questa compresa
            boolean withoutLimit = false, unreadable = false, onlyThis = false;
            List<String> stillOpenInCatalog = new ArrayList<>();
            for (int i = 0; issues != null && i < issues.length(); i++) {
                JSONObject p = issues.getJSONObject(i);
                JSONArray ranges = p.optJSONArray("ranges");
                List<Bound> its = null;
                for (int k = 0; ranges != null && k < ranges.length(); k++) {
                    List<Bound> es = bounds(ranges.getString(k));
                    if (inside(installed, es, c)) { its = es; break; }
                }
                JSONObject d = new JSONObject().put("description", p.optString("description"))
                        .put("cve", p.optJSONArray("cve")).put("url", p.optString("url"))
                        .put("ranges", ranges);
                if (its == null) {
                    unreadable = true;
                    d.put("type", "unknown");
                } else {
                    Bound upperBound = null;
                    boolean exact = false;
                    for (Bound e : its) {
                        if (e.op().equals("<") || e.op().equals("<=")) upperBound = e;
                        if (e.op().equals("=")) exact = true;
                    }
                    if (exact) {
                        onlyThis = true;
                        d.put("type", "this-version-only");
                    } else if (upperBound == null) {
                        withoutLimit = true;
                        d.put("type", "no-upper-bound");
                    } else if (upperBound.op().equals("<")) {
                        d.put("type", "fixed-in").put("firstFixed", upperBound.version());
                        if (firstFixed == null || c.compare(upperBound.version(), firstFixed) > 0) firstFixed = upperBound.version();
                    } else {
                        d.put("type", "vulnerable-up-to").put("upTo", upperBound.version());
                        upTo = upperBound.version();
                    }
                }
                if (newerCatalog && insideAny(catalog, ranges, c)) {
                    stillOpenInCatalog.add(p.optString("description"));
                    d.put("openInCatalog", true);
                }
                details.put(d);
            }
            r.put("issues", details);
            if (firstFixed != null) r.put("firstFixed", firstFixed);

            String verdict, explain;
            if (unreadable) {
                verdict = "unknown";
                explain = I18n.tr("server.plan.v.unknownRange");
            } else if (newerCatalog && stillOpenInCatalog.isEmpty()) {
                verdict = "fixed-by-upgrade";
                explain = I18n.tr("server.plan.v.fixedByUpgrade", java.util.Map.of("v", String.valueOf(catalog)));
            } else if (newerCatalog) {
                verdict = "upgrade-not-enough";
                explain = I18n.tr("server.plan.v.upgradeNotEnough", java.util.Map.of("v", String.valueOf(catalog), "list", String.valueOf(String.join("; ", stillOpenInCatalog))))
                        + (firstFixed != null ? " " + I18n.tr("server.plan.v.fixedFrom", java.util.Map.of("v", String.valueOf(firstFixed))) : "");
            } else if (withoutLimit) {
                verdict = "no-fix";
                explain = I18n.tr("server.plan.v.noFix");
            } else if (upTo != null && firstFixed == null) {
                verdict = "fix-not-stated";
                explain = I18n.tr("server.plan.v.fixNotStated", java.util.Map.of("upTo", String.valueOf(upTo), "cat", String.valueOf(emptyIf(catalog, installed))));
            } else if (onlyThis && firstFixed == null) {
                verdict = "fix-outside-branch";
                explain = I18n.tr("server.plan.v.onlyThis", java.util.Map.of("v", String.valueOf(installed)));
            } else if (firstFixed != null) {
                verdict = "fix-outside-branch";
                explain = I18n.tr("server.plan.v.fixOutsideBranch", java.util.Map.of("fixed", String.valueOf(firstFixed), "cat", String.valueOf(emptyIf(catalog, installed))));
            } else {
                verdict = "unknown";
                explain = I18n.tr("server.plan.v.noComparable");
            }
            return r.put("verdict", verdict).put("explanation", explain);
        } catch (RuntimeException e) {
            return r.put("verdict", "unknown").put("explanation", I18n.tr("server.plan.v.compareFailed", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    private static String emptyIf(String catalog, String installed) {
        return catalog == null || catalog.isEmpty() ? installed + " " + I18n.tr("server.plan.noNewer") : catalog;
    }

    /**
     * Per ogni pacchetto vulnerabile: se e dove esiste la fix. Legge il database delle
     * vulnerabilita' gia' scaricato (chi chiama decide se riscaricarlo prima) e il catalogo.
     */
    public static JSONObject fixes() {
        Shell.Result a = Shell.runShell(Duration.ofSeconds(180), "pkg audit -Rjson 2>/dev/null");
        // pkg audit esce con 0 senza vulnerabilita' e con un codice diverso quando ne trova:
        // conta se il JSON c'e', non il codice.
        String out = a.output();
        if (out == null || out.indexOf('{') < 0)
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.plan.auditUnreadable", java.util.Map.of("c", String.valueOf(a.exitCode()))));
        JSONObject vuln;
        try { vuln = readAudit(out); }
        catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.plan.auditJson", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
        VersionComparator c = pkgComparison();
        JSONObject per = new JSONObject();
        for (String name : vuln.keySet()) {
            if (!isValidName(name)) continue;
            JSONObject v = vuln.getJSONObject(name);
            String catalog = "";
            for (String line : sh("pkg rquery -U %v " + name + " 2>/dev/null", 60).split("\n")) {
                String x = line.trim();
                if (!validVersion(x)) continue;
                try { if (catalog.isEmpty() || c.compare(x, catalog) > 0) catalog = x; }
                catch (RuntimeException ignore) { /* resta quella che c'era */ }
            }
            per.put(name, assessFix(v.getString("version"), catalog, v.getJSONArray("issues"), c));
        }
        return new JSONObject().put("success", true).put("packages", per);
    }

    // ===================== utilita' =====================

    // ===================== il quadro dei pacchetti =====================

    private static final Pattern TO_UPDATE = Pattern.compile("^(\\S+)-([^\\s-]+)\\s+<\\s.*\\(remote has ([^)]+)\\)\\s*$");

    /**
     * Le righe "<" di {@code pkg version -U -vRL=}: nome -> versione del catalogo. Le altre
     * ("?" fuori catalogo, ">" piu' nuovo del catalogo, "!" non confrontabile) non sono
     * aggiornamenti disponibili e restano fuori.
     */
    public static Map<String, String> toUpdate(String output) {
        Map<String, String> r = new java.util.TreeMap<>();
        for (String line : (output == null ? "" : output).split("\n")) {
            Matcher m = TO_UPDATE.matcher(line.trim());
            if (m.find() && isValidName(m.group(1)) && validVersion(m.group(3))) r.put(m.group(1), m.group(3));
        }
        return r;
    }

    /** Da {@code pkg query '%n\t%v\t%k'}: nome -> {versione, "1" se bloccato}. */
    public static Map<String, String[]> installed(String output) {
        Map<String, String[]> r = new java.util.TreeMap<>();
        for (String line : (output == null ? "" : output).split("\n")) {
            String[] c = line.split("\t");
            if (c.length == 3 && isValidName(c[0].trim()) && validVersion(c[1].trim()))
                r.put(c[0].trim(), new String[]{c[1].trim(), c[2].trim()});
        }
        return r;
    }

    /** I pacchetti installati, letti adesso. */
    public static Map<String, String[]> installed() {
        return installed(Shell.runShell(Duration.ofSeconds(60), "pkg query '%n\t%v\t%k' 2>/dev/null").output());
    }

    /** Gli aggiornamenti disponibili nel catalogo gia' scaricato: -U, nessuna rete. */
    public static Shell.Result readToUpdate() {
        return Shell.runShell(Duration.ofSeconds(180), "pkg version -U -vRL= 2>&1");
    }

    private static JSONObject failed(String error) {
        return new JSONObject().put("success", false).put("measured", false).put("error", error)
                .put("changes", new JSONArray()).put("lockedPackages", new JSONArray()).put("pkgErrors", new JSONArray());
    }

    private static long number(String s) {
        try { return Long.parseLong(s.trim().split("\\s+")[0]); } catch (Exception e) { return -1; }
    }
}
