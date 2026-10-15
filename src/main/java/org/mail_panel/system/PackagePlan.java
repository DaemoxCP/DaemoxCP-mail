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
 *    catalogo offre diventa una risposta esatta: si corregge aggiornando; oppure la correzione
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
    private static final String[][] SEZIONI = {
        {"Installed packages to be UPGRADED:",    "aggiorna"},
        {"Installed packages to be DOWNGRADED:",  "retrocede"},
        {"New packages to be INSTALLED:",         "installa"},
        {"Installed packages to be REINSTALLED:", "reinstalla"},
        {"Installed packages to be REMOVED:",     "rimuove"},
        {"Installed packages LOCKED:",            "protetto"},
        {"New packages to be FETCHED:",           "scarica"},
        {"New groups to be UPGRADED:",            "gruppo"},
        {"New groups to be INSTALLED:",           "gruppo"},
    };

    /** I totali che pkg scrive in fondo al piano: il controllo incrociato del parser. */
    private static final String[][] TOTALI = {
        {"Number of packages to be upgraded: ",    "aggiorna"},
        {"Number of packages to be downgraded: ",  "retrocede"},
        {"Number of packages to be installed: ",   "installa"},
        {"Number of packages to be reinstalled: ", "reinstalla"},
        {"Number of packages to be removed: ",     "rimuove"},
        {"Number of packages to be fetched: ",     "scarica"},
    };

    private static final String VULNERABILE = " (vulnerable!)";

    private static final Pattern DA_A = Pattern.compile("^(\\S+): (\\S+) -> (\\S+)(?: \\[([^\\]]+)\\])?$");
    private static final Pattern REPO_VERSION_NAME = Pattern.compile("^(\\S+): (\\S+)(?: \\[([^\\]]+)\\])?$");
    private static final Pattern REINSTALLA = Pattern.compile("^(\\S+)-([^\\s-]+)(?: \\[([^\\]]+)\\])?(?: \\((.*)\\))?$");
    private static final Pattern RIMUOVE = Pattern.compile("^(\\S+): (\\S+)(?: \\((.*)\\))?$");
    private static final Pattern PROTETTO_NEL_PIANO = Pattern.compile(
            "^Package (\\S+)-([^\\s-]+) is locked and may not be (\\S+)(?: to version (\\S+))?");
    private static final Pattern PROTETTO_EVENTO = Pattern.compile("^(\\S+)-([^\\s-]+) is locked and may not be modified$");

    /**
     * Il piano come lo stampa {@code pkg upgrade -n}, letto sezione per sezione.
     *
     * Funzione pura: riceve il testo, non lancia niente, cosi' si prova con uscite vere. Se una
     * riga dentro una sezione non si lascia leggere, o i conti non tornano con i totali che pkg
     * stampa da solo, il piano esce con "misurato" falso: un piano letto a meta' e presentato
     * come completo e' peggio di nessun piano.
     */
    static JSONObject leggiPiano(String uscita) {
        JSONArray cambi = new JSONArray(), bloccati = new JSONArray();
        JSONArray errori = new JSONArray(), avvisi = new JSONArray(), illeggibili = new JSONArray();
        Map<String, Integer> contati = new HashMap<>(), dichiarati = new HashMap<>();
        Set<String> giaBloccati = new LinkedHashSet<>();
        boolean aggiornato = false, conflitti = false;
        String sezione = null;

        for (String grezza : (uscita == null ? "" : uscita).split("\n")) {
            String riga = grezza.replace("\r", "");
            String t = riga.trim();

            String nuova = null;
            for (String[] s : SEZIONI) if (t.equals(s[0])) nuova = s[1];
            if (nuova != null) { sezione = nuova; continue; }

            if (sezione != null && riga.startsWith("\t") && !t.isEmpty()) {
                if (!leggiVoce(sezione, t, cambi, bloccati, giaBloccati)) illeggibili.put(t);
                else if (!"protetto".equals(sezione) && !"gruppo".equals(sezione))
                    contati.merge(sezione, 1, Integer::sum);
                continue;
            }
            sezione = null;   // una riga vuota o non rientrata chiude la sezione
            if (t.isEmpty()) continue;

            Matcher ev = PROTETTO_EVENTO.matcher(t);
            if (ev.find()) {
                if (giaBloccati.add(ev.group(1)))
                    bloccati.put(new JSONObject().put("nome", ev.group(1)).put("versione", ev.group(2))
                            .put("azione", "modified").put("verso", ""));
                continue;
            }
            boolean totale = false;
            for (String[] tt : TOTALI) {
                if (t.startsWith(tt[0])) {
                    try { dichiarati.put(tt[1], Integer.parseInt(t.substring(tt[0].length()).trim())); }
                    catch (NumberFormatException e) { illeggibili.put(t); }
                    totale = true;
                }
            }
            if (totale) continue;
            if (t.equals("Your packages are up to date.")) { aggiornato = true; continue; }
            if (t.startsWith("Conflicts with the existing packages")) { conflitti = true; continue; }
            if (t.startsWith("pkg:")) {
                if (t.toLowerCase().contains("warning")) avvisi.put(t); else errori.put(t);
            }
            // Il resto (dimensioni, "Checking for upgrades", "Updating ... repository catalogue")
            // non cambia il piano.
        }

        JSONObject r = new JSONObject().put("cambi", cambi).put("bloccati", bloccati)
                .put("erroriPkg", errori).put("avvisiPkg", avvisi)
                .put("nienteDaFare", aggiornato || (cambi.isEmpty() && bloccati.isEmpty() && errori.isEmpty()))
                .put("conflitti", conflitti);

        if (illeggibili.length() > 0)
            return r.put("misurato", false).put("illeggibili", illeggibili)
                    .put("errore", I18n.tr("server.plan.unreadableLines", java.util.Map.of("n", String.valueOf(illeggibili.length()), "first", String.valueOf(illeggibili.getString(0)))));
        // pkg stampa un totale per ogni tipo che compare: i due conti devono coincidere, in
        // entrambe le direzioni. Un tipo contato senza totale e' un totale che non ho letto.
        Set<String> tipi = new LinkedHashSet<>(contati.keySet());
        tipi.addAll(dichiarati.keySet());
        for (String tipo : tipi) {
            int a = contati.getOrDefault(tipo, 0), b = dichiarati.getOrDefault(tipo, -1);
            if (a != b)
                return r.put("misurato", false)
                        .put("errore", I18n.tr("server.plan.countMismatch", java.util.Map.of("b", String.valueOf(b < 0 ? I18n.tr("server.plan.noTotal") : String.valueOf(b)), "kind", String.valueOf(tipo), "a", String.valueOf(a))));
        }
        return r.put("misurato", true);
    }

    /** Una riga rientrata di una sezione. false se non ha la forma che la sezione prevede. */
    private static boolean leggiVoce(String sezione, String t, JSONArray cambi, JSONArray bloccati, Set<String> giaBloccati) {
        boolean vulnerabile = t.endsWith(VULNERABILE);
        String s = vulnerabile ? t.substring(0, t.length() - VULNERABILE.length()) : t;
        Matcher m;
        switch (sezione) {
            case "aggiorna", "retrocede" -> {
                m = DA_A.matcher(s);
                if (!m.find()) return false;
                cambi.put(voce(sezione, m.group(1), m.group(2), m.group(3), "", m.group(4), vulnerabile));
            }
            case "installa" -> {
                m = REPO_VERSION_NAME.matcher(s);
                if (!m.find()) return false;
                cambi.put(voce(sezione, m.group(1), "", m.group(2), "", m.group(3), vulnerabile));
            }
            case "reinstalla" -> {
                m = REINSTALLA.matcher(s);
                if (!m.find()) return false;
                cambi.put(voce(sezione, m.group(1), m.group(2), m.group(2), m.group(4), m.group(3), vulnerabile));
            }
            case "rimuove" -> {
                m = RIMUOVE.matcher(s);
                if (!m.find()) return false;
                cambi.put(voce(sezione, m.group(1), m.group(2), "", m.group(3), null, false));
            }
            case "protetto" -> {
                m = PROTETTO_NEL_PIANO.matcher(s);
                if (!m.find()) return false;
                if (giaBloccati.add(m.group(1)))
                    bloccati.put(new JSONObject().put("nome", m.group(1)).put("versione", m.group(2))
                            .put("azione", m.group(3)).put("verso", m.group(4) == null ? "" : m.group(4)));
            }
            case "scarica", "gruppo" -> { /* non cambiano pacchetti installati */ }
            default -> { return false; }
        }
        return true;
    }

    private static JSONObject voce(String tipo, String nome, String da, String a, String motivo,
                                   String repo, boolean vulnerabile) {
        return new JSONObject().put("tipo", tipo).put("nome", nome).put("da", da).put("a", a)
                .put("motivo", motivo == null ? "" : motivo).put("repo", repo == null ? "" : repo)
                .put("ancoraVulnerabile", vulnerabile);
    }

    /**
     * L'impronta di un piano: cio' che e' stato approvato e cio' che si esegue devono coincidere.
     *
     * Dentro ci sono le protezioni da togliere e ogni cambiamento con le sue versioni, in ordine
     * fisso. Fra la lettura del piano e il click puo' passare un aggiornamento del catalogo: con
     * l'impronta, il pannello se ne accorge e si ferma invece di eseguire un piano diverso da
     * quello che e' stato letto.
     */
    static String firma(JSONObject piano) {
        List<String> righe = new ArrayList<>();
        JSONArray sb = piano.optJSONArray("sbloccati");
        for (int i = 0; sb != null && i < sb.length(); i++) righe.add("sblocca " + sb.getString(i));
        JSONArray c = piano.optJSONArray("cambi");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            righe.add(x.optString("tipo") + " " + x.optString("nome") + " " + x.optString("da") + " " + x.optString("a"));
        }
        java.util.Collections.sort(righe);
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", righe).getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(h).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    // ===================== chiedere il piano a pkg =====================

    /** Solo nomi di pacchetto plausibili: finiscono in una riga di comando. */
    /** Il tipo di cambiamento ("aggiorna", "rimuove"...) detto nella lingua di chi legge. */
    public static String typeName(String tipo) {
        return switch (tipo == null ? "" : tipo) {
            case "aggiorna" -> I18n.tr("up.tUpgrade");
            case "installa" -> I18n.tr("up.tInstall");
            case "reinstalla" -> I18n.tr("up.tReinstall");
            case "rimuove" -> I18n.tr("up.tRemove");
            case "retrocede" -> I18n.tr("up.tDowngrade");
            default -> String.valueOf(tipo);
        };
    }

    static boolean isValidName(String n) {
        return n != null && n.matches("[A-Za-z0-9._+-]{1,64}");
    }

    private static String sh(String cmd, int secondi) {
        return Shell.runShell(Duration.ofSeconds(secondi), cmd).outputTrim();
    }

    /** La cartella del database di pkg: la si chiede a pkg invece di supporla. */
    static String cartellaDb() {
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
    public static JSONObject simula(List<String> daSbloccare, List<String> pacchetti) {
        for (String n : daSbloccare) if (!isValidName(n)) return fallito(I18n.tr("server.plan.badName", java.util.Map.of("n", String.valueOf(n))));
        for (String n : pacchetti) if (!isValidName(n)) return fallito(I18n.tr("server.plan.badName", java.util.Map.of("n", String.valueOf(n))));
        String list = pacchetti.isEmpty() ? "" : " " + String.join(" ", pacchetti);
        String prefisso = "pkg";
        String copia = null;
        try {
            if (!daSbloccare.isEmpty()) {
                String db = cartellaDb();
                long kb = number(sh("du -sk " + db + " 2>/dev/null | cut -f1", 120));
                long liberi = number(sh("df -k /var/tmp 2>/dev/null | tail -1 | awk '{print $4}'", 30));
                if (kb <= 0) return fallito(I18n.tr("server.plan.cannotMeasure", java.util.Map.of("db", String.valueOf(db))));
                if (liberi < kb * 2)
                    return fallito(I18n.tr("server.plan.noSpace", java.util.Map.of("mb", String.valueOf(kb / 1024), "free", String.valueOf(liberi / 1024))));
                copia = sh("mktemp -d /var/tmp/pannello-simulazione.XXXXXX 2>/dev/null", 30);
                if (!copia.matches("/var/tmp/pannello-simulazione\\.[A-Za-z0-9]{6,}")) {
                    String cartellaStrana = copia;
                    copia = null;
                    return fallito(I18n.tr("server.plan.mktempFailed", java.util.Map.of("d", String.valueOf(cartellaStrana))));
                }
                Shell.Result cp = Shell.runShell(Duration.ofSeconds(600), "cp -Rp " + db + "/. " + copia + "/ 2>&1");
                if (!cp.success()) return fallito(I18n.tr("server.plan.copyFailed", java.util.Map.of("out", String.valueOf(cp.outputTrim()))));
                prefisso = "pkg -o PKG_DBDIR=" + copia;
                for (String n : daSbloccare) {
                    Shell.Result u = Shell.runShell(Duration.ofSeconds(60), prefisso + " unlock -y " + n + " 2>&1");
                    if (!u.success()) return fallito(I18n.tr("server.plan.unlockFailed", java.util.Map.of("n", String.valueOf(n), "out", String.valueOf(u.outputTrim()))));
                }
            }
            Shell.Result r = Shell.runShell(Duration.ofSeconds(600), prefisso + " upgrade -n -U" + list + " 2>&1");
            JSONObject piano = leggiPiano(r.output());
            return piano.put("success", true).put("codice", r.exitCode()).put("uscita", r.outputTrim())
                    .put("sullaCopia", copia != null)
                    .put("comando", "pkg upgrade -n -U" + list);
        } finally {
            // La copia se ne va sempre. Il percorso e' quello creato da mktemp e verificato sopra.
            if (copia != null) Shell.runShell(Duration.ofSeconds(300), "rm -rf " + copia);
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
     * @param motivoPerNonSbloccare riceve il pacchetto protetto che pkg ha nominato (nome, versione
     *                          e, se pkg la dice, la versione a cui andrebbe); restituisce null se
     *                          si puo' sbloccare, altrimenti il perche'
     */
    public static JSONObject pianoPer(List<String> pacchetti, Set<String> protetti,
                                      Function<JSONObject, String> motivoPerNonSbloccare) {
        LinkedHashSet<String> sblocca = new LinkedHashSet<>();
        for (String p : pacchetti) if (protetti.contains(p)) sblocca.add(p);
        return pianoCon(pacchetti, sblocca, protetti, motivoPerNonSbloccare, true);
    }

    /**
     * Il piano della manutenzione completa: tutto cio' che pkg aggiornerebbe, con 'daSbloccare'
     * sbloccati. Qui un pacchetto protetto che pkg nomina e che non si puo' sbloccare non e' un
     * impedimento: e' uno di quelli trattenuti apposta, pkg lo salta e aggiorna il resto. Resta
     * nel piano, con il suo motivo, perche' chi legge sappia cosa NON verra' aggiornato.
     */
    public static JSONObject pianoTotale(Set<String> daSbloccare, Set<String> protetti,
                                         Function<JSONObject, String> motivoPerNonSbloccare) {
        return pianoCon(List.of(), new LinkedHashSet<>(daSbloccare), protetti, motivoPerNonSbloccare, false);
    }

    private static JSONObject pianoCon(List<String> pacchetti, LinkedHashSet<String> sblocca, Set<String> protetti,
                                       Function<JSONObject, String> motivoPerNonSbloccare, boolean impedimentiBloccano) {
        JSONObject piano = null;
        JSONArray impedimenti = new JSONArray();
        for (int giro = 0; giro < 6; giro++) {
            piano = simula(new ArrayList<>(sblocca), pacchetti);
            if (!piano.optBoolean("success") || !piano.optBoolean("misurato")) break;
            impedimenti = new JSONArray();
            boolean aggiunti = false;
            JSONArray bl = piano.getJSONArray("bloccati");
            for (int i = 0; i < bl.length(); i++) {
                JSONObject blocco = bl.getJSONObject(i);
                String n = blocco.getString("nome");
                if (sblocca.contains(n)) continue;
                String no = !protetti.contains(n)
                        ? I18n.tr("server.plan.lockedUnknown")
                        : motivoPerNonSbloccare.apply(blocco);
                if (no != null) { impedimenti.put(new JSONObject().put("nome", n).put("motivo", no)); continue; }
                sblocca.add(n);
                aggiunti = true;
            }
            if (!aggiunti) break;
        }
        piano.put("sbloccati", new JSONArray(new ArrayList<>(sblocca))).put("impedimenti", impedimenti);

        // I pacchetti chiesti che il piano NON cambia: pkg li lascerebbe dove sono.
        JSONArray fermi = new JSONArray();
        JSONArray cambi = piano.optJSONArray("cambi");
        for (String p : pacchetti) {
            boolean cambia = false;
            for (int i = 0; cambi != null && i < cambi.length(); i++)
                if (p.equals(cambi.getJSONObject(i).optString("nome"))) cambia = true;
            if (!cambia) fermi.put(p);
        }
        piano.put("nonCambiano", fermi);

        // pkg aggiorna prima se stesso. In un aggiornamento vero, se il catalogo ha un pkg piu'
        // recente, pkg installa quello, si rilancia e poi fa il resto; con -n questo passo lo
        // salta, quindi la simulazione non lo mostra. Un piano "esatto" che tace un pacchetto
        // che cambiera' non lo e': si aggiunge in testa, entra nell'impronta e viene verificato.
        JSONObject prima = piano.optBoolean("misurato") ? pkgDaAggiornare() : null;
        if (prima != null && cambi != null) {
            boolean gia = false;
            for (int i = 0; i < cambi.length(); i++) if ("pkg".equals(cambi.getJSONObject(i).optString("nome"))) gia = true;
            if (!gia) {
                JSONArray conPkg = new JSONArray().put(voce("aggiorna", "pkg", prima.getString("da"), prima.getString("a"),
                        I18n.tr("server.plan.pkgFirst"), "", false));
                for (int i = 0; i < cambi.length(); i++) conPkg.put(cambi.get(i));
                piano.put("cambi", conPkg);
                cambi = conPkg;
            }
        }

        boolean eseguibile = piano.optBoolean("success") && piano.optBoolean("misurato")
                && (!impedimentiBloccano || (impedimenti.isEmpty() && piano.optJSONArray("bloccati") != null
                                             && piano.getJSONArray("bloccati").length() == 0))
                && piano.getJSONArray("erroriPkg").length() == 0 && !piano.optBoolean("conflitti")
                && cambi != null && cambi.length() > 0
                // Se nessuno dei pacchetti chiesti cambia, non c'e' niente da eseguire: nemmeno
                // se nel piano c'e' pkg che aggiornerebbe se stesso.
                && (pacchetti.isEmpty() || fermi.length() < pacchetti.size());
        return piano.put("eseguibile", eseguibile).put("firma", piano.optBoolean("misurato") ? firma(piano) : "");
    }

    /** Il pkg installato e quello del catalogo, se il catalogo ne ha uno piu' recente; altrimenti null. */
    static JSONObject pkgDaAggiornare() {
        String da = sh("pkg query %v pkg 2>/dev/null", 30), a = "";
        for (String riga : sh("pkg rquery -U %v pkg 2>/dev/null", 60).split("\n"))
            if (versioneValida(riga.trim())) { a = riga.trim(); break; }
        if (!versioneValida(da) || !versioneValida(a)) return null;
        try {
            return confrontoPkg().confronta(a, da) > 0 ? new JSONObject().put("da", da).put("a", a) : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Dopo l'aggiornamento vero: ogni pacchetto del piano e' dove il piano diceva?
     * Una riga per cambiamento, con cio' che era atteso e cio' che c'e'.
     */
    public static JSONArray verificaEsito(JSONObject piano) {
        JSONArray esito = new JSONArray();
        JSONArray c = piano.optJSONArray("cambi");
        for (int i = 0; c != null && i < c.length(); i++) {
            JSONObject x = c.getJSONObject(i);
            String nome = x.optString("nome");
            if (!isValidName(nome)) continue;
            String ora = sh("pkg query %v " + nome + " 2>/dev/null", 30);
            String atteso = "rimuove".equals(x.optString("tipo")) ? "" : x.optString("a");
            esito.put(new JSONObject().put("nome", nome).put("tipo", x.optString("tipo"))
                    .put("atteso", atteso.isEmpty() ? I18n.tr("server.plan.removed") : atteso)
                    .put("trovato", ora.isEmpty() ? I18n.tr("server.plan.notInstalled") : ora)
                    .put("ok", atteso.equals(ora)));
        }
        return esito;
    }

    // ===================== la correzione c'e'? =====================

    /** Confronto di due versioni, con le regole di pkg. Negativo, zero o positivo. */
    public interface Confronto { int confronta(String a, String b); }

    /** Solo versioni plausibili: finiscono in una riga di comando. */
    static boolean versioneValida(String v) {
        return v != null && v.matches("[A-Za-z0-9._,+~]{1,64}");
    }

    /**
     * Il confronto lo fa pkg stesso ({@code pkg version -t}), non una copia delle sue regole:
     * epoch dopo la virgola, revisione del port dopo il trattino basso, "p", "a", "b", "rc".
     * Riscriverle qui vorrebbe dire sbagliarle sul caso che conta. Le risposte si ricordano:
     * lo stesso confronto non si chiede due volte.
     */
    public static Confronto confrontoPkg() {
        Map<String, Integer> gia = new HashMap<>();
        return (a, b) -> {
            if (!versioneValida(a) || !versioneValida(b))
                throw new IllegalArgumentException("version not comparable: " + a + " / " + b);
            return gia.computeIfAbsent(a + " " + b, k -> {
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
    record Estremo(String op, String versione) {}

    private static final Pattern ESTREMO = Pattern.compile("^(<=|>=|<|>|=)\\s*(\\S+)$");

    /** "&gt;= 1.25.0 : &lt; 1.30.5,3" diventa due estremi; "&lt; 1.30.5,3" uno solo. */
    static List<Estremo> estremi(String intervallo) {
        List<Estremo> r = new ArrayList<>();
        for (String parte : intervallo.split(":")) {
            Matcher m = ESTREMO.matcher(parte.trim());
            if (m.find()) r.add(new Estremo(m.group(1), m.group(2)));
        }
        return r;
    }

    static boolean dentro(String v, List<Estremo> es, Confronto c) {
        if (es.isEmpty()) return false;
        for (Estremo e : es) {
            int x = c.confronta(v, e.versione());
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

    private static boolean dentroUnoQualsiasi(String v, JSONArray intervalli, Confronto c) {
        for (int i = 0; intervalli != null && i < intervalli.length(); i++)
            if (dentro(v, estremi(intervalli.getString(i)), c)) return true;
        return false;
    }

    /**
     * {@code pkg audit -Rjson} ridotto a cio' che serve: per ogni pacchetto la versione e i
     * problemi, ognuno con gli intervalli di versioni vulnerabili.
     *
     * Attenzione alla forma dell'opzione: e' {@code -Rjson}, attaccato. Con {@code -R json}
     * pkg prende "json" per il nome di un pacchetto e produce un altro formato.
     */
    static JSONObject leggiAudit(String json) {
        JSONObject fuori = new JSONObject();
        int g = json == null ? -1 : json.indexOf('{');
        if (g < 0) return fuori;
        JSONObject top = new JSONObject(json.substring(g));
        JSONObject pk = top.optJSONObject("packages");
        if (pk == null) return fuori;
        for (String nome : pk.keySet()) {
            JSONObject p = pk.getJSONObject(nome);
            JSONArray problemi = new JSONArray();
            JSONArray is = p.optJSONArray("issues");
            for (int i = 0; is != null && i < is.length(); i++) {
                JSONObject x = is.getJSONObject(i);
                problemi.put(new JSONObject()
                        .put("intervalli", x.optJSONArray("Affected versions") == null ? new JSONArray()
                                : x.getJSONArray("Affected versions"))
                        .put("descrizione", x.optString("description", ""))
                        .put("cve", x.optJSONArray("cve") == null ? new JSONArray() : x.getJSONArray("cve"))
                        .put("url", x.optString("url", "")));
            }
            fuori.put(nome, new JSONObject().put("versione", p.optString("version", "")).put("problemi", problemi));
        }
        return fuori;
    }

    /**
     * La risposta a "la correzione c'e'?" per un pacchetto: la versione installata, quella che
     * il catalogo offre, e gli intervalli di VuXML di ogni problema.
     *
     * Verdetti, dal migliore al peggiore:
     *  - "si-risolve-aggiornando": il catalogo ha una versione piu' recente che VuXML non
     *    considera vulnerabile per nessuno dei problemi;
     *  - "aggiornamento-non-basta": il catalogo ha una versione piu' recente, ma per almeno un
     *    problema e' ancora vulnerabile;
     *  - "correzione-fuori-dal-ramo": il catalogo non va oltre, ma VuXML indica da quale
     *    versione il problema e' corretto — esiste, non e' ancora nel tuo ramo;
     *  - "correzione-non-indicata": vulnerabile fino a una versione compresa, senza dire la prima
     *    corretta;
     *  - "nessuna-correzione": VuXML non mette un limite superiore, cioe' nessuna versione
     *    pubblicata e' corretta;
     *  - "non-so": un intervallo non si lascia leggere o il confronto non ha risposto.
     */
    static JSONObject valutaCorrezione(String installata, String catalogo, JSONArray problemi, Confronto c) {
        JSONObject r = new JSONObject().put("installata", installata).put("catalogo", catalogo == null ? "" : catalogo);
        try {
            boolean catalogoPiuNuovo = catalogo != null && !catalogo.isEmpty() && c.confronta(catalogo, installata) > 0;
            JSONArray dettagli = new JSONArray();
            String primaCorretta = null;          // la piu' alta fra le prime versioni corrette
            String finoA = null;                  // un "<=": vulnerabile fino a questa compresa
            boolean senzaLimite = false, illeggibile = false, soloQuesta = false;
            List<String> ancoraApertiNelCatalogo = new ArrayList<>();
            for (int i = 0; problemi != null && i < problemi.length(); i++) {
                JSONObject p = problemi.getJSONObject(i);
                JSONArray intervalli = p.optJSONArray("intervalli");
                List<Estremo> suo = null;
                for (int k = 0; intervalli != null && k < intervalli.length(); k++) {
                    List<Estremo> es = estremi(intervalli.getString(k));
                    if (dentro(installata, es, c)) { suo = es; break; }
                }
                JSONObject d = new JSONObject().put("descrizione", p.optString("descrizione"))
                        .put("cve", p.optJSONArray("cve")).put("url", p.optString("url"))
                        .put("intervalli", intervalli);
                if (suo == null) {
                    illeggibile = true;
                    d.put("tipo", "non-so");
                } else {
                    Estremo sup = null;
                    boolean esatta = false;
                    for (Estremo e : suo) {
                        if (e.op().equals("<") || e.op().equals("<=")) sup = e;
                        if (e.op().equals("=")) esatta = true;
                    }
                    if (esatta) {
                        soloQuesta = true;
                        d.put("tipo", "solo-questa-versione");
                    } else if (sup == null) {
                        senzaLimite = true;
                        d.put("tipo", "senza-limite");
                    } else if (sup.op().equals("<")) {
                        d.put("tipo", "corretta-da").put("primaCorretta", sup.versione());
                        if (primaCorretta == null || c.confronta(sup.versione(), primaCorretta) > 0) primaCorretta = sup.versione();
                    } else {
                        d.put("tipo", "vulnerabile-fino-a").put("finoA", sup.versione());
                        finoA = sup.versione();
                    }
                }
                if (catalogoPiuNuovo && dentroUnoQualsiasi(catalogo, intervalli, c)) {
                    ancoraApertiNelCatalogo.add(p.optString("descrizione"));
                    d.put("apertoNelCatalogo", true);
                }
                dettagli.put(d);
            }
            r.put("problemi", dettagli);
            if (primaCorretta != null) r.put("primaCorretta", primaCorretta);

            String verdetto, spiega;
            if (illeggibile) {
                verdetto = "non-so";
                spiega = I18n.tr("server.plan.v.unknownRange");
            } else if (catalogoPiuNuovo && ancoraApertiNelCatalogo.isEmpty()) {
                verdetto = "si-risolve-aggiornando";
                spiega = I18n.tr("server.plan.v.fixedByUpgrade", java.util.Map.of("v", String.valueOf(catalogo)));
            } else if (catalogoPiuNuovo) {
                verdetto = "aggiornamento-non-basta";
                spiega = I18n.tr("server.plan.v.upgradeNotEnough", java.util.Map.of("v", String.valueOf(catalogo), "list", String.valueOf(String.join("; ", ancoraApertiNelCatalogo))))
                        + (primaCorretta != null ? " " + I18n.tr("server.plan.v.fixedFrom", java.util.Map.of("v", String.valueOf(primaCorretta))) : "");
            } else if (senzaLimite) {
                verdetto = "nessuna-correzione";
                spiega = I18n.tr("server.plan.v.noFix");
            } else if (finoA != null && primaCorretta == null) {
                verdetto = "correzione-non-indicata";
                spiega = I18n.tr("server.plan.v.fixNotStated", java.util.Map.of("upTo", String.valueOf(finoA), "cat", String.valueOf(vuotoSe(catalogo, installata))));
            } else if (soloQuesta && primaCorretta == null) {
                verdetto = "correzione-fuori-dal-ramo";
                spiega = I18n.tr("server.plan.v.onlyThis", java.util.Map.of("v", String.valueOf(installata)));
            } else if (primaCorretta != null) {
                verdetto = "correzione-fuori-dal-ramo";
                spiega = I18n.tr("server.plan.v.fixOutsideBranch", java.util.Map.of("fixed", String.valueOf(primaCorretta), "cat", String.valueOf(vuotoSe(catalogo, installata))));
            } else {
                verdetto = "non-so";
                spiega = I18n.tr("server.plan.v.noComparable");
            }
            return r.put("verdetto", verdetto).put("spiegazione", spiega);
        } catch (RuntimeException e) {
            return r.put("verdetto", "non-so").put("spiegazione", I18n.tr("server.plan.v.compareFailed", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    private static String vuotoSe(String catalogo, String installata) {
        return catalogo == null || catalogo.isEmpty() ? installata + " " + I18n.tr("server.plan.noNewer") : catalogo;
    }

    /**
     * Per ogni pacchetto vulnerabile: se e dove esiste la correzione. Legge il database delle
     * vulnerabilita' gia' scaricato (chi chiama decide se riscaricarlo prima) e il catalogo.
     */
    public static JSONObject correzioni() {
        Shell.Result a = Shell.runShell(Duration.ofSeconds(180), "pkg audit -Rjson 2>/dev/null");
        // pkg audit esce con 0 senza vulnerabilita' e con un codice diverso quando ne trova:
        // conta se il JSON c'e', non il codice.
        String out = a.output();
        if (out == null || out.indexOf('{') < 0)
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.plan.auditUnreadable", java.util.Map.of("c", String.valueOf(a.exitCode()))));
        JSONObject vul;
        try { vul = leggiAudit(out); }
        catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.plan.auditJson", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
        Confronto c = confrontoPkg();
        JSONObject per = new JSONObject();
        for (String nome : vul.keySet()) {
            if (!isValidName(nome)) continue;
            JSONObject v = vul.getJSONObject(nome);
            String catalogo = "";
            for (String riga : sh("pkg rquery -U %v " + nome + " 2>/dev/null", 60).split("\n")) {
                String x = riga.trim();
                if (!versioneValida(x)) continue;
                try { if (catalogo.isEmpty() || c.confronta(x, catalogo) > 0) catalogo = x; }
                catch (RuntimeException ignora) { /* resta quella che c'era */ }
            }
            per.put(nome, valutaCorrezione(v.getString("versione"), catalogo, v.getJSONArray("problemi"), c));
        }
        return new JSONObject().put("success", true).put("pacchetti", per);
    }

    // ===================== utilita' =====================

    // ===================== il quadro dei pacchetti =====================

    private static final Pattern DA_AGGIORNARE = Pattern.compile("^(\\S+)-([^\\s-]+)\\s+<\\s.*\\(remote has ([^)]+)\\)\\s*$");

    /**
     * Le righe "<" di {@code pkg version -U -vRL=}: nome -> versione del catalogo. Le altre
     * ("?" fuori catalogo, ">" piu' nuovo del catalogo, "!" non confrontabile) non sono
     * aggiornamenti disponibili e restano fuori.
     */
    public static Map<String, String> daAggiornare(String uscita) {
        Map<String, String> r = new java.util.TreeMap<>();
        for (String riga : (uscita == null ? "" : uscita).split("\n")) {
            Matcher m = DA_AGGIORNARE.matcher(riga.trim());
            if (m.find() && isValidName(m.group(1)) && versioneValida(m.group(3))) r.put(m.group(1), m.group(3));
        }
        return r;
    }

    /** Da {@code pkg query '%n\t%v\t%k'}: nome -> {versione, "1" se bloccato}. */
    public static Map<String, String[]> installati(String uscita) {
        Map<String, String[]> r = new java.util.TreeMap<>();
        for (String riga : (uscita == null ? "" : uscita).split("\n")) {
            String[] c = riga.split("\t");
            if (c.length == 3 && isValidName(c[0].trim()) && versioneValida(c[1].trim()))
                r.put(c[0].trim(), new String[]{c[1].trim(), c[2].trim()});
        }
        return r;
    }

    /** I pacchetti installati, letti adesso. */
    public static Map<String, String[]> installati() {
        return installati(Shell.runShell(Duration.ofSeconds(60), "pkg query '%n\t%v\t%k' 2>/dev/null").output());
    }

    /** Gli aggiornamenti disponibili nel catalogo gia' scaricato: -U, nessuna rete. */
    public static Shell.Result leggiDaAggiornare() {
        return Shell.runShell(Duration.ofSeconds(180), "pkg version -U -vRL= 2>&1");
    }

    private static JSONObject fallito(String errore) {
        return new JSONObject().put("success", false).put("misurato", false).put("error", errore)
                .put("cambi", new JSONArray()).put("bloccati", new JSONArray()).put("erroriPkg", new JSONArray());
    }

    private static long number(String s) {
        try { return Long.parseLong(s.trim().split("\\s+")[0]); } catch (Exception e) { return -1; }
    }
}
