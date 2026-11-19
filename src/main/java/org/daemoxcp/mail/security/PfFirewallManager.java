package org.daemoxcp.mail.security;

import org.daemoxcp.mail.util.Shell;
import org.daemoxcp.mail.i18n.I18n;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Gestione firewall pf con:
 *  - Whitelist/blacklist CIDR manuali (es. 109.105.211.0/24)
 *  - Whitelist/blacklist paesi via GeoIP (range CIDR da ipdeny.com)
 *  - Anchor separato 'panel-fw' su /etc/pf.conf
 *  - Apply atomico con syntax check + rollback
 *
 * File di stato (configurazione persistente):
 *   /usr/local/etc/daemoxcp-mail/firewall.json
 *
 * Storage GeoIP (zone files):
 *   /var/db/daemoxcp-mail/geoip/{cc}.zone
 *
 * Anchor pf generato:
 *   /etc/pf.anchors/panel-fw.conf
 *
 * SAFETY:
 *  - Ogni modifica pf.conf fa backup .bak.&lt;timestamp&gt;
 *  - pfctl -nf per syntax check prima di applicare
 *  - Whitelist mode SOLO sulle porte AUTH (no port 25) per evitare di bloccare la consegna mail in entrata
 */
public class PfFirewallManager {

    private static final Logger LOGGER = Logger.getLogger(PfFirewallManager.class.getName());

    // === Paths ===
    private static final String STATE_DIR  = "/usr/local/etc/daemoxcp-mail";
    private static final String STATE_FILE = STATE_DIR + "/firewall.json";
    private static final String GEOIP_DIR  = "/var/db/daemoxcp-mail/geoip";
    private static final String ANCHOR_FILE = "/etc/pf.anchors/panel-fw.conf";
    private static final String PF_CONF    = "/etc/pf.conf";

    // === Porte protette dalla geo-whitelist (AUTH/USER-facing) ===
    // Port 25 (SMTP receive) NON e' in whitelist by default: i mail server esteri
    // devono poter consegnare. Si puo' bloccare se l'utente lo vuole esplicitamente.
    // POP3 (110, 995) solo se l'amministratore l'ha acceso (Pop3): spento, Dovecot non lo serve e pf
    // non lo fa entrare (PfPolicy), e qui non c'e'.
    private static String authPorts() {
        return org.daemoxcp.mail.system.Pop3.wanted() ? "{ 465, 587, 143, 993, 110, 995 }" : "{ 465, 587, 143, 993 }";
    }

    private static String mailPorts() {
        return org.daemoxcp.mail.system.Pop3.wanted() ? "{ 25, 465, 587, 143, 993, 110, 995 }" : "{ 25, 465, 587, 143, 993 }";
    }

    // === Modi ===
    public enum Mode {
        DISABLED,         // anchor caricato vuoto
        CIDR_ONLY,        // solo whitelist/blacklist manuali
        GEO_WHITELIST,    // solo paesi in lista possono accedere alle porte AUTH
        GEO_BLACKLIST     // paesi in lista bloccati (su tutte le porte mail)
    }

    public static class FirewallState {
        public Mode mode = Mode.CIDR_ONLY;
        public boolean enabled = false;
        public Set<String> whitelistCidrs = new LinkedHashSet<>();
        public Set<String> blacklistCidrs = new LinkedHashSet<>();
        public Set<String> geoCountries   = new LinkedHashSet<>(); // ISO-3166 alpha-2 lowercase
        public Map<String, Long> geoLastSync = new HashMap<>();   // cc -> epoch millis
        public boolean applyGeoToPort25 = false;
        // === Auto-sync GeoIP ===
        public boolean autoSyncEnabled = false;
        public int autoSyncIntervalDays = 7;   // ogni quanti giorni considerare "stale" un paese
        public long lastAutoSyncCheck = 0;     // epoch ms ultimo check (non download)
        public long lastAutoSyncRun = 0;       // epoch ms ultimo download fatto dall'auto-sync
    }

    /** Stato 'freschezza' di un paese sincronizzato. */
    public enum Freshness {
        NEVER,    // mai scaricato
        FRESH,    // < 7 giorni
        AGING,    // 7-30 giorni
        STALE,    // 30-90 giorni
        VERY_STALE // > 90 giorni
    }

    public static Freshness computeFreshness(long lastSyncMs, int intervalDays) {
        if (lastSyncMs <= 0) return Freshness.NEVER;
        long ageMs = System.currentTimeMillis() - lastSyncMs;
        long ageDays = ageMs / (24L * 3600L * 1000L);
        // Soglie relative all'intervallo configurato dall'utente
        long fresh = Math.max(1, intervalDays);
        if (ageDays < fresh) return Freshness.FRESH;
        if (ageDays < fresh * 2L) return Freshness.AGING;
        if (ageDays < fresh * 6L) return Freshness.STALE;
        return Freshness.VERY_STALE;
    }

    private FirewallState state = new FirewallState();

    private final java.util.concurrent.ScheduledExecutorService scheduler =
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = Thread.ofVirtual().unstarted(r);
            t.setName("pf-firewall-geosync");
            t.setDaemon(true);
            return t;
        });

    public PfFirewallManager() {
        this(true);
    }

    /** background false: solo lo stato salvato, senza riapplicare all'avvio e senza la sincronizzazione dei paesi. */
    private PfFirewallManager(boolean background) {
        loadState();
        if (!background) return;
        // Auto-apply al boot: se il firewall era ATTIVO prima del riavvio, ri-applica
        // l'anchor nel kernel. Importante perche' in pf.conf non c'e' "load anchor",
        // quindi al boot l'anchor panel-fw e' vuoto finche' il pannello non lo carica.
        if (state.enabled && state.mode != Mode.DISABLED) {
            scheduler.schedule(() -> {
                try {
                    LOGGER.info("Auto-apply firewall config al boot (mode=" + state.mode + ")");
                    ApplyResult r = applyConfiguration();
                    LOGGER.info("Auto-apply at boot: " + (r.success ? "OK" : "FAIL — " + r.message));
                } catch (Exception e) {
                    LOGGER.warning("Auto-apply at boot failed: " + e.getMessage());
                }
            }, 10, java.util.concurrent.TimeUnit.SECONDS);
        }
        // Avvia auto-sync ogni ora (controlla, scarica solo se serve)
        scheduler.scheduleWithFixedDelay(this::autoSyncTick,
            5, 60 * 60, java.util.concurrent.TimeUnit.SECONDS);
    }

    /**
     * L'anchor panel-fw di nuovo, dallo stato salvato, senza avviare i lavori in sottofondo: per la console, che cambia
     * la scelta IPv4/IPv6 (Main --ip-family) e poi esce. L'anchor dipende dalla scelta (il rifiuto della famiglia
     * chiusa e' la sua prima regola): dalla pagina lo ricarica gia' /api/ip-family, dalla console non lo ricaricava
     * nessuno. Null se il firewall del pannello e' spento o disattivato: allora l'anchor e' vuoto e decide pf.conf.
     */
    public static ApplyResult reapplySaved() {
        PfFirewallManager m = new PfFirewallManager(false);
        if (!m.state.enabled || m.state.mode == Mode.DISABLED) return null;
        return m.applyConfiguration();
    }

    /**
     * Tick periodico (1/h) del scheduler. Controlla quali paesi sono "stale"
     * (oltre l'intervallo configurato) e li ri-scarica. NOOP se auto-sync disattivato.
     *
     * Strategia: scarica al massimo 5 paesi per tick per non saturare la banda.
     * Se ci sono piu' di 5 paesi stale, gli altri verranno presi al prossimo tick.
     */
    private void autoSyncTick() {
        try {
            FirewallState s;
            synchronized (this) {
                state.lastAutoSyncCheck = System.currentTimeMillis();
                saveState();
                if (!state.autoSyncEnabled) return;
                s = getState();
            }
            int intervalDays = Math.max(1, s.autoSyncIntervalDays);
            long thresholdMs = intervalDays * 24L * 3600L * 1000L;
            long now = System.currentTimeMillis();

            int done = 0;
            for (String cc : s.geoCountries) {
                if (done >= 5) break;
                long last = s.geoLastSync.getOrDefault(cc, 0L);
                if (last == 0 || (now - last) >= thresholdMs) {
                    LOGGER.info("Auto-sync country " + cc + " (last=" + last + ", interval=" + intervalDays + "d)");
                    SyncResult r = syncCountry(cc);
                    if (r.success) done++;
                }
            }
            if (done > 0) {
                synchronized (this) {
                    state.lastAutoSyncRun = System.currentTimeMillis();
                    saveState();
                }
                LOGGER.info("Auto-sync completed: " + done + " countries updated");
            }
        } catch (Exception e) {
            LOGGER.warning("Auto-sync tick failed: " + e.getMessage());
        }
    }

    public synchronized boolean setAutoSync(boolean enabled, int intervalDays) {
        state.autoSyncEnabled = enabled;
        state.autoSyncIntervalDays = Math.max(1, Math.min(intervalDays, 365));
        saveState();
        return true;
    }

    // ================================================================
    // STATO: load / save JSON
    // ================================================================
    public synchronized FirewallState getState() {
        // Ritorna una copia per evitare mutazioni accidentali
        FirewallState copy = new FirewallState();
        copy.mode = state.mode;
        copy.enabled = state.enabled;
        copy.whitelistCidrs = new LinkedHashSet<>(state.whitelistCidrs);
        copy.blacklistCidrs = new LinkedHashSet<>(state.blacklistCidrs);
        copy.geoCountries = new LinkedHashSet<>(state.geoCountries);
        copy.geoLastSync = new HashMap<>(state.geoLastSync);
        copy.applyGeoToPort25 = state.applyGeoToPort25;
        copy.autoSyncEnabled = state.autoSyncEnabled;
        copy.autoSyncIntervalDays = state.autoSyncIntervalDays;
        copy.lastAutoSyncCheck = state.lastAutoSyncCheck;
        copy.lastAutoSyncRun = state.lastAutoSyncRun;
        return copy;
    }

    private synchronized void loadState() {
        try {
            Path p = Paths.get(STATE_FILE);
            if (!Files.exists(p)) return;
            String content = Files.readString(p);
            org.json.JSONObject j = new org.json.JSONObject(content);
            state.mode = Mode.valueOf(j.optString("mode", "CIDR_ONLY"));
            state.enabled = j.optBoolean("enabled", false);
            state.applyGeoToPort25 = j.optBoolean("apply_geo_to_port25", false);
            state.autoSyncEnabled = j.optBoolean("auto_sync_enabled", false);
            state.autoSyncIntervalDays = Math.max(1, j.optInt("auto_sync_interval_days", 7));
            state.lastAutoSyncCheck = j.optLong("last_auto_sync_check", 0);
            state.lastAutoSyncRun = j.optLong("last_auto_sync_run", 0);
            state.whitelistCidrs.clear();
            for (Object o : j.optJSONArray("whitelist_cidrs") == null
                    ? new org.json.JSONArray()
                    : j.optJSONArray("whitelist_cidrs")) {
                state.whitelistCidrs.add(String.valueOf(o));
            }
            state.blacklistCidrs.clear();
            for (Object o : j.optJSONArray("blacklist_cidrs") == null
                    ? new org.json.JSONArray()
                    : j.optJSONArray("blacklist_cidrs")) {
                state.blacklistCidrs.add(String.valueOf(o));
            }
            state.geoCountries.clear();
            for (Object o : j.optJSONArray("geo_countries") == null
                    ? new org.json.JSONArray()
                    : j.optJSONArray("geo_countries")) {
                state.geoCountries.add(String.valueOf(o).toLowerCase());
            }
            state.geoLastSync.clear();
            org.json.JSONObject syncObj = j.optJSONObject("geo_last_sync");
            if (syncObj != null) {
                for (String k : syncObj.keySet()) {
                    state.geoLastSync.put(k, syncObj.getLong(k));
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Cannot load firewall state: " + e.getMessage());
        }
    }

    private synchronized void saveState() {
        try {
            Files.createDirectories(Paths.get(STATE_DIR));
            org.json.JSONObject j = new org.json.JSONObject();
            j.put("mode", state.mode.name());
            j.put("enabled", state.enabled);
            j.put("apply_geo_to_port25", state.applyGeoToPort25);
            j.put("auto_sync_enabled", state.autoSyncEnabled);
            j.put("auto_sync_interval_days", state.autoSyncIntervalDays);
            j.put("last_auto_sync_check", state.lastAutoSyncCheck);
            j.put("last_auto_sync_run", state.lastAutoSyncRun);
            j.put("whitelist_cidrs", new org.json.JSONArray(state.whitelistCidrs));
            j.put("blacklist_cidrs", new org.json.JSONArray(state.blacklistCidrs));
            j.put("geo_countries", new org.json.JSONArray(state.geoCountries));
            org.json.JSONObject syncObj = new org.json.JSONObject();
            state.geoLastSync.forEach(syncObj::put);
            j.put("geo_last_sync", syncObj);
            Files.writeString(Paths.get(STATE_FILE), j.toString(2), StandardCharsets.UTF_8);
            // perms restrittive (root only)
            try { Files.setPosixFilePermissions(Paths.get(STATE_FILE),
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); }
            catch (Exception ignored) {}
        } catch (Exception e) {
            LOGGER.warning("Cannot save firewall state: " + e.getMessage());
        }
    }

    // ================================================================
    // VALIDAZIONE
    // ================================================================
    /** Valida un IP/CIDR. Accetta v4, v6, con o senza /N. */
    public static boolean isValidCidr(String cidr) {
        if (cidr == null) return false;
        cidr = cidr.trim();
        return cidr.matches("^[0-9a-fA-F:.]+(/[0-9]{1,3})?$") && cidr.length() <= 64;
    }

    /** Valida un codice paese ISO-3166-1 alpha-2. */
    public static boolean isValidCountryCode(String cc) {
        if (cc == null) return false;
        return cc.toLowerCase().matches("^[a-z]{2}$");
    }

    // ================================================================
    // CIDR MANAGEMENT
    // ================================================================
    public synchronized boolean addCidrWhitelist(String cidr) {
        if (!isValidCidr(cidr)) return false;
        boolean changed = state.whitelistCidrs.add(cidr.trim());
        if (changed) saveState();
        return changed;
    }

    public synchronized boolean removeCidrWhitelist(String cidr) {
        boolean changed = state.whitelistCidrs.remove(cidr);
        if (changed) saveState();
        return changed;
    }

    public synchronized boolean addCidrBlacklist(String cidr) {
        if (!isValidCidr(cidr)) return false;
        boolean changed = state.blacklistCidrs.add(cidr.trim());
        if (changed) saveState();
        return changed;
    }

    public synchronized boolean removeCidrBlacklist(String cidr) {
        boolean changed = state.blacklistCidrs.remove(cidr);
        if (changed) saveState();
        return changed;
    }

    // ================================================================
    // GEO MANAGEMENT
    // ================================================================
    public synchronized boolean setMode(Mode mode) {
        if (mode == null) return false;
        state.mode = mode;
        saveState();
        return true;
    }

    public synchronized boolean setApplyGeoToPort25(boolean v) {
        state.applyGeoToPort25 = v;
        saveState();
        return true;
    }

    public synchronized boolean addGeoCountry(String cc) {
        if (!isValidCountryCode(cc)) return false;
        boolean changed = state.geoCountries.add(cc.toLowerCase());
        if (changed) saveState();
        return changed;
    }

    public synchronized boolean removeGeoCountry(String cc) {
        boolean changed = state.geoCountries.remove(cc.toLowerCase());
        if (changed) saveState();
        return changed;
    }

    /**
     * Aggiunge una lista di paesi (es. tutti i membri UE). Salta i codici non validi.
     * Ritorna il numero di paesi effettivamente aggiunti (esclusi duplicati).
     */
    public synchronized int bulkAddCountries(Collection<String> codes) {
        int added = 0;
        for (String cc : codes) {
            if (isValidCountryCode(cc)) {
                if (state.geoCountries.add(cc.toLowerCase())) added++;
            }
        }
        if (added > 0) saveState();
        return added;
    }

    /**
     * Rimuove una lista di paesi.
     */
    public synchronized int bulkRemoveCountries(Collection<String> codes) {
        int removed = 0;
        for (String cc : codes) {
            if (cc != null && state.geoCountries.remove(cc.toLowerCase())) removed++;
        }
        if (removed > 0) saveState();
        return removed;
    }

    /** Svuota completamente la lista paesi selezionati. */
    public synchronized int clearCountries() {
        int n = state.geoCountries.size();
        state.geoCountries.clear();
        if (n > 0) saveState();
        return n;
    }

    /**
     * Scarica gli indirizzi di un paese da ipdeny.com, IPv4 e IPv6, nello stesso file: una tabella di pf tiene tutte e
     * due le famiglie. Prima c'era solo la lista IPv4: con la whitelist ogni client IPv6 restava fuori dalle porte di
     * accesso, con la blacklist nessun IPv6 del paese veniva bloccato.
     * Sorgenti: https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone (IPv4) e
     * https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone (IPv6).
     * Senza la lista IPv4 non si scrive niente; senza quella IPv6 (un paese senza indirizzi IPv6, o ipdeny che non
     * risponde) si scrive la sola IPv4 e lo si dice.
     */
    public SyncResult syncCountry(String cc) {
        SyncResult res = new SyncResult();
        res.country = cc;
        if (!isValidCountryCode(cc)) {
            res.error = I18n.tr("server.pffw.badCountry");
            return res;
        }
        // ipdeny.com non ha l'IPv6 (nessun AAAA, 18/11/2026): senza IPv4 non si scarica, e lo si dice subito invece di
        // aspettare il tempo massimo. Le liste gia' scaricate restano in uso.
        if (!org.daemoxcp.mail.system.ServerAddresses.read().v4().present()) {
            res.error = I18n.tr("server.pffw.noIpv4Source");
            return res;
        }
        try {
            Files.createDirectories(Paths.get(GEOIP_DIR));
            Path target = Paths.get(GEOIP_DIR, cc.toLowerCase() + ".zone");
            String code = cc.toLowerCase();
            String[] v4 = fetchZone("https://www.ipdeny.com/ipblocks/data/aggregated/" + code + "-aggregated.zone");
            if (v4[0] == null) {
                res.error = v4[1];
                return res;
            }
            String[] v6 = fetchZone("https://www.ipdeny.com/ipv6/ipaddresses/aggregated/" + code + "-aggregated.zone");
            int lines4 = countCidr(v4[0]), lines6 = v6[0] == null ? 0 : countCidr(v6[0]);
            String body = v4[0].endsWith("\n") ? v4[0] : v4[0] + "\n";
            if (v6[0] != null) body += "# IPv6\n" + v6[0];
            Files.writeString(target, body, StandardCharsets.UTF_8);
            synchronized (this) {
                state.geoLastSync.put(code, System.currentTimeMillis());
                saveState();
            }
            res.success = true;
            res.cidrCount = lines4 + lines6;
            res.message = I18n.tr("server.pffw.downloaded", java.util.Map.of("n", String.valueOf(lines4 + lines6), "cc", String.valueOf(cc)))
                    + (v6[0] == null ? " " + I18n.tr("server.pffw.noIpv6List", java.util.Map.of("e", String.valueOf(v6[1]))) : "");
        } catch (Exception e) {
            res.error = org.daemoxcp.mail.util.ErrorText.detail("PfFirewallManager", e);
        }
        return res;
    }

    /** Le righe CIDR (IPv4 o IPv6) di una lista. */
    public static int countCidr(String body) {
        int n = 0;
        for (String line : body.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#") && t.matches("^[0-9a-fA-F:.]+/\\d+\\s*$")) n++;
        }
        return n;
    }

    /** {testo, null} se la lista e' arrivata e ha almeno una riga CIDR; altrimenti {null, motivo}. */
    private static String[] fetchZone(String url) {
        try {
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder(java.net.URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("User-Agent", "DaemoxCP-Mail-Firewall/1.0")
                .GET().build();
            java.net.http.HttpResponse<String> resp = client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                return new String[]{null, I18n.tr("server.pffw.httpFrom", java.util.Map.of("c", String.valueOf(resp.statusCode())))};
            if (countCidr(resp.body()) == 0) return new String[]{null, I18n.tr("server.pffw.emptyAnswer")};
            return new String[]{resp.body(), null};
        } catch (Exception e) {
            return new String[]{null, String.valueOf(e.getMessage())};
        }
    }

    /** Sync di tutti i paesi attualmente selezionati. */
    public List<SyncResult> syncAllSelectedCountries() {
        List<SyncResult> out = new ArrayList<>();
        for (String cc : new LinkedHashSet<>(state.geoCountries)) {
            out.add(syncCountry(cc));
        }
        return out;
    }

    public static class SyncResult {
        public String country;
        public boolean success;
        public int cidrCount;
        public String message;
        public String error;
    }

    /** Numero di CIDR scaricati per un paese (o 0 se zone file mancante). */
    public int getCountryCidrCount(String cc) {
        try {
            Path p = Paths.get(GEOIP_DIR, cc.toLowerCase() + ".zone");
            if (!Files.exists(p)) return 0;
            int n = 0;
            for (String line : Files.readAllLines(p)) {
                String t = line.trim();
                if (!t.isEmpty() && !t.startsWith("#") && t.matches("^[0-9a-fA-F:.]+/\\d+\\s*$")) n++;
            }
            return n;
        } catch (Exception e) {
            return 0;
        }
    }

    // ================================================================
    // GENERAZIONE ANCHOR PF + APPLY
    // ================================================================
    /**
     * La riga di una tabella dell'anchor. Vuota si scrive {@code { }}: senza graffe pf, ricaricando l'anchor, tiene il
     * contenuto di prima, e l'ultimo indirizzo tolto da una lista (consentiti o bloccati) restava attivo in pf fino al
     * riavvio (prova di tutte le funzioni del pannello 0.9.0 su FreeBSD 15.1, 18/11/2026: con {@code { }} la tabella si
     * svuota). pf non accetta commenti dentro le graffe.
     */
    static String tableLine(String name, java.util.Collection<String> cidrs) {
        return "table <" + name + "> persist { " + String.join(", ", cidrs) + (cidrs.isEmpty() ? "" : " ") + "}\n";
    }

    /**
     * Genera il contenuto dell'anchor panel-fw secondo lo stato corrente e la scelta IPv4/IPv6 (IpFamily).
     */
    public String generateAnchorContent() {
        StringBuilder sb = new StringBuilder();
        sb.append("# Anchor panel-fw — written by DaemoxCP Mail\n");
        sb.append("# Generato: ").append(Instant.now()).append("\n");
        sb.append("# NON modificare a mano: viene sovrascritto.\n\n");
        if (state.mode == Mode.DISABLED) return sb.append(anchorBody(state, List.of(), null)).toString();
        List<String> geoFiles = new ArrayList<>();
        if (state.mode == Mode.GEO_WHITELIST || state.mode == Mode.GEO_BLACKLIST) {
            for (String cc : state.geoCountries) {
                Path p = Paths.get(GEOIP_DIR, cc.toLowerCase() + ".zone");
                if (Files.exists(p)) geoFiles.add(p.toString());
            }
        }
        return sb.append(anchorBody(state, geoFiles, PfPolicy.closedRefusalForAnchor())).toString();
    }

    /**
     * Le tabelle e le regole dell'anchor. geoFiles: le liste dei paesi gia' scaricate; refusal: il rifiuto della famiglia
     * chiusa dalla scelta IPv4/IPv6 (PfPolicy.closedRefusal, quick), o null. Puro, a parte le porte di POP3 (senza
     * database POP3 e' spento).
     */
    static String anchorBody(FirewallState state, List<String> geoFiles, String refusal) {
        StringBuilder sb = new StringBuilder();
        if (state.mode == Mode.DISABLED) {
            sb.append("# Firewall panel-fw DISABILITATO — nessuna regola attiva.\n");
            return sb.toString();
        }

        // Definizione tabelle (tableLine: vuote con { }, mai senza graffe).
        sb.append(tableLine("panel_wl_cidrs", state.whitelistCidrs));
        sb.append(tableLine("panel_bl_cidrs", state.blacklistCidrs));

        // Geo: una tabella unica con TUTTI i CIDR dei paesi selezionati
        // Se modalita' GEO ma nessun zone file disponibile, salta le regole geo
        // (altrimenti GEO_WHITELIST con tabella vuota = lockout totale!)
        boolean geoActive = false;
        if (state.mode == Mode.GEO_WHITELIST || state.mode == Mode.GEO_BLACKLIST) {
            geoActive = !geoFiles.isEmpty();

            if (geoActive) {
                String geoTableName = (state.mode == Mode.GEO_WHITELIST) ? "panel_geo_wl" : "panel_geo_bl";
                sb.append("table <").append(geoTableName).append("> persist");
                for (String f : geoFiles) {
                    sb.append(" file \"").append(f).append("\"");
                }
                sb.append("\n");
            } else {
                sb.append("# ATTENZIONE: modalita' ").append(state.mode)
                  .append(" ma nessun zone file scaricato. Regole geo IGNORATE per evitare lockout.\n");
                sb.append("# Per attivare la modalita' geo: 1) seleziona paesi, 2) clicca 'Sincronizza ora', 3) Applica.\n");
            }
        }

        sb.append("\n");

        // === Regole ===
        // 0. La famiglia chiusa dalla scelta IPv4/IPv6 (IpFamily): un rifiuto subito, prima di tutto il resto. Senza,
        //    le regole quick qui sotto decidevano da sole: l'IPv6 di un paese consentito o di un indirizzo consentito
        //    entrava anche con la posta in IPv6 solo in uscita, e quello degli altri spariva in silenzio invece del «no».
        //    SSH non c'e': la sua regola non la cambia il pannello, e da li' si torna sempre indietro.
        if (refusal != null) {
            sb.append("# La famiglia chiusa dalla scelta IPv4/IPv6: rifiutata subito, prima di liste e paesi\n");
            sb.append(refusal).append("\n");
        }

        // 1. CIDR whitelist: sempre pass (override tutto)
        sb.append("# Whitelist CIDR: sempre permesso\n");
        sb.append("pass in quick from <panel_wl_cidrs> to any keep state\n");

        // 2. CIDR blacklist: sempre block
        sb.append("# Blacklist CIDR: sempre bloccato\n");
        sb.append("block in quick from <panel_bl_cidrs> to any\n");

        // 3. Geo rules — solo se geoActive (zone files presenti)
        if (geoActive && state.mode == Mode.GEO_WHITELIST) {
            String ports = state.applyGeoToPort25
                ? mailPorts()
                : authPorts();
            sb.append("# Geo whitelist: solo paesi selezionati su porte AUTH\n");
            sb.append("pass in quick proto tcp from <panel_geo_wl> to any port ")
              .append(ports).append(" keep state\n");
            sb.append("block in quick proto tcp to any port ")
              .append(ports).append("\n");
        } else if (geoActive && state.mode == Mode.GEO_BLACKLIST) {
            String ports = mailPorts();
            sb.append("# Geo blacklist: paesi selezionati bloccati su tutte le porte mail\n");
            sb.append("block in quick proto tcp from <panel_geo_bl> to any port ")
              .append(ports).append("\n");
        }

        return sb.toString();
    }

    /**
     * Apply atomico:
     *  1. Scrive nuovo anchor in temp
     *  2. pfctl -nf -a panel-fw temp  → syntax check
     *  3. Se OK: cp temp → ANCHOR_FILE
     *  4. pfctl -a panel-fw -f ANCHOR_FILE → carica nel kernel
     *  5. Backup vecchio anchor con .bak.timestamp
     *
     * In caso di errore, anchor precedente rimane attivo.
     */
    /**
     * Calcola il numero totale di CIDR caricati nelle zone files dei paesi selezionati.
     * Serve per dimensionare net.pf.request_maxcount.
     */
    private long countTotalGeoCidrs() {
        long total = 0;
        for (String cc : state.geoCountries) {
            total += getCountryCidrCount(cc);
        }
        return total;
    }

    /**
     * Assicura che net.pf.request_maxcount sia abbastanza alto per le nostre tabelle.
     * Default FreeBSD = 65535. Per geo whitelist di EU+altri serve facilmente 100k+.
     * Imposta runtime + rende persistente al boot via /etc/sysctl.conf.
     */
    private void ensurePfRequestMaxcount(long needed) {
        // Margine di sicurezza: ci serve 2× il numero atteso per crescita futura
        long target = Math.max(needed * 2L, 200_000L);
        // Arrotonda al milione successivo per non dover toccare ogni volta
        if (target > 1_000_000L) target = ((target / 1_000_000L) + 1L) * 1_000_000L;
        else target = 1_000_000L;

        try {
            // Verifica valore corrente
            Shell.Result q = Shell.run(Duration.ofSeconds(5),
                "/sbin/sysctl", "-n", "net.pf.request_maxcount");
            long current = 0;
            try { current = Long.parseLong(q.outputTrim()); } catch (Exception ignored) {}
            if (current >= target) return; // gia' sufficiente

            // Imposta a runtime
            Shell.run(Duration.ofSeconds(5),
                "/sbin/sysctl", "net.pf.request_maxcount=" + target);

            // Persistenza in /etc/sysctl.conf
            Path sysctl = Paths.get("/etc/sysctl.conf");
            String existing = Files.exists(sysctl) ? Files.readString(sysctl) : "";
            // Rimuovi eventuali righe vecchie net.pf.request_maxcount=
            StringBuilder cleaned = new StringBuilder();
            for (String line : existing.split("\n", -1)) {
                if (!line.trim().startsWith("net.pf.request_maxcount=")) {
                    cleaned.append(line).append("\n");
                }
            }
            // Rimuovi trailing newline doppi
            String cleanedStr = cleaned.toString().replaceAll("\n+$", "\n");
            cleanedStr += "# Pannello: aumentato per tabelle pf con molti CIDR (GeoIP)\n";
            cleanedStr += "net.pf.request_maxcount=" + target + "\n";

            // Backup
            if (Files.exists(sysctl)) {
                org.daemoxcp.mail.system.ConfigBackups.copy(sysctl);
            }
            Files.writeString(sysctl, cleanedStr, StandardCharsets.UTF_8);
            LOGGER.info("net.pf.request_maxcount raised to " + target + " (was " + current + ")");
        } catch (Exception e) {
            LOGGER.warning("ensurePfRequestMaxcount failed: " + e.getMessage());
        }
    }

    public ApplyResult applyConfiguration() {
        ApplyResult r = new ApplyResult();
        try {
            Files.createDirectories(Paths.get("/etc/pf.anchors"));

            // 0. PRE-CHECK: se geo mode attiva, assicura che net.pf.request_maxcount
            //    sia abbastanza alto. Default FreeBSD = 65535 — troppo basso per EU+geo.
            if (state.mode == Mode.GEO_WHITELIST || state.mode == Mode.GEO_BLACKLIST) {
                long totalCidrs = countTotalGeoCidrs();
                if (totalCidrs > 0) {
                    ensurePfRequestMaxcount(totalCidrs);
                }
            }

            // 1. Genera nuovo contenuto
            String newContent = generateAnchorContent();
            Path tempFile = Paths.get(ANCHOR_FILE + ".new");
            Files.writeString(tempFile, newContent, StandardCharsets.UTF_8);

            // 2. Syntax check
            Shell.Result check = Shell.run(Duration.ofSeconds(15),
                "/sbin/pfctl", "-nf", tempFile.toString());
            if (!check.success()) {
                r.success = false;
                r.message = I18n.tr("server.pffw.syntaxFailed", java.util.Map.of("out", String.valueOf(check.output())));
                Files.deleteIfExists(tempFile);
                return r;
            }

            // 3. Backup attuale (se esiste)
            Path current = Paths.get(ANCHOR_FILE);
            if (Files.exists(current)) {
                Path backup = org.daemoxcp.mail.system.ConfigBackups.copy(current);
                r.backupPath = backup.toString();
            }

            // 4. Replace
            Files.move(tempFile, current, StandardCopyOption.REPLACE_EXISTING);

            // 5. Assicurati che pf.conf includa l'anchor panel-fw
            ensureAnchorInPfConf();

            // 6. Carica nel kernel
            Shell.Result load = Shell.run(Duration.ofSeconds(20),
                "/sbin/pfctl", "-a", "panel-fw", "-f", ANCHOR_FILE);
            if (!load.success()) {
                r.success = false;
                r.message = I18n.tr("server.pffw.loadFailed", java.util.Map.of("out", String.valueOf(load.output())));
                return r;
            }

            state.enabled = (state.mode != Mode.DISABLED);
            saveState();

            r.success = true;
            r.message = I18n.tr("server.pffw.applied", java.util.Map.of("mode", String.valueOf(state.mode)));
            r.anchorContent = newContent;
        } catch (Exception e) {
            r.success = false;
            r.message = I18n.tr("server.pffw.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("PfFirewallManager", e)));
        }
        return r;
    }

    public static class ApplyResult {
        public boolean success;
        public String message;
        public String backupPath;
        public String anchorContent;
    }

    /**
     * Verifica che /etc/pf.conf includa 'anchor "panel-fw"' e 'load anchor panel-fw'.
     * Se manca, lo aggiunge (con backup).
     */
    private void ensureAnchorInPfConf() throws IOException {
        Path pfConf = Paths.get(PF_CONF);
        if (!Files.exists(pfConf)) return;
        String content = Files.readString(pfConf);
        boolean hasAnchor = content.contains("anchor \"panel-fw\"") || content.contains("anchor panel-fw");
        // IMPORTANTE: NON usiamo "load anchor" in pf.conf. Pf carica atomicamente
        // l'intera config con il limit VECCHIO della tabella attivo durante il parse,
        // quindi se proviamo a caricare 100k+ CIDR via "load anchor" con limit=200k
        // di default, fallisce ANCHE se subito sopra c'e' "set limit ... 2000000".
        // Soluzione: il pannello carica l'anchor SEPARATAMENTE via "pfctl -a panel-fw -f"
        // DOPO che pf.conf ha aumentato il limit. Quindi rimuoviamo eventuali
        // "load anchor panel-fw" gia' presenti.

        boolean hasTableLimit = false;
        // Verifica righe non-commento per "set limit table-entries"
        for (String line : content.split("\n")) {
            String t = line.trim();
            if (t.startsWith("#") || t.isEmpty()) continue;
            if (t.matches("^set\\s+limit\\s+table-entries\\s+\\d+.*")) {
                hasTableLimit = true;
                break;
            }
        }

        boolean hasLoadAnchor = content.contains("load anchor \"panel-fw\"") || content.contains("load anchor panel-fw");

        if (hasAnchor && hasTableLimit && !hasLoadAnchor) return; // gia' OK

        long totalCidrs = countTotalGeoCidrs() + state.whitelistCidrs.size() + state.blacklistCidrs.size();
        long targetLimit = Math.max(totalCidrs * 2L, 2_000_000L);

        // Backup
        org.daemoxcp.mail.system.ConfigBackups.copy(pfConf);

        String newContent = content;

        // 1. RIMUOVI eventuali "load anchor panel-fw" — non li vogliamo in pf.conf
        if (hasLoadAnchor) {
            StringBuilder out = new StringBuilder();
            for (String line : newContent.split("\n", -1)) {
                String t = line.trim();
                if (t.startsWith("load anchor \"panel-fw\"") || t.startsWith("load anchor panel-fw")) {
                    out.append("# (rimosso da panel) ").append(line).append("\n");
                } else {
                    out.append(line).append("\n");
                }
            }
            newContent = out.toString().replaceAll("\n+$", "\n");
        }

        // 2. Aggiungi/aggiorna "set limit table-entries" all'inizio (PRIMA di qualsiasi altra direttiva)
        if (!hasTableLimit) {
            String[] lines = newContent.split("\n", -1);
            StringBuilder out = new StringBuilder();
            boolean inserted = false;
            for (String line : lines) {
                if (!inserted && !line.trim().startsWith("#") && !line.trim().isEmpty()) {
                    out.append("# Panel firewall: aumenta limit tabelle per geo CIDR\n");
                    out.append("set limit table-entries ").append(targetLimit).append("\n\n");
                    inserted = true;
                }
                out.append(line).append("\n");
            }
            if (!inserted) {
                out.append("\nset limit table-entries ").append(targetLimit).append("\n");
            }
            newContent = out.toString().replaceAll("\n+$", "\n");
        }

        // 3. Aggiungi "anchor panel-fw" (senza load anchor!) se mancante
        if (!hasAnchor) {
            if (!newContent.endsWith("\n")) newContent += "\n";
            newContent += "\n# Panel firewall anchor (caricato dal pannello via pfctl -a)\n";
            newContent += "anchor \"panel-fw\"\n";
        }

        Files.writeString(pfConf, newContent, StandardCharsets.UTF_8);

        // Reload pf.conf — adesso senza "load anchor" il reload e' solo per set limit + struttura
        Shell.Result reload = Shell.run(Duration.ofSeconds(30), "/sbin/pfctl", "-f", PF_CONF);
        if (!reload.success()) {
            LOGGER.warning("pf.conf reload failed: " + reload.output());
        } else {
            LOGGER.info("pf.conf reload OK with anchor panel-fw (empty) + table-entries limit " + targetLimit);
        }
    }

    /**
     * Conta gli IP/CIDR attualmente caricati nelle tabelle pf (a runtime).
     */
    public Map<String, Integer> getTableSizes() {
        Map<String, Integer> sizes = new LinkedHashMap<>();
        for (String t : List.of("panel_wl_cidrs", "panel_bl_cidrs", "panel_geo_wl", "panel_geo_bl")) {
            // Timeout 30s: tabelle geo possono avere 100k+ entries e l'output e' grande.
            Shell.Result r = Shell.run(Duration.ofSeconds(30),
                "/sbin/pfctl", "-a", "panel-fw", "-t", t, "-T", "show");
            if (r.success()) {
                int count = 0;
                String out = r.output();
                // Conta solo righe che hanno un CIDR/IP (escludi warning ALTQ ed eventuali errori)
                for (String line : out.split("\n")) {
                    String tr = line.trim();
                    if (tr.isEmpty()) continue;
                    // Riga valida: inizia con cifra o esadecimale (IPv4 o IPv6)
                    if (tr.matches("^[0-9a-fA-F].*")) count++;
                }
                sizes.put(t, count);
            } else {
                sizes.put(t, 0);
            }
        }
        return sizes;
    }
}
