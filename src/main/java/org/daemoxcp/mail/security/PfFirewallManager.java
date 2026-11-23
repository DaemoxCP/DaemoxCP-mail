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
 * pf firewall management with:
 *  - Manual CIDR whitelist/blacklist (e.g. 109.105.211.0/24)
 *  - Country whitelist/blacklist via GeoIP (CIDR ranges from ipdeny.com)
 *  - Separate 'panel-fw' anchor on /etc/pf.conf
 *  - Atomic apply with syntax check + rollback
 *
 * State file (persistent configuration):
 *   /usr/local/etc/daemoxcp-mail/firewall.json
 *
 * GeoIP storage (zone files):
 *   /var/db/daemoxcp-mail/geoip/{cc}.zone
 *
 * Generated pf anchor:
 *   /etc/pf.anchors/panel-fw.conf
 *
 * SAFETY:
 *  - Every pf.conf change makes a .bak.&lt;timestamp&gt; backup
 *  - pfctl -nf for the syntax check before applying
 *  - Whitelist mode ONLY on the AUTH ports (no port 25) to avoid blocking incoming mail delivery
 */
public class PfFirewallManager {

    private static final Logger LOGGER = Logger.getLogger(PfFirewallManager.class.getName());

    // === Paths ===
    private static final String STATE_DIR  = "/usr/local/etc/daemoxcp-mail";
    private static final String STATE_FILE = STATE_DIR + "/firewall.json";
    private static final String GEOIP_DIR  = "/var/db/daemoxcp-mail/geoip";
    private static final String ANCHOR_FILE = "/etc/pf.anchors/panel-fw.conf";
    private static final String PF_CONF    = "/etc/pf.conf";

    // === Ports protected by the geo-whitelist (AUTH/USER-facing) ===
    // Port 25 (SMTP receive) is NOT in the whitelist by default: foreign mail servers
    // must be able to deliver. It can be blocked if the user explicitly wants it.
    // POP3 (110, 995) only if the administrator has switched it on (Pop3): when off, Dovecot does not serve it and pf
    // does not let it in (PfPolicy), and it is not here.
    private static String authPorts() {
        return org.daemoxcp.mail.system.Pop3.wanted() ? "{ 465, 587, 143, 993, 110, 995 }" : "{ 465, 587, 143, 993 }";
    }

    private static String mailPorts() {
        return org.daemoxcp.mail.system.Pop3.wanted() ? "{ 25, 465, 587, 143, 993, 110, 995 }" : "{ 25, 465, 587, 143, 993 }";
    }

    // === Modes ===
    public enum Mode {
        DISABLED,         // anchor loaded empty
        CIDR_ONLY,        // manual whitelist/blacklist only
        GEO_WHITELIST,    // only listed countries can reach the AUTH ports
        GEO_BLACKLIST     // listed countries blocked (on all mail ports)
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
        public int autoSyncIntervalDays = 7;   // after how many days a country is considered "stale"
        public long lastAutoSyncCheck = 0;     // epoch ms of the last check (not download)
        public long lastAutoSyncRun = 0;       // epoch ms of the last download made by the auto-sync
    }

    /** 'Freshness' state of a synchronised country. */
    public enum Freshness {
        NEVER,    // never downloaded
        FRESH,    // < 7 days
        AGING,    // 7-30 days
        STALE,    // 30-90 days
        VERY_STALE // > 90 days
    }

    public static Freshness computeFreshness(long lastSyncMs, int intervalDays) {
        if (lastSyncMs <= 0) return Freshness.NEVER;
        long ageMs = System.currentTimeMillis() - lastSyncMs;
        long ageDays = ageMs / (24L * 3600L * 1000L);
        // Thresholds relative to the interval configured by the user
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

    /** background false: only the saved state, without re-applying at startup and without synchronising the countries. */
    private PfFirewallManager(boolean background) {
        loadState();
        if (!background) return;
        // Auto-apply at boot: if the firewall was ACTIVE before the restart, re-apply
        // the anchor in the kernel. Important because pf.conf has no "load anchor",
        // so at boot the panel-fw anchor is empty until the panel loads it.
        if (state.enabled && state.mode != Mode.DISABLED) {
            scheduler.schedule(() -> {
                try {
                    LOGGER.info("Auto-apply firewall config at boot (mode=" + state.mode + ")");
                    ApplyResult r = applyConfiguration();
                    LOGGER.info("Auto-apply at boot: " + (r.success ? "OK" : "FAIL — " + r.message));
                } catch (Exception e) {
                    LOGGER.warning("Auto-apply at boot failed: " + e.getMessage());
                }
            }, 10, java.util.concurrent.TimeUnit.SECONDS);
        }
        // Start the hourly auto-sync (checks, downloads only if needed)
        scheduler.scheduleWithFixedDelay(this::autoSyncTick,
            5, 60 * 60, java.util.concurrent.TimeUnit.SECONDS);
    }

    /**
     * The panel-fw anchor again, from the saved state, without starting the background jobs: for the console, which changes
     * the IPv4/IPv6 choice (Main --ip-family) and then exits. The anchor depends on the choice (refusing the closed
     * family is its first rule): from the page /api/ip-family already reloads it, from the console nobody
     * reloaded it. Null if the panel firewall is off or disabled: then the anchor is empty and pf.conf decides.
     */
    public static ApplyResult reapplySaved() {
        PfFirewallManager m = new PfFirewallManager(false);
        if (!m.state.enabled || m.state.mode == Mode.DISABLED) return null;
        return m.applyConfiguration();
    }

    /**
     * Periodic scheduler tick (1/h). Checks which countries are "stale"
     * (beyond the configured interval) and downloads them again. NOOP if auto-sync is disabled.
     *
     * Strategy: download at most 5 countries per tick so as not to saturate the bandwidth.
     * If there are more than 5 stale countries, the others will be picked up at the next tick.
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
        // Returns a copy to avoid accidental mutations
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
    // VALIDATION
    // ================================================================
    /** Validates an IP/CIDR. Accepts v4, v6, with or without /N. */
    public static boolean isValidCidr(String cidr) {
        if (cidr == null) return false;
        cidr = cidr.trim();
        return cidr.matches("^[0-9a-fA-F:.]+(/[0-9]{1,3})?$") && cidr.length() <= 64;
    }

    /** Validates an ISO-3166-1 alpha-2 country code. */
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
     * Adds a list of countries (e.g. all EU members). Skips invalid codes.
     * Returns the number of countries actually added (duplicates excluded).
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
     * Removes a list of countries.
     */
    public synchronized int bulkRemoveCountries(Collection<String> codes) {
        int removed = 0;
        for (String cc : codes) {
            if (cc != null && state.geoCountries.remove(cc.toLowerCase())) removed++;
        }
        if (removed > 0) saveState();
        return removed;
    }

    /** Completely empties the list of selected countries. */
    public synchronized int clearCountries() {
        int n = state.geoCountries.size();
        state.geoCountries.clear();
        if (n > 0) saveState();
        return n;
    }

    /**
     * Downloads a country's addresses from ipdeny.com, IPv4 and IPv6, into the same file: a pf table holds both
     * families. There used to be only the IPv4 list: with the whitelist every IPv6 client stayed out of the access
     * ports, with the blacklist no IPv6 address of the country was blocked.
     * Sources: https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone (IPv4) and
     * https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{cc}-aggregated.zone (IPv6).
     * Without the IPv4 list nothing is written; without the IPv6 one (a country without IPv6 addresses, or ipdeny not
     * answering) only the IPv4 one is written, and that is reported.
     */
    public SyncResult syncCountry(String cc) {
        SyncResult res = new SyncResult();
        res.country = cc;
        if (!isValidCountryCode(cc)) {
            res.error = I18n.tr("server.pffw.badCountry");
            return res;
        }
        // ipdeny.com has no IPv6 (no AAAA, 2026-11-18): without IPv4 nothing is downloaded, and that is said at once
        // instead of waiting for the maximum time. The lists already downloaded stay in use.
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

    /** The CIDR lines (IPv4 or IPv6) of a list. */
    public static int countCidr(String body) {
        int n = 0;
        for (String line : body.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#") && t.matches("^[0-9a-fA-F:.]+/\\d+\\s*$")) n++;
        }
        return n;
    }

    /** {text, null} if the list arrived and has at least one CIDR line; otherwise {null, reason}. */
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

    /** Sync of all the currently selected countries. */
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

    /** Number of CIDRs downloaded for a country (or 0 if the zone file is missing). */
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
    // PF ANCHOR GENERATION + APPLY
    // ================================================================
    /**
     * The line of an anchor table. An empty one is written {@code { }}: without braces pf, when reloading the anchor,
     * keeps the previous content, and the last address removed from a list (allowed or blocked) stayed active in pf
     * until the restart (test of all the panel functions 0.9.0 on FreeBSD 15.1, 2026-11-18: with {@code { }} the table
     * is emptied). pf does not accept comments inside the braces.
     */
    static String tableLine(String name, java.util.Collection<String> cidrs) {
        return "table <" + name + "> persist { " + String.join(", ", cidrs) + (cidrs.isEmpty() ? "" : " ") + "}\n";
    }

    /**
     * Generates the content of the panel-fw anchor according to the current state and the IPv4/IPv6 choice (IpFamily).
     */
    public String generateAnchorContent() {
        StringBuilder sb = new StringBuilder();
        sb.append("# Anchor panel-fw — written by DaemoxCP Mail\n");
        sb.append("# Generated: ").append(Instant.now()).append("\n");
        sb.append("# Do NOT edit by hand: it is overwritten.\n\n");
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
     * The anchor's tables and rules. geoFiles: the country lists already downloaded; refusal: the refusal of the family
     * closed by the IPv4/IPv6 choice (PfPolicy.closedRefusal, quick), or null. Pure, apart from the POP3 ports (without a
     * database POP3 is off).
     */
    static String anchorBody(FirewallState state, List<String> geoFiles, String refusal) {
        StringBuilder sb = new StringBuilder();
        if (state.mode == Mode.DISABLED) {
            sb.append("# Firewall panel-fw DISABLED: no rule is active.\n");
            return sb.toString();
        }

        // Table definitions (tableLine: empty ones with { }, never without braces).
        sb.append(tableLine("panel_wl_cidrs", state.whitelistCidrs));
        sb.append(tableLine("panel_bl_cidrs", state.blacklistCidrs));

        // Geo: a single table with ALL the CIDRs of the selected countries
        // If GEO mode but no zone file available, skip the geo rules
        // (otherwise GEO_WHITELIST with an empty table = total lockout!)
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
                sb.append("# WARNING: mode ").append(state.mode)
                  .append(" but no zone file downloaded. Geo rules IGNORED to avoid a lockout.\n");
                sb.append("# To turn the geo mode on: 1) choose countries, 2) click 'Sync now', 3) Apply.\n");
            }
        }

        sb.append("\n");

        // === Rules ===
        // 0. The family closed by the IPv4/IPv6 choice (IpFamily): an immediate refusal, before everything else.
        //    Without it, the quick rules below decided on their own: the IPv6 address of an allowed country or of an
        //    allowed address got in even with mail in IPv6 outgoing only, and that of the others vanished silently
        //    instead of the "no". SSH is not here: its rule is not changed by the panel, and from there one can always
        //    go back.
        if (refusal != null) {
            sb.append("# The family closed by the IPv4/IPv6 choice: refused at once, before lists and countries\n");
            sb.append(refusal).append("\n");
        }

        // 1. CIDR whitelist: always pass (overrides everything)
        sb.append("# CIDR allow list: always allowed\n");
        sb.append("pass in quick from <panel_wl_cidrs> to any keep state\n");

        // 2. CIDR blacklist: always block
        sb.append("# CIDR block list: always blocked\n");
        sb.append("block in quick from <panel_bl_cidrs> to any\n");

        // 3. Geo rules - only if geoActive (zone files present)
        if (geoActive && state.mode == Mode.GEO_WHITELIST) {
            String ports = state.applyGeoToPort25
                ? mailPorts()
                : authPorts();
            sb.append("# Geo allow list: only the chosen countries on the AUTH ports\n");
            sb.append("pass in quick proto tcp from <panel_geo_wl> to any port ")
              .append(ports).append(" keep state\n");
            sb.append("block in quick proto tcp to any port ")
              .append(ports).append("\n");
        } else if (geoActive && state.mode == Mode.GEO_BLACKLIST) {
            String ports = mailPorts();
            sb.append("# Geo block list: the chosen countries blocked on all the mail ports\n");
            sb.append("block in quick proto tcp from <panel_geo_bl> to any port ")
              .append(ports).append("\n");
        }

        return sb.toString();
    }

    /**
     * Atomic apply:
     *  1. Writes the new anchor to temp
     *  2. pfctl -nf -a panel-fw temp  -> syntax check
     *  3. If OK: cp temp -> ANCHOR_FILE
     *  4. pfctl -a panel-fw -f ANCHOR_FILE -> loads into the kernel
     *  5. Backs up the old anchor with .bak.timestamp
     *
     * In case of error, the previous anchor stays active.
     */
    /**
     * Computes the total number of CIDRs loaded in the zone files of the selected countries.
     * Used to size net.pf.request_maxcount.
     */
    private long countTotalGeoCidrs() {
        long total = 0;
        for (String cc : state.geoCountries) {
            total += getCountryCidrCount(cc);
        }
        return total;
    }

    /**
     * Makes sure net.pf.request_maxcount is high enough for our tables.
     * FreeBSD default = 65535. A geo whitelist of EU+others easily needs 100k+.
     * Sets it at runtime + makes it persistent at boot via /etc/sysctl.conf.
     */
    private void ensurePfRequestMaxcount(long needed) {
        // Safety margin: we need 2x the expected number for future growth
        long target = Math.max(needed * 2L, 200_000L);
        // Round up to the next million so we do not have to touch it every time
        if (target > 1_000_000L) target = ((target / 1_000_000L) + 1L) * 1_000_000L;
        else target = 1_000_000L;

        try {
            // Check the current value
            Shell.Result q = Shell.run(Duration.ofSeconds(5),
                "/sbin/sysctl", "-n", "net.pf.request_maxcount");
            long current = 0;
            try { current = Long.parseLong(q.outputTrim()); } catch (Exception ignored) {}
            if (current >= target) return; // already enough

            // Set at runtime
            Shell.run(Duration.ofSeconds(5),
                "/sbin/sysctl", "net.pf.request_maxcount=" + target);

            // Persistence in /etc/sysctl.conf
            Path sysctl = Paths.get("/etc/sysctl.conf");
            String existing = Files.exists(sysctl) ? Files.readString(sysctl) : "";
            // Remove any old net.pf.request_maxcount= lines
            StringBuilder cleaned = new StringBuilder();
            for (String line : existing.split("\n", -1)) {
                if (!line.trim().startsWith("net.pf.request_maxcount=")) {
                    cleaned.append(line).append("\n");
                }
            }
            // Remove double trailing newlines
            String cleanedStr = cleaned.toString().replaceAll("\n+$", "\n");
            cleanedStr += "# Panel: raised for pf tables with many CIDRs (GeoIP)\n";
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

            // 0. PRE-CHECK: if geo mode is active, make sure net.pf.request_maxcount
            //    is high enough. FreeBSD default = 65535 - too low for EU+geo.
            if (state.mode == Mode.GEO_WHITELIST || state.mode == Mode.GEO_BLACKLIST) {
                long totalCidrs = countTotalGeoCidrs();
                if (totalCidrs > 0) {
                    ensurePfRequestMaxcount(totalCidrs);
                }
            }

            // 1. Generate the new content
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

            // 3. Back up the current one (if it exists)
            Path current = Paths.get(ANCHOR_FILE);
            if (Files.exists(current)) {
                Path backup = org.daemoxcp.mail.system.ConfigBackups.copy(current);
                r.backupPath = backup.toString();
            }

            // 4. Replace
            Files.move(tempFile, current, StandardCopyOption.REPLACE_EXISTING);

            // 5. Make sure pf.conf includes the panel-fw anchor
            ensureAnchorInPfConf();

            // 6. Load into the kernel
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
     * Checks that /etc/pf.conf includes 'anchor "panel-fw"' and 'load anchor panel-fw'.
     * If missing, adds it (with a backup).
     */
    private void ensureAnchorInPfConf() throws IOException {
        Path pfConf = Paths.get(PF_CONF);
        if (!Files.exists(pfConf)) return;
        String content = Files.readString(pfConf);
        boolean hasAnchor = content.contains("anchor \"panel-fw\"") || content.contains("anchor panel-fw");
        // IMPORTANT: we do NOT use "load anchor" in pf.conf. Pf loads the whole config
        // atomically with the OLD table limit active during the parse,
        // so if we try to load 100k+ CIDRs via "load anchor" with the default limit=200k,
        // it fails EVEN IF right above there is "set limit ... 2000000".
        // Solution: the panel loads the anchor SEPARATELY via "pfctl -a panel-fw -f"
        // AFTER pf.conf has raised the limit. So we remove any
        // "load anchor panel-fw" already present.

        boolean hasTableLimit = false;
        // Check non-comment lines for "set limit table-entries"
        for (String line : content.split("\n")) {
            String t = line.trim();
            if (t.startsWith("#") || t.isEmpty()) continue;
            if (t.matches("^set\\s+limit\\s+table-entries\\s+\\d+.*")) {
                hasTableLimit = true;
                break;
            }
        }

        boolean hasLoadAnchor = content.contains("load anchor \"panel-fw\"") || content.contains("load anchor panel-fw");

        if (hasAnchor && hasTableLimit && !hasLoadAnchor) return; // already OK

        long totalCidrs = countTotalGeoCidrs() + state.whitelistCidrs.size() + state.blacklistCidrs.size();
        long targetLimit = Math.max(totalCidrs * 2L, 2_000_000L);

        // Backup
        org.daemoxcp.mail.system.ConfigBackups.copy(pfConf);

        String newContent = content;

        // 1. REMOVE any "load anchor panel-fw" -- we do not want them in pf.conf
        if (hasLoadAnchor) {
            StringBuilder out = new StringBuilder();
            for (String line : newContent.split("\n", -1)) {
                String t = line.trim();
                if (t.startsWith("load anchor \"panel-fw\"") || t.startsWith("load anchor panel-fw")) {
                    out.append("# (removed by the panel) ").append(line).append("\n");
                } else {
                    out.append(line).append("\n");
                }
            }
            newContent = out.toString().replaceAll("\n+$", "\n");
        }

        // 2. Add/update "set limit table-entries" at the top (BEFORE any other directive)
        if (!hasTableLimit) {
            String[] lines = newContent.split("\n", -1);
            StringBuilder out = new StringBuilder();
            boolean inserted = false;
            for (String line : lines) {
                if (!inserted && !line.trim().startsWith("#") && !line.trim().isEmpty()) {
                    out.append("# Panel firewall: raises the table limit for the geo CIDRs\n");
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

        // 3. Add "anchor panel-fw" (without load anchor!) if missing
        if (!hasAnchor) {
            if (!newContent.endsWith("\n")) newContent += "\n";
            newContent += "\n# Panel firewall anchor (loaded by the panel with pfctl -a)\n";
            newContent += "anchor \"panel-fw\"\n";
        }

        Files.writeString(pfConf, newContent, StandardCharsets.UTF_8);

        // Reload pf.conf - now without "load anchor" the reload is only for set limit + structure
        Shell.Result reload = Shell.run(Duration.ofSeconds(30), "/sbin/pfctl", "-f", PF_CONF);
        if (!reload.success()) {
            LOGGER.warning("pf.conf reload failed: " + reload.output());
        } else {
            LOGGER.info("pf.conf reload OK with anchor panel-fw (empty) + table-entries limit " + targetLimit);
        }
    }

    /**
     * Counts the IPs/CIDRs currently loaded in the pf tables (at runtime).
     */
    public Map<String, Integer> getTableSizes() {
        Map<String, Integer> sizes = new LinkedHashMap<>();
        for (String t : List.of("panel_wl_cidrs", "panel_bl_cidrs", "panel_geo_wl", "panel_geo_bl")) {
            // Timeout 30s: geo tables can have 100k+ entries and the output is large.
            Shell.Result r = Shell.run(Duration.ofSeconds(30),
                "/sbin/pfctl", "-a", "panel-fw", "-t", t, "-T", "show");
            if (r.success()) {
                int count = 0;
                String out = r.output();
                // Count only lines that have a CIDR/IP (exclude ALTQ warnings and any errors)
                for (String line : out.split("\n")) {
                    String tr = line.trim();
                    if (tr.isEmpty()) continue;
                    // Valid line: starts with a digit or a hex digit (IPv4 or IPv6)
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
