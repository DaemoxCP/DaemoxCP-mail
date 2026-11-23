package org.daemoxcp.mail.security;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The provider's firewall in front of the server, and the Cloudflare addresses to put in it (finding 245).
 *
 * <p>The panel (2096) and the webmail (8443) go through the Cloudflare proxy: in the provider's firewall (Hetzner Cloud
 * or another) those two ports must be open only to the Cloudflare ranges, and that list changes now and then. The
 * Hetzner Cloud firewall does have an API, but its token is "Read" or "Read &amp; Write" on the whole project: a
 * token that can change the firewall can also delete the server, and must not be on the mail server. So the
 * list is updated by hand, and the panel helps: it downloads it from cloudflare.com, shows it ready to paste, with the
 * rules to create (derived from the real ports: sshd, mail, POP3 if it is on, the panel and the webmail), and remembers
 * the fingerprint of the list the administrator said they put in. When Cloudflare changes it, Diagnostics says so
 * until the administrator confirms again.
 *
 * <p>The panel does not see the provider's firewall: "confirmed" only means that someone said they did it.
 * The fingerprint is the SHA-256 of the sorted list; the state is in a root file, 0600.
 */
public final class ProviderFirewall {

    private ProviderFirewall() {}

    static final Path STATE = Path.of("/var/db/daemoxcp-mail/provider-firewall.json");
    static final String URL_V4 = "https://www.cloudflare.com/ips-v4";
    static final String URL_V6 = "https://www.cloudflare.com/ips-v6";
    /** Like UpdateManager.cloudflareRanges: below these thresholds the response is broken, not a new list. */
    static final int MIN_V4 = 10, MIN_V6 = 5;
    static final Duration CACHE = Duration.ofHours(1);
    static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{64}");

    /** The official list. */
    public record Official(List<String> v4, List<String> v6) {}

    /** Where the list comes from: cloudflare.com, or a fake list in tests. */
    interface Source {
        Official download() throws Exception;
    }

    static Source source = () -> new Official(
            org.daemoxcp.mail.system.UpdateManager.downloadIntervals(URL_V4, true),
            org.daemoxcp.mail.system.UpdateManager.downloadIntervals(URL_V6, false));
    static Path statePath = STATE;

    private static Official cached;
    private static Instant cachedAt = Instant.EPOCH;

    /** The SHA-256 of the sorted list, IPv4 then IPv6. */
    static String fingerprint(Official o) {
        List<String> all = new ArrayList<>(new TreeSet<>(o.v4()));
        all.add("--");
        all.addAll(new TreeSet<>(o.v6()));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", all).getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The list downloaded now, or the one from the last hour; null if cloudflare.com does not give a credible list. */
    static synchronized Official official(boolean fresh) {
        if (!fresh && cached != null && Instant.now().isBefore(cachedAt.plus(CACHE))) return cached;
        try {
            Official o = source.download();
            if (o == null || o.v4().size() < MIN_V4 || o.v6().size() < MIN_V6) return null;
            cached = new Official(List.copyOf(o.v4()), List.copyOf(o.v6()));
            cachedAt = Instant.now();
            return cached;
        } catch (Exception e) {
            return null;
        }
    }

    /** The confirmed fingerprint and when, or null. */
    static JSONObject acknowledged() {
        try {
            if (!Files.isRegularFile(statePath, LinkOption.NOFOLLOW_LINKS) || Files.size(statePath) > 4096) return null;
            JSONObject j = new JSONObject(Files.readString(statePath, StandardCharsets.UTF_8));
            String fp = j.optString("fingerprint", "");
            return FINGERPRINT.matcher(fp).matches() ? j : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** The rules to create in the provider's firewall, from this server's real ports. */
    static JSONObject rules(SortedSet<Integer> ssh, int panelPort, int webmailPort, boolean pop3) {
        SortedSet<Integer> mail = new TreeSet<>(PfPolicy.FIXED);
        if (pop3) mail.addAll(List.of(110, 995));
        SortedSet<Integer> sshPorts = ssh.isEmpty() ? new TreeSet<>(List.of(22)) : ssh;
        SortedSet<Integer> cf = new TreeSet<>();
        if (panelPort > 0) cf.add(panelPort);
        if (webmailPort > 0) cf.add(webmailPort);
        return new JSONObject().put("ssh", new JSONArray(sshPorts)).put("open", new JSONArray(mail))
                .put("cloudflare", new JSONArray(cf)).put("pop3", pop3);
    }

    /** The state for the page and for Diagnostics. */
    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        SortedSet<Integer> ssh = PfPolicy.sshPorts(Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-P", "tcp").output());
        r.put("rules", rules(ssh, port(configValue("panel_port")),
                port(org.daemoxcp.mail.Main.dbManager == null ? null : org.daemoxcp.mail.Main.dbManager.getRoundcubePort()),
                org.daemoxcp.mail.system.Pop3.wanted()));
        return withList(r, official(false), acknowledged());
    }

    /** The part about the list and the comparison with the confirmed one: pure with respect to its arguments. */
    static JSONObject withList(JSONObject r, Official o, JSONObject ack) {
        if (ack != null) r.put("acknowledged", new JSONObject().put("fingerprint", ack.optString("fingerprint"))
                .put("at", ack.optString("at", "")));
        if (o == null) return r.put("state", "unknown").put("error", I18n.tr("pfw.downloadFailed"));
        String fp = fingerprint(o);
        r.put("listV4", new JSONArray(o.v4())).put("listV6", new JSONArray(o.v6())).put("fingerprint", fp);
        List<String> all = new ArrayList<>(o.v4());
        all.addAll(o.v6());
        r.put("commaList", String.join(", ", all));
        if (ack == null) return r.put("state", "never");
        return r.put("state", fp.equals(ack.optString("fingerprint")) ? "current" : "changed");
    }

    /**
     * The administrator says they put into the provider's firewall the list they saw (its fingerprint). It is
     * downloaded again: if the list has changed in the meantime, a list that is not the current one is not confirmed.
     */
    public static JSONObject acknowledge(String fp) {
        if (fp == null || !FINGERPRINT.matcher(fp).matches())
            return new JSONObject().put("success", false).put("error", I18n.tr("pfw.badFingerprint"));
        Official o = official(true);
        if (o == null) return new JSONObject().put("success", false).put("error", I18n.tr("pfw.downloadFailed"));
        if (!fp.equals(fingerprint(o)))
            return new JSONObject().put("success", false).put("error", I18n.tr("pfw.listChanged"));
        JSONObject j = new JSONObject().put("fingerprint", fp).put("at", Instant.now().toString());
        try {
            write(statePath, j.toString());
        } catch (IOException e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("pfw.notSaved"));
        }
        JSONObject r = state();
        return r.put("success", true);
    }

    /** Atomic write, 0600 owned by root: a temporary file in the same folder, then rename. */
    static void write(Path file, String text) throws IOException {
        Path dir = file.getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, ".provider-firewall-", ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            Files.writeString(tmp, text, StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static int port(String v) {
        if (v == null || !v.trim().matches("[0-9]{1,5}")) return 0;
        int p = Integer.parseInt(v.trim());
        return p > 0 && p < 65536 ? p : 0;
    }

    private static String configValue(String column) {
        if (org.daemoxcp.mail.Main.dbManager == null) return null;
        try (java.sql.ResultSet r = org.daemoxcp.mail.Main.dbManager.get_data_config()) {
            return r != null && r.next() ? r.getString(column) : null;
        } catch (Exception e) {
            return null;
        }
    }
}
