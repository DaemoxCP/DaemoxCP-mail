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
 * Il firewall del provider davanti al server, e gli indirizzi di Cloudflare da metterci (reperto 245).
 *
 * <p>Il pannello (2096) e la webmail (8443) passano dal proxy di Cloudflare: nel firewall del provider (Hetzner Cloud
 * o un altro) quelle due porte vanno aperte solo agli intervalli di Cloudflare, e quella lista cambia ogni tanto. Il
 * firewall di Hetzner Cloud un'API ce l'ha, ma il suo token vale «Read» o «Read &amp; Write» su tutto il progetto: un
 * token che puo' cambiare il firewall puo' anche cancellare il server, e non deve stare sul server di posta. Quindi la
 * lista si aggiorna a mano, e il pannello aiuta: la scarica da cloudflare.com, la mostra pronta da incollare, con le
 * regole da creare (ricavate dalle porte vere: sshd, la posta, POP3 se e' acceso, il pannello e la webmail), e ricorda
 * l'impronta della lista che l'amministratore ha detto di aver messo. Quando Cloudflare la cambia, Diagnostica lo dice
 * finche' l'amministratore non conferma di nuovo.
 *
 * <p>Il pannello non vede il firewall del provider: «confermato» vuol dire solo che qualcuno ha detto di averlo fatto.
 * L'impronta e' lo SHA-256 della lista ordinata; lo stato sta in un file di root, 0600.
 */
public final class ProviderFirewall {

    private ProviderFirewall() {}

    static final Path STATE = Path.of("/var/db/daemoxcp-mail/provider-firewall.json");
    static final String URL_V4 = "https://www.cloudflare.com/ips-v4";
    static final String URL_V6 = "https://www.cloudflare.com/ips-v6";
    /** Come UpdateManager.cloudflareRanges: sotto queste soglie la risposta e' rotta, non una lista nuova. */
    static final int MIN_V4 = 10, MIN_V6 = 5;
    static final Duration CACHE = Duration.ofHours(1);
    static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{64}");

    /** La lista ufficiale. */
    public record Official(List<String> v4, List<String> v6) {}

    /** Da dove viene la lista: cloudflare.com, o una lista finta nelle prove. */
    interface Source {
        Official download() throws Exception;
    }

    static Source source = () -> new Official(
            org.daemoxcp.mail.system.UpdateManager.downloadIntervals(URL_V4, true),
            org.daemoxcp.mail.system.UpdateManager.downloadIntervals(URL_V6, false));
    static Path statePath = STATE;

    private static Official cached;
    private static Instant cachedAt = Instant.EPOCH;

    /** Lo SHA-256 della lista ordinata, IPv4 poi IPv6. */
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

    /** La lista scaricata adesso, o quella dell'ultima ora; null se cloudflare.com non da' una lista credibile. */
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

    /** L'impronta confermata e quando, o null. */
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

    /** Le regole da creare nel firewall del provider, dalle porte vere di questo server. */
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

    /** Lo stato per la pagina e per Diagnostica. */
    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        SortedSet<Integer> ssh = PfPolicy.sshPorts(Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-P", "tcp").output());
        r.put("rules", rules(ssh, port(configValue("mail_panel_port")),
                port(org.daemoxcp.mail.Main.dbManager == null ? null : org.daemoxcp.mail.Main.dbManager.getRoundcubePort()),
                org.daemoxcp.mail.system.Pop3.wanted()));
        return withList(r, official(false), acknowledged());
    }

    /** La parte della lista e del confronto con quella confermata: pura rispetto ai suoi argomenti. */
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
     * L'amministratore dice di aver messo nel firewall del provider la lista che ha visto (la sua impronta). Si
     * riscarica: se nel frattempo la lista e' cambiata, non si conferma una lista che non e' quella di adesso.
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

    /** Scrittura atomica, 0600 di root: un file temporaneo nella stessa cartella, poi rename. */
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
