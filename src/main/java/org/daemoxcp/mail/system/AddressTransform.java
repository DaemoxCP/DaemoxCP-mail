package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.security.RootOnlyPath;
import org.daemoxcp.mail.util.Shell;
import org.daemoxcp.mail.webserver.SecurityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Turning an alias into a real mailbox, and a mailbox into an alias: only when it is really
 * possible, and saying first what changes.
 *
 * How mail arrives here (scripts/FullMailServerScript, DovecotConfig):
 *  - Postfix asks the database first for the active aliases (aliases.source), then for the active mailboxes that
 *    receive (mailboxes.email): an address with active aliases goes to their destinations, and to the
 *    mailbox only if it is itself among them;
 *  - a mailbox's mail is in /var/vmail/domain/name, its compiled filters in
 *    /var/mail/sieve/domain/name. The database does not contain it: deleting the mailbox row
 *    does not touch it, and a new mailbox with the same address would find it again.
 *
 * Alias -> mailbox is possible if the address has a name before the @ (a "@domain" catch-all is not),
 * the domain belongs to the panel and the address is not already a mailbox. A password is needed: a real
 * mailbox wants one, for IMAP and SMTP. The previous destinations either go away, or stay and the mailbox
 * keeps a copy. If on disk there is the mail of an earlier mailbox with the same address, one
 * chooses: recover it, or set it aside and start empty. The leftover filters of that mailbox must not
 * apply to the new one.
 *
 * Mailbox -> alias is possible towards valid destinations, different from the address, that do not lead back to
 * it (that would be an endless loop, which Postfix rejects) and that, if they are on a panel domain,
 * exist: a receiving mailbox, an active alias or a catch-all. The mailbox's login, automatic
 * reply, filters and forwards are lost, and the preview lists them. Mail that has already arrived
 * stays where it is.
 *
 * The preview hands over a fingerprint of the state: if between preview and confirmation something changes (an
 * alias, the mailbox, mail appearing on disk), the transformation does not start.
 */
public final class AddressTransform {

    private AddressTransform() {}

    private static final Logger LOGGER = Logger.getLogger(AddressTransform.class.getName());

    /** Where Dovecot keeps the mail and the filters. Tests move them to a temporary folder. */
    static Path vmail = Path.of("/var/vmail");
    static Path sieve = Path.of("/var/mail/sieve");
    /** Mail set aside: under /var/vmail (same disk, the move is instantaneous), with a name no domain can have. */
    static Path archive() { return vmail.resolve(".panel-archive"); }
    /**
     * The panel's rules set aside: in root's tree, next to the live ones (same disk), with a name that
     * no domain can have. Never under /var/vmail: that belongs to vmail (finding 222).
     */
    static Path rulesArchive() { return sieve.resolve(".panel-archive"); }

    /**
     * How one becomes vmail to move the mail: chroot(8) with root /, without a shell or PAM, and only the vmail group
     * (without -G the command would keep root's supplementary groups). Tests without root empty it: then the move
     * is done by the user running them, in their own folders.
     */
    static List<String> asVmail = List.of("/usr/sbin/chroot", "-u", "vmail", "-g", "vmail", "-G", "vmail", "/");

    /**
     * The mail move, run as vmail: $1 the phase, then the paths, always absolute (never an argument that
     * starts with a hyphen). It writes a single line: MOVED and where it ended up, or NOTHING if there was no folder.
     *  archive: $2 the mailbox, $3 the domain's archive folder (created if missing), $4 the wanted name; if it is taken,
     *           -2, -3...;
     *  back:    $2 from where, $3 to where; if there is already something at the destination nothing is moved.
     * Following a link here gives vmail only what vmail already has.
     */
    static final String MOVE_SCRIPT = """
            PATH=/bin:/usr/bin; export PATH
            cd / || exit 1
            umask 077
            case "$1" in
            archive)
              src=$2; base=$3; dest=$4
              if [ ! -d "$src" ] || [ -L "$src" ]; then echo NOTHING; exit 0; fi
              mkdir -p "$base" || exit 1
              try=$dest; k=2
              while [ -e "$try" ] || [ -L "$try" ]; do try=$dest-$k; k=$((k + 1)); done
              mv "$src" "$try" || exit 1
              echo "MOVED $try" ;;
            back)
              from=$2; to=$3
              if [ -e "$to" ] || [ -L "$to" ]; then echo "taken: $to"; exit 1; fi
              mv "$from" "$to" || exit 1
              echo "MOVED $to" ;;
            *)
              exit 2 ;;
            esac
            """;

    static final int MAX_DESTINATIONS = 20;
    /** Beyond that, the message count stops and says "at least". */
    static final int MAX_COUNTED_FILES = 200_000;

    private static final DateTimeFormatter ARCHIVE_NAME = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    // ===================== The state of an address =====================

    /** The mail on disk for an address. */
    public record MailContent(boolean present, long messages, boolean atLeast, long totalBytes, long lastMs, boolean filters) {
        static final MailContent NONE = new MailContent(false, 0, false, 0, 0, false);
    }

    /** What a mailbox has and an alias does not. */
    public record Losses(boolean autoReply, List<String> forwards, int filters) {}

    /** What matters for deciding, read from the database and from disk. */
    public record AddressState(String address, boolean panelDomain, MailDatabase.Mailbox mailbox,
                        List<MailDatabase.Alias> withThisSource, List<MailDatabase.Alias> towardsHere,
                        MailContent mail, Losses losses) {}

    /** The questions about the destinations, answered by the database (or by the test). */
    public interface Network {
        boolean panelDomain(String domain) throws SQLException;
        /** An active mailbox that receives: Postfix knows it. */
        boolean receives(String address) throws SQLException;
        /** The destinations of the active aliases with this source. */
        List<String> activeDestinations(String source) throws SQLException;
    }

    public static AddressState state(MailDatabase db, String address) throws SQLException {
        String domain = domain(address);
        boolean ofPanel = domain != null && db.getDomainByName(domain) != null;
        MailDatabase.Mailbox m = db.getMailboxByEmail(address);
        Losses losses = null;
        if (m != null) {
            MailDatabase.AutoResponder ar = db.getAutoResponder(m.id);
            List<String> forwards = new ArrayList<>();
            for (MailDatabase.ForwardingRule f : db.getForwardingRules(m.id)) if (f.enabled) forwards.add(f.destination);
            losses = new Losses(ar != null && ar.enabled, forwards, db.getSieveFilters(m.id).size());
        }
        return new AddressState(address, ofPanel, m, db.getAliasesBySource(address), db.getAliasesByDestination(address),
                mail(address), losses);
    }

    public static Network network(MailDatabase db) {
        return new Network() {
            @Override public boolean panelDomain(String d) throws SQLException { return db.getDomainByName(d) != null; }
            @Override public boolean receives(String a) throws SQLException {
                MailDatabase.Mailbox m = db.getMailboxByEmail(a);
                return m != null && m.active && m.receiveEnabled;
            }
            @Override public List<String> activeDestinations(String s) throws SQLException {
                List<String> d = new ArrayList<>();
                for (MailDatabase.Alias a : db.getAliasesBySource(s)) if (a.active) d.add(a.destination);
                return d;
            }
        };
    }

    // ===================== Addresses and paths =====================

    /** An address as the panel wants it: the characters of isValidEmail, 254 in all, 64 before the @. */
    public static boolean validAddress(String a) {
        return a != null && a.length() <= 254 && SecurityUtils.isValidEmail(a) && a.indexOf('@') <= 64;
    }

    /** Printable ASCII only: the whitelist for free text (the name of a mailbox). */
    public static boolean printable(String t) {
        for (int k = 0; k < t.length(); k++) if (t.charAt(k) < 0x20 || t.charAt(k) > 0x7E) return false;
        return true;
    }

    /** Where the address's mail is, to tell the administrator. */
    public static String mailFolder(String address) {
        Path p = folder(vmail, address);
        return p == null ? "" : p.toString();
    }

    static String domain(String a) {
        int at = a == null ? -1 : a.lastIndexOf('@');
        return at < 0 ? null : a.substring(at + 1);
    }

    /**
     * The mail folder of an address, or null if the name cannot be used as a path.
     * isValidEmail also allows "..@domain": here a name like that would escape from /var/vmail.
     */
    static Path folder(Path root, String address) {
        if (!validAddress(address)) return null;
        String name = address.substring(0, address.lastIndexOf('@'));
        String dom = domain(address);
        if (name.startsWith(".") || dom.startsWith(".")) return null;
        Path p = root.resolve(dom).resolve(name).normalize();
        return p.startsWith(root) && !p.equals(root) ? p : null;
    }

    /** How much mail there is on disk for the address: the messages are the files in cur/ and new/, in the folders too. */
    public static MailContent mail(String address) {
        Path dir = folder(vmail, address);
        Path filters = folder(sieve, address);
        boolean hasFilters = filters != null && Files.isRegularFile(filters.resolve(".dovecot.sieve"));
        if (dir == null || !Files.isDirectory(dir)) return new MailContent(false, 0, false, 0, 0, hasFilters);
        long messages = 0, totalBytes = 0, last = 0;
        boolean atLeast = false;
        try (Stream<Path> s = Files.walk(dir, 3)) {
            java.util.Iterator<Path> it = s.iterator();
            while (it.hasNext()) {
                Path p = it.next();
                Path parentFolder = p.getParent();
                if (parentFolder == null || parentFolder.getFileName() == null) continue;
                String parentName = parentFolder.getFileName().toString();
                if (!parentName.equals("cur") && !parentName.equals("new")) continue;
                try {
                    BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);
                    if (!a.isRegularFile()) continue;
                    messages++;
                    totalBytes += a.size();
                    last = Math.max(last, a.lastModifiedTime().toMillis());
                } catch (IOException ignored) {
                    continue;   // a file gone while counting
                }
                if (messages >= MAX_COUNTED_FILES) { atLeast = true; break; }
            }
        } catch (IOException | java.io.UncheckedIOException e) {
            // Unreadable: it is there, but how much is unknown.
            return new MailContent(true, 0, true, 0, 0, hasFilters);
        }
        return new MailContent(true, messages, atLeast, totalBytes, last, hasFilters);
    }

    /**
     * Sets aside the address's mail in /var/vmail/.panel-archive/domain/name-DATE, and the panel's rules in
     * /var/mail/sieve/.panel-archive/domain/name-DATE-filters. Returns the {from, to} pairs moved, the mail
     * first, to put them back if the rest does not succeed.
     *
     * Neither of the two steps goes through a folder of another user (finding 222). They used to be done by root, both
     * under /var/vmail, which with everything it contains belongs to vmail (the user Dovecot delivers as): vmail could
     * put a link in place of .panel-archive or of the domain folder, and root followed it. Measured on the
     * VM: root created folders of its own where vmail cannot write, renamed a root folder from outside into
     * vmail's archive, and when putting things back moved a root folder in place of the mailbox. Moreover the
     * rules, owned by root, ended up in vmail's tree; and where /var/mail and /var/vmail are on two datasets (on the VM, as
     * the FreeBSD installer makes them) moving the rules did not work at all (DirectoryNotEmptyException:
     * Java does not move a non-empty folder from one disk to another), and with it the whole transformation.
     * Now:
     * <ul>
     *   <li>the mail is moved by vmail (MOVE_SCRIPT): it is its own, like the archive; a link it puts there gives it only
     *       what it already has;</li>
     *   <li>the rules stay with root, in its own tree: every folder from / is checked (RootOnlyPath), those
     *       of the archive are born that way, and the rename does not leave /var/mail/sieve.</li>
     * </ul>
     */
    public static List<Path[]> archive(String address, long nowMs) throws IOException {
        List<Path[]> done = new ArrayList<>();
        String when = ARCHIVE_NAME.format(Instant.ofEpochMilli(nowMs).atOffset(ZoneOffset.UTC));
        String name = address.substring(0, address.lastIndexOf('@'));
        String dom = domain(address);
        try {
            Path mail = folder(vmail, address);
            if (mail != null) {
                Path base = archive().resolve(dom);
                Path dest = moveAsVmail("archive", mail, base, base.resolve(name + "-" + when));
                if (dest != null) {
                    if (!dest.startsWith(base)) throw new IOException("vmail moved " + mail + " outside " + base + ": " + dest);
                    done.add(new Path[] { mail, dest });
                }
            }
            Path filters = folder(sieve, address);
            if (filters != null && Files.exists(filters, LinkOption.NOFOLLOW_LINKS)) {
                String why = RootOnlyPath.problem(filters);
                if (why != null) throw new IOException(why);
                Path base = RootOnlyPath.folders(sieve, rulesArchive().getFileName().toString(), dom);
                Path dest = free(base.resolve(name + "-" + when + "-filters"));
                Files.move(filters, dest, StandardCopyOption.ATOMIC_MOVE);
                done.add(new Path[] { filters, dest });
            }
            return done;
        } catch (IOException e) {
            restore(done);
            throw e;
        }
    }

    /** The first free name among p, p-2, p-3...: only in a root folder (the rules), so without following links. */
    private static Path free(Path p) {
        Path q = p;
        for (int k = 2; Files.exists(q, LinkOption.NOFOLLOW_LINKS); k++) q = p.resolveSibling(p.getFileName() + "-" + k);
        return q;
    }

    /**
     * A mail move done by vmail (MOVE_SCRIPT, with {@link #asVmail} and an empty environment): where it ended up,
     * or null if there was no folder to move.
     *
     * @throws IOException with what mkdir or mv wrote, if vmail does not manage it
     */
    static Path moveAsVmail(String phase, Path... paths) throws IOException {
        List<String> cmd = new ArrayList<>(asVmail);
        cmd.addAll(List.of("/usr/bin/env", "-i", "/bin/sh", "-c", MOVE_SCRIPT, "sh", phase));
        for (Path p : paths) cmd.add(p.toAbsolutePath().normalize().toString());
        Shell.Result r = Shell.run(Duration.ofSeconds(120), cmd.toArray(new String[0]));
        String out = r.outputTrim();
        String last = out.substring(out.lastIndexOf('\n') + 1);
        if (r.success() && last.equals("NOTHING")) return null;
        if (r.success() && last.startsWith("MOVED /")) return Path.of(last.substring("MOVED ".length()));
        throw new IOException("vmail could not move " + paths[0] + ": "
                + (out.isEmpty() ? (r.timedOut() ? "timed out" : "exit " + r.exitCode()) : out.replace('\n', ' ')));
    }

    /**
     * Puts back where they were the folders moved by archive(), starting from the last: vmail puts back the mail, root
     * the rules, only if the source and destination folders pass RootOnlyPath. Whatever does not go back stays in the
     * archive (better there than lost), and the log says so.
     */
    public static void restore(List<Path[]> moved) {
        for (int k = moved.size() - 1; k >= 0; k--) {
            Path to = moved.get(k)[0], from = moved.get(k)[1];
            try {
                if (to.startsWith(vmail)) {
                    moveAsVmail("back", from, to);
                } else {
                    String why = RootOnlyPath.problem(from.getParent());
                    if (why == null) why = RootOnlyPath.problem(to.getParent());
                    if (why != null) throw new IOException(why);
                    // rename(2) would replace an empty folder recreated in the meantime: here it is left alone.
                    if (Files.exists(to, LinkOption.NOFOLLOW_LINKS)) throw new IOException("taken: " + to);
                    Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
                }
            } catch (IOException e) {
                LOGGER.warning("[AddressTransform] " + from + " not put back in " + to + ", it stays there: " + e.getMessage());
            }
        }
    }

    // ===================== Fingerprint =====================

    /** The state the preview showed. The number of messages does not count: in a mailbox it changes all the time. */
    public static String fingerprint(AddressState s) {
        StringBuilder t = new StringBuilder(s.address()).append('|').append(s.panelDomain()).append('|');
        MailDatabase.Mailbox m = s.mailbox();
        t.append(m == null ? "-" : m.id + "," + m.email + "," + m.active + "," + m.receiveEnabled).append('|');
        for (MailDatabase.Alias a : sorted(s.withThisSource())) t.append(a.id).append(':').append(a.destination).append(':').append(a.active).append(';');
        t.append('|');
        for (MailDatabase.Alias a : sorted(s.towardsHere())) t.append(a.id).append(':').append(a.source).append(':').append(a.active).append(';');
        t.append('|').append(s.mail().present()).append('|');
        Losses p = s.losses();
        t.append(p == null ? "-" : p.autoReply() + "," + String.join(",", p.forwards()) + "," + p.filters());
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(t.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<MailDatabase.Alias> sorted(List<MailDatabase.Alias> l) {
        List<MailDatabase.Alias> o = new ArrayList<>(l);
        o.sort((x, y) -> Integer.compare(x.id, y.id));
        return o;
    }

    // ===================== Alias -> mailbox =====================

    /** Why the address cannot become a mailbox, or null if it can. */
    public static String noMailboxReason(AddressState s) {
        String a = s.address();
        if (a != null && a.startsWith("@"))
            return I18n.tr("server.convert.catchAll", java.util.Map.of("a", String.valueOf(a)));
        if (!validAddress(a) || folder(vmail, a) == null) return I18n.tr("server.convert.notMailboxAddress");
        if (!s.panelDomain()) return I18n.tr("server.convert.notPanelDomain", java.util.Map.of("a", String.valueOf(a)));
        if (s.mailbox() != null) return I18n.tr("server.convert.alreadyMailbox", java.util.Map.of("a", String.valueOf(a)));
        if (s.withThisSource().isEmpty()) return I18n.tr("server.convert.noAlias", java.util.Map.of("a", String.valueOf(a)));
        return null;
    }

    public static JSONObject previewToMailbox(AddressState s, ZoneId zone) {
        JSONObject o = new JSONObject().put("address", s.address());
        String no = noMailboxReason(s);
        if (no != null) return o.put("possible", false).put("reason", no);
        JSONArray dest = new JSONArray();
        boolean copy = false;
        for (MailDatabase.Alias a : s.withThisSource()) {
            if (a.destination.equals(s.address())) { copy = true; continue; }
            dest.put(new JSONObject().put("destination", a.destination).put("active", a.active));
        }
        return o.put("possible", true).put("destinations", dest).put("copy", copy)
                .put("towardsHere", towardsHere(s)).put("mail", mail(s.mail(), zone)).put("fingerprint", fingerprint(s));
    }

    // ===================== Mailbox -> alias =====================

    public static JSONObject previewToAlias(AddressState s, ZoneId zone) {
        JSONObject o = new JSONObject().put("address", s.address());
        MailDatabase.Mailbox m = s.mailbox();
        if (m == null) return o.put("possible", false).put("reason", I18n.tr("server.convert.notMailbox", java.util.Map.of("a", String.valueOf(s.address()))));
        Losses p = s.losses() == null ? new Losses(false, List.of(), 0) : s.losses();
        JSONArray already = new JSONArray();
        boolean copy = false;
        for (MailDatabase.Alias a : s.withThisSource()) {
            if (a.destination.equals(s.address())) { copy = true; continue; }
            already.put(new JSONObject().put("destination", a.destination).put("active", a.active));
        }
        JSONObject losses = new JSONObject()
                .put("lastAccess", m.lastLogin == null ? "" : ISO.format(m.lastLogin.toInstant().atZone(zone)))
                .put("sendOnly", !m.receiveEnabled).put("active", m.active)
                .put("autoReply", p.autoReply()).put("forwards", new JSONArray(p.forwards())).put("filters", p.filters());
        // The mailbox's forwards already do what the alias will do: they are the proposed destinations.
        List<String> proposals = new ArrayList<>(new LinkedHashSet<>(p.forwards()));
        proposals.removeIf(x -> x.equals(s.address()));
        return o.put("possible", true).put("losses", losses).put("proposals", new JSONArray(proposals))
                .put("alreadyForwarded", already).put("copy", copy).put("towardsHere", towardsHere(s))
                .put("mail", mail(s.mail(), zone)).put("folder", mailFolder(s.address()))
                .put("fingerprint", fingerprint(s));
    }

    /**
     * The requested destinations, checked: valid, different from the address, existing if they are on the
     * panel's domains, and without a loop leading back to the address. Throws IllegalArgumentException
     * with the reason.
     */
    public static List<String> destinations(AddressState s, JSONArray requests, Network network) throws SQLException {
        String address = s.address();
        List<String> d = new ArrayList<>();
        for (int k = 0; requests != null && k < requests.length(); k++) {
            String x = requests.optString(k, "").trim().toLowerCase(Locale.ROOT);
            if (x.isEmpty() || d.contains(x)) continue;
            if (!validAddress(x)) throw org.daemoxcp.mail.util.ShownException.Argument.of("server.convert.badAddress", java.util.Map.of("x", String.valueOf(x)));
            if (x.equals(address))
                throw org.daemoxcp.mail.util.ShownException.Argument.of("server.convert.selfDest", java.util.Map.of("a", String.valueOf(address)));
            d.add(x);
        }
        if (d.isEmpty()) throw org.daemoxcp.mail.util.ShownException.Argument.of("server.convert.needDest", java.util.Map.of("a", String.valueOf(address)));
        if (d.size() > MAX_DESTINATIONS) throw org.daemoxcp.mail.util.ShownException.Argument.of("server.convert.maxDest", java.util.Map.of("n", String.valueOf(MAX_DESTINATIONS)));
        for (String x : d) {
            String dom = domain(x);
            if (network.panelDomain(dom) && !network.receives(x) && network.activeDestinations(x).isEmpty()
                    && network.activeDestinations("@" + dom).isEmpty())
                throw org.daemoxcp.mail.util.ShownException.Argument.of("server.convert.deadDest", java.util.Map.of("x", String.valueOf(x)));
        }
        // Afterwards, mail for the address will go to the new destinations and to those it already has.
        Set<String> all = new LinkedHashSet<>(d);
        for (MailDatabase.Alias a : s.withThisSource()) if (a.active && !a.destination.equals(address)) all.add(a.destination);
        for (String x : all) {
            String round = round(x, address, network);
            if (round != null)
                throw org.daemoxcp.mail.util.ShownException.Argument.of("server.convert.loop", java.util.Map.of("x", String.valueOf(x), "a", String.valueOf(address), "loop", String.valueOf(round)));
        }
        return d;
    }

    /** The path from one address to the other following the active aliases, or null if there is none. */
    static String round(String from, String to, Network network) throws SQLException {
        Deque<List<String>> queue = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        queue.add(List.of(from));
        seen.add(from);
        while (!queue.isEmpty() && seen.size() < 1000) {
            List<String> route = queue.poll();
            for (String next : network.activeDestinations(route.get(route.size() - 1))) {
                List<String> s = new ArrayList<>(route);
                s.add(next);
                if (next.equals(to)) return String.join(" -> ", s);
                if (seen.add(next)) queue.add(s);
            }
        }
        return null;
    }

    // ===================== For the page =====================

    private static JSONArray towardsHere(AddressState s) {
        JSONArray v = new JSONArray();
        for (MailDatabase.Alias a : s.towardsHere())
            if (!a.source.equals(s.address())) v.put(new JSONObject().put("source", a.source).put("active", a.active));
        return v;
    }

    private static JSONObject mail(MailContent p, ZoneId zone) {
        JSONObject o = new JSONObject().put("present", p.present()).put("messages", p.messages()).put("atLeast", p.atLeast())
                .put("bytes", p.totalBytes()).put("size", size(p.totalBytes())).put("filters", p.filters());
        if (p.lastMs() > 0) o.put("last", ISO.format(Instant.ofEpochMilli(p.lastMs()).atZone(zone)));
        return o;
    }

    static String size(long b) {
        if (b < 1024) return b + " byte";
        if (b < 1024L * 1024) return String.format(Locale.ITALY, "%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format(Locale.ITALY, "%.1f MB", b / (1024.0 * 1024));
        return String.format(Locale.ITALY, "%.2f GB", b / (1024.0 * 1024 * 1024));
    }
}
