package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.webserver.SecurityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.sql.SQLException;
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
import java.util.stream.Stream;

/**
 * Trasformare un alias in una casella vera, e una casella in un alias: solo quando si puo'
 * davvero, e dicendo prima che cosa cambia.
 *
 * Come arriva la posta qui (scripts/FullMailServerScript, DovecotConfig):
 *  - Postfix chiede al database prima gli alias attivi (aliases.source), poi le caselle attive che
 *    ricevono (mailboxes.email): un indirizzo con alias attivi va alle loro destinazioni, e alla
 *    casella solo se fra queste c'e' lui stesso;
 *  - la posta di una casella sta in /var/vmail/dominio/nome, i suoi filtri compilati in
 *    /var/mail/sieve/dominio/nome. Il database non la contiene: eliminare la riga della casella
 *    non la tocca, e una casella nuova con lo stesso indirizzo la ritroverebbe.
 *
 * Alias -> casella si puo' se l'indirizzo ha un nome prima della @ (una raccolta "@dominio" no),
 * il dominio e' del pannello e l'indirizzo non e' gia' una casella. Serve una password: una casella
 * vera la vuole, per IMAP e SMTP. Le destinazioni di prima o se ne vanno, o restano e la casella ne
 * tiene una copia. Se sul disco c'e' la posta di una casella di prima con lo stesso indirizzo, si
 * sceglie: ritrovarla, o metterla da parte e partire vuoti. I filtri rimasti di quella casella non
 * devono valere per la nuova.
 *
 * Casella -> alias si puo' verso destinazioni valide, diverse dall'indirizzo, che non riportino a
 * lui (sarebbe un giro senza fine, che Postfix rifiuta) e che, se stanno su un dominio del pannello,
 * esistano: casella che riceve, alias attivo o raccolta. Si perdono il login, la risposta
 * automatica, i filtri e gli inoltri della casella, e l'anteprima li elenca. La posta gia' arrivata
 * resta dov'e'.
 *
 * L'anteprima consegna un'fingerprint dello stato: se fra anteprima e conferma qualcosa cambia (un
 * alias, la casella, la posta che compare sul disco), la trasformazione non parte.
 */
public final class AddressTransform {

    private AddressTransform() {}

    /** Dove Dovecot tiene la posta e i filtri. Le prove li spostano in una cartella temporanea. */
    static Path vmail = Path.of("/var/vmail");
    static Path sieve = Path.of("/var/mail/sieve");
    /** La posta messa da parte: sotto /var/vmail (stesso disco, lo spostamento e' istantaneo), con un nome che nessun dominio puo' avere. */
    static Path archive() { return vmail.resolve(".archivio-pannello"); }

    static final int MAX_DESTINATIONS = 20;
    /** Oltre, il conto dei messaggi si ferma e si dice "almeno". */
    static final int MAX_COUNTED_FILES = 200_000;

    private static final DateTimeFormatter ARCHIVE_NAME = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    // ===================== Lo stato di un indirizzo =====================

    /** La posta sul disco per un indirizzo. */
    public record MailContent(boolean present, long messages, boolean atLeast, long totalBytes, long lastMs, boolean filters) {
        static final MailContent NONE = new MailContent(false, 0, false, 0, 0, false);
    }

    /** Cio' che una casella ha e un alias no. */
    public record Losses(boolean autoReply, List<String> forwards, int filters) {}

    /** Quello che conta per decidere, letto dal database e dal disco. */
    public record AddressState(String address, boolean panelDomain, MailDatabase.Mailbox mailbox,
                        List<MailDatabase.Alias> withThisSource, List<MailDatabase.Alias> towardsHere,
                        MailContent mail, Losses losses) {}

    /** Le domande sulle destinazioni, a cui risponde il database (o la prova). */
    public interface Network {
        boolean panelDomain(String domain) throws SQLException;
        /** Una casella attiva che riceve: Postfix la conosce. */
        boolean receives(String address) throws SQLException;
        /** Le destinazioni degli alias attivi con questa sorgente. */
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

    // ===================== Indirizzi e percorsi =====================

    /** Un indirizzo come lo vuole il pannello: i caratteri di isValidEmail, 254 in tutto, 64 prima della @. */
    public static boolean validAddress(String a) {
        return a != null && a.length() <= 254 && SecurityUtils.isValidEmail(a) && a.indexOf('@') <= 64;
    }

    /** Solo ASCII stampabile: la lista bianca dei testi liberi (il nome di una casella). */
    public static boolean printable(String t) {
        for (int k = 0; k < t.length(); k++) if (t.charAt(k) < 0x20 || t.charAt(k) > 0x7E) return false;
        return true;
    }

    /** Dove sta la posta dell'indirizzo, per dirlo all'amministratore. */
    public static String mailFolder(String address) {
        Path p = folder(vmail, address);
        return p == null ? "" : p.toString();
    }

    static String domain(String a) {
        int at = a == null ? -1 : a.lastIndexOf('@');
        return at < 0 ? null : a.substring(at + 1);
    }

    /**
     * La cartella della posta di un indirizzo, o null se il nome non si puo' usare come percorso.
     * isValidEmail ammette anche "..@dominio": qui un nome cosi' uscirebbe da /var/vmail.
     */
    static Path folder(Path root, String address) {
        if (!validAddress(address)) return null;
        String name = address.substring(0, address.lastIndexOf('@'));
        String dom = domain(address);
        if (name.startsWith(".") || dom.startsWith(".")) return null;
        Path p = root.resolve(dom).resolve(name).normalize();
        return p.startsWith(root) && !p.equals(root) ? p : null;
    }

    /** Quanta posta c'e' sul disco per l'indirizzo: i messaggi sono i file in cur/ e new/, anche nelle cartelle. */
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
                String padre = parentFolder.getFileName().toString();
                if (!padre.equals("cur") && !padre.equals("new")) continue;
                try {
                    BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);
                    if (!a.isRegularFile()) continue;
                    messages++;
                    totalBytes += a.size();
                    last = Math.max(last, a.lastModifiedTime().toMillis());
                } catch (IOException ignored) {
                    continue;   // un file sparito mentre si conta
                }
                if (messages >= MAX_COUNTED_FILES) { atLeast = true; break; }
            }
        } catch (IOException | java.io.UncheckedIOException e) {
            // Illeggibile: c'e', ma non si sa quanta.
            return new MailContent(true, 0, true, 0, 0, hasFilters);
        }
        return new MailContent(true, messages, atLeast, totalBytes, last, hasFilters);
    }

    /**
     * Mette da parte posta e filtri dell'indirizzo, in /var/vmail/.archive-pannello/dominio/nome-DATA.
     * Restituisce le coppie {da, a} spostate, per rimetterle a posto se il resto non riesce.
     */
    public static List<Path[]> archive(String address, long nowMs) throws IOException {
        List<Path[]> done = new ArrayList<>();
        String when = ARCHIVE_NAME.format(Instant.ofEpochMilli(nowMs).atOffset(ZoneOffset.UTC));
        String name = address.substring(0, address.lastIndexOf('@'));
        Path base = archive().resolve(domain(address));
        try {
            Path mail = folder(vmail, address);
            if (mail != null && Files.isDirectory(mail)) {
                Files.createDirectories(base);
                Path dest = free(base.resolve(name + "-" + when));
                Files.move(mail, dest, StandardCopyOption.ATOMIC_MOVE);
                done.add(new Path[] { mail, dest });
            }
            Path filters = folder(sieve, address);
            if (filters != null && Files.isDirectory(filters)) {
                Files.createDirectories(base);
                Path dest = free(base.resolve(name + "-" + when + "-filtri"));
                // Su un altro disco ATOMIC_MOVE non si puo': allora si copia e si toglie, come fa mv.
                try {
                    Files.move(filters, dest, StandardCopyOption.ATOMIC_MOVE);
                } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                    Files.move(filters, dest);
                }
                done.add(new Path[] { filters, dest });
            }
            return done;
        } catch (IOException e) {
            restore(done);
            throw e;
        }
    }

    private static Path free(Path p) {
        Path q = p;
        for (int k = 2; Files.exists(q); k++) q = p.resolveSibling(p.getFileName() + "-" + k);
        return q;
    }

    /** Rimette dov'erano le cartelle spostate da archive(), dall'ultima. */
    public static void restore(List<Path[]> moved) {
        for (int k = moved.size() - 1; k >= 0; k--) {
            try {
                Files.move(moved.get(k)[1], moved.get(k)[0]);
            } catch (IOException ignored) { /* resta in archivio: meglio li' che perso */ }
        }
    }

    // ===================== Impronta =====================

    /** Lo stato che l'anteprima ha mostrato. Il numero dei messaggi non conta: in una casella cambia di continuo. */
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

    // ===================== Alias -> casella =====================

    /** Perche' l'indirizzo non puo' diventare una casella, o null se puo'. */
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
        JSONObject o = new JSONObject().put("indirizzo", s.address());
        String no = noMailboxReason(s);
        if (no != null) return o.put("possibile", false).put("reason", no);
        JSONArray dest = new JSONArray();
        boolean copy = false;
        for (MailDatabase.Alias a : s.withThisSource()) {
            if (a.destination.equals(s.address())) { copy = true; continue; }
            dest.put(new JSONObject().put("destinazione", a.destination).put("attivo", a.active));
        }
        return o.put("possibile", true).put("destinazioni", dest).put("copia", copy)
                .put("versoQui", towardsHere(s)).put("posta", mail(s.mail(), zone)).put("fingerprint", fingerprint(s));
    }

    // ===================== Casella -> alias =====================

    public static JSONObject previewToAlias(AddressState s, ZoneId zone) {
        JSONObject o = new JSONObject().put("indirizzo", s.address());
        MailDatabase.Mailbox m = s.mailbox();
        if (m == null) return o.put("possibile", false).put("reason", I18n.tr("server.convert.notMailbox", java.util.Map.of("a", String.valueOf(s.address()))));
        Losses p = s.losses() == null ? new Losses(false, List.of(), 0) : s.losses();
        JSONArray already = new JSONArray();
        boolean copy = false;
        for (MailDatabase.Alias a : s.withThisSource()) {
            if (a.destination.equals(s.address())) { copy = true; continue; }
            already.put(new JSONObject().put("destinazione", a.destination).put("attivo", a.active));
        }
        JSONObject losses = new JSONObject()
                .put("ultimoAccesso", m.lastLogin == null ? "" : ISO.format(m.lastLogin.toInstant().atZone(zone)))
                .put("soloInvio", !m.receiveEnabled).put("attiva", m.active)
                .put("rispostaAutomatica", p.autoReply()).put("inoltri", new JSONArray(p.forwards())).put("filtri", p.filters());
        // Gli inoltri della casella fanno gia' quello che fara' l'alias: sono le destinazioni proposte.
        List<String> proposals = new ArrayList<>(new LinkedHashSet<>(p.forwards()));
        proposals.removeIf(x -> x.equals(s.address()));
        return o.put("possibile", true).put("perdite", losses).put("proposte", new JSONArray(proposals))
                .put("giaInoltrata", already).put("copia", copy).put("versoQui", towardsHere(s))
                .put("posta", mail(s.mail(), zone)).put("cartella", mailFolder(s.address()))
                .put("fingerprint", fingerprint(s));
    }

    /**
     * Le destinazioni chieste, controllate: valide, diverse dall'indirizzo, esistenti se sono sui
     * domini del pannello, e senza un giro che torni all'indirizzo. Lancia IllegalArgumentException
     * con il motivo.
     */
    public static List<String> destinations(AddressState s, JSONArray requests, Network network) throws SQLException {
        String address = s.address();
        List<String> d = new ArrayList<>();
        for (int k = 0; requests != null && k < requests.length(); k++) {
            String x = requests.optString(k, "").trim().toLowerCase(Locale.ROOT);
            if (x.isEmpty() || d.contains(x)) continue;
            if (!validAddress(x)) throw new IllegalArgumentException(I18n.tr("server.convert.badAddress", java.util.Map.of("x", String.valueOf(x))));
            if (x.equals(address))
                throw new IllegalArgumentException(I18n.tr("server.convert.selfDest", java.util.Map.of("a", String.valueOf(address))));
            d.add(x);
        }
        if (d.isEmpty()) throw new IllegalArgumentException(I18n.tr("server.convert.needDest", java.util.Map.of("a", String.valueOf(address))));
        if (d.size() > MAX_DESTINATIONS) throw new IllegalArgumentException(I18n.tr("server.convert.maxDest", java.util.Map.of("n", String.valueOf(MAX_DESTINATIONS))));
        for (String x : d) {
            String dom = domain(x);
            if (network.panelDomain(dom) && !network.receives(x) && network.activeDestinations(x).isEmpty()
                    && network.activeDestinations("@" + dom).isEmpty())
                throw new IllegalArgumentException(I18n.tr("server.convert.deadDest", java.util.Map.of("x", String.valueOf(x))));
        }
        // Dopo, la posta per l'indirizzo andra' alle destinazioni nuove e a quelle che ha gia'.
        Set<String> all = new LinkedHashSet<>(d);
        for (MailDatabase.Alias a : s.withThisSource()) if (a.active && !a.destination.equals(address)) all.add(a.destination);
        for (String x : all) {
            String round = round(x, address, network);
            if (round != null)
                throw new IllegalArgumentException(I18n.tr("server.convert.loop", java.util.Map.of("x", String.valueOf(x), "a", String.valueOf(address), "loop", String.valueOf(round))));
        }
        return d;
    }

    /** La strada da un indirizzo all'altro seguendo gli alias attivi, o null se non c'e'. */
    static String round(String da, String a, Network network) throws SQLException {
        Deque<List<String>> queue = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        queue.add(List.of(da));
        seen.add(da);
        while (!queue.isEmpty() && seen.size() < 1000) {
            List<String> route = queue.poll();
            for (String next : network.activeDestinations(route.get(route.size() - 1))) {
                List<String> s = new ArrayList<>(route);
                s.add(next);
                if (next.equals(a)) return String.join(" -> ", s);
                if (seen.add(next)) queue.add(s);
            }
        }
        return null;
    }

    // ===================== Per la pagina =====================

    private static JSONArray towardsHere(AddressState s) {
        JSONArray v = new JSONArray();
        for (MailDatabase.Alias a : s.towardsHere())
            if (!a.source.equals(s.address())) v.put(new JSONObject().put("sorgente", a.source).put("attivo", a.active));
        return v;
    }

    private static JSONObject mail(MailContent p, ZoneId zone) {
        JSONObject o = new JSONObject().put("presente", p.present()).put("messaggi", p.messages()).put("almeno", p.atLeast())
                .put("byte", p.totalBytes()).put("dimensione", size(p.totalBytes())).put("filtri", p.filters());
        if (p.lastMs() > 0) o.put("ultimo", ISO.format(Instant.ofEpochMilli(p.lastMs()).atZone(zone)));
        return o;
    }

    static String size(long b) {
        if (b < 1024) return b + " byte";
        if (b < 1024L * 1024) return String.format(Locale.ITALY, "%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format(Locale.ITALY, "%.1f MB", b / (1024.0 * 1024));
        return String.format(Locale.ITALY, "%.2f GB", b / (1024.0 * 1024 * 1024));
    }
}
