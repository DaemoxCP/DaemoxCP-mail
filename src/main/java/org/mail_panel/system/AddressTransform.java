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
 * L'anteprima consegna un'impronta dello stato: se fra anteprima e conferma qualcosa cambia (un
 * alias, la casella, la posta che compare sul disco), la trasformazione non parte.
 */
public final class AddressTransform {

    private AddressTransform() {}

    /** Dove Dovecot tiene la posta e i filtri. Le prove li spostano in una cartella temporanea. */
    static Path vmail = Path.of("/var/vmail");
    static Path sieve = Path.of("/var/mail/sieve");
    /** La posta messa da parte: sotto /var/vmail (stesso disco, lo spostamento e' istantaneo), con un nome che nessun dominio puo' avere. */
    static Path archivio() { return vmail.resolve(".archivio-pannello"); }

    static final int MASSIMO_DESTINAZIONI = 20;
    /** Oltre, il conto dei messaggi si ferma e si dice "almeno". */
    static final int MASSIMO_FILE_CONTATI = 200_000;

    private static final DateTimeFormatter NOME_ARCHIVIO = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    // ===================== Lo stato di un indirizzo =====================

    /** La posta sul disco per un indirizzo. */
    public record Posta(boolean presente, long messaggi, boolean almeno, long byteTotali, long ultimoMs, boolean filtri) {
        static final Posta NESSUNA = new Posta(false, 0, false, 0, 0, false);
    }

    /** Cio' che una casella ha e un alias no. */
    public record Perdite(boolean rispostaAutomatica, List<String> inoltri, int filtri) {}

    /** Quello che conta per decidere, letto dal database e dal disco. */
    public record Stato(String indirizzo, boolean dominioDelPannello, MailDatabase.Mailbox mailbox,
                        List<MailDatabase.Alias> conQuestaSorgente, List<MailDatabase.Alias> versoQui,
                        Posta posta, Perdite perdite) {}

    /** Le domande sulle destinazioni, a cui risponde il database (o la prova). */
    public interface Rete {
        boolean dominioDelPannello(String dominio) throws SQLException;
        /** Una casella attiva che riceve: Postfix la conosce. */
        boolean riceve(String indirizzo) throws SQLException;
        /** Le destinazioni degli alias attivi con questa sorgente. */
        List<String> destinazioniAttive(String sorgente) throws SQLException;
    }

    public static Stato stato(MailDatabase db, String indirizzo) throws SQLException {
        String dominio = dominio(indirizzo);
        boolean delPannello = dominio != null && db.getDomainByName(dominio) != null;
        MailDatabase.Mailbox m = db.getMailboxByEmail(indirizzo);
        Perdite perdite = null;
        if (m != null) {
            MailDatabase.AutoResponder ar = db.getAutoResponder(m.id);
            List<String> inoltri = new ArrayList<>();
            for (MailDatabase.ForwardingRule f : db.getForwardingRules(m.id)) if (f.enabled) inoltri.add(f.destination);
            perdite = new Perdite(ar != null && ar.enabled, inoltri, db.getSieveFilters(m.id).size());
        }
        return new Stato(indirizzo, delPannello, m, db.getAliasesBySource(indirizzo), db.getAliasesByDestination(indirizzo),
                posta(indirizzo), perdite);
    }

    public static Rete rete(MailDatabase db) {
        return new Rete() {
            @Override public boolean dominioDelPannello(String d) throws SQLException { return db.getDomainByName(d) != null; }
            @Override public boolean riceve(String a) throws SQLException {
                MailDatabase.Mailbox m = db.getMailboxByEmail(a);
                return m != null && m.active && m.receiveEnabled;
            }
            @Override public List<String> destinazioniAttive(String s) throws SQLException {
                List<String> d = new ArrayList<>();
                for (MailDatabase.Alias a : db.getAliasesBySource(s)) if (a.active) d.add(a.destination);
                return d;
            }
        };
    }

    // ===================== Indirizzi e percorsi =====================

    /** Un indirizzo come lo vuole il pannello: i caratteri di isValidEmail, 254 in tutto, 64 prima della @. */
    public static boolean indirizzoValido(String a) {
        return a != null && a.length() <= 254 && SecurityUtils.isValidEmail(a) && a.indexOf('@') <= 64;
    }

    /** Solo ASCII stampabile: la lista bianca dei testi liberi (il nome di una casella). */
    public static boolean stampabile(String t) {
        for (int k = 0; k < t.length(); k++) if (t.charAt(k) < 0x20 || t.charAt(k) > 0x7E) return false;
        return true;
    }

    /** Dove sta la posta dell'indirizzo, per dirlo all'amministratore. */
    public static String cartellaPosta(String indirizzo) {
        Path p = cartella(vmail, indirizzo);
        return p == null ? "" : p.toString();
    }

    static String dominio(String a) {
        int at = a == null ? -1 : a.lastIndexOf('@');
        return at < 0 ? null : a.substring(at + 1);
    }

    /**
     * La cartella della posta di un indirizzo, o null se il nome non si puo' usare come percorso.
     * isValidEmail ammette anche "..@dominio": qui un nome cosi' uscirebbe da /var/vmail.
     */
    static Path cartella(Path radice, String indirizzo) {
        if (!indirizzoValido(indirizzo)) return null;
        String nome = indirizzo.substring(0, indirizzo.lastIndexOf('@'));
        String dom = dominio(indirizzo);
        if (nome.startsWith(".") || dom.startsWith(".")) return null;
        Path p = radice.resolve(dom).resolve(nome).normalize();
        return p.startsWith(radice) && !p.equals(radice) ? p : null;
    }

    /** Quanta posta c'e' sul disco per l'indirizzo: i messaggi sono i file in cur/ e new/, anche nelle cartelle. */
    public static Posta posta(String indirizzo) {
        Path dir = cartella(vmail, indirizzo);
        Path filtri = cartella(sieve, indirizzo);
        boolean ciSonoFiltri = filtri != null && Files.isRegularFile(filtri.resolve(".dovecot.sieve"));
        if (dir == null || !Files.isDirectory(dir)) return new Posta(false, 0, false, 0, 0, ciSonoFiltri);
        long messaggi = 0, byteTotali = 0, ultimo = 0;
        boolean almeno = false;
        try (Stream<Path> s = Files.walk(dir, 3)) {
            java.util.Iterator<Path> it = s.iterator();
            while (it.hasNext()) {
                Path p = it.next();
                Path cartellaPadre = p.getParent();
                if (cartellaPadre == null || cartellaPadre.getFileName() == null) continue;
                String padre = cartellaPadre.getFileName().toString();
                if (!padre.equals("cur") && !padre.equals("new")) continue;
                try {
                    BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);
                    if (!a.isRegularFile()) continue;
                    messaggi++;
                    byteTotali += a.size();
                    ultimo = Math.max(ultimo, a.lastModifiedTime().toMillis());
                } catch (IOException ignorata) {
                    continue;   // un file sparito mentre si conta
                }
                if (messaggi >= MASSIMO_FILE_CONTATI) { almeno = true; break; }
            }
        } catch (IOException | java.io.UncheckedIOException e) {
            // Illeggibile: c'e', ma non si sa quanta.
            return new Posta(true, 0, true, 0, 0, ciSonoFiltri);
        }
        return new Posta(true, messaggi, almeno, byteTotali, ultimo, ciSonoFiltri);
    }

    /**
     * Mette da parte posta e filtri dell'indirizzo, in /var/vmail/.archivio-pannello/dominio/nome-DATA.
     * Restituisce le coppie {da, a} spostate, per rimetterle a posto se il resto non riesce.
     */
    public static List<Path[]> archivia(String indirizzo, long adessoMs) throws IOException {
        List<Path[]> fatti = new ArrayList<>();
        String quando = NOME_ARCHIVIO.format(Instant.ofEpochMilli(adessoMs).atOffset(ZoneOffset.UTC));
        String nome = indirizzo.substring(0, indirizzo.lastIndexOf('@'));
        Path base = archivio().resolve(dominio(indirizzo));
        try {
            Path posta = cartella(vmail, indirizzo);
            if (posta != null && Files.isDirectory(posta)) {
                Files.createDirectories(base);
                Path dest = libero(base.resolve(nome + "-" + quando));
                Files.move(posta, dest, StandardCopyOption.ATOMIC_MOVE);
                fatti.add(new Path[] { posta, dest });
            }
            Path filtri = cartella(sieve, indirizzo);
            if (filtri != null && Files.isDirectory(filtri)) {
                Files.createDirectories(base);
                Path dest = libero(base.resolve(nome + "-" + quando + "-filtri"));
                // Su un altro disco ATOMIC_MOVE non si puo': allora si copia e si toglie, come fa mv.
                try {
                    Files.move(filtri, dest, StandardCopyOption.ATOMIC_MOVE);
                } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                    Files.move(filtri, dest);
                }
                fatti.add(new Path[] { filtri, dest });
            }
            return fatti;
        } catch (IOException e) {
            rimetti(fatti);
            throw e;
        }
    }

    private static Path libero(Path p) {
        Path q = p;
        for (int k = 2; Files.exists(q); k++) q = p.resolveSibling(p.getFileName() + "-" + k);
        return q;
    }

    /** Rimette dov'erano le cartelle spostate da archivia(), dall'ultima. */
    public static void rimetti(List<Path[]> spostate) {
        for (int k = spostate.size() - 1; k >= 0; k--) {
            try {
                Files.move(spostate.get(k)[1], spostate.get(k)[0]);
            } catch (IOException ignorata) { /* resta in archivio: meglio li' che perso */ }
        }
    }

    // ===================== Impronta =====================

    /** Lo stato che l'anteprima ha mostrato. Il numero dei messaggi non conta: in una casella cambia di continuo. */
    public static String impronta(Stato s) {
        StringBuilder t = new StringBuilder(s.indirizzo()).append('|').append(s.dominioDelPannello()).append('|');
        MailDatabase.Mailbox m = s.mailbox();
        t.append(m == null ? "-" : m.id + "," + m.email + "," + m.active + "," + m.receiveEnabled).append('|');
        for (MailDatabase.Alias a : ordinati(s.conQuestaSorgente())) t.append(a.id).append(':').append(a.destination).append(':').append(a.active).append(';');
        t.append('|');
        for (MailDatabase.Alias a : ordinati(s.versoQui())) t.append(a.id).append(':').append(a.source).append(':').append(a.active).append(';');
        t.append('|').append(s.posta().presente()).append('|');
        Perdite p = s.perdite();
        t.append(p == null ? "-" : p.rispostaAutomatica() + "," + String.join(",", p.inoltri()) + "," + p.filtri());
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(t.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<MailDatabase.Alias> ordinati(List<MailDatabase.Alias> l) {
        List<MailDatabase.Alias> o = new ArrayList<>(l);
        o.sort((x, y) -> Integer.compare(x.id, y.id));
        return o;
    }

    // ===================== Alias -> casella =====================

    /** Perche' l'indirizzo non puo' diventare una casella, o null se puo'. */
    public static String motivoNoCasella(Stato s) {
        String a = s.indirizzo();
        if (a != null && a.startsWith("@"))
            return I18n.tr("server.convert.catchAll", java.util.Map.of("a", String.valueOf(a)));
        if (!indirizzoValido(a) || cartella(vmail, a) == null) return I18n.tr("server.convert.notMailboxAddress");
        if (!s.dominioDelPannello()) return I18n.tr("server.convert.notPanelDomain", java.util.Map.of("a", String.valueOf(a)));
        if (s.mailbox() != null) return I18n.tr("server.convert.alreadyMailbox", java.util.Map.of("a", String.valueOf(a)));
        if (s.conQuestaSorgente().isEmpty()) return I18n.tr("server.convert.noAlias", java.util.Map.of("a", String.valueOf(a)));
        return null;
    }

    public static JSONObject anteprimaACasella(Stato s, ZoneId zona) {
        JSONObject o = new JSONObject().put("indirizzo", s.indirizzo());
        String no = motivoNoCasella(s);
        if (no != null) return o.put("possibile", false).put("motivo", no);
        JSONArray dest = new JSONArray();
        boolean copia = false;
        for (MailDatabase.Alias a : s.conQuestaSorgente()) {
            if (a.destination.equals(s.indirizzo())) { copia = true; continue; }
            dest.put(new JSONObject().put("destinazione", a.destination).put("attivo", a.active));
        }
        return o.put("possibile", true).put("destinazioni", dest).put("copia", copia)
                .put("versoQui", versoQui(s)).put("posta", posta(s.posta(), zona)).put("impronta", impronta(s));
    }

    // ===================== Casella -> alias =====================

    public static JSONObject anteprimaAAlias(Stato s, ZoneId zona) {
        JSONObject o = new JSONObject().put("indirizzo", s.indirizzo());
        MailDatabase.Mailbox m = s.mailbox();
        if (m == null) return o.put("possibile", false).put("motivo", I18n.tr("server.convert.notMailbox", java.util.Map.of("a", String.valueOf(s.indirizzo()))));
        Perdite p = s.perdite() == null ? new Perdite(false, List.of(), 0) : s.perdite();
        JSONArray gia = new JSONArray();
        boolean copia = false;
        for (MailDatabase.Alias a : s.conQuestaSorgente()) {
            if (a.destination.equals(s.indirizzo())) { copia = true; continue; }
            gia.put(new JSONObject().put("destinazione", a.destination).put("attivo", a.active));
        }
        JSONObject perdite = new JSONObject()
                .put("ultimoAccesso", m.lastLogin == null ? "" : ISO.format(m.lastLogin.toInstant().atZone(zona)))
                .put("soloInvio", !m.receiveEnabled).put("attiva", m.active)
                .put("rispostaAutomatica", p.rispostaAutomatica()).put("inoltri", new JSONArray(p.inoltri())).put("filtri", p.filtri());
        // Gli inoltri della casella fanno gia' quello che fara' l'alias: sono le destinazioni proposte.
        List<String> proposte = new ArrayList<>(new LinkedHashSet<>(p.inoltri()));
        proposte.removeIf(x -> x.equals(s.indirizzo()));
        return o.put("possibile", true).put("perdite", perdite).put("proposte", new JSONArray(proposte))
                .put("giaInoltrata", gia).put("copia", copia).put("versoQui", versoQui(s))
                .put("posta", posta(s.posta(), zona)).put("cartella", cartellaPosta(s.indirizzo()))
                .put("impronta", impronta(s));
    }

    /**
     * Le destinazioni chieste, controllate: valide, diverse dall'indirizzo, esistenti se sono sui
     * domini del pannello, e senza un giro che torni all'indirizzo. Lancia IllegalArgumentException
     * con il motivo.
     */
    public static List<String> destinazioni(Stato s, JSONArray richieste, Rete rete) throws SQLException {
        String indirizzo = s.indirizzo();
        List<String> d = new ArrayList<>();
        for (int k = 0; richieste != null && k < richieste.length(); k++) {
            String x = richieste.optString(k, "").trim().toLowerCase(Locale.ROOT);
            if (x.isEmpty() || d.contains(x)) continue;
            if (!indirizzoValido(x)) throw new IllegalArgumentException(I18n.tr("server.convert.badAddress", java.util.Map.of("x", String.valueOf(x))));
            if (x.equals(indirizzo))
                throw new IllegalArgumentException(I18n.tr("server.convert.selfDest", java.util.Map.of("a", String.valueOf(indirizzo))));
            d.add(x);
        }
        if (d.isEmpty()) throw new IllegalArgumentException(I18n.tr("server.convert.needDest", java.util.Map.of("a", String.valueOf(indirizzo))));
        if (d.size() > MASSIMO_DESTINAZIONI) throw new IllegalArgumentException(I18n.tr("server.convert.maxDest", java.util.Map.of("n", String.valueOf(MASSIMO_DESTINAZIONI))));
        for (String x : d) {
            String dom = dominio(x);
            if (rete.dominioDelPannello(dom) && !rete.riceve(x) && rete.destinazioniAttive(x).isEmpty()
                    && rete.destinazioniAttive("@" + dom).isEmpty())
                throw new IllegalArgumentException(I18n.tr("server.convert.deadDest", java.util.Map.of("x", String.valueOf(x))));
        }
        // Dopo, la posta per l'indirizzo andra' alle destinazioni nuove e a quelle che ha gia'.
        Set<String> tutte = new LinkedHashSet<>(d);
        for (MailDatabase.Alias a : s.conQuestaSorgente()) if (a.active && !a.destination.equals(indirizzo)) tutte.add(a.destination);
        for (String x : tutte) {
            String giro = giro(x, indirizzo, rete);
            if (giro != null)
                throw new IllegalArgumentException(I18n.tr("server.convert.loop", java.util.Map.of("x", String.valueOf(x), "a", String.valueOf(indirizzo), "loop", String.valueOf(giro))));
        }
        return d;
    }

    /** La strada da un indirizzo all'altro seguendo gli alias attivi, o null se non c'e'. */
    static String giro(String da, String a, Rete rete) throws SQLException {
        Deque<List<String>> coda = new ArrayDeque<>();
        Set<String> visti = new HashSet<>();
        coda.add(List.of(da));
        visti.add(da);
        while (!coda.isEmpty() && visti.size() < 1000) {
            List<String> strada = coda.poll();
            for (String prossimo : rete.destinazioniAttive(strada.get(strada.size() - 1))) {
                List<String> s = new ArrayList<>(strada);
                s.add(prossimo);
                if (prossimo.equals(a)) return String.join(" -> ", s);
                if (visti.add(prossimo)) coda.add(s);
            }
        }
        return null;
    }

    // ===================== Per la pagina =====================

    private static JSONArray versoQui(Stato s) {
        JSONArray v = new JSONArray();
        for (MailDatabase.Alias a : s.versoQui())
            if (!a.source.equals(s.indirizzo())) v.put(new JSONObject().put("sorgente", a.source).put("attivo", a.active));
        return v;
    }

    private static JSONObject posta(Posta p, ZoneId zona) {
        JSONObject o = new JSONObject().put("presente", p.presente()).put("messaggi", p.messaggi()).put("almeno", p.almeno())
                .put("byte", p.byteTotali()).put("dimensione", dimensione(p.byteTotali())).put("filtri", p.filtri());
        if (p.ultimoMs() > 0) o.put("ultimo", ISO.format(Instant.ofEpochMilli(p.ultimoMs()).atZone(zona)));
        return o;
    }

    static String dimensione(long b) {
        if (b < 1024) return b + " byte";
        if (b < 1024L * 1024) return String.format(Locale.ITALY, "%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format(Locale.ITALY, "%.1f MB", b / (1024.0 * 1024));
        return String.format(Locale.ITALY, "%.2f GB", b / (1024.0 * 1024 * 1024));
    }
}
