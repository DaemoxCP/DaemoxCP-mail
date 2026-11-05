package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Le email del pannello: busta, codifiche e contenuto.
 *
 * Il difetto del 05/11/2026: il committente riceve dal server vero un'email da "Control panel"
 * con oggetto "[freebsd] 1 thing to do - 05/11/2026". Ne' quale pannello, ne' quale server
 * ("freebsd" e' hostname(1), il server si chiama mail.domain-b.test), ne' che cosa fare. In piu'
 * il piede del rapporto mostrava un "\n" scritto per davvero, e il messaggio era solo testo.
 *
 * Qui si prova, senza toccare il sistema:
 *  - la busta: mittente "Mail control panel (server)", oggetto in RFC 2047 entro i 75 caratteri
 *    per parola, Date, Message-ID, Content-Language, Auto-Submitted, multipart con testo e HTML
 *    in quoted-printable che si decodificano esattamente in cio' che si e' scritto;
 *  - il rapporto: l'oggetto dice server e cosa fare, ogni voce ha urgenza scritta, titolo,
 *    spiegazione e posto nel pannello, in testo e in HTML, nelle due lingue, senza chiavi di
 *    lingua scoperte, senza "\n" letterali, con l'HTML che non lascia passare markup dai dati;
 *  - i codici: il codice nel corpo ma non nell'oggetto ne' nell'anteprima, l'IP di chi l'ha
 *    chiesto solo nei messaggi che vanno all'amministratore, mai nel cambio dell'email.
 *
 * Si lancia sulla VM come le altre:
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PanelMailTest
 * Con -Dpanelmail.dump=<cartella> scrive anche i messaggi composti (.eml), per guardarli in un
 * programma di posta.
 */
public class PanelMailTest {

    private static int failed = 0, passed = 0;

    private static final ZonedDateTime WHEN = ZonedDateTime.of(2026, 11, 5, 20, 15, 0, 0, ZoneId.of("UTC"));
    private static final String SERVER = "mail.example.org";

    public static void main(String[] args) throws Exception {
        envelope();
        report();
        codes();
        texts();
        dump();
        System.out.println("\n" + passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }

    // ===================== la busta =====================

    static void envelope() {
        System.out.println("== la busta ==");
        String long1 = "Una riga lunghissima con lettere accentate: perché, più, città, è, à, ò, ù — "
                + "e ancora testo ".repeat(12) + "fine.";
        String tricky = "a=b\ttab finale \nspazio finale \n\n=3D non decodificato\n" + long1 + "\nultima";
        String qp = PanelMail.quotedPrintable(tricky);
        check("quoted-printable: nessuna riga oltre 76", qp.lines().allMatch(l -> l.length() <= 76));
        check("quoted-printable: solo ASCII stampabile", qp.chars().allMatch(c -> c == '\r' || c == '\n' || (c >= 32 && c < 127)));
        check("quoted-printable: si decodifica esattamente nel testo di partenza", qpDecode(qp).equals(tricky.replace("\r\n", "\n")));
        check("quoted-printable: lo spazio a fine riga diventa =20", qp.contains("finale=20\r\n"));
        check("quoted-printable: '=' diventa =3D", qp.contains("a=3Db"));

        String subject = "[mail.esempio.it] Urgente: Applica 2 correzioni di sicurezza, e altre 2 cose - rapporto del 5 novembre 2026 — città";
        String h = PanelMail.encodeHeader(subject, 9);
        List<String> words = new ArrayList<>();
        Matcher m = Pattern.compile("=\\?UTF-8\\?B\\?([A-Za-z0-9+/=]*)\\?=").matcher(h);
        StringBuilder decoded = new StringBuilder();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        while (m.find()) { words.add(m.group()); bytes.writeBytes(Base64.getDecoder().decode(m.group(1))); }
        decoded.append(bytes.toString(StandardCharsets.UTF_8));
        check("RFC 2047: piu' parole codificate per un oggetto lungo", words.size() > 1);
        check("RFC 2047: ogni parola codificata entro 75 caratteri", words.stream().allMatch(w -> w.length() <= 75));
        check("RFC 2047: le parole si ricompongono nell'oggetto esatto", decoded.toString().equals(subject));
        check("RFC 2047: righe piegate con CRLF e spazio", h.contains("\r\n ") && !h.contains("\n\n"));
        check("RFC 2047: un oggetto ASCII resta com'e'", PanelMail.encodeHeader("[mail.example.org] All good", 9).equals("[mail.example.org] All good"));
        check("intestazione: un a capo nell'oggetto non apre un'intestazione nuova",
                !PanelMail.encodeHeader("x\r\nBcc: someone@example.com", 9).contains("\n"));

        String from = PanelMail.address(PanelMail.senderName("en", SERVER), "no-reply@example.org");
        check("mittente: \"Mail control panel (mail.example.org)\" <no-reply@example.org>",
                from.equals("\"Mail control panel (mail.example.org)\" <no-reply@example.org>"));
        check("mittente: le virgolette nel nome si proteggono", PanelMail.address("A \"B\"", "x@example.org").equals("\"A \\\"B\\\"\" <x@example.org>"));
        check("mittente: un nome non ASCII va in RFC 2047", PanelMail.address("Pannello è", "x@example.org").startsWith("=?UTF-8?B?"));
        check("mittente senza server: solo il nome del pannello", PanelMail.senderName("en", "").equals("Mail control panel"));
        check("mittente in italiano", PanelMail.senderName("it", SERVER).equals("Pannello di controllo della posta (mail.example.org)"));

        PanelMail.Message msg = new PanelMail.Message("Prova è", tricky, "<p>città</p>", "it");
        String raw = PanelMail.compose(PanelMail.senderName("it", SERVER), "no-reply@example.org", "admin@example.org", msg,
                "report.1@example.org", WHEN);
        String head = raw.substring(0, raw.indexOf("\r\n\r\n"));
        check("busta: From con il nome del pannello e del server", head.contains("From: \"Pannello di controllo della posta (mail.example.org)\" <no-reply@example.org>"));
        check("busta: Date in forma RFC 5322", head.contains("\r\nDate: Thu, 5 Nov 2026 20:15:00 +0000"));
        check("busta: Message-ID", head.contains("\r\nMessage-ID: <report.1@example.org>"));
        check("busta: Content-Language", head.contains("\r\nContent-Language: it"));
        check("busta: Auto-Submitted e X-Auto-Response-Suppress", head.contains("\r\nAuto-Submitted: auto-generated") && head.contains("\r\nX-Auto-Response-Suppress: All"));
        Matcher bm = Pattern.compile("boundary=\"([^\"]+)\"").matcher(head);
        check("busta: multipart/alternative con il suo separatore", head.contains("Content-Type: multipart/alternative;") && bm.find());
        String boundary = bm.group(1);
        String[] parts = raw.split("--" + Pattern.quote(boundary));
        check("busta: due parti e la chiusura", parts.length == 4 && parts[3].startsWith("--"));
        check("busta: prima il testo, poi l'HTML (i programmi mostrano l'ultima che sanno leggere)",
                parts[1].contains("Content-Type: text/plain; charset=UTF-8") && parts[2].contains("Content-Type: text/html; charset=UTF-8"));
        check("busta: il testo si decodifica in cio' che si e' scritto", qpDecode(body(parts[1])).equals(tricky));
        check("busta: l'HTML si decodifica in cio' che si e' scritto", qpDecode(body(parts[2])).equals("<p>città</p>"));
        check("busta: nessuna riga oltre 78 caratteri", raw.lines().allMatch(l -> l.length() <= 78));
        check("busta: righe chiuse da CRLF", !raw.replace("\r\n", "").contains("\n"));

        // Le intestazioni lunghe vere: il nome del pannello in italiano con un server lungo, un
        // oggetto ASCII di cento caratteri, un oggetto accentato di cento.
        PanelMail.Message longOnes = new PanelMail.Message(
                "[mail.example.org] Urgent: Restart the stopped services: dovecot, and 3 more - report of 5 November 2026",
                "x", "<p>x</p>", "it");
        String raw2 = PanelMail.compose(PanelMail.senderName("it", "posta-principale.esempio-molto-lungo.it"), "no-reply@esempio-molto-lungo.it",
                "admin@example.org", longOnes, "report.2@example.org", WHEN);
        String head2 = raw2.substring(0, raw2.indexOf("\r\n\r\n"));
        check("intestazioni lunghe: nessuna riga oltre 78", head2.lines().allMatch(l -> l.length() <= 78));
        check("intestazioni lunghe: il mittente va a capo prima dell'indirizzo",
                head2.contains("(posta-principale.esempio-molto-lungo.it)\"\r\n <no-reply@esempio-molto-lungo.it>"));
        check("intestazioni lunghe: l'oggetto ripiegato si ricompone identico",
                unfold(head2, "Subject").equals(longOnes.subject()));
        String raw3 = PanelMail.compose("x", "a@example.org", "b@example.org", new PanelMail.Message(subject, "x", "y", "it"),
                "report.3@example.org", WHEN);
        check("intestazioni lunghe: anche l'oggetto codificato sta nei 78", raw3.substring(0, raw3.indexOf("\r\n\r\n")).lines().allMatch(l -> l.length() <= 78));
    }

    /** Il valore di un'intestazione con le righe ripiegate riunite (RFC 5322, 2.2.3). */
    private static String unfold(String head, String name) {
        String u = head.replace("\r\n ", " ").replace("\r\n\t", "\t");
        for (String l : u.split("\r\n")) if (l.startsWith(name + ": ")) return l.substring(name.length() + 2);
        return null;
    }

    private static String body(String part) {
        String p = part.substring(part.indexOf("\r\n\r\n") + 4);
        return p.endsWith("\r\n") ? p.substring(0, p.length() - 2) : p;
    }

    static String qpDecode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String t = s.replace("=\r\n", "").replace("\r\n", "\n");
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '=' && i + 2 < t.length()) {
                out.write(Integer.parseInt(t.substring(i + 1, i + 3), 16));
                i += 2;
            } else out.write(c);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    // ===================== il rapporto =====================

    static JSONObject data(JSONArray toDo) {
        return new JSONObject()
                .put("toDo", toDo)
                .put("system", new JSONObject().put("installedKernel", "15.1-RELEASE-p3").put("runningKernel", "15.1-RELEASE-p2")
                        .put("userland", "15.1-RELEASE-p3").put("architecture", "arm64").put("endOfSupport", "31/12/2026"))
                .put("daysToEndOfSupport", 56)
                .put("branch", new JSONObject().put("branch", "quarterly"))
                .put("totalPackages", 143).put("lockedPackageCount", 40).put("packagesWithUpdate", 3)
                .put("toUpdate", new JSONArray().put("nginx 1.30.5,3 -> 1.30.6,3 (protected: pkg upgrade skips it)").put("<script>alert(1)</script> 1 -> 2"))
                .put("vulnDbDays", 0).put("vulnDbUpdatedNow", true).put("catalogDays", 2).put("catalogDate", "03/11/2026")
                .put("refreshedCatalog", true)
                .put("vulnWithRemedy", new JSONArray().put("nginx: 1.30.5,3 -> 1.30.6,3"))
                .put("vulnWithoutRemedy", new JSONArray())
                .put("certificate", new JSONObject().put("name", "mail.example.org").put("issuer", "R11 (Let's Encrypt)")
                        .put("expired", false).put("days", 10).put("expiresOn", "15 November 2026"))
                .put("services", new JSONArray().put(new JSONObject().put("name", "postfix").put("active", true))
                        .put(new JSONObject().put("name", "dovecot").put("active", false)))
                .put("inactiveServices", new JSONArray().put("dovecot"))
                .put("missingLibraries", new JSONArray())
                .put("space", "zroot/ROOT/default   29G   5.1G   24G    18%    /")
                .put("environments", new JSONObject().put("success", true).put("environments", new JSONArray()
                        .put(new JSONObject().put("name", "default").put("space", "4.3G").put("state", "in use now and at the next restart"))));
    }

    static JSONObject item(int urgency, String title, String what, String where) {
        JSONObject o = new JSONObject().put("urgency", urgency).put("what", what).put("where", where);
        if (title != null) o.put("title", title);
        return o;
    }

    static void report() {
        System.out.println("\n== il rapporto ==");
        JSONArray four = new JSONArray()
                .put(item(0, "Restart the stopped services: dovecot", "Services NOT running: dovecot", "Panel home"))
                .put(item(1, "Apply 1 security fix", "1 vulnerable package has a fix available: nginx: 1.30.5,3 -> 1.30.6,3", "Updates -> Guided update of a protected package"))
                .put(item(1, "Renew the TLS certificate (it expires in 10 days)", "The TLS certificate expires in 10 days.", "SSL certificates"))
                .put(item(2, null, "An item from an older producer, without a title.", "Updates"));
        ReportMail.Context en = new ReportMail.Context("en", SERVER, "admin@example.org", true, "weekly", WHEN);
        PanelMail.Message m = ReportMail.message(en, data(four));
        System.out.println("  oggetto: " + m.subject());
        check("oggetto: server, urgenza, la cosa piu' urgente, quante altre, data",
                m.subject().equals("[mail.example.org] Urgent: Restart the stopped services: dovecot, and 3 more - report of 5 November 2026"));
        check("oggetto: niente piu' \"thing to do\" generico ne' data numerica", !m.subject().contains("thing to do") && !m.subject().contains("05/11/2026"));
        for (int i = 0; i < four.length(); i++) {
            JSONObject x = four.getJSONObject(i);
            String title = ReportMail.title(x);
            check("testo: la voce \"" + title + "\" c'e', con il posto nel pannello",
                    flat(m.text()).contains(title) && flat(m.text()).contains(x.getString("where")));
            check("HTML: la voce \"" + title + "\" c'e', con il posto nel pannello",
                    m.html().contains(PanelMail.esc(title)) && m.html().contains(PanelMail.esc(x.getString("where").replace(" -> ", " → "))));
        }
        check("testo: le urgenze scritte, non solo colori", m.text().contains("[Act now]") && m.text().contains("[Urgent]") && m.text().contains("[To do]"));
        check("HTML: le urgenze scritte", m.html().contains(">Act now<") && m.html().contains(">Urgent<") && m.html().contains(">To do<"));
        check("una voce senza titolo usa il suo testo", flat(m.text()).contains("An item from an older producer, without a title."));
        check("stato in cima: quante e quante urgenti", m.text().contains("4 THINGS TO DO") && flat(m.text()).contains("3 are urgent and come first."));
        check("tipo di rapporto e ora con il fuso", m.text().contains("Weekly report, 5 November 2026 at 20:15 UTC"));
        check("le sezioni dello stato, in testo e in HTML", List.of("System", "Packages", "Known vulnerabilities", "TLS certificate",
                "Services", "Libraries", "Disk space", "Ways back (boot environments)").stream()
                .allMatch(s -> m.text().contains(s.toUpperCase()) && m.html().contains(">" + PanelMail.esc(s) + "<")));
        check("spazio: la riga di df detta in parole", flat(m.text()).contains("File system /: 18% used, 24G free of 29G"));
        check("certificato: nome, emittente, scadenza", flat(m.text()).contains("Expiry: in 10 days, on 15 November 2026"));
        check("piede: perche' arriva e come si ferma", flat(m.text()).contains("sent automatically by the mail control panel of mail.example.org to admin@example.org")
                && flat(m.text()).contains("Settings, Periodic email report"));
        check("nessun \\n scritto per davvero (il piede di prima lo mostrava)", !m.text().contains("\\n") && !m.html().contains("\\n"));
        check("testo: nessuna riga oltre 72 colonne, salvo le parole che non si spezzano",
                m.text().lines().allMatch(l -> l.length() <= 72 || !l.trim().contains(" ")));
        check("HTML: i dati non portano markup (<script> dai nomi dei pacchetti)",
                !m.html().contains("<script>") && m.html().contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        check("HTML: lingua dichiarata e un solo h1", m.html().contains("<html lang=\"en\">") && count(m.html(), "<h1") == 1);
        check("HTML: tabelle di impaginazione dichiarate come tali, tabelle di dati con th scope",
                m.html().contains("role=\"presentation\"") && m.html().contains("<th scope=\"row\""));
        check("HTML: nessuna risorsa esterna, nessun collegamento", !m.html().contains("http://") && !m.html().contains("https://")
                && !m.html().contains("<a ") && !m.html().contains("<img") && !m.html().contains("<link"));
        check("HTML: riga di anteprima nascosta con le prime cose da fare",
                m.html().contains("display:none") && m.html().contains("4 things to do: Restart the stopped services: dovecot; Apply 1 security fix;"));

        JSONArray one = new JSONArray().put(item(2, "Update 3 packages", "3 packages have a newer version in the repository.", "Updates -> Maintenance plan"));
        check("oggetto con una voce non urgente", ReportMail.message(en, data(one)).subject()
                .equals("[mail.example.org] To do: Update 3 packages - report of 5 November 2026"));
        PanelMail.Message none = ReportMail.message(en, data(new JSONArray()));
        check("oggetto senza niente da fare", none.subject().equals("[mail.example.org] All good, nothing to do - report of 5 November 2026"));
        check("senza niente da fare lo si dice in una riga", none.text().contains("ALL GOOD: NOTHING TO DO") && !none.text().contains("WHAT TO DO"));

        ReportMail.Context onRequest = new ReportMail.Context("en", SERVER, "admin@example.org", false, "weekly", WHEN);
        PanelMail.Message manual = ReportMail.message(onRequest, data(one));
        check("inviato dal pulsante: lo dice, e non si spaccia per settimanale",
                manual.text().contains("Report sent on request from the panel") && !manual.text().contains("Weekly report"));

        ReportMail.Context it = new ReportMail.Context("it", "mail.esempio.it", "admin@esempio.it", true, "monthly", WHEN);
        PanelMail.Message mi = ReportMail.message(it, data(new JSONArray().put(item(1, "Applica 2 correzioni di sicurezza", "x", "Aggiornamenti")).put(item(3, "Aggiorna il catalogo dei pacchetti", "y", "Aggiornamenti"))));
        System.out.println("  oggetto: " + mi.subject());
        check("italiano: oggetto", mi.subject().equals("[mail.esempio.it] Urgente: Applica 2 correzioni di sicurezza, e un'altra cosa - rapporto del 5 novembre 2026"));
        check("italiano: rapporto mensile, data con il mese per esteso", mi.text().contains("Rapporto mensile, 5 novembre 2026 alle 20:15 UTC"));
        check("italiano: html lang=it", mi.html().contains("<html lang=\"it\">"));

        ReportMail.Context noName = new ReportMail.Context("en", "", "admin@example.org", true, "weekly", WHEN);
        check("senza nome del server: 'mail server', non parentesi vuote", ReportMail.message(noName, data(one)).subject().startsWith("[mail server] "));
    }

    // ===================== i codici =====================

    static void codes() {
        System.out.println("\n== i codici ==");
        for (CodeMail.Kind k : CodeMail.Kind.values()) {
            for (String lang : List.of("en", "it")) {
                PanelMail.Message m = CodeMail.message(k, lang, SERVER, "482913", 10, "203.0.113.7", WHEN);
                String name = k + "/" + lang;
                check(name + ": il codice nel testo e nell'HTML", m.text().contains("482913") && m.html().contains(">482913<"));
                Matcher d = Pattern.compile("\\b(\\d{6})\\b").matcher(m.text());
                check(name + ": la prima cifra da sei nel testo e' il codice (le prove lo cercano cosi')", d.find() && d.group(1).equals("482913"));
                check(name + ": il codice NON nell'oggetto", !m.subject().contains("482913"));
                String pre = m.html().substring(m.html().indexOf("display:none"), m.html().indexOf("</div>", m.html().indexOf("display:none")));
                check(name + ": il codice NON nella riga di anteprima", !pre.contains("482913"));
                check(name + ": l'oggetto dice il server", m.subject().startsWith("[" + SERVER + "] "));
                check(name + ": l'IP di chi l'ha chiesto " + (k == CodeMail.Kind.EMAIL_CHANGE ? "NON c'e' (va a un indirizzo nuovo)" : "c'e'"),
                        (k == CodeMail.Kind.EMAIL_CHANGE) != (m.text().contains("203.0.113.7") && m.html().contains("203.0.113.7")));
                check(name + ": quando e' stato chiesto", m.text().contains(lang.equals("en") ? "5 November 2026 at 20:15 UTC" : "5 novembre 2026 alle 20:15 UTC"));
                check(name + ": validita' in minuti", m.text().contains("10"));
                check(name + ": nessun collegamento", !m.html().contains("<a ") && !m.html().contains("http"));
            }
        }
        PanelMail.Message en = CodeMail.message(CodeMail.Kind.LOGIN, "en", SERVER, "482913", 10, "203.0.113.7", WHEN);
        check("accesso: oggetto", en.subject().equals("[mail.example.org] Your sign-in code for the mail control panel"));
        PanelMail.Message ip6 = CodeMail.message(CodeMail.Kind.LOGIN, "en", SERVER, "482913", 10, "2001:db8:123:456::1", WHEN);
        Matcher d = Pattern.compile("\\b(\\d{6})\\b").matcher(ip6.text());
        check("accesso da IPv6: la prima cifra da sei e' ancora il codice", d.find() && d.group(1).equals("482913"));
    }

    // ===================== i testi =====================

    /**
     * Nessuna chiave di lingua scoperta (I18n.t restituisce la chiave quando il testo manca):
     * si compongono tutte le forme nelle due lingue e si cerca "mail.report." / "mail.code." /
     * "mail.common." nel risultato.
     */
    static void texts() {
        System.out.println("\n== i testi ==");
        Pattern rawKey = Pattern.compile("\\bmail\\.(?:report|code|common)\\.[A-Za-z]");
        List<String> outputs = new ArrayList<>();
        for (String lang : List.of("en", "it")) {
            for (boolean auto : List.of(true, false))
                for (String f : List.of("daily", "weekly", "monthly"))
                    for (JSONArray todo : List.of(new JSONArray(), new JSONArray().put(item(3, "x", "y", "z")),
                            new JSONArray().put(item(0, "a", "b", "c")).put(item(2, "d", "e", "f")))) {
                        PanelMail.Message m = ReportMail.message(new ReportMail.Context(lang, SERVER, "a@example.org", auto, f, WHEN), data(todo));
                        outputs.add(m.subject()); outputs.add(m.text()); outputs.add(m.html());
                    }
            JSONObject d = data(new JSONArray());
            d.put("certificate", new JSONObject().put("name", "x").put("issuer", "y").put("expired", true).put("expiresOn", "1 November 2026"));
            d.put("vulnWithRemedy", new JSONArray()).put("vulnCountMismatch", "z").put("vulnNotUnderstood", new JSONArray().put("q"));
            d.put("missingLibraries", new JSONArray().put("p")).put("vulnDbDays", 3).put("catalogDays", -1).put("space", "strange");
            PanelMail.Message m = ReportMail.message(new ReportMail.Context(lang, "", "a@example.org", true, "weekly", WHEN), d);
            outputs.add(m.subject()); outputs.add(m.text()); outputs.add(m.html());
            for (CodeMail.Kind k : CodeMail.Kind.values()) {
                PanelMail.Message c = CodeMail.message(k, lang, "", "123456", 15, "", WHEN);
                outputs.add(c.subject()); outputs.add(c.text()); outputs.add(c.html());
            }
        }
        List<String> leaks = new ArrayList<>();
        for (String o : outputs) { Matcher x = rawKey.matcher(o); while (x.find()) leaks.add(o.substring(x.start(), Math.min(o.length(), x.start() + 50))); }
        check(outputs.size() + " forme composte: nessuna chiave di lingua scoperta" + (leaks.isEmpty() ? "" : ": " + leaks.subList(0, Math.min(5, leaks.size()))), leaks.isEmpty());
        check("nessuna forma dice ancora soltanto \"Control panel\"",
                outputs.stream().noneMatch(o -> o.matches("(?s).*(?<!Mail )Control panel.*")));
        check("nessuna forma ha una graffa rimasta da un segnaposto", outputs.stream().noneMatch(o -> o.matches("(?s).*\\{[A-Za-z]+\\}.*")));
    }

    /** Con -Dpanelmail.dump=<cartella>: i messaggi composti, da aprire in un programma di posta. */
    static void dump() throws Exception {
        String dir = System.getProperty("panelmail.dump");
        if (dir == null) return;
        java.nio.file.Path d = java.nio.file.Path.of(dir);
        java.nio.file.Files.createDirectories(d);
        JSONArray four = new JSONArray()
                .put(item(0, "Restart the stopped services: dovecot", "Services NOT running: dovecot", "Panel home"))
                .put(item(1, "Apply 1 security fix", "1 vulnerable package has a fix available: nginx: 1.30.5,3 -> 1.30.6,3 (protected: pkg upgrade will not apply this fix)", "Updates -> Guided update of a protected package"))
                .put(item(2, "Update 3 packages", "3 packages have a newer version in the repository.", "Updates -> Maintenance plan"));
        write(d, "report-en.eml", ReportMail.message(new ReportMail.Context("en", SERVER, "admin@example.org", true, "weekly", WHEN), data(four)));
        write(d, "report-none-it.eml", ReportMail.message(new ReportMail.Context("it", SERVER, "admin@example.org", true, "weekly", WHEN), data(new JSONArray())));
        write(d, "code-login-en.eml", CodeMail.message(CodeMail.Kind.LOGIN, "en", SERVER, "482913", 10, "203.0.113.7", WHEN));
        System.out.println("  scritti in " + d);
    }

    private static void write(java.nio.file.Path d, String name, PanelMail.Message m) throws Exception {
        java.nio.file.Files.writeString(d.resolve(name), PanelMail.compose(PanelMail.senderName(m.lang(), SERVER),
                "no-reply@example.org", "admin@example.org", m, "test." + name + "@example.org", WHEN));
    }

    private static String flat(String s) { return s.replaceAll("\\s+", " "); }

    private static int count(String s, String what) {
        int n = 0;
        for (int i = s.indexOf(what); i >= 0; i = s.indexOf(what, i + 1)) n++;
        return n;
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + name);
        if (ok) passed++; else failed++;
    }
}
