package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Il rapporto periodico come email: oggetto, testo e HTML, dai dati gia' raccolti.
 *
 * Funzione pura: riceve i dati (UpdateManager.reportData piu' le voci che aggiunge il rapporto)
 * e restituisce il messaggio, senza toccare il sistema. Cosi' si prova sul Mac con dati scritti
 * a mano e sulla VM con quelli veri, e le due forme — testo e HTML — nascono dalle stesse
 * sezioni: non possono dire cose diverse.
 *
 * Com'e' fatto, perche' chi lo riceve capisca in dieci secondi:
 *  - l'OGGETTO dice il server e la cosa piu' importante da fare ("[mail.example.org] Urgent:
 *    Apply 2 security fixes, and 1 more"), non "1 thing to do";
 *  - in cima, una riga di stato e le cose da fare, dalla piu' urgente, ognuna con l'urgenza
 *    SCRITTA (non solo un colore), cosa e' successo e dove si fa nel pannello;
 *  - sotto, lo stato completo per chi vuole controllare;
 *  - in fondo, perche' arriva e come si cambia o si ferma.
 */
public final class ReportMail {

    private ReportMail() {}

    /** Chi riceve, in che lingua, e se il rapporto parte da solo o l'ha chiesto qualcuno dal pannello. */
    public record Context(String lang, String server, String recipient, boolean automatic,
                          String frequency, ZonedDateTime when) {}

    // ===================== l'oggetto =====================

    /** Urgente vuol dire "subito" o "urgente": le voci con urgenza 0 e 1. */
    static boolean urgent(JSONObject item) { return item.optInt("urgency", 9) <= 1; }

    /** Il titolo breve di una voce; per le voci senza titolo (vecchie o di altri), il testo intero. */
    static String title(JSONObject item) {
        String t = item.optString("title", "");
        return t.isEmpty() ? item.optString("what", "") : t;
    }

    static String subject(Context c, JSONArray toDo) {
        String lang = c.lang();
        String server = c.server().isEmpty() ? I18n.t(lang, "mail.report.unnamedServer") : c.server();
        String date = I18n.t(lang, "mail.report.subject.date", Map.of("date", PanelMail.longDate(lang, c.when())));
        int n = toDo == null ? 0 : toDo.length();
        if (n == 0)
            return I18n.t(lang, "mail.report.subject.none", Map.of("server", server, "date", date));
        JSONObject first = toDo.getJSONObject(0);
        String more = n == 1 ? "" : plural(lang, "mail.report.subject.more", n - 1, Map.of());
        return I18n.t(lang, urgent(first) ? "mail.report.subject.urgent" : "mail.report.subject.todo",
                Map.of("server", server, "title", title(first), "more", more, "date", date));
    }

    /** chiave.one o chiave.other secondo il numero, che entra come {n}. */
    static String plural(String lang, String key, long n, Map<String, ?> params) {
        Map<String, Object> values = new java.util.HashMap<>(params);
        values.put("n", n);
        return I18n.t(lang, key + (n == 1 ? ".one" : ".other"), values);
    }

    // ===================== le sezioni =====================

    /** Un pezzo di sezione: righe nome/valore, una frase, o un elenco con la sua etichetta. */
    sealed interface Block permits Facts, Note, Bullets {}
    record Facts(List<String[]> rows) implements Block {}
    record Note(String text) implements Block {}
    record Bullets(String label, List<String> lines) implements Block {}
    record Section(String title, List<Block> blocks) {}

    private static List<String> strings(JSONArray a) {
        List<String> l = new ArrayList<>();
        for (int i = 0; a != null && i < a.length(); i++) l.add(a.optString(i));
        return l;
    }

    /** Lo stato completo, sezione per sezione: le stesse per il testo e per l'HTML. */
    static List<Section> sections(String lang, JSONObject d) {
        List<Section> out = new ArrayList<>();

        // --- sistema ---
        JSONObject os = d.optJSONObject("system");
        JSONObject branch = d.optJSONObject("branch");
        if (os != null || branch != null) {
            List<String[]> rows = new ArrayList<>();
            if (os != null) {
                rows.add(new String[]{I18n.t(lang, "mail.report.fact.installed"), os.optString("installedKernel", "?")});
                rows.add(new String[]{I18n.t(lang, "mail.report.fact.running"), os.optString("runningKernel", "?")});
                rows.add(new String[]{I18n.t(lang, "mail.report.fact.userland"), os.optString("userland", "?")});
                // La chiave e' "arch" (operatingSystem): con "architecture" il rapporto ha sempre scritto "?".
                rows.add(new String[]{I18n.t(lang, "mail.report.fact.architecture"), os.optString("arch", "?")});
                long days = d.optLong("daysToEndOfSupport", -1);
                rows.add(new String[]{I18n.t(lang, "mail.report.fact.endOfSupport"), os.optString("endOfSupport", "?")
                        + (days >= 0 ? " " + I18n.t(lang, "mail.report.fact.inDays", Map.of("n", days)) : "")});
            }
            if (branch != null)
                rows.add(new String[]{I18n.t(lang, "mail.report.fact.branch"), branch.optString("branch", "?")});
            out.add(new Section(I18n.t(lang, "mail.report.section.system"), List.of(new Facts(rows))));
        }

        // --- pacchetti ---
        if (d.has("totalPackages")) {
            List<Block> b = new ArrayList<>();
            b.add(new Facts(List.of(
                    new String[]{I18n.t(lang, "mail.report.fact.packagesInstalled"), String.valueOf(d.optInt("totalPackages"))},
                    new String[]{I18n.t(lang, "mail.report.fact.packagesProtected"), String.valueOf(d.optInt("lockedPackageCount"))},
                    new String[]{I18n.t(lang, "mail.report.fact.packagesUpdatable"), String.valueOf(d.optInt("packagesWithUpdate"))})));
            List<String> upd = strings(d.optJSONArray("toUpdate"));
            if (!upd.isEmpty()) b.add(new Bullets(I18n.t(lang, "mail.report.list.toUpdate"), upd));
            out.add(new Section(I18n.t(lang, "mail.report.section.packages"), b));
        }

        // --- vulnerabilita' ---
        // Prima l'eta' dei dati: i numeri escono dal database delle vulnerabilita' e dal catalogo
        // dei pacchetti GIA' presenti sul server, e dire quanto sono vecchi e' l'unica cosa che
        // distingue una misura da un numero che sembra una misura.
        {
            List<Block> b = new ArrayList<>();
            long gv = d.optLong("vulnDbDays", -1), gc = d.optLong("catalogDays", -1);
            String db = (gv < 0 ? I18n.t(lang, "mail.report.fact.ageUnknown")
                         : gv == 0 ? I18n.t(lang, "mail.report.fact.updatedToday")
                         : I18n.t(lang, "mail.report.fact.daysAgo", Map.of("n", gv)))
                    + " " + (d.optBoolean("vulnDbUpdatedNow", false)
                             ? I18n.t(lang, "mail.report.fact.downloadedNow") : I18n.t(lang, "mail.report.fact.notDownloadedNow"));
            // Del catalogo si dice quando e' stato PUBBLICATO sul server di pkg (vedi PkgCatalog).
            String catalog = (gc < 0 ? I18n.t(lang, "mail.report.fact.catalogUnknown")
                              : I18n.t(lang, "mail.report.fact.published",
                                       Map.of("howMuch", PkgCatalog.howMuch(gc), "date", d.optString("catalogDate"))))
                    + (d.optBoolean("refreshedCatalog", false) ? ", " + I18n.t(lang, "mail.report.fact.checkedNow") : "");
            b.add(new Facts(List.of(new String[]{I18n.t(lang, "mail.report.fact.vulnDb"), db},
                                    new String[]{I18n.t(lang, "mail.report.fact.catalog"), catalog})));
            // Piu' repository, uno senza catalogo, o nessuna data: la frase intera, che dice quale e perche'.
            JSONObject cat = d.optJSONObject("catalog");
            if (cat != null) {
                int found = 0;
                JSONArray rep = cat.optJSONArray("repository");
                for (int i = 0; rep != null && i < rep.length(); i++)
                    if (rep.getJSONObject(i).optBoolean("found")) found++;
                JSONArray missing = cat.optJSONArray("missing");
                if ((gc < 0 || found > 1 || (missing != null && missing.length() > 0)) && !cat.optString("note").isEmpty())
                    b.add(new Note(cat.optString("note")));
            }
            // Se il conto non torna lo si dice PRIMA dell'elenco: un elenco parziale letto come
            // completo e' peggio di nessun elenco.
            String mismatch = d.optString("vulnCountMismatch", "");
            if (!mismatch.isEmpty()) b.add(new Note(I18n.t(lang, "mail.report.warning", Map.of("text", mismatch))));
            List<String> unparsed = strings(d.optJSONArray("vulnNotUnderstood"));
            if (!unparsed.isEmpty()) b.add(new Bullets(I18n.t(lang, "mail.report.list.unparsed"), unparsed));
            List<String> withFix = strings(d.optJSONArray("vulnWithRemedy"));
            List<String> withoutFix = strings(d.optJSONArray("vulnWithoutRemedy"));
            if (withFix.isEmpty() && withoutFix.isEmpty()) b.add(new Note(I18n.t(lang, "mail.report.vulnNone")));
            if (!withFix.isEmpty()) b.add(new Bullets(I18n.t(lang, "mail.report.list.withFix"), withFix));
            if (!withoutFix.isEmpty()) b.add(new Bullets(I18n.t(lang, "mail.report.list.withoutFix"), withoutFix));
            out.add(new Section(I18n.t(lang, "mail.report.section.vulns"), b));
        }

        // --- certificato ---
        JSONObject cert = d.optJSONObject("certificate");
        if (cert != null) {
            List<Block> b = new ArrayList<>();
            if (!cert.optString("problem").isEmpty()) {
                b.add(new Note(cert.optString("problem")));
            } else {
                String expiry = cert.optBoolean("expired")
                        ? I18n.t(lang, "mail.report.fact.certExpired", Map.of("date", cert.optString("expiresOn", "?")))
                        : I18n.t(lang, "mail.report.fact.certExpiresIn",
                                 Map.of("n", cert.optInt("days"), "date", cert.optString("expiresOn", "?")));
                b.add(new Facts(List.of(
                        new String[]{I18n.t(lang, "mail.report.fact.certName"), cert.optString("name", "-")},
                        new String[]{I18n.t(lang, "mail.report.fact.certIssuer"), cert.optString("issuer", "-")},
                        new String[]{I18n.t(lang, "mail.report.fact.certExpiry"), expiry})));
            }
            out.add(new Section(I18n.t(lang, "mail.report.section.cert"), b));
        }

        // --- servizi ---
        JSONArray sv = d.optJSONArray("services");
        if (sv != null) {
            int active = 0;
            for (int i = 0; i < sv.length(); i++) if (sv.getJSONObject(i).optBoolean("active")) active++;
            List<Block> b = new ArrayList<>();
            b.add(new Facts(List.<String[]>of(new String[]{I18n.t(lang, "mail.report.fact.servicesRunning"),
                    I18n.t(lang, "mail.report.fact.nOfTotal", Map.of("n", active, "total", sv.length()))})));
            List<String> down = strings(d.optJSONArray("inactiveServices"));
            if (!down.isEmpty()) b.add(new Bullets(I18n.t(lang, "mail.report.list.notRunning"), down));
            out.add(new Section(I18n.t(lang, "mail.report.section.services"), b));
        }

        // --- librerie ---
        if (d.has("missingLibraries")) {
            JSONArray broken = d.optJSONArray("missingLibraries");
            out.add(new Section(I18n.t(lang, "mail.report.section.libraries"), List.of(new Note(
                    broken == null || broken.length() == 0
                            ? I18n.t(lang, "mail.report.librariesOk")
                            : I18n.t(lang, "mail.report.librariesMissing", Map.of("n", broken.length()))))));
        }

        // --- spazio ---
        if (d.has("space")) {
            String df = d.optString("space", "").trim();
            // "zroot/ROOT/default  29G  5.1G  24G  18%  /": la riga di df(1) detta in parole.
            String[] f = df.split("\\s+");
            Block b = f.length == 6 && f[4].endsWith("%")
                    ? new Facts(List.<String[]>of(new String[]{I18n.t(lang, "mail.report.fact.disk", Map.of("mount", f[5])),
                        I18n.t(lang, "mail.report.fact.diskUse", Map.of("used", f[4], "free", f[3], "size", f[1]))}))
                    : new Note(df.isEmpty() ? "-" : df);
            out.add(new Section(I18n.t(lang, "mail.report.section.space"), List.of(b)));
        }

        // --- ambienti di avvio ---
        JSONObject be = d.optJSONObject("environments");
        if (be != null && be.optBoolean("success")) {
            List<String[]> rows = new ArrayList<>();
            JSONArray el = be.optJSONArray("environments");
            for (int i = 0; el != null && i < el.length(); i++) {
                JSONObject x = el.getJSONObject(i);
                rows.add(new String[]{x.optString("name"), x.optString("state") + " (" + x.optString("space") + ")"});
            }
            if (!rows.isEmpty())
                out.add(new Section(I18n.t(lang, "mail.report.section.waysBack"),
                        List.of(new Note(I18n.t(lang, "mail.report.waysBackNote")), new Facts(rows))));
        }
        return out;
    }

    // ===================== il messaggio =====================

    public static PanelMail.Message message(Context c, JSONObject d) {
        String lang = I18n.normalize(c.lang());
        JSONArray toDo = d.optJSONArray("toDo");
        if (toDo == null) toDo = new JSONArray();
        String subject = subject(c, toDo);
        List<Section> sections = sections(lang, d);

        int n = toDo.length(), urgentCount = 0;
        for (int i = 0; i < n; i++) if (urgent(toDo.getJSONObject(i))) urgentCount++;
        String statusTitle = n == 0 ? I18n.t(lang, "mail.report.status.none")
                : plural(lang, "mail.report.status.count", n, Map.of());
        String statusDetail = n == 0 ? I18n.t(lang, "mail.report.status.noneDetail")
                : urgentCount == 0 ? I18n.t(lang, "mail.report.status.noUrgent")
                : plural(lang, "mail.report.status.urgent", urgentCount, Map.of());
        String kind = !c.automatic() ? I18n.t(lang, "mail.report.kind.onRequest")
                : I18n.t(lang, "mail.report.kind." + switch (c.frequency() == null ? "" : c.frequency()) {
                      case "daily" -> "daily"; case "monthly" -> "monthly"; default -> "weekly"; });
        String when = I18n.t(lang, "mail.report.sentAt", Map.of("kind", kind, "when", PanelMail.longDateTime(lang, c.when())));
        String server = c.server().isEmpty() ? I18n.t(lang, "mail.report.unnamedServer") : c.server();
        String footerWhy = I18n.t(lang, c.automatic() ? "mail.report.footer.automatic" : "mail.report.footer.onRequest",
                Map.of("server", server, "recipient", c.recipient()));
        String footerHow = I18n.t(lang, "mail.report.footer.how");
        String whereLabel = I18n.t(lang, "mail.report.where");

        // --- testo ---
        StringBuilder t = new StringBuilder();
        t.append(I18n.t(lang, "mail.common.product")).append(" - ").append(server).append('\n')
         .append(I18n.t(lang, "mail.report.title")).append('\n')
         .append(when).append("\n\n")
         .append(statusTitle.toUpperCase(PanelMail.localeOf(lang))).append('\n')
         .append(PanelMail.wrap(statusDetail, 72, "")).append('\n');
        if (n > 0) {
            t.append(PanelMail.textHeading(I18n.t(lang, "mail.report.todoHeading")));
            for (int i = 0; i < n; i++) {
                JSONObject x = toDo.getJSONObject(i);
                String label = I18n.t(lang, "mail.report.urgency." + Math.min(3, Math.max(0, x.optInt("urgency", 3))));
                t.append(PanelMail.wrap((i + 1) + ". [" + label + "] " + title(x), 72, "").stripTrailing()).append('\n');
                String what = x.optString("what", "");
                if (!what.isEmpty() && !what.equals(title(x))) t.append(PanelMail.wrap(what, 72, "   "));
                if (!x.optString("where").isEmpty())
                    t.append(PanelMail.wrap(whereLabel + " " + x.optString("where"), 72, "   "));
                t.append('\n');
            }
        }
        t.append(PanelMail.textHeading(I18n.t(lang, "mail.report.stateHeading"))).append('\n');
        for (Section s : sections) {
            t.append(s.title().toUpperCase(PanelMail.localeOf(lang))).append('\n');
            for (Block b : s.blocks()) t.append(text(b));
            t.append('\n');
        }
        t.append("-- \n").append(PanelMail.wrap(footerWhy, 72, "")).append(PanelMail.wrap(footerHow, 72, ""));

        // --- HTML ---
        StringBuilder h = new StringBuilder();
        h.append(PanelMail.h1(I18n.t(lang, "mail.report.title")))
         .append(PanelMail.muted(when))
         .append(PanelMail.banner(n == 0 ? PanelMail.Tone.GOOD : PanelMail.Tone.of(toDo.getJSONObject(0).optInt("urgency", 3)),
                 statusTitle, statusDetail));
        if (n > 0) {
            h.append(PanelMail.h2(I18n.t(lang, "mail.report.todoHeading")));
            for (int i = 0; i < n; i++) {
                JSONObject x = toDo.getJSONObject(i);
                int u = Math.min(3, Math.max(0, x.optInt("urgency", 3)));
                h.append(PanelMail.item(PanelMail.Tone.of(u), I18n.t(lang, "mail.report.urgency." + u), title(x),
                        x.optString("what", ""), whereLabel, x.optString("where", "").replace(" -> ", " → ")));
            }
        }
        h.append(PanelMail.h2(I18n.t(lang, "mail.report.stateHeading")));
        for (Section s : sections) {
            h.append(PanelMail.h3(s.title()));
            for (Block b : s.blocks()) h.append(html(b));
        }
        String footer = PanelMail.footerLine(footerWhy) + PanelMail.footerLine(footerHow);

        String preheader = n == 0 ? I18n.t(lang, "mail.report.preheader.none", Map.of("server", server))
                : statusTitle + ": " + titles(toDo, 3, lang);
        String html = PanelMail.page(lang, subject, preheader, c.server(), h.toString(), footer);
        return new PanelMail.Message(subject, t.toString(), html, lang);
    }

    /** I primi titoli, separati da punto e virgola, per la riga di anteprima dell'elenco. */
    private static String titles(JSONArray toDo, int max, String lang) {
        List<String> l = new ArrayList<>();
        for (int i = 0; i < toDo.length() && i < max; i++) l.add(title(toDo.getJSONObject(i)));
        String s = String.join("; ", l);
        if (toDo.length() > max) s += plural(lang, "mail.report.subject.more", toDo.length() - max, Map.of());
        return s;
    }

    private static String text(Block b) {
        StringBuilder t = new StringBuilder();
        switch (b) {
            case Facts f -> {
                int w = 0;
                for (String[] r : f.rows()) w = Math.max(w, r[0].length());
                for (String[] r : f.rows()) {
                    String head = "  " + r[0] + ":" + " ".repeat(Math.max(1, w - r[0].length() + 2));
                    String value = r[1] == null || r[1].isBlank() ? "-" : r[1];
                    t.append(PanelMail.wrap(value, 72, head, " ".repeat(head.length())));
                }
            }
            case Note n -> t.append(PanelMail.wrap(n.text(), 72, "  "));
            case Bullets l -> {
                t.append(PanelMail.wrap(l.label(), 72, "  "));
                for (String x : l.lines()) t.append(PanelMail.wrap("- " + x, 72, "    ", "      "));
            }
        }
        return t.toString();
    }

    private static String html(Block b) {
        return switch (b) {
            case Facts f -> PanelMail.facts(null, f.rows());
            case Note n -> PanelMail.muted(n.text());
            case Bullets l -> "<p style=\"margin:8px 0 2px;font-size:14px;line-height:20px;\">" + PanelMail.esc(l.label()) + "</p>\n"
                              + PanelMail.list(l.lines());
        };
    }
}
