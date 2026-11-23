package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The periodic report as an email: subject, text and HTML, from the data already collected.
 *
 * Pure function: it receives the data (UpdateManager.reportData plus the entries the report adds)
 * and returns the message, without touching the system. So it is tested on the Mac with data written
 * by hand and on the VM with the real ones, and the two forms, text and HTML, come from the same
 * sections: they cannot say different things.
 *
 * How it is made, so that whoever receives it understands it in ten seconds:
 *  - the SUBJECT names the server and the most important thing to do ("[mail.example.org] Urgent:
 *    Apply 2 security fixes, and 1 more"), not "1 thing to do";
 *  - at the top, a status line and the things to do, most urgent first, each with its urgency
 *    WRITTEN (not only a color), what happened and where in the panel it is done;
 *  - below, the full status for whoever wants to check;
 *  - at the bottom, why it arrives and how to change or stop it.
 */
public final class ReportMail {

    private ReportMail() {}

    /**
     * Who receives it, in which language, and whether the report goes out on its own or someone asked for it
     * from the panel.
     */
    public record Context(String lang, String server, String recipient, boolean automatic,
                          String frequency, ZonedDateTime when) {}

    // ===================== the subject =====================

    /** Urgent means "immediately" or "urgent": the items with urgency 0 and 1. */
    static boolean urgent(JSONObject item) { return item.optInt("urgency", 9) <= 1; }

    /** The short title of an entry; for entries without a title (old ones or from others), the whole text. */
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

    /** key.one or key.other depending on the number, which goes in as {n}. */
    static String plural(String lang, String key, long n, Map<String, ?> params) {
        Map<String, Object> values = new java.util.HashMap<>(params);
        values.put("n", n);
        return I18n.t(lang, key + (n == 1 ? ".one" : ".other"), values);
    }

    // ===================== the sections =====================

    /** A piece of a section: name/value rows, a sentence, or a list with its label. */
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

    /** The full status, section by section: the same ones for the text and for the HTML. */
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
                // The key is "arch" (operatingSystem): with "architecture" the report always wrote "?".
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

        // --- vulnerabilities ---
        // First the age of the data: the numbers come from the vulnerability database and from the catalog
        // of the packages ALREADY on the server, and saying how old they are is the only thing that
        // tells a measurement apart from a number that looks like a measurement.
        {
            List<Block> b = new ArrayList<>();
            long gv = d.optLong("vulnDbDays", -1), gc = d.optLong("catalogDays", -1);
            String db = (gv < 0 ? I18n.t(lang, "mail.report.fact.ageUnknown")
                         : gv == 0 ? I18n.t(lang, "mail.report.fact.updatedToday")
                         : I18n.t(lang, "mail.report.fact.daysAgo", Map.of("n", gv)))
                    + " " + (d.optBoolean("vulnDbUpdatedNow", false)
                             ? I18n.t(lang, "mail.report.fact.downloadedNow") : I18n.t(lang, "mail.report.fact.notDownloadedNow"));
            // For the catalog we say when it was PUBLISHED on the pkg server (see PkgCatalog).
            String catalog = (gc < 0 ? I18n.t(lang, "mail.report.fact.catalogUnknown")
                              : I18n.t(lang, "mail.report.fact.published",
                                       Map.of("howMuch", PkgCatalog.howMuch(gc), "date", d.optString("catalogDate"))))
                    + (d.optBoolean("refreshedCatalog", false) ? ", " + I18n.t(lang, "mail.report.fact.checkedNow") : "");
            b.add(new Facts(List.of(new String[]{I18n.t(lang, "mail.report.fact.vulnDb"), db},
                                    new String[]{I18n.t(lang, "mail.report.fact.catalog"), catalog})));
            // Several repositories, one without a catalog, or no date: the whole sentence, which says which one
            // and why.
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
            // If the count does not add up it is said BEFORE the list: a partial list read as
            // complete is worse than no list.
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

        // --- certificate ---
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

        // --- services ---
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

        // --- libraries ---
        if (d.has("missingLibraries")) {
            JSONArray broken = d.optJSONArray("missingLibraries");
            out.add(new Section(I18n.t(lang, "mail.report.section.libraries"), List.of(new Note(
                    broken == null || broken.length() == 0
                            ? I18n.t(lang, "mail.report.librariesOk")
                            : I18n.t(lang, "mail.report.librariesMissing", Map.of("n", broken.length()))))));
        }

        // --- space ---
        if (d.has("space")) {
            String df = d.optString("space", "").trim();
            // "zroot/ROOT/default  29G  5.1G  24G  18%  /": the df(1) line put into words.
            String[] f = df.split("\\s+");
            Block b = f.length == 6 && f[4].endsWith("%")
                    ? new Facts(List.<String[]>of(new String[]{I18n.t(lang, "mail.report.fact.disk", Map.of("mount", f[5])),
                        I18n.t(lang, "mail.report.fact.diskUse", Map.of("used", f[4], "free", f[3], "size", f[1]))}))
                    : new Note(df.isEmpty() ? "-" : df);
            out.add(new Section(I18n.t(lang, "mail.report.section.space"), List.of(b)));
        }

        // --- boot environments ---
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

    // ===================== the message =====================

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

        // --- text ---
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

    /** The first titles, separated by semicolons, for the preview line of the list. */
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
