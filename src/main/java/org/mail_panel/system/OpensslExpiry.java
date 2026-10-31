package org.mail_panel.system;

import org.json.JSONArray;
import org.mail_panel.i18n.I18n;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/**
 * Quale OpenSSL usa davvero questo server, e per quanto tempo ancora riceve correzioni.
 *
 * Il motivo per cui la domanda non si risponde leggendo le note di rilascio: le note dicono
 * cosa c'era il giorno della release, non cosa gira adesso su QUESTA macchina. Un port
 * installato, un aggiornamento a meta', un sistema piu' vecchio di quel che si crede: sono
 * tutte cose che si vedono solo chiedendo al binario che versione ha.
 *
 * Le date sono quelle della strategia di rilascio ufficiale di OpenSSL, lette il 01/09/2026.
 * Non sono calcolate: sono trascritte, perche' inventare una regola ("ogni LTS dura 5 anni")
 * produrrebbe date plausibili e sbagliate.
 *
 * Attenzione a una distinzione che cambia il verdetto: **OpenSSL della base non e' il port.**
 * Quello della base lo mantiene il progetto FreeBSD, che pubblica correzioni per le release
 * supportate; il port segue il calendario di upstream. Confonderli fa suonare un allarme che
 * non c'e', o tacere uno che c'e'.
 */
public class OpensslExpiry {

    /** ramo -> fine del supporto upstream. Trascritte da openssl-library.org. */
    private static final String[][] DEADLINES = {
        { "4.0",   "2027-05-14", "no"  },
        { "3.6",   "2026-11-01", "no"  },
        { "3.5",   "2030-04-08", "si"  },
        { "3.4",   "2026-10-22", "no"  },
        { "3.3",   "2026-04-09", "no"  },
        { "3.2",   "2025-11-23", "no"  },
        { "3.1",   "2025-03-14", "no"  },
        { "3.0",   "2026-09-07", "si"  },
        { "1.1.1", "2023-09-11", "si"  },
        { "1.0.2", "2019-12-31", "si"  },
    };

    private OpensslExpiry() {}

    /* ===================================================================
     * Parte pura, provabile senza server
     * =================================================================== */

    /** Il ramo di una versione: "3.5.6" -> "3.5", "1.1.1w" -> "1.1.1". */
    public static String branch(String version) {
        if (version == null) return null;
        String v = version.trim();
        if (v.startsWith("1.1.1")) return "1.1.1";
        if (v.startsWith("1.0.2")) return "1.0.2";
        String[] p = v.split("\\.");
        if (p.length < 2) return null;
        String a = digitsOnly(p[0]), b = digitsOnly(p[1]);
        if (a.isEmpty() || b.isEmpty()) return null;
        return a + "." + b;
    }

    private static String digitsOnly(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) { if (!Character.isDigit(c)) break; sb.append(c); }
        return sb.toString();
    }

    /** La data di fine supporto di quel ramo, o null se il ramo non e' in tabella. */
    public static String endOfSupport(String version) {
        String r = branch(version);
        if (r == null) return null;
        for (String[] s : DEADLINES) if (s[0].equals(r)) return s[1];
        return null;
    }

    public static boolean isLts(String version) {
        String r = branch(version);
        if (r == null) return false;
        for (String[] s : DEADLINES) if (s[0].equals(r)) return "si".equals(s[2]);
        return false;
    }

    /** Giorni che mancano. Negativi se la data e' passata. "oggi" si passa: cosi' si prova. */
    public static Long daysLeft(String version, LocalDate today) {
        String f = endOfSupport(version);
        if (f == null || today == null) return null;
        try {
            return ChronoUnit.DAYS.between(today, LocalDate.parse(f));
        } catch (Exception e) {
            return null;
        }
    }

    /** 0 = a posto, 1 = scade presto (entro 90 giorni), 2 = scaduto, 3 = non lo so. */
    public static int urgency(String version, LocalDate today) {
        Long g = daysLeft(version, today);
        if (g == null) return 3;
        if (g < 0) return 2;
        if (g <= 90) return 1;
        return 0;
    }

    /** La versione dentro l'uscita di "openssl version": "OpenSSL 3.5.6 30 Sep 2025" -> 3.5.6 */
    public static String extractVersion(String output) {
        if (output == null) return null;
        for (String line : output.split("\n")) {
            String t = line.trim();
            if (!t.startsWith("OpenSSL") && !t.startsWith("LibreSSL")) continue;
            String[] p = t.split("\\s+");
            if (p.length >= 2 && !p[1].isEmpty() && Character.isDigit(p[1].charAt(0))) return p[1];
        }
        return null;
    }

    /* ===================================================================
     * Parte che interroga il server
     * =================================================================== */

    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        LocalDate today = LocalDate.now();
        r.put("today", today.toString());

        JSONArray found = new JSONArray();
        found.put(review("base", "/usr/bin/openssl", today,
                I18n.tr("server.sslexp.base")));
        found.put(review("port", "/usr/local/bin/openssl", today,
                I18n.tr("server.sslexp.port")));
        r.put("installs", found);

        // Chi vince nel PATH del pannello: e' quello che finirebbe negli script.
        RunResult which = run("sh", "-c", "command -v openssl");
        r.put("inPath", which.code == 0 ? which.output.trim() : "");

        RunResult fv = run("freebsd-version", "-k");
        if (fv.code == 0) r.put("freebsd", fv.output.trim());

        // Il verdetto guarda solo cio' che c'e' davvero.
        int worst = 0;
        boolean something = false;
        for (int i = 0; i < found.length(); i++) {
            JSONObject o = found.getJSONObject(i);
            if (!o.optBoolean("present", false)) continue;
            something = true;
            worst = Math.max(worst, o.optInt("urgency", 3));
        }
        r.put("urgency", something ? worst : 3);
        r.put("note", !something
                ? I18n.tr("server.sslexp.noBinary")
                : worst == 0 ? I18n.tr("server.sslexp.allSupported")
                : worst == 1 ? I18n.tr("server.sslexp.soon")
                : worst == 2 ? I18n.tr("server.sslexp.expired")
                : I18n.tr("server.sslexp.unknownVersion"));
        return r;
    }

    private static JSONObject review(String type, String path, LocalDate today, String whatItMeans) {
        JSONObject o = new JSONObject().put("type", type).put("path", path)
                .put("whatItMeans", whatItMeans);
        RunResult v = run(path, "version");
        if (v.code != 0) return o.put("present", false);

        String version = extractVersion(v.output);
        o.put("present", true).put("output", v.output.trim()).put("version", version == null ? "" : version);
        if (version == null)
            return o.put("urgency", 3)
                    .put("comment", I18n.tr("server.sslexp.unreadable", java.util.Map.of("out", String.valueOf(v.output.trim()))));

        String end = endOfSupport(version);
        Long days = daysLeft(version, today);
        int u = urgency(version, today);
        o.put("branch", branch(version)).put("lts", isLts(version)).put("urgency", u);
        if (end == null)
            return o.put("comment", I18n.tr("server.sslexp.notInTable", java.util.Map.of("b", String.valueOf(branch(version)))));

        o.put("endOfSupport", end).put("days", days);
        o.put("comment", u == 2
                ? I18n.tr("server.sslexp.outSince", java.util.Map.of("date", String.valueOf(end), "d", String.valueOf(-days)))
                : u == 1 ? I18n.tr("server.sslexp.leaves", java.util.Map.of("date", String.valueOf(end), "d", String.valueOf(days)))
                : I18n.tr("server.sslexp.until", java.util.Map.of("date", String.valueOf(end), "lts", String.valueOf(isLts(version) ? " (LTS)" : ""), "d", String.valueOf(days))));
        return o;
    }

    private record RunResult(int code, String output) {}

    private static RunResult run(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new RunResult(p.waitFor(), out);
        } catch (Exception e) {
            return new RunResult(-1, String.valueOf(e.getMessage()));
        }
    }
}
