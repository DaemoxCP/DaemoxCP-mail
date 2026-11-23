package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/**
 * Which OpenSSL this server really uses, and for how much longer it receives fixes.
 *
 * Why the question cannot be answered by reading the release notes: the notes say what
 * was there on the day of the release, not what runs now on THIS machine. An installed
 * port, an update left halfway, a system older than one believes: these are all things
 * that can be seen only by asking the binary which version it has.
 *
 * The dates are those of OpenSSL's official release strategy, read on 2026-09-01.
 * They are not computed: they are transcribed, because inventing a rule ("every LTS lasts
 * 5 years") would produce dates that are plausible and wrong.
 *
 * Beware of a distinction that changes the verdict: **the base system's OpenSSL is not the
 * port.** The base one is maintained by the FreeBSD project, which publishes fixes for the
 * supported releases; the port follows upstream's calendar. Confusing them sounds an alarm
 * that is not there, or silences one that is.
 */
public class OpensslExpiry {

    /** branch -> end of upstream support. Transcribed from openssl-library.org. */
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

    /*
     * ===================================================================
     * Pure part, testable without a server
     * ===================================================================
     */

    /** The branch of a version: "3.5.6" -> "3.5", "1.1.1w" -> "1.1.1". */
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

    /** The end-of-support date of that branch, or null if the branch is not in the table. */
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

    /** Days left. Negative if the date has passed. "today" is passed in: that way it can be tested. */
    public static Long daysLeft(String version, LocalDate today) {
        String f = endOfSupport(version);
        if (f == null || today == null) return null;
        try {
            return ChronoUnit.DAYS.between(today, LocalDate.parse(f));
        } catch (Exception e) {
            return null;
        }
    }

    /** 0 = fine, 1 = expires soon (within 90 days), 2 = expired, 3 = unknown. */
    public static int urgency(String version, LocalDate today) {
        Long g = daysLeft(version, today);
        if (g == null) return 3;
        if (g < 0) return 2;
        if (g <= 90) return 1;
        return 0;
    }

    /** The version inside the output of "openssl version": "OpenSSL 3.5.6 30 Sep 2025" -> 3.5.6 */
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

    /*
     * ===================================================================
     * Part that queries the server
     * ===================================================================
     */

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

        // Whoever wins in the panel's PATH: it is the one that would end up in the scripts.
        RunResult which = run("sh", "-c", "command -v openssl");
        r.put("inPath", which.code == 0 ? which.output.trim() : "");

        RunResult fv = run("freebsd-version", "-k");
        if (fv.code == 0) r.put("freebsd", fv.output.trim());

        // The verdict looks only at what is really there.
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
