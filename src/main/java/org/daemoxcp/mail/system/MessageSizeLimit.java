package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.util.Map;

/**
 * The maximum size of a message, that is, the Postfix parameter message_size_limit.
 *
 * The "maximum size" field already existed on the sending limits page, but it was not
 * connected to anything: the value was written and nothing happened. Here it is connected to
 * the real parameter, with the same discipline used elsewhere: the current value is read, the
 * new one is written, it is validated with "postfix check", and if the validation fails the
 * previous one is put back without reloading.
 *
 * The value in Postfix is in BYTES, in the interface in megabytes: the conversion lives here, in
 * one place only, instead of being scattered between page and server, where two different
 * roundings would end up showing one number and saving another.
 *
 * The notes and errors are for whoever uses the panel: in the language of the request (server.size.*).
 */
public class MessageSizeLimit {

    private MessageSizeLimit() {}

    public static final int MEGA = 1024 * 1024;

    /** Megabytes -> bytes. */
    public static long toBytes(int mb) { return (long) mb * MEGA; }

    /** Bytes -> megabytes, rounded down but never to zero if there is a limit. */
    public static int aMega(long totalBytes) {
        if (totalBytes <= 0) return 0;
        int mb = (int) (totalBytes / MEGA);
        return mb == 0 ? 1 : mb;
    }

    /** The current value in megabytes, or -1 if it cannot be read. */
    public static int readMegabytes() {
        RunResult r = run("postconf", "-h", "message_size_limit");
        if (r.code != 0) return -1;
        try {
            return aMega(Long.parseLong(r.output.trim()));
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Sets the limit. Always returns a readable outcome, never a silent exception.
     */
    public static JSONObject set(int mb) {
        JSONObject r = new JSONObject().put("megabytes", mb);
        if (mb < 1 || mb > 1024)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.outOfRange", Map.of("mb", mb)));

        int before = readMegabytes();
        if (before < 0)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.unreadable"));
        r.put("before", before);
        if (before == mb)
            return r.put("success", true).put("unchanged", true)
                    .put("note", I18n.tr("server.size.unchanged", Map.of("mb", mb)));

        RunResult set = run("postconf", "-e", "message_size_limit=" + toBytes(mb));
        if (set.code != 0)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.postconfRefused", Map.of("output", set.output.trim())));

        RunResult check = run("postfix", "check");
        if (check.code != 0) {
            run("postconf", "-e", "message_size_limit=" + toBytes(before));
            return r.put("success", false).put("restored", true)
                    .put("error", I18n.tr("server.size.checkFailed", Map.of("before", before, "output", check.output.trim())));
        }

        RunResult reload = run("postfix", "reload");
        if (reload.code != 0) {
            run("postconf", "-e", "message_size_limit=" + toBytes(before));
            run("postfix", "reload");
            return r.put("success", false).put("restored", true)
                    .put("error", I18n.tr("server.size.reloadFailed", Map.of("before", before, "output", reload.output.trim())));
        }

        // It is not enough that the commands did not complain: the value is read again.
        int after = readMegabytes();
        r.put("after", after);
        if (after != mb)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.readBackDiffers", Map.of("mb", mb, "after", after)));

        return r.put("success", true)
                .put("note", I18n.tr("server.size.changed", Map.of("before", before, "mb", mb)));
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
