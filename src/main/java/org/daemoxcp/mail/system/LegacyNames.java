package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * The names that old versions of the panel left on the servers, and the current ones.
 *
 * <p>Until the end of October 2026 the panel wrote Italian names on disk and in the services: files and
 * folders, the jail of 443, the boot environments, the keys of the version-jump state, the report
 * frequency. The code is now all in English (r26), but servers already running still have those
 * names, and the new panel must recognise them to bring them to the current names without breaking
 * anything.
 *
 * <p>Those old names live in one place only, the data file legacy-names.json inside the jar,
 * and not in the code: it is the owner's choice (2026-10-30). Each section is a list of
 * [old, new] pairs, in the order in which they must be applied (where it matters: a folder before
 * the files it contains). The code asks for the section and never writes an old name.
 *
 * <p>When no server has a version from before any more, the file is emptied and the code that
 * reads it no longer finds anything to do.
 */
public final class LegacyNames {

    private static final Logger LOGGER = Logger.getLogger(LegacyNames.class.getName());
    static final String RESOURCE = "/legacy-names.json";

    private static volatile JSONObject data;

    private LegacyNames() {}

    private static JSONObject data() {
        JSONObject d = data;
        if (d != null) return d;
        try (InputStream in = LegacyNames.class.getResourceAsStream(RESOURCE)) {
            if (in == null) throw new IllegalStateException(RESOURCE + " is not in the jar");
            d = new JSONObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            // Without the file the migrations find nothing to do: the panel starts anyway,
            // but it must say so, because an old server would be left halfway.
            LOGGER.severe("[LegacyNames] cannot read " + RESOURCE + ": " + e);
            d = new JSONObject();
        }
        data = d;
        return d;
    }

    /** The [old, new] pairs of a section, in the file's order. */
    public static List<String[]> pairs(String section) {
        JSONArray a = data().optJSONArray(section);
        if (a == null) return List.of();
        List<String[]> out = new ArrayList<>();
        for (int i = 0; i < a.length(); i++) {
            JSONArray p = a.optJSONArray(i);
            if (p != null && p.length() == 2) out.add(new String[]{p.getString(0), p.getString(1)});
        }
        return Collections.unmodifiableList(out);
    }

    /** The same section as an old -> new map, in the file's order. */
    public static Map<String, String> map(String section) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String[] p : pairs(section)) m.put(p[0], p[1]);
        return m;
    }

    /** The old names that are now called {@code current}. */
    public static List<String> oldNamesOf(String section, String current) {
        List<String> out = new ArrayList<>();
        for (String[] p : pairs(section)) if (p[1].equals(current)) out.add(p[0]);
        return out;
    }

    /** The current name: the new one if {@code value} is an old name, otherwise as it is. */
    public static String current(String section, String value) {
        if (value == null) return null;
        for (String[] p : pairs(section)) if (p[0].equals(value)) return p[1];
        return value;
    }

    /** The old name of the section that has only one, or "" if there is none. */
    public static String single(String section) {
        List<String[]> p = pairs(section);
        return p.isEmpty() ? "" : p.get(0)[0];
    }
}
