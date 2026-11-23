package org.daemoxcp.mail.system;

/**
 * The product name, in one place only, in the three forms needed on the server.
 *
 * <p>The panel has been called DaemoxCP Mail since 2026-11-17 (before, FreeBSD Mail Panel, "mailpanel" on disk).
 * The name that panel users see lives in the language files (brand.name); here live the technical ones, which
 * are not translated:
 * <ul>
 *   <li>{@link #NAME}: in the log lines that the scripts read back, in the signatures of the files written by the
 *       panel, in the User-Agents;</li>
 *   <li>{@link #SLUG}: where the hyphen can be used, that is folders, files, the jar, the logs;</li>
 *   <li>{@link #ID}: where the hyphen cannot be used, that is the rc.d service and its variables, the MySQL
 *       database and users, the system user, the Roundcube plugin.</li>
 * </ul>
 * The previous names live in legacy-names.json, never in the code.
 */
public final class Product {

    public static final String NAME = "DaemoxCP Mail";
    public static final String SLUG = "daemoxcp-mail";
    public static final String ID = "daemoxcp_mail";
    /** The jar name, without version (since 0.9.0): the one in the console commands and in the README (JarName). */
    public static final String JAR_FILE = SLUG + ".jar";

    private Product() {}
}
