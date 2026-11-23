package org.daemoxcp.mail.scripts;

import org.daemoxcp.mail.system.RoundcubeDbUser;

/**
 * The SQL statements with which the installation scripts create the webmail's MySQL user
 * ({@value RoundcubeDbUser#USER}) and take its database away from the panel's user.
 *
 * <p>They used to be in RoundcubeDbUser, which however at startup talks to MySQL only with the statements of the
 * catalog. These are shell text for the mysql client, like the rest of the
 * installation scripts: they go into an UNQUOTED here-document run by root, where the password variable is expanded
 * only once (the generator's alphabet has no quotes). No backticks around the names: in the here-document they
 * would open a command substitution.
 */
public final class RoundcubeDbAccountScript {

    private RoundcubeDbAccountScript() {}

    /**
     * The webmail account with the password that the panel passes in the environment, privileges on the webmail's
     * database only, and those of the panel's user on that database removed, because a reinstallation finds them
     * from the previous version.
     */
    public static String sql(String passwordVariable, String panelUser) {
        String account = "'" + RoundcubeDbUser.USER + "'@'" + RoundcubeDbUser.HOST + "'";
        String db = RoundcubeDbUser.DATABASE;
        return "CREATE USER IF NOT EXISTS " + account + " IDENTIFIED BY '" + passwordVariable + "';\n"
             + "ALTER USER " + account + " IDENTIFIED BY '" + passwordVariable + "';\n"
             + "GRANT ALL PRIVILEGES ON " + db + ".* TO " + account + ";\n"
             + "REVOKE IF EXISTS ALL PRIVILEGES ON " + db + ".* FROM '" + panelUser + "'@'localhost', '"
             + panelUser + "'@'127.0.0.1' IGNORE UNKNOWN USER;\n";
    }
}
