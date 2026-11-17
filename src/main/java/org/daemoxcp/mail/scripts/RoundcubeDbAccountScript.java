package org.daemoxcp.mail.scripts;

import org.daemoxcp.mail.system.RoundcubeDbUser;

/**
 * Le istruzioni SQL con cui gli script d'installazione creano l'utente MySQL della webmail
 * ({@value RoundcubeDbUser#USER}) e tolgono il suo database all'utente del pannello.
 *
 * <p>Stavano in RoundcubeDbUser, che pero' all'avvio parla con MySQL solo con le istruzioni del catalogo.
 * Queste sono testo di shell per il client mysql, come il resto degli script
 * d'installazione: vanno in un here-document NON quotato eseguito da root, dove la variabile della password si espande
 * una volta sola (l'alfabeto del generatore non ha apici). Niente accenti gravi intorno ai nomi: nel here-document
 * aprirebbero una sostituzione di comando.
 */
public final class RoundcubeDbAccountScript {

    private RoundcubeDbAccountScript() {}

    /**
     * L'account della webmail con la password che il pannello passa nell'ambiente, i privilegi sul solo database della
     * webmail, e quelli dell'utente del pannello su quel database tolti, perche' una reinstallazione li trova dalla
     * versione di prima.
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
