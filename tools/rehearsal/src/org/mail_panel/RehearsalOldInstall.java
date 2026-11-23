package org.mail_panel;

/**
 * The test of the upgrade from the server's version (419b0a2, 2026-10-11): the installation as its
 * menu did it (Main, lines 470-680 of that version), without the menu. It is compiled against the
 * server's jar and launched from /home/panel, as root.
 */
public class RehearsalOldInstall {
    public static void main(String[] a) throws Exception {
        String host = a[0];
        Main.createDirectoryIfNotExists("./database/");
        Main.createDirectoryIfNotExists("./install_scripts/");
        Main.dbManager = new org.mail_panel.sqli.dataBaseManager();
        Main.dbManager.ensureMailHostnameColumn();
        Main.dbManager.ensureSslChainColumn();
        Main.dbManager.ensureRoundcubeColumns();
        Main.dbManager.ensurePostfixColumn();
        if (Main.dbManager.check_tables() < 1) { Main.dbManager.create_tables(); Main.dbManager.insert_data_default(); }
        Main.dbManager.setMailHostname(host);
        Main.dbManager.resetAllServices();
        String chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        StringBuilder pwd = new StringBuilder();
        for (int i = 0; i < 24; i++) pwd.append(chars.charAt(rnd.nextInt(chars.length())));
        Main.dbManager.update_mysql_config("127.0.0.1", "3306", "mailpanel", pwd.toString(), "mailserver");
        // The Roundcube domain: the menu asked for it beforehand, and without it the script stops.
        String webmail = a[1], cert = "/usr/local/etc/ssl/mail/fullchain.pem", key = "/usr/local/etc/ssl/mail/privkey.pem";
        Main.dbManager.updateRoundcubeConfig(webmail, "8443", cert, key, "");
        new org.mail_panel.scripts.FullMailServerScript().write_file();
        // On today's catalogue the script of that time has two package names that no longer work
        // (findings, point 135). postfix-mysql brings mysql84-client, which removes mysql80-server already
        // in the packages phase, before MySQL has ever started: no database, and the script
        // says `riuscita` ("succeeded") all the same. And dovecot-pigeonhole leaves lmtp without sieve. The
        // production server has mysql84-server and dovecot-pigeonhole-mysql: those two lines are changed
        // and nothing else.
        java.nio.file.Path script = java.nio.file.Path.of("./install_scripts/install_mail_server.sh");
        String before = java.nio.file.Files.readString(script);
        String[][] fixes = {
            {"pkg install -y mysql80-server mysql80-client\n", "pkg install -y mysql84-server mysql84-client\n"},
            {"pkg install -y dovecot-mysql dovecot-pigeonhole\n", "pkg install -y dovecot-mysql dovecot-pigeonhole-mysql\n"}};
        String after = before;
        for (String[] f : fixes) {
            if (!after.contains(f[0])) throw new IllegalStateException("riga non trovata nello script: " + f[0].trim());
            after = after.replace(f[0], f[1]);
        }
        java.nio.file.Files.writeString(script, after);
        System.out.println("script corretto: mysql84-server, dovecot-pigeonhole-mysql");
        boolean ok = Main.executeScript("./install_scripts/install_mail_server.sh", "Mail server",
                "127.0.0.1", "3306", "mailpanel", pwd.toString(), "mailserver", host, webmail, "8443", cert, key, "");
        if (ok) for (String s : new String[]{"postfix", "dovecot", "rspamd", "clamav"}) Main.dbManager.setServiceInstalled(s, true);
        System.out.println(ok ? "INSTALLAZIONE RIUSCITA" : "INSTALLAZIONE FALLITA");
        System.exit(ok ? 0 : 1);
    }
}
