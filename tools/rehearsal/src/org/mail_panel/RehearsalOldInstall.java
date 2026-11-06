package org.mail_panel;

/**
 * La prova del passaggio dalla versione del server (419b0a2, 11/10/2026): l'installazione come la
 * faceva il suo menu (Main, righe 470-680 di quella versione), senza il menu. Si compila contro il
 * jar del server e si lancia da /home/panel, da root.
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
        // Il dominio di Roundcube: il menu lo chiedeva prima, e senza lo script si ferma.
        String webmail = a[1], cert = "/usr/local/etc/ssl/mail/fullchain.pem", key = "/usr/local/etc/ssl/mail/privkey.pem";
        Main.dbManager.updateRoundcubeConfig(webmail, "8443", cert, key, "");
        new org.mail_panel.scripts.FullMailServerScript().write_file();
        // Sul catalogo di oggi lo script di allora ha due nomi di pacchetto che non vanno piu'
        // (reperti, punto 135). postfix-mysql porta mysql84-client, che toglie mysql80-server gia'
        // nella fase dei pacchetti, prima che MySQL sia mai partito: niente database, e lo script
        // dice lo stesso «riuscita». E dovecot-pigeonhole lascia lmtp senza sieve. Il server vero ha
        // mysql84-server e dovecot-pigeonhole-mysql: si cambiano quelle due righe e nient'altro.
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
