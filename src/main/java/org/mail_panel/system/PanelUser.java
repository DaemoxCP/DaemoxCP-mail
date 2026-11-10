package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.time.Duration;

/**
 * Un utente di sistema che crea il pannello per far girare qualcosa senza root: nessuna password, nessuna shell, casa
 * /nonexistent, un gruppo suo con lo stesso nome e nessun altro membro. Se esiste gia' con un'altra forma non e' del
 * pannello, e non lo si usa.
 *
 * Il controllo era in PanelSeparation per mailpanel; e' qui perche' ne serve un secondo, sievec (SieveCompiler,
 * reperto 218), e i due devono essere controllati allo stesso modo.
 *
 * @param name  il nome dell'utente, e del suo gruppo
 * @param gecos il commento con cui il pannello lo crea: un utente con quel nome e un altro commento non e' suo
 */
public record PanelUser(String name, String gecos) {

    public static final String HOME = "/nonexistent";
    public static final String SHELL = "/usr/sbin/nologin";

    /** Com'e' andata: null se l'utente c'e' ed e' quello del pannello, altrimenti il motivo; created se l'ha creato ora. */
    public record Ensured(String problem, boolean created) {}

    /**
     * Crea gruppo e utente se mancano, poi li controlla. Il formato di pw usershow e' quello di master.passwd:
     * nome:password:uid:gid:classe:cambio:scadenza:commento:cartella:shell (pw(8)); quello di pw groupshow e'
     * nome:password:gid:membri.
     */
    public Ensured ensure() {
        Duration t = Duration.ofSeconds(15);
        boolean created = false;
        if (!Shell.run(t, "pw", "groupshow", name).success()) {
            if (!Shell.run(t, "pw", "groupadd", name).success()) return new Ensured("the group " + name + " could not be created", false);
            created = true;
        }
        if (!Shell.run(t, "pw", "usershow", name).success()) {
            if (!Shell.run(t, "pw", "useradd", name, "-g", name, "-d", HOME, "-s", SHELL, "-c", gecos, "-w", "no").success())
                return new Ensured("the user " + name + " could not be created", created);
            created = true;
        }
        return new Ensured(problem(Shell.run(t, "pw", "usershow", name).outputTrim(),
                Shell.run(t, "pw", "groupshow", name).outputTrim()), created);
    }

    /** Null se le righe di pw sono quelle dell'utente creato dal pannello; altrimenti cosa non torna. Pura. */
    public String problem(String userLine, String groupLine) {
        String[] u = userLine.split(":", -1);
        String[] g = groupLine.split(":", -1);
        if (u.length < 10 || g.length < 4) return "the user " + name + " or its group cannot be read";
        String other = "the user " + name + " exists and is not the panel's: ";
        if (!name.equals(u[0])) return other + "name " + u[0];
        if ("0".equals(u[2])) return other + "uid 0";
        if (!gecos.equals(u[7])) return other + "comment '" + u[7] + "'";
        if (!HOME.equals(u[8])) return other + "home " + u[8];
        if (!SHELL.equals(u[9])) return other + "shell " + u[9];
        if (!"*".equals(u[1]) && !u[1].startsWith("*LOCKED*")) return other + "it has a password";
        if (!name.equals(g[0]) || !g[2].equals(u[3])) return other + "its group is not " + name;
        if (!g[3].isEmpty()) return "the group " + name + " has other members (" + g[3] + "): they would read the panel's files";
        return null;
    }
}
