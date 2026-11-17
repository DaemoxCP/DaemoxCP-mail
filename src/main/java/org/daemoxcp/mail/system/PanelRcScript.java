package org.daemoxcp.mail.system;

/**
 * Lo script di avvio del pannello in /usr/local/etc/rc.d, in un posto solo: lo scrivono la pagina «Avvio
 * automatico» (UpdateManager.panelRcScript) e il passaggio al nome nuovo (PanelServiceRename), e deve essere lo
 * stesso testo.
 *
 * <p>Il servizio si chiama come il prodotto dove il trattino non si puo' usare (Product.ID): rc.subr chiama le
 * variabili ${name}_enable, ${name}_jar e cosi' via, e un nome di variabile della shell non ha trattini. Il testo e'
 * in inglese, come tutto quello che il pannello scrive fuori dai file di lingua, e porta la firma del pannello
 * (PanelMarker.WRITTEN): RcScriptRepair tocca solo gli script che la portano.
 */
public final class PanelRcScript {

    public static final String NAME = Product.ID;
    public static final String PATH = "/usr/local/etc/rc.d/" + NAME;
    public static final String PIDFILE = "/var/run/" + NAME + ".pid";
    /** Dove scrive daemon(8) quello che il pannello stampa (il registro del servizio). */
    public static final String LOG = DataFolderRename.NEW + "/panel.log";

    /** I due messaggi dello script (RcScriptRepair riconosce quelli di prima). */
    static final String STARTING = "echo \"Starting ${name} (web only). Log: ${" + NAME + "_log}\"";
    static final String RUNNING = "echo \"${name}: already running (pid $(cat ${pidfile}))\"";

    private PanelRcScript() {}

    /**
     * Il testo dello script. Puro.
     *
     * @param dir  la cartella da cui il pannello parte (database/, install_scripts/ sono relativi a lei)
     * @param java la java con cui gira
     * @param jar  il jar
     * @param opts le opzioni della macchina virtuale
     */
    public static String text(String dir, String java, String jar, String opts) {
        String v = NAME;
        return "#!/bin/sh\n"
             + "#\n"
             + "# PROVIDE: " + v + "\n"
             + "# REQUIRE: LOGIN\n"
             + "# KEYWORD: shutdown\n"
             + "#\n"
             + "# " + PanelMarker.WRITTEN + ". " + Product.NAME + " in web-only mode (--web): no menu on\n"
             + "# the screen, no terminal needed. For the menu: service " + v + " stop, then start the jar by hand\n"
             + "# without --web.\n"
             + "#\n"
             + "# Enable it with:  sysrc " + v + "_enable=YES\n"
             + "\n"
             + ". /etc/rc.subr\n"
             + "\n"
             + "# Started by rc.d the panel gets PATH=/sbin:/bin:/usr/sbin:/usr/bin, without /usr/local, where half of the\n"
             + "# tools it uses live (mysql, doveadm, postmap, rspamadm, fail2ban-client, nginx). The panel completes the PATH\n"
             + "# of what it runs by itself; setting it here too makes the environment plain to whoever reads this file.\n"
             + "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin\n"
             + "export PATH\n"
             + "\n"
             + "name=" + v + "\n"
             + "rcvar=" + v + "_enable\n"
             + "\n"
             + "load_rc_config $name\n"
             + "\n"
             + ": ${" + v + "_enable:=\"NO\"}\n"
             + ": ${" + v + "_dir:=\"" + dir + "\"}\n"
             + ": ${" + v + "_java:=\"" + java + "\"}\n"
             + ": ${" + v + "_jar:=\"" + jar + "\"}\n"
             + ": ${" + v + "_opts:=\"" + opts + "\"}\n"
             + ": ${" + v + "_log:=\"" + LOG + "\"}\n"
             + "\n"
             + "pidfile=\"/var/run/${name}.pid\"\n"
             + "# rc.subr compares the pid in the pidfile with procname: daemon -p writes the pid of the child, which is java\n"
             + "# after the exec. With /usr/sbin/daemon here, status would always say the panel is not running.\n"
             + "procname=\"${" + v + "_java}\"\n"
             + "\n"
             + "start_cmd=\"${name}_start\"\n"
             + "stop_postcmd=\"${name}_poststop\"\n"
             + "\n"
             + v + "_start()\n"
             + "{\n"
             + "\t# kill -0 rather than pgrep -F: POSIX, the same everywhere, and it can be tested.\n"
             + "\tif [ -f \"${pidfile}\" ] && kill -0 \"$(cat \"${pidfile}\")\" 2>/dev/null; then\n"
             + "\t\t" + RUNNING + "\n"
             + "\t\treturn 1\n"
             + "\tfi\n"
             + "\tmkdir -p \"$(dirname \"${" + v + "_log}\")\"\n"
             + "\t# The log grows by appending: past 10 MB it is set aside.\n"
             + "\tif [ -f \"${" + v + "_log}\" ] && [ $(stat -f %z \"${" + v + "_log}\") -gt 10485760 ]; then\n"
             + "\t\tmv \"${" + v + "_log}\" \"${" + v + "_log}.1\"\n"
             + "\tfi\n"
             + "\t" + STARTING + "\n"
             + "\t/usr/sbin/daemon -f -o \"${" + v + "_log}\" -p \"${pidfile}\" -t \"${name}\" \\\n"
             + "\t\t/bin/sh -c \"cd '${" + v + "_dir}' && exec '${" + v + "_java}' ${" + v + "_opts} -jar '${" + v + "_jar}' --web\"\n"
             + "}\n"
             + "\n"
             + v + "_poststop()\n"
             + "{\n"
             + "\trm -f \"${pidfile}\"\n"
             + "}\n"
             + "\n"
             + "run_rc_command \"$1\"\n";
    }
}
