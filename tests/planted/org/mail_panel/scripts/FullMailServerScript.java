package org.mail_panel.scripts;

/**
 * La classe ombra di FullMailServerScript per ReinstallJobTest: stessa interfaccia, script piantato
 * (fase 1, dodici passi da un secondo, poi un segno). Messa DAVANTI al jar nel classpath, la usa il
 * pannello vero, compresa la reinstallazione staccata (Main --reinstall), che lo script lo riscrive
 * sempre dal "suo jar" appena prima di eseguirlo (InstallScripts, reperto 169). Non sta in tests/: la
 * si compila a parte (tests/planted), solo per le prove che la vogliono.
 */
public class FullMailServerScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/install_mail_server.sh";

    private final String data = "#!/bin/sh\n# prova: piantato al posto di install_mail_server.sh (classe ombra)\n"
            + "echo \"[PHASE 1/10] Cleaning up existing installation...\"\n"
            + "i=1; while [ $i -le 12 ]; do echo \"planted: step $i\"; sleep 1; i=$((i+1)); done\n"
            + "touch ./script-done\nexit 0\n";

    public void write_file() {
        this.writed = InstallScripts.write(SCRIPT_PATH, data);
    }

    public String getScriptContent() {
        return data;
    }
}
