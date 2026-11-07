package org.mail_panel.scripts;

/**
 * The shadow class of FullMailServerScript for ReinstallJobTest: same interface, planted script
 * (phase 1, twelve one-second steps, then a mark). Put BEFORE the jar in the classpath, the real
 * panel uses it, the detached reinstallation included (Main --reinstall), which always rewrites the
 * script from "its jar" just before running it (InstallScripts, reperto 169). It is not in tests/:
 * it is compiled apart (tests/planted), only for the tests that want it.
 */
public class FullMailServerScript {

    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/install_mail_server.sh";

    private final String data = "#!/bin/sh\n# test: planted in place of install_mail_server.sh (shadow class)\n"
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
