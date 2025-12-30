package org.mail_panel.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Wrapper for SetTimeOnSystem script with file writing capability
 */
public class SetTimeOnSystemScript {
    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/setup_timezone_and_dns.sh";

    public void write_file() {
        File scriptFile = new File(SCRIPT_PATH);
        if (scriptFile.exists()) {
            // Script already exists, don't overwrite
            return;
        }

        SetTimeOnSystem script = new SetTimeOnSystem();
        try (FileWriter writer = new FileWriter(SCRIPT_PATH)) {
            writer.write(script.getScriptContent());
            scriptFile.setExecutable(true);
            this.writed = true;
        } catch (IOException e) {
            System.out.println("Error writing script: " + e.getMessage());
        }
    }
}
