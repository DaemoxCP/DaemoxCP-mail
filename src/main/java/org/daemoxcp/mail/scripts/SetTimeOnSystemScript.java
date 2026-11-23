package org.daemoxcp.mail.scripts;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Wrapper for SetTimeOnSystem script with file writing capability
 */
public class SetTimeOnSystemScript {
    public boolean writed = false;
    private static final String SCRIPT_PATH = "./install_scripts/setup_timezone_and_dns.sh";

    /** Always, all or nothing, with the jar's fingerprint (InstallScripts): never a script from an earlier version. */
    public void write_file() {
        this.writed = InstallScripts.write(SCRIPT_PATH, new SetTimeOnSystem().getScriptContent());
    }
}
