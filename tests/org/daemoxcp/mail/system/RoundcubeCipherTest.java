package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Roundcube encrypts with AES-256-CBC and a 32-character key, no longer with DES-EDE3-CBC (reperto 239). Against a
 * fake Roundcube whose logins work only if the configured method and key are a pair PHP accepts:
 *  1. the installer writes a 32-character des_key and cipher_method AES-256-CBC; the new keys are 32 characters of
 *     letters and digits, never the same;
 *  2. the installer's config of before: DONE, the des_key line replaced by the new key and the method, nothing else
 *     changed; the second run does nothing;
 *  3. what does not start: no config, the admin's own cipher_method, no des_key line as the installer writes it or two,
 *     the webmail not answering;
 *  4. a fault after the change (PHP not encrypting, the webmail not answering, the real login failing): the file byte
 *     for byte as before; no real login possible before (no SSO): DONE, saying so.
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.RoundcubeCipherTest
 */
public class RoundcubeCipherTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final Path CONFIG = Path.of("/fake/config.inc.php");
    static final String BEFORE = "<?php\n$config['db_dsnw'] = 'mysql://roundcube:x@127.0.0.1/roundcubemail';\n"
            + "$config['product_name'] = 'FreeBSD Webmail';\n$config['des_key'] = 'Ab3dEf6hIj9kLm2nOp5qRs8t';\n$config['skin'] = 'elastic';\n";

    static class Machine implements RoundcubeCipher.Services {
        final Map<Path, String> files = new HashMap<>();
        String fault;   // "php", "down", "login", "no-sso"
        int writes = 0;

        @Override public String read(Path f) { return files.get(f); }
        @Override public void write(Path f, String t) { writes++; files.put(f, t); }
        @Override public boolean cipherWorks(Path c) {
            String t = files.get(c);
            return !"php".equals(fault) && t.contains("$config['cipher_method'] = 'AES-256-CBC';\n")
                    && t.matches("(?s).*\\$config\\['des_key'\\] = '[A-Za-z0-9]{32}';\n.*");
        }
        @Override public boolean webmailAnswers() { return !"down".equals(fault); }
        @Override public String realLogin() {
            if ("no-sso".equals(fault)) return "the panel's SSO is not available";
            return "login".equals(fault) && files.get(CONFIG).contains("AES") ? "did not open the mailbox with its folders" : null;
        }
    }

    static RoundcubeCipher.Result run(Machine m) { return RoundcubeCipher.run(m, CONFIG); }

    static Machine before() {
        Machine m = new Machine();
        m.files.put(CONFIG, BEFORE);
        return m;
    }

    public static void main(String[] args) {
        System.out.println("== 1. What the installer writes");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("a 32-character des_key", installer.contains("ROUNDCUBE_DES_KEY=$(openssl rand -base64 48 | tr -d '/+=' | head -c 32)"));
        check("cipher_method AES-256-CBC after it", installer.contains("\\$config['des_key'] = '$ROUNDCUBE_DES_KEY';\n\\$config['cipher_method'] = 'AES-256-CBC';\n"));
        String k1 = RoundcubeCipher.newKey(), k2 = RoundcubeCipher.newKey();
        check("new keys: 32 letters and digits, never the same", k1.matches("[A-Za-z0-9]{32}") && !k1.equals(k2));
        check("the PHP probe refuses anything but AES-256-CBC with a 32-character key", RoundcubeCipher.PHP_PROBE.contains("$m === 'AES-256-CBC' && strlen($k) === 32"));

        System.out.println("\n== 2. The installer's config of before");
        Machine m = before();
        RoundcubeCipher.Result r = run(m);
        check("DONE (" + r.detail() + ")", r.outcome() == RoundcubeCipher.Outcome.DONE && r.detail().contains("real login"));
        String after = m.files.get(CONFIG);
        check("  the des_key line replaced by the new key and the method, nothing else changed",
                after.replaceAll("\\$config\\['des_key'\\] = '[A-Za-z0-9]{32}';\n(//[^\n]*\n)*\\$config\\['cipher_method'\\] = 'AES-256-CBC';\n",
                        "\\$config['des_key'] = 'Ab3dEf6hIj9kLm2nOp5qRs8t';\n").equals(BEFORE));
        check("  the old key gone", !after.contains("Ab3dEf6hIj9kLm2nOp5qRs8t"));
        int writes = m.writes;
        check("  a second run: NOTHING, nothing written", run(m).outcome() == RoundcubeCipher.Outcome.NOTHING && m.writes == writes);

        System.out.println("\n== 3. What does not start");
        check("no config: NOTHING", run(new Machine()).outcome() == RoundcubeCipher.Outcome.NOTHING);
        for (String[] c : new String[][]{
                {"the admin's cipher_method", BEFORE + "$config['cipher_method'] = 'AES-128-CBC';\n"},
                {"the admin's cipher_method in double quotes", BEFORE + "$config[\"cipher_method\"] = 'DES-EDE3-CBC';\n"},
                {"a des_key the installer does not write", BEFORE.replace("'Ab3dEf6hIj9kLm2nOp5qRs8t'", "'short'")},
                {"two des_key lines", BEFORE + "$config['des_key'] = 'Zz3dEf6hIj9kLm2nOp5qRs8t';\n"}}) {
            Machine x = new Machine();
            x.files.put(CONFIG, c[1]);
            r = run(x);
            check(c[0] + ": LEFT, untouched", r.outcome() == RoundcubeCipher.Outcome.LEFT && x.files.get(CONFIG).equals(c[1]) && x.writes == 0);
        }
        Machine down = before();
        down.fault = "down";
        r = run(down);
        check("the webmail not answering now: LEFT, untouched", r.outcome() == RoundcubeCipher.Outcome.LEFT && down.writes == 0);

        System.out.println("\n== 4. A fault after the change: the file as before");
        for (String fault : new String[]{"php", "login"}) {
            Machine x = before();
            x.fault = fault;
            r = run(x);
            check(fault + ": ROLLED_BACK (" + r.detail() + ")", r.outcome() == RoundcubeCipher.Outcome.ROLLED_BACK
                    && x.files.get(CONFIG).equals(BEFORE));
        }
        Machine downAfter = new Machine() {
            @Override public boolean webmailAnswers() { return !files.get(CONFIG).contains("AES"); }
        };
        downAfter.files.put(CONFIG, BEFORE);
        r = run(downAfter);
        check("the webmail not answering after: ROLLED_BACK, as before", r.outcome() == RoundcubeCipher.Outcome.ROLLED_BACK
                && downAfter.files.get(CONFIG).equals(BEFORE));
        Machine noSso = before();
        noSso.fault = "no-sso";
        r = run(noSso);
        check("no SSO for a real login: DONE, saying so (" + r.detail() + ")", r.outcome() == RoundcubeCipher.Outcome.DONE
                && r.detail().contains("without a real login"));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
