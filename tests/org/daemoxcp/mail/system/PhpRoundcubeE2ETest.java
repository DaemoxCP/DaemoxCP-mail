package org.daemoxcp.mail.system;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.daemoxcp.mail.util.Shell;

/**
 * Reperti 238 and 239 on the VM's real PHP, php-fpm, nginx and Roundcube, as root with -De2e.vm=yes, from an
 * installation of before (php.ini as the installer of before wrote it, the pool without the limit, config.inc.php with
 * a 24-character des_key and no cipher_method). The path of tests/mail-login-probe.sh is -De2e.probe.
 *  1. 238 as on the real server: php.ini taken away, php-fpm reloaded: the webmail answers with X-Powered-By (the
 *     fault); PhpHardening: DONE, php.ini is PhpHardening.INI, X-Powered-By gone, session upload progress off for
 *     php-fpm too, the pool with the limit, php-fpm -t; the second run does nothing;
 *  2. a fault from that state of before (php-fpm -t refusing): ROLLED_BACK, no php.ini, the pool as before, X-Powered-By
 *     again; then DONE again;
 *  3. 239: the probe's real webmail login works with DES-EDE3-CBC; RoundcubeCipher (no SSO in a test: without the real
 *     login inside): DONE, AES-256-CBC and a 32-character key, PHP encrypts and decrypts with them, and the probe's real
 *     login opens the mailbox with its folders from IMAP; the second run does nothing;
 *  4. a fault (PHP refusing the cipher): ROLLED_BACK, config.inc.php byte for byte; then DONE again.
 *   java -De2e.vm=yes -De2e.probe=/var/tmp/x/mail-login-probe.sh -cp "tests:daemoxcp-mail.jar" org.daemoxcp.mail.system.PhpRoundcubeE2ETest
 */
public class PhpRoundcubeE2ETest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(300), cmd).outputTrim();
    }

    @SuppressWarnings("unchecked")
    static <T> T with(Class<T> type, T real, String method, java.util.function.Function<Object[], Object> replacement) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, a) -> {
            if (m.getName().equals(method)) return replacement.apply(a);
            try {
                return m.invoke(real, a);
            } catch (java.lang.reflect.InvocationTargetException e) {
                throw e.getCause();
            }
        });
    }

    static String page() {
        PhpHardening.Services php = PhpHardening.real();
        return php.webmail(php.sites().get(0));
    }

    /** php-fpm read a php.ini with expose_php = Off: the answer has no X-Powered-By. */
    static boolean poweredBy() {
        String p = page();
        return p != null && PhpHardening.poweredBy(p);
    }

    static boolean webmailLogin(String probe) {
        String out = sh("cd /var/tmp && sh " + probe + " 2>&1");
        int at = out.indexOf("== Webmail");
        String part = at < 0 ? "" : out.substring(at, Math.min(out.length(), at + 600));
        System.out.println("      " + part.replace("\n", "\n      ").trim());
        return part.contains("RESULT: OK");
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Turned on with -De2e.vm=yes, as root, on the VM: it changes PHP and Roundcube.");
            System.exit(0);
        }
        String probe = System.getProperty("e2e.probe", "/var/tmp/mail-login-probe.sh");
        Path ini = PhpHardening.PHP_INI, pool = PhpHardening.POOL, rot = PhpHardening.ROTATION, config = RoundcubeCipher.CONFIG;
        String iniBefore = Files.readString(ini), poolBefore = Files.readString(pool), configBefore = Files.readString(config);
        String rotBefore = Files.exists(rot) ? Files.readString(rot) : null;

        System.out.println("== 1. 238 as on the real server: no php.ini");
        check("before: the pool without the limit, config.inc.php without cipher_method", !PhpHardening.hasLimit(poolBefore)
                && !configBefore.contains("cipher_method"));
        Files.move(ini, Path.of("/var/tmp/php.ini.e2e-238"));
        PhpHardening.real().fpmReload();
        Thread.sleep(2000);
        check("without php.ini the webmail answers with X-Powered-By (the fault)", poweredBy());
        PhpHardening.Result r = PhpHardening.run(PhpHardening.real(), ini, pool, rot, 30);
        check("DONE (" + r.detail() + ")", r.outcome() == PhpHardening.Outcome.DONE);
        check("  php.ini is PhpHardening.INI, root:wheel 0644", PhpHardening.INI.equals(Files.readString(ini))
                && sh("stat -f '%Su:%Sg %Sp' " + ini).equals("root:wheel -rw-r--r--"));
        check("  X-Powered-By gone, the login page there", page() != null && !poweredBy());
        check("  the pool with the limit, php-fpm -t accepts it", PhpHardening.hasLimit(Files.readString(pool))
                && Shell.run(Duration.ofSeconds(30), "php-fpm", "-t").success());
        check("  php-fpm runs the pool roundcube as roundcube only", sh("ps -axww -o user= -o command= | grep '[p]hp-fpm: pool roundcube' | awk '{print $1}' | sort -u").equals("roundcube"));
        check("  the CLI reads it too: session upload progress off", sh("php -r 'echo var_export(ini_get(\"session.upload_progress.enabled\"), true);'").equals("''")
                || sh("php -r 'echo ini_get(\"session.upload_progress.enabled\");'").equals("0"));
        check("  a second run: NOTHING", PhpHardening.run(PhpHardening.real(), ini, pool, rot, 30).outcome() == PhpHardening.Outcome.NOTHING);

        System.out.println("\n== 2. A fault from the state of before");
        Files.delete(ini);
        if (rotBefore == null) Files.deleteIfExists(rot);
        PhpHardening.real().write(pool, poolBefore);
        PhpHardening.real().fpmReload();
        Thread.sleep(2000);
        PhpHardening.Services refuses = with(PhpHardening.Services.class, PhpHardening.real(), "fpmTest", a -> false);
        r = PhpHardening.run(refuses, ini, pool, rot, 30);
        Thread.sleep(2000);
        check("php-fpm -t refusing: ROLLED_BACK (" + r.detail() + ")", r.outcome() == PhpHardening.Outcome.ROLLED_BACK);
        check("  no php.ini, the pool as before, X-Powered-By again", !Files.exists(ini) && Files.readString(pool).equals(poolBefore) && poweredBy());
        r = PhpHardening.run(PhpHardening.real(), ini, pool, rot, 30);
        check("then DONE again", r.outcome() == PhpHardening.Outcome.DONE && !poweredBy());

        System.out.println("\n== 3. 239: AES-256-CBC");
        check("before: the probe's real webmail login works with DES-EDE3-CBC", webmailLogin(probe));
        RoundcubeCipher.Result c = RoundcubeCipher.run(RoundcubeCipher.real(null), config);
        check("DONE (" + c.detail() + ")", c.outcome() == RoundcubeCipher.Outcome.DONE);
        String after = Files.readString(config);
        check("  AES-256-CBC and a 32-character key, root:roundcube 0640", after.contains("$config['cipher_method'] = 'AES-256-CBC';")
                && after.matches("(?s).*\\$config\\['des_key'\\] = '[A-Za-z0-9]{32}';\n.*")
                && sh("stat -f '%Su:%Sg %Sp' " + config).equals("root:roundcube -rw-r-----"));
        check("  PHP encrypts and decrypts with them", RoundcubeCipher.real(null).cipherWorks(config));
        Thread.sleep(3000);   // OPcache: revalidate_freq = 2
        check("  the probe's real login opens the mailbox with its folders", webmailLogin(probe));
        check("  a second run: NOTHING", RoundcubeCipher.run(RoundcubeCipher.real(null), config).outcome() == RoundcubeCipher.Outcome.NOTHING);

        System.out.println("\n== 4. A fault from the state of before");
        RoundcubeCipher.real(null).write(config, configBefore);
        RoundcubeCipher.Services phpRefuses = with(RoundcubeCipher.Services.class, RoundcubeCipher.real(null), "cipherWorks", a -> false);
        c = RoundcubeCipher.run(phpRefuses, config);
        check("PHP refusing the cipher: ROLLED_BACK (" + c.detail() + ")", c.outcome() == RoundcubeCipher.Outcome.ROLLED_BACK);
        check("  config.inc.php byte for byte, root:roundcube 0640", Files.readString(config).equals(configBefore)
                && sh("stat -f '%Su:%Sg %Sp' " + config).equals("root:roundcube -rw-r-----"));
        c = RoundcubeCipher.run(RoundcubeCipher.real(null), config);
        Thread.sleep(3000);
        check("then DONE again, and the real login works", c.outcome() == RoundcubeCipher.Outcome.DONE && webmailLogin(probe));

        System.out.println("\n(php.ini of before kept in /var/tmp/php.ini.e2e-238, " + iniBefore.length() + " bytes)");
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
