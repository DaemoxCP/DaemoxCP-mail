package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A service that was not running before either is not a service that fell.
 *
 * Four jobs ended with a picture of the services, and three of them counted as a failure ANY
 * service not running at that moment, without knowing how it was before.
 *
 * Measured on the FreeBSD 15.1 VM on 23/10/2026: a guided update of nginx that succeeded at every
 * step — plan respected (signature 24ddf05e8623c1d2), nginx 1.30.5_2,3 -> 1.30.6,3, configuration
 * accepted, service restarted with a new pid (68238 -> 16297), vulnerabilities queried, package
 * protected again — ended in "error" with "Update done, but a service did not come back as it
 * should". The two services: local_unbound, which is not even enabled on that machine, and ntpd,
 * which has not been starting since before.
 *
 * An alarm that always rings teaches people to ignore it, and when it rings for real nobody tells
 * it apart. That is why the checks below measure BOTH directions: that a real failure is still
 * caught, and that a service stopped since before does not become one.
 *
 * The panel's messages are read in English (I18n.setCurrent): outside a request it writes Italian.
 */
public class ServiceFallTest {

    private static int failures = 0;

    public static void main(String[] args) {
        I18n.setCurrent("en");

        // --- The case measured on the VM: 13 services, two stopped since before ---
        Map<String, Boolean> before = vmServices(), now = vmServices();
        UpdateManager.Job j = new UpdateManager.Job("test", "test");
        boolean fallen = UpdateManager.fallenServices(j, before, now);
        String log = j.toJson().optString("consoleLog", "");
        check("the measured machine: no service fell", !fallen);
        check("  local_unbound still appears in the picture", log.contains("local_unbound"));
        check("  and ntpd too", log.contains("ntpd"));
        check("  no alarm in the log", !log.toUpperCase().contains("ALARM"));

        // --- A real failure is still seen: it was running, now it is not ---
        Map<String, Boolean> afterFault = vmServices();
        afterFault.put("dovecot", false);
        UpdateManager.Job j2 = new UpdateManager.Job("test2", "test");
        check("a service that was running and now is not: fallen",
             UpdateManager.fallenServices(j2, before, afterFault));
        String log2 = j2.toJson().optString("consoleLog", "");
        check("  and the log names it", log2.contains("dovecot"));
        check("  with an alarm", log2.toUpperCase().contains("ALARM"));

        // --- A service the update STARTED is not a failure ---
        Map<String, Boolean> turnedOn = vmServices();
        turnedOn.put("ntpd", true);
        UpdateManager.Job j3 = new UpdateManager.Job("test3", "test");
        check("a service stopped before and running now: no failure",
             !UpdateManager.fallenServices(j3, before, turnedOn));
        check("  and it does not say it was not running before either, because now it is",
             !j3.toJson().optString("consoleLog", "").contains("ntpd: running ("));

        // --- A service that VANISHED (the package went away) while it was running ---
        Map<String, Boolean> vanished = vmServices();
        vanished.remove("rspamd");
        UpdateManager.Job j4 = new UpdateManager.Job("test4", "test");
        check("a running service that no longer exists: fallen",
             UpdateManager.fallenServices(j4, before, vanished));
        check("  and the log names it", j4.toJson().optString("consoleLog", "").contains("rspamd"));

        // --- A service that appeared now shows in the picture ---
        Map<String, Boolean> appeared = vmServices();
        appeared.put("opendkim", true);
        UpdateManager.Job j5 = new UpdateManager.Job("test5", "test");
        check("a service that appeared with the update is not a failure",
             !UpdateManager.fallenServices(j5, before, appeared));
        check("  but it shows in the picture", j5.toJson().optString("consoleLog", "").contains("opendkim"));

        // --- Everything running before and after ---
        Map<String, Boolean> all = new LinkedHashMap<>();
        all.put("postfix", true); all.put("dovecot", true);
        UpdateManager.Job j6 = new UpdateManager.Job("test6", "test");
        check("everything running before and after: no failure",
             !UpdateManager.fallenServices(j6, all, new LinkedHashMap<>(all)));

        // --- No starting state: no failure is made up ---
        // It happens if servicesState() found no rc.d script. Without a "before" nothing can be
        // said to have fallen, and saying so would be an invented alarm.
        UpdateManager.Job j7 = new UpdateManager.Job("test7", "test");
        check("without a starting state no failure is declared",
             !UpdateManager.fallenServices(j7, new LinkedHashMap<>(), vmServices()));

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /** The VM's services as the measurement of 23/10/2026 saw them. */
    private static Map<String, Boolean> vmServices() {
        Map<String, Boolean> m = new LinkedHashMap<>();
        for (String s : new String[]{"postfix", "dovecot", "rspamd", "redis", "clamav_clamd",
                                     "clamav_freshclam", "mysql-server", "nginx", "php_fpm",
                                     "fail2ban", "pf"}) m.put(s, true);
        m.put("local_unbound", false);   // not even enabled on that machine
        m.put("ntpd", false);            // enabled but not starting, since before the update
        return m;
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
