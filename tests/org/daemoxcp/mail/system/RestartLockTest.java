package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;

import org.daemoxcp.mail.webserver.Access;

/**
 * The rules behind "no change while a restart is scheduled" (RestartLock, finding 200), with no system underneath:
 *
 *  1. which requests change something (Access.changes): GET never; a POST does, unless its action only reads or its
 *     permission only views;
 *  2. what stays possible with the restart scheduled: cancelling it, restarting now, its state, and nothing else;
 *  3. the time of the restart from ps ("seconds command"): "+N" minutes and "now"; any other form: unknown (0);
 *  4. the time the panel records when it schedules the restart, and that cancelling removes it.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RestartLockTest
 */
public class RestartLockTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. which requests change something ==");
        // As /api/updates: reads mapped to system.view, the rest system.manage, service_users declared as a read.
        Access updates = Access.api("system.view", "system.manage", Access.actions("system.view", "os_status", "reboot_state"))
                .reading("service_users");
        check("GET never changes", !updates.changes("GET", null) && !updates.changes("HEAD", "os_patch_install"));
        check("a POST read mapped to the view permission does not change", !updates.changes("POST", "os_status"));
        check("a POST action declared as a read does not change", !updates.changes("POST", "service_users"));
        check("a POST action with the manage permission changes", updates.changes("POST", "os_patch_install")
                && updates.changes("POST", "reboot_now") && updates.changes("POST", null));
        // As /api/dkim: the read actions declared with reading(), rotate_check left as a change (it writes the state).
        Access dkim = Access.api("dns.view", "dns.manage").reading("domains_summary", "orphans_scan", "rotate_status", "schedule_get");
        check("DKIM: the four reads do not change", !dkim.changes("POST", "domains_summary") && !dkim.changes("POST", "orphans_scan")
                && !dkim.changes("POST", "rotate_status") && !dkim.changes("POST", "schedule_get"));
        check("DKIM: rotate_check and generate change", dkim.changes("POST", "rotate_check") && dkim.changes("POST", "generate"));
        check("a route whose only permission views never changes (/api/status)", !Access.api("home.view").changes("POST", null));
        check("a route whose only permission manages changes on POST (/api/pop3)", Access.api("settings.manage").changes("POST", null)
                && !Access.api("settings.manage").changes("GET", null));
        check("public routes and pages are not API changes (sign-in, sign-out)", !Access.PUBLIC.changes("POST", null)
                && !Access.page("home.view").changes("POST", null));
        check("a DELETE changes", Access.api("mail.view", "domains.manage").changes("DELETE", null));

        System.out.println("\n== 2. what stays possible ==");
        check("cancelling, restarting now and the state stay possible", RestartLock.exempt("/api/updates", "reboot_cancel")
                && RestartLock.exempt("/api/updates", "reboot_now") && RestartLock.exempt("/api/updates", "reboot_state"));
        check("nothing else: a job, another route, no action", !RestartLock.exempt("/api/updates", "os_patch_install")
                && !RestartLock.exempt("/api/updates", "package_update") && !RestartLock.exempt("/api/domains", "reboot_cancel")
                && !RestartLock.exempt("/api/updates", null) && !RestartLock.exempt(null, "reboot_cancel"));

        System.out.println("\n== 3. the time from ps ==");
        long now = 1_800_000_000_000L;
        check("the panel's command: started 300 s ago, +5 minutes -> now", RestartLock.atFromPs(
                "300 /sbin/shutdown -r +5 Restart requested by DaemoxCP Mail", now) == now);
        check("+15, started 60 s ago", RestartLock.atFromPs("60 shutdown -r +15 msg", now) == now - 60_000 + 15 * 60_000);
        check("now: when it started", RestartLock.atFromPs("2 shutdown -r now", now) == now - 2_000);
        check("an absolute time (2330) or no time: unknown", RestartLock.atFromPs("10 shutdown -r 2330", now) == 0
                && RestartLock.atFromPs("10 shutdown -r", now) == 0);
        check("a line of another shape: unknown", RestartLock.atFromPs("", now) == 0 && RestartLock.atFromPs("x shutdown -r +5", now) == 0
                && RestartLock.atFromPs("10", now) == 0);

        System.out.println("\n== 4. the recorded time ==");
        Path dir = Files.createTempDirectory("restart-lock");
        Path before = RestartLock.AT;
        try {
            RestartLock.AT = dir.resolve("reboot-at");
            RestartLock.record("4321", now);
            check("recorded: pid and time", Files.readString(RestartLock.AT).trim().equals("4321 " + now));
            RestartLock.record("not-a-pid", now);
            check("a pid of another shape is not written", Files.readString(RestartLock.AT).trim().equals("4321 " + now));
            RestartLock.cleared();
            check("cancelled: the file is gone", !Files.exists(RestartLock.AT));
            RestartLock.cleared();
            check("cancelling twice is not an error", !Files.exists(RestartLock.AT));
        } finally {
            RestartLock.AT = before;
            Files.deleteIfExists(dir.resolve("reboot-at"));
            Files.deleteIfExists(dir);
        }

        check("the state's two constants: none is known, unknown is not", RestartLock.State.NONE.known() && !RestartLock.State.NONE.scheduled()
                && !RestartLock.State.UNKNOWN.known());
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
