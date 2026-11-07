package org.mail_panel.system;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * When the periodic report decides to go.
 *
 * It must be tested because its defect showed on no screen: on a failed send only the outcome was
 * written, not the date, and the date was the only thing this method looked at. The condition
 * "six days have passed" stayed true forever and the scheduler retried at every tick — one every
 * quarter of an hour, ninety-six a day towards somebody else's SMTP server. Each single try, taken
 * alone, was legitimate.
 */
public class ReportScheduleTest {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    private static final LocalDateTime NOW = LocalDateTime.of(2026, 9, 3, 18, 0);
    private static int failed = 0;

    private static String hoursAgo(int hours) { return NOW.minusHours(hours).format(ISO); }

    public static void main(String[] args) {
        // --- The case that broke in production ---
        // Weekly, last SUCCESSFUL send eight days ago, last failed try a minute ago. Without the
        // fix it retried here, and it would have retried at the next tick, and the one after,
        // indefinitely.
        real("after a failure it does not retry at once",
            !PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(0), "failed: auth", NOW));
        real("it does not retry after 5 hours either",
            !PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(5), "failed: auth", NOW));
        // But it must not stop forever either: after the pause it retries.
        real("after 6 hours it retries",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(6), "failed: auth", NOW));
        real("after 7 hours it retries",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(7), "failed: auth", NOW));

        // --- The pause must NOT slow down the normal case ---
        real("last outcome successful: it goes as before",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(0), "delivered", NOW));
        real("never sent: it goes",
            PeriodicReport.isTheMoment("weekly", "8", "", "", "", NOW));
        real("weekly, 3 days ago: it does NOT go",
            !PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 3), "", "", NOW));
        real("daily, 21 hours ago: it goes",
            PeriodicReport.isTheMoment("daily", "8", hoursAgo(21), "", "", NOW));
        real("monthly, 10 days ago: it does NOT go",
            !PeriodicReport.isTheMoment("monthly", "8", hoursAgo(24 * 10), "", "", NOW));
        real("before the set hour: it does NOT go",
            !PeriodicReport.isTheMoment("weekly", "20", hoursAgo(24 * 8), "", "", NOW));

        // --- An unreadable value must not block forever ---
        // The pause exists so as not to hammer somebody else's server, not to silence the report:
        // if the try's date cannot be read, it goes on instead of standing still.
        real("unreadable try date: it does not block",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), "garbage", "failed: auth", NOW));
        real("try never recorded: it does not block",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), "", "failed: auth", NOW));
        real("no outcome: it does not block",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), hoursAgo(0), "", NOW));

        // --- Clock gone backwards ---
        real("try in the future: it does not block",
            PeriodicReport.isTheMoment("weekly", "8", hoursAgo(24 * 8), NOW.plusHours(3).format(ISO),
                "failed: auth", NOW));

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
