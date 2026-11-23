package org.daemoxcp.mail.security;

import org.daemoxcp.mail.database.MailDatabase;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Background scheduler for DKIM rotation.
 *
 * Tasks (every tick = every hour):
 *
 *  1) For domains in state "pending_dns": check DNS propagation of the pending key.
 *     If found -> the state changes to "propagated".
 *
 *  2) For domains in state "propagated" for at least AUTO_ACTIVATE_AFTER_HOURS hours:
 *     if the domain has a Cloudflare account (automatic rotation), activate the key.
 *     In manual mode, activation is left to the user.
 *
 *  3) For domains in state "active_grace" for at least GRACE_PERIOD_DAYS days:
 *     if the domain has a Cloudflare account, complete the rotation automatically
 *     (delete the previous key from the DB + Cloudflare). Otherwise wait for the user.
 *
 *  4) SCHEDULED ROTATION: for each domain with dkim_rotation_interval_days > 0,
 *     if >= intervalDays days have passed since the last rotation (or if no rotation
 *     has ever been done), and there is no rotation already in progress:
 *     automatically start startRotation(automatic=true).
 *     Prerequisite for full automation: the domain must have a Cloudflare
 *     account assigned. Without CF, the scheduler does NOT start the rotation and
 *     the UI only shows the "rotation recommended" warning.
 */
public class DkimRotationScheduler {

    /** Grace period (days) before completing the rotation. */
    public static final int GRACE_PERIOD_DAYS = 7;

    /** Hours to wait after "propagated" before activating automatically. */
    public static final int AUTO_ACTIVATE_AFTER_HOURS = 24;

    private final MailDatabase database;
    private final DkimManager dkim;
    private final ScheduledExecutorService scheduler;

    public DkimRotationScheduler(MailDatabase database, DkimManager dkim) {
        this.database = database;
        this.dkim = dkim;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "DKIM-Rotation-Scheduler");
            t.setDaemon(true);
            return t;
        });
    }

    /** Starts the scheduler. Call it only once, at server startup. */
    public void start() {
        scheduler.scheduleAtFixedRate(this::tick, 60, 3600, TimeUnit.SECONDS);
        System.out.println("[DKIM-Rotation] Scheduler started (hourly tick: propagation, auto-activate, auto-complete, scheduled rotation)");
    }

    public void stop() {
        scheduler.shutdownNow();
        try {
            scheduler.awaitTermination(2, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void tick() {
        // Mark all events logged during the tick as "scheduler"
        DkimManager.CURRENT_TRIGGER.set("scheduler");
        try {
            // 1) + 2) + 3): handling of domains with a rotation in progress
            try {
                for (MailDatabase.Domain d : database.getDomainsInRotation()) {
                    handleDomainInRotation(d);
                }
            } catch (Exception e) {
                System.err.println("[DKIM-Rotation] Tick error (in-rotation): " + e.getMessage());
            }

            // 4): scheduled rotation
            try {
                for (MailDatabase.Domain d : database.getDomainsWithRotationSchedule()) {
                    handleScheduledRotation(d);
                }
            } catch (Exception e) {
                System.err.println("[DKIM-Rotation] Tick error (schedule): " + e.getMessage());
            }
        } finally {
            DkimManager.CURRENT_TRIGGER.remove();
        }
    }

    private void handleDomainInRotation(MailDatabase.Domain d) {
        try {
            String state = d.dkimRotationState;
            if (state == null) return;

            if ("pending_dns".equals(state)) {
                DkimManager.PropagationCheckResult res = dkim.checkPropagation(d.id);
                if (res.success && res.propagated) {
                    System.out.println("[DKIM-Rotation] " + d.domain + ": pending key '" + d.dkimPendingSelector + "' propagated in DNS");
                }
                return;
            }

            if ("propagated".equals(state)) {
                // Auto-activate only if there is a CF account (i.e. "automatic" rotation wanted)
                if (d.cloudflareAccountId <= 0) return;
                if (d.dkimRotationStartedAt == null) return;
                long elapsedMs = System.currentTimeMillis() - d.dkimRotationStartedAt.getTime();
                long thresholdMs = AUTO_ACTIVATE_AFTER_HOURS * 60L * 60L * 1000L;
                if (elapsedMs >= thresholdMs) {
                    DkimManager.RotationActionResult r = dkim.activatePending(d.id, false);
                    System.out.println("[DKIM-Rotation] " + d.domain + ": auto-activate -> " + r.message);
                }
                return;
            }

            if ("active_grace".equals(state)) {
                // Auto-complete after grace_period
                if (d.dkimRotationActivatedAt == null) return;
                if (!isGracePeriodOver(d.dkimRotationActivatedAt)) return;
                // Complete only if the user has automatic rotation (CF assigned)
                if (d.cloudflareAccountId <= 0) return;
                DkimManager.RotationActionResult r = dkim.completeRotation(d.id);
                System.out.println("[DKIM-Rotation] " + d.domain + ": auto-complete -> " + r.message);
            }
        } catch (Exception e) {
            System.err.println("[DKIM-Rotation] Error on " + d.domain + ": " + e.getMessage());
        }
    }

    private void handleScheduledRotation(MailDatabase.Domain d) {
        try {
            if (d.dkimRotationIntervalDays <= 0) return;
            // Do not start a rotation if one is already in progress
            if (d.dkimRotationState != null) return;
            // A Cloudflare account is needed to activate automatic rotation
            // (without CF, there is no way to publish the DNS record on our own)
            if (d.cloudflareAccountId <= 0) return;
            // The domain must have DKIM configured (otherwise there is nothing to rotate)
            if (!d.hasDkim) return;

            // Check whether it is time to rotate
            long intervalMs = (long) d.dkimRotationIntervalDays * 24L * 60L * 60L * 1000L;
            long now = System.currentTimeMillis();
            boolean due;
            if (d.dkimLastRotationAt == null) {
                // Never rotated -> rotate now
                due = true;
            } else {
                due = (now - d.dkimLastRotationAt.getTime()) >= intervalMs;
            }
            if (!due) return;

            System.out.println("[DKIM-Rotation] " + d.domain + ": scheduled rotation due (interval="
                + d.dkimRotationIntervalDays + "d, last=" + d.dkimLastRotationAt + ") — starting automatically");
            DkimManager.RotationStartResult res = dkim.startRotation(d.id, true);
            if (!res.success) {
                System.err.println("[DKIM-Rotation] " + d.domain + ": scheduled rotation failed: " + res.error);
            } else {
                System.out.println("[DKIM-Rotation] " + d.domain + ": new pending key '" + res.pendingSelector + "' created by the schedule");
            }
        } catch (Exception e) {
            System.err.println("[DKIM-Rotation] Schedule error on " + d.domain + ": " + e.getMessage());
        }
    }

    /**
     * Computes whether the grace period is over (>= GRACE_PERIOD_DAYS since activation).
     * Used by the UI to show the "Complete rotation" button.
     */
    public static boolean isGracePeriodOver(java.sql.Timestamp activatedAt) {
        if (activatedAt == null) return false;
        long elapsedMs = System.currentTimeMillis() - activatedAt.getTime();
        long graceMs = GRACE_PERIOD_DAYS * 24L * 60L * 60L * 1000L;
        return elapsedMs >= graceMs;
    }
}
