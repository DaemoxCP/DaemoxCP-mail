package org.mail_panel.security;

import org.mail_panel.database.MailDatabase;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Background scheduler per la rotazione DKIM.
 *
 * Compiti (ogni tick = ogni ora):
 *
 *  1) Per domini con stato "pending_dns": check propagazione DNS della chiave pending.
 *     Se trovata → stato passa a "propagated".
 *
 *  2) Per domini con stato "propagated" da almeno AUTO_ACTIVATE_AFTER_HOURS ore:
 *     se il dominio ha un account Cloudflare (rotazione automatica), attiva la chiave.
 *     In modalità manuale, lascia all'utente l'attivazione.
 *
 *  3) Per domini con stato "active_grace" da almeno GRACE_PERIOD_DAYS giorni:
 *     se il dominio ha un account Cloudflare, completa la rotazione automaticamente
 *     (cancella la previous key dal DB + Cloudflare). Altrimenti aspetta l'utente.
 *
 *  4) ROTAZIONE PROGRAMMATA: per ogni dominio con dkim_rotation_interval_days > 0,
 *     se sono passati >= intervalDays giorni dall'ultima rotazione (o se non è mai
 *     stata fatta una rotazione), e non c'è già una rotazione in corso:
 *     avvia automaticamente startRotation(automatic=true).
 *     Pre-requisito per il pieno automatismo: il dominio deve avere un account
 *     Cloudflare assegnato. Senza CF, lo scheduler NON parte la rotazione e
 *     l'UI mostra solo l'avviso "rotazione consigliata".
 */
public class DkimRotationScheduler {

    /** Grace period (giorni) prima di completare la rotazione. */
    public static final int GRACE_PERIOD_DAYS = 7;

    /** Ore di attesa dopo "propagated" prima di attivare automaticamente. */
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

    /** Avvia lo scheduler. Chiamare una volta sola all'avvio del server. */
    public void start() {
        scheduler.scheduleAtFixedRate(this::tick, 60, 3600, TimeUnit.SECONDS);
        System.out.println("[DKIM-Rotation] Scheduler avviato (tick orario: propagation, auto-activate, auto-complete, scheduled rotation)");
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
        // Marca tutti gli eventi loggati durante il tick come "scheduler"
        DkimManager.CURRENT_TRIGGER.set("scheduler");
        try {
            // 1) + 2) + 3): gestione domini con rotazione in corso
            try {
                for (MailDatabase.Domain d : database.getDomainsInRotation()) {
                    handleDomainInRotation(d);
                }
            } catch (Exception e) {
                System.err.println("[DKIM-Rotation] Errore nel tick (in-rotation): " + e.getMessage());
            }

            // 4): rotazione programmata
            try {
                for (MailDatabase.Domain d : database.getDomainsWithRotationSchedule()) {
                    handleScheduledRotation(d);
                }
            } catch (Exception e) {
                System.err.println("[DKIM-Rotation] Errore nel tick (schedule): " + e.getMessage());
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
                    System.out.println("[DKIM-Rotation] " + d.domain + ": chiave pending '" + d.dkimPendingSelector + "' propagata in DNS");
                }
                return;
            }

            if ("propagated".equals(state)) {
                // Auto-attiva solo se c'è un account CF (cioè rotazione "automatica" voluta)
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
                // Auto-completa dopo grace_period
                if (d.dkimRotationActivatedAt == null) return;
                if (!isGracePeriodOver(d.dkimRotationActivatedAt)) return;
                // Completa solo se l'utente ha rotazione automatica (CF assegnato)
                if (d.cloudflareAccountId <= 0) return;
                DkimManager.RotationActionResult r = dkim.completeRotation(d.id);
                System.out.println("[DKIM-Rotation] " + d.domain + ": auto-complete -> " + r.message);
            }
        } catch (Exception e) {
            System.err.println("[DKIM-Rotation] Errore su " + d.domain + ": " + e.getMessage());
        }
    }

    private void handleScheduledRotation(MailDatabase.Domain d) {
        try {
            if (d.dkimRotationIntervalDays <= 0) return;
            // Non avviare una rotazione se ce n'è già una in corso
            if (d.dkimRotationState != null) return;
            // Serve un account Cloudflare per attivare la rotazione automatica
            // (senza CF, non c'è modo di pubblicare il record DNS in autonomia)
            if (d.cloudflareAccountId <= 0) return;
            // Il dominio deve avere DKIM configurato (altrimenti non c'è nulla da ruotare)
            if (!d.hasDkim) return;

            // Verifica se è ora di ruotare
            long intervalMs = (long) d.dkimRotationIntervalDays * 24L * 60L * 60L * 1000L;
            long now = System.currentTimeMillis();
            boolean due;
            if (d.dkimLastRotationAt == null) {
                // Mai ruotato → ruota subito
                due = true;
            } else {
                due = (now - d.dkimLastRotationAt.getTime()) >= intervalMs;
            }
            if (!due) return;

            System.out.println("[DKIM-Rotation] " + d.domain + ": rotazione programmata dovuta (interval="
                + d.dkimRotationIntervalDays + "d, last=" + d.dkimLastRotationAt + ") — avvio automatico");
            DkimManager.RotationStartResult res = dkim.startRotation(d.id, true);
            if (!res.success) {
                System.err.println("[DKIM-Rotation] " + d.domain + ": rotazione programmata fallita: " + res.error);
            } else {
                System.out.println("[DKIM-Rotation] " + d.domain + ": nuova chiave pending '" + res.pendingSelector + "' creata via schedule");
            }
        } catch (Exception e) {
            System.err.println("[DKIM-Rotation] Errore schedule su " + d.domain + ": " + e.getMessage());
        }
    }

    /**
     * Calcola se il grace period è terminato (>= GRACE_PERIOD_DAYS dall'attivazione).
     * Usato dalla UI per mostrare il pulsante "Completa rotazione".
     */
    public static boolean isGracePeriodOver(java.sql.Timestamp activatedAt) {
        if (activatedAt == null) return false;
        long elapsedMs = System.currentTimeMillis() - activatedAt.getTime();
        long graceMs = GRACE_PERIOD_DAYS * 24L * 60L * 60L * 1000L;
        return elapsedMs >= graceMs;
    }
}
