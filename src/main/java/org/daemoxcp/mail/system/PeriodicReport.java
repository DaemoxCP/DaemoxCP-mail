package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.util.Shell;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The periodic report that the panel sends to itself.
 *
 * Why it exists: the panel's tabs say everything, but only to whoever opens them. A server that
 * works is almost never opened, and the things to do - a vulnerability that finally has a
 * fix, a certificate about to expire, a release that goes out of support - arrive without
 * anyone watching.
 *
 * Three principles:
 *
 *  1. WHAT THERE IS TO DO GOES AT THE TOP, not the status. If there is nothing to do, the email
 *     says so in one line: a report that always looks the same stops being read, and the
 *     day it contains something nobody notices.
 *  2. SENDING GOES THROUGH POSTFIX, with ITS sendmail(1): not with the first sendmail in the
 *     PATH, which on FreeBSD is mailwrapper and hands over to dma (see postfixSendmail). The
 *     panel runs ON the mail server: no SMTP credentials to guard, no configuration that
 *     could diverge, and the message goes out DKIM-signed like any other.
 *  3. THE OUTCOME IS VERIFIED. sendmail accepts the message and returns 0 even when the
 *     delivery will fail later, and it also returned 0 when the message did not go through
 *     Postfix at all. So the panel follows the message in the mail log, by its Message-ID,
 *     and records what the recipient's server answered: not "sendmail said 0", which means
 *     nothing.
 */
public final class PeriodicReport {

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    private final ScheduledExecutorService scheduler;

    public PeriodicReport() {
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "periodic-report");
            t.setDaemon(true);
            return t;
        });
    }

    /** Every quarter of an hour it checks whether it is time. The real work happens rarely. */
    public void start() {
        scheduler.scheduleAtFixedRate(this::tick, 120, 900, TimeUnit.SECONDS);
        System.out.println("[Report] Scheduler started (checks every 15 minutes whether it is time to send)");
    }

    public void stop() {
        scheduler.shutdownNow();
        try { scheduler.awaitTermination(2, TimeUnit.SECONDS); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ===================== settings =====================

    /**
     * The saved frequency, with the current names. Until 2026-10-24 it was saved with the previous
     * names (data file, reportFrequencies): a schedule already set up must keep applying.
     */
    static String normalizedFrequency(String f) {
        return LegacyNames.current("reportFrequencies", f);
    }

    /** The outcome of a failed send starts like this, and the scheduler recognizes it by this. */
    static final String FAILED_PREFIX = "failed: ";
    /**
     * The outcome with the current prefix. Until 2026-10-24 a different one was written (data file,
     * reportFailedPrefix): an outcome already saved must be recognized.
     */
    static String currentOutcome(String outcome) {
        for (String old : LegacyNames.oldNamesOf("reportFailedPrefix", FAILED_PREFIX))
            if (!old.isEmpty() && outcome.startsWith(old)) return FAILED_PREFIX + outcome.substring(old.length());
        return outcome;
    }

    static boolean isFailedOutcome(String outcome) {
        return currentOutcome(outcome).startsWith(FAILED_PREFIX);
    }

    /** The outcome as whoever opens the page reads it: the prefix is a code, not a text. */
    static String shownOutcome(String outcome) {
        String o = currentOutcome(outcome);
        if (o.startsWith(FAILED_PREFIX))
            return I18n.tr("server.rp.lastFailed", java.util.Map.of("error", o.substring(FAILED_PREFIX.length())));
        return outcome;
    }

    private static String setting(String key, String defaultValue) {
        try { return Main.mailDatabase.getSetting(key, defaultValue); }
        catch (Exception e) { return defaultValue; }
    }

    private static void storeSetting(String key, String value) {
        try { Main.mailDatabase.setSetting(key, value); } catch (Exception ignored) { }
    }

    /**
     * The domain the panel identifies itself with.
     *
     * It is NOT "the first domain in the list": that is the order of a list, and taking it
     * ends up proposing an identity on the domain of a site that has nothing to do with it - it
     * happened, with domain-a.test. The panel has a hostname of its own, mail.domain-b.test: the
     * domain is what comes after the first dot.
     */
    private static String panelDomain() {
        String host = "";
        try { host = Main.mailDatabase.getSetting("mail_hostname", ""); } catch (Exception ignored) { }
        if (host.isEmpty())
            host = Shell.runShell(java.time.Duration.ofSeconds(20),
                    "postconf -h myhostname 2>/dev/null").outputTrim();
        int p = host.indexOf('.');
        if (p > 0 && p + 1 < host.length()) return host.substring(p + 1);
        String d = Shell.runShell(java.time.Duration.ofSeconds(20),
                "postconf -h mydomain 2>/dev/null").outputTrim();
        return d;
    }

    public static JSONObject state() {
        String domain = panelDomain();
        String last = setting("report_last", "");
        JSONObject r = new JSONObject()
                .put("success", true)
                .put("active", "1".equals(setting("report_enabled", "0")))
                .put("sender", setting("report_from", "no-reply@" + domain))
                .put("recipient", setting("report_to", ""))
                .put("frequency", normalizedFrequency(setting("report_freq", "weekly")))
                .put("now", setting("report_hour", "8"))
                .put("domain", domain)
                .put("lastSend", last)
                .put("lastOutcome", shownOutcome(setting("report_last_result", "")));
        r.put("next", describeNext(r));
        return r;
    }

    private static String describeNext(JSONObject s) {
        if (!s.getBoolean("active")) return I18n.tr("server.rp.disabled");
        String freq = s.getString("frequency");
        String now = s.getString("now");
        String u = s.getString("lastSend");
        String every = "daily".equals(freq) ? I18n.tr("server.rp.everyDay")
                    : "monthly".equals(freq) ? I18n.tr("server.rp.everyMonth") : I18n.tr("server.rp.everyWeek");
        return I18n.tr("server.rp.schedule", java.util.Map.of("every", String.valueOf(every), "now", String.valueOf(now)))
                + " " + (u.isEmpty() ? I18n.tr("server.rp.neverSent")
                               : I18n.tr("server.rp.lastSent", java.util.Map.of("when", String.valueOf(u.replace('T', ' ')))));
    }

    /**
     * Saves the settings, validating EVERY field with a whitelist. The addresses end up
     * in a header of the message: a line break inside an address would allow arbitrary
     * headers to be added, which is the classic way of turning a mail form into a relay
     * for anyone.
     */
    public static JSONObject saveSettings(String recipient, String sender,
                                               String frequency, String now, boolean active) {
        JSONObject r = new JSONObject();
        recipient = recipient == null ? "" : recipient.trim();
        sender = sender == null ? "" : sender.trim();

        if (active && recipient.isEmpty())
            return r.put("success", false).put("error", I18n.tr("server.rp.needRecipient"));
        if (!recipient.isEmpty() && !org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(recipient))
            return r.put("success", false).put("error", I18n.tr("server.rp.badRecipient"));
        if (!sender.isEmpty()) {
            if (!org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(sender))
                return r.put("success", false).put("error", I18n.tr("server.rp.badSender"));
            // A real whitelist: not "it is a well-formed address", but "it is ONE OF the mailboxes
            // that exist on this panel's domain". The panel knows the list, so the check
            // can be exact instead of approximate.
            JSONObject id = identityState();
            JSONArray choices = id.optJSONArray("availableMailboxes");
            boolean allowed = false;
            if (choices != null)
                for (int i = 0; i < choices.length(); i++)
                    if (choices.getString(i).equalsIgnoreCase(sender)) allowed = true;
            if (!allowed)
                return r.put("success", false).put("availableMailboxes", choices == null ? new JSONArray() : choices)
                        .put("error", I18n.tr("server.rp.senderMustExist", java.util.Map.of("domain", String.valueOf(id.optString("panelDomain", "?")))) + " "
                                + (choices == null || choices.length() == 0
                                   ? I18n.tr("server.rp.noMailboxYet")
                                   : I18n.tr("server.rp.pickOne")));
        }
        // No line break may enter a header, in any form.
        for (String v : new String[]{recipient, sender})
            if (v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0 || v.indexOf('\0') >= 0)
                return r.put("success", false).put("error", I18n.tr("server.rp.badAddress"));
        if (!java.util.List.of("daily", "weekly", "monthly").contains(frequency))
            return r.put("success", false).put("error", I18n.tr("server.rp.badFreq"));
        int h;
        try { h = Integer.parseInt(now.trim()); }
        catch (Exception e) { return r.put("success", false).put("error", I18n.tr("server.rp.badHour")); }
        if (h < 0 || h > 23) return r.put("success", false).put("error", I18n.tr("server.rp.hourRange"));

        storeSetting("report_to", recipient);
        if (!sender.isEmpty()) storeSetting("report_from", sender);
        storeSetting("report_freq", frequency);
        storeSetting("report_hour", String.valueOf(h));
        storeSetting("report_enabled", active ? "1" : "0");
        // The automatic report starts by itself, outside any request: it goes out in the language
        // of whoever saved the settings
        storeSetting("report_lang", I18n.current());
        return state().put("success", true).put("note", active
                ? I18n.tr("server.rp.savedOn", java.util.Map.of("recipient", String.valueOf(recipient)))
                : I18n.tr("server.rp.savedOff"));
    }

    /** The message that would be sent, without sending it: sender, subject and text. */
    public static JSONObject preview() {
        try {
            // The preview does not touch the network: the tab promises a read, and must stay one.
            JSONObject data = UpdateManager.reportData(false);
            JSONArray toDo = data.optJSONArray("toDo");
            if (toDo == null) toDo = new JSONArray();
            JSONObject cert = certificateWarning();
            if (cert != null) toDo.put(cert);
            JSONObject release = releaseWarning();
            if (release != null) toDo.put(release);
            data.put("toDo", sortedByUrgency(toDo)).put("certificate", certificateState());
            String server = PanelMail.serverName();
            String sender = setting("report_from", "no-reply@" + panelDomain());
            String recipient = setting("report_to", "");
            String lang = I18n.current();
            PanelMail.Message m = ReportMail.message(new ReportMail.Context(lang, server,
                    recipient.isEmpty() ? I18n.tr("server.rp.noRecipient") : recipient, true,
                    normalizedFrequency(setting("report_freq", "weekly")), java.time.ZonedDateTime.now()), data);
            return new JSONObject().put("success", true)
                    .put("from", PanelMail.address(PanelMail.senderName(lang, server), sender))
                    .put("subject", m.subject())
                    .put("text", m.text())
                    .put("thingsToDo", data.getJSONArray("toDo").length());
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.rp.composeFailed", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e))));
        }
    }

    /** The things to do, most urgent first. When they are equal, the order in which they arrived stays. */
    static JSONArray sortedByUrgency(JSONArray a) {
        java.util.List<JSONObject> l = new java.util.ArrayList<>();
        for (int i = 0; i < a.length(); i++) l.add(a.getJSONObject(i));
        l.sort(java.util.Comparator.comparingInt(x -> x.optInt("urgency", 9)));
        JSONArray sorted = new JSONArray();
        for (JSONObject x : l) sorted.put(x);
        return sorted;
    }

    // ===================== the panel's identity =====================

    /**
     * The panel has no identity until one is created for it.
     *
     * A report can also go out with a sender that does not exist as a mailbox - sendmail
     * accepts it - but it would be a choice paid for later: whoever replies gets a rejection,
     * the recipients' anti-spam checks look at whether the sender exists, and any
     * non-delivery notification would go back nowhere.
     *
     * So the panel creates a real mailbox for itself on the domain it manages. The password is
     * random and of no use to anyone: the report does not log in, it goes out through local
     * sendmail. It stays in the panel's vault like every other mailbox, so it can be recovered
     * if one day those replies really needed to be read.
     */
    /**
     * What already occupies an address: a mailbox, an alias, or nothing.
     *
     * The first version looked ONLY at the mailboxes. On domain-a.test the no-reply address
     * existed as an ALIAS of the site: the panel said "it does not exist", offered to create it,
     * and by creating it put a mailbox in front of a working alias - changing where the mail
     * for that address ends up. A check that looks at half of the things does not say
     * "I don't know": it says "free", and that is much worse.
     */
    private static JSONObject busy(org.daemoxcp.mail.database.MailDatabase.Domain dom, String address)
            throws Exception {
        for (var m : Main.mailDatabase.getMailboxes(dom.id))
            if (m.email != null && m.email.equalsIgnoreCase(address))
                return new JSONObject().put("type", "mailbox").put("name", m.name == null ? "" : m.name)
                        .put("created", m.createdAt == null ? "" : m.createdAt.toString());
        for (var a : Main.mailDatabase.getAliases(dom.id))
            if (a.source != null && a.source.equalsIgnoreCase(address))
                return new JSONObject().put("type", "alias").put("destination", a.destination == null ? "" : a.destination)
                        .put("created", a.createdAt == null ? "" : a.createdAt.toString());
        return null;
    }

    public static JSONObject identityState() {
        JSONObject r = new JSONObject().put("success", true);
        String sender = setting("report_from", "").trim();
        try {
            java.util.List<org.daemoxcp.mail.database.MailDatabase.Domain> domains = Main.mailDatabase.getDomains();
            JSONArray names = new JSONArray();
            for (var d : domains) names.put(d.domain);
            r.put("managedDomains", names).put("sender", sender);

            // An address is NO LONGER proposed on our own. Before, "no-reply@" was chosen on the
            // FIRST domain in the list: an address the panel had never seen, on a domain
            // chosen by the order of a list. Now the address is written by whoever knows what
            // it is for, and the panel only says what is already there.
            String mine = panelDomain();
            org.daemoxcp.mail.database.MailDatabase.Domain myDomain = null;
            for (var d : domains) if (d.domain.equalsIgnoreCase(mine)) myDomain = d;
            r.put("panelDomain", mine).put("panelDomainManaged", myDomain != null);
            boolean myManaged = myDomain != null;

            // The mailboxes that exist on the panel's domain: they are the ONLY valid choices
            // for the sender. A free text field would let anyone write anything in it -
            // including the domain of a site, which is exactly the mistake already made
            // with domain-a.test.
            JSONArray choices = new JSONArray();
            if (myDomain != null)
                for (var m : Main.mailDatabase.getMailboxes(myDomain.id))
                    if (m.email != null) choices.put(m.email);
            r.put("availableMailboxes", choices);
            if (myManaged) {
                String proposed = "no-reply@" + mine;
                boolean proposedExists = false;
                for (int q = 0; q < choices.length(); q++)
                    if (choices.getString(q).equalsIgnoreCase(proposed)) proposedExists = true;
                r.put("suggested", proposed).put("suggestedExists", proposedExists);
            }
            if (sender.isEmpty())
                return r.put("exists", false).put("managedDomain", false).put("toChoose", true)
                        .put("note", I18n.tr("server.rp.pickSender")
                                + (myManaged ? " " + I18n.tr("server.rp.suggestSender", java.util.Map.of("mine", String.valueOf(mine))) : ""));

            String domain = sender.substring(sender.indexOf('@') + 1);
            org.daemoxcp.mail.database.MailDatabase.Domain its = null;
            for (var d : domains) if (d.domain.equalsIgnoreCase(domain)) its = d;
            r.put("domain", domain).put("managedDomain", its != null);
            if (its == null)
                return r.put("exists", false)
                        .put("note", I18n.tr("server.rp.domainNotManaged", java.util.Map.of("domain", String.valueOf(domain))));

            JSONObject already = busy(its, sender);
            r.put("busy", already == null ? JSONObject.NULL : already);
            boolean itsDomain = !mine.isEmpty() && domain.equalsIgnoreCase(mine);
            r.put("onOwnDomain", itsDomain);
            if (already == null)
                return r.put("exists", false).put("creatable", itsDomain)
                        .put("note", itsDomain
                                ? I18n.tr("server.rp.addressFree", java.util.Map.of("sender", String.valueOf(sender)))
                                : I18n.tr("server.rp.addressFreeOther", java.util.Map.of("sender", String.valueOf(sender), "domain", String.valueOf(domain), "mine", String.valueOf(mine))));
            if ("alias".equals(already.optString("type")))
                return r.put("exists", true).put("eAlias", true)
                        .put("note", I18n.tr("server.rp.isAlias", java.util.Map.of("sender", String.valueOf(sender), "destination", String.valueOf(already.optString("destination")))));
            return r.put("exists", true).put("eAlias", false)
                    .put("note", I18n.tr("server.rp.mailboxExists", java.util.Map.of("sender", String.valueOf(sender)))
                            + (already.optString("name").isEmpty() ? "" : " (\"" + already.optString("name") + "\")")
                            + (already.optString("created").isEmpty() ? "" : ", " + I18n.tr("server.rp.createdOn", java.util.Map.of("d", String.valueOf(already.optString("created")))))
                            + ": " + I18n.tr("server.rp.realSender"));
        } catch (Exception e) {
            return new JSONObject().put("success", false)
                    .put("error", I18n.tr("server.rp.readFailed", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e))));
        }
    }

    /** Creates the panel's mailbox. Touches nothing if it already exists. */
    public static JSONObject createIdentity(String address) {
        JSONObject r = new JSONObject().put("address", address);
        if (address == null || !org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(address))
            return r.put("success", false).put("error", I18n.tr("server.rp.badAddressLower"));
        String domain = address.substring(address.indexOf('@') + 1);
        try {
            org.daemoxcp.mail.database.MailDatabase.Domain its = null;
            for (var d : Main.mailDatabase.getDomains()) if (d.domain.equalsIgnoreCase(domain)) its = d;
            if (its == null)
                return r.put("success", false)
                        .put("error", I18n.tr("server.rp.domainNotManaged2", java.util.Map.of("domain", String.valueOf(domain))));
            String mine = panelDomain();
            if (mine.isEmpty())
                return r.put("success", false)
                        .put("error", I18n.tr("server.rp.noPanelDomain"));
            if (!domain.equalsIgnoreCase(mine))
                return r.put("success", false).put("panelDomain", mine)
                        .put("error", I18n.tr("server.rp.onlyOwnDomain", java.util.Map.of("domain", String.valueOf(domain), "mine", String.valueOf(mine))));

            JSONObject already = busy(its, address);
            if (already != null) {
                boolean alias = "alias".equals(already.optString("type"));
                return r.put("success", !alias).put("alreadyExisted", true).put("busy", already)
                        .put(alias ? "error" : "note", alias
                                ? I18n.tr("server.rp.aliasNoCreate", java.util.Map.of("address", String.valueOf(address), "destination", String.valueOf(already.optString("destination"))))
                                : I18n.tr("server.rp.existedAlready"));
            }

            // Strong random password: nobody has to type it, the report does not log in.
            java.security.SecureRandom random = new java.security.SecureRandom();
            String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            StringBuilder pw = new StringBuilder();
            for (int i = 0; i < 32; i++) pw.append(alphabet.charAt(random.nextInt(alphabet.length())));

            int id = Main.mailDatabase.addMailbox(its.id, address, pw.toString(),
                    I18n.tr("server.rp.mailboxName"), 128, true);
            if (id <= 0) return r.put("success", false).put("error", I18n.tr("server.rp.createFailed"));
            storeSetting("report_from", address);
            return r.put("success", true).put("alreadyExisted", false).put("id", id)
                    .put("note", I18n.tr("server.rp.created"));
        } catch (Exception e) {
            return r.put("success", false).put("error", I18n.tr("server.rp.createError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e))));
        }
    }

    // ===================== when to send =====================

    private void tick() {
        try {
            if (!"1".equals(setting("report_enabled", "0"))) return;
            String a = setting("report_to", "");
            if (a.isEmpty()) return;
            if (!isTheMoment()) return;
            // Outside any request: the report goes out in the language of whoever configured it
            I18n.setCurrent(setting("report_lang", "it"));
            JSONObject outcome;
            try { outcome = sendNow(a, true); }
            finally { I18n.clearCurrent(); }
            System.out.println("[Report] automatic send: "
                    + (outcome.optBoolean("success") ? "succeeded" : "FAILED - " + outcome.optString("error")));
        } catch (Exception e) {
            System.out.println("[Report] error in the periodic check: " + e.getMessage());
        }
    }

    /**
     * True if it is time to send. The comparison is on the ELAPSED INTERVAL, not on a
     * calendar: this way a panel switched off for two days sends the report when it comes back
     * up, instead of skipping it because "the right day has passed".
     */
    static boolean isTheMoment(String frequency, String nowText, String lastIso,
                              String lastAttemptIso, String lastOutcome, LocalDateTime now) {
        int hour;
        try { hour = Integer.parseInt(nowText.trim()); } catch (Exception e) { hour = 8; }
        if (hour < 0 || hour > 23) hour = 8;
        if (now.getHour() < hour) return false;

        // A failed send must not be retried every quarter of an hour forever.
        //
        // "report_last" is written only when the send SUCCEEDS, and it was the only date this
        // method looked at: after a failure it stayed old, the condition "six days have
        // passed" stayed true, and the scheduler tried again at the next tick. With wrong
        // credentials that makes 96 attempts a day against someone else's SMTP server, which is
        // the way to get the address blocked. The defect did not show because each attempt,
        // taken on its own, was legitimate.
        //
        // So the LAST ATTEMPT is looked at too, successful or not. The date of the attempt is
        // written BEFORE trying, not after: if the process dies halfway through sending, on
        // restart it must not start again right away.
        if (lastOutcome != null && isFailedOutcome(lastOutcome)
                && lastAttemptIso != null && !lastAttemptIso.isBlank()) {
            try {
                long fromAttempt = java.time.temporal.ChronoUnit.HOURS.between(
                        LocalDateTime.parse(lastAttemptIso, ISO), now);
                if (fromAttempt >= 0 && fromAttempt < HOURS_AFTER_FAILURE) return false;
            } catch (Exception ignore) {
                // Unreadable date: sending is not blocked over a value that cannot be read.
            }
        }

        if (lastIso == null || lastIso.isBlank()) return true;      // never sent
        LocalDateTime last;
        try { last = LocalDateTime.parse(lastIso, ISO); }
        catch (Exception e) { return true; }                            // unreadable date: send
        long hours = java.time.temporal.ChronoUnit.HOURS.between(last, now);
        if (hours < 0) return false;                                      // clock went backwards
        switch (frequency == null ? "" : frequency) {
            case "daily": return hours >= 20;
            case "monthly":     return hours >= 24 * 29;
            default:            return hours >= 24 * 6;                   // settimanale
        }
    }

    /** Hours to wait before retrying after a failed send. */
    static final int HOURS_AFTER_FAILURE = 6;

    private boolean isTheMoment() {
        return isTheMoment(normalizedFrequency(setting("report_freq", "weekly")), setting("report_hour", "8"),
                setting("report_last", ""), setting("report_last_try", ""), setting("report_last_result", ""),
                LocalDateTime.now());
    }

    // ===================== sending =====================

    /** The send requested from the panel ("Send a test now"). */
    public static JSONObject sendNow(String recipient) { return sendNow(recipient, false); }

    /**
     * Collects the data, composes the report and delivers it. "automatic" only says how the
     * message presents itself (weekly report or sent on request): the data and the sending
     * are the same.
     */
    public static JSONObject sendNow(String recipient, boolean automatic) {
        JSONObject r = new JSONObject().put("recipient", recipient);
        if (!org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(recipient))
            return r.put("success", false).put("error", I18n.tr("server.rp.badRecipientLower"));
        String sender = setting("report_from", "no-reply@" + panelDomain());
        if (!org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(sender))
            return r.put("success", false).put("error", I18n.tr("server.rp.badSenderLower", java.util.Map.of("m", String.valueOf(sender))));

        JSONObject data;
        try { data = UpdateManager.reportData(); }
        catch (Exception e) { return r.put("success", false).put("error", I18n.tr("server.rp.collectFailed", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e)))); }
        // Only this class knows the certificate: it is added to the things to do here,
        // and the list is sorted again, otherwise "expires in 3 days" would end up at the bottom.
        JSONArray df = data.optJSONArray("toDo");
        if (df == null) df = new JSONArray();

        JSONObject certWarning = certificateWarning();
        if (certWarning != null) df.put(certWarning);

        // News about the specifications and the deadlines ends up in the report instead of
        // being discovered by chance while doing something else. It is the reason the
        // monitoring exists: a warning nobody goes looking for is not a warning.
        for (JSONObject x : watchWarnings()) df.put(x);
        // A new version of the panel on GitHub: from the last saved check, without the network.
        JSONObject release = releaseWarning();
        if (release != null) df.put(release);
        data.put("toDo", sortedByUrgency(df)).put("certificate", certificateState());

        String server = PanelMail.serverName();
        int howMany = data.getJSONArray("toDo").length();
        PanelMail.Message message = ReportMail.message(new ReportMail.Context(I18n.current(), server, recipient,
                automatic, normalizedFrequency(setting("report_freq", "weekly")), java.time.ZonedDateTime.now()), data);

        // Before trying, not after: if the panel dies during the send, on restart this
        // date is already there and the pause after a failure applies all the same.
        storeSetting("report_last_try", LocalDateTime.now().format(ISO));

        JSONObject outcome = delivery(sender, recipient, message, server, "report");
        r.put("subject", message.subject()).put("body", message.text()).put("sender", sender)
         .put("thingsToDo", howMany).put("output", outcome.optString("output", ""));
        if (outcome.optBoolean("success")) {
            String now = LocalDateTime.now().format(ISO);
            storeSetting("report_last", now);
            storeSetting("report_last_result", outcome.optString("outcome", I18n.tr("server.rp.lastSucceeded")));
            return r.put("success", true).put("when", now)
                    .put("warning", outcome.optBoolean("warning", false))
                    .put("note", outcome.optString("note", ""));
        }
        storeSetting("report_last_result", FAILED_PREFIX + outcome.optString("error", "?"));
        return r.put("success", false).put("error", outcome.optString("error", I18n.tr("server.rp.sendFailed")));
    }

    /**
     * A message from the panel to an administrator (the codes), with the same sender and the
     * same Postfix sendmail as the report. It returns only whether it went out: the body contains
     * a one-time code and must not end up in any log, so sendmail's output and the lines of
     * the mail log are not returned here.
     */
    public static boolean sendPanelMessage(String recipient, PanelMail.Message message) {
        String sender = setting("report_from", "no-reply@" + panelDomain());
        if (!org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(sender)
                || !org.daemoxcp.mail.webserver.SecurityUtils.isValidEmail(recipient)) return false;
        return delivery(sender, recipient, message, PanelMail.serverName(), "code").optBoolean("success", false);
    }

    /**
     * Hands the message to Postfix with its sendmail(1), then follows it in the mail log.
     * The envelope (headers, text and HTML, encodings) is built by PanelMail. The Message-ID is
     * chosen by the panel: it is the thread that ties the message to the lines Postfix writes
     * in the log.
     */
    private static JSONObject delivery(String from, String to, PanelMail.Message m, String server, String kind) {
        JSONObject r = new JSONObject();
        JSONObject chosen = postfixSendmail();
        if (!chosen.optBoolean("success")) return r.put("success", false).put("error", chosen.optString("error"));
        String sendmail = chosen.getString("path");

        String messageId = newMessageId(kind, from);
        String message = PanelMail.compose(PanelMail.senderName(m.lang(), server), from, to, m, messageId,
                java.time.ZonedDateTime.now());
        StringBuilder output = new StringBuilder()
                .append("* ").append(I18n.tr("server.rp.postfixSendmail", java.util.Map.of("p", String.valueOf(sendmail)))).append('\n')
                .append("* Message-ID: <").append(messageId).append(">\n");

        // Where the log ends now: the lines of this message all come after this point.
        long logStart = logSize();
        try {
            ProcessBuilder pb = new ProcessBuilder(sendmail, "-t", "-i", "-f", from);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (OutputStream os = p.getOutputStream()) {
                os.write(message.getBytes(StandardCharsets.UTF_8));
            }
            String said = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (!said.isEmpty()) output.append(said).append('\n');
            r.put("output", output.toString());
            boolean finished = p.waitFor(60, TimeUnit.SECONDS);
            if (!finished) { p.destroyForcibly(); return r.put("success", false).put("error", I18n.tr("server.rp.sendmailTimeout")); }
            int code = p.exitValue();
            r.put("code", code);
            if (code != 0)
                return r.put("success", false).put("error", I18n.tr("server.rp.sendmailExit", java.util.Map.of("c", String.valueOf(code)))
                        + (said.isEmpty() ? "" : ": " + said));
        } catch (Exception e) {
            return r.put("output", output.toString()).put("success", false)
                    .put("error", I18n.tr("server.rp.cannotRun", java.util.Map.of("p", String.valueOf(sendmail), "m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e))));
        }

        // Exit code 0 only says that the message is in Postfix's incoming queue.
        // Where it ended up is what the log says.
        JSONObject log = followInLog(logStart, messageId, to);
        JSONArray lines = log.optJSONArray("lines");
        if (lines != null && lines.length() > 0) {
            output.append("* ").append(I18n.tr("server.rp.fromMaillog", java.util.Map.of("f", String.valueOf(org.daemoxcp.mail.monitoring.LogManager.MAILLOG)))).append('\n');
            for (int i = 0; i < lines.length(); i++) output.append(lines.getString(i)).append('\n');
        } else {
            output.append("* ").append(I18n.tr("server.rp.noLogLine")).append('\n');
        }
        return verdict(log).put("output", output.toString());
    }

    // ===================== which sendmail =====================

    /** The sendmail installed by the Postfix port: tried when postconf does not answer. */
    static final String PORTS_SENDMAIL = "/usr/local/sbin/sendmail";

    /** mailwrapper(8). On FreeBSD /usr/sbin/sendmail is this one, not Postfix. */
    static final String MAILWRAPPER = "/usr/sbin/mailwrapper";

    /**
     * Postfix's OWN sendmail, not "the first sendmail found in the PATH".
     *
     * Until 2026-09-25 it was looked up in the PATH, where /usr/sbin comes before /usr/local/sbin.
     * That found /usr/sbin/sendmail, which on FreeBSD is mailwrapper(8): it hands the message to
     * whatever mailer.conf says, and if nobody has changed it - the Postfix package does not change
     * it by itself - since FreeBSD 14 that is dma(8). dma accepted, returned 0, and delivered by
     * itself to the recipient's MX: without going through the milter, so without a DKIM signature,
     * and without STARTTLS. The panel wrote "succeeded"; Gmail received an unencrypted, unsigned
     * message, other recipients did not show it at all.
     *
     * Postfix knows where its sendmail is: it is sendmail_path. If postconf does not answer, the
     * port's path is tried. A candidate that is mailwrapper is discarded, and if nothing is left
     * there is NO fallback to another sendmail: an error that says what is missing is better than
     * a send that goes out of the wrong door and declares itself successful.
     *
     * Since 2026-10-24 the installer writes mailer.conf for Postfix (scripts/LocalMtaScript), and
     * on a server installed since then mailwrapper too would reach Postfix. This choice stays as it
     * is all the same: the servers installed earlier still hand over to dma, and the report must
     * not depend on how someone has left mailer.conf.
     */
    static JSONObject postfixSendmail() {
        String declared = Shell.runShell(java.time.Duration.ofSeconds(10),
                "postconf -h sendmail_path 2>/dev/null").outputTrim();
        return sendmailChoice(declared, PORTS_SENDMAIL, MAILWRAPPER);
    }

    /** The actual choice, kept apart from postconf and from the real paths so that it can be tested. */
    static JSONObject sendmailChoice(String declared, String fromPort, String mailwrapper) {
        java.util.LinkedHashSet<String> candidates = new java.util.LinkedHashSet<>();
        if (declared != null && declared.startsWith("/") && declared.indexOf('\n') < 0)
            candidates.add(declared);
        candidates.add(fromPort);
        java.util.List<String> discarded = new java.util.ArrayList<>();
        for (String c : candidates) {
            String no = notPostfix(c, mailwrapper);
            if (no == null) return new JSONObject().put("success", true).put("path", c);
            discarded.add(no);
        }
        return new JSONObject().put("success", false)
                .put("error", I18n.tr("server.rp.noPostfixSendmail", java.util.Map.of("reasons", String.valueOf(String.join("; ", discarded)))));
    }

    /** null if the path can be Postfix's sendmail, otherwise the reason why it is not. */
    static String notPostfix(String path, String mailwrapper) {
        java.nio.file.Path p = java.nio.file.Path.of(path);
        if (!java.nio.file.Files.isRegularFile(p) || !java.nio.file.Files.isExecutable(p))
            return I18n.tr("server.rp.notExecutable", java.util.Map.of("p", String.valueOf(path)));
        try {
            // Same file, whether through a symbolic link or a hard link: it is mailwrapper.
            java.nio.file.Path mw = java.nio.file.Path.of(mailwrapper);
            if (java.nio.file.Files.exists(mw) && java.nio.file.Files.isSameFile(p, mw))
                return I18n.tr("server.rp.isMailwrapper", java.util.Map.of("p", String.valueOf(path)));
        } catch (java.io.IOException e) {
            return I18n.tr("server.rp.cannotCheck", java.util.Map.of("p", String.valueOf(path), "m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e)));
        }
        return null;
    }

    /** A Message-ID that no other message has: type, UTC time, 12 random bytes, sender's domain. */
    static String newMessageId(String kind, String sender) {
        byte[] randomBytes = new byte[12];
        new java.security.SecureRandom().nextBytes(randomBytes);
        return kind + "." + LocalDateTime.now(java.time.ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
                + "." + java.util.HexFormat.of().formatHex(randomBytes)
                + "@" + sender.substring(sender.indexOf('@') + 1);
    }

    // ===================== how it went =====================

    /** How long the message is followed in the log, before giving up watching. */
    static final int SECONDS_IN_LOG = 30;

    /** At most 4 MB of new log is read: a server under load writes a lot of it. */
    private static final int MAX_LOG = 4 << 20;

    private static long logSize() {
        try { return java.nio.file.Files.size(java.nio.file.Path.of(org.daemoxcp.mail.monitoring.LogManager.MAILLOG)); }
        catch (Exception e) { return -1; }
    }

    /** The lines written to the mail log from 'from' onwards. If it was rotated in the meantime, from the start. */
    private static java.util.List<String> logLines(long from) {
        try (java.io.RandomAccessFile f = new java.io.RandomAccessFile(org.daemoxcp.mail.monitoring.LogManager.MAILLOG, "r")) {
            long end = f.length();
            long start = from < 0 || from > end ? 0 : from;
            start = Math.max(start, end - MAX_LOG);
            byte[] b = new byte[(int) (end - start)];
            f.seek(start);
            f.readFully(b);
            return new String(b, StandardCharsets.UTF_8).lines().toList();
        } catch (Exception e) {
            return java.util.List.of();
        }
    }

    /**
     * Watches the log until Postfix says how it went, for at most SECONDS_IN_LOG.
     * A normal delivery completes in a couple of seconds; if the recipient's server does not
     * answer, Postfix takes its own time and the outcome stays "queued".
     */
    private static JSONObject followInLog(long from, String messageId, String recipient) {
        long expiry = System.nanoTime() + TimeUnit.SECONDS.toNanos(SECONDS_IN_LOG);
        while (true) {
            JSONObject e = outcomeInLog(logLines(from), messageId, recipient);
            String state = e.optString("state", "");
            if ((!state.isEmpty() && !"queued".equals(state)) || System.nanoTime() >= expiry) return e;
            try { Thread.sleep(1000); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); return e; }
        }
    }

    /**
     * What Postfix's log says about the message with this Message-ID. It receives the lines instead
     * of reading the file, so that it can be tested with real lines.
     *
     * cleanup writes the Message-ID next to the queue number ("4hB2Kq3Xz9: message-id=<...>"),
     * and every later line about the same message carries that number. dma and the other MTAs do not
     * write that line: if it is missing, Postfix has not seen the message, and the "state" stays
     * empty instead of becoming "successful".
     *
     * States: "" (Postfix has not seen it), "queued" (seen, outcome not written yet),
     * "delivered", "deferred" (Postfix will retry by itself), "rejected" (by the recipient's
     * server), "refused" (by Postfix itself, before leaving: milter or checks).
     */
    static JSONObject outcomeInLog(java.util.List<String> lines, String messageId, String recipient) {
        JSONObject r = new JSONObject().put("state", "").put("lines", new JSONArray());
        java.util.regex.Pattern withId = java.util.regex.Pattern.compile(
                "(?:^|\\s)([0-9A-Za-z]+): message-id=<" + java.util.regex.Pattern.quote(messageId) + ">");
        String queue = null;
        for (String line : lines) {
            java.util.regex.Matcher m = withId.matcher(line);
            if (m.find()) { queue = m.group(1); break; }
        }
        if (queue == null) return r;
        r.put("queue", queue).put("state", "queued");

        // The lines of THIS message: the queue number as a whole word, followed by ": ".
        java.util.regex.Pattern ownPattern = java.util.regex.Pattern.compile(
                "(?:^|\\s)" + java.util.regex.Pattern.quote(queue) + ": (.*)$");
        java.util.regex.Pattern state = java.util.regex.Pattern.compile(", status=([a-z]+) \\((.*)\\)\\s*$");
        java.util.List<Integer> indexes = new java.util.ArrayList<>();
        int delivery = -1;              // the "to=<...> ... status=" line that decides
        boolean forRecipient = false;
        String refusal = null;
        for (int i = 0; i < lines.size(); i++) {
            java.util.regex.Matcher m = ownPattern.matcher(lines.get(i));
            if (!m.find()) continue;
            indexes.add(i);
            String rest = m.group(1);
            for (String type : new String[]{"milter-reject: ", "reject: ", "milter-discard: ", "discard: "})
                if (rest.startsWith(type)) refusal = rest.substring(type.length());
            if (!rest.startsWith("to=<") || !state.matcher(rest).find()) continue;
            // With several recipients (an alias, a blind copy) what counts is the line of the
            // report's recipient; among those, the last one, because a "deferred" can be followed
            // by a "delivered".
            boolean its = recipient.equalsIgnoreCase(between(rest, "to=<", ">"))
                       || recipient.equalsIgnoreCase(between(rest, "orig_to=<", ">"));
            if (its || !forRecipient) { delivery = i; forRecipient = its; }
        }

        if (delivery >= 0) {
            java.util.regex.Matcher m = ownPattern.matcher(lines.get(delivery));
            m.find();
            String rest = m.group(1);
            java.util.regex.Matcher s = state.matcher(rest);
            s.find();
            String relay = between(rest, "relay=", ",");
            r.put("relay", relay).put("answer", s.group(2)).put("state", switch (s.group(1)) {
                case "sent" -> "delivered";
                case "deferred" -> "deferred";
                case "bounced", "expired" -> "rejected";
                default -> "queued";
            });
            // If the connection was encrypted, the smtp process that delivered writes so when it
            // opens it (with smtp_tls_loglevel >= 1). It is what Gmail calls "standard encryption".
            // If the evidence is not there nothing is claimed: its absence does not prove the opposite.
            int opening = tlsOpening(lines, delivery, queue, relay);
            if (opening >= 0) {
                String line = lines.get(opening);
                String tls = "TLS connection established to " + relay + ": ";
                java.util.regex.Matcher t = java.util.regex.Pattern.compile("^(\\S+) with cipher (\\S+)")
                        .matcher(line.substring(line.indexOf(tls) + tls.length()));
                if (t.find()) r.put("tls", t.group(1) + " (" + t.group(2) + ")");
                indexes.add(opening);
            }
        } else if (refusal != null) {
            // A temporary rejection (4.x.x) is not the end: Postfix tries again.
            boolean temporary = java.util.regex.Pattern.compile("(?:^|\\s)4\\.\\d{1,3}\\.\\d{1,3}(?:\\s|$)")
                    .matcher(refusal).find();
            r.put("state", temporary ? "deferred" : "refused").put("answer", refusal);
        }

        java.util.Collections.sort(indexes);
        JSONArray text = new JSONArray();
        for (int i : indexes) if (text.length() < 30) text.put(lines.get(i));
        return r.put("lines", text);
    }

    /** Who wrote a log line (program and pid: "postfix/smtp[81242]") and what. */
    record Row(String process, String text) {}

    private static final java.util.regex.Pattern LINE_5424 = java.util.regex.Pattern.compile(
            "^<\\d{1,3}>1 \\S+ \\S+ (\\S+) ([0-9]+) \\S+ (?:-|(?:\\[[^\\]]*\\])+) ?(.*)$");
    private static final java.util.regex.Pattern LINE_CLASSIC = java.util.regex.Pattern.compile(
            "(?:^|\\s)([^\\s\\[\\]]+)\\[([0-9]+)\\]: (.*)$");

    /** The line split into its parts, in classic syslog format or in RFC 5424; null if it is neither. */
    static Row line(String r) {
        java.util.regex.Matcher m = LINE_5424.matcher(r);
        if (!m.find()) {
            m = LINE_CLASSIC.matcher(r);
            if (!m.find()) return null;
        }
        return new Row(m.group(1) + "[" + m.group(2) + "]", m.group(3));
    }

    /**
     * The line in which the smtp process that delivered opened the encrypted connection the
     * message left on, or -1 if it cannot be pointed out with certainty.
     *
     * The relay alone is not enough: another smtp process can open, at the same moment, a
     * connection of its own to the same server, encrypted while this one is not. So only the
     * lines of the process that wrote the delivery count (same program, same pid), going back up
     * the log. The deliveries of the same message to the other recipients (same connection) are
     * skipped, and so are the TLS session lines that smtp writes after the opening with
     * smtp_tls_loglevel 2 or higher. The first different line decides: if it is the TLS opening
     * towards the same relay, it is this connection. Anything else (another message, a dropped
     * connection, the fallback to plaintext after a failed TLS) means that an opening written
     * further up belonged to another connection.
     *
     * A reused connection (conn_use= in the delivery) was opened earlier, for another message
     * and possibly by another process: its opening is not tied to this delivery.
     */
    static int tlsOpening(java.util.List<String> lines, int delivery, String queue, String relay) {
        Row who = line(lines.get(delivery));
        if (who == null || relay.isEmpty() || "none".equals(relay) || who.text().contains(", conn_use=")) return -1;
        java.util.regex.Pattern opening = java.util.regex.Pattern.compile(
                "^(?:Anonymous|Untrusted|Trusted|Verified) TLS connection established to "
                + java.util.regex.Pattern.quote(relay) + ": \\S+ with cipher ");
        java.util.regex.Pattern ownDelivery = java.util.regex.Pattern.compile(
                "^" + java.util.regex.Pattern.quote(queue) + ": to=<.*, status=[a-z]+ \\(");
        for (int i = delivery - 1; i >= 0; i--) {
            Row r = line(lines.get(i));
            if (r == null || !who.process().equals(r.process())) continue;
            String t = r.text();
            if (ownDelivery.matcher(t).find() || t.startsWith("SSL_connect:")
                    || t.startsWith("save session ") || t.startsWith("remove session ")) continue;
            return opening.matcher(t).find() ? i : -1;
        }
        return -1;
    }

    /** The text between 'after' and the first 'until' that follows it; "" if 'after' is not there. */
    private static String between(String s, String after, String until) {
        int i = s.indexOf(after);
        if (i < 0) return "";
        i += after.length();
        int j = s.indexOf(until, i);
        return (j < 0 ? s.substring(i) : s.substring(i, j)).trim();
    }

    /**
     * From the log to the verdict: what is recorded as the outcome and what is told to whoever
     * pressed the button.
     *
     * "success" means that the panel must not send it again. It also applies to a message that
     * Postfix keeps in the queue and will retry by itself: sending it again would deliver two
     * reports. It is false only when the message will certainly not arrive. "warning" means
     * that it has not arrived yet, or that it is not known.
     */
    static JSONObject verdict(JSONObject log) {
        String queue = log.optString("queue", "");
        String relay = log.optString("relay", "");
        String answer = log.optString("answer", "");
        String tls = log.optString("tls", "");
        JSONObject v = new JSONObject();
        switch (log.optString("state", "")) {
            case "delivered" -> {
                String where = relay + (tls.isEmpty() ? "" : " " + I18n.tr("server.rp.withTls", java.util.Map.of("tls", String.valueOf(tls))));
                return v.put("success", true).put("warning", false)
                        .put("outcome", brief(I18n.tr("server.rp.deliveredTo", java.util.Map.of("where", String.valueOf(where), "answer", String.valueOf(answer)))))
                        .put("note", I18n.tr("server.rp.deliveredNote", java.util.Map.of("where", String.valueOf(where), "answer", String.valueOf(answer))));
            }
            case "deferred" -> {
                return v.put("success", true).put("warning", true)
                        .put("outcome", brief(I18n.tr("server.rp.deferred", java.util.Map.of("answer", String.valueOf(answer)))))
                        .put("note", I18n.tr("server.rp.deferredNote", java.util.Map.of("queue", String.valueOf(queue), "answer", String.valueOf(answer))));
            }
            case "rejected" -> {
                return v.put("success", false).put("error", brief(relay.isEmpty() || "none".equals(relay)
                        ? I18n.tr("server.rp.bounced", java.util.Map.of("answer", String.valueOf(answer)))
                        : I18n.tr("server.rp.bouncedBy", java.util.Map.of("relay", String.valueOf(relay), "answer", String.valueOf(answer)))));
            }
            case "refused" -> {
                return v.put("success", false).put("error", brief(I18n.tr("server.rp.rejected", java.util.Map.of("answer", String.valueOf(answer)))));
            }
            case "queued" -> {
                return v.put("success", true).put("warning", true)
                        .put("outcome", I18n.tr("server.rp.accepted", java.util.Map.of("queue", String.valueOf(queue))))
                        .put("note", I18n.tr("server.rp.acceptedNote", java.util.Map.of("queue", String.valueOf(queue), "s", String.valueOf(SECONDS_IN_LOG), "log", String.valueOf(org.daemoxcp.mail.monitoring.LogManager.MAILLOG))));
            }
            default -> {
                return v.put("success", true).put("warning", true)
                        .put("outcome", I18n.tr("server.rp.notInLog"))
                        .put("note", I18n.tr("server.rp.notInLogNote", java.util.Map.of("s", String.valueOf(SECONDS_IN_LOG), "log", String.valueOf(org.daemoxcp.mail.monitoring.LogManager.MAILLOG))));
            }
        }
    }

    /** The outcome ends up in one line of the tab: a long answer from the server is shortened. */
    private static String brief(String s) {
        return s.length() <= 300 ? s : s.substring(0, 297) + "...";
    }

    // ===================== the items the report adds =====================

    /**
     * The items that come from the monitoring: specifications replaced or updated, and versions
     * of OpenSSL going out of support.
     *
     * If the check fails (no network, source unreachable) it does NOT stay silent: an item is added
     * that says the check could not be done. A report that is silent because the check failed
     * is indistinguishable from a report that is silent because everything is fine, and they
     * are two opposite things.
     */
    static java.util.List<JSONObject> watchWarnings() {
        java.util.List<JSONObject> outside = new java.util.ArrayList<>();
        try {
            JSONObject c = StandardsWatch.check();
            JSONArray st = c.optJSONArray("standard");
            if (st != null) for (int i = 0; i < st.length(); i++) {
                JSONObject o = st.getJSONObject(i);
                int g = o.optInt("severity", 0);
                if (g == 2)
                    outside.add(new JSONObject().put("urgency", 1)
                            .put("title", I18n.tr("mail.report.title.standardChanged"))
                            .put("what", o.optString("comment"))
                            .put("where", I18n.tr("server.rp.whereSurveillance")));
                else if (g == 1)
                    outside.add(new JSONObject().put("urgency", 3)
                            .put("title", I18n.tr("mail.report.title.standardChanged"))
                            .put("what", o.optString("comment"))
                            .put("where", I18n.tr("server.rp.whereSurveillance")));
            }
            if (c.optInt("unread", 0) > 0)
                outside.add(new JSONObject().put("urgency", 3)
                        .put("title", I18n.tr("mail.report.title.watchIncomplete"))
                        .put("what", I18n.tr("server.rp.rfcUnread", java.util.Map.of("n", String.valueOf(c.optInt("unread")))))
                        .put("where", I18n.tr("server.rp.whereSurveillance")));
        } catch (Exception e) {
            outside.add(new JSONObject().put("urgency", 3)
                    .put("title", I18n.tr("mail.report.title.watchIncomplete"))
                    .put("what", I18n.tr("server.rp.survFailed", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e))))
                    .put("where", I18n.tr("server.rp.whereSurveillance")));
        }

        try {
            JSONObject o = OpensslExpiry.state();
            JSONArray inst = o.optJSONArray("installs");
            if (inst != null) for (int i = 0; i < inst.length(); i++) {
                JSONObject x = inst.getJSONObject(i);
                if (!x.optBoolean("present", false)) continue;
                int u = x.optInt("urgency", 0);
                if (u == 1 || u == 2)
                    outside.add(new JSONObject().put("urgency", u == 2 ? 1 : 2)
                            .put("title", I18n.tr("mail.report.title.openssl", java.util.Map.of("version", x.optString("version"))))
                            .put("what", "OpenSSL " + x.optString("version") + " ("
                                    + x.optString("type") + "): " + x.optString("comment"))
                            .put("where", I18n.tr("server.rp.whereSurveillance")));
            }
        } catch (Exception ignore) {}

        return outside;
    }

    /**
     * The certificate manager is WIRED IN by whoever starts the panel, not looked up through
     * reflection: this way the compiler checks the names. The first version looked up a field
     * "Main.acmeManager" that does not exist - it is private inside SSLMailServer - so the
     * report would have written "I cannot read the certificate" forever, without anything
     * flagging it.
     */
    private static org.daemoxcp.mail.security.AcmeManager acme;

    public static void link(org.daemoxcp.mail.security.AcmeManager a) { acme = a; }

    /**
     * The state of the certificate for the report's section: name, issuer, expiry; or,
     * in "problem", the sentence that says why it is not known.
     */
    static JSONObject certificateState() {
        JSONObject r = new JSONObject();
        if (acme == null) return r.put("problem", I18n.tr("server.rp.c.acmeMissing"));
        try {
            org.daemoxcp.mail.security.AcmeManager.CertificateInfo i = acme.getCertificateInfo();
            if (i == null || !i.installed) return r.put("problem", I18n.tr("server.rp.c.noCert"));
            String lang = I18n.current();
            return r.put("name", i.commonName == null ? "-" : i.commonName)
                    .put("issuer", (i.issuer == null ? "-" : i.issuer) + (i.letsEncrypt ? " (Let's Encrypt)" : ""))
                    .put("expired", i.expired)
                    .put("days", i.daysUntilExpiry)
                    .put("expiresOn", i.expiresAt == null ? "?"
                            : PanelMail.longDate(lang, i.expiresAt.atZone(java.time.ZoneId.systemDefault())));
        } catch (Exception e) {
            return r.put("problem", I18n.tr("server.rp.c.certReadFailed", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("PeriodicReport", e))));
        }
    }

    /** The certificate also goes among the things to do, if it is about to expire or has expired. */
    /**
     * A new version of the panel among the GitHub releases (ReleaseCheck), from the last saved outcome:
     * whoever never opens the panel reads it here. Low urgency: there is nothing wrong with the running panel.
     */
    static JSONObject releaseWarning() {
        try {
            JSONObject n = ReleaseCheck.available();
            if (n == null) return null;
            return new JSONObject().put("urgency", 3)
                    .put("title", I18n.tr("mail.report.title.newRelease", java.util.Map.of("version", n.optString("version"))))
                    .put("what", I18n.tr("server.rp.c.newRelease", java.util.Map.of("version", n.optString("version"),
                            "current", n.optString("current"), "url", n.optString("url"))))
                    .put("where", I18n.tr("mail.report.where.updates"));
        } catch (Exception e) {
            return null;
        }
    }

    static JSONObject certificateWarning() {
        if (acme == null) return null;
        try {
            org.daemoxcp.mail.security.AcmeManager.CertificateInfo i = acme.getCertificateInfo();
            if (i == null || !i.installed)
                return new JSONObject().put("urgency", 2)
                        .put("title", I18n.tr("mail.report.title.certMissing"))
                        .put("what", I18n.tr("server.rp.c.noTlsCert"))
                        .put("where", I18n.tr("mail.report.where.ssl"));
            if (i.expired)
                return new JSONObject().put("urgency", 0)
                        .put("title", I18n.tr("mail.report.title.certExpired"))
                        .put("what", I18n.tr("server.rp.c.tlsExpired"))
                        .put("where", I18n.tr("mail.report.where.ssl"));
            if (i.daysUntilExpiry <= 15)
                return new JSONObject().put("urgency", i.daysUntilExpiry <= 5 ? 0 : 1)
                        .put("title", I18n.tr("mail.report.title.certExpiring", java.util.Map.of("n", String.valueOf(i.daysUntilExpiry))))
                        .put("what", I18n.tr("server.rp.c.tlsExpiresIn", java.util.Map.of("n", String.valueOf(i.daysUntilExpiry))))
                        .put("where", I18n.tr("mail.report.where.ssl"));
        } catch (Exception ignored) { }
        return null;
    }
}
