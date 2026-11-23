package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.security.AcmeManager;
import org.daemoxcp.mail.security.AutoDns;
import org.daemoxcp.mail.security.CloudflareManager;
import org.daemoxcp.mail.security.DnsRules;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MTA-STS turned on with a single button.
 *
 * Why it exists. Activating MTA-STS requires eight things done IN THE RIGHT ORDER: the
 * include line in nginx, the configuration of 443, the jail, a CNAME per domain, that CNAME
 * pointing STRAIGHT to the server and not going through a proxy, a certificate that covers
 * those names, the check that the policy answers, and only at the end the TXT record. Having
 * them done by hand one by one means getting the order wrong, as happened
 * to me, when I asked to test with curl a name that the next step had yet to create.
 *
 * The order is not a matter of convenience: each step is the precondition of the next. The
 * TXT published before the policy answers is a public declaration that is not kept; the
 * certificate issued before the CNAME cannot validate the name; the configuration written
 * before the include ends up in a file nginx does not read.
 *
 * So the sequence is known by the panel, which also knows where it stands and resumes from
 * there. Each step verifies its own outcome before the next one begins, and at the first
 * one that fails it stops, explaining what is missing: going on after a failure would mean
 * building on nothing.
 */
public class MtaStsSetup {

    private MtaStsSetup() {}

    /**
     * How long, at most, the sequence waits for a newly created DNS record to become visible.
     *
     * It is not a number chosen by feel: a resolver that already has the previous answer in its
     * cache keeps it for the TTL of that answer, and on a Cloudflare wildcard that TTL measured
     * 300 seconds. Under five minutes the wait would be useless; six leave the margin for the
     * cache to really expire.
     */
    private static final long MAX_WAIT_MS = 6 * 60 * 1000L;

    /**
     * How often it retries. Thirty seconds, because the JVM caches successful resolutions for
     * thirty seconds: retrying more often would mean rereading its own cache and believing it
     * had queried DNS.
     */
    private static final long WAIT_INTERVAL_MS = 30 * 1000L;

    public static class Step {
        public String key, title, detail, state, reason;
        public JSONObject json() {
            return new JSONObject().put("key", key).put("title", title)
                    .put("detail", detail == null ? "" : detail)
                    .put("state", state).put("reason", reason == null ? "" : reason);
        }
    }

    private static Step step(String c, String t, String d, String s, String m) {
        Step p = new Step();
        p.key = c; p.title = t; p.detail = d; p.state = s; p.reason = m;
        return p;
    }

    /*
     * ===================================================================
     * Where we stand
     * ===================================================================
     */

    public static JSONObject plan() {
        JSONObject r = new JSONObject().put("success", true);
        List<Step> steps = new ArrayList<>();

        // 1-2-3: the surface on 443
        JSONObject web = WebProtection.state();
        JSONObject inclusion = web.optJSONObject("include");
        boolean includeOk = inclusion != null && inclusion.optBoolean("ok", false);
        steps.add(step("include", I18n.tr("server.sts.stepInclude"),
                inclusion == null ? "" : inclusion.optString("reason", ""),
                includeOk ? "done" : "todo", null));
        steps.add(step("config443", I18n.tr("server.sts.step443"),
                web.optString("file", ""),
                web.optBoolean("installed", false) ? "done" : "todo", null));
        steps.add(step("jail", I18n.tr("server.sts.stepJail"), "",
                jailActive() ? "done" : "todo", null));

        // 4 and 4-bis: the CNAMEs. A single read of the zone for both steps, so they
        // cannot contradict each other as happened with domain-d.test.
        List<NameReview> reviews = reviewCname();
        // If the examination does not cover all the domains, it means it stopped because of a fault:
        // without this line the lists would stay empty and the plan would say "all in place"
        // precisely because it looked at nothing. It is the error I am removing from the panel:
        // it must not come back through the back door.
        int domainCount = domains().size();
        Breakdown breakdown = split(reviews);
        List<String> absent = breakdown.absent, crooked = breakdown.crooked, proxied = breakdown.proxied,
                     blindOnes = breakdown.blind, propagating = breakdown.propagating;
        boolean proxyFromWildcard = breakdown.proxyFromWildcard;
        if (reviews.size() < domainCount)
            blindOnes.add(I18n.tr("server.sts.notExamined", java.util.Map.of("n", String.valueOf((domainCount - reviews.size())))));
        List<String> cnameTroubles = new ArrayList<>(absent); cnameTroubles.addAll(crooked);
        String cnameDetail;
        if (!cnameTroubles.isEmpty()) cnameDetail = I18n.tr("server.sts.toFix", java.util.Map.of("list", String.valueOf(String.join("; ", cnameTroubles))));
        else if (!blindOnes.isEmpty()) cnameDetail = I18n.tr("server.sts.unverifiable", java.util.Map.of("list", String.valueOf(String.join("; ", blindOnes))));
        else if (!propagating.isEmpty())
            cnameDetail = I18n.tr("server.sts.propagating", java.util.Map.of("list", String.valueOf(String.join(", ", propagating))));
        else if (!proxied.isEmpty())
            cnameDetail = I18n.tr("server.sts.allPresentProxy");
        else cnameDetail = I18n.tr("server.sts.allPresentOk");
        steps.add(step("cname", I18n.tr("server.sts.stepCname"), cnameDetail,
                !cnameTroubles.isEmpty() ? "todo" : (blindOnes.isEmpty() ? "done" : "uncertain"),
                blindOnes.isEmpty() ? null
                    : I18n.tr("server.sts.blindDns")));

        // 4-bis: the records that must point STRAIGHT to the server
        boolean blind = !blindOnes.isEmpty();
        steps.add(step("proxy", I18n.tr("server.sts.stepProxy"),
                !proxied.isEmpty() ? I18n.tr("server.sts.viaCf", java.util.Map.of("list", String.valueOf(String.join(", ", proxied))))
                        : (blind ? I18n.tr("server.sts.checkedVisible")
                                 : I18n.tr("server.sts.noneViaCf")),
                !proxied.isEmpty() ? "todo" : (blind ? "uncertain" : "done"),
                proxied.isEmpty() ? null
                    : I18n.tr("server.sts.proxyWhy")
                    + (proxyFromWildcard
                        ? " " + I18n.tr("server.sts.wildcardWhy")
                        : "")));

        // 5: the certificate
        List<String> servedNames = namesToCover();
        List<String> uncovered = new ArrayList<>();
        for (String n : servedNames) if (!certificateCovers(n)) uncovered.add(n);
        List<String> excluded = domainsOnOtherAccount();
        steps.add(step("certificate", I18n.tr("server.sts.stepCert"),
                uncovered.isEmpty() ? I18n.tr("server.sts.allCovered") : I18n.tr("server.sts.uncovered", java.util.Map.of("list", String.valueOf(String.join(", ", uncovered)))),
                uncovered.isEmpty() ? "done" : "todo",
                excluded.isEmpty() ? null
                    : I18n.tr("server.sts.otherAccount", java.util.Map.of("list", String.valueOf(String.join(", ", excluded))))));

        // 6-7: the test and the record
        List<TxtReview> txtReviews = new ArrayList<>();
        for (String d : domains()) {
            boolean answers = MtaSts.publicTest(d).optBoolean("ok", false);
            // The TXT is ALWAYS read, and above all when the policy does NOT answer: that is exactly
            // the combination to discover, a record already published that sends the world's
            // senders against an error. Before, there was an "else if" here and that branch was
            // never reached: on domain-d.test the panel wrote "waiting for the previous steps"
            // while the record was published, with an old id, and the policy gave 526. Blind
            // exactly to the thing this tab exists to watch over.
            txtReviews.add(new TxtReview(d, answers, readTxt(d)));
        }
        steps.addAll(testAndTxtSteps(txtReviews, expectedTxt()));

        JSONArray a = new JSONArray();
        int toDo = 0, uncertain = 0;
        for (Step p : steps) {
            a.put(p.json());
            if ("todo".equals(p.state)) toDo++;
            else if ("uncertain".equals(p.state)) uncertain++;
        }
        r.put("steps", a).put("toDo", toDo).put("uncertain", uncertain);
        // "complete" turns on the green tick and makes the button disappear, so it cannot be
        // enough that there is nothing TO DO: there must also be nothing left to VERIFY.
        // With the condition toDo==0 alone, an "uncertain" step (that is, one the panel
        // could not check) would have been enough on its own to declare "active on all domains".
        boolean complete = toDo == 0 && uncertain == 0;
        r.put("complete", complete);
        String uncertainCount = uncertain == 1 ? I18n.tr("server.sts.steps.one") : I18n.tr("server.sts.steps.other", java.util.Map.of("n", String.valueOf(uncertain)));
        r.put("note", complete
                ? I18n.tr("server.sts.complete")
                : toDo == 0
                  ? I18n.tr("server.sts.onlyUncertain", java.util.Map.of("steps", String.valueOf(uncertainCount)))
                  : (toDo == 1 ? I18n.tr("server.sts.missing.one") : I18n.tr("server.sts.missing.other", java.util.Map.of("n", String.valueOf(toDo))))
                    + (uncertain > 0 ? ", " + I18n.tr("server.sts.plusUncertain", java.util.Map.of("steps", String.valueOf(uncertainCount))) : "")
                    + ". " + I18n.tr("server.sts.buttonRuns"));
        return r;
    }

    /** What was seen of a domain for the test step and the record step. */
    static final class TxtReview {
        final String domain; final boolean answers; final TxtReading txt;
        TxtReview(String domain, boolean answers, TxtReading txt) {
            this.domain = domain; this.answers = answers; this.txt = txt;
        }
    }

    /**
     * The "test" and "txt" steps of the plan, from what was seen domain by domain. It is here
     * that the record step becomes "done", and it stands alone so that the tests can verify it
     * with constructed readings, without DNS and without the real policy: two v=STSv1 records
     * must not be able to make it "done".
     */
    static List<Step> testAndTxtSteps(List<TxtReview> reviews, String expected) {
        List<String> notAnswering = new ArrayList<>(), withoutTxt = new ArrayList<>(),
                     unmaintained = new ArrayList<>(), unknownTxt = new ArrayList<>(),
                     tooMany = new ArrayList<>();
        for (TxtReview e : reviews) {
            String d = e.domain;
            TxtReading txt = e.txt;
            if (!e.answers) {
                notAnswering.add(d);
                // Even with several records: if one is malformed, the senders that discard it
                // count only the other, and that one sends them against the policy that does
                // not answer.
                if (txt.outcome == TxtOutcome.PRESENT || txt.outcome == TxtOutcome.TOO_MANY)
                    unmaintained.add(d + " -> " + String.join("  ||  ", txt.values));
                continue;
            }
            switch (txt.outcome) {
                case NOT_ASKED -> unknownTxt.add(d + " (" + txt.reason + ")");
                case ABSENT -> withoutTxt.add(d);
                case TOO_MANY -> tooMany.add(d + " (" + txt.values.size() + " record: "
                        + String.join("  ||  ", txt.values) + ")");
                case PRESENT -> {
                    if (!expected.equals(txt.content)) withoutTxt.add(d + " " + I18n.tr("server.sts.idToUpdate"));
                }
            }
        }
        List<Step> steps = new ArrayList<>();
        steps.add(step("test", I18n.tr("server.sts.stepTest"),
                notAnswering.isEmpty()
                    ? I18n.tr("server.sts.answersAll")
                    : I18n.tr("server.sts.noAnswerFor", java.util.Map.of("list", String.valueOf(String.join(", ", notAnswering)))),
                notAnswering.isEmpty() ? "done" : "todo", null));

        String txtDetail, txtState, txtReason = null;
        if (!unmaintained.isEmpty()) {
            txtDetail = I18n.tr("server.sts.notKept", java.util.Map.of("list", String.valueOf(String.join("; ", unmaintained))));
            txtState = "todo";
            txtReason = I18n.tr("server.sts.notKeptWhy");
        } else if (!tooMany.isEmpty()) {
            txtDetail = I18n.tr("server.sts.moreThanOne", java.util.Map.of("list", String.valueOf(String.join(", ", tooMany))));
            txtState = "todo";
            txtReason = I18n.tr("server.sts.moreThanOneWhy");
        } else if (!unknownTxt.isEmpty()) {
            txtDetail = I18n.tr("server.sts.unknownFor", java.util.Map.of("list", String.join(", ", unknownTxt)));
            txtState = "uncertain";
            txtReason = I18n.tr("server.sts.notMarkedDone");
        } else if (!notAnswering.isEmpty()) {
            txtDetail = I18n.tr("server.sts.waitingPrev"); txtState = "todo";
        } else if (!withoutTxt.isEmpty()) {
            txtDetail = I18n.tr("server.sts.missingList", java.util.Map.of("list", String.valueOf(String.join(", ", withoutTxt)))); txtState = "todo";
        } else {
            txtDetail = I18n.tr("server.sts.allPublished"); txtState = "done";
        }
        steps.add(step("txt", I18n.tr("server.sts.stepTxt"), txtDetail, txtState, txtReason));
        return steps;
    }

    /**
     * How the examined domains are distributed among the steps of the plan.
     *
     * It is in a method of its own, detached from plan(), for a precise reason: it is HERE that
     * the false greens were born. A domain without a record that answered thanks to a proxied
     * wildcard did not enter the proxy count, and the step said "nobody goes through Cloudflare";
     * a record both WRONG and PROXIED ended up only in the proxy count (because the
     * classification looked for the word "Cloudflare" inside a sentence written for a human
     * being) and the CNAME step declared "all present and correct" a record that pointed
     * elsewhere.
     *
     * Inside plan(), which needs the database and Cloudflare to exist, this logic could not be
     * tested. Logic that no test can reach is logic nobody checks: here, in fact, nobody
     * checked it.
     */
    static final class Breakdown {
        final List<String> absent = new ArrayList<>(), crooked = new ArrayList<>(),
                           proxied = new ArrayList<>(), blind = new ArrayList<>(),
                           propagating = new ArrayList<>();
        boolean proxyFromWildcard;
    }

    static Breakdown split(List<NameReview> reviews) {
        Breakdown r = new Breakdown();
        for (NameReview e : reviews) {
            // The proxy is counted on its own, from a boolean: a record can be both
            // wrong AND proxied, and both facts must appear, in the two steps they
            // belong to.
            if (e.goesThroughProxy) {
                boolean fromWildcard = e.state == NameState.ABSENT;
                if (fromWildcard) r.proxyFromWildcard = true;
                r.proxied.add(e.domain + (fromWildcard
                        ? " " + I18n.tr("server.sts.wildcardAnswers", java.util.Map.of("d", String.valueOf(e.domain))) : ""));
            }
            switch (e.state) {
                case ABSENT -> r.absent.add(e.domain + " (" + e.reason + ")");
                case BLIND -> r.blind.add(e.domain + " (" + e.reason + ")");
                case TO_FIX -> {
                    if (e.wrongContent) r.crooked.add(e.domain + " (" + e.reason + ")");
                }
                case RIGHT -> { if (!e.resolves) r.propagating.add(e.domain); }
            }
        }
        return r;
    }

    /**
     * Time, passed in from outside.
     *
     * It is needed only so that the wait below can be tested: glued to Thread.sleep and
     * System.currentTimeMillis, a test would have had to wait six real minutes to exercise it,
     * that is, it would never have exercised it.
     */
    interface Clock {
        long now();
        void sleep(long ms) throws InterruptedException;
    }

    static final Clock REAL_CLOCK = new Clock() {
        public long now() { return System.currentTimeMillis(); }
        public void sleep(long ms) throws InterruptedException { Thread.sleep(ms); }
    };

    /**
     * Waits for the given domains to answer, and returns those that did not make it.
     *
     * Three properties that must hold, and that the test verifies one by one: it tries
     * IMMEDIATELY before sleeping (if they already answer, it does not wait an instant); it stops
     * as soon as the list is empty; and it stops anyway at the deadline, because a wait loop
     * without a guaranteed exit, inside a production panel, is a hang that never ends.
     */
    static List<String> waitForPropagation(List<String> domains,
                                            java.util.function.Predicate<String> answers,
                                            Clock clock, long maxMs, long intervalMs,
                                            java.util.function.Consumer<String> log) {
        List<String> remain = new ArrayList<>(domains);
        long expiry = clock.now() + maxMs;
        while (true) {
            remain.removeIf(answers);
            if (remain.isEmpty() || clock.now() >= expiry) break;
            log.accept("    " + I18n.tr("server.sts.stillNotAnswering", java.util.Map.of("list", String.valueOf(String.join(", ", remain)), "s", String.valueOf((intervalMs / 1000)))));
            try {
                clock.sleep(intervalMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                log.accept("    " + I18n.tr("server.sts.waitInterrupted"));
                break;
            }
        }
        return remain;
    }

    /*
     * ===================================================================
     * The execution
     * ===================================================================
     */

    public static JSONObject run() { return run(null, null); }

    public static JSONObject run(UpdateManager.Job job) { return run(job, null); }

    /**
     * The domains the sequence must act on.
     *
     * An empty list is NOT "no domain to do": it means the requested name does not exist, and
     * the caller must notice it instead of seeing a sequence that "succeeds" without having
     * touched anything.
     */
    private static List<MailDatabase.Domain> domainsToTouch(String domainOnly) throws Exception {
        return filter(Main.mailDatabase.getDomains(), domainOnly);
    }

    /**
     * The actual filter, separate from reading the database so that it can be tested: inside
     * domainsToTouch it would be reachable only with a live database, and a test that does not
     * reach the line it must verify verifies nothing.
     *
     * The comparison is case-insensitive because domain names have no case, and it is EXACT:
     * "in-d.test" must not find "domain-d.test".
     */
    static List<MailDatabase.Domain> filter(List<MailDatabase.Domain> allItems, String domainOnly) {
        List<MailDatabase.Domain> out = new ArrayList<>();
        if (allItems == null) return out;
        for (MailDatabase.Domain d : allItems)
            if (domainOnly == null || (d != null && domainOnly.equalsIgnoreCase(d.domain)))
                out.add(d);
        return out;
    }

    /**
     * @param job if present, the progress is written there as it happens.
     * @param domainOnly if present, the per-domain steps touch only that one. The first three
     *        (nginx include, 443, jail) stay global because that surface is a single one for
     *        all domains, and installing it is idempotent. The certificate stays global for a
     *        more serious reason, explained at its step.
     *
     * Issuing the certificate takes longer than a proxy's time limit: if the HTTP request is
     * kept open, the browser receives an error page while on the server the operation goes on.
     * Whoever is watching no longer knows what happened, and an unknown state on a production
     * certificate is the antechamber of damage.
     */
    public static JSONObject run(UpdateManager.Job job, String domainOnly) {
        JSONObject r = new JSONObject();
        JSONArray doneOnes = new JSONArray();
        if (job != null) job.write("=== " + I18n.tr("server.sts.jobTitle") + " ==="
                + (domainOnly == null ? "" : " " + I18n.tr("server.sts.onlyDomain", java.util.Map.of("d", String.valueOf(domainOnly)))));

        // A name that matches no domain must not produce a sequence that "succeeds":
        // the per-domain loops would run empty, no step would fail, and the outcome
        // would say everything went well without anything having been touched. It is
        // the quietest false success of all, and it must be stopped here.
        if (domainOnly != null) {
            try {
                if (domainsToTouch(domainOnly).isEmpty())
                    return stopped(r, doneOnes, I18n.tr("server.sts.notPanelDomain", java.util.Map.of("d", String.valueOf(domainOnly))));
            } catch (Exception e) {
                return stopped(r, doneOnes, I18n.tr("server.sts.domainsUnreadable", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("MtaStsSetup", e))));
            }
        }

        // 1. include
        JSONObject web = WebProtection.state();
        JSONObject inclusion = web.optJSONObject("include");
        if (inclusion == null || !inclusion.optBoolean("ok", false)) {
            JSONObject e = WebProtection.addInclude();
            doneOnes.put(outcome("include", I18n.tr("server.sts.includeTitle"), e));
            if (job != null) job.write("[1/8] " + (e.optBoolean("success", false) ? I18n.tr("server.sts.includeOk")
                    : I18n.tr("server.sts.includeFail") + " \u2014 " + e.optString("error", "")));
            if (!e.optBoolean("success", false)) return stopped(r, doneOnes,
                    I18n.tr("server.sts.noIncludeStop"));
        } else doneOnes.put(already("include", I18n.tr("server.sts.includeTitle")));

        // 2. port 443
        if (!WebProtection.state().optBoolean("installed", false)) {
            JSONObject e = WebProtection.install("", "");
            doneOnes.put(outcome("config443", I18n.tr("server.sts.config443Title"), e));
            if (job != null) job.write("[2/8] " + (e.optBoolean("success", false) ? I18n.tr("server.sts.c443Ok")
                    : I18n.tr("server.sts.c443Fail") + " \u2014 " + e.optString("error", "")));
            if (!e.optBoolean("success", false)) return stopped(r, doneOnes,
                    I18n.tr("server.sts.no443Stop"));
        } else doneOnes.put(already("config443", I18n.tr("server.sts.config443Title")));

        // 3. the jail
        if (!jailActive()) {
            JSONObject e = WebProtection.installJail();
            doneOnes.put(outcome("jail", "Jail fail2ban", e));
            // A missing jail does not prevent MTA-STS from working: it is noted and we go on.
        } else doneOnes.put(already("jail", "Jail fail2ban"));

        // 4. the CNAMEs
        //
        // The domains in which something really CHANGES are marked: they are the only ones for
        // which, further on, it makes sense to wait for propagation. Where nothing changed there is
        // nothing to propagate, and a wait would only be time taken from whoever is watching.
        LinkedHashSet<String> justChanged = new LinkedHashSet<>();
        JSONArray cname = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : domainsToTouch(domainOnly)) {
                // Before, there was a shortcut here: if "mta-sts.<domain>" ANSWERED, the
                // record was taken as done. But answering does not mean existing: a
                // wildcard "*.domain" makes any name answer. On domain-d.test it was
                // exactly so: the name answered thanks to the wildcard, behind
                // Cloudflare, and the policy returned 526. createOptional looks at the
                // record with the EXACT name inside the zone, fixes the wrong or proxied
                // ones and creates the missing ones: it is the one that must decide.
                JSONObject e = auto.createOptional(d.id, "mta_sts");
                if (e.optBoolean("unmanaged", false)) {
                    // Domain not on Cloudflare: it is not an error, but not a confirmation either.
                    boolean answers = resolves("mta-sts." + d.domain);
                    cname.put(note(d.domain, answers,
                            answers ? I18n.tr("server.sts.answersNoCf")
                                     : I18n.tr("server.sts.noAnswerNoCf")));
                    continue;
                }
                if (e.optBoolean("success", false) && !e.optBoolean("unchanged", false))
                    justChanged.add(d.domain);
                cname.put(note(d.domain, e.optBoolean("success", false),
                        e.optString("note", e.optString("error", ""))));
            }
        } catch (Exception e) {
            cname.put(note("", false, I18n.tr("server.sts.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("MtaStsSetup", e)))));
        }
        doneOnes.put(new JSONObject().put("key", "cname").put("title", "CNAME mta-sts")
                .put("detail", cname));
        if (job != null) { job.advance(4, 8); job.write("[4/8] " + I18n.tr("server.sts.cnameExamined", java.util.Map.of("n", String.valueOf(cname.length())))); }

        // 4-bis. The mta-sts names must point straight to the server.
        // Each domain reports WHAT I SAW. Before, this step said "it was already in place"
        // every time it had not DONE anything, including when it had not SEEN anything:
        // account missing, zone not found, API silent. "I could not check" disguised as
        // "everything is fine" is the fastest way to make a wrong decision: here,
        // publishing an MTA-STS record on a name that goes through Cloudflare.
        JSONArray proxy = new JSONArray();
        int fixed = 0, straight = 0, blind = 0;
        try {
            CloudflareManager cf = new CloudflareManager(Main.mailDatabase);
            for (MailDatabase.Domain d : domainsToTouch(domainOnly)) {
                MailDatabase.CloudflareAccount a = cf.getAccountForDomain(d.id);
                if (a == null) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.notLinkedCf")));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.zoneNotFoundCf")));
                    continue;
                }
                String name = ("mta-sts." + d.domain).toLowerCase(Locale.ROOT);
                java.util.List<CloudflareManager.DnsRecordInfo> allItems;
                try {
                    allItems = cf.listRecords(a.apiToken, zl.zoneId);
                } catch (CloudflareManager.ZoneReadException e) {
                    // A zone that cannot be read is not a zone without the name: nothing is touched.
                    blind++;
                    proxy.put(note(d.domain, false, e.getMessage()));
                    continue;
                }
                if (allItems.isEmpty()) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.emptyZone")));
                    continue;
                }
                boolean seen = false;
                for (CloudflareManager.DnsRecordInfo t : allItems) {
                    if (t.name == null || !t.name.toLowerCase(Locale.ROOT).equals(name)) continue;
                    seen = true;
                    if (!t.proxied) {
                        straight++;
                        proxy.put(note(d.domain, true, I18n.tr("server.sts.pointsStraight", java.util.Map.of("kind", String.valueOf(t.type)))));
                        continue;
                    }
                    CloudflareManager.RecordOp op = cf.setProxy(a.apiToken, zl.zoneId, t.id, false);
                    boolean done = op != null && op.success;
                    if (done) { fixed++; justChanged.add(d.domain); }
                    proxy.put(note(d.domain, done,
                            done ? I18n.tr("server.sts.proxyRemoved", java.util.Map.of("kind", String.valueOf(t.type)))
                                  : I18n.tr("server.sts.proxyNotRemoved", java.util.Map.of("kind", String.valueOf(t.type), "e", String.valueOf(op == null ? I18n.tr("server.adns.noAnswer") : op.error)))));
                }
                if (!seen) {
                    blind++;
                    proxy.put(note(d.domain, false, I18n.tr("server.sts.noRecordNamed", java.util.Map.of("name", String.valueOf(name)))));
                }
            }
        } catch (Exception e) {
            blind++;
            proxy.put(note("", false, I18n.tr("server.sts.checkError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("MtaStsSetup", e)))));
        }
        doneOnes.put(new JSONObject().put("key", "proxy")
                .put("title", I18n.tr("server.sts.stepProxy"))
                .put("detail", proxy));
        if (job != null) job.write("[5/8] " + I18n.tr("server.sts.proxySummary", java.util.Map.of("d", String.valueOf(straight), "s", String.valueOf(fixed), "c", String.valueOf(blind))));

        // 5. the certificate
        //
        // This step does NOT respect the per-domain filter, and that is intended: the certificate
        // is a single one and "--issue --force" REDEFINES the set of names. Issuing it with only
        // the names of the current domain would remove from the certificate the mta-sts.* and
        // autoconfig.* of all the others, and with the MTA-STS records already published, that is
        // rejected mail. All the names are always looked at; it is issued only if some are missing.
        List<String> names = namesToCover();
        List<String> uncovered = new ArrayList<>();
        for (String n : names) if (!certificateCovers(n)) uncovered.add(n);
        if (!uncovered.isEmpty()) {
            AcmeManager acme = new AcmeManager(Main.mailDatabase);
            String host = MtaSts.mailHost();

            // The "scoperti.isEmpty()" guard above avoids reissuing when the names are
            // already there: Let's Encrypt allows 5 issuances a week for the same set
            // of names, and a button that reissues at every press uses up that margin,
            // leaving no renewal exactly when it would be needed.
            if (job != null) { job.advance(6, 8); job.write("[6/8] " + I18n.tr("server.sts.issuingCert", java.util.Map.of("n", String.valueOf(names.size()), "m", String.valueOf(uncovered.size())))); }
            AcmeManager.CertificateResult cr = acme.emitWithNames(host, names);
            // "Issuance failed" alone helps nobody: the real reason is in the output of
            // acme.sh (a domain the token does not cover, a Let's Encrypt limit, a zone
            // that is not visible). Without that line nothing can be diagnosed.
            String detail = cr.output == null ? "" : cr.output.trim();
            if (detail.length() > 4000) detail = detail.substring(detail.length() - 4000);
            JSONObject e = new JSONObject().put("success", cr.success)
                    .put("note", cr.message).put("error", cr.message);
            JSONObject line = outcome("certificate", I18n.tr("server.sts.certTitle"), e);
            line.put("names", new JSONArray(names));
            // The output is ALWAYS shown, not only when it fails. Throwing it away when
            // the command "succeeds" removes the evidence exactly in the worst case: the
            // one in which it succeeds but did not do what we believed.
            line.put("output", detail);
            doneOnes.put(line);
            if (job != null) {
                job.write("--- " + I18n.tr("server.sts.acmeOutput") + " ---");
                for (String r2 : detail.split("\n")) job.write("  " + r2);
                job.write("--- " + I18n.tr("server.sts.outputEnd") + " ---");
            }
            if (!cr.success) return stopped(r, doneOnes,
                    I18n.tr("server.sts.noCertStop"));
        } else doneOnes.put(already("certificate", I18n.tr("server.sts.certTitle")));

        // 6-bis. Waiting for propagation, and only where needed.
        //
        // A newly created DNS record is not visible right away: whoever has the previous answer
        // in cache keeps it for its TTL. On a name covered by a Cloudflare wildcard that TTL is
        // 300 seconds, so the policy can stay unreachable for five minutes after the CNAME was
        // created. Testing immediately, the sequence would always stop one step before the end and
        // leave whoever is watching the task of pressing again later: exactly the manual work this
        // button exists to remove, and on top of that without saying how much later.
        //
        // So it waits. But only for the domains in which something changed; it tests immediately
        // before sleeping, and it stops as soon as they answer: a wait that never ends when the
        // outcome is already good is as much a defect as not waiting.
        if (!justChanged.isEmpty()) {
            if (job != null) job.write("[7/8] " + I18n.tr("server.sts.waitingDns", java.util.Map.of("n", String.valueOf(justChanged.size()), "min", String.valueOf((MAX_WAIT_MS / 60000)))));
            List<String> remain = waitForPropagation(
                    new ArrayList<>(justChanged),
                    dom -> MtaSts.publicTest(dom).optBoolean("ok", false),
                    REAL_CLOCK, MAX_WAIT_MS, WAIT_INTERVAL_MS,
                    line -> { if (job != null) job.write(line); });
            if (job != null) job.write(remain.isEmpty()
                    ? "    " + I18n.tr("server.sts.allAnswer")
                    : "    " + I18n.tr("server.sts.stillNot", java.util.Map.of("list", String.valueOf(String.join(", ", remain)))));
        }

        // 6-7. the test and the record, domain by domain
        JSONArray finals = new JSONArray();
        try {
            AutoDns auto = new AutoDns(Main.mailDatabase, new CloudflareManager(Main.mailDatabase));
            for (MailDatabase.Domain d : domainsToTouch(domainOnly)) {
                JSONObject test = MtaSts.publicTest(d.domain);
                if (!test.optBoolean("ok", false)) {
                    finals.put(note(d.domain, false, I18n.tr("server.sts.policyNotYet", java.util.Map.of("e", String.valueOf(test.optString("error", ""))))));
                    continue;
                }
                // It is no longer skipped when the record is there: it must be checked that
                // the id matches the served policy. The records created by the old panel
                // have a fixed id that would never change.
                JSONObject e = auto.createTxtMtaSts(d.id);
                finals.put(note(d.domain, e.optBoolean("success", false),
                        e.optString("note", e.optString("error", ""))));
            }
        } catch (Exception e) {
            finals.put(note("", false, I18n.tr("server.sts.error", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("MtaStsSetup", e)))));
        }
        if (job != null) { job.advance(8, 8); job.write("[7-8/8] " + I18n.tr("server.sts.finalExamined", java.util.Map.of("n", String.valueOf(finals.length())))); }
        doneOnes.put(new JSONObject().put("key", "txt").put("title", I18n.tr("server.sts.finalTitle"))
                .put("detail", finals));

        return r.put("success", true).put("steps", doneOnes)
                .put("note", I18n.tr("server.sts.sequenceDone"));
    }

    /**
     * The outcome of the sequence translated into the rows the DNS page already knows how to
     * draw ({title, ok, message}).
     *
     * The translation is HERE and not in the DNS page because the shapes that come out of run()
     * belong to this class: if the caller knew them too, every change in here would have to be
     * remembered there, and that is how two pieces of code start to diverge.
     *
     * An interrupted step does not disappear: if the sequence stopped, the last row says why.
     * A list of successful steps that breaks off without explanation would be the worst thing
     * to show, because it looks like a success.
     */
    public static JSONArray asEntries(JSONObject outcome) {
        JSONArray entries = new JSONArray();
        JSONArray steps = outcome.optJSONArray("steps");
        for (int i = 0; steps != null && i < steps.length(); i++) {
            JSONObject p = steps.optJSONObject(i);
            if (p == null) continue;
            String title = p.optString("title", p.optString("key", "step"));
            JSONArray detail = p.optJSONArray("detail");
            if (detail == null) {
                entries.put(new JSONObject().put("title", title)
                        .put("ok", p.optBoolean("ok", false))
                        .put("messageText", p.optString("messageText", "")));
                continue;
            }
            // One step per domain: successful only if all its rows are, and the message
            // reports them all. Summarising it as "done" would lose the only row that
            // explains.
            boolean all = detail.length() > 0;
            List<String> lines = new ArrayList<>();
            for (int j = 0; j < detail.length(); j++) {
                JSONObject x = detail.optJSONObject(j);
                if (x == null) continue;
                if (!x.optBoolean("ok", false)) all = false;
                String dom = x.optString("domain", "");
                lines.add((dom.isEmpty() ? "" : dom + ": ") + x.optString("messageText", ""));
            }
            entries.put(new JSONObject().put("title", title).put("ok", all)
                    .put("messageText", String.join(" | ", lines)));
        }
        if (!outcome.optBoolean("success", false) && !outcome.optString("error", "").isEmpty())
            entries.put(new JSONObject().put("title", I18n.tr("server.sts.interrupted")).put("ok", false)
                    .put("messageText", outcome.getString("error")));
        return entries;
    }

    private static JSONObject stopped(JSONObject r, JSONArray done, String why) {
        return r.put("success", false).put("steps", done).put("error", why);
    }

    private static JSONObject outcome(String key, String title, JSONObject e) {
        return new JSONObject().put("key", key).put("title", title)
                .put("ok", e.optBoolean("success", false))
                .put("messageText", e.optString("note", e.optString("error", "")));
    }

    private static JSONObject already(String key, String title) {
        return new JSONObject().put("key", key).put("title", title)
                .put("ok", true).put("messageText", I18n.tr("server.sts.alreadyOk"));
    }

    private static JSONObject note(String domain, boolean ok, String message) {
        return new JSONObject().put("domain", domain).put("ok", ok).put("messageText", message);
    }

    /*
     * ===================================================================
     * Measurements
     * ===================================================================
     */

    private static List<String> domains() {
        List<String> l = new ArrayList<>();
        try { for (var d : Main.mailDatabase.getDomains()) l.add(d.domain); } catch (Exception ignore) {}
        return l;
    }

    /** The names the certificate must cover: the hostname plus the domains' mta-sts and autoconfig names. */
    public static List<String> namesToCover() {
        LinkedHashSet<String> n = new LinkedHashSet<>();
        List<String> excluded = domainsOnOtherAccount();
        for (String d : domains()) {
            if (excluded.contains(d)) continue;
            n.add("mta-sts." + d);
            n.add("autoconfig." + d);
        }
        return new ArrayList<>(n);
    }

    /**
     * The domains that are on a Cloudflare account different from the certificate's.
     *
     * It is not pedantry: acme.sh validates all the names of a certificate with a single token, and
     * a name that cannot be validated makes the WHOLE issuance fail. Excluding them first means
     * getting a certificate valid for the others, instead of no certificate at all.
     */
    public static List<String> domainsOnOtherAccount() {
        List<String> outside = new ArrayList<>();
        try {
            AcmeManager acme = new AcmeManager(Main.mailDatabase);
            var certAcct = acme.certificateAccount(MtaSts.mailHost());
            if (certAcct == null) return outside;
            for (var d : Main.mailDatabase.getDomains()) {
                var a = acme.accountOf(d.id);
                if (a == null || a.id != certAcct.id) outside.add(d.domain);
            }
        } catch (Exception ignore) {}
        return outside;
    }

    private static boolean certificateCovers(String name) {
        try {
            Path cert = Path.of("/usr/local/etc/ssl/mail/fullchain.pem");
            if (!Files.isReadable(cert)) return false;
            ProcessBuilder pb = new ProcessBuilder("openssl", "x509", "-in", cert.toString(),
                    "-noout", "-text");
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            // A single implementation of reading the names, shared with AcmeManager:
            // two separate readings end up diverging, and one of the two goes wrong silently.
            for (String n : AcmeManager.namesFromSubjectAltName(out))
                if (n.equalsIgnoreCase(name)) return true;
        } catch (Exception ignore) {}
        return false;
    }

    /**
     * What the panel REALLY knows about a domain's mta-sts name.
     *
     * Before, there were two separate checks ("does the name resolve?" and "is the record
     * proxied?") and both answered "fine" when they had seen nothing. On domain-d.test this
     * produced the contradiction: the plan said "CNAME present" because the name answered
     * (thanks to a wildcard in the zone), while no record with that name existed in the zone.
     * A single question, a single answer, and a dedicated value for "I don't know".
     */
    public enum NameState { RIGHT, TO_FIX, ABSENT, BLIND }

    public static final class NameReview {
        public final String domain; public final NameState state;
        public final String reason; public final boolean resolves;
        /**
         * The name answers THROUGH Cloudflare: either the explicit record is proxied, or the
         * record is missing and what answers is a proxied wildcard. In both cases the effect is
         * the same (whoever reads the policy never talks to the server) but the remedy is not,
         * and that is why the fact travels as a boolean instead of inside a sentence.
         *
         * Before, the plan derived this information by looking for the word "Cloudflare" in the
         * reason. A record both WRONG and PROXIED thus ended up only in the proxy count, and the
         * CNAME step declared "all present and correct" a record that pointed elsewhere. A
         * classification is computed where the facts are, not by rereading the text written for a
         * human being.
         */
        public final boolean goesThroughProxy;
        /** The record is there but its content is wrong: wrong type or wrong destination. */
        public final boolean wrongContent;
        NameReview(String d, NameState s, String m, boolean r) { this(d, s, m, r, false, false); }
        NameReview(String d, NameState s, String m, boolean r, boolean proxy, boolean crooked) {
            domain = d; state = s; reason = m; resolves = r;
            goesThroughProxy = proxy; wrongContent = crooked;
        }
    }

    public static List<NameReview> reviewCname() {
        List<NameReview> out = new ArrayList<>();
        CloudflareManager cf;
        List<MailDatabase.Domain> domains;
        try {
            cf = new CloudflareManager(Main.mailDatabase);
            domains = Main.mailDatabase.getDomains();
        } catch (Exception e) {
            // No domain examined: the caller sees an empty list, not a false "in place".
            return out;
        }
        for (MailDatabase.Domain d : domains) {
            String full = "mta-sts." + d.domain;
            boolean resolves = resolves(full);
            try {
                MailDatabase.CloudflareAccount a = cf.getAccountForDomain(d.id);
                if (a == null) {
                    out.add(new NameReview(d.domain, NameState.BLIND,
                            I18n.tr("server.sts.blindNoAccount"), resolves));
                    continue;
                }
                CloudflareManager.ZoneLookup zl = cf.findZone(a.apiToken, d.domain);
                if (!zl.found) {
                    out.add(new NameReview(d.domain, NameState.BLIND,
                            I18n.tr("server.sts.blindZone"), resolves));
                    continue;
                }
                List<CloudflareManager.DnsRecordInfo> allItems;
                try {
                    allItems = cf.listRecords(a.apiToken, zl.zoneId);
                } catch (CloudflareManager.ZoneReadException e) {
                    out.add(new NameReview(d.domain, NameState.BLIND, e.getMessage(), resolves));
                    continue;
                }
                if (allItems.isEmpty()) {
                    out.add(new NameReview(d.domain, NameState.BLIND,
                            I18n.tr("server.sts.blindEmpty"), resolves));
                    continue;
                }
                CloudflareManager.DnsRecordInfo found = null;
                String searched = full.toLowerCase(Locale.ROOT);
                for (CloudflareManager.DnsRecordInfo t : allItems)
                    if (t.name != null && t.name.toLowerCase(Locale.ROOT).equals(searched)) {
                        found = t; break;
                    }
                if (found == null) {
                    // "Almost certainly there is a wildcard" was a guess, written while the
                    // complete list of the zone's records was already in hand. The wildcard is
                    // checked. And the difference matters: a wildcard BEHIND A PROXY is not
                    // only the reason the name answers, it is the reason it answers 526: a
                    // fact the proxy step must know, and that a guess cannot give it.
                    CloudflareManager.DnsRecordInfo wildcard = null;
                    String wildcardName = ("*." + d.domain).toLowerCase(Locale.ROOT);
                    for (CloudflareManager.DnsRecordInfo t : allItems)
                        if (t.name != null && t.name.toLowerCase(Locale.ROOT).equals(wildcardName)) {
                            wildcard = t; break;
                        }
                    String why;
                    if (wildcard != null)
                        // No parentheses in here: this reason is already shown inside
                        // parentheses, and two nested levels read badly.
                        why = ", " + (wildcard.proxied
                                ? I18n.tr("server.sts.wildcardProxied", java.util.Map.of("d", String.valueOf(d.domain), "kind", String.valueOf(wildcard.type), "v", String.valueOf(wildcard.content)))
                                : I18n.tr("server.sts.wildcardStraight", java.util.Map.of("d", String.valueOf(d.domain), "kind", String.valueOf(wildcard.type), "v", String.valueOf(wildcard.content))));
                    else if (resolves)
                        why = ", " + I18n.tr("server.sts.answersFromOutside", java.util.Map.of("d", String.valueOf(d.domain)));
                    else why = "";
                    out.add(new NameReview(d.domain, NameState.ABSENT,
                            I18n.tr("server.sts.noRecordInZone") + why, resolves,
                            wildcard != null && wildcard.proxied, false));
                    continue;
                }
                String target = Main.mailDatabase.getSetting("mail_hostname", "mail." + d.domain);
                List<String> badOnes = new ArrayList<>();
                boolean crooked = false;
                if (!"CNAME".equalsIgnoreCase(found.type)) {
                    badOnes.add(I18n.tr("server.sts.notCname", java.util.Map.of("kind", String.valueOf(found.type))));
                    crooked = true;
                } else if (!DnsRules.sameName(found.content, target)) {
                    badOnes.add(I18n.tr("server.sts.pointsElsewhere", java.util.Map.of("v", String.valueOf(found.content), "b", String.valueOf(target))));
                    crooked = true;
                }
                if (found.proxied)
                    badOnes.add(I18n.tr("server.sts.viaCfInstead"));
                out.add(badOnes.isEmpty()
                        ? new NameReview(d.domain, NameState.RIGHT, I18n.tr("server.sts.pointsStraightTo", java.util.Map.of("b", String.valueOf(target))), resolves)
                        : new NameReview(d.domain, NameState.TO_FIX, String.join("; ", badOnes),
                                        resolves, found.proxied, crooked));
            } catch (Exception e) {
                out.add(new NameReview(d.domain, NameState.BLIND,
                        I18n.tr("server.sts.checkError", java.util.Map.of("m", org.daemoxcp.mail.util.ErrorText.detail("MtaStsSetup", e))), resolves));
            }
        }
        return out;
    }


    private static boolean resolves(String name) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", name);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor();
            return !out.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * What DNS says about the _mta-sts record, with a dedicated value for "I did not ask".
     *
     * Before, this reading was a single boolean ("is the record there and is it the right one?")
     * and it answered NO in three very different cases: record missing, record present with an
     * old id, and DNS query failed. The plan could not tell them apart, and in fact the second
     * case (the only dangerous one, because it is a public declaration already out there)
     * disappeared. Three different answers want three different values.
     *
     * NON_CHIESTO means "I don't know": dig that does not start, a DNS that does not answer, or a
     * DNS that answers with an error (SERVFAIL, REFUSED) instead of with the content of the name.
     *
     * TROPPI means more than one v=STSv1 record on the same name: for senders it is like having
     * none (RFC 8461 Section 3.1, see DnsRules.onlyMtaSts). Before, the first one was read and the
     * answer was PRESENTE, and the step could appear done on an MTA-STS nobody uses.
     *
     * It is public because the DNS page needs the same reading: two readings of the same record
     * are two readings that one day answer differently.
     */
    public enum TxtOutcome { PRESENT, ABSENT, TOO_MANY, NOT_ASKED }

    public static final class TxtReading {
        public final TxtOutcome outcome;
        /**
         * With PRESENTE, the record. Otherwise empty, even with TROPPI: there, "the" record does not
         * exist.
         */
        public final String content;
        /** All the v=STSv1 records found: one with PRESENTE, more than one with TROPPI. */
        public final List<String> values;
        /**
         * With NON_CHIESTO, the reason: "the DNS answers SERVFAIL" and "no DNS answers"
         * lead to looking for the fault in different places.
         */
        public final String reason;

        private TxtReading(TxtOutcome outcome, List<String> values, String reason) {
            this.outcome = outcome;
            this.values = List.copyOf(values);
            this.content = outcome == TxtOutcome.PRESENT ? values.get(0) : "";
            this.reason = reason;
        }
    }

    /** From the name's v=STSv1 records: none, only one, or too many. */
    private static TxtReading found(List<String> sts) {
        TxtOutcome e = sts.isEmpty() ? TxtOutcome.ABSENT
                   : sts.size() == 1 ? TxtOutcome.PRESENT : TxtOutcome.TOO_MANY;
        return new TxtReading(e, sts, "");
    }

    private static TxtReading unknown(String reason) {
        return new TxtReading(TxtOutcome.NOT_ASKED, List.of(), reason);
    }

    public static TxtReading readTxt(String domain) {
        try {
            // Without +short: the status of the answer is needed. With +short a SERVFAIL (a broken
            // zone, a DNSSEC that does not validate) exits with 0 and prints nothing, exactly like a
            // name without records: the plan read "absent" and offered to publish a record that
            // might already be there.
            ProcessBuilder pb = new ProcessBuilder("dig", "+noall", "+comments", "+answer",
                    "TXT", "_mta-sts." + domain);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return parseTxt(p.waitFor(), out);
        } catch (Exception e) {
            // dig missing or not starting: I asked nobody anything.
            return unknown(I18n.tr("server.sts.digNoStart"));
        }
    }

    // ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55131"
    private static final Pattern DIG_STATE = Pattern.compile("->>HEADER<<-.*\\bstatus:\\s*([A-Z]+)");
    // "_mta-sts.domain-d.test.  3600  IN  TXT  "v=STSv1; id=..."": name, TTL and class, then the type
    private static final Pattern LINE_TXT = Pattern.compile("^\\S+\\s+(?:\\d+\\s+)?(?:IN\\s+)?TXT\\s+(.+)$",
            Pattern.CASE_INSENSITIVE);

    /**
     * What the output of "dig +noall +comments +answer TXT _mta-sts.<domain>" means: the code
     * dig exited with and what it printed. It stands alone so that the tests can verify it with
     * recorded dig outputs, without needing a reachable DNS; it is public because the DNS page
     * tests use it too, and they are in another package.
     *
     * The status of the answer decides before the content:
     *   NOERROR  -> the name exists: its v=STSv1 records are counted. None is ASSENTE, one
     *               is PRESENTE, more than one is TROPPI;
     *   NXDOMAIN -> the name does not exist: ASSENTE;
     *   another status (SERVFAIL, REFUSED...) or none -> the DNS did not say what is there:
     *   NON_CHIESTO.
     */
    public static TxtReading parseTxt(int digOutput, String printed) {
        // dig returns 0 even when the name does not exist: a non-zero exit means that I
        // did not ASK, not that the answer is "nothing". They are opposite things.
        if (digOutput == 9) return unknown(I18n.tr("server.sts.noDnsAnswers"));
        if (digOutput != 0 || printed == null) return unknown(I18n.tr("server.sts.digExit", java.util.Map.of("c", String.valueOf(digOutput))));
        Matcher state = DIG_STATE.matcher(printed);
        String s = state.find() ? state.group(1) : "";
        if (s.equals("NXDOMAIN")) return found(List.of());
        if (s.isEmpty()) return unknown(I18n.tr("server.sts.digNoStatus"));
        if (!s.equals("NOERROR")) return unknown(I18n.tr("server.sts.dnsAnswers", java.util.Map.of("s", String.valueOf(s))));
        // All the TXT records of the name, not the first one that fits: the count of v=STSv1
        // records is part of the answer.
        List<String> txt = new ArrayList<>();
        for (String line : printed.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith(";")) continue;
            Matcher m = LINE_TXT.matcher(t);          // a CNAME in front of the TXT is skipped
            if (m.matches()) txt.addAll(DnsRules.recordTxt(m.group(1)));
        }
        return found(DnsRules.onlyMtaSts(txt));
    }

    /**
     * The TXT record this panel would write now.
     *
     * It is not enough that the record exists: the id must match the served policy, otherwise
     * senders will not notice future changes. The records created by the old panel have a
     * fixed id (a clock reading written once only) that would never change. A plan that took
     * them as "done" would hide exactly the thing to fix.
     */
    private static String expectedTxt() {
        // It is not recomputed here: MtaSts knows it, and it is also what serves the policy.
        // Three places that compose the same string are three strings that one day diverge,
        // and it has already happened, with the clock-based id of the DNS summary.
        return MtaSts.currentTxtRecord();
    }

    private static boolean jailActive() {
        try {
            ProcessBuilder pb = new ProcessBuilder("fail2ban-client", "status", WebProtection.NAME);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
