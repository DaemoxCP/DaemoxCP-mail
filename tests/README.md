# The panel's tests

They are not part of the build: Maven does not look at this folder, and the jar does not contain
them. They are classes with a `main`, compiled against the jar already built and run by hand.

The jar is compiled for Java 25 (`<release>25</release>` in the pom). With a newer JDK on the Mac,
the tests must be compiled with `--release 25`, otherwise they do not start on the VM:
«has been compiled by a more recent version of the Java Runtime (class file version 70.0),
this version ... recognizes class file versions up to 69.0». The jar instead is fine, because
Maven declares the release.

And the outcome of a test is its **exit code**: `java ... | tail -4` returns that of `tail`, that
is always zero. A test that does not start at all, read that way, looks passed.

    mvn -o -q package -DskipTests
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/system/*.java
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/webserver/*.java
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/database/*.java
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/security/PasswordGeneratorTest.java
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/security/MtaStsRecordTest.java
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MtaStsTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PackageCatalogTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.MtaStsRecordTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PropagationWaitTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MtaStsSequenceTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.AutoconfigTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MtaStsOldLogicTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.SrvRecordTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ReportDeliveryTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelMailTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PackagePlanTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PackageQueueTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InstallLocksTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PendingDbPasswordTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PendingDbPasswordE2ETest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.sqli.SqliteSharedTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.database.MysqlReconnectTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InstallWayBackTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ReinstallWayBackE2ETest
    javac -cp target/daemoxcp-mail.jar -d tests/planted tests/planted/org/daemoxcp/mail/scripts/FullMailServerScript.java
    java -De2e.vm=yes -cp "tests/planted:tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ReinstallJobTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InterruptionWatchTest
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.scripts.InstallScriptsTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.scripts.InstallScriptVersionTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ReinstallReturnE2ETest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.NoBootEnvironmentTest
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InterruptionReportTest
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.LockMarksTest
    expect tests/menu-way-back.exp <ssh key> <clone host> <panel folder on the clone> <jar>
    expect tests/menu-reinstall-warning.exp <ssh key> <clone host> <panel folder on the clone> <jar>
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PackageTurnAcrossProcessesTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.util.ShellShortPathTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.AliasMessagesTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.PasswordGeneratorTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SoftwareVersionsTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.AddressConversionTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PkgBranchTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ChildStdinTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.HeldUpdatesReportTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PlanDivergenceTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PlanAfterFetchTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ServiceFallTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.AuditReportTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.LockTraceTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InstallSideEffectsTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InstallScriptDriftTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.EverythingTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixInetProtocolsTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.CloudflareCommentsTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.CloudflareTokensTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RcScriptRepairTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SafeOwnershipTest   (VM, as root)
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.AcmeCloudflareCopyTest   (VM, as root)
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotSocketsTest   (VM, as root: it restarts Dovecot)
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotMoveTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveStorageTest
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/integration/*.java
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.integration.SieveGeneratorTest
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveForcedKeepTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveActionsE2ETest   (VM, as root, real deliveries)
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveCompilerTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveCompilerE2ETest   (VM, as root, real deliveries)
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveFolderOwnerTest   (VM, as root, real deliveries)
    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveGroupMailTest   (VM, as root, real deliveries)
    su -m nobody -c 'java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.SieveRulesNotWrittenTest'   (VM, test MySQL, unprivileged)
    su -m nobody -c 'java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.SieveDialogFieldsTest'   (VM, test MySQL, unprivileged)
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveRulesOwnerTest   (VM, as root)
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.FreshInstallDovecotTest

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotHomeTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotHomeE2ETest   (VM, Dovecot 2.3, home of before)

    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.AddressTransformLinksTest   (VM, as root, real /var/vmail)

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SieveRulesRefreshTest

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DovecotMasterUserTest   (VM, as root, real doveadm)

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.scripts.FullMailStackCleanupTest   (VM, as root, pw -R on a copy)
    cd /home/panel && java -De2e.vm=yes -cp "<tests>:<jar>" org.daemoxcp.mail.system.Dovecot24MoveE2ETest   (VM, Dovecot 2.3, changes it)
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RunningJobTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RestartServicesTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.database.ResetDatabaseTest
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/monitoring/*.java
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.monitoring.MailQueueTest
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/sqli/*.java
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.sqli.ConfigSecretsTest
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/scripts/*.java
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.scripts.LocalMtaTest
    sh tests/pkg-simulation-test.sh
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InstallPackagesTest

Every test is in English, comments and messages included. When a check needs an Italian text of the
panel, it reads it from `src/main/resources/lang/it.json` by key (in Java with `I18n.t("it", key)`,
in the browser tests from the parsed file), never writes it out; the Java tests that read the
panel's messages set `I18n.setCurrent("en")`, because outside a request the panel speaks Italian.

## The tests of the updates area

`ChildStdinTest`, `HeldUpdatesReportTest`, `PlanDivergenceTest`, `PlanAfterFetchTest`,
`ServiceFallTest`, `AuditReportTest` and `LockTraceTest` must be run **on the FreeBSD VM**, not on
the Mac: part of them asks `pkg` what the machine is really like (the keys `packagesStatus` sets,
the packages `pkg audit` calls vulnerable, the locked packages) and on the Mac that part **is
skipped, saying so**, because a test skipped in silence counts as green without having tested
anything.

Two of them touch the system and put everything back as it was: `LockTraceTest` writes the
`daemoxcp_mail_lock` annotation on a package and removes it, and writes the locks note in a temporary
folder (not in `/var/db`, like `PackageQueueTest` with its list). `AuditReportTest` asks `pkg audit`
about the installed packages and changes nothing. They are fine on a test machine, not on a real
mail server.

`InstallScriptDriftTest` is the test of reperto 42 (postfix's install script removing IPv6 from
main.cf) and has two parts. The first reads the real output of that update and runs anywhere. The
second runs the three real jobs — guided update, unprotected packages, full maintenance — on a fake
package, `drift-probe`, which it builds by itself with `pkg create`: it is turned on only with
`-De2e.vm=yes`, as root, on FreeBSD. For the duration of the test it turns off the FreeBSD-ports
and FreeBSD-ports-kmods repositories (a file in `/usr/local/etc/pkg/repos`), puts an `nc` listening
on port 47425 of 127.0.0.1 and ::1, and the maintenance unlocks and locks again the protected
packages as always; before every job it checks that the plan contains only `drift-probe`, and at
the end it checks that packages, protections and repositories are those of before. Only on a test
machine. It takes a few minutes: a missing address is waited for sixty seconds before it is called
lost.

    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InstallScriptDriftTest

`UpdaterRobustnessE2ETest` tests the edges of the package update with real jobs on fake packages
(`nginx-robust-probe`, `robust-probe-other`) from a `file://` catalog, with the real repositories
turned off: the way back (M1), the turn across processes (M2, M2b), an external pkg holding the
lock (M3), the panel killed halfway through pkg (M4), the timeout (M5), the report after an
interrupted job (M6), and the job completed by the panel service by itself (M8: a guided update killed
halfway, nginx restarted with a new pid, everything verified; M8b: the same for the update of the
unprotected packages, which unlocks nothing). M8 needs the panel service running the build under test:
with an older one its four completion checks fail. It creates and removes `packages-before-*` boot
environments. M7 (the machine
switched off abruptly during pkg) comes in two steps: `-Dmeasure=m7`, then `reboot -nq` when it
prints "M7 IN PKG", then, with the panel started again, the `m7-after` mode. Only on a test machine.

    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.UpdaterRobustnessE2ETest

`SignedJobsE2ETest` runs the three dedicated package jobs end to end under the signed plan: the
Roundcube update, the Python transition and the MySQL 8.4 migration. For each one: the checks and
the plan (measured, with a fingerprint; the two jobs that remove packages first say it at the top of
the plan), the job refused without a fingerprint, the job refused with a fingerprint that is not the
plan's BEFORE touching anything (same packages, same protections, no list of unlocked packages), then
the real run: the approved plan, nothing changed outside it, every line where it said, the
protections back. Each mode needs the old situation prepared by `tests/signed-jobs-setup.sh` with the
same mode (`roundcube`: Roundcube recorded one version behind the catalog; `python`: `py311-build`
installed and protected; `mysql84`: MySQL 8.0 in place of the 8.4, with the data and the accounts
loaded back), and puts it back with `restore-python` / `restore-mysql84`; `cleanup` removes the
`packages-before-*` boot environments the jobs created. It starts from the panel's folder, because
the jobs read the panel's configuration (read-only here). Only on a test machine; the full log of
each job goes to `/var/tmp/signed-jobs-<mode>-<attempt>.log`. How it went on the VM: reperto 189.

    sh tests/signed-jobs-setup.sh roundcube
    cd /home/panel && java -De2e.vm=yes -cp "<compiled tests>:<jar>" org.daemoxcp.mail.system.SignedJobsE2ETest roundcube

With `-Doutside=tree` the real run also gets a change outside its plan: a real package installed between the
inventory photo and pkg (`UpdateManager.PlanWatch.afterTaken`, null in the service), as someone running pkg from SSH.
The job must end in error naming it, with every line of the plan still where it said; with `-Doutside.when=before`
the package goes in before the job instead, and those three checks must fail (reperto 190).

`signed-jobs-browser-test.js` uses two of the same procedures, Python's move and the move to MySQL 8.4 (from their rows of "Update the server", reperto 197; Roundcube is a step of "Update everything" since reperto 207) in a real browser (Playwright with the Chrome installed on
the Mac), against the panel of the test VM through an SSH tunnel: "Check prerequisites", the plan and its
fingerprint in the card, start from the panel's window (the word goes in the request), the log to the end. It checks that the start request
carries the fingerprint the card showed and that the job ran that one. It signs in with a console code and gives
its session the fresh confirmation with the `confirm` mode of `signed-jobs-setup.sh` (VM only). It also reports
every JavaScript error of the pages it opens.

`os-patch-browser-test.js` does the FreeBSD patches on the test VM as a person would (reperto 196), in two phases:
`install` (check for updates if none is known; the FreeBSD row with the patches ready and no button of its own, the
patches as the first step of "Update everything" at the top, reperto 207; the confirmation, the progress in one line
with the details closed, the outcome with what is installed and the restart left, the FreeBSD row with the restart's
button; the operation logs in Diagnostics with the job's log on disk; the restart from the panel's window) and
`after` (once the VM is back: nothing left in the FreeBSD row, the logs written before the restart still there). It
changes the VM: patches, a boot environment, a restart.

`everything-browser-test.js` does "Update everything" on the test VM as a person would (reperto 207): the row at
the top with the steps in order and one button, "Cancel" that leaves the button where it is, the confirmation with
every step numbered, the request with the fingerprints read and the changes shown, the one job to its end with the
end as the last line of its log. With the panel's Java last (it took the place of `java-update-browser-test.js`): the
page reloaded while the Java script works says "In progress: the update of the panel's Java", where it is ("Now: [n/7]
..."), offers nothing and warns of no job that did not finish (reperto 210); then the
page that reloads by itself on the sign-in page when the panel comes back (a restart ends every session), the sign-in
again, the Java report in Diagnostics, and on the VM through `java-update-state.sh` the service that sees the panel
again (its pidfile is the root part), the web part as daemoxcp_mail holding the port, the JVM new and protected again.
Afterwards: nothing left to update, Update everything completed in the operation logs, every service up, the
protected packages protected again, postfix's `inet_protocols` written and postfix listening as before. It needs
updates waiting on the VM; the way back is the boot environment the job makes before the first step.

`dovecot24-move-browser-test.js` does the move to Dovecot 2.4 on the test VM from the page (reperto 213): Diagnostics
before (Dovecot to look at, pointing to Updates), the row "Dovecot 2.4" with Prepare, the checks with the exact plan
(2.3 removed first, 2.4 installed, no second MySQL client), the tests and the mailbox they run on, one confirmation,
the job to its end with its eight steps and the same mail tests passing on 2.3 before and on 2.4 after (IMAP login,
LMTP delivery, the password process not root, Dovecot's own MySQL user), no way back taken; Diagnostics after, with
the compatibility card saying 2.4 is installed. It needs Dovecot 2.3 on the VM and it changes it; the way back is the
boot environment the job makes, or the one made before.

`database-restart-browser-test.js` stops MySQL on the test VM for about 25 seconds with the panel open (reperto 209):
a read asked meanwhile waits with the strip that says the database is restarting and gets its answer when it is back;
a page opened in that moment answers 503 "the database is restarting" and reloads by itself into the page, not the
sign-in; afterwards the session is the same. With the jar of main three of its checks fail (the page opened during the
stop lands on the sign-in page).

`diagnostics-browser-test.js` presses "Check everything" in Diagnostics on the panel of the test VM (reperto 199):
the ten read-only checks one after the other, each with its verdict, what needs a look first and the most important
first, its state in words and at most one button, what is fine closed below; "Open the details" brings its card into
view. Read only.

`restart-lock-browser-test.js` schedules a restart on the test VM with a stand-in (reperto 200): a program called
`shutdown` that only sleeps, compiled with cc and started as `shutdown -r +7`, so nothing can restart the VM. On the
real panel: the strip with the time and "only reads", a button of the page that does nothing and says why; 409 on a
route of the web part, on one of the root and on one that asks for a recent confirmation (without asking for it
first); reads that pass; "Cancel the restart" (with the session's fresh confirmation from `signed-jobs-setup.sh
confirm`) ends the stand-in, and the same change is no longer refused. The stand-in is ended by its exact PID anyway.

`console-confirmation-browser-test.js` (Playwright, VM): the confirmation of a sensitive operation with a code from
the server console, for an administrator without a passkey on a server that cannot send mail yet. Signed in with a
console code and no passkey, a harmless change in Settings opens the confirmation window; it offers the console way with
the command and the administrator's name; a wrong code is refused and the window stays; the command shown, run on the
server, gives the code that confirms, and the change goes through; the same code again gets 401.

`ReleaseCheckTest` (anywhere, no network) is the new-version notice: which GitHub release is newer than the running
panel (semver order, drafts never, pre-releases only for a 0.x or suffixed panel, the link built from the tag and never
taken from the answer), when the panel asks again (once a day, "Check now" at most once a minute, a date in the future
does not stop it), and what it does with each of GitHub's answers, given by a local HTTP server: a list, an empty list,
404, the rate limit, 500, a page instead of JSON, an answer over 2 MB, nobody answering.

`release-notice-browser-test.js` (Playwright, VM): the same notice in the pages. The *Updates* card with the running
version and the daily check on; "Check now" asking GitHub for real (until the repository is public it answers 404,
and the card says so in words) and not asking again within a minute; the daily check off (the recent confirmation:
cancelled, the switch goes back; confirmed with a console code, it goes off) and on, with a reload and the audit log;
a newer release (the page's API answer replaced in the browser) on the card and on the *Dashboard*, with the link, a
link that is not a GitHub release page left out, and the contrast of the link in both themes; at 375 px the card
fits.

`MailboxAddressMapTest` and `CatchAllTest` (anywhere) are the catch-all's decisions without Postfix: when the start
adds Postfix's mailbox map after the aliases, rewrites a map that says something else, or leaves a hand-written
`virtual_alias_maps` alone; the map's text made from the aliases' map (only the mailboxes that receive); when a
catch-all can be created; that both installers write the map; what a catch-all source is, and a destination that
would come back to the catch-all itself.

`catch-all-browser-test.js` (Playwright, VM) is the catch-all with real mail, on a domain of its own that it removes
at the end. Before the catch-all, from outside (the machine's own address, not in mynetworks), Postfix refuses an
invented address and a mailbox that does not receive, and accepts a mailbox: the map changes nothing without a
catch-all. The catch-all made from the Aliases page; then, over SMTP and checked with `doveadm search`, an invented
address and the mailbox that does not receive land in the catch-all, the mailbox and an alias keep their mail. The
control: with `virtual_alias_maps` put back to the aliases alone (and restored), the mailbox's mail goes to the
catch-all, and the panel refuses to create one.

`WebmailPasswordPluginTest` (where `php` is, the test machine) runs the config the panel writes into Roundcube's
`config.inc.php` with the real PHP: the `password` plugin added to the list when it is missing, never twice, and no
list created when the list is in another file; the current password asked for; and the SSO plugin the panel writes
sends the webmail's key under the panel's header name and parses.

`webmail-password-browser-test.js` (Playwright, VM; the webmail on 8443) changes a mailbox's password from Roundcube
on a domain of its own: after the sign-in Roundcube's log has no new "did not answer the password copy request" (it
had one after every sign-in from 17/11 to 18/11/2026); Settings has *Password*, with the current password; a password
under 12 characters is refused; a good one is saved, and IMAP takes the new one and refuses the old one.
`MailboxPasswordTest` with `-Droundcube.dir` does not see a broken sign-in hook: its second run also changes the
password, which writes the copy by itself.

`DovecotQuotaTest` (anywhere; the doveconf part where doveconf is) is the mailbox quotas without Dovecot: the quota
userdb right before userdb static in `auth-sql.conf.ext`, once, and a file the panel did not write left alone; what the
start does on 2.3, on 2.4 with and without the quota pieces; the question to quota-status right after
`reject_unauth_destination`; the lines of `doveadm -f tab quota get -A`; and the installer's whole 2.4 configuration,
with the quota pieces, parsed by the real doveconf.

`quota-browser-test.js` (Playwright, VM) is the quotas with real mail, on a domain of its own: Dovecot gives a 1 MB
mailbox its limit; empty, Postfix accepts it from outside; a 2 MB message fills it (Dovecot's grace lets that one
through); then from outside 452 4.2.2, a mailbox without a limit 250; one more message from the machine is refused by
LMTP and the bounce says the quota; IMAP's GETQUOTAROOT gives 1024 KB; the Mailboxes page says "Full" with a bar at
100 %; the limit taken away from the panel, the recipient is accepted again at once.

`SendingLimitsTest` (anywhere) is the panel as Postfix's policy service for the sending limits, without Postfix: which
limit applies (the mailbox's own if active, else the global one, else none); what is not counted (another request,
another stage, incoming mail without sasl_username); recipients per message (550), per hour and per day (450), with
the windows moving; the counts saved and read back after a restart; the limits on a request (line length, attribute
names and number); the question first in smtpd_data_restrictions; and a real Unix socket with two requests on one
connection, as Postfix sends them.

`sending-limits-browser-test.js` (Playwright, VM; it stops and starts the panel) is the sending limits with real
submissions on 587, on a domain of its own: Postfix asks the panel at DATA; with a limit of 3 per hour the fourth gets
450 4.7.1 saying why; incoming mail for the sender is not counted; the Sending limits page says "Applied", the sender's
3 / 3 and the senders of the day; raised to 10 the fourth goes at once; the counts are on disk within a minute, root
only; with the panel stopped Postfix lets the mail pass, and started again the counts are back and the limit holds.

`MailLogStatsTest` (anywhere; the .bz2 part where bzip2 is) is the sent and received counts read from Postfix's log,
without the real log: a message a mailbox sent (received by the local mailbox, sent once per recipient, outside too),
incoming mail, a bounce of incoming and of sent mail, a deferral (nothing), Rspamd's refusals (spam, virus), the queue
entry dropped at «removed»; the UTC day of syslog dates (00:30 in Rome, a single-digit day, December read in January,
RFC 5424); the sums once per group; complete lines from a position; the rest of a turned-over file from maillog.0
while newsyslog has not compressed it (same inode, even with a half-written .bz2 beside it), from its .bz2 once
maillog.0 is gone, and a wait while neither is there (the real server at 00:00:02 on 21/11/2026), given up after 10
minutes.

`mail-stats-browser-test.js` (Playwright, VM) is the counts with real mail, on a domain of its own: two messages from
A to B on 587, one from outside to B, one from A to an address that does not exist (it bounces, and Postfix's notice
reaches A), GTUBE from outside (Rspamd refuses it); within two minutes today's counts grow by exactly 2 sent,
4 received, 1 bounced, 1 spam, the domain's row the same, and the Statistics page shows them with the note that says
what each number counts. The senders from outside are addresses of the run's domain: example.org has a null MX, and
Postfix refuses it as a sender.

`MenuReinstall` is not a test but the driver of the full reinstallation from the menu
(`ReinstallJob.runFromMenu`, the same function as the menu entry: it starts it detached with
daemon(8) and follows its log) on a server where the panel has already started: it unlocks the
protected packages, runs the script with the panel's turn, locks them again. It stops the mail,
empties `/var/vmail` and changes the panel's MySQL password: only on a clone of a boot environment,
and from a COPY of the panel folder if that is in `/home` (outside the boot environments). How it
was used on the VM, with the concurrency attempts halfway: reperto 154.

    cd <copy of the panel folder> && java -De2e.vm=yes -cp "<compiled tests>:daemoxcp-mail.jar" org.daemoxcp.mail.system.MenuReinstall

The four tests that run real jobs (this one, `InstallScriptDriftTest`, `PackageReplacementE2ETest`,
`PostfixMapsJobsE2ETest`) remove at the end the boot environments their jobs created.

`HeldUpdatesReportTest` and `AuditReportTest` need the vulnerability database (`pkg audit -F`):
without it, they say which checks they skipped and why.

## The full installation

`InstallPackagesTest` is the test of reperto 52 (the installer put in a Dovecot without MySQL and
declared itself successful). Since reperto 215 the script picks Dovecot 2.4 or 2.3 itself
(`install_packages $DOVECOT_PACKAGES`): part 0 reads the two choices from the script, A and B run on
the script as it runs with each, C on the one this machine's catalog would pick. Parts 0, A, B and D
run anywhere: the script's text, its real install
lines run against a fake pkg that drops a requested package and exits with 0 (the script must stop
there), and the updater's labels. Part C asks pkg's REAL solver for the plan of every line as on a
freshly installed machine: a copy of pkg's database with only pkg installed, the packages
downloaded into a temporary folder (~180 MB, because pkg sees file conflicts only after downloading
them), and every requested package must be in the final plan. It installs nothing and does not
touch the real database; it is turned on with `-De2e.vm=yes`, as root, on FreeBSD.

    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InstallPackagesTest

`PostfixLevelTest` (reperto 251), as root on the VM (part 3 needs Postfix): the three scripts that write main.cf write
the 3.6 floor and decide every parameter a reviewed level above it changes (smtp_tls_security_level; TLS-RPT is off,
so its change does not apply); the level piece runs once, after main.cf and before Postfix starts; every default that
the real `postconf -d` shows as depending on the level is listed in PostfixLevels at that level, and the level this
Postfix asks for is reviewed; the piece with a fake postfix and postconf raises only to a reviewed, higher level (not
reviewed, no request, lower, the same, a strange answer: unchanged). Falsified with planted copies: 6 FAILED.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixLevelTest

`CloudflareTokensTest` (with the secrets in a temporary folder it sets itself): the Cloudflare API tokens sealed in
the database with DataCrypto (AES-256-GCM, a random nonce each time) and read back the same; a token in clear, written
before the migration, read as it is; a sealed value that does not decrypt gives "", never the sealed text; the boot
migration seals the tokens in clear row by row, only where the row still has the value read (a row changed meanwhile
stays, PARTIAL), and a second start has nothing to do; MailDatabase seals on every write and opens on the one read.

`SafeOwnershipTest` (as root on the VM, from the project root): root giving a folder to a user without giving it
other people's files (reperto 252). On FreeBSD anyone can hard-link another user's file on the same file system, and
/var/vmail is on the file system of /etc: "chown -R vmail:vmail /var/vmail" gave vmail a root file linked in there.
What is safe to change (a folder, a file with one name; not a file with two names, a link, a FIFO); the script piece
on a real tree with a root file hard-linked and one behind a link (both stay root's, the hard link is said); names
that are not a panel folder refused; the installation scripts, the mail folders' regeneration (created as vmail),
Roundcube's folders and acme.sh's walk use it; RoundcubeUser.apply on a tree with a hard link. Falsified with the old
SafeOwnership: 10 FAILED.

`AcmeCloudflareCopyTest` (as root on the VM, from the project root): the clear copy of the Cloudflare token that
acme.sh saves in its account.conf (SAVED_CF_Token, SAVED_CF_Account_ID) removed after every run the panel gives the
token to, and at boot: only those lines go, the rest stays byte for byte with owner and permissions; a link or a file
with two names is left; a second run has nothing to do. Falsified with a version that removes nothing: 4 FAILED.

`DovecotSocketsTest`: the three Dovecot sockets open to anyone that the panel does not use, closed (indexer 0660
root:vmail, imap-urlauth and auth-token 0600; dns-client stays). The decision (only on 2.4; write, restart or nothing),
the file (each listener in its own service: imap-urlauth belongs to imap-urlauth-login, and in imap-urlauth Dovecot does
not start), the installer and the move to 2.4 write it. With -De2e.vm=yes, before the panel applied it: the wrong file
written by the migration, accepted by doveconf and refused at the restart, is taken away and Dovecot brought back with
authentication, LMTP and IMAP answering. Falsified with a decision that always writes: 3 FAILED.

`RcScriptRepairTest` (from the project root, it reads UpdateManager.java): the start script the panel wrote, with the
old file names and the old Italian messages, repaired at boot (whole lines only, sh -n, same owner and mode, atomic
rename; a script without the panel's signature left alone); the script the panel writes today has today's messages.

After an installation from scratch (`InstallFromScratch`), `mail-login-probe.sh` does a real login:
it creates a test mailbox in `login-probe.test`, tries `doveadm auth test`, an IMAP LOGIN on 993 and
an AUTH PLAIN on 587, shows the maillog lines and removes mailbox and domain. On 24/10/2026, with
the installer of before, the services were all running and it failed on all three entrances. Since
reperto 214 it also tries Sieve: a script of the mailbox's own through ManageSieve on 4190
(PUTSCRIPT, SETACTIVE) and a rule of the panel written as the panel writes it, then a real delivery
through Postfix: the panel's rule must run first and the mailbox's own script after it, `doveadm
sieve list` must open the scripts, and no "dovecot.sieve" may show among the folders. With the Sieve
layout of before it fails there (ManageSieve: "BYE Internal error"). Since reperto 216 a second delivery
with a panel's rule that moves, written with no keep at the end as the panel writes it now: the message
only in the panel's folder, not in INBOX, and the mailbox's own script does not run on it (with a `keep;`
put back at the end, measured, the own script runs too and it fails). Since reperto 217 the mailbox's
script uses the Sieve "duplicate" test, which writes Dovecot's duplicate database in the home as
autoreplies and forwards do: with the home of before (the mail root) "dovecot", "dovecot.lda-dupes"
and "dovecot.lda-dupes.locks" show among the folders and it fails (measured on the VM). Since reperto 239 a real
Roundcube login on the webmail's nginx site, then the mailbox page: it must carry the folder list, which comes from
IMAP, so Roundcube decrypted the IMAP password from its session (des_key, cipher_method). "task mail" and the logout
link are not enough: with IMAP refused Roundcube still draws the mail page, with an error and no folders (measured on
the VM by changing des_key between the login and the page: with the folder list it fails, without it it passed).
Roundcube's row for the probe mailbox is removed at the end. As root, in the panel folder:

    sh tests/mail-login-probe.sh

## With a test MySQL

AddressConversionTest, SoftwareVersionsTest and ResetDatabaseTest have a part that runs on a real
MySQL, and without the `-Dmysql.*` options they skip it, saying so. It needs the official MySQL 8.0,
the one the panel installs (mysql80-server), not MariaDB: on FreeBSD `pkg install mysql80-server`,
on macOS `brew install mysql@8.0`. A throwaway server, in a test folder and only on 127.0.0.1 (as
root add `--user=root` to the two mysqld lines):

    M=$(mktemp -d)
    mysqld --initialize-insecure --datadir=$M/data
    mysqld --datadir=$M/data --socket=$M/m.sock --port=33062 --bind-address=127.0.0.1 \
           --mysqlx=OFF --secure-file-priv= --pid-file=$M/m.pid &
    mysql -uroot -S $M/m.sock -e "CREATE DATABASE daemoxcp_mail_test;
        CREATE USER 'daemoxcp_mail'@'127.0.0.1' IDENTIFIED BY 'test-password';
        GRANT ALL ON daemoxcp_mail_test.* TO 'daemoxcp_mail'@'127.0.0.1';"
    P="-Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=test-password -Dmysql.database=daemoxcp_mail_test"
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.AddressConversionTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SoftwareVersionsTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.VersionsApiTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.LanguageRoutesTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.QueueApiTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.RateLimitsApiTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.CsrfFilterTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.RolesTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.LoginRoutesTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.MailboxPasswordTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.LoginSecurityTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.database.ResetDatabaseTest

The tests default to the database `daemoxcp_mail_test` when `-Dmysql.database` is not given.

**Never on the panel's database**: AddressConversionTest's part drops and creates again all the
tables of the database it is given (VersionsApiTest, LanguageRoutesTest, QueueApiTest,
RateLimitsApiTest, CsrfFilterTest, LoginRoutesTest and MailboxPasswordTest use the tables it
leaves), LoginSecurityTest drops them and creates them again as an old installation with
passwords, and ResetDatabaseTest empties it completely, tables that are not the panel's included.
SoftwareVersionsTest instead only reads (SELECT VERSION()).

### The guided installation (reperti 242-250)

**GuidedInstallTest** — no system: the time zone of menu option 1 (an IANA name known to Java and present as a
plain file in zoneinfo, never a path, a link or a made-up name; the current one from /var/db/zoneinfo, UTC when
unknown); the three names before installing from the menu (the factory webmail name stops, a mail name without a dot
stops, mail and web on the same name stop, a panel without a name is only a warning); outbound port 25 with a fake
dialer (open on the first answer, blocked when names resolve and nobody answers, unknown without names).

**PanelCertificateTest** — with openssl (on the VM): the panel certificate checked before menu option 2 saves it (a
certificate signed by a small CA for `*.example.com`: what it covers, the issuer, the expiry, the key; a wildcard
covers one label only; another name, expired, not valid yet, a foreign key refused; five minutes of clock skew
accepted; a panel without a domain name and a self-signed certificate warned; PKCS#1 RSA and PKCS#8 EC keys; paths,
links and files without PEM); then the provider firewall's list (the fingerprint independent of the order; never,
current, changed, unknown; the rules from the ports, POP3 included; a confirmation of a list that changed meanwhile
refused, a good one written 0600; a short list from cloudflare.com not believed).

**SetUpEverythingTest** — as root on the VM, with the service's umask (`sh -c 'umask 077; java ...'`): "Set up
everything" on a server installed from scratch (reperto 250). The MTA-STS policy written readable by nginx (folder
0755, file 0644, also over 0700 and 0600), through a file beside it renamed in place, a link planted there removed
and its target untouched, a link in place of the folder refused; the boot repair (DONE, then nothing to do; links in
place of the folder or the policy left as they are); the Cloudflare account checked before touching anything (the
domain's own that sees the zone; the only one of the panel that sees it, assigned; none in the panel, none that sees
it, several, no answer: refused with what to do). Falsified with planted copies of the old behaviour: 13 FAILED.

`menu-guided-install.exp` drives the real terminal menu on the VM from the Mac (expect through `ssh -tt`) on a copy of
the panel folder: option 1 refuses a made-up time zone in a dialog; option 2 refuses a certificate given as a path
that does not cover the panel name, and shows the right one in the confirmation (its key, the self-signed warning);
Cancel saves nothing. The header says how to prepare the copy and how to read the log.

`real-ip-browser-test.js` (Playwright, VM): whose address the panel believes and which names it answers to (r18),
reaching the panel directly from this computer's address in the VM's private network, the case that used to be trusted
like Cloudflare: another name with Cloudflare's headers gets 421, the panel's own name answers, and a sign-in with a
forged CF-Connecting-IP leaves this computer's real address in the session. Red on the panel before the fix in all three.

`acme-install-browser-test.js` (Playwright, VM, reperto 247): on a server installed from scratch acme.sh is not
there, and nothing in the pages installed it. The SSL page shows the card "Let's Encrypt is not ready" while acme.sh or
its Let's Encrypt account is missing; a malformed address is refused in the page; "Install acme.sh" installs the
package (user acme) and asks for the account. With a test address Let's Encrypt refuses the account, and the panel
says so with Let's Encrypt's reason (never "account created"), and the card stays. Measured on the VM: the first run
installed the package from scratch; creating the account for real needs a real address.

`provider-firewall-browser-test.js` (Playwright, VM): the Firewall page's card "Your provider's firewall" with the
three rules from the server's real ports, Cloudflare's official list ready to paste, "not confirmed yet"; the
confirmation in the panel's window, then "current list", the state file 0600; Diagnostics "Check everything" with the
provider firewall fine and outgoing port 25 closed (the VM's network closes it), naming what to ask the provider.

`ip-family-browser-test.js` (Playwright, VM): IPv4 only, IPv6 only and both, through the real panel. IPv6 only without
an IPv6 default route is refused; IPv4 only and IPv6 only (with a temporary IPv6 default route, removed at the end) are
measured on the listening sockets of 25, 993 and 8443, on pf's rule and from this computer over both families; both
again from the Settings card; then the console command `--ip-family`. In every step the SSH rule has no family and SSH
answers. A virtual passkey gives the recent confirmation, and is removed at the end. IPv6 only keeps IPv4 on the
loopback (since 18/11/2026: the webmail, the antispam milter and the sending limits talk to Postfix and Dovecot on
127.0.0.1, and with `inet_protocols = ipv6` and `listen = ::` they could not): there an IPv6 socket must listen, IPv4
ones may stay, from this computer IPv4 must not answer (pf), and on the server 127.0.0.1:993 and :587 must.

`address-guide-browser-test.js` (Playwright, VM): the Settings card "Server addresses" (ServerAddresses, AddressGuide)
through the real panel. The table with a row per family in words, the three goals, exactly one step "now"; goal IPv6
only starts with the IPv6 address and its form (no provider suggestion on the VM); a documentation address is refused
before anything changes; a benchmarking address (2001:2::/48, global in form, never routed) is added live, the probe
cannot reach the internet over IPv6, and everything goes back: the interface, the routes and /etc/rc.conf exactly as
before, the operation's log on disk saying so. Goals IPv4 only and both, only looking; the console `--addresses show`
and its usage. A virtual passkey gives the recent confirmation, and is removed at the end.

**MetadataRootOnlyTest** — the provider's metadata service (169.254.169.254) only for root, on the VM's live pf after
the panel has started (PfPolicy.METADATA_RULE, `-De2e.vm=yes` as root): the live rules block TCP and UDP to it for every
user but root (`user != 0`, with `return`); as www a connection is refused at once (under 2 s: on a socket of the
machine itself a block with `return` shows up as "Permission denied"); as root pf does not
refuse it (the VM has no metadata service: a timeout); another link-local address stays free. On the real server, on
18/11/2026, the service handed out to any local user the configuration the server was created with, an initial root
password included. On the live pf of the release before the rule it fails (www waits 4 s, no rule).

**ServerAddressesTest** — the server's addresses (ServerAddresses): ifconfig and netstat read (only global IPv6 counts,
not link-local, local fd00::/8 or tentative), Hetzner's network configuration read for the IPv6 suggestion, the short
form of RFC 5952, the checks of what is typed (an address with other characters never reaches a command). On a
simulated FreeBSD that answers every command as FreeBSD 15 does: adding IPv6 runs `-ifdisabled`, the alias, waits for
DAD, the route with the interface, and writes rc.conf only after the probe, keeping the previous lines (state file
0600, a copy of rc.conf beside it); a failing probe, a duplicated address and a refused route leave nothing behind;
removing puts the previous rc.conf lines back; the IPv4 clean-up refuses while IPv4 still reaches the internet or IPv6
does not. In the sources: never `netif` or `routing` (they remove every address or route of both families), never
pkill, never sh -c, never sshd. On the VM, as root (`-De2e.vm=yes`): the real ifconfig and route with a documentation
address and a forced probe, rc.conf a copy: added, removed, the interface and the routes exactly as before; a failing
probe leaves nothing.

**AddressGuideTest** — the guide's steps (AddressGuide), pure: towards IPv4 and IPv6 from IPv4 only, one step at a time
(the reverse DNS is the administrator's, the rest the panel's); mail moves to IPv6 only with the IPv6 reverse DNS;
towards IPv4 only (web names, mail, the AAAA record, then the address, never while the panel is reached over IPv6);
towards IPv6 only (web names, mail only from IPv6, the A record, the provider only from IPv6 and with SSH on IPv6, the
leftovers); a server born with IPv6 only, and back to both.

**ReverseDnsTest** — the reverse DNS of an IPv4 or IPv6 address confirmed forward (ReverseDns) with a fake dig: the
PTR must give the mail name and the name point back, with A for IPv4 and AAAA for IPv6 (the check before always used
A); another name, none, one that does not point back, dig's own error lines, bad input. The guide's reverse DNS step
is done when the PTR gives the name (the AAAA comes after). FreshDns: the question goes to the zone's own servers (SOA,
NS, no recursion), the second when the first does not answer, the server's resolver only when none does, no odd
server name reaches dig. HostRecords: the names it accepts and the records of the same name and type.

`geo-ipv6-browser-test.js` (Playwright, VM): blocking by country over IPv4 and IPv6. A country is synced (its file must
have both lists), this computer's IPv6 /64 is added to that file, then blacklist and whitelist are applied through the
Firewall API: the pf table must have IPv4 and IPv6 entries, the rule no family, and from this computer 993 must close
over the family the mode blocks and stay open over the other. SSH always answers (the country rules cover only the mail
ports). At the end the firewall state file goes back as it was, the panel restarts on it, the anchor is emptied and the
country folder removed if the run created it.

## In the browser

The pages generated by the panel in Chromium, with Playwright and the simulated server.
PageGenerator writes them complete as the server sends them, with the frame and the texts:
name.html in Italian and name.en.html in English, plus the scripts' dictionaries in i18n/ (to serve
as /i18n/it.js and /i18n/en.js). Since 07/11/2026 (reperto 178) the pages have no inline scripts
or styles any more: they are files in assets/ (to serve as /assets/...), and csp.txt is the panel's
Content-Security-Policy. Every test serves them and sends the policy with `tests/browser-csp.js`,
and a violation is a page error.

**What runs where.** PageGenerator and the Java tests run on the FreeBSD test machine
(192.168.1.20), never on the Mac; on the Mac only the browser: the pages generated on the VM are
copied to the Mac, and the browser tests run there (also with the installed Chrome,
`CHROMIUM=".../Google Chrome"`, and only the Playwright package, without its Chromium):

    D=$(mktemp -d)
    javac -cp target/daemoxcp-mail.jar -d tests tests/org/daemoxcp/mail/content/PageGenerator.java
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.content.PageGenerator $D
    NODE_PATH=$(npm root -g) node tests/address-conversion-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/software-versions-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/pkg-branch-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/layout-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/queue-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/limits-statistics-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/english-pages-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/packages-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/way-back-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/csp-browser-test.js $D
    NODE_PATH=$(npm root -g) node tests/home-panel-browser-test.js $D [screenshot-folder]
    NODE_PATH=$(npm root -g) node tests/update-center-browser-test.js $D [screenshot-folder]

On the Mac the Playwright package is enough, without its Chromium: with `CHROMIUM` the tests use
the installed Chrome (all of them read it since 07/11/2026, reperto 177). The package can be kept
outside the project:

    mkdir -p $PW && (cd $PW && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --ignore-scripts playwright)
    CHROMIUM="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" NODE_PATH=$PW/node_modules \
        node tests/way-back-browser-test.js $D [screenshot-folder]

The passwordless login instead runs on the real server (LoginE2EServer), with the test MySQL, and
Chromium with a virtual authenticator. The server starts from an empty folder with the jar inside:

    D=$(mktemp -d) && cp target/daemoxcp-mail.jar $D/
    MYSQL="$P" NODE_PATH=$(npm root -g) node tests/login-browser-test.js $D [screenshot-folder]

With the server on the test machine and the browser on the Mac (the way it must be done): a folder
on the VM with the jar, the tests compiled on the VM, the test MySQL running there, the clone's
panel service stopped (the test uses its port 2096, the only one the VM's firewall lets through):

    REMOTE=root@192.168.1.20 REMOTE_KEY=~/.ssh/freebsd_test_vm PORT=2096 TESTS_CLASSES=/var/tmp/csp/tc \
    MYSQL="$P" NODE_PATH=... node tests/login-browser-test.js /var/tmp/csp/login [screenshot-folder]

## What they test

**MtaStsTest** — `split()`, that is how the domains end up in the plan's steps, and the reading of
the `_mta-sts` record. It covers the case of domain-d.test (no record, a proxied wildcard answers) and
the case of a record that is both wrong and proxied. The reading decides from the status of the DNS
answer: with NOERROR the v=STSv1 records are counted (none is ABSENT, one is PRESENT, more than one
is TOO_MANY); NXDOMAIN is ABSENT; an error (SERVFAIL, REFUSED) or no answer is NOT_ASKED, with the
reason the plan writes next to the domain. It is tested in two ways:
- `parseTxt()` with real `dig` outputs, recorded on 2/10/2026 (published record, SERVFAIL of
  dnssec-failed.org, NXDOMAIN, name without TXT, DNS not answering), plus variants built on those
  (split record, next to other TXT records, behind a CNAME, REFUSED, two v=STSv1 records in various
  forms). It holds anywhere, even without a network;
- `readTxt()` on the real DNS. If `dig` reaches a DNS from here the real facts are required: on
  domain-d.test the record is there, a nonexistent name does not have it, and if the resolver
  validates DNSSEC the SERVFAIL of dnssec-failed.org is NOT_ASKED. If it does not reach one (`dig`
  missing or network closed) NOT_ASKED is required, never a made-up ABSENT.
Before, the reading used `dig +short`, which for a SERVFAIL prints nothing, as for a name without a
record: the plan read "absent" and proposed publishing a record that might already be there.
Against that version the test fails in five points. And before that the test took the DNS for
granted and failed on every machine that did not have it.
It also tests `testAndTxtSteps()`, where the record's step becomes "done": with two v=STSv1 records
it must not, because for senders two records count as zero (RFC 8461 §3.1). Before, the reading
took the first record: if it was the right one, the step came out done.

**MtaStsRecordTest** — the `_mta-sts` record from Cloudflare's side and the DNS page's, without a
network. The common rule (`DnsRules.eMtaSts`: it counts every record that at least one real sender
counts, even written in uppercase). The writing, `AutoDns.alignMtaStsTxt()`, against a fake
Cloudflare with the zone in memory: it creates, leaves alone, updates, and with several records it
leaves only one, the right one, without touching the other TXT records; with Cloudflare refusing a
deletion or an update it says so; if the first reading of the zone comes back empty because of an
error, the final re-reading notices the two records. The DNS page's MTA-STS line, `mtaStsCheck()`:
two records are never green, a SERVFAIL is not "Not active". At the end it puts the writing of
before in front of the two records, one already right: it said "unchanged" and left both, and the
test sees it.

**PackageCatalogTest** — how old the package catalog is (`PkgCatalog`). Home and the report said
"age unknown" because they looked at `/var/db/pkg/repo-FreeBSD.sqlite`: the name used by old pkg
versions and by the "FreeBSD" repository before FreeBSD 15. Today the catalog of every repository is
`$PKG_DBDIR/repos/<name>/db`, and pkg gives it the publication date on the server (pkg's source:
`libpkg/repo/binary/common.c` and `update.c`). The test reads a `pkg -vv` output in the form of
`print_repository()` (also "yes (overridden by pkg)"), builds a pkg folder with dates of its
choosing and checks: only the enabled repositories, the oldest counts, an enabled one without a
catalog is said, without catalogs it says where it looked, all repositories disabled is not "I do
not know", the old name is still recognised, a name with `../` does not end up in a path, a clock
running behind does not give negative ages. Then the real line of the report, from `ReportMail`.

**JavaUpdateScriptTest** — the detached script that upgrades the JVM the panel runs on (reperto
195). The script is generated as the panel does and RUN, with fake pkg, sockstat, curl, ps and java
in front of the PATH, a sleeping process as the panel and another as the web part's supervisor;
the panel log, the backup folder and the pidfiles are in a temporary folder. As text, in English and
Italian: `sh -n`, no placeholder left, every variable a report line prints is set by the script
(`{VIA}` and `{backupPath}` were not), dates in UTC, download before the stop. Run: everything
works (way back, unlock and lock of every package of the plan, web part stopped, panel started
again, the port checked); the download fails and the job is cancelled with the protections back and
the panel restarted to close it; no way back; the port held by root instead of daemoxcp_mail (TO
CHECK); the new java does not start and the way back goes in. Plus the service detection (rc script
and pidfile). FreeBSD only (`stat -f`): on the VM. The same flow from the browser, on the real VM
panel, is in reperto 195.

**RestartLockTest** — the rules behind "no change while a restart is scheduled" (`RestartLock`, reperto 200): which
requests change something (`Access.changes`: a GET never; a POST unless its action only reads or its permission only
views; the DKIM reads), what stays possible (cancelling, restarting now, the state, nothing else), the time of the
restart from ps ("+N" minutes and "now"; any other form unknown), the time the panel records and that cancelling
removes it. Pure, on the VM.

**Dovecot24MoveE2ETest** — the move to Dovecot 2.4 going back by itself (reperto 213), on the VM with Dovecot 2.3, as
root with `-De2e.vm=yes`: the job runs for real (packages replaced, 2.4 configuration written, tests on 2.4), then a
problem the test adds makes it put 2.3 back. Afterwards the job is in error saying 2.3 is back and passes the tests of
before; the packages, their versions and protections are those of before; the configuration is the one of before file
by file, the refused 2.4 one kept in the copy (0700); Dovecot runs and listens where it did; the tests again on 2.3
all pass; no list of unlocked packages left.

**FreshInstallDovecotTest** — an installation from scratch puts in Dovecot 2.4 where the catalog offers it (reperto
215): the three installers use the one choice (`DovecotConfig.packagesShell`) and install `$DOVECOT_PACKAGES`, never the
2.3 names written out, and still parse with `sh -n`; the choice with a fake pkg: 2.4 offered -> 2.4, not offered ->
2.3, 2.4 already installed -> stays 2.4, always the MySQL flavor and its Pigeonhole. On the VM.

**SieveStorageTest** — users' Sieve scripts in their mail folder, the panel's rules before them (reperto 214): what
the panel writes on 2.3 and 2.4 (`sieve_before` / a `before` script from /var/mail/sieve, the users' storage in
`~/sieve`, the active script `~/dovecot.sieve` without a dot, which Maildir++ would take for a mail folder); the
migration of servers installed before (the exact block the panel wrote becomes the new one, the rest untouched; done,
hand-written or twice: nothing); a ManageSieve link made by hand under /var/mail/sieve is seen and left; the mailbox to
try `doveadm sieve list` on. On the VM.

**SieveGeneratorTest** — the panel's Sieve rules with no keep forced at the end (reperto 216): until 09/11/2026 every
script ended with an explicit `keep;`, so "move" left the message in INBOX too, a forward without a copy kept one and
"delete" deleted nothing. Rule by rule (move, copy, delete, forward with and without a copy, a filter's forward,
autoresponder, all together): the action as Sieve means it and no top-level keep; a script without rules is just the
require line. With `-De2e.vm=yes` every script also goes through the real sievec. With the forced keep put back in the
jar: 10 checks fail.

**SieveForcedKeepTest** — the boot repair of the scripts written before (reperto 216, SieveForcedKeep): a script with
either require line the panel ever wrote loses only the tail and becomes what the generator writes now; already fixed,
hand-written, another require or the tail not at the end: nothing. On a folder like /var/mail/sieve only
domain/user/.dovecot.sieve regular files, owner and mode kept, compiled once, a ManageSieve link and other depths left,
a script the compiler refuses put back, nothing the second time. With `-De2e.vm=yes` the real sievec, the binary newer
than the script.

**SieveActionsE2ETest** — the same rules with real deliveries, on the VM as root with `-De2e.vm=yes` (it creates
`sieve-actions.test` with three mailboxes in the mail database and removes it): each rule written by SieveGenerator and
saveSieveScript, a message through Postfix's sendmail, `doveadm search` for where it landed. Move: only in the folder;
copy: folder and INBOX; forward without a copy: only at the destination, with a copy: both; delete: nowhere;
autoresponder: INBOX and the reply at the sender; reject: not kept, the refusal at the sender; the mailbox's own script
saved through ManageSieve runs when the panel's rules keep the message and does not when they move it; a script written
before is fixed by SieveForcedKeep.repair and then the move moves. Measured on 09/11/2026 on Dovecot 2.3.21: 25 checks
pass; with the forced keep put back in the jar 7 fail (move, forward without a copy, delete and reject keep INBOX, the
own script runs after a move, and in the last part the faulty generator writes the keep again).

**SieveCompilerTest** — Pigeonhole's sievec run as the user `sievec`, never as root (reperto 218, SieveCompiler). Without a
system: the binary's name beside the script; the minimal configuration passed with `-c` (empty for Dovecot 2.3, the two
version lines of the panel's own 2.4 dovecot.conf, nothing that is not a version number); sievec's output read as a
refusal only when it names a line of the script (an unreadable or missing script exits 89 like a syntax error, and is
not one); the command through chroot as `sievec` with only its group; an environment with nothing of root's; the user
accepted only as the panel creates it. With `-De2e.vm=yes`, as root: a panel script compiles, its binary is installed
beside it with the script's owner, group and mode, strictly newer, byte for byte what root's sievec makes with Dovecot's
real configuration; a script with an error is refused and the binary of before stays; an unreadable script, a folder
others can write and a link are not compiled and nothing is installed; validate() agrees with root's sievec on three
texts; no working folder is left in /tmp. It tests SieveCompiler itself, so it passes with or without the change in
SieveGenerator.

**SieveCompilerE2ETest** — the same through the panel's own entry points (SieveGenerator.saveSieveScript, compileScript,
validateScript), with real deliveries and the kernel's process accounting on (on the VM as root with `-De2e.vm=yes`; it
creates `sieve-compile.test` with two mailboxes, removes it, and turns accounting on into a file of its own only if it was
off). The binary has the script's owner, group and mode and is newer; a delivery lands where the rule says; with the
script changed and its time put before the binary's the delivery follows the binary, so Dovecot runs the precompiled one;
no Sieve error in the maillog, while a delivery with the binary taken away logs "save: failed to create temporary file
... Permission denied (euid=5000(vmail)" (the check can fail); validateScript refuses at the right line; vmail can touch
neither the script nor the binary nor add a file beside them; `lastcomm` says every sievec ran as `sievec`. Measured on
10/11/2026 on Dovecot 2.3.21: all pass; with SieveGenerator put back as it was (sievec as root) 2 fail: "sievec ran 5
times, as [root]".

**SieveFolderOwnerTest** — the folder of the panel's Sieve rules, `/var/mail/sieve`, stays root's (reperto 220). Until
10/11/2026 the Dovecot component's script (DovecotScript) gave it to vmail with `chown -R vmail:vmail`: vmail could then
rename a domain's folder of root's and make its own in its place, with rules of its own. Without a system: every command
of the script that touches `/var/mail/sieve` gives it to root and no write to group or others (and the checks can
fail). With `-De2e.vm=yes`, as root: the script's own commands run for real on a bench folder under a parent made like
`/var/mail` (root:mail 0775), never on the real one; on no folder they make it and `global` root:mail 0755 and vmail
creates nothing; on a folder the old script gave to vmail (first vmail renames a domain's folder: the probe works) they
leave everything root:mail with no write for group or others, follow no link vmail made, and vmail can rename, rewrite
or add nothing while it still reads the rules. Then the real `/var/mail/sieve` with `sieve-owner.test` (created and
removed): a rule saved by the panel moves a message, vmail can rename neither the domain's folder nor the mailbox's nor
the rule or its binary, nor rewrite them or add a folder, and the next delivery still follows the rule. Measured on
10/11/2026 on Dovecot 2.3.21: all pass; with DovecotScript put back as it was 12 fail (parts 1 and 2; part 3 measures
the real folder, which the panel makes root's, and passes on both). The script itself runs on no path today: the route
`/api/install` is gone since the first commit and `install_dovecot.sh` is retired (InstallScripts.RETIRED).

**SieveGroupMailTest** — the panel's Sieve rules out of reach of the group `mail` (reperto 221). `/var/mail` is
root:mail 0775: a process with the group `mail` (postfix, clamav, dma which is setgid mail, Dovecot's mail processes
through `mail_privileged_group`) could rename `/var/mail/sieve` and put its own in its place, and `saveSieveScript`
wrote as root following links. Without a system: the sticky mode; the line `mail_privileged_group = mail` taken out of
dovecot.conf only when it is exactly the panel's, the result being what the installer writes now (2.3 and 2.4); mbox,
/etc/group and `procstat -s` read right. With `-De2e.vm=yes`, as root: on bench folders RootOnlyPath refuses links,
folders of others and folders others can write (above the last one only with the sticky bit), and a write over a
planted link leaves the file it points to alone; in a spool made like `/var/mail` a process with the group mail renames
root's rules folder (the probe works) and after MailSpoolSticky it cannot, while it still makes and removes a lock file
of its own. Then the real system with `sieve-group-mail.test` (created and removed): MailSpoolSticky on the real
`/var/mail` (the probe renames a root folder of its own there, never `/var/mail/sieve`); DovecotPrivilegedGroup on the
real dovecot.conf, an imap of the mailbox (`doveadm exec imap -u`) with SVGID 6 before and 5000 after; a rule saved by
the panel moves a real delivery; a link planted at the rule's and at the binary's place: saving again leaves both files
(nobody's, 0600) as they were, the rule is root's again, the next delivery still follows it. At the end dovecot.conf
and the mode of `/var/mail` go back as they were. Measured on 10/11/2026 on Dovecot 2.3.21: all pass; with the three
fixes taken out (saveSieveScript as before, no sticky, the line kept in DovecotConfig and dovecot.conf) 20 fail.
Since this reperto root writes rules only under a sticky `/var/mail`, as the panel leaves it at boot: SieveActionsE2ETest,
SieveCompilerE2ETest and SieveFolderOwnerTest give `/var/mail` that state in their setUp (MailSpoolSticky) and put its
mode back at the end.

**SieveRulesNotWrittenTest** — the page is told when the panel's Sieve rules were not written (reperto 223).
`saveSieveScript` returns false when it writes nothing (since reperto 221 also while a folder from / to
`/var/mail/sieve` can be changed by others, `/var/mail` without the sticky bit for one), and its callers dropped it: the
page said "done" while Dovecot kept the earlier rules. On the real server over HTTPS, with the test MySQL and a
SieveGenerator that refuses or accepts on request: forwarding (create, update, delete), filters (create, update,
delete), auto-reply and alias to mailbox of an address that left filters behind. Refused: success false, saved true,
`server.sieve.notWritten` (English, and Italian once; for the alias `server.convert.oldFiltersKept` after the usual
message), the change still in the database; accepted: success true and nothing else; the generator gets the address and
the rules of the database as it is now. Run it as an unprivileged user (`nobody`), with the jar and the tests in a folder
it cannot write: the conversion runs the panel's mail configuration script, which then cannot even be written; as root
the alias part is skipped, saying so (otherwise folders in `/var/vmail` and Postfix and Dovecot reloaded). As nobody the
test gives the vault a public key of its own in its temporary secrets folder, as root writes it for the web part.
Measured on 10/11/2026 on the VM: 36 OK; with SSLMailServer as before 8 fail, one for each place that saves rules.

**SieveRulesRefreshTest** — a Sieve filter that moves or copies to a folder that is not there yet creates it (reperto
229), and the panel's rules already written are written again from the database at start, where they differ from what
the panel writes now. Before, «Move» to a new folder (also the dialog's own suggestion, INBOX.Filtered) moved nothing:
Dovecot answered «Mailbox doesn't exist» and the message stayed in INBOX (seen on the real server and on the VM). The
generator writes `fileinto :create` (require "mailbox"); SieveForcedKeep still recognises the require line of before.
With a fake store of rule files and the real generator: a file of before written again once and the second run writes
nothing; today's text, a script written by hand and a mailbox without rules or file untouched; a missing file with
rules in the database written; a refused write counted by the mailbox's number. On the VM SieveActionsE2ETest case 9
does it with real deliveries: the text of before leaves the message in INBOX and makes no folder, the refresh writes
it again (compiled by sievec), then the folder is made and the message is only there; a copy too.

**SieveBinariesTest** — the panel's Sieve rules compiled by the Pigeonhole installed now (reperto 241). After the move
to Dovecot 2.4 the binaries next to the panel's rules were still 2.3's (header version 02 against 03): Dovecot compiled
the rules again at every message and logged two errors each time («binary ... save: failed to create temporary file»,
«The LDA Sieve plugin does not have permission to save global Sieve script binaries»), and neither the move nor the
panel's start noticed, because the text of the rules had not changed. With a fake compiler: every rule compiled, the
binary replaced only where it differs and kept where it is the same, so the second start writes nothing; a rule that
does not compile counted by its status, never by its path; rules that cannot be listed: nothing compiled. On a folder
made by the test: only domain/name/.dovecot.sieve starting with the panel's require lines, never through a link to a
folder or a file, never a file too big. On the VM the move to Dovecot 2.4 from the page and upgrade-panel.sh do it with
real deliveries: no Sieve error in the maillog after the move, and the binaries compiled again once.

**DovecotMasterUserTest** — Dovecot's master user, the one «Open webmail» logs in with, gets a real hash (reperto 227).
FullMailServerScript asked `doveadm pw` for the hash before dovecot.conf existed: doveadm exited with 75 and
master-users stayed "admin:" without a hash, so the single sign-on never got in on a fresh installation;
FullMailStackScript wrote the hash in a root:wheel file that Dovecot's auth process (user dovecot) cannot read. The
three scripts now share one piece (`DovecotMasterUser.shell`: `doveadm -O pw` with the password on standard input,
the hash checked with `doveadm pw -t` against the key, the file root:dovecot 640), and `DovecotMasterUser.ensureAtBoot`
repairs servers installed before: only the two shapes those scripts left, with the key next to them, checked with a
real `doveadm auth test mailbox*admin` (or `doveadm pw -t` when there is no mailbox), and put back as it was otherwise.
The repair on real files with real owners and a fake Dovecot that reads like the real one, a planted fault for every
step (nothing changes, or the file goes back byte for byte with owner and mode); files that are not the scripts' left
alone (a hand-written {PLAIN}, two users, a comment, a link, another key's hash); the shell piece run with the real
doveadm, also without a configuration, where main's piece of before leaves "admin:" without a hash. As root on the VM.

**FullMailStackCleanupTest** — the cleanup of the «all» installation (FullMailStackScript, phase 1) removes only the
users phase 2 creates again (reperto 226). It used to run pw userdel on www, a base system user (uid 80), and on the
users of clamav, redis, mysql and rspamd: with www went its group, the one nginx opens Roundcube's socket with, and its
crontab, and nothing created them again (nginx locked by the panel, or the later pkg install failing), so nginx said
getpwnam("www") failed. The test reads the script's text (every user and group removed is created again by phase 2 and
none is of the base system, with the line recogniser tried first on a known text) and runs the cleanup's pw lines with
pw -R on a copy of the stock users plus the users of the packages and vmail: www, its group and the users of the packages stay, exactly
what the lines name goes away, the machine's own files unchanged. As root on the VM.

**SieveRulesOwnerTest** — the panel's Sieve rules folder given back to root at start (reperto 225). On the real server
`/var/mail/sieve` belonged to vmail (the installation of 11/10/2026): since reperto 221 root does not write rules where
somebody else can change the path, so the first start of the new panel stopped (MailSpoolSticky warned, SieveForcedKeep
left the rules as they were) and every save for those mailboxes would have answered "not written". In a test folder
under /var/tmp, as root, with real owners (vmail, nobody): the real server's layout copied (owners, groups, modes):
folders and rule files root's after (0755, 0644), readable by vmail and no longer writable by it, root:vmail files,
Dovecot's log and every content as they were, RootOnlyPath accepting the mailbox folders, a second run with nothing to
do; a link, a hard link to a root-only file of the same disk, a file of nobody, a FIFO, a spool that is not root's:
nothing changed at all and the reason given; a root folder others can write loses only that write; a rule file with
the system immutable flag half way: every entry back as it was. Measured on 10/11/2026 on the VM: 34 OK; with the
checks taken out 9 fail, with the rollback taken out 1. And the upgrade with `upgrade-panel.sh` from main's jar of
before on a clone with the real server's owners: with the jar of main 92931d1 it stops at the first start (the same
three warnings), with this one six migrations and SieveRulesOwner say DONE, the second start is quiet, and
mail-login-probe.sh, SieveActionsE2ETest and sieve-dialogs-browser-test.js on the real panel pass.

**SieveDialogFieldsTest** — the Sieve dialogs of the Mailboxes page and their routes speak the same language
(reperto 224). The Filters dialog sent conditions and actions as JSON text, which `/api/sieve` reads with optJSONArray
(null for a text): creating a filter ended in a NullPointerException whose English text reached the page. Editing asked
`GET /api/sieve?id=`, which the route did not know, and sent `id` where it reads `filter_id`; deleting a forward sent
`id` where `/api/forwarding` reads `rule_id`, and no `mailbox_id`. And the routes rewrote the rules of the mailbox named
by the request, not of the row they changed. On the real server over HTTPS, with the test MySQL and a SieveGenerator that
writes nothing and remembers the address it was asked for, the requests as the fixed page sends them: a filter created
(enabled or not, as the dialog says), read back by `?id=` with conditions and actions as arrays, changed by `filter_id`
alone, deleted; a forward deleted by `rule_id` alone; each time the rules written are those of the row's mailbox, also
when the request names another one. Conditions or actions as text, empty, or not objects: refused with
`server.filter.badRules` (English and Italian), nothing changed; a number that is not a row: `server.filter.notFound` /
`server.forward.notFound`; `mailbox_id=abc` gives no exception text. Reperto 223 still holds (success false, saved,
`server.sieve.notWritten`). It uses only what MailDatabase had before, so it runs against the jar of before too. Run it
as nobody, as SieveRulesNotWrittenTest. Measured on 10/11/2026 on the VM: 43 OK; with SSLMailServer, MailDatabase and
SqlCatalog as before 25 fail (among them the NullPointerException text and `For input string: "abc"` in the answer).

**VacationTrackingTest** — "reset tracking" of the autoresponder and the boot repair of what it left (reperto 219,
VacationTracking). Until 10/11/2026 the reset also deleted the binary beside the panel's rules and restarted Dovecot;
Pigeonhole keeps the senders already answered only in `.dovecot.lda-dupes` in the mailbox's home. Without a system:
the file is vmail/domain/user/home/.dovecot.lda-dupes (Dovecot's home since reperto 217), and an address that is not one
(`../../x@...`, `a/b@...`, `al..ice@...`) gives nothing; on a folder like /var/vmail only that file goes, with the one of
before in the mailbox's root (mail, the `.locks` folder and other mailboxes stay,
twice is fine, nothing outside the folder is touched); a binary missing, older, as old as the script or a link is stale;
on a folder like /var/mail/sieve the boot repair compiles only the panel's scripts without a newer binary, once, leaves a
ManageSieve link and other depths, reports a compiler that fails or installs nothing, and finds nothing the second
time. On the VM, as any user. Measured on 10/11/2026: all pass; with the old reset and no boot repair in the jar 11 fail.

**VacationTrackingE2ETest** — the same with real deliveries (on the VM as root with `-De2e.vm=yes`; it creates
`vacation-reset.test` with two mailboxes and removes it): the autoresponder answers a sender once, the reset removes the
memory and nothing else (the binary untouched and newer than the script, Dovecot's master process the same), the sender
gets the reply again and then not again, with no Sieve error in the maillog; with the binary taken away a delivery logs
"save: failed to create temporary file ... Permission denied (euid=5000(vmail)" (the check can fail), ensureAtBoot
compiles it again with the script's owner, group and mode, and the next delivery is quiet. An IMAP session is no proof
of the restart: on Dovecot 2.3.21 one logged in before outlived `service dovecot restart`. Measured on 10/11/2026: all
pass; with the old reset and no boot repair in the jar 9 fail: the binary gone, Dovecot's master process another one,
"Error: sieve: binary ... save: failed" and "The LDA Sieve plugin does not have permission to save global Sieve script
binaries" on the deliveries after the reset, and no repair at boot.

**LmtpSocketTest** — Postfix delivers to Dovecot through a socket in its own queue, `private/dovecot-lmtp`, 0600
postfix's, and no longer through port 24 or the 0666 socket in /var/run/dovecot, from which any process of the machine
could deliver into any mailbox, bypassing Postfix and rspamd (reperto 234; Dovecot's "Postfix and Dovecot LMTP" guide,
2.3 and 2.4). Against a fake Postfix and a fake Dovecot that listens where its configuration says: what the panel writes
now (2.3 and 2.4, no TCP listener, last_valid_uid/gid 5000, the installers' transport); the move from the block of
before in three steps (socket opened beside port 24, Postfix moved, port 24 closed), DONE then nothing; a block that is
not the panel's or Postfix delivering elsewhere: left alone; a fault in the first two steps: everything back, mail
flowing on port 24; a fault in the last: the middle state, which works both ways, finished by the next run; killed
after each step: the next run finishes. A reload that takes effect a few seconds late, as Dovecot's does (reperto
240): the run waits for port 24 to close and for the probe to answer, and ends DONE instead of INCOMPLETE; listeners
that never come within the wait still put everything back. No system.

**LmtpSocketE2ETest** — the same on the VM's real Dovecot and Postfix (as root, `-De2e.vm=yes`, from the block of
before): `nobody` is greeted on /var/run/dovecot/lmtp before (the fault) and on neither socket after; the socket is
postfix's 0600, port 24 closed, /var/run/dovecot/lmtp root's 0600, last_valid_uid/gid in doveconf; a real delivery
through Postfix arrives through the socket; back to before, then Postfix refusing the transport: ROLLED_BACK, port 24
again and a delivery still arrives; the move again. Measured on 16/11/2026 on Dovecot 2.3.21: all OK, and
mail-login-probe.sh passes afterwards.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.LmtpSocketTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.LmtpSocketE2ETest   (VM, as root, real deliveries)

**RedisSocketTest** — redis only on its Unix socket, `/var/run/redis/redis.sock`, 0770 of the group redis, with rspamd
in that group (reperto 235). The package's redis.conf listens on 127.0.0.1:6379 and ::1 without a password: any process
of the machine read and wrote rspamd's data (Bayes, greylist, limits, history). Against a fake redis that listens where
its redis.conf says (the last line wins) and a fake rspamd that reaches it only if started in the group and pointed at
the socket: what the installer writes (RedisSocket.FINAL, rspamd in the group before both start); the move from the
package's file in three steps (socket beside the port, rspamd moved, port closed), DONE then nothing; another port, a
socket already there, an include, rspamd pointed elsewhere: left alone; a fault in the first two steps (no socket, the
group not taken, rspamd not on the socket, redis restarted empty): everything back byte for byte; a fault in the last:
the middle state, finished by the next run. And `socketClients` on real `CLIENT LIST` lines: each line has `laddr=` too,
and counting the text `addr=...` made the asker's own connection count twice, so the check passed with rspamd refused
(found by RspamdBackendsE2ETest's fault on the real redis, 16/11/2026). No system.

**ClamdSocketTest** — clamd's socket only for the group clamav, 0660, with rspamd in that group (reperto 237; the
package's clamd.conf leaves it 0666, "socket is world accessible"). The installer's lines; the move from the VM's
clamd.conf (LocalSocket twice), DONE then nothing; a group or mode already set, another socket: left alone; rspamd not
really in the group, clamd not coming back, rspamd not scanning after joining: everything back. The EICAR probe is the
real test string with 1 to 40 random trailing blanks: rspamd caches the antivirus result per attachment (measured on the
VM: the same attachment a second time never reaches clamd), so a fixed probe would pass with clamd unreachable. The
class file does not carry the string in clear. No system.

**RspamdControllerTest** — rspamd's controller (11334) only with the panel's password (reperto 236). The package's
worker-controller.inc has `password = "q1"` in clear and `secure_ip` 127.0.0.1 and ::1: any local process got in with no
password. The panel writes override.d/worker-controller.inc (the hash of a generated password, kept in root's secrets,
in password and enable_password; `secure_ip = []`). Against a fake controller: DONE then nothing; a file the panel did
not write, the admin's own password or secure_ip in local.d (override.d would silently win), the controller down,
rspamadm giving no hash: nothing written; configtest refusing, the reload not taken, the file not writable: the file
gone and the old secret back. No system.

**RspamdBackendsE2ETest** — the three on the VM's real redis, clamd and rspamd (as root, `-De2e.vm=yes`, from an
installation of before): `nobody` gets PONG from redis and VERSION from clamd, and the controller answers 200 with no
password, before; after, `nobody` is refused by both, port 6379 is closed, the update's data check still reads redis,
root still asks clamd its version, rspamd finds a never-seen EICAR and clamd's log shows the scan, the controller
answers 401 without the password (also with q1) and 200 with it, and the panel's RspamdManager reads the statistics.
Then each fault from the state of before on the real services (rspamd not really in the group, for redis and for clamd;
configtest refusing; rspamd not reloaded): ROLLED_BACK and the service as before; the admin's secure_ip in local.d:
left alone. Measured on 16/11/2026 (redis 8.10.3, ClamAV 1.5.4, rspamd 4.1.0).

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RedisSocketTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ClamdSocketTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RspamdControllerTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RspamdBackendsE2ETest   (VM, as root)

**PhpHardeningTest** — php.ini written when it is missing, and `security.limit_extensions = .php` in the panel's
Roundcube pool (reperto 238). The real server had no php.ini (installed before the installer wrote one): PHP ran on its
built-in defaults, `expose_php` On and "X-Powered-By: PHP/8.4" in every webmail answer, errors to the output, sessions
in /tmp. The text is PhpHardening.INI, the installer's own, plus `session.upload_progress.enabled = Off`. Against a fake
php-fpm that sends X-Powered-By until it has read a php.ini: DONE (the file, the sessions folder, the log and its
rotation, the pool), then nothing; a php.ini already there or a pool the panel did not write: untouched; no webmail
site or the webmail down: nothing written; php-fpm -t refusing, the webmail down after the reload, php-fpm not reading
the file, a file not writable: everything back. No system.

**RoundcubeCipherTest** — Roundcube encrypts the IMAP password in its session with AES-256-CBC and a 32-character key,
no longer DES-EDE3-CBC ("for backward compatibility", says defaults.inc.php, which calls AES-256-CBC "a better choice")
(reperto 239). Only the installer's des_key line is replaced, only if cipher_method is not set; before and after, the
webmail answers, PHP encrypts and decrypts with the file's method and key, and a real login through the panel's SSO
(RoundcubeDbUser.realLogin, which now also wants the folder list) opens the mailbox. No system.

**PhpRoundcubeE2ETest** — the two on the VM's real PHP 8.4, php-fpm, nginx and Roundcube 1.7.5 (as root,
`-De2e.vm=yes`, `-De2e.probe=` the path of mail-login-probe.sh): php.ini taken away as on the real server, X-Powered-By
appears; PhpHardening: DONE, X-Powered-By gone, the pool with the limit and still running as roundcube; php-fpm -t
refusing: ROLLED_BACK and X-Powered-By again. Roundcube: the probe's real webmail login before (DES), RoundcubeCipher
DONE, the real login after (AES-256-CBC, folders from IMAP); PHP refusing the cipher: config.inc.php byte for byte.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PhpHardeningTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RoundcubeCipherTest
    java -De2e.vm=yes -De2e.probe=tests/mail-login-probe.sh -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PhpRoundcubeE2ETest   (VM, as root)

**DovecotHomeTest** — every mailbox's Dovecot home in its own folder, `home/`, not the mail root (reperto 217): with
home = the Maildir root, the files Dovecot keeps in the home showed up as mail folders ("dovecot", "dovecot.lda-dupes",
"dovecot.lda-dupes.locks" after one autoreply, measured on the VM; Dovecot's documentation says the home should not be
the Maildir, and lists "home under mail" among its layouts). What the panel writes on 2.3 and 2.4 (the home in `home/`,
the mail where it was); the migration of the configuration (the home the panel wrote gets `/home`, the rest untouched;
done, hand-written or twice: nothing); the script vmail runs on the files, on a folder like /var/vmail: prepare copies,
undo takes the copies away, finish moves what is left in the root and removes the false folder unless it holds mail,
never chooses between two different user scripts, never goes through a link, a second run does nothing. On the VM;
with the fix taken out it fails.

**ManageSieveLocalTest** — ManageSieve (4190) only on 127.0.0.1, where the webmail uses it (`ManageSieveLocal`): found
installing from the README on a clean VM, Dovecot listened on `*:4190` even after the panel's first start. The file
for 2.3 (`address`) and 2.4 (`listen`), the version read from `dovecot --version`, sockstat read and «only local» only
when every address is 127.0.0.1, and the installer writing the same file (2.4 file list, 2.3 shell fragment).

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ManageSieveLocalTest

**UnusedMaildirTest** — the empty `Maildir/` folders the mailbox script used to create, which Dovecot never used,
removed at boot (`UnusedMaildir`, with rmdir as vmail). Nothing when Dovecot keeps the mail in a folder named Maildir;
the script run for real on a throwaway tree: an empty one goes, one with a message or an extra folder stays untouched,
links are not followed, a second run finds nothing; the mailbox script now creates the mail in the mailbox's own folder
and the home.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.UnusedMaildirTest

**SpecialFoldersTest** — the special folders and spam in Junk (`SpecialFolders`): found on the VM installed from the
README, mail that Rspamd marked (`X-Spam: Yes`) stayed in INBOX, and with the vacation reply on, a spam message got its
reply (backscatter towards a forged sender); Dovecot had no namespace, so no special-use folders (RFC 6154). The
conf.d file for 2.4 and 2.3 (Drafts, Sent, Trash and Junk with special_use and auto = subscribe; the spam script first:
precedence 1 on 2.4, sieve_before with the panel's rules moved to sieve_before2 on 2.3), the Sieve script, the pure
helpers, and the installer writing the same files. With `-De2e.vm=yes`, as root on the VM: Dovecot reads the script,
it is precompiled, IMAP shows the four folders with their flags, and over LMTP with a vacation rule of the panel's spam
goes to Junk with no reply while ordinary mail goes to INBOX with its reply; test mail and rule removed afterwards.
Measured 20/11/2026 on Dovecot 2.4.5: all OK; with the conf.d file taken out 11 checks fail. The 2.3 file was checked
with the real 2.3.21 doveconf and sieve-test in a separate root.

    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SpecialFoldersTest

**SenderLoginMapTest** — a client that signs in sends only from its own addresses (`SenderLoginMap`): found on the VM
installed from the README, Postfix had no `smtpd_sender_login_maps`, so a mailbox could send as another mailbox of the
server (signed with the domain's DKIM key) or as anybody. The decision (the installer's settings are applied, ours
with the file current is nothing, settings written by hand are left alone), the table (a mailbox owns its address even
when it does not receive, an alias belongs to its destination), the map file with the aliases map's connection, the
installer, MailDbUsers keeping the file and running its query, and the order at boot. Since 21/11/2026 the check is on
the submission ports only (`-o smtpd_sender_restrictions` on 587 and 465 in master.cf), not in main.cf: port 25 has no
AUTH, and there Postfix logged «restriction `reject_authenticated_sender_login_mismatch' ignored: no SASL support» for
every incoming message (the real server, after build 816); a server with the check in main.cf gets it moved. With
`-De2e.vm=yes`, as root on the VM: the settings in main.cf and master.cf; postmap answers a mailbox with itself; with
XCLIENT LOGIN on port 587 and on port 465 (allowed from 127.0.0.1 only for the test, then removed) the mailbox's own
address is accepted, another address of the domain and an outside one get `553 5.7.1 … not owned by user`; on port 25
without a login the same sender is accepted, with no «no SASL support» line in the mail log. Nothing is delivered.
Measured 20/11/2026: all OK; with the check taken out of `smtpd_sender_restrictions` the refusals fail.

    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SenderLoginMapTest

**HeaderFromCheckTest** — a client that signs in writes in the `From:` header only its own sender address
(`HeaderFromCheck`): with `SenderLoginMap` the envelope was checked, but on the VM a mailbox signed in on port 587 with its
own envelope and `From: boss@` of the same domain went through, signed with the domain's DKIM key. The decision (only
on the panel's milter Rspamd; a file of the same name written by hand is left alone), the Lua rule (only signed-in
clients, a prefilter that rejects; one address in one From header, the envelope or the mailbox), the installer writing
the same file, the order at boot and the verdict on the two probe scans. With `-De2e.vm=yes`, as root on the VM: rspamc
as a signed-in user (own From, capitals, an alias as envelope, an empty envelope with the mailbox pass; another
address, an outside one, an empty envelope with another address, two From headers, two addresses in one From are
rejected; mail that does not sign in is not looked at); through Postfix with XCLIENT LOGIN on port 587 the own From is
queued and another address gets `554 5.7.1` with the panel's text; on port 25 without a login the same From is not
refused for it. What gets through is delivered to the test mailbox and expunged. Measured 20/11/2026: all OK; with the
rule removed 7 checks fail, the 554 through Postfix among them.

    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.HeaderFromCheckTest

**DkimFallbackTest** — Rspamd signs only the domains that have their own DKIM key (`DkimFallback`): `try_fallback = false`
in `local.d/dkim_signing.conf`. On the real server root's nightly reports (the machine's own name, not a mail domain)
made Rspamd log «cannot load dkim key /var/db/rspamd/dkim/…» every night; on the VM installed from the README the file
did not exist and every local or signed-in message of a domain without a key did the same. The decision (only on the
panel's milter Rspamd: a missing file is written, the panel's file gets the line, `try_fallback` already set or a file
written by hand is left alone), the line right after `allow_username_mismatch` with the rest byte for byte, the
configdump reading, DkimManager and the Rspamd installer writing the line, the order at boot. With `-De2e.vm=yes`, as
root on the VM after the repair: configdump says `false`; a signed-in scan of a domain without a key is not signed and
adds no «cannot load dkim key» line to Rspamd's log; a domain given a key for a moment (then the file put back) is still
signed. Measured 21/11/2026: before the repair 2 checks red (configdump `true`, one more error line), after it all OK.

    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.DkimFallbackTest

**PostfixDaneTest** — DANE for outgoing mail (`PostfixDane`): `smtp_tls_security_level = dane` with
`smtp_dns_support_level = dnssec`; before, Postfix sent with opportunistic TLS and never checked whose certificate it
got. The decision (the installer's old values with a local validating resolver: apply; values set by hand: left
alone; no validating resolver on this machine: left as it is, and said), reading `/etc/resolv.conf` and drill's ad
flag, the installer, the order at boot. With `-De2e.vm=yes`, as root on the VM: Postfix reads dane and dnssec, the
local resolver answers the root's DNSKEY with ad, and posttls-finger with main.cf's level asks for the TLSA records of
the MX of ietf.org and posteo.de and for none of gmail.com (unsigned). Port 25 out is closed on the VM: only the DNS
part is measured. Measured 20/11/2026: all OK; with the old values (may, default) 4 checks fail, the TLSA lookups among
them. posttls-finger on its own uses dane: the test gives it main.cf's level, or it would prove nothing.

    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PostfixDaneTest

**SpamLearningTest** — Rspamd learns from the users (`SpamLearning`, `SpamLearner`): a message moved or copied into
Junk is spam, one moved out of it is ham, unless it goes to Trash; before, Rspamd learned only from rspamc run by hand.
The decision (only Dovecot 2.4 with the panel's Junk; a configuration written by hand is left alone), the
configuration, the two Sieve scripts and the program Dovecot pipes to (it only leaves the message in the spool as
vmail, and always exits 0); a round of the root part on a throwaway spool with a fake Rspamd (whole messages learned
and deleted oldest first, the ones still being written wait, empty, too big and week-old ones dropped unread, a link
removed without reading its target, a 400 dropped, Rspamd not answering or refusing the password keeps them); the
webmail's spam button (markasjunk) once in the panel's block; the order at boot. With `-De2e.vm=yes`, as root on the
VM: the configuration in place and compiled, the program's folders 0755 and the program writing as vmail; real IMAP
moves for the first mailbox: INBOX -> Junk leaves a spam message and Rspamd's «learned» counter grows when the root
part's round hands it over, Junk -> INBOX the same as ham, Junk -> Trash leaves nothing; no Sieve error in the mail
log; the test messages expunged. The VM's Bayes learns the test message (a new one each run). Measured 20/11/2026:
all OK. The first live run found that Java's HTTP client, trying h2c on plain http, reached Rspamd's controller with
no body («got zero length body»): the round now speaks HTTP/1.1.

    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SpamLearningTest

**MailboxCleanupTest** — automatic emptying of Junk and Trash per mailbox, off until asked, and the emergency
emptying from the console. The days (never, 7, 14, 30, 60, 90, the same for the panel and the webmail); MySQL (the two
columns for new installs and as a migration, the panel's update and its web-part procedure in the same order, the
procedures that read mailboxes, the grants of the routines and of Dovecot's user); Dovecot's userdb query
(`namespace/inbox/mailbox/{Junk,Trash}/mailbox_autoexpunge` only above 0, NULL otherwise, the same query MailDbUsers runs
as Dovecot's user, its first line unchanged so DovecotQuota replaces the block of before); the panel's window and what
it sends, the audit log line; the webmail's block, the plugin (the same days, the mailbox before the star of a single
sign-on, the panel's answer read strictly) and its texts; the route in every list; the emergency emptying's words,
count, plan and run. With `-De2e.vm=yes`, as root on the VM: the route as Roundcube calls it (set, get, Dovecot's
userdb, 400 and 404 refusals, back to never), the plugin's PHP read by PHP, the console refusing without a terminal,
and the emergency emptying of a test mailbox's Junk. Measured 20/11/2026: all OK; then by hand through `script(1)`,
a real terminal: a wrong number cancels and deletes nothing, the right one empties and writes `EMERGENCY_EMPTY` in
the audit log. Measured on the VM before writing it: a NULL userdb field reaches Dovecot as nothing, and the value is
applied after each session (a message older than the time goes).

    java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MailboxCleanupTest

**mailbox-cleanup-browser-test.js** — the same in the browser, on the VM through ssh tunnels: a mailbox of this run,
never by default; in the panel's window the two choices with labels and help, Junk 30 and Trash 14 saved, opened again,
Dovecot's userdb 30d and 14d; in the webmail the spam button, Preferences with «Automatic emptying» showing 30 and 14,
Junk 7 and Trash never saved, the panel reading 7 and 0, Dovecot 7d and nothing for Trash; no script errors; everything
removed. Measured 20/11/2026: all OK.

    HOST=<panel name> WEBMAIL=<webmail name> CHROMIUM=<chrome> REMOTE=root@<test machine> REMOTE_KEY=<key> \
      NODE_PATH=<playwright> node tests/mailbox-cleanup-browser-test.js

**WebPartWaitTest** — the root part waits for the web part (`PanelSeparation.waitForWeb`): on the VM, once over many
starts, the root part read daemon(8)'s pidfile right after daemon returned, before the new supervisor had written it,
said «the web part stopped right away» and served everything as root. A pause before every check; the supervisor
missing at the first checks and then answering: up; missing three checks in a row: stopped; missing now and then:
still waited for; never answering: silent at the deadline. Measured 20/11/2026: all OK; then six real restarts on the
VM, each with a new web part as daemoxcp_mail and no NOT_APPLIED.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.WebPartWaitTest

**DovecotHomeE2ETest** — the same with real deliveries and the VM's real configuration (it must start with the home of
before), as root with `-De2e.vm=yes`. Before: an autoreply written by the panel and a script of the mailbox's own
(ManageSieve), one delivery, and the false folders are in IMAP LIST; a second mailbox gets a message moved into its
false folder. A fault planted (Dovecot gives another home than the expected one): the configuration goes back exactly
as it was and the copies are taken away. Then DovecotHome as at boot: the new home in the configuration and from
`doveadm user`, IMAP LIST without false folders, Dovecot's files only in the home (vmail, 0700), the autoreply still
remembers whom it answered (no second reply, "discarded duplicate vacation response" in the maillog), the mailbox's own
script still runs; the false folder with a message stays. A mailbox whose rules the panel writes now has its home
before the first delivery, and no "duplicate db" error. The second run changes nothing. At the end the configuration
goes back, the VM's other mailboxes get their files back in the root, and the test domain is removed. Measured
10/11/2026 on Dovecot 2.3.21: all OK; with the fix taken out 8 checks fail.

**AddressTransformLinksTest** — setting aside the old mail of an address without following vmail's links (reperto
222). When an alias becomes a mailbox and the old mail is set aside, `AddressTransform.archive` moved it as root inside
`/var/vmail`, which with everything under it is vmail's: vmail could plant a link at `.panel-archive` or at the
domain's folder, and root's mkdir and rename followed it. Now vmail moves its mail (chroot -u vmail, only the group
vmail) and the panel's rules stay in root's tree (`/var/mail/sieve/.panel-archive`, RootOnlyPath). With `-De2e.vm=yes`,
as root, on bench folders made like `/var/vmail` (vmail:vmail 0770) and `/var/mail/sieve`: the control (set aside and
put back, the mail vmail's, nothing of root's in vmail's tree); `.panel-archive` as vmail's link to a root folder (root
makes nothing there, the mail stays); the domain's folder as vmail's link to a root folder holding `alice` (root's
`alice` stays); after a setting aside, the archive's domain folder as vmail's link (putting back leaves root's folder
alone). Every probe first shows it can plant its link, and that vmail alone cannot do what root did for it. Then the
real system with `address-transform.test` (created and removed, mail written by `doveadm save`): a mailbox with mail
and panel rules set aside and put back, Dovecot reads and writes it again; and a link `/var/vmail/address-transform-link.test`
to a root folder in `/var` (the same file system as `/var/vmail`). `/var/mail` is made sticky for the duration if it
is not, and put back. Measured on 10/11/2026: all pass; with the jar before the fix 11 fail, among them the real
setting aside of a mailbox with rules: `/var/mail` and `/var/vmail` are two ZFS datasets on the VM, and Java does not
move a full folder from one to the other (DirectoryNotEmptyException), so that choice always failed there.

**DovecotMoveTest** — the move to Dovecot 2.4 (reperto 213), what can be proven without a Dovecot: the 2.4
configuration with the two lines a real 2.4.5 refused written the way it accepts them; the packages by origin and what
replaces them (MySQL flavor only); the protected dependencies used as they are; a second MySQL client in the plan
named; where Postfix delivers with LMTP; before against after (a failed test, a port lost or new, a Sieve extension
gone, a test not run, the password process back to root); the probes against servers on this machine: IMAP on TLS
only with the pinned certificate, EXAMINE and never SELECT, the password quoted; LMTP never reaching DATA; ManageSieve;
the authentication socket that greets, the silent one and the missing one. On the VM.

**JobJournalTest** — the jobs' log on disk (`JobJournal`, reperto 196): one file per job in
`/var/db/daemoxcp-mail/jobs` (here a temporary folder), that survives a restart of the panel or of the server and is
read from Diagnostics, Operation logs. The start line, every line with its UTC time, the end with status, error and
duration written once only; folder 0700 and files 0600; only the newest KEEP stay; the list newest first, with the
type from the name and the status from the end line (a job that never ended says so); reading only a well formed
name inside the folder (no `..`, no absolute path, no other file); a folder that cannot be written does not stop the
job. On the VM.

**PropagationWaitTest** — waiting for propagation, with a fake clock instead of six real minutes. It
verifies the three properties that must hold: no waiting if the domains already answer, it stops as
soon as they answer, and it leaves anyway at the deadline instead of running forever.

**MtaStsSequenceTest** — the pieces born from merging the two sequences: `filter()`, the filter by
domain (exact comparison, case-insensitive: "in-d.test" must not catch "domain-d.test", and a nonexistent
domain must give an empty list, which is the guard against the false success), and `asEntries()`,
which turns the outcome into the DNS page's rows without losing the red rows.

**AutoconfigTest** — the verdict of the Autoconfig tab. The case that matters is `ready(true, 0, 0)`:
zero domains tried, zero successful, and without the condition `reviewed > 0` the count would say
green exactly when nothing was looked at.

**SrvRecordTest** — the comparison of an SRV record, which made production rewrite two SRV records
that were already right at every run. Cloudflare puts three fields in an SRV's `content` (weight,
port, target) and keeps the priority apart; `analyzeSrv` requires four because it is written for
`dig`'s output, so it returned `null` — "I do not recognise it" — and the record came out wrong. The
test covers all three forms and ends by reproducing the defect on the old logic: if one day that
last check passes, the test no longer verifies anything.

**ReportDeliveryTest** — which sendmail the periodic report leaves from and how the panel
understands how it went. On 25/09/2026 the report left from /usr/sbin/sendmail, that is mailwrapper,
that is dma: it arrived in clear and without a DKIM signature, and the panel wrote "successful". The
test verifies that mailwrapper is never chosen (symbolic link or hard link alike), and reads real
log lines: delivered with TLS, deferred, bounced for DMARC, refused by the milter, RFC 5424 format,
and dma's lines, with which the outcome must NOT become "delivered" because Postfix never saw that
message. TLS is taken only from the line of the smtp process that delivered (same pid) and of the
connection it left on: another process opening an encrypted connection to the same server, an
earlier connection of the same process, a reused one (conn_use) or the fallback in clear after a
failed TLS must not make a report sent in clear say "with TLS".

**LocalMtaTest** — Postfix as the local MTA (LocalMtaScript), on the VM because `postconf` and
`sysrc` are needed. Until 24/10/2026 none of the three scripts that install Postfix wrote
`/usr/local/etc/mail/mailer.conf`, and the mail of cron, of periodic and of PHP's mail() left from
dma. The test verifies that all three contain the piece after `pkg install`, has `postconf` read
their `main.cf` (myorigin = localhost, mydestination without the server's name, local delivery on)
and runs the piece in a fake folder, with the system paths replaced and checked: without Postfix it
writes nothing, repeated it rewrites nothing, a different mailer.conf is set aside, a message left
in dma's queue is said. It does not touch the system.

**PackagePlanTest** — the exact plan of an update and the answer to "is the patch there?". It reads
outputs of `pkg upgrade -n` and of `pkg audit -Rjson` in the form pkg's source prints them
(sections, totals at the bottom, `(vulnerable!)`, VuXML ranges like ">= a : < b"), and refuses to
call complete a plan with a line it does not understand or with totals that do not add up. Inside
is the case that prompted it: nginx 1.30.4,3 with the catalog stuck at the same version and VuXML
"< 1.30.5,3" — the fix exists, the branch does not have it, and the lock has nothing to do with it.
At the end the Packages tab's readings: the "<" lines of `pkg version -U -vRL=` (with real lines
from FreeBSD 15.1: the "?" and ">" are not updates, a version with strange characters stays out),
`pkg query '%n\t%v\t%k'` with version and lock, the kind of change in the reader's language.

**PackageQueueTest** — one job at a time on the packages, and the list to lock them again really
written before unlocking them. It comes from a review of the web panel, and the defect here
was the same: two jobs started together and overwrote each other's list on disk, and if the list
could not be written the job unlocked anyway. The test has 64 threads ask for the turn at the same
instant (only one takes it), checks that the turn is freed even when the job fails, that the list
of an interrupted job is not overwritten, that a list not written is said, and that with that list
on disk no job that installs or updates starts, while putting the protections back stays possible.

**InstallLocksTest** — the full reinstallation on a server with protected packages
(`InstallLocks`), with a fake pkg for the faults the real pkg does not give: an unlock that says yes
and does not unlock, a reading of the protections that does not answer, a re-lock that fails, pkg
blowing up halfway. For each one: whether the script can start, what stays protected, whether the
list on disk (and the job record next to it) is closed or stays, whether the turn is freed.

**PackageTurnAcrossProcessesTest** — the turn of the packages across processes: a second real process
(`TurnHolder`) holds it, and this one does not take it, does not lock again the other's list at
start, does not apply the locks rule (and says so); with the other killed by kill -9, the list is
locked again with the notice naming the interrupted job. Then `lockf(1)` against the panel, in both
directions, and the turn part of `install_mail_server.sh` (from the real text, up to the check of
the protected packages: it never reaches phase 1) from the menu, by hand, with the variables set by
hand. As root, on the VM: everything in a folder of `/var/tmp`, pkg read-only. Reperto 153.

**PendingDbPasswordTest** — the panel's new MySQL password stays pending until MySQL knows it
(`PendingDbPassword`, reperto 157), with a fake MySQL: the script that exits before MySQL (the old
one is kept), the one that gets there (the new one is adopted), MySQL silent (nothing is decided,
and the next installation reuses the pending one), the pending password that cannot be written,
Postfix's copy for the servers broken by the previous version (adopted only if MySQL accepts it and
only if it belongs to the same user). It runs anywhere, but it is run on the VM like the others.

**PendingDbPasswordE2ETest** — the same with real MySQL and the real body of the installation
(`Main.installOnTurn`): in place of `install_mail_server.sh` a planted script that exits before
MySQL, fails after it, succeeds, or kills the panel with kill -9 before or after changing the
password; then the start (`settleAtStartup`), also with the turn of the packages held by another process
and with MySQL not answering (port 1). After every round: does the panel get into MySQL
(`Main.connectFromConfig`)? Every round has its own folder, SQLite and secrets file, and a MySQL
test user (`e2e_pending`) removed at the end; it reads root's password from the real secrets file.
It is turned on only with `-De2e.vm=yes`, as root, with MySQL running.

**SqliteSharedTest** — the panel's SQLite database used by two processes together, like the
`--web` service and the menu from the same folder (reperto 160): one process does the service's
reads and stays up, another writes what the reinstallation writes, all at once and without
`SQLITE_BUSY`; then a write held 6 seconds by one and the other waiting and succeeding (6 and not
3: sqlite-jdbc already waits 3 seconds on its own). It does NOT see the ResultSet that
`startWebServer` kept open for the whole life of the service: only the reinstallation from the menu
with the real service running sees that, on the clone (reperto 161).

**FreshConfigTableTest** — the panel's configuration table on a server where it does not exist yet, the first
start of the menu (step 6 of the README). Found in the clean-install rehearsal of 18/11/2026 with the 0.9.0 jar: the
start added the newer columns before creating the table, and option 3 of the menu said "no such column:
roundcube_ssl_chain" until a second start. In child processes, each in its own folder: `dataBaseManager.prepareAtStartup()` on a new
server (the table, every column, saving the webmail settings works), a second start (nothing created again, nothing lost), and a server installed with an
older version (old column names renamed with their values, the missing column added). With a jar in the old order
the first two failed (5 checks), the third passed: installed servers never had the defect.

**MysqlReconnectTest** — the running panel reconnects to MySQL with the password that is in the
secrets file now, not with the one from the start. Real MySQL, test user `e2e_reconnect` removed at
the end; `-De2e.vm=yes`, as root.

**InstallWayBackTest** — the reinstallation's way back without bectl: the step that creates it runs
with the turn and before the unlock, a refusal of it stops everything, and `Main.installOnTurn` says
"it changed the system" only if the (planted) script reaches phase 1.

**ReinstallWayBackE2ETest** — the same with real bectl: when the boot environment stays and when it
is removed, and at the end the same boot environments and snapshots as before. It creates and
removes boot environments: only on a clone, and it refuses to start (code 2) if there are already
ways back of package jobs, which the pruning would remove.

**ReinstallJobTest** — the full reinstallation detached from the menu (`ReinstallJob`, reperto
163): the menu killed, the menu's terminal closing (SIGHUP to its group), a second menu opened
halfway, the reinstallation itself killed (and a "service" with the watcher that notices by itself,
reperto 166). Planted script, the rest real (detached JVM, turn, pkg, bectl): only on a clone,
`-De2e.vm=yes`, as root; it refuses to start if there are already ways back of reinstallations or a
list of unlocked packages.

**InterruptionWatchTest** — the running service's watcher (`UpdateManager.watchOnce`, reperto 166):
when it does NOT touch the list of unlocked packages (the list of the JVM's update, whoever wrote it
still alive, a job of this process, the turn held by another process) and the text of the notice of
an interrupted reinstallation. Without pkg: the case that really locks again is `ReinstallJobTest`
J4.

**InterruptedJobRecoveryTest** — a package job that died halfway completed by the panel (InterruptedJobRecovery,
reperto 188), with a fake system: the trace the package turn writes and removes (and the relock does not); what to do
with a service (restart on the old files, start if it fell, only check if it already started after the change, leave
it if it was off); the completion with every fault said in the notice (configuration refused, same pid, not running,
files still broken, mail lookups); the complete reinstallation not touched; when it waits (a live job, the list still
on disk, pkg still working, a restart by design).

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.InterruptedJobRecoveryTest

**InstallScriptsTest** — the install scripts on disk are always those of the running jar
(`InstallScripts`, reperto 169): all-or-nothing writing, the old script rewritten, those nobody
writes any more set aside, the jar's fingerprint after the `#!`; with `-De2e.vm=yes` also a real
start of the panel doing it.

**InstallScriptVersionTest** — `install_mail_server.sh` started by hand stops if it belongs to a
different panel version from the service's, before changing anything. Real script, as root, on the
VM: it always stops before phase 1, and puts rc.conf back.

**ReinstallReturnE2ETest** — going back to the way back of a reinstallation with the mail that
arrived afterwards merged in (`ReinstallReturn`, reperto 170), with real bectl and without
rebooting; everything put back in the right order (bectl activate promotes). Only on a clone.

**NoBootEnvironmentTest** — a system without boot environments (a fake bectl first in the PATH that
always fails): the way back is not created and it is said, the space is not measured, the return
refuses every name, the tab says there are none (reperto 172).

**InterruptionReportTest** — the interrupted reinstallation in the periodic report: the most urgent
thing, with its title and the command to go back; any other job stays as it was. With
`-De2e.vm=yes` also the report's real data (`UpdateManager.reportData`). Reperto 172.

**LockMarksTest** — the "locked by the panel" sign on all and only the locked packages. With
`-De2e.vm=yes` also check 5, which unlocks ALL packages (only on a clone) and puts locks and signs
back as it found them: with no locked package `pkg lock -l` exits with 1, and the signs left never
went away (reperto 173).

**menu-way-back.exp** — entry 6 of the on-screen menu, in a real terminal (`ssh -tt`), with expect:
a copy of the panel, a real way back (`MakeReinstallWayBack`) and the notice of an interrupted
reinstallation must be prepared on the clone; afterwards, the way back is the one of the next boot
and the mail is stopped, and everything must be put back (reperto 174). Lanterna redraws only the
cells that change: it waits for a line that arrives whole, not just any line.

`ReinstallJobTest` wants the shadow class of `FullMailServerScript` (`tests/planted`) in front of
the jar: the reinstallation always rewrites the script from its jar, and without the shadow it
would run the real one (the test checks it and refuses). `MenuGoBack` is the driver of the menu's
entry 6, like `MenuReinstall`. The three drivers (`MenuReinstall`, `MenuGoBack`, `MakeReinstallWayBack`)
do nothing without `-De2e.vm=yes`: on 17/11/2026 a run of every class with a main on the VM went back to
a reinstallation's way back (the next boot's system, mail stopped) because `MenuGoBack` had no guard.

**AliasMessagesTest** — what the panel says after creating, editing, disabling or deleting an
alias. Postfix reads only the active aliases and applies them before the mailboxes: a mailbox with
an active forward and without an active "itself -> itself" no longer receives anything, and an
address that is not a mailbox exists only while it has an active alias (or the domain an active
catch-all). Since an alias can be disabled, the copy's row can be there and be off: the logic of
before looked at the row and not at its state, and stayed silent exactly there. The test ends by
reproducing that silence on the old logic.

**PasswordGeneratorTest** — the password generator and the rule the panel applies to mailbox
passwords. With "All characters" the generator also put in < > / ~ and the backtick, which the rule
refuses: the password proposed by the panel was rejected by the panel itself, seven times out of
ten. The test generates thousands of passwords for every type and combination and requires them all
to pass, checks that the entropy estimate uses the same sets, that the rule stayed the same as
before character by character, that mailbox passwords want at least 12 (the admin login stays as it
was: raising it would have locked out whoever has a shorter password), and ends by reproducing the
refusal with the old symbols.

**AddressConversionTest** — turning an alias into a mailbox and a mailbox into an alias
(AddressTransform and MailDatabase), only when it can really be done. Without a database: the
refusals (@domain catch-all, an address that is already a mailbox, a domain that is not the
panel's, names that would leave /var/vmail, like "..@domain"), the destinations (valid, existing if
they are on the panel's domains, twenty at most, no loop back to the address), the mail of an
earlier mailbox found on disk (counted, set aside without deleting it, put back if the
transformation fails) and the preview's fingerprint, which changes when the state changes. On
MySQL: the two transactions, looked at with the same queries Postfix uses; if the last step fails
the database goes back to how it was; the UNIQUE constraint refuses a second mailbox with the same
address; with the mailbox go auto-reply, filters, forwards and limits, and the "itself -> itself"
alias; there and back.

**ResetDatabaseTest** — the reset of the panel's database (MailDatabase.dropAllTables, which Main
uses in the reset). First it redoes the old reset, which dropped the tables one at a time: MySQL
refused mailboxes, domains and panel_admin because other tables point at them with a foreign key,
and they stayed with their data (together with admin_passkeys, cloudflare_accounts and
dkim_rotation_history, which the list did not have) while the reset called itself complete. Then
the new one: every table that createSchema and the migrations create is in its list; with a row in
each, and the virtual_* tables of the old versions, none is left and a table of someone else's next
to them is not touched; created again, they are empty; on the database already empty it gives no
errors; if a table of someone else's points at domains MySQL refuses, nothing is dropped (a single
DROP, atomic) and the error says what is left. Without a connection the reset does not start.

**SoftwareVersionsTest** — Home's versions (SoftwareVersions). A fake system answers with the real
outputs of the programs on FreeBSD (postconf, dovecot, rspamd, redis-server, nginx, php-fpm,
openssl, freebsd-version, clamd, mysqld, pkg which, pkg query) and it checks: every version
recognised; the package found from the binary even when it is called postfix-mysql or
dovecot-mysql (by name it was not found); pkg called twice in all; "to restart" when the process
started before the package was installed, or answers with another version (MySQL, ClamAV, the
panel's Java, the kernel), and never when it is not known (no pidfile, process gone, PHP-FPM
reloading in the same process). The crooked cases: clamd not answering, signatures nineteen days
old, MySQL unreachable, programs answering with an error or with HTML, which never passes as a
version. Then clamd's socket, for real: a fake daemon that answers and a silent one, from which the
reading must detach in three seconds.

**VersionsApiTest** — /api/versions and /api/service on the real server (SSLMailServer), over
HTTPS, with a session like the login's: only the HTTP server with its routes is started, not the
handlers that would touch the system. Without a session 401; with the session the versions, MySQL
read from the real server; the reading kept thirty seconds and "fresh" that does not re-read
before three; wrong parameters and methods refused. /api/service without a CSRF token, or with a
wrong token, is 403 and ends up in the audit log; with the right token the request goes through; an
action on a service goes to the log, with the same outcome as the response, and makes the versions
be read again. The action is a real `service redis restart`: where the mail server is installed,
redis really restarts.

That is why, on the VM, **never under `timeout` without `-f`**: FreeBSD's `timeout(1)` acts as the
reaper of the command and its descendants, and also waits for the redis just restarted. Measured on
30/10/2026: the test prints "ALL GREEN" and its JVM exits, but `timeout 60` stays there until the
deadline, exits with 124 and kills redis (`redis is not running`). With `timeout -f 60`: exit 0 in
4 seconds, redis running.

**PkgBranchTest** — the branch of the packages, quarterly or latest (PkgBranch). The fake system does
what pkg does (libpkg/pkg_config.c, read on 03/10/2026): it starts from the /etc/pkg/FreeBSD.conf of
FreeBSD 15.0 RELEASE (quarterly, kernel modules with the minor version, FreeBSD-base off) and reads
the files of /usr/local/etc/pkg/repos in alphabetical order, with every block overwriting the fields
of its repository and pkg's variables expanded. It tests: reading the repositories (official or
not, packages, modules, base system; FreeBSD 14's names and -STABLE's modules without a minor
version), when it cannot be changed (packages from a repository of one's own) and why, the mixed
branches; the preview, which touches nothing and writes the addresses with ${ABI} and
${VERSION_MINOR} instead of today's values, and writes priority and ip_version back unchanged (a
block would reset them); the change quarterly -> latest and back, where the panel's file is removed
if the default branch is enough; the user's FreeBSD.conf never touched; and the ways back: a file
read after the panel's that wins, a catalog that does not download, a folder that cannot be
written, a configuration changed after the preview. At the end the real file on disk: permissions
rw-r--r--, no temporary file left, the .conf files listed as pkg reads them.

**pkg-branch-browser-test.js** — the "Package branch" row of the Updates page (its panel opens in place
under the row, reperto 193): it reads by itself,
names and addresses only as text, the preview, the branch name typed by hand to confirm,
fingerprint and CSRF token in the request, the job followed to its outcome, the error of a change
that does not start; dark theme and phone.

**packages-browser-test.js** — the packages on the Updates page, with the simulated server (reperti 202, 203, 207): one
row says the state (how many in one plan, how many of the mail server and in how many steps, the fixes, the
vulnerabilities not fixed yet, the held ones with their reason) with no button; "Update everything" at the top has the
one button: first protecting a mail server package that is not locked, then the steps in order (the PHP family one
step). Its checks first; a plan of the other packages that would remove a package is left out with the reason;
cancelling starts nothing and the button stays; confirming sends ONE request with the signature of every step and the changes
shown. Under the row, closed, the list one by one: the summary, the warning about the unlocked ones with the button to
lock them, for every package installed and catalog version, verdict on the vulnerability (text, never HTML), lock,
"held" where the advisory says to wait, the JDK saying it has its own procedure, no update button; Lock with name and
CSRF token.

**packages-row-browser-test.js** — on the real panel of the test VM, only reads (reperto 202): the packages are
one row of "Update the server" with at most one button, no separate card and no separate mail server row; the list
under the row is closed, and opened shows the packages with version and lock in words and no update button; at 375 px
no horizontal scrolling with the list open and every visible button 44 px; no request that changes anything.

**fingerprint-routes-browser-test.js** — on the real panel of the test VM (reperto 204): the two features that send the
root part a fingerprint the panel computed itself go through the root's closed list. The package branch to latest and
back to quarterly (16 hex digits, each job followed to the end; the VM put back on quarterly in any case), and "Turn
into mailbox" on a test alias (64 hex digits), with the mailbox deleted after; no forwarded request refused in the
root's log while it ran.

**running-job-browser-test.js** — on the real panel of the test VM (reperto 206): "Check for updates" started in one
tab, and in a second tab the Updates page says what is running and since when, with its log, while the buttons of the steps
and "Check for updates" wait; a job asked meanwhile is refused and leaves no log in the jobs folder; when the search ends
the line goes and the buttons come back. The search only downloads the lists.

**address-conversion-browser-test.js** — the "Turn into mailbox" (Aliases page) and "Turn into
alias" (Mailboxes page) windows: the preview, the password proposed by the generator, the mandatory
choice about the earlier mail, the address typed to confirm, the fingerprint and the CSRF token in
the requests, the token also in "Delete mailbox"; dark theme and phone.

**software-versions-browser-test.js** — Home: the Version column of "Mail services" (with the MySQL
and Redis rows), "Other software", the "to restart" notes, a version with HTML inside that stays
text, the names of the buttons for screen readers, the question before stopping a service or restarting
MySQL (cancelled, nothing starts), the CSRF token to /api/service, the re-reading after every
command; dark theme and phone, where the tables become cards.

**FixedTextsTest** — the i18n stays complete: no fixed text a person reads. In the page templates (between two tags),
in the scripts (a sentence outside `t()`), in the attributes read or heard (title, aria-label, placeholder, alt), in
the server's answers (a fixed "message" or "error", `sendJsonError` with a fixed text), in the console's windows,
labels, buttons, titles and menu items; an error for the page is a ShownException, and no raw `e.getMessage()` goes
into a translated text or an answer (`ErrorText.detail`). The technical texts, the same in every language, are listed,
and a list may not keep an entry no longer used. Every check first finds a fixed text in a sample made wrong on
purpose. Logs, journals and the output of other programs are not checked: they stay in English.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.i18n.FixedTextsTest

**CleanInstallFindingsTest** — what the installation from the README on a clean VM found on 20/11/2026, kept fixed:
the installation ends with pf closed and MySQL on 127.0.0.1 (before, they waited for the panel's first start); option 1
sets the time zone with tzsetup, never with cp through the /etc/localtime link; MySQL not installed yet does not read
like a failure; every yes/no window has its own text and Upgrade asks once; the menu stays on the item just used and
Enter confirms a window with one field; the README names the start item as the menu does and mentions freebsd-update's
pager. On the sources before the fixes it fails on exactly those points.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.CleanInstallFindingsTest

**EnglishLogsTest** — the panel's log lines stay in English, the same for everyone. The texts written in a log call
(a java.util.logging logger, `System.out`, `System.err`) and in the message of an exception created in the code have
no Italian word: one of a short list English does not have (`al`, `della`, `sono`, `gia'`, `senza`...). Comments and translation
keys are not read. The checks first find an Italian line in a sample made wrong on purpose; on the sources before
this test they find «Auto-apply firewall config al boot», seen in the real server's log on 19/11/2026.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.i18n.EnglishLogsTest

**I18nTest** — the interface's languages (I18n) and the pages' frame (Layout). The panel's languages
are the files in lang/, each named with its ISO 639-1 code. Italian and English are complete, with
the same keys. Every language, partial ones too, has only keys Italian has, no empty text, the same
{values}, only the plural forms CLDR gives it, a written plural rule, and no right-to-left language
yet. Each of these rules is also run on a bad file made in the test, to see it fail for the right
reason. Then any number of languages: the files found, the fallback chain (the language, English,
Italian), the plural forms of ten languages, the names of the languages in their own language, two
buttons for two languages and a menu for three, the database procedure taking exactly the panel's
languages. Every {{t:key}} and every t('key') of the scripts exists in Italian and English; no script
hides the t function behind a variable with the same name; a completed page has no placeholders
left. Then the language of a request (Accept-Language with the weights, the cookie) and the frame:
the four sections, every page served by the panel in the menu, the page you are on marked.

**LanguageRoutesTest** — the languages on the real server (SSLMailServer), over HTTPS, with the
test MySQL: the dictionary /i18n/(language).js, the language of the sign-in page (cookie before the
browser, English for a browser that asks for neither), /api/language before signing in (only with
the sign-in page's token) and after (with the session's token: it is saved in the account), the
saved choice that wins over the browser and the cookie realigned, the frame around the pages.

**LoginSecurityTest** — the passwordless login, with the test MySQL. The migration of an old
installation: away with the columns password_hash, totp_secret, totp_enabled and backup_codes, the
DATETIME dates converted to UTC, the oldest administrator made superadmin if there was none, the
earlier passkeys tied to their user handle and still good for signing in; the keys in a 600 file
outside the database. The AES-256-GCM encryption (random nonce, one character changed and it does
not decrypt, another key does not decrypt) and the blind index. Passkeys signed by a software
authenticator (SoftAuthenticator): valid registration and login, and refused with another session,
another origin, another rpId, without user verification, with the counter going backwards, with
the signature spoiled, with the challenge reused or expired, with a key of nobody or of a disabled
administrator; the confirmation of an operation only with one's own passkey and one's own session.
The one-time codes: only the HMAC in the database, once only, five attempts, ten minutes, the limits
per address, IP and subnet, the console code, the confirmation one, the email change that holds
only when the code comes back, and never a code or an address in the log. The sessions: only the
token's fingerprint, IP and browser encrypted, the same browser, 30 minutes without requests and 12
hours at most, the revocation (one, the others, at sign-out, by the administrator), the derived
CSRF token.

**LoginRoutesTest** — the sign-in routes on the real server, over HTTPS: the sign-in page creates
nothing on the server and ties its token to a cookie; every request before the login wants token
and cookie; asking for a code for nobody's address answers as for a real one (status, text, time),
and so does a wrong code; right code, console code and passkey open a session in the database with
the __Host- cookie; /api/account wants the session's token; administrators have an email and no
password; the vault wants a recent confirmation; signing out closes the session in the database;
the old routes with password and TOTP no longer answer.

**MailboxPasswordTest** — mailbox passwords can always be seen again, with the test MySQL and the
real server. Every password is saved twice, bcrypt hash and encrypted copy; if the vault does not
encrypt nothing is saved. "Reveal" shows the copy only if it is still the password (comparison with
the hash): missing, old or unreadable copies each have their own message. The rows left in clear
(the webmail's old sql driver) are recognised and at start become hash + copy.
/api/internal/mailbox-password (the change from the webmail): only from loopback, without a
proxy's headers, with the webmail's key; current password checked, hash and copy together, limited
attempts, no password in the log. /api/internal/mailbox-vault fills a missing copy after a webmail
login. Roundcube's configuration: away with the sql driver's lines (with the panel's MySQL
password), the panel's block only once, file not readable by other users.
With `-Droundcube.dir=<roundcubemail-1.6.x-complete unpacked>` and `php` it also runs Roundcube's
real code (webmail-roundcube-test.php): the httpapi driver with its Guzzle and the daemoxcp_mail_sso
plugin's login hook, against the panel.

**ConfigBackupsTest** — the backup copies the panel makes of a configuration file before changing it: the latest ten
of each file are kept. Found walking every function of the 0.9.0 panel (18/11/2026): no copy was ever removed, and the
real server had 221 of /etc/pf.conf and 267 of the firewall anchor. Only the two names the panel writes count
(`file.bak.<13-digit milliseconds>` beside the file, `file.bak.<yyyyMMdd-HHmmss>` in the fail2ban folder); names
written by hand, links and folders with the name of a copy, and BanActionRepair's one-off copies are left. The fail2ban
folder is pruned before the new copy; the first start removes the copies of the earlier versions once, and the second
finds nothing. In the sources, every copy goes through ConfigBackups. On the sources of 0.9.0 it fails (the 13 places
that built a copy name), and with a ConfigBackups that removes nothing too.

**ConfigSecretsTest** — the MySQL password and the TLS private key leave the SQLite database even
on a server already started: at the first start they move to the secrets file (600, folder 700) and
the columns are emptied; what the panel saves afterwards goes into the file; a value written by an
old version wins at the next start; the PEM key comes back identical; with the file not writable
the value stays in SQLite and is read all the same; database/ 700 and daemoxcp-mail.db 600.

**csp-browser-test.js** — every generated page in Chromium with the panel's
Content-Security-Policy (without 'unsafe-inline', reperto 178): no violation, no on...= handler or
inline style in the DOM, every data-on-* in panel-actions.js's language and only with the panel's
functions, every data-style applied, and the functions called from the HTML the scripts build later
exist.

**SessionRunTest** — sessions last for one start of the jar, with Strict cookies (reperto 184), with
the test MySQL: the cookies (Strict, the session one without expiry), the fingerprint in the
database that is not the token's SHA-256, a second process on the same database (the restarted
jar) that does not recognise the token and computes another CSRF token for it, `beginRun` removing
the rows of before, and on the real server the 302 to `/index?session=ended`, the 401 with
`X-Panel-Session: ended`, the wrong confirmation code without that signal, signing out with
`Clear-Site-Data`.

**session-restart-browser-test.js** — the same with the real Chrome and the real server
(HomePanelE2EServer on the VM), which the test restarts with the command in `START`: the cookies as
the server sets them, a link from another site arriving without the session, the open page that
after the restart goes to the sign-in page and says why, the old cookie going away, the new start's
session getting in.

**update-center-browser-test.js** — updating from the panel (reperti 185-187), with a simulated
server: the restart banner on every page (and the Italian text taken from it.json), the "Update the
server" card with its rows in words (a dedicated procedure only when it applies; every row acts in place,
reperto 193; one button at most per row, reperto 197; one row for all the packages and no separate Packages card,
reperto 202), the package update confirmed in the panel's window with the exact plan and its signature and its outcome
under the row, after which the same row's step is the mail server package by name, the FreeBSD patches with their outcome
and the restart left (reperto 196), a new FreeBSD release in four steps with only the current one's button,
the checks that stop a preparation, a dedicated procedure guided (Roundcube: one line on the checks, what to
know before, the plan, one button, the panel's window, the outcome that stays in the row; and when the checks
stop it), the restart window (what stops, the chosen delay, the time, cancelling, Escape), reads that queue
up instead of failing, 44 px touch buttons at 375 px, and no browser dialog at all. Diagnostics, "Check everything"
(reperto 199): one button, every check run, what needs a look first with one button each (the failed job's log, the
patches on Updates), what is fine closed below with how many, and the compatibility verdict saying what and whose,
component by component, with the card's own rules. A restart scheduled (reperto 200): the strip with the time and
"only reads", a button of the page that does nothing and says why (once), a refused change (409) that makes the strip
read again, cancelling that unlocks the page; with a job running, the restart window says which and has no button.
A job in progress started elsewhere (reperto 206): the card says what and since when with its log, the buttons of the steps
wait saying why, and when it ends the card reads itself again.

**panel-dialogs-browser-test.js** — on the real panel of the test VM (reperto 198): every page of the menu loads with
no page error and no browser dialog; on Domains and Mailboxes "Delete" opens the panel's window with the red button,
and cancelling it changes nothing. Read only.

**check-pages.sh** — the pages generated by PageGenerator (the folder as argument, or built here): every page and
every script file it loads (`/assets`, `/i18n`) parses, every element is closed, and no script calls the browser's
dialogs, `alert`, `confirm` or `prompt` (reperto 198: confirmations are the panel's window, messages its notices). A
folder given as argument is left as it is. Usage: `sh tests/check-pages.sh <folder>`.

**OsPatchTest** — the decisions behind installing FreeBSD patches (OsPatch): the target version from
freebsd-update's tag file, its outputs (nothing to fetch, nothing to install, reboot then install
again), whether a restart is needed or advised, and the install configuration with CreateBootEnv no.

**home-panel-browser-test.js** — the panel card at the top of the dashboard (reperto 183), with the
simulated server two hours ahead of the browser: how long it has been running (counted with the
server's time) and since when, with the time zone; the eye closed at first and the details asked
for only when it is opened, with the mouse and with the keyboard; the ten rows of details and the
fingerprint copied to the clipboard; whoever cannot see them has no eye, a 403 says so, a jar
without a recorded build or with changes outside the commit says so; in English, at 375 px without
horizontal scrolling and with 44 px touch buttons. With `REMOTE` it runs on the real server
(**HomePanelE2EServer**, on the VM) and compares the card with the machine's data: the jar's
fingerprint, commit, FreeBSD, port.

**sieve-rules-browser-test.js** — the page when the mail server did not get the rules (reperto 223), only against the
real server: **SieveRulesE2EServer** on the VM (as root, the test MySQL, the REAL SieveGenerator; it seeds
`sieve-rules-shown.test` with alice, the alias bob and bob's filters left on the disk, and starts only with a plain file
`install_scripts` next to the jar, so the alias conversion cannot run the mail configuration script). The port through
an SSH tunnel (`ssh -N -L PORT:127.0.0.1:PORT`), `REMOTE=https://panel.localhost:PORT MAP=127.0.0.1 SESSION=...`.
`PHASE=refused`, with `/var/mail` at FreeBSD's 0775: a forward of alice and her auto-reply, each with the red notice of
it.json on top of the dialog, still there after 10 s; the forward in the list and the field empty; the auto-reply
dialog open; bob turned into a mailbox, the dialog closed and the alias page saying in red that his old filters still
apply. `PHASE=written`, with `/var/mail` at 1775: a second forward with no notice, and alice's rules file then holds both
forwards and the auto-reply saved while refused. At the end `rm -r /var/mail/sieve/sieve-rules-shown.test` and
`/var/mail` back as it was. Measured on 10/11/2026: all OK; with SSLMailServer as before 8 fail, with the page as before
5 (the forward missing from the list, the dialog of bob still open).

**sieve-dialogs-browser-test.js** — the Filters and Forwarding dialogs of the Mailboxes page work from the browser
(reperto 224), only against the real server: **SieveDialogsE2EServer** on the VM (as root, the test MySQL, the REAL
SieveGenerator; it seeds `sieve-dialog-fields.test` with alice, no filters and one forward put straight in the database,
`seeded@elsewhere.example`). Each phase on a freshly started server. The port through an SSH tunnel,
`REMOTE=https://panel.localhost:PORT MAP=127.0.0.1 SESSION=...`, and `RULES` the command that prints alice's rules file
(`ssh ... root@192.168.1.20 cat /var/mail/sieve/sieve-dialog-fields.test/alice/.dovecot.sieve`). `PHASE=written` (the
default), with `/var/mail` at 1775: a filter created in the dialog (no notice, in the list as a button, in the rules file
with the seeded forward); opened again from the keyboard (Tab, Enter) with its name, condition and action back in the
dialog, changed, and the rules file follows; deleted with «Elimina filtro», confirmed, gone from list and file; the seeded
forward deleted, gone from list and file. Each part starts from the page loaded again, and a step that times out is a
failed check, not the end of the test. `PHASE=refused`, with `/var/mail` at 0775: a filter created, the filter deleted and
the forward deleted each show `server.sieve.notWritten` on top of the dialog, the list shows the panel as it is, the
rules file does not change. At the end `rm -r /var/mail/sieve/sieve-dialog-fields.test` and `/var/mail` back as it was.
Measured on 10/11/2026: both phases all OK; with the page as before 10 fail (the filter refused as text, the forward "not
found"), with the server as before 8 (the filter does not open, the forward's deletion rewrites no mailbox and says so).
It also runs on the REAL panel of the VM (separated, with RootGate between its parts), signing in with a console code:
`REMOTE=https://127.0.0.1:2096 VM_LOGIN="ssh ... root@192.168.1.20" DOMAIN=rehearsal.test FORWARD=bob@rehearsal.test`
and `RULES` on alice's file there; alice must have no filters and that one forward. All OK on 10/11/2026, after the
upgrade of the whole Sieve chain (reperti 212-224) with `tools/upgrade/upgrade-panel.sh`.

SieveDialogsE2EServer, SieveRulesE2EServer and HomePanelE2EServer keep the panel's secrets and the vault's old key in
their working folder unless `-Ddaemoxcp.mail.secrets.dir` / `-Ddaemoxcp.mail.vault.key` say otherwise. Before 10/11/2026 they
wrote their test MySQL password and TLS key into `/usr/local/etc/daemoxcp-mail`, the RUNNING panel's: the VM's panel went
on until its next start, then could not reach MySQL and stopped separating.

**PanelInfoTest** — what the card reads (PanelInfo): the entries Maven writes into the jar and those
it did not replace, the machine's boot from `kern.boottime`, the JVM's start, the process details,
and the jar's fingerprint computed again on its own. On the VM, after `tools/build-jar.sh`, with
`-Dbuild.script=yes` it also requires the build number and the commit.

**PageAssetsTest** — scripts and styles as files (PageAssets), who can have them, writing and
cleanup, the policy, the generated pages and the sources without inline code. The part on the
sources must be run from the project root (on the VM, from a copy).

**login-browser-test.js** — signing in in Chromium with a virtual authenticator, on the real server:
the first sign-in with the console code (java ... Main --access-code), the passkey created on the
Account page, the sign-in email confirmed with its code, the open sessions, the vault key (in
Settings) asking for confirmation with the passkey, signing out and in with the passkey alone, a new
administrator with the email, signing in with a code by email (and a wrong one refused); then the
roles: the new administrator (Reader) signs in with a code and finds a reduced menu, "Read only"
and the refusals (mailbox passwords, queued messages), promoted to Operator can change the mailboxes
at the next page, deleted is out at once. At the end the sign-in page on a phone in Italian.

**dialog-focus-browser-test.js** — the focus when a panel window closes (r9), on the generated pages with a
simulated server. Found walking every function of the 0.9.0 panel on a clean server (18/11/2026): a window opened
over another ("Go ahead?" before revealing a password, the fresh confirmation) did not even get the focus (the
focus trap of Bootstrap 5.3.0 focuses the new window before turning off the old one's), and when it closed the
focus fell on the body: the window below no longer heard Escape. The client configuration of a mailbox: the focus
inside, Escape, back on the button that opened it; "Reveal", "Go ahead?" with the focus, cancelled, the focus back
on "Reveal", Tab kept inside, Escape; "Yes, go ahead", the password, the focus still inside, Escape. With the
pages of 0.9.0 it fails (3 checks); the fix is in the shared panel-reboot.js.

**layout-browser-test.js** — the frame in Chromium: the sidebar with four sections (with the Queue,
Sending limits, Statistics and Administrators pages, which no link reached before), the entry of the
page you are on, "Section › Page" in the top bar, "Skip to content" at the first Tab, the language
change (the request with the CSRF token, the page coming back in English, the scripts' English
dictionary, and back), each button named in its own language, the language choice on the sign-in and
installation pages, the menu on the phone (it opens, takes the focus, closes with Esc and with the
X), no sideways scrolling, the dark theme. With three languages, the menu PageGenerator writes
(language-select.html) in place of the buttons: its label, each language in its own language, the
choice sent with the token, a refused language shown in an alert. The plural forms: for every
language in I18n.PLURAL_RULES and 136 numbers, the form Java gives (plural-categories.json) is the
one Chromium's Intl.PluralRules gives; tn() falls back to .other for a form the file does not have.

**MailQueueTest** — Postfix's queue (MailQueueManager) with a fake executor that records the
commands instead of running them. The queue ID never reaches a shell: every command is a list of
arguments, and an ID that is not alphanumeric is refused before running anything (before it ended
up in "sh -c postcat -q <id>", and /api/queue?action=message&id=X;command ran the command). The list
read from postqueue -j, with the deferral reason for every recipient (postqueue -p put it on a line
the old reader took for the recipient: the Error column stayed empty and "Delete failed" never found
anything); permanent only a message with a 5xx for EVERY recipient; only the confirmed messages
that still have a permanent error are deleted; the messages in the request's language, the
exceptions in English.

**QueueApiTest** — /api/queue on the real server, over HTTPS, with the test MySQL and the fake
executor: without a session 401; the list with the deferral reason and the arrival in UTC; an ID
with shell characters refused without running anything; every POST without a CSRF token or with a
wrong token 403, without running anything and written to the audit log; with the token the deletion
runs postsuper with the ID as the only argument and ends up in the log; the deletion of the failed
ones wants the IDs seen and their number, and touches only those.

**queue-browser-test.js** — the Queue page in Chromium, in Italian and in English: the four counters
from the fields the server really sends (before it read inflight/tempfail/permfail, which the
server never sent), sender, subject, deferral reason and text with HTML inside shown as text and
never run, the CSRF token in every POST, deleting a message after the confirmation, deleting the
failed ones only by typing their number, the dates in the page's language, no sideways scrolling
on the phone.

**RateLimitsApiTest** — /api/ratelimits on the real server, with the test MySQL: without a session
401; every POST without a CSRF token 403; zero and a daily limit below the hourly one refused with
the reason; saving the global limits again UPDATES the single global row (with target_id NULL
MySQL's UNIQUE index let a row be added at every save) and removes the NULL rows left; a mailbox's
limit created, updated in place and deleted with the names and fields the page sends (before it
sent create/update/id, which the server did not know); everything in the audit log.

**limits-statistics-browser-test.js** — Sending limits and Statistics in Chromium, in Italian and
in English. Limits: the warning that the hourly and daily limits are saved but not applied, the
global limits saved with the CSRF token, a mailbox's limit created (save_mailbox), edited without
changing mailbox and deleted after the confirmation, an address with HTML inside that stays text.
Statistics: the warning that the sending and receiving counts are not collected, the cards from
"totals" and the table from "domains", Rspamd's numbers read where the server puts them (before it
looked for them under "stats": always "-"), the period sent as days, numbers and dates in the page's
language; no sideways scrolling on the phone.

**RolesTest** — roles and named permissions on the real server, over HTTPS, with the test MySQL.
Before, only administrators and the vault belonged to the superadmin, and a Reader could change
everything else. It checks every role's permissions, the routes table (each one declares its
access, the public ones are only those of the sign-in, autoconfig, MTA-STS and the webmail, every
menu entry asks for the same permission as its route) and the check in front of every route for
every role: 302 and 401 without a session, 403 for a mailbox's password, a queued message, a
mailbox's webmail, a service, the reboot, the vault, the firewall; the body put back in place for
the handler; the changed role holding at once; the removed administrator out; the refusals in the
log.

**RootChannelTest** — the channel between the two parts of the separated panel,
without a database: a request goes and comes back the same; the
headers outside the short list (Cookie, X-CSRF-Token, Authorization, Host, the proxies' ones) never
pass; a field out of shape refuses the whole request (".." or an encoded dot, an unknown method, a
client address that is not an IP, no administrator or session, a body over the limit); the socket is
0660 and a connection from another user gets nothing; the in-memory exchange enforces the declared
length, HEAD has no body, and a handler that answers nothing or throws gives a 500.

**SeparatedPanelTest** — the two parts together, in one JVM with the test MySQL: a WEB_PART server on
a port, a ROOT_PART server without one, the socket between them. A signed-in API reaches the root
part with who asked and never the cookie, the token or the CSRF token; what the web part refuses (no
session, no CSRF token, no permission) never reaches the root; the account API stays in the web part.
Then requests forged on the socket, as a broken-into web part would send them: a viewer's session
asking to create an administrator gets 403 and creates nothing, someone else's administrator id or a
revoked session 401, a public route, a page or the account API 404; the role is the database's. A
Set-Cookie from the root never reaches the browser, and with the root gone the web answers 503. The
routes the web part serves by itself (domains, mailboxes...) never reach the root, and the root refuses
them on its socket; its one operation, mail-folders, is refused to a viewer, with GET, with a body,
without a live session, and an operation that is not in the list.

    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.RootChannelTest
    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.SeparatedPanelTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelSeparationTest
    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.SecretsSplitTest

**SqlCatalogTest** — the panel runs only the SQL of its catalog (SqlCatalog):
every statement is a fixed text; the guard (CatalogGuard) refuses any other text by every way one reaches
the driver; from the project folder, no SQL outside the catalog and every JDBC call gets a catalog
constant; the web part's list, and its procedures: one for every MySQL statement of the list, with the
session first and then the same parameters, bound to the session save the public ones, the idle time of
WebSessions, no DKIM private key and no password hash or copy out of the database save Show password's two.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.database.SqlCatalogTest

With the test MySQL and `-Dmysql.root=yes` its part 5 ends by dropping `'daemoxcp_mail'@'127.0.0.1'`, the user the
other MySQL tests sign in with: in a series, run it last (on 18/11/2026 the tests after it all said "connected to
MySQL as the panel user: FAILED").

**WebRoutinesTest** — the web part's own MySQL user, on the test MySQL as
its root. The migration (WebDbAccess): the locked owner of the procedures, the 40 procedures, the web
user with EXECUTE on its 39 and nothing else, the role permissions, its password in the web's secrets
file and the panel user's moved to root's; a second run changes nothing; a dropped procedure, a table
privilege given by hand, a changed password, an unlocked owner are put back. The web user by itself: no
table, no helper, no DDL; the public procedures answer; the others need a live session (not expired,
not idle, administrator active) whose role allows it; only the settings the web reads. The web part's
connection used like the handlers use it: the same answers as the panel user's, new ids, rows touched,
a transaction of four procedures, no DKIM private key, a viewer and an operator stopped where their role
stops, the session check of every request. Planting a procedure that ignores the role makes it fail.

    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.database.WebRoutinesTest

**VaultKeysTest** — the asymmetric vault of the mailbox password copies, as root
in a test folder: the key pair generated once, the private key only in root's secrets file and the public one in
the web part's, a lost or wrong public key written again from the private one; a copy is "v2:", different every
time, opens back, and does not open with one byte changed or with another pair; as the web part it encrypts but
decrypts nothing and exports no key; a copy of before (master.key) still opens; with the test MySQL, in a database of
its own, the copies of before encrypted again at start (the second time nothing) and a rotation that keeps the
previous private key. A vault that decrypts outside root, or a private key not kept to root's file, makes it fail.

    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.VaultKeysTest

**MailDbUsersTest** — Postfix and Dovecot with their own MySQL users, without MySQL.
The connection read from the files exactly as both installers and both Dovecot versions write them, rewritten
changing only user and password; files the panel did not write (another host, database or user, a setting twice, a
continuation line, quotes) not read as the panel's. The switch with fake services in a temporary folder: the new
user in every file, the mode kept, a second run touching nothing; postmap failing after the change, a Postfix
reload failing, Dovecot's lookup failing, MySQL not seeing Dovecot's new user, doveconf refusing, a Dovecot reload
failing each put that service's files back byte for byte; a map that already fails, Dovecot not running, a file of
someone else and a symbolic link are left alone.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MailDbUsersTest

**MailDbUsersMysqlTest** — the same users on the test MySQL, as its root: both host names, only their columns and
no table, database or global privilege; a second run changes nothing. Each user over its own connection: the lookups
of its files give the right rows; the password hashes, the vault copies, the DKIM keys, the administrators and every
write refused. An extra table or global privilege taken away, a column given again (and really readable: MySQL 8.4
needs the privileges reloaded), a changed password set again. The whole migration with fake services: the user and
password written in the files really enter MySQL; with MySQL root refused the files stay as they were.

    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MailDbUsersMysqlTest

**UpdateManagerSqlTest** — the update manager's questions to MySQL through JDBC, on
the test MySQL: every statement it uses answers as the mysql client did (one row per line, the columns separated by a
tab, "" when MySQL refuses), as the panel's user and as root; an address with a quote is a value and finds nothing;
the panel's user cannot read MySQL's accounts; a text outside the catalog and a wrong password give "".

    java $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.UpdateManagerSqlTest

**MysqlRootTest** — MySQL's root password (MysqlRoot), as root on the VM with `-De2e.vm=yes`: a throwaway MySQL of
its own (root without a password, as on the servers installed before) and a secrets folder of its own, set before
anything else. The mysql client gets only statements of the catalog; the repair sets the password through JDBC (host
and password as parameters), then root does not get in without it from the socket or from TCP; the second time it
does nothing; a password set by hand is never replaced; two root accounts are fixed; with a secrets file that cannot
be written MySQL is not touched.

    java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.database.MysqlRootTest

**RoundcubeDbUserMysqlTest** — the webmail moved to its own MySQL user (RoundcubeDbUser) against the test MySQL as its
root: the catalog statements run by MySQL, the privileges read back with SHOW GRANTS,
a small fake webmail that writes its session into the real session table. It succeeds (roundcube with everything on
its database and nothing else, the panel's user without it from both hosts); php-fpm with the old configuration and
something still entering as the panel after the revoke go back (the panel gets its database again, roundcube
dropped); the scripts of before get their old password back on a fault; a roundcube account with more, or a panel
with only part of the database, are left alone. A way back that forgets the panel's privileges makes it fail.

    java -Dmysql.port=33062 -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RoundcubeDbUserMysqlTest

**PanelDbPasswordTest** — the password of the panel's MySQL user changed once (reperto 232): on old servers it sat for
years in Roundcube's config.inc.php. Against a fake MySQL with a primary and a secondary password per account (RETAIN
CURRENT PASSWORD, DISCARD OLD PASSWORD, 127.0.0.1 landing on localhost) and the real PendingDbPassword.settle: the
change (both local accounts, the old password refused, another host's account untouched, the copies rewritten, the
state "done" without any password in it, nothing the second time); what does not start and changes nothing (done
already, no password, an installation's password waiting, MySQL not answering, the password still in a service's file,
a second password not ours, a short new password); RETAIN refused or MySQL not taking both: back to the old password
alone, then done; DISCARD refused: finished at the next run; killed before any RETAIN, after the first, before the
panel adopts: the next start always ends with one password, the panel's, not the old one; putting MySQL back failing;
the file helpers (a service file blocks, a backup name, a link and the copies do not; a copy gets the new password with
its mode minus others); MySQL errors reduced to their code. Any user, no system.

**PanelDbPasswordMysqlTest** — the same against the test MySQL as its root, with the real catalog statements and logins:
a test user `pdptest` with two local accounts; the change (the new password gets in, the old one gets 1045, no second
password in mysql.user, nothing the second time), RETAIN refused on localhost (back as it was), and killed before the
panel adopts (settle adopts the new one, the run finishes it). It refuses port 3306 and drops `pdptest` at the end.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelDbPasswordTest
    java -Ddaemoxcp.mail.mysql.port=33062 -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelDbPasswordMysqlTest

**RootDistrustsDataTest** — the root part does not trust the names it reads from MySQL, which the
web part can write. Names planted straight into MySQL, as a
broken-into web part would: SafeNames' shapes; DKIM key paths with ".." or a quote refused; Sieve with
a mailbox ".." refused and nothing written (as root); the mail configuration script leaving out a
domain with a command in its name and a mailbox "..", the good ones between quotes and sh -n happy
(test MySQL); the certificate's DNS challenge check not running a command planted in the saved
record name (test MySQL, as root). With the jar before the fix both planted commands reached root.

    java -De2e.vm=yes $P -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.RootDistrustsDataTest

**RootGateTest** — the root part's closed list (RootGate), before any handler: routes and methods, the
shape of every value (control characters, field names, lengths, nesting), the strict shapes of the
fields that end up in commands and configurations (a host name starting with a dash, an IP with a
command after it, jails, ports, packages, services, countries, logs, PEM blocks with something else
inside); from the project folder, every call the pages make to a root route uses a method in the list.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.RootGateTest

**WebPartShellTest** — in the web part Shell runs no system command except dig, sendmail, postconf -h
and hostname: the root part's commands are refused through Shell.run, Shell.runShell and applyPath, the
web part's own pass.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.util.WebPartShellTest

**HeadRequestTest** — HEAD on the real server, without MySQL. Before, every handler sent the body's
length and then wrote the body: Java's HTTP server logged a warning for the length and refused the
write, and the sign-in page logged it as SEVERE (seen on the real server with one `curl -I`). Now a
HEAD is a GET without a body for every filter and handler (HeadExchange): the sign-in page, a script
of it, a Font Awesome file, a protected page (sends to the sign-in like the GET), an API without a
session, a wrong Host; each with the GET's status, no body, the GET's length in Content-Length, and
nothing logged. With the jar before the fix it fails.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.webserver.HeadRequestTest

**PanelSeparationTest** — the root part's preparation: a user daemoxcp_mail that is not the panel's
(another comment, home or shell, a password, uid 0, another group, other members in the group) is
refused with its reason; the daemon(8) line; as root on the VM, a folder opened to the web part is
0750 root:daemoxcp_mail with its data files 0640, every other file only root's and back in root's group,
and a symbolic link where a data file should be is refused.

**separation-service-test.sh** — the separated panel as the real service on the VM, as root, with
the jar to test installed in the panel folder and the compiled tests in a folder daemoxcp_mail can read:

    sh tests/separation-service-test.sh /home/panel /var/tmp/sep-tests

Who runs what and who listens (the web part as daemoxcp_mail on 2096, the root part on no port), every
shared file's permissions, what daemoxcp_mail can and cannot read or write, a sign-in with a console code
and the API through the web part, the routes the web part serves by itself (a test domain and mailbox
added and removed, their mail folders made by the root part as vmail, the password read back from the
vault by the web part), requests forged on the real socket, a second start with no DONE and no WARNING; then the planted faults, each put back: the user daemoxcp_mail someone else's, the jar
unreadable by daemoxcp_mail, the web part killed every time it starts (the panel goes back to serving
everything as root), the root part killed with -9 (the next start stops the web part left behind).

**CsrfFilterTest** — the CSRF token checked once for all the routes (the filter of
SSLMailServer.context), on the real server. Twenty-five authenticated routes accepted POST without
asking for it; the probe is one of them, /api/timezone-diag, with a request the handler refuses
without touching anything: without a token 403, with the X-CSRF-Token header or with the csrf_token
field it reaches the handler, which reads the same body; a wrong header wins over a right token in
the body; without a session the handler answers (401); GET and the routes used before signing in
are not touched; every refusal in the audit log.

**english-pages-browser-test.js** — the translated pages in Chromium, IN ENGLISH, with a simulated
server that answers every API plausibly (and in English). For every page: the scripts run without
errors, <html lang="en">, and the visible text after the scripts have filled the page, plus title,
aria-label and placeholder, has no Italian words left. For the DNS page a domain is chosen, the
check, the time diagnostics and the autodns, autoconfig and MTA-STS tabs. Every API the page calls
must have a simulated reply: an unknown call still gets `{ success: true }`, but the page fails. A
bare reply hides the fields the page reads, and the error that follows looks like the page's fault
(Settings and `GET /api/ssh-keys`, red from #116 until it was added; reperto 194). On the Security page the Fail2ban
checks answer a second time with a jail that could not be read (reperto 200): the reason and what to do, no "if you
do not fix it", no fix and no "fix all", "Not everything could be checked" on top, and "not checked" in words.

**pkg-simulation-test.sh** — the simulation on a COPY of pkg's database, against a fake pkg that
keeps the "locks" as files in `$FAKE_DB/locked`. It shows that the unlock happens in the copy and
not in the real database, that the protected dependencies named by pkg are added only if they can
be unlocked, and that the copy disappears at the end (the `simulation` mode of PackagePlanTest);
then the family twin, protected mysql84-client and postfix-mysql to upgrade, in its two cases
(`family-new-catalog`, `family-real-conflict`).

**MtaStsOldLogicTest** — the classification logic as it was before the fix, put in front of the
same two cases. It serves to show that MtaStsTest's checks are not decorative: here they must fail.
If one day this one passes too, it means the test is no longer verifying anything.

**RoundcubeUserTest** — Roundcube from php-fpm's `www` pool (nginx's user) to the `roundcube` pool
(RoundcubeUser.migrate), in a folder of `/var/tmp` with real files, owners and permissions and with
fake php-fpm, nginx and webmail; the fake php-fpm, reloaded, runs the pools it finds in the files.
For every step that can go wrong a planted fault (php-fpm -t, nginx -t, the two reloads, the www
pool that stays, the webmail not answering, a file with `chflags schg`), and the migration must put
EVERY file back as it was, compared with a picture of content, owner, group and permissions. Then
the refusals, the link put in `logs` (not followed), the second time, the drifts (Roundcube updated
putting `logs` back to `www`, php84 copying `www.conf.default` again) and the three install
scripts. It touches real owners and creates the `roundcube` user: **as root, on the VM**.

**AcmeUserTest** — acme.sh from `/root/.acme.sh` to the `acme` user (AcmeUser.migrate) in temporary
folders, with fake pkg, cron and `--list` and a fault for every step (the package that does not
install, a certificate acme.sh does not see, the cron that cannot be read or rewritten,
`/root/.acme.sh` that does not move); the HTTP challenge's door (tokens, paths outside the folder,
links, methods); and the real run as `acme` (user, home, empty environment, Cloudflare's token
arriving, `acme.sh --version`). This last part wants the `security/acme.sh` package and is skipped,
saying so. **As root, on the VM.**

**ServiceUsersTest** — the check of who runs every service (ServiceUsers.examine) on the VM's `ps`
output before and after, with a planted fault for every warning and the cases that must NOT warn
(Postfix's `local`, Dovecot's `auth`). Dovecot's `anvil` as root warns on 2.3 and not on 2.4, which needs it to reach
every session's process (measured on the VM, reperto 213); `auth-worker` as root warns on both. And what every user of
a service does (reperto 228, the owner asked for it on 15/11/2026): the processes of each user by a short name (Dovecot:
root master/log/config/lmtp, dovecot anvil/auth/auth-worker, dovenull imap-login, vmail imap; Postfix: root master and
local, postfix the rest; the panel's root part and web part; mysqld and mysqld_safe, not sh), root first on the page,
sievec listed although it runs only when rules are saved, and a sentence in both languages for every user the panel
installs (none for a user it does not know). It calls nothing.

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.RoundcubeUserTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.security.AcmeUserTest
    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ServiceUsersTest

**ErrorTextTest** — what an exception says to the page (ErrorText, reperto 231). The routes used to put
`e.getMessage()` of any exception in the answer: a MySQL duplicate showed the table and the key, a missing file its
path. Now only an error already translated for the page passes: ShownException (and ShownException.Argument, an
IllegalArgumentException, both TranslatedError) and PasskeyException's key. Any other exception, also an
IllegalArgumentException or IllegalStateException with an English text written in the code or wrapping another one,
an IOException with a path, an SQLException naming a table, a NullPointerException or no message give the generic
text, with one WARNING line in the log carrying the route's method and the exception; a MySQL duplicate (1062, also wrapped) says "it
already exists" without the key. Then in the sources: no route answer of SSLMailServer and no "success" answer of
UpdateManager puts `getMessage()` by itself. It calls nothing; run from the project root (it reads `src/`).

    java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.util.ErrorTextTest

## The panel's emails

`PanelMailTest` tests the envelope (sender, subject in RFC 2047, quoted-printable, headers) and the
content of the report and of the codes in both languages, without touching the system; on the VM
it also checks that the server's name comes from Postfix and not from hostname(1). With
`-Dpanelmail.dump=<folder>` it writes the composed messages as `.eml`, to open in a mail program.

`PanelMailE2ETest` sends real mail: the report and the three code emails, through Postfix's
sendmail, to a mailbox of the server; then it finds them again in the Maildir and checks the
message as it arrived. Only on a test machine, with `-De2e.vm=yes`:

    java -De2e.vm=yes -Dpanelmail.to=alice@rehearsal.test \
         -Dpanelmail.maildir=/var/vmail/rehearsal.test/alice -Dpanelmail.copies=/var/tmp/panel-emails/copies \
         -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PanelMailE2ETest

**PfListTablesTest** — the allow and block lists of the Firewall page in pf. Found walking every function of the
0.9.0 panel (18/11/2026): the last address taken off a list stayed in pf until a restart, because an empty list was
written as `table <x> persist` with no braces and pf keeps a table's contents when the anchor is loaded again with
such a line. The line of an empty list is `{ }`; on the VM, as root (`-De2e.vm=yes`), the real pfctl in an anchor no
rule uses: loaded again as an empty list the table is empty, with the line of 0.9.0 it keeps the address.

