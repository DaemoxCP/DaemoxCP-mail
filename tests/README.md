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
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/system/*.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/webserver/*.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/database/*.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/security/PasswordGeneratorTest.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/security/MtaStsRecordTest.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MtaStsTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageCatalogTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.MtaStsRecordTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PropagationWaitTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MtaStsSequenceTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AutoconfigTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MtaStsOldLogicTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.SrvRecordTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReportDeliveryTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PanelMailTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackagePlanTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageQueueTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallLocksTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PendingDbPasswordTest
    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PendingDbPasswordE2ETest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.sqli.SqliteSharedTest
    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.MysqlReconnectTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallWayBackTest
    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReinstallWayBackE2ETest
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests/planted tests/planted/org/mail_panel/scripts/FullMailServerScript.java
    java -De2e.vm=yes -cp "tests/planted:tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReinstallJobTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InterruptionWatchTest
    java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.scripts.InstallScriptsTest
    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.scripts.InstallScriptVersionTest
    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReinstallReturnE2ETest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.NoBootEnvironmentTest
    java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InterruptionReportTest
    java [-De2e.vm=yes] -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.LockMarksTest
    expect tests/menu-way-back.exp <ssh key> <clone host> <panel folder on the clone> <jar>
    expect tests/menu-reinstall-warning.exp <ssh key> <clone host> <panel folder on the clone> <jar>
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageTurnAcrossProcessesTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.util.ShellShortPathTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.AliasMessagesTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.PasswordGeneratorTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SoftwareVersionsTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AddressConversionTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PkgBranchTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ChildStdinTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.HeldUpdatesReportTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PlanDivergenceTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PlanAfterFetchTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ServiceFallTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AuditReportTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.LockTraceTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallSideEffectsTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallScriptDriftTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RestartServicesTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.ResetDatabaseTest
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/monitoring/*.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.monitoring.MailQueueTest
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/sqli/*.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.sqli.ConfigSecretsTest
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/scripts/*.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.scripts.LocalMtaTest
    sh tests/pkg-simulation-test.sh
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallPackagesTest

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
`mail_panel_lock` annotation on a package and removes it, and writes the locks note in a temporary
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

    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallScriptDriftTest

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

    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.UpdaterRobustnessE2ETest

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
    cd /home/panel && java -De2e.vm=yes -cp "<compiled tests>:<jar>" org.mail_panel.system.SignedJobsE2ETest roundcube

With `-Doutside=tree` the real run also gets a change outside its plan: a real package installed between the
inventory photo and pkg (`UpdateManager.PlanWatch.afterTaken`, null in the service), as someone running pkg from SSH.
The job must end in error naming it, with every line of the plan still where it said; with `-Doutside.when=before`
the package goes in before the job instead, and those three checks must fail (reperto 190).

`signed-jobs-browser-test.js` uses the same three cards in a real browser (Playwright with the Chrome installed on
the Mac), against the panel of the test VM through an SSH tunnel: "Check prerequisites", the plan and its
fingerprint in the card, start with the confirmation word, the log to the end. It checks that the start request
carries the fingerprint the card showed and that the job ran that one. It signs in with a console code and gives
its session the fresh confirmation with the `confirm` mode of `signed-jobs-setup.sh` (VM only). It also reports
every JavaScript error of the pages it opens.

`MenuReinstall` is not a test but the driver of the full reinstallation from the menu
(`ReinstallJob.runFromMenu`, the same function as the menu entry: it starts it detached with
daemon(8) and follows its log) on a server where the panel has already started: it unlocks the
protected packages, runs the script with the panel's turn, locks them again. It stops the mail,
empties `/var/vmail` and changes the panel's MySQL password: only on a clone of a boot environment,
and from a COPY of the panel folder if that is in `/home` (outside the boot environments). How it
was used on the VM, with the concurrency attempts halfway: reperto 154.

    cd <copy of the panel folder> && java -cp "<compiled tests>:freebsd-mail-panel-1.0.jar" org.mail_panel.system.MenuReinstall

The four tests that run real jobs (this one, `InstallScriptDriftTest`, `PackageReplacementE2ETest`,
`PostfixMapsJobsE2ETest`) remove at the end the boot environments their jobs created.

`HeldUpdatesReportTest` and `AuditReportTest` need the vulnerability database (`pkg audit -F`):
without it, they say which checks they skipped and why.

## The full installation

`InstallPackagesTest` is the test of reperto 52 (the installer put in a Dovecot without MySQL and
declared itself successful). Parts A, B and D run anywhere: the script's text, its real install
lines run against a fake pkg that drops a requested package and exits with 0 (the script must stop
there), and the updater's labels. Part C asks pkg's REAL solver for the plan of every line as on a
freshly installed machine: a copy of pkg's database with only pkg installed, the packages
downloaded into a temporary folder (~180 MB, because pkg sees file conflicts only after downloading
them), and every requested package must be in the final plan. It installs nothing and does not
touch the real database; it is turned on with `-De2e.vm=yes`, as root, on FreeBSD.

    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallPackagesTest

After an installation from scratch (`InstallFromScratch`), `mail-login-probe.sh` does a real login:
it creates a test mailbox in `login-probe.test`, tries `doveadm auth test`, an IMAP LOGIN on 993 and
an AUTH PLAIN on 587, shows the maillog lines and removes mailbox and domain. On 24/10/2026, with
the installer of before, the services were all running and it failed on all three entrances. As
root, in the panel folder:

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
    mysql -uroot -S $M/m.sock -e "CREATE DATABASE mailpanel_test;
        CREATE USER 'mailpanel'@'127.0.0.1' IDENTIFIED BY 'test-password';
        GRANT ALL ON mailpanel_test.* TO 'mailpanel'@'127.0.0.1';"
    P="-Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=test-password -Dmysql.database=mailpanel_test"
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AddressConversionTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SoftwareVersionsTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.VersionsApiTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.LanguageRoutesTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.QueueApiTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RateLimitsApiTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.CsrfFilterTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RolesTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.LoginRoutesTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.MailboxPasswordTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.LoginSecurityTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.ResetDatabaseTest

The tests default to the database `mailpanel_test` when `-Dmysql.database` is not given.

**Never on the panel's database**: AddressConversionTest's part drops and creates again all the
tables of the database it is given (VersionsApiTest, LanguageRoutesTest, QueueApiTest,
RateLimitsApiTest, CsrfFilterTest, LoginRoutesTest and MailboxPasswordTest use the tables it
leaves), LoginSecurityTest drops them and creates them again as an old installation with
passwords, and ResetDatabaseTest empties it completely, tables that are not the panel's included.
SoftwareVersionsTest instead only reads (SELECT VERSION()).

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
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D
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

    D=$(mktemp -d) && cp target/freebsd-mail-panel-1.0.jar $D/
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

**PropagationWaitTest** — waiting for propagation, with a fake clock instead of six real minutes. It
verifies the three properties that must hold: no waiting if the domains already answer, it stops as
soon as they answer, and it leaves anyway at the deadline instead of running forever.

**MtaStsSequenceTest** — the pieces born from merging the two sequences: `filter()`, the filter by
domain (exact comparison, case-insensitive: "ake.net" must not catch "domain-d.test", and a nonexistent
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

    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InterruptedJobRecoveryTest

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
entry 6, like `MenuReinstall`.

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

**packages-browser-test.js** — the Packages tab of the Updates page, with the simulated server: it
reads by itself; the summary; the warning about the stack's unlocked packages with the button to
lock them; for every row installed and catalog version, verdict on the vulnerability (text, never
HTML), lock; "Update" also on a locked package, "held" where the advisory says to wait, the panel's
JDK saying it has its own procedure (its row in "Update the server", without a button that jumps
there); Lock/Unlock with name and CSRF token. The update window: exact
plan, the steps in plain words, the button off until the package name is typed right, the request
with confirmation and fingerprint, the job followed to its outcome. And in the Updates tab the
header of a vulnerability saying the same verdict as the detail (it was "the update fixes it" above
a "the update is not enough"), with the Update button next to it.

**address-conversion-browser-test.js** — the "Turn into mailbox" (Aliases page) and "Turn into
alias" (Mailboxes page) windows: the preview, the password proposed by the generator, the mandatory
choice about the earlier mail, the address typed to confirm, the fingerprint and the CSRF token in
the requests, the token also in "Delete mailbox"; dark theme and phone.

**software-versions-browser-test.js** — Home: the Version column of "Mail services" (with the MySQL
and Redis rows), "Other software", the "to restart" notes, a version with HTML inside that stays
text, the names of the buttons for screen readers, the question before stopping a service or restarting
MySQL (cancelled, nothing starts), the CSRF token to /api/service, the re-reading after every
command; dark theme and phone, where the tables become cards.

**I18nTest** — the interface's languages (I18n) and the pages' frame (Layout). The language files
have the same keys, no empty text and the same {values} in Italian and in English; every
{{t:key}} and every t('key') of the scripts exists in both languages; no script hides the t
function behind a variable with the same name; a completed page has no placeholders left. Then the
language of a request (Accept-Language with the weights, the cookie) and the frame: the four
sections, every page served by the panel in the menu, the page you are on marked.

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
real code (webmail-roundcube-test.php): the httpapi driver with its Guzzle and the mailpanel_sso
plugin's login hook, against the panel.

**ConfigSecretsTest** — the MySQL password and the TLS private key leave the SQLite database even
on a server already started: at the first start they move to the secrets file (600, folder 700) and
the columns are emptied; what the panel saves afterwards goes into the file; a value written by an
old version wins at the next start; the PEM key comes back identical; with the file not writable
the value stays in SQLite and is read all the same; database/ 700 and mail_panel.db 600.

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
reperto 193), the package update confirmed in the panel's window with
the exact plan and its signature, the FreeBSD patch install with INSTALL PATCHES, the restart window
(what stops, the chosen delay, the time, cancelling, Escape), reads that queue up instead of
failing, 44 px touch buttons at 375 px, and no browser dialog at all.

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

**layout-browser-test.js** — the frame in Chromium: the sidebar with four sections (with the Queue,
Sending limits, Statistics and Administrators pages, which no link reached before), the entry of the
page you are on, "Section › Page" in the top bar, "Skip to content" at the first Tab, the language
change (the request with the CSRF token, the page coming back in English, the scripts' English
dictionary, and back), the language choice on the sign-in and installation pages, the menu on the
phone (it opens, takes the focus, closes with Esc and with the X), no sideways scrolling, the dark
theme.

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

    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RootChannelTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.SeparatedPanelTest
    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PanelSeparationTest
    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.SecretsSplitTest

**SqlCatalogTest** — the panel runs only the SQL of its catalog (SqlCatalog):
every statement is a fixed text; the guard (CatalogGuard) refuses any other text by every way one reaches
the driver; from the project folder, no SQL outside the catalog and every JDBC call gets a catalog
constant; the web part's list, and its procedures: one for every MySQL statement of the list, with the
session first and then the same parameters, bound to the session save the public ones, the idle time of
WebSessions, no DKIM private key and no password hash or copy out of the database save Show password's two.

    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.SqlCatalogTest

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

    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.WebRoutinesTest

**VaultKeysTest** — the asymmetric vault of the mailbox password copies, as root
in a test folder: the key pair generated once, the private key only in root's secrets file and the public one in
the web part's, a lost or wrong public key written again from the private one; a copy is "v2:", different every
time, opens back, and does not open with one byte changed or with another pair; as the web part it encrypts but
decrypts nothing and exports no key; a copy of before (master.key) still opens; with the test MySQL, in a database of
its own, the copies of before encrypted again at start (the second time nothing) and a rotation that keeps the
previous private key. A vault that decrypts outside root, or a private key not kept to root's file, makes it fail.

    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.VaultKeysTest

**MailDbUsersTest** — Postfix and Dovecot with their own MySQL users, without MySQL.
The connection read from the files exactly as both installers and both Dovecot versions write them, rewritten
changing only user and password; files the panel did not write (another host, database or user, a setting twice, a
continuation line, quotes) not read as the panel's. The switch with fake services in a temporary folder: the new
user in every file, the mode kept, a second run touching nothing; postmap failing after the change, a Postfix
reload failing, Dovecot's lookup failing, MySQL not seeing Dovecot's new user, doveconf refusing, a Dovecot reload
failing each put that service's files back byte for byte; a map that already fails, Dovecot not running, a file of
someone else and a symbolic link are left alone.

    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MailDbUsersTest

**MailDbUsersMysqlTest** — the same users on the test MySQL, as its root: both host names, only their columns and
no table, database or global privilege; a second run changes nothing. Each user over its own connection: the lookups
of its files give the right rows; the password hashes, the vault copies, the DKIM keys, the administrators and every
write refused. An extra table or global privilege taken away, a column given again (and really readable: MySQL 8.4
needs the privileges reloaded), a changed password set again. The whole migration with fake services: the user and
password written in the files really enter MySQL; with MySQL root refused the files stay as they were.

    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MailDbUsersMysqlTest

**UpdateManagerSqlTest** — the update manager's questions to MySQL through JDBC, on
the test MySQL: every statement it uses answers as the mysql client did (one row per line, the columns separated by a
tab, "" when MySQL refuses), as the panel's user and as root; an address with a quote is a value and finds nothing;
the panel's user cannot read MySQL's accounts; a text outside the catalog and a wrong password give "".

    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.UpdateManagerSqlTest

**MysqlRootTest** — MySQL's root password (MysqlRoot), as root on the VM with `-De2e.vm=yes`: a throwaway MySQL of
its own (root without a password, as on the servers installed before) and a secrets folder of its own, set before
anything else. The mysql client gets only statements of the catalog; the repair sets the password through JDBC (host
and password as parameters), then root does not get in without it from the socket or from TCP; the second time it
does nothing; a password set by hand is never replaced; two root accounts are fixed; with a secrets file that cannot
be written MySQL is not touched.

    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.MysqlRootTest

**RoundcubeDbUserMysqlTest** — the webmail moved to its own MySQL user (RoundcubeDbUser) against the test MySQL as its
root: the catalog statements run by MySQL, the privileges read back with SHOW GRANTS,
a small fake webmail that writes its session into the real session table. It succeeds (roundcube with everything on
its database and nothing else, the panel's user without it from both hosts); php-fpm with the old configuration and
something still entering as the panel after the revoke go back (the panel gets its database again, roundcube
dropped); the scripts of before get their old password back on a fault; a roundcube account with more, or a panel
with only part of the database, are left alone. A way back that forgets the panel's privileges makes it fail.

    java -Dmysql.port=33062 -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RoundcubeDbUserMysqlTest

**RootDistrustsDataTest** — the root part does not trust the names it reads from MySQL, which the
web part can write. Names planted straight into MySQL, as a
broken-into web part would: SafeNames' shapes; DKIM key paths with ".." or a quote refused; Sieve with
a mailbox ".." refused and nothing written (as root); the mail configuration script leaving out a
domain with a command in its name and a mailbox "..", the good ones between quotes and sh -n happy
(test MySQL); the certificate's DNS challenge check not running a command planted in the saved
record name (test MySQL, as root). With the jar before the fix both planted commands reached root.

    java -De2e.vm=yes $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.RootDistrustsDataTest

**RootGateTest** — the root part's closed list (RootGate), before any handler: routes and methods, the
shape of every value (control characters, field names, lengths, nesting), the strict shapes of the
fields that end up in commands and configurations (a host name starting with a dash, an IP with a
command after it, jails, ports, packages, services, countries, logs, PEM blocks with something else
inside); from the project folder, every call the pages make to a root route uses a method in the list.

    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RootGateTest

**WebPartShellTest** — in the web part Shell runs no system command except dig, sendmail, postconf -h
and hostname: the root part's commands are refused through Shell.run, Shell.runShell and applyPath, the
web part's own pass.

    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.util.WebPartShellTest

**HeadRequestTest** — HEAD on the real server, without MySQL. Before, every handler sent the body's
length and then wrote the body: Java's HTTP server logged a warning for the length and refused the
write, and the sign-in page logged it as SEVERE (seen on the real server with one `curl -I`). Now a
HEAD is a GET without a body for every filter and handler (HeadExchange): the sign-in page, a script
of it, a Font Awesome file, a protected page (sends to the sign-in like the GET), an API without a
session, a wrong Host; each with the GET's status, no body, the GET's length in Content-Length, and
nothing logged. With the jar before the fix it fails.

    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.HeadRequestTest

**PanelSeparationTest** — the root part's preparation: a user mailpanel that is not the panel's
(another comment, home or shell, a password, uid 0, another group, other members in the group) is
refused with its reason; the daemon(8) line; as root on the VM, a folder opened to the web part is
0750 root:mailpanel with its data files 0640, every other file only root's and back in root's group,
and a symbolic link where a data file should be is refused.

**separation-service-test.sh** — the separated panel as the real service on the VM, as root, with
the jar to test installed in the panel folder and the compiled tests in a folder mailpanel can read:

    sh tests/separation-service-test.sh /home/panel /var/tmp/sep-tests

Who runs what and who listens (the web part as mailpanel on 2096, the root part on no port), every
shared file's permissions, what mailpanel can and cannot read or write, a sign-in with a console code
and the API through the web part, the routes the web part serves by itself (a test domain and mailbox
added and removed, their mail folders made by the root part as vmail, the password read back from the
vault by the web part), requests forged on the real socket, a second start with no DONE and no WARNING; then the planted faults, each put back: the user mailpanel someone else's, the jar
unreadable by mailpanel, the web part killed every time it starts (the panel goes back to serving
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
(Settings and `GET /api/ssh-keys`, red from #116 until it was added; reperto 194).

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
(Postfix's `local`, Dovecot's `auth`). It calls nothing.

    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RoundcubeUserTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.AcmeUserTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ServiceUsersTest

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
         -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PanelMailE2ETest
