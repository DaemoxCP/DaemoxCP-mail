# Rehearsing the upgrade from an old version

> Since 2026-11-17 the panel is called DaemoxCP Mail: service `daemoxcp_mail`, folder `/var/db/daemoxcp-mail`, jar
> `daemoxcp-mail.jar`. These tools rehearse the upgrade from the earlier versions, which still have the `mailpanel`
> names: `check-state.sh`, `photo.sh` and the Roundcube scripts find either one; `upgrade-phase.sh` stays the one of
> 2026-10-31, for the panel of 2026-10-11. Today's upgrade is rehearsed with `tools/upgrade/upgrade-panel.sh`.

Tools to redo on the test VM what happens on a server already running when the new panel is put on it. First used on
2026-10-31, with the jar of the production mail server (commit 419b0a2, 2026-10-11): findings, item 112.

They are not in `tests/` because the two drivers are compiled against the OLD jar: they call its classes by the names
they had then (`ProtezioneWeb`, `MtaSts.impostaModo`, ...), while the full suite compiles everything it finds in
`tests/` against today's jar.

## The pieces

- `src/org/mail_panel/RehearsalOldInstall.java`: the installation as that version's menu did it. Arguments: the mail
  name, the Roundcube domain.
- `src/org/mail_panel/RehearsalOldSetup.java`: what a real server has on top of that:
  - the panel's certificate and the first administrator;
  - a domain with two mailboxes, with their test credentials in `/root/rehearsal/mailboxes`, readable by root only;
  - the surface on port 443 with MTA-STS in enforce mode, and its jail;
  - the startup script.
- `check-state.sh DOMAIN`: the state to compare before and after:
  - the file names;
  - the startup script;
  - nginx and MTA-STS on 443;
  - fail2ban and pf;
  - Postfix as the local MTA;
  - the services;
  - a mailbox login and a delivery.
- `upgrade-phase.sh JAR LABEL DOMAIN`: the upgrade as a person does it. It stops the service, swaps the jar, restarts
  with the existing script, then restarts a second time. The state of the two starts goes to `/root/rehearsal/LABEL`.
  Since 2026-11-05 the upgrade is rehearsed instead with the production script, `tools/upgrade/upgrade-panel.sh`,
  which does the same and stops by itself.
- `server-leftovers.sh`: what the production server has that the test bench does not: two certificates with the DNS
  challenge and the Italian names left in `/var/db/mailpanel` (findings, item 135).
- `photo.sh take|restore`: the snapshot of the bench, that is a boot environment holding copies of `/home/panel` and
  `/var/log`, which are outside the boot environments.

## How it is done (redone on 2026-11-05, findings item 135)

On the clean VM the owner restores, work happens on `default` (the owner keeps the clean copies). Everything as root on
the VM, except building the jars.

1. **The old jar.** On the Mac, `git archive 419b0a2 | tar -x -C <folder>` and `mvn -B -o -q package -DskipTests`
   (sha256 `957886b5...`; the server's, `6303a647...`, only adds the changes to the updater). It goes to
   `/home/panel/freebsd-mail-panel-1.0.jar`.
2. **The drivers and the certificate.** Only the two `RehearsalOld*`: `RehearsalCurrentSetup` is compiled against
   `main`'s jar, not this one.

   ```sh
   javac --release 25 -cp /home/panel/freebsd-mail-panel-1.0.jar -d classes src/org/mail_panel/RehearsalOld*.java
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /usr/local/etc/ssl/mail/privkey.pem \
       -out /usr/local/etc/ssl/mail/fullchain.pem -subj "/CN=mail.rehearsal.test"
   ```
3. **The installation of 2026-10-11**, from `/home/panel`:
   `java -cp freebsd-mail-panel-1.0.jar:classes org.mail_panel.RehearsalOldInstall mail.rehearsal.test webmail.rehearsal.test`.

   The driver changes two package names in the script, because with today's catalogue:
   - `postfix-mysql` brings `mysql84-client`, which removes `mysql80-server` already in the packages phase, before
     MySQL ever started. The script still says "success", but there is no database. On 2026-10-31 the server was
     removed later;
   - `dovecot-pigeonhole` leaves lmtp without sieve.

   The production server has `mysql84-server` and `dovecot-pigeonhole-mysql`, and those are the two lines changed.
4. **fail2ban and pf**, as the server has them (the old version installed fail2ban from its page). `/etc/pf.conf` is
   the one today's installer writes (table `<permaban>`, anchor `f2b/*`, `pass`), with `/var/db/mail-panel/permaban.list`
   empty:

   ```sh
   pkg install -y py312-fail2ban && sysrc fail2ban_enable=YES pf_enable=YES
   service fail2ban start && service pf start
   ```
5. **`RehearsalOldSetup mail.rehearsal.test rehearsal.test`**, from `/home/panel` with the same classpath.
6. **Like the server**, looked at read-only on 2026-11-05:
   - **the locked packages.** The same 40 as the server, `pkg lock -y` on the installed ones:
     `clamav dovecot-mysql dovecot-pigeonhole-mysql mysql84-client mysql84-server nginx openjdk25
     php84 php84-ctype php84-curl php84-dom php84-exif php84-extensions php84-fileinfo
     php84-filter php84-gd php84-iconv php84-intl php84-ldap php84-mbstring php84-mysqli
     php84-opcache php84-pdo php84-pdo_mysql php84-pdo_sqlite php84-phar php84-posix php84-session
     php84-simplexml php84-sqlite3 php84-tokenizer php84-xml php84-xmlreader php84-xmlwriter
     php84-zip postfix-mysql py312-fail2ban redis roundcube-php84 rspamd`. On the bench they are 39: `php84-ldap` is
     not there;
   - **the hash of Dovecot's master user.** The server has it, today's installations do not:

     ```sh
     K=$(head -1 /var/db/mailpanel/dovecot_master.key)
     printf "admin:%s\n" "$(printf "%s\n%s\n" "$K" "$K" | doveadm pw -s BLF-CRYPT)" > /usr/local/etc/dovecot/master-users.new
     chown root:dovecot /usr/local/etc/dovecot/master-users.new && chmod 640 /usr/local/etc/dovecot/master-users.new
     mv /usr/local/etc/dovecot/master-users.new /usr/local/etc/dovecot/master-users
     ```
   - **acme.sh as root**, as `get.acme.sh` installed it. The program, with `dnsapi`, `deploy` and `notify`, is taken
     from the package without installing it (`pkg fetch -o DIR acme.sh`, then `tar -xf` of the `.pkg`). Then:

     ```sh
     HOME=/root ./acme.sh --install --home /root/.acme.sh --accountemail admin@rehearsal.test
     /root/.acme.sh/acme.sh --home /root/.acme.sh --set-default-ca --server letsencrypt
     ```

     `--install` also writes the line in root's cron. The account and the certificate are made locally, because
     `mail.rehearsal.test` cannot be validated:
     - `ca/acme-v02.api.letsencrypt.org/directory/` with `account.key` (EC), `account.json` and `ca.conf`;
     - `mail.rehearsal.test_ecc/` with an EC key, `.csr`, a self-signed `.cer`, `ca.cer`, `fullchain.cer`,
       `.csr.conf` and the `.conf` with the `Le_*` fields acme.sh writes.

     In the end `acme.sh --list` must list the certificate;
   - **`server-leftovers.sh`**: the second certificate, the DNS challenges and the Italian names left behind.
7. **The state before.** `service mailpanel start`, then `check-state.sh rehearsal.test` and `roundcube-db-state.sh`
   (since PR 91).
8. **The snapshot:** `photo.sh take rehearsal-october-11`.
9. **One phase per version**, each one from the snapshot:
   - `photo.sh restore rehearsal-october-11 <clone>`, then `shutdown -r now`;
   - wait until the clone shows the `N` flag in `bectl list`: right after the restart the old machine may still
     answer;
   - `tools/upgrade/upgrade-panel.sh -m alice@rehearsal.test -p <file> <jar> <sha256>`.

   Careful: `/root` is inside the boot environment. The tools and jars copied after the snapshot must be kept outside
   (`/var/tmp`) and put back in every clone.

## Careful: the bench is no longer "before" (2026-10-31, superseded by the bench of 2026-11-05)

Since the evening of 2026-10-31 `rehearsal-before-healthy` already contains the upgrade of PR 89: there is
`/root/rehearsal/after-branch` (21:56), the startup script writes `panel.log`, nginx includes
`mailpanel-public.conf`. The "2026-10-11" state is only in the two shared folders of `before2/`, and put on top of
this boot environment they do not agree (the old jar on files already renamed, nginx's logs with the old name next to
the new one: `BOTH_NAMES`).

For a test about something else it is fine as it is, with `main`'s jar (73bfbcd) in `/home/panel` as "before" and
without putting nginx's logs back: it is how PR 84 to PR 89 leave the production server. The test of the services'
users was done that way (findings, item 116). To redo the upgrade from 2026-10-11 the bench has to be rebuilt.

## The bench with today's jar (2026-11-05)

For the tests that are not about the upgrade from 2026-10-11, "before" is made with `main`'s jar on a clean VM
(findings, item 124):
1. `InstallFromScratch` of `main`'s commit, compiled against its jar, in `/root/panel`;
2. `src/org/daemoxcp/mail/RehearsalCurrentSetup.java`, compiled against the same jar and run from `/root/panel`:
   certificate, administrator, `rehearsal.test` with alice and bob, the startup script (it points to `/root/panel`,
   inside the boot environment: nothing to put back in `/home`);
3. `sysrc mailpanel_enable=YES` and `service mailpanel start`.

Two more tools:
- `roundcube-db-state.sh`: who logs in to MySQL for the webmail, the accounts with privileges, who reads what, the
  login page, a real login of alice from the form, and the hash of Dovecot's master user. It prints no password: for
  each one it says whose it is;
- `roundcube-db-faults.sh plant|clear NAME`: the faults planted for RoundcubeDbUser. Two of them (`users-trigger`,
  `session-update`) do not break the webmail, and the migration says so: they stayed as an example of a fault that
  was not one.

Careful: starting the panel locks the packages, and afterwards the installer cannot reinstall them. To redo an
installation on top of the bench: `pkg unlock -a -y` first.
