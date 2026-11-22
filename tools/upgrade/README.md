# Upgrading the panel

**English** · [Italiano](README.it.md)

How to replace the panel running on a server with a newer release, and how to go back. There are two scripts:

- `upgrade-panel.sh` puts the new jar in place and stops at the first sign that something is wrong;
- `rollback-panel.sh` puts the server back as it was before the upgrade, without losing the mail that arrived
  in the meantime.

The mail keeps working for the whole upgrade: only the panel stops while it restarts. An upgrade restarts the
panel, so everyone signs in to it again. Some versions also reload nginx, PHP or Postfix while they start, and
the webmail may not answer for an instant.

## What you need

The script checks all of this before it changes anything, and stops if something is missing:

- a server installed as the main [README](../../README.md) describes, with the panel running as the service
  `daemoxcp_mail`;
- FreeBSD on ZFS boot environments (`bectl check` must succeed), with at least 1 GiB free in the pool;
- no `pkg` running at the same time;
- a root shell on the server.

## 1. The jar and its SHA-256

- **From a release**: download `daemoxcp-mail.jar` from the
  [release](https://github.com/DaemoxCP/mail/releases) and take its SHA-256 from the release notes. The script
  compares the two, so the SHA-256 must come from the release notes, never from the downloaded file.
- **Built by you**: on any computer with Java 25 and Maven, from the repository at the commit you want:

  ```bash
  tools/build-jar.sh
  ```

  It writes `target/daemoxcp-mail.jar`, with the build number and the commit inside (the *Dashboard* shows them),
  and prints the jar's SHA-256. Take the SHA-256 on the computer where you built it, not on the server. A jar built
  with a plain `mvn package` works too, but the *Dashboard* then says that the build is not recorded.

## 2. Copy the jar and the two scripts to the server

Use the two scripts of the same version as the jar: from the release's tag, or from your copy of the repository.
They must stay in the same folder, because `upgrade-panel.sh` tells you to run `rollback-panel.sh` from it.

On the server:

```bash
install -d -m 700 /root/panel-upgrade
```

From your computer, in the folder of your copy of the repository (write `target/daemoxcp-mail.jar` if you built
the jar):

```bash
scp daemoxcp-mail.jar tools/upgrade/upgrade-panel.sh tools/upgrade/rollback-panel.sh root@203.0.113.10:/root/panel-upgrade/
```

## 3. A test mailbox (recommended)

With `-m` and `-p` the script also tries, before and after the upgrade:

- the sign-in to the mailbox;
- a delivery to it (the test message is then deleted);
- the sign-in to the webmail with its address and password.

Create a mailbox for this on *Mailboxes*, for example `upgrade-test@example.com`. Put its password on one line in
a file that only root can read:

```bash
install -m 600 /dev/null /root/panel-upgrade/test.pass
```

```bash
ee /root/panel-upgrade/test.pass
```

The password never leaves that file: the script reads it from there and does not print it.

## 4. The upgrade

As root, with the SHA-256 from step 1:

```bash
sh /root/panel-upgrade/upgrade-panel.sh -m upgrade-test@example.com -p /root/panel-upgrade/test.pass /root/panel-upgrade/daemoxcp-mail.jar <SHA-256>
```

Without a test mailbox:

```bash
sh /root/panel-upgrade/upgrade-panel.sh /root/panel-upgrade/daemoxcp-mail.jar <SHA-256>
```

It takes a few minutes. What it does, in order:

| Step | What it does | It stops if |
|---|---|---|
| 1 | the checks | it is not run as root, or not on FreeBSD; the jar's SHA-256 is not the expected one, or the jar is not an intact archive; the panel is not running as a service; this jar is already running; there is no ZFS boot environment, or less than 1 GiB free; a `pkg` is running |
| 2 | the snapshot of the server's state: the services turned on in `rc.conf`, MySQL, the listening ports, `nginx -t`, `postfix check`, `doveconf`, fail2ban, the panel on port 2096, MTA-STS on 443, the webmail's login page, the test mailbox, the locked packages | something is already down or refused: fix that first |
| 3 | stops the panel, creates the boot environment `before-panel-upgrade-<date>`, copies the panel's folder | the panel does not stop, or `bectl` or the copy fails: it starts the previous panel again |
| 4 | puts the new jar in place and starts it, then reads the log of the start | the panel stops while starting, the start does not finish within 15 minutes, or the log has a warning, an error or an exception |
| 5 | compares the state with the snapshot | a line changed, or a package that was locked is not any more (newly locked packages are only listed) |
| 6 | restarts the panel | the log of the second start has a migration or a warning: a second start must have nothing left to do |
| 7 | compares the state with the snapshot again | as in step 5 |

The first start of a new version may run its migrations: the changes that bring an existing server in line with
the new version. The script lists them. They must all succeed, and the second start must find nothing left to do.

At the end it prints `DONE`, and what it leaves for the way back.

### The record of the upgrade

Everything the script sees goes into a folder next to the panel's, `/home/panel-upgrade-<date>/` (the date is in
UTC, and the script prints the folder's name when it begins). `/home` is outside the boot environments, so the
folder stays even after going back. It holds:

- `summary.txt`: the jars before and after, the boot environment, the outcome and the migrations;
- the snapshot and the state after each start, with their differences;
- the log of each start, and the migrations it ran;
- the copy of the panel's folder (`panel-dir.tar`) and the previous jar.

To read a log again with the same rules as the script:

```bash
sh /root/panel-upgrade/upgrade-panel.sh --check-log /home/panel-upgrade-<date>/first-start.log first
```

(`second` for the second start). It ends with `outcome: go` or `outcome: STOPPED`.

### If it stops

It prints `STOPPED`, the step and the reason, and then how to go back, with the real names of this upgrade:

- **in steps 1 to 3** the jar was not changed and there is nothing to put back. If the panel is stopped:
  `service daemoxcp_mail start`;
- **from step 4 on**, go back with `rollback-panel.sh`, as described below.

## Going back

Once the new jar has started, put the previous jar back only with `rollback-panel.sh`. Copying the old jar over
the new one is not a way back, because the new version's migrations may have changed the system in ways the
previous panel does not know.

As root, with the folder the upgrade printed:

```bash
sh /root/panel-upgrade/rollback-panel.sh /home/panel-upgrade-<date>
```

```bash
shutdown -r now
```

It does not reboot by itself, so that you choose the moment; Postfix and Dovecot stay stopped until you do.
What it does:

- **It keeps the mail.** `/var/vmail` is inside the boot environment, so a plain `bectl activate` would lose the
  mail that arrived after the upgrade. The script stops Postfix and Dovecot and copies the current mail into the
  previous boot environment; the mail that was there at the time of the upgrade stays next to it, in
  `/var/vmail.before-rollback-<date>`.
- **It activates the boot environment** created by the upgrade, for the next start.
- **It puts the panel's folder back** from its copy. The one from after the upgrade stays next to it, in
  `/home/panel.after-upgrade-<date>`.
- **It puts back what the migrations changed outside the boot environment**: the names of a few logs in
  `/var/log` and the owner of two of them. It also removes the empty system mailboxes in `/var/mail` of users
  that did not exist before.

After the restart, the whole system is back as it was at the moment of the upgrade, **MySQL included**: domains,
mailboxes and aliases created after the upgrade must be created again, so it is best to decide early. If Postfix's
queue is not empty, it goes back to the queue of that moment, and the script says so.

The way back has been tried several times on a test machine: each time the state matched the snapshot again and
the mail that arrived after the upgrade was still there. After going back, the same upgrade can be run again.

## Afterwards

- The *Dashboard* shows the new version and build.
- *Diagnostics* → *Check everything* has nothing new to report.
- On the *Diagnostics* page, *Service users* has no warnings.

When the new panel has worked for a few days, remove what the upgrade left for the way back:

```bash
bectl destroy -o before-panel-upgrade-<date>
```

```bash
rm -r /home/panel-upgrade-<date>
```

Then remove the test mailbox on *Mailboxes*, and its password file:

```bash
rm /root/panel-upgrade/test.pass
```
