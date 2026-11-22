# Security policy

**English** · [Italiano](SECURITY.it.md)

## Reporting a vulnerability

Please do not open a public issue for a security problem: everyone could read it before a fix exists.

Report it privately on GitHub: on the [DaemoxCP/DaemoxCP-mail](https://github.com/DaemoxCP/DaemoxCP-mail) page, *Security*, then
*Report a vulnerability*. Only the maintainer sees the report, and the conversation stays there until a fix is out.

Please include:

- the version and the build, from the panel's *Dashboard*;
- what an attacker can do, and from where: the internet, a mailbox, the webmail, the panel, a user on the server;
- the steps to reproduce it. Try them only on a server of your own, never on someone else's.

## Supported versions

| Version | Security fixes |
|---|---|
| 1.0.x | yes |

A fix comes as a new release. How to install it: [Keeping it up to date](README.md#keeping-it-up-to-date).

## What this covers

- the panel, both its parts;
- the installation and upgrade scripts;
- the configuration the panel writes for Postfix, Dovecot, Rspamd, ClamAV, Redis, MySQL, Roundcube, nginx, fail2ban
  and pf.

A vulnerability in one of those programs goes to its own project. The panel's *Updates* page installs their fixes
once FreeBSD packages them. If the panel's configuration makes such a problem worse, or exposes something it should
not, report it here.
