/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║                         FreeBSD Mail Panel                                    ║
 * ║                    Native Mail Server Control Panel                           ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  A complete mail server solution for FreeBSD 15+, similar to Mailcow but     ║
 * ║  100% native (NO Docker).                                                     ║
 * ║                                                                               ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                           MAIL SERVER STACK                                   ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  ┌───────────────────────────────────────────────────────────────────────┐   ║
 * ║  │                         SMTP: Postfix                                 │   ║
 * ║  │  ═══════════════════════════════════════════════════════════════════  │   ║
 * ║  │  • Postfix with MySQL virtual users                                  │   ║
 * ║  │  • Ports: 25 (SMTP), 587 (Submission), 465 (SMTPS)                    │   ║
 * ║  │  • Service: postfix                                                   │   ║
 * ║  │  • Config: /usr/local/etc/postfix/main.cf                             │   ║
 * ║  │  • MySQL tables for virtual domains/users/aliases                     │   ║
 * ║  │  • Rspamd integration via milter (port 11332)                         │   ║
 * ║  │  • LMTP delivery to Dovecot (port 24)                                 │   ║
 * ║  └───────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                               ║
 * ║  ┌───────────────────────────────────────────────────────────────────────┐   ║
 * ║  │                        IMAP/POP3: Dovecot                              │   ║
 * ║  │  ═══════════════════════════════════════════════════════════════════  │   ║
 * ║  │  • Ports: 143 (IMAP), 993 (IMAPS), 110 (POP3), 995 (POP3S)            │   ║
 * ║  │  • LMTP: 127.0.0.1:24 (for Postfix delivery)                          │   ║
 * ║  │  • SASL: /var/spool/postfix/private/auth (for Postfix auth)           │   ║
 * ║  │  • Mailboxes: /var/vmail/{domain}/{user}                              │   ║
 * ║  │  • Config: /usr/local/etc/dovecot/                                    │   ║
 * ║  └───────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                               ║
 * ║  ┌───────────────────────────────────────────────────────────────────────┐   ║
 * ║  │                        Anti-Spam: Rspamd                               │   ║
 * ║  │  ═══════════════════════════════════════════════════════════════════  │   ║
 * ║  │  • Ports: 11332 (milter), 11333 (worker), 11334 (web UI)              │   ║
 * ║  │  • Config: /usr/local/etc/rspamd/                                     │   ║
 * ║  │  • ClamAV integration for virus scanning                              │   ║
 * ║  └───────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                               ║
 * ║  ┌───────────────────────────────────────────────────────────────────────┐   ║
 * ║  │                        Antivirus: ClamAV                               │   ║
 * ║  │  ═══════════════════════════════════════════════════════════════════  │   ║
 * ║  │  • Socket: /var/run/clamav/clamd.sock                                 │   ║
 * ║  │  • Services: clamav_clamd, clamav_freshclam                           │   ║
 * ║  │  • Integrated with Rspamd                                             │   ║
 * ║  └───────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                               ║
 * ║  ┌───────────────────────────────────────────────────────────────────────┐   ║
 * ║  │                        Database: MySQL 8.0                             │   ║
 * ║  │  ═══════════════════════════════════════════════════════════════════  │   ║
 * ║  │  • Port: 3306                                                         │   ║
 * ║  │  • Database: mailpanel                                                │   ║
 * ║  │  • Tables: domains, mailboxes, aliases                                │   ║
 * ║  │  • Postfix uses MySQL directly (no file sync needed)                  │   ║
 * ║  └───────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                               ║
 * ║  ┌───────────────────────────────────────────────────────────────────────┐   ║
 * ║  │                           Cache: Redis                                 │   ║
 * ║  │  ═══════════════════════════════════════════════════════════════════  │   ║
 * ║  │  • Port: 6379                                                         │   ║
 * ║  │  • Used by Rspamd for caching                                         │   ║
 * ║  └───────────────────────────────────────────────────────────────────────┘   ║
 * ║                                                                               ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                           SSL CERTIFICATES                                    ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║  • Path: /usr/local/etc/ssl/mail/                                            ║
 * ║  • fullchain.pem - Certificate + intermediate chain                          ║
 * ║  • privkey.pem   - Private key                                               ║
 * ║  • Self-signed generated on install, replace with Let's Encrypt              ║
 * ║                                                                               ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                           PANEL CONFIGURATION                                 ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║  • SQLite: ./database/mailpanel.db - Panel settings only                     ║
 * ║  • MySQL: Mail data (domains, users, aliases)                                ║
 * ║  • Web panel: HTTPS on port 2096 (configurable)                              ║
 * ║  • Terminal GUI: Lanterna library                                            ║
 * ║                                                                               ║
 * ╠══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║                    ╔═══════════════════════════════════╗                      ║
 * ║                    ║  IMPORTANT: We use Postfix with   ║                      ║
 * ║                    ║  MySQL virtual users.             ║                      ║
 * ║                    ║                                   ║                      ║
 * ║                    ║  Postfix delivers to Dovecot      ║                      ║
 * ║                    ║  via LMTP on port 24.             ║                      ║
 * ║                    ╚═══════════════════════════════════╝                      ║
 * ║                                                                               ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 *
 * @author FreeBSD Mail Panel Team
 * @version 1.0
 */
package org.mail_panel;
