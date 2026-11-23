
        // ---------- the panel's state, in Home ----------
        // There are no buttons here that ACT: those are in Updates, in a single
        // place. Two copies of the same command diverge, and the copy that is pressed rarely
        // falls behind: it is the defect we removed all day long. Here one reads and is
        // sent elsewhere.
        async function homeApi(action) {
            try {
                const res = await fetch('/api/updates', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: action,
                        csrf_token: document.getElementById('csrf_token').value })
                });
                return await res.json();
            } catch (e) {
                return { success: false, error: t('common.networkError', { message: e.message }) };
            }
        }

        function homeEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        // It loads by itself: it is two shell commands, it is light. And it is the thing that matters
        // most, because the DKIM rotation scheduler, the certificate renewal and the periodic report
        // live inside the web server: if the panel does not come back up, those
        // stop where they are and nobody reports it.
        async function homeState() {
            const el = document.getElementById('home-startup');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + homeEsc(t('hs.reading')) + '</span>';
            const r = await homeApi('rc_state');
            if (!r || r.success === false) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>'
                             + homeEsc((r && (r.reason || r.error)) || t('hs.notChecked'))
                             + '</div>';
                return;
            }
            const ok = r.active === true;
            // The text is written by the server, in "reason": no second one is composed here.
            //
            // Before, this line prepended a title ("After a server restart the panel
            // comes back up by itself") and then appended reason, which said the same thing in
            // other words: on screen the sentence appeared twice in a row. Two places that write
            // the same sentence are two places that will one day write it differently.
            el.innerHTML = '<div class="alert alert-' + (ok ? 'success' : 'warning') + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (ok ? 'check-circle' : 'triangle-exclamation') + ' me-1" aria-hidden="true"></i>'
                + '<strong>' + homeEsc(r.reason || (ok ? t('hs.restarts') : t('hs.noRestart'))) + '</strong>'
                + (ok ? '' : ' <a href="/diagnostics#diag-os" class="alert-link">' + homeEsc(t('hs.goOs')) + '</a>')
                + '</div>';
        }

        // This one does NOT: it makes two downloads from cloudflare.com, and loading Home must not
        // depend on an external network. It is pressed when needed.
        async function homeTrust() {
            const el = document.getElementById('home-trust');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                         + homeEsc(t('hs.comparingCf')) + '</span>';
            const r = await homeApi('cf_intervals');
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>'
                             + homeEsc((r && r.error) || t('hs.checkFailed')) + '</div>';
                return;
            }
            const missingOnes = r.missing || [], extraOnes = r.extra || [];
            const cls = missingOnes.length ? 'danger' : (extraOnes.length ? 'warning' : 'success');
            el.innerHTML = '<div class="alert alert-' + cls + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (cls === 'success' ? 'check-circle' : 'triangle-exclamation') + ' me-1" aria-hidden="true"></i>'
                + homeEsc(r.note) + ' <a href="/diagnostics#cf-body" class="alert-link">' + homeEsc(t('hs.seeList')) + '</a></div>';
        }

        document.addEventListener('DOMContentLoaded', () => {
            if (document.getElementById('home-startup')) {
                homeState();
                const f = document.getElementById('home-trust');
                if (f) f.innerHTML = '<button class="btn btn-sm btn-outline-secondary" data-on-click="homeTrust()">'
                    + '<i class="fas fa-user-shield me-1" aria-hidden="true"></i>' + homeEsc(t('hs.checkCf')) + '</button>'
                    + '<div class="small text-muted mt-1">' + homeEsc(t('hs.checkCfHint')) + '</div>';
            }
        });

        // The end of support is NOT measured: it is a table copied by hand from the official
        // FreeBSD page, and the panel does not go back to reread it. Showing its date without
        // saying that it is a memory makes it look like a current measurement.
        //
        // And the case that matters is the one where the series is NOT in the table: it happens when
        // the system is newer than the snapshot, that is exactly when it should be reread. Before,
        // in that case nothing appeared, and a silence reads as "nothing to report".
        function supportLine(so) {
            const read = so.supportSourceRead ? ' <span class="text-muted">'
                        + homeEsc(t('hs.tableCopied', { date: so.supportSourceRead })) + '</span>' : '';
            if (so.knownSeries === false || !so.endOfSupport) {
                if (!so.series) return '';
                return '<div class="small text-warning"><i class="fas fa-circle-question me-1" aria-hidden="true"></i>'
                     + t('hs.unknownSeries.html', { series: homeEsc(so.series) }) + read + '</div>';
            }
            // If the date has passed or is near, say so: a date alone does not explain itself.
            let state = '';
            const p = String(so.endOfSupport).split('/');
            if (p.length === 3) {
                const q = new Date(+p[2], +p[1] - 1, +p[0]);
                const dayCount = Math.round((q - Date.now()) / 86400000);
                if (dayCount < 0) state = ' <span class="badge bg-danger">' + homeEsc(t('hs.supportEnded')) + '</span>';
                else if (dayCount < 90) state = ' <span class="badge bg-warning text-dark">' + homeEsc(tn('hs.inDays', dayCount)) + '</span>';
            }
            return '<div class="small text-muted">' + homeEsc(t('hs.endOfSupport', { series: so.series }))
                 + ' <strong>' + homeEsc(so.endOfSupport) + '</strong>' + state + read + '</div>';
        }

        // ---------- versions, restart, updates ----------
        // It loads by itself because it is fast: it reads the ALREADY downloaded catalog, it does not
        // run "pkg update" or "pkg upgrade -n". Those are on the Updates page and
        // can take minutes; a Home that keeps spinning is no longer opened by anyone.
        //
        // The price is that the numbers can be old, and this is said: next to the count
        // there is the catalog's age. A precise number derived from data three weeks old
        // looks like a measurement and is not.
        async function homeSystem() {
            const el = document.getElementById('home-system');
            if (!el) return;
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                         + homeEsc(t('hs.readingSystem')) + '</span>';
            const r = await homeApi('system_summary');
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>'
                             + homeEsc((r && r.error) || t('hs.systemNotRead'))
                             + '</div>';
                return;
            }
            const so = r.os || {};
            // The age of the data next to the data: a count without its date looks like a
            // current measurement even when it comes from three weeks ago.
            const ageText = (g, whatItem) => (g === undefined || g === null || g < 0) ? ''
                : (g === 0 ? ' <span class="text-muted">' + homeEsc(t('hs.ageToday', { what: whatItem })) + '</span>'
                           : ' <span class="' + (g > 14 ? 'text-warning' : 'text-muted') + '">'
                             + homeEsc(tn('hs.ageDays', g, { what: whatItem })) + '</span>');

            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><tbody>';
            h += '<tr><td data-style="width:15rem"><strong>FreeBSD</strong></td><td><code>'
               + homeEsc(so.userland || '?') + '</code>'
               + (so.arch ? ' <span class="text-muted small">' + homeEsc(so.arch) + '</span>' : '')
               + supportLine(so)
               + '</td></tr>';

            // Installed kernel and running kernel are two different things: if they differ a
            // restart is missing, and this is the only way to notice it.
            h += '<tr><td><strong>Kernel</strong></td><td>'
               + homeEsc(t('hs.kernelRunning')) + ' <code>' + homeEsc(so.uname || '?') + '</code>'
               + (so.installedKernel && so.installedKernel !== so.uname
                   ? ' &middot; ' + homeEsc(t('hs.kernelInstalled')) + ' <code>' + homeEsc(so.installedKernel) + '</code>' : '')
               + (so.restartNeeded
                   ? '<div class="small text-warning"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>'
                     + homeEsc(t('hs.kernelReboot')) + '</div>'
                   : '')
               + '</td></tr>';

            // Two different counts, and they must be labelled as such.
            //
            // "To update" comes from pkg version: packages with a more recent version
            // in the catalog. "Vulnerable" comes from pkg audit: packages with known CVEs.
            // They are not the same set and often do not even resemble each other: a package
            // can be vulnerable WITHOUT a fix existing, and upgradable without having
            // any vulnerability. Placed one under the other with two different numbers they
            // read as a contradiction, and whoever looks thinks that one of the two is broken.
            const n = r.toUpdate || 0;
            // The other three categories are NOT updates, and must be kept separate: counting them
            // together gave a number that no other screen confirmed.
            const others = [];
            if (r.newerThanCatalog) others.push(t('hs.newerThanCatalog.html', { n: homeEsc(r.newerThanCatalog) }));
            if (r.outsideCatalog) others.push(t('hs.notInCatalog.html', { n: homeEsc(r.outsideCatalog) }));
            if (r.notComparable) others.push(t('hs.notComparable.html', { n: homeEsc(r.notComparable) }));
            h += '<tr><td><strong>' + homeEsc(t('hs.toUpdate')) + '</strong></td><td>'
               + (n === 0 ? '<span class="badge bg-success">' + homeEsc(t('hs.none')) + '</span>'
                          : '<span class="badge bg-warning text-dark">' + n + '</span>')
               // The catalog's date is that of its publication on the pkg server: the full
               // sentence (several repositories, one without a catalog) is in the title.
               // homeEsc does not touch quotes: inside an attribute those are needed too.
               + (r.catalogDate
                   ? ' <span class="' + (r.catalogDays > 14 ? 'text-warning' : 'text-muted') + '" title="'
                     + homeEsc(r.catalogNote || '').replace(/"/g, '&quot;') + '">'
                     + homeEsc(t('hs.catalogPublished', { date: r.catalogDate })) + '</span>'
                   : (r.catalogNote ? ' <span class="text-muted" title="'
                                       + homeEsc(r.catalogNote).replace(/"/g, '&quot;')
                                       + '">' + homeEsc(t('hs.catalogNoDate')) + '</span>' : ''))
               + '<div class="small text-muted">' + t('hs.toUpdateHint.html') + ' <a href="/updates">' + homeEsc(t('nav.updates')) + '</a></div>'
               + (others.length
                   ? '<div class="small text-muted mt-1">' + t('hs.otherDiff.html') + ' ' + others.join('; ') + '.</div>'
                   : '')
               + '</td></tr>';

            const v = r.vulnerable || 0;
            h += '<tr><td><strong>' + homeEsc(t('hs.vulnerable')) + '</strong></td><td>'
               + (v === 0 ? '<span class="badge bg-success">' + homeEsc(t('hs.none')) + '</span>'
                          : '<span class="badge bg-danger">' + v + '</span>')
               + ageText(r.vulnDbDays, t('hs.database'))
               + '<div class="small text-muted">' + t('hs.vulnHint.html') + '</div>'
               + '</td></tr>';

            if (so.readyExist)
                h += '<tr><td><strong>freebsd-update</strong></td><td>'
                   + '<span class="badge bg-warning text-dark">' + homeEsc(t('hs.fuReady')) + '</span>'
                   + '<div class="small text-muted">' + homeEsc(t('hs.fuReadyHint')) + '</div></td></tr>';

            h += '</tbody></table></div>';
            el.innerHTML = h;
        }

        document.addEventListener('DOMContentLoaded', () => { homeSystem(); });
