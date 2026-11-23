
        // ---------- the Cloudflare ranges: the real ones against the compiled ones ----------
        // The compiled list is always drawn: it is the panel's knowledge, it does not depend on
        // cloudflare.com. It is in a function of its own because it is needed in BOTH branches: when the
        // comparison succeeds and when it fails. In fact, when it fails it is needed more, because it is
        // the only moment when nothing else can be known.
        function cfLists(r) {
            const one = (titleText, entries) => !entries || !entries.length ? ''
                : '<div class="small fw-bold mt-2 mb-1">' + escHtml(titleText) + ' (' + entries.length + ')</div>'
                  + '<div class="small" data-style="line-height:1.9">'
                  + entries.map(c => '<code class="me-2">' + updEsc(c) + '</code>').join('') + '</div>';
            return one('Cloudflare IPv4', r.listV4)
                 + one('Cloudflare IPv6', r.listV6)
                 + '<div class="small text-muted mt-2">' + escHtml(t('cfi.compiledOn', { date: r.updatedOn || '?' })) + ' '
                 + t('cfi.bitwise.html') + '</div>';
        }

        async function cfIntervals() {
            const el = document.getElementById('cf-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('cfi.downloading')) + '';
            const r = await updApi('cf_intervals');
            if (!r.success) {
                // "I could not check" is not "all good", and must not look like it.
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-2">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>' + updEsc(r.error || t('cfi.failed'))
                             + '</div>' + cfLists(r);
                return;
            }
            const missingOnes = r.missing || [], extraOnes = r.extra || [];
            const cls = missingOnes.length ? 'danger' : (extraOnes.length ? 'warning' : 'success');
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (cls === 'success' ? 'check-circle' : 'triangle-exclamation') + ' me-1" aria-hidden="true"></i>'
                  + updEsc(r.note) + '</div>';

            h += '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
               + '<tr class="upd-cell"><td data-style="width:16rem"><strong>' + escHtml(t('cfi.official')) + '</strong></td><td>'
               + updEsc(r.officialV4) + ' IPv4 &middot; ' + updEsc(r.officialV6) + ' IPv6</td></tr>'
               + '<tr class="upd-cell"><td><strong>' + escHtml(t('cfi.compiled')) + '</strong></td><td>'
               + updEsc(r.compiledV4) + ' IPv4 &middot; ' + updEsc(r.compiledV6) + ' IPv6'
               + '<div class="small text-muted">' + escHtml(t('cfi.alignedOn', { date: r.updatedOn })) + '</div></td></tr>'
               + '</tbody></table></div>';

            if (missingOnes.length) {
                h += '<div class="small fw-bold mb-1 text-danger">' + t('cfi.missing.html') + '</div><ul class="small mb-2">';
                missingOnes.forEach(c => { h += '<li><code>' + updEsc(c) + '</code></li>'; });
                h += '</ul>';
            }
            if (extraOnes.length) {
                h += '<div class="small fw-bold mb-1">' + escHtml(t('cfi.extra')) + '</div><ul class="small mb-2">';
                extraOnes.forEach(c => { h += '<li><code>' + updEsc(c) + '</code></li>'; });
                h += '</ul>';
            }
            h += cfLists(r);
            el.innerHTML = h;
        }
