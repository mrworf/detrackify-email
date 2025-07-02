document.addEventListener('DOMContentLoaded', function () {
    var opts = {{ opts | tojson }};

    function esc(txt) {
        return txt.replace(/[&<>]/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;'}[c] || c;
        });
    }

    function highlight(url) {
        url = esc(url);
        var m = url.match(/https?:\/\/([^/]+)/i);
        if (m) {
            var d = m[1];
            var cls = (opts.sender_domain && d.toLowerCase() === opts.sender_domain.toLowerCase()) ? 'good' : 'bad';
            return url.replace(d, '<span class="highlight ' + cls + '">' + d + '</span>');
        }
        return url;
    }

    var urlEl = document.getElementById('url');
    if (urlEl) {
        urlEl.innerHTML = highlight(urlEl.textContent);
    }

    var enable = function () {
        var b = document.getElementById('cont');
        if (b) { b.disabled = false; }
    };

    if (!opts.resolve) {
        setTimeout(enable, opts.timeout_ms || 0);
        return;
    }

    var progress = document.getElementById('progress');

    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, (opts.timeout_ms || 0) + 10000);

    fetch('/guard/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sha: opts.sha, data: opts.data }),
        signal: controller.signal
    })
        .then(function (r) {
            if (!r.ok) {
                var ct = r.headers.get('content-type') || '';
                if (ct.indexOf('application/json') === 0) {
                    return r.json().then(function (j) {
                        throw { status: r.status, message: j.error || '' };
                    });
                }
                throw { status: r.status };
            }
            return r.json();
        })
        .then(function (data) {
            if (data.url && data.hash) {
                var u = document.getElementById('final');
                var h = document.getElementById('hash');
                if (u) { u.value = data.url; }
                if (h) { h.value = data.hash; }
                if (progress) {
                    progress.classList.add('fade');
                    progress.style.opacity = 0;
                    setTimeout(function () {
                        var html = highlight(data.url);
                        if (data.title) {
                            html += '<br><span class="title">' + esc(data.title) + '</span>';
                        }
                        progress.innerHTML = html;
                        progress.style.opacity = 1;
                    }, 500);
                }
            }
        })
        .catch(function (err) {
            var msg = 'Error resolving link';
            if (err.name === 'AbortError') { msg = 'Connection timed out'; }
            else if (err.status === 404) { msg = 'Link not found'; }
            else if (err.status === 403) { msg = 'Invalid link information'; }
            else if (err.status === 500) { msg = 'Internal error'; }
            if (err.message && err.name !== 'AbortError') { msg += ': ' + err.message; }
            var box = document.getElementById('error');
            if (box) { box.textContent = msg + '. You can still continue to the original URL.'; }
            var form = document.getElementById('continueForm');
            if (form) { form.action = ''; }
            if (progress) {
                progress.classList.add('fade');
                progress.style.opacity = 0;
                setTimeout(function () {
                    progress.textContent = msg;
                    progress.style.opacity = 1;
                }, 500);
            }
        })
        .finally(function () {
            clearTimeout(timer);
            setTimeout(enable, opts.timeout_ms || 0);
        });
});
