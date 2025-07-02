document.addEventListener('DOMContentLoaded', function () {
    var opts = window.guardOpts || {};

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
    var result = document.getElementById('result');
    var title = document.getElementById('title');

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
                if (progress && result) {
                    progress.style.display = 'none';
                    result.innerHTML = highlight(data.url);
                    result.style.display = 'block';
                    
                    if (data.title && title) {
                        title.textContent = data.title;
                        title.style.display = 'block';
                    }
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
            if (progress && result) {
                progress.style.display = 'none';
                result.textContent = msg;
                result.style.display = 'block';
            }
        })
        .finally(function () {
            clearTimeout(timer);
            setTimeout(enable, opts.timeout_ms || 0);
        });
});
