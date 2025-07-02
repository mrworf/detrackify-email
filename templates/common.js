document.addEventListener('DOMContentLoaded', function() {
    var opts = window.guardOptions || {};
    var enable = function() {
        var btn = document.getElementById('cont');
        if (btn) { btn.disabled = false; }
    };
    if (!opts.resolve) {
        setTimeout(enable, opts.timeout_ms || 0);
        return;
    }
    var urlElem = document.getElementById('url');
    var progress = document.getElementById('progress');
    var controller = new AbortController();
    var timer = setTimeout(function() { controller.abort(); }, opts.timeout_ms + 10000);
    fetch('/guard/resolve', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({sha: opts.sha, data: opts.data}),
        signal: controller.signal
    })
    .then(function(r) {
        if (!r.ok) {
            return r.json().then(function(j) {
                throw {status: r.status, message: j.error || ''};
            });
        }
        return r.json();
    })
    .then(function(data) {
        if (data.url && data.hash) {
            if (urlElem) { urlElem.textContent = data.url; }
            var f = document.getElementById('continueForm');
            if (f) {
                var u = document.getElementById('final');
                var h = document.getElementById('hash');
                if (u) { u.value = data.url; }
                if (h) { h.value = data.hash; }
            }
        }
    })
    .catch(function(err) {
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
    })
    .finally(function() {
        clearTimeout(timer);
        if (progress) { progress.remove(); }
        setTimeout(enable, opts.timeout_ms || 0);
    });
});
