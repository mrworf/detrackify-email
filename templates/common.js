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
    var progress = document.getElementById('progress');

    function highlight(url) {
        var m = url.match(/https?:\/\/([^/]+)/i);
        if (m) {
            var d = m[1];
            var cls = (opts.sender_domain && d.toLowerCase() === opts.sender_domain.toLowerCase()) ? 'good' : 'bad';
            return url.replace(d, '<span class="highlight ' + cls + '">' + d + '</span>');
        }
        return url;
    }

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
            var u = document.getElementById('final');
            var h = document.getElementById('hash');
            if (u) { u.value = data.url; }
            if (h) { h.value = data.hash; }
            if (progress) {
                progress.classList.add('fade');
                progress.style.opacity = 0;
                setTimeout(function() {
                    progress.innerHTML = highlight(data.url);
                    progress.style.opacity = 1;
                }, 500);
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
        if (progress) {
            progress.classList.add('fade');
            progress.style.opacity = 0;
            setTimeout(function() {
                progress.textContent = msg;
                progress.style.opacity = 1;
            }, 500);
        }
    })
    .finally(function() {
        clearTimeout(timer);
        setTimeout(enable, opts.timeout_ms || 0);
    });
});
