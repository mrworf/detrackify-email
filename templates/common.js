document.addEventListener('DOMContentLoaded', function () {
    var opts = window.guardOpts || {};

    // Check for blocking reason from server-side (now a string)
    var blockReason = opts.block_reason || '';
    
    // Handle blocking - if there is a block reason, show blocking UI
    // More explicit check for non-empty string
    if (blockReason && typeof blockReason === 'string' && blockReason.trim().length > 0) {
        handleBlocking(blockReason);
        return; // Don't continue with normal flow
    }

    // Function to add tooltip functionality to URL elements
    function addUrlTooltip(element) {
        if (!element) return;
        
        // Get the full URL from the element's HTML content
        var fullUrl = element.textContent.trim();
        
        // Add hover functionality (desktop)
        element.addEventListener('mouseenter', function() {
            showTooltip(fullUrl, element);
        });
        
        element.addEventListener('mouseleave', function() {
            hideTooltip();
        });
        
        // Add touch functionality (mobile)
        var touchTimeout;
        var tooltipShown = false;
        
        element.addEventListener('touchstart', function(e) {
            e.preventDefault();
            if (tooltipShown) {
                hideTooltip();
                tooltipShown = false;
            } else {
                showTooltip(fullUrl, element);
                tooltipShown = true;
                
                // Auto-hide tooltip after 3 seconds
                touchTimeout = setTimeout(function() {
                    hideTooltip();
                    tooltipShown = false;
                }, 3000);
            }
        });
        
        // Hide tooltip when touching elsewhere
        element.addEventListener('touchend', function(e) {
            e.preventDefault();
        });
        
        // Add click outside to hide tooltip
        document.addEventListener('click', function(e) {
            if (tooltipShown && !element.contains(e.target) && !document.getElementById('url-tooltip')?.contains(e.target)) {
                hideTooltip();
                tooltipShown = false;
                clearTimeout(touchTimeout);
            }
        });
    }
    
    // Function to show custom tooltip
    function showTooltip(text, element) {
        // Remove existing tooltip
        hideTooltip();
        
        var tooltip = document.createElement('div');
        tooltip.id = 'url-tooltip';
        tooltip.textContent = text;
        tooltip.style.cssText = `
            position: absolute;
            background: #333;
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
            max-width: 400px;
            word-wrap: break-word;
            z-index: 1000;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
            pointer-events: none;
        `;
        
        document.body.appendChild(tooltip);
        
        // Position tooltip
        var rect = element.getBoundingClientRect();
        var tooltipRect = tooltip.getBoundingClientRect();
        
        var left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
        var top = rect.top - tooltipRect.height - 10;
        
        // Adjust if tooltip goes off screen
        if (left < 10) left = 10;
        if (left + tooltipRect.width > window.innerWidth - 10) {
            left = window.innerWidth - tooltipRect.width - 10;
        }
        if (top < 10) {
            top = rect.bottom + 10;
        }
        
        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
    }
    
    // Function to hide custom tooltip
    function hideTooltip() {
        var tooltip = document.getElementById('url-tooltip');
        if (tooltip) {
            tooltip.remove();
        }
    }

    // Initialize button progress bar animation
    var button = document.getElementById('cont');
    var progressBar = document.getElementById('button-progress');
    
    // Function to start progress bar animation
    var startProgressBar = function(duration) {
        if (button && progressBar) {
            var startTime = Date.now();
            
            // Start progress bar animation
            var updateProgress = function() {
                var elapsed = Date.now() - startTime;
                var progress = Math.min(elapsed / duration, 1);
                var remainingWidth = (1 - progress) * 100;
                
                progressBar.style.width = remainingWidth + '%';
                
                if (progress < 1) {
                    requestAnimationFrame(updateProgress);
                } else {
                    // Animation complete, enable button
                    button.disabled = false;
                    progressBar.style.display = 'none';
                }
            };
            
            requestAnimationFrame(updateProgress);
        }
    };

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

    function highlightAsPhishing(url) {
        url = esc(url);
        var m = url.match(/https?:\/\/([^/]+)/i);
        if (m) {
            var d = m[1];
            // Always highlight as bad (red) for phishing warnings
            return url.replace(d, '<span class="highlight bad">' + d + '</span>');
        }
        return url;
    }

    var urlEl = document.getElementById('url');
    if (urlEl) {
        urlEl.innerHTML = highlightAsPhishing(urlEl.textContent);
        // Add tooltip functionality to main URL display
        addUrlTooltip(urlEl);
    }

    // Function to add tooltips to all URL elements
    function applyUrlTooltips() {
        // Find all URL elements that might need tooltips
        var urlElements = document.querySelectorAll('.url-value, .result-message');
        urlElements.forEach(function(element) {
            addUrlTooltip(element);
        });
    }

    // Function to handle blocking
    function handleBlocking(blockReason) {
        // Hide the normal form
        var form = document.getElementById('continueForm');
        if (form) form.style.display = 'none';
        
        // Show the blocked state
        var blockedState = document.getElementById('blocked-state');
        if (blockedState) blockedState.classList.remove('hidden');
        // Display the block reason if present
        var reasonSpan = document.getElementById('block-reason');
        var reasonLine = document.getElementById('block-reason-line');
        if (blockReason && reasonSpan && reasonLine) {
            reasonSpan.textContent = blockReason;
            reasonLine.style.display = '';
        }
    }

    var enable = function () {
        var b = document.getElementById('cont');
        var progressBar = document.getElementById('button-progress');
        if (b) { 
            b.disabled = false; 
            if (progressBar) {
                progressBar.style.display = 'none';
            }
        }
    };

    // Handle button click to show redirecting state and prevent multiple clicks
    var button = document.getElementById('cont');
    var redirectingState = document.getElementById('redirecting-state');
    
    if (button) {
        button.addEventListener('click', function() {
            // Hide button and show redirecting state
            if (button) button.style.display = 'none';
            if (redirectingState) redirectingState.classList.remove('hidden');
        });
    }

    if (!opts.resolve) {
        // No URL resolution - start progress bar immediately with timeout
        startProgressBar(opts.timeout_ms || 2000);
        return;
    }

    var progress = document.getElementById('progress');
    var spinner = document.getElementById('resolve-spinner');
    var urlMatch = document.getElementById('url-match');
    var urlMismatch = document.getElementById('url-mismatch');
    var resultMatch = document.getElementById('result-match');
    var resultMismatch = document.getElementById('result-mismatch');
    var titleMatch = document.getElementById('title-match');
    var titleMismatch = document.getElementById('title-mismatch');

    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, (opts.timeout_ms || 0) + 10000);
    
    // Minimum display time for resolve (2 seconds)
    var minDisplayTime = 1000;
    var resolveStartTime = Date.now();

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
            // Check if the resolved URL is blocked
            if (data.block) {
                // Hide the normal resolve UI
                if (progress) progress.style.display = 'none';
                if (spinner) spinner.style.display = 'none';
                
                // Show the blocked URL message
                var urlBlocked = document.getElementById('url-blocked');
                if (urlBlocked) urlBlocked.classList.remove('hidden');
                
                // Hide the form since it's blocked
                var form = document.getElementById('continueForm');
                if (form) form.style.display = 'none';
                
                return; // Don't continue with normal flow
            }
            
            if (data.url && data.hash) {
                var u = document.getElementById('final');
                var h = document.getElementById('hash');
                if (u) { u.value = data.url; }
                if (h) { h.value = data.hash; }
                
                // Calculate remaining time to meet minimum display requirement
                var elapsed = Date.now() - resolveStartTime;
                var remainingTime = Math.max(0, minDisplayTime - elapsed);
                
                setTimeout(function() {
                    if (progress) {
                        progress.style.display = 'none';
                        
                        // Replace spinner with arrow
                        if (spinner) {
                            spinner.classList.remove('spinner');
                            spinner.classList.add('arrow-down');
                            spinner.id = ''; // Remove the spinner ID since it's now an arrow
                        }
                        
                        // Determine if URL matches sender domain
                        var urlMatchesDomain = false;
                        if (opts.sender_domain && data.url) {
                            var urlDomain = data.url.match(/https?:\/\/([^/]+)/i);
                            if (urlDomain) {
                                urlMatchesDomain = urlDomain[1].toLowerCase() === opts.sender_domain.toLowerCase();
                            }
                        }
                        
                        // Show appropriate div based on match
                        if (urlMatchesDomain) {
                            if (urlMatch) urlMatch.style.display = 'block';
                            if (resultMatch) resultMatch.innerHTML = highlight(data.url);
                            if (data.title && titleMatch) {
                                titleMatch.textContent = data.title;
                                titleMatch.style.display = 'block';
                            }
                        } else {
                            if (urlMismatch) urlMismatch.style.display = 'block';
                            if (resultMismatch) resultMismatch.innerHTML = highlight(data.url);
                            if (data.title && titleMismatch) {
                                titleMismatch.textContent = data.title;
                                titleMismatch.style.display = 'block';
                            }
                        }
                        
                        // Apply URL truncation to newly added URL elements
                        setTimeout(applyUrlTooltips, 100);
                        
                        // Start progress bar after URL resolution completes
                        startProgressBar(opts.timeout_ms || 2000);
                    }
                }, remainingTime);
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
            
            // Calculate remaining time to meet minimum display requirement
            var elapsed = Date.now() - resolveStartTime;
            var remainingTime = Math.max(0, minDisplayTime - elapsed);
            
            setTimeout(function() {
                if (progress) {
                    progress.style.display = 'none';
                    
                    // Replace spinner with arrow
                    if (spinner) {
                        spinner.classList.remove('spinner');
                        spinner.classList.add('arrow-down');
                        spinner.id = ''; // Remove the spinner ID since it's now an arrow
                    }
                    
                    // Show mismatch div for errors (since we can't verify the domain)
                    if (urlMismatch) {
                        urlMismatch.style.display = 'block';
                        if (resultMismatch) resultMismatch.textContent = msg;
                    }
                    
                    // Apply URL truncation to newly added URL elements
                    setTimeout(applyUrlTooltips, 100);
                    
                    // Start progress bar after error handling completes
                    startProgressBar(opts.timeout_ms || 2000);
                }
            }, remainingTime);
        })
        .finally(function () {
            clearTimeout(timer);
        });
});
