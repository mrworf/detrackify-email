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

    // Domain matching utilities - moved from Python logic
    function normalizeDomain(domain) {
        if (!domain) return "";
        return domain.toLowerCase().trim();
    }

    function isSubdomain(domain1, domain2) {
        if (!domain1 || !domain2) return false;
        domain1 = normalizeDomain(domain1);
        domain2 = normalizeDomain(domain2);
        return domain1 === domain2 || domain1.endsWith('.' + domain2);
    }

    function areDomainsAliases(domain1, domain2, aliases) {
        if (!domain1 || !domain2) return false;
        
        domain1 = normalizeDomain(domain1);
        domain2 = normalizeDomain(domain2);
        
        // Direct match
        if (domain1 === domain2) return true;
        
        // Subdomain check
        if (isSubdomain(domain1, domain2) || isSubdomain(domain2, domain1)) return true;
        
        // Check aliases if provided
        if (aliases && typeof aliases === 'object') {
            for (var owner in aliases) {
                var aliasList = aliases[owner];
                if (typeof aliasList === 'string') {
                    aliasList = [aliasList];
                } else if (!Array.isArray(aliasList)) {
                    continue;
                }
                
                owner = normalizeDomain(owner);
                aliasList = aliasList.map(function(alias) { return normalizeDomain(alias); });
                
                var domain1InGroup = (domain1 === owner || aliasList.indexOf(domain1) !== -1 ||
                    aliasList.some(function(d) { return isSubdomain(domain1, d); }));
                var domain2InGroup = (domain2 === owner || aliasList.indexOf(domain2) !== -1 ||
                    aliasList.some(function(d) { return isSubdomain(domain2, d); }));
                
                if (domain1InGroup && domain2InGroup) {
                    return true;
                }
            }
        }
        
        return false;
    }

    function extractDomainFromUrl(url) {
        try {
            var match = url.match(/https?:\/\/([^\/]+)/i);
            if (match) {
                var domain = match[1].split(':')[0]; // Remove port if present
                return normalizeDomain(domain);
            }
        } catch (e) {
            // Ignore errors
        }
        return null;
    }

    // Enhanced domain matching function
    function domainsMatch(url, senderDomain, aliases) {
        if (!url || !senderDomain) return false;
        
        var urlDomain = extractDomainFromUrl(url);
        if (!urlDomain) return false;
        
        return areDomainsAliases(urlDomain, senderDomain, aliases);
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

    // Enhanced highlighting function that uses the new domain matching logic
    function highlight(url, senderDomain, aliases) {
        url = esc(url);
        var urlDomain = extractDomainFromUrl(url);
        if (urlDomain && senderDomain) {
            var matches = domainsMatch(url, senderDomain, aliases);
            var cls = matches ? 'good' : 'bad';
            var m = url.match(/https?:\/\/([^/]+)/i);
            if (m) {
                return url.replace(m[1], '<span class="highlight ' + cls + '">' + m[1] + '</span>');
            }
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

    // Function to show warning modal
    function showWarningModal(warningType, customMessage) {
        var modal = document.getElementById('warning-modal');
        var header = document.getElementById('warning-header');
        var message = document.getElementById('warning-message');
        var meaningHeader = document.getElementById('warning-meaning-header');
        var meaningContent = document.getElementById('warning-meaning-content');
        var actionHeader = document.getElementById('warning-action-header');
        var actionContent = document.getElementById('warning-action-content');
        var details = document.getElementById('warning-details');
        var link = document.getElementById('warning-link');
        var acknowledgeBtn = document.getElementById('warning-acknowledge');
        
        if (modal && header && message && meaningHeader && meaningContent && actionHeader && actionContent) {
            // Get warning definition
            var warningDef = WARNING_DEFINITIONS[warningType];
            if (!warningDef) {
                // Fallback to generic warning if type not found
                warningDef = {
                    header: '⚠️ Warning',
                    message: customMessage || 'An unknown warning occurred',
                    meaningHeader: 'What this means',
                    meaningContent: 'We encountered an issue while verifying this link.',
                    actionHeader: 'What you should do',
                    actionContent: 'Proceed with caution if you trust the source of this link.',
                    details: null
                };
            }
            
            // Set modal content
            header.textContent = warningDef.header;
            message.textContent = customMessage || warningDef.message;
            meaningHeader.textContent = warningDef.meaningHeader;
            meaningContent.textContent = warningDef.meaningContent;
            actionHeader.textContent = warningDef.actionHeader;
            actionContent.textContent = warningDef.actionContent;
            
            // Handle details link
            if (warningDef.details) {
                link.href = warningDef.details;
                details.classList.remove('hidden');
            } else {
                details.classList.add('hidden');
            }
            
            modal.classList.remove('hidden');
            
            // Handle acknowledgment
            if (acknowledgeBtn) {
                acknowledgeBtn.onclick = function() {
                    modal.classList.add('hidden');
                    // Continue with the normal flow after acknowledgment
                    if (resolvedData) {
                        continueAfterWarning();
                    } else {
                        // Handle error case - show error state and start countdown
                        continueAfterError();
                    }
                };
            }
        }
    }

    // Function to continue after error acknowledgment
    function continueAfterError() {
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
                    if (resultMismatch) resultMismatch.textContent = 'Could not verify the final destination';
                }
                
                // Apply URL truncation to newly added URL elements
                setTimeout(applyUrlTooltips, 100);
                
                // Start progress bar after error handling completes
                startProgressBar(opts.timeout_ms || 2000);
            }
        }, remainingTime);
    }

    // Function to continue after warning acknowledgment
    function continueAfterWarning() {
        if (!resolvedData) return; // Safety check
        
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
                
                // Use the new domain matching logic
                var urlMatchesDomain = domainsMatch(resolvedData.url, opts.sender_domain, opts.domain_aliases);
                
                // Show appropriate div based on match
                if (urlMatchesDomain) {
                    if (urlMatch) urlMatch.style.display = 'block';
                    if (resultMatch) resultMatch.innerHTML = highlight(resolvedData.url, opts.sender_domain, opts.domain_aliases);
                    if (resolvedData.title && titleMatch) {
                        titleMatch.textContent = resolvedData.title;
                        titleMatch.style.display = 'block';
                    }
                } else {
                    if (urlMismatch) urlMismatch.style.display = 'block';
                    if (resultMismatch) resultMismatch.innerHTML = highlight(resolvedData.url, opts.sender_domain, opts.domain_aliases);
                    if (resolvedData.title && titleMismatch) {
                        titleMismatch.textContent = resolvedData.title;
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
    var resolvedData = null; // Store resolved data for use in warning flow

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
            resolvedData = data; // Store for use in warning flow
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
                
                // Show warning modal if resolution had issues
                if (data.warning) {
                    // Parse warning format: "type:message"
                    var warningType = 'unexpected_error'; // default
                    var warningMessage = data.warning;
                    
                    if (data.warning.includes(':')) {
                        var parts = data.warning.split(':', 2);
                        warningType = parts[0];
                        warningMessage = parts[1];
                    }
                    
                    showWarningModal(warningType, warningMessage);
                    return; // Don't continue with normal flow until user acknowledges
                }
                
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
                        
                        // Use the new domain matching logic
                        var urlMatchesDomain = domainsMatch(data.url, opts.sender_domain, opts.domain_aliases);
                        
                        // Show appropriate div based on match
                        if (urlMatchesDomain) {
                            if (urlMatch) urlMatch.style.display = 'block';
                            if (resultMatch) resultMatch.innerHTML = highlight(data.url, opts.sender_domain, opts.domain_aliases);
                            if (data.title && titleMatch) {
                                titleMatch.textContent = data.title;
                                titleMatch.style.display = 'block';
                            }
                        } else {
                            if (urlMismatch) urlMismatch.style.display = 'block';
                            if (resultMismatch) resultMismatch.innerHTML = highlight(data.url, opts.sender_domain, opts.domain_aliases);
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
            var warningType = 'unexpected_error';
            var warningMsg = '';
            
            if (err.name === 'AbortError') { 
                msg = 'Connection timed out'; 
                warningType = 'connection_timeout';
                warningMsg = 'Could not verify the final destination due to a timeout';
            }
            else if (err.status === 404) { 
                msg = 'Link not found'; 
                warningMsg = 'Could not verify the final destination';
            }
            else if (err.status === 403) { 
                msg = 'Invalid link information'; 
                warningMsg = 'Could not verify the final destination due to invalid link information';
            }
            else if (err.status === 500) { 
                msg = 'Internal error'; 
                warningMsg = 'Could not verify the final destination due to a server error';
            }
            else {
                warningMsg = 'Could not verify the final destination';
            }
            
            if (err.message && err.name !== 'AbortError') { msg += ': ' + err.message; }
            
            // Show warning modal for errors too
            showWarningModal(warningType, warningMsg);
            return; // Don't continue with normal flow until user acknowledges
        })
        .finally(function () {
            clearTimeout(timer);
        });
});
