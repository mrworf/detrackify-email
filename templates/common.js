/* ==============================================
   DETRACKIFY GUARD - COMMON JAVASCRIPT
   ============================================== */

// Multi-part TLD list for proper domain matching
const MULTI_PART_TLDS = [
  'co.uk', 'com.au', 'gov.uk', 'org.uk', 'net.uk', 'ac.uk', 'edu.au', 
  'gov.au', 'com.br', 'org.br', 'co.in', 'net.in', 'org.in', 'co.za',
  'org.za', 'net.za', 'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp'
];

/* ==============================================
   DOMAIN UTILITY FUNCTIONS
   ============================================== */

// Helper function to extract domain from URL
function extractDomainFromUrl(url) {
  try {
    const match = url.match(/https?:\/\/([^\/]+)/i);
    if (match) {
      return match[1].split(':')[0].toLowerCase().trim();
    }
  } catch (e) {
    // Ignore errors
  }
  return null;
}

// Extract effective domain for TLD-based matching (last 2+ components)
function extractEffectiveDomain(domain) {
  if (!domain) return null;
  
  const parts = domain.toLowerCase().split('.');
  if (parts.length < 2) return null;
  
  // Check if this domain uses a multi-part TLD
  for (const multiTld of MULTI_PART_TLDS) {
    if (domain.endsWith('.' + multiTld)) {
      // For multi-part TLDs, we need at least 3 components total
      if (parts.length >= 3) {
        return parts.slice(-3).join('.');
      }
      return domain; // If less than 3 parts, use the whole domain
    }
  }
  
  // For regular TLDs, use last 2 components
  return parts.slice(-2).join('.');
}

// Check if two domains match using TLD-based rules
function domainsMatch(domain1, domain2) {
  if (!domain1 || !domain2) return false;
  
  const effective1 = extractEffectiveDomain(domain1);
  const effective2 = extractEffectiveDomain(domain2);
  
  return effective1 === effective2;
}

// Helper function to extract domain from email
function extractDomainFromEmail(email) {
  try {
    if (email && email.includes('@')) {
      return email.split('@')[1].toLowerCase().trim();
    }
  } catch (e) {
    // Ignore errors
  }
  return null;
}

/* ==============================================
   UTILITY FUNCTIONS
   ============================================== */

// Regex pattern for escaping domain names in regex expressions
const DOMAIN_ESCAPE_REGEX = /[.*+?^${}()|[\]\\]/g;

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, function(match) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[match];
  });
}

function escapeOrUnknown(val) {
  return val ? escapeHtml(val) : 'Unknown';
}

// Unified function to determine domain highlighting class based on matching rules
function getDomainHighlightClass(targetDomain, senderDomain, originalUrl, resolvedUrl) {
  if (!targetDomain || !senderDomain) {
    return 'domain-highlight-red';
  }
  
  if (resolvedUrl) {
    // Rule 2: If sender and resolve link domains match, highlight green
    const resolvedDomain = extractDomainFromUrl(resolvedUrl);
    if (resolvedDomain && domainsMatch(senderDomain, resolvedDomain)) {
      return 'domain-highlight-green';
    }
  } else {
    // Rule 1: If sender and original link domains match, highlight green
    const originalDomain = extractDomainFromUrl(originalUrl);
    if (originalDomain && domainsMatch(senderDomain, originalDomain)) {
      return 'domain-highlight-green';
    }
  }
  
  return 'domain-highlight-red';
}

// Parse warning type from warning string (format: "type:message")
function parseWarningType(warningString) {
  if (!warningString || !warningString.includes(':')) {
    return 'unexpected_error';
  }
  return warningString.split(':', 2)[0];
}

// Helper function to prepare phishing domain data without highlighting
function preparePhishingDomains(senderEmail, senderDisplay, originalUrl, resolvedUrl, senderDomain) {
  const linkUrl = resolvedUrl || originalUrl;
  const linkDomain = extractDomainFromUrl(linkUrl);
  
  return {
    phishingSenderDisplay: escapeOrUnknown(senderDisplay),
    phishingSenderEmail: escapeOrUnknown(senderEmail),
    phishingLinkDomain: escapeOrUnknown(linkDomain)
  };
}





/* ==============================================
   HIGHLIGHTING FUNCTIONS
   ============================================== */

// Highlight sender email domain based on matching logic
function highlightSenderEmail(email, displayName, senderDomain, originalUrl, resolvedUrl) {
  if (!email) return 'Unknown';
  
  const emailDomain = extractDomainFromEmail(email);
  if (!emailDomain) return email; // No domain to highlight
  
  // Use unified domain matching logic
  const highlightClass = getDomainHighlightClass(emailDomain, senderDomain, originalUrl, resolvedUrl);
  
  // Escape HTML in email and display name
  const escapedEmail = escapeHtml(email);
  const escapedDisplay = displayName ? escapeHtml(displayName) : '';
  
  // Highlight the domain part of the email
  const domainRegex = new RegExp('@(' + emailDomain.replace(DOMAIN_ESCAPE_REGEX, '\\$&') + ')', 'i');
  const highlightedEmail = escapedEmail.replace(domainRegex, '@<span class="' + highlightClass + '">$1</span>');
  
  // Format with display name if available
  if (escapedDisplay) {
    return escapedDisplay + ' (' + highlightedEmail + ')';
  } else {
    return highlightedEmail;
  }
}

// Highlight domains in URLs based on matching logic
function highlightUrlDomains(url, senderDomain, resolvedUrl, isOriginalUrl) {
  if (!url) return '';
  
  const urlDomain = extractDomainFromUrl(url);
  const escapedUrl = escapeHtml(url);
  
  if (!urlDomain) return escapedUrl;
  
  // Special case: For original URLs with resolved URLs, check if we should skip highlighting
  if (resolvedUrl && isOriginalUrl) {
    const resolvedDomain = extractDomainFromUrl(resolvedUrl);
    if (resolvedDomain && domainsMatch(senderDomain, resolvedDomain)) {
      // Sender matches resolved, so don't highlight original (return plain)
      return escapedUrl;
    }
  }
  
  // Use unified domain matching logic for highlighting
  const highlightClass = getDomainHighlightClass(urlDomain, senderDomain, url, resolvedUrl);
  
  // Replace domain in URL with highlighted version
  const escapedDomain = urlDomain.replace(DOMAIN_ESCAPE_REGEX, '\\$&');
  const domainRegex = new RegExp('(https?:\\/\\/)(' + escapedDomain + ')', 'i');
  return escapedUrl.replace(domainRegex, '$1<span class="' + highlightClass + '">$2</span>');
}



/* ==============================================
   STATE MANAGEMENT FUNCTIONS
   ============================================== */

// Show the appropriate state based on the scenario
function showState(stateId, domains) {
  // Hide all states
  const states = ['checking-state', 'safe-state', 'unsafe-state', 'blocked-state', 'phishing-state',
                  'non-resolve-safe', 'non-resolve-unsafe', 'non-resolve-phishing', 'non-resolve-blocked'];
  states.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  });
  
  // Stop progress bar animation when transitioning away from checking state
  // or when showing safe state
  if (stateId === 'safe-state' || stateId === 'non-resolve-safe') {
    const checkingState = document.getElementById('checking-state');
    if (checkingState) {
      const progressBarFill = checkingState.querySelector('.progress-bar-fill');
      if (progressBarFill) {
        // Stop the CSS animation by removing the animation property
        progressBarFill.style.animation = 'none';
      }
    }
  }
  
  // Show the requested state
  const stateEl = document.getElementById(stateId);
  if (stateEl) {
    stateEl.classList.remove('hidden');
    
    // Show/hide technical details based on state
    const techDetailsSection = document.getElementById('technical-details-section');
    const techDetailsContent = document.getElementById('technical-details');
    
    // Handle button and technical details visibility based on state
    const form = document.getElementById('continueForm');
    
    if (stateId === 'checking-state') {
      // Hide form and technical details during checking/resolving
      if (form) form.style.display = 'none';
      if (techDetailsSection) techDetailsSection.style.display = 'none';
      if (techDetailsContent) techDetailsContent.style.display = 'none';
    } else if (stateId === 'blocked-state' || stateId === 'non-resolve-blocked') {
      // Hide form for blocked states, show technical details
      if (form) form.style.display = 'none';
      if (techDetailsSection) techDetailsSection.style.display = '';
    } else {
      // Show form and technical details for all other states (safe, unsafe, phishing)
      if (form) form.style.display = '';
      if (techDetailsSection) techDetailsSection.style.display = '';
    }
    if (stateId !== 'checking-state') {
      if (techDetailsContent) {
        techDetailsContent.style.display = '';
        techDetailsContent.classList.remove('show');
      }
      resetTechnicalDetailsToggle();
    }
    
    // Populate domain information if provided
    if (domains) {
      if (domains.safeDomain) {
        const safeDomainEl = document.getElementById('safe-domain') || document.getElementById('non-resolve-safe-domain');
        if (safeDomainEl) safeDomainEl.textContent = domains.safeDomain;
      }
      if (domains.senderDomain) {
        const senderDomainEl = document.getElementById('sender-domain') || document.getElementById('non-resolve-sender-domain');
        if (senderDomainEl) senderDomainEl.textContent = domains.senderDomain;
      }
      if (domains.unsafeDomain) {
        const unsafeDomainEl = document.getElementById('unsafe-domain') || document.getElementById('non-resolve-unsafe-domain');
        if (unsafeDomainEl) unsafeDomainEl.textContent = domains.unsafeDomain;
      }
      
      // Handle phishing state domain population
      if (domains.phishingSenderDisplay) {
        const phishingSenderDisplayEl = document.getElementById('phishing-sender-display') || document.getElementById('non-resolve-phishing-sender-display');
        if (phishingSenderDisplayEl) phishingSenderDisplayEl.innerHTML = domains.phishingSenderDisplay;
      }
      if (domains.phishingSenderEmail) {
        const phishingSenderEmailEl = document.getElementById('phishing-sender-email') || document.getElementById('non-resolve-phishing-sender-email');
        if (phishingSenderEmailEl) phishingSenderEmailEl.innerHTML = domains.phishingSenderEmail;
      }
      if (domains.phishingLinkDomain) {
        const phishingLinkDomainEl = document.getElementById('phishing-link-domain') || document.getElementById('non-resolve-phishing-link-domain');
        if (phishingLinkDomainEl) phishingLinkDomainEl.innerHTML = domains.phishingLinkDomain;
      }
    }
  }
}

/* ==============================================
   TECHNICAL DETAILS FUNCTIONS
   ============================================== */

function setTechnicalDetailsToggleState(isOpen) {
  const arrow = document.getElementById('tech-details-arrow');
  const textEl = document.getElementById('tech-details-toggle-text');
  const s = (window.guardOpts && window.guardOpts.jsStrings) || {};
  const hideStr = s.tech_details_hide || 'Hide Details';
  const showStr = s.tech_details_show || 'Show Details';
  if (arrow) arrow.textContent = isOpen ? '▼' : '▶';
  if (textEl) textEl.textContent = isOpen ? hideStr : showStr;
}

function toggleTechnicalDetails() {
  const content = document.getElementById('technical-details');
  const arrow = document.getElementById('tech-details-arrow');
  const textEl = document.getElementById('tech-details-toggle-text');
  
  if (content && arrow && textEl) {
    if (content.classList.contains('show')) {
      content.classList.remove('show');
      setTechnicalDetailsToggleState(false);
    } else {
      content.classList.add('show');
      setTechnicalDetailsToggleState(true);
    }
  }
}

function resetTechnicalDetailsToggle() {
  setTechnicalDetailsToggleState(false);
}

// Generic populate technical details function
function populateTechnicalDetails(data, opts, templateData, warningDefinitions) {
  opts = opts || {};
  templateData = templateData || {};
  warningDefinitions = warningDefinitions || {};
  
  // Get URLs for highlighting logic
  const originalUrl = templateData.url || opts.url || '';
  const resolvedUrl = data ? data.url : null;
  
  // Prepare data for technical details mapping
  const senderEmail = templateData.sender_email || opts.sender_email;
  const senderDisplay = templateData.sender_display || opts.sender_display;
  const displayText = templateData.display || opts.display;
  
  // Create mapping object for technical details
  const techDetailsMap = {
    'tech-sender': senderEmail ? highlightSenderEmail(senderEmail, senderDisplay, opts.sender_domain, originalUrl, resolvedUrl) : 'Unknown',
    'tech-link-name': displayText || 'Unknown',
    'tech-original-url': highlightUrlDomains(originalUrl, opts.sender_domain, resolvedUrl, true),
    'tech-resolved-url': (opts.resolve && data && data.url) ? highlightUrlDomains(data.url, opts.sender_domain, resolvedUrl, false) : '',
    'tech-title': (opts.resolve && data && data.title) ? (() => {
      let displayTitle = data.title.trim();
      if (displayTitle.length > 100) {
        displayTitle = displayTitle.substring(0, 97) + '...';
      }
      return escapeHtml(displayTitle);
    })() : '',
    'tech-warning': (data && data.warning) ? (() => {
      const warningType = parseWarningType(data.warning);
      const warningDef = warningDefinitions[warningType];
      if (warningDef) {
        return escapeHtml(warningDef.header || warningType);
      }
      return escapeHtml(warningType);
    })() : '',
    'tech-block-reason': escapeHtml((data && data.block) || opts.block_reason || '')
  };
  
  // Update all technical details elements
  updateTechnicalDetails(techDetailsMap);
  
  // Handle visibility and special cases
  handleTechnicalDetailsVisibility(opts, data);

  // Handle original URL label based on resolve mode
  const techOriginalLabel = document.getElementById('tech-original-label');
  if (techOriginalLabel) {
    techOriginalLabel.textContent = opts.resolve ? 'Original Link:' : 'Link:';
  }

  // Link-choice row: set checkbox label and ensure unchecked when original differs from resolved
  if (opts.resolve && data && data.original_url) {
    const jsStrings = opts.jsStrings || (window.guardOpts && window.guardOpts.jsStrings) || {};
    const labelEl = document.getElementById('use-original-label');
    const cb = document.getElementById('use-original-checkbox');
    if (labelEl) labelEl.textContent = jsStrings.use_original_label || 'Use the original link from the email.';
    if (cb) cb.checked = false;
  }
}

// Update technical details using mapping object
function updateTechnicalDetails(techDetailsMap) {
  for (const [elementId, value] of Object.entries(techDetailsMap)) {
    const element = document.getElementById(elementId);
    if (element) {
      try {
        // Use innerHTML with escaped content for security
        element.innerHTML = value;
      } catch (error) {
        // Fallback to innerText if innerHTML fails
        element.innerText = value;
      }
    } else {
      // Element not found - blank it out in case HTML had temp value
      console.warn(`Technical details element not found: ${elementId}`);
    }
  }
}

// Handle visibility of technical detail rows
function handleTechnicalDetailsVisibility(opts, data) {
  const ROW_VISIBILITY = [
    ['tech-resolved-row', function() { return opts.resolve && data && data.url; }],
    ['tech-title-row', function() { return opts.resolve && data && data.title; }],
    ['tech-warning-row', function() { return data && data.warning; }],
    ['tech-block-reason-row', function() { return ((data && data.block) || opts.block_reason || '').trim() !== ''; }],
    ['tech-link-choice-row', function() { return opts.resolve && data && data.original_url; }]
  ];
  ROW_VISIBILITY.forEach(function(entry) {
    const id = entry[0];
    const cond = entry[1];
    const row = document.getElementById(id);
    if (row) row.style.display = cond() ? '' : 'none';
  });
}



/* ==============================================
   BUTTON & PROGRESS BAR FUNCTIONS
   ============================================== */

function setupButtonCore(isSafe, jsStrings, immediate) {
  jsStrings = jsStrings || {};
  const button = document.getElementById('cont');
  const buttonText = document.getElementById('button-text');
  const redirectingText = document.getElementById('redirecting-text');
  
  if (buttonText) {
    buttonText.textContent = isSafe ?
      (jsStrings.button_continue_safe || 'Go to website') :
      (jsStrings.button_continue || 'Continue anyway (not recommended)');
  }
  if (redirectingText) {
    redirectingText.textContent = isSafe ?
      (jsStrings.redirecting_final || 'Redirecting to final destination...') :
      (jsStrings.redirecting_generic || 'Redirecting...');
  }
  
  if (button) {
    button.style.display = '';
    button.disabled = !immediate;
    if (immediate) {
      const progressBar = document.getElementById('button-progress');
      if (progressBar) {
        progressBar.style.display = 'none';
        progressBar.style.width = '0%';
      }
    } else {
      startProgressBar((window.guardOpts && window.guardOpts.timeout_ms) || 2000);
    }
    button.onclick = function() {
      button.style.display = 'none';
      const redirectingState = document.getElementById('redirecting-state');
      if (redirectingState) redirectingState.classList.remove('hidden');
    };
  }
}

function setupButton(isSafe, jsStrings) {
  setupButtonCore(isSafe, jsStrings, false);
}

function setupButtonImmediate(isSafe, jsStrings) {
  setupButtonCore(isSafe, jsStrings, true);
}

// Progress bar function
function startProgressBar(duration) {
  var button = document.getElementById('cont');
  var progressBar = document.getElementById('button-progress');
  
  if (button && progressBar) {
    var startTime = Date.now();
    
    var updateProgress = function() {
      var elapsed = Date.now() - startTime;
      var progress = Math.min(elapsed / duration, 1);
      var remainingWidth = (1 - progress) * 100;
      
      progressBar.style.width = remainingWidth + '%';
      
      if (progress < 1) {
        requestAnimationFrame(updateProgress);
      } else {
        button.disabled = false;
        progressBar.style.display = 'none';
      }
    };
    
    requestAnimationFrame(updateProgress);
  }
}

/* ==============================================
   RESOLVE MODE FUNCTIONS
   ============================================== */

function handleNonResolveMode(opts, warningDefinitions) {
  // Extract domains for comparison
  var urlDomain = extractDomainFromUrl(opts.url || window.location.search);
  var senderDomain = opts.sender_domain;
  var s = opts.jsStrings || {};
  
  if (urlDomain && senderDomain) {
    // Simple domain comparison using the new domain matching logic
    var domainsMatchResult = domainsMatch(urlDomain, senderDomain);
    
    if (domainsMatchResult) {
      showState('non-resolve-safe', { safeDomain: senderDomain });
      setupButtonImmediate(true, s);
    } else {
      showState('non-resolve-unsafe', { 
        senderDomain: senderDomain, 
        unsafeDomain: urlDomain 
      });
      setupButton(false, s);
    }
  } else {
    // If we can't determine domains, show unsafe
    showState('non-resolve-unsafe', { 
      senderDomain: senderDomain || 'unknown', 
      unsafeDomain: urlDomain || 'unknown' 
    });
    setupButton(false, s);
  }
  
  // Populate technical details for non-resolve mode
  populateTechnicalDetails(null, opts, window.templateData || {});
}

function handleResolveMode(opts, warningDefinitions) {
  // Get template data and block reason early
  const templateData = window.templateData || {};
  var blockReason = templateData.block_reason || opts.block_reason || '';
  var s = opts.jsStrings || {};
  
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, (opts.timeout_ms || 0) + 10000);
  
  // Minimum display time for checking state
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
    // Store resolved URL data
    if (data.url && data.hash) {
      var u = document.getElementById('final');
      var h = document.getElementById('hash');
      if (u) u.value = data.url;
      if (h) h.value = data.hash;
    }
    if (data.original_url && data.original_hash) {
      window.guardOriginalOption = { url: data.original_url, hash: data.original_hash };
    } else {
      window.guardOriginalOption = null;
    }

    // Check for auto redirect before minimum display time
    if (opts.auto_redirect && data.domains_match && !data.block && !data.warning) {
      var startField = document.querySelector('input[name="ts"]');
      if (startField && opts.timeout_ms) {
        var startVal = parseFloat(startField.value) || Date.now() / 1000;
        startField.value = (startVal - (opts.timeout_ms / 1000)).toString();
      }
      var form = document.getElementById('continueForm');
      if (form) form.submit();
      return;
    }
    
    // Check if this is a safe link (domains match, no block, no blocking warning)
    // Safe links should be shown immediately without delay
    var hasBlockingWarning = data.warning && opts.deny_on_warnings && 
                             opts.deny_on_warnings.includes(parseWarningType(data.warning));
    var isSafeLink = data.domains_match && !data.block && !hasBlockingWarning && 
                     (!blockReason || typeof blockReason !== 'string' || blockReason.trim().length === 0);
    
    // Calculate remaining time to meet minimum display requirement (only for non-safe links)
    var elapsed = Date.now() - resolveStartTime;
    var remainingTime = isSafeLink ? 0 : Math.max(0, minDisplayTime - elapsed);
    
    setTimeout(function() {
      // Handle different resolution outcomes
      if (data.block) {
        showState('blocked-state');
      } else if (blockReason && typeof blockReason === 'string' && blockReason.trim().length > 0) {
        // Original block reason
        showState('blocked-state');
      } else if (data.warning && opts.deny_on_warnings) {
        const warningType = parseWarningType(data.warning);
        
        if (opts.deny_on_warnings.includes(warningType)) {
          showState('blocked-state');
          return;
        }
      }
      
      // Show warning modal if needed (but not blocking)
      if (data.warning && !(opts.deny_on_warnings && opts.deny_on_warnings.includes(parseWarningType(data.warning)))) {
        // Handle non-blocking warnings - for now, continue with normal flow
        // Could show a modal here if needed
      }
      
      // Extract resolved domain
      var resolvedDomain = extractDomainFromUrl(data.url);
      var senderDomain = opts.sender_domain;
      
      // Check for phishing first (if block reason is phishy)
      
      if (blockReason === 'phishy') {
        const phishingDomains = preparePhishingDomains(
          templateData.sender_email || opts.sender_email, 
          templateData.sender_display || opts.sender_display, 
          templateData.url || opts.url, 
          data.url, 
          opts.sender_domain
        );
        showState('phishing-state', phishingDomains);
        setupButton(false, s);
      } else if (data.domains_match) {
        // Use backend's domain match result - safe link, enable immediately
        showState('safe-state', { safeDomain: resolvedDomain || senderDomain });
        setupButtonImmediate(true, s);
      } else {
        showState('unsafe-state', { 
          senderDomain: senderDomain, 
          unsafeDomain: resolvedDomain 
        });
        setupButton(false, s);
      }
      
      // Populate technical details
      populateTechnicalDetails(data, opts, window.templateData || {}, warningDefinitions);
    }, remainingTime);
  })
  .catch(function (err) {
    window.guardOriginalOption = null;
    // Handle errors by showing unsafe state
    var elapsed = Date.now() - resolveStartTime;
    var remainingTime = Math.max(0, minDisplayTime - elapsed);

    setTimeout(function() {
      var senderDomain = opts.sender_domain;
      var urlDomain = extractDomainFromUrl(opts.url);
      
      showState('unsafe-state', { 
        senderDomain: senderDomain, 
        unsafeDomain: urlDomain || 'unknown' 
      });
      setupButton(false, s);
      
      // Populate technical details for error case
      populateTechnicalDetails(null, opts, window.templateData || {}, warningDefinitions);
    }, remainingTime);
  })
  .finally(function () {
    clearTimeout(timer);
  });
}

/* ==============================================
   INITIALIZATION
   ============================================== */

// Main initialization function that can be called by templates
function initializeGuard(opts, jsStrings, warningDefinitions, templateData) {
  opts = opts || window.guardOpts || {};
  jsStrings = jsStrings || {};
  warningDefinitions = warningDefinitions || {};
  templateData = templateData || {};
  opts.jsStrings = jsStrings;

  // Check for blocking reason from server-side or template data
  var blockReason = templateData.block_reason || opts.block_reason || '';
  
  // Check if this is a phishing case
  if (blockReason === 'phishy') {
    if (opts.resolve) {
      // For resolve mode, still resolve the link but show phishing warning
      showState('checking-state');
      handleResolveMode(opts, warningDefinitions);
      return;
    } else {
      // For non-resolve mode, show phishing warning immediately
      const phishingDomains = preparePhishingDomains(
        templateData.sender_email || opts.sender_email, 
        templateData.sender_display || opts.sender_display, 
        templateData.url || opts.url, 
        null, 
        opts.sender_domain
      );
      showState('non-resolve-phishing', phishingDomains);
      setupButton(false, opts.jsStrings);
      populateTechnicalDetails(null, opts, templateData, warningDefinitions);
      return;
    }
  }
  
  // Check if there's an initial block - if so, never resolve and show blocked state immediately
  if (blockReason && typeof blockReason === 'string' && blockReason.trim().length > 0) {
    if (opts.resolve) {
      showState('blocked-state');
    } else {
      showState('non-resolve-blocked');
    }
    // Populate technical details even for blocked links (but no resolve data)
    populateTechnicalDetails(null, opts, templateData, warningDefinitions);
    return;
  }
  
  if (opts.resolve) {
    // Always show checking state initially
    showState('checking-state');

    handleResolveMode(opts, warningDefinitions);
  } else {
    // Non-resolve mode - compare domains immediately
    handleNonResolveMode(opts, warningDefinitions);
  }

  // Form submit: when "use original" is checked, swap #final and #hash before submit
  var form = document.getElementById('continueForm');
  if (form) {
    form.addEventListener('submit', function() {
      var opt = window.guardOriginalOption;
      var cb = document.getElementById('use-original-checkbox');
      var finalEl = document.getElementById('final');
      var hashEl = document.getElementById('hash');
      if (opt && cb && cb.checked && finalEl && hashEl) {
        finalEl.value = opt.url;
        hashEl.value = opt.hash;
      }
    });
  }

  // Initialize URL highlighting for existing elements
  var urlEl = document.getElementById('url');
  if (urlEl) {
    urlEl.innerHTML = highlightUrlDomains(urlEl.textContent, opts.sender_domain, null, false);
  }
}