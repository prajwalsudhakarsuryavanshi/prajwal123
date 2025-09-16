// Navigation between sections
document.querySelectorAll('.nav__link').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var target = document.querySelector(btn.getAttribute('data-target'));
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      document.getElementById('app').focus({ preventScroll: true });
    }
  });
});

// Password strength checker
(function() {
  var input = document.getElementById('password-input');
  var bar = document.getElementById('strength-bar');
  var text = document.getElementById('strength-text');
  var toggle = document.getElementById('toggle-visibility');

  if (!input) return;

  toggle.addEventListener('click', function() {
    var isPassword = input.getAttribute('type') === 'password';
    input.setAttribute('type', isPassword ? 'text' : 'password');
    toggle.textContent = isPassword ? 'Hide' : 'Show';
  });

  function estimatePasswordStrength(password) {
    var score = 0;
    var length = password.length;
    var hasLower = /[a-z]/.test(password);
    var hasUpper = /[A-Z]/.test(password);
    var hasDigit = /\d/.test(password);
    var hasSymbol = /[^A-Za-z0-9]/.test(password);
    var variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

    if (length >= 8) score += 20;
    if (length >= 12) score += 20;
    if (length >= 16) score += 20;
    score += variety * 10;

    // common patterns penalties
    if (/^(?:password|qwerty|letmein|admin|welcome|iloveyou|123456|12345678|123456789)$/i.test(password)) score = 5;
    if (/^[A-Za-z]+$/.test(password) && length < 10) score -= 10;
    if (/^\d+$/.test(password) && length < 10) score -= 10;

    // repeating chars penalty
    if (/(.)\1{2,}/.test(password)) score -= 10;

    // Clamp
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    return score;
  }

  function updateStrengthUI(value) {
    bar.style.width = value + '%';
    bar.parentElement.setAttribute('aria-valuenow', String(value));
    var label = 'Weak';
    var color = '#ef4444';
    if (value >= 70) { label = 'Strong'; color = '#22c55e'; }
    else if (value >= 40) { label = 'Medium'; color = '#f59e0b'; }
    bar.style.backgroundColor = color;
    text.textContent = 'Strength: ' + label + ' (' + value + '%)';
  }

  input.addEventListener('input', function() {
    var value = input.value || '';
    updateStrengthUI(estimatePasswordStrength(value));
  });
})();

// Password generator
(function() {
  var lower = document.getElementById('gen-lower');
  var upper = document.getElementById('gen-upper');
  var digit = document.getElementById('gen-digit');
  var symbol = document.getElementById('gen-symbol');
  var lengthEl = document.getElementById('gen-length');
  var output = document.getElementById('generated-password');
  var genBtn = document.getElementById('generate-btn');
  var copyBtn = document.getElementById('copy-btn');

  function pickRandom(chars) {
    var idx = Math.floor(Math.random() * chars.length);
    return chars[idx];
  }

  function generate() {
    var pools = [];
    if (lower.checked) pools.push('abcdefghijklmnopqrstuvwxyz');
    if (upper.checked) pools.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (digit.checked) pools.push('0123456789');
    if (symbol.checked) pools.push('!@#$%^&*()_+{}[]:;,.?~-');
    var len = Math.max(8, Math.min(64, parseInt(lengthEl.value || '16', 10)));
    if (!pools.length) return '';

    // Ensure at least one from each selected pool (no lookalikes removal for simplicity)
    var passwordChars = [];
    pools.forEach(function(pool) { passwordChars.push(pickRandom(pool)); });

    var all = pools.join('');
    for (var i = passwordChars.length; i < len; i++) {
      passwordChars.push(pickRandom(all));
    }

    // Shuffle (Fisher–Yates)
    for (var j = passwordChars.length - 1; j > 0; j--) {
      var k = Math.floor(Math.random() * (j + 1));
      var t = passwordChars[j];
      passwordChars[j] = passwordChars[k];
      passwordChars[k] = t;
    }
    return passwordChars.join('');
  }

  genBtn.addEventListener('click', function() {
    var pwd = generate();
    output.value = pwd;
  });

  copyBtn.addEventListener('click', function() {
    if (!output.value) return;
    output.select();
    document.execCommand('copy');
    copyBtn.textContent = 'Copied';
    setTimeout(function() { copyBtn.textContent = 'Copy'; }, 1200);
  });
})();

// Phishing URL checker (heuristics only; no external requests)
(function() {
  var input = document.getElementById('url-input');
  var result = document.getElementById('url-result');
  var btn = document.getElementById('analyze-url');

  function analyze(urlStr) {
    var issues = [];
    var info = [];
    try {
      var url = new URL(urlStr);
      var host = url.hostname;
      var isHttps = url.protocol === 'https:';
      if (!isHttps) issues.push('Does not use HTTPS');

      // IP address host
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) issues.push('Uses raw IP address as host');

      // Too many subdomains
      var labels = host.split('.');
      if (labels.length >= 5) issues.push('Excessive subdomains');

      // Typosquatting patterns
      if (/[0o]fficial|log[io]n|sec(ure)?-?update|verify-?account/i.test(host)) issues.push('Suspicious domain words');

      // Homoglyph-like numbers in brand-looking names
      if (/(payp[a4]l|faceb00k|g00gle|amaz0n)/i.test(host)) issues.push('Brand impersonation lookalike');

      // Shorteners
      if (/(bit\.ly|goo\.gl|t\.co|tinyurl\.com|ow\.ly|is\.gd|rebrand\.ly)$/i.test(host)) info.push('URL shortener detected');

      // Tracking params
      if ([...url.searchParams.keys()].some(function(k){ return /^utm_|fbclid|gclid/i.test(k); })) info.push('Tracking parameters present');

      // Port nonstandard for https
      if (url.port && url.port !== '443' && url.protocol === 'https:') info.push('Non-standard HTTPS port');

      var risk = 'Low';
      if (issues.length >= 3) risk = 'High';
      else if (issues.length === 2) risk = 'Medium';

      return { ok: true, host: host, risk: risk, issues: issues, info: info };
    } catch (e) {
      return { ok: false, message: 'Invalid URL' };
    }
  }

  function render(res) {
    if (!res.ok) {
      result.innerHTML = '<span style="color:#ef4444">' + res.message + '</span>';
      return;
    }
    var color = res.risk === 'High' ? '#ef4444' : (res.risk === 'Medium' ? '#f59e0b' : '#22c55e');
    var html = '' +
      '<div><strong>Host:</strong> ' + res.host + '</div>' +
      '<div><strong>Risk:</strong> <span style="color:' + color + '">' + res.risk + '</span></div>' +
      (res.issues.length ? '<div><strong>Issues:</strong><ul>' + res.issues.map(function(i){ return '<li>' + i + '</li>'; }).join('') + '</ul></div>' : '') +
      (res.info.length ? '<div><strong>Info:</strong><ul>' + res.info.map(function(i){ return '<li>' + i + '</li>'; }).join('') + '</ul></div>' : '') +
      '<div class="muted">Always verify the domain in the address bar before entering credentials.</div>';
    result.innerHTML = html;
  }

  btn.addEventListener('click', function() {
    var val = (input.value || '').trim();
    render(analyze(val));
  });
})();

// Quiz
(function() {
  var questions = [
    { q: 'Which password is strongest?', options: ['Summer2024', 'P@ssw0rd123', 'rW9!fZ2#qmB7^L'], a: 2 },
    { q: 'You receive an unexpected email with a link to "verify your account". What do you do?', options: ['Click link and login', 'Ignore or verify via official site/app', 'Reply asking for more info'], a: 1 },
    { q: '2FA provides additional security by requiring:', options: ['Another password', 'A second factor like code or key', 'Security questions'], a: 1 },
    { q: 'Public Wi‑Fi best practice:', options: ['Access bank apps freely', 'Use VPN and avoid sensitive logins', 'Turn off firewall for speed'], a: 1 },
  ];

  var container = document.getElementById('quiz-container');
  var submitBtn = document.getElementById('submit-quiz');
  var resetBtn = document.getElementById('reset-quiz');
  var result = document.getElementById('quiz-result');

  function renderQuiz() {
    container.innerHTML = questions.map(function(item, idx) {
      var name = 'q' + idx;
      return '<div class="quiz-item">' +
        '<div class="quiz-q"><strong>Q' + (idx+1) + '.</strong> ' + item.q + '</div>' +
        '<div class="quiz-opts">' +
          item.options.map(function(opt, oi) {
            var id = name + '-' + oi;
            return '<div><label><input type="radio" name="' + name + '" value="' + oi + '"> ' + opt + '</label></div>';
          }).join('') +
        '</div>' +
      '</div>';
    }).join('');
  }

  function grade() {
    var correct = 0;
    questions.forEach(function(item, idx) {
      var selected = document.querySelector('input[name="q' + idx + '"]:checked');
      if (selected && parseInt(selected.value, 10) === item.a) correct++;
    });
    var score = Math.round((correct / questions.length) * 100);
    var color = score >= 75 ? '#22c55e' : (score >= 50 ? '#f59e0b' : '#ef4444');
    result.innerHTML = '<strong>Score:</strong> <span style="color:' + color + '">' + score + '%</span> — ' + (score >= 75 ? 'Great job!' : (score >= 50 ? 'Good start, review tips.' : 'Review safety tips and try again.'));
  }

  submitBtn.addEventListener('click', grade);
  resetBtn.addEventListener('click', function() { renderQuiz(); result.textContent = ''; });
  renderQuiz();
})();


