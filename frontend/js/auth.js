/**
 * SigmaWork — Auth pages JavaScript.
 *
 * Handles:
 *   • Registration form validation & submission
 *   • Login form submission
 *   • Forgot-password form submission
 *   • Password show/hide toggle
 *   • Password strength indicator
 *   • OAuth button redirects
 *   • Token extraction from URL after OAuth callback
 */

const API = '/api/auth';

// ── Helpers ──────────────────────────────────────────────

/** Show a message banner (error or success) inside the form. */
function showMessage(id, text, type = 'error') {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className = `message show ${type}`;
}

/** Hide the message banner. */
function hideMessage(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'message';
}

/** Show a field-level error. */
function showFieldError(inputId, text) {
  const el = document.getElementById(`${inputId}-error`);
  if (!el) return;
  el.textContent = text;
  el.classList.add('show');
  const input = document.getElementById(inputId);
  if (input) input.classList.add('error');
}

/** Clear a field-level error. */
function clearFieldError(inputId) {
  const el = document.getElementById(`${inputId}-error`);
  if (!el) return;
  el.classList.remove('show');
  const input = document.getElementById(inputId);
  if (input) input.classList.remove('error');
}

/** Clear all field errors on the page. */
function clearAllFieldErrors() {
  document.querySelectorAll('.field-error').forEach(el => el.classList.remove('show'));
  document.querySelectorAll('.input-wrapper input').forEach(el => el.classList.remove('error'));
}

/** Set button loading state. */
function setLoading(btn, loading) {
  if (loading) {
    btn.classList.add('loading');
    btn.disabled = true;
  } else {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

/** Make a JSON API call. */
async function apiCall(endpoint, data) {
  const response = await fetch(`${API}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const json = await response.json();
  return { ok: response.ok, status: response.status, data: json };
}


// ── Password strength ────────────────────────────────────

function checkPasswordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) score++;
  return score; // 0-5
}

function updateStrengthUI(password) {
  const bars = document.querySelectorAll('.password-strength .bar');
  const label = document.querySelector('.strength-label');
  if (!bars.length || !label) return;

  const score = checkPasswordStrength(password);

  const levels = [
    { max: 0, label: '', cls: '' },
    { max: 2, label: 'Weak', cls: 'weak' },
    { max: 3, label: 'Fair', cls: 'weak' },
    { max: 4, label: 'Good', cls: 'medium' },
    { max: 5, label: 'Strong', cls: 'strong' },
  ];

  let level = levels[0];
  for (const l of levels) {
    if (score <= l.max) { level = l; break; }
    level = l;
  }

  bars.forEach((bar, i) => {
    bar.className = 'bar';
    if (password.length > 0 && i < score) {
      bar.classList.add(level.cls);
    }
  });

  label.textContent = password.length > 0 ? level.label : '';
  label.style.color = level.cls === 'weak' ? 'var(--error)'
                     : level.cls === 'medium' ? '#FFB300'
                     : level.cls === 'strong' ? 'var(--success)'
                     : 'var(--text-muted)';
}


// ── Password toggle ──────────────────────────────────────

function initPasswordToggles() {
  document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const input = btn.parentElement.querySelector('input');
      if (!input) return;
      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';
      btn.textContent = isPassword ? 'HIDE' : 'SHOW';
    });
  });
}


// ── Registration ─────────────────────────────────────────

function initRegisterForm() {
  const form = document.getElementById('register-form');
  if (!form) return;

  const passwordInput = document.getElementById('reg-password');
  if (passwordInput) {
    passwordInput.addEventListener('input', () => {
      updateStrengthUI(passwordInput.value);
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAllFieldErrors();
    hideMessage('form-message');

    const fullName = document.getElementById('reg-name').value.trim();
    const email    = document.getElementById('reg-email').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm  = document.getElementById('reg-confirm').value;

    // Client-side validation
    let hasError = false;

    if (!fullName) {
      showFieldError('reg-name', 'Full name is required.');
      hasError = true;
    }
    if (!email) {
      showFieldError('reg-email', 'Email address is required.');
      hasError = true;
    }
    if (password.length < 8) {
      showFieldError('reg-password', 'Password must be at least 8 characters.');
      hasError = true;
    }
    if (password !== confirm) {
      showFieldError('reg-confirm', 'Passwords do not match.');
      hasError = true;
    }

    if (hasError) return;

    const btn = form.querySelector('.btn-primary');
    setLoading(btn, true);

    try {
      const result = await apiCall('/register', {
        full_name: fullName,
        email,
        password,
        confirm_password: confirm,
      });

      if (result.ok) {
        showMessage('form-message', 'Account created! Redirecting to login…', 'success');
        setTimeout(() => {
          window.location.href = 'index.html';
        }, 1500);
      } else {
        const detail = result.data.detail || 'Registration failed.';
        showMessage('form-message', detail, 'error');
      }
    } catch (err) {
      showMessage('form-message', 'Network error. Please try again.', 'error');
    } finally {
      setLoading(btn, false);
    }
  });
}


// ── Login ────────────────────────────────────────────────

function initLoginForm() {
  const form = document.getElementById('login-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAllFieldErrors();
    hideMessage('form-message');

    const email    = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;

    let hasError = false;
    if (!email) {
      showFieldError('login-email', 'Email address is required.');
      hasError = true;
    }
    if (!password) {
      showFieldError('login-password', 'Password is required.');
      hasError = true;
    }
    if (hasError) return;

    const btn = form.querySelector('.btn-primary');
    setLoading(btn, true);

    try {
      const result = await apiCall('/login', { email, password });

      if (result.ok) {
        // Store tokens
        localStorage.setItem('access_token', result.data.access_token);
        localStorage.setItem('refresh_token', result.data.refresh_token);
        localStorage.setItem('user', JSON.stringify(result.data.user));

        showMessage('form-message', `Welcome back, ${result.data.user.full_name}!`, 'success');

        // TODO: redirect to dashboard/feed once it exists
        setTimeout(() => {
          showMessage('form-message', 'Logged in successfully! Dashboard coming soon.', 'success');
        }, 1000);
      } else {
        const detail = result.data.detail || 'Login failed.';
        showMessage('form-message', detail, 'error');
      }
    } catch (err) {
      showMessage('form-message', 'Network error. Please try again.', 'error');
    } finally {
      setLoading(btn, false);
    }
  });
}


// ── Forgot Password ──────────────────────────────────────

function initForgotForm() {
  const form = document.getElementById('forgot-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearAllFieldErrors();
    hideMessage('form-message');

    const email = document.getElementById('forgot-email').value.trim();

    if (!email) {
      showFieldError('forgot-email', 'Email address is required.');
      return;
    }

    const btn = form.querySelector('.btn-primary');
    setLoading(btn, true);

    try {
      const result = await apiCall('/forgot-password', { email });

      // Always show success to prevent email enumeration
      showMessage(
        'form-message',
        'If an account with that email exists, a reset link has been sent.',
        'success'
      );

      // In dev mode, show the token for testing
      if (result.data.detail && result.data.detail.startsWith('DEV_ONLY')) {
        const token = result.data.detail.replace('DEV_ONLY_RESET_TOKEN: ', '');
        console.log('🔑 DEV Reset Token:', token);
        const devNote = document.createElement('div');
        devNote.className = 'message show success';
        devNote.style.marginTop = '8px';
        devNote.style.fontSize = '0.75rem';
        devNote.style.wordBreak = 'break-all';
        devNote.innerHTML = `<strong>DEV MODE</strong> — Reset token:<br><code>${token}</code>`;
        form.appendChild(devNote);
      }
    } catch (err) {
      showMessage('form-message', 'Network error. Please try again.', 'error');
    } finally {
      setLoading(btn, false);
    }
  });
}


// ── OAuth token extraction ───────────────────────────────

function checkOAuthCallback() {
  const params = new URLSearchParams(window.location.search);
  const accessToken = params.get('access_token');
  const refreshToken = params.get('refresh_token');

  if (accessToken && refreshToken) {
    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);

    // Clean URL
    window.history.replaceState({}, '', window.location.pathname);

    showMessage('form-message', 'Signed in with OAuth successfully!', 'success');
  }
}


// ── Init on DOM ready ────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initPasswordToggles();
  initRegisterForm();
  initLoginForm();
  initForgotForm();
  checkOAuthCallback();
});
