// ── If already authenticated, skip login and go straight to chat ─────────────
if (localStorage.getItem('access_token')) {
    window.location.replace('/chat-ui');
}

// ── Login form submission ────────────────────────────────────────────────────
const loginForm  = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const submitBtn  = document.getElementById('login-submit-btn');

loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    loginError.textContent = '';
    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in…';

    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;

    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);

    try {
        const response = await fetch('/token', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const data = await response.json();
            loginError.textContent = data.detail || 'Login failed. Please try again.';
            return;
        }

        const data = await response.json();
        localStorage.setItem('access_token', data.access_token);

        // Redirect to chat interface
        window.location.replace('/chat-ui');

    } catch (err) {
        loginError.textContent = 'Could not connect to server. Is it running?';
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Sign In';
    }
});
