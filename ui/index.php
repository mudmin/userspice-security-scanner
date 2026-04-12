<?php
require_once __DIR__ . '/helpers.php';
if (session_status() === PHP_SESSION_NONE) session_start();

$authenticated = is_authenticated();
$has_password = has_password();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UserSpice Security Scanner</title>
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link rel="stylesheet" href="assets/style.css?v=<?= filemtime(__DIR__ . '/assets/style.css') ?>">
<?php if (!$authenticated): ?>
    <style>
        .auth-page { max-width: 400px; margin: 4rem auto; text-align: center; }
        .auth-page h1 { font-size: 1.3rem; margin-bottom: 0.5rem; }
        .auth-page p { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 1.5rem; }
        .auth-form { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: left; }
        .auth-form .form-group { margin-bottom: 1rem; }
        .auth-form label { display: block; font-size: 0.8rem; margin-bottom: 0.3rem; color: var(--text-muted); }
        .auth-form input[type="password"] { width: 100%; padding: 0.5rem 0.75rem; font-size: 0.9rem; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text); }
        .auth-form button { width: 100%; padding: 0.6rem; font-size: 0.9rem; }
        .auth-error { color: var(--red); font-size: 0.8rem; margin-top: 0.5rem; display: none; }
    </style>
<?php endif; ?>
</head>
<body>

<?php if (!$authenticated && !$has_password): ?>
<!-- First-run: Set a password -->
<div class="auth-page">
    <h1>Welcome to UserSpice Security Scanner</h1>
    <p>Set a password to secure the web interface. This will be stored as a bcrypt hash in scanner.conf.</p>
    <div class="auth-form">
        <form id="setup-form" onsubmit="return handleSetup(event)">
            <div class="form-group">
                <label>Choose a password</label>
                <input type="password" id="setup-pass" required minlength="6" autofocus>
            </div>
            <div class="form-group">
                <label>Confirm password</label>
                <input type="password" id="setup-pass-confirm" required minlength="6">
            </div>
            <button type="submit" class="btn btn-primary">Set Password & Continue</button>
            <div id="setup-error" class="auth-error"></div>
        </form>
    </div>
</div>
<script>
async function handleSetup(e) {
    e.preventDefault();
    const pass = document.getElementById('setup-pass').value;
    const confirm = document.getElementById('setup-pass-confirm').value;
    const err = document.getElementById('setup-error');
    err.style.display = 'none';

    if (pass !== confirm) {
        err.textContent = 'Passwords do not match.';
        err.style.display = 'block';
        return;
    }
    if (pass.length < 6) {
        err.textContent = 'Password must be at least 6 characters.';
        err.style.display = 'block';
        return;
    }

    const resp = await fetch('api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'set-password', password: pass })
    }).then(r => r.json());

    if (resp.success) {
        window.location.reload();
    } else {
        err.textContent = resp.error || 'Failed to set password.';
        err.style.display = 'block';
    }
}
</script>

<?php elseif (!$authenticated): ?>
<!-- Login -->
<div class="auth-page">
    <h1>UserSpice Security Scanner</h1>
    <p>Enter your password to continue.</p>
    <div class="auth-form">
        <form id="login-form" onsubmit="return handleLogin(event)">
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="login-pass" required autofocus>
            </div>
            <button type="submit" class="btn btn-primary">Sign In</button>
            <div id="login-error" class="auth-error"></div>
        </form>
    </div>
</div>
<script>
async function handleLogin(e) {
    e.preventDefault();
    const pass = document.getElementById('login-pass').value;
    const err = document.getElementById('login-error');
    err.style.display = 'none';

    const resp = await fetch('api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'login', password: pass })
    }).then(r => r.json());

    if (resp.success) {
        window.location.reload();
    } else {
        err.textContent = resp.error || 'Invalid password.';
        err.style.display = 'block';
    }
}
</script>

<?php else: ?>
<!-- Authenticated: Load the app -->
<header>
    <h1>UserSpice Security Scanner</h1>
    <span class="subtitle">Local security scanning for UserSpice projects</span>
    <nav>
        <a href="#dashboard" class="btn btn-sm">Dashboard</a>
        <a href="#docs" class="btn btn-sm">Docs</a>
        <a href="#" class="btn btn-sm" onclick="logout(); return false;">Logout</a>
    </nav>
</header>

<div class="container" id="main">
    <p style="color: var(--text-muted);">Loading...</p>
</div>

<script src="assets/app.js?v=<?= filemtime(__DIR__ . '/assets/app.js') ?>"></script>
<script>
async function logout() {
    await fetch('api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'logout' })
    });
    window.location.reload();
}
</script>
<?php endif; ?>

</body>
</html>
