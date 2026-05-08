<?php
require_once __DIR__ . '/helpers.php';
if (session_status() === PHP_SESSION_NONE) session_start();

// VirtualBox/VM first-boot gate: if the firstboot service hasn't finished, show a waiting page
$firstboot_flag = '/var/lib/userspice-firstboot.done';
$firstboot_creds_file = dirname(__DIR__) . '/.firstboot-credentials.json';
$is_firstboot_pending = file_exists('/etc/systemd/system/userspice-firstboot.service') && !file_exists($firstboot_flag);
$firstboot_creds = null;

// Check if we need to show credentials (one-time display after first boot)
if (!$is_firstboot_pending && file_exists($firstboot_creds_file)) {
    $creds_json = @file_get_contents($firstboot_creds_file);
    if ($creds_json) {
        $firstboot_creds = @json_decode($creds_json, true);
        // Mark as shown after this page load
        if ($firstboot_creds && isset($firstboot_creds['shown']) && $firstboot_creds['shown'] === false) {
            $firstboot_creds['shown'] = true;
            @file_put_contents($firstboot_creds_file, json_encode($firstboot_creds, JSON_PRETTY_PRINT));
        } else {
            $firstboot_creds = null; // Already shown, don't display again
        }
    }
}

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

<?php if ($is_firstboot_pending): ?>
<!-- First-boot in progress: Docker images being pulled -->
<style>
    .firstboot-page { max-width: 500px; margin: 4rem auto; text-align: center; padding: 2rem; }
    .firstboot-page h1 { font-size: 1.5rem; margin-bottom: 1rem; }
    .firstboot-page p { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem; }
    .spinner { width: 48px; height: 48px; border: 4px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 1s linear infinite; margin: 2rem auto; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .firstboot-note { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-top: 2rem; text-align: left; font-size: 0.85rem; }
    .firstboot-note code { background: var(--bg); padding: 0.2em 0.4em; border-radius: 3px; }
</style>
<meta http-equiv="refresh" content="15">
<div class="firstboot-page">
    <h1>Setting Up Scanner...</h1>
    <div class="spinner"></div>
    <p>First-boot setup is in progress. This typically takes 5-10 minutes.</p>
    <p>The page will automatically refresh when ready.</p>
    <div class="firstboot-note">
        <strong>What's happening:</strong>
        <ul style="margin: 0.5rem 0 0 1.5rem; padding: 0;">
            <li>Generating unique passwords</li>
            <li>Pulling Docker scanner images (~4GB)</li>
            <li>Configuring services</li>
        </ul>
        <p style="margin-top: 1rem; margin-bottom: 0;">
            You can also check progress via SSH:<br>
            <code>journalctl -fu userspice-firstboot</code>
        </p>
    </div>
</div>

<?php elseif ($firstboot_creds && isset($firstboot_creds['root_pw'])): ?>
<!-- First-boot complete: Show credentials once -->
<style>
    .creds-page { max-width: 550px; margin: 3rem auto; padding: 1.5rem; }
    .creds-page h1 { font-size: 1.4rem; margin-bottom: 0.5rem; color: var(--green); }
    .creds-page .subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
    .creds-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
    .creds-box h3 { font-size: 0.9rem; margin: 0 0 0.75rem 0; color: var(--text-muted); }
    .creds-row { display: flex; justify-content: space-between; padding: 0.4rem 0; font-size: 0.9rem; }
    .creds-row .label { color: var(--text-muted); }
    .creds-row .value { font-family: monospace; font-weight: 600; }
    .creds-warning { background: rgba(234, 179, 8, 0.1); border: 1px solid var(--yellow); border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; }
    .creds-warning strong { color: var(--yellow); }
    .creds-continue { text-align: center; margin-top: 1.5rem; }
</style>
<div class="creds-page">
    <h1>Setup Complete!</h1>
    <p class="subtitle">Your scanner VM is ready. Here are your generated credentials:</p>

    <div class="creds-warning">
        <strong>Save these credentials now!</strong> They will not be shown again.<br>
        A backup is also saved at <code>/var/lib/userspice-firstboot-creds.txt</code>
    </div>

    <div class="creds-box">
        <h3>SSH / System Access</h3>
        <div class="creds-row"><span class="label">Username:</span> <span class="value">root</span></div>
        <div class="creds-row"><span class="label">Password:</span> <span class="value"><?= htmlspecialchars($firstboot_creds['root_pw']) ?></span></div>
    </div>

    <div class="creds-box">
        <h3>MariaDB / phpMyAdmin / Tiny File Manager</h3>
        <div class="creds-row"><span class="label">Username:</span> <span class="value">root</span> <span style="color: var(--text-muted);">(or admin for TFM)</span></div>
        <div class="creds-row"><span class="label">Password:</span> <span class="value"><?= htmlspecialchars($firstboot_creds['mysql_pw']) ?></span></div>
    </div>

    <div class="creds-continue">
        <a href="?" class="btn btn-primary">Continue to Scanner Setup</a>
    </div>
</div>

<?php elseif (!$has_password): ?>
<!-- First-run: Set a password (no password exists yet; setup form gates everything) -->
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
<?php if (file_exists(BASE_SCAN_DIR . '/files/index.php')): ?>
        <a href="/files/" target="_blank" rel="noopener" class="btn btn-sm">Files</a>
<?php endif; ?>
<?php if (is_dir('/usr/share/phpmyadmin')): ?>
        <a href="/phpmyadmin/" target="_blank" rel="noopener" class="btn btn-sm">phpMyAdmin</a>
<?php endif; ?>
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
