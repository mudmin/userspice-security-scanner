<?php
/**
 * UserSpice Security Scanner — UI Helpers
 * Shared functions for the web interface.
 */

define('SCANNER_ROOT', dirname(__DIR__));
define('REPORTS_DIR', SCANNER_ROOT . '/reports');
define('SCAN_SCRIPT', SCANNER_ROOT . '/scan.sh');
define('PID_DIR', SCANNER_ROOT . '/reports/.pids');

// Load local config (created by setup.sh). scanner.conf is also sourced as a
// bash file by lib/common.sh, so values containing shell metacharacters ($, `, etc.)
// must be single-quoted in the file. We strip surrounding quotes on read here.
$_scannerConf = [];
$_confFile = SCANNER_ROOT . '/scanner.conf';
if (file_exists($_confFile)) {
    foreach (file($_confFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (str_contains($line, '=')) {
            [$key, $val] = explode('=', $line, 2);
            $val = trim($val);
            if (strlen($val) >= 2
                && (($val[0] === "'" && $val[-1] === "'")
                 || ($val[0] === '"' && $val[-1] === '"'))) {
                $val = substr($val, 1, -1);
            }
            $_scannerConf[trim($key)] = $val;
        }
    }
}
define('BASE_SCAN_DIR', $_scannerConf['BASE_SCAN_DIR'] ?? '/var/www/html');
define('SETUP_COMPLETE', file_exists($_confFile));
define('AUTH_HASH', $_scannerConf['AUTH_HASH'] ?? '');

// ---- Authentication ----

/**
 * Check if a password has been set.
 */
function has_password(): bool {
    return AUTH_HASH !== '';
}

/**
 * Check if the current session is authenticated.
 * A fresh install (no password set) is NOT authenticated — the UI must
 * render the first-run setup form instead, and the API must reject everything
 * except the `set-password` action until a password exists.
 */
function is_authenticated(): bool {
    if (session_status() === PHP_SESSION_NONE) session_start();
    return !empty($_SESSION['scanner_auth']);
}

/**
 * Verify a password against the stored hash.
 */
function verify_password(string $password): bool {
    if (!has_password()) return false;
    return password_verify($password, AUTH_HASH);
}

/**
 * Set the auth password — writes bcrypt hash to scanner.conf.
 * Returns true on success.
 */
function set_password(string $password): bool {
    $hash = password_hash($password, PASSWORD_BCRYPT);
    $conf_file = SCANNER_ROOT . '/scanner.conf';

    if (!file_exists($conf_file)) {
        // Create minimal config
        file_put_contents($conf_file, "# UserSpice Security Scanner — Local Configuration\nBASE_SCAN_DIR=/var/www/html\n");
    }

    $content = file_get_contents($conf_file);

    // Single-quote the hash. scanner.conf is sourced as bash, and the bcrypt
    // hash starts with $2y$... — unquoted, bash would try to expand $2y, $10,
    // etc. as shell variables and crash every scan under `set -u`. Single
    // quotes prevent expansion and are stripped by the PHP reader above.
    $quoted = "AUTH_HASH='" . $hash . "'";

    if (preg_match('/^AUTH_HASH=.*$/m', $content)) {
        $content = preg_replace('/^AUTH_HASH=.*$/m', $quoted, $content);
    } else {
        $content = rtrim($content) . "\n\n# Web UI password (bcrypt hash)\n" . $quoted . "\n";
    }

    return file_put_contents($conf_file, $content) !== false;
}

/**
 * Require authentication. For API calls, returns 401 JSON. For pages, redirects.
 * Call this at the top of protected endpoints.
 */
function require_auth(bool $is_api = false): void {
    if (is_authenticated()) return;

    if ($is_api) {
        json_response(['error' => 'authentication required'], 401);
    }
    // For page requests, index.php handles the login form
}

/**
 * Sanitize a project name to prevent path traversal / injection.
 * Only allows: a-z, A-Z, 0-9, hyphen, underscore, dot
 */
function sanitize_project(string $name): string {
    return preg_replace('/[^a-zA-Z0-9_\-.]/', '', $name);
}

/**
 * Validate that a project directory actually exists.
 */
function project_exists(string $project): bool {
    $project = sanitize_project($project);
    if ($project === '' || $project === '.' || $project === '..') return false;
    return is_dir(BASE_SCAN_DIR . '/' . $project);
}

/**
 * Discover scannable projects in BASE_SCAN_DIR.
 * A directory is considered a project if it contains users/ or usersc/ or index.php.
 */
function discover_projects(): array {
    $projects = [];
    $dirs = scandir(BASE_SCAN_DIR);
    if (!$dirs) return $projects;

    $self = basename(SCANNER_ROOT);
    foreach ($dirs as $d) {
        if ($d === '.' || $d === '..' || $d === $self) continue;
        $path = BASE_SCAN_DIR . '/' . $d;
        if (!is_dir($path)) continue;

        $is_userspice = is_dir($path . '/users') && is_dir($path . '/usersc');
        $has_us_root = file_exists($path . '/z_us_root.php');
        $has_reports = is_dir(REPORTS_DIR . '/' . $d);

        // Show if it's a UserSpice project OR if we've previously scanned it
        if ($is_userspice || $has_us_root || $has_reports) {
            $projects[] = [
                'name' => $d,
                'path' => $path,
                'userspice' => $is_userspice,
                'scan_count' => count_reports($d),
                'latest_scan' => get_latest_report($d),
                'is_scanning' => is_scanning($d),
            ];
        }
    }

    usort($projects, fn($a, $b) => strcasecmp($a['name'], $b['name']));
    return $projects;
}

/**
 * Count reports for a project.
 */
function count_reports(string $project): int {
    $dir = REPORTS_DIR . '/' . sanitize_project($project);
    if (!is_dir($dir)) return 0;
    $items = array_filter(scandir($dir), fn($d) => $d !== '.' && $d !== '..' && is_dir("$dir/$d"));
    return count($items);
}

/**
 * Get all reports for a project, newest first.
 */
function get_reports(string $project): array {
    $project = sanitize_project($project);
    $dir = REPORTS_DIR . '/' . $project;
    if (!is_dir($dir)) return [];

    $reports = [];
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $report_dir = "$dir/$item";
        if (!is_dir($report_dir)) continue;

        $summary_file = "$report_dir/summary.json";
        $summary = null;
        if (file_exists($summary_file)) {
            $summary = json_decode(file_get_contents($summary_file), true);
        }

        $delta = null;
        $delta_file = "$report_dir/delta.json";
        if (file_exists($delta_file)) {
            $delta = json_decode(file_get_contents($delta_file), true);
        }

        $headers = null;
        $headers_file = "$report_dir/headers.json";
        if (file_exists($headers_file)) {
            $headers = json_decode(file_get_contents($headers_file), true);
        }

        $reports[] = [
            'id' => $item,
            'path' => $report_dir,
            'summary' => $summary,
            'delta' => $delta,
            'headers' => $headers,
            'has_zap_html' => file_exists("$report_dir/zap.html"),
        ];
    }

    usort($reports, fn($a, $b) => strcmp($b['id'], $a['id']));
    return $reports;
}

/**
 * Get the latest report summary for a project.
 */
function get_latest_report(string $project): ?array {
    $reports = get_reports($project);
    return $reports[0] ?? null;
}

/**
 * Check if a scan is currently running for a project.
 */
function is_scanning(string $project): bool {
    $project = sanitize_project($project);
    $pid_file = PID_DIR . "/$project.pid";
    if (!file_exists($pid_file)) return false;

    $pid = trim(file_get_contents($pid_file));
    if (!$pid || !is_numeric($pid)) {
        unlink($pid_file);
        return false;
    }

    // Check if process is still running
    if (file_exists("/proc/$pid")) {
        return true;
    }

    // Process finished — clean up
    unlink($pid_file);
    return false;
}

/**
 * Start a scan for a project in the background.
 * Returns the PID or false on failure.
 */
function start_scan(string $project, string $url = '', string $zap_profile = 'standard', string $zap_user = '', string $zap_pass = '', string $skip = '', string $zap_login = '', string $include = ''): int|false {
    $project = sanitize_project($project);
    if (!project_exists($project)) return false;
    if (is_scanning($project)) return false;

    if (!is_dir(PID_DIR)) {
        mkdir(PID_DIR, 0755, true);
    }

    // Build command
    $cmd = escapeshellcmd(SCAN_SCRIPT) . ' ' . escapeshellarg($project);
    if ($url !== '') {
        $cmd .= ' --url ' . escapeshellarg($url);
        $cmd .= ' --zap-profile ' . escapeshellarg($zap_profile);
    }
    if ($zap_user !== '' && $zap_pass !== '') {
        $cmd .= ' --zap-user ' . escapeshellarg($zap_user);
        $cmd .= ' --zap-pass ' . escapeshellarg($zap_pass);
    }
    if ($zap_login !== '') {
        $cmd .= ' --zap-login ' . escapeshellarg($zap_login);
    }
    if ($skip !== '') {
        $cmd .= ' --skip ' . escapeshellarg($skip);
    }
    if ($include !== '') {
        $cmd .= ' --include ' . escapeshellarg($include);
    }

    // Create a log file for the scan output
    $log_dir = REPORTS_DIR . '/' . $project;
    if (!is_dir($log_dir)) {
        mkdir($log_dir, 0775, true);
        chmod($log_dir, 0775 | 02000); // group-writable + setgid
    }
    $log_file = $log_dir . '/scan-running.log';

    // Run in background, capture PID
    $full_cmd = "nohup $cmd > " . escapeshellarg($log_file) . " 2>&1 & echo $!";
    $pid = trim(shell_exec($full_cmd));

    if ($pid && is_numeric($pid)) {
        file_put_contents(PID_DIR . "/$project.pid", $pid);
        return (int)$pid;
    }

    return false;
}

/**
 * Get the running scan log for a project.
 */
function get_scan_log(string $project): string {
    $project = sanitize_project($project);
    $log_file = REPORTS_DIR . '/' . $project . '/scan-running.log';
    if (!file_exists($log_file)) return '';
    return file_get_contents($log_file);
}

/**
 * Map severity to a CSS class.
 */
function severity_class(string $severity): string {
    $severity = strtolower($severity);
    return match($severity) {
        'error', 'high', 'critical' => 'severity-high',
        'warning', 'medium' => 'severity-medium',
        'info', 'low' => 'severity-low',
        default => 'severity-info',
    };
}

/**
 * Map owner to a display label.
 */
function owner_label(string $owner): string {
    return match($owner) {
        'userspice-core' => 'UserSpice Core',
        'userspice-customizable' => 'UserSpice (Customizable)',
        'project' => 'Your Code',
        'dependency' => 'Dependency',
        default => $owner,
    };
}

/**
 * Format a timestamp from report directory name (YYYYMMDD-HHMMSS).
 */
function format_report_date(string $id): string {
    if (preg_match('/^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})$/', $id, $m)) {
        return "{$m[1]}-{$m[2]}-{$m[3]} {$m[4]}:{$m[5]}:{$m[6]}";
    }
    return $id;
}

/**
 * Simple JSON API response helper.
 */
function json_response(array $data, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}
