<?php
/**
 * UserSpice Security Scanner — API Endpoints
 *
 * ?action=projects              List all discoverable projects
 * ?action=scan&project=X        Start a scan
 * ?action=status&project=X      Check scan status
 * ?action=reports&project=X     List reports for a project
 * ?action=report&project=X&id=Y Get a specific report
 * ?action=suppress              Add suppression(s)
 * ?action=unsuppress            Remove suppression(s)
 * ?action=suppressions          List suppressions for a project
 * ?action=scanlog               Get scan log
 * ?action=snippet               Get source code snippet
 * ?action=docs                  Get HOW-IT-WORKS.md
 * ?action=preflight             Check environment
 * ?action=prune&project=X       Prune old reports
 */

require_once __DIR__ . '/helpers.php';

if (session_status() === PHP_SESSION_NONE) session_start();

// Read action from GET, POST, or JSON body
$_json_body = null;
if (($_SERVER['CONTENT_TYPE'] ?? '') === 'application/json') {
    $_json_body = json_decode(file_get_contents('php://input'), true) ?: [];
}
$action = $_GET['action'] ?? $_POST['action'] ?? $_json_body['action'] ?? '';
$project = sanitize_project($_GET['project'] ?? $_POST['project'] ?? $_json_body['project'] ?? '');

// Auth endpoints are always accessible
if ($action === 'auth-status') {
    json_response([
        'authenticated' => is_authenticated(),
        'has_password' => has_password(),
        'setup_complete' => SETUP_COMPLETE,
    ]);
}

if ($action === 'login') {
    $password = $_POST['password'] ?? $_json_body['password'] ?? '';
    if (verify_password($password)) {
        $_SESSION['scanner_auth'] = true;
        json_response(['success' => true]);
    }
    json_response(['error' => 'Invalid password'], 401);
}

if ($action === 'set-password') {
    // Only allow if no password set yet, or if already authenticated
    if (has_password() && !is_authenticated()) {
        json_response(['error' => 'authentication required'], 401);
    }
    $password = $_POST['password'] ?? $_json_body['password'] ?? '';
    if (strlen($password) < 6) {
        json_response(['error' => 'Password must be at least 6 characters'], 400);
    }
    if (set_password($password)) {
        $_SESSION['scanner_auth'] = true;
        json_response(['success' => true]);
    }
    json_response(['error' => 'Failed to save password'], 500);
}

if ($action === 'logout') {
    $_SESSION = [];
    session_destroy();
    json_response(['success' => true]);
}

// All other endpoints require authentication
require_auth(true);

switch ($action) {

    case 'projects':
        json_response([
            'projects' => discover_projects(),
            'setup_complete' => SETUP_COMPLETE,
            'base_scan_dir' => BASE_SCAN_DIR,
        ]);

    case 'preflight':
        // Check if the environment is ready to run scans
        $checks = [];

        // Docker installed?
        $docker_path = trim(shell_exec('which docker 2>/dev/null') ?? '');
        $checks['docker_installed'] = $docker_path !== '';

        // Docker daemon accessible by this user?
        $docker_ok = false;
        if ($checks['docker_installed']) {
            exec('docker info 2>&1', $out, $code);
            $docker_ok = ($code === 0);
        }
        $checks['docker_accessible'] = $docker_ok;

        // Who are we running as?
        $checks['web_user'] = trim(shell_exec('whoami') ?? 'unknown');
        $checks['web_user_groups'] = trim(shell_exec('groups 2>/dev/null') ?? '');
        $checks['in_docker_group'] = str_contains($checks['web_user_groups'], 'docker');

        // jq installed?
        $checks['jq_installed'] = trim(shell_exec('which jq 2>/dev/null') ?? '') !== '';

        // scan.sh exists and is executable?
        $checks['scanner_exists'] = file_exists(SCAN_SCRIPT);
        $checks['scanner_executable'] = is_executable(SCAN_SCRIPT);

        $checks['ready'] = $checks['docker_accessible'] && $checks['jq_installed'] && $checks['scanner_executable'];

        json_response($checks);

    case 'scan':
        if (!$project) json_response(['error' => 'project required'], 400);
        if (!project_exists($project)) json_response(['error' => 'project not found'], 404);
        if (is_scanning($project)) json_response(['error' => 'scan already running', 'scanning' => true], 409);

        $url = trim($_POST['url'] ?? '');
        $zap_profile = sanitize_project($_POST['zap_profile'] ?? 'standard');
        $zap_user = trim($_POST['zap_user'] ?? '');
        $zap_pass = $_POST['zap_pass'] ?? '';
        $zap_login = trim($_POST['zap_login'] ?? '');
        $skip = preg_replace('/[^a-zA-Z0-9,]/', '', $_POST['skip'] ?? '');
        $include = preg_replace('/[^a-zA-Z0-9,]/', '', $_POST['include'] ?? '');

        $pid = start_scan($project, $url, $zap_profile, $zap_user, $zap_pass, $skip, $zap_login, $include);
        if ($pid) {
            json_response(['started' => true, 'pid' => $pid, 'project' => $project]);
        } else {
            json_response(['error' => 'failed to start scan'], 500);
        }

    case 'status':
        if (!$project) json_response(['error' => 'project required'], 400);
        $scanning = is_scanning($project);
        $log = $scanning ? get_scan_log($project) : '';
        // Strip ANSI color codes for clean display
        $log = preg_replace('/\033\[[0-9;]*m/', '', $log);
        json_response([
            'project' => $project,
            'scanning' => $scanning,
            'log' => $log,
        ]);

    case 'reports':
        if (!$project) json_response(['error' => 'project required'], 400);
        $reports = get_reports($project);
        // Slim down for listing — don't include full findings
        $slim = array_map(function($r) {
            return [
                'id' => $r['id'],
                'date' => format_report_date($r['id']),
                'totals' => $r['summary']['totals'] ?? null,
                'owner_summary' => $r['summary']['owner_summary'] ?? null,
                'duration' => $r['summary']['meta']['duration_seconds'] ?? null,
                'options' => $r['summary']['meta']['options'] ?? null,
                'tool_status' => $r['summary']['meta']['tool_status'] ?? null,
                'has_delta' => $r['delta'] !== null,
                'has_headers' => $r['headers'] !== null,
                'has_zap' => $r['has_zap_html'],
            ];
        }, $reports);
        json_response(['project' => $project, 'reports' => $slim]);

    case 'report':
        if (!$project) json_response(['error' => 'project required'], 400);
        $id = sanitize_project($_GET['id'] ?? '');
        if (!$id) json_response(['error' => 'report id required'], 400);

        $report_path = REPORTS_DIR . "/$project/$id/summary.json";
        if (!file_exists($report_path)) json_response(['error' => 'report not found'], 404);

        $summary = json_decode(file_get_contents($report_path), true);

        $delta = null;
        $delta_path = REPORTS_DIR . "/$project/$id/delta.json";
        if (file_exists($delta_path)) {
            $delta = json_decode(file_get_contents($delta_path), true);
        }

        $headers = null;
        $headers_path = REPORTS_DIR . "/$project/$id/headers.json";
        if (file_exists($headers_path)) {
            $headers = json_decode(file_get_contents($headers_path), true);
        }

        // Scan log — check report dir first, then project-level running log
        $scan_log = '';
        $log_candidates = [
            REPORTS_DIR . "/$project/$id/scan.log",
            REPORTS_DIR . "/$project/scan-running.log",
        ];
        foreach ($log_candidates as $lf) {
            if (file_exists($lf) && filesize($lf) > 0) {
                $scan_log = file_get_contents($lf);
                // Strip ANSI color codes
                $scan_log = preg_replace('/\033\[[0-9;]*m/', '', $scan_log);
                break;
            }
        }

        json_response([
            'project' => $project,
            'id' => $id,
            'summary' => $summary,
            'delta' => $delta,
            'headers' => $headers,
            'has_zap_html' => file_exists(REPORTS_DIR . "/$project/$id/zap.html"),
            'has_scan_log' => $scan_log !== '',
        ]);

    case 'prune':
        if (!$project) json_response(['error' => 'project required'], 400);
        $keep = max(1, intval($_POST['keep'] ?? 5));
        $before = count_reports($project);
        shell_exec(escapeshellcmd(SCAN_SCRIPT) . ' ' . escapeshellarg($project) . ' --prune ' . intval($keep) . ' 2>&1');
        $after = count_reports($project);
        json_response(['pruned' => $before - $after, 'remaining' => $after]);

    case 'suppress':
        if (!$project) json_response(['error' => 'project required'], 400);

        // Accept single or bulk suppressions
        $input = $_json_body;
        if (!$input) json_response(['error' => 'JSON body required'], 400);

        $items = isset($input['items']) ? $input['items'] : [$input];
        $supps_file = SCANNER_ROOT . "/overrides/$project/suppressions.json";
        $supps_dir = dirname($supps_file);
        if (!is_dir($supps_dir)) mkdir($supps_dir, 0775, true);

        $existing = [];
        if (file_exists($supps_file)) {
            $existing = json_decode(file_get_contents($supps_file), true) ?: [];
        }

        $added = 0;
        foreach ($items as $item) {
            $tool = $item['tool'] ?? '';
            $rule = $item['rule'] ?? '';
            $file = $item['file'] ?? '';
            $scope = $item['scope'] ?? 'exact'; // exact, file, rule

            if (!$tool || !$rule) continue;

            // Clean file path
            $file = preg_replace('#^(/?\.\./)?/?src/#', '', $file);
            $file = ltrim($file, '/');

            // Generate content hash if we have file + line
            $content_hash = '';
            $line = intval($item['line'] ?? 0);
            if ($scope === 'exact' && $file && $line > 0 && project_exists($project)) {
                $full_path = BASE_SCAN_DIR . '/' . sanitize_project($project) . '/' . $file;
                if (file_exists($full_path)) {
                    $lines = file($full_path);
                    if (isset($lines[$line - 1])) {
                        $content_hash = md5(preg_replace('/\s+/', '', $lines[$line - 1]));
                    }
                }
            }

            $entry = [
                'tool' => $tool,
                'rule' => $rule,
                'file' => $file,
                'line' => $line,
                'content_hash' => $content_hash,
                'scope' => $scope,
                'disposition' => $item['disposition'] ?? 'not_vulnerable',
                'reason' => $item['reason'] ?? '',
                'date' => date('Y-m-d'),
            ];

            // Check for duplicate (same tool+rule+file+hash or tool+rule+file+line)
            $dup = false;
            foreach ($existing as $e) {
                if ($e['tool'] === $entry['tool'] && $e['rule'] === $entry['rule'] && $e['file'] === $entry['file']) {
                    if ($scope !== 'exact' || ($e['content_hash'] && $e['content_hash'] === $entry['content_hash']) || ($e['line'] === $entry['line'])) {
                        $dup = true;
                        break;
                    }
                }
            }

            if (!$dup) {
                $existing[] = $entry;
                $added++;
            }
        }

        file_put_contents($supps_file, json_encode($existing, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        json_response(['added' => $added, 'total' => count($existing)]);

    case 'unsuppress':
        if (!$project) json_response(['error' => 'project required'], 400);

        $input = $_json_body;
        if (!$input) json_response(['error' => 'JSON body required'], 400);

        $supps_file = SCANNER_ROOT . "/overrides/$project/suppressions.json";
        if (!file_exists($supps_file)) json_response(['removed' => 0, 'total' => 0]);

        $existing = json_decode(file_get_contents($supps_file), true) ?: [];
        $tool = $input['tool'] ?? '';
        $rule = $input['rule'] ?? '';
        $file = preg_replace('#^(/?\.\./)?/?src/#', '', $input['file'] ?? '');
        $line = intval($input['line'] ?? 0);

        $before = count($existing);
        $existing = array_values(array_filter($existing, function($e) use ($tool, $rule, $file, $line) {
            if ($e['tool'] !== $tool || $e['rule'] !== $rule) return true;
            if ($file && $e['file'] !== $file) return true;
            if ($line && $e['line'] !== $line) return true;
            return false; // Match — remove it
        }));

        file_put_contents($supps_file, json_encode($existing, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        json_response(['removed' => $before - count($existing), 'total' => count($existing)]);

    case 'suppressions':
        if (!$project) json_response(['error' => 'project required'], 400);

        // Load project suppressions
        $supps_file = SCANNER_ROOT . "/overrides/$project/suppressions.json";
        $project_supps = file_exists($supps_file) ? (json_decode(file_get_contents($supps_file), true) ?: []) : [];

        // Load shared suppressions
        $shared_file = SCANNER_ROOT . '/shared/suppressions.json';
        $shared_supps = file_exists($shared_file) ? (json_decode(file_get_contents($shared_file), true) ?: []) : [];

        // Load ZAP rules
        $zap_rules = [];
        $zap_file = SCANNER_ROOT . '/shared/zap/rules.tsv';
        if (file_exists($zap_file)) {
            foreach (file($zap_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if (str_starts_with(trim($line), '#')) continue;
                $parts = explode("\t", $line);
                if (count($parts) >= 3 && strtoupper($parts[1]) === 'IGNORE') {
                    $zap_rules[] = ['id' => $parts[0], 'action' => $parts[1], 'description' => $parts[2]];
                }
            }
        }

        // Load semgrepignore paths
        $ignore_paths = [];
        $ignore_file = SCANNER_ROOT . '/shared/semgrep/.semgrepignore';
        if (file_exists($ignore_file)) {
            foreach (file($ignore_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#') continue;
                $ignore_paths[] = $line;
            }
        }

        json_response([
            'project' => $project,
            'project_suppressions' => $project_supps,
            'shared_suppressions' => $shared_supps,
            'zap_ignored' => $zap_rules,
            'semgrep_ignored_paths' => $ignore_paths,
            'counts' => [
                'project' => count($project_supps),
                'shared' => count($shared_supps),
                'zap_ignored' => count($zap_rules),
                'paths_ignored' => count($ignore_paths),
            ],
        ]);

    case 'scanlog':
        if (!$project) json_response(['error' => 'project required'], 400);
        $id = sanitize_project($_GET['id'] ?? '');

        $log = '';
        $candidates = [];
        if ($id) {
            $candidates[] = REPORTS_DIR . "/$project/$id/scan.log";
        }
        $candidates[] = REPORTS_DIR . "/$project/scan-running.log";

        foreach ($candidates as $lf) {
            if (file_exists($lf) && filesize($lf) > 0) {
                $log = file_get_contents($lf);
                $log = preg_replace('/\033\[[0-9;]*m/', '', $log);
                break;
            }
        }

        json_response(['project' => $project, 'id' => $id, 'log' => $log]);

    case 'docs':
        $md_file = SCANNER_ROOT . '/HOW-IT-WORKS.md';
        if (!file_exists($md_file)) json_response(['error' => 'docs not found'], 404);
        json_response(['content' => file_get_contents($md_file)]);

    case 'snippet':
        // Read source code around a finding location
        if (!$project) json_response(['error' => 'project required'], 400);
        if (!project_exists($project)) json_response(['error' => 'project not found'], 404);

        $file = $_GET['file'] ?? '';
        $line = max(1, intval($_GET['line'] ?? 0));
        $context = max(1, min(10, intval($_GET['context'] ?? 5)));

        // Clean the file path — strip /src/ or ../src/ prefix, leading slash
        $file = preg_replace('#^(/?\.\./)?/?src/#', '', $file);
        $file = ltrim($file, '/');

        // Security: prevent path traversal
        if (str_contains($file, '..') || $file === '') {
            json_response(['error' => 'invalid file path'], 400);
        }

        $full_path = BASE_SCAN_DIR . '/' . $project . '/' . $file;
        if (!file_exists($full_path) || !is_file($full_path)) {
            json_response(['error' => 'file not found', 'path' => $file], 404);
        }

        $lines = file($full_path);
        if ($lines === false) {
            json_response(['error' => 'could not read file'], 500);
        }

        $start = max(0, $line - $context - 1);
        $end = min(count($lines), $line + $context);
        $snippet_lines = [];
        for ($i = $start; $i < $end; $i++) {
            $snippet_lines[] = [
                'num' => $i + 1,
                'text' => rtrim($lines[$i], "\r\n"),
                'highlight' => ($i + 1 === $line),
            ];
        }

        json_response([
            'file' => $file,
            'line' => $line,
            'snippet' => $snippet_lines,
        ]);

    case 'export':
        if (!$project) json_response(['error' => 'project required'], 400);
        $id = sanitize_project($_GET['id'] ?? $_POST['id'] ?? '');
        if (!$id) json_response(['error' => 'report id required'], 400);

        $report_dir = REPORTS_DIR . "/$project/$id";
        if (!file_exists("$report_dir/summary.json")) json_response(['error' => 'report not found'], 404);

        $html_path = "$report_dir/report.html";
        if (!file_exists($html_path)) {
            // Generate on demand
            $cmd = escapeshellcmd(SCANNER_ROOT . '/lib/report-html.sh');
            // Source common.sh for log functions, then call generate_html_report
            $gen = "bash -c 'source " . escapeshellarg(SCANNER_ROOT . '/lib/common.sh') . " && source " . escapeshellarg(SCANNER_ROOT . '/lib/report-html.sh') . " && generate_html_report " . escapeshellarg($report_dir) . "' 2>&1";
            shell_exec($gen);
        }

        if (file_exists($html_path)) {
            json_response(['url' => "../reports/$project/$id/report.html"]);
        } else {
            json_response(['error' => 'failed to generate report'], 500);
        }

    case 'trends':
        if (!$project) json_response(['error' => 'project required'], 400);
        $reports = get_reports($project);
        // Cap at last 50 reports, oldest first for time series
        $reports = array_slice($reports, 0, 50);
        $reports = array_reverse($reports);

        $series = [];
        foreach ($reports as $r) {
            $t = $r['summary']['totals'] ?? null;
            $sev = $r['summary']['severity_summary'] ?? null;
            if (!$t) continue;
            $series[] = [
                'date' => format_report_date($r['id']),
                'id' => $r['id'],
                'total' => $t['all_findings'] ?? 0,
                'semgrep' => $t['semgrep'] ?? 0,
                'psalm' => $t['psalm'] ?? 0,
                'trivy' => ($t['trivy_vulnerabilities'] ?? 0) + ($t['trivy_secrets'] ?? 0),
                'gitleaks' => $t['gitleaks'] ?? 0,
                'phpstan' => $t['phpstan'] ?? 0,
                'zap' => $t['zap'] ?? 0,
                'severity' => $sev,
            ];
        }
        json_response(['project' => $project, 'series' => $series]);

    default:
        json_response(['error' => 'unknown action', 'actions' => [
            'projects', 'scan', 'status', 'reports', 'report', 'snippet', 'trends', 'prune'
        ]], 400);
}
