#!/usr/bin/env bash
set -uo pipefail
# Note: -e intentionally omitted — we want the scan to continue when individual tools fail

# ============================================================================
# scan.sh — UserSpice Security Scanner Orchestrator
#
# Usage:
#   ./scan.sh <project>                  Scan /var/www/html/<project> with all tools
#   ./scan.sh <project> --only semgrep   Run only semgrep
#   ./scan.sh <project> --only psalm     Run only psalm
#   ./scan.sh <project> --only trivy     Run only trivy
#   ./scan.sh <project> --only gitleaks  Run only gitleaks
#   ./scan.sh <project> --only zap       Run only ZAP
#   ./scan.sh <project> --skip psalm     Skip psalm (comma-separated: --skip psalm,trivy)
#   ./scan.sh <project> --include phpstan  Include opt-in tools (comma-separated)
#   ./scan.sh <project> --url <url>      Target URL for ZAP + header checks
#   ./scan.sh <project> --zap-profile quick|standard|deep   ZAP scan profile (default: standard)
#   ./scan.sh <project> --pull           Pull latest Docker images before scanning
#   ./scan.sh <project> --init           Create per-project override templates
#   ./scan.sh <project> --prune [N]      Keep only N most recent reports (default: 5)
#   ./scan.sh <project> --threshold high  Exit 1 if new findings >= severity (critical,high,medium,low)
#   ./scan.sh <project> --sarif          Output SARIF 2.1.0 (GitHub Code Scanning)
#   ./scan.sh <project> --report         Generate self-contained HTML report for clients
#   ./scan.sh --list-reports <project>   List previous scan reports
#   ./scan.sh --latest <project>         Show path to latest report
#   ./scan.sh --help                     Show this help
#
# Reports are written to: reports/<project>/<timestamp>/
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source modules
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/semgrep.sh"
source "${SCRIPT_DIR}/lib/psalm.sh"
source "${SCRIPT_DIR}/lib/trivy.sh"
source "${SCRIPT_DIR}/lib/gitleaks.sh"
source "${SCRIPT_DIR}/lib/summary.sh"
source "${SCRIPT_DIR}/lib/init-overrides.sh"
source "${SCRIPT_DIR}/lib/prescan.sh"
source "${SCRIPT_DIR}/lib/classmap.sh"
source "${SCRIPT_DIR}/lib/zap.sh"
source "${SCRIPT_DIR}/lib/headers.sh"
source "${SCRIPT_DIR}/lib/delta.sh"
source "${SCRIPT_DIR}/lib/owners.sh"
source "${SCRIPT_DIR}/lib/prune.sh"
source "${SCRIPT_DIR}/lib/suppressions.sh"
source "${SCRIPT_DIR}/lib/phpstan.sh"

# ---- CLI Parsing ----
usage() {
    sed -n '/^# Usage:/,/^# ===/p' "$0" | sed 's/^# \?//'
    exit 0
}

PROJECT=""
ONLY_TOOL=""
SKIP_TOOLS=""
INCLUDE_TOOLS=""

# Tools that are off by default — require --include or --only to run
OPT_IN_TOOLS="phpstan"
PULL_IMAGES=false
LIST_REPORTS=false
SHOW_LATEST=false
CHECK_UPDATES=false
INIT_OVERRIDES=false
TARGET_URL=""
ZAP_PROFILE="standard"
ZAP_USER=""
ZAP_PASS=""
ZAP_LOGIN_PATH=""
PRUNE_REPORTS=false
PRUNE_KEEP=5
THRESHOLD=""
SARIF_OUTPUT=false
HTML_REPORT=false
DIFF_REF=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)       usage ;;
        --only)          ONLY_TOOL="$2"; shift 2 ;;
        --skip)          SKIP_TOOLS="$2"; shift 2 ;;
        --include)       INCLUDE_TOOLS="$2"; shift 2 ;;
        --pull)          PULL_IMAGES=true; shift ;;
        --init)          INIT_OVERRIDES=true; shift ;;
        --list-reports)  LIST_REPORTS=true; shift ;;
        --latest)        SHOW_LATEST=true; shift ;;
        --check-updates) CHECK_UPDATES=true; shift ;;
        --url)           TARGET_URL="$2"; shift 2 ;;
        --zap-profile)   ZAP_PROFILE="$2"; shift 2 ;;
        --zap-user)      ZAP_USER="$2"; shift 2 ;;
        --zap-pass)      ZAP_PASS="$2"; shift 2 ;;
        --zap-login)     ZAP_LOGIN_PATH="$2"; shift 2 ;;
        --prune)         PRUNE_REPORTS=true
                         if [[ "${2:-}" =~ ^[0-9]+$ ]]; then PRUNE_KEEP="$2"; shift; fi
                         shift ;;
        --threshold)     THRESHOLD="$2"; shift 2 ;;
        --sarif)         SARIF_OUTPUT=true; shift ;;
        --report)        HTML_REPORT=true; shift ;;
        --diff)          DIFF_REF="HEAD~1"
                         if [[ "${2:-}" != "" && "${2:-}" != -* ]]; then DIFF_REF="$2"; shift; fi
                         shift ;;
        -*)              log_error "Unknown option: $1"; usage ;;
        *)               PROJECT="$1"; shift ;;
    esac
done

# ---- Standalone modes that don't require a project ----
if $CHECK_UPDATES; then
    check_image_updates
    exit 0
fi

if [[ -z "$PROJECT" ]]; then
    log_error "Project name is required."
    echo ""
    usage
fi

# ---- Report listing mode ----
if $LIST_REPORTS; then
    report_dir="${REPORTS_DIR}/${PROJECT}"
    if [[ -d "$report_dir" ]]; then
        echo "Reports for ${PROJECT}:"
        ls -1t "$report_dir" | head -20
    else
        echo "No reports found for ${PROJECT}"
    fi
    exit 0
fi

if $SHOW_LATEST; then
    report_dir="${REPORTS_DIR}/${PROJECT}"
    if [[ -d "$report_dir" ]]; then
        latest=$(ls -1t "$report_dir" | head -1)
        if [[ -n "$latest" ]]; then
            echo "${report_dir}/${latest}"
        else
            echo "No reports found for ${PROJECT}"
            exit 1
        fi
    else
        echo "No reports found for ${PROJECT}"
        exit 1
    fi
    exit 0
fi

# ---- Init overrides mode ----
if $INIT_OVERRIDES; then
    init_overrides "$PROJECT"
    exit 0
fi

# ---- Prune mode ----
if $PRUNE_REPORTS; then
    prune_reports "$PROJECT" "$PRUNE_KEEP"
    exit 0
fi

# ---- Main scan flow ----
if [[ ! -f "${SCANNER_ROOT}/scanner.conf" ]]; then
    log_warn "scanner.conf not found. Run ./setup.sh first for full configuration."
    log_warn "Using default scan directory: ${BASE_SCAN_DIR}"
fi

log_header "UserSpice Security Scanner"
log_info "Project:  ${PROJECT}"

check_prerequisites

PROJECT_DIR="$(resolve_project_dir "$PROJECT")" || exit 1
REPORT_DIR="$(setup_report_dir "$PROJECT")"

log_info "Scan dir: ${PROJECT_DIR}"
log_info "Report:   ${REPORT_DIR}"

# Helper: check if a tool should run
should_run() {
    local tool="$1"

    # If --only is set, only run that tool
    if [[ -n "$ONLY_TOOL" ]]; then
        [[ "$ONLY_TOOL" == "$tool" ]]
        return
    fi

    # If --skip includes this tool, skip it
    if [[ -n "$SKIP_TOOLS" ]]; then
        echo "$SKIP_TOOLS" | tr ',' '\n' | grep -qx "$tool" && return 1
    fi

    # Opt-in tools require --include to run
    if echo "$OPT_IN_TOOLS" | tr ',' '\n' | grep -qx "$tool"; then
        echo "$INCLUDE_TOOLS" | tr ',' '\n' | grep -qx "$tool" && return 0
        return 1
    fi

    return 0
}

# Pull images if requested
if $PULL_IMAGES; then
    log_header "Pulling Docker Images"
    should_run semgrep  && docker pull "${SEMGREP_IMAGE}"
    should_run psalm    && docker pull "${PSALM_IMAGE}"
    should_run trivy    && docker pull "${TRIVY_IMAGE}"
    should_run gitleaks && docker pull "${GITLEAKS_IMAGE}"
    should_run phpstan  && docker pull "${PHPSTAN_IMAGE}"
    should_run zap      && docker pull "${ZAP_IMAGE}"
fi

# Pre-scan: discover project structure
run_prescan "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR"

# Diff mode: discover changed files
CHANGED_FILES=""
if [[ -n "$DIFF_REF" ]]; then
    if git -C "$PROJECT_DIR" rev-parse HEAD &>/dev/null; then
        log_info "Diff mode: comparing against ${DIFF_REF}"
        CHANGED_FILES=$(git -C "$PROJECT_DIR" diff --name-only "$DIFF_REF" HEAD -- '*.php' '*.js' 2>/dev/null || true)
        local_count=$(echo "$CHANGED_FILES" | grep -c . || true)
        log_info "  ${local_count} changed PHP/JS file(s)"
        echo "$CHANGED_FILES" > "${REPORT_DIR}/changed-files.txt"
        export SCANNER_DIFF_FILES="${REPORT_DIR}/changed-files.txt"
    else
        log_warn "Not a git repository — ignoring --diff"
        DIFF_REF=""
    fi
fi

# Save scan options so the report knows what was run
cat > "${REPORT_DIR}/scan-options.json" <<OPTS
{
    "url": $(printf '%s' "${TARGET_URL}" | jq -Rs .),
    "zap_profile": $(printf '%s' "${ZAP_PROFILE}" | jq -Rs .),
    "zap_user": $(printf '%s' "${ZAP_USER}" | jq -Rs .),
    "zap_pass": $(printf '%s' "${ZAP_PASS}" | jq -Rs .),
    "zap_login_path": $(printf '%s' "${ZAP_LOGIN_PATH}" | jq -Rs .),
    "only": $(printf '%s' "${ONLY_TOOL}" | jq -Rs .),
    "skip": $(printf '%s' "${SKIP_TOOLS}" | jq -Rs .),
    "include": $(printf '%s' "${INCLUDE_TOOLS}" | jq -Rs .),
    "diff_ref": $(printf '%s' "${DIFF_REF}" | jq -Rs .)
}
OPTS

# Track overall timing and results
SCAN_START="$(timer_start)"
TOOLS_RUN=0
TOOLS_FAILED=0
declare -A TOOL_STATUS

# Helper: run a tool and record its status
run_tool() {
    local tool="$1"
    shift
    if should_run "$tool"; then
        if "$@"; then
            TOOL_STATUS[$tool]="success"
            ((TOOLS_RUN++))
        else
            TOOL_STATUS[$tool]="failed"
            ((TOOLS_FAILED++))
            ((TOOLS_RUN++))
        fi
    else
        TOOL_STATUS[$tool]="skipped"
    fi
}

# Run each tool
run_tool semgrep run_semgrep "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR"
run_tool psalm run_psalm "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR"
run_tool trivy run_trivy "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR"
run_tool gitleaks run_gitleaks "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR"
run_tool phpstan run_phpstan "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR"

# ZAP requires a target URL — auto-derive or use --url
if should_run zap; then
    local_url="${TARGET_URL:-http://localhost/${PROJECT}/}"
    run_tool zap run_zap "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR" "$local_url" "$ZAP_PROFILE" "$ZAP_USER" "$ZAP_PASS" "$ZAP_LOGIN_PATH"
else
    TOOL_STATUS[zap]="skipped"
fi

# HTTP header check (runs if we have a URL, regardless of --only)
if [[ -n "$TARGET_URL" ]] || should_run zap; then
    header_url="${TARGET_URL:-http://localhost/${PROJECT}/}"
    if run_header_check "$PROJECT" "$header_url" "$REPORT_DIR"; then
        TOOL_STATUS[headers]="success"
    else
        TOOL_STATUS[headers]="failed"
    fi
else
    TOOL_STATUS[headers]="skipped"
fi

# Write tool status JSON
_first=true
{
    echo '{'
    for tool in semgrep psalm trivy gitleaks phpstan zap headers; do
        $_first || echo ','
        printf '  "%s": "%s"' "$tool" "${TOOL_STATUS[$tool]:-skipped}"
        _first=false
    done
    echo ''
    echo '}'
} > "${REPORT_DIR}/tool-status.json"

TOTAL_ELAPSED="$(timer_elapsed "$SCAN_START")"

# Generate unified summary
generate_summary "$PROJECT" "$PROJECT_DIR" "$REPORT_DIR" "$TOTAL_ELAPSED"

# Enrich findings with owner classification
enrich_findings_with_owners "$REPORT_DIR"

# Apply user suppressions
apply_suppressions "$PROJECT" "$REPORT_DIR"

# Diff mode: filter findings to only changed files (for tools that scan everything)
if [[ -n "$DIFF_REF" && -f "${REPORT_DIR}/changed-files.txt" && -f "${REPORT_DIR}/summary.json" ]]; then
    log_info "Diff mode: filtering findings to changed files..."
    jq --slurpfile cf <(jq -R '.' "${REPORT_DIR}/changed-files.txt" | jq -s '.') '
        ($cf[0] | map(select(. != ""))) as $files |
        def in_changed: . as $f | ($f | gsub("^(/?\\.\\./)?/?src/";"")) as $clean | $files | any(. == $clean);
        .findings.psalm = [.findings.psalm[]? | select(.file | in_changed)] |
        .findings.phpstan = [.findings.phpstan[]? | select(.file | in_changed)] |
        .totals.psalm = (.findings.psalm | length) |
        .totals.phpstan = (.findings.phpstan | length) |
        .totals.all_findings = (.totals.semgrep + .totals.psalm + .totals.phpstan + .totals.trivy_vulnerabilities + .totals.trivy_misconfigurations + .totals.trivy_secrets + .totals.gitleaks + .totals.zap) |
        .meta.diff_mode = true |
        .meta.changed_files = ($files | length)
    ' "${REPORT_DIR}/summary.json" > "${REPORT_DIR}/summary.json.tmp" && mv "${REPORT_DIR}/summary.json.tmp" "${REPORT_DIR}/summary.json"
fi

# Delta analysis vs previous scan
generate_delta "$PROJECT" "$REPORT_DIR"

# SARIF export
if $SARIF_OUTPUT; then
    source "${SCRIPT_DIR}/lib/sarif.sh"
    generate_sarif "$REPORT_DIR"
fi

# HTML report
if $HTML_REPORT; then
    source "${SCRIPT_DIR}/lib/report-html.sh"
    generate_html_report "$REPORT_DIR"
fi

# Final status
echo ""
if [[ $TOOLS_FAILED -eq 0 ]]; then
    log_success "All ${TOOLS_RUN} tools completed successfully."
else
    log_warn "${TOOLS_FAILED} of ${TOOLS_RUN} tools had errors. Check stderr logs in ${REPORT_DIR}."
fi

echo ""
log_info "Full reports: ${REPORT_DIR}/"
log_info "Summary:      ${REPORT_DIR}/summary.json"
if [[ -f "${REPORT_DIR}/delta.json" ]]; then
    log_info "Delta:        ${REPORT_DIR}/delta.json"
fi
if [[ -f "${REPORT_DIR}/results.sarif" ]]; then
    log_info "SARIF:        ${REPORT_DIR}/results.sarif"
fi
if [[ -f "${REPORT_DIR}/report.html" ]]; then
    log_info "HTML Report:  ${REPORT_DIR}/report.html"
fi
if [[ -f "${REPORT_DIR}/zap.json" ]]; then
    log_info "ZAP report:   ${REPORT_DIR}/zap.html"
fi
if [[ -f "${REPORT_DIR}/headers.json" ]]; then
    log_info "Headers:      ${REPORT_DIR}/headers.json"
fi
echo ""
log_info "To review with AI: open a conversation in this repo and reference the summary.json path."

# Copy the running log into the report directory for future reference
RUNNING_LOG="${REPORTS_DIR}/${PROJECT}/scan-running.log"
if [[ -f "$RUNNING_LOG" ]]; then
    cp "$RUNNING_LOG" "${REPORT_DIR}/scan.log" 2>/dev/null || true
fi

# Threshold gate — exit 1 if findings meet or exceed the severity level
# Checked last so all output and log copying happens first
if [[ -n "$THRESHOLD" && -f "${REPORT_DIR}/summary.json" ]]; then
    # Severity ordering: critical=4, high=3, medium=2, low=1
    case "$THRESHOLD" in
        critical) min_level=4 ;;
        high)     min_level=3 ;;
        medium)   min_level=2 ;;
        low)      min_level=1 ;;
        *)        log_error "Unknown threshold: $THRESHOLD (use critical, high, medium, low)"; exit 2 ;;
    esac

    # Count findings at or above threshold using normalized_severity
    breach_count=$(jq --argjson min "$min_level" '
        [
            .findings | to_entries[] | .value |
            if type == "array" then .[] else empty end |
            .normalized_severity as $s |
            (if $s == "critical" then 4 elif $s == "high" then 3 elif $s == "medium" then 2 elif $s == "low" then 1 else 0 end) |
            select(. >= $min)
        ] | length
    ' "${REPORT_DIR}/summary.json")

    if [[ "$breach_count" -gt 0 ]]; then
        log_error "Threshold breach: ${breach_count} finding(s) at or above '${THRESHOLD}' severity."
        exit 1
    else
        log_success "Threshold check passed: no findings at or above '${THRESHOLD}' severity."
    fi
fi
