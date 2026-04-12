#!/usr/bin/env bash
# Common functions and configuration for the scanning stack

# ----- Tool Docker images (pin versions for reproducibility) -----
SEMGREP_IMAGE="returntocorp/semgrep:1.156.0"
PSALM_IMAGE="ghcr.io/psalm/psalm-github-actions@sha256:0f3baedfc96a630074b94f71d1a143a859048bfeeed8a79ee48e9c07b26e2eae"
TRIVY_IMAGE="aquasec/trivy:0.69.3"
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.1"
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
PHPSTAN_IMAGE="ghcr.io/phpstan/phpstan@sha256:ae7325faaeb3bc6aa62b0584806b8214f17d9973e8d2f7cbe808070841477c63"

# ----- Paths -----
SCANNER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHARED_DIR="${SCANNER_ROOT}/shared"
OVERRIDES_DIR="${SCANNER_ROOT}/overrides"
REPORTS_DIR="${SCANNER_ROOT}/reports"
LIB_DIR="${SCANNER_ROOT}/lib"

# Load local config (created by setup.sh)
CONF_FILE="${SCANNER_ROOT}/scanner.conf"
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
fi
# Default if not set by config
BASE_SCAN_DIR="${BASE_SCAN_DIR:-/var/www/html}"
ZAP_DOCKER_NETWORK="${ZAP_DOCKER_NETWORK:-}"

# ----- Colors -----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ----- Logging -----
log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_header()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}\n"; }

# ----- Setup -----
setup_report_dir() {
    local project="$1"
    local timestamp
    timestamp="$(date +%Y%m%d-%H%M%S)"
    REPORT_OUT="${REPORTS_DIR}/${project}/${timestamp}"
    mkdir -p "${REPORT_OUT}"
    # Ensure group-writable so both terminal user and www-data can create reports
    chmod g+ws "${REPORTS_DIR}/${project}" 2>/dev/null || true
    chmod g+ws "${REPORT_OUT}" 2>/dev/null || true
    echo "${REPORT_OUT}"
}

# Resolve the project's scan target directory
resolve_project_dir() {
    local project="$1"
    local project_dir="${BASE_SCAN_DIR}/${project}"

    if [[ ! -d "$project_dir" ]]; then
        log_error "Project directory not found: ${project_dir}"
        return 1
    fi

    echo "${project_dir}"
}

# Get a config file, preferring project-specific override over shared default
resolve_config() {
    local tool="$1"
    local filename="$2"
    local project="$3"

    local override="${OVERRIDES_DIR}/${project}/${tool}/${filename}"
    local shared="${SHARED_DIR}/${tool}/${filename}"

    if [[ -f "$override" ]]; then
        echo "$override"
    elif [[ -f "$shared" ]]; then
        echo "$shared"
    else
        echo ""
    fi
}

# Check if a Docker image is available, pull if not
ensure_image() {
    local image="$1"
    if ! docker image inspect "$image" &>/dev/null; then
        log_info "Pulling ${image}..."
        docker pull "$image" || {
            log_error "Failed to pull ${image}"
            return 1
        }
    fi
}

# Record tool timing
timer_start() { date +%s; }
timer_elapsed() {
    local start="$1"
    local end
    end="$(date +%s)"
    echo $(( end - start ))
}

# Check for newer Docker image versions
check_image_updates() {
    log_header "Docker Image Update Check"

    if ! command -v curl &>/dev/null; then
        log_error "curl is required for update checks"
        return 1
    fi

    local semver_pat='^[0-9]+\.[0-9]+\.[0-9]+$'
    local vsemver_pat='^v[0-9]+\.[0-9]+\.[0-9]+$'

    printf "  %-25s %-20s %-20s %s\n" "Image" "Pinned" "Latest" "Status"
    printf "  %-25s %-20s %-20s %s\n" "-----" "------" "------" "------"

    _check_hub_tag() {
        local repo="$1" pinned_tag="$2" tag_pat="$3"
        local latest
        latest=$(curl -sf "https://hub.docker.com/v2/repositories/${repo}/tags/?page_size=100&ordering=last_updated" 2>/dev/null \
            | jq -r --arg pat "$tag_pat" \
                '[.results[] | select(.name | test($pat))] | sort_by(.last_updated) | reverse | .[0].name // "unknown"' \
                2>/dev/null) || latest="error"

        local status="OK"
        if [[ "$latest" == "error" || "$latest" == "unknown" ]]; then
            status="?"
        elif [[ "$latest" != "$pinned_tag" ]]; then
            status="UPDATE AVAILABLE"
        fi

        printf "  %-25s %-20s %-20s %s\n" "$repo" "$pinned_tag" "$latest" "$status"
    }

    _check_hub_tag "returntocorp/semgrep" "${SEMGREP_IMAGE##*:}" "$semver_pat"
    _check_hub_tag "aquasec/trivy" "${TRIVY_IMAGE##*:}" "$semver_pat"
    _check_hub_tag "zricethezav/gitleaks" "${GITLEAKS_IMAGE##*:}" "$vsemver_pat"

    # SHA-pinned images — just note they're pinned
    echo ""
    log_info "SHA-pinned images (check manually):"
    echo "  ghcr.io/psalm/psalm-github-actions (pinned by SHA)"
    echo "  ghcr.io/phpstan/phpstan (pinned by SHA)"
    echo "  ghcr.io/zaproxy/zaproxy:stable (floating tag)"
    echo ""
    log_info "Update versions in lib/common.sh, then run: ./scan.sh <project> --pull"
}

# Check prerequisites
check_prerequisites() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker is required but not installed."
        exit 1
    fi

    if ! docker info &>/dev/null 2>&1; then
        log_error "Docker daemon is not running or current user lacks permissions."
        exit 1
    fi

    if ! command -v jq &>/dev/null; then
        log_warn "jq is not installed. Summary generation will be limited."
        log_warn "Install with: sudo apt-get install jq"
    fi
}
