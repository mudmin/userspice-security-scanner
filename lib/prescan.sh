#!/usr/bin/env bash
# Pre-scan module — discovers project structure before running tools
# Reports on dependency manifests, project layout, and scan-relevant metadata

run_prescan() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"

    log_header "Pre-Scan — Project Discovery"

    local prescan_file="${report_dir}/prescan.json"

    # Find dependency manifests
    local composer_locks composer_jsons package_locks package_jsons
    composer_locks=$(find "$project_dir" -name "composer.lock" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null | sed "s|${project_dir}/||g" | sort)
    composer_jsons=$(find "$project_dir" -name "composer.json" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null | sed "s|${project_dir}/||g" | sort)
    package_locks=$(find "$project_dir" -name "package-lock.json" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null | sed "s|${project_dir}/||g" | sort)
    package_jsons=$(find "$project_dir" -name "package.json" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null | sed "s|${project_dir}/||g" | sort)

    # Check for autoloader (Psalm needs this)
    local has_autoloader=false
    if [[ -f "${project_dir}/vendor/autoload.php" ]]; then
        has_autoloader=true
    fi

    # Check for UserSpice structure
    local has_users=false has_usersc=false
    [[ -d "${project_dir}/users" ]] && has_users=true
    [[ -d "${project_dir}/usersc" ]] && has_usersc=true

    # Count PHP and JS files (excluding vendor/node_modules)
    local php_count js_count
    php_count=$(find "$project_dir" -name "*.php" -not -path "*/vendor/*" -not -path "*/node_modules/*" 2>/dev/null | wc -l)
    js_count=$(find "$project_dir" -name "*.js" -not -path "*/vendor/*" -not -path "*/node_modules/*" -not -path "*/users/js/*" 2>/dev/null | wc -l)

    # Report findings
    if [[ -n "$composer_locks" ]]; then
        log_info "Composer lockfiles found:"
        echo "$composer_locks" | while read -r f; do log_info "  $f"; done
    else
        log_warn "No composer.lock found — Trivy CVE scanning for PHP deps will be limited."
    fi

    if [[ -n "$package_locks" ]]; then
        log_info "npm lockfiles found:"
        echo "$package_locks" | while read -r f; do log_info "  $f"; done
    else
        if [[ -n "$package_jsons" ]]; then
            log_warn "package.json found but no package-lock.json — run npm install to enable JS CVE scanning."
        fi
    fi

    if [[ "$has_autoloader" == "false" ]]; then
        log_warn "No vendor/autoload.php — Psalm deep analysis will be limited."
        log_warn "  Run 'composer install' in the project to enable full taint analysis."
    fi

    log_info "Project: ${php_count} PHP files, ${js_count} JS files"
    log_info "UserSpice: users/=$([ "$has_users" = true ] && echo 'yes' || echo 'no'), usersc/=$([ "$has_usersc" = true ] && echo 'yes' || echo 'no')"

    # Write prescan JSON for summary
    if command -v jq &>/dev/null; then
        jq -n \
            --argjson php_count "$php_count" \
            --argjson js_count "$js_count" \
            --argjson has_autoloader "$has_autoloader" \
            --argjson has_users "$has_users" \
            --argjson has_usersc "$has_usersc" \
            --arg composer_locks "$composer_locks" \
            --arg composer_jsons "$composer_jsons" \
            --arg package_locks "$package_locks" \
            --arg package_jsons "$package_jsons" \
            '{
                files: { php: $php_count, js: $js_count },
                userspice: { has_users: $has_users, has_usersc: $has_usersc },
                autoloader: $has_autoloader,
                dependency_manifests: {
                    composer_lock: ($composer_locks | split("\n") | map(select(. != ""))),
                    composer_json: ($composer_jsons | split("\n") | map(select(. != ""))),
                    package_lock: ($package_locks | split("\n") | map(select(. != ""))),
                    package_json: ($package_jsons | split("\n") | map(select(. != "")))
                }
            }' > "$prescan_file"
    fi
}
