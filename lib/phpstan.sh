#!/usr/bin/env bash
# PHPStan scanner module
# Handles: PHP code quality analysis (type checking, logic bugs, dead code)
#
# This is separate from security scanning — PHPStan finds code quality issues,
# not vulnerabilities. It complements Psalm (taint/security) with broader
# type-level analysis.
#
# Default: skipped unless explicitly included via --include phpstan or UI checkbox.

run_phpstan() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"

    log_header "PHPStan — PHP Code Quality Analysis"
    local start
    start="$(timer_start)"

    ensure_image "${PHPSTAN_IMAGE}" || return 1

    # Check if project has PHP files
    if ! find "${project_dir}" -maxdepth 3 -name '*.php' -print -quit 2>/dev/null | grep -q .; then
        log_warn "No PHP files found in ${project_dir}, skipping PHPStan."
        echo '[]' > "${report_dir}/phpstan.json"
        return 0
    fi

    # Prepare config staging area
    local phpstan_staging="${report_dir}/phpstan-config"
    mkdir -p "$phpstan_staging"

    # Generate phpstan.neon config
    generate_phpstan_config "$project" "$project_dir" "${phpstan_staging}/phpstan.neon"

    # Build ignore entries for vendor dirs (same approach as Psalm)
    local exclude_paths=()
    while IFS= read -r vdir; do
        exclude_paths+=("${vdir#${project_dir}/}")
    done < <(find "$project_dir" -maxdepth 4 -type d \( -name "vendor" -o -name "node_modules" \) 2>/dev/null)

    # Add static excludes
    for skip_dir in patch users/classes/phpmailer users/classes/PHPMailer; do
        if [[ -d "${project_dir}/${skip_dir}" ]]; then
            exclude_paths+=("$skip_dir")
        fi
    done

    # Append excludes to config if any
    if [[ ${#exclude_paths[@]} -gt 0 ]]; then
        {
            echo ""
            echo "    excludePaths:"
            echo "        analyseAndScan:"
            for p in "${exclude_paths[@]}"; do
                echo "            - /src/${p}"
            done
        } >> "${phpstan_staging}/phpstan.neon"
    fi

    local docker_args=(
        docker run --rm
        -v "${project_dir}:/src:ro"
        -v "${phpstan_staging}:/config:ro"
        -v "${report_dir}:/output"
        -w /src
        --entrypoint phpstan
        "${PHPSTAN_IMAGE}"
    )

    local phpstan_args=(
        analyse
        --configuration=/config/phpstan.neon
        --error-format=json
        --no-progress
        --no-ansi
    )

    log_info "Scanning ${project_dir} with PHPStan (level 5)..."
    "${docker_args[@]}" "${phpstan_args[@]}" > "${report_dir}/phpstan-raw.json" 2>"${report_dir}/phpstan-stderr.log"
    local exit_code=$?

    # PHPStan outputs JSON to stdout. Parse it.
    local count=0
    if [[ -f "${report_dir}/phpstan-raw.json" ]] && command -v jq &>/dev/null; then
        # PHPStan JSON format: {"totals":{"errors":N,"file_errors":N},"files":{...},"errors":[...]}
        # Transform to our standard format
        jq '[
            .files // {} | to_entries[] |
            .key as $file |
            .value.messages[]? | {
                tool: "phpstan",
                rule: (.identifier // "phpstan-error"),
                severity: (if .ignorable == false then "error" else "warning" end),
                normalized_severity: (if .ignorable == false then "medium" else "low" end),
                message: .message,
                file: ($file | sub("^/src/";"") | sub("^\\.\\./src/";"")),
                line: .line,
                tip: .tip
            }
        ]' "${report_dir}/phpstan-raw.json" > "${report_dir}/phpstan.json" 2>/dev/null || echo '[]' > "${report_dir}/phpstan.json"

        count=$(jq 'if type == "array" then length else 0 end' "${report_dir}/phpstan.json" 2>/dev/null || echo 0)
        [[ -z "$count" ]] && count=0
    else
        echo '[]' > "${report_dir}/phpstan.json"
    fi

    local elapsed
    elapsed="$(timer_elapsed "$start")"

    # PHPStan exit codes: 0=clean, 1=errors found, 2+=crash
    if [[ $exit_code -le 1 ]]; then
        log_success "PHPStan complete: ${count} findings (${elapsed}s)"
        return 0
    else
        log_error "PHPStan failed (exit ${exit_code}). Check ${report_dir}/phpstan-stderr.log"
        return 1
    fi
}

generate_phpstan_config() {
    local project="$1"
    local project_dir="$2"
    local output_file="$3"

    cat > "$output_file" <<'NEON'
parameters:
    level: 5
    paths:
        - /src
    treatPhpDocTypesAsCertain: false
    reportUnmatchedIgnoredErrors: false
    ignoreErrors:
        # Suppress noise common in UserSpice projects
        - '#Variable \$[a-z_]+ might not be defined#'
        - '#Variable \$abs_us_root might not be defined#'
        - '#Variable \$us_url_root might not be defined#'
        - '#Variable \$user might not be defined#'
        - '#Variable \$db might not be defined#'
        - '#Variable \$settings might not be defined#'
        - '#Variable \$lang might not be defined#'
        - '#Function [a-zA-Z_]+ invoked with#'
        - '#Call to an undefined method DB::#'
NEON

    log_info "Generated PHPStan config at ${output_file}"
}
