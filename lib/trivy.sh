#!/usr/bin/env bash
# Trivy scanner module
# Handles: dependency/supply-chain scanning (Composer, npm), config scanning, filesystem scanning

run_trivy() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"

    log_header "Trivy — Dependency & Configuration Scanning"
    local start
    start="$(timer_start)"

    ensure_image "${TRIVY_IMAGE}" || return 1

    local docker_args=(
        docker run --rm
        -v "${project_dir}:/src:ro"
        -v "${report_dir}:/output"
    )

    # Mount trivyignore to /config/ (not /src/ which is :ro)
    local trivyignore
    trivyignore="$(resolve_config trivy .trivyignore "$project")"
    if [[ -n "$trivyignore" ]]; then
        docker_args+=(-v "${trivyignore}:/config/.trivyignore:ro")
    fi

    # Mount trivy config if available
    local trivy_config
    trivy_config="$(resolve_config trivy trivy.yaml "$project")"
    if [[ -n "$trivy_config" ]]; then
        docker_args+=(-v "${trivy_config}:/config/trivy.yaml:ro")
    fi

    docker_args+=("${TRIVY_IMAGE}")

    local trivy_args=(
        fs
        --format json
        --output /output/trivy.json
        --scanners vuln,misconfig,secret
        --severity LOW,MEDIUM,HIGH,CRITICAL
    )

    if [[ -n "$trivyignore" ]]; then
        trivy_args+=(--ignorefile /config/.trivyignore)
    fi

    if [[ -n "$trivy_config" ]]; then
        trivy_args+=(--config /config/trivy.yaml)
    fi

    trivy_args+=(/src)

    log_info "Scanning ${project_dir} with Trivy..."
    "${docker_args[@]}" "${trivy_args[@]}" 2>"${report_dir}/trivy-stderr.log"
    local exit_code=$?

    local elapsed
    elapsed="$(timer_elapsed "$start")"

    if [[ $exit_code -eq 0 ]]; then
        local vuln_count=0
        local misconfig_count=0
        if [[ -f "${report_dir}/trivy.json" ]] && command -v jq &>/dev/null; then
            vuln_count=$(jq '[.Results[]? | .Vulnerabilities // [] | length] | add // 0' "${report_dir}/trivy.json" 2>/dev/null || echo 0)
            misconfig_count=$(jq '[.Results[]? | .Misconfigurations // [] | length] | add // 0' "${report_dir}/trivy.json" 2>/dev/null || echo 0)
        fi
        log_success "Trivy complete: ${vuln_count} vulnerabilities, ${misconfig_count} misconfigs (${elapsed}s)"
        return 0
    else
        log_error "Trivy failed (exit ${exit_code}). Check ${report_dir}/trivy-stderr.log"
        return 1
    fi
}
