#!/usr/bin/env bash
# Gitleaks scanner module
# Handles: secrets detection (API keys, tokens, passwords, credentials)

run_gitleaks() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"

    log_header "Gitleaks — Secrets Detection"
    local start
    start="$(timer_start)"

    ensure_image "${GITLEAKS_IMAGE}" || return 1

    # Resolve gitleaks config
    local gitleaks_config
    gitleaks_config="$(resolve_config gitleaks .gitleaks.toml "$project")"

    local docker_args=(
        docker run --rm
        -v "${project_dir}:/src:ro"
        -v "${report_dir}:/output"
    )

    if [[ -n "$gitleaks_config" ]]; then
        docker_args+=(-v "${gitleaks_config}:/config/.gitleaks.toml:ro")
    fi

    docker_args+=("${GITLEAKS_IMAGE}")

    local gitleaks_args=(
        detect
        --source /src
        --report-format json
        --report-path /output/gitleaks.json
        --no-git
    )

    if [[ -n "$gitleaks_config" ]]; then
        gitleaks_args+=(--config /config/.gitleaks.toml)
    fi

    log_info "Scanning ${project_dir} with Gitleaks..."
    "${docker_args[@]}" "${gitleaks_args[@]}" 2>"${report_dir}/gitleaks-stderr.log"
    local exit_code=$?

    local elapsed
    elapsed="$(timer_elapsed "$start")"

    # Gitleaks: 0=no leaks, 1=leaks found, 2+=error
    if [[ $exit_code -le 1 ]]; then
        local count=0
        if [[ -f "${report_dir}/gitleaks.json" ]] && command -v jq &>/dev/null; then
            count=$(jq 'length' "${report_dir}/gitleaks.json" 2>/dev/null || echo 0)
        fi

        if [[ $count -gt 0 ]]; then
            log_warn "Gitleaks found ${count} potential secret(s) (${elapsed}s)"
        else
            log_success "Gitleaks complete: no secrets found (${elapsed}s)"
        fi
        return 0
    else
        log_error "Gitleaks failed (exit ${exit_code}). Check ${report_dir}/gitleaks-stderr.log"
        return 1
    fi
}
