#!/usr/bin/env bash
# Semgrep scanner module
# Two-pass approach:
#   Pass 1: Custom UserSpice-aware rules (no metrics, no registry)
#   Pass 2: Registry community rules (requires --metrics=on) for broader coverage

run_semgrep() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"

    log_header "Semgrep — Code Security Analysis"
    local start
    start="$(timer_start)"

    ensure_image "${SEMGREP_IMAGE}" || return 1

    # Resolve configs
    local custom_rules
    custom_rules="$(resolve_config semgrep userspice-rules.yml "$project")"
    local semgrepignore
    semgrepignore="$(resolve_config semgrep .semgrepignore "$project")"

    # Build common exclude args from .semgrepignore
    local exclude_args=()
    if [[ -n "$semgrepignore" && -f "$semgrepignore" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            exclude_args+=(--exclude "$line")
        done < "$semgrepignore"
    fi

    # Diff mode: only scan changed files
    local include_args=()
    if [[ -n "${SCANNER_DIFF_FILES:-}" && -f "${SCANNER_DIFF_FILES}" ]]; then
        while IFS= read -r f; do
            [[ -z "$f" ]] && continue
            include_args+=(--include "$f")
        done < "${SCANNER_DIFF_FILES}"
        if [[ ${#include_args[@]} -eq 0 ]]; then
            log_info "Diff mode: no PHP/JS files changed — skipping semgrep"
            echo '{"results":[],"errors":[]}' > "${report_dir}/semgrep.json"
            return 0
        fi
        log_info "Diff mode: scanning ${#include_args[@]} changed file(s)"
    fi

    local pass1_ok=false
    local pass2_ok=false

    # ---- Pass 1: Custom UserSpice rules (no registry, no metrics) ----
    if [[ -n "$custom_rules" ]]; then
        log_info "Pass 1: UserSpice-aware rules..."

        local docker_args=(
            docker run --rm
            -v "${project_dir}:/src:ro"
            -v "${report_dir}:/output"
            -v "${custom_rules}:/rules/userspice-rules.yml:ro"
            "${SEMGREP_IMAGE}"
        )

        local semgrep_args=(
            semgrep
            --config /rules/userspice-rules.yml
            --json
            --output /output/semgrep-custom.json
            --no-git-ignore
            --metrics off
            "${exclude_args[@]}"
            "${include_args[@]}"
            /src
        )

        "${docker_args[@]}" "${semgrep_args[@]}" 2>"${report_dir}/semgrep-custom-stderr.log"
        local ec=$?
        # Exit 0=no findings, 1=findings found, 2=findings+rule errors (results still valid)
        if [[ $ec -le 2 ]]; then
            local c1=0
            if [[ -f "${report_dir}/semgrep-custom.json" ]] && command -v jq &>/dev/null; then
                c1=$(jq '.results | length' "${report_dir}/semgrep-custom.json" 2>/dev/null || echo 0)
            fi
            [[ $ec -eq 2 ]] && log_warn "  Custom rules: ${c1} findings (some rule parse errors — check stderr log)"
            [[ $ec -le 1 ]] && log_success "  Custom rules: ${c1} findings"
            pass1_ok=true
        else
            log_warn "  Custom rules failed (exit ${ec})"
        fi
    fi

    # ---- Pass 2: Registry community rules (requires metrics) ----
    log_info "Pass 2: Community security rules (registry)..."

    local docker_args2=(
        docker run --rm
        -v "${project_dir}:/src:ro"
        -v "${report_dir}:/output"
        "${SEMGREP_IMAGE}"
    )

    local semgrep_args2=(
        semgrep
        --config p/default
        --config p/php
        --config p/javascript
        --json
        --output /output/semgrep-registry.json
        --no-git-ignore
        --metrics on
        # Exclude generic rules we've replaced with framework-aware versions
        --exclude-rule php.lang.security.unlink-use.unlink-use
        --exclude-rule php.lang.security.injection.echoed-request.echoed-request
        "${exclude_args[@]}"
        "${include_args[@]}"
        /src
    )

    "${docker_args2[@]}" "${semgrep_args2[@]}" 2>"${report_dir}/semgrep-registry-stderr.log"
    local ec2=$?
    if [[ $ec2 -le 2 ]]; then
        local c2=0
        if [[ -f "${report_dir}/semgrep-registry.json" ]] && command -v jq &>/dev/null; then
            c2=$(jq '.results | length' "${report_dir}/semgrep-registry.json" 2>/dev/null || echo 0)
        fi
        [[ $ec2 -eq 2 ]] && log_warn "  Registry rules: ${c2} findings (some rule errors — check stderr log)"
        [[ $ec2 -le 1 ]] && log_success "  Registry rules: ${c2} findings"
        pass2_ok=true
    else
        log_warn "  Registry rules failed (exit ${ec2}). Check ${report_dir}/semgrep-registry-stderr.log"
        log_warn "  (This is OK — registry rules require network access and metrics consent)"
    fi

    # ---- Merge results ----
    merge_semgrep_results "$report_dir"

    local elapsed
    elapsed="$(timer_elapsed "$start")"

    local total=0
    if [[ -f "${report_dir}/semgrep.json" ]] && command -v jq &>/dev/null; then
        total=$(jq '.results | length' "${report_dir}/semgrep.json" 2>/dev/null || echo 0)
    fi

    if $pass1_ok || $pass2_ok; then
        log_success "Semgrep complete: ${total} findings (${elapsed}s)"
        return 0
    else
        log_error "Both Semgrep passes failed. Check stderr logs in ${report_dir}."
        return 1
    fi
}

merge_semgrep_results() {
    local report_dir="$1"

    if ! command -v jq &>/dev/null; then
        # Without jq, just use whichever file exists
        if [[ -f "${report_dir}/semgrep-custom.json" ]]; then
            cp "${report_dir}/semgrep-custom.json" "${report_dir}/semgrep.json"
        elif [[ -f "${report_dir}/semgrep-registry.json" ]]; then
            cp "${report_dir}/semgrep-registry.json" "${report_dir}/semgrep.json"
        fi
        return
    fi

    local custom="${report_dir}/semgrep-custom.json"
    local registry="${report_dir}/semgrep-registry.json"

    if [[ -f "$custom" && -f "$registry" ]]; then
        # Merge results arrays, deduplicate by (check_id + path + line)
        jq -s '
            .[0] as $a | .[1] as $b |
            ($a.results + $b.results) | unique_by(.check_id + .path + (.start.line|tostring)) |
            $a * {results: .}
        ' "$custom" "$registry" > "${report_dir}/semgrep.json"
    elif [[ -f "$custom" ]]; then
        cp "$custom" "${report_dir}/semgrep.json"
    elif [[ -f "$registry" ]]; then
        cp "$registry" "${report_dir}/semgrep.json"
    else
        echo '{"results":[],"errors":[]}' > "${report_dir}/semgrep.json"
    fi
}

