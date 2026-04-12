#!/usr/bin/env bash
# Delta analysis module
# Compares current scan findings against the most recent previous scan
# Shows new findings, resolved findings, and drift

generate_delta() {
    local project="$1"
    local report_dir="$2"

    if ! command -v jq &>/dev/null; then return; fi

    # Find previous report
    local project_reports_dir="${REPORTS_DIR}/${project}"
    local current_dirname
    current_dirname=$(basename "$report_dir")

    local prev_report=""
    if [[ -d "$project_reports_dir" ]]; then
        prev_report=$(ls -1t "$project_reports_dir" | grep -v "^${current_dirname}$" | head -1)
    fi

    if [[ -z "$prev_report" || ! -f "${project_reports_dir}/${prev_report}/summary.json" ]]; then
        log_info "No previous scan found — skipping delta analysis."
        return
    fi

    local prev_summary="${project_reports_dir}/${prev_report}/summary.json"
    local curr_summary="${report_dir}/summary.json"

    log_info "Delta vs previous scan: ${prev_report}"

    # Load tool status to skip delta for failed tools
    local tool_status='{}'
    if [[ -f "${report_dir}/tool-status.json" ]]; then
        tool_status=$(cat "${report_dir}/tool-status.json")
    fi

    tool_ok() {
        local tool="$1"
        local status
        status=$(echo "$tool_status" | jq -r --arg t "$tool" '.[$t] // "success"')
        [[ "$status" == "success" ]]
    }

    # Extract finding keys from both reports
    local new_semgrep=0 resolved_semgrep=0
    local new_psalm=0 resolved_psalm=0
    local new_trivy=0 resolved_trivy=0
    local new_gitleaks=0 resolved_gitleaks=0

    if tool_ok semgrep; then
        local curr_semgrep prev_semgrep
        curr_semgrep=$(jq -r '[.findings.semgrep[]? | "\(.rule)|\(.file)|\(.line)"] | sort | .[]' "$curr_summary" 2>/dev/null)
        prev_semgrep=$(jq -r '[.findings.semgrep[]? | "\(.rule)|\(.file)|\(.line)"] | sort | .[]' "$prev_summary" 2>/dev/null)
        new_semgrep=$(comm -23 <(echo "$curr_semgrep" | sort) <(echo "$prev_semgrep" | sort) | grep -c . || true)
        resolved_semgrep=$(comm -13 <(echo "$curr_semgrep" | sort) <(echo "$prev_semgrep" | sort) | grep -c . || true)
    fi

    if tool_ok psalm; then
        local curr_psalm prev_psalm
        curr_psalm=$(jq -r '[.findings.psalm[]? | "\(.rule)|\(.file)|\(.line)"] | sort | .[]' "$curr_summary" 2>/dev/null)
        prev_psalm=$(jq -r '[.findings.psalm[]? | "\(.rule)|\(.file)|\(.line)"] | sort | .[]' "$prev_summary" 2>/dev/null)
        new_psalm=$(comm -23 <(echo "$curr_psalm" | sort) <(echo "$prev_psalm" | sort) | grep -c . || true)
        resolved_psalm=$(comm -13 <(echo "$curr_psalm" | sort) <(echo "$prev_psalm" | sort) | grep -c . || true)
    fi

    if tool_ok trivy; then
        local curr_trivy prev_trivy
        curr_trivy=$(jq -r '[.findings.trivy_vulnerabilities[]? | "\(.rule)|\(.file)"] | sort | .[]' "$curr_summary" 2>/dev/null)
        prev_trivy=$(jq -r '[.findings.trivy_vulnerabilities[]? | "\(.rule)|\(.file)"] | sort | .[]' "$prev_summary" 2>/dev/null)
        new_trivy=$(comm -23 <(echo "$curr_trivy" | sort) <(echo "$prev_trivy" | sort) | grep -c . || true)
        resolved_trivy=$(comm -13 <(echo "$curr_trivy" | sort) <(echo "$prev_trivy" | sort) | grep -c . || true)
    fi

    if tool_ok gitleaks; then
        local curr_gitleaks prev_gitleaks
        curr_gitleaks=$(jq -r '[.findings.gitleaks[]? | "\(.rule)|\(.file)|\(.line)"] | sort | .[]' "$curr_summary" 2>/dev/null)
        prev_gitleaks=$(jq -r '[.findings.gitleaks[]? | "\(.rule)|\(.file)|\(.line)"] | sort | .[]' "$prev_summary" 2>/dev/null)
        new_gitleaks=$(comm -23 <(echo "$curr_gitleaks" | sort) <(echo "$prev_gitleaks" | sort) | grep -c . || true)
        resolved_gitleaks=$(comm -13 <(echo "$curr_gitleaks" | sort) <(echo "$prev_gitleaks" | sort) | grep -c . || true)
    fi

    # Previous totals
    local prev_totals
    prev_totals=$(jq '.totals' "$prev_summary")

    # ZAP delta (if both have zap)
    local zap_delta="null"
    if [[ -f "${report_dir}/zap.json" && -f "${project_reports_dir}/${prev_report}/zap.json" ]]; then
        local curr_zap_alerts prev_zap_alerts
        curr_zap_alerts=$(jq '[.site[]?.alerts[]? | .name] | sort | group_by(.) | map({name: .[0], count: length})' "${report_dir}/zap.json" 2>/dev/null || echo "[]")
        prev_zap_alerts=$(jq '[.site[]?.alerts[]? | .name] | sort | group_by(.) | map({name: .[0], count: length})' "${project_reports_dir}/${prev_report}/zap.json" 2>/dev/null || echo "[]")
        zap_delta=$(jq -n --argjson curr "$curr_zap_alerts" --argjson prev "$prev_zap_alerts" '{current: $curr, previous: $prev}')
    fi

    # Headers delta
    local headers_delta="null"
    if [[ -f "${report_dir}/headers.json" && -f "${project_reports_dir}/${prev_report}/headers.json" ]]; then
        local curr_hfail prev_hfail
        curr_hfail=$(jq '.counts.fail' "${report_dir}/headers.json" 2>/dev/null || echo 0)
        prev_hfail=$(jq '.counts.fail' "${project_reports_dir}/${prev_report}/headers.json" 2>/dev/null || echo 0)
        headers_delta=$(jq -n --argjson curr "$curr_hfail" --argjson prev "$prev_hfail" '{current_fail: $curr, previous_fail: $prev}')
    fi

    # Build delta JSON
    jq -n \
        --arg prev_report "$prev_report" \
        --argjson prev_totals "$prev_totals" \
        --argjson new_semgrep "$new_semgrep" \
        --argjson resolved_semgrep "$resolved_semgrep" \
        --argjson new_psalm "$new_psalm" \
        --argjson resolved_psalm "$resolved_psalm" \
        --argjson new_trivy "$new_trivy" \
        --argjson resolved_trivy "$resolved_trivy" \
        --argjson new_gitleaks "$new_gitleaks" \
        --argjson resolved_gitleaks "$resolved_gitleaks" \
        --argjson zap "$zap_delta" \
        --argjson headers "$headers_delta" \
        '{
            previous_scan: $prev_report,
            previous_totals: $prev_totals,
            semgrep: { new: $new_semgrep, resolved: $resolved_semgrep },
            psalm: { new: $new_psalm, resolved: $resolved_psalm },
            trivy: { new: $new_trivy, resolved: $resolved_trivy },
            gitleaks: { new: $new_gitleaks, resolved: $resolved_gitleaks },
            zap: $zap,
            headers: $headers
        }' > "${report_dir}/delta.json"

    # Print summary
    local total_new=$((new_semgrep + new_psalm + new_trivy + new_gitleaks))
    local total_resolved=$((resolved_semgrep + resolved_psalm + resolved_trivy + resolved_gitleaks))

    echo ""
    echo -e "${BOLD}Delta vs ${prev_report}:${NC}"
    if [[ $total_new -eq 0 && $total_resolved -eq 0 ]]; then
        echo -e "  ${GREEN}No changes in findings${NC}"
    else
        [[ $new_semgrep -gt 0 ]]       && echo -e "  ${RED}+${new_semgrep} new${NC} Semgrep findings"
        [[ $resolved_semgrep -gt 0 ]]   && echo -e "  ${GREEN}-${resolved_semgrep} resolved${NC} Semgrep findings"
        [[ $new_psalm -gt 0 ]]          && echo -e "  ${RED}+${new_psalm} new${NC} Psalm findings"
        [[ $resolved_psalm -gt 0 ]]     && echo -e "  ${GREEN}-${resolved_psalm} resolved${NC} Psalm findings"
        [[ $new_trivy -gt 0 ]]          && echo -e "  ${RED}+${new_trivy} new${NC} Trivy findings"
        [[ $resolved_trivy -gt 0 ]]     && echo -e "  ${GREEN}-${resolved_trivy} resolved${NC} Trivy findings"
        [[ $new_gitleaks -gt 0 ]]       && echo -e "  ${RED}+${new_gitleaks} new${NC} Gitleaks findings"
        [[ $resolved_gitleaks -gt 0 ]]  && echo -e "  ${GREEN}-${resolved_gitleaks} resolved${NC} Gitleaks findings"
    fi
}
