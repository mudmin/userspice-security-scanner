#!/usr/bin/env bash
# Summary generator — aggregates all tool outputs into a unified summary.json
# Designed to be AI-friendly for review conversations

generate_summary() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"
    local total_elapsed="$4"

    log_header "Generating Summary"

    if ! command -v jq &>/dev/null; then
        log_warn "jq not available — writing minimal summary"
        cat > "${report_dir}/summary.json" <<EOF
{
    "project": "${project}",
    "scan_dir": "${project_dir}",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "duration_seconds": ${total_elapsed},
    "note": "Install jq for detailed summary generation"
}
EOF
        return
    fi

    # Parse semgrep results
    local semgrep_findings="[]"
    local semgrep_count=0
    if [[ -f "${report_dir}/semgrep.json" ]]; then
        semgrep_count=$(jq '.results | length' "${report_dir}/semgrep.json" 2>/dev/null || echo 0)
        semgrep_findings=$(jq '[.results[] | {
            tool: "semgrep",
            rule: .check_id,
            severity: .extra.severity,
            normalized_severity: (if .extra.severity == "ERROR" then "high" elif .extra.severity == "WARNING" then "medium" else "info" end),
            message: .extra.message,
            file: .path,
            line: .start.line,
            end_line: .end.line,
            snippet: .extra.lines
        }]' "${report_dir}/semgrep.json" 2>/dev/null || echo "[]")
    fi
    # Parse psalm results
    local psalm_findings="[]"
    local psalm_count=0
    if [[ -f "${report_dir}/psalm.json" ]]; then
        psalm_count=$(jq 'if type == "array" then length else 0 end' "${report_dir}/psalm.json" 2>/dev/null || echo 0)
        psalm_findings=$(jq 'if type == "array" then [.[] | {
            tool: "psalm",
            rule: .type,
            severity: .severity,
            normalized_severity: (if .severity == "error" then "high" else "info" end),
            message: .message,
            file: .file_name,
            line: .line_from,
            end_line: .line_to,
            snippet: .snippet
        }] else [] end' "${report_dir}/psalm.json" 2>/dev/null || echo "[]")
    fi

    # Parse trivy results
    local trivy_vulns="[]"
    local trivy_misconfigs="[]"
    local trivy_vuln_count=0
    local trivy_misconfig_count=0
    local trivy_secret_count=0
    local trivy_secrets="[]"
    if [[ -f "${report_dir}/trivy.json" ]]; then
        trivy_vuln_count=$(jq '[.Results[]? | .Vulnerabilities // [] | length] | add // 0' "${report_dir}/trivy.json" 2>/dev/null || echo 0)
        trivy_misconfig_count=$(jq '[.Results[]? | .Misconfigurations // [] | length] | add // 0' "${report_dir}/trivy.json" 2>/dev/null || echo 0)
        trivy_secret_count=$(jq '[.Results[]? | .Secrets // [] | length] | add // 0' "${report_dir}/trivy.json" 2>/dev/null || echo 0)
        trivy_vulns=$(jq '[.Results[]? | (.Target // "") as $target | .Vulnerabilities // [] | .[] | {
            tool: "trivy",
            rule: .VulnerabilityID,
            severity: .Severity,
            normalized_severity: (.Severity | ascii_downcase),
            message: (.PkgName + "@" + .InstalledVersion + " → " + ((.FixedVersion // "no fix available")) + " — " + (.Title // .VulnerabilityID)),
            file: $target,
            package: .PkgName,
            installed_version: .InstalledVersion,
            fixed_version: .FixedVersion
        }]' "${report_dir}/trivy.json" 2>/dev/null || echo "[]")
        trivy_misconfigs=$(jq '[.Results[]? | .Misconfigurations // [] | .[] | {
            tool: "trivy",
            rule: .ID,
            severity: .Severity,
            normalized_severity: (.Severity | ascii_downcase),
            message: .Title,
            file: .CauseMetadata.Resource,
            resolution: .Resolution
        }]' "${report_dir}/trivy.json" 2>/dev/null || echo "[]")
        trivy_secrets=$(jq '[.Results[]? | (.Target // "") as $target | .Secrets // [] | .[] | {
            tool: "trivy-secret",
            rule: .RuleID,
            severity: .Severity,
            normalized_severity: (.Severity | ascii_downcase),
            message: .Title,
            file: $target,
            line: .StartLine,
            match: .Match
        }]' "${report_dir}/trivy.json" 2>/dev/null || echo "[]")
    fi

    # Parse gitleaks results
    local gitleaks_findings="[]"
    local gitleaks_count=0
    if [[ -f "${report_dir}/gitleaks.json" ]]; then
        gitleaks_count=$(jq 'length' "${report_dir}/gitleaks.json" 2>/dev/null || echo 0)
        gitleaks_findings=$(jq '[.[] | {
            tool: "gitleaks",
            rule: .RuleID,
            severity: "HIGH",
            normalized_severity: "high",
            message: .Description,
            file: .File,
            line: .StartLine,
            end_line: .EndLine,
            match: .Match
        }]' "${report_dir}/gitleaks.json" 2>/dev/null || echo "[]")
    fi

    # Parse PHPStan results
    local phpstan_findings="[]"
    local phpstan_count=0
    if [[ -f "${report_dir}/phpstan.json" ]]; then
        phpstan_count=$(jq 'length' "${report_dir}/phpstan.json" 2>/dev/null || echo 0)
        phpstan_findings=$(cat "${report_dir}/phpstan.json" 2>/dev/null || echo "[]")
    fi

    # Parse ZAP results, filtering out ignored alerts from the rules config
    local zap_findings="[]"
    local zap_count=0
    if [[ -f "${report_dir}/zap.json" ]]; then
        # Build list of ignored alert IDs from the rules.tsv
        local zap_ignore_ids="[]"
        local zap_rules_file
        zap_rules_file="$(resolve_config zap rules.tsv "$project")"
        if [[ -n "$zap_rules_file" && -f "$zap_rules_file" ]]; then
            zap_ignore_ids=$(grep -v '^#' "$zap_rules_file" | grep $'\tIGNORE\t' | awk -F'\t' '{print $1}' | jq -R '.' | jq -s '.')
        fi

        # Get project path for filtering non-project URLs
        local project_path="/${project}/"

        zap_count=$(jq --argjson ignore "$zap_ignore_ids" --arg pp "$project_path" \
            '[.site[]?.alerts // [] | .[] |
              select(.pluginid as $pid | $ignore | map(. == $pid) | any | not) |
              # Filter instances to only project URLs, recount
              .instances = [.instances[]? | select(.uri | contains($pp))] |
              select(.instances | length > 0)
            ] | length' \
            "${report_dir}/zap.json" 2>/dev/null || echo 0)
        zap_findings=$(jq --argjson ignore "$zap_ignore_ids" --arg pp "$project_path" \
            '[.site[]?.alerts[]? |
              select(.pluginid as $pid | $ignore | map(. == $pid) | any | not) |
              # Filter instances to only project URLs
              .instances = [.instances[]? | select(.uri | contains($pp))] |
              select(.instances | length > 0) |
              {
                tool: "zap",
                rule: .alertRef,
                name: .name,
                severity: (if .riskcode == "3" then "HIGH" elif .riskcode == "2" then "MEDIUM" elif .riskcode == "1" then "LOW" else "INFO" end),
                normalized_severity: (if .riskcode == "3" then "high" elif .riskcode == "2" then "medium" elif .riskcode == "1" then "low" else "info" end),
                risk: .riskdesc,
                confidence: .confidence,
                description: .desc,
                solution: .solution,
                count: (.instances | length),
                instances: [.instances[]? | {uri: .uri, method: .method, param: .param}]
              }
            ]' "${report_dir}/zap.json" 2>/dev/null || echo "[]")
    fi

    local total_findings=$(( semgrep_count + psalm_count + phpstan_count + trivy_vuln_count + trivy_misconfig_count + trivy_secret_count + gitleaks_count + zap_count ))

    # Build unified severity summary across all tools
    local severity_breakdown='{"critical":0,"high":0,"medium":0,"low":0,"info":0}'

    # Write intermediate JSON files to avoid "argument list too long" with large findings
    local tmp_dir="${report_dir}/.tmp_summary"
    mkdir -p "$tmp_dir"

    echo "$semgrep_findings" > "$tmp_dir/semgrep.json"
    echo "$psalm_findings" > "$tmp_dir/psalm.json"
    echo "$trivy_vulns" > "$tmp_dir/trivy_vulns.json"
    echo "$trivy_misconfigs" > "$tmp_dir/trivy_misconfigs.json"
    echo "$trivy_secrets" > "$tmp_dir/trivy_secrets.json"
    echo "$gitleaks_findings" > "$tmp_dir/gitleaks.json"
    echo "$phpstan_findings" > "$tmp_dir/phpstan.json"
    echo "$zap_findings" > "$tmp_dir/zap.json"
    # Load scan options if available
    local scan_opts='{}'
    if [[ -f "${report_dir}/scan-options.json" ]]; then
        scan_opts=$(cat "${report_dir}/scan-options.json")
    fi
    echo "$scan_opts" > "$tmp_dir/scan_options.json"

    # Load tool status if available
    local tool_status='{}'
    if [[ -f "${report_dir}/tool-status.json" ]]; then
        tool_status=$(cat "${report_dir}/tool-status.json")
    fi
    echo "$tool_status" > "$tmp_dir/tool_status.json"

    # Build summary by reading from files instead of passing as args
    jq -n \
        --arg project "$project" \
        --arg scan_dir "$project_dir" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson duration "$total_elapsed" \
        --argjson total "$total_findings" \
        --argjson semgrep_count "$semgrep_count" \
        --argjson psalm_count "$psalm_count" \
        --argjson trivy_vuln_count "$trivy_vuln_count" \
        --argjson trivy_misconfig_count "$trivy_misconfig_count" \
        --argjson trivy_secret_count "$trivy_secret_count" \
        --argjson gitleaks_count "$gitleaks_count" \
        --argjson phpstan_count "$phpstan_count" \
        --argjson zap_count "$zap_count" \
        --arg report_dir "$report_dir" \
        --slurpfile semgrep_findings "$tmp_dir/semgrep.json" \
        --slurpfile psalm_findings "$tmp_dir/psalm.json" \
        --slurpfile trivy_vulns "$tmp_dir/trivy_vulns.json" \
        --slurpfile trivy_misconfigs "$tmp_dir/trivy_misconfigs.json" \
        --slurpfile trivy_secrets "$tmp_dir/trivy_secrets.json" \
        --slurpfile gitleaks_findings "$tmp_dir/gitleaks.json" \
        --slurpfile phpstan_findings "$tmp_dir/phpstan.json" \
        --slurpfile zap_findings "$tmp_dir/zap.json" \
        --slurpfile scan_opts "$tmp_dir/scan_options.json" \
        --slurpfile tool_status "$tmp_dir/tool_status.json" \
        '{
            meta: {
                project: $project,
                scan_dir: $scan_dir,
                timestamp: $timestamp,
                duration_seconds: $duration,
                report_dir: $report_dir,
                options: $scan_opts[0],
                tool_status: $tool_status[0]
            },
            totals: {
                all_findings: $total,
                semgrep: $semgrep_count,
                psalm: $psalm_count,
                trivy_vulnerabilities: $trivy_vuln_count,
                trivy_misconfigurations: $trivy_misconfig_count,
                trivy_secrets: $trivy_secret_count,
                gitleaks: $gitleaks_count,
                phpstan: $phpstan_count,
                zap: $zap_count
            },
            severity_summary: (
                [$semgrep_findings[0][], $psalm_findings[0][], $trivy_vulns[0][], $trivy_misconfigs[0][], $trivy_secrets[0][], $gitleaks_findings[0][], $phpstan_findings[0][], $zap_findings[0][]] |
                {
                    critical: [.[] | select(.normalized_severity == "critical")] | length,
                    high: [.[] | select(.normalized_severity == "high")] | length,
                    medium: [.[] | select(.normalized_severity == "medium")] | length,
                    low: [.[] | select(.normalized_severity == "low")] | length,
                    info: [.[] | select(.normalized_severity == "info")] | length
                }
            ),
            findings: {
                semgrep: $semgrep_findings[0],
                psalm: $psalm_findings[0],
                trivy_vulnerabilities: $trivy_vulns[0],
                trivy_misconfigurations: $trivy_misconfigs[0],
                trivy_secrets: $trivy_secrets[0],
                gitleaks: $gitleaks_findings[0],
                phpstan: $phpstan_findings[0],
                zap: $zap_findings[0]
            }
        }' > "${report_dir}/summary.json"

    # Clean up temp files
    rm -rf "$tmp_dir"

    log_success "Summary written to ${report_dir}/summary.json"

    # Print a quick overview to stdout
    echo ""
    echo -e "${BOLD}Scan Summary for ${project}${NC}"
    echo -e "  Report: ${report_dir}"
    echo -e "  Duration: ${total_elapsed}s"
    echo ""
    printf "  %-20s %s\n" "Tool" "Findings"
    printf "  %-20s %s\n" "----" "--------"
    printf "  %-20s %s\n" "Semgrep" "${semgrep_count}"
    printf "  %-20s %s\n" "Psalm" "${psalm_count}"
    printf "  %-20s %s\n" "Trivy (vulns)" "${trivy_vuln_count}"
    printf "  %-20s %s\n" "Trivy (misconfig)" "${trivy_misconfig_count}"
    printf "  %-20s %s\n" "Trivy (secrets)" "${trivy_secret_count}"
    printf "  %-20s %s\n" "Gitleaks" "${gitleaks_count}"
    if [[ $phpstan_count -gt 0 ]] || [[ -f "${report_dir}/phpstan.json" ]]; then
        printf "  %-20s %s\n" "PHPStan (quality)" "${phpstan_count}"
    fi
    if [[ $zap_count -gt 0 ]] || [[ -f "${report_dir}/zap.json" ]]; then
        printf "  %-20s %s\n" "ZAP (alerts)" "${zap_count}"
    fi
    printf "  %-20s %s\n" "---" "---"
    printf "  ${BOLD}%-20s %s${NC}\n" "TOTAL" "${total_findings}"
    echo ""
}
