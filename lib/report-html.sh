#!/usr/bin/env bash
# HTML report generator — creates a self-contained, print-friendly HTML report
# Excludes suppressed findings and PHPStan (code quality, not security)

generate_html_report() {
    local report_dir="$1"
    local summary="${report_dir}/summary.json"
    local headers_file="${report_dir}/headers.json"
    local output="${report_dir}/report.html"

    if ! command -v jq &>/dev/null; then
        log_error "jq required for HTML report generation"
        return 1
    fi
    if [[ ! -f "$summary" ]]; then
        log_error "No summary.json found in ${report_dir}"
        return 1
    fi

    log_info "Generating HTML report..."

    # Extract data
    local project timestamp duration
    project=$(jq -r '.meta.project' "$summary")
    timestamp=$(jq -r '.meta.timestamp' "$summary")
    duration=$(jq -r '.meta.duration_seconds' "$summary")

    local suppressed
    suppressed=$(jq '.totals.suppressed // 0' "$summary")

    # Compute severity counts from security tools only (exclude phpstan)
    local sev_json sev_critical sev_high sev_medium sev_low sev_info
    sev_json=$(jq '
        [(.findings.semgrep // []), (.findings.psalm // []), (.findings.trivy_vulnerabilities // []),
         (.findings.trivy_secrets // []), (.findings.trivy_misconfigurations // []),
         (.findings.gitleaks // []), (.findings.zap // [])] | add // [] |
        {
            critical: [.[] | select(.normalized_severity == "critical")] | length,
            high: [.[] | select(.normalized_severity == "high")] | length,
            medium: [.[] | select(.normalized_severity == "medium")] | length,
            low: [.[] | select(.normalized_severity == "low")] | length,
            info: [.[] | select(.normalized_severity == "info")] | length
        }
    ' "$summary")
    sev_critical=$(echo "$sev_json" | jq '.critical')
    sev_high=$(echo "$sev_json" | jq '.high')
    sev_medium=$(echo "$sev_json" | jq '.medium')
    sev_low=$(echo "$sev_json" | jq '.low')
    sev_info=$(echo "$sev_json" | jq '.info')

    # Owner counts
    local owner_project owner_core owner_custom
    owner_project=$(jq '[.owner_summary // {} | to_entries[] | .value.project // 0] | add // 0' "$summary")
    owner_core=$(jq '[.owner_summary // {} | to_entries[] | .value.userspice_core // 0] | add // 0' "$summary")
    owner_custom=$(jq '[.owner_summary // {} | to_entries[] | .value.userspice_customizable // 0] | add // 0' "$summary")

    # Tool status
    local tool_status
    tool_status=$(jq -r '.meta.tool_status // {} | to_entries[] | select(.value != "skipped") | "<tr><td>\(.key)</td><td class=\"status-\(.value)\">\(.value)</td></tr>"' "$summary")

    # Build findings HTML (exclude phpstan — code quality, not security)
    local findings_html
    findings_html=$(jq -r '
        # Severity sort order
        def sev_order: if . == "critical" then 0 elif . == "high" then 1 elif . == "medium" then 2 elif . == "low" then 3 else 4 end;

        [
            (.findings.semgrep // []),
            (.findings.psalm // []),
            (.findings.trivy_vulnerabilities // []),
            (.findings.trivy_secrets // []),
            (.findings.trivy_misconfigurations // []),
            (.findings.gitleaks // []),
            (.findings.zap // [])
        ] | add // [] |
        sort_by(.normalized_severity | sev_order) |
        group_by(.normalized_severity) |
        map(
            (.[0].normalized_severity // "info") as $sev |
            "<div class=\"severity-group\"><h3 class=\"sev-header sev-" + $sev + "\">" +
            ($sev | ascii_upcase) + " (" + (length | tostring) + ")</h3>" +
            (map(
                "<div class=\"finding\">" +
                "<div class=\"finding-meta\">" +
                "<span class=\"badge tool\">" + (.tool // "unknown") + "</span>" +
                "<span class=\"badge sev-" + (.normalized_severity // "info") + "\">" + (.normalized_severity // "info" | ascii_upcase) + "</span>" +
                (if .owner then "<span class=\"badge owner-" + .owner + "\">" + (
                    if .owner == "project" then "Your Code"
                    elif .owner == "userspice-core" then "Framework"
                    elif .owner == "userspice-customizable" then "Customizable"
                    elif .owner == "dependency" then "Dependency"
                    else .owner end
                ) + "</span>" else "" end) +
                "</div>" +
                "<div class=\"finding-location\">" + (if .tool == "zap" then (.count // 0 | tostring) + " instance(s)" else ((.file // "") | gsub("^/src/";"")) + (if .line then ":" + (.line | tostring) else "" end) end) + "</div>" +
                "<div class=\"finding-rule\">" + (.name // .rule // "") + "</div>" +
                "<div class=\"finding-message\">" + (.message // .description // "") + "</div>" +
                "</div>"
            ) | join("")) +
            "</div>"
        ) | join("")
    ' "$summary")

    # Build headers HTML if available
    local headers_html=""
    if [[ -f "$headers_file" ]]; then
        headers_html=$(jq -r '
            "<div class=\"section\"><h2>HTTP Security Headers</h2><table class=\"headers-table\"><tr><th>Header</th><th>Status</th><th>Level</th></tr>" +
            ([.headers[]? |
                "<tr class=\"hdr-" + .status + "\">" +
                "<td>" + .header + "</td>" +
                "<td>" + (
                    if .status == "present" then "Present"
                    elif .status == "absent" then "Not Exposed"
                    elif .status == "exposed" then "EXPOSED"
                    else "MISSING" end
                ) + "</td>" +
                "<td>" + .level + "</td>" +
                "</tr>"
            ] | join("")) +
            "</table></div>"
        ' "$headers_file")
    fi

    # Build ZAP crawl coverage section if ZAP was run
    local zap_file="${report_dir}/zap.json"
    local zap_coverage_html=""
    if [[ -f "$zap_file" ]]; then
        local zap_user zap_auth_status project_url
        zap_user=$(jq -r '.meta.options.zap_user // ""' "$summary")
        project_url=$(jq -r '.meta.options.url // ""' "$summary")

        # Extract unique project URLs (filter out non-project URLs like /robots.txt)
        local project_path
        project_path=$(echo "$project_url" | sed 's|https\?://[^/]*/||; s|/$||')

        local page_list
        page_list=$(jq -r --arg pp "/$project/" \
            '[.site[]?.alerts[]?.instances[]?.uri // empty] | unique | map(select(contains($pp))) | map(
                gsub("https?://[^/]*";"") |
                gsub("\\?.*$";"")
            ) | unique | sort | .[]' "$zap_file" 2>/dev/null)

        local page_count
        page_count=$(echo "$page_list" | grep -c . || true)

        local auth_info=""
        if [[ -n "$zap_user" ]]; then
            auth_info="Authenticated as <strong>${zap_user}</strong>"
        else
            auth_info="Unauthenticated (public pages only)"
        fi

        zap_coverage_html="<div class=\"section\"><h2>ZAP Crawl Coverage</h2>"
        zap_coverage_html+="<p style=\"font-size: 0.85rem; margin-bottom: 0.75rem;\">$auth_info &mdash; ${page_count} unique page(s) scanned</p>"
        zap_coverage_html+="<div style=\"font-family: monospace; font-size: 0.8rem; line-height: 1.8; column-count: 2; column-gap: 2rem;\">"
        while IFS= read -r page; do
            [[ -z "$page" ]] && continue
            zap_coverage_html+="<div>${page}</div>"
        done <<< "$page_list"
        zap_coverage_html+="</div></div>"
    fi

    # Determine pass/fail
    local status_class="pass" status_text="PASS"
    if [[ $sev_critical -gt 0 || $sev_high -gt 0 ]]; then
        status_class="fail"
        status_text="FINDINGS DETECTED"
    elif [[ $sev_medium -gt 0 ]]; then
        status_class="warn"
        status_text="REVIEW RECOMMENDED"
    fi

    # Security findings count (excluding phpstan)
    local security_total
    security_total=$(( sev_critical + sev_high + sev_medium + sev_low + sev_info ))

    # Write HTML
    cat > "$output" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Scan Report</title>
<style>
HTMLEOF

    cat >> "$output" <<'CSSEOF'
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a2e; line-height: 1.6; padding: 2rem; max-width: 1000px; margin: 0 auto; font-size: 14px; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
h2 { font-size: 1.15rem; margin-bottom: 0.75rem; color: #1a1a2e; border-bottom: 2px solid #e8e8e8; padding-bottom: 0.4rem; }
h3 { font-size: 1rem; margin-bottom: 0.5rem; }
.header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 3px solid #1a1a2e; }
.header-left { flex: 1; }
.header-right { text-align: right; font-size: 0.85rem; color: #666; }
.status-badge { display: inline-block; padding: 0.35rem 1rem; border-radius: 4px; font-weight: 700; font-size: 0.9rem; letter-spacing: 0.02em; }
.status-badge.pass { background: #d4edda; color: #155724; }
.status-badge.warn { background: #fff3cd; color: #856404; }
.status-badge.fail { background: #f8d7da; color: #721c24; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
.summary-box { background: #f8f9fa; border: 1px solid #e8e8e8; border-radius: 6px; padding: 0.75rem; text-align: center; }
.summary-box .number { font-size: 1.75rem; font-weight: 700; line-height: 1.2; }
.summary-box .label { font-size: 0.7rem; color: #666; text-transform: uppercase; letter-spacing: 0.03em; }
.summary-box.critical .number { color: #dc3545; }
.summary-box.high .number { color: #e74c3c; }
.summary-box.medium .number { color: #f39c12; }
.summary-box.low .number { color: #27ae60; }
.summary-box.info .number { color: #3498db; }
.section { margin-bottom: 1.5rem; }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th, td { padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid #e8e8e8; }
th { background: #f8f9fa; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; color: #666; }
.status-success { color: #27ae60; font-weight: 600; }
.status-failed { color: #e74c3c; font-weight: 600; }
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.7rem; font-weight: 600; margin-right: 0.35rem; }
.badge.tool { background: #e8e8e8; color: #555; }
.badge.sev-critical { background: #f8d7da; color: #721c24; }
.badge.sev-high { background: #f8d7da; color: #721c24; }
.badge.sev-medium { background: #fff3cd; color: #856404; }
.badge.sev-low { background: #d4edda; color: #155724; }
.badge.sev-info { background: #d1ecf1; color: #0c5460; }
.badge.owner-project { background: #d1ecf1; color: #0c5460; }
.badge.owner-userspice-core { background: #e8daef; color: #6c3483; }
.badge.owner-userspice-customizable { background: #e8daef; color: #6c3483; }
.badge.owner-dependency { background: #fff3cd; color: #856404; }
.severity-group { margin-bottom: 1rem; }
.sev-header { padding: 0.4rem 0.75rem; border-radius: 4px; font-size: 0.85rem; }
.sev-header.sev-critical { background: #f8d7da; color: #721c24; }
.sev-header.sev-high { background: #f8d7da; color: #721c24; }
.sev-header.sev-medium { background: #fff3cd; color: #856404; }
.sev-header.sev-low { background: #d4edda; color: #155724; }
.sev-header.sev-info { background: #d1ecf1; color: #0c5460; }
.finding { padding: 0.6rem 0.75rem; border-bottom: 1px solid #f0f0f0; }
.finding:last-child { border-bottom: none; }
.finding-meta { margin-bottom: 0.25rem; }
.finding-location { font-family: 'SF Mono', Consolas, monospace; font-size: 0.8rem; color: #2563eb; }
.finding-rule { font-family: 'SF Mono', Consolas, monospace; font-size: 0.75rem; color: #888; }
.finding-message { font-size: 0.85rem; margin-top: 0.2rem; }
.headers-table .hdr-missing td:nth-child(2), .headers-table .hdr-exposed td:nth-child(2) { color: #e74c3c; font-weight: 600; }
.headers-table .hdr-present td:nth-child(2), .headers-table .hdr-absent td:nth-child(2) { color: #27ae60; }
.footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e8e8e8; font-size: 0.75rem; color: #999; text-align: center; }
@media print {
    body { padding: 0.5rem; font-size: 12px; }
    .finding { page-break-inside: avoid; }
    .severity-group { page-break-inside: avoid; }
    .section { page-break-inside: avoid; }
}
CSSEOF

    cat >> "$output" <<HTMLEOF
</style>
</head>
<body>

<div class="header">
    <div class="header-left">
        <h1>Security Scan Report</h1>
        <div style="color: #666; font-size: 0.9rem;">${project}</div>
    </div>
    <div class="header-right">
        <div class="status-badge ${status_class}">${status_text}</div>
        <div style="margin-top: 0.5rem;">${timestamp}</div>
        <div>Duration: ${duration}s</div>
    </div>
</div>

<div class="summary-grid">
    <div class="summary-box"><div class="number">${security_total}</div><div class="label">Security Findings</div></div>
    <div class="summary-box critical"><div class="number">${sev_critical}</div><div class="label">Critical</div></div>
    <div class="summary-box high"><div class="number">${sev_high}</div><div class="label">High</div></div>
    <div class="summary-box medium"><div class="number">${sev_medium}</div><div class="label">Medium</div></div>
    <div class="summary-box low"><div class="number">${sev_low}</div><div class="label">Low</div></div>
    <div class="summary-box info"><div class="number">${suppressed}</div><div class="label">Suppressed</div></div>
</div>

<div class="two-col">
    <div class="section">
        <h2>Tools</h2>
        <table>
            <tr><th>Tool</th><th>Status</th></tr>
            ${tool_status}
        </table>
    </div>
    <div class="section">
        <h2>Ownership</h2>
        <table>
            <tr><th>Owner</th><th>Findings</th></tr>
HTMLEOF

    [[ $owner_project -gt 0 ]] && echo "            <tr><td>Your Code</td><td>${owner_project}</td></tr>" >> "$output"
    [[ $owner_core -gt 0 ]] && echo "            <tr><td>Framework (upstream)</td><td>${owner_core}</td></tr>" >> "$output"
    [[ $owner_custom -gt 0 ]] && echo "            <tr><td>Customizable</td><td>${owner_custom}</td></tr>" >> "$output"

    cat >> "$output" <<HTMLEOF
        </table>
    </div>
</div>

${headers_html}

${zap_coverage_html}

<div class="section">
    <h2>Findings</h2>
    ${findings_html}
</div>

<div class="footer">
    Generated by UserSpice Security Scanner &middot; ${timestamp}
</div>

</body>
</html>
HTMLEOF

    log_success "HTML report: ${output}"
}
