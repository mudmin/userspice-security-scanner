#!/usr/bin/env bash
# Suppression system — filters findings against user-reviewed suppressions
#
# Suppressions are stored as JSON in:
#   shared/suppressions.json          — framework-level (ships)
#   overrides/<project>/suppressions.json — project-level (gitignored)
#
# Each suppression matches on: tool + rule + file + content_hash
# Falls back to: tool + rule + file + line
#
# This is the unified suppression system for all tools.

apply_suppressions() {
    local project="$1"
    local report_dir="$2"

    if ! command -v jq &>/dev/null; then return; fi
    if [[ ! -f "${report_dir}/summary.json" ]]; then return; fi

    # Load suppressions (project overrides + shared, merged)
    local project_supps shared_supps
    project_supps="$(resolve_config "" suppressions.json "$project" 2>/dev/null)"
    shared_supps="${SHARED_DIR}/suppressions.json"

    local merged_supps="[]"
    if [[ -f "$project_supps" ]]; then
        merged_supps=$(jq -s '.[0] + .[1]' "$project_supps" "$shared_supps" 2>/dev/null || cat "$project_supps")
    elif [[ -f "$shared_supps" ]]; then
        merged_supps=$(cat "$shared_supps")
    fi

    if [[ "$merged_supps" == "[]" || -z "$merged_supps" ]]; then
        return
    fi

    local supp_count
    supp_count=$(echo "$merged_supps" | jq 'length')
    log_info "Applying ${supp_count} suppression(s)..."

    local project_dir
    project_dir="$(resolve_project_dir "$project" 2>/dev/null)" || project_dir=""

    # Build suppression keys for matching
    # Write merged suppressions to temp file for jq
    local tmp_supps="${report_dir}/.tmp_suppressions.json"
    echo "$merged_supps" > "$tmp_supps"

    # Apply suppressions to summary.json — move matched findings to suppressed section
    local summary="${report_dir}/summary.json"
    jq --slurpfile supps "$tmp_supps" '
        # Build O(1) hash-map lookups by scope (avoids jq stack overflow on large finding sets)

        # Exact scope: match by content_hash or line number
        ($supps[0] | [.[] | select((.scope // "exact") == "exact")] |
            ([.[] | {(.tool + "|" + .rule + "|" + .file + "|" + (.content_hash // "")): true}] | add // {}) as $by_hash |
            ([.[] | {(.tool + "|" + .rule + "|" + .file + "|" + ((.line // 0) | tostring)): true}] | add // {}) as $by_line |
            {hash: $by_hash, line: $by_line}
        ) as $exact |

        # File scope: match tool + rule + file
        ($supps[0] | [.[] | select(.scope == "file") |
            {(.tool + "|" + .rule + "|" + .file): true}] | add // {}
        ) as $by_file |

        # Rule scope: match tool + rule (all files)
        ($supps[0] | [.[] | select(.scope == "rule") |
            {(.tool + "|" + .rule): true}] | add // {}
        ) as $by_rule |

        # Glob scope: pre-expand patterns against all unique finding files,
        # then convert to file-scope entries for O(1) lookup.
        # This avoids calling test() inside any() which blows jq stack on large sets.
        ([.findings | to_entries[] | .value | if type == "array" then .[].file // empty else empty end] | unique) as $all_files |
        ($supps[0] | [.[] | select(.scope == "glob")] | [.[] as $g |
            ($g.file | gsub("[.]";"[.]") | gsub("[*]";"[^/]*") | "^" + . + "$") as $pat |
            $all_files[] | select(test($pat)) |
            {($g.tool + "|" + $g.rule + "|" + .): true}
        ] | add // {}) as $by_glob |

        # Check if a finding is suppressed via any scope
        def is_suppressed($tool; $rule; $file; $line; $hash):
            ($tool + "|" + $rule + "|" + $file + "|" + ($hash // "")) as $ck |
            ($tool + "|" + $rule + "|" + $file + "|" + ($line | tostring)) as $lk |
            ($tool + "|" + $rule + "|" + $file) as $rfk |
            ($tool + "|" + $rule) as $rk |
            ($exact.hash | has($ck)) or ($exact.line | has($lk))
            or ($by_file | has($rfk))
            or ($by_rule | has($rk))
            or ($by_glob | has($rfk));

        # Process each findings array
        .findings as $f |

        # Helper to clean file paths
        def clean_file: gsub("^(/?\\.\\./)?/?src/";"");

        # Filter each tool
        ($f.semgrep // [] | map(
            . as $item |
            if is_suppressed("semgrep"; ($item.rule // ""); ($item.file | clean_file); ($item.line // 0); ($item.content_hash // ""))
            then {item: $item, suppressed: true}
            else {item: $item, suppressed: false}
            end
        )) as $sg |

        ($f.psalm // [] | map(
            . as $item |
            if is_suppressed("psalm"; ($item.rule // ""); ($item.file | clean_file); ($item.line // 0); "")
            then {item: $item, suppressed: true}
            else {item: $item, suppressed: false}
            end
        )) as $ps |

        ($f.trivy_secrets // [] | map(
            . as $item |
            if is_suppressed("trivy"; ($item.rule // ""); ($item.file // ""); ($item.line // 0); "")
            then {item: $item, suppressed: true}
            else {item: $item, suppressed: false}
            end
        )) as $ts |

        ($f.gitleaks // [] | map(
            . as $item |
            if is_suppressed("gitleaks"; ($item.rule // ""); ($item.file // ""); ($item.line // 0); "")
            then {item: $item, suppressed: true}
            else {item: $item, suppressed: false}
            end
        )) as $gl |

        ($f.phpstan // [] | map(
            . as $item |
            if is_suppressed("phpstan"; ($item.rule // ""); ($item.file | clean_file); ($item.line // 0); "")
            then {item: $item, suppressed: true}
            else {item: $item, suppressed: false}
            end
        )) as $ph |

        ($f.zap // [] | map(
            . as $item |
            if is_suppressed("zap"; ($item.rule // ""); ""; 0; "")
            then {item: $item, suppressed: true}
            else {item: $item, suppressed: false}
            end
        )) as $zp |

        # Rebuild findings with only non-suppressed
        .findings.semgrep = [$sg[] | select(.suppressed | not) | .item] |
        .findings.psalm = [$ps[] | select(.suppressed | not) | .item] |
        .findings.phpstan = [$ph[] | select(.suppressed | not) | .item] |
        .findings.trivy_secrets = [$ts[] | select(.suppressed | not) | .item] |
        .findings.gitleaks = [$gl[] | select(.suppressed | not) | .item] |
        .findings.zap = [$zp[] | select(.suppressed | not) | .item] |

        # Add suppressed findings section
        .suppressed = {
            count: ([$sg[] | select(.suppressed)] + [$ps[] | select(.suppressed)] + [$ph[] | select(.suppressed)] + [$ts[] | select(.suppressed)] + [$gl[] | select(.suppressed)] + [$zp[] | select(.suppressed)] | length),
            semgrep: [$sg[] | select(.suppressed) | .item],
            psalm: [$ps[] | select(.suppressed) | .item],
            phpstan: [$ph[] | select(.suppressed) | .item],
            trivy_secrets: [$ts[] | select(.suppressed) | .item],
            gitleaks: [$gl[] | select(.suppressed) | .item],
            zap: [$zp[] | select(.suppressed) | .item]
        } |

        # Update totals
        .totals.semgrep = (.findings.semgrep | length) |
        .totals.psalm = (.findings.psalm | length) |
        .totals.phpstan = (.findings.phpstan | length) |
        .totals.trivy_secrets = (.findings.trivy_secrets | length) |
        .totals.gitleaks = (.findings.gitleaks | length) |
        .totals.zap = (.findings.zap | length) |
        .totals.suppressed = .suppressed.count |
        .totals.all_findings = (.totals.semgrep + .totals.psalm + .totals.phpstan + .totals.trivy_vulnerabilities + .totals.trivy_misconfigurations + .totals.trivy_secrets + .totals.gitleaks + .totals.zap) |

        # Recompute severity_summary from active (non-suppressed) findings
        .severity_summary = (
            [.findings | to_entries[] | .value | if type == "array" then .[] else empty end] |
            {
                critical: [.[] | select(.normalized_severity == "critical")] | length,
                high: [.[] | select(.normalized_severity == "high")] | length,
                medium: [.[] | select(.normalized_severity == "medium")] | length,
                low: [.[] | select(.normalized_severity == "low")] | length,
                info: [.[] | select(.normalized_severity == "info")] | length
            }
        )
    ' "$summary" > "${summary}.tmp" && mv "${summary}.tmp" "$summary"

    rm -f "$tmp_supps"

    local suppressed_count
    suppressed_count=$(jq '.totals.suppressed // 0' "$summary")
    if [[ "$suppressed_count" -gt 0 ]]; then
        log_info "  ${suppressed_count} finding(s) suppressed"
    fi
}
