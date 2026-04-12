#!/usr/bin/env bash
# SARIF 2.1.0 export module
# Converts summary.json into SARIF format for GitHub Code Scanning

generate_sarif() {
    local report_dir="$1"
    local summary="${report_dir}/summary.json"

    if ! command -v jq &>/dev/null; then return; fi
    if [[ ! -f "$summary" ]]; then return; fi

    log_info "Generating SARIF export..."

    jq '{
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [
            # Semgrep
            {
                tool: {
                    driver: {
                        name: "Semgrep",
                        informationUri: "https://semgrep.dev",
                        rules: [.findings.semgrep // [] | group_by(.rule) | .[] | .[0] | {
                            id: .rule,
                            shortDescription: { text: .message },
                            defaultConfiguration: {
                                level: (if .normalized_severity == "critical" or .normalized_severity == "high" then "error"
                                       elif .normalized_severity == "medium" then "warning"
                                       else "note" end)
                            }
                        }]
                    }
                },
                results: [.findings.semgrep // [] | .[] | {
                    ruleId: .rule,
                    level: (if .normalized_severity == "critical" or .normalized_severity == "high" then "error"
                           elif .normalized_severity == "medium" then "warning"
                           else "note" end),
                    message: { text: .message },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: .file },
                            region: { startLine: (.line // 1) }
                        }
                    }]
                }]
            },
            # Psalm
            {
                tool: {
                    driver: {
                        name: "Psalm",
                        informationUri: "https://psalm.dev",
                        rules: [.findings.psalm // [] | group_by(.rule) | .[] | .[0] | {
                            id: .rule,
                            shortDescription: { text: .message },
                            defaultConfiguration: {
                                level: (if .normalized_severity == "high" then "error" else "note" end)
                            }
                        }]
                    }
                },
                results: [.findings.psalm // [] | .[] | {
                    ruleId: .rule,
                    level: (if .normalized_severity == "high" then "error" else "note" end),
                    message: { text: .message },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: .file },
                            region: { startLine: (.line // 1) }
                        }
                    }]
                }]
            },
            # Trivy vulnerabilities
            {
                tool: {
                    driver: {
                        name: "Trivy",
                        informationUri: "https://trivy.dev",
                        rules: [.findings.trivy_vulnerabilities // [] | group_by(.rule) | .[] | .[0] | {
                            id: .rule,
                            shortDescription: { text: .message },
                            defaultConfiguration: {
                                level: (if .normalized_severity == "critical" or .normalized_severity == "high" then "error"
                                       elif .normalized_severity == "medium" then "warning"
                                       else "note" end)
                            }
                        }]
                    }
                },
                results: [.findings.trivy_vulnerabilities // [] | .[] | {
                    ruleId: .rule,
                    level: (if .normalized_severity == "critical" or .normalized_severity == "high" then "error"
                           elif .normalized_severity == "medium" then "warning"
                           else "note" end),
                    message: { text: (.message + (if .installed_version then " (installed: " + .installed_version + ", fix: " + (.fixed_version // "none") + ")" else "" end)) },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: (.file // "composer.lock") }
                        }
                    }]
                }]
            },
            # Gitleaks
            {
                tool: {
                    driver: {
                        name: "Gitleaks",
                        informationUri: "https://gitleaks.io",
                        rules: [.findings.gitleaks // [] | group_by(.rule) | .[] | .[0] | {
                            id: .rule,
                            shortDescription: { text: .message },
                            defaultConfiguration: { level: "error" }
                        }]
                    }
                },
                results: [.findings.gitleaks // [] | .[] | {
                    ruleId: .rule,
                    level: "error",
                    message: { text: .message },
                    locations: [{
                        physicalLocation: {
                            artifactLocation: { uri: .file },
                            region: { startLine: (.line // 1) }
                        }
                    }]
                }]
            }
        ] | [.[] | select(.results | length > 0)]
    }' "$summary" > "${report_dir}/results.sarif"

    local result_count
    result_count=$(jq '[.runs[].results | length] | add // 0' "${report_dir}/results.sarif")
    log_success "SARIF written: ${result_count} result(s) in ${report_dir}/results.sarif"
}
