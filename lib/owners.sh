#!/usr/bin/env bash
# Owner classification module
# Tags each finding as "userspice-core", "userspice-customizable", or "project"
# Used by summary.sh to classify findings in the report

classify_owner() {
    local filepath="$1"

    # Strip /src/ prefix if present
    filepath="${filepath#/src/}"

    case "$filepath" in
        # UserSpice core — shipped with framework, upstream-only fixes
        users/classes/*|users/helpers/*|users/parsers/*|users/includes/*|\
        users/modules/*|users/views/*|users/auth/*|users/cron/*|\
        users/init.php|users/init.live|users/index.php|\
        users/login.php|users/logout.php|users/join.php|\
        users/admin.php|users/admin_pin.php|\
        users/account.php|users/complete.php|\
        users/forgot_password.php|users/forgot_password_reset.php|\
        users/verify.php|users/verify_resend.php|\
        users/user_settings.php|users/maintenance.php|\
        users/passkeys.php|users/passwordless.php|\
        users/totp_management.php|users/totp_verification.php|\
        users/update.php|users/updates/*|\
        users/js/*|users/css/*|users/fonts/*|users/images/*|users/licenses/*|\
        users/lang/*|users/logs/*|\
        z_us_root.php)
            echo "userspice-core"
            ;;

        # UserSpice customizable — ships with framework, user CAN modify
        usersc/includes/*|usersc/scripts/*|usersc/lang/*|\
        usersc/oauth_client/*|usersc/oauth_server/*|\
        usersc/images/*)
            echo "userspice-customizable"
            ;;

        # Patch directory — staging copy of core
        patch/*)
            echo "userspice-core"
            ;;

        # Everything else is project-owned
        *)
            echo "project"
            ;;
    esac
}

# Add owner field to all findings in summary.json
enrich_findings_with_owners() {
    local report_dir="$1"
    local summary="${report_dir}/summary.json"

    if ! command -v jq &>/dev/null; then return; fi
    if [[ ! -f "$summary" ]]; then return; fi

    # Create a temp file with enriched findings
    local tmp="${report_dir}/.tmp_owners.json"

    # Process each finding type and add owner field
    jq '
        # Helper function to classify based on file path
        def classify_owner:
            # Strip /src/ or ../src/ prefix (Psalm uses ../src/)
            gsub("^(/?\\.\\./)?/?src/";"") |
            if test("^users/(classes|helpers|parsers|includes|modules|views|auth|cron|js|css|fonts|images|licenses|lang|logs|updates)/") then "userspice-core"
            elif test("^users/(init|index|login|logout|join|admin|admin_pin|account|complete|forgot_password|verify|user_settings|maintenance|passkeys|passwordless|totp_|update)\\.php") then "userspice-core"
            elif test("^z_us_root\\.php$") then "userspice-core"
            elif test("^patch/") then "userspice-core"
            elif test("^usersc/") then "userspice-customizable"
            else "project"
            end;

        .findings.semgrep = [.findings.semgrep[]? | .owner = (.file | classify_owner)] |
        .findings.psalm = [.findings.psalm[]? | .owner = (.file | classify_owner)] |
        .findings.trivy_vulnerabilities = [.findings.trivy_vulnerabilities[]? | .owner = "dependency"] |
        .findings.trivy_misconfigurations = [.findings.trivy_misconfigurations[]? | .owner = (.file // "" | classify_owner)] |
        .findings.gitleaks = [.findings.gitleaks[]? | .owner = (.file | classify_owner)] |

        # Add owner summary counts
        .owner_summary = {
            semgrep: {
                project: [.findings.semgrep[]? | select(.owner == "project")] | length,
                userspice_core: [.findings.semgrep[]? | select(.owner == "userspice-core")] | length,
                userspice_customizable: [.findings.semgrep[]? | select(.owner == "userspice-customizable")] | length
            },
            psalm: {
                project: [.findings.psalm[]? | select(.owner == "project")] | length,
                userspice_core: [.findings.psalm[]? | select(.owner == "userspice-core")] | length,
                userspice_customizable: [.findings.psalm[]? | select(.owner == "userspice-customizable")] | length
            },
            gitleaks: {
                project: [.findings.gitleaks[]? | select(.owner == "project")] | length,
                userspice_core: [.findings.gitleaks[]? | select(.owner == "userspice-core")] | length
            }
        }
    ' "$summary" > "$tmp" && mv "$tmp" "$summary"

    # Print owner breakdown
    local proj_count core_count cust_count
    proj_count=$(jq '[.owner_summary | to_entries[] | .value.project // 0] | add // 0' "$summary")
    core_count=$(jq '[.owner_summary | to_entries[] | .value.userspice_core // 0] | add // 0' "$summary")
    cust_count=$(jq '[.owner_summary | to_entries[] | .value.userspice_customizable // 0] | add // 0' "$summary")

    if [[ $((proj_count + core_count + cust_count)) -gt 0 ]]; then
        echo ""
        echo -e "${BOLD}Ownership:${NC}"
        [[ $proj_count -gt 0 ]]  && printf "  %-30s %s\n" "Your project code" "${proj_count}"
        [[ $core_count -gt 0 ]]  && printf "  %-30s %s\n" "UserSpice core (upstream)" "${core_count}"
        [[ $cust_count -gt 0 ]]  && printf "  %-30s %s\n" "UserSpice customizable" "${cust_count}"
    fi
}
