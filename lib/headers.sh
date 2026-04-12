#!/usr/bin/env bash
# Response header validation module
# Checks HTTP security headers on a running application

run_header_check() {
    local project="$1"
    local target_url="$2"
    local report_dir="$3"

    log_header "HTTP Security Headers"
    local start
    start="$(timer_start)"

    # Ensure trailing slash
    [[ "$target_url" != */ ]] && target_url="${target_url}/"

    # Fetch headers
    log_info "Checking headers at ${target_url}"
    local headers_file="${report_dir}/response-headers.txt"
    curl -s -D "$headers_file" -o /dev/null --connect-timeout 5 "$target_url" 2>/dev/null
    if [[ ! -s "$headers_file" ]]; then
        log_error "Could not fetch headers from ${target_url}"
        echo '{"passed":false,"error":"could not fetch headers"}' > "${report_dir}/headers.json"
        return 1
    fi

    # Normalize header names to lowercase for comparison
    local headers_lower
    headers_lower=$(tr '[:upper:]' '[:lower:]' < "$headers_file")

    local pass=0
    local warn=0
    local fail=0
    local results=()

    # Required headers
    check_header() {
        local name="$1"
        local level="$2"  # required or recommended
        local name_lower
        name_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')

        local value
        value=$(echo "$headers_lower" | grep "^${name_lower}:" | head -1 | sed "s/^${name_lower}: *//" | tr -d '\r')

        if [[ -n "$value" ]]; then
            results+=("{\"header\":\"${name}\",\"status\":\"present\",\"value\":$(echo "$value" | jq -Rs .),\"level\":\"${level}\"}")
            ((pass++))
            return 0
        else
            results+=("{\"header\":\"${name}\",\"status\":\"missing\",\"value\":null,\"level\":\"${level}\"}")
            if [[ "$level" == "required" ]]; then
                ((fail++))
            else
                ((warn++))
            fi
            return 1
        fi
    }

    # Check for exposure headers (should NOT be present)
    check_absent() {
        local name="$1"
        local name_lower
        name_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')

        local value
        value=$(echo "$headers_lower" | grep "^${name_lower}:" | head -1 | sed "s/^${name_lower}: *//" | tr -d '\r')

        if [[ -z "$value" ]]; then
            results+=("{\"header\":\"${name}\",\"status\":\"absent\",\"value\":null,\"level\":\"good\"}")
            ((pass++))
        else
            results+=("{\"header\":\"${name}\",\"status\":\"exposed\",\"value\":$(echo "$value" | jq -Rs .),\"level\":\"warning\"}")
            ((warn++))
        fi
    }

    # Required security headers
    check_header "X-Content-Type-Options" "required"
    check_header "X-Frame-Options" "required"
    check_header "Referrer-Policy" "required"

    # HSTS only required over HTTPS — recommended otherwise
    if [[ "$target_url" == https://* ]]; then
        check_header "Strict-Transport-Security" "required"
    else
        check_header "Strict-Transport-Security" "recommended"
    fi

    # Recommended headers
    check_header "Content-Security-Policy" "recommended"
    check_header "Permissions-Policy" "recommended"
    check_header "X-XSS-Protection" "recommended"

    # Should NOT be present
    check_absent "X-Powered-By"
    check_absent "Server"

    local elapsed
    elapsed="$(timer_elapsed "$start")"

    # Build JSON report
    local results_json
    results_json=$(printf '%s\n' "${results[@]}" | jq -s '.')

    jq -n \
        --arg url "$target_url" \
        --argjson pass "$pass" \
        --argjson warn "$warn" \
        --argjson fail "$fail" \
        --argjson results "$results_json" \
        '{
            url: $url,
            passed: ($fail == 0),
            counts: { pass: $pass, warn: $warn, fail: $fail },
            headers: $results
        }' > "${report_dir}/headers.json"

    # Print results
    if [[ $fail -eq 0 && $warn -eq 0 ]]; then
        log_success "All security headers present (${elapsed}s)"
    elif [[ $fail -eq 0 ]]; then
        log_warn "Headers OK with ${warn} warning(s) (${elapsed}s)"
    else
        log_warn "${fail} required header(s) missing, ${warn} warning(s) (${elapsed}s)"
    fi

    # Print details
    for r in "${results[@]}"; do
        local h s l
        h=$(echo "$r" | jq -r '.header')
        s=$(echo "$r" | jq -r '.status')
        l=$(echo "$r" | jq -r '.level')
        case "$s" in
            present)  printf "  ${GREEN}%-35s %s${NC}\n" "$h" "present" ;;
            missing)
                if [[ "$l" == "required" ]]; then
                    printf "  ${RED}%-35s %s${NC}\n" "$h" "MISSING (required)"
                else
                    printf "  ${YELLOW}%-35s %s${NC}\n" "$h" "missing (recommended)"
                fi
                ;;
            absent)   printf "  ${GREEN}%-35s %s${NC}\n" "$h" "not exposed" ;;
            exposed)  printf "  ${YELLOW}%-35s %s${NC}\n" "$h" "EXPOSED (should remove)" ;;
        esac
    done

    return 0
}
