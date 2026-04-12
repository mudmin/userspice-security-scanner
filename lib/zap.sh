#!/usr/bin/env bash
# OWASP ZAP scanner module
# Handles: runtime HTTP vulnerability scanning (DAST)
#
# Profiles:
#   standard — baseline scan, ~2-5 min crawl (default)
#   deep     — full scan with Ajax spider, ~15 min
#
# Authentication:
#   If --zap-user and --zap-pass are provided, bootstraps a UserSpice
#   session via curl (GET login → extract CSRF → POST login) and injects
#   the session cookie into ZAP via the replacer add-on.

run_zap() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"
    local target_url="${4:-}"
    local zap_profile="${5:-standard}"
    local zap_user="${6:-}"
    local zap_pass="${7:-}"
    local zap_login_path="${8:-}"

    log_header "OWASP ZAP — Dynamic Application Security Testing"
    local start
    start="$(timer_start)"

    ensure_image "${ZAP_IMAGE}" || return 1

    # Auto-derive URL if not provided
    if [[ -z "$target_url" ]]; then
        target_url="http://localhost/${project}/"
        log_info "No --url provided, using: ${target_url}"
    fi

    # Ensure trailing slash
    [[ "$target_url" != */ ]] && target_url="${target_url}/"

    # Preflight: check if target is reachable
    log_info "Checking target reachability: ${target_url}"
    local http_code
    http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "$target_url" 2>/dev/null || echo "000")
    if [[ "$http_code" == "000" ]]; then
        log_error "Target ${target_url} is not reachable. Skipping ZAP."
        echo '{"findings":[],"skipped":true,"reason":"target not reachable"}' > "${report_dir}/zap.json"
        return 1
    fi
    log_info "Target responded with HTTP ${http_code}"

    # Build docker network args and rewrite localhost URLs for container access
    local net_args=()
    local container_url="$target_url"
    if [[ -n "$ZAP_DOCKER_NETWORK" ]] && docker network inspect "$ZAP_DOCKER_NETWORK" &>/dev/null 2>&1; then
        net_args=(--network "$ZAP_DOCKER_NETWORK")
        log_info "Using Docker network: ${ZAP_DOCKER_NETWORK}"
    else
        net_args=(--add-host=host.docker.internal:host-gateway)
        # Rewrite localhost/127.0.0.1 URLs so ZAP container can reach the host
        container_url=$(echo "$target_url" | sed -E 's|http://(localhost\|127\.0\.0\.1)|http://host.docker.internal|')
        if [[ "$container_url" != "$target_url" ]]; then
            log_info "Rewriting URL for container: ${container_url}"
        fi
    fi

    # ---- Authentication bootstrap ----
    # ---- Authentication bootstrap ----
    local auth_cookie=""
    if [[ -n "$zap_user" && -n "$zap_pass" ]]; then
        log_info "Bootstrapping authenticated session for: ${zap_user}"
        auth_cookie=$(bootstrap_userspice_session "$target_url" "$zap_user" "$zap_pass" "$report_dir" "$zap_login_path")
        if [[ -n "$auth_cookie" ]]; then
            log_success "Authenticated session obtained"
        else
            log_warn "Authentication failed — ZAP will scan as unauthenticated visitor"
        fi
    else
        log_info "No credentials provided — scanning as unauthenticated visitor"
    fi

    # ---- Determine profile settings ----
    # quick    → zap-baseline.py (passive only, no active scan)
    # standard → zap-full-scan.py with spider 5m + ascan capped at 10m
    # deep     → zap-full-scan.py with spider 15m + ascan capped at 45m + Ajax spider
    local spider_min ascan_cap_min use_ajax scanner profile_desc
    case "$zap_profile" in
        quick)
            spider_min=2; ascan_cap_min=0; use_ajax=0
            scanner="zap-baseline.py"
            profile_desc="quick (passive scan only, ~3 min)"
            ;;
        deep)
            spider_min=15; ascan_cap_min=45; use_ajax=1
            scanner="zap-full-scan.py"
            profile_desc="deep (spider 15m + ascan cap 45m + ajax, up to ~60 min)"
            ;;
        standard|*)
            zap_profile="standard"
            spider_min=5; ascan_cap_min=10; use_ajax=0
            scanner="zap-full-scan.py"
            profile_desc="standard (spider 5m + ascan cap 10m, up to ~15 min)"
            ;;
    esac
    log_info "Profile: ${profile_desc}"

    # ---- Build ZAP hook script ----
    # Handles auth cookie injection, seed-URL override (fixes zap-full-scan.py
    # stripping the path to host root), ascan time cap, and writes ZAP's
    # dynamic API port to /zap/wrk/.zap-port so the host can poll progress.
    local cookie_line=""
    if [[ -n "$auth_cookie" ]]; then
        cookie_line="cookie = 'PHPSESSID=${auth_cookie}'"
    else
        cookie_line="cookie = None"
    fi

    local target_path
    target_path=$(printf '%s' "$container_url" | sed -E 's|^https?://[^/]+||; s|/$||')
    local target_host
    target_host=$(printf '%s' "$container_url" | sed -E 's|^(https?://[^/]+).*|\1|')

    ZAP_HOOK="${report_dir}/zap-hook.py"
    cat > "$ZAP_HOOK" <<ZAPHOOK
import logging, glob, os

TARGET_HOST = '${target_host}'
TARGET_PATH = '${target_path}'
ASCAN_MAX_MIN = ${ascan_cap_min}
${cookie_line}

SEED_URL = TARGET_HOST + TARGET_PATH + '/' if TARGET_PATH else TARGET_HOST + '/'

def _discover_zap_port():
    # ZAPv2 proxies dict holds the actual API endpoint.
    # Attribute is name-mangled (_ZAPv2__proxies) in some versions.
    return _zap_port_from_proxies() or _zap_port_from_proc()

def _zap_port_from_proxies():
    try:
        from urllib.parse import urlparse
        import sys
        mod = sys.modules.get('zap_common')
        zap_obj = getattr(mod, 'zap', None) if mod else None
        if zap_obj is None:
            return None
        for attr in ('_ZAPv2__proxies', 'proxies'):
            p = getattr(zap_obj, attr, None)
            if isinstance(p, dict):
                http = p.get('http') or p.get('https')
                if http:
                    return urlparse(http).port
    except Exception:
        return None
    return None

def _zap_port_from_proc():
    try:
        for d in glob.glob('/proc/[0-9]*/cmdline'):
            try:
                with open(d) as f:
                    args = f.read().split('\x00')
            except Exception:
                continue
            if not any('zap-' in a and a.endswith('.jar') for a in args):
                continue
            for i, a in enumerate(args):
                if a == '-port' and i + 1 < len(args):
                    return int(args[i + 1])
    except Exception:
        return None
    return None

def zap_spider(zap, target):
    """Undo zap-full-scan.py's path stripping (its lines 350-352) so the
    spider seeds at the target subpath instead of the webroot."""
    logging.info('Hook zap_spider: overriding target %r -> %r', target, SEED_URL)
    return (zap, SEED_URL)

def zap_ajax_spider(zap, target, max_time):
    logging.info('Hook zap_ajax_spider: overriding target %r -> %r', target, SEED_URL)
    return (zap, SEED_URL, max_time)

def zap_active_scan(zap, target, policy):
    logging.info('Hook zap_active_scan: overriding target %r -> %r', target, SEED_URL)
    return (zap, SEED_URL, policy)

def zap_started(zap, target):
    # Write the API port so the host-side orchestrator can poll progress
    try:
        port = _discover_zap_port()
        if port:
            with open('/zap/wrk/.zap-port', 'w') as f:
                f.write(str(port))
            logging.info('Hook: wrote ZAP port %s to /zap/wrk/.zap-port', port)
        else:
            logging.warning('Hook: could not discover ZAP API port')
    except Exception as e:
        logging.warning('Hook: port-file write failed: %s', e)

    # Cap active scan duration so "deep" runs can't go runaway
    if ASCAN_MAX_MIN and ASCAN_MAX_MIN > 0:
        try:
            zap.ascan.set_option_max_scan_duration_in_mins(ASCAN_MAX_MIN)
            logging.info('Hook: ascan max duration set to %d min', ASCAN_MAX_MIN)
        except Exception as e:
            logging.warning('Hook: could not set ascan duration cap: %s', e)

    # Inject auth cookie
    if cookie:
        logging.info('Hook: Adding auth cookie via replacer: %s...', cookie[:30])
        try:
            result = zap.replacer.add_rule(
                description='auth-session',
                enabled=True,
                matchtype='REQ_HEADER',
                matchregex=False,
                matchstring='Cookie',
                replacement=cookie
            )
            logging.info('Hook: Replacer result: %s', result)
        except Exception as e:
            logging.error('Hook: Failed to configure replacer: %s', e)

    # Spider exclusions: skip common Apache/system paths
    if TARGET_PATH:
        excludes = [
            r'.*/etc(/.*)?\$',
            r'.*/var(/.*)?\$',
            r'.*/usr(/.*)?\$',
            r'.*/srv(/.*)?\$',
            r'.*/icons(/.*)?\$',
            r'.*/manual(/.*)?\$',
            r'.*/\.env.*',
            r'.*/sitemap\.xml.*',
            '.*' + TARGET_PATH.replace('.', r'\.') + r'/.*logout.*',
        ]
        for pattern in excludes:
            try:
                zap.spider.exclude_from_scan(pattern)
            except Exception as e:
                logging.warning('Hook: Could not exclude %s: %s', pattern, e)

def zap_pre_shutdown(zap):
    try:
        urls = zap.core.urls()
        in_scope = [u for u in urls if TARGET_PATH and TARGET_PATH in u]
        logging.info('Hook: URLs in scope: %d, total: %d', len(in_scope), len(urls))
    except Exception as e:
        logging.warning('Hook: Could not get URLs: %s', e)
ZAPHOOK

    # ---- Prep working dir and rules ----
    local zap_wrk="${report_dir}/zap-wrk"
    mkdir -p "$zap_wrk"
    chmod 777 "$zap_wrk"

    cp "$ZAP_HOOK" "${zap_wrk}/zap-hook.py"
    chmod 644 "${zap_wrk}/zap-hook.py"

    local zap_rules_arg=()
    local zap_rules
    zap_rules="$(resolve_config zap rules.tsv "$project")"
    if [[ -n "$zap_rules" ]]; then
        cp "$zap_rules" "${zap_wrk}/rules.tsv"
        chmod 644 "${zap_wrk}/rules.tsv"
        zap_rules_arg=(-c rules.tsv)
        log_info "Using ZAP rules config ($(grep -c 'IGNORE' "$zap_rules") suppressed alerts)"
    fi

    # ---- Build docker + zap command ----
    local cid_file="${report_dir}/.zap-cid"
    rm -f "$cid_file"

    local docker_args=(
        docker run --rm
        --cidfile "$cid_file"
        -v "${zap_wrk}:/zap/wrk:rw"
        "${net_args[@]}"
        "${ZAP_IMAGE}"
    )

    local zap_args=(
        "$scanner"
        -t "$container_url"
        "${zap_rules_arg[@]}"
        -J zap.json
        -r zap.html
        -m "$spider_min"
        -I
        --hook /zap/wrk/zap-hook.py
    )
    (( use_ajax )) && zap_args+=(-j)

    # ---- Run backgrounded, poll for progress ----
    local zap_log="${report_dir}/zap-stderr.log"
    log_info "Scanning ${target_url} with ZAP..."
    "${docker_args[@]}" "${zap_args[@]}" >"$zap_log" 2>&1 &
    local docker_pid=$!

    # Wait for cidfile to appear (container started)
    local wait_start=$SECONDS
    while [[ ! -s "$cid_file" ]]; do
        if ! kill -0 "$docker_pid" 2>/dev/null; then
            wait "$docker_pid"; local ec=$?
            log_error "ZAP container exited before starting (code ${ec}). See ${zap_log}"
            return 1
        fi
        (( SECONDS - wait_start > 60 )) && { log_warn "Timeout waiting for container id"; break; }
        sleep 1
    done
    local cid=""
    [[ -s "$cid_file" ]] && cid=$(<"$cid_file")

    # Wait for hook to write the API port (up to 90s; addon install is slow)
    local port="" port_file="${zap_wrk}/.zap-port"
    wait_start=$SECONDS
    while [[ -z "$port" ]] && kill -0 "$docker_pid" 2>/dev/null; do
        [[ -s "$port_file" ]] && port=$(<"$port_file")
        (( SECONDS - wait_start > 90 )) && break
        sleep 1
    done
    if [[ -n "$port" ]]; then
        log_info "ZAP API up on container port ${port} (cid=${cid:0:12})"
    else
        log_warn "ZAP API port not discovered — progress updates unavailable"
    fi

    # Poll loop: 5s interval, always logs so the user sees liveness
    local poll_count=0
    while kill -0 "$docker_pid" 2>/dev/null; do
        local t_elapsed=$(($(date +%s) - start))
        local t_fmt
        t_fmt=$(printf '%dm%02ds' $((t_elapsed/60)) $((t_elapsed%60)))
        if [[ -n "$port" && -n "$cid" ]]; then
            # Single docker exec runs all API queries to cut latency.
            # The trailing `echo` after each curl guarantees a newline so the
            # next '===section===' marker lands on its own line.
            local api_out status
            api_out=$(docker exec "$cid" sh -c "
                echo '===spider==='; curl -s 'http://localhost:${port}/JSON/spider/view/scans/'; echo
                echo '===ascan==='; curl -s 'http://localhost:${port}/JSON/ascan/view/scans/'; echo
                echo '===msgs==='; curl -s 'http://localhost:${port}/JSON/core/view/numberOfMessages/'; echo
                echo '===pscan==='; curl -s 'http://localhost:${port}/JSON/pscan/view/recordsToScan/'; echo
            " 2>/dev/null)
            status=$(_zap_format_status "$api_out")
            log_info "ZAP [${t_fmt}] ${status:-working...}"
        else
            # Port not yet discovered — heartbeat only
            (( poll_count % 2 == 0 )) && log_info "ZAP [${t_fmt}] starting up..."
        fi
        ((poll_count++))
        sleep 5
    done
    wait "$docker_pid"
    local exit_code=$?

    # Move ZAP outputs from wrk subdirectory to report root
    [[ -f "${zap_wrk}/zap.json" ]] && mv "${zap_wrk}/zap.json" "${report_dir}/zap.json"
    [[ -f "${zap_wrk}/zap.html" ]] && mv "${zap_wrk}/zap.html" "${report_dir}/zap.html"
    rm -rf "$zap_wrk" 2>/dev/null || true
    rm -f "$cid_file"

    local elapsed
    elapsed="$(timer_elapsed "$start")"

    # ZAP exit codes: 0=pass, 1=warn (alerts found), 2=fail (scan error)
    # -I flag makes warnings non-fatal
    if [[ $exit_code -le 2 ]]; then
        local alert_count=0
        if [[ -f "${report_dir}/zap.json" ]] && command -v jq &>/dev/null; then
            alert_count=$(jq '[.site[]?.alerts // [] | length] | add // 0' "${report_dir}/zap.json" 2>/dev/null || echo 0)
        fi
        local auth_note=""
        [[ -n "$auth_cookie" ]] && auth_note=" (authenticated)"
        log_success "ZAP complete: ${alert_count} alert types${auth_note} (${elapsed}s)"
        return 0
    else
        log_error "ZAP failed (exit ${exit_code}). Check ${zap_log}"
        return 1
    fi
}

# Format a compact ZAP progress line from concatenated API output.
# Input is a single blob with '===spider===', '===ascan===', '===msgs===',
# '===pscan===' section markers (produced by the poll loop's docker exec).
_zap_format_status() {
    local blob="${1:-}"
    [[ -z "$blob" ]] && return 0
    command -v python3 &>/dev/null || return 0
    python3 - "$blob" 2>/dev/null <<'PYEOF'
import sys, json

raw = sys.argv[1]
sections = {}
cur = None
buf = []
for line in raw.splitlines():
    if line.startswith('===') and line.endswith('==='):
        if cur is not None:
            sections[cur] = '\n'.join(buf).strip()
        cur = line.strip('=')
        buf = []
    else:
        buf.append(line)
if cur is not None:
    sections[cur] = '\n'.join(buf).strip()

def safe(s):
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {}

spider = safe(sections.get('spider'))
ascan = safe(sections.get('ascan'))
msgs = safe(sections.get('msgs'))
pscan = safe(sections.get('pscan'))
parts = []

for s in spider.get('scans', []):
    state = s.get('state', '')
    prog = s.get('progress', '0')
    if state == 'RUNNING':
        parts.append(f"spider {prog}%")
    elif state == 'FINISHED':
        parts.append("spider done")

for a in ascan.get('scans', []):
    state = a.get('state', '')
    prog = a.get('progress', '0')
    reqs = a.get('reqCount', '0')
    alerts = a.get('alertCount', '0')
    try:
        reqs_fmt = f"{int(reqs):,}"
    except Exception:
        reqs_fmt = reqs
    if state == 'RUNNING':
        parts.append(f"ascan {prog}% · {reqs_fmt} reqs · {alerts} alerts")
    elif state == 'FINISHED':
        parts.append(f"ascan done · {reqs_fmt} reqs")

# Passive scan queue (only show if there's pending work)
try:
    pending = int(pscan.get('recordsToScan', '0'))
    if pending > 0:
        parts.append(f"pscan queue: {pending}")
except Exception:
    pass

try:
    nmsgs = int(msgs.get('numberOfMessages', '0'))
    if nmsgs > 0:
        parts.append(f"{nmsgs:,} msgs")
except Exception:
    pass

# Always produce some output so the poll loop has something to print
if not parts:
    parts.append('idle (waiting for spider)')

print(' | '.join(parts))
PYEOF
}

# Bootstrap a UserSpice login session via curl.
# Returns the PHPSESSID cookie value on stdout on success, empty on failure.
# All log messages go to stderr so they don't contaminate the captured output.
bootstrap_userspice_session() {
    local base_url="$1"
    local username="$2"
    local password="$3"
    local report_dir="$4"
    local login_path="${5:-users/login.php}"

    # Default to users/login.php if not specified
    [[ -z "$login_path" ]] && login_path="users/login.php"
    local login_url="${base_url}${login_path}"
    local cookie_jar="${report_dir}/.zap-auth-cookies"

    # Step 1: GET the login page to obtain CSRF token + initial session cookie.
    # Follow redirects (-L) and capture the final URL — some setups rewrite
    # login.php to /login via .htaccess. We must POST to the final URL,
    # not the original, or the rewrite will 302 the POST and lose form data.
    local login_page actual_login_url
    login_page=$(curl -s -c "$cookie_jar" -L -w '\n%{url_effective}' "$login_url" 2>/dev/null)
    actual_login_url=$(echo "$login_page" | tail -1)
    login_page=$(echo "$login_page" | sed '$d')

    if [[ -z "$login_page" ]]; then
        log_warn "Could not fetch login page at ${login_url}" >&2
        return 1
    fi

    if [[ "$actual_login_url" != "$login_url" ]]; then
        log_info "Login URL rewritten: ${actual_login_url}" >&2
    fi

    # Extract CSRF token from the form
    # UserSpice puts it in: <input type="hidden" name="csrf" value="TOKEN">
    local csrf_token
    csrf_token=$(echo "$login_page" | grep -oP 'name="csrf"\s+value="\K[^"]+' | head -1)
    if [[ -z "$csrf_token" ]]; then
        # Try alternate form: value="..." name="csrf"
        csrf_token=$(echo "$login_page" | grep -oP 'value="\K[^"]+(?="\s*name="csrf")' | head -1)
    fi

    if [[ -z "$csrf_token" ]]; then
        log_warn "Could not extract CSRF token from login page" >&2
        return 1
    fi

    # Step 2: POST login to the actual URL (after any rewrites)
    local login_response
    login_response=$(curl -s -b "$cookie_jar" -c "$cookie_jar" -L \
        -w '\n%{http_code}' \
        --data-urlencode "username=${username}" \
        --data-urlencode "password=${password}" \
        --data-urlencode "csrf=${csrf_token}" \
        -d "remember=&dest=" \
        "$actual_login_url" 2>/dev/null)

    local response_code
    response_code=$(echo "$login_response" | tail -1)

    # Step 3: Extract the session cookie
    local session_id
    session_id=$(grep -P '\tPHPSESSID\t' "$cookie_jar" 2>/dev/null | awk '{print $NF}')

    # Verify the session is authenticated by checking for a redirect to dashboard
    # or the absence of the login form in the response
    local response_body
    response_body=$(echo "$login_response" | sed '$d')

    if [[ -z "$session_id" ]]; then
        log_warn "No session cookie obtained" >&2
        rm -f "$cookie_jar"
        return 1
    fi

    # Verify auth by requesting a protected page with the session cookie.
    # Follow all redirects (pretty URLs may chain .php -> /path -> /?view=path).
    # If the final URL contains "login", auth failed (redirected back to login).
    local verify_url="${base_url}users/account.php"
    local verify_result
    verify_result=$(curl -sL -o /dev/null -w '%{http_code} %{url_effective}' \
        -b "PHPSESSID=${session_id}" \
        "$verify_url" 2>/dev/null) || verify_result="000"

    local verify_code verify_final_url
    verify_code="${verify_result%% *}"
    verify_final_url="${verify_result#* }"

    if [[ "$verify_code" != "200" ]] || echo "$verify_final_url" | grep -qi "login"; then
        log_warn "Login verification failed (account.php -> HTTP ${verify_code}, final: ${verify_final_url})" >&2
        log_warn "Check username/password and ensure the account exists in the target project" >&2
        rm -f "$cookie_jar"
        return 1
    fi

    log_info "Login verified (HTTP ${verify_code}, ${verify_final_url})" >&2

    # Save auth details for the report
    echo "${session_id}" > "${report_dir}/.zap-auth-session"
    echo "user=${username}" > "${report_dir}/.zap-auth-info"
    echo "login_url=${login_url}" >> "${report_dir}/.zap-auth-info"
    echo "http_code=${response_code}" >> "${report_dir}/.zap-auth-info"
    echo "verified=true" >> "${report_dir}/.zap-auth-info"

    # Clean up cookie jar (contains password-adjacent data)
    rm -f "$cookie_jar"

    echo "$session_id"
}
