#!/usr/bin/env bash
# Psalm scanner module
# Handles: PHP-specific deep analysis, UserSpice-aware taint analysis
#
# The target project is mounted read-only at /src.
# All generated config, stubs, and autoloader go in /config inside the container,
# mapped to a staging dir in the report directory. Nothing is written to the project.
#
# If the project has no vendor/autoload.php, we generate a classmap autoloader
# so Psalm can resolve types for taint analysis.

run_psalm() {
    local project="$1"
    local project_dir="$2"
    local report_dir="$3"

    log_header "Psalm — PHP Static Analysis + Taint Detection"
    local start
    start="$(timer_start)"

    ensure_image "${PSALM_IMAGE}" || return 1

    # Check if project has PHP files
    if ! find "${project_dir}" -maxdepth 3 -name '*.php' -print -quit 2>/dev/null | grep -q .; then
        log_warn "No PHP files found in ${project_dir}, skipping Psalm."
        echo '{"findings":[],"skipped":true,"reason":"no PHP files found"}' > "${report_dir}/psalm.json"
        return 0
    fi

    # Prepare config staging area (never in the project)
    local psalm_staging="${report_dir}/psalm-config"
    mkdir -p "$psalm_staging"

    # Determine autoloader strategy
    local autoloader_line=""
    if [[ -f "${project_dir}/vendor/autoload.php" ]]; then
        # Project has a real composer autoloader
        autoloader_line='autoloader="/src/vendor/autoload.php"'
        log_info "Using project autoloader: vendor/autoload.php"
    else
        # Generate classmap autoloader
        generate_classmap_autoloader "$project_dir" "${psalm_staging}/classmap_autoloader.php"
        autoloader_line='autoloader="/config/classmap_autoloader.php"'
    fi

    # Copy stubs into staging if available
    local stubs
    stubs="$(resolve_config psalm userspice-stubs.php "$project")"
    if [[ -n "$stubs" ]]; then
        cp "$stubs" "${psalm_staging}/userspice-stubs.php"
    fi

    # Copy baseline into staging if available
    local baseline
    baseline="$(resolve_config psalm userspice-baseline.xml "$project")"
    if [[ -n "$baseline" ]]; then
        cp "$baseline" "${psalm_staging}/psalm-baseline.xml"
    fi

    # Generate psalm.xml config
    generate_psalm_config "$project" "$project_dir" "${psalm_staging}/psalm.xml" "$autoloader_line" "$stubs"

    # Mount project read-only, config staging separately, output separately
    local docker_args=(
        docker run --rm
        --entrypoint /composer/vendor/bin/psalm
        -v "${project_dir}:/src:ro"
        -v "${psalm_staging}:/config"
        -v "${report_dir}:/output"
        "${PSALM_IMAGE}"
    )

    local psalm_args=(
        --config=/config/psalm.xml
        --output-format=json
        --report=/output/psalm.json
        --no-cache
        --threads=4
        --taint-analysis
    )

    # Use baseline if available
    if [[ -n "$baseline" ]]; then
        psalm_args+=(--use-baseline=/config/psalm-baseline.xml)
    fi

    log_info "Scanning ${project_dir} with Psalm (taint analysis enabled)..."
    "${docker_args[@]}" "${psalm_args[@]}" 2>"${report_dir}/psalm-stderr.log"
    local exit_code=$?

    local elapsed
    elapsed="$(timer_elapsed "$start")"

    # Psalm exit codes: 0=clean, 1=issues at error level, 2=issues found at lower levels
    # We accept 0-2 as success (findings are captured in the JSON report)
    if [[ $exit_code -le 2 ]]; then
        local count=0
        if [[ -f "${report_dir}/psalm.json" ]] && command -v jq &>/dev/null; then
            count=$(jq 'if type == "array" then length else 0 end' "${report_dir}/psalm.json" 2>/dev/null || echo 0)
        fi
        log_success "Psalm complete: ${count} findings (${elapsed}s)"
        return 0
    else
        log_error "Psalm failed (exit ${exit_code}). Check ${report_dir}/psalm-stderr.log"
        return 1
    fi
}

generate_psalm_config() {
    local project="$1"
    local project_dir="$2"
    local output_file="$3"
    local autoloader_line="$4"
    local has_stubs="$5"

    local stubs_block=""
    if [[ -n "$has_stubs" ]]; then
        stubs_block='
    <stubs>
        <file name="/config/userspice-stubs.php" preloadClasses="true" />
    </stubs>'
    fi

    # Build ignoreFiles entries — find ALL vendor/node_modules dirs plus known third-party
    local ignore_entries=""

    # Static excludes
    for skip_dir in patch users/classes/phpmailer users/classes/PHPMailer; do
        if [[ -d "${project_dir}/${skip_dir}" ]]; then
            ignore_entries+="            <directory name=\"/src/${skip_dir}\" />"$'\n'
        fi
    done

    # Dynamic: find all vendor/ and node_modules/ directories at any depth
    while IFS= read -r vdir; do
        local reldir="${vdir#${project_dir}/}"
        ignore_entries+="            <directory name=\"/src/${reldir}\" />"$'\n'
    done < <(find "$project_dir" -maxdepth 4 -type d \( -name "vendor" -o -name "node_modules" \) 2>/dev/null)

    local ignore_block=""
    if [[ -n "$ignore_entries" ]]; then
        ignore_block="
        <ignoreFiles>
${ignore_entries}        </ignoreFiles>"
    fi

    cat > "$output_file" <<PSALMXML
<?xml version="1.0"?>
<psalm
    errorLevel="3"
    resolveFromConfigFile="false"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="https://getpsalm.org/schema/config"
    findUnusedBaselineEntry="false"
    ${autoloader_line}
>
    <projectFiles>
        <directory name="/src" />${ignore_block}
    </projectFiles>

    <issueHandlers>
        <!-- Suppress noise that isn't security-relevant -->
        <MissingReturnType errorLevel="suppress" />
        <MissingParamType errorLevel="suppress" />
        <MissingPropertyType errorLevel="suppress" />
        <MissingClosureReturnType errorLevel="suppress" />
        <MissingClosureParamType errorLevel="suppress" />
        <UnusedVariable errorLevel="suppress" />
        <UnusedParam errorLevel="suppress" />
        <PossiblyUnusedMethod errorLevel="suppress" />
        <MixedAssignment errorLevel="suppress" />
        <MixedArgument errorLevel="suppress" />
        <MixedMethodCall errorLevel="suppress" />
        <MixedArrayAccess errorLevel="suppress" />
        <MixedOperand errorLevel="suppress" />
        <MixedReturnStatement errorLevel="suppress" />
        <MixedPropertyFetch errorLevel="suppress" />
        <MixedArrayOffset errorLevel="suppress" />
        <MissingConstructor errorLevel="suppress" />
        <UndefinedClass errorLevel="suppress" />
        <UndefinedFunction errorLevel="suppress" />
        <UndefinedMethod errorLevel="suppress" />
        <UndefinedPropertyFetch errorLevel="suppress" />
        <UndefinedPropertyAssignment errorLevel="suppress" />
        <UndefinedVariable errorLevel="suppress" />
        <UndefinedGlobalVariable errorLevel="suppress" />
        <UndefinedConstant errorLevel="suppress" />
        <UndefinedMagicMethod errorLevel="suppress" />
        <PossiblyUndefinedVariable errorLevel="suppress" />
        <PossiblyUndefinedGlobalVariable errorLevel="suppress" />
        <PossiblyNullReference errorLevel="suppress" />
        <PossiblyNullPropertyFetch errorLevel="suppress" />
        <PossiblyNullArgument errorLevel="suppress" />
        <PossiblyInvalidArgument errorLevel="suppress" />
        <PossiblyInvalidMethodCall errorLevel="suppress" />
        <InvalidArgument errorLevel="suppress" />
        <InvalidReturnType errorLevel="suppress" />
        <InvalidReturnStatement errorLevel="suppress" />
        <InvalidPropertyAssignmentValue errorLevel="suppress" />
        <InvalidScalarArgument errorLevel="suppress" />
        <TypeDoesNotContainType errorLevel="suppress" />
        <RedundantCondition errorLevel="suppress" />
        <PropertyNotSetInConstructor errorLevel="suppress" />
        <InternalMethod errorLevel="suppress" />
    </issueHandlers>
    ${stubs_block}
</psalm>
PSALMXML

    log_info "Generated Psalm config at ${output_file}"
}
