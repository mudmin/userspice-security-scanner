#!/usr/bin/env bash
# Report pruning module
# Manages report directory lifecycle to prevent unbounded growth

prune_reports() {
    local project="$1"
    local keep="${2:-5}"  # Number of recent reports to keep

    local project_reports_dir="${REPORTS_DIR}/${project}"

    if [[ ! -d "$project_reports_dir" ]]; then
        log_info "No reports found for ${project}"
        return 0
    fi

    local total
    total=$(ls -1d "${project_reports_dir}"/*/ 2>/dev/null | wc -l)

    if [[ $total -le $keep ]]; then
        log_info "${project}: ${total} report(s), keeping all (threshold: ${keep})"
        return 0
    fi

    local to_delete=$(( total - keep ))
    log_info "${project}: ${total} reports, pruning ${to_delete} oldest (keeping ${keep})"

    ls -1dt "${project_reports_dir}"/*/ | tail -n "$to_delete" | while read -r dir; do
        local dirname
        dirname=$(basename "$dir")
        rm -rf "$dir"
        log_info "  Removed ${dirname}"
    done

    log_success "Pruned ${to_delete} old report(s) for ${project}"
}

# Prune all projects
prune_all_reports() {
    local keep="${1:-5}"

    if [[ ! -d "$REPORTS_DIR" ]]; then
        log_info "No reports directory found"
        return 0
    fi

    for project_dir in "${REPORTS_DIR}"/*/; do
        [[ -d "$project_dir" ]] || continue
        local project
        project=$(basename "$project_dir")
        prune_reports "$project" "$keep"
    done
}
