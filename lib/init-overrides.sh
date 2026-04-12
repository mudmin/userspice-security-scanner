#!/usr/bin/env bash
# Initialize per-project override directory with empty config templates

init_overrides() {
    local project="$1"
    local override_dir="${OVERRIDES_DIR}/${project}"

    if [[ -d "$override_dir" ]]; then
        log_info "Override directory already exists: ${override_dir}"
        return 0
    fi

    log_header "Initializing overrides for ${project}"

    mkdir -p "${override_dir}"/{semgrep,psalm,trivy,gitleaks}

    # Semgrep: project-specific ignores
    cat > "${override_dir}/semgrep/.semgrepignore" <<'EOF'
# Project-specific Semgrep ignores
# These are ADDED to the shared .semgrepignore
# Uncomment or add paths specific to this project

# Example: ignore a legacy module you're not touching
# legacy_module/
EOF

    # Psalm: project-specific baseline
    cat > "${override_dir}/psalm/userspice-baseline.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!-- Project-specific Psalm baseline — suppresses known-accepted issues -->
<files psalm-version="5.x">
    <!-- Add suppressed issues here after review -->
</files>
EOF

    # Trivy: project-specific ignores
    cat > "${override_dir}/trivy/.trivyignore" <<'EOF'
# Project-specific Trivy ignores
# Add CVE or misconfig IDs accepted for THIS project only
EOF

    # Gitleaks: project-specific allowlist
    cat > "${override_dir}/gitleaks/.gitleaks.toml" <<'EOF'
# Project-specific Gitleaks allowlist
# Extends the shared config for this project only

title = "Project-specific Gitleaks Config"

[allowlist]
  description = "Project-specific allowlist"
  paths = []
  regexes = []
EOF

    log_success "Created override templates at ${override_dir}/"
    log_info "Edit these files to add project-specific suppressions."
}
