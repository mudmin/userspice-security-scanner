#!/usr/bin/env bash
# Classmap generator — builds a PHP autoloader from class/interface/trait declarations
# This lets Psalm resolve types without requiring composer install.
#
# Scans the project for PHP declarations and generates a classmap autoloader file.
# Handles the UserSpice pattern of scattered vendor/ dirs in plugins.

generate_classmap_autoloader() {
    local project_dir="$1"
    local output_file="$2"

    log_info "Generating classmap autoloader for Psalm..."

    # Find all PHP files, including plugin vendor dirs but excluding node_modules
    # Use grep to extract class/interface/trait/enum declarations
    local classmap_entries=""
    local count=0

    while IFS= read -r phpfile; do
        # Extract declarations: class Foo, interface Bar, trait Baz, enum Qux
        # Handle: abstract class, final class, readonly class
        while IFS= read -r match; do
            local type name
            type=$(echo "$match" | sed -E 's/^.*(class|interface|trait|enum)\s+/\1 /' | awk '{print $1}')
            name=$(echo "$match" | sed -E 's/^.*(class|interface|trait|enum)\s+([A-Za-z0-9_]+).*/\2/')

            if [[ -n "$name" && "$name" != "$type" ]]; then
                # Convert host path to container path
                local container_path="/src${phpfile#$project_dir}"
                classmap_entries+="    '${name}' => '${container_path}',"$'\n'
                ((count++))
            fi
        done < <(grep -nEh '^\s*(abstract\s+|final\s+|readonly\s+)*(class|interface|trait|enum)\s+[A-Za-z_]' "$phpfile" 2>/dev/null)
    done < <(find "$project_dir" -name '*.php' -not -path '*/node_modules/*' -not -path '*/vendor/*' 2>/dev/null)

    # Write the autoloader file
    cat > "$output_file" <<'AUTOLOADER_HEAD'
<?php
/**
 * Generated classmap autoloader for Psalm taint analysis.
 * Maps class/interface/trait names to file paths so Psalm can resolve types
 * without requiring composer install.
 *
 * AUTO-GENERATED — do not edit. Regenerated on each scan.
 */

$classmap = [
AUTOLOADER_HEAD

    echo "$classmap_entries" >> "$output_file"

    cat >> "$output_file" <<'AUTOLOADER_TAIL'
];

spl_autoload_register(function ($class) use ($classmap) {
    // Try exact match first
    if (isset($classmap[$class])) {
        if (file_exists($classmap[$class])) {
            require_once $classmap[$class];
        }
        return;
    }

    // Try case-insensitive match (PHP class names are case-insensitive)
    $lower = strtolower($class);
    foreach ($classmap as $name => $file) {
        if (strtolower($name) === $lower) {
            if (file_exists($file)) {
                require_once $file;
            }
            return;
        }
    }
});
AUTOLOADER_TAIL

    log_info "  Mapped ${count} classes/interfaces/traits"
}
