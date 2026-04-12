<?php

/**
 * UserSpice Psalm Stubs — Taint Analysis Annotations
 *
 * Teaches Psalm which framework functions sanitize input, which are safe sinks,
 * and which produce tainted data. Stubs override the real class definitions
 * for taint-analysis purposes only.
 *
 * Based on analysis of UserSpice 5 core.
 *
 * @see https://psalm.dev/docs/security_analysis/
 */

// ============================================================================
// INPUT CLASS — the primary interface for user input
// ============================================================================

class Input {
    /**
     * Check if POST/GET data exists.
     */
    public static function exists(string $type = 'post'): bool {}

    /**
     * Retrieve from $_POST/$_GET and apply htmlspecialchars(ENT_QUOTES, UTF-8).
     *
     * The real class reads from superglobals (Psalm sees that as taint source).
     * We only annotate the ESCAPE here — htmlspecialchars makes the output safe
     * for HTML context. The data is still tainted for non-HTML contexts (SQL,
     * file paths, headers, etc.) which is correct behavior.
     *
     * @psalm-taint-escape html
     */
    public static function get(string $item, $trim_or_default = true, bool $fallback = false, string $default_value = ''): string {}

    /**
     * Sanitize a value with htmlspecialchars(ENT_QUOTES, UTF-8).
     * users/classes/Input.php:75
     *
     * @psalm-taint-escape html
     * @psalm-flow ($item) -> return
     */
    public static function sanitize($item, bool $trim = true, bool $fallback = false): string {}

    /**
     * Recursively sanitize arrays/objects.
     *
     * @psalm-taint-escape html
     */
    public static function recursive($object, bool $trim = true, bool $fallback = false): array {}

    /**
     * JSON decode + sanitize all values.
     *
     * @psalm-taint-escape html
     */
    public static function json(string $json, bool $associative = false, bool $encode = false, bool $trim = true, bool $fallback = false): mixed {}
}


// ============================================================================
// OUTPUT ESCAPING FUNCTIONS
// ============================================================================

/**
 * safeReturn() — htmlspecialchars($string, ENT_QUOTES, 'UTF-8')
 * users/helpers/us_helpers.php:1935
 *
 * @psalm-taint-escape html
 */
function safeReturn(string $string): string {}

/**
 * hed() — htmlspecialchars_decode(html_entity_decode(...))
 * users/helpers/us_helpers.php:1656
 *
 * WARNING: This DECODES entities — it makes data LESS safe for HTML output.
 * Do NOT mark as taint-escape. Psalm correctly flags hed() output as tainted.
 * If you intentionally use hed() for admin output of trusted data, suppress
 * the finding at the call site or in the Psalm baseline.
 */
function hed(string $string, bool $stripTags = false): string {}

/**
 * encodeURIComponent() — rawurlencode with safe char exceptions
 * users/helpers/us_helpers.php:476
 *
 * @psalm-taint-escape url
 */
function encodeURIComponent(string $str): string {}

/**
 * sanitizedDest() — validates redirect destination against pages table + whitelist
 * users/helpers/us_helpers.php:272
 *
 * @psalm-taint-escape html
 * @psalm-taint-escape url
 */
function sanitizedDest(string $varname = 'dest'): mixed {}


// ============================================================================
// REDIRECT CLASS
// ============================================================================

class Redirect {
    /**
     * Standard redirect — no sanitization of $location.
     * @psalm-taint-sink header $location
     */
    public static function to(string $location, ?array $args = null, int $code = 302): void {}

    /**
     * Sanitized redirect — strips control chars, enforces same-origin,
     * supports whitelist of allowed hosts, escapes for JSON and HTML contexts.
     * users/classes/Redirect.php:140
     *
     * @psalm-taint-escape html
     * @psalm-taint-escape header
     * @psalm-taint-escape url
     */
    public static function sanitized(string $location, ?array $args = null, int $code = 302, array $opts = []): void {}
}


// ============================================================================
// SERVER CLASS
// ============================================================================

class Server {
    /**
     * Type-aware sanitization of $_SERVER values.
     * Validates: host (regex), IP (filter_var), URI (control char strip),
     * method (allowlist), user_agent (length cap + control strip).
     *
     * @psalm-taint-escape html
     * @psalm-taint-escape header
     */
    public static function get(string $key): ?string {}
}


// ============================================================================
// DB CLASS — Parameterized Query Wrappers
// ============================================================================

class DB {
    /**
     * @psalm-taint-sink sql $sql
     */
    public function query(string $sql, array $params = []): self {}

    public function action(string $action, string $table, array $where = []): self {}
    public function insert(string $table, array $fields = [], bool $update = false): self {}
    public function update(string $table, $id, array $fields): self {}
    public function get(string $table, array $where): self {}
    public function delete(string $table, array $where): self {}
    public function findById($id, string $table): self {}
    public static function getInstance(): self {}
    public function results(): array {}
    public function first(): ?object {}
    public function count(): int {}
    public function error(): bool {}
    public function errorString(): string {}
}


// ============================================================================
// CSRF PROTECTION
// ============================================================================

class Token {
    public static function generate(bool $force = false): string {}
    public static function check(string $token): bool {}
}


// ============================================================================
// HASHING
// ============================================================================

class Hash {
    /**
     * SHA256 hash for non-password data (tokens, vericodes).
     * NOT for passwords.
     */
    public static function make(string $string, string $salt = ''): string {}

    /** Cryptographically secure random hex token — bin2hex(random_bytes(32)) */
    public static function unique(): string {}
}


// ============================================================================
// VALIDATION
// ============================================================================

class Validate {
    public function check(array $source, array $items = [], bool $sanitize = false): self {}
    public function passed(): bool {}
    public function errors(): array {}
}
