<?php
declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Redaction;

/**
 * Redacts sensitive material from connector response payloads before they leave
 * the host app. Works on both structured arrays (by key) and free-form strings
 * (by pattern), so it catches secrets that surface inside error messages, config
 * dumps, and stack traces as well as in well-named fields.
 */
final class ResponseRedactor
{
    private const MASK = '[redacted]';

    /**
     * Array-key fragments that mark a value as sensitive. Matching is a
     * case-insensitive substring test, so `db_password`, `webhook_secret`,
     * `x-api-key`, etc. are all covered.
     */
    private const SENSITIVE_KEYS = [
        'secret', 'token', 'password', 'passwd', 'pwd', 'apikey', 'api_key',
        'hmac', 'private', 'credential', 'webhook', 'authorization', 'cookie',
        'set-cookie', 'access_key', 'secret_key', 'app_key', 'dotenv', 'env_dump',
        'database_url', 'db_url', 'dsn', 'connection_string', 'conn_string',
    ];

    public function redact(mixed $value): mixed
    {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $key => $item) {
                $out[$key] = $this->isSensitiveKey((string) $key) ? self::MASK : $this->redact($item);
            }
            return $out;
        }
        if (is_string($value)) {
            return $this->redactString($value);
        }
        return $value;
    }

    private function redactString(string $value): string
    {
        $patterns = [
            // Authorization header value (with or without an auth scheme).
            '/(authorization)\s*[:=]\s*(?:\S+\s+)?\S+/i' => '$1: ' . self::MASK,
            // Bearer / Basic credentials appearing anywhere.
            '/\b(bearer|basic)\s+[A-Za-z0-9._\-\/+=]{8,}/i' => '$1 ' . self::MASK,
            // Cookie / Set-Cookie header values.
            '/(set-cookie|cookie)\s*[:=]\s*[^\r\n]+/i' => '$1: ' . self::MASK,
            // Credentials embedded in a URL or DSN: scheme://user:pass@host.
            '#\b([a-z][a-z0-9+.\-]*://)[^/@\s:]+:[^/@\s]+@#i' => '$1' . self::MASK . '@',
            // key:value / key=value whose key contains a sensitive fragment
            // (covers webhook_secret, db_password, client-secret, api_key, dsn...).
            '/\b([\w.\-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|webhook[_-]?secret|hmac|app[_-]?key|private[_-]?key|dsn|database[_-]?url|connection[_-]?string)["\']?\s*[:=]\s*["\']?)[^\s"\',;}]+/i' => '$1' . self::MASK,
            // AWS access key id.
            '/\bAKIA[0-9A-Z]{16}\b/' => self::MASK,
            // Raw env / dotenv dump: NAME=value (uppercase, env-style names).
            '/\b([A-Z][A-Z0-9_]{2,})=([^\s"\';]+)/' => '$1=' . self::MASK,
            // Private (RFC1918 / loopback) IPv4 addresses.
            '/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/' => self::MASK,
            // Private filesystem paths that leak host/user layout.
            '#/(?:home|Users)/[^/\s:;,()"\']+#' => self::MASK,
            '#/(?:root|var/www|srv)(?=[/\s:;,()"\']|$)#' => self::MASK,
            // Source-file references (with optional line/column suffix).
            '#/[^\s:()]+\.php(?:[:(]\d+\)?)?#' => self::MASK,
        ];
        foreach ($patterns as $pattern => $replacement) {
            $value = (string) preg_replace($pattern, $replacement, $value);
        }

        // Collapse any remaining exception stack trace to a single marker.
        return (string) preg_replace('/(Stack trace:|#\d+\s+).*/s', '[stack trace redacted]', $value);
    }

    private function isSensitiveKey(string $key): bool
    {
        $lower = strtolower($key);
        foreach (self::SENSITIVE_KEYS as $fragment) {
            if (str_contains($lower, $fragment)) {
                return true;
            }
        }
        return false;
    }
}
