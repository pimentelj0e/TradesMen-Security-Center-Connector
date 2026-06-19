<?php
declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Redaction;

final class ResponseRedactor
{
    private const MASK = '[redacted]';
    private const SENSITIVE_KEYS = [
        'secret', 'token', 'password', 'passwd', 'pwd', 'apikey', 'api_key',
        'hmac', 'private', 'credential', 'webhook', 'authorization', 'cookie',
        'set-cookie', 'access_key', 'secret_key', 'app_key', 'dotenv',
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
            '/(authorization)\s*[:=]\s*(?:\S+\s+)?\S+/i' => '$1: ' . self::MASK,
            '/\b(bearer|basic)\s+[A-Za-z0-9._\-\/+=]{8,}/i' => '$1 ' . self::MASK,
            '/(set-cookie|cookie)\s*[:=]\s*[^\r\n]+/i' => '$1: ' . self::MASK,
            '#\b([a-z][a-z0-9+.\-]*://)[^/@\s:]+:[^/@\s]+@#i' => '$1' . self::MASK . '@',
            '/\b(["\']?(?:password|passwd|pwd|secret|token|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|hmac|app_key|private[_-]?key)["\']?\s*[:=]\s*["\']?)[^\s"\',;}]+/i' => '$1' . self::MASK,
            '/\bAKIA[0-9A-Z]{16}\b/' => self::MASK,
            '/\b([A-Z][A-Z0-9_]{2,})=([^\s"\';]+)/' => '$1=' . self::MASK,
            '/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/' => self::MASK,
            '#/[^\s:()]+\.php(?:[:(]\d+\)?)#' => self::MASK,
        ];
        foreach ($patterns as $pattern => $replacement) {
            $value = (string) preg_replace($pattern, $replacement, $value);
        }
        return (string) preg_replace('/(Stack trace:|#0\s+).*/s', '[stack trace redacted]', $value);
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
