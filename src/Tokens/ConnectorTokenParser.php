<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Tokens;
final class ConnectorTokenParser
{
    public const MAX_LENGTH = 8192;

    public static function parse(string $raw, ?int $now = null): array
    {
        $token = trim($raw);
        if (str_starts_with($token, ConnectorTokenFactory::ENV_PREFIX)) {
            $token = trim(substr($token, strlen(ConnectorTokenFactory::ENV_PREFIX)));
        }
        // Reject any other ENV_NAME= wrapper (e.g. legacy connector token
        // wrappers). Only the canonical wrapper or a bare tsc1_ token are valid.
        if (preg_match('/^[A-Za-z][A-Za-z0-9_]*=/', $token)) {
            throw new \InvalidArgumentException('unrecognized_token_wrapper');
        }
        if ($token === '' || strlen($token) > self::MAX_LENGTH) {
            throw new \InvalidArgumentException('invalid_token');
        }
        if (!str_starts_with($token, ConnectorTokenFactory::PREFIX)) {
            throw new \InvalidArgumentException('unrecognized_token');
        }
        $encoded = substr($token, strlen(ConnectorTokenFactory::PREFIX));
        $json = base64_decode(strtr($encoded, '-_', '+/') . str_repeat('=', (4 - strlen($encoded) % 4) % 4), true);
        if (!is_string($json) || strlen($json) > self::MAX_LENGTH) {
            throw new \InvalidArgumentException('invalid_token_encoding');
        }
        $payload = json_decode($json, true);
        if (!is_array($payload)) {
            throw new \InvalidArgumentException('invalid_token_payload');
        }
        foreach (['app_id', 'key_id', 'secret', 'base_url'] as $field) {
            if (!isset($payload[$field]) || !is_string($payload[$field]) || trim($payload[$field]) === '') {
                throw new \InvalidArgumentException('missing_' . $field);
            }
        }
        if (!filter_var($payload['base_url'], FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException('invalid_base_url');
        }
        $expires = isset($payload['expires_at']) ? (int) $payload['expires_at'] : null;
        if ($expires !== null && $expires <= ($now ?? time())) {
            throw new \InvalidArgumentException('token_expired');
        }
        $payload['scopes'] = self::stringList($payload['scopes'] ?? [], 'scopes');
        $payload['allowed_ips'] = self::stringList($payload['allowed_ips'] ?? [], 'allowed_ips');
        return $payload;
    }

    private static function stringList(mixed $value, string $field): array
    {
        if (!is_array($value) || !array_is_list($value)) {
            throw new \InvalidArgumentException('invalid_' . $field);
        }

        $out = [];
        foreach ($value as $item) {
            if (!is_string($item)) {
                throw new \InvalidArgumentException('invalid_' . $field);
            }
            $item = trim($item);
            if ($item !== '') {
                $out[] = $item;
            }
        }
        return $out;
    }
}
