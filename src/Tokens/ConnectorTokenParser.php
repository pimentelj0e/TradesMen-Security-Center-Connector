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
            $token = substr($token, strlen(ConnectorTokenFactory::ENV_PREFIX));
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
            if (trim((string) ($payload[$field] ?? '')) === '') {
                throw new \InvalidArgumentException('missing_' . $field);
            }
        }
        if (!filter_var((string) $payload['base_url'], FILTER_VALIDATE_URL)) {
            throw new \InvalidArgumentException('invalid_base_url');
        }
        $expires = isset($payload['expires_at']) ? (int) $payload['expires_at'] : null;
        if ($expires !== null && $expires <= ($now ?? time())) {
            throw new \InvalidArgumentException('token_expired');
        }
        $payload['scopes'] = array_values(array_filter(array_map('strval', (array) ($payload['scopes'] ?? []))));
        $payload['allowed_ips'] = array_values(array_filter(array_map('strval', (array) ($payload['allowed_ips'] ?? []))));
        return $payload;
    }
}
