<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Tokens;
final class ConnectorTokenFactory
{
    /** Token body prefix. Kept stable for cross-app compatibility. */
    public const PREFIX = 'tsc1_';

    /** Canonical env wrapper. The only wrapper emitted. */
    public const ENV_PREFIX = 'TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN=';

    /**
     * Expected connector token payload fields. The factory itself stays a thin
     * encoder; field validation is enforced by {@see ConnectorTokenParser}.
     *
     * @var list<string>
     */
    public const PAYLOAD_FIELDS = [
        'app_id',
        'app_name',
        'slug',
        'base_url',
        'environment',
        'instance',
        'connector_mode',
        'key_id',
        'secret',
        'scopes',
        'allowed_ips',
        'connector_version',
        'issued_at',
        'expires_at',
    ];

    /**
     * Encode a connector token.
     *
     * @param array<string, mixed> $payload
     * @param bool $wrapEnv Wrap the token in the canonical env assignment line.
     */
    public static function issue(array $payload, bool $wrapEnv = true): string
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new \InvalidArgumentException('invalid_payload');
        }
        $encoded = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $token = self::PREFIX . $encoded;

        if (!$wrapEnv) {
            return $token;
        }

        return self::ENV_PREFIX . $token;
    }
}
