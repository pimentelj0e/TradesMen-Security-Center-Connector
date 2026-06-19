<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Tokens;
final class ConnectorTokenFactory
{
    public const PREFIX = 'tsc1_';
    public const ENV_PREFIX = 'TSC_CONNECTOR_TOKEN=';

    public static function issue(array $payload, bool $wrapEnv = true): string
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($json)) {
            throw new \InvalidArgumentException('invalid_payload');
        }
        $encoded = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        $token = self::PREFIX . $encoded;
        return $wrapEnv ? self::ENV_PREFIX . $token : $token;
    }
}
