<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Config;

/**
 * Canonical TradesMen Security Center connector environment variable names
 * plus the backward-compatible alias maps.
 *
 * Resolution priority is always:
 *   1. TRADESMEN_SECURITY_CENTER_* (canonical)
 *   2. TSC_*                       (legacy primary alias)
 *   3. SECURITY_CENTER_* / APP_*   (legacy app-specific alias, only where mapped)
 *
 * The class only describes names and their relationships. It never reads,
 * prints, or logs any value. Value resolution lives in {@see EnvResolver}.
 */
final class ConnectorEnvNames
{
    public const TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED = 'TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED';
    public const TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE = 'TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE';
    public const TRADESMEN_SECURITY_CENTER_APP_ID = 'TRADESMEN_SECURITY_CENTER_APP_ID';
    public const TRADESMEN_SECURITY_CENTER_INSTANCE = 'TRADESMEN_SECURITY_CENTER_INSTANCE';
    public const TRADESMEN_SECURITY_CENTER_ENVIRONMENT = 'TRADESMEN_SECURITY_CENTER_ENVIRONMENT';
    public const TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS = 'TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS';
    public const TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS = 'TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS';
    public const TRADESMEN_SECURITY_CENTER_KEY_ID = 'TRADESMEN_SECURITY_CENTER_KEY_ID';
    public const TRADESMEN_SECURITY_CENTER_SHARED_SECRET = 'TRADESMEN_SECURITY_CENTER_SHARED_SECRET';
    public const TRADESMEN_SECURITY_CENTER_SCOPES = 'TRADESMEN_SECURITY_CENTER_SCOPES';
    public const TRADESMEN_SECURITY_CENTER_ALLOWED_IPS = 'TRADESMEN_SECURITY_CENTER_ALLOWED_IPS';
    public const TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST = 'TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST';
    public const TRADESMEN_SECURITY_CENTER_URL = 'TRADESMEN_SECURITY_CENTER_URL';
    public const TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED = 'TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED';
    public const TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS = 'TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS';
    public const TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS = 'TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS';
    public const TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN = 'TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN';

    /**
     * Canonical name => ordered list of legacy alias names.
     *
     * Order matters: the first alias that resolves to a non-empty value wins.
     *
     * @return array<string, list<string>>
     */
    public static function aliases(): array
    {
        return [
            self::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED => [
                'TSC_CONNECTOR_ENABLED',
                'SECURITY_CENTER_CONNECTOR_ENABLED',
            ],
            self::TRADESMEN_SECURITY_CENTER_APP_ID => [
                'TSC_APP_ID',
                'SECURITY_CENTER_APP_ID',
            ],
            self::TRADESMEN_SECURITY_CENTER_INSTANCE => [
                'TSC_INSTANCE',
                'APP_INSTANCE',
            ],
            self::TRADESMEN_SECURITY_CENTER_ENVIRONMENT => [
                'TSC_ENVIRONMENT',
                'APP_ENV',
            ],
            self::TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS => [
                'TSC_ALLOWED_CLOCK_SKEW_SECONDS',
                'SECURITY_CENTER_SIGNATURE_TTL_SECONDS',
            ],
            self::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS => [
                'TSC_NONCE_TTL_SECONDS',
                'TSC_CONNECTOR_NONCE_TTL_SECONDS',
                'SECURITY_CENTER_NONCE_TTL_SECONDS',
                'SECURITY_CENTER_NONCE_RETENTION_MINUTES',
            ],
            self::TRADESMEN_SECURITY_CENTER_KEY_ID => [
                'TSC_KEY_ID',
            ],
            self::TRADESMEN_SECURITY_CENTER_SHARED_SECRET => [
                'TSC_SHARED_SECRET',
            ],
            self::TRADESMEN_SECURITY_CENTER_SCOPES => [
                'TSC_SCOPES',
            ],
            self::TRADESMEN_SECURITY_CENTER_ALLOWED_IPS => [
                'TSC_ALLOWED_IPS',
                'SECURITY_CENTER_DEFAULT_ALLOWED_IPS',
            ],
            self::TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST => [
                'TSC_REQUIRE_IP_ALLOWLIST',
                'SECURITY_CENTER_REQUIRE_IP_ALLOWLIST',
            ],
            self::TRADESMEN_SECURITY_CENTER_URL => [
                'TSC_SECURITY_CENTER_URL',
                'SECURITY_CENTER_HEARTBEAT_URL',
            ],
            self::TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED => [
                'TSC_HEARTBEAT_ENABLED',
                'SECURITY_CENTER_HEARTBEAT_ENABLED',
            ],
            self::TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS => [
                'TSC_HEARTBEAT_INTERVAL_SECONDS',
                'SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS',
            ],
            self::TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS => [
                'TSC_HEARTBEAT_TIMEOUT_SECONDS',
                'SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS',
            ],
            self::TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN => [
                'TSC_CONNECTOR_TOKEN',
            ],
        ];
    }

    /**
     * Alias names whose stored value is expressed in minutes and must be
     * multiplied by 60 to become the canonical seconds value.
     *
     * @return array<string, int> alias name => multiplier to reach seconds
     */
    public static function minuteAliases(): array
    {
        return [
            'SECURITY_CENTER_NONCE_RETENTION_MINUTES' => 60,
        ];
    }

    /**
     * Ordered list of candidate env names for a canonical name: the canonical
     * name first, then each alias in priority order.
     *
     * @return list<string>
     */
    public static function candidates(string $canonical): array
    {
        $aliases = self::aliases()[$canonical] ?? [];
        return array_merge([$canonical], $aliases);
    }

    /**
     * Every canonical env name.
     *
     * @return list<string>
     */
    public static function canonicalNames(): array
    {
        return [
            self::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED,
            self::TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE,
            self::TRADESMEN_SECURITY_CENTER_APP_ID,
            self::TRADESMEN_SECURITY_CENTER_INSTANCE,
            self::TRADESMEN_SECURITY_CENTER_ENVIRONMENT,
            self::TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS,
            self::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS,
            self::TRADESMEN_SECURITY_CENTER_KEY_ID,
            self::TRADESMEN_SECURITY_CENTER_SHARED_SECRET,
            self::TRADESMEN_SECURITY_CENTER_SCOPES,
            self::TRADESMEN_SECURITY_CENTER_ALLOWED_IPS,
            self::TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST,
            self::TRADESMEN_SECURITY_CENTER_URL,
            self::TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED,
            self::TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS,
            self::TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS,
            self::TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN,
        ];
    }

    /**
     * Every name this package may read: canonical names plus all aliases.
     * Useful for test isolation.
     *
     * @return list<string>
     */
    public static function allKnownNames(): array
    {
        $names = self::canonicalNames();
        foreach (self::aliases() as $aliases) {
            foreach ($aliases as $alias) {
                $names[] = $alias;
            }
        }
        return array_values(array_unique($names));
    }
}
