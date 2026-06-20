<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Config;

use InvalidArgumentException;

/**
 * Connector credential storage modes.
 *
 * - env        : the app reads key_id and shared_secret from .env. Suitable for
 *                small apps and local development.
 * - managed_db : the app stores connector secrets encrypted in its own
 *                database. Used by larger apps such as TradesMen Network.
 *
 * The ecosystem default is {@see self::ENV}; apps that need managed credentials
 * opt into {@see self::MANAGED_DB} explicitly.
 */
final class ConnectorMode
{
    public const ENV = 'env';
    public const MANAGED_DB = 'managed_db';

    public const DEFAULT = self::ENV;

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return [self::ENV, self::MANAGED_DB];
    }

    public static function normalize(string $mode): string
    {
        return strtolower(trim($mode));
    }

    public static function isValid(string $mode): bool
    {
        return in_array(self::normalize($mode), self::all(), true);
    }

    /**
     * Strict parse: throws on an invalid mode. Use where misconfiguration must
     * surface immediately (e.g. issuing a connector token).
     */
    public static function fromString(string $mode): string
    {
        $normalized = self::normalize($mode);
        if (!in_array($normalized, self::all(), true)) {
            throw new InvalidArgumentException('invalid_connector_mode');
        }

        return $normalized;
    }

    /**
     * Lenient parse: returns the default for an empty or invalid value. Use in
     * runtime config resolution where a safe default is preferable to a fatal.
     */
    public static function fromStringOrDefault(string $mode, string $default = self::DEFAULT): string
    {
        $normalized = self::normalize($mode);
        if (!in_array($normalized, self::all(), true)) {
            return $default;
        }

        return $normalized;
    }
}
