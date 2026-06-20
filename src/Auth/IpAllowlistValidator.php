<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Auth;

use TradesMen\SecurityCenterConnector\Config\EnvResolver;

/**
 * Validates a client IP against a connector allowlist.
 *
 * Supports:
 *   - single IPv4 (e.g. 203.0.113.10)
 *   - single IPv6 (e.g. 2001:db8::1)
 *   - comma/space separated lists
 *   - IPv4 CIDR (e.g. 203.0.113.0/24)
 *   - IPv6 CIDR (e.g. 2001:db8::/32)
 *
 * Empty-allowlist behaviour is controlled by $requireAllowlist: when the list is
 * empty and an allowlist is required, all requests are denied; when not required,
 * all requests are allowed.
 *
 * This validator does NOT inspect request headers such as X-Forwarded-For. The
 * caller (an app adapter) must pass a trusted client IP it has already derived.
 */
final class IpAllowlistValidator
{
    /**
     * @param list<string>|string $allowList
     */
    public function isAllowed(?string $clientIp, array|string $allowList, bool $requireAllowlist): bool
    {
        $entries = self::normalizeList($allowList);

        if ($entries === []) {
            return !$requireAllowlist;
        }

        if ($clientIp === null || filter_var($clientIp, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        foreach ($entries as $entry) {
            if (self::matches($clientIp, $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Flatten and clean an allowlist into individual entries. Each element may
     * itself be a comma/space separated list.
     *
     * @param list<string>|string $allowList
     * @return list<string>
     */
    public static function normalizeList(array|string $allowList): array
    {
        $raw = is_string($allowList) ? [$allowList] : $allowList;

        $out = [];
        foreach ($raw as $item) {
            if (!is_string($item)) {
                continue;
            }
            foreach (EnvResolver::splitList($item) as $entry) {
                if (!in_array($entry, $out, true)) {
                    $out[] = $entry;
                }
            }
        }

        return $out;
    }

    /**
     * Whether a single, already-validated client IP matches one allowlist entry.
     */
    public static function matches(string $ip, string $entry): bool
    {
        $entry = trim($entry);
        if ($entry === '') {
            return false;
        }

        if (str_contains($entry, '/')) {
            [$subnet, $bitsString] = explode('/', $entry, 2);
            if (!preg_match('/^\d+$/', $bitsString)) {
                return false;
            }
            $bits = (int) $bitsString;

            return str_contains($subnet, ':')
                ? self::matchesV6Cidr($ip, $subnet, $bits)
                : self::matchesV4Cidr($ip, $subnet, $bits);
        }

        $a = @inet_pton($ip);
        $b = @inet_pton($entry);
        if ($a === false || $b === false) {
            return false;
        }

        return $a === $b;
    }

    private static function matchesV4Cidr(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        $mask = -1 << (32 - $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private static function matchesV6Cidr(string $ip, string $subnet, int $bits): bool
    {
        if ($bits < 0 || $bits > 128) {
            return false;
        }

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false) {
            return false;
        }
        // Both operands must be IPv6 (16 bytes); reject mixed-family comparisons.
        if (strlen($ipBin) !== 16 || strlen($subnetBin) !== 16) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        $wholeBytes = intdiv($bits, 8);
        $remainderBits = $bits % 8;

        if ($wholeBytes > 0 && substr($ipBin, 0, $wholeBytes) !== substr($subnetBin, 0, $wholeBytes)) {
            return false;
        }

        if ($remainderBits !== 0) {
            $mask = (0xff << (8 - $remainderBits)) & 0xff;
            if ((ord($ipBin[$wholeBytes]) & $mask) !== (ord($subnetBin[$wholeBytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }
}
