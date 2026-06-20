<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Config;

/**
 * Reads connector configuration from the process environment.
 *
 * Resolution prefers the canonical TRADESMEN_SECURITY_CENTER_* name, then the
 * TSC_* alias, then any documented SECURITY_CENTER_* / APP_* alias. Values are
 * read from getenv(), $_ENV, and $_SERVER (in that order) so the resolver works
 * across CLI, FPM, and framework bootstraps.
 *
 * The resolver never prints, echoes, or logs a value; secrets pass through
 * untouched and are only returned to the caller.
 */
final class EnvResolver
{
    /**
     * Low-level single-name lookup across getenv(), $_ENV and $_SERVER.
     * Returns the trimmed value, or null when unset or (by default) empty.
     */
    public function raw(string $name, bool $allowEmpty = false): ?string
    {
        $value = null;

        $fromGetenv = getenv($name);
        if (is_string($fromGetenv)) {
            $value = $fromGetenv;
        } elseif (array_key_exists($name, $_ENV)) {
            $value = $_ENV[$name];
        } elseif (array_key_exists($name, $_SERVER)) {
            $value = $_SERVER[$name];
        }

        if (!is_string($value)) {
            return null;
        }

        $value = trim($value);
        if ($value === '' && !$allowEmpty) {
            return null;
        }

        return $value;
    }

    /**
     * First non-empty value among an explicit, ordered list of raw env names.
     *
     * @param list<string> $names
     */
    public function firstNonEmpty(array $names, bool $allowEmpty = false): ?string
    {
        foreach ($names as $name) {
            $value = $this->raw($name, $allowEmpty);
            if ($value !== null) {
                return $value;
            }
        }

        return null;
    }

    /**
     * Resolve a canonical name through its alias chain, returning the value and
     * the env name it came from.
     *
     * @return array{0: ?string, 1: ?string} [value, sourceName]
     */
    public function resolveWithSource(string $canonical, bool $allowEmpty = false): array
    {
        foreach (ConnectorEnvNames::candidates($canonical) as $name) {
            $value = $this->raw($name, $allowEmpty);
            if ($value !== null) {
                return [$value, $name];
            }
        }

        return [null, null];
    }

    /**
     * String value for a canonical name (alias-aware), or the default.
     */
    public function string(string $canonical, ?string $default = null, bool $allowEmpty = false): ?string
    {
        [$value] = $this->resolveWithSource($canonical, $allowEmpty);
        return $value ?? $default;
    }

    /**
     * Boolean value. Accepts 1/0, true/false, yes/no, on/off (case-insensitive).
     */
    public function bool(string $canonical, bool $default = false): bool
    {
        [$value] = $this->resolveWithSource($canonical);
        if ($value === null) {
            return $default;
        }

        $normalized = strtolower($value);
        if (in_array($normalized, ['1', 'true', 'yes', 'on'], true)) {
            return true;
        }
        if (in_array($normalized, ['0', 'false', 'no', 'off'], true)) {
            return false;
        }

        return $default;
    }

    /**
     * Integer value. Honours minute-based aliases by converting to seconds.
     */
    public function int(string $canonical, int $default = 0): int
    {
        [$value, $source] = $this->resolveWithSource($canonical);
        if ($value === null || !preg_match('/^-?\d+$/', $value)) {
            return $default;
        }

        $result = (int) $value;

        $multiplier = ConnectorEnvNames::minuteAliases()[$source] ?? null;
        if ($multiplier !== null) {
            $result *= $multiplier;
        }

        return $result;
    }

    /**
     * Comma/space separated list value, trimmed and de-duplicated, empties dropped.
     *
     * @return list<string>
     */
    public function csvList(string $canonical): array
    {
        [$value] = $this->resolveWithSource($canonical);
        if ($value === null) {
            return [];
        }

        return self::splitList($value);
    }

    /**
     * Split a raw comma/space/newline separated string into a clean list.
     *
     * @return list<string>
     */
    public static function splitList(string $value): array
    {
        $parts = preg_split('/[\s,]+/', $value) ?: [];
        $out = [];
        foreach ($parts as $part) {
            $part = trim($part);
            if ($part !== '' && !in_array($part, $out, true)) {
                $out[] = $part;
            }
        }

        return $out;
    }
}
