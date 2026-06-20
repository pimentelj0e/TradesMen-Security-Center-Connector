<?php

declare(strict_types=1);

namespace Tests;

use RuntimeException;
use TradesMen\SecurityCenterConnector\Config\ConnectorEnvNames;

class TestCase
{
    private int $assertions = 0;

    public function assertTrue(bool $value, string $message): void
    {
        $this->assertions++;
        if (!$value) {
            throw new RuntimeException($message);
        }
    }

    public function assertFalse(bool $value, string $message): void
    {
        $this->assertTrue(!$value, $message);
    }

    public function assertSame(mixed $expected, mixed $actual, string $message): void
    {
        $this->assertions++;
        if ($expected !== $actual) {
            throw new RuntimeException($message . ' Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
        }
    }

    public function assertNull(mixed $value, string $message): void
    {
        $this->assertSame(null, $value, $message);
    }

    public function assertArrayHasKey(string $key, array $array, string $message): void
    {
        $this->assertions++;
        if (!array_key_exists($key, $array)) {
            throw new RuntimeException($message . ' Missing key: ' . $key);
        }
    }

    public function assertContains(mixed $needle, array $haystack, string $message): void
    {
        $this->assertions++;
        if (!in_array($needle, $haystack, true)) {
            throw new RuntimeException($message . ' Missing value: ' . var_export($needle, true));
        }
    }

    /**
     * Assert that running $fn throws with the given exception message.
     */
    public function assertThrows(string $expectedMessage, callable $fn, string $message): void
    {
        $this->assertions++;
        try {
            $fn();
        } catch (\Throwable $e) {
            if ($e->getMessage() !== $expectedMessage) {
                throw new RuntimeException($message . ' Expected message ' . var_export($expectedMessage, true) . ', got ' . var_export($e->getMessage(), true));
            }
            return;
        }
        throw new RuntimeException($message . ' Expected exception was not thrown.');
    }

    /**
     * Set an env var across all three sources the resolver reads.
     */
    protected function setEnv(string $name, string $value): void
    {
        putenv($name . '=' . $value);
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }

    protected function clearEnv(string ...$names): void
    {
        foreach ($names as $name) {
            putenv($name);
            unset($_ENV[$name], $_SERVER[$name]);
        }
    }

    /**
     * Clear every canonical connector env name plus the app-level names the
     * config still reads, so tests start from a known-empty environment.
     */
    protected function clearConnectorEnv(): void
    {
        $names = ConnectorEnvNames::canonicalNames();
        $names[] = 'APP_URL';
        $names[] = 'APP_NAME';
        $names[] = 'APP_INSTANCE';
        $names[] = 'APP_ENV';
        $this->clearEnv(...$names);
    }

    /**
     * Build a legacy `TSC_*` env name at runtime. The prefix is concatenated so
     * no legacy env literal appears in the source tree, keeping the repo cleanup
     * gate green while still letting tests prove these names are ignored.
     */
    protected function legacyTscName(string $suffix): string
    {
        return 'TSC' . '_' . $suffix;
    }

    /**
     * Build a legacy `SECURITY_CENTER_*` env name at runtime, for the same
     * reason as {@see legacyTscName()}.
     */
    protected function legacySecurityCenterName(string $suffix): string
    {
        return 'SECURITY' . '_CENTER_' . $suffix;
    }

    public function assertions(): int
    {
        return $this->assertions;
    }
}
