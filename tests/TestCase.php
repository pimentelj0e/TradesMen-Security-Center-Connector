<?php

declare(strict_types=1);

namespace Tests;

use RuntimeException;

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

    public function assertArrayHasKey(string $key, array $array, string $message): void
    {
        $this->assertions++;
        if (!array_key_exists($key, $array)) {
            throw new RuntimeException($message . ' Missing key: ' . $key);
        }
    }

    public function assertions(): int
    {
        return $this->assertions;
    }
}
