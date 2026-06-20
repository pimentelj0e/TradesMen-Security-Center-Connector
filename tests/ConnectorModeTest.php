<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Config\ConnectorMode;

final class ConnectorModeTest extends TestCase
{
    public function testValidModes(): void
    {
        $this->assertTrue(ConnectorMode::isValid('env'), 'env is valid');
        $this->assertTrue(ConnectorMode::isValid('managed_db'), 'managed_db is valid');
        $this->assertTrue(ConnectorMode::isValid(' MANAGED_DB '), 'mode normalizes case and whitespace');
    }

    public function testInvalidMode(): void
    {
        $this->assertFalse(ConnectorMode::isValid('bogus'), 'bogus is invalid');
    }

    public function testDefaultIsEnv(): void
    {
        $this->assertSame('env', ConnectorMode::DEFAULT, 'default mode is env');
    }

    public function testFromStringThrowsOnInvalid(): void
    {
        $this->assertThrows(
            'invalid_connector_mode',
            static fn () => ConnectorMode::fromString('nope'),
            'invalid mode throws InvalidArgumentException',
        );
    }

    public function testFromStringAcceptsValid(): void
    {
        $this->assertSame('managed_db', ConnectorMode::fromString('managed_db'), 'valid mode returned');
    }

    public function testFromStringOrDefaultReturnsSafeDefault(): void
    {
        $this->assertSame('env', ConnectorMode::fromStringOrDefault('nope'), 'invalid falls back to default');
        $this->assertSame('managed_db', ConnectorMode::fromStringOrDefault('managed_db'), 'valid passes through');
    }
}
