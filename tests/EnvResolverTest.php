<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Config\ConnectorEnvNames;
use TradesMen\SecurityCenterConnector\Config\EnvResolver;

final class EnvResolverTest extends TestCase
{
    public function testCanonicalWinsOverTscAndSecurityCenter(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv('SECURITY_CENTER_APP_ID', 'legacy-app');
        $this->setEnv('TSC_APP_ID', 'tsc-app');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'canonical-app');

        $env = new EnvResolver();
        $this->assertSame('canonical-app', $env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'canonical name wins');

        $this->clearConnectorEnv();
    }

    public function testTscAliasStillWorks(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv('TSC_APP_ID', 'tsc-app');

        $env = new EnvResolver();
        $this->assertSame('tsc-app', $env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'TSC_* alias resolves');

        $this->clearConnectorEnv();
    }

    public function testSecurityCenterLegacyFallbackOnlyWhereMapped(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv('SECURITY_CENTER_APP_ID', 'legacy-app');

        $env = new EnvResolver();
        $this->assertSame('legacy-app', $env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'documented SECURITY_CENTER_* fallback resolves');

        $this->clearConnectorEnv();
    }

    public function testEmptyStringIsTreatedAsUnset(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, '   ');
        $this->setEnv('TSC_APP_ID', 'tsc-app');

        $env = new EnvResolver();
        $this->assertSame('tsc-app', $env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'empty canonical falls through to alias');

        $this->clearConnectorEnv();
    }

    public function testEmptyStringReturnedWhenExplicitlyAllowed(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_INSTANCE, '');

        $env = new EnvResolver();
        $this->assertSame('', $env->raw(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_INSTANCE, true), 'empty returned when allowEmpty');

        $this->clearConnectorEnv();
    }

    public function testBoolParsing(): void
    {
        $this->clearConnectorEnv();
        $env = new EnvResolver();

        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'true');
        $this->assertTrue($env->bool(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, false), 'true parses');

        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'off');
        $this->assertFalse($env->bool(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, true), 'off parses');

        $this->clearConnectorEnv();
        $this->assertTrue($env->bool(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, true), 'default used when unset');
    }

    public function testIntParsingAndMinutesConversion(): void
    {
        $this->clearConnectorEnv();
        $env = new EnvResolver();

        $this->assertSame(300, $env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, 300), 'default int used when unset');

        // Legacy minutes alias must convert to seconds.
        $this->setEnv('SECURITY_CENTER_NONCE_RETENTION_MINUTES', '5');
        $this->assertSame(300, $env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, 0), '5 minutes becomes 300 seconds');

        // A seconds-based alias must NOT be multiplied.
        $this->setEnv('TSC_NONCE_TTL_SECONDS', '120');
        $this->assertSame(120, $env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, 0), 'seconds alias not converted');

        $this->clearConnectorEnv();
    }

    public function testCsvListParsing(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SCOPES, 'health:read, status:read  version:read,health:read');

        $env = new EnvResolver();
        $this->assertSame(['health:read', 'status:read', 'version:read'], $env->csvList(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SCOPES), 'csv splits, trims and dedupes');

        $this->clearConnectorEnv();
    }

    public function testFirstNonEmpty(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv('APP_URL', 'https://app.example.com');

        $env = new EnvResolver();
        $this->assertSame('https://app.example.com', $env->firstNonEmpty(['MISSING_ONE', 'APP_URL']), 'firstNonEmpty picks first set value');
        $this->assertNull($env->firstNonEmpty(['MISSING_ONE', 'MISSING_TWO']), 'firstNonEmpty returns null when none set');

        $this->clearConnectorEnv();
    }
}
