<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Config\ConnectorEnvNames;
use TradesMen\SecurityCenterConnector\Config\EnvResolver;

final class EnvResolverTest extends TestCase
{
    public function testReadsCanonicalName(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'canonical-app');

        $env = new EnvResolver();
        $this->assertSame('canonical-app', $env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'canonical name resolves');

        $this->clearConnectorEnv();
    }

    public function testTscAliasIsIgnored(): void
    {
        $this->clearConnectorEnv();
        $legacy = $this->legacyTscName('APP_ID');
        $this->setEnv($legacy, 'tsc-app');

        $env = new EnvResolver();
        $this->assertNull($env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'TSC_* alias is not read');

        $this->clearEnv($legacy);
        $this->clearConnectorEnv();
    }

    public function testSecurityCenterAliasIsIgnored(): void
    {
        $this->clearConnectorEnv();
        $legacy = $this->legacySecurityCenterName('APP_ID');
        $this->setEnv($legacy, 'legacy-app');

        $env = new EnvResolver();
        $this->assertNull($env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'SECURITY_CENTER_* alias is not read');

        $this->clearEnv($legacy);
        $this->clearConnectorEnv();
    }

    public function testCanonicalWinsAndLegacyNamesDoNotLeak(): void
    {
        $this->clearConnectorEnv();
        $tsc = $this->legacyTscName('APP_ID');
        $sc = $this->legacySecurityCenterName('APP_ID');
        $this->setEnv($sc, 'legacy-app');
        $this->setEnv($tsc, 'tsc-app');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'canonical-app');

        $env = new EnvResolver();
        $this->assertSame('canonical-app', $env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'only the canonical value is returned');

        $this->clearEnv($tsc, $sc);
        $this->clearConnectorEnv();
    }

    public function testEmptyCanonicalDoesNotFallBackToLegacy(): void
    {
        $this->clearConnectorEnv();
        $legacy = $this->legacyTscName('APP_ID');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, '   ');
        $this->setEnv($legacy, 'tsc-app');

        $env = new EnvResolver();
        $this->assertNull($env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'empty canonical does not fall through to any alias');

        $this->clearEnv($legacy);
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

    public function testRequiredReturnsCanonicalValue(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'canonical-app');

        $env = new EnvResolver();
        $this->assertSame('canonical-app', $env->required(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID), 'required resolves canonical');

        $this->clearConnectorEnv();
    }

    public function testRequiredThrowsWhenUnset(): void
    {
        $this->clearConnectorEnv();
        $env = new EnvResolver();
        $this->assertThrows(
            'required_env_missing',
            static fn () => $env->required(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID),
            'required throws an operator-safe error when unset',
        );

        $this->clearConnectorEnv();
    }

    public function testOptionalUsesDefault(): void
    {
        $this->clearConnectorEnv();
        $env = new EnvResolver();
        $this->assertSame('fallback', $env->optional(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'fallback'), 'optional returns default when unset');

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

    public function testIntParsing(): void
    {
        $this->clearConnectorEnv();
        $env = new EnvResolver();

        $this->assertSame(300, $env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, 300), 'default int used when unset');

        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, '120');
        $this->assertSame(120, $env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, 0), 'canonical seconds value read as-is');

        $this->clearConnectorEnv();
    }

    public function testIntIgnoresLegacyMinutesAlias(): void
    {
        $this->clearConnectorEnv();
        $env = new EnvResolver();

        // The legacy minutes alias must not be read or converted.
        $legacy = $this->legacySecurityCenterName('NONCE_RETENTION_MINUTES');
        $this->setEnv($legacy, '5');
        $this->assertSame(0, $env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, 0), 'legacy minutes alias is ignored');

        $this->clearEnv($legacy);
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
