<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Config\ConnectorEnvNames;
use TradesMen\SecurityCenterConnector\Config\ConnectorMode;
use TradesMen\SecurityCenterConnector\Config\EnvConnectorConfig;
use TradesMen\SecurityCenterConnector\Contracts\ConnectorConfigInterface;
use TradesMen\SecurityCenterConnector\Contracts\ExtendedConnectorConfigInterface;

final class EnvConnectorConfigTest extends TestCase
{
    public function testImplementsBaseInterface(): void
    {
        $config = new EnvConnectorConfig();
        $this->assertTrue($config instanceof ConnectorConfigInterface, 'is a ConnectorConfigInterface');
        $this->assertTrue($config instanceof ExtendedConnectorConfigInterface, 'is an ExtendedConnectorConfigInterface');
    }

    public function testReadsCanonicalValues(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'true');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'tradesmen-tools');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_ENVIRONMENT, 'staging');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS, '120');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, '90');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_URL, 'https://security.example.com');
        $this->setEnv('APP_URL', 'https://tools.example.com');

        $config = new EnvConnectorConfig();
        $this->assertTrue($config->enabled(), 'enabled');
        $this->assertSame('tradesmen-tools', $config->appId(), 'app id');
        $this->assertSame('staging', $config->environment(), 'environment');
        $this->assertSame(120, $config->signatureTtlSeconds(), 'clock skew maps to signature ttl');
        $this->assertSame(90, $config->nonceTtlSeconds(), 'nonce ttl');
        $this->assertSame('https://security.example.com', $config->securityCenterUrl(), 'security center url');
        $this->assertSame('https://tools.example.com', $config->baseUrl(), 'base url from APP_URL');

        $this->clearConnectorEnv();
    }

    public function testDefaults(): void
    {
        $this->clearConnectorEnv();
        $config = new EnvConnectorConfig();

        $this->assertFalse($config->enabled(), 'disabled by default');
        $this->assertSame('production', $config->environment(), 'environment defaults to production');
        $this->assertSame(300, $config->signatureTtlSeconds(), 'clock skew defaults to 300');
        $this->assertSame(300, $config->nonceTtlSeconds(), 'nonce ttl defaults to 300');
        $this->assertSame(ConnectorMode::ENV, $config->mode(), 'mode defaults to env');
        $this->assertSame(60, $config->heartbeatIntervalSeconds(), 'heartbeat interval default');
        $this->assertSame(10, $config->heartbeatTimeoutSeconds(), 'heartbeat timeout default');
        $this->assertFalse($config->requireIpAllowlist(), 'ip allowlist not required by default');
        $this->assertSame([], $config->allowedIps(), 'no allowed ips by default');

        $this->clearConnectorEnv();
    }

    public function testModeOverrideToManagedDb(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE, 'managed_db');

        $config = new EnvConnectorConfig();
        $this->assertSame(ConnectorMode::MANAGED_DB, $config->mode(), 'mode override to managed_db');

        $this->clearConnectorEnv();
    }

    public function testInvalidModeFallsBackToEnvDefault(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE, 'bogus');

        $config = new EnvConnectorConfig();
        $this->assertSame(ConnectorMode::ENV, $config->mode(), 'invalid mode falls back to env safe default');

        $this->clearConnectorEnv();
    }

    public function testScopesAndAllowedIps(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SCOPES, 'health:read,status:read');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_ALLOWED_IPS, '203.0.113.10, 198.51.100.0/24');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST, 'true');

        $config = new EnvConnectorConfig();
        $this->assertSame(['health:read', 'status:read'], $config->scopes(), 'scopes parsed');
        $this->assertSame(['203.0.113.10', '198.51.100.0/24'], $config->allowedIps(), 'allowed ips parsed');
        $this->assertTrue($config->requireIpAllowlist(), 'require ip allowlist');

        $this->clearConnectorEnv();
    }

    public function testInstanceReadsCanonicalOnly(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv('APP_INSTANCE', 'node-7');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_INSTANCE, 'vps1');

        $config = new EnvConnectorConfig();
        $this->assertSame('vps1', $config->instance(), 'instance resolves only from the canonical name');

        $this->clearConnectorEnv();
    }

    public function testLegacyInstanceAliasIsIgnored(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv('APP_INSTANCE', 'node-7');

        $config = new EnvConnectorConfig();
        $this->assertSame('', $config->instance(), 'legacy APP_INSTANCE alias is not read');

        $this->clearConnectorEnv();
    }
}
