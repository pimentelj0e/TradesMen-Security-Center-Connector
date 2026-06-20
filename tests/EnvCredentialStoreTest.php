<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Config\ConnectorEnvNames;
use TradesMen\SecurityCenterConnector\Config\EnvConnectorConfig;
use TradesMen\SecurityCenterConnector\Support\EnvCredentialStore;

final class EnvCredentialStoreTest extends TestCase
{
    private const KEY_ID = 'tsc_live_key_id';
    private const SECRET = 'env_mode_shared_secret_0123456789_abcdef';

    private function enableEnvMode(): void
    {
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'true');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE, 'env');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'tradesmen-tools');
    }

    public function testReturnsCredentialWhenConfigured(): void
    {
        $this->clearConnectorEnv();
        $this->enableEnvMode();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, self::KEY_ID);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, self::SECRET);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SCOPES, 'health:read,status:read');

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $credential = $store->findActive('tradesmen-tools', self::KEY_ID);

        $this->assertTrue($credential !== null, 'credential returned');
        $this->assertSame(self::KEY_ID, $credential->keyId, 'key id matches');
        $this->assertSame(self::SECRET, $credential->secret, 'secret matches');
        $this->assertSame(['health:read', 'status:read'], $credential->scopes, 'scopes from env');
        $this->assertFalse($store->hasError(), 'no error on success');

        $this->clearConnectorEnv();
    }

    public function testMissingCredentialsReturnsNullWithSafeError(): void
    {
        $this->clearConnectorEnv();
        $this->enableEnvMode();
        // No key id / secret set.

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $this->assertNull($store->findActive('tradesmen-tools', self::KEY_ID), 'no credential when missing');
        $this->assertSame('connector_env_credentials_missing', $store->error(), 'operator-safe error code');

        $this->clearConnectorEnv();
    }

    public function testKeyIdAndSecretCannotBeEqual(): void
    {
        $this->clearConnectorEnv();
        $this->enableEnvMode();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, self::SECRET);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, self::SECRET);

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $this->assertNull($store->findActive('tradesmen-tools', self::SECRET), 'equal key/secret rejected');
        $this->assertSame('connector_env_key_secret_equal', $store->error(), 'equal key/secret error');

        $this->clearConnectorEnv();
    }

    public function testSecretMustBeLongEnough(): void
    {
        $this->clearConnectorEnv();
        $this->enableEnvMode();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, self::KEY_ID);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, 'too-short');

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $this->assertNull($store->findActive('tradesmen-tools', self::KEY_ID), 'short secret rejected');
        $this->assertSame('connector_env_secret_too_short', $store->error(), 'short secret error');

        $this->clearConnectorEnv();
    }

    public function testErrorMessagesNeverContainSecret(): void
    {
        $this->clearConnectorEnv();
        $this->enableEnvMode();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, self::KEY_ID);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, 'too-short');

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $store->findActive('tradesmen-tools', self::KEY_ID);
        $this->assertFalse(str_contains((string) $store->error(), 'too-short'), 'error must not leak the secret');

        $this->clearConnectorEnv();
    }

    public function testTscAliasesAccepted(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'true');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'tradesmen-tools');
        $this->setEnv('TSC_KEY_ID', self::KEY_ID);
        $this->setEnv('TSC_SHARED_SECRET', self::SECRET);

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $credential = $store->findActive('tradesmen-tools', self::KEY_ID);
        $this->assertTrue($credential !== null, 'credential resolved from TSC_* aliases');

        $this->clearConnectorEnv();
    }

    public function testManagedDbModeReturnsNoCredential(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'true');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE, 'managed_db');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'tradesmen-network');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, self::KEY_ID);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, self::SECRET);

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $this->assertNull($store->findActive('tradesmen-network', self::KEY_ID), 'env store inactive in managed_db mode');

        $this->clearConnectorEnv();
    }

    public function testMismatchedKeyReturnsNull(): void
    {
        $this->clearConnectorEnv();
        $this->enableEnvMode();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, self::KEY_ID);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, self::SECRET);

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $this->assertNull($store->findActive('tradesmen-tools', 'wrong-key'), 'mismatched key id returns null');
        $this->assertNull($store->findActive('wrong-app', self::KEY_ID), 'mismatched app id returns null');

        $this->clearConnectorEnv();
    }

    public function testDisabledConnectorReturnsNull(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'false');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'tradesmen-tools');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, self::KEY_ID);
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, self::SECRET);

        $store = new EnvCredentialStore(new EnvConnectorConfig());
        $this->assertNull($store->findActive('tradesmen-tools', self::KEY_ID), 'disabled connector returns null');

        $this->clearConnectorEnv();
    }
}
