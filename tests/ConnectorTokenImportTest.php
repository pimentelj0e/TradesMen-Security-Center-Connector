<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Tokens\ConnectorTokenFactory;
use TradesMen\SecurityCenterConnector\Tokens\ConnectorTokenImporter;

/**
 * Security Center import-side validation contract for connector setup tokens.
 */
final class ConnectorTokenImportTest extends TestCase
{
    private const NOW = 1700000001;

    /** @param array<string, mixed> $overrides */
    private function token(array $overrides = [], bool $wrapEnv = true): string
    {
        $payload = array_merge([
            'app_id' => 'tradesmen-tools',
            'app_name' => 'TradesMen Tools',
            'slug' => 'tradesmen-tools',
            'base_url' => 'https://tools.example.com',
            'environment' => 'production',
            'instance' => 'node-1',
            'connector_mode' => 'managed_db',
            'key_id' => 'tsc_live_key',
            'secret' => 'env_mode_shared_secret_0123456789_abcdef',
            'scopes' => ['health:read', 'status:read'],
            'allowed_ips' => ['203.0.113.10'],
            'connector_version' => '1.0.0',
            'issued_at' => 1700000000,
            'expires_at' => 1700086400,
        ], $overrides);

        foreach ($overrides as $key => $value) {
            if ($value === null) {
                unset($payload[$key]);
            }
        }

        return ConnectorTokenFactory::issue($payload, $wrapEnv);
    }

    public function testValidTokenImports(): void
    {
        $importer = new ConnectorTokenImporter();
        $payload = $importer->import($this->token(), [], self::NOW);

        $this->assertSame('tradesmen-tools', $payload['app_id'], 'app id imported');
        $this->assertSame('tsc_live_key', $payload['key_id'], 'key id imported');
        $this->assertSame(['health:read', 'status:read'], $payload['scopes'], 'scopes imported');
    }

    public function testMalformedTokenRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $this->assertThrows(
            'invalid_token_encoding',
            static fn () => $importer->import('tsc1_!!!not-base64!!!', [], self::NOW),
            'malformed token rejected',
        );
    }

    public function testExpiredTokenRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $token = $this->token(['expires_at' => 100]);
        $this->assertThrows(
            'token_expired',
            static fn () => $importer->import($token, [], 101),
            'expired token rejected',
        );
    }

    public function testDuplicateKeyRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $token = $this->token(['key_id' => 'tsc_live_key']);
        $this->assertThrows(
            'duplicate_key',
            static fn () => $importer->import($token, ['other-key', 'tsc_live_key'], self::NOW),
            'duplicate key id rejected',
        );
    }

    public function testLegacyTokenRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        // A legacy env wrapper around an otherwise valid token body.
        $bare = $this->token([], false);
        $legacy = $this->legacySecurityCenterName('CONNECTOR_TOKEN') . '=' . $bare;
        $this->assertThrows(
            'unrecognized_token_wrapper',
            static fn () => $importer->import($legacy, [], self::NOW),
            'legacy token wrapper rejected',
        );
    }

    public function testLegacyTokenBodyPrefixRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        // Older token bodies that do not carry the tsc1_ prefix are refused.
        $this->assertThrows(
            'unrecognized_token',
            static fn () => $importer->import('tsc0_deadbeef', [], self::NOW),
            'legacy token body prefix rejected',
        );
    }

    public function testMissingAppIdRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $token = $this->token(['app_id' => null]);
        $this->assertThrows(
            'missing_app_id',
            static fn () => $importer->import($token, [], self::NOW),
            'missing app id rejected',
        );
    }

    public function testMissingSecretRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $token = $this->token(['secret' => null]);
        $this->assertThrows(
            'missing_secret',
            static fn () => $importer->import($token, [], self::NOW),
            'missing secret rejected',
        );
    }

    public function testInvalidScopesRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $token = $this->token(['scopes' => ['health:read', 'totally:bogus']]);
        $this->assertThrows(
            'invalid_scopes',
            static fn () => $importer->import($token, [], self::NOW),
            'non-canonical scope rejected',
        );
    }

    public function testEmptyScopesRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $token = $this->token(['scopes' => []]);
        $this->assertThrows(
            'invalid_scopes',
            static fn () => $importer->import($token, [], self::NOW),
            'empty scope set rejected',
        );
    }

    public function testInvalidConnectorModeRejected(): void
    {
        $importer = new ConnectorTokenImporter();
        $token = $this->token(['connector_mode' => 'bogus_mode']);
        $this->assertThrows(
            'invalid_connector_mode',
            static fn () => $importer->import($token, [], self::NOW),
            'invalid connector mode rejected',
        );
    }

    public function testImportNeverLeaksSecretInErrors(): void
    {
        $importer = new ConnectorTokenImporter();
        $secret = 'env_mode_shared_secret_0123456789_abcdef';
        $token = $this->token(['scopes' => ['totally:bogus']]);
        try {
            $importer->import($token, [], self::NOW);
        } catch (\InvalidArgumentException $e) {
            $this->assertFalse(str_contains($e->getMessage(), $secret), 'secret must not appear in import error');
            return;
        }
        $this->assertTrue(false, 'expected import to throw');
    }
}
