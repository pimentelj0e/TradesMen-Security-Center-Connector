<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Tokens\ConnectorTokenFactory;
use TradesMen\SecurityCenterConnector\Tokens\ConnectorTokenParser;

final class ConnectorTokenPrefixTest extends TestCase
{
    private function payload(): array
    {
        return [
            'app_id' => 'tradesmen-tools',
            'app_name' => 'TradesMen Tools',
            'slug' => 'tradesmen-tools',
            'base_url' => 'https://tools.example.com',
            'environment' => 'production',
            'instance' => 'node-1',
            'connector_mode' => 'env',
            'key_id' => 'tsc_live_key',
            'secret' => 'env_mode_shared_secret_0123456789_abcdef',
            'scopes' => ['health:read', 'status:read'],
            'allowed_ips' => ['203.0.113.10'],
            'connector_version' => '1.0.0',
            'issued_at' => 1700000000,
            'expires_at' => 1700086400,
        ];
    }

    public function testFactoryEmitsCanonicalWrapperByDefault(): void
    {
        $token = ConnectorTokenFactory::issue($this->payload());
        $this->assertTrue(
            str_starts_with($token, 'TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN=tsc1_'),
            'default wrapper is the canonical TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN',
        );
    }

    public function testFactoryEmitsLegacyWrapperOnRequest(): void
    {
        $token = ConnectorTokenFactory::issue($this->payload(), true, true);
        $this->assertTrue(
            str_starts_with($token, 'TSC_CONNECTOR_TOKEN=tsc1_'),
            'legacy wrapper emitted when explicitly requested',
        );
    }

    public function testFactoryCanEmitBareToken(): void
    {
        $token = ConnectorTokenFactory::issue($this->payload(), false);
        $this->assertTrue(str_starts_with($token, 'tsc1_'), 'bare token keeps tsc1_ body prefix');
        $this->assertFalse(str_contains($token, '='), 'bare token has no env wrapper');
    }

    public function testParserAcceptsCanonicalWrapper(): void
    {
        $token = ConnectorTokenFactory::issue($this->payload());
        $parsed = ConnectorTokenParser::parse($token, 1700000001);
        $this->assertSame('tradesmen-tools', $parsed['app_id'], 'canonical wrapper parses');
        $this->assertSame('env', $parsed['connector_mode'], 'connector_mode round trips');
        $this->assertSame('node-1', $parsed['instance'], 'instance round trips');
    }

    public function testParserAcceptsLegacyWrapper(): void
    {
        $token = ConnectorTokenFactory::issue($this->payload(), true, true);
        $parsed = ConnectorTokenParser::parse($token, 1700000001);
        $this->assertSame('tradesmen-tools', $parsed['app_id'], 'legacy wrapper parses');
    }

    public function testParserAcceptsBareToken(): void
    {
        $token = ConnectorTokenFactory::issue($this->payload(), false);
        $parsed = ConnectorTokenParser::parse($token, 1700000001);
        $this->assertSame('tradesmen-tools', $parsed['app_id'], 'bare token parses');
    }

    public function testParserRejectsOversizedToken(): void
    {
        $oversized = 'tsc1_' . str_repeat('A', ConnectorTokenParser::MAX_LENGTH + 10);
        $this->assertThrows(
            'invalid_token',
            static fn () => ConnectorTokenParser::parse($oversized),
            'oversized token rejected',
        );
    }

    public function testParserRejectsInvalidBase64(): void
    {
        $this->assertThrows(
            'invalid_token_encoding',
            static fn () => ConnectorTokenParser::parse('tsc1_!!!!****'),
            'invalid base64 rejected',
        );
    }

    public function testParserRejectsInvalidJson(): void
    {
        // Valid base64url of a non-JSON byte string.
        $encoded = rtrim(strtr(base64_encode('not json at all'), '+/', '-_'), '=');
        $this->assertThrows(
            'invalid_token_payload',
            static fn () => ConnectorTokenParser::parse('tsc1_' . $encoded),
            'invalid JSON rejected',
        );
    }

    public function testParserRejectsMissingSecret(): void
    {
        $payload = $this->payload();
        unset($payload['secret']);
        $token = ConnectorTokenFactory::issue($payload);
        $this->assertThrows(
            'missing_secret',
            static fn () => ConnectorTokenParser::parse($token, 1700000001),
            'missing secret rejected',
        );
    }

    public function testParserRejectsInvalidBaseUrl(): void
    {
        $payload = $this->payload();
        $payload['base_url'] = 'not-a-url';
        $token = ConnectorTokenFactory::issue($payload);
        $this->assertThrows(
            'invalid_base_url',
            static fn () => ConnectorTokenParser::parse($token, 1700000001),
            'invalid base url rejected',
        );
    }

    public function testSecretNeverAppearsInExceptionMessage(): void
    {
        $payload = $this->payload();
        $payload['base_url'] = 'not-a-url';
        $token = ConnectorTokenFactory::issue($payload);
        try {
            ConnectorTokenParser::parse($token, 1700000001);
        } catch (\InvalidArgumentException $e) {
            $this->assertFalse(str_contains($e->getMessage(), $payload['secret']), 'secret must not be in exception message');
            return;
        }
        $this->assertTrue(false, 'expected exception');
    }
}
