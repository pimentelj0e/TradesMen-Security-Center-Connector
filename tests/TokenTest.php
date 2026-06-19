<?php
declare(strict_types=1);
namespace Tests;
use TradesMen\SecurityCenterConnector\Tokens\ConnectorTokenFactory;
use TradesMen\SecurityCenterConnector\Tokens\ConnectorTokenParser;
final class TokenTest extends TestCase
{
    public function testTokenRoundTrip(): void
    {
        $payload = [
            'app_id' => 'tradesmen-tools',
            'app_name' => 'TradesMen Tools',
            'slug' => 'tradesmen-tools',
            'base_url' => 'https://tools.example.com',
            'environment' => 'staging',
            'key_id' => 'tsc_live_key',
            'secret' => 'tsc_secret',
            'scopes' => ['health:read', 'status:read'],
            'allowed_ips' => ['203.0.113.10'],
            'connector_version' => '1.0.0',
            'issued_at' => 1700000000,
            'expires_at' => 1700086400,
        ];

        $token = ConnectorTokenFactory::issue($payload);
        $this->assertTrue(str_starts_with($token, 'TSC_CONNECTOR_TOKEN=tsc1_'), 'env-wrapped token prefix');

        $parsed = ConnectorTokenParser::parse($token, 1700000001);
        $this->assertSame('tradesmen-tools', $parsed['app_id'], 'app id round trips');
        $this->assertSame('tsc_secret', $parsed['secret'], 'secret round trips');
        $this->assertSame(['health:read', 'status:read'], $parsed['scopes'], 'scopes round trip');
    }

    public function testExpiredTokenRejected(): void
    {
        $token = ConnectorTokenFactory::issue([
            'app_id' => 'tradesmen-tools',
            'app_name' => 'TradesMen Tools',
            'base_url' => 'https://tools.example.com',
            'environment' => 'staging',
            'key_id' => 'key',
            'secret' => 'secret',
            'expires_at' => 100,
        ]);

        try {
            ConnectorTokenParser::parse($token, 101);
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('token_expired', $e->getMessage(), 'expired token rejected');
            return;
        }
        $this->assertTrue(false, 'expired token must throw');
    }
}
