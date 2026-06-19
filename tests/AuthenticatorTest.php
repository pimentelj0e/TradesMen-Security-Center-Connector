<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Auth\ConnectorAuthenticator;
use TradesMen\SecurityCenterConnector\Auth\Credential;
use TradesMen\SecurityCenterConnector\Contracts\ClockInterface;
use TradesMen\SecurityCenterConnector\Contracts\ConnectorConfigInterface;
use TradesMen\SecurityCenterConnector\Protocol\HmacSigner;
use TradesMen\SecurityCenterConnector\Support\ArrayAccessLog;
use TradesMen\SecurityCenterConnector\Support\InMemoryCredentialStore;
use TradesMen\SecurityCenterConnector\Support\InMemoryNonceStore;

final class AuthenticatorTest extends TestCase
{
    public function testValidRequestAuthenticates(): void
    {
        $config = $this->config('tradesmen-tools', true, 300);
        $credentials = new InMemoryCredentialStore([
            new Credential('connector-1', 'tradesmen-tools', 'key-1', 'secret-1', 'active', ['health:read'], null),
        ]);
        $nonces = new InMemoryNonceStore();
        $logs = new ArrayAccessLog();
        $auth = new ConnectorAuthenticator($config, $credentials, $nonces, $logs, $this->clock(1700000000));

        $headers = HmacSigner::headers('tradesmen-tools', 'key-1', 'secret-1', 'GET', '/api/security-center/v1/health', '', 1700000000, 'nonce-1');
        $result = $auth->authenticate('GET', '/api/security-center/v1/health', $headers, '', '203.0.113.10', 'test-agent');

        $this->assertTrue($result->ok, 'valid request accepted');
        $this->assertSame('ok', $result->reason, 'valid request reason');
        $this->assertSame('key-1', $result->keyId, 'key id carried through');
        $this->assertSame(1, count($logs->rows), 'accepted request logged');
    }

    public function testReplayIsRejected(): void
    {
        $config = $this->config('tradesmen-tools', true, 300);
        $credentials = new InMemoryCredentialStore([
            new Credential('connector-1', 'tradesmen-tools', 'key-1', 'secret-1', 'active', ['health:read'], null),
        ]);
        $nonces = new InMemoryNonceStore();
        $logs = new ArrayAccessLog();
        $auth = new ConnectorAuthenticator($config, $credentials, $nonces, $logs, $this->clock(1700000000));

        $headers = HmacSigner::headers('tradesmen-tools', 'key-1', 'secret-1', 'GET', '/api/security-center/v1/health', '', 1700000000, 'nonce-1');

        $this->assertTrue($auth->authenticate('GET', '/api/security-center/v1/health', $headers, '', null, null)->ok, 'first request accepted');
        $this->assertFalse($auth->authenticate('GET', '/api/security-center/v1/health', $headers, '', null, null)->ok, 'second request rejected');
    }

    public function testMissingHeaderIsRejected(): void
    {
        $auth = new ConnectorAuthenticator(
            $this->config('tradesmen-tools', true, 300),
            new InMemoryCredentialStore([]),
            new InMemoryNonceStore(),
            new ArrayAccessLog(),
            $this->clock(1700000000),
        );

        $result = $auth->authenticate('GET', '/api/security-center/v1/health', [], '', null, null);
        $this->assertFalse($result->ok, 'missing headers rejected');
        $this->assertSame('missing_header', $result->reason, 'missing header reason');
        $this->assertSame(400, $result->status, 'missing header status');
    }

    private function config(string $appId, bool $enabled, int $ttl): ConnectorConfigInterface
    {
        return new class($appId, $enabled, $ttl) implements ConnectorConfigInterface {
            public function __construct(private string $appId, private bool $enabled, private int $ttl) {}
            public function appId(): string { return $this->appId; }
            public function appName(): string { return 'TradesMen Tools'; }
            public function environment(): string { return 'testing'; }
            public function connectorVersion(): string { return '1.0.0'; }
            public function enabled(): bool { return $this->enabled; }
            public function signatureTtlSeconds(): int { return $this->ttl; }
            public function nonceTtlSeconds(): int { return $this->ttl; }
            public function baseUrl(): string { return 'https://tools.example.com'; }
            public function securityCenterUrl(): string { return 'https://security.example.com'; }
        };
    }

    private function clock(int $now): ClockInterface
    {
        return new class($now) implements ClockInterface {
            public function __construct(private int $now) {}
            public function now(): int { return $this->now; }
        };
    }
}
