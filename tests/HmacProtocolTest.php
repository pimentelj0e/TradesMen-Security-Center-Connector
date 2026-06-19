<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Protocol\Headers;
use TradesMen\SecurityCenterConnector\Protocol\HmacSigner;
use TradesMen\SecurityCenterConnector\Protocol\HmacVerifier;

final class HmacProtocolTest extends TestCase
{
    public function testOfficialVectorMatches(): void
    {
        $canonical = HmacSigner::canonicalString(
            'GET',
            '/api/security-center/v1/health?full=1',
            '1700000000',
            'test-nonce-001',
            Headers::EMPTY_BODY_SHA256,
        );

        $this->assertSame(
            "GET\n/api/security-center/v1/health?full=1\n1700000000\ntest-nonce-001\n" . Headers::EMPTY_BODY_SHA256,
            $canonical,
            'canonical string must match official five-line format',
        );

        $this->assertSame(
            'kcgXvdcFBkWw7hB45hF87ZJ9dnXVaXcpYbOHCBmm30s=',
            HmacSigner::signCanonical($canonical, 'test_shared_secret_1234567890'),
            'signature must match official vector',
        );
    }

    public function testVerifierRejectsHexSignature(): void
    {
        $canonical = HmacSigner::canonicalString('GET', '/api/security-center/v1/health', '1700000000', 'n', Headers::EMPTY_BODY_SHA256);
        $hex = hash_hmac('sha256', $canonical, 'secret');

        $this->assertFalse(HmacVerifier::signatureMatches($canonical, 'secret', $hex), 'hex HMAC must not verify');
    }

    public function testHeadersAreNormalizedCaseInsensitively(): void
    {
        $headers = HmacVerifier::normalizeHeaders([
            'X-TSC-App-Id' => 'app',
            'x-tsc-key-id' => 'key',
        ]);

        $this->assertSame('app', $headers['x-tsc-app-id'], 'app id header normalized');
        $this->assertSame('key', $headers['x-tsc-key-id'], 'key id header normalized');
    }
}
