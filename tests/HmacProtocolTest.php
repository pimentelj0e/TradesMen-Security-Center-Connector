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

    public function testProtocolHeaderNamesAreStable(): void
    {
        // The env naming changed; the signed HTTP protocol must NOT.
        $this->assertSame('X-TSC-App-Id', Headers::APP_ID, 'app id header name stable');
        $this->assertSame('X-TSC-Key-Id', Headers::KEY_ID, 'key id header name stable');
        $this->assertSame('X-TSC-Timestamp', Headers::TIMESTAMP, 'timestamp header name stable');
        $this->assertSame('X-TSC-Nonce', Headers::NONCE, 'nonce header name stable');
        $this->assertSame('X-TSC-Body-SHA256', Headers::BODY_SHA256, 'body hash header name stable');
        $this->assertSame('X-TSC-Signature', Headers::SIGNATURE, 'signature header name stable');
    }

    public function testPostBodyVectorRemainsStable(): void
    {
        // A second fixed vector, this time over a non-empty POST body, locks the
        // canonical-string + body-hash + base64-HMAC formats in place.
        $body = '{"status":"healthy"}';
        $bodyHash = HmacSigner::bodyHash($body);
        $this->assertSame(
            'b808daea0f225957b3cddad9d5e33cb8dd4da1dbfc1d764e291f8d2e9fa4f857',
            $bodyHash,
            'sha256 body hash of the fixed payload',
        );

        $canonical = HmacSigner::canonicalString('POST', '/api/ingest/heartbeat', '1700000000', 'nonce-post-001', $bodyHash);
        $this->assertSame(
            "POST\n/api/ingest/heartbeat\n1700000000\nnonce-post-001\n" . $bodyHash,
            $canonical,
            'canonical string five-line format with body',
        );

        $signature = HmacSigner::signCanonical($canonical, 'test_shared_secret_1234567890');
        $this->assertSame(
            'MVhjeK4NumQcJqut89d8cOzcXUct1Mj6SybgD3ls35Q=',
            $signature,
            'base64 HMAC vector remains unchanged',
        );

        // Round-trips through the verifier: proves the base64 HMAC format is unchanged.
        $this->assertTrue(
            HmacVerifier::signatureMatches($canonical, 'test_shared_secret_1234567890', $signature),
            'signed canonical verifies with same secret',
        );
        $this->assertFalse(
            HmacVerifier::signatureMatches($canonical, 'wrong_secret', $signature),
            'signature does not verify under a different secret',
        );
    }
}
