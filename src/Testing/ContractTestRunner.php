<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Testing;
use TradesMen\SecurityCenterConnector\Protocol\Headers;
use TradesMen\SecurityCenterConnector\Protocol\HmacSigner;
final class ContractTestRunner
{
    public const REQUIRED_ENDPOINTS = [
        '/manifest',
        '/health',
        '/status',
        '/server',
        '/queues',
        '/workers',
        '/deployments',
        '/security-events',
        '/config-check',
        '/version',
    ];

    public function runStaticChecks(array $registeredEndpoints): array
    {
        $missing = [];
        foreach (self::REQUIRED_ENDPOINTS as $endpoint) {
            if (!in_array($endpoint, $registeredEndpoints, true)) {
                $missing[] = $endpoint;
            }
        }

        return [
            'hmac_vector' => $this->hmacVectorPasses(),
            'missing_endpoints' => $missing,
        ];
    }

    private function hmacVectorPasses(): bool
    {
        $canonical = HmacSigner::canonicalString(
            'GET',
            '/api/security-center/v1/health?full=1',
            '1700000000',
            'test-nonce-001',
            Headers::EMPTY_BODY_SHA256,
        );

        return HmacSigner::signCanonical($canonical, 'test_shared_secret_1234567890') === 'kcgXvdcFBkWw7hB45hF87ZJ9dnXVaXcpYbOHCBmm30s=';
    }
}
