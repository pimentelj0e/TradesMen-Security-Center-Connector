<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Testing;

use TradesMen\SecurityCenterConnector\Auth\ConnectorAuthenticator;
use TradesMen\SecurityCenterConnector\Auth\Credential;
use TradesMen\SecurityCenterConnector\Contracts\ClockInterface;
use TradesMen\SecurityCenterConnector\Contracts\ConnectorConfigInterface;
use TradesMen\SecurityCenterConnector\Contracts\TelemetryProviderInterface;
use TradesMen\SecurityCenterConnector\Protocol\Headers;
use TradesMen\SecurityCenterConnector\Protocol\HmacSigner;
use TradesMen\SecurityCenterConnector\Redaction\ResponseRedactor;
use TradesMen\SecurityCenterConnector\Response\ConnectorResponseBuilder;
use TradesMen\SecurityCenterConnector\Scopes\ScopeRegistry;
use TradesMen\SecurityCenterConnector\Support\ArrayAccessLog;
use TradesMen\SecurityCenterConnector\Support\InMemoryCredentialStore;
use TradesMen\SecurityCenterConnector\Support\InMemoryNonceStore;

/**
 * Reusable connector contract harness.
 *
 * Ships with the package so every host app can prove, against the shared core,
 * that it speaks the protocol correctly: it locks the HMAC test vector, checks
 * the ten required endpoints are wired, and exercises the full authentication
 * behaviour (missing/bad signature, stale timestamp, replayed nonce,
 * insufficient scope, disabled/revoked connector) plus response redaction.
 */
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

    private const APP_ID = 'contract-app';
    private const KEY_ID = 'contract-key';
    private const SECRET = 'contract_shared_secret_0123456789_abcdef';
    private const PATH = '/api/security-center/v1/health';
    private const TIMESTAMP = 1700000000;
    private const TTL_SECONDS = 300;

    /**
     * Static checks: HMAC vector stability + required endpoint coverage.
     *
     * @param list<string> $registeredEndpoints
     * @return array{hmac_vector: bool, missing_endpoints: list<string>}
     */
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

    /**
     * Behavioural protocol contract checks. Each entry is true when the shared
     * core enforces that rule correctly.
     *
     * @return array<string, bool>
     */
    public function runProtocolChecks(): array
    {
        return [
            'valid_request' => $this->validRequestAccepted(),
            'missing_signature' => $this->missingSignatureRejected(),
            'bad_signature' => $this->badSignatureRejected(),
            'expired_timestamp' => $this->expiredTimestampRejected(),
            'replayed_nonce' => $this->replayedNonceRejected(),
            'insufficient_scope' => $this->insufficientScopeRejected(),
            'disabled_connector' => $this->disabledConnectorRejected(),
            'revoked_connector' => $this->revokedConnectorRejected(),
            'redaction' => $this->responseRedacted(),
        ];
    }

    /**
     * Full report combining static and behavioural checks.
     *
     * @param list<string> $registeredEndpoints
     * @return array{
     *     hmac_vector: bool,
     *     missing_endpoints: list<string>,
     *     protocol: array<string, bool>,
     *     passed: bool
     * }
     */
    public function run(array $registeredEndpoints): array
    {
        $static = $this->runStaticChecks($registeredEndpoints);
        $protocol = $this->runProtocolChecks();

        $passed = $static['hmac_vector']
            && $static['missing_endpoints'] === []
            && !in_array(false, $protocol, true);

        return [
            'hmac_vector' => $static['hmac_vector'],
            'missing_endpoints' => $static['missing_endpoints'],
            'protocol' => $protocol,
            'passed' => $passed,
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

    private function validRequestAccepted(): bool
    {
        $auth = $this->authenticator(true);
        $result = $auth->authenticate('GET', self::PATH, $this->signedHeaders(), '', null, null);

        return $result->ok && $result->reason === 'ok';
    }

    private function missingSignatureRejected(): bool
    {
        $auth = $this->authenticator(true);
        $headers = $this->signedHeaders();
        unset($headers[Headers::SIGNATURE]);
        $result = $auth->authenticate('GET', self::PATH, $headers, '', null, null);

        return !$result->ok && $result->reason === 'missing_header';
    }

    private function badSignatureRejected(): bool
    {
        $auth = $this->authenticator(true);
        $headers = $this->signedHeaders();
        // Valid base64 of 32 zero bytes: well-formed but never a real signature.
        $headers[Headers::SIGNATURE] = base64_encode(str_repeat("\0", 32));
        $result = $auth->authenticate('GET', self::PATH, $headers, '', null, null);

        return !$result->ok && $result->reason === 'bad_signature';
    }

    private function expiredTimestampRejected(): bool
    {
        $auth = $this->authenticator(true);
        // Correctly signed, but far outside the allowed clock skew.
        $headers = $this->signedHeaders(self::TIMESTAMP - (self::TTL_SECONDS * 100), 'nonce-stale');
        $result = $auth->authenticate('GET', self::PATH, $headers, '', null, null);

        return !$result->ok && $result->reason === 'stale_timestamp';
    }

    private function replayedNonceRejected(): bool
    {
        $auth = $this->authenticator(true);
        $headers = $this->signedHeaders(self::TIMESTAMP, 'nonce-replay');
        $first = $auth->authenticate('GET', self::PATH, $headers, '', null, null);
        $second = $auth->authenticate('GET', self::PATH, $headers, '', null, null);

        return $first->ok && !$second->ok && $second->reason === 'replayed_nonce';
    }

    private function insufficientScopeRejected(): bool
    {
        // Scope enforcement is the registry's contract: a connector granted only
        // health:read must not satisfy a server:read endpoint.
        $scopes = new ScopeRegistry();
        $required = $scopes->requiredScope('/api/security-center/v1/server');

        return $required === 'server:read'
            && $scopes->granted(['health:read'], $required) === false;
    }

    private function disabledConnectorRejected(): bool
    {
        $auth = $this->authenticator(false);
        $result = $auth->authenticate('GET', self::PATH, $this->signedHeaders(), '', null, null);

        return !$result->ok && $result->reason === 'connector_disabled' && $result->status === 503;
    }

    private function revokedConnectorRejected(): bool
    {
        $auth = $this->authenticator(true, 'revoked');
        $result = $auth->authenticate('GET', self::PATH, $this->signedHeaders(), '', null, null);

        return !$result->ok && $result->reason === 'unknown_key';
    }

    private function responseRedacted(): bool
    {
        $provider = new class implements TelemetryProviderInterface {
            public function manifest(): array { return ['app' => 'contract-app']; }
            public function health(): array { return ['status' => 'healthy', 'db_password' => 'super-secret']; }
            public function status(): array { return ['status' => 'healthy']; }
            public function server(): array { return ['php' => '8.1']; }
            public function queues(): array { return ['depth' => 0]; }
            public function workers(): array { return ['online' => 1]; }
            public function deployments(): array { return ['version' => '1.0.0']; }
            public function securityEvents(): array { return ['failed_logins_24h' => 0]; }
            public function configCheck(): array { return ['missing' => []]; }
            public function version(): array { return ['version' => '1.0.0']; }
        };

        $payload = (new ConnectorResponseBuilder($provider, new ResponseRedactor()))->build('health');

        return ($payload['data']['db_password'] ?? null) === '[redacted]';
    }

    /**
     * @param 'active'|'revoked'|string $credentialStatus
     * @param list<string> $scopes
     */
    private function authenticator(bool $enabled, string $credentialStatus = 'active', array $scopes = ['health:read']): ConnectorAuthenticator
    {
        $config = new class($enabled, self::APP_ID, self::TTL_SECONDS) implements ConnectorConfigInterface {
            public function __construct(private bool $enabled, private string $appId, private int $ttl) {}
            public function appId(): string { return $this->appId; }
            public function appName(): string { return 'Contract App'; }
            public function environment(): string { return 'testing'; }
            public function connectorVersion(): string { return '1.0.0'; }
            public function enabled(): bool { return $this->enabled; }
            public function signatureTtlSeconds(): int { return $this->ttl; }
            public function nonceTtlSeconds(): int { return $this->ttl; }
            public function baseUrl(): string { return 'https://app.example.com'; }
            public function securityCenterUrl(): string { return 'https://security.example.com'; }
        };

        $clock = new class(self::TIMESTAMP) implements ClockInterface {
            public function __construct(private int $now) {}
            public function now(): int { return $this->now; }
        };

        $credentials = new InMemoryCredentialStore([
            new Credential('contract-credential', self::APP_ID, self::KEY_ID, self::SECRET, $credentialStatus, $scopes, null),
        ]);

        return new ConnectorAuthenticator($config, $credentials, new InMemoryNonceStore(), new ArrayAccessLog(), $clock);
    }

    /**
     * @return array<string, string>
     */
    private function signedHeaders(int $timestamp = self::TIMESTAMP, string $nonce = 'contract-nonce'): array
    {
        return HmacSigner::headers(self::APP_ID, self::KEY_ID, self::SECRET, 'GET', self::PATH, '', $timestamp, $nonce);
    }
}
