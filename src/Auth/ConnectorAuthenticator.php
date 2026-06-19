<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Auth;
use TradesMen\SecurityCenterConnector\Contracts\AccessLogInterface;
use TradesMen\SecurityCenterConnector\Contracts\ConnectorConfigInterface;
use TradesMen\SecurityCenterConnector\Contracts\CredentialStoreInterface;
use TradesMen\SecurityCenterConnector\Contracts\NonceStoreInterface;
use TradesMen\SecurityCenterConnector\Protocol\Headers;
use TradesMen\SecurityCenterConnector\Protocol\HmacSigner;
use TradesMen\SecurityCenterConnector\Protocol\HmacVerifier;

final class ConnectorAuthenticator
{
    /** @param callable():int $clock */
    public function __construct(
        private readonly ConnectorConfigInterface $config,
        private readonly CredentialStoreInterface $credentials,
        private readonly NonceStoreInterface $nonces,
        private readonly AccessLogInterface $logs,
        private readonly mixed $clock,
    ) {}

    public function authenticate(string $method, string $pathWithQuery, array $headers, string $rawBody, ?string $ipAddress, ?string $userAgent): VerificationResult
    {
        $result = $this->verify($method, $pathWithQuery, $headers, $rawBody);
        $this->logs->record($result, $method, $pathWithQuery, $ipAddress, $userAgent);
        if ($result->ok && $result->credentialId !== null) {
            $this->credentials->markUsed($result->credentialId);
        }
        return $result;
    }

    private function verify(string $method, string $pathWithQuery, array $headers, string $rawBody): VerificationResult
    {
        if (!$this->config->enabled()) {
            return VerificationResult::deny(503, 'connector_disabled');
        }

        $missing = HmacVerifier::missingRequiredHeaders($headers);
        if ($missing !== []) {
            return VerificationResult::deny(400, 'missing_header');
        }

        $h = HmacVerifier::normalizeHeaders($headers);
        $appId = $h[strtolower(Headers::APP_ID)];
        $keyId = $h[strtolower(Headers::KEY_ID)];
        $timestamp = $h[strtolower(Headers::TIMESTAMP)];
        $nonce = $h[strtolower(Headers::NONCE)];
        $bodyHash = strtolower($h[strtolower(Headers::BODY_SHA256)]);
        $signature = $h[strtolower(Headers::SIGNATURE)];

        if (!hash_equals($this->config->appId(), $appId)) {
            return VerificationResult::deny(401, 'unknown_app', $appId, $keyId);
        }

        if (!preg_match('/^\d{1,20}$/', $timestamp) || !preg_match('/^[a-f0-9]{64}$/', $bodyHash)) {
            return VerificationResult::deny(400, 'malformed_header', $appId, $keyId);
        }

        $now = ($this->clock)();
        if (abs($now - (int) $timestamp) > $this->config->signatureTtlSeconds()) {
            return VerificationResult::deny(401, 'stale_timestamp', $appId, $keyId);
        }

        $actualBodyHash = HmacSigner::bodyHash($rawBody);
        if (!hash_equals($actualBodyHash, $bodyHash)) {
            return VerificationResult::deny(401, 'body_hash_mismatch', $appId, $keyId);
        }

        $credential = $this->credentials->findActive($appId, $keyId);
        if ($credential === null) {
            return VerificationResult::deny(401, 'unknown_key', $appId, $keyId);
        }

        if ($credential->expiresAt !== null && $credential->expiresAt < $now) {
            return VerificationResult::deny(403, 'key_expired', $appId, $keyId);
        }

        $canonical = HmacSigner::canonicalString($method, $pathWithQuery, $timestamp, $nonce, $actualBodyHash);
        if (!HmacVerifier::signatureMatches($canonical, $credential->secret, $signature)) {
            return VerificationResult::deny(401, 'bad_signature', $appId, $keyId);
        }

        if (!$this->nonces->claim($keyId, $nonce, $now + $this->config->nonceTtlSeconds())) {
            return VerificationResult::deny(401, 'replayed_nonce', $appId, $keyId);
        }

        return VerificationResult::ok($credential);
    }
}
