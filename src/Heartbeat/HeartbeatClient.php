<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Heartbeat;

use TradesMen\SecurityCenterConnector\Config\EnvConnectorConfig;
use TradesMen\SecurityCenterConnector\Contracts\HttpClientInterface;
use TradesMen\SecurityCenterConnector\Protocol\HmacSigner;
use TradesMen\SecurityCenterConnector\Support\EnvCredentialStore;

final class HeartbeatClient
{
    /** @param callable():int $clock @param callable():string $nonceFactory */
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly mixed $clock,
        private readonly mixed $nonceFactory,
    ) {}

    /**
     * Convenience wrapper for env-mode apps: pulls the Security Center URL, app
     * id, timeout and signing credential straight from config + credential
     * store. The shared secret is only ever used to sign — it is never placed in
     * the payload.
     *
     * @param array<string, mixed> $payload
     * @return array{status:int,body:string,error?:string}
     */
    public function sendFromConfig(EnvConnectorConfig $config, EnvCredentialStore $credentials, array $payload, ?int $timeoutSeconds = null): array
    {
        $credential = $credentials->current();
        if ($credential === null) {
            return ['status' => 0, 'body' => '', 'error' => $credentials->error() ?? 'missing_credential'];
        }

        return $this->send(
            $config->securityCenterUrl(),
            $config->appId(),
            $credential->keyId,
            $credential->secret,
            $payload,
            $timeoutSeconds ?? $config->heartbeatTimeoutSeconds(),
        );
    }

    public function send(string $securityCenterBaseUrl, string $appId, string $keyId, string $secret, array $payload, int $timeoutSeconds = 10): array
    {
        return $this->sendToUrl(
            rtrim($securityCenterBaseUrl, '/') . '/api/ingest/heartbeat',
            $appId,
            $keyId,
            $secret,
            $payload,
            $timeoutSeconds,
        );
    }

    public function sendToUrl(string $targetUrl, string $appId, string $keyId, string $secret, array $payload, int $timeoutSeconds = 10): array
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($body)) {
            $body = '{}';
        }
        $parsed = parse_url($targetUrl);
        $path = (string) ($parsed['path'] ?? '/');
        $query = isset($parsed['query']) ? '?' . $parsed['query'] : '';
        $pathWithQuery = $path . $query;
        $headers = HmacSigner::headers($appId, $keyId, $secret, 'POST', $pathWithQuery, $body, ($this->clock)(), ($this->nonceFactory)());
        $headers['Content-Type'] = 'application/json';
        $headers['Accept'] = 'application/json';

        return $this->http->postJson($targetUrl, $headers, $body, $timeoutSeconds);
    }
}
