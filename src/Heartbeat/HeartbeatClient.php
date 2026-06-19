<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Heartbeat;

use TradesMen\SecurityCenterConnector\Contracts\HttpClientInterface;
use TradesMen\SecurityCenterConnector\Protocol\HmacSigner;

final class HeartbeatClient
{
    /** @param callable():int $clock @param callable():string $nonceFactory */
    public function __construct(
        private readonly HttpClientInterface $http,
        private readonly mixed $clock,
        private readonly mixed $nonceFactory,
    ) {}

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
