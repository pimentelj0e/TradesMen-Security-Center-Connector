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
        $path = '/api/ingest/heartbeat';
        $url = rtrim($securityCenterBaseUrl, '/') . $path;
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (!is_string($body)) {
            $body = '{}';
        }
        $headers = HmacSigner::headers($appId, $keyId, $secret, 'POST', $path, $body, ($this->clock)(), ($this->nonceFactory)());
        $headers['Content-Type'] = 'application/json';
        $headers['Accept'] = 'application/json';

        return $this->http->postJson($url, $headers, $body, $timeoutSeconds);
    }
}
