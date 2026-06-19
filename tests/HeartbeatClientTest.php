<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Contracts\HttpClientInterface;
use TradesMen\SecurityCenterConnector\Heartbeat\HeartbeatClient;
use TradesMen\SecurityCenterConnector\Protocol\Headers;

final class HeartbeatClientTest extends TestCase
{
    public function testHeartbeatPostsSignedPayload(): void
    {
        $transport = new class implements HttpClientInterface {
            public array $calls = [];

            public function postJson(string $url, array $headers, string $jsonBody, int $timeoutSeconds): array
            {
                $this->calls[] = compact('url', 'headers', 'jsonBody', 'timeoutSeconds');

                return ['status' => 200, 'body' => '{"ok":true}'];
            }
        };

        $client = new HeartbeatClient($transport, static fn (): int => 1700000000, static fn (): string => 'nonce-heartbeat');
        $result = $client->send('https://security.example.com', 'tradesmen-tools', 'key-1', 'secret-1', ['status' => 'healthy'], 10);

        $this->assertSame(200, $result['status'], 'heartbeat response status');
        $this->assertSame('https://security.example.com/api/ingest/heartbeat', $transport->calls[0]['url'], 'heartbeat URL');
        $this->assertSame('tradesmen-tools', $transport->calls[0]['headers'][Headers::APP_ID], 'signed app id');
        $this->assertSame('key-1', $transport->calls[0]['headers'][Headers::KEY_ID], 'signed key id');
        $this->assertSame('1700000000', $transport->calls[0]['headers'][Headers::TIMESTAMP], 'signed timestamp');
        $this->assertSame('nonce-heartbeat', $transport->calls[0]['headers'][Headers::NONCE], 'signed nonce');
    }
}
