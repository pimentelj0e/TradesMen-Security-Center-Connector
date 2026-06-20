<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Config\ConnectorEnvNames;
use TradesMen\SecurityCenterConnector\Config\EnvConnectorConfig;
use TradesMen\SecurityCenterConnector\Contracts\HttpClientInterface;
use TradesMen\SecurityCenterConnector\Heartbeat\HeartbeatClient;
use TradesMen\SecurityCenterConnector\Protocol\Headers;
use TradesMen\SecurityCenterConnector\Support\EnvCredentialStore;

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

    public function testHeartbeatCanPostToFullIngestUrl(): void
    {
        $transport = new class implements HttpClientInterface {
            public array $calls = [];

            public function postJson(string $url, array $headers, string $jsonBody, int $timeoutSeconds): array
            {
                $this->calls[] = compact('url', 'headers', 'jsonBody', 'timeoutSeconds');

                return ['status' => 202, 'body' => '{"ok":true}'];
            }
        };

        $client = new HeartbeatClient($transport, static fn (): int => 1700000000, static fn (): string => 'nonce-full-url');
        $result = $client->sendToUrl('https://security.example.com/custom/ingest?source=network', 'tradesmen-network', 'key-1', 'secret-1', ['status' => 'ok'], 7);

        $this->assertSame(202, $result['status'], 'heartbeat response status');
        $this->assertSame('https://security.example.com/custom/ingest?source=network', $transport->calls[0]['url'], 'full URL preserved');
        $this->assertSame('tradesmen-network', $transport->calls[0]['headers'][Headers::APP_ID], 'signed app id');
        $this->assertSame('nonce-full-url', $transport->calls[0]['headers'][Headers::NONCE], 'signed nonce');
    }

    public function testSendFromConfigUsesEnvCredentialsAndNeverLeaksSecret(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'true');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'tradesmen-tools');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_URL, 'https://security.example.com');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID, 'tsc_live_key');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET, 'env_mode_shared_secret_0123456789_abcdef');

        $transport = new class implements HttpClientInterface {
            public array $calls = [];

            public function postJson(string $url, array $headers, string $jsonBody, int $timeoutSeconds): array
            {
                $this->calls[] = compact('url', 'headers', 'jsonBody', 'timeoutSeconds');

                return ['status' => 200, 'body' => '{"ok":true}'];
            }
        };

        $config = new EnvConnectorConfig();
        $credentials = new EnvCredentialStore($config);
        $client = new HeartbeatClient($transport, static fn (): int => 1700000000, static fn (): string => 'nonce-from-config');

        $result = $client->sendFromConfig($config, $credentials, ['status' => 'healthy', 'instance' => $config->instance()]);

        $this->assertSame(200, $result['status'], 'heartbeat sent from config');
        $this->assertSame('https://security.example.com/api/ingest/heartbeat', $transport->calls[0]['url'], 'security center url used');
        $this->assertSame('tradesmen-tools', $transport->calls[0]['headers'][Headers::APP_ID], 'app id from config');
        $this->assertSame('tsc_live_key', $transport->calls[0]['headers'][Headers::KEY_ID], 'key id from credential store');
        $this->assertFalse(str_contains($transport->calls[0]['jsonBody'], 'env_mode_shared_secret'), 'shared secret never appears in payload');

        $this->clearConnectorEnv();
    }

    public function testSendFromConfigReturnsErrorWhenCredentialMissing(): void
    {
        $this->clearConnectorEnv();
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, 'true');
        $this->setEnv(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, 'tradesmen-tools');
        // No key id / secret configured.

        $transport = new class implements HttpClientInterface {
            public array $calls = [];

            public function postJson(string $url, array $headers, string $jsonBody, int $timeoutSeconds): array
            {
                $this->calls[] = compact('url', 'headers', 'jsonBody', 'timeoutSeconds');

                return ['status' => 200, 'body' => '{}'];
            }
        };

        $config = new EnvConnectorConfig();
        $credentials = new EnvCredentialStore($config);
        $client = new HeartbeatClient($transport, static fn (): int => 1700000000, static fn (): string => 'nonce');

        $result = $client->sendFromConfig($config, $credentials, ['status' => 'healthy']);
        $this->assertSame('connector_env_credentials_missing', $result['error'] ?? '', 'missing credential surfaces safe error');
        $this->assertSame(0, count($transport->calls), 'no request made without a credential');

        $this->clearConnectorEnv();
    }
}
