<?php
declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Contracts\TelemetryProviderInterface;
use TradesMen\SecurityCenterConnector\Response\ConnectorResponseBuilder;

final class ResponseBuilderTest extends TestCase
{
    public function testBuildsRedactedEnvelope(): void
    {
        $provider = new class implements TelemetryProviderInterface {
            public function manifest(): array { return ['app' => 'tradesmen-tools']; }
            public function health(): array { return ['status' => 'healthy', 'db_password' => 'secret']; }
            public function status(): array { return ['status' => 'healthy']; }
            public function server(): array { return ['php_version' => PHP_VERSION]; }
            public function queues(): array { return ['depth' => 0]; }
            public function workers(): array { return ['online' => 1]; }
            public function deployments(): array { return ['version' => '1.0.0']; }
            public function securityEvents(): array { return ['failed_logins_24h' => 0]; }
            public function configCheck(): array { return ['missing' => []]; }
            public function version(): array { return ['version' => '1.0.0']; }
        };

        $payload = (new ConnectorResponseBuilder($provider))->build('health');
        $this->assertSame(true, $payload['ok'], 'ok envelope');
        $this->assertSame('health', $payload['check'], 'check key');
        $this->assertSame('[redacted]', $payload['data']['db_password'], 'redacted data');
        $this->assertArrayHasKey('generated_at', $payload['meta'], 'generated timestamp');
    }
}
