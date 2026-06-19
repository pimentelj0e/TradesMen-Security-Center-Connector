<?php
declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Response;

use TradesMen\SecurityCenterConnector\Contracts\TelemetryProviderInterface;
use TradesMen\SecurityCenterConnector\Redaction\ResponseRedactor;

final class ConnectorResponseBuilder
{
    private const METHOD_BY_CHECK = [
        'manifest' => 'manifest',
        'health' => 'health',
        'status' => 'status',
        'server' => 'server',
        'queues' => 'queues',
        'workers' => 'workers',
        'deployments' => 'deployments',
        'security-events' => 'securityEvents',
        'security_events' => 'securityEvents',
        'config-check' => 'configCheck',
        'config_check' => 'configCheck',
        'version' => 'version',
    ];

    public function __construct(
        private readonly TelemetryProviderInterface $provider,
        private readonly ResponseRedactor $redactor = new ResponseRedactor(),
    ) {}

    public function build(string $checkKey): array
    {
        $method = self::METHOD_BY_CHECK[$checkKey] ?? null;
        if ($method === null) {
            return [
                'ok' => false,
                'check' => $checkKey,
                'error' => ['code' => 'unknown_check'],
                'meta' => ['generated_at' => gmdate('c'), 'schema' => 'v1'],
            ];
        }

        return [
            'ok' => true,
            'check' => $checkKey,
            'data' => $this->redactor->redact($this->provider->{$method}()),
            'meta' => ['generated_at' => gmdate('c'), 'schema' => 'v1'],
        ];
    }
}
