<?php
declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Contracts;

interface TelemetryProviderInterface
{
    public function manifest(): array;
    public function health(): array;
    public function status(): array;
    public function server(): array;
    public function queues(): array;
    public function workers(): array;
    public function deployments(): array;
    public function securityEvents(): array;
    public function configCheck(): array;
    public function version(): array;
}
