<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Contracts;

/**
 * Optional extension of {@see ConnectorConfigInterface} exposing the wider
 * universal-connector configuration surface (mode, instance, heartbeat and IP
 * allowlist settings).
 *
 * It is intentionally separate from the base interface so existing hosts that
 * only implement {@see ConnectorConfigInterface} continue to work unchanged.
 */
interface ExtendedConnectorConfigInterface extends ConnectorConfigInterface
{
    public function mode(): string;

    public function instance(): string;

    public function heartbeatEnabled(): bool;

    public function heartbeatIntervalSeconds(): int;

    public function heartbeatTimeoutSeconds(): int;

    /** @return list<string> */
    public function allowedIps(): array;

    public function requireIpAllowlist(): bool;

    /** @return list<string> */
    public function scopes(): array;
}
