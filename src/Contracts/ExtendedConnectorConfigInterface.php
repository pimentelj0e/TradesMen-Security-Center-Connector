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

    /**
     * Default allowed IPs applied when no per-credential allowlist is configured.
     *
     * @return list<string>
     */
    public function defaultAllowedIps(): array;

    /**
     * Trusted proxy CIDRs. Only requests forwarded through one of these may have
     * their client IP derived from {@see clientIpHeaders()}.
     *
     * @return list<string>
     */
    public function trustedProxyCidrs(): array;

    /**
     * Ordered client-IP header names the host may consult when behind a trusted
     * proxy (e.g. X-Forwarded-For). Empty means: trust only the socket peer.
     *
     * @return list<string>
     */
    public function clientIpHeaders(): array;

    /** Retention window, in days, for connector access logs. */
    public function accessLogRetentionDays(): int;

    /** Retention window, in seconds, for replay-protection nonce records. */
    public function nonceLogRetentionSeconds(): int;

    /** @return list<string> */
    public function scopes(): array;
}
