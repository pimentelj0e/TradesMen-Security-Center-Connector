<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Config;

use TradesMen\SecurityCenterConnector\Contracts\ExtendedConnectorConfigInterface;

/**
 * Connector configuration sourced from the process environment.
 *
 * Implements the existing {@see \TradesMen\SecurityCenterConnector\Contracts\ConnectorConfigInterface}
 * (via {@see ExtendedConnectorConfigInterface}) so it is a drop-in for any host
 * that already consumes the base interface, while exposing the additional
 * universal-connector settings as extra methods.
 *
 * All reads go through {@see EnvResolver}, which reads only the canonical
 * TRADESMEN_SECURITY_CENTER_* names. No value is ever printed or logged.
 */
final class EnvConnectorConfig implements ExtendedConnectorConfigInterface
{
    public const VERSION = '1.0.0';

    private readonly EnvResolver $env;

    public function __construct(
        ?EnvResolver $env = null,
        private readonly string $connectorVersion = self::VERSION,
    ) {
        $this->env = $env ?? new EnvResolver();
    }

    public function appId(): string
    {
        return (string) $this->env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_APP_ID, '');
    }

    public function appName(): string
    {
        $name = $this->env->firstNonEmpty(['APP_NAME']);
        if ($name !== null) {
            return $name;
        }

        return $this->appId();
    }

    public function environment(): string
    {
        return (string) $this->env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_ENVIRONMENT, 'production');
    }

    public function connectorVersion(): string
    {
        return $this->connectorVersion;
    }

    public function enabled(): bool
    {
        return $this->env->bool(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED, false);
    }

    public function signatureTtlSeconds(): int
    {
        return $this->env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS, 300);
    }

    public function nonceTtlSeconds(): int
    {
        return $this->env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS, 300);
    }

    public function baseUrl(): string
    {
        return (string) $this->env->firstNonEmpty(['APP_URL']);
    }

    public function securityCenterUrl(): string
    {
        return (string) $this->env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_URL, '');
    }

    public function mode(): string
    {
        $raw = (string) $this->env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE, ConnectorMode::DEFAULT);
        return ConnectorMode::fromStringOrDefault($raw);
    }

    public function instance(): string
    {
        return (string) $this->env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_INSTANCE, '');
    }

    public function heartbeatEnabled(): bool
    {
        return $this->env->bool(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED, false);
    }

    public function heartbeatIntervalSeconds(): int
    {
        return $this->env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS, 60);
    }

    public function heartbeatTimeoutSeconds(): int
    {
        return $this->env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS, 10);
    }

    /** @return list<string> */
    public function allowedIps(): array
    {
        return $this->env->csvList(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_ALLOWED_IPS);
    }

    public function requireIpAllowlist(): bool
    {
        return $this->env->bool(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST, false);
    }

    /** @return list<string> */
    public function defaultAllowedIps(): array
    {
        return $this->env->csvList(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_DEFAULT_ALLOWED_IPS);
    }

    /** @return list<string> */
    public function trustedProxyCidrs(): array
    {
        return $this->env->csvList(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_TRUSTED_PROXY_CIDRS);
    }

    /** @return list<string> */
    public function clientIpHeaders(): array
    {
        return $this->env->csvList(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_CLIENT_IP_HEADERS);
    }

    public function accessLogRetentionDays(): int
    {
        return $this->env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_ACCESS_LOG_RETENTION_DAYS, 30);
    }

    public function nonceLogRetentionSeconds(): int
    {
        return $this->env->int(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_NONCE_LOG_RETENTION_SECONDS, 86400);
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return $this->env->csvList(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SCOPES);
    }
}
