<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Support;

use TradesMen\SecurityCenterConnector\Auth\Credential;
use TradesMen\SecurityCenterConnector\Config\ConnectorEnvNames;
use TradesMen\SecurityCenterConnector\Config\ConnectorMode;
use TradesMen\SecurityCenterConnector\Config\EnvConnectorConfig;
use TradesMen\SecurityCenterConnector\Config\EnvResolver;
use TradesMen\SecurityCenterConnector\Contracts\CredentialStoreInterface;

/**
 * Credential store backed by the process environment, for connectors running in
 * {@see ConnectorMode::ENV} mode.
 *
 * Reads:
 *   - TRADESMEN_SECURITY_CENTER_KEY_ID        (alias TSC_KEY_ID)
 *   - TRADESMEN_SECURITY_CENTER_SHARED_SECRET (alias TSC_SHARED_SECRET)
 *   - TRADESMEN_SECURITY_CENTER_SCOPES        (alias TSC_SCOPES)
 *
 * Validation rules:
 *   - key_id is a public identifier; shared_secret is secret.
 *   - key_id and shared_secret must not be equal.
 *   - shared_secret must meet a minimum length for production use.
 *
 * The shared secret is never logged or placed in an error message. When the
 * connector is enabled in env mode but credentials are missing or invalid, the
 * store returns no credential and exposes an operator-safe error code via
 * {@see error()}.
 */
final class EnvCredentialStore implements CredentialStoreInterface
{
    /** Minimum shared-secret length considered safe for production. */
    public const MIN_SECRET_LENGTH = 32;

    private readonly EnvResolver $env;

    private ?string $error = null;

    public function __construct(
        private readonly EnvConnectorConfig $config,
        ?EnvResolver $env = null,
        private readonly int $minSecretLength = self::MIN_SECRET_LENGTH,
    ) {
        $this->env = $env ?? new EnvResolver();
    }

    public function findActive(string $appId, string $keyId): ?Credential
    {
        $credential = $this->resolveCredential();
        if ($credential === null) {
            return null;
        }

        if (!hash_equals($credential->appId, $appId) || !hash_equals($credential->keyId, $keyId)) {
            return null;
        }

        return $credential;
    }

    public function markUsed(string $credentialId): void
    {
        // Environment-backed credentials are stateless; nothing to persist.
    }

    /**
     * The connector's own credential as configured in the environment, or null
     * when unavailable. Useful for outbound calls such as heartbeats where the
     * app already knows it is acting as itself.
     */
    public function current(): ?Credential
    {
        return $this->resolveCredential();
    }

    /** Operator-safe error code from the last resolution, if any. */
    public function error(): ?string
    {
        return $this->error;
    }

    public function hasError(): bool
    {
        return $this->error !== null;
    }

    private function resolveCredential(): ?Credential
    {
        $this->error = null;

        if ($this->config->mode() !== ConnectorMode::ENV) {
            // Credentials for managed_db mode are supplied by the host app, not here.
            return null;
        }

        if (!$this->config->enabled()) {
            return null;
        }

        $keyId = $this->env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_KEY_ID);
        $secret = $this->env->string(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SHARED_SECRET);

        if ($keyId === null || $secret === null) {
            $this->error = 'connector_env_credentials_missing';
            return null;
        }

        if (hash_equals($keyId, $secret)) {
            $this->error = 'connector_env_key_secret_equal';
            return null;
        }

        if (strlen($secret) < $this->minSecretLength) {
            $this->error = 'connector_env_secret_too_short';
            return null;
        }

        $appId = $this->config->appId();
        if ($appId === '') {
            $this->error = 'connector_env_app_id_missing';
            return null;
        }

        $scopes = $this->env->csvList(ConnectorEnvNames::TRADESMEN_SECURITY_CENTER_SCOPES);
        if ($scopes === []) {
            $scopes = $this->config->scopes();
        }

        return new Credential(
            'env:' . $appId . ':' . $keyId,
            $appId,
            $keyId,
            $secret,
            'active',
            $scopes,
            null,
        );
    }
}
