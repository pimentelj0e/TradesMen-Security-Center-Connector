<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Tokens;

use InvalidArgumentException;
use TradesMen\SecurityCenterConnector\Config\ConnectorMode;
use TradesMen\SecurityCenterConnector\Scopes\ScopeRegistry;

/**
 * Validating import side of the connector setup-token codec.
 *
 * Security Center calls {@see import()} when an operator pastes a
 * `TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN=tsc1_...` line. It layers the
 * registry-aware checks (duplicate key id, canonical scopes, valid connector
 * mode) on top of the structural decoding/validation done by
 * {@see ConnectorTokenParser::parse()}.
 *
 * Every failure surfaces as an operator-safe {@see InvalidArgumentException}
 * code; the shared secret never appears in any message. Rejection codes:
 *
 *   - malformed token  : invalid_token / invalid_token_encoding /
 *                        invalid_token_payload / unrecognized_token
 *   - legacy token     : unrecognized_token / unrecognized_token_wrapper
 *   - expired token    : token_expired
 *   - missing app id   : missing_app_id
 *   - missing secret   : missing_secret
 *   - invalid scopes   : invalid_scopes
 *   - invalid mode     : invalid_connector_mode
 *   - duplicate key    : duplicate_key
 */
final class ConnectorTokenImporter
{
    private readonly ScopeRegistry $scopes;

    public function __construct(?ScopeRegistry $scopes = null)
    {
        $this->scopes = $scopes ?? new ScopeRegistry();
    }

    /**
     * Validate and decode a connector token for registration in Security Center.
     *
     * @param list<string> $existingKeyIds Key ids already registered. A token
     *                                     reusing one of these is rejected.
     * @return array<string, mixed> The validated, decoded payload.
     *
     * @throws InvalidArgumentException with an operator-safe rejection code.
     */
    public function import(string $raw, array $existingKeyIds = [], ?int $now = null): array
    {
        $payload = ConnectorTokenParser::parse($raw, $now);

        $this->assertValidMode($payload);
        $this->assertCanonicalScopes($payload);
        $this->assertKeyNotDuplicate($payload, $existingKeyIds);

        return $payload;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function assertValidMode(array $payload): void
    {
        $mode = $payload['connector_mode'] ?? null;
        if ($mode === null || $mode === '') {
            return;
        }
        if (!is_string($mode) || !ConnectorMode::isValid($mode)) {
            throw new InvalidArgumentException('invalid_connector_mode');
        }
    }

    /**
     * Scopes must be present and every entry must be a canonical connector scope.
     *
     * @param array<string, mixed> $payload
     */
    private function assertCanonicalScopes(array $payload): void
    {
        /** @var list<string> $scopes */
        $scopes = $payload['scopes'] ?? [];
        if ($scopes === []) {
            throw new InvalidArgumentException('invalid_scopes');
        }
        foreach ($scopes as $scope) {
            if (!$this->scopes->isCanonical($scope)) {
                throw new InvalidArgumentException('invalid_scopes');
            }
        }
    }

    /**
     * @param array<string, mixed> $payload
     * @param list<string>         $existingKeyIds
     */
    private function assertKeyNotDuplicate(array $payload, array $existingKeyIds): void
    {
        $keyId = (string) ($payload['key_id'] ?? '');
        foreach ($existingKeyIds as $existing) {
            if (hash_equals((string) $existing, $keyId)) {
                throw new InvalidArgumentException('duplicate_key');
            }
        }
    }
}
