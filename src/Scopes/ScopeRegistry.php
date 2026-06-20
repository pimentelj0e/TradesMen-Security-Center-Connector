<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Scopes;
final class ScopeRegistry
{
    /**
     * Canonical connector scopes supported across the ecosystem.
     *
     * @var list<string>
     */
    private const CANONICAL_SCOPES = [
        'manifest:read',
        'health:read',
        'status:read',
        'server:read',
        'database:read',
        'cache:read',
        'queue:read',
        'workers:read',
        'deployments:read',
        'security_summary:read',
        'config_check:read',
        'version:read',
        'heartbeat:write',
    ];

    private const ENDPOINT_SCOPES = [
        'manifest' => 'manifest:read',
        'health' => 'health:read',
        'status' => 'status:read',
        'server' => 'server:read',
        'database' => 'database:read',
        'cache' => 'cache:read',
        'queue' => 'queue:read',
        'queues' => 'queue:read',
        'workers' => 'workers:read',
        'deployments' => 'deployments:read',
        'security-events' => 'security_summary:read',
        'config-check' => 'config_check:read',
        'version' => 'version:read',
    ];

    private const ALIASES = [
        'manifest' => 'manifest:read',
        'health' => 'health:read',
        'status' => 'status:read',
        'server' => 'server:read',
        'database' => 'database:read',
        'cache' => 'cache:read',
        'queues' => 'queue:read',
        'queue' => 'queue:read',
        'workers' => 'workers:read',
        'deployments' => 'deployments:read',
        'security_events' => 'security_summary:read',
        'security-events' => 'security_summary:read',
        'security_summary' => 'security_summary:read',
        'config_check' => 'config_check:read',
        'config-check' => 'config_check:read',
        'version' => 'version:read',
        'heartbeat' => 'heartbeat:write',
    ];

    public function requiredScope(string $path): ?string
    {
        $last = trim(basename(parse_url($path, PHP_URL_PATH) ?: ''), '/');
        return self::ENDPOINT_SCOPES[$last] ?? null;
    }

    public function normalize(string $scope): string
    {
        $scope = strtolower(trim($scope));
        return self::ALIASES[$scope] ?? $scope;
    }

    public function normalizeList(array $scopes): array
    {
        $out = [];
        foreach ($scopes as $scope) {
            $normalized = $this->normalize((string) $scope);
            if ($normalized !== '' && !in_array($normalized, $out, true)) {
                $out[] = $normalized;
            }
        }
        return $out;
    }

    public function granted(array $grantedScopes, string $requiredScope): bool
    {
        return in_array($this->normalize($requiredScope), $this->normalizeList($grantedScopes), true);
    }

    /** @return list<string> */
    public function canonicalScopes(): array
    {
        return self::CANONICAL_SCOPES;
    }

    public function isCanonical(string $scope): bool
    {
        return in_array($this->normalize($scope), self::CANONICAL_SCOPES, true);
    }
}
