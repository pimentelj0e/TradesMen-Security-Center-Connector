<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Scopes;
final class ScopeRegistry
{
    private const ENDPOINT_SCOPES = [
        'manifest' => 'manifest:read',
        'health' => 'health:read',
        'status' => 'status:read',
        'server' => 'server:read',
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

    public function canonicalScopes(): array
    {
        return array_values(array_unique(array_merge(array_values(self::ENDPOINT_SCOPES), ['heartbeat:write'])));
    }
}
