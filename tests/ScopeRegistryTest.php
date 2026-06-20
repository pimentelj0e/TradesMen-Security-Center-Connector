<?php
declare(strict_types=1);
namespace Tests;
use TradesMen\SecurityCenterConnector\Scopes\ScopeRegistry;
final class ScopeRegistryTest extends TestCase
{
    public function testEndpointScopes(): void
    {
        $r = new ScopeRegistry();
        $this->assertSame('manifest:read', $r->requiredScope('/api/security-center/v1/manifest'), 'manifest scope');
        $this->assertSame('queue:read', $r->requiredScope('/api/security-center/v1/queues'), 'queues scope');
        $this->assertSame('security_summary:read', $r->requiredScope('/api/security-center/v1/security-events'), 'security events scope');
        $this->assertSame('config_check:read', $r->requiredScope('/api/security-center/v1/config-check'), 'config check scope');
    }

    public function testAliasesNormalize(): void
    {
        $r = new ScopeRegistry();
        $this->assertSame(['queue:read', 'security_summary:read', 'config_check:read'], $r->normalizeList(['queues', 'security_events', 'config_check']), 'aliases normalize');
    }

    public function testGrantedUsesAliases(): void
    {
        $r = new ScopeRegistry();
        $this->assertTrue($r->granted(['queues'], 'queue:read'), 'queues alias grants queue read');
        $this->assertFalse($r->granted(['version:read'], 'health:read'), 'version does not grant health');
    }

    public function testCanonicalScopesIncludeFullSet(): void
    {
        $r = new ScopeRegistry();
        $expected = [
            'manifest:read', 'health:read', 'status:read', 'server:read', 'database:read',
            'cache:read', 'queue:read', 'workers:read', 'deployments:read',
            'security_summary:read', 'config_check:read', 'version:read', 'heartbeat:write',
        ];
        foreach ($expected as $scope) {
            $this->assertContains($scope, $r->canonicalScopes(), 'canonical scope present: ' . $scope);
            $this->assertTrue($r->isCanonical($scope), 'scope reported canonical: ' . $scope);
        }
    }

    public function testDatabaseAndCacheEndpointScopes(): void
    {
        $r = new ScopeRegistry();
        $this->assertSame('database:read', $r->requiredScope('/api/security-center/v1/database'), 'database scope');
        $this->assertSame('cache:read', $r->requiredScope('/api/security-center/v1/cache'), 'cache scope');
    }

    public function testHeartbeatAliasNormalizes(): void
    {
        $r = new ScopeRegistry();
        $this->assertSame('heartbeat:write', $r->normalize('heartbeat'), 'heartbeat alias normalizes');
    }
}
