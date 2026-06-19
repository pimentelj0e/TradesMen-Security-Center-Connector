<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Support;
use TradesMen\SecurityCenterConnector\Auth\Credential;
use TradesMen\SecurityCenterConnector\Contracts\CredentialStoreInterface;
final class InMemoryCredentialStore implements CredentialStoreInterface
{
    public array $used = [];
    /** @param list<Credential> $credentials */
    public function __construct(private array $credentials) {}
    public function findActive(string $appId, string $keyId): ?Credential
    {
        foreach ($this->credentials as $credential) {
            if ($credential->appId === $appId && $credential->keyId === $keyId && $credential->status === 'active') {
                return $credential;
            }
        }
        return null;
    }
    public function markUsed(string $credentialId): void
    {
        $this->used[] = $credentialId;
    }
}
