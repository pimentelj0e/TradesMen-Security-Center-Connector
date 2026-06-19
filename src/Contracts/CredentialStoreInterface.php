<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Contracts;
use TradesMen\SecurityCenterConnector\Auth\Credential;
interface CredentialStoreInterface
{
    public function findActive(string $appId, string $keyId): ?Credential;
    public function markUsed(string $credentialId): void;
}
