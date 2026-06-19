<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Support;
use TradesMen\SecurityCenterConnector\Contracts\NonceStoreInterface;
final class InMemoryNonceStore implements NonceStoreInterface
{
    private array $claimed = [];
    public function claim(string $keyId, string $nonce, int $expiresAt): bool
    {
        $k = $keyId . ':' . $nonce;
        if (isset($this->claimed[$k])) {
            return false;
        }
        $this->claimed[$k] = $expiresAt;
        return true;
    }
}
