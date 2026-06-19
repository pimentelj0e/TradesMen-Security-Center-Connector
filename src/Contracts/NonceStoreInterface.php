<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Contracts;
interface NonceStoreInterface
{
    public function claim(string $keyId, string $nonce, int $expiresAt): bool;
}
