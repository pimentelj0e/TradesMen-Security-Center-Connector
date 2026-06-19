<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Auth;
final class Credential
{
    public function __construct(
        public readonly string $id,
        public readonly string $appId,
        public readonly string $keyId,
        public readonly string $secret,
        public readonly string $status,
        public readonly array $scopes,
        public readonly ?int $expiresAt,
    ) {}
}
