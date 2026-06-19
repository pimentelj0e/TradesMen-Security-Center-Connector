<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Auth;
final class VerificationResult
{
    public function __construct(
        public readonly bool $ok,
        public readonly int $status,
        public readonly string $reason,
        public readonly ?string $appId = null,
        public readonly ?string $keyId = null,
        public readonly ?string $credentialId = null,
        public readonly array $scopes = [],
    ) {}

    public static function ok(Credential $credential): self
    {
        return new self(true, 200, 'ok', $credential->appId, $credential->keyId, $credential->id, $credential->scopes);
    }

    public static function deny(int $status, string $reason, ?string $appId = null, ?string $keyId = null): self
    {
        return new self(false, $status, $reason, $appId, $keyId);
    }
}
