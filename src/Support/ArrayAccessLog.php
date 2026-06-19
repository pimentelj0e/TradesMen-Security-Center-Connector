<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Support;
use TradesMen\SecurityCenterConnector\Auth\VerificationResult;
use TradesMen\SecurityCenterConnector\Contracts\AccessLogInterface;
final class ArrayAccessLog implements AccessLogInterface
{
    public array $rows = [];
    public function record(VerificationResult $result, string $method, string $pathWithQuery, ?string $ipAddress, ?string $userAgent): void
    {
        $this->rows[] = [
            'ok' => $result->ok,
            'status' => $result->status,
            'reason' => $result->reason,
            'app_id' => $result->appId,
            'key_id' => $result->keyId,
            'method' => strtoupper($method),
            'path' => $pathWithQuery,
            'ip' => $ipAddress,
            'user_agent' => $userAgent,
        ];
    }
}
