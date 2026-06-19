<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Contracts;
use TradesMen\SecurityCenterConnector\Auth\VerificationResult;
interface AccessLogInterface
{
    public function record(VerificationResult $result, string $method, string $pathWithQuery, ?string $ipAddress, ?string $userAgent): void;
}
