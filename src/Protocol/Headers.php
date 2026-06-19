<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Protocol;

final class Headers
{
    public const APP_ID = 'X-TSC-App-Id';
    public const KEY_ID = 'X-TSC-Key-Id';
    public const TIMESTAMP = 'X-TSC-Timestamp';
    public const NONCE = 'X-TSC-Nonce';
    public const BODY_SHA256 = 'X-TSC-Body-SHA256';
    public const SIGNATURE = 'X-TSC-Signature';
    public const REQUEST_ID = 'X-TSC-Request-Id';

    public const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    public static function required(): array
    {
        return [
            self::APP_ID,
            self::KEY_ID,
            self::TIMESTAMP,
            self::NONCE,
            self::BODY_SHA256,
            self::SIGNATURE,
        ];
    }
}
