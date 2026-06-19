<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Protocol;

final class HmacSigner
{
    public static function bodyHash(string $rawBody): string
    {
        return hash('sha256', $rawBody);
    }

    public static function canonicalString(string $method, string $pathWithQuery, string $timestamp, string $nonce, string $bodySha256): string
    {
        return implode("\n", [
            strtoupper($method),
            $pathWithQuery,
            $timestamp,
            $nonce,
            strtolower($bodySha256),
        ]);
    }

    public static function signCanonical(string $canonical, string $secret): string
    {
        return base64_encode(hash_hmac('sha256', $canonical, $secret, true));
    }

    public static function signRequest(string $method, string $pathWithQuery, string $timestamp, string $nonce, string $bodySha256, string $secret): string
    {
        return self::signCanonical(
            self::canonicalString($method, $pathWithQuery, $timestamp, $nonce, $bodySha256),
            $secret,
        );
    }

    public static function headers(string $appId, string $keyId, string $secret, string $method, string $pathWithQuery, string $body = '', ?int $timestamp = null, ?string $nonce = null): array
    {
        $timestamp ??= time();
        $nonce ??= 'n_' . bin2hex(random_bytes(16));
        $bodyHash = self::bodyHash($body);

        return [
            Headers::APP_ID => $appId,
            Headers::KEY_ID => $keyId,
            Headers::TIMESTAMP => (string) $timestamp,
            Headers::NONCE => $nonce,
            Headers::BODY_SHA256 => $bodyHash,
            Headers::SIGNATURE => self::signRequest($method, $pathWithQuery, (string) $timestamp, $nonce, $bodyHash, $secret),
        ];
    }
}
