<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Protocol;

final class HmacVerifier
{
    public static function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $value) {
            $normalized[strtolower((string) $name)] = is_array($value) ? (string) reset($value) : (string) $value;
        }
        return $normalized;
    }

    public static function signatureMatches(string $canonical, string $secret, string $providedSignature): bool
    {
        if ($providedSignature === '') {
            return false;
        }

        $provided = base64_decode($providedSignature, true);
        if ($provided === false || strlen($provided) !== 32) {
            return false;
        }

        $expected = hash_hmac('sha256', $canonical, $secret, true);
        return hash_equals($expected, $provided);
    }

    public static function missingRequiredHeaders(array $headers): array
    {
        $normalized = self::normalizeHeaders($headers);
        $missing = [];
        foreach (Headers::required() as $header) {
            if (($normalized[strtolower($header)] ?? '') === '') {
                $missing[] = $header;
            }
        }
        return $missing;
    }
}
