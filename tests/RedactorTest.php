<?php
declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Redaction\ResponseRedactor;

final class RedactorTest extends TestCase
{
    public function testSensitiveKeysAreRedacted(): void
    {
        $redacted = (new ResponseRedactor())->redact([
            'ok' => true,
            'db_password' => 'secret',
            'nested' => ['api_token' => 'abc', 'count' => 5],
        ]);

        $this->assertSame('[redacted]', $redacted['db_password'], 'password key redacted');
        $this->assertSame('[redacted]', $redacted['nested']['api_token'], 'token key redacted');
        $this->assertSame(5, $redacted['nested']['count'], 'safe count preserved');
    }

    public function testStringSecretsAreRedacted(): void
    {
        $text = 'Authorization: Bearer abcdefghijklmnop DB_PASSWORD=secret postgres://user:pass@example/db 10.1.2.3';
        $redacted = (new ResponseRedactor())->redact($text);

        $this->assertFalse(str_contains($redacted, 'abcdefghijklmnop'), 'bearer removed');
        $this->assertFalse(str_contains($redacted, 'DB_PASSWORD=secret'), 'env value removed');
        $this->assertFalse(str_contains($redacted, 'user:pass'), 'dsn credentials removed');
        $this->assertFalse(str_contains($redacted, '10.1.2.3'), 'private ip removed');
    }
}
