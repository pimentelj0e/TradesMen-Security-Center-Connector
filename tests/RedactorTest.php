<?php
declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Redaction\ResponseRedactor;

final class RedactorTest extends TestCase
{
    private function redact(mixed $value): mixed
    {
        return (new ResponseRedactor())->redact($value);
    }

    public function testSensitiveKeysAreRedacted(): void
    {
        $redacted = $this->redact([
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
        $redacted = $this->redact($text);

        $this->assertFalse(str_contains($redacted, 'abcdefghijklmnop'), 'bearer removed');
        $this->assertFalse(str_contains($redacted, 'DB_PASSWORD=secret'), 'env value removed');
        $this->assertFalse(str_contains($redacted, 'user:pass'), 'dsn credentials removed');
        $this->assertFalse(str_contains($redacted, '10.1.2.3'), 'private ip removed');
    }

    public function testSecretValuesInStrings(): void
    {
        $redacted = $this->redact('the client_secret=sk_live_0123456789abcdef must not leak');
        $this->assertFalse(str_contains($redacted, 'sk_live_0123456789abcdef'), 'client secret value removed');
        $this->assertTrue(str_contains($redacted, '[redacted]'), 'mask applied');
    }

    public function testTokensInStrings(): void
    {
        $redacted = $this->redact('access_token: "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"');
        $this->assertFalse(str_contains($redacted, 'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'), 'access token value removed');
    }

    public function testDatabaseUrlsAreRedacted(): void
    {
        $redacted = $this->redact('DATABASE_URL=mysql://root:hunter2@db.internal:3306/app');
        $this->assertFalse(str_contains($redacted, 'hunter2'), 'db url password removed');
        $this->assertFalse(str_contains($redacted, 'root:hunter2'), 'db url credentials removed');
    }

    public function testDsnsAreRedacted(): void
    {
        $keyed = $this->redact(['dsn' => 'pgsql://app:s3cr3t@127.0.0.1/db']);
        $this->assertSame('[redacted]', $keyed['dsn'], 'dsn key redacted');

        $inline = $this->redact('Sentry dsn: https://abc123@o0.ingest.sentry.io/12345');
        $this->assertTrue(str_contains($inline, '[redacted]'), 'inline dsn masked');
    }

    public function testAuthorizationHeadersAreRedacted(): void
    {
        $redacted = $this->redact('Authorization: Basic dXNlcjpwYXNzd29yZA==');
        $this->assertFalse(str_contains($redacted, 'dXNlcjpwYXNzd29yZA=='), 'basic auth value removed');

        $keyed = $this->redact(['Authorization' => 'Bearer xyz']);
        $this->assertSame('[redacted]', $keyed['Authorization'], 'authorization key redacted');
    }

    public function testCookiesAreRedacted(): void
    {
        $redacted = $this->redact('Set-Cookie: session=abc123; HttpOnly');
        $this->assertFalse(str_contains($redacted, 'session=abc123'), 'cookie value removed');

        $keyed = $this->redact(['set-cookie' => 'session=abc123']);
        $this->assertSame('[redacted]', $keyed['set-cookie'], 'cookie key redacted');
    }

    public function testWebhookSecretsAreRedacted(): void
    {
        $keyed = $this->redact(['webhook_secret' => 'whsec_0123456789']);
        $this->assertSame('[redacted]', $keyed['webhook_secret'], 'webhook secret key redacted');

        $inline = $this->redact('stripe webhook_secret=whsec_live_9f8e7d6c5b4a');
        $this->assertFalse(str_contains($inline, 'whsec_live_9f8e7d6c5b4a'), 'inline webhook secret removed');
    }

    public function testPrivateFilesystemPathsAreRedacted(): void
    {
        $redacted = $this->redact('config loaded from /home/joepimms/app/storage/.env and /var/www/html/config/database.php');
        $this->assertFalse(str_contains($redacted, 'joepimms'), 'home directory user removed');
        $this->assertFalse(str_contains($redacted, '/home/'), 'home path removed');
        $this->assertFalse(str_contains($redacted, '/var/www'), 'web root path removed');

        $mac = $this->redact('/Users/joepimms/.aws/credentials');
        $this->assertFalse(str_contains($mac, 'joepimms'), 'macOS home user removed');
    }

    public function testStackTracesAreRedacted(): void
    {
        $trace = "RuntimeException: boom\nStack trace:\n#0 /var/www/app/Service.php(42): doThing()\n#1 {main}";
        $redacted = $this->redact($trace);
        $this->assertTrue(str_contains($redacted, '[stack trace redacted]'), 'stack trace collapsed');
        $this->assertFalse(str_contains($redacted, 'Service.php'), 'trace frame path removed');
        $this->assertFalse(str_contains($redacted, '{main}'), 'trace tail removed');
    }

    public function testRawEnvDumpsAreRedacted(): void
    {
        $dump = "APP_KEY=base64:Zm9vYmFyYmF6\nDB_PASSWORD=hunter2\nMAIL_PASSWORD=letmein\nAPP_ENV=production";
        $redacted = $this->redact($dump);

        $this->assertFalse(str_contains($redacted, 'base64:Zm9vYmFyYmF6'), 'app key value removed');
        $this->assertFalse(str_contains($redacted, 'hunter2'), 'db password value removed');
        $this->assertFalse(str_contains($redacted, 'letmein'), 'mail password value removed');
    }

    public function testNonSensitiveValuesArePreserved(): void
    {
        $redacted = $this->redact(['status' => 'healthy', 'uptime_seconds' => 1234, 'version' => '1.0.0']);
        $this->assertSame('healthy', $redacted['status'], 'status preserved');
        $this->assertSame(1234, $redacted['uptime_seconds'], 'numeric value preserved');
        $this->assertSame('1.0.0', $redacted['version'], 'version preserved');
    }
}
