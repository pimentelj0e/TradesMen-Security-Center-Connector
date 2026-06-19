<?php

declare(strict_types=1);

require __DIR__ . '/TestCase.php';

spl_autoload_register(static function (string $class): void {
    $prefix = 'TradesMen\\SecurityCenterConnector\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

$files = array_values(array_filter(glob(__DIR__ . '/*Test.php') ?: [], static fn (string $file): bool => basename($file) !== 'TestCase.php'));
sort($files);

$totalAssertions = 0;
$failures = 0;

foreach ($files as $file) {
    require $file;
    $class = 'Tests\\' . basename($file, '.php');
    $test = new $class();
    foreach (get_class_methods($test) as $method) {
        if (!str_starts_with($method, 'test')) {
            continue;
        }
        try {
            $test->{$method}();
            fwrite(STDOUT, 'PASS ' . basename($file) . '::' . $method . PHP_EOL);
        } catch (Throwable $e) {
            $failures++;
            fwrite(STDERR, 'FAIL ' . basename($file) . '::' . $method . ' - ' . $e->getMessage() . PHP_EOL);
        }
    }
    if (method_exists($test, 'assertions')) {
        $totalAssertions += $test->assertions();
    }
}

fwrite(STDOUT, "Assertions: {$totalAssertions}, Failures: {$failures}" . PHP_EOL);
exit($failures === 0 ? 0 : 1);
