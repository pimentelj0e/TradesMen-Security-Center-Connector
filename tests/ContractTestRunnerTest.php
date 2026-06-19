<?php
declare(strict_types=1);
namespace Tests;
use TradesMen\SecurityCenterConnector\Testing\ContractTestRunner;
final class ContractTestRunnerTest extends TestCase
{
    public function testRunnerReportsRequiredEndpointsAndHmacVector(): void
    {
        $runner = new ContractTestRunner();
        $report = $runner->runStaticChecks(['/manifest', '/health', '/status', '/server', '/queues', '/workers', '/deployments', '/security-events', '/config-check', '/version']);

        $this->assertSame(true, $report['hmac_vector'], 'hmac vector passes');
        $this->assertSame([], $report['missing_endpoints'], 'no missing endpoints');
    }

    public function testRunnerReportsMissingEndpoint(): void
    {
        $runner = new ContractTestRunner();
        $report = $runner->runStaticChecks(['/health']);

        $this->assertTrue(in_array('/manifest', $report['missing_endpoints'], true), 'manifest missing');
        $this->assertTrue(in_array('/version', $report['missing_endpoints'], true), 'version missing');
    }
}
