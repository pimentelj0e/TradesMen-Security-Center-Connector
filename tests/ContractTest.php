<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Testing\ContractTestRunner;

/**
 * Exercises the reusable {@see ContractTestRunner} behavioural contract suite so
 * the shared core's protocol enforcement is locked in one place.
 */
final class ContractTest extends TestCase
{
    public function testAllProtocolChecksPass(): void
    {
        $checks = (new ContractTestRunner())->runProtocolChecks();

        foreach ($checks as $name => $passed) {
            $this->assertTrue($passed, 'protocol contract check passes: ' . $name);
        }
    }

    public function testProtocolChecksCoverRequiredCases(): void
    {
        $checks = (new ContractTestRunner())->runProtocolChecks();

        foreach ([
            'valid_request',
            'missing_signature',
            'bad_signature',
            'expired_timestamp',
            'replayed_nonce',
            'insufficient_scope',
            'disabled_connector',
            'revoked_connector',
            'redaction',
        ] as $case) {
            $this->assertArrayHasKey($case, $checks, 'contract suite includes case: ' . $case);
        }
    }

    public function testRunReportsPassWhenEndpointsRegistered(): void
    {
        $report = (new ContractTestRunner())->run(ContractTestRunner::REQUIRED_ENDPOINTS);

        $this->assertTrue($report['passed'], 'full contract report passes with all endpoints registered');
        $this->assertSame([], $report['missing_endpoints'], 'no missing endpoints');
        $this->assertTrue($report['hmac_vector'], 'hmac vector stable');
    }

    public function testRunFailsWhenEndpointsMissing(): void
    {
        $report = (new ContractTestRunner())->run(['/health']);

        $this->assertFalse($report['passed'], 'report fails when endpoints are missing');
        $this->assertTrue(in_array('/manifest', $report['missing_endpoints'], true), 'manifest reported missing');
    }

    public function testAllTenRequiredEndpointsAreListed(): void
    {
        $this->assertSame(10, count(ContractTestRunner::REQUIRED_ENDPOINTS), 'exactly ten required endpoints');
        foreach ([
            '/manifest', '/health', '/status', '/server', '/queues',
            '/workers', '/deployments', '/security-events', '/config-check', '/version',
        ] as $endpoint) {
            $this->assertContains($endpoint, ContractTestRunner::REQUIRED_ENDPOINTS, 'endpoint required: ' . $endpoint);
        }
    }
}
