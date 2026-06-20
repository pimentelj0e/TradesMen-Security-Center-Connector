<?php

declare(strict_types=1);

namespace Tests;

use TradesMen\SecurityCenterConnector\Auth\IpAllowlistValidator;

final class IpAllowlistValidatorTest extends TestCase
{
    public function testSingleIpv4Match(): void
    {
        $v = new IpAllowlistValidator();
        $this->assertTrue($v->isAllowed('203.0.113.10', ['203.0.113.10'], true), 'exact IPv4 allowed');
        $this->assertFalse($v->isAllowed('203.0.113.11', ['203.0.113.10'], true), 'different IPv4 denied');
    }

    public function testSingleIpv6Match(): void
    {
        $v = new IpAllowlistValidator();
        $this->assertTrue($v->isAllowed('2001:db8::1', ['2001:0db8:0000::1'], true), 'normalized IPv6 allowed');
        $this->assertFalse($v->isAllowed('2001:db8::2', ['2001:db8::1'], true), 'different IPv6 denied');
    }

    public function testCommaAndSpaceSeparatedList(): void
    {
        $v = new IpAllowlistValidator();
        $list = ['203.0.113.10, 198.51.100.5   192.0.2.1'];
        $this->assertTrue($v->isAllowed('198.51.100.5', $list, true), 'value found in mixed-delimiter list');
        $this->assertTrue($v->isAllowed('192.0.2.1', $list, true), 'space-separated value found');
        $this->assertFalse($v->isAllowed('10.0.0.1', $list, true), 'value not in list denied');
    }

    public function testIpv4Cidr(): void
    {
        $v = new IpAllowlistValidator();
        $this->assertTrue($v->isAllowed('198.51.100.42', ['198.51.100.0/24'], true), 'IPv4 inside /24 allowed');
        $this->assertFalse($v->isAllowed('198.51.101.1', ['198.51.100.0/24'], true), 'IPv4 outside /24 denied');
        $this->assertTrue($v->isAllowed('10.1.2.3', ['10.0.0.0/8'], true), 'IPv4 inside /8 allowed');
        $this->assertFalse($v->isAllowed('11.0.0.1', ['10.0.0.0/8'], true), 'IPv4 outside /8 denied');
    }

    public function testIpv6Cidr(): void
    {
        $v = new IpAllowlistValidator();
        $this->assertTrue($v->isAllowed('2001:db8:abcd:1234::1', ['2001:db8::/32'], true), 'IPv6 inside /32 allowed');
        $this->assertFalse($v->isAllowed('2001:db9::1', ['2001:db8::/32'], true), 'IPv6 outside /32 denied');
    }

    public function testMixedFamilyDoesNotMatch(): void
    {
        $v = new IpAllowlistValidator();
        $this->assertFalse($v->isAllowed('203.0.113.10', ['2001:db8::/32'], true), 'IPv4 client vs IPv6 CIDR denied');
        $this->assertFalse($v->isAllowed('2001:db8::1', ['203.0.113.0/24'], true), 'IPv6 client vs IPv4 CIDR denied');
    }

    public function testEmptyAllowlistBehaviour(): void
    {
        $v = new IpAllowlistValidator();
        $this->assertTrue($v->isAllowed('203.0.113.10', [], false), 'empty list + not required allows all');
        $this->assertFalse($v->isAllowed('203.0.113.10', [], true), 'empty list + required denies all');
    }

    public function testInvalidClientIpDenied(): void
    {
        $v = new IpAllowlistValidator();
        $this->assertFalse($v->isAllowed('not-an-ip', ['203.0.113.0/24'], true), 'invalid client ip denied');
        $this->assertFalse($v->isAllowed(null, ['203.0.113.0/24'], true), 'null client ip denied');
    }
}
