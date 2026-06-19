<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Contracts;
interface ClockInterface
{
    public function now(): int;
}
