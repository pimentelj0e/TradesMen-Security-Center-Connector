<?php
declare(strict_types=1);
namespace TradesMen\SecurityCenterConnector\Contracts;
interface ConnectorConfigInterface
{
    public function appId(): string;
    public function appName(): string;
    public function environment(): string;
    public function connectorVersion(): string;
    public function enabled(): bool;
    public function signatureTtlSeconds(): int;
    public function nonceTtlSeconds(): int;
    public function baseUrl(): string;
    public function securityCenterUrl(): string;
}
