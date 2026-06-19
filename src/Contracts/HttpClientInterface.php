<?php

declare(strict_types=1);

namespace TradesMen\SecurityCenterConnector\Contracts;

interface HttpClientInterface
{
    /** @return array{status:int,body:string,error?:string} */
    public function postJson(string $url, array $headers, string $jsonBody, int $timeoutSeconds): array;
}
