# TradesMen Security Center Connector

Shared PHP connector core for TradesMen webapps monitored by TradesMen Security
Center.

This package implements the official TSC HMAC v1 protocol:

- `X-TSC-App-Id`
- `X-TSC-Key-Id`
- `X-TSC-Timestamp`
- `X-TSC-Nonce`
- `X-TSC-Body-SHA256`
- `X-TSC-Signature`

Canonical string:

```text
METHOD
PATH_WITH_QUERY
TIMESTAMP
NONCE
BODY_SHA256
```

Signature:

```text
base64(HMAC_SHA256(canonical, shared_secret))
```

The package is framework-neutral. Host apps provide route wiring, request and
response objects, credential storage, nonce storage, access logging, and
telemetry adapters.

Run tests:

```bash
composer test
```
