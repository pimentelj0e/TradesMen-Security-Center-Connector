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

## Local path repository usage

During rollout, a sibling app repo can consume this package with a Composer path
repository.

For a root PHP app:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "../TradesMen-Security-Center-Connector",
      "options": { "symlink": true }
    }
  ],
  "require": {
    "tradesmen/security-center-connector": "dev-main"
  }
}
```

For backend subdirectories such as `TradesMen-Tools/backend`, use:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "../../TradesMen-Security-Center-Connector",
      "options": { "symlink": true }
    }
  ],
  "require": {
    "tradesmen/security-center-connector": "dev-main"
  }
}
```
