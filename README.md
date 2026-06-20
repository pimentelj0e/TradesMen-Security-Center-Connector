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

## Canonical environment configuration

The universal connector core reads configuration from the environment using the
canonical `TRADESMEN_SECURITY_CENTER_*` names:

```dotenv
TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED=false
TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE=env
TRADESMEN_SECURITY_CENTER_APP_ID=
TRADESMEN_SECURITY_CENTER_INSTANCE=
TRADESMEN_SECURITY_CENTER_ENVIRONMENT=production
TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS=300
TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS=300
TRADESMEN_SECURITY_CENTER_KEY_ID=
TRADESMEN_SECURITY_CENTER_SHARED_SECRET=
TRADESMEN_SECURITY_CENTER_SCOPES=manifest:read,health:read,status:read,version:read,heartbeat:write
TRADESMEN_SECURITY_CENTER_ALLOWED_IPS=
TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST=false
TRADESMEN_SECURITY_CENTER_URL=
TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED=false
TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS=60
TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS=10
```

The connector token wrapper is also canonicalized:

```dotenv
TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN=tsc1_...
```

> Never commit real `.env` values, generated secrets, or local database files.
> The values above are placeholders.

### Connector modes

`TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE` selects how connector credentials are
stored:

- **`managed_db`** — the app stores connector secrets **encrypted in its own
  database**. The host app supplies its own `CredentialStoreInterface`.
  **TradesMen Network should use `managed_db`.**
- **`env`** — the app reads `key_id` and `shared_secret` directly from `.env`
  via `EnvCredentialStore`. Suitable for **small apps** and local development.

`env` is the default. Apps that need managed credentials (such as Network)
override the mode to `managed_db`.

### Env naming rules

- `TRADESMEN_SECURITY_CENTER_*` is the **only** supported env prefix. The legacy
  `TSC_*` and `SECURITY_CENTER_*` names are no longer read — set the canonical
  names instead.
- `app_id` (`TRADESMEN_SECURITY_CENTER_APP_ID`) is the canonical app slug only,
  e.g. `tradesmen-tools`.
- `instance` (`TRADESMEN_SECURITY_CENTER_INSTANCE`) is where the deployment
  identity goes, e.g. `production`, `staging`, `rpi5-dev`, or `vps1`.

The monitored app base URL is read from `APP_URL`.

**Important:** the `X-TSC-*` values are **protocol headers**, not env variables.
The signed HTTP protocol is unchanged — the wire headers remain `X-TSC-*` and the
connector token body prefix remains `tsc1_` for cross-app compatibility. Only the
env naming changed.

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
