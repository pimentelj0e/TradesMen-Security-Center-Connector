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

### Backward-compatible aliases

The old names remain supported so existing apps keep working. Resolution order
is always: canonical first, then `TSC_*`, then a documented app-specific legacy
alias.

| Canonical (`TRADESMEN_SECURITY_CENTER_*`) | `TSC_*` alias | Legacy app alias |
| --- | --- | --- |
| `…_CONNECTOR_ENABLED` | `TSC_CONNECTOR_ENABLED` | `SECURITY_CENTER_CONNECTOR_ENABLED` |
| `…_APP_ID` | `TSC_APP_ID` | `SECURITY_CENTER_APP_ID` |
| `…_INSTANCE` | `TSC_INSTANCE` | `APP_INSTANCE` |
| `…_ENVIRONMENT` | `TSC_ENVIRONMENT` | `APP_ENV` |
| `…_ALLOWED_CLOCK_SKEW_SECONDS` | `TSC_ALLOWED_CLOCK_SKEW_SECONDS` | `SECURITY_CENTER_SIGNATURE_TTL_SECONDS` |
| `…_NONCE_TTL_SECONDS` | `TSC_NONCE_TTL_SECONDS`, `TSC_CONNECTOR_NONCE_TTL_SECONDS` | `SECURITY_CENTER_NONCE_TTL_SECONDS`, `SECURITY_CENTER_NONCE_RETENTION_MINUTES` (minutes → seconds) |
| `…_KEY_ID` | `TSC_KEY_ID` | — |
| `…_SHARED_SECRET` | `TSC_SHARED_SECRET` | — |
| `…_SCOPES` | `TSC_SCOPES` | — |
| `…_ALLOWED_IPS` | `TSC_ALLOWED_IPS` | `SECURITY_CENTER_DEFAULT_ALLOWED_IPS` |
| `…_REQUIRE_IP_ALLOWLIST` | `TSC_REQUIRE_IP_ALLOWLIST` | `SECURITY_CENTER_REQUIRE_IP_ALLOWLIST` |
| `…_URL` | `TSC_SECURITY_CENTER_URL` | `SECURITY_CENTER_HEARTBEAT_URL` |
| `…_HEARTBEAT_ENABLED` | `TSC_HEARTBEAT_ENABLED` | `SECURITY_CENTER_HEARTBEAT_ENABLED` |
| `…_HEARTBEAT_INTERVAL_SECONDS` | `TSC_HEARTBEAT_INTERVAL_SECONDS` | `SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS` |
| `…_HEARTBEAT_TIMEOUT_SECONDS` | `TSC_HEARTBEAT_TIMEOUT_SECONDS` | `SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS` |
| `…_CONNECTOR_TOKEN` | `TSC_CONNECTOR_TOKEN` | — |

The monitored app base URL is read from `APP_URL`.

**Important:** the old `TSC_*` and `SECURITY_CENTER_*` names are **env aliases
only**. The signed HTTP protocol is unchanged — the wire headers remain
`X-TSC-*` and the connector token body prefix remains `tsc1_` for cross-app
compatibility.

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
