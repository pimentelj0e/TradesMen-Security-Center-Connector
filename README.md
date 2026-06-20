# TradesMen Security Center Connector

Shared PHP connector core for TradesMen webapps monitored by TradesMen Security
Center.

This package is the single shared source of truth for the ecosystem's:

- HMAC signing and validation
- canonical environment names
- scope registry
- nonce / replay behaviour
- response redaction
- setup-token import/export helpers
- contract tests

It is framework-neutral. Host apps provide route wiring, request and response
objects, credential storage, nonce storage, access logging, and telemetry
adapters. **No app-specific business logic lives in this package.**

## HMAC v1 protocol

The protocol is fixed and locked by test vectors. The signed request headers are:

- `X-TSC-App-Id`
- `X-TSC-Key-Id`
- `X-TSC-Timestamp`
- `X-TSC-Nonce`
- `X-TSC-Body-SHA256`
- `X-TSC-Signature`

Canonical string (five lines, `\n`-joined):

```text
METHOD
PATH_WITH_QUERY
TIMESTAMP
NONCE
BODY_SHA256
```

Signature:

```text
base64(HMAC_SHA256(canonical_string, shared_secret))
```

> The `X-TSC-*` values are **protocol headers**, not env variables. The wire
> headers stay `X-TSC-*` and the connector token body prefix stays `tsc1_` for
> cross-app compatibility. Only the env naming is canonicalized.

Run tests:

```bash
composer test
```

## Endpoints

The connector exposes ten read endpoints under
`/api/security-center/v1/<endpoint>`, each gated by a scope:

| Endpoint           | Required scope            |
| ------------------ | ------------------------- |
| `/manifest`        | `manifest:read`           |
| `/health`          | `health:read`             |
| `/status`          | `status:read`             |
| `/server`          | `server:read`             |
| `/queues`          | `queue:read`              |
| `/workers`         | `workers:read`            |
| `/deployments`     | `deployments:read`        |
| `/security-events` | `security_summary:read`   |
| `/config-check`    | `config_check:read`       |
| `/version`         | `version:read`            |

Outbound heartbeats POST to `/api/ingest/heartbeat` on the Security Center and
require `heartbeat:write`. The canonical scope set additionally includes
`database:read` and `cache:read` for apps that expose those checks.

The reusable `ContractTestRunner` proves every host wires all ten endpoints,
keeps the HMAC vector stable, and enforces the full authentication contract
(missing/bad signature, stale timestamp, replayed nonce, insufficient scope,
disabled/revoked connector, and response redaction).

## Canonical environment configuration

The connector core reads configuration **only** from the canonical
`TRADESMEN_SECURITY_CENTER_*` names:

```dotenv
TRADESMEN_SECURITY_CENTER_CONNECTOR_ENABLED=false
TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE=managed_db
TRADESMEN_SECURITY_CENTER_APP_ID=
TRADESMEN_SECURITY_CENTER_INSTANCE=
TRADESMEN_SECURITY_CENTER_ENVIRONMENT=production
TRADESMEN_SECURITY_CENTER_ALLOWED_CLOCK_SKEW_SECONDS=300
TRADESMEN_SECURITY_CENTER_NONCE_TTL_SECONDS=300
TRADESMEN_SECURITY_CENTER_REQUIRE_IP_ALLOWLIST=false
TRADESMEN_SECURITY_CENTER_DEFAULT_ALLOWED_IPS=
TRADESMEN_SECURITY_CENTER_TRUSTED_PROXY_CIDRS=
TRADESMEN_SECURITY_CENTER_CLIENT_IP_HEADERS=
TRADESMEN_SECURITY_CENTER_ACCESS_LOG_RETENTION_DAYS=30
TRADESMEN_SECURITY_CENTER_NONCE_LOG_RETENTION_SECONDS=86400
TRADESMEN_SECURITY_CENTER_URL=
TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED=false
TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS=60
TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS=10
TRADESMEN_SECURITY_CENTER_KEY_ID=
TRADESMEN_SECURITY_CENTER_SHARED_SECRET=
TRADESMEN_SECURITY_CENTER_SCOPES=manifest:read,health:read,status:read,version:read,heartbeat:write
TRADESMEN_SECURITY_CENTER_ALLOWED_IPS=
```

The connector token wrapper is also canonical:

```dotenv
TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN=tsc1_...
```

> Never commit real `.env` values, generated secrets, or local database files.
> The values above are placeholders.

The monitored app base URL is read from `APP_URL`. The app display name is read
from `APP_NAME` (falling back to the app id).

### Connector modes

`TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE` selects how connector credentials are
stored:

- **`managed_db` — production default.** The app stores connector secrets
  **encrypted in its own database** and supplies its own
  `CredentialStoreInterface`. Use this for production deployments (e.g.
  **TradesMen Network**).
- **`env` — development fallback.** The app reads `key_id` and `shared_secret`
  directly from `.env` via `EnvCredentialStore`. Suitable for small apps and
  local development. `env` is also the safe value used when the mode is unset or
  unrecognized.

Production deployments should set
`TRADESMEN_SECURITY_CENTER_CONNECTOR_MODE=managed_db`.

### Env naming rules — no legacy aliases

`TRADESMEN_SECURITY_CENTER_*` is the **only** supported env prefix. The following
legacy names are **never read**; set the canonical names instead:

- `TSC_*`
- `SECURITY_CENTER_*`
- `SECURITY_CENTER_API_KEY`
- `SECURITY_CENTER_TOKEN`
- `FEATURE_SECURITY_CENTER_API`

Additional rules:

- `app_id` (`TRADESMEN_SECURITY_CENTER_APP_ID`) is the canonical app slug only,
  e.g. `tradesmen-tools`.
- `instance` (`TRADESMEN_SECURITY_CENTER_INSTANCE`) carries the deployment
  identity, e.g. `production`, `staging`, `rpi5-dev`, or `vps1`. Legacy
  `APP_INSTANCE` is not read.

## Security Center import flow

The setup token is the hand-off artifact between an app and the Security Center.

1. **Export (app side).** `ConnectorTokenFactory::issue()` encodes a payload into
   a `tsc1_` token wrapped as
   `TRADESMEN_SECURITY_CENTER_CONNECTOR_TOKEN=tsc1_...`. The payload carries:
   `app_id`, `app_name`, `base_url`, `environment`, `instance`,
   `connector_mode`, `key_id`, the shared secret **once**, `scopes`,
   `allowed_ips`, `connector_version`, `issued_at`, and `expires_at`.
2. **Import (Security Center side).** `ConnectorTokenImporter::import()` decodes
   and validates the token before registering the connector. It rejects, with an
   operator-safe error code and **without ever echoing the secret**:
   - malformed tokens
   - expired tokens
   - duplicate key ids (already registered)
   - legacy tokens (non-`tsc1_` body or a legacy env wrapper)
   - tokens missing `app_id`
   - tokens missing the shared secret
   - tokens with empty or non-canonical scopes
   - tokens with an invalid connector mode

The shared secret travels in the token exactly once, at issue time, and is then
stored by whichever side owns credentials for the chosen connector mode.

## Heartbeat flow

When `TRADESMEN_SECURITY_CENTER_HEARTBEAT_ENABLED=true`, the app periodically
posts a signed heartbeat to the Security Center:

1. The host schedules a heartbeat every
   `TRADESMEN_SECURITY_CENTER_HEARTBEAT_INTERVAL_SECONDS`.
2. `HeartbeatClient::sendFromConfig()` reads `TRADESMEN_SECURITY_CENTER_URL`, the
   app id, and the signing credential, then POSTs the payload to
   `/api/ingest/heartbeat` signed with the HMAC v1 protocol, timing out after
   `TRADESMEN_SECURITY_CENTER_HEARTBEAT_TIMEOUT_SECONDS`.
3. The shared secret is used **only to sign** — it never appears in the payload.

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
