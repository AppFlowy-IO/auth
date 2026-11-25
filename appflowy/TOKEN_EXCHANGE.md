# Delegated Entra access for a backend

A dashboard can exchange a signed-in user's delegated Entra access token at GoTrue's
`POST /token` (public AppFlowy path `/gotrue/token`). Each response authorizes one
resource API and identifies both the GoTrue user and the dashboard client. The grant is
disabled by default. A resource API must implement the validation described below before
its operator enables exchange. Existing AppFlowy workspace APIs need that consumer change.

## Configure the installation

1. Register the downstream API in the customer's Microsoft Entra workforce tenant and
   expose delegated scopes, for example `data.read` and `data.write`. Configure v2 access
   tokens and consent the dashboard to the scopes it needs. A middle-tier dashboard API
   obtains a user token for the resource through Entra's On-Behalf-Of flow. A server-side
   web app can acquire it using its user token cache.
   [Microsoft delegation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
2. Configure an enabled GoTrue custom OIDC provider for the same tenant-specific v2 issuer.
   The user must already have an email-confirmed GoTrue account linked through that provider.
   Exchange resolves the signed tenant and object IDs against the verified data on that
   provider identity. It rejects absent or ambiguous links, including email-only and
   SCIM-only accounts. An existing user can establish the link through normal OIDC sign-in.
3. Set the following on GoTrue and restart it. Leave `GOTRUE_TOKEN_EXCHANGE_CLIENTS`
   empty the first time: an enabled installation with no clients refuses every exchange
   and opens the admin client registry used in the next step.

   | Setting | Value |
   | --- | --- |
   | `GOTRUE_TOKEN_EXCHANGE_ENABLED` | `true` |
   | `GOTRUE_TOKEN_EXCHANGE_TENANT_ID` | Customer's lowercase Entra tenant UUID |
   | `GOTRUE_TOKEN_EXCHANGE_PROVIDER` | Enabled OIDC provider identifier, e.g. `custom:entra` |
   | `GOTRUE_TOKEN_EXCHANGE_CLIENTS` | JSON keyed by the GoTrue client UUID, as shown in step 4. Empty until the first backend is registered. |
   | `GOTRUE_TOKEN_EXCHANGE_SIGNING_KEYS` | JSON array of dedicated ES256 P-256 JWKs with unique nonempty `kid` values. Give the active private key `"alg":"ES256","key_ops":["sign"]`. Supply older public keys with `"key_ops":["verify"]` during rotation. |
   | `GOTRUE_TOKEN_EXCHANGE_RATE_LIMIT` | Optional. Sustained requests per five minutes per authenticated client per GoTrue process. Defaults to 150, with a burst of 30. |
   | `GOTRUE_TOKEN_EXCHANGE_MAX_CONCURRENT` | Optional. Simultaneous exchanges per GoTrue process. Defaults to 8. |

4. Register each backend as a confidential GoTrue OAuth client using
   `POST /admin/oauth/clients` with `token_endpoint_auth_method=client_secret_basic` and
   a GoTrue admin token. Registration requires a redirect URI, so supply a
   dashboard-owned HTTPS callback. Store the generated secret in the dashboard backend,
   name the returned client ID in `GOTRUE_TOKEN_EXCHANGE_CLIENTS`, and restart GoTrue.
   The sample IDs illustrate the three distinct registrations. Each additional dashboard
   gets its own map entry.

   ```json
   {
     "11111111-1111-4111-8111-111111111111": {
       "entra_client_id": "22222222-2222-4222-8222-222222222222",
       "audience": "33333333-3333-4333-8333-333333333333",
       "scopes": ["data.read", "data.write"]
     }
   }
   ```

   `entra_client_id` is the calling dashboard application's Entra ID (`azp`).
   `audience` is the Entra application ID of the downstream API (`aud`). The verifier
   uses the public Microsoft cloud's tenant-specific signing keys. Tenant-independent,
   sovereign-cloud, v1 and app-only tokens are outside this profile.

Token exchange needs the client registry and none of the OAuth server's authorization
endpoints. Leave `GOTRUE_OAUTH_SERVER_ENABLED` unset unless the installation uses that
server for another purpose: with it on, a registered client can send a user through
`/oauth/authorize` and receive an ordinary login token, which a resource API that checks
only the login signature and session treats as a full session.

For large directories, check the identity lookup plan before rollout. GoTrue's default
indexes do not cover Entra object IDs. This optional partial index lets PostgreSQL look
up the existing OIDC identity by provider, tenant and object ID. Use the installation's
auth schema and run the statement outside a transaction.

```sql
CREATE INDEX CONCURRENTLY identities_entra_object_idx ON auth.identities
  (provider, (identity_data #>> '{custom_claims,tid}'),
             (identity_data #>> '{custom_claims,oid}'))
  WHERE (identity_data #>> '{custom_claims,oid}') IS NOT NULL;
```

## Exchange a token

Send HTTP Basic authentication with the registered GoTrue client ID and secret over
HTTPS. Use a form-encoded body with these fields.

| Field | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token` |
| `subject_token` | The Entra delegated access token for the API |
| `audience` | Optional. Defaults to the client's registered target |
| `scope` | Optional space-separated subset of authorized scopes. By default GoTrue grants the intersection of the client's configuration and Entra's `scp` |

The backend receives `access_token`, `issued_token_type`, `token_type`, `scope` and
`expires_in`. Cache it server-side by user, client, audience and scopes. Renew by
presenting valid Entra delegation. Exchange issues no refresh credential. Token lifetime
is bounded by five minutes, the upstream expiry, and any shorter GoTrue JWT or session
timebox limit. Exchange rate and concurrency limits apply independently of normal sign-ins
and token refreshes.

## Resource API contract

Fetch public keys from the configured GoTrue URL at `/.well-known/token-exchange-jwks.json`
(under `/gotrue` with AppFlowy's reverse proxy). Validate ES256, `typ=at+jwt`, the signature,
the exact public GoTrue issuer (`API_EXTERNAL_URL` with any trailing slash removed), the
resource's audience, and expiry. Enforce the requested action's scope, then apply normal
permissions to the GoTrue UUID in `sub`. Record `client_id` alongside the user for audit.
The interactive-login JWKS and the exchange JWKS have independent keys.

Use `session_id` to check the live GoTrue session, including its owner, client, scopes,
`not_after`, and user ban. Offline signature verification alone only bounds revocation by
the token expiry. Refreshes of the same active grant reuse the session. After the session
ends, a new exchange gets a new session ID. Removing a client registration or disabling its
OIDC provider stops new issuance. Revoke existing sessions as well when immediate removal
is required. Retain previous public signing keys until tokens signed with them have expired.
