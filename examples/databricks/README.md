# Databricks (per-user OAuth U2M), egress-locked to SQL

Warehouse access is a primary agent use case. The built-in `databricks()` provider brokers a
**per-user** Databricks credential (OAuth U2M) and, by default, locks the injected token to the
**SQL Statement Execution API** — nothing else on the workspace.

## Why per-user matters here

Because the agent acts **as the connected human**, Unity Catalog governance applies to *that person*
automatically: column masks, row filters, and grants are enforced by Databricks per identity. A shared
bot token would flatten everyone to one principal and defeat that. Tags alone enforce nothing —
policies, masks, and grants do; per-user connection is what makes them bite.

> Governance is Databricks' job. Vouchr's job is to make sure the agent uses *your* identity and
> can't wander off the statements API with it.

## The egress lock

`databricks({ host, clientId })` ships these defaults:

- `egressAllow`: your workspace hostname only.
- `egressPaths`: `['/api/2.0/sql/statements']` — this one prefix covers both `POST …/statements`
  (submit) and `GET …/statements/<id>` (poll/cancel). Jobs, secrets, DBFS, SCIM, and workspace admin
  are **denied** by default.
- `egressMethods`: `['GET', 'POST']`. POST is required to submit a statement, so a broker fronting
  this provider needs `allowWrites` on plus these methods for the submit path; GET alone only polls.

Need more surface? Widen `egressPaths` explicitly — the default is deliberately minimal:

```ts
databricks({ host, clientId, egressPaths: ['/api/2.0/sql/statements', '/api/2.1/jobs/'] })
```

## Client shapes

- **Public** (PKCE-only, no secret): `databricks({ host, clientId })`.
- **Confidential** (custom OAuth app with a secret): `databricks({ host, clientId, clientSecret })`.

Both use PKCE. `all-apis` is the U2M scope for calling workspace APIs as the user; `offline_access`
yields a refresh token so connections outlive the ~1h access token (Vouchr refreshes on demand).

## Run

```bash
export SLACK_BOT_TOKEN=… SLACK_SIGNING_SECRET=… PUBLIC_URL=https://<ngrok>.app
export DATABRICKS_HOST=https://<workspace>.cloud.databricks.com
export DATABRICKS_CLIENT_ID=…            # + DATABRICKS_CLIENT_SECRET for a confidential app
export DATABRICKS_WAREHOUSE_ID=…
node --import tsx examples/databricks/app.ts
```

Then `@your-app run a query` in Slack → a private Connect prompt → after connecting, the agent runs
`SELECT current_user()` as you. The offline-mocked behavior (URL construction, the public/confidential
token exchange, and the egress lock rejecting non-statements paths) is proven in
[`test/databricks.test.ts`](../../test/databricks.test.ts).
