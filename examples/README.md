# Examples

Each directory is a runnable or copyable example. Each one has its own README.

- [`bolt-github/`](./bolt-github): the main demo. A Bolt app answers `@vouchr who am I on github?` as the person who asked.
- [`dry-run/`](./dry-run): run your real Vouchr wiring with no network calls. Needs only a local PostgreSQL.
- [`google-user/`](./google-user): the agent acts as the person who asked on a Google API.
- [`databricks/`](./databricks): per-user Databricks OAuth, with the token locked to the SQL Statement Execution API.
- [`multi-provider-agent/`](./multi-provider-agent): one agent, several providers, each person acting as themselves.
- [`internal-api-key/`](./internal-api-key): each person supplies their own static API key for an internal service.
- [`aws-secrets-manager/`](./aws-secrets-manager): store a reference to an AWS Secrets Manager secret. Vouchr fetches it just in time and never stores it.
- [`azure-key-vault/`](./azure-key-vault): the same reference pattern for an Azure Key Vault secret.
- [`gcp-secret-manager/`](./gcp-secret-manager): the same reference pattern for a GCP Secret Manager secret version.
- [`hashicorp-vault/`](./hashicorp-vault): the same reference pattern for a HashiCorp Vault KV v2 field.
- [`postgres-kms/`](./postgres-kms): production template with PostgreSQL and AWS KMS envelope encryption.
- [`broker-client/`](./broker-client): the headless broker's two roles, trusted minter and agent worker, in TypeScript.
- [`python-client/`](./python-client): the broker worker in Python, standard library only.
- [`mcp-gateway/`](./mcp-gateway): Vouchr as the credential and policy layer in front of an MCP tool call.
- [`prometheus/`](./prometheus): turn Vouchr's event hook into Prometheus metrics with no extra dependency.
- [`scim/`](./scim): revoke a person's connections in every workspace when they are removed from the organisation.

The Slack app manifests the [quickstart](../QUICKSTART.md) uses are `slack-manifest.bootstrap.yml`
(create the app) and `slack-manifest.yml` (the finished app). `channel-tool-manifest.ts` shows a
per-channel tool manifest that mixes tools acting as a person with service-to-service tools.
