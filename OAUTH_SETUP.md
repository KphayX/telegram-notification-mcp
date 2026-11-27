# GitHub OAuth setup

The existing /mcp endpoint still uses MCP_AUTH_TOKEN. The separate /mcp-oauth endpoint requires OAuth 2.1, with GitHub identity restricted to KphayX (numeric user ID 106802443) and scope telegram:publish. Both routes share the same fixed Telegram recipient.

1. Create a GitHub OAuth App at https://github.com/settings/applications/new. Homepage: https://telegram-notification-mcp.dvson-dev.workers.dev. Authorization callback: https://telegram-notification-mcp.dvson-dev.workers.dev/callback.
2. Add GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET as Worker Secrets, not build variables. Never commit either value. The original three secrets remain unchanged.
3. Configure ChatGPT Custom MCP with https://telegram-notification-mcp.dvson-dev.workers.dev/mcp-oauth and OAuth. Client registration is dynamic or CIMD, subject to ChatGPT support.
4. Approve the displayed client and redirect host, sign in as KphayX. Do not approve an unexpected client. Access token lifetime 1 hour; refresh grant lifetime 7 days.

OAuth storage uses a dedicated KV namespace, with eventual consistency. GitHub access tokens are not persisted. OAuth is unavailable until both GitHub secrets are configured. ChatGPT plan restrictions and real end-to-end login/send are independent of a successful build.
