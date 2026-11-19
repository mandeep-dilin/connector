# cPanel connector for Claude

Lets Claude manage one cPanel account: website files, domains, databases, git, and read emails (read-only).
Runs as a Node app in the user's own cPanel (AI App Hosting).

## Deploy
- Build command: `npm install`
- Startup command: `npm run start`

## Environment variables
| Name | Example | Needed |
|---|---|---|
| CONNECTOR_SECRET | 40 random letters/numbers | yes (min 24) |
| CPANEL_USER | masvrlogs1 | yes |
| CPANEL_TOKEN | (from Manage API Tokens) | yes |
| CPANEL_URL | https://localhost:2083 | optional |
| ALLOW_WRITES | true / false | optional (default true) |
| MAIL_USER | test@yourdomain.com | for email |
| MAIL_PASSWORD | mailbox password | for email |
| MAIL_HOST / MAIL_PORT | localhost / 993 | optional |

## Connect to Claude
Settings -> Connectors -> Add custom connector -> URL:
`https://<your-domain>/mcp/<CONNECTOR_SECRET>`

Anyone with this URL can use the connector. Keep it private.

## Check
`https://<your-domain>/health` shows what is configured (no secrets).
