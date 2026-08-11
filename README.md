# Connect a standalone app to Shopify

Tutorial for authenticating standalone apps using the OAuth authorization code grant flow.

**Tutorial:** [Connect a standalone app to Shopify](https://shopify.dev/docs/apps/build/authentication-authorization/connect-standalone)

## Languages

- `node/` — Node.js example
- `python/` — Python example (Flask)
- `curl/` — cURL/Bash example

## Setup

1. Copy `.env.example` to `.env` and add your credentials
2. Install dependencies:
   - Node.js: run `npm install` in the `node/` directory
   - Python (3.9 or later): create a virtual environment and install requirements:
     ```sh
     python3 -m venv .venv && source .venv/bin/activate
     pip install -r python/requirements.txt
     ```
3. Start a server from the repo root:
   - Node.js: `node node/index.js`
   - Python: `python python/main.py`
4. Open the app in your dev store

Both servers listen on port 3000, so run one at a time.

## Environment variables

| Variable | Description |
|---|---|
| `SHOPIFY_CLIENT_ID` | Your app's client ID from the Dev Dashboard. |
| `SHOPIFY_CLIENT_SECRET` | Your app's client secret from the Dev Dashboard. |
| `REDIRECT_URI` | The callback URL configured in the Dev Dashboard. |
| `SCOPES` | Comma-separated list of access scopes (for example, `read_products,write_orders`). |
| `COOKIE_SECRET` | Node.js only. Signs session cookies. Generate a long random value: `openssl rand -hex 64`. Falls back to a random secret in dev. |
| `SESSION_SECRET` | Python only. Signs the session cookie. Generate a long random value: `openssl rand -hex 64`. Falls back to a random secret in dev. |
| `NODE_ENV` | Node.js only. Set to `production` when serving over HTTPS so the cookie gets the `Secure` flag. Defaults to `development` for local HTTP. |
| `APP_ENV` | Python only. Set to `production` when serving over HTTPS so the cookie gets the `Secure` flag. Defaults to `development` for local HTTP. |

## Note

This repository is for documentation purposes. Issues and pull requests are not accepted.
