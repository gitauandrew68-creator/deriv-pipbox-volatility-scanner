# Deriv AI + PipBox-Style Volatility Scanner — Public Build

This project preserves the existing V2.1 Digit Transition Mesh, signal-scoring, contract-family selection, and paper-verification logic. The update only clarifies the public OAuth setup flow so visitors are never asked to type an ID into the scanner page.

## What's in the build

- Public market data uses Deriv's documented no-auth Options WebSocket: `wss://api.derivws.com/trading/v1/options/ws/public`.
- Connect uses the same browser tab to redirect to Deriv OAuth, then returns to `/callback`.
- OAuth uses state validation and PKCE; token exchange happens on the server. Tokens are kept in server memory and are not embedded in `index.html`.
- Opening the scanner starts a fresh scanner-side session. This does not sign the user out of Deriv itself; if Deriv keeps their existing web login, they may need to sign out on Deriv before authorizing a different identity.
- Trading remains DISARMED on load. To send any order, the user must authorize Deriv, select the correct account type and account, and explicitly arm execution. Real account execution is never armed by default.
- If the OAuth app is not configured yet, the public page tells visitors that setup belongs to the site owner. It does not ask them to paste an account ID, API token, password, or auth code.

## Deploy to Render (public HTTPS site)

1. Put `server.py`, `index.html`, `render.yaml`, and `.gitignore` at the root of a GitHub repository.
2. In Render, create a new Blueprint from that repository and apply the `render.yaml` configuration.
3. Wait for the first deploy, then copy the service's exact public HTTPS URL, e.g. `https://YOUR-SERVICE.onrender.com`.
4. In the Deriv developer dashboard, register an OAuth 2.0 application with this exact redirect URL: `https://YOUR-SERVICE.onrender.com/callback`. The callback must match exactly.
5. In Render → the service → Environment, set `DERIV_CLIENT_ID` to the OAuth Client ID from that Deriv developer app. Optionally set `DERIV_REDIRECT_URI` to the same full callback URL, including `/callback`, to make it explicit. Save and redeploy.
6. Open the public HTTPS URL. Public scanning should be usable without connecting an account. Click **Connect Deriv with OAuth** to be redirected to Deriv itself; after approval, Deriv returns to the scanner.
7. Verify `https://YOUR-SERVICE.onrender.com/health` returns JSON with `"ok": true`. Test the market-data WebSocket and OAuth in the browser before arming any execution.

The site owner needs to configure the OAuth app once, but visitors do not enter any app/account ID into the website. OAuth needs a registered client and an exact HTTPS redirect URI; these are required by Deriv's OAuth flow.

## Local smoke-test mode

Python 3.10+ is sufficient; the server uses only the Python standard library. Local mode opens `http://localhost:8000/`. For local OAuth, register `http://localhost:8000/callback` in the Deriv OAuth app and complete the one-time local setup. Public production mode uses Render environment variables instead and never writes a public shared Client ID to `config.json`.

## Limits / truthful status

Local syntax and HTTP route smoke tests can be run on the code bundle. Live Deriv WebSocket connectivity, actual OAuth consent, account listing and contract execution must be verified against the live hosted service. A Deriv/Cloudflare “unusual activity” security block can only be resolved with Deriv Support; this project does not bypass it. Scanner output and historical paper results are not guarantees of future profit.