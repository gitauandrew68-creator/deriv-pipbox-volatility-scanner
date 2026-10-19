#!/usr/bin/env python3
"""Deriv PipBox-style scanner with OAuth and explicitly armed account trading.

OAuth access tokens remain server-side in memory. The browser can request a
short-lived, single-use Deriv WebSocket OTP only for an authorized account.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import secrets
import time
import webbrowser
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
CONFIG = ROOT / "config.json"
PUBLIC_DEPLOY = os.getenv("PUBLIC_DEPLOY", "0").strip() == "1"
# Local launches deliberately ignore inherited HOST/PORT values, which can
# otherwise make the browser open :8000 while the server binds elsewhere.
PORT = int(os.getenv("PORT", "8000")) if PUBLIC_DEPLOY else 8000
HOST = os.getenv("HOST", "0.0.0.0") if PUBLIC_DEPLOY else "127.0.0.1"
LOCAL_REDIRECT_URI = f"http://localhost:{PORT}/callback"
SESSION_COOKIE = "deriv_scanner_session"
AUTH_URL = "https://auth.deriv.com/oauth2/auth"
TOKEN_URL = "https://auth.deriv.com/oauth2/token"
API_BASE = "https://api.derivws.com"

# This is intentionally in-memory: tokens are not written to the page, config, or logs.
sessions: dict[str, dict[str, Any]] = {}
pending_oauth: dict[str, dict[str, Any]] = {}


def load_config() -> tuple[str, str, str]:
    """Load OAuth settings safely for local or public-hosted deployments.

    Public deployments must use environment variables for the Client ID and must
    never let visitors overwrite the application's shared OAuth configuration.
    """
    cfg: dict[str, Any] = {}
    if not PUBLIC_DEPLOY and CONFIG.exists():
        try:
            loaded = json.loads(CONFIG.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg = loaded
        except (OSError, json.JSONDecodeError):
            cfg = {}

    client_id = os.getenv("DERIV_CLIENT_ID", "").strip()
    if not PUBLIC_DEPLOY and not client_id:
        client_id = str(cfg.get("client_id", "")).strip()

    # Local OAuth always uses the stable localhost:8000 callback. The prior
    # launcher could silently select :8001 while config.json still pointed to
    # :8000, causing Deriv to return to the wrong process. On a local run, keep
    # callback configuration deterministic and preserve only the saved Client ID/scopes.
    if PUBLIC_DEPLOY:
        public_base = (os.getenv("PUBLIC_BASE_URL", "").strip()
                       or os.getenv("RENDER_EXTERNAL_URL", "").strip()).rstrip("/")
        redirect_uri = os.getenv("DERIV_REDIRECT_URI", "").strip()
        if not redirect_uri and public_base:
            redirect_uri = public_base + "/callback"
    else:
        redirect_uri = LOCAL_REDIRECT_URI

    scopes = os.getenv("DERIV_SCOPES", "").strip()
    if not scopes and not PUBLIC_DEPLOY:
        scopes = str(cfg.get("scopes", "trade")).strip()
    return client_id, redirect_uri, scopes or "trade"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def new_verifier() -> str:
    # 64 random bytes generate a verifier within OAuth's permitted 43–128 char range.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(alphabet[b % len(alphabet)] for b in secrets.token_bytes(64))


def challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def save_config(client_id: str, scopes: str) -> None:
    if PUBLIC_DEPLOY:
        raise RuntimeError("On public hosting, set DERIV_CLIENT_ID in the hosting environment settings.")
    safe_scopes = " ".join(x for x in scopes.split() if x in {"trade", "account_manage", "application_read", "payment"})
    if not safe_scopes:
        safe_scopes = "trade"
    _, redirect_uri, _ = load_config()
    payload = {
        "client_id": client_id.strip(),
        "redirect_uri": redirect_uri or LOCAL_REDIRECT_URI,
        "scopes": safe_scopes,
    }
    CONFIG.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def get_cookie(handler: BaseHTTPRequestHandler, name: str) -> str | None:
    cookie = SimpleCookie()
    try:
        cookie.load(handler.headers.get("Cookie", ""))
    except Exception:
        return None
    item = cookie.get(name)
    return item.value if item else None


def current_session(handler: BaseHTTPRequestHandler) -> tuple[str | None, dict[str, Any] | None]:
    sid = get_cookie(handler, SESSION_COOKIE)
    return (sid, sessions.get(sid)) if sid else (None, None)


def json_response(handler: BaseHTTPRequestHandler, payload: Any, status: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def html_response(handler: BaseHTTPRequestHandler, content: str, status: int = 200) -> None:
    body = content.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def redirect(handler: BaseHTTPRequestHandler, location: str, cookie: str | None = None) -> None:
    handler.send_response(HTTPStatus.FOUND)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    if cookie:
        handler.send_header("Set-Cookie", cookie)
    handler.end_headers()


def api_get(path: str, token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        API_BASE + path,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def api_post_empty(path: str, token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        API_BASE + path,
        data=b"",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def post_form(url: str, form: dict[str, str]) -> dict[str, Any]:
    body = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            # Identify the legitimate server-side OAuth client in upstream logs.
            # Do not spoof a browser or attempt to bypass provider security checks.
            "User-Agent": "DerivPipBoxScanner/2.1 (server-side OAuth token exchange)",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def oauth_client_secret() -> str:
    # Optional confidential-client secret. PKCE-only clients can leave this unset.
    # This value stays server-side and is never sent to the browser.
    return os.getenv("DERIV_CLIENT_SECRET", "").strip()


def with_optional_client_secret(form: dict[str, str]) -> dict[str, str]:
    secret = oauth_client_secret()
    if secret:
        form["client_secret"] = secret
    return form


def exchange_code(code: str, verifier: str, client_id: str, redirect_uri: str) -> dict[str, Any]:
    return post_form(TOKEN_URL, with_optional_client_secret({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
    }))


def refresh_access_token(session: dict[str, Any], client_id: str) -> str:
    if session.get("expires_at", 0) > time.time() + 45:
        return str(session["access_token"])
    refresh = session.get("refresh_token")
    if not refresh:
        raise RuntimeError("Deriv login expired. Press Connect Deriv and sign in again.")
    data = post_form(TOKEN_URL, with_optional_client_secret({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": str(refresh),
    }))
    access_token = data.get("access_token")
    if not access_token:
        raise RuntimeError("Deriv did not return a refreshed access token. Sign in again.")
    session["access_token"] = access_token
    session["expires_at"] = time.time() + int(data.get("expires_in", 3600))
    if data.get("refresh_token"):
        session["refresh_token"] = data["refresh_token"]
    return str(access_token)


def account_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw: Any = payload.get("data", payload.get("accounts", []))
    if isinstance(raw, dict):
        raw = raw.get("accounts", raw.get("data", []))
    if not isinstance(raw, list):
        raw = []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        loginid = str(item.get("loginid") or item.get("login_id") or item.get("account_id") or item.get("accountId") or item.get("id") or "").strip()
        account_id = str(item.get("account_id") or item.get("accountId") or item.get("id") or item.get("loginid") or item.get("login_id") or "").strip()
        if not account_id or account_id in seen:
            continue
        seen.add(account_id)
        raw_type = str(item.get("account_type") or item.get("type") or "").strip().lower()
        virtual = item.get("is_virtual", item.get("isVirtual", None))
        if isinstance(virtual, bool):
            normalized_type = "demo" if virtual else "real"
        elif any(word in raw_type for word in ("demo", "virtual", "practice")) or loginid.upper().startswith("VRTC"):
            normalized_type = "demo"
        elif "real" in raw_type or loginid.upper().startswith("CR"):
            normalized_type = "real"
        elif raw_type in {"demo", "real"}:
            normalized_type = raw_type
        else:
            # Unknown account types are never made tradable by inference.
            normalized_type = "unknown"
        balance = item.get("balance")
        # Deriv may return balances as decimal strings or numbers. Preserve the
        # returned numeric scalar; the UI formats it and never invents a value.
        if isinstance(balance, bool) or not isinstance(balance, (str, int, float)) or str(balance).strip() == "":
            balance = None
        rows.append({
            "account_id": account_id,
            "loginid": loginid or account_id,
            "account_type": normalized_type,
            "currency": str(item.get("currency") or "USD").strip().upper(),
            "balance": balance,
            "is_virtual": virtual if isinstance(virtual, bool) else (normalized_type == "demo" if normalized_type != "unknown" else None),
        })
    return rows


def oauth_exchange_error_message(exc: urllib.error.HTTPError) -> str:
    """Summarize OAuth endpoint errors without showing provider HTML."""
    content_type = (exc.headers.get("Content-Type", "") if exc.headers else "").lower()
    request_id = ""
    if exc.headers:
        request_id = (exc.headers.get("cf-ray") or exc.headers.get("x-request-id")
                      or exc.headers.get("request-id") or "")
    suffix = f" Reference: {request_id}." if request_id else ""
    if exc.code == 403 and "html" in content_type:
        message = (
            "Deriv returned HTTP 403 HTML during the server-side OAuth token exchange; "
            "the user approved login, but no access token was issued. Confirm this Client ID "
            "and callback belong to the same OAuth app."
        )
        if not oauth_client_secret():
            message += (
                " If the Deriv dashboard provides a Client Secret for this app, set it privately "
                "as DERIV_CLIENT_SECRET in Render Environment; do not paste it into the scanner."
            )
        return (message + suffix)[:650]
    try:
        payload = json.loads(exc.read().decode("utf-8", "replace"))
        errors = payload.get("errors", [])
        if errors and isinstance(errors[0], dict):
            return f"Deriv token exchange failed ({exc.code}): {errors[0].get('message', 'OAuth request rejected')}."[:650]
    except Exception:
        pass
    return f"Deriv token exchange failed ({exc.code}).{suffix}"[:650]


SETUP_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Deriv OAuth</title><style>
:root{color-scheme:dark}body{margin:0;background:#08111e;color:#edf4ff;font:16px Segoe UI,Arial,sans-serif}.wrap{max-width:760px;margin:36px auto;padding:0 18px}.panel{background:#101d32;border:1px solid #263c5b;border-radius:16px;padding:24px}.muted{color:#9cb0cc;line-height:1.55}.field{display:block;margin:18px 0 7px}input,select{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #385071;background:#091626;color:#fff;font:inherit}button{margin-top:18px;border:0;border-radius:10px;padding:12px 16px;background:#236de1;color:white;font-weight:700;font:inherit;cursor:pointer}.info{padding:14px;border:1px solid #24415e;background:#0a1728;border-radius:10px;margin-top:16px;line-height:1.55}a{color:#8cbaff}code{overflow-wrap:anywhere;color:#b4d0ff}.tiny{font-size:12px;color:#91a7c3}</style></head><body>
<div class="wrap"><div class="panel"><h1>Connect your Deriv account</h1>
<p class="muted">This scanner uses Deriv OAuth 2.0. You sign in on Deriv itself; do not enter your Deriv password or API token here. Only the OAuth Client ID is saved in this folder.</p>
<form method="post" action="/setup"><label class="field" for="client_id">Deriv OAuth Client ID</label><input id="client_id" name="client_id" autocomplete="off" placeholder="Enter the Client ID created for your app" required>
<label class="field" for="scopes">Permission requested</label><select id="scopes" name="scopes"><option value="trade" selected>trade — account/trading access</option></select>
<button type="submit">Save Client ID and continue to Deriv</button></form>
<div class="info"><b>One-time Deriv setup</b><p class="muted">In your Deriv developer dashboard, register an OAuth 2.0 application and set the Redirect URL to this exact address:</p><p><code>__REDIRECT_URI__</code></p><p class="muted">Use the same Client ID in the form above. The redirect URL must match exactly, including port and path.</p></div>
<p class="tiny">OAuth docs: <a href="https://developers.deriv.com/docs/intro/oauth/" target="_blank" rel="noreferrer">Deriv OAuth 2.0 documentation</a></p>
<p><a href="/">Return to scanner</a></p></div></div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "DerivPipBoxScanner/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Log only the path, never query values such as OAuth authorization codes.
        try:
            path = self.path.split("?", 1)[0]
            code = getattr(self, "_response_code", "-")
            print(f"[{self.log_date_time_string()}] {self.command} {path} {code}")
        except Exception:
            pass

    def send_response(self, code: int, message: str | None = None) -> None:
        self._response_code = code
        super().send_response(code, message)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/trade/otp":
            self.trade_otp()
            return
        if path != "/setup":
            self.send_error(404)
            return
        if PUBLIC_DEPLOY:
            html_response(self, "<!doctype html><meta charset='utf-8'><title>Hosted OAuth setup</title><body style='font:16px Arial;background:#08111e;color:#fff;margin:40px'><h2>Public-hosting setup</h2><p>For safety, visitors cannot change this site's shared OAuth Client ID. Set DERIV_CLIENT_ID in the hosting dashboard's environment variables, then redeploy/restart the service.</p><p><a style='color:#8cbaff' href='/setup'>Back</a></p></body>", 403)
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 16_384)
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            client_id = (form.get("client_id") or [""])[0].strip()
            scopes = (form.get("scopes") or ["trade"])[0].strip() or "trade"
            if not client_id or len(client_id) > 200 or any(ch.isspace() for ch in client_id):
                raise ValueError("Enter a valid Deriv OAuth Client ID.")
            save_config(client_id, scopes)
            redirect(self, "/login")
        except Exception as exc:
            message = html.escape(str(exc))
            html_response(self, f"<!doctype html><meta charset='utf-8'><title>Setup error</title><body style='font:16px Arial;background:#08111e;color:#fff;margin:40px'><h2>Setup error</h2><p>{message}</p><a style='color:#8cbaff' href='/setup'>Go back</a></body>", 400)

    def trade_otp(self) -> None:
        # This endpoint only issues an OTP for the current browser's own OAuth session.
        # Same-origin checks reduce the risk of cross-site request forgery.
        origin = self.headers.get("Origin", "").strip()
        host = self.headers.get("Host", "").strip()
        if not origin or urllib.parse.urlparse(origin).netloc.lower() != host.lower():
            json_response(self, {"error": "Same-origin request required. Open the scanner using its own HTTPS URL."}, 403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 8192:
                json_response(self, {"error": "Invalid request body."}, 400)
                return
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("Invalid trade setup request.")
            mode = str(body.get("mode", "")).strip().lower()
            account_id = str(body.get("account_id", "")).strip()
            if mode not in {"demo", "real"}:
                json_response(self, {"error": "Select either a demo or real Options account."}, 400)
                return
            if not account_id or len(account_id) > 128:
                json_response(self, {"error": "Select an authorized Deriv account."}, 400)
                return
            sid, session = current_session(self)
            if not sid or not session or not session.get("access_token"):
                json_response(self, {"error": "Connect Deriv first, then choose an authorized account."}, 401)
                return
            client_id, _, _ = load_config()
            if not client_id:
                json_response(self, {"error": "The scanner owner has not configured a Deriv OAuth Client ID."}, 503)
                return
            token = refresh_access_token(session, client_id)
            payload = api_get("/trading/v1/options/accounts", token)
            account = next((row for row in account_rows(payload) if row["account_id"] == account_id), None)
            if not account:
                json_response(self, {"error": "That account was not returned by Deriv for this signed-in session. Refresh the account list and try again."}, 403)
                return
            if account.get("account_type") != mode:
                json_response(self, {"error": f"Account-type mismatch: selected mode is {mode.upper()}, Deriv identifies this account as {str(account.get('account_type')).upper()}."}, 403)
                return
            account_path = urllib.parse.quote(account_id, safe="")
            otp_payload = api_post_empty(f"/trading/v1/options/accounts/{account_path}/otp", token)
            data = otp_payload.get("data", otp_payload)
            ws_url = str(data.get("url", "")) if isinstance(data, dict) else ""
            parsed = urllib.parse.urlparse(ws_url)
            expected_path = f"/trading/v1/options/ws/{mode}"
            if parsed.scheme != "wss" or parsed.hostname != "api.derivws.com" or parsed.path != expected_path or not urllib.parse.parse_qs(parsed.query).get("otp"):
                json_response(self, {"error": "Deriv returned an unexpected trading WebSocket URL. No connection was opened."}, 502)
                return
            # The OTP is single-use and short-lived. Never log it or persist it.
            json_response(self, {
                "ok": True,
                "ws_url": ws_url,
                "mode": mode,
                "account_id": account["account_id"],
                "loginid": account["loginid"],
                "currency": account["currency"],
            })
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", "replace")[:500]
            except Exception:
                detail = ""
            json_response(self, {"error": f"Deriv could not authorize the trading connection ({exc.code}).", "detail": detail}, exc.code)
        except (ValueError, json.JSONDecodeError) as exc:
            json_response(self, {"error": str(exc) or "Invalid JSON request."}, 400)
        except Exception as exc:
            json_response(self, {"error": f"Could not prepare the authorized trading connection: {exc}"}, 500)

    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        params = urllib.parse.parse_qs(query)
        try:
            if path == "/":
                if not INDEX.exists():
                    self.send_error(404, "index.html missing")
                    return
                # Keep the current scanner session across ordinary page reloads.
                # Clearing the server-side OAuth session on every GET / left the
                # browser showing an authorized account while /api/trade/otp returned
                # 401 after a refresh/navigation. A deliberate account switch still
                # starts a fresh OAuth session in login(), which revokes the old one.
                body = INDEX.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/setup":
                _, redirect_uri, _ = load_config()
                page = SETUP_HTML.replace("__REDIRECT_URI__", html.escape(redirect_uri or "Set PUBLIC_BASE_URL/RENDER_EXTERNAL_URL first"))
                if PUBLIC_DEPLOY:
                    form_start = page.find("<form")
                    form_end = page.find("</form>", form_start) + len("</form>") if form_start >= 0 else -1
                    hosted_note = ("<div class='info'><b>Hosted app setup</b><p class='muted'>This public site's OAuth Client ID is managed by the site owner in the hosting dashboard. Do not enter account passwords or API tokens here. Set the environment variable DERIV_CLIENT_ID on the host, and register the callback shown below in your Deriv OAuth app.</p></div>")
                    if form_start >= 0 and form_end > form_start:
                        page = page[:form_start] + hosted_note + page[form_end:]
                html_response(self, page)
                return
            if path == "/login":
                self.login()
                return
            if path == "/callback":
                self.callback(params)
                return
            if path in ("/logout", "/api/logout"):
                self.logout()
                return
            if path == "/api/config":
                client_id, redirect_uri, scopes = load_config()
                json_response(self, {"configured": bool(client_id and redirect_uri), "redirect_uri": redirect_uri, "scopes": scopes, "public_deploy": PUBLIC_DEPLOY})
                return
            if path == "/api/auth/status":
                self.auth_status()
                return
            if path == "/health":
                _, redirect_uri, _ = load_config()
                json_response(self, {"ok": True, "app": "DerivPipBoxScanner", "public_deploy": PUBLIC_DEPLOY, "redirect_uri": redirect_uri})
                return
            self.send_error(404)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", "replace")[:700]
            except Exception:
                detail = ""
            # Provider responses sometimes include diagnostic material; do not log it.
            json_response(self, {"error": f"Deriv request failed ({exc.code})", "detail": detail}, exc.code)
        except Exception as exc:
            json_response(self, {"error": str(exc)}, 500)

    def login(self) -> None:
        # Switching accounts starts a new scanner-side authorization session and
        # removes the previous browser session from server memory.
        old_sid = get_cookie(self, SESSION_COOKIE)
        if old_sid:
            old_session = sessions.pop(old_sid, None)
            if old_session and old_session.get("oauth_pending_id"):
                pending_oauth.pop(str(old_session["oauth_pending_id"]), None)
        client_id, redirect_uri, scopes = load_config()
        if not client_id or not redirect_uri:
            redirect(self, "/setup")
            return
        now = time.time()
        for old_id in [key for key, val in pending_oauth.items() if now - val.get("created_at", now) > 600]:
            pending_oauth.pop(old_id, None)
        verifier = new_verifier()
        state = b64url(secrets.token_bytes(24))
        pending_id = secrets.token_urlsafe(24)
        sid = secrets.token_urlsafe(32)
        pending_oauth[pending_id] = {"state": state, "verifier": verifier, "created_at": now}
        sessions[sid] = {"oauth_pending_id": pending_id}
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scopes,
            "state": state,
            "code_challenge": challenge(verifier),
            "code_challenge_method": "S256",
        }
        secure = "; Secure" if redirect_uri.lower().startswith("https://") else ""
        cookie = f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax{secure}"
        redirect(self, AUTH_URL + "?" + urllib.parse.urlencode(params), cookie)

    def callback(self, params: dict[str, list[str]]) -> None:
        provider_error = (params.get("error_description") or params.get("error") or [""])[0]
        if provider_error:
            redirect(self, "/?auth_error=" + urllib.parse.quote(provider_error[:300]))
            return
        code = (params.get("code") or [""])[0]
        state = (params.get("state") or [""])[0]
        if not code or not state:
            redirect(self, "/?auth_error=Missing+authorization+code+or+state")
            return
        sid, session = current_session(self)
        if not sid or not session:
            redirect(self, "/?auth_error=Browser+session+was+not+found.+Please+connect+again")
            return
        pending_id = session.get("oauth_pending_id")
        pending = pending_oauth.get(str(pending_id))
        if not pending or time.time() - pending.get("created_at", 0) > 600:
            sessions.pop(sid, None)
            redirect(self, "/?auth_error=OAuth+request+expired.+Please+connect+again")
            return
        if not secrets.compare_digest(state, str(pending.get("state", ""))):
            sessions.pop(sid, None)
            pending_oauth.pop(str(pending_id), None)
            redirect(self, "/?auth_error=OAuth+state+verification+failed")
            return
        client_id, redirect_uri, _ = load_config()
        try:
            tokens = exchange_code(code, str(pending["verifier"]), client_id, redirect_uri)
        except Exception as exc:
            sessions.pop(sid, None)
            # Do not expose provider HTML pages, authorization codes, tokens, or secrets.
            message = oauth_exchange_error_message(exc) if isinstance(exc, urllib.error.HTTPError) else str(exc)
            redirect(self, "/?auth_error=" + urllib.parse.quote(message[:650]))
            return
        finally:
            # The authorization code is single-use; delete its verifier immediately.
            pending_oauth.pop(str(pending_id), None)
        access_token = tokens.get("access_token")
        if not access_token:
            sessions.pop(sid, None)
            redirect(self, "/?auth_error=Deriv+did+not+return+an+access+token")
            return
        sessions[sid] = {
            "access_token": access_token,
            "expires_at": time.time() + int(tokens.get("expires_in", 3600)),
            "refresh_token": tokens.get("refresh_token"),
            "created_at": time.time(),
        }
        redirect(self, "/?oauth_callback=complete")

    def auth_status(self) -> None:
        sid, session = current_session(self)
        if not sid or not session or not session.get("access_token"):
            client_id, redirect_uri, _ = load_config()
            json_response(self, {"authenticated": False, "configured": bool(client_id and redirect_uri)})
            return
        client_id, _, _ = load_config()
        try:
            token = refresh_access_token(session, client_id)
            payload = api_get("/trading/v1/options/accounts", token)
            json_response(self, {
                "authenticated": True,
                "configured": True,
                "accounts": account_rows(payload),
                "expires_at": session.get("expires_at"),
            })
        except urllib.error.HTTPError as exc:
            json_response(self, {"authenticated": False, "configured": True, "error": f"Deriv account check failed ({exc.code}). Sign in again if needed."}, 200)
        except Exception as exc:
            json_response(self, {"authenticated": False, "configured": True, "error": str(exc)}, 200)

    def logout(self) -> None:
        sid = get_cookie(self, SESSION_COOKIE)
        if sid:
            sessions.pop(sid, None)
        _, redirect_uri, _ = load_config()
        secure = "; Secure" if redirect_uri.lower().startswith("https://") else ""
        cookie = f"{SESSION_COOKIE}=deleted; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{secure}"
        redirect(self, "/", cookie)


def main() -> None:
    global PORT, HOST, LOCAL_REDIRECT_URI
    print("=" * 62)
    print("DERIV AI + PIPBOX-STYLE VOLATILITY SCANNER — BUILD V2.1-STABLE-OAUTH-20261015")
    print("Starting local server..." if not PUBLIC_DEPLOY else "Starting public-hosted server...")

    server = None
    if PUBLIC_DEPLOY:
        # The hosting platform supplies the required port; do not silently change it.
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    else:
        # The OAuth redirect is registered against localhost:8000. Never silently
        # move to :8001+ because Deriv requires an exact redirect_uri match.
        HOST = "127.0.0.1"
        PORT = 8000
        LOCAL_REDIRECT_URI = "http://localhost:8000/callback"
        try:
            server = ThreadingHTTPServer((HOST, PORT), Handler)
        except OSError as exc:
            print("ERROR: localhost:8000 is already in use or cannot be opened.")
            print("Close any older Deriv PipBox scanner CMD windows, then run this launcher again.")
            print("The scanner will not switch ports because that would break the registered OAuth callback.")
            print(f"Details: {exc}")
            raise SystemExit(2)

    _, redirect_uri, _ = load_config()
    print(f"Server bind: {HOST}:{PORT}")
    if PUBLIC_DEPLOY:
        print("Public-hosting mode: enabled")
        print(f"OAuth callback: {redirect_uri or 'MISSING — set PUBLIC_BASE_URL / DERIV_REDIRECT_URI'}")
    else:
        url = f"http://localhost:{PORT}/"
        print(f"READY — open in Chrome: {url}")
        print(f"OAuth callback: {redirect_uri}")
    print("Market data: documented public Options WebSocket only")
    print("OAuth: same-tab redirect to Deriv, then return to this scanner")
    print("Public market scanning: enabled; account trading requires explicit in-page arming")
    print("Keep this black CMD window open while using the scanner.")
    print("Press Ctrl+C here to stop the server.")
    print("=" * 62)
    if not PUBLIC_DEPLOY:
        try:
            webbrowser.open(f"http://localhost:{PORT}/", new=2)
        except Exception:
            pass
    server.serve_forever()


if __name__ == "__main__":
    main()