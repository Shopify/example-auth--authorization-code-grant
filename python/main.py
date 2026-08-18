# python/main.py
import hashlib
import hmac
import os
import re
import secrets
import time
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, session

load_dotenv()

CLIENT_ID = os.environ.get('SHOPIFY_CLIENT_ID')
CLIENT_SECRET = os.environ.get('SHOPIFY_CLIENT_SECRET')
REDIRECT_URI = os.environ.get('REDIRECT_URI')
SCOPES = os.environ.get('SCOPES', 'read_products,write_orders')

app = Flask(__name__)

# Send the session cookie only over HTTPS in production; over plain HTTP on
# localhost in dev. HttpOnly + SameSite protect it the rest of the time.
# Falls back to a random secret for local dev. Set SESSION_SECRET in production
# so the signed session stays valid across restarts and deployments.
app.secret_key = os.environ.get('SESSION_SECRET') or secrets.token_hex(64)
app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get('APP_ENV') == 'production',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# In-memory token store (use a database in production)
token_store = {}

SHOP_DOMAIN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$')


# A valid expiring-token response includes expires_in (seconds until the access
# token expires). Return None when it's absent or non-positive: treat the token
# as non-expiring and never refresh it. Storing time.time() instead would make
# the next request refresh a token that has no refresh_token — a permanent 401.
def expires_at_from(expires_in):
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError):
        return None
    return time.time() + seconds if seconds > 0 else None


def is_valid_shop_domain(shop):
    return bool(shop and SHOP_DOMAIN.match(shop))


# [START oauth.build-authorization-url]
@app.get('/install')
def install():
    shop = request.args.get('shop')

    if not is_valid_shop_domain(shop):
        return 'Invalid shop domain', 400

    nonce = secrets.token_hex(16)
    # Store the nonce in the signed session so you can verify it against the callback
    session['oauth_state'] = nonce

    auth_url = f'https://{shop}/admin/oauth/authorize?' + urlencode({
        'client_id': CLIENT_ID,
        'scope': SCOPES,
        'redirect_uri': REDIRECT_URI,
        'state': nonce,
    })

    return redirect(auth_url)
# [END oauth.build-authorization-url]


@app.get('/callback')
def callback():
    code = request.args.get('code')
    hmac_param = request.args.get('hmac')
    shop = request.args.get('shop')
    state = request.args.get('state')

    # [START oauth.validate-state]
    expected_state = session.pop('oauth_state', None)
    if not state or not expected_state or not hmac.compare_digest(state, expected_state):
        return 'Invalid state parameter', 403
    # [END oauth.validate-state]

    # [START oauth.verify-hmac]
    message = '&'.join(
        f'{key}={value}'
        for key, value in sorted(request.args.items())
        if key != 'hmac'
    )
    digest = hmac.new(
        CLIENT_SECRET.encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    # compare_digest is constant-time, so the check doesn't leak timing information
    if not hmac_param or not hmac.compare_digest(digest, hmac_param):
        return 'Invalid HMAC', 403
    # [END oauth.verify-hmac]

    # [START oauth.validate-shop]
    if not is_valid_shop_domain(shop):
        return 'Invalid shop domain', 400
    # [END oauth.validate-shop]

    # [START oauth.exchange-code]
    token_response = requests.post(
        f'https://{shop}/admin/oauth/access_token',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        },
        data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code': code,
            'expiring': '1',
        },
        timeout=30,
    )

    if not token_response.ok:
        return 'Token exchange failed', 403

    data = token_response.json()
    access_token = data['access_token']
    refresh_token = data.get('refresh_token')
    expires_in = data.get('expires_in')
    scope = data['scope']
    # [END oauth.exchange-code]

    # [START oauth.confirm-scopes]
    granted = scope.split(',')
    # A write_* grant includes its matching read_* scope, so Shopify may return
    # only the write scope. Treat a requested read_* as satisfied by its write_*.
    missing = [
        s for s in SCOPES.split(',')
        if s not in granted
        and not (s.startswith('read_') and f'write_{s[len("read_"):]}' in granted)
    ]
    if missing:
        return f'Missing scopes: {", ".join(missing)}', 403
    # [END oauth.confirm-scopes]

    # Store tokens server-side, keyed by shop (use a database in production).
    # Track when the access token expires so requests can refresh it in time.
    token_store[shop] = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'expires_at': expires_at_from(expires_in),
    }

    # Store the shop in the signed session cookie
    session['shop'] = shop

    return jsonify({'message': 'App installed', 'shop': shop, 'scope': scope})


# Exchange the stored refresh token for a new access token. The return value
# tells the caller how to react, and matches the refresh error handling used
# across grant types:
#   'refreshed'   — got a new access token
#   'reauthorize' — a 401 means the refresh token is terminal (expired, revoked,
#                   replayed after the one-hour retry window, or the app was
#                   uninstalled); send the merchant back through OAuth
#   'retry'       — a transient failure (network, timeout, 5xx, 429); safe to
#                   retry later with the same refresh token
#   'failed'      — any other non-OK status, such as a malformed request or bad
#                   client credentials; retrying sends the identical request and
#                   fails the same way, so surface it instead of hiding it
def refresh_access_token(shop):
    stored = token_store.get(shop)
    if not stored or not stored.get('refresh_token'):
        return 'reauthorize'

    try:
        response = requests.post(
            f'https://{shop}/admin/oauth/access_token',
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
            },
            data={
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'refresh_token': stored['refresh_token'],
            },
            timeout=30,
        )
    except requests.RequestException:
        # Network failure or timeout: the refresh token is untouched, so retrying
        # later with the same one is safe.
        return 'retry'

    # A 401 is terminal: drop the dead token so the merchant reinstalls.
    if response.status_code == 401:
        token_store.pop(shop, None)
        return 'reauthorize'
    # Only a rate limit or a server fault is worth retrying. Treating every other
    # non-OK status as transient would retry an unrecoverable refresh forever —
    # a 400 for a malformed body, or a 403 for bad client credentials, returns the
    # same response no matter how long you wait.
    if response.status_code == 429 or response.status_code >= 500:
        return 'retry'
    if not response.ok:
        return 'failed'

    data = response.json()
    token_store[shop] = {
        'access_token': data['access_token'],
        'refresh_token': data.get('refresh_token'),
        'expires_at': expires_at_from(data.get('expires_in')),
    }
    return 'refreshed'


# [START oauth.make-request]
@app.get('/products')
def products():
    shop = session.get('shop')
    if not shop:
        return 'Not authenticated', 401

    stored = token_store.get(shop)
    if not stored:
        return 'Not authenticated', 401

    # Expiring access tokens are short-lived. Refresh ~60 seconds before the token
    # actually expires so a request never goes out with a token that lapses
    # mid-flight.
    if stored.get('expires_at') is not None and time.time() >= stored['expires_at'] - 60:
        result = refresh_access_token(shop)
        if result == 'reauthorize':
            return 'Reauthorization required', 401
        if result == 'retry':
            return 'Token refresh failed, try again', 503
        if result == 'failed':
            # Not the merchant's problem and not worth retrying: fix the app's
            # request or credentials. Don't fall through — `stored` still holds
            # the token that is about to expire.
            return 'Token refresh failed', 502
        stored = token_store[shop]

    def call_admin_api(access_token):
        return requests.post(
            f'https://{shop}/admin/api/2026-04/graphql.json',
            headers={
                'Content-Type': 'application/json',
                'X-Shopify-Access-Token': access_token,
            },
            json={'query': '{ products(first: 5) { edges { node { id handle } } } }'},
            timeout=30,
        )

    response = call_admin_api(stored['access_token'])

    # Shopify rejected the access token: it was revoked, the app's access scopes
    # changed, or it lapsed sooner than expires_in implied. This app runs outside
    # the Shopify admin, so it has no ID token to exchange — the refresh token is
    # the only way back. Try it once, then give up rather than sending the same
    # rejected token again on every later request.
    if response.status_code == 401:
        result = refresh_access_token(shop)
        if result == 'retry':
            # Transient: the refresh token is untouched, so a later attempt is fine.
            return 'Token refresh failed, try again', 503
        if result == 'failed':
            return 'Token refresh failed', 502
        if result != 'refreshed':
            # Drop the rejected token so the next request doesn't send it again.
            token_store.pop(shop, None)
            return 'Reauthorization required', 401

        response = call_admin_api(token_store[shop]['access_token'])

        # Retry once, not in a loop. A freshly refreshed token that's also rejected
        # means something is wrong beyond a lapsed credential, so stop and send the
        # merchant back through OAuth.
        if response.status_code == 401:
            token_store.pop(shop, None)
            return 'Reauthorization required', 401

    # Forward Shopify's status. Answering a rate limit or an outage with a 200 and
    # an error body in it would tell the client the request succeeded.
    return jsonify(response.json()), response.status_code
# [END oauth.make-request]


# The routes above let a transport failure or timeout propagate. The request never
# reached Shopify, so nothing was consumed and the caller can try again: 503 says
# that, while the traceback Flask would otherwise return says the app is broken.
@app.errorhandler(requests.RequestException)
def handle_shopify_unreachable(_error):
    return 'Could not reach Shopify, try again', 503


if __name__ == '__main__':
    # Flask's development server. Use a production WSGI server (gunicorn, uWSGI)
    # when you deploy.
    app.run(port=3000)
