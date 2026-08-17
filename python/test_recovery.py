# Recovery tests for the Python authorization code grant sample.
#
# Every scenario runs a real install first, then injects a failure — a revoked
# access token, a dead refresh token, a rate limit — and asserts what the app
# ends up doing about it. Asserting on the whole loop, rather than on one
# response, is what catches the class of bug where an error is answered in a way
# that reads as correct but leaves the app stuck: this route used to hand
# Shopify's 401 straight back to the client with the dead token still cached, so
# every later request failed the same way until the merchant reinstalled.
#
# The Node.js port has the same scenarios in the same order, so a defect in one
# language shows up as a diff between the two suites.
#
# Run with: python test_recovery.py

import hashlib
import hmac
import json
import os
from urllib.parse import urlencode, urlparse

CLIENT_ID = 'test-client-id'
# At least 32 bytes, like a real client secret.
CLIENT_SECRET = 'test-client-secret-0123456789abcdef'
SCOPES = 'read_products,write_orders'

# Set configuration before importing the app: it reads os.environ at import time,
# and load_dotenv doesn't overwrite variables that are already set, so a
# developer's real .env can't leak into a test run.
os.environ['SHOPIFY_CLIENT_ID'] = CLIENT_ID
os.environ['SHOPIFY_CLIENT_SECRET'] = CLIENT_SECRET
os.environ['REDIRECT_URI'] = 'http://localhost:3000/callback'
os.environ['SCOPES'] = SCOPES
os.environ['SESSION_SECRET'] = 'test-session-secret-0123456789abcdef'

import main  # noqa: E402


# ---------------------------------------------------------------------------
# A fake Shopify, so failures can be injected on demand
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._body


class FakeShopify:
    def __init__(self):
        self.reset()

    def reset(self):
        # Access tokens Shopify still accepts. Removing one simulates a revoked
        # token or an app whose access scopes changed.
        self.live_access_tokens = set()
        self.live_refresh_tokens = set()
        # When False, a refresh still succeeds but returns a token Shopify
        # rejects: the "recovery didn't help" case.
        self.refreshed_tokens_work = True
        # Status for the refresh grant. 401 is terminal, 5xx is transient.
        self.refresh_status = 200
        # Status for the GraphQL Admin API when the token is accepted.
        self.api_status = 200
        self.expires_in = 86_400
        self.minted = []
        self.calls = []

    def mint_access_token(self, works=True):
        token = f'access-{len(self.minted) + 1}'
        self.minted.append(token)
        if works:
            self.live_access_tokens.add(token)
        return token

    def mint_refresh_token(self):
        token = f'refresh-{len(self.minted)}'
        self.live_refresh_tokens.add(token)
        return token

    def calls_of_type(self, call_type):
        return [call for call in self.calls if call['type'] == call_type]

    # Stands in for requests.post. The sample only ever POSTs, to the token
    # endpoint and to the GraphQL Admin API.
    def post(self, url, headers=None, data=None, json=None, timeout=None):
        path = urlparse(url).path

        if path == '/admin/oauth/access_token':
            form = data or {}

            if form.get('grant_type') == 'refresh_token':
                self.calls.append(
                    {'type': 'refresh', 'refresh_token': form['refresh_token']}
                )

                if self.refresh_status != 200:
                    return FakeResponse({'error': 'server_error'}, self.refresh_status)
                if form['refresh_token'] not in self.live_refresh_tokens:
                    return FakeResponse({'error': 'invalid_grant'}, 401)
                # A refresh token is single use.
                self.live_refresh_tokens.discard(form['refresh_token'])
                return FakeResponse(
                    {
                        'access_token': self.mint_access_token(
                            works=self.refreshed_tokens_work
                        ),
                        'refresh_token': self.mint_refresh_token(),
                        'expires_in': self.expires_in,
                    }
                )

            # No grant_type means the initial authorization code exchange.
            self.calls.append(
                {
                    'type': 'exchange',
                    'code': form.get('code'),
                    'expiring': form.get('expiring'),
                }
            )
            return FakeResponse(
                {
                    'access_token': self.mint_access_token(),
                    'refresh_token': self.mint_refresh_token(),
                    'scope': SCOPES,
                    'expires_in': self.expires_in,
                }
            )

        if path.startswith('/admin/api/'):
            token = headers['X-Shopify-Access-Token']
            self.calls.append({'type': 'graphql', 'token': token})
            if token not in self.live_access_tokens:
                return FakeResponse(
                    {'errors': [{'message': 'Invalid API key or access token'}]}, 401
                )
            if self.api_status != 200:
                return FakeResponse(
                    {'errors': [{'message': 'Throttled'}]}, self.api_status
                )
            return FakeResponse({'data': {'products': {'edges': []}}})

        raise AssertionError(f'Unexpected request: {url}')


shopify = FakeShopify()
main.requests.post = shopify.post


# ---------------------------------------------------------------------------
# Driving the app
# ---------------------------------------------------------------------------

# The token store is keyed by shop, so giving every scenario its own shop
# isolates it without needing a reset hook in the sample.
_shop_counter = 0


def fresh_shop():
    global _shop_counter
    _shop_counter += 1
    return f'recovery-{_shop_counter}.myshopify.com'


# Walk the real OAuth flow: /install issues the state nonce, then /callback
# exchanges the code and stores the shop in the session.
def install(client, shop):
    installed = client.get(f'/install?shop={shop}')
    assert installed.status_code == 302, 'install should redirect to Shopify'

    with client.session_transaction() as flask_session:
        nonce = flask_session['oauth_state']

    params = {
        'code': 'test-authorization-code',
        'shop': shop,
        'state': nonce,
        'timestamp': '1700000000',
    }
    message = '&'.join(f'{key}={value}' for key, value in sorted(params.items()))
    digest = hmac.new(
        CLIENT_SECRET.encode(), message.encode(), hashlib.sha256
    ).hexdigest()

    callback = client.get(f'/callback?{urlencode({**params, "hmac": digest})}')
    assert callback.status_code == 200, callback.get_data(as_text=True)


class Result:
    def __init__(self, response):
        self.status = response.status_code
        self.body = response.get_data(as_text=True)


def get_products(client):
    return Result(client.get('/products'))


SCENARIOS = []


def scenario(name):
    def register(run):
        SCENARIOS.append((name, run))
        return run

    return register


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


@scenario('a revoked access token is recovered with the refresh token')
def revoked_access_token_recovers(client):
    install(client, fresh_shop())
    access_token = shopify.minted[0]

    # Shopify revokes the access token mid-session.
    shopify.live_access_tokens.discard(access_token)

    result = get_products(client)

    # The whole point: the request the merchant made succeeds.
    assert result.status == 200, result.body
    assert json.loads(result.body) == {'data': {'products': {'edges': []}}}

    assert len(shopify.calls_of_type('refresh')) == 1, (
        'the app should refresh the token'
    )

    graphql = shopify.calls_of_type('graphql')
    assert len(graphql) == 2
    assert graphql[1]['token'] != access_token, (
        'the retry should use the refreshed token'
    )


@scenario(
    'a rejected access token with a dead refresh token forces reauthorization '
    'and is evicted'
)
def dead_credentials_force_reauthorization(client):
    install(client, fresh_shop())

    # The app was uninstalled: both credentials are dead.
    shopify.live_access_tokens.clear()
    shopify.live_refresh_tokens.clear()

    first = get_products(client)
    assert first.status == 401, first.status
    assert first.body == 'Reauthorization required', first.body

    # The dead token must not be sent again. A second request should stop before
    # reaching Shopify at all.
    calls_so_far = len(shopify.calls)
    second = get_products(client)
    assert second.status == 401, second.status
    assert second.body == 'Not authenticated', (
        'the rejected token should have been dropped from the store'
    )
    assert len(shopify.calls) == calls_so_far, (
        'a request with no usable token should not call Shopify'
    )


@scenario('a refreshed token that Shopify also rejects stops after one retry')
def refreshed_token_also_rejected(client):
    install(client, fresh_shop())

    # The refresh works, but nothing it hands back is accepted.
    shopify.live_access_tokens.clear()
    shopify.refreshed_tokens_work = False

    result = get_products(client)

    assert result.status == 401, result.status
    assert result.body == 'Reauthorization required', result.body
    assert len(shopify.calls_of_type('refresh')) == 1, (
        'exactly one recovery attempt, not a loop'
    )
    assert len(shopify.calls_of_type('graphql')) == 2


@scenario(
    'a transient refresh failure during recovery is retryable and keeps the '
    'refresh token'
)
def transient_refresh_failure_during_recovery(client):
    install(client, fresh_shop())
    shopify.live_access_tokens.discard(shopify.minted[0])

    # Shopify's token endpoint is briefly unavailable.
    shopify.refresh_status = 500

    during = get_products(client)
    assert during.status == 503, during.status
    assert during.body == 'Token refresh failed, try again', during.body

    # The refresh token survived, so the next attempt recovers on its own.
    shopify.refresh_status = 200
    after = get_products(client)
    assert after.status == 200, after.body


@scenario('an access token close to expiry is refreshed before the API call')
def near_expiry_access_token_refreshes(client):
    shopify.expires_in = 30
    install(client, fresh_shop())

    result = get_products(client)
    assert result.status == 200, result.body

    assert len(shopify.calls_of_type('refresh')) == 1
    graphql = shopify.calls_of_type('graphql')
    assert len(graphql) == 1, 'the refreshed token should work first time'
    assert graphql[0]['token'] == shopify.minted[-1]


@scenario('a dead refresh token at expiry sends the merchant back through OAuth')
def dead_refresh_token_at_expiry(client):
    shopify.expires_in = 30
    install(client, fresh_shop())

    shopify.live_refresh_tokens.clear()

    result = get_products(client)
    assert result.status == 401, result.status
    assert result.body == 'Reauthorization required', result.body
    assert len(shopify.calls_of_type('graphql')) == 0, (
        'do not send a token the app already knows is dead'
    )


@scenario('an error status from Shopify is forwarded, not reported as success')
def error_status_is_forwarded(client):
    install(client, fresh_shop())

    # The token is fine; the request is throttled.
    shopify.api_status = 429

    result = get_products(client)

    assert result.status == 429, 'a throttled request is not a successful one'
    assert len(shopify.calls_of_type('refresh')) == 0, (
        'a rate limit is not a credential problem, so do not refresh'
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run():
    failures = 0
    for name, scenario_fn in SCENARIOS:
        shopify.reset()
        # A fresh client per scenario, so the session cookie doesn't carry over.
        with main.app.test_client() as client:
            try:
                scenario_fn(client)
                print(f'  ok    {name}')
            except AssertionError as error:
                failures += 1
                print(f'  FAIL  {name}')
                print(f'        {error}')

    print(f'\n{len(SCENARIOS) - failures}/{len(SCENARIOS)} recovery scenarios passed')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(run())
