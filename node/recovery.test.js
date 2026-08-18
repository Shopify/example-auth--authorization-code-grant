// Recovery tests for the Node.js authorization code grant sample.
//
// Every scenario runs a real install first, then injects a failure — a revoked
// access token, a dead refresh token, a rate limit — and asserts what the app
// ends up doing about it. Asserting on the whole loop, rather than on one
// response, is what catches the class of bug where an error is answered in a way
// that reads as correct but leaves the app stuck: this route used to hand
// Shopify's 401 straight back to the client with the dead token still cached, so
// every later request failed the same way until the merchant reinstalled.
//
// The Python port has the same scenarios in the same order, so a defect in one
// language shows up as a diff between the two suites.
//
// Run with: npm test

import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const CLIENT_ID = 'test-client-id';
// At least 32 bytes, like a real client secret.
const CLIENT_SECRET = 'test-client-secret-0123456789abcdef';
const SCOPES = 'read_products,write_orders';
const BASE = 'http://127.0.0.1:3000';

// The test drives the app over HTTP, so keep a handle on the real fetch before
// the fake replaces the global one.
const realFetch = globalThis.fetch;

// Set configuration before importing the app: it reads process.env at import
// time, and dotenv doesn't overwrite variables that are already set, so a
// developer's real .env can't leak into a test run.
process.env.SHOPIFY_CLIENT_ID = CLIENT_ID;
process.env.SHOPIFY_CLIENT_SECRET = CLIENT_SECRET;
process.env.REDIRECT_URI = 'http://localhost:3000/callback';
process.env.SCOPES = SCOPES;
process.env.COOKIE_SECRET = 'test-cookie-secret-0123456789abcdef';

// ---------------------------------------------------------------------------
// A fake Shopify, so failures can be injected on demand
// ---------------------------------------------------------------------------

const shopify = {
  // Access tokens Shopify still accepts. Removing one simulates a revoked token
  // or an app whose access scopes changed.
  liveAccessTokens: new Set(),
  liveRefreshTokens: new Set(),
  // When false, a refresh still succeeds but returns a token Shopify rejects:
  // the "recovery didn't help" case.
  refreshedTokensWork: true,
  // Status for the refresh grant. 401 is terminal, 5xx is transient.
  refreshStatus: 200,
  // Status for the GraphQL Admin API when the token is accepted.
  apiStatus: 200,
  expiresIn: 86_400,
  minted: [],
  calls: [],
};

function resetShopify() {
  shopify.liveAccessTokens.clear();
  shopify.liveRefreshTokens.clear();
  shopify.refreshedTokensWork = true;
  shopify.refreshStatus = 200;
  shopify.apiStatus = 200;
  shopify.expiresIn = 86_400;
  shopify.minted = [];
  shopify.calls = [];
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function mintAccessToken({ works = true } = {}) {
  const token = `access-${shopify.minted.length + 1}`;
  shopify.minted.push(token);
  if (works) shopify.liveAccessTokens.add(token);
  return token;
}

function mintRefreshToken() {
  const token = `refresh-${shopify.minted.length}`;
  shopify.liveRefreshTokens.add(token);
  return token;
}

globalThis.fetch = async (url, options = {}) => {
  const { pathname } = new URL(url);

  if (pathname === '/admin/oauth/access_token') {
    const form = Object.fromEntries(new URLSearchParams(String(options.body)));

    if (form.grant_type === 'refresh_token') {
      shopify.calls.push({ type: 'refresh', refreshToken: form.refresh_token });

      if (shopify.refreshStatus !== 200) {
        return json({ error: 'server_error' }, shopify.refreshStatus);
      }
      if (!shopify.liveRefreshTokens.has(form.refresh_token)) {
        return json({ error: 'invalid_grant' }, 401);
      }
      // A refresh token is single use.
      shopify.liveRefreshTokens.delete(form.refresh_token);
      return json({
        access_token: mintAccessToken({ works: shopify.refreshedTokensWork }),
        refresh_token: mintRefreshToken(),
        expires_in: shopify.expiresIn,
      });
    }

    // No grant_type means the initial authorization code exchange.
    shopify.calls.push({ type: 'exchange', code: form.code, expiring: form.expiring });
    return json({
      access_token: mintAccessToken(),
      refresh_token: mintRefreshToken(),
      scope: SCOPES,
      expires_in: shopify.expiresIn,
    });
  }

  if (pathname.startsWith('/admin/api/')) {
    const token = options.headers['X-Shopify-Access-Token'];
    shopify.calls.push({ type: 'graphql', token });
    if (!shopify.liveAccessTokens.has(token)) {
      return json({ errors: [{ message: 'Invalid API key or access token' }] }, 401);
    }
    if (shopify.apiStatus !== 200) {
      return json({ errors: [{ message: 'Throttled' }] }, shopify.apiStatus);
    }
    return json({ data: { products: { edges: [] } } });
  }

  throw new Error(`Unexpected request: ${url}`);
};

// ---------------------------------------------------------------------------
// Driving the app
// ---------------------------------------------------------------------------

// The token store is keyed by shop, so giving every scenario its own shop
// isolates it without needing a reset hook in the sample.
let shopCounter = 0;
function freshShop() {
  return `recovery-${++shopCounter}.myshopify.com`;
}

// Node's fetch doesn't keep cookies, and this app authenticates with a signed
// session cookie, so each scenario carries its own jar.
function newJar() {
  return new Map();
}

function jarHeaders(jar) {
  if (jar.size === 0) return {};
  const cookie = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
  return { Cookie: cookie };
}

function absorbCookies(jar, response) {
  for (const raw of response.headers.getSetCookie()) {
    const [pair] = raw.split(';');
    const separator = pair.indexOf('=');
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    // res.clearCookie sends an empty value.
    if (value === '') jar.delete(name);
    else jar.set(name, value);
  }
}

// cookie-parser stores a signed cookie as `s:<value>.<signature>`.
function signedValue(raw) {
  const decoded = decodeURIComponent(raw);
  const body = decoded.slice('s:'.length);
  return body.slice(0, body.lastIndexOf('.'));
}

// Walk the real OAuth flow: /install issues the state nonce, then /callback
// exchanges the code and sets the session cookie.
async function install(shop, jar) {
  const installed = await realFetch(`${BASE}/install?shop=${shop}`, {
    redirect: 'manual',
    headers: jarHeaders(jar),
  });
  assert.equal(installed.status, 302, 'install should redirect to Shopify');
  absorbCookies(jar, installed);

  const params = {
    code: 'test-authorization-code',
    shop,
    state: signedValue(jar.get('oauth_state')),
    timestamp: '1700000000',
  };
  const message = Object.entries(params)
    .sort()
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
  const hmac = crypto
    .createHmac('sha256', CLIENT_SECRET)
    .update(message)
    .digest('hex');

  const query = new URLSearchParams({ ...params, hmac });
  const callback = await realFetch(`${BASE}/callback?${query}`, {
    headers: jarHeaders(jar),
  });
  absorbCookies(jar, callback);
  assert.equal(callback.status, 200, await callback.text());
}

async function getProducts(jar) {
  const response = await realFetch(`${BASE}/products`, { headers: jarHeaders(jar) });
  return { status: response.status, body: await response.text() };
}

function callsOfType(type) {
  return shopify.calls.filter((entry) => entry.type === type);
}

const scenarios = [];
function scenario(name, run) {
  scenarios.push({ name, run });
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

scenario('a revoked access token is recovered with the refresh token', async () => {
  const jar = newJar();
  await install(freshShop(), jar);
  const [accessToken] = shopify.minted;

  // Shopify revokes the access token mid-session.
  shopify.liveAccessTokens.delete(accessToken);

  const result = await getProducts(jar);

  // The whole point: the request the merchant made succeeds.
  assert.equal(result.status, 200, result.body);
  assert.deepEqual(JSON.parse(result.body), { data: { products: { edges: [] } } });

  assert.equal(callsOfType('refresh').length, 1, 'the app should refresh the token');

  const graphql = callsOfType('graphql');
  assert.equal(graphql.length, 2);
  assert.notEqual(
    graphql[1].token,
    accessToken,
    'the retry should use the refreshed token',
  );
});

scenario(
  'a rejected access token with a dead refresh token forces reauthorization and is evicted',
  async () => {
    const jar = newJar();
    await install(freshShop(), jar);

    // The app was uninstalled: both credentials are dead.
    shopify.liveAccessTokens.clear();
    shopify.liveRefreshTokens.clear();

    const first = await getProducts(jar);
    assert.equal(first.status, 401);
    assert.equal(first.body, 'Reauthorization required');

    // The dead token must not be sent again. A second request should stop before
    // reaching Shopify at all.
    const callsSoFar = shopify.calls.length;
    const second = await getProducts(jar);
    assert.equal(second.status, 401);
    assert.equal(
      second.body,
      'Not authenticated',
      'the rejected token should have been dropped from the store',
    );
    assert.equal(
      shopify.calls.length,
      callsSoFar,
      'a request with no usable token should not call Shopify',
    );
  },
);

scenario('a refreshed token that Shopify also rejects stops after one retry', async () => {
  const jar = newJar();
  await install(freshShop(), jar);

  // The refresh works, but nothing it hands back is accepted.
  shopify.liveAccessTokens.clear();
  shopify.refreshedTokensWork = false;

  const result = await getProducts(jar);

  assert.equal(result.status, 401);
  assert.equal(result.body, 'Reauthorization required');
  assert.equal(callsOfType('refresh').length, 1, 'exactly one recovery attempt, not a loop');
  assert.equal(callsOfType('graphql').length, 2);
});

scenario(
  'a transient refresh failure during recovery is retryable and keeps the refresh token',
  async () => {
    const jar = newJar();
    await install(freshShop(), jar);
    const [accessToken] = shopify.minted;
    shopify.liveAccessTokens.delete(accessToken);

    // Shopify's token endpoint is briefly unavailable.
    shopify.refreshStatus = 500;

    const during = await getProducts(jar);
    assert.equal(during.status, 503);
    assert.equal(during.body, 'Token refresh failed, try again');

    // The refresh token survived, so the next attempt recovers on its own.
    shopify.refreshStatus = 200;
    const after = await getProducts(jar);
    assert.equal(after.status, 200, after.body);
  },
);

scenario('an access token close to expiry is refreshed before the API call', async () => {
  const jar = newJar();
  shopify.expiresIn = 30;
  await install(freshShop(), jar);

  const result = await getProducts(jar);
  assert.equal(result.status, 200, result.body);

  assert.equal(callsOfType('refresh').length, 1);
  assert.equal(
    callsOfType('graphql').length,
    1,
    'the refreshed token should work first time',
  );
  assert.equal(callsOfType('graphql')[0].token, shopify.minted.at(-1));
});

scenario('a dead refresh token at expiry sends the merchant back through OAuth', async () => {
  const jar = newJar();
  shopify.expiresIn = 30;
  await install(freshShop(), jar);

  shopify.liveRefreshTokens.clear();

  const result = await getProducts(jar);
  assert.equal(result.status, 401);
  assert.equal(result.body, 'Reauthorization required');
  assert.equal(
    callsOfType('graphql').length,
    0,
    'do not send a token the app already knows is dead',
  );
});

scenario('an error status from Shopify is forwarded, not reported as success', async () => {
  const jar = newJar();
  await install(freshShop(), jar);

  // The token is fine; the request is throttled.
  shopify.apiStatus = 429;

  const result = await getProducts(jar);

  assert.equal(result.status, 429, 'a throttled request is not a successful one');
  assert.equal(
    callsOfType('refresh').length,
    0,
    'a rate limit is not a credential problem, so do not refresh',
  );
});

scenario(
  'a non-transient refresh failure during recovery is surfaced, not retried',
  async () => {
    const jar = newJar();
    await install(freshShop(), jar);
    const [accessToken] = shopify.minted;
    shopify.liveAccessTokens.delete(accessToken);

    // A malformed request or bad client credentials. Unlike a 5xx, waiting
    // changes nothing: the identical request returns the identical response.
    shopify.refreshStatus = 400;

    const result = await getProducts(jar);

    assert.equal(
      result.status,
      502,
      'a 400 from the token endpoint is not a "try again later" condition',
    );
    assert.equal(
      callsOfType('refresh').length,
      1,
      'do not retry an unrecoverable refresh',
    );
  },
);

scenario(
  'a non-transient refresh failure at expiry does not send the lapsing token',
  async () => {
    const jar = newJar();
    shopify.expiresIn = 30;
    await install(freshShop(), jar);

    shopify.refreshStatus = 400;

    const result = await getProducts(jar);

    assert.equal(result.status, 502);
    assert.equal(
      callsOfType('graphql').length,
      0,
      'the refresh failed, so the about-to-expire token must not go out',
    );
  },
);

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

// index.js calls app.listen() at import and exports no handle to close, so this
// file runs the scenarios itself and exits explicitly rather than leaving a
// listener holding the event loop open.
await import('./index.js');
await waitForServer();

let failures = 0;
for (const { name, run } of scenarios) {
  resetShopify();
  try {
    await run();
    console.log(`  ok    ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`  FAIL  ${name}`);
    console.error(`        ${error.message.split('\n').join('\n        ')}`);
  }
}

console.log(
  `\n${scenarios.length - failures}/${scenarios.length} recovery scenarios passed`,
);
process.exit(failures > 0 ? 1 : 0);

async function waitForServer() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      await realFetch(`${BASE}/products`);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`Server never came up on ${BASE}`);
}
