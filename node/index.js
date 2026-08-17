import express from 'express';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import * as dotenv from 'dotenv';

dotenv.config();

// Falls back to a random secret for local dev. Set COOKIE_SECRET in production
// so signed cookies stay valid across restarts and deployments.
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(64).toString('hex');

const app = express();
app.use(cookieParser(COOKIE_SECRET));

const CLIENT_ID = process.env.SHOPIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const SCOPES = process.env.SCOPES || 'read_products,write_orders';

// In-memory token store (use a database in production)
const tokenStore = {};

// Send cookies only over HTTPS in production; over plain HTTP on localhost in
// dev. httpOnly + sameSite protect them the rest of the time.
const cookieOptions = {
  signed: true,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
};

// A valid expiring-token response includes expires_in (seconds until the access
// token expires). Return null when it's absent or non-positive: treat the token
// as non-expiring and never refresh it. Storing Date.now() instead would make
// the next request refresh a token that has no refresh_token — a permanent 401.
function expiresAtFrom(expiresIn) {
  const seconds = Number(expiresIn);
  return seconds > 0 ? Date.now() + seconds * 1000 : null;
}

function isValidShopDomain(shop) {
  return /^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop);
}

// Node's fetch has no timeout, so a stalled connection to Shopify would hang a
// request until the client gives up. Give every call a deadline, and tag transport
// failures so callers can tell "Shopify said no" from "we never reached Shopify".
// fetch rejects only on a transport failure or this timeout: every HTTP status,
// including 5xx, resolves and is the caller's to handle.
const SHOPIFY_TIMEOUT_MS = 30_000;

class ShopifyUnreachable extends Error {}

async function shopifyFetch(url, options) {
  try {
    return await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(SHOPIFY_TIMEOUT_MS),
    });
  } catch (cause) {
    throw new ShopifyUnreachable(`Could not reach ${new URL(url).hostname}`, { cause });
  }
}

// [START oauth.build-authorization-url]
app.get('/install', (req, res) => {
  const { shop } = req.query;

  if (!isValidShopDomain(shop)) {
    return res.status(400).send('Invalid shop domain');
  }

  const nonce = crypto.randomBytes(16).toString('hex');
  // Store the nonce in a signed cookie so you can verify it against the callback
  res.cookie('oauth_state', nonce, cookieOptions);

  const authUrl = `https://${shop}/admin/oauth/authorize?` +
    new URLSearchParams({
      client_id: CLIENT_ID,
      scope: SCOPES,
      redirect_uri: REDIRECT_URI,
      state: nonce,
    });

  res.redirect(authUrl);
});
// [END oauth.build-authorization-url]

app.get('/callback', async (req, res) => {
  const { code, hmac, shop, state } = req.query;

  // [START oauth.validate-state]
  if (!state || state !== req.signedCookies.oauth_state) {
    return res.status(403).send('Invalid state parameter');
  }
  res.clearCookie('oauth_state');
  // [END oauth.validate-state]

  // [START oauth.verify-hmac]
  const params = Object.fromEntries(
    Object.entries(req.query).filter(([key]) => key !== 'hmac')
  );
  const message = Object.entries(params).sort().map(([k, v]) => `${k}=${v}`).join('&');
  const digest = crypto.createHmac('sha256', CLIENT_SECRET).update(message).digest('hex');
  const digestBuf = Buffer.from(digest);
  const hmacBuf = Buffer.from(String(hmac));
  if (digestBuf.length !== hmacBuf.length || !crypto.timingSafeEqual(digestBuf, hmacBuf)) {
    return res.status(403).send('Invalid HMAC');
  }
  // [END oauth.verify-hmac]

  // [START oauth.validate-shop]
  if (!isValidShopDomain(shop)) {
    return res.status(400).send('Invalid shop domain');
  }
  // [END oauth.validate-shop]

  // [START oauth.exchange-code]
  const tokenResponse = await shopifyFetch(`https://${shop}/admin/oauth/access_token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      expiring: '1',
    }),
  });

  if (!tokenResponse.ok) {
    return res.status(403).send('Token exchange failed');
  }

  const { access_token, refresh_token, scope, expires_in } = await tokenResponse.json();
  // [END oauth.exchange-code]

  // [START oauth.confirm-scopes]
  const granted = scope.split(',');
  // A write_* grant includes its matching read_* scope, so Shopify may return
  // only the write scope. Treat a requested read_* as satisfied by its write_*.
  const missing = SCOPES.split(',').filter(s =>
    !granted.includes(s) &&
    !(s.startsWith('read_') && granted.includes(`write_${s.slice(5)}`))
  );
  if (missing.length > 0) return res.status(403).send(`Missing scopes: ${missing.join(', ')}`);
  // [END oauth.confirm-scopes]

  // Store tokens server-side, keyed by shop (use a database in production).
  // Track when the access token expires so requests can refresh it in time.
  tokenStore[shop] = {
    access_token,
    refresh_token,
    expires_at: expiresAtFrom(expires_in),
  };

  // Set a signed session cookie so subsequent requests can identify the shop
  res.cookie('shop', shop, cookieOptions);
  res.json({ message: 'App installed', shop, scope });
});

// Exchange the stored refresh token for a new access token. The return value
// tells the caller how to react, and matches the refresh error handling used
// across grant types:
//   'refreshed'   — got a new access token
//   'reauthorize' — a 401 means the refresh token is terminal (expired, revoked,
//                   replayed after the one-hour retry window, or the app was
//                   uninstalled); send the merchant back through OAuth
//   'retry'       — a transient failure (network, timeout, 5xx, 429); safe to
//                   retry later with the same refresh token
async function refreshAccessToken(shop) {
  const stored = tokenStore[shop];
  if (!stored?.refresh_token) return 'reauthorize';

  let response;
  try {
    response = await shopifyFetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'refresh_token',
        refresh_token: stored.refresh_token,
      }),
    });
  } catch (error) {
    // Only a transport failure or timeout becomes 'retry': the request never
    // reached Shopify, so the refresh token is untouched and a later attempt is
    // safe. Anything else is a bug in this code — let it surface.
    if (!(error instanceof ShopifyUnreachable)) throw error;
    return 'retry';
  }

  if (response.status === 401) {
    delete tokenStore[shop];
    return 'reauthorize';
  }
  if (!response.ok) return 'retry';

  const { access_token, refresh_token, expires_in } = await response.json();
  tokenStore[shop] = {
    access_token,
    refresh_token,
    expires_at: expiresAtFrom(expires_in),
  };
  return 'refreshed';
}

// [START oauth.make-request]
app.get('/products', async (req, res) => {
  const shop = req.signedCookies.shop;
  if (!shop) return res.status(401).send('Not authenticated');

  let stored = tokenStore[shop];
  if (!stored) return res.status(401).send('Not authenticated');

  // Expiring access tokens are short-lived. Refresh ~60 seconds before the token
  // actually expires so a request never goes out with a token that lapses
  // mid-flight.
  if (stored.expires_at && Date.now() >= stored.expires_at - 60 * 1000) {
    const result = await refreshAccessToken(shop);
    if (result === 'reauthorize') {
      return res.status(401).send('Reauthorization required');
    }
    if (result === 'retry') {
      return res.status(503).send('Token refresh failed, try again');
    }
    stored = tokenStore[shop];
  }

  const callAdminApi = (accessToken) =>
    shopifyFetch(`https://${shop}/admin/api/2026-04/graphql.json`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': accessToken,
      },
      body: JSON.stringify({ query: '{ products(first: 5) { edges { node { id handle } } } }' }),
    });

  let response = await callAdminApi(stored.access_token);

  // Shopify rejected the access token: it was revoked, the app's access scopes
  // changed, or it lapsed sooner than expires_in implied. This app runs outside
  // the Shopify admin, so it has no ID token to exchange — the refresh token is
  // the only way back. Try it once, then give up rather than sending the same
  // rejected token again on every later request.
  if (response.status === 401) {
    const result = await refreshAccessToken(shop);
    if (result === 'retry') {
      // Transient: the refresh token is untouched, so a later attempt is fine.
      return res.status(503).send('Token refresh failed, try again');
    }
    if (result !== 'refreshed') {
      // Drop the rejected token so the next request doesn't send it again.
      delete tokenStore[shop];
      return res.status(401).send('Reauthorization required');
    }

    response = await callAdminApi(tokenStore[shop].access_token);

    // Retry once, not in a loop. A freshly refreshed token that's also rejected
    // means something is wrong beyond a lapsed credential, so stop and send the
    // merchant back through OAuth.
    if (response.status === 401) {
      delete tokenStore[shop];
      return res.status(401).send('Reauthorization required');
    }
  }

  // Forward Shopify's status. Answering a rate limit or an outage with a 200 and
  // an error body in it would tell the client the request succeeded.
  res.status(response.status).json(await response.json());
});
// [END oauth.make-request]

// The routes above let a transport failure or timeout propagate. The request never
// reached Shopify, so nothing was consumed and the caller can try again: 503 says
// that, while the stack trace Express would otherwise return says the app is broken.
app.use((err, req, res, next) => {
  if (err instanceof ShopifyUnreachable) {
    return res.status(503).send('Could not reach Shopify, try again');
  }
  next(err);
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
