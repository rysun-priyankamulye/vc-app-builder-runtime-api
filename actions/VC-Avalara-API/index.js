const axios = require('axios');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';

function validateSessionToken(params) {
  const raw = params.__ow_headers?.['x-session-token'];
  if (!raw) return false;

  try {
    const decoded = JSON.parse(
      Buffer.from(raw, 'base64').toString('utf-8')
    );

    const { exp, sig, ...payload } = decoded;

    const expectedSig = crypto
      .createHmac('sha256', SECRET)
      .update(JSON.stringify({ exp, ...payload }))
      .digest('hex');

    return sig === expectedSig && Date.now() <= exp;
  } catch {
    return false;
  }
}

function parseBody(params) {
  if (typeof params.__ow_body !== 'string' || params.__ow_body.trim().length === 0) {
    return {};
  }

  try {
    const decodedBody = Buffer.from(params.__ow_body, 'base64').toString('utf-8');
    return JSON.parse(decodedBody);
  } catch {
    return null;
  }
}

async function getAvalaraToken(tokenParams = {}) {
  const clientId = tokenParams.client_id || tokenParams.AVALARA_CLIENT_ID;
  const clientSecret = tokenParams.client_secret || tokenParams.AVALARA_CLIENT_SECRET;
  const grantType = tokenParams.grant_type || 'client_credentials';
  const scope = tokenParams.scope || 'avatax_api';

  if (!clientId || !clientSecret) {
    throw Object.assign(new Error('Missing Avalara client_id or client_secret'), { statusCode: 400 });
  }

  const form = new URLSearchParams();
  form.append('client_id', clientId);
  form.append('client_secret', clientSecret);
  form.append('grant_type', grantType);
  form.append('scope', scope);

  const response = await axios({
    method: 'POST',
    url: params.AVALARA_TOKEN_URL || 'https://identity.avalara.com/connect/token',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    data: form.toString(),
    timeout: 30000
  });

  return response.data;
}

async function resolveAddress(token, addressBody = {}, params = {}) {
  if (!token) {
    throw Object.assign(new Error('Avalara access token is required for address resolution'), { statusCode: 400 });
  }

  if (!addressBody || typeof addressBody !== 'object') {
    throw Object.assign(new Error('Missing address body to resolve'), { statusCode: 400 });
  }

  const clientHeaderValue = params.AVALARA_CLIENT_ID || params.AVALARA_CLIENT || null;

  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`
  };

  if (clientHeaderValue) {
    headers['X-Avalara-Client'] = clientHeaderValue;
  }

  const response = await axios({
    method: 'POST',
    url: params.AVALARA_RESOLVE_URL || 'https://rest.avatax.com/api/v2/addresses/resolve',
    headers,
    data: addressBody,
    timeout: 30000
  });

  return response.data;
}

async function main(params) {
  if (params.__ow_method === 'options') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': '*'
      }
    };
  }

  if (!validateSessionToken(params)) {
    return {
      statusCode: 401,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: 'Unauthorized access' })
    };
  }

  const body = parseBody(params);
  if (body === null) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Invalid JSON body' })
    };
  }

  try {
    if (body.operation === 'tokenCreate') {
      const tokenData = await getAvalaraToken({
        client_id: body.client_id || params.AVALARA_CLIENT_ID,
        client_secret: body.client_secret || params.AVALARA_CLIENT_SECRET,
        grant_type: body.grant_type || params.AVALARA_GRANT_TYPE || 'client_credentials',
        scope: body.scope || params.AVALARA_SCOPE || 'avatax_api'
      });

      return {
        statusCode: 200,
        body: tokenData
      };
    }

    if (body.operation === 'resolveAddress') {
      let token = body.token || (body.authorization?.replace(/^Bearer\s+/i, '') ?? null);

      if (!token) {
        const tokenResponse = await getAvalaraToken({
          client_id: body.client_id || params.AVALARA_CLIENT_ID,
          client_secret: body.client_secret || params.AVALARA_CLIENT_SECRET,
          grant_type: body.grant_type || params.AVALARA_GRANT_TYPE || 'client_credentials',
          scope: body.scope || params.AVALARA_SCOPE || 'avatax_api'
        });
        token = tokenResponse.access_token;
      }

      const resolved = await resolveAddress(token, body.address, params);
      return {
        statusCode: 200,
        body: resolved
      };
    }

    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Unsupported operation. Use operation: tokenCreate or resolveAddress' })
    };
  } catch (error) {
    return {
      statusCode: error.response?.status || error.statusCode || 500,
      body: JSON.stringify(error.response?.data || { error: error.message || 'Avalara request failed' })
    };
  }
}

exports.main = main;
