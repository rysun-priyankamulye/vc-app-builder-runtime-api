const axios = require('axios');
const { Core } = require('@adobe/aio-sdk');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';

const ALLOWED_V1_PREFIXES = [
  '/v1/d365-integration-apis',
  '/v1/track-notify'
];

function resolveBoomiConfig(path, params) {
  if (typeof path === 'string') {
    if (path.startsWith('/v1/d365-integration-apis')) {
      return {
        apiUrl: params.BOOMI_API_URL,
        apiKey: params.V1_D365_BOOMI_API_KEY
      };
    }

    if (path.startsWith('/v1/track-notify')) {
      return {
        apiUrl: params.BOOMI_API_URL,
        apiKey: params.V1_TRACK_NOTIFY_BOOMI_API_KEY
      };
    }

    if (path.startsWith('/v2/')) {
      return {
        apiUrl: params.BOOMI_API_URL,
        apiKey: params.V2_BOOMI_API_KEY
      };
    }

    if (path.startsWith('/v3/')) {
      return {
        apiUrl: params.BOOMI_API_URL_DEV,
        apiKey: params.V3_BOOMI_API_KEY
      };
    }
  }

  return {
    apiUrl: params.BOOMI_API_URL,
    apiKey: params.V2_BOOMI_API_KEY
  };
}

function isAllowedPath(path) {
  if (typeof path !== 'string' || path.length === 0) return false;
  if (!path.startsWith('/')) return false;

  // Restrict v1 requests to a known-safe allowlist.
  if (path.startsWith('/v1/')) {
    return ALLOWED_V1_PREFIXES.some((prefix) => path.startsWith(prefix));
  }

  // Keep existing behavior for other versions/paths.
  return true;
}

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

  let body = {};

  if (
    typeof params.__ow_body === 'string' &&
    params.__ow_body.trim().length > 0
  ) {
    try {
      const decodedBody = Buffer
        .from(params.__ow_body, 'base64')
        .toString('utf-8');

      body = JSON.parse(decodedBody);
    } catch (e) {
      return {
        statusCode: 400,
        body: {
          error: 'Invalid JSON body',
          raw: params.__ow_body
        }
      };
    }
  }

  const { path, method = 'GET', data } = body;

  if (!path) {
    return { statusCode: 400, body: { error: 'Missing path' } };
  }

  if (!isAllowedPath(path)) {
    return {
      statusCode: 400,
      body: {
        error: 'Path not allowed',
        allowedV1Prefixes: ALLOWED_V1_PREFIXES
      }
    };
  }

  const boomiConfig = resolveBoomiConfig(path, params);
  const { apiUrl, apiKey } = boomiConfig;

  if (!apiUrl || !apiKey) {
    return {
      statusCode: 500,
      body: { error: 'Missing Boomi config for the requested API version' }
    };
  }

  try {
    const response = await axios({
      method,
      url: `${apiUrl}${path}`,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey
      },
      data: method !== 'GET' ? data : undefined,
      timeout: 30000
    });

    return {
      statusCode: response.status,
      body: response.data
    };
  } catch (error) {
    return {
      statusCode: error.response?.status || 500,
      body: error.response?.data || { error: 'Boomi request failed' }
    };
  }
}

exports.main = main;
