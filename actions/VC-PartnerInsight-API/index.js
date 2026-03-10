const axios = require('axios');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';

function resolveApiConfig(path, params) {
  if (typeof path === 'string' && path.startsWith('/api/getaccount')) {
    return {
      apiUrl: params.WSP_GETACCOUNT_API_URL,
      apiKey: params.WSP_GETACCOUNT_API_KEY,
      error: 'Missing WSP getaccount config'
    };
  }

  return {
    apiUrl: params.PARTNER_INSIGHT_API_URL,
    apiKey: params.PARTNER_INSIGHT_API_KEY,
    error: 'Missing Partner Insight config'
  };
}

function buildRequestUrl(apiUrl, path) {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }

  if (typeof apiUrl === 'string' && apiUrl.endsWith(path)) {
    return apiUrl;
  }

  return `${apiUrl}${path}`;
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
    } catch {
      return {
        statusCode: 400,
        body: { error: 'Invalid JSON body' }
      };
    }
  }

  const { path, method = 'GET', data } = body;

  if (!path) {
    return { statusCode: 400, body: { error: 'Missing path' } };
  }

  const apiConfig = resolveApiConfig(path, params);
  const { apiUrl, apiKey, error: configError } = apiConfig;

  if (!apiUrl || !apiKey) {
    return {
      statusCode: 500,
      body: { error: configError }
    };
  }

  try {
    const response = await axios({
      method,
      url: buildRequestUrl(apiUrl, path),
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
      body: error.response?.data || { error: 'Partner Insight request failed' }
    };
  }
}

exports.main = main;
