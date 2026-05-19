const axios = require('axios');
const { Core } = require('@adobe/aio-sdk');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';

function resolveBoomiConfig(path, params) {
  if (typeof path === 'string') {
    if (path.startsWith('/v1/')) {
      return {
        apiUrl: params.BOOMI_API_URL,
        apiKey: params.V1_BOOMI_API_KEY
      };
    }

    if (path.startsWith('/v2/')) {
      return {
        apiUrl: params.BOOMI_API_URL,
        apiKey: params.V2_BOOMI_API_KEY
      };
    }
  }

  return {
    apiUrl: params.BOOMI_API_URL,
    apiKey: params.BOOMI_API_KEY
  };
}

function validateSessionToken(params) {
  const raw = params.__ow_headers?.['x-session-token'];
  console.log('Headers received:', params.__ow_headers);
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

  console.log('Received params:', params);

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
