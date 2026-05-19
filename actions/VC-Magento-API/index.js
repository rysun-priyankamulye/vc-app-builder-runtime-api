const axios = require('axios');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';

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

function parseBody(params) {
  if (
    typeof params.__ow_body !== 'string' ||
    params.__ow_body.trim().length === 0
  ) {
    return {};
  }

  try {
    const decodedBody = Buffer
      .from(params.__ow_body, 'base64')
      .toString('utf-8');

    return JSON.parse(decodedBody);
  } catch {
    return null;
  }
}

function buildRequestUrl(baseUrl, path) {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }

  const normalizedBase = String(baseUrl || '').replace(/\/+$/, '');
  const normalizedPath = String(path || '').startsWith('/')
    ? path
    : `/${path}`;

  return `${normalizedBase}${normalizedPath}`;
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
      body: { error: 'Unauthorized access' }
    };
  }

  const body = parseBody(params);

  if (body === null) {
    return {
      statusCode: 400,
      body: { error: 'Invalid JSON body' }
    };
  }

  const { path, method = 'POST', data = {} } = body;

  if (!path) {
    return {
      statusCode: 400,
      body: { error: 'Missing path' }
    };
  }

  const baseUrl = params.MAGENTO_API_URL;

  if (!baseUrl) {
    return {
      statusCode: 500,
      body: { error: 'Missing Magento API URL' }
    };
  }

  if (!data.customerEmail) {
    return {
      statusCode: 400,
      body: { error: 'customerEmail is required' }
    };
  }

  try {
    const response = await axios({
      method,
      url: buildRequestUrl(baseUrl, path),
      headers: {
        'Content-Type': 'application/json'
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
      body: error.response?.data || { error: 'Magento request failed' }
    };
  }
}

exports.main = main;
