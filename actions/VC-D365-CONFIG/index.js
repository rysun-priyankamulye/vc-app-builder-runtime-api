const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';
const CONNECTIONS = [
  { connectionId: 'sat', prefix: 'D365_SAT' },
  { connectionId: 'sat3-us', prefix: 'D365_SAT3_US' },
  { connectionId: 'sat3-uk-eu', prefix: 'D365_SAT3_UK_EU' }
];
const CONFIG_FIELDS = [
  'APP_ID',
  'API_URL',
  'CLIENT_ID',
  'GRANT_TYPE',
  'CLIENT_SECRET'
];

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

function maskSecret(secret) {
  if (!secret) {
    return '';
  }

  if (secret.length <= 8) {
    return '********';
  }

  return `${secret.slice(0, 4)}********${secret.slice(-4)}`;
}

function getConfigValue(params, prefix, field) {
  const value = params[`${prefix}_${field}`];

  if (value || prefix !== 'D365_PRODUCTION') {
    return value || '';
  }

  return params[`D365_${field}`] || '';
}

function buildConfiguration(params, { connectionId, prefix }) {
  return CONFIG_FIELDS.reduce((config, field) => {
    const key = `D365_${field}`;
    const value = getConfigValue(params, prefix, field);
    config[key] = field === 'CLIENT_SECRET' ? maskSecret(value) : value;
    return config;
  }, { connectionId });
}

async function main(params) {
  if (params.__ow_method === 'options') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': '*'
      }
    };
  }

  if (params.__ow_method && params.__ow_method !== 'get') {
    return {
      statusCode: 405,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: { error: 'Method not allowed' }
    };
  }

  if (!validateSessionToken(params)) {
    return {
      statusCode: 401,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: { error: 'Unauthorized access' }
    };
  }

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    },
    body: {
      data: {
        configurations: CONNECTIONS.map((connection) => buildConfiguration(params, connection))
      }
    }
  };
}

exports.main = main;
