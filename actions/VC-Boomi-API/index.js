const axios = require('axios');
const { Core } = require('@adobe/aio-sdk');

async function main(params) {
  const logger = Core.Logger('main', { level: 'info' });

  logger.info('Incoming params:', JSON.stringify(params, null, 2));

  const { path, method = 'GET', data } = params;

  if (!path) {
    return {
      statusCode: 400,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'Missing required param: path' })
    };
  }

  const BOOMI_API_URL = params.BOOMI_API_URL;
  const BOOMI_API_KEY = params.BOOMI_API_KEY;

  if (!BOOMI_API_URL || !BOOMI_API_KEY) {
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'Missing Boomi config' })
    };
  }

  try {
    const response = await axios({
      method: method.toUpperCase(),
      url: `${BOOMI_API_URL}${path}`,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': BOOMI_API_KEY
      },
      data: method !== 'GET' ? data : undefined,
      timeout: 30000
    });

    return {
      statusCode: response.status,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(response.data)
    };
  } catch (error) {
    return {
      statusCode: error.response?.status || 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(
        error.response?.data || { error: 'Boomi request failed' }
      )
    };
  }
}

exports.main = main;
