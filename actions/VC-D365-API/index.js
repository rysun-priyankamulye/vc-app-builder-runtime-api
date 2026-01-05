const fetch = require('node-fetch');
const { Core } = require('@adobe/aio-sdk');
const { errorResponse, stringParameters } = require('../utils');


function parseQuery(queryString = '') {
  return Object.fromEntries(new URLSearchParams(queryString));
}

async function main(params) {
  const logger = Core.Logger('main', { level: params.LOG_LEVEL || 'info' });

  const D365_API_URL = params.D365_API_URL;
  const D365_API_KEY = params.D365_API_KEY;

  if (!D365_API_URL || !D365_API_KEY) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Missing D365 configuration' }),
    };
  }

  const queryParams = parseQuery(params.__ow_query);

  const {
    customerId,
    action,
    recordId,
    page,
    pageSize,
    searchTerm,
  } = queryParams;


  if (!action) {
    return errorResponse(400, 'Missing required param: action', logger);
  }

  // Build endpoint dynamically
  let endpoint = '';
  switch (action) {
    case 'ordersHistory':
      endpoint = `${D365_API_URL}/customers/${customerId}/orders`;
      break;
    case 'orderDetails':
      endpoint = `${D365_API_URL}/orders/${recordId}`;
      break;
    case 'invoiceHistory':
      endpoint = `${D365_API_URL}/customers/invoices?accounts=${customerId}`;
      break;
    case 'invoiceDetails':
      endpoint = `${D365_API_URL}/customers/invoices/${recordId}`;
      break;
    case 'invoiceSearch':
      endpoint = `${D365_API_URL}/customers/invoices/search?account=${customerId}&searchTerm=${searchTerm}&page=${page || 1}&pageSize=${pageSize || 20}&sortBy=amount_desc`;
      break;
    case 'creditMemoHistory':
      endpoint = `${D365_API_URL}/customers/credits?accounts=${customerId}`;
      break;
    case 'creditMemoDetails':
      endpoint = `${D365_API_URL}/customers/credits/${recordId}`;
      break;
    case 'creditMemoSearch':
      endpoint = `${D365_API_URL}/customers/credits/search?account=${customerId}&searchTerm=${searchTerm}&page=${page || 1}&pageSize=${pageSize || 20}&sortBy=CreditMemoDate_desc`;
      break;
    default:
      return errorResponse(400, 'Invalid action param', logger);
  }

  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': D365_API_KEY,
      },
    });

    if (!res.ok) {
      throw new Error(`Request failed with status ${res.status}`);
    }

    const content = await res.json();
    return {
      statusCode: 200,
      body: content,
    };
  } catch (error) {
    logger.error(error);
    return errorResponse(500, 'Server error', logger);
  }
}

exports.main = main;