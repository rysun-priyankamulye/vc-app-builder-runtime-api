const axios = require('axios');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';
const HEADER_API = 'VCSalesQuotationHeaders';
const LINE_ITEM_API = 'VCSalesQuotationLines';
const REGION_CODE = 'WEB';
const DELETE_API = '/api/services/VCSOPOServiceGroup/VCPOService/cancelSalesQuotation';
const CONNECTION_ENV_PREFIXES = {
  sat: 'D365_SAT',
  'sat3-us': 'D365_SAT3_US',
  'sat3-uk-eu': 'D365_SAT3_UK_EU'
};

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

function buildRequestUrl(baseUrl, path) {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }

  const normalizedBase = String(baseUrl || '').replace(/\/+$/, '');
  const normalizedPath = String(path || '').startsWith('/') ? path : `/${path}`;
  return `${normalizedBase}${normalizedPath}`;
}

function parseBody(params) {
  if (
    typeof params.__ow_body !== 'string' ||
    params.__ow_body.trim().length === 0
  ) {
    return {};
  }

  try {
    const decodedBody = Buffer.from(params.__ow_body, 'base64').toString('utf-8');
    return JSON.parse(decodedBody);
  } catch {
    return null;
  }
}

function readD365Config(params, prefix) {
  return {
    D365_APP_ID: params[`${prefix}_APP_ID`],
    D365_API_URL: params[`${prefix}_API_URL`],
    D365_CLIENT_ID: params[`${prefix}_CLIENT_ID`],
    D365_GRANT_TYPE: params[`${prefix}_GRANT_TYPE`],
    D365_CLIENT_SECRET: params[`${prefix}_CLIENT_SECRET`]
  };
}

function readLegacyD365Config(params) {
  return {
    D365_APP_ID: params.D365_APP_ID,
    D365_API_URL: params.D365_API_URL,
    D365_CLIENT_ID: params.D365_CLIENT_ID,
    D365_GRANT_TYPE: params.D365_GRANT_TYPE,
    D365_CLIENT_SECRET: params.D365_CLIENT_SECRET
  };
}

function resolveD365Config(params, body) {
  const rawConnectionId =
    body.connectionId ||
    params.connectionId ||
    params.connectionid;

  if (!rawConnectionId) {
    throw Object.assign(new Error('Missing connectionId'), {
      statusCode: 400
    });
  }

  const connectionId = String(rawConnectionId).trim().toLowerCase();

  // Production uses the existing D365_* variables
  if (connectionId === 'production') {
    return readLegacyD365Config(params);
  }

  const prefix = CONNECTION_ENV_PREFIXES[connectionId];

  if (!prefix) {
    throw Object.assign(
      new Error(`Unsupported connectionId: ${rawConnectionId}`),
      { statusCode: 400 }
    );
  }

  return readD365Config(params, prefix);
}

async function getD365AccessToken(config) {
  const {
    D365_APP_ID,
    D365_API_URL,
    D365_CLIENT_ID,
    D365_GRANT_TYPE,
    D365_CLIENT_SECRET
  } = config;

  if (!D365_APP_ID || !D365_API_URL || !D365_CLIENT_ID || !D365_GRANT_TYPE || !D365_CLIENT_SECRET) {
    throw Object.assign(new Error('Missing D365 configuration'), { statusCode: 500 });
  }

  const form = new URLSearchParams();
  form.append('client_id', D365_CLIENT_ID);
  form.append('grant_type', D365_GRANT_TYPE);
  form.append('resource', D365_API_URL);
  form.append('client_secret', D365_CLIENT_SECRET);

  const authResponse = await axios({
    method: 'POST',
    url: `https://login.windows.net/${D365_APP_ID}/oauth2/token`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    data: form.toString(),
    timeout: 30000
  });

  return `${authResponse.data.token_type} ${authResponse.data.access_token}`;
}

function buildQuoteHeadersPath(data) {
  const {
    d365CustID,
    searchQuery = '',
    hasSearch = false,
    cancelled = false,
    confirmed = false,
    skip = 0,
    top = 10,
    orderby = 'ModifiedAt desc',
    perPage
  } = data;

  if (!d365CustID) {
    throw Object.assign(new Error('Missing d365CustID'), { statusCode: 400 });
  }

  let filter;
  if (searchQuery) {
    if (hasSearch) {
      filter = `RequestingCustomerAccountNumber eq '${d365CustID}' and (VCProjectName eq '*${searchQuery}*' or SalesQuotationNumber eq '*${searchQuery}*') and SalesQuotationStatus ne Microsoft.Dynamics.DataEntities.SalesQuotationStatus'Cancelled' and SalesQuotationStatus ne Microsoft.Dynamics.DataEntities.SalesQuotationStatus'Confirmed'`;
    } else if (cancelled && confirmed) {
      filter = `RequestingCustomerAccountNumber eq '${d365CustID}' and SalesQuotationNumber eq '${searchQuery}'`;
    } else {
      filter = `RequestingCustomerAccountNumber eq '${d365CustID}' and SalesQuotationNumber eq '${searchQuery}' and SalesQuotationStatus ne Microsoft.Dynamics.DataEntities.SalesQuotationStatus'Cancelled' and SalesQuotationStatus ne Microsoft.Dynamics.DataEntities.SalesQuotationStatus'Confirmed'`;
    }
  } else {
    filter = `RequestingCustomerAccountNumber eq '${d365CustID}' and SalesQuotationStatus ne Microsoft.Dynamics.DataEntities.SalesQuotationStatus'Cancelled' and SalesQuotationStatus ne Microsoft.Dynamics.DataEntities.SalesQuotationStatus'Confirmed'`;
  }

  const query = new URLSearchParams();
  query.set('$filter', filter);
  query.set('$top', String(top));
  query.set('$skip', String(skip));
  query.set('$count', 'true');
  query.set('$orderby', orderby);
  if (perPage) {
    query.set('perPage', String(perPage));
  }

  return `/data/${HEADER_API}?${query.toString()}`;
}

function buildQuoteLinesPath(data) {
  const {
    SalesQuotationNumber,
    skip = 0,
    top = 100,
    select
  } = data;

  if (!SalesQuotationNumber) {
    throw Object.assign(new Error('Missing SalesQuotationNumber'), { statusCode: 400 });
  }

  const query = new URLSearchParams();
  query.set('$filter', `SalesQuotationNumber eq '${SalesQuotationNumber}'`);
  query.set('$top', String(top));
  query.set('$skip', String(skip));
  query.set('$orderby', 'LineNumber');
  if (select) {
    query.set('$select', select);
  }

  return `/data/${LINE_ITEM_API}?${query.toString()}`;
}

function buildDeleteQuoteRequest(data) {
  const salesQuotationNumber = data.SalesQuotationNumber || data.salesQuotationNumber;

  if (!salesQuotationNumber) {
    throw Object.assign(new Error('Missing SalesQuotationNumber'), { statusCode: 400 });
  }

  return {
    method: 'POST',
    path: DELETE_API,
    data: {
      request: [
        {
          QuotationNumber: salesQuotationNumber,
          ReasonCode: REGION_CODE
        }
      ]
    }
  };
}

function buildDeleteQuoteLineItemRequest(data) {
  const inventoryLotId = data.InventoryLotId || data.inventoryLotId;
  const dataAreaId = data.dataAreaId || 'VC';

  if (inventoryLotId) {
    return {
      method: 'DELETE',
      path: `/data/${LINE_ITEM_API}(InventoryLotId='${encodeURIComponent(inventoryLotId)}',dataAreaId='${dataAreaId}')`
    };
  }

  const apiName = data.apiName;

  if (!apiName) {
    throw Object.assign(new Error('Missing InventoryLotId or apiName'), { statusCode: 400 });
  }

  if (
    apiName.includes(`${LINE_ITEM_API}(`) &&
    apiName.includes('SalesQuotationNumber=') &&
    apiName.includes('LineNumber=')
  ) {
    throw Object.assign(
      new Error('deleteQuoteLineItem expects InventoryLotId for VCSalesQuotationLines deletes. Pass InventoryLotId instead of SalesQuotationNumber/LineNumber.'),
      { statusCode: 400 }
    );
  }

  return {
    method: 'DELETE',
    path: `/data/${apiName}`
  };
}

function buildUpdateQuoteLineItemRequest(data) {
  const inventoryLotId = data.InventoryLotId || data.inventoryLotId;
  const dataAreaId = data.dataAreaId || 'VC';

  if (!inventoryLotId) {
    throw Object.assign(new Error('Missing InventoryLotId'), { statusCode: 400 });
  }

  let updateData = {};
  const hasQty = data.RequestedSalesQuantity !== undefined && !isNaN(parseInt(data.RequestedSalesQuantity, 10));
  const hasSidemark = data.VCSidemark !== undefined && data.VCSidemark !== '';

  if (hasQty) {
    updateData.RequestedSalesQuantity = parseInt(data.RequestedSalesQuantity, 10);
  }
  if (hasSidemark) {
    updateData.VCSidemark = data.VCSidemark;
  }

  if (Object.keys(updateData).length === 0) {
    throw Object.assign(new Error('No valid fields to update (only RequestedSalesQuantity or VCSidemark allowed)'), { statusCode: 400 });
  }

  return {
    method: 'PATCH',
    path: `/data/${LINE_ITEM_API}(InventoryLotId='${encodeURIComponent(inventoryLotId)}',dataAreaId='${dataAreaId}')`,
    data: updateData
  };

}

function resolveRequest(body) {
  if (body.path) {
    return {
      method: body.method || 'GET',
      path: body.path,
      data: body.data,
      headers: body.headers || {}
    };
  }

  if (body.operation === 'listQuoteHeaders') {
    return {
      method: 'GET',
      path: buildQuoteHeadersPath(body),
      data: undefined,
      headers: body.headers || {}
    };
  }

  if (body.operation === 'listQuoteLines') {
    return {
      method: 'GET',
      path: buildQuoteLinesPath(body),
      data: undefined,
      headers: body.headers || {}
    };
  }

  if (body.operation === 'deleteQuote') {
    return {
      ...buildDeleteQuoteRequest(body),
      headers: body.headers || {}
    };
  }

  if (body.operation === 'deleteQuoteLineItem') {
    return {
      ...buildDeleteQuoteLineItemRequest(body),
      headers: body.headers || {}
    };
  }

  if (body.operation === 'updateQuoteLineItem') {
    return {
      ...buildUpdateQuoteLineItemRequest(body),
      headers: body.headers || {}
    };
  }

  return null;
}

async function main(params) {
  if (params.__ow_method === 'options') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, PATCH, DELETE, OPTIONS',
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
      body: { error: 'Invalid JSON body' }
    };
  }

  const requestConfig = resolveRequest(body);

  if (!requestConfig?.path) {
    return {
      statusCode: 400,
      body: { error: 'Missing path or supported operation' }
    };
  }

  try {
    const d365Config = resolveD365Config(params, body);
    const accessToken = await getD365AccessToken(d365Config);
    const response = await axios({
      method: requestConfig.method,
      url: buildRequestUrl(d365Config.D365_API_URL, requestConfig.path),
      headers: {
        'Content-Type': 'application/json',
        Authorization: accessToken,
        ...requestConfig.headers
      },
      data: requestConfig.method !== 'GET' ? requestConfig.data : undefined,
      timeout: 30000
    });

    return {
      statusCode: response.status,
      body: response.data
    };
  } catch (error) {
    return {
      statusCode: error.response?.status || error.statusCode || 500,
      body: error.response?.data || { error: error.statusCode ? error.message : 'D365 request failed' }
    };
  }
}

exports.main = main;
