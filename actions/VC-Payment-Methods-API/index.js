const axios = require('axios');
const crypto = require('crypto');

const PROVIDER_FISERV = 'fiserv';
const PROVIDER_FISERV_US_BUSINESS = 'fiserv_us_business';
const PROVIDER_CYBERSOURCE = 'cybersource';
const PROVIDER_CYBERSOURCE_US_BUSINESS = 'cybersource_us_business';
const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';

function shouldDebug(params) {
  return ['debug', 'trace'].includes(String(params.LOG_LEVEL || '').toLowerCase());
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

function pickFirst(...values) {
  return values.find((value) => typeof value === 'string' && value.trim() !== '') || '';
}

function normalizeCustomerType(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  if (['wholesale', 'ws'].includes(raw)) return 'wholesale';
  if (['retail', 'rt'].includes(raw)) return 'retail';
  if (['trade', 'tl'].includes(raw)) return 'trade';
  return raw;
}

function getPayload(params) {
  const body = parseBody(params);
  if (body === null) {
    return { error: 'Invalid JSON body' };
  }

  const query = params.__ow_query || {};
  const method = String(params.__ow_method || 'get').toLowerCase();

  const provider = body.provider || query.provider || PROVIDER_FISERV;
  const operationRaw = body.operation || query.operation || (method === 'delete' ? 'delete' : 'list');
  const operation = ['add', 'create', 'save'].includes(String(operationRaw || '').toLowerCase())
    ? 'add'
    : String(operationRaw || '').toLowerCase();

  const customerNumbers = {
    customerNumberVC: pickFirst(
      body.customerNumberVC,
      body.customer_number_vc,
      query.customerNumberVC,
      query.customer_number_vc
    ),
    customerNumberTL: pickFirst(
      body.customerNumberTL,
      body.customer_number_tl,
      body.customerNumberTech,
      body.customer_number_tech,
      query.customerNumberTL,
      query.customer_number_tl,
      query.customerNumberTech,
      query.customer_number_tech
    ),
    customerNumberGL: pickFirst(
      body.customerNumberGL,
      body.customer_number_gl,
      query.customerNumberGL,
      query.customer_number_gl
    ),
    customerNumberD365: pickFirst(
      body.customerNumberD365,
      body.customer_number_d365,
      body.d365_customer_number,
      query.customerNumberD365,
      query.customer_number_d365,
      query.d365_customer_number
    )
  };

  return {
    provider,
    operation: String(operation).toLowerCase(),
    customerType: normalizeCustomerType(
      pickFirst(
        body.customerType,
        body.customer_type,
        query.customerType,
        query.customer_type
      )
    ),
    customerId: pickFirst(body.customerId, body.customer_id, query.customerId, query.customer_id),
    cardToken: pickFirst(body.cardToken, body.token, query.cardToken, query.token),
    customerTokenId: pickFirst(body.customerTokenId, body.customer_token_id, query.customerTokenId, query.customer_token_id),
    paymentInstrumentId: pickFirst(
      body.paymentInstrumentId,
      body.payment_instrument_id,
      query.paymentInstrumentId,
      query.payment_instrument_id
    ),
    cardInformation: body.cardInformation || body.card_information || null,
    cardNumber: pickFirst(
      body.cardNumber,
      body.card_number,
      body.number,
      body.cc_number,
      query.cardNumber,
      query.card_number,
      query.number,
      query.cc_number
    ),
    cardExpirationMonth: pickFirst(
      body.cardExpirationMonth,
      body.card_expiration_month,
      body.expirationMonth,
      body.expiration_month,
      body.cc_expiration_month,
      query.cardExpirationMonth,
      query.card_expiration_month,
      query.expirationMonth,
      query.expiration_month,
      query.cc_expiration_month
    ),
    cardExpirationYear: pickFirst(
      body.cardExpirationYear,
      body.card_expiration_year,
      body.expirationYear,
      body.expiration_year,
      body.cc_expiration_year,
      query.cardExpirationYear,
      query.card_expiration_year,
      query.expirationYear,
      query.expiration_year,
      query.cc_expiration_year
    ),
    cardCvv: pickFirst(
      body.cardCvv,
      body.card_cvv,
      body.ccv,
      body.cvv,
      body.cc_cvv,
      query.cardCvv,
      query.card_cvv,
      query.ccv,
      query.cvv,
      query.cc_cvv
    ),
    cardType: pickFirst(
      body.cardType,
      body.card_type,
      body.type,
      body.cc_type,
      query.cardType,
      query.card_type,
      query.type,
      query.cc_type
    ),
    cardHolderName: pickFirst(
      body.cardHolderName,
      body.card_holder_name,
      body.cc_holder_name,
      body.name_on_card,
      query.cardHolderName,
      query.card_holder_name,
      query.cc_holder_name,
      query.name_on_card
    ),
    cardNickname: pickFirst(
      body.cardNickname,
      body.card_nickname,
      body.cc_nickname,
      query.cardNickname,
      query.card_nickname,
      query.cc_nickname
    ),
    transactionAmount: pickFirst(body.transactionAmount, body.transaction_amount, query.transactionAmount, query.transaction_amount),
    saveForFutureOrders: body.saveForFutureOrders ?? body.save_for_future_orders ?? body.save_credit_card ?? body.saveCard ?? query.saveForFutureOrders ?? query.save_for_future_orders ?? query.save_credit_card ?? query.saveCard ?? null,
    currency: pickFirst(body.currency, query.currency),
    reference: pickFirst(body.reference, body.orderReference, body.order_reference, query.reference, query.orderReference, query.order_reference),
    purchaseOrder: pickFirst(body.purchaseOrder, body.purchase_order, body.po, query.purchaseOrder, query.purchase_order, query.po),
    orderId: pickFirst(body.orderId, body.order_id, body.incrementId, body.increment_id, query.orderId, query.order_id, query.incrementId, query.increment_id),
    billTo: body.billTo || body.bill_to || body.billingAddress || body.billing_address || null,
    billingAddressId: pickFirst(
      body.billingAddressId,
      body.billing_address_id,
      query.billingAddressId,
      query.billing_address_id
    ),
    isDefaultCard: body.isDefaultCard ?? body.is_default ?? body.isDefault ?? query.isDefaultCard ?? query.is_default ?? query.isDefault ?? null,
    customerNumbers
  };
}

function trimSlashes(value) {
  return String(value || '').replace(/^\/+|\/+$/g, '');
}

function buildProviderConfig(params, provider) {
  if (provider === PROVIDER_FISERV || provider === PROVIDER_FISERV_US_BUSINESS) {
    return {
      provider,
      baseUrl: params.FISERV_USB_API_URL,
      apiKey: params.FISERV_USB_API_KEY,
      appName: params.FISERV_USB_X_APPLICATION_NAME,
      appNameWholesale: params.FISERV_USB_X_APPLICATION_NAME_WHOLESALE,
      appNameRetail: params.FISERV_USB_X_APPLICATION_NAME_RETAIL,
      listPath: params.FISERV_USB_LIST_PATH || 'api/FiservPayment/saved-cards',
      deletePath: params.FISERV_USB_DELETE_PATH || 'api/FiservPayment/delete-card',
      addPath: params.FISERV_USB_ADD_PATH || 'api/FiservPayment/authorize'
    };
  }

  if (provider === PROVIDER_CYBERSOURCE || provider === PROVIDER_CYBERSOURCE_US_BUSINESS) {
    const useTestMode = String(params.CYBERSOURCE_USE_TEST_MODE || '').toLowerCase();
    const defaultBaseUrl = useTestMode === '1' || useTestMode === 'true'
      ? 'https://apitest.cybersource.com'
      : 'https://api.cybersource.com';

    return {
      provider,
      // CyberSource direct credentials (REST HTTP Signature auth)
      baseUrl: params.CYBERSOURCE_API_BASE_URL || defaultBaseUrl,
      merchantId: params.CYBERSOURCE_MERCHANT_ID || '',
      keyId: params.CYBERSOURCE_REST_KEY_ID || '',
      sharedSecret: params.CYBERSOURCE_REST_KEY_VALUE || '',
      tmsCustomerPathPrefix: params.CYBERSOURCE_TMS_CUSTOMER_PATH_PREFIX || 'tms/v2/customers'
    };
  }

  return null;
}

function buildUrl(baseUrl, path) {
  const normalizedBase = String(baseUrl || '').replace(/\/+$/, '');
  const normalizedPath = trimSlashes(path);
  return `${normalizedBase}/${normalizedPath}`;
}

function hasCustomerNumbers(numbers) {
  return Object.values(numbers).some((value) => typeof value === 'string' && value.trim() !== '');
}

function normalizeNumbers(numbers, isTradeRetail = true) {
  const normalized = {
    customerNumberVC: pickFirst(numbers.customerNumberVC),
    customerNumberTL: pickFirst(numbers.customerNumberTL),
    customerNumberGL: pickFirst(numbers.customerNumberGL),
    customerNumberD365: pickFirst(numbers.customerNumberD365)
  };

  // Magento behavior: for non-wholesale customers, GL is aligned with D365.
  if (isTradeRetail && !normalized.customerNumberGL && normalized.customerNumberD365) {
    normalized.customerNumberGL = normalized.customerNumberD365;
  }

  return normalized;
}

function isWholesaleCustomer(payload) {
  return payload.customerType === 'wholesale';
}

function pickAnyCustomerNumber(numbers) {
  return pickFirst(
    numbers.customerNumberD365,
    numbers.customerNumberGL,
    numbers.customerNumberTL,
    numbers.customerNumberVC
  );
}

function expandCustomerNumbersForFiserv(numbers, params, payload = null) {
  // Keep wholesale identifiers exact. Their VC/TL/GL/D365 account numbers
  // can differ, and auto-filling missing values with one fallback can cause
  // saved-card delete/list requests to miss the real token.
  if (payload && isWholesaleCustomer(payload)) {
    return numbers;
  }

  const enabledRaw = String(params.FISERV_AUTO_FILL_CUSTOMER_NUMBERS || 'true').toLowerCase();
  const enabled = !['0', 'false', 'no'].includes(enabledRaw);
  if (!enabled) {
    return numbers;
  }

  const fallback = pickAnyCustomerNumber(numbers);
  if (!fallback) {
    return numbers;
  }

  return {
    customerNumberVC: numbers.customerNumberVC || fallback,
    customerNumberTL: numbers.customerNumberTL || fallback,
    customerNumberGL: numbers.customerNumberGL || fallback,
    customerNumberD365: numbers.customerNumberD365 || fallback
  };
}

function tryExtractNumbers(source) {
  if (!source || typeof source !== 'object') {
    return null;
  }

  return {
    customerNumberVC: pickFirst(source.customerNumberVC, source.customer_number_vc),
    customerNumberTL: pickFirst(source.customerNumberTL, source.customer_number_tech, source.customerNumberTech),
    customerNumberGL: pickFirst(source.customerNumberGL, source.customer_number_gl),
    customerNumberD365: pickFirst(source.customerNumberD365, source.d365_customer_number, source.customer_number_d365)
  };
}

async function fetchCustomerNumbersByCustomerId(customerId, params) {
  const apiUrl = params.WSP_GETACCOUNT_API_URL;
  const apiKey = params.WSP_GETACCOUNT_API_KEY;
  const apiPath = params.WSP_GETACCOUNT_API_PATH || '/api/getaccount';

  if (!apiUrl || !apiKey || !customerId) {
    return null;
  }

  const response = await axios({
    method: 'GET',
    url: buildUrl(apiUrl, apiPath),
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey
    },
    params: {
      customer_id: customerId,
      customerId
    },
    timeout: 30000
  });

  const payload = response.data;
  const candidates = [
    payload,
    payload?.data,
    payload?.account,
    Array.isArray(payload?.data) ? payload.data[0] : null
  ];

  for (const candidate of candidates) {
    const extracted = tryExtractNumbers(candidate);
    if (extracted && hasCustomerNumbers(extracted)) {
      return extracted;
    }
  }

  return null;
}

async function resolveCustomerNumbers(payload, params) {
  const fromRequest = normalizeNumbers(payload.customerNumbers, !isWholesaleCustomer(payload));
  if (hasCustomerNumbers(fromRequest)) {
    return expandCustomerNumbersForFiserv(fromRequest, params, payload);
  }

  const fromLookup = await fetchCustomerNumbersByCustomerId(payload.customerId, params);
  if (fromLookup) {
    return expandCustomerNumbersForFiserv(
      normalizeNumbers(fromLookup, !isWholesaleCustomer(payload)),
      params,
      payload
    );
  }

  return null;
}

function resolveFiservAppName(config, payload) {
  const wholesaleApp = pickFirst(config.appNameWholesale);
  const retailApp = pickFirst(config.appNameRetail, config.appName);

  if (payload && isWholesaleCustomer(payload)) {
    return pickFirst(wholesaleApp, retailApp);
  }

  if (payload && ['retail', 'trade'].includes(payload.customerType)) {
    return pickFirst(retailApp, wholesaleApp);
  }

  return pickFirst(retailApp, wholesaleApp);
}

function buildProviderHeaders(config, payload = null) {
  const headers = {
    'Content-Type': 'application/json',
    'x-api-key': config.apiKey
  };

  const appName = resolveFiservAppName(config, payload);
  if (appName) {
    headers['x-application-name'] = appName;
  }

  return headers;
}

function normalizeBoolean(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'true' || raw === '1' || raw === 'yes') return true;
  if (raw === 'false' || raw === '0' || raw === 'no') return false;
  return null;
}

function buildCardInformation(payload) {
  if (payload.cardInformation && typeof payload.cardInformation === 'object') {
    return {
      number: pickFirst(
        payload.cardInformation.number,
        payload.cardInformation.cardNumber,
        payload.cardInformation.cc_number
      ),
      expirationMonth: pickFirst(
        payload.cardInformation.expirationMonth,
        payload.cardInformation.expiration_month,
        payload.cardInformation.cc_exp_month
      ),
      expirationYear: pickFirst(
        payload.cardInformation.expirationYear,
        payload.cardInformation.expiration_year,
        payload.cardInformation.cc_exp_year
      ),
      cvv: pickFirst(
        payload.cardInformation.cvv,
        payload.cardInformation.securityCode,
        payload.cardInformation.ccv
      ),
      type: pickFirst(
        payload.cardInformation.type,
        payload.cardInformation.cardType,
        payload.cardInformation.cc_type
      ),
      holderName: pickFirst(
        payload.cardInformation.holderName,
        payload.cardInformation.holder_name,
        payload.cardInformation.cardHolderName,
        payload.cardInformation.card_holder_name,
        payload.cardInformation.cc_holder_name,
        payload.cardInformation.name_on_card
      ),
      nickName: pickFirst(
        payload.cardInformation.nickName,
        payload.cardInformation.nick_name,
        payload.cardInformation.cardNickname,
        payload.cardInformation.card_nickname,
        payload.cardInformation.cc_nickname
      )
    };
  }

  if (payload.cardNumber || payload.cardExpirationMonth || payload.cardExpirationYear || payload.cardCvv || payload.cardType || payload.cardHolderName || payload.cardNickname) {
    return {
      number: payload.cardNumber,
      expirationMonth: payload.cardExpirationMonth,
      expirationYear: payload.cardExpirationYear,
      cvv: payload.cardCvv,
      type: payload.cardType,
      holderName: payload.cardHolderName,
      nickName: payload.cardNickname
    };
  }

  return null;
}

function buildFiservCreatePayload(payload, customerNumbers) {
  const cardInformation = buildCardInformation(payload);
  const saveForFutureOrders = normalizeBoolean(payload.saveForFutureOrders);
  const shouldSave = saveForFutureOrders === null ? true : saveForFutureOrders;

  const body = {
    ...customerNumbers,
    transactionAmount: payload.transactionAmount || 0,
    currency: payload.currency || 'USD',
    reference: payload.reference || payload.purchaseOrder || 'save-card',
    purchaseOrder: payload.purchaseOrder || payload.reference || 'save-card',
    orderId: payload.orderId || payload.customerId || '0',
    saveForFutureOrders: shouldSave
  };

  if (payload.customerType) {
    body.customerType = payload.customerType;
  }

  if (payload.billTo && typeof payload.billTo === 'object') {
    body.billTo = payload.billTo;
  }

  if (!body.billTo && payload.billingAddress && typeof payload.billingAddress === 'object') {
    body.billTo = payload.billingAddress;
  }

  if (cardInformation) {
    body.cardInformation = { ...cardInformation };
    if (cardInformation.holderName) {
      body.cardInformation.holderName = cardInformation.holderName;
    }
    if (cardInformation.nickName) {
      body.cardInformation.nickName = cardInformation.nickName;
    }
  }

  if (payload.billingAddressId) {
    body.billingAddressId = payload.billingAddressId;
  }

  if (payload.isDefaultCard !== null && payload.isDefaultCard !== undefined) {
    body.isDefaultCard = payload.isDefaultCard;
  }

  if (payload.cardNickname && !body.cardInformation?.nickName) {
    if (!body.cardInformation) {
      body.cardInformation = {};
    }
    body.cardInformation.nickName = payload.cardNickname;
  }

  if (payload.cardHolderName && !body.cardInformation?.holderName) {
    if (!body.cardInformation) {
      body.cardInformation = {};
    }
    body.cardInformation.holderName = payload.cardHolderName;
  }

  if (payload.cardToken) {
    body.token = payload.cardToken;
    if (payload.cardCvv) {
      body.cc_cid = payload.cardCvv;
    }
  }

  return body;
}

async function createFiservCard(config, customerNumbers, payload) {
  const body = buildFiservCreatePayload(payload, customerNumbers);
  if (!body.cardInformation && !body.token) {
    throw new Error('Missing card data for add operation. Provide cardInformation or cardToken.');
  }

  return axios({
    method: 'POST',
    url: buildUrl(config.baseUrl, config.addPath),
    headers: buildProviderHeaders(config, payload),
    data: body,
    timeout: 30000
  });
}

function buildCybersourceCardPayload(payload) {
  const cardInformation = buildCardInformation(payload);
  if (cardInformation) {
    const card = {
      number: cardInformation.number,
      expirationMonth: cardInformation.expirationMonth,
      expirationYear: cardInformation.expirationYear,
      securityCode: cardInformation.cvv
    };

    if (cardInformation.holderName) {
      card.cardholderName = cardInformation.holderName;
    }

    return {
      paymentInstrument: {
        card
      }
    };
  }

  if (payload.cardToken) {
    return {
      paymentInstrument: {
        tokenizedCard: {
          transactionType: '1',
          token: payload.cardToken
        }
      }
    };
  }

  return null;
}

async function createCybersourceCard(config, customerTokenId, payload, debug = false) {
  const prefix = trimSlashes(config.tmsCustomerPathPrefix || 'tms/v2/customers');
  const path = `${prefix}/${toSafePathSegment(customerTokenId)}/payment-instruments`;
  const body = buildCybersourceCardPayload(payload);
  if (!body) {
    throw new Error('Missing card data for CyberSource add operation. Provide cardInformation or cardToken.');
  }
  return callCybersource(config, 'POST', path, body, debug);
}

async function listCards(config, requestFields, payload = null) {
  return axios({
    method: 'GET',
    url: buildUrl(config.baseUrl, config.listPath),
    headers: buildProviderHeaders(config, payload),
    params: requestFields,
    timeout: 30000
  });
}

async function deleteCard(config, requestFields, cardToken, payload = null) {
  return axios({
    method: 'DELETE',
    url: buildUrl(config.baseUrl, config.deletePath),
    headers: buildProviderHeaders(config, payload),
    params: {
      ...requestFields,
      token: cardToken,
      cardToken
    },
    timeout: 30000
  });
}

function isCybersourceProvider(provider) {
  return provider === PROVIDER_CYBERSOURCE || provider === PROVIDER_CYBERSOURCE_US_BUSINESS;
}

function toSafePathSegment(value) {
  return encodeURIComponent(String(value || '').trim());
}

function hashBody(body = '') {
  return crypto.createHash('sha256').update(body, 'utf8').digest('base64');
}

function createCybersourceSignature({
  method,
  host,
  pathWithQuery,
  merchantId,
  keyId,
  sharedSecret,
  date,
  digestHeader
}) {
  const headersList = ['host', 'date', '(request-target)', 'v-c-merchant-id'];
  const lines = [
    `host: ${host}`,
    `date: ${date}`,
    `(request-target): ${String(method).toLowerCase()} ${pathWithQuery}`,
    `v-c-merchant-id: ${merchantId}`
  ];

  if (digestHeader) {
    headersList.push('digest');
    lines.push(`digest: ${digestHeader}`);
  }

  const signatureString = lines.join('\n');

  // CyberSource shared secret is usually base64 encoded.
  let hmacKey;
  try {
    hmacKey = Buffer.from(sharedSecret, 'base64');
    if (!hmacKey || hmacKey.length === 0) {
      hmacKey = Buffer.from(sharedSecret, 'utf8');
    }
  } catch {
    hmacKey = Buffer.from(sharedSecret, 'utf8');
  }

  const signature = crypto.createHmac('sha256', hmacKey)
    .update(signatureString, 'utf8')
    .digest('base64');

  return `keyid="${keyId}", algorithm="HmacSHA256", headers="${headersList.join(' ')}", signature="${signature}"`;
}

async function callCybersource(config, method, path, body = null, debug = false) {
  const base = String(config.baseUrl || '').replace(/\/+$/, '');
  const normalizedPath = `/${trimSlashes(path)}`;
  const url = `${base}${normalizedPath}`;
  const host = new URL(base).host;
  const date = new Date().toUTCString();
  const payload = body ? JSON.stringify(body) : '';
  const digestHeader = payload ? `SHA-256=${hashBody(payload)}` : null;

  const signature = createCybersourceSignature({
    method,
    host,
    pathWithQuery: normalizedPath,
    merchantId: config.merchantId,
    keyId: config.keyId,
    sharedSecret: config.sharedSecret,
    date,
    digestHeader
  });

  const headers = {
    Accept: 'application/hal+json;charset=utf-8',
    'Content-Type': 'application/json;charset=utf-8',
    Host: host,
    Date: date,
    'v-c-merchant-id': config.merchantId,
    Signature: signature
  };

  if (digestHeader) {
    headers.Digest = digestHeader;
  }

  if (debug) {
    console.log('[VC-Payment-Methods-API][CyberSource] request meta', {
      method,
      host,
      path: normalizedPath,
      merchantId: config.merchantId,
      keyId: config.keyId,
      date,
      hasDigest: Boolean(digestHeader),
      baseUrl: base
    });
  }

  return axios({
    method,
    url,
    headers,
    data: payload || undefined,
    timeout: 30000
  });
}

async function listCybersourceCards(config, customerTokenId, debug = false) {
  const prefix = trimSlashes(config.tmsCustomerPathPrefix || 'tms/v2/customers');
  const path = `${prefix}/${toSafePathSegment(customerTokenId)}/payment-instruments`;
  return callCybersource(config, 'GET', path, null, debug);
}

async function deleteCybersourceCard(config, customerTokenId, paymentInstrumentId, debug = false) {
  const prefix = trimSlashes(config.tmsCustomerPathPrefix || 'tms/v2/customers');
  const path = `${prefix}/${toSafePathSegment(customerTokenId)}/payment-instruments/${toSafePathSegment(paymentInstrumentId)}`;
  return callCybersource(config, 'DELETE', path, null, debug);
}

async function main(params) {
  if (String(params.__ow_method || '').toLowerCase() === 'options') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*'
      }
    };
  }

  if (!validateSessionToken(params)) {
    return {
      statusCode: 401,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: { error: 'Unauthorized access' }
    };
  }

  const payload = getPayload(params);
  if (payload.error) {
    return {
      statusCode: 400,
      body: { error: payload.error }
    };
  }

  const providerConfig = buildProviderConfig(params, payload.provider);
  if (!providerConfig) {
    return {
      statusCode: 400,
      body: { error: `Unsupported provider: ${payload.provider}` }
    };
  }

  try {
    if (isCybersourceProvider(payload.provider)) {
      const debug = shouldDebug(params);
      if (!providerConfig.baseUrl || !providerConfig.merchantId || !providerConfig.keyId || !providerConfig.sharedSecret) {
        return {
          statusCode: 500,
          body: {
            error: `Missing CyberSource configuration. Required: CYBERSOURCE_API_BASE_URL, CYBERSOURCE_MERCHANT_ID, CYBERSOURCE_REST_KEY_ID, CYBERSOURCE_REST_KEY_VALUE`
          }
        };
      }

      const customerTokenId = payload.customerTokenId || payload.customerId;
      if (!customerTokenId) {
        return {
          statusCode: 400,
          body: { error: 'Missing required parameter: customerTokenId (or customer_id)' }
        };
      }

      let response;
      if (payload.operation === 'list') {
        response = await listCybersourceCards(providerConfig, customerTokenId, debug);
      } else if (payload.operation === 'delete') {
        const paymentInstrumentId = payload.paymentInstrumentId || payload.cardToken;
        if (!paymentInstrumentId) {
          return {
            statusCode: 400,
            body: { error: 'Missing required parameter: paymentInstrumentId (or cardToken)' }
          };
        }
        response = await deleteCybersourceCard(providerConfig, customerTokenId, paymentInstrumentId, debug);
      } else if (payload.operation === 'add') {
        response = await createCybersourceCard(providerConfig, customerTokenId, payload, debug);
      } else {
        return {
          statusCode: 400,
          body: { error: `Unsupported operation: ${payload.operation}` }
        };
      }

      return {
        statusCode: response.status,
        body: response.data
      };
    }

    if (!providerConfig.baseUrl || !providerConfig.apiKey) {
      return {
        statusCode: 500,
        body: { error: `Missing provider configuration for ${payload.provider}` }
      };
    }

    const customerNumbers = await resolveCustomerNumbers(payload, params);
    if (!customerNumbers || !hasCustomerNumbers(customerNumbers)) {
      return {
        statusCode: 400,
        body: {
          error: 'At least one of customerNumberVC, customerNumberTL, customerNumberGL or customerNumberD365 must be provided'
        }
      };
    }

    let response;

    if (payload.operation === 'list') {
      response = await listCards(providerConfig, customerNumbers, payload);
    } else if (payload.operation === 'delete') {
      if (!payload.cardToken) {
        return {
          statusCode: 400,
          body: { error: 'Missing required parameter: cardToken' }
        };
      }
      response = await deleteCard(providerConfig, customerNumbers, payload.cardToken, payload);
    } else if (payload.operation === 'add') {
      response = await createFiservCard(providerConfig, customerNumbers, payload);
    } else {
      return {
        statusCode: 400,
        body: { error: `Unsupported operation: ${payload.operation}` }
      };
    }

    return {
      statusCode: response.status,
      body: response.data
    };
  } catch (error) {
    if (isCybersourceProvider(payload.provider) && shouldDebug(params)) {
      console.log('[VC-Payment-Methods-API][CyberSource] error meta', {
        status: error.response?.status || 500,
        message: error.message,
        responseData: error.response?.data || null
      });
    }
    return {
      statusCode: error.response?.status || 500,
      body: error.response?.data || { error: 'Payment provider request failed' }
    };
  }
}

exports.main = main;
