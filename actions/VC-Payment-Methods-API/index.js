const axios = require('axios');
const crypto = require('crypto');

const PROVIDER_FISERV = 'fiserv';
const PROVIDER_FISERV_US_BUSINESS = 'fiserv_us_business';
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
  const normalizedOperation = String(operationRaw || '').toLowerCase();
  const operation = ['add', 'create', 'save'].includes(normalizedOperation)
    ? 'add'
    : ['detect', 'card-meta', 'card_meta', 'network', 'card-network', 'card_network'].includes(normalizedOperation)
      ? 'detect'
      : normalizedOperation;

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
    page: Number(body.page || query.page || 1),
    limit: Number(body.limit || query.limit || 10),
    customerNumbers
  };
}

function trimSlashes(value) {
  return String(value || '').replace(/^\/+|\/+$/g, '');
}

function buildProviderConfig(params, provider) {
  if (provider === PROVIDER_FISERV || provider === PROVIDER_FISERV_US_BUSINESS) {
    const rsaPublicKey = params.FISERV_USB_RSA_PUBLIC_KEY || params.FISERV_RSA_PUBLIC_KEY || process.env.FISERV_USB_RSA_PUBLIC_KEY || process.env.FISERV_RSA_PUBLIC_KEY;
    console.log('[DEBUG] Fiserv RSA Public Key resolved:', rsaPublicKey ? 'Present' : 'Missing', 'Length:', rsaPublicKey ? rsaPublicKey.length : 0);
    return {
      provider,
      baseUrl: params.FISERV_USB_API_URL || process.env.FISERV_USB_API_URL,
      apiKey: params.FISERV_USB_API_KEY || process.env.FISERV_USB_API_KEY,
      appName: params.FISERV_USB_X_APPLICATION_NAME || process.env.FISERV_USB_X_APPLICATION_NAME,
      appNameWholesale: params.FISERV_USB_X_APPLICATION_NAME_WHOLESALE || process.env.FISERV_USB_X_APPLICATION_NAME_WHOLESALE,
      appNameRetail: params.FISERV_USB_X_APPLICATION_NAME_RETAIL || process.env.FISERV_USB_X_APPLICATION_NAME_RETAIL,
      listPath: params.FISERV_USB_LIST_PATH || process.env.FISERV_USB_LIST_PATH || 'api/FiservPayment/saved-cards',
      deletePath: params.FISERV_USB_DELETE_PATH || process.env.FISERV_USB_DELETE_PATH || 'api/FiservPayment/delete-card',
      addPath: params.FISERV_USB_ADD_PATH || process.env.FISERV_USB_ADD_PATH || 'api/FiservPayment/authorize',
      rsaPublicKey
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

function normalizeRsaPublicKey(rawKey) {
  if (!rawKey || typeof rawKey !== 'string') {
    return '';
  }

  let key = rawKey.trim();
  if (key.includes('\\n') && !key.includes('\n')) {
    key = key.replace(/\\n/g, '\n');
  }

  return key;
}

function encryptFiservField(value, publicKey) {
  if (value === null || value === undefined || String(value).trim() === '') {
    return '';
  }

  const key = normalizeRsaPublicKey(publicKey);
  if (!key) {
    throw new Error('Missing Fiserv RSA public key for encrypting card data');
  }

  try {
    const encrypted = crypto.publicEncrypt(
      {
        key,
        padding: crypto.constants.RSA_PKCS1_PADDING
      },
      Buffer.from(String(value), 'utf-8')
    );

    return encrypted.toString('base64');
  } catch (error) {
    throw new Error(`Fiserv RSA encryption failed: ${error.message}`);
  }
}

function encryptFiservCardInformation(cardInformation, publicKey) {
  if (!cardInformation || typeof cardInformation !== 'object') {
    return null;
  }

  return {
    ...cardInformation,
    number: encryptFiservField(cardInformation.number, publicKey),
    expirationMonth: encryptFiservField(cardInformation.expirationMonth, publicKey),
    expirationYear: encryptFiservField(cardInformation.expirationYear, publicKey),
    cvv: encryptFiservField(cardInformation.cvv, publicKey)
  };
}

function normalizeBoolean(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'true' || raw === '1' || raw === 'yes') return true;
  if (raw === 'false' || raw === '0' || raw === 'no') return false;
  return null;
}

function getNormalizedCardNumber(payload) {
  const cardInformationNumber = payload.cardInformation && typeof payload.cardInformation === 'object'
    ? pickFirst(
      payload.cardInformation.number,
      payload.cardInformation.cardNumber,
      payload.cardInformation.cc_number
    )
    : '';

  return String(cardInformationNumber || payload.cardNumber || '').replace(/\D/g, '');
}

function detectCardNetwork(cardNumber) {
  if (!cardNumber) {
    return 'unknown';
  }

  if (/^4\d{12}(\d{3})?(\d{3})?$/.test(cardNumber)) {
    return 'visa';
  }

  if (/^(5[1-5]\d{14}|2(2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$/.test(cardNumber)) {
    return 'mastercard';
  }

  if (/^3[47]\d{13}$/.test(cardNumber)) {
    return 'amex';
  }

  if (/^6(?:011|5\d{2}|4[4-9]\d|22(?:1[2-9]|[2-8]\d|9[01]))\d{12}$/.test(cardNumber)) {
    return 'discover';
  }

  return 'unknown';
}

function passesLuhn(cardNumber) {
  if (!cardNumber) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;

  for (let index = cardNumber.length - 1; index >= 0; index -= 1) {
    let digit = Number(cardNumber[index]);
    if (Number.isNaN(digit)) {
      return false;
    }

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

function maskCardNumber(cardNumber) {
  if (!cardNumber) {
    return '';
  }

  const visibleDigits = cardNumber.slice(-4);
  const maskedLength = Math.max(cardNumber.length - 4, 0);
  return `${'*'.repeat(maskedLength)}${visibleDigits}`;
}

function detectCardMetadata(payload) {
  const cardNumber = getNormalizedCardNumber(payload);
  const networkType = detectCardNetwork(cardNumber);
  const networkCodeMap = {
    visa: 'VI',
    mastercard: 'MC',
    amex: 'AX',
    discover: 'DI',
    unknown: ''
  };
  const networkCode = networkCodeMap[networkType] || '';

  return {
    cardNumberMasked: maskCardNumber(cardNumber),
    cardNumberLength: cardNumber.length,
    networkType,
    networkCode,
    isKnownNetwork: networkType !== 'unknown',
    passesLuhn: passesLuhn(cardNumber),
    isPotentiallyValid: cardNumber.length >= 12 && passesLuhn(cardNumber) && networkType !== 'unknown'
  };
}

function splitCardHolderName(holderName) {
  if (!holderName || typeof holderName !== 'string') {
    return { firstName: '', lastName: '' };
  }
  const parts = holderName.trim().split(/\s+/);
  return {
    firstName: parts[0] || '',
    lastName: parts.slice(1).join(' ') || ''
  };
}

function buildCardInformation(payload) {
  if (payload.cardInformation && typeof payload.cardInformation === 'object') {
    return {
      number: String(pickFirst(
        payload.cardInformation.number,
        payload.cardInformation.cardNumber,
        payload.cardInformation.cc_number
      ) || '').replace(/\D/g, ''),
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
      cardState: '',
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
      number: String(payload.cardNumber || '').replace(/\D/g, ''),
      expirationMonth: payload.cardExpirationMonth,
      expirationYear: payload.cardExpirationYear,
      cvv: payload.cardCvv,
      type: payload.cardType,
      cardState: '',
      holderName: payload.cardHolderName,
      nickName: payload.cardNickname
    };
  }

  return null;
}

function buildFiservCreatePayload(payload, customerNumbers, rsaPublicKey) {
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

  if (payload.customerId) {
    body.customerId = payload.customerId;
    body.userId = payload.customerId;
  }

  const holderName = cardInformation?.holderName || payload.cardHolderName;
  const { firstName, lastName } = splitCardHolderName(holderName);
  if (!body.billTo) {
    body.billTo = {};
  }
  if (firstName) {
    body.billTo.firstName = firstName;
  }
  if (lastName) {
    body.billTo.lastName = lastName;
  }

  if (payload.billTo && typeof payload.billTo === 'object') {
    body.billTo = payload.billTo;
  }

  if (!body.billTo && payload.billingAddress && typeof payload.billingAddress === 'object') {
    body.billTo = payload.billingAddress;
  }

  if (cardInformation) {
    body.cardInformation = encryptFiservCardInformation(cardInformation, rsaPublicKey);
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
      body.CvvEncrypted = encryptFiservField(payload.cardCvv, rsaPublicKey);
    }
  }

  return body;
}

async function createFiservCard(config, customerNumbers, payload) {
  const body = buildFiservCreatePayload(payload, customerNumbers, config.rsaPublicKey);
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

async function listCards(config, requestFields, payload = null) {
  return axios({
    method: 'GET',
    url: buildUrl(config.baseUrl, config.listPath),
    headers: buildProviderHeaders(config, payload),
    params: {
      ...requestFields,
      page: payload.page,
      limit: payload.limit
    },
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

  if (payload.operation === 'detect') {
    const cardNumber = getNormalizedCardNumber(payload);
    if (!cardNumber) {
      return {
        statusCode: 400,
        body: { error: 'Missing required parameter: cardNumber (or cardInformation.number)' }
      };
    }

    return {
      statusCode: 200,
      body: detectCardMetadata(payload)
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

      const cards = Array.isArray(response.data?.data)
        ? response.data.data
        : [];

      const page = Math.max(Number(payload.page || 1), 1);
      const limit = Math.max(Number(payload.limit || 10), 1);

      const start = (page - 1) * limit;
      const end = start + limit;

      const paginatedCards = cards.slice(start, end);

      response.data = {
        ...response.data,
        data: paginatedCards,
        pagination: {
          page,
          limit,
          total: cards.length,
          totalPages: Math.max(Math.ceil(cards.length / limit), 1),
          hasNextPage: end < cards.length,
          hasPreviousPage: page > 1
        }
      };
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
    const debug = shouldDebug(params);
    const errorMeta = {
      provider: payload.provider,
      operation: payload.operation,
      status: error.response?.status || error.code || 'unknown',
      message: error.message,
      responseData: error.response?.data || null,
      requestUrl: error.config?.url || null,
      requestMethod: error.config?.method || null
    };

    if (debug) {
      console.log('[VC-Payment-Methods-API] error meta', errorMeta);
    }

    return {
      statusCode: error.response?.status || 500,
      body: debug
        ? { error: 'Payment provider request failed', details: errorMeta }
        : error.response?.data || { error: 'Payment provider request failed' }
    };
  }
}

exports.main = main;
