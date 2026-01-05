/* 
* <license header>
*/

/* global fetch */

/**
 * Invokes a web action
 *
 * @param  {string} actionUrl
 * @param {object} headers
 * @param  {object} params
 *
 * @returns {Promise<string|object>} the response
 *
 */
async function actionWebInvoke (actionUrl, headers = {}, params = {}, options = { method: 'POST' }) {
  const actionHeaders = {
    'Content-Type': 'application/json',
    ...headers
  }

  const fetchConfig = {
    headers: actionHeaders
  }

  if (window.location.hostname === 'localhost') {
    actionHeaders['x-ow-extra-logging'] = 'on'
  }

  fetchConfig.method = options.method.toUpperCase()

  if (fetchConfig.method === 'GET') {
    actionUrl = new URL(actionUrl)
    Object.keys(params).forEach(key => actionUrl.searchParams.append(key, params[key]))
  } else if (fetchConfig.method === 'POST') {
    fetchConfig.body = JSON.stringify(params)
  }

  const response = await fetch(actionUrl, fetchConfig)

  let content = await response.text()

  if (!response.ok) {
    throw new Error(`failed request to '${actionUrl}' with status: ${response.status} and message: ${content}`)
  }
  try {
    content = JSON.parse(content)
  } catch (e) {
    // response is not json
  }
  return content
}

/**
 * Get Adobe I/O Runtime Bearer token from JWT
 * ⚠️ Keep secrets inline for testing only
 *
 * @returns {Promise<string>} access token
 */
export async function getJWTAccessToken() {
  const clientId = 'YOUR_API_KEY';          // replace with your Adobe I/O API Key
  const clientSecret = 'YOUR_CLIENT_SECRET';// replace with your Adobe I/O Client Secret
  const jwtToken = `YOUR_JWT`;              // replace with your JWT

  const body = new URLSearchParams();
  body.append('client_id', clientId);
  body.append('client_secret', clientSecret);
  body.append('jwt_token', jwtToken);

  const response = await fetch('https://ims-na1.adobelogin.com/ims/exchange/jwt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });

  const data = await response.json();
  return data.access_token; // this is the Bearer token
}

export default actionWebInvoke;
