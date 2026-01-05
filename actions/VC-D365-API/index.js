const axios = require('axios');
const FormData = require('form-data');

async function main(params) {

  const D365_APP_ID = params.D365_APP_ID;
  const D365_API_URL = params.D365_API_URL;
  const D365_CLIENT_ID = params.D365_CLIENT_ID;
  const D365_GRANT_TYPE = params.D365_GRANT_TYPE;
  const D365_CLIENT_SECRET = params.D365_CLIENT_SECRET;

  if (!D365_APP_ID || !D365_API_URL || !D365_CLIENT_ID || !D365_GRANT_TYPE || !D365_CLIENT_SECRET) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Missing D365 configuration' }),
    };
  }

  let formData = new FormData();
  formData.append('client_Id', D365_CLIENT_ID);
  formData.append('grant_type', D365_GRANT_TYPE);
  formData.append('resource', D365_API_URL);
  formData.append('client_secret', D365_CLIENT_SECRET);

  const authOptions = {
    method: 'POST',
    maxBodyLength: Infinity,
    url: `https://login.microsoftonline.com/${D365_APP_ID}/oauth2/token`,
    headers: {
      ...formData.getHeaders(),
    },
    data: formData
  };

  const authResponse = await axios.request(authOptions);

  if (authResponse.statusText !== 'OK') {
    throw new Error(`Request failed with status ${authResponse.status}`);
  }

  const requestOptions = {
    method: params.method,
    url: `${D365_API_URL}${params.path}`,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `${authResponse.data.token_type} ${authResponse.data.access_token}`,
    }
  }
  if (params.method === 'POST') {
    requestOptions.data = JSON.stringify(params.data);
  }

  try {
    const response =  await axios.request(requestOptions);
    return {
      statusCode: response.status,
      body: response.data
    };
  } catch (error) {
    return {
      statusCode: error.response.status,
      body: error.response.data
    };
  }


}

exports.main = main;
