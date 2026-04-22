const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'replace-this-secret';

function sign(payload) {
  return crypto
    .createHmac('sha256', SECRET)
    .update(JSON.stringify(payload))
    .digest('hex');
}

async function main() {
  const payload = {
    exp: Date.now() + 15 * 60 * 1000, // 15 min
    nonce: crypto.randomBytes(8).toString('hex')
  };

  const token = Buffer.from(
    JSON.stringify({ ...payload, sig: sign(payload) })
  ).toString('base64');

  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    },
    body: { token, expiresIn: 900 }
  };
}

exports.main = main;
