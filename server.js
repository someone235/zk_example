const express = require('express');
const bodyParser = require('body-parser');
const srp = require('secure-remote-password/server');
const aes256 = require('aes256');
const NodeRSA = require('node-rsa');

const app = express();
app.use(bodyParser.json());

const privateKey = new NodeRSA(`-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAIlaGW6Uwmx3amQQHWgoSOePR8Ox8o6psyGHY1dOKiizP7Pt/qsd
wWqIlJZi7ZHzZWxM6vLc/LIvkwQQkHogC98CAwEAAQJAA4VbwYnusfkdsRL4rgLa
W5VAsbOOFDolbWabFVHbos9rqIR8NeUe5wa+OmSlP9QgR3nNks1c4aG52jKiiTZN
gQIhAOooUm6yjDnO4UFpGfX0mO32z0uwPq2m1mkMXtUHhULrAiEAlioP3tirniNT
oQXWbmZJYi+wDX3nf/WeHmXxntLIFd0CIQCvzgheDnYT7QzYpIWWUcgEWls3U6Mr
k+jFREFrJlNacwIgKClnxTo97DWWkGJ3T1+cEN6gP3uFBvwyJf8t+ER3ryECIQCX
GWKpol3I0/dd0OCYqdDvAK/DXwJjyc8xgT4/OgQ8Ng==
-----END RSA PRIVATE KEY-----`);

const data = new Map();

app.post('/register', (req, res) => {
  const { encryptedData } = req.body;
  const registrationData = decryptData(encryptedData);
  const { username } = registrationData;
  if (data.get(username)) {
    throw new Error('Username already exists');
  }
  data.set(username, registrationData);
  res.json({ status: 'ok' });
});

app.post('/login1', (req, res) => {
  const { username, clientPublicEphemeral } = req.body;
  const userData = data.get(username);
  const verifier = userData.verifier;
  const serverEphemeral = srp.generateEphemeral(verifier);
  userData.serverEphemeral = serverEphemeral;
  userData.clientPublicEphemeral = clientPublicEphemeral;
  res.json({ serverPublicEphemeral: serverEphemeral.public });
});

app.post('/login2', (req, res) => {
  const { username, clientSessionProof } = req.body;
  const userData = data.get(username);
  const verifier = userData.verifier;
  const serverSession = srp.deriveSession(userData.serverEphemeral.secret,
    userData.clientPublicEphemeral,
    userData.salt,
    username,
    userData.verifier,
    clientSessionProof);

  res.json({
    secretData: aes256.encrypt(serverSession.key, userData.secretData),
    serverSessionProof: serverSession.proof
  });
});

app.listen(3000, () => console.log('ZK-server listening on port 3000'));

function decryptData(data) {
  return JSON.parse(privateKey.decrypt(data, 'utf8'));
}