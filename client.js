const srp = require('secure-remote-password/client');
const request = require('request-promise');
const argv = require('yargs').argv;
const aes256 = require('aes256');
const NodeRSA = require('node-rsa');

(async () => {
  // These should come from the user signing up
  const username = 'orinewman1@gmail.com';
  const password = 'MyPassword';
  const serverPublicKey = new NodeRSA(`-----BEGIN PUBLIC KEY-----
  MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIlaGW6Uwmx3amQQHWgoSOePR8Ox8o6p
  syGHY1dOKiizP7Pt/qsdwWqIlJZi7ZHzZWxM6vLc/LIvkwQQkHogC98CAwEAAQ==
  -----END PUBLIC KEY-----`);

  switch (argv.step) {
    case 'register': {
      const { username, password } = argv;
      const salt = srp.generateSalt();
      const privateKey = srp.derivePrivateKey(salt, username, password);
      const verifier = srp.deriveVerifier(privateKey);
      const encryptedData = serverPublicKey.encrypt(JSON.stringify({
        salt,
        verifier,
        username,
        secretData: argv.secretdata
      }), 'base64');
      await post('register', {
        encryptedData
      });
      console.log('Your salt is: ', salt);
      break;
    }
    case 'login': {
      const { salt, username, password } = argv;
      const privateKey = srp.derivePrivateKey(salt, username, password);
      const clientEphemeral = srp.generateEphemeral();
      const { serverPublicEphemeral } = await post('login1', {
        username,
        clientPublicEphemeral: clientEphemeral.public,
      });
      const clientSession = srp.deriveSession(clientEphemeral.secret, serverPublicEphemeral, salt, username, privateKey);
      const { serverSessionProof, secretData } = await post('login2', {
        username,
        clientSessionProof: clientSession.proof
      });
      srp.verifySession(clientEphemeral.public, clientSession, serverSessionProof);
      console.log('My secret data: ', aes256.decrypt(clientSession.key, secretData));
    }
  }
})();

async function post(endpoint, body) {
  return request({
    method: 'POST',
    uri: `http://localhost:3000/${endpoint}`,
    body,
    json: true
  });
}