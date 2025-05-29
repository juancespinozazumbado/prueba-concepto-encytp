const crypto = require('crypto');
const fs = require('fs');
const jose = require('node-jose');

function encryptData() {
  // Replace these with your actual hex strings
  const keyHex = 'A8AA8DBF16EA510D943A7DB6CCCEAB8E20D3AEC1CB057C7186C842A529B775B6';
  const ivHex = '3B097E347861737FCC4B6822';
  const plaintext = "4224102259999908";

  // Convert hex strings to buffers
  const key = Buffer.from(keyHex, 'hex');
  const iv = Buffer.from(ivHex, 'hex');

  // Create cipher
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  // Encrypt the plaintext
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Get the authentication tag
  const authTag = cipher.getAuthTag().toString('hex');

  console.log('Ciphertext:', encrypted);
  console.log('Auth Tag:', authTag);
  let encryptedData = {
    ciphertext: encrypted,
    key: keyHex,
    iv: ivHex,
    tag: authTag
  };

  return encryptedData;
}


//########### ENCRYPT  ########################################

async function generateJWEToken() {
  // Plaintext PAN
  const payloadData = encryptData();
  // AES Key (Hex to Buffer)
  const aesKeyHex = 'A8AA8DBF16EA510D943A7DB6CCCEAB8E20D3AEC1CB057C7186C842A529B775B6';
  const aesKey = Buffer.from(aesKeyHex, 'hex');
  // Initialization Vector (Hex to Buffer)
  const ivHex = '3B097E347861737FCC4B6822';
  const iv = Buffer.from(ivHex, 'hex');

  // Load RSA public key from PEM file
  const publicKeyPem = fs.readFileSync('test_key.pem.pub', 'utf8');

  // Import RSA public key
  const key = await jose.JWK.asKey(publicKeyPem, 'pem');

  // Define JWE header
  const header = {
    typ: "JOSE",
    enc: "A256GCM",
    iat: "1625057896",
    alg: "RSA-OAEP-256",
    kid: "123456",
  };

  // Create JWE encryptor
  const encryptor = jose.JWE.createEncrypt(
    { format: 'compact', fields: header },
    { key, reference: false }
  );

  // Encrypt plaintext
  const jweToken = await encryptor.update(JSON.stringify(payloadData), 'utf8').final();

  console.log('JWE Token:');
  console.log(jweToken);
  return jweToken;

}


//########### DECRYPT  ########################################
async function decodeJWEToken(jweToken) {

  // Load RSA private key from PEM file
  const privateKeyPem = fs.readFileSync('test_key.pem', 'utf8');
  try {
    // Import the private key
    const key = await jose.JWK.asKey(privateKeyPem, 'pem');

    // Create a decrypter
    const decryptor = jose.JWE.createDecrypt(key);

    // Decrypt the token
    const result = await decryptor.decrypt(jweToken);

    // Output the decrypted payload
    console.log('Decrypted Payload:', result.plaintext.toString('utf8'));
    console.log('Protected Header:', result.header);
    return JSON.parse(result.plaintext.toString('utf8'));

  } catch (err) {
    console.error('Decryption failed:', err);
  }
}


///Usage example
async function main() {

  const token = await generateJWEToken();
  console.log('Generated JWE Token:', token);

  const originalData = await decodeJWEToken(token);
  console.log('Original Data:', originalData);
}

main().catch(console.error);


