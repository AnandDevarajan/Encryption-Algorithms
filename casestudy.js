const data = require('./data.json');
const crypto = require('crypto');
const fs = require('fs');
const encryptionEncoding = 'base64';
const bufferEncryption = 'utf-8';
const bcrypt = require('bcrypt');
const json2csv = require('json2csv').Parser;
const { publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const startTime = new Date();
//RSA
const encryptionRSA = (message) => {
  const encryptedData = crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(message)
  );
  return encryptedData.toString('base64');
};

//AES
const encryptionAES = (message) => {
  const aesKey = Buffer.from(
    'xNRxA48aNYd33PXaODSutRNFyCu4cAe/InKT/Rx+bw0=',
    'base64'
  );
  const aesiv = Buffer.from('81dFxOpX7BPG1UpZQPcS6w', 'base64');
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, aesiv);
  let encrypted =
    cipher.update(message, bufferEncryption, encryptionEncoding) +
    cipher.final('base64');
  return encrypted;
};

//VIGENERE
const encryptionVigenere = (message, key) => {
  let cipher = '';
  message = message.toUpperCase();
  for (let i = 0; i < message.length; i++) {
    if (message[i] === ' ') {
      cipher += message[i];
    } else {
      cipher += String.fromCharCode(
        ((message.charCodeAt(i) + key.charCodeAt(i)) % 26) + 65
      );
    }
  }
  return cipher;
};

//HASHING
const encryptionHash = (message) => {
  const hash = bcrypt.hashSync(message, 10);
  return hash;
};

(async () => {
  let newData = [];
  for (const item of data) {
    const encry_CVV = encryptionRSA(JSON.stringify(item.CVV));
    let encry_Account_No = encryptionAES(
      JSON.stringify(item['Account Number'])
    );
    let encty_Phone_no = encryptionVigenere(
      JSON.stringify(item['Phone no']),
      'CBENU4CSE18207'
    );
    let encry_Name = encryptionHash(item.Name);
    let userID = item.UserID;
    newData.push({
      userID,
      encry_Name,
      encty_Phone_no,
      encry_Account_No,
      encry_CVV,
    });
  }
  const j2cp = new json2csv();
  const csv = j2cp.parse(newData);
  fs.writeFileSync('./out.csv', csv, 'utf-8');
  const endTime = new Date();
  console.log(
    'Total time take = ' +
      (endTime.getTime() - startTime.getTime()) / 1000 +
      ' seconds'
  );
})();
var original = fs.statSync('./CaseStudy.csv').size;
var encrypted = fs.statSync('./Out.csv').size;
console.log('Extra storage taken = ' + (encrypted - original) / 1000 + ' KB');
