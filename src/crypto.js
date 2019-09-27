var CryptoJS = require('crypto-js');

function base64UrlSafeEncode(string) {
  /*return string.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');*/

  return CryptoJS.enc.Base64.stringify(string)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function sha256(buffer) {
  //return crypto.createHash('sha256').update(buffer).digest();
  return CryptoJS.SHA256(buffer);
}

exports.generateProofKey = function generateProofKey() {
  //var codeVerifier = base64UrlSafeEncode(crypto.randomBytes(32));
  var codeVerifier = base64UrlSafeEncode(CryptoJS.lib.WordArray.random(32));
  var codeChallenge = base64UrlSafeEncode(sha256(codeVerifier));
  return {
    codeVerifier: codeVerifier,
    codeChallenge: codeChallenge
  };
};

exports.generateState = function generateState() {
  //return base64UrlSafeEncode(crypto.randomBytes(32));
  return base64UrlSafeEncode(CryptoJS.lib.WordArray.random(32));
};
