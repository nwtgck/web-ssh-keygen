/* eslint no-bitwise: 0 */

function wrap(text: string, len: number) {
  const length = len || 72;
  let result = "";
  for (let i = 0; i < text.length; i += length) {
    result += text.slice(i, i + length);
    result += "\n";
  }
  return result;
}

// TODO: any
function pemPrivateKey(key: any) {
  return `-----BEGIN PRIVATE KEY-----\n${wrap(key, 64)}-----END PRIVATE KEY-----`;
}

function stripPemFormatting(str: string) {
  return str
    .replace(/^-----BEGIN (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m, "")
    .replace(/^-----END (?:RSA )?(?:PRIVATE|PUBLIC) KEY-----$/m, "")
    .replace(/[\n\r]/g, "");
}
// TODO: any
export function arrayToPem(a: any[]) {
  return window.btoa(a.map(c => String.fromCharCode(c)).join(""));
}

function stringToArray(s: string) {
  // TODO: any
  return s.split("").map(c => (c as any).charCodeAt());
}

export function pemToArray(pem: string) {
  return stringToArray(window.atob(pem));
}

const prefix = [
  0x30,
  0x82,
  0x04,
  0xbc,
  0x02,
  0x01,
  0x00,
  0x30,
  0x0d,
  0x06,
  0x09,
  0x2a,
  0x86,
  0x48,
  0x86,
  0xf7,
  0x0d,
  0x01,
  0x01,
  0x01,
  0x05,
  0x00,
  0x04,
  0x82,
  0x04,
  0xa6,
];

export function pkcs1To8(privateKeyPkcs1Pem: string) {
  const pem = stripPemFormatting(privateKeyPkcs1Pem);
  const privateKeyPkcs1Array = pemToArray(pem);
  const prefixPkcs8 = prefix.concat(privateKeyPkcs1Array);
  const privateKeyPkcs8Pem = arrayToPem(prefixPkcs8);
  const pkcs8Pem = pemPrivateKey(privateKeyPkcs8Pem);
  return pkcs8Pem;
}

// crypto.subtle.importKey(
//   "spki",
//   keyTextBuffer,
//   {
//     name: "RSASSA-PKCS1-v1_5",
//     hash: { name: "SHA-256" },
//   },
//   true,
//   ["verify"]
// );
