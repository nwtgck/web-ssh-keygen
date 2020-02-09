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

function pemPublicKey(key: string) {
  return `---- BEGIN RSA PUBLIC KEY ----\n${wrap(key, 65)}---- END RSA PUBLIC KEY ----`;
}

function integerToOctet(n: number) {
  const result = [];
  for (let i = n; i > 0; i >>= 8) {
    result.push(i & 0xff);
  }
  return result.reverse();
}

function asnEncodeLen(n: number) {
  let result = [];
  if (n >> 7) {
    result = integerToOctet(n);
    result.unshift(0x80 + result.length);
  } else {
    result.push(n);
  }
  return result;
}

// TODO: any
function checkHighestBit(v: any[]) {
  if (v[0] >> 7 === 1) {
    v.unshift(0); // add leading zero if first bit is set
  }
  return v;
}

// TODO: any
function asn1Int(int: any) {
  const v = checkHighestBit(int);
  const len = asnEncodeLen(v.length);
  return [0x02].concat(len, v); // int tag is 0x02
}

// TODO: any
function asn1Seq(seq: any) {
  const len = asnEncodeLen(seq.length);
  return [0x30].concat(len, seq); // seq tag is 0x30
}

// TODO: any
function arrayToPem(a: any[]) {
  return window.btoa(a.map(c => String.fromCharCode(c)).join(""));
}

// TODO: any
export function arrayToString(a: any) {
  return String.fromCharCode.apply(null, a);
}

function stringToArray(s: string) {
  // TODO: any
  return s.split("").map(c => (c as any).charCodeAt());
}

function pemToArray(pem: string) {
  return stringToArray(window.atob(pem));
}

function arrayToLen(a: number[]) {
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result = result * 256 + a[i];
  }
  return result;
}

function decodePublicKey(s: string) {
  const split = s.split(" ");
  const prefix = split[0];
  if (prefix !== "ssh-rsa") {
    throw new Error(`Unknown prefix: ${prefix}`);
  }
  const buffer = pemToArray(split[1]);
  const nameLen = arrayToLen(buffer.splice(0, 4));
  const type = arrayToString(buffer.splice(0, nameLen));
  if (type !== "ssh-rsa") {
    throw new Error(`Unknown key type: ${type}`);
  }
  const exponentLen = arrayToLen(buffer.splice(0, 4));
  const exponent = buffer.splice(0, exponentLen);
  const keyLen = arrayToLen(buffer.splice(0, 4));
  const key = buffer.splice(0, keyLen);
  return { type, exponent, key, name: split[2] };
}

export function publicSshToPem(publicKey: string) {
  const { key, exponent } = decodePublicKey(publicKey);
  const seq = [key, exponent].map(asn1Int).reduce((acc, a) => acc.concat(a));
  return pemPublicKey(arrayToPem(asn1Seq(seq)));
}
