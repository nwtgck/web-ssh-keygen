/* eslint no-bitwise: 0 */
/* global base64urlDecode */
import {base64urlDecode} from './base64url';

// TODO: any
function arrayToString(a: any[]) {
  return String.fromCharCode.apply(null, a);
}

function stringToArray(s: string) {
  // TODO: any
  return s.split("").map(c => (c as any).charCodeAt());
}

export function base64urlToArray(s: string) {
  return stringToArray(base64urlDecode(s));
}

function pemToArray(pem: string) {
  return stringToArray(window.atob(pem));
}

// TODO: any
function arrayToPem(a: any) {
  // TODO: any
  return window.btoa(a.map((c: any) => String.fromCharCode(c)).join(""));
}

// TODO: any
function arrayToLen(a: any[]) {
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result = result * 256 + a[i];
  }
  return result;
}

function integerToOctet(n: number) {
  const result = [];
  for (let i = n; i > 0; i >>= 8) {
    result.push(i & 0xff);
  }
  return result.reverse();
}

function lenToArray(n: number) {
  const oct = integerToOctet(n);
  let i;
  for (i = oct.length; i < 4; i += 1) {
    oct.unshift(0);
  }
  return oct;
}

export function decodePublicKey(s: string) {
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

// TODO: any
function checkHighestBit(v: any[]) {
  if (v[0] >> 7 === 1) {
    // add leading zero if first bit is set
    v.unshift(0);
  }
  return v;
}

// TODO: any
function jwkToInternal(jwk: any) {
  return {
    type: "ssh-rsa",
    exponent: checkHighestBit(stringToArray(base64urlDecode(jwk.e))),
    name: "name",
    key: checkHighestBit(stringToArray(base64urlDecode(jwk.n))),
  };
}

// TODO: any
export function encodePublicKey(jwk: any, name: string) {
  const k = jwkToInternal(jwk);
  k.name = name;
  const keyLenA = lenToArray(k.key.length);
  const exponentLenA = lenToArray(k.exponent.length);
  const typeLenA = lenToArray(k.type.length);
  // TODO: remove ignore
  // @ts-ignore
  const array = [].concat((typeLenA as any), stringToArray(k.type), exponentLenA, k.exponent, keyLenA, k.key);
  const encoding = arrayToPem(array);
  return `${k.type} ${encoding} ${k.name}`;
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
export function encodePrivateKey(jwk: any) {
  const order = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];
  const list = order.map(prop => {
    const v = checkHighestBit(stringToArray(base64urlDecode(jwk[prop])));
    const len = asnEncodeLen(v.length);
    return [0x02].concat(len, v); // int tag is 0x02
  });
  let seq = [0x02, 0x01, 0x00]; // extra seq for SSH
  seq = seq.concat(...list);
  const len = asnEncodeLen(seq.length);
  const a = [0x30].concat(len, seq); // seq is 0x30
  return arrayToPem(a);
}

