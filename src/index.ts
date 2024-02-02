import {encodePrivateKey, encodePublicKey} from './ssh-util';
import {wrapString} from './util';

let _crypto: Crypto

const isNode = Object.prototype.toString.call(typeof process !== 'undefined' ? process : 0) === '[object process]'

if(isNode){
  const mainVersion = +process.versions.node.split('.')[0]
  if(mainVersion<16) throw new Error('Your Node.js version not support "webcrypto", lowest Node.js v16')
  
  _crypto = require('crypto').webcrypto
}else{
  _crypto = crypto
}

const extractable = true;

function rsaPrivateKey(key: string): string {
  return `-----BEGIN RSA PRIVATE KEY-----\n${key}-----END RSA PRIVATE KEY-----`;
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export async function generateKeyPair(
  {alg, size, name, hash}:
  {alg: "RSASSA-PKCS1-v1_5", size: 1024 | 2048 | 4096, hash: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512", name: string}): Promise<{privateKey: string, publicKey: string}> {
  const key = await _crypto.subtle
    .generateKey(
      {
        name: alg,
        modulusLength: size,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: hash },
      },
      extractable,
      ["sign", "verify"]
    );

    const privateKeyPromise = _crypto.subtle
      .exportKey("jwk", key.privateKey)
      .then(encodePrivateKey)
      .then(wrapString)
      .then(rsaPrivateKey);

    const publicKeyPromise = _crypto.subtle.exportKey("jwk", key.publicKey).then(jwk => encodePublicKey(jwk, name));
    const [privateKey, publicKey] = await Promise.all([privateKeyPromise, publicKeyPromise] as const);
    return {
      privateKey,
      publicKey
    };
}
