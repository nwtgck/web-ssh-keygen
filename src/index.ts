/* global encodePrivateKey, encodePublicKey */
import {encodePrivateKey, encodePublicKey} from './ssh-util';
const extractable = true;

function wrap(text: string, len: number): string {
  const length = len || 72;
  let result = "";
  for (let i = 0; i < text.length; i += length) {
    result += text.slice(i, i + length);
    result += "\n";
  }
  return result;
}

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
  return window.btoa(binary);
}

// TODO: any in return type
export function generateKeyPair(alg: string, size: number, name: string): any {
  return window.crypto.subtle
    .generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048, // can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-1" }, // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
      },
      extractable,
      ["sign", "verify"]
    )
    .then(key => {
      const privateKey = window.crypto.subtle
        .exportKey("jwk", key.privateKey)
        .then(encodePrivateKey)
        // TODO: any
        .then((wrap as any))
        // TODO: any
        .then((rsaPrivateKey as any));

      const publicKey = window.crypto.subtle.exportKey("jwk", key.publicKey).then(jwk => encodePublicKey(jwk, name));
      return Promise.all([privateKey, publicKey]);
    });
}
