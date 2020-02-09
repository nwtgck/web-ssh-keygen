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

export async function generateKeyPair(
  {alg, size, name, hash}:
  {alg: "RSASSA-PKCS1-v1_5", size: 1024 | 2048 | 4096, hash: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512", name: string}): Promise<{privateKey: string, publicKey: string}> {
  const key = await window.crypto.subtle
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

    const privateKeyPromise = window.crypto.subtle
      .exportKey("jwk", key.privateKey)
      .then(encodePrivateKey)
      // TODO: any
      .then((wrap as any))
      // TODO: any
      .then((rsaPrivateKey as any));

    const publicKeyPromise = window.crypto.subtle.exportKey("jwk", key.publicKey).then(jwk => encodePublicKey(jwk, name));
    const [privateKey, publicKey] = await Promise.all([privateKeyPromise, publicKeyPromise] as const);
    return {
      privateKey,
      publicKey
    };
}
