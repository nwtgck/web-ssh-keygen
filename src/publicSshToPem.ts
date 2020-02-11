import {wrapString} from "./util";
import {
  asnEncodeLen,
  checkHighestBit,
  arrayToPem,
  arrayToString,
  pemToArray,
  arrayToLen,
} from "./ssh-util";

function pemPublicKey(key: string): string {
  return `---- BEGIN RSA PUBLIC KEY ----\n${wrapString(key, 65)}---- END RSA PUBLIC KEY ----`;
}

function asn1Int(int: number[]): number[] {
  const v = checkHighestBit(int);
  const len = asnEncodeLen(v.length);
  return [0x02].concat(len, v); // int tag is 0x02
}

function asn1Seq(seq: readonly number[]): number[] {
  const len = asnEncodeLen(seq.length);
  return [0x30].concat(len, seq); // seq tag is 0x30
}

function decodePublicKey(s: string): {type: 'ssh-rsa', exponent: number[], key: number[], name: string} {
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
