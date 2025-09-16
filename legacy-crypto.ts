import * as Crypto from 'expo-crypto';
import { Buffer } from 'buffer';
import 'react-native-get-random-values';
import nacl from 'tweetnacl';
import { scrypt } from 'scrypt-js';

if (typeof global.Buffer === 'undefined') {
  global.Buffer = Buffer;
}

const SALT_LEN = 16;
const NONCE_LEN = 24;
const KEY_LEN = 32;
const SCRYPT_N = 2 ** 12; // Original mobile-optimized value
const SCRYPT_r = 8;
const SCRYPT_p = 1;

const toBase64 = (u8: Uint8Array): string => Buffer.from(u8).toString('base64');
const fromBase64 = (b64: string): Uint8Array => new Uint8Array(Buffer.from(b64, 'base64'));

async function deriveKeyLegacy(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const pw = new TextEncoder().encode(password);
  return new Uint8Array(await scrypt(pw, salt, SCRYPT_N, SCRYPT_r, SCRYPT_p, KEY_LEN));
}

export async function encryptToBase64Legacy(plaintext: string, password: string): Promise<string> {
  try {
    const salt = new Uint8Array(await Crypto.getRandomBytesAsync(SALT_LEN));
    const nonce = new Uint8Array(await Crypto.getRandomBytesAsync(NONCE_LEN));
    const key = await deriveKeyLegacy(password, salt);
    const msg = new TextEncoder().encode(plaintext);

    const box = nacl.secretbox(msg, nonce, key);
    if (!box) {
      throw new Error('Encryption failed');
    }
    
    const packed = new Uint8Array(salt.length + nonce.length + box.length);
    packed.set(salt, 0);
    packed.set(nonce, salt.length);
    packed.set(box, salt.length + nonce.length);
    return toBase64(packed);
  } catch (error) {
    console.error('Error in legacy encryptToBase64:', error);
    throw error;
  }
}

export async function decryptFromBase64(b64: string, password: string): Promise<string> {
  try {
    const all = fromBase64(b64);
    if (all.length <= SALT_LEN + NONCE_LEN + 16) {
      throw new Error('Encrypted text too short');
    }

    const salt = all.slice(0, SALT_LEN);
    const nonce = all.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
    const box = all.slice(SALT_LEN + NONCE_LEN);
    const key = await deriveKeyLegacy(password, salt);

    const plain = nacl.secretbox.open(box, nonce, key);
    if (!plain) {
      throw new Error('Incorrect password or corrupted data');
    }
    return new TextDecoder().decode(plain);
  } catch (error) {
    console.error('Error in legacy decryptFromBase64:', error);
    throw error;
  }
}
