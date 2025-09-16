import * as Crypto from 'expo-crypto';
import { Buffer } from 'buffer';
import 'react-native-get-random-values';
import nacl from 'tweetnacl';
import { deriveKey, DEFAULT_ARGON2ID, KdfConfig } from './kdf';
import { createHeader, parseHeader, createBlob, blobToBase64, base64ToBlob } from './crypto-header';

if (typeof global.Buffer === 'undefined') {
  global.Buffer = Buffer;
}

const SALT_LEN = 16;
const NONCE_LEN = 24;

/**
 * Encrypt plaintext with versioned header using Argon2id/scrypt + NaCl secretbox
 * Returns Base64 encoded blob with header: magic|version|kdf|params|salt|nonce|ciphertext
 */
export async function encryptV2(
  plaintext: string, 
  password: string, 
  kdfConfig?: Partial<KdfConfig>
): Promise<string> {
  try {
    console.log('🔐 Starting v2 encryption with versioned header...');
    
    // Generate random salt and nonce
    const salt = new Uint8Array(await Crypto.getRandomBytesAsync(SALT_LEN));
    const nonce = new Uint8Array(await Crypto.getRandomBytesAsync(NONCE_LEN));
    
    console.log('🧂 Generated salt and nonce');
    
    // Derive key with Argon2id (preferred) or scrypt (fallback)
    const { key, config } = await deriveKey(password, salt, kdfConfig);
    console.log(`✅ Key derived using ${config.id}`);
    
    // Encrypt with NaCl secretbox (XSalsa20-Poly1305)
    const msg = new TextEncoder().encode(plaintext);
    const box = nacl.secretbox(msg, nonce, key);
    if (!box) {
      throw new Error('NaCl encryption failed');
    }
    console.log('✅ NaCl secretbox encryption complete');
    
    // Create versioned header
    const header = createHeader(config, salt, nonce);
    console.log('✅ Versioned header created');
    
    // Create final blob
    const blob = createBlob(header, box);
    const result = blobToBase64(blob);
    
    console.log(`✅ v2 encryption complete, blob size: ${blob.length} bytes`);
    return result;
    
  } catch (error) {
    console.error('💥 v2 encryption failed:', error);
    throw error;
  }
}

/**
 * Decrypt Base64 blob with versioned header validation
 * Automatically detects and uses correct KDF based on header
 */
export async function decryptV2(b64: string, password: string): Promise<string> {
  try {
    console.log('🔓 Starting v2 decryption with header parsing...');
    
    // Parse Base64 blob
    const blob = base64ToBlob(b64);
    console.log(`📥 Parsed blob, size: ${blob.length} bytes`);
    
    // Parse versioned header
    const { header, ciphertext } = parseHeader(blob);
    console.log(`✅ Header parsed: ${header.magic} v${header.version}, KDF: ${header.kdfId}`);
    
    // Derive key using header-specified KDF and params
    const { key } = await deriveKey(password, header.salt, header.kdfConfig);
    console.log(`✅ Key re-derived using ${header.kdfId}`);
    
    // Decrypt with NaCl secretbox
    const plain = nacl.secretbox.open(ciphertext, header.nonce, key);
    if (!plain) {
      throw new Error('Decryption failed: incorrect password or corrupted data');
    }
    console.log('✅ NaCl secretbox decryption complete');
    
    const result = new TextDecoder().decode(plain);
    console.log('✅ v2 decryption complete');
    
    return result;
    
  } catch (error) {
    console.error('💥 v2 decryption failed:', error);
    throw error;
  }
}

/**
 * Legacy decrypt function for backward compatibility with old format
 * Tries v2 first, falls back to legacy format
 */
export async function decryptAuto(b64: string, password: string): Promise<string> {
  try {
    // Try v2 format first
    return await decryptV2(b64, password);
  } catch (error) {
    console.log('⚠️ v2 decryption failed, trying legacy format...');
    
    // Fall back to legacy format (your original implementation)
    try {
      // Import legacy decrypt function
      const { decryptFromBase64 } = await import('./legacy-crypto');
      return await decryptFromBase64(b64, password);
    } catch (legacyError) {
      console.error('💥 Both v2 and legacy decryption failed');
      throw new Error('Decryption failed: incorrect password or unsupported format');
    }
  }
}

/**
 * Get KDF info from encrypted blob without decrypting
 */
export function getKdfInfo(b64: string): { kdfId: KdfId; config: Required<KdfConfig> } | null {
  try {
    const blob = base64ToBlob(b64);
    const { header } = parseHeader(blob);
    return { kdfId: header.kdfId, config: header.kdfConfig };
  } catch (error) {
    console.log('⚠️ Could not parse header, likely legacy format');
    return null;
  }
}
