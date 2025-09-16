import { scrypt } from 'scrypt-js';

// Platform detection
const isWeb = typeof window !== 'undefined';

let argon2: any = null;

// Lazy load Argon2 from hash-wasm
async function loadArgon2() {
  if (argon2) return argon2;
  
  try {
    const { argon2id } = await import('hash-wasm');
    argon2 = argon2id;
    console.log('✅ Argon2id loaded from hash-wasm');
    return argon2;
  } catch (error) {
    console.log('⚠️ Failed to load Argon2 from hash-wasm:', error);
    return null;
  }
}

// KDF Configuration types
export type KdfId = 'argon2id' | 'scrypt';

export interface KdfConfig {
  id: KdfId;
  // Argon2id params
  m?: number;     // memory KiB (default 19 * 1024)
  t?: number;     // iterations (default 2)
  p?: number;     // parallelism (default 1)
  // scrypt params
  N?: number;     // default 1<<17 (131072)
  r?: number;     // default 8
  s_p?: number;   // default 1
  keyLen?: number; // default 32
}

// Default configurations per OWASP recommendations
export const DEFAULT_ARGON2ID: Required<KdfConfig> = {
  id: 'argon2id',
  m: 19 * 1024,    // 19 MiB
  t: 2,            // 2 iterations
  p: 1,            // 1 thread
  N: 0, r: 0, s_p: 0, // unused for argon2id
  keyLen: 32
};

export const DEFAULT_SCRYPT: Required<KdfConfig> = {
  id: 'scrypt',
  N: 1 << 17,      // 131072 (OWASP minimum)
  r: 8,
  s_p: 1,
  m: 0, t: 0, p: 0, // unused for scrypt
  keyLen: 32
};

// Lightweight scrypt fallback for mobile (faster but still secure)
export const MOBILE_SCRYPT: Required<KdfConfig> = {
  id: 'scrypt',
  N: 1 << 12,      // 4096 (mobile optimized - your original value)
  r: 8,
  s_p: 1,
  m: 0, t: 0, p: 0,
  keyLen: 32
};


async function deriveKeyArgon2id(
  password: string, 
  salt: Uint8Array, 
  config: Required<KdfConfig>
): Promise<Uint8Array> {
  const argon2Lib = await loadArgon2();
  if (!argon2Lib) {
    throw new Error('Argon2 not available');
  }

  console.log(`🔐 Argon2id: m=${config.m}KiB, t=${config.t}, p=${config.p}`);
  
  // hash-wasm argon2id signature
  const result = await argon2Lib({
    password: password,
    salt: salt,
    parallelism: config.p,
    iterations: config.t,
    memorySize: config.m, // in KiB
    hashLength: config.keyLen,
    outputType: 'binary'
  });

  return new Uint8Array(result);
}

async function deriveKeyScrypt(
  password: string, 
  salt: Uint8Array, 
  config: Required<KdfConfig>
): Promise<Uint8Array> {
  console.log(`🔐 scrypt: N=${config.N}, r=${config.r}, p=${config.s_p}`);
  
  const pw = new TextEncoder().encode(password);
  const result = await scrypt(pw, salt, config.N, config.r, config.s_p, config.keyLen);
  return new Uint8Array(result);
}

/**
 * Derive encryption key using Argon2id (preferred) or scrypt (fallback)
 * Follows OWASP recommendations for password-based key derivation
 */
export async function deriveKey(
  password: string, 
  salt: Uint8Array, 
  cfg?: Partial<KdfConfig>
): Promise<{ key: Uint8Array; config: Required<KdfConfig> }> {
  // Merge with defaults
  const config = { ...DEFAULT_ARGON2ID, ...cfg } as Required<KdfConfig>;
  
  try {
    // Try Argon2id first (OWASP preferred)
    if (config.id === 'argon2id' || !cfg?.id) {
      try {
        const key = await deriveKeyArgon2id(password, salt, config);
        return { key, config: { ...config, id: 'argon2id' } };
      } catch (error) {
        console.log('⚠️ Argon2id failed, falling back to scrypt');
        // Fall through to scrypt
      }
    }
    
    // Scrypt fallback with platform optimization
    const scryptConfig = cfg?.id === 'scrypt' ? 
      { ...DEFAULT_SCRYPT, ...cfg } : 
      MOBILE_SCRYPT; // Always use mobile-optimized scrypt for fallback
    
    const key = await deriveKeyScrypt(password, salt, scryptConfig as Required<KdfConfig>);
    return { key, config: scryptConfig as Required<KdfConfig> };
    
  } catch (error) {
    console.error('💥 All KDF methods failed:', error);
    throw new Error(`Key derivation failed: ${error}`);
  }
}

// Serialize KDF config to 12 bytes for header
export function serializeKdfParams(config: Required<KdfConfig>): Uint8Array {
  const params = new Uint8Array(12);
  const view = new DataView(params.buffer);
  
  if (config.id === 'argon2id') {
    view.setUint32(0, config.m, true);    // memory KiB (little endian)
    view.setUint32(4, config.t, true);    // iterations
    view.setUint32(8, config.p, true);    // parallelism
  } else if (config.id === 'scrypt') {
    view.setUint32(0, config.N, true);    // N parameter
    view.setUint32(4, config.r, true);    // r parameter  
    view.setUint32(8, config.s_p, true); // p parameter
  }
  
  return params;
}

// Deserialize KDF params from 12 bytes
export function deserializeKdfParams(kdfId: KdfId, params: Uint8Array): Required<KdfConfig> {
  const view = new DataView(params.buffer, params.byteOffset);
  
  if (kdfId === 'argon2id') {
    return {
      id: 'argon2id',
      m: view.getUint32(0, true),
      t: view.getUint32(4, true),
      p: view.getUint32(8, true),
      N: 0, r: 0, s_p: 0, // unused
      keyLen: 32
    };
  } else if (kdfId === 'scrypt') {
    return {
      id: 'scrypt',
      N: view.getUint32(0, true),
      r: view.getUint32(4, true),
      s_p: view.getUint32(8, true),
      m: 0, t: 0, p: 0, // unused
      keyLen: 32
    };
  } else {
    throw new Error(`Unknown KDF ID: ${kdfId}`);
  }
}
