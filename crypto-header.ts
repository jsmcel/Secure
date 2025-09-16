import { KdfId, KdfConfig, serializeKdfParams, deserializeKdfParams } from './kdf';

// Protocol constants
export const MAGIC = 'SS1';
export const VERSION = 1;

// KDF ID mappings
export const KDF_IDS: Record<KdfId, number> = {
  'argon2id': 0x01,
  'scrypt': 0x02
};

export const KDF_NAMES: Record<number, KdfId> = {
  0x01: 'argon2id',
  0x02: 'scrypt'
};

// Header structure: magic(3) | ver(1) | kdf_id(1) | params(12) | salt(16) | nonce(24) | box(...)
export const HEADER_SIZE = 3 + 1 + 1 + 12 + 16 + 24; // 57 bytes

export interface CryptoHeader {
  magic: string;
  version: number;
  kdfId: KdfId;
  kdfConfig: Required<KdfConfig>;
  salt: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Create versioned header for encrypted blob
 */
export function createHeader(
  kdfConfig: Required<KdfConfig>,
  salt: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer);
  let offset = 0;

  // Magic (3 bytes)
  const magicBytes = new TextEncoder().encode(MAGIC);
  header.set(magicBytes, offset);
  offset += 3;

  // Version (1 byte)
  view.setUint8(offset, VERSION);
  offset += 1;

  // KDF ID (1 byte)
  const kdfIdByte = KDF_IDS[kdfConfig.id];
  if (kdfIdByte === undefined) {
    throw new Error(`Unknown KDF ID: ${kdfConfig.id}`);
  }
  view.setUint8(offset, kdfIdByte);
  offset += 1;

  // KDF params (12 bytes)
  const params = serializeKdfParams(kdfConfig);
  header.set(params, offset);
  offset += 12;

  // Salt (16 bytes)
  header.set(salt, offset);
  offset += 16;

  // Nonce (24 bytes)
  header.set(nonce, offset);
  offset += 24;

  return header;
}

/**
 * Parse versioned header from encrypted blob
 */
export function parseHeader(blob: Uint8Array): { header: CryptoHeader; ciphertext: Uint8Array } {
  if (blob.length < HEADER_SIZE) {
    throw new Error('Blob too short for header');
  }

  const view = new DataView(blob.buffer, blob.byteOffset);
  let offset = 0;

  // Magic (3 bytes)
  const magicBytes = blob.slice(offset, offset + 3);
  const magic = new TextDecoder().decode(magicBytes);
  if (magic !== MAGIC) {
    throw new Error(`Invalid magic: expected "${MAGIC}", got "${magic}"`);
  }
  offset += 3;

  // Version (1 byte)
  const version = view.getUint8(offset);
  if (version !== VERSION) {
    throw new Error(`Unsupported version: ${version}`);
  }
  offset += 1;

  // KDF ID (1 byte)
  const kdfIdByte = view.getUint8(offset);
  const kdfId = KDF_NAMES[kdfIdByte];
  if (!kdfId) {
    throw new Error(`Unknown KDF ID: 0x${kdfIdByte.toString(16)}`);
  }
  offset += 1;

  // KDF params (12 bytes)
  const paramsBytes = blob.slice(offset, offset + 12);
  const kdfConfig = deserializeKdfParams(kdfId, paramsBytes);
  offset += 12;

  // Salt (16 bytes)
  const salt = blob.slice(offset, offset + 16);
  offset += 16;

  // Nonce (24 bytes)
  const nonce = blob.slice(offset, offset + 24);
  offset += 24;

  // Remaining data is ciphertext
  const ciphertext = blob.slice(offset);

  const header: CryptoHeader = {
    magic,
    version,
    kdfId,
    kdfConfig,
    salt,
    nonce
  };

  return { header, ciphertext };
}

/**
 * Create complete encrypted blob with versioned header
 */
export function createBlob(
  header: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  const blob = new Uint8Array(header.length + ciphertext.length);
  blob.set(header, 0);
  blob.set(ciphertext, header.length);
  return blob;
}

/**
 * Convert blob to Base64 for storage/transmission
 */
export function blobToBase64(blob: Uint8Array): string {
  // Use Buffer for consistent Base64 encoding
  return Buffer.from(blob).toString('base64');
}

/**
 * Convert Base64 back to blob
 */
export function base64ToBlob(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
