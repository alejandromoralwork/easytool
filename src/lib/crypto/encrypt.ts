import { sha256Text } from './hash';
import { deriveKeywordKey, DEFAULT_SCRYPT_PARAMS } from './kdf';
import { fromBase64, hexToBytes, toArrayBuffer, toBase64, utf8ToBytes, bytesToUtf8 } from '../utils/encoding';

export interface CipherBundle {
  version: 1;
  mode: 'secure' | 'compat';
  kdf: 'scrypt' | 'sha256';
  salt: string;
  iv: string;
  ciphertext: string;
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function importAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toArrayBuffer(keyBytes), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function encryptBytesWithKeyword(data: Uint8Array, keyword: string, mode: 'secure' | 'compat' = 'secure'): Promise<CipherBundle> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const keyBytes = mode === 'secure' ? await deriveKeywordKey(keyword, salt, DEFAULT_SCRYPT_PARAMS) : hexToBytes(sha256Text(keyword));
  const aesKey = await importAesKey(keyBytes);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv) },
      aesKey,
      toArrayBuffer(data),
    ),
  );

  return {
    version: 1,
    mode,
    kdf: mode === 'secure' ? 'scrypt' : 'sha256',
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };
}

export async function decryptBytesWithKeyword(bundle: CipherBundle, keyword: string): Promise<Uint8Array> {
  const salt = fromBase64(bundle.salt);
  const iv = fromBase64(bundle.iv);
  const keyBytes = bundle.kdf === 'scrypt' ? await deriveKeywordKey(keyword, salt, DEFAULT_SCRYPT_PARAMS) : hexToBytes(sha256Text(keyword));
  const aesKey = await importAesKey(keyBytes);
  const plaintextBytes = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    aesKey,
    toArrayBuffer(fromBase64(bundle.ciphertext)),
  ));

  return plaintextBytes;
}

export async function encryptWithKeyword(plaintext: string, keyword: string, mode: 'secure' | 'compat' = 'secure'): Promise<CipherBundle> {
  return encryptBytesWithKeyword(utf8ToBytes(plaintext), keyword, mode);
}

export async function decryptWithKeyword(bundle: CipherBundle, keyword: string): Promise<string> {
  const bytes = await decryptBytesWithKeyword(bundle, keyword);
  return bytesToUtf8(bytes);
}

export function serializeCipherBundle(bundle: CipherBundle): string {
  return JSON.stringify(bundle, null, 2);
}

export function parseCipherBundle(value: string): CipherBundle {
  const parsed = JSON.parse(value) as CipherBundle;
  if (parsed.version !== 1 || (parsed.mode !== 'secure' && parsed.mode !== 'compat')) {
    throw new Error('Unsupported cipher bundle');
  }
  return parsed;
}
