import { scryptAsync } from '@noble/hashes/scrypt';
import { utf8ToBytes } from '../utils/encoding';

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  length: number;
}

export const DEFAULT_SCRYPT_PARAMS: ScryptParams = {
  N: 16384,
  r: 8,
  p: 1,
  length: 32,
};

export async function deriveKeywordKey(keyword: string, salt: Uint8Array, params: ScryptParams = DEFAULT_SCRYPT_PARAMS): Promise<Uint8Array> {
  return scryptAsync(utf8ToBytes(keyword), salt, {
    N: params.N,
    r: params.r,
    p: params.p,
    dkLen: params.length,
  });
}
