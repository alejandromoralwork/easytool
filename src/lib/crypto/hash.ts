import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../utils/encoding';

export function sha256Text(value: string): string {
  return bytesToHex(nobleSha256(utf8ToBytes(value)));
}

export function sha256Hex(value: string): string {
  return bytesToHex(nobleSha256(hexToBytes(value)));
}

export function sha256Bytes(value: Uint8Array): string {
  return bytesToHex(nobleSha256(value));
}
