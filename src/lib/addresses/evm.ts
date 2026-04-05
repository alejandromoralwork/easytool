import { computeAddress } from 'ethers';
import { Point } from '@noble/secp256k1';
import bs58 from 'bs58';
import { bytesToHex, hexToBytes, toArrayBuffer } from '../utils/encoding';

export function deriveEvmAddress(publicKeyHex: string): string {
  const clean = publicKeyHex.trim().replace(/^0x/i, '');
  const normalized = clean.length === 66 ? `0x${bytesToHex(Point.fromHex(clean).toBytes(false))}` : `0x${clean}`;
  return computeAddress(normalized);
}

export async function deriveTronAddressAsync(publicKeyHex: string): Promise<string> {
  const evmAddress = deriveEvmAddress(publicKeyHex);
  const payload = hexToBytes(`41${evmAddress.slice(2)}`);
  const first = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(payload)));
  const second = new Uint8Array(await crypto.subtle.digest('SHA-256', first));
  const checksum = second.slice(0, 4);
  const combined = new Uint8Array(payload.length + checksum.length);
  combined.set(payload, 0);
  combined.set(checksum, payload.length);
  return bs58.encode(combined);
}
