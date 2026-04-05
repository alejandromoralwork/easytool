import bs58 from 'bs58';
import { hexToBytes } from '../utils/encoding';

export function deriveSolanaAddress(publicKeyHex: string): string {
  const clean = publicKeyHex.trim().replace(/^0x/i, '');
  const bytes = hexToBytes(clean);
  if (bytes.length !== 32) {
    throw new Error('Solana public keys must be 32 bytes in hex form');
  }
  return bs58.encode(bytes);
}
