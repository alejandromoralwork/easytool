import { getPublicKey, Point } from '@noble/secp256k1';
import * as bip39 from 'bip39';
import { HDKey } from '@scure/bip32';
import { bytesToHex, hexToBytes } from '../utils/encoding';

export type InputKind = 'publicKeyHex' | 'privateKeyHex' | 'mnemonic' | 'xpub';

export interface DerivationSource {
  kind: InputKind;
  value: string;
  publicKeyHex: string;
}

export function normalizePublicKeyHex(value: string): string {
  const clean = value.trim().replace(/^0x/i, '');
  const bytes = hexToBytes(clean);
  if (bytes.length !== 33 && bytes.length !== 65) {
    throw new Error('Public key must be 33 or 65 bytes long');
  }
  return clean.toLowerCase();
}

export function normalizePrivateKeyHex(value: string): string {
  const clean = value.trim().replace(/^0x/i, '');
  const bytes = hexToBytes(clean);
  if (bytes.length !== 32) {
    throw new Error('Private key must be 32 bytes long');
  }
  return clean.toLowerCase();
}

export function resolvePublicKeyHex(input: string, kind: InputKind, derivationPath = "m/44'/0'/0'/0/0"): DerivationSource {
  if (kind === 'publicKeyHex') {
    return {
      kind,
      value: normalizePublicKeyHex(input),
      publicKeyHex: normalizePublicKeyHex(input),
    };
  }

  if (kind === 'privateKeyHex') {
    const privateKeyHex = normalizePrivateKeyHex(input);
    return {
      kind,
      value: privateKeyHex,
      publicKeyHex: bytesToHex(getPublicKey(hexToBytes(privateKeyHex), true)),
    };
  }

  if (kind === 'mnemonic') {
    if (!bip39.validateMnemonic(input.trim())) {
      throw new Error('Invalid BIP39 mnemonic');
    }
    const seed = bip39.mnemonicToSeedSync(input.trim());
    const node = HDKey.fromMasterSeed(seed).derive(derivationPath);
    if (!node.publicKey) {
      throw new Error('Failed to derive public key from mnemonic');
    }
    return {
      kind,
      value: input.trim(),
      publicKeyHex: bytesToHex(node.publicKey),
    };
  }

  const node = HDKey.fromExtendedKey(input.trim());
  const derived = node.derive(derivationPath);
  if (!derived.publicKey) {
    throw new Error('Failed to derive public key from xpub');
  }
  return {
    kind,
    value: input.trim(),
    publicKeyHex: bytesToHex(derived.publicKey),
  };
}

export function toUncompressedPublicKeyHex(publicKeyHex: string): string {
  const point = Point.fromHex(publicKeyHex.replace(/^0x/i, ''));
  return bytesToHex(point.toBytes(false));
}

export function isSupportedInputKind(value: string): value is InputKind {
  return ['publicKeyHex', 'privateKeyHex', 'mnemonic', 'xpub'].includes(value);
}
