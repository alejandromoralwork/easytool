import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { Wallet } from 'ethers';
import { bytesToHex, concatBytes, utf8ToBytes } from '../utils/encoding';

const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

export interface DerivePrivateKeyOptions {
  words: string;
  salt?: string;
  rounds?: number;
  normalizeInput?: boolean;
}

export interface DerivationInputData {
  normalization_enabled: boolean;
  raw_words: string;
  normalized_words?: string;
}

export interface EvmWordsDerivationResult {
  algorithm: 'sha256';
  rounds: number;
  salt: string;
  note: string;
  input: DerivationInputData;
  private_key: string;
  ethereum: {
    address: string;
    private_key: string;
  };
  bsc: {
    address: string;
    private_key: string;
    chain_id: 97;
  };
}

function digestToBigInt(digest: Uint8Array): bigint {
  return BigInt(`0x${bytesToHex(digest)}`);
}

export function normalizeWords(text: string): string {
  const cleaned = text.trim().toLowerCase().replace(/\s+/g, ' ');
  if (!cleaned) {
    throw new Error('Input words cannot be empty');
  }
  return cleaned;
}

export function derivePrivateKeyFromWords(options: DerivePrivateKeyOptions): string {
  const rounds = options.rounds ?? 1;
  const salt = options.salt ?? '';
  const normalizeInput = options.normalizeInput ?? true;

  if (rounds < 1) {
    throw new Error('rounds must be >= 1');
  }

  const words = options.words;
  const baseWords = normalizeInput
    ? normalizeWords(words)
    : (() => {
        if (!words || !words.trim()) {
          throw new Error('Input words cannot be empty');
        }
        return words;
      })();

  const material = utf8ToBytes(`${baseWords}|${salt}`);
  let digest = nobleSha256(material);

  for (let index = 0; index < rounds - 1; index += 1) {
    digest = nobleSha256(digest);
  }

  let value = digestToBigInt(digest);

  if (value === 0n || value >= SECP256K1_N) {
    const retryMaterial = concatBytes(digest, utf8ToBytes('|retry'));
    digest = nobleSha256(retryMaterial);
    value = digestToBigInt(digest);

    if (value === 0n || value >= SECP256K1_N) {
      throw new Error('Derived key was out of valid secp256k1 range');
    }
  }

  return `0x${bytesToHex(digest)}`;
}

export function buildEvmWordsDerivationResult(options: {
  privateKeyHex: string;
  words: string;
  salt: string;
  rounds: number;
  normalizeInput: boolean;
}): EvmWordsDerivationResult {
  const account = new Wallet(options.privateKeyHex);

  const inputData: DerivationInputData = {
    normalization_enabled: options.normalizeInput,
    raw_words: options.words,
  };

  if (options.normalizeInput) {
    inputData.normalized_words = normalizeWords(options.words);
  }

  return {
    algorithm: 'sha256',
    rounds: options.rounds,
    salt: options.salt,
    note: 'ETH and BSC use the same EVM private key format.',
    input: inputData,
    private_key: options.privateKeyHex,
    ethereum: {
      address: account.address,
      private_key: options.privateKeyHex,
    },
    bsc: {
      address: account.address,
      private_key: options.privateKeyHex,
      chain_id: 97,
    },
  };
}

export function deriveEvmAndBscFromWords(options: DerivePrivateKeyOptions): EvmWordsDerivationResult {
  const rounds = options.rounds ?? 1;
  const salt = options.salt ?? '';
  const normalizeInput = options.normalizeInput ?? true;
  const privateKeyHex = derivePrivateKeyFromWords({
    words: options.words,
    salt,
    rounds,
    normalizeInput,
  });

  return buildEvmWordsDerivationResult({
    privateKeyHex,
    words: options.words,
    salt,
    rounds,
    normalizeInput,
  });
}
