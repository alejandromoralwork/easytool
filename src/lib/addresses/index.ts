import { deriveBitcoinLikeAddresses } from './bitcoin';
import { deriveEvmAddress, deriveTronAddressAsync } from './evm';
import { deriveSolanaAddress } from './solana';
import { resolvePublicKeyHex, toUncompressedPublicKeyHex, type InputKind } from '../keys/normalizeInput';

export {
  normalizeWords,
  derivePrivateKeyFromWords,
  buildEvmWordsDerivationResult,
  deriveEvmAndBscFromWords,
  type DerivePrivateKeyOptions,
  type DerivationInputData,
  type EvmWordsDerivationResult,
} from './evmWordsDerivation';

export type NetworkId = 'btc' | 'ltc' | 'doge' | 'eth' | 'trx' | 'sol' | 'pol';

export interface AddressResult {
  network: NetworkId;
  label: string;
  address: string;
  note?: string;
}

const defaultPaths: Record<NetworkId, string> = {
  btc: "m/84'/0'/0'/0/0",
  ltc: "m/84'/2'/0'/0/0",
  doge: "m/44'/3'/0'/0/0",
  eth: "m/44'/60'/0'/0/0",
  trx: "m/44'/195'/0'/0/0",
  sol: "m/44'/501'/0'/0/0",
  pol: "m/44'/60'/0'/0/0",
};

export async function deriveAddresses(options: {
  input: string;
  inputKind: InputKind;
  networks: NetworkId[];
  derivationPath?: string;
}): Promise<AddressResult[]> {
  const path = options.derivationPath ?? defaultPaths[options.networks[0] ?? 'btc'];
  const source = resolvePublicKeyHex(options.input, options.inputKind, path);
  const publicKeyHex = source.publicKeyHex;
  const uncompressed = toUncompressedPublicKeyHex(publicKeyHex);

  const results: AddressResult[] = [];

  for (const network of options.networks) {
    if (network === 'eth' || network === 'pol') {
      results.push({
        network,
        label: network === 'eth' ? 'Ethereum' : 'Polygon',
        address: deriveEvmAddress(uncompressed),
      });
      continue;
    }

    if (network === 'trx') {
      results.push({
        network,
        label: 'Tron',
        address: await deriveTronAddressAsync(uncompressed),
      });
      continue;
    }

    if (network === 'sol') {
      results.push({
        network,
        label: 'Solana',
        address: deriveSolanaAddress(publicKeyHex),
        note: 'Uses a raw 32-byte public key input for Solana compatibility.',
      });
      continue;
    }

    const { network: resolvedNetwork, addresses } = deriveBitcoinLikeAddresses(publicKeyHex, network);
    addresses.forEach((entry: { type: string; address: string }) => {
      results.push({
        network,
        label: `${resolvedNetwork} ${entry.type}`,
        address: entry.address,
      });
    });
  }

  return results;
}
