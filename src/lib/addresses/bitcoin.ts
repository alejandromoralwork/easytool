import * as bitcoin from 'bitcoinjs-lib';
import { Point } from '@noble/secp256k1';
import { hexToBytes } from '../utils/encoding';

export interface BitcoinLikeNetwork {
  name: string;
  pubKeyHash: number;
  scriptHash: number;
  bech32?: string;
}

const networkMap: Record<string, BitcoinLikeNetwork> = {
  btc: { name: 'Bitcoin', pubKeyHash: 0x00, scriptHash: 0x05, bech32: 'bc' },
  ltc: { name: 'Litecoin', pubKeyHash: 0x30, scriptHash: 0x32, bech32: 'ltc' },
  doge: { name: 'Dogecoin', pubKeyHash: 0x1e, scriptHash: 0x16 },
  pol: { name: 'Polygon', pubKeyHash: 0x00, scriptHash: 0x05, bech32: 'bc' },
};

export function deriveBitcoinLikeAddresses(publicKeyHex: string, networkId: keyof typeof networkMap) {
  const network = networkMap[networkId];
  const clean = publicKeyHex.trim().replace(/^0x/i, '');
  const publicKey = clean.length === 130 ? Point.fromHex(clean).toBytes(true) : hexToBytes(clean);

  const bitcoinNetwork: bitcoin.Network = {
    messagePrefix: '\u0018Bitcoin Signed Message:\n',
    bip32: { public: 0, private: 0 },
    pubKeyHash: network.pubKeyHash,
    scriptHash: network.scriptHash,
    wif: 0x80,
    bech32: network.bech32 ?? '',
  };

  const legacy = bitcoin.payments.p2pkh({ pubkey: publicKey, network: bitcoinNetwork }).address ?? '';
  const nestedSegwit = network.bech32
    ? bitcoin.payments.p2sh({
        redeem: bitcoin.payments.p2wpkh({ pubkey: publicKey, network: bitcoinNetwork }),
        network: bitcoinNetwork,
      }).address ?? ''
    : '';
  const nativeSegwit = network.bech32
    ? bitcoin.payments.p2wpkh({ pubkey: publicKey, network: bitcoinNetwork }).address ?? ''
    : '';

  return {
    network: network.name,
    addresses: [
      { type: 'legacy', address: legacy },
      ...(nativeSegwit ? [{ type: 'native-segwit', address: nativeSegwit }] : []),
      ...(nestedSegwit ? [{ type: 'nested-segwit', address: nestedSegwit }] : []),
    ],
  };
}
