import { useMemo, useState } from 'react';
import { sha256Text } from './lib/crypto/hash';
import {
  encryptWithKeyword,
  decryptWithKeyword,
  encryptBytesWithKeyword,
  decryptBytesWithKeyword,
  parseCipherBundle,
  serializeCipherBundle,
} from './lib/crypto/encrypt';
import {
  deriveAddresses,
  deriveEvmAndBscFromWords,
  type NetworkId,
  type EvmWordsDerivationResult,
} from './lib/addresses';
import type { InputKind } from './lib/keys/normalizeInput';
import { toArrayBuffer } from './lib/utils/encoding';

interface EncryptedFileBundle {
  version: 1;
  mode: 'secure' | 'compat';
  kdf: 'scrypt' | 'sha256';
  salt: string;
  iv: string;
  ciphertext: string;
  fileName: string;
  fileType: string;
  fileSize: number;
}

const networkOptions: { id: NetworkId; label: string }[] = [
  { id: 'btc', label: 'Bitcoin' },
  { id: 'ltc', label: 'Litecoin' },
  { id: 'doge', label: 'Dogecoin' },
  { id: 'eth', label: 'Ethereum' },
  { id: 'trx', label: 'Tron' },
  { id: 'sol', label: 'Solana' },
  { id: 'pol', label: 'Polygon' },
];

const inputKinds: { id: InputKind; label: string }[] = [
  { id: 'publicKeyHex', label: 'Public key hex' },
  { id: 'privateKeyHex', label: 'Private key hex' },
  { id: 'mnemonic', label: 'Mnemonic' },
  { id: 'xpub', label: 'xpub' },
];

export default function App() {
  const [hashInput, setHashInput] = useState('');
  const [hashOutput, setHashOutput] = useState('');
  const [cryptoInput, setCryptoInput] = useState('');
  const [inputKind, setInputKind] = useState<InputKind>('publicKeyHex');
  const [selectedNetworks, setSelectedNetworks] = useState<NetworkId[]>(['btc', 'eth', 'trx', 'sol', 'ltc', 'doge', 'pol']);
  const [derivationPath, setDerivationPath] = useState("m/44'/0'/0'/0/0");
  const [addressOutput, setAddressOutput] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [keyword, setKeyword] = useState('');
  const [cipherMode, setCipherMode] = useState<'secure' | 'compat'>('secure');
  const [ciphertext, setCiphertext] = useState('');
  const [decryptOutput, setDecryptOutput] = useState('');
  const [decryptError, setDecryptError] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileKeyword, setFileKeyword] = useState('');
  const [fileCipherMode, setFileCipherMode] = useState<'secure' | 'compat'>('secure');
  const [fileCipherBundle, setFileCipherBundle] = useState('');
  const [fileDecryptBundle, setFileDecryptBundle] = useState('');
  const [fileDecryptUrl, setFileDecryptUrl] = useState('');
  const [fileDecryptName, setFileDecryptName] = useState('');
  const [fileError, setFileError] = useState('');
  const [walletWords, setWalletWords] = useState('');
  const [walletSalt, setWalletSalt] = useState('');
  const [walletRounds, setWalletRounds] = useState('1');
  const [walletNoNormalize, setWalletNoNormalize] = useState(false);
  const [walletJson, setWalletJson] = useState(true);
  const [walletOutFileName, setWalletOutFileName] = useState('derived-evm-wallet.json');
  const [walletOutput, setWalletOutput] = useState('');
  const [walletError, setWalletError] = useState('');
  const [walletResult, setWalletResult] = useState<EvmWordsDerivationResult | null>(null);
  const [walletCopyStatus, setWalletCopyStatus] = useState('');

  const selectedNetworkLabels = useMemo(
    () => networkOptions.filter((network) => selectedNetworks.includes(network.id)).map((network) => network.label),
    [selectedNetworks],
  );

  async function handleDerive() {
    setAddressOutput('Working...');
    try {
      const results = await deriveAddresses({
        input: cryptoInput,
        inputKind,
        networks: selectedNetworks,
        derivationPath,
      });
      setAddressOutput(JSON.stringify(results, null, 2));
    } catch (error) {
      setAddressOutput(error instanceof Error ? error.message : 'Failed to derive addresses');
    }
  }

  async function handleEncrypt() {
    try {
      const bundle = await encryptWithKeyword(plaintext, keyword, cipherMode);
      setCiphertext(serializeCipherBundle(bundle));
      setDecryptError('');
    } catch (error) {
      setDecryptError(error instanceof Error ? error.message : 'Encryption failed');
    }
  }

  async function handleDecrypt() {
    try {
      const bundle = parseCipherBundle(ciphertext);
      const output = await decryptWithKeyword(bundle, keyword);
      setDecryptOutput(output);
      setDecryptError('');
    } catch (error) {
      setDecryptError(error instanceof Error ? error.message : 'Decryption failed');
    }
  }

  async function handleFileEncrypt() {
    if (!selectedFile) {
      setFileError('Pick a file first.');
      return;
    }
    if (!fileKeyword.trim()) {
      setFileError('Enter a keyword/password for file encryption.');
      return;
    }

    try {
      const bytes = new Uint8Array(await selectedFile.arrayBuffer());
      const bundle = await encryptBytesWithKeyword(bytes, fileKeyword, fileCipherMode);
      const fileBundle: EncryptedFileBundle = {
        ...bundle,
        fileName: selectedFile.name,
        fileType: selectedFile.type || 'application/octet-stream',
        fileSize: selectedFile.size,
      };
      const serialized = JSON.stringify(fileBundle, null, 2);
      setFileCipherBundle(serialized);
      setFileDecryptBundle(serialized);
      setFileError('');
    } catch (error) {
      setFileError(error instanceof Error ? error.message : 'File encryption failed');
    }
  }

  async function handleFileDecrypt() {
    if (!fileKeyword.trim()) {
      setFileError('Enter the keyword/password used for this file.');
      return;
    }

    try {
      const parsed = JSON.parse(fileDecryptBundle) as EncryptedFileBundle;
      const coreBundle = parseCipherBundle(JSON.stringify(parsed));
      const bytes = await decryptBytesWithKeyword(coreBundle, fileKeyword);
      const blob = new Blob([toArrayBuffer(bytes)], { type: parsed.fileType || 'application/octet-stream' });

      if (fileDecryptUrl) {
        URL.revokeObjectURL(fileDecryptUrl);
      }

      const nextUrl = URL.createObjectURL(blob);
      setFileDecryptUrl(nextUrl);
      setFileDecryptName(parsed.fileName || 'decrypted.bin');
      setFileError('');
    } catch (error) {
      setFileError(error instanceof Error ? error.message : 'File decryption failed');
    }
  }

  function handleDownloadDecryptedFile() {
    if (!fileDecryptUrl) {
      return;
    }
    const anchor = document.createElement('a');
    anchor.href = fileDecryptUrl;
    anchor.download = fileDecryptName;
    anchor.click();
  }

  function handleCreateWalletByWords() {
    const rounds = Number.parseInt(walletRounds, 10);
    if (!Number.isFinite(rounds) || rounds < 1) {
      setWalletError('rounds must be >= 1');
      return;
    }

    try {
      const result = deriveEvmAndBscFromWords({
        words: walletWords,
        salt: walletSalt,
        rounds,
        normalizeInput: !walletNoNormalize,
      });
      setWalletResult(result);

      if (walletJson) {
        setWalletOutput(JSON.stringify(result, null, 2));
      } else {
        setWalletOutput(
          [
            'Derived EVM Private Key',
            `Private Key: ${result.private_key}`,
            `ETH Address: ${result.ethereum.address}`,
            `BSC Address: ${result.bsc.address} (chain_id=${result.bsc.chain_id})`,
            'Note: ETH and BSC use the same private key format.',
          ].join('\n'),
        );
      }

      setWalletError('');
      setWalletCopyStatus('');
    } catch (error) {
      setWalletError(error instanceof Error ? error.message : 'Wallet derivation failed');
      setWalletResult(null);
    }
  }

  function handleDownloadWalletOutput() {
    if (!walletOutput.trim()) {
      setWalletError('Generate wallet output first.');
      return;
    }

    const fileName = walletOutFileName.trim() || 'derived-evm-wallet.json';
    const blob = new Blob([walletOutput], { type: walletJson ? 'application/json' : 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function handleCopyWalletValue(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setWalletCopyStatus(`${label} copied.`);
    } catch {
      setWalletCopyStatus(`Could not copy ${label.toLowerCase()}.`);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero panel">
        <div className="badges">
          <span className="badge">Local-first</span>
          <span className="badge">Hashing</span>
          <span className="badge">Address derivation</span>
          <span className="badge">Keyword encryption</span>
        </div>
        <h1>EasyTool Crypto Suite</h1>
        <p>
          A personal crypto workspace for hashing, deriving addresses across multiple networks,
          and encrypting secrets with either strong or compatibility-focused keyword flows.
        </p>
        <p className="small">
          Selected networks: {selectedNetworkLabels.join(', ')}
        </p>
      </section>

      <section className="grid">
        <article className="panel">
          <h2>Create wallet from words</h2>
          <div className="field-grid">
            <textarea
              value={walletWords}
              onChange={(event) => setWalletWords(event.target.value)}
              placeholder="words"
            />
            <input
              value={walletSalt}
              onChange={(event) => setWalletSalt(event.target.value)}
              placeholder="salt"
            />
            <input
              value={walletRounds}
              onChange={(event) => setWalletRounds(event.target.value)}
              placeholder="rounds (default: 1)"
            />
            <div className="row">
              <label className="badge" style={{ display: 'flex', gap: '0.45rem', alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={walletNoNormalize}
                  onChange={(event) => setWalletNoNormalize(event.target.checked)}
                />
                no-normalize
              </label>
              <label className="badge" style={{ display: 'flex', gap: '0.45rem', alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={walletJson}
                  onChange={(event) => setWalletJson(event.target.checked)}
                />
                json output
              </label>
            </div>
            <input
              value={walletOutFileName}
              onChange={(event) => setWalletOutFileName(event.target.value)}
              placeholder="out file name"
            />
            <div className="actions">
              <button type="button" onClick={handleCreateWalletByWords}>Create wallet</button>
              <button type="button" className="secondary" onClick={handleDownloadWalletOutput}>Download output</button>
            </div>
            <div className="actions">
              <button
                type="button"
                className="secondary"
                disabled={!walletResult}
                onClick={() => walletResult && handleCopyWalletValue('Private key', walletResult.private_key)}
              >
                Copy private key
              </button>
              <button
                type="button"
                className="secondary"
                disabled={!walletResult}
                onClick={() => walletResult && handleCopyWalletValue('ETH address', walletResult.ethereum.address)}
              >
                Copy ETH address
              </button>
              <button
                type="button"
                className="secondary"
                disabled={!walletResult}
                onClick={() => walletResult && handleCopyWalletValue('BSC address', walletResult.bsc.address)}
              >
                Copy BSC address
              </button>
            </div>
            {walletCopyStatus ? <p className="small success">{walletCopyStatus}</p> : null}
            <div className="output">{walletOutput || 'Wallet output appears here.'}</div>
            {walletError ? <div className="output warning">{walletError}</div> : null}
          </div>
        </article>

        <article className="panel">
          <h2>SHA-256</h2>
          <div className="field-grid">
            <textarea value={hashInput} onChange={(event) => setHashInput(event.target.value)} placeholder="Text to hash" />
            <div className="actions">
              <button type="button" onClick={() => setHashOutput(sha256Text(hashInput))}>Hash text</button>
            </div>
            <div className="output">{hashOutput || 'Hash output appears here.'}</div>
          </div>
        </article>

        <article className="panel">
          <h2>Address derivation</h2>
          <div className="field-grid">
            <select value={inputKind} onChange={(event) => setInputKind(event.target.value as InputKind)}>
              {inputKinds.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}
            </select>
            <textarea value={cryptoInput} onChange={(event) => setCryptoInput(event.target.value)} placeholder="Public key, private key, mnemonic, or xpub" />
            <input value={derivationPath} onChange={(event) => setDerivationPath(event.target.value)} placeholder="m/44'/0'/0'/0/0" />
            <div className="row">
              {networkOptions.map((network) => (
                <label key={network.id} className="badge" style={{ display: 'flex', gap: '0.45rem', alignItems: 'center' }}>
                  <input
                    type="checkbox"
                    checked={selectedNetworks.includes(network.id)}
                    onChange={(event) => {
                      setSelectedNetworks((current) =>
                        event.target.checked
                          ? [...current, network.id]
                          : current.filter((entry) => entry !== network.id),
                      );
                    }}
                  />
                  {network.label}
                </label>
              ))}
            </div>
            <div className="actions">
              <button type="button" onClick={handleDerive}>Derive addresses</button>
            </div>
            <div className="output">{addressOutput || 'Derived addresses will be shown here.'}</div>
          </div>
        </article>

        <article className="panel">
          <h2>Encrypt</h2>
          <div className="field-grid">
            <textarea value={plaintext} onChange={(event) => setPlaintext(event.target.value)} placeholder="Secret text" />
            <input value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="Keyword / password" />
            <select value={cipherMode} onChange={(event) => setCipherMode(event.target.value as 'secure' | 'compat')}>
              <option value="secure">Secure mode (scrypt + AES-GCM)</option>
              <option value="compat">Compatibility mode (sha256 + AES-GCM)</option>
            </select>
            <div className="actions">
              <button type="button" onClick={handleEncrypt}>Encrypt</button>
              <button type="button" className="secondary" onClick={handleDecrypt}>Decrypt</button>
            </div>
            <div className="output">{ciphertext || 'Encrypted payload appears here.'}</div>
            <div className="output success">{decryptOutput || 'Decrypted output appears here.'}</div>
            {decryptError ? <div className="output warning">{decryptError}</div> : null}
          </div>
        </article>

        <article className="panel">
          <h2>File encryption</h2>
          <div className="field-grid">
            <input
              type="file"
              onChange={(event) => {
                const file = event.target.files?.[0] ?? null;
                setSelectedFile(file);
              }}
            />
            <input
              value={fileKeyword}
              onChange={(event) => setFileKeyword(event.target.value)}
              placeholder="Keyword / password"
            />
            <select value={fileCipherMode} onChange={(event) => setFileCipherMode(event.target.value as 'secure' | 'compat')}>
              <option value="secure">Secure mode (scrypt + AES-GCM)</option>
              <option value="compat">Compatibility mode (sha256 + AES-GCM)</option>
            </select>
            <div className="actions">
              <button type="button" onClick={handleFileEncrypt}>Encrypt file</button>
              <button type="button" className="secondary" onClick={handleFileDecrypt}>Decrypt bundle</button>
              <button type="button" className="secondary" onClick={handleDownloadDecryptedFile} disabled={!fileDecryptUrl}>Download decrypted file</button>
            </div>
            <p className="small">File operations run locally in your browser and never upload file bytes.</p>
            <textarea
              value={fileDecryptBundle}
              onChange={(event) => setFileDecryptBundle(event.target.value)}
              placeholder="Encrypted file bundle JSON"
            />
            <div className="output">{fileCipherBundle || 'Encrypted file bundle appears here.'}</div>
            {fileError ? <div className="output warning">{fileError}</div> : null}
          </div>
        </article>
      </section>
    </main>
  );
}
