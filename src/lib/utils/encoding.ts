const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8ToBytes(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function bytesToUtf8(value: Uint8Array): string {
  return textDecoder.decode(value);
}

export function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(value: string): Uint8Array {
  const clean = value.trim().replace(/^0x/i, '').replace(/\s+/g, '');
  if (clean.length === 0 || clean.length % 2 !== 0 || /[^0-9a-f]/i.test(clean)) {
    throw new Error('Invalid hex input');
  }

  const bytes = new Uint8Array(clean.length / 2);
  for (let index = 0; index < clean.length; index += 2) {
    bytes[index / 2] = Number.parseInt(clean.slice(index, index + 2), 16);
  }
  return bytes;
}

export function isHex(value: string): boolean {
  return /^[0-9a-f]+$/i.test(value.trim().replace(/^0x/i, ''));
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    merged.set(part, offset);
    offset += part.length;
  }
  return merged;
}

export function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(value.byteLength);
  new Uint8Array(buffer).set(value);
  return buffer;
}

export function toBase64(value: Uint8Array): string {
  if (typeof btoa === 'function') {
    let binary = '';
    value.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  }

  return Buffer.from(value).toString('base64');
}

export function fromBase64(value: string): Uint8Array {
  if (typeof atob === 'function') {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  return new Uint8Array(Buffer.from(value, 'base64'));
}
