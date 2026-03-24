// SSH Key Generation via Web Crypto API
// Supports Ed25519 and RSA (2048/4096)

export type KeyType = 'ed25519' | 'rsa-2048' | 'rsa-4096';

export interface GeneratedKey {
  privateKey: string;
  publicKey: string;
  fingerprint: string;
  command: string;
  keyType: KeyType;
}

// --- Utility helpers ---

function encodeUint32BE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = (n >>> 24) & 0xff;
  buf[1] = (n >>> 16) & 0xff;
  buf[2] = (n >>> 8) & 0xff;
  buf[3] = n & 0xff;
  return buf;
}

function sshString(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const result = new Uint8Array(4 + bytes.length);
  result.set(encodeUint32BE(bytes.length), 0);
  result.set(bytes, 4);
  return result;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function toBase64(data: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

function wrapPem(tag: string, base64: string): string {
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 70) {
    lines.push(base64.slice(i, i + 70));
  }
  return `-----BEGIN ${tag}-----\n${lines.join('\n')}\n-----END ${tag}-----\n`;
}

// --- Ed25519 ---

async function generateEd25519(comment: string): Promise<GeneratedKey> {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

  // Extract seed from PKCS8 (bytes 16..48)
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const seed = pkcs8.slice(16, 48);

  // Extract public key from SPKI (last 32 bytes)
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const pubRaw = spki.slice(spki.length - 32);

  // Public key blob (for one-liner and fingerprint)
  const pubBlob = concat(sshString('ssh-ed25519'), sshString(pubRaw));

  // Public key one-liner
  const publicKeyStr = `ssh-ed25519 ${toBase64(pubBlob)}${comment ? ' ' + comment : ''}`;

  // Fingerprint: SHA256 of public key blob, base64 no padding
  const hashBuf = await crypto.subtle.digest('SHA-256', pubBlob);
  const fingerprint = `SHA256:${toBase64(new Uint8Array(hashBuf)).replace(/=+$/, '')}`;

  // OpenSSH private key format
  const privateKeyStr = buildOpenSshEd25519(seed, pubRaw, comment);

  const cmd = `ssh-keygen -t ed25519${comment ? ` -C "${comment}"` : ''}`;

  return { privateKey: privateKeyStr, publicKey: publicKeyStr, fingerprint, command: cmd, keyType: 'ed25519' };
}

function buildOpenSshEd25519(seed: Uint8Array, pubKey: Uint8Array, comment: string): string {
  const AUTH_MAGIC = new TextEncoder().encode('openssh-key-v1\0');

  // Cipher/KDF = none (unencrypted)
  const cipherName = sshString('none');
  const kdfName = sshString('none');
  const kdfOptions = sshString(new Uint8Array(0));
  const numKeys = encodeUint32BE(1);

  // Public key section
  const pubBlob = concat(sshString('ssh-ed25519'), sshString(pubKey));
  const pubSection = sshString(pubBlob);

  // Private key section
  const checkInt = crypto.getRandomValues(new Uint8Array(4));
  const privKey64 = concat(seed, pubKey); // 64 bytes: seed || pubkey
  const commentBytes = new TextEncoder().encode(comment);

  const privPayload = concat(
    checkInt,
    checkInt, // same value twice
    sshString('ssh-ed25519'),
    sshString(pubKey),
    sshString(privKey64),
    sshString(commentBytes),
  );

  // Pad to multiple of 8 (cipher block size for "none")
  const padLen = (8 - (privPayload.length % 8)) % 8;
  const padding = new Uint8Array(padLen);
  for (let i = 0; i < padLen; i++) {
    padding[i] = (i + 1) & 0xff;
  }

  const privSection = sshString(concat(privPayload, padding));

  // Assemble
  const binary = concat(AUTH_MAGIC, cipherName, kdfName, kdfOptions, numKeys, pubSection, privSection);

  return wrapPem('OPENSSH PRIVATE KEY', toBase64(binary));
}

// --- RSA ---

async function generateRsa(bits: 2048 | 4096, comment: string): Promise<GeneratedKey> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  // PKCS8 private key (OpenSSH reads this natively since 7.8)
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const privateKeyStr = wrapPem('PRIVATE KEY', toBase64(pkcs8));

  // Public key in SSH format
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const { n, e } = extractRsaComponents(spki);

  const pubBlob = concat(sshString('ssh-rsa'), sshString(e), sshString(n));
  const publicKeyStr = `ssh-rsa ${toBase64(pubBlob)}${comment ? ' ' + comment : ''}`;

  // Fingerprint
  const hashBuf = await crypto.subtle.digest('SHA-256', pubBlob);
  const fingerprint = `SHA256:${toBase64(new Uint8Array(hashBuf)).replace(/=+$/, '')}`;

  const cmd = `ssh-keygen -t rsa -b ${bits}${comment ? ` -C "${comment}"` : ''}`;

  return { privateKey: privateKeyStr, publicKey: publicKeyStr, fingerprint, command: cmd, keyType: `rsa-${bits}` as KeyType };
}

// Minimal ASN.1 DER parser for RSA SPKI to extract n and e
function extractRsaComponents(spki: Uint8Array): { n: Uint8Array; e: Uint8Array } {
  let offset = 0;

  function readLength(): number {
    let length = spki[offset++];
    if (length & 0x80) {
      const numBytes = length & 0x7f;
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | spki[offset++];
      }
    }
    return length;
  }

  function readTag(): { tag: number; length: number } {
    const tag = spki[offset++];
    const length = readLength();
    return { tag, length };
  }

  function skipTlv(): void {
    offset++; // tag
    const length = readLength();
    offset += length;
  }

  function readInteger(): Uint8Array {
    const { tag, length } = readTag();
    if (tag !== 0x02) throw new Error('Expected INTEGER');
    const data = spki.slice(offset, offset + length);
    offset += length;
    return data;
  }

  // Outer SEQUENCE
  readTag(); // SEQUENCE (outer)

  // AlgorithmIdentifier SEQUENCE — skip entirely
  const algSeq = readTag(); // SEQUENCE (algorithm)
  offset += algSeq.length; // skip OID + optional NULL inside

  // BIT STRING containing RSAPublicKey
  const bitString = readTag();
  if (bitString.tag !== 0x03) throw new Error('Expected BIT STRING');
  offset++; // skip unused bits byte (0x00)

  // Inner SEQUENCE (RSAPublicKey)
  readTag(); // SEQUENCE

  const n = readInteger(); // modulus
  const e = readInteger(); // exponent

  return { n, e };
}

// --- Public API ---

export async function generateSshKey(type: KeyType, comment: string): Promise<GeneratedKey> {
  switch (type) {
    case 'ed25519':
      return generateEd25519(comment);
    case 'rsa-2048':
      return generateRsa(2048, comment);
    case 'rsa-4096':
      return generateRsa(4096, comment);
  }
}

export function isEd25519Supported(): boolean {
  try {
    return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
  } catch {
    return false;
  }
}
