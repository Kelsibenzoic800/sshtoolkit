import { describe, it, expect } from 'vitest';
import { generateSshKey, isEd25519Supported } from '../crypto';

// Web Crypto is available in Node 22+ (which this project requires)

describe('isEd25519Supported', () => {
  it('returns true in Node 22+ environment', () => {
    expect(isEd25519Supported()).toBe(true);
  });
});

describe('generateSshKey - Ed25519', () => {
  it('generates valid ed25519 key pair', async () => {
    const key = await generateSshKey('ed25519', 'test@host');
    expect(key.keyType).toBe('ed25519');
    expect(key.privateKey).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(key.privateKey).toContain('-----END OPENSSH PRIVATE KEY-----');
    expect(key.publicKey).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]+ test@host$/);
    expect(key.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
    expect(key.command).toBe('ssh-keygen -t ed25519 -C "test@host"');
  });

  it('generates key without comment', async () => {
    const key = await generateSshKey('ed25519', '');
    expect(key.publicKey).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]+$/);
    expect(key.command).toBe('ssh-keygen -t ed25519');
  });

  it('generates unique keys each time', async () => {
    const key1 = await generateSshKey('ed25519', '');
    const key2 = await generateSshKey('ed25519', '');
    expect(key1.publicKey).not.toBe(key2.publicKey);
    expect(key1.privateKey).not.toBe(key2.privateKey);
    expect(key1.fingerprint).not.toBe(key2.fingerprint);
  });

  it('public key blob is 51 bytes (base64 of 51 = 68 chars)', async () => {
    const key = await generateSshKey('ed25519', '');
    // "ssh-ed25519 <68 chars base64>"
    const base64Part = key.publicKey.split(' ')[1];
    expect(base64Part).toHaveLength(68);
  });
});

describe('generateSshKey - RSA', () => {
  it('generates valid RSA-2048 key pair', async () => {
    const key = await generateSshKey('rsa-2048', 'test@host');
    expect(key.keyType).toBe('rsa-2048');
    expect(key.privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    expect(key.privateKey).toContain('-----END PRIVATE KEY-----');
    expect(key.publicKey).toMatch(/^ssh-rsa [A-Za-z0-9+/=]+ test@host$/);
    expect(key.fingerprint).toMatch(/^SHA256:/);
    expect(key.command).toBe('ssh-keygen -t rsa -b 2048 -C "test@host"');
  });

  it('generates valid RSA-4096 key pair', async () => {
    const key = await generateSshKey('rsa-4096', '');
    expect(key.keyType).toBe('rsa-4096');
    expect(key.publicKey).toMatch(/^ssh-rsa /);
    expect(key.command).toContain('-b 4096');
  });
}, 15000);
