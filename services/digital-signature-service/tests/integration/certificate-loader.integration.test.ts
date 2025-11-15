import { describe, it, expect, beforeEach, afterAll, jest } from '@jest/globals';
import * as fsPromises from 'fs/promises';
import forge from 'node-forge';
import { fs as memfsFs, vol } from 'memfs';
import { loadCertificateFromFile } from '../../src/certificate-parser.js';

type ReadFile = typeof fsPromises.readFile;

const readFileSpy = jest
  .spyOn(fsPromises, 'readFile')
  .mockImplementation((async (filePath: string | Buffer | URL, options?: { encoding?: BufferEncoding }) => {
    return memfsFs.promises.readFile(filePath.toString(), options?.encoding as BufferEncoding);
  }) as ReadFile);

beforeEach(() => {
  vol.reset();
});

afterAll(() => {
  readFileSpy.mockRestore();
});

describe('loadCertificateFromFile (memfs integration)', () => {
  it('reads PKCS#12 payload from virtual filesystem', async () => {
    const password = 'SecretMemfs!1';
    const pkcs12Buffer = createPkcs12Fixture(password);
    vol.fromJSON({ '/certs/test-signer.p12': pkcs12Buffer });

    const parsed = await loadCertificateFromFile('/certs/test-signer.p12', password);

    expect(parsed.info.subjectDN).toContain('Memfs Fixture');
    expect(parsed.privateKeyPEM).toContain('PRIVATE KEY');
    expect(parsed.certificatePEM).toContain('BEGIN CERTIFICATE');
  });
});

function createPkcs12Fixture(password: string): Buffer {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 1024 });
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = '01';
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date(certificate.validity.notBefore.getTime() + 24 * 60 * 60 * 1000);
  const subjectAttrs = [{ name: 'commonName', value: 'Memfs Fixture' }];
  certificate.setSubject(subjectAttrs);
  certificate.setIssuer(subjectAttrs);
  certificate.sign(keys.privateKey);

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, certificate, password, {
    algorithm: '3des',
  });
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(p12Der, 'binary');
}
