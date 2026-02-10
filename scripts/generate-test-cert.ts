#!/usr/bin/env tsx
/**
 * Generate a test PKCS#12 certificate for unit tests
 * This script creates a self-signed certificate and exports it in PKCS#12 format
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as forge from 'node-forge';

const OUTPUT_DIR = path.join(__dirname, '..', 'tests', 'fixtures');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'test-cert.p12');
const PASSWORD = 'test123';

async function generateTestCertificate() {
  console.log('Generating test PKCS#12 certificate...');

  // Generate RSA key pair
  console.log('  - Generating 2048-bit RSA key pair...');
  const keys = forge.pki.rsa.generateKeyPair(2048);

  // Create certificate
  console.log('  - Creating self-signed certificate...');
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const subject = [{
    name: 'commonName',
    value: 'Test Certificate'
  }, {
    name: 'countryName',
    value: 'HR'
  }, {
    name: 'stateOrProvinceName',
    value: 'Zagreb'
  }, {
    name: 'localityName',
    value: 'Zagreb'
  }];

  cert.setSubject(subject);
  cert.setIssuer(subject);

  // Extensions for CA and basic constraints
  cert.setExtensions([{
    name: 'basicConstraints',
    cA: true
  }, {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  }, {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true
  }]);

  // Self-sign the certificate
  console.log('  - Self-signing certificate...');
  cert.sign(keys.privateKey);

  // Convert to PKCS#12
  console.log('  - Creating PKCS#12 container...');
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    keys.privateKey,
    cert,
    PASSWORD,
    { algorithm: '3des' }
  );

  // Convert to DER (binary) format
  const p12Der = forge.asn1.toDer(p12Asn1).getBytes();

  // Ensure output directory exists
  await fs.mkdir(OUTPUT_DIR, { recursive: true });

  // Write to file
  console.log(`  - Writing to ${OUTPUT_FILE}...`);
  await fs.writeFile(OUTPUT_FILE, Buffer.from(p12Der, 'binary'));

  console.log('\n✅ Test certificate generated successfully!');
  console.log(`   Location: ${OUTPUT_FILE}`);
  console.log(`   Password: ${PASSWORD}`);
}

generateTestCertificate().catch(error => {
  console.error('❌ Error generating test certificate:', error);
  process.exit(1);
});
