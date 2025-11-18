/**
 * Certificate Authority Mock Service
 * Production-grade mock for X.509 certificate operations
 *
 * Features:
 * - Certificate generation (self-signed for testing)
 * - Certificate validation
 * - CRL (Certificate Revocation List) responses
 * - OCSP (Online Certificate Status Protocol) responder
 * - Certificate renewal flow
 * - Test certificates for all services
 */

import express from 'express';
import bodyParser from 'body-parser';
import winston from 'winston';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

interface Certificate {
  id: string;
  serialNumber: string;
  subject: {
    commonName: string;
    organization: string;
    country: string;
    oib?: string;
  };
  issuer: {
    commonName: string;
    organization: string;
    country: string;
  };
  validFrom: Date;
  validTo: Date;
  publicKey: string;
  privateKey?: string; // Only stored for generated certs
  fingerprint: string;
  status: 'active' | 'revoked' | 'expired';
  revokedAt?: Date;
  revokedReason?: string;
  usage: string[]; // digitalSignature, keyEncipherment, etc.
}

interface MockConfig {
  port: number;
  autoApprove: boolean;
  defaultValidityDays: number;
}

class CertMockService {
  private app: express.Application;
  private config: MockConfig;
  private logger: winston.Logger;
  private certificates: Map<string, Certificate> = new Map();
  private certificatesBySerial: Map<string, Certificate> = new Map();
  private revokedCerts: Set<string> = new Set();
  private metrics: {
    requests: number;
    issued: number;
    validated: number;
    revoked: number;
    startTime: Date;
  };

  constructor(config: Partial<MockConfig> = {}) {
    this.app = express();
    this.config = {
      port: config.port || 8453,
      autoApprove: config.autoApprove ?? true,
      defaultValidityDays: config.defaultValidityDays || 365
    };

    this.metrics = {
      requests: 0,
      issued: 0,
      validated: 0,
      revoked: 0,
      startTime: new Date()
    };

    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
          )
        }),
        new winston.transports.File({ filename: 'cert-mock.log' })
      ]
    });

    this.app.use(bodyParser.json());
    this.setupRoutes();
    this.generateRootCA();
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'operational',
        certificates: this.certificates.size,
        revoked: this.revokedCerts.size,
        uptime: Date.now() - this.metrics.startTime.getTime(),
        metrics: this.metrics
      });
    });

    // Request new certificate
    this.app.post('/api/v1/certificates/request', (req, res) => {
      this.metrics.requests++;

      const { commonName, organization, country, oib, usage, validityDays } = req.body;

      if (!commonName || !organization) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'commonName and organization are required'
        });
      }

      const cert = this.generateCertificate({
        commonName,
        organization,
        country: country || 'HR',
        oib,
        usage: usage || ['digitalSignature', 'keyEncipherment'],
        validityDays: validityDays || this.config.defaultValidityDays
      });

      this.certificates.set(cert.id, cert);
      this.certificatesBySerial.set(cert.serialNumber, cert);
      this.metrics.issued++;

      this.logger.info(`Certificate issued: ${cert.serialNumber} for ${commonName}`);

      res.status(201).json({
        certificateId: cert.id,
        serialNumber: cert.serialNumber,
        subject: cert.subject,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        fingerprint: cert.fingerprint,
        publicKey: cert.publicKey,
        privateKey: cert.privateKey, // Only in mock - never expose in production!
        downloadUrl: `/api/v1/certificates/${cert.id}/download`
      });
    });

    // Get certificate by ID
    this.app.get('/api/v1/certificates/:id', (req, res) => {
      this.metrics.requests++;

      const cert = this.certificates.get(req.params.id);
      if (!cert) {
        return res.status(404).json({
          error: 'CERTIFICATE_NOT_FOUND',
          message: 'Certificate not found'
        });
      }

      res.json({
        id: cert.id,
        serialNumber: cert.serialNumber,
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        fingerprint: cert.fingerprint,
        status: cert.status,
        usage: cert.usage
      });
    });

    // Validate certificate
    this.app.post('/api/v1/certificates/validate', (req, res) => {
      this.metrics.requests++;
      this.metrics.validated++;

      const { serialNumber, fingerprint } = req.body;

      let cert: Certificate | undefined;
      if (serialNumber) {
        cert = this.certificatesBySerial.get(serialNumber);
      } else if (fingerprint) {
        cert = Array.from(this.certificates.values())
          .find(c => c.fingerprint === fingerprint);
      }

      if (!cert) {
        return res.json({
          valid: false,
          reason: 'CERTIFICATE_NOT_FOUND'
        });
      }

      const now = new Date();
      if (cert.status === 'revoked') {
        return res.json({
          valid: false,
          reason: 'REVOKED',
          revokedAt: cert.revokedAt,
          revokedReason: cert.revokedReason
        });
      }

      if (now < cert.validFrom || now > cert.validTo) {
        return res.json({
          valid: false,
          reason: 'EXPIRED',
          validFrom: cert.validFrom,
          validTo: cert.validTo
        });
      }

      res.json({
        valid: true,
        certificate: {
          serialNumber: cert.serialNumber,
          subject: cert.subject,
          validFrom: cert.validFrom,
          validTo: cert.validTo,
          status: cert.status
        }
      });
    });

    // Revoke certificate
    this.app.post('/api/v1/certificates/:id/revoke', (req, res) => {
      this.metrics.requests++;

      const cert = this.certificates.get(req.params.id);
      if (!cert) {
        return res.status(404).json({
          error: 'CERTIFICATE_NOT_FOUND',
          message: 'Certificate not found'
        });
      }

      const { reason } = req.body;
      cert.status = 'revoked';
      cert.revokedAt = new Date();
      cert.revokedReason = reason || 'unspecified';

      this.revokedCerts.add(cert.serialNumber);
      this.metrics.revoked++;

      this.logger.info(`Certificate revoked: ${cert.serialNumber}`);

      res.json({
        success: true,
        message: 'Certificate revoked successfully',
        revokedAt: cert.revokedAt
      });
    });

    // CRL (Certificate Revocation List)
    this.app.get('/api/v1/crl', (req, res) => {
      this.metrics.requests++;

      const crl = this.generateCRL();

      res.setHeader('Content-Type', 'text/plain');
      res.send(crl);
    });

    // OCSP (Online Certificate Status Protocol)
    this.app.post('/api/v1/ocsp', (req, res) => {
      this.metrics.requests++;

      const { serialNumber } = req.body;
      if (!serialNumber) {
        return res.status(400).json({
          error: 'INVALID_REQUEST',
          message: 'serialNumber is required'
        });
      }

      const cert = this.certificatesBySerial.get(serialNumber);
      if (!cert) {
        return res.json({
          status: 'unknown',
          serialNumber
        });
      }

      if (cert.status === 'revoked') {
        return res.json({
          status: 'revoked',
          serialNumber,
          revokedAt: cert.revokedAt,
          revokedReason: cert.revokedReason
        });
      }

      const now = new Date();
      if (now > cert.validTo) {
        return res.json({
          status: 'expired',
          serialNumber,
          validTo: cert.validTo
        });
      }

      res.json({
        status: 'good',
        serialNumber,
        validFrom: cert.validFrom,
        validTo: cert.validTo
      });
    });

    // List all certificates
    this.app.get('/api/v1/certificates', (req, res) => {
      this.metrics.requests++;

      const status = req.query.status as string;
      let certs = Array.from(this.certificates.values());

      if (status) {
        certs = certs.filter(c => c.status === status);
      }

      res.json({
        count: certs.length,
        certificates: certs.map(c => ({
          id: c.id,
          serialNumber: c.serialNumber,
          subject: c.subject,
          validFrom: c.validFrom,
          validTo: c.validTo,
          status: c.status
        }))
      });
    });

    // Renew certificate
    this.app.post('/api/v1/certificates/:id/renew', (req, res) => {
      this.metrics.requests++;

      const oldCert = this.certificates.get(req.params.id);
      if (!oldCert) {
        return res.status(404).json({
          error: 'CERTIFICATE_NOT_FOUND',
          message: 'Certificate not found'
        });
      }

      const { validityDays } = req.body;

      const newCert = this.generateCertificate({
        commonName: oldCert.subject.commonName,
        organization: oldCert.subject.organization,
        country: oldCert.subject.country,
        oib: oldCert.subject.oib,
        usage: oldCert.usage,
        validityDays: validityDays || this.config.defaultValidityDays
      });

      this.certificates.set(newCert.id, newCert);
      this.certificatesBySerial.set(newCert.serialNumber, newCert);

      // Revoke old certificate
      oldCert.status = 'revoked';
      oldCert.revokedAt = new Date();
      oldCert.revokedReason = 'superseded';

      this.logger.info(`Certificate renewed: ${oldCert.serialNumber} -> ${newCert.serialNumber}`);

      res.json({
        certificateId: newCert.id,
        serialNumber: newCert.serialNumber,
        validFrom: newCert.validFrom,
        validTo: newCert.validTo,
        fingerprint: newCert.fingerprint,
        publicKey: newCert.publicKey,
        privateKey: newCert.privateKey
      });
    });
  }

  private generateRootCA(): void {
    const rootCA = this.generateCertificate({
      commonName: 'Mock Root CA',
      organization: 'eRacun Mock Services',
      country: 'HR',
      usage: ['keyCertSign', 'cRLSign'],
      validityDays: 3650 // 10 years
    });

    this.certificates.set('root-ca', rootCA);
    this.certificatesBySerial.set(rootCA.serialNumber, rootCA);

    this.logger.info('Root CA generated');
  }

  private generateCertificate(options: {
    commonName: string;
    organization: string;
    country: string;
    oib?: string;
    usage: string[];
    validityDays: number;
  }): Certificate {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    const serialNumber = crypto.randomBytes(16).toString('hex').toUpperCase();
    const fingerprint = crypto
      .createHash('sha256')
      .update(publicKey)
      .digest('hex')
      .toUpperCase()
      .match(/.{2}/g)!
      .join(':');

    const validFrom = new Date();
    const validTo = new Date(validFrom.getTime() + options.validityDays * 24 * 60 * 60 * 1000);

    return {
      id: uuidv4(),
      serialNumber,
      subject: {
        commonName: options.commonName,
        organization: options.organization,
        country: options.country,
        oib: options.oib
      },
      issuer: {
        commonName: 'Mock Root CA',
        organization: 'eRacun Mock Services',
        country: 'HR'
      },
      validFrom,
      validTo,
      publicKey,
      privateKey,
      fingerprint,
      status: 'active',
      usage: options.usage
    };
  }

  private generateCRL(): string {
    let crl = '-----BEGIN X509 CRL-----\n';
    crl += `Version: 2 (0x1)\n`;
    crl += `Signature Algorithm: sha256WithRSAEncryption\n`;
    crl += `Issuer: CN=Mock Root CA, O=eRacun Mock Services, C=HR\n`;
    crl += `Last Update: ${new Date().toISOString()}\n`;
    crl += `Next Update: ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()}\n`;
    crl += `\nRevoked Certificates:\n`;

    for (const serialNumber of this.revokedCerts) {
      const cert = this.certificatesBySerial.get(serialNumber);
      if (cert) {
        crl += `    Serial Number: ${serialNumber}\n`;
        crl += `    Revocation Date: ${cert.revokedAt?.toISOString()}\n`;
        crl += `    Reason: ${cert.revokedReason}\n`;
      }
    }

    crl += '-----END X509 CRL-----\n';
    return crl;
  }

  public start(): void {
    this.app.listen(this.config.port, () => {
      this.logger.info(`Certificate Mock Service started on port ${this.config.port}`);
      this.logger.info(`Auto-approve: ${this.config.autoApprove}`);
    });
  }
}

// Start the service
if (require.main === module) {
  const config: Partial<MockConfig> = {
    port: parseInt(process.env.CERT_PORT || '8453'),
    autoApprove: process.env.AUTO_APPROVE !== 'false',
    defaultValidityDays: parseInt(process.env.VALIDITY_DAYS || '365')
  };

  const service = new CertMockService(config);
  service.start();
}

export { CertMockService, MockConfig, Certificate };
