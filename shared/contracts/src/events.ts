/**
 * Kafka Event Messages
 * Events represent facts that have already occurred
 * All events follow CloudEvents 1.0 specification
 */

import { ValidationResult } from './validation';

// Base event following CloudEvents 1.0
export interface BaseEvent {
  specversion: '1.0';
  type: string;                    // e.g., 'hr.eracun.invoice.received'
  source: string;                  // Service that emitted
  id: string;                      // Event ID (UUID)
  time: string;                    // ISO 8601
  datacontenttype: 'application/json';
  subject?: string;                // Invoice ID typically
  data: any;                       // Event-specific payload
}

// Team 2 Events
export interface InvoiceReceivedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.received';
  data: {
    invoiceId: string;
    source: 'email' | 'sftp' | 'api';
    receivedAt: string;
    size: number;                  // bytes
    format: string;
  };
}

// Team 1 Events
export interface InvoiceValidatedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.validated';
  data: {
    invoiceId: string;
    valid: boolean;
    validationResult: ValidationResult;
  };
}

export interface InvoiceTransformedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.transformed';
  data: {
    invoiceId: string;
    fromFormat: string;
    toFormat: 'UBL2.1';
    successful: boolean;
  };
}

// Team 3 Events
export interface InvoiceSubmittedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.submitted';
  data: {
    invoiceId: string;
    authority: 'FINA' | 'POREZNA';
    jir?: string;                  // If FINA submission
    confirmationNumber?: string;    // If Porezna
    timestamp: string;
  };
}

export interface CertificateExpiringEvent extends BaseEvent {
  type: 'hr.eracun.certificate.expiring';
  data: {
    certificateId: string;
    serialNumber: string;
    expiresAt: string;
    daysRemaining: number;
  };
}

export interface InvoiceArchivedEvent extends BaseEvent {
  type: 'hr.eracun.invoice.archived';
  data: {
    invoiceId: string;
    archiveId: string;
    location: string;
    retentionUntil: string;        // 11 years from now
  };
}
