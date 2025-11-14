/**
 * RabbitMQ Command Messages
 * Commands represent requests for actions to be performed
 */

import { UBLInvoice } from './invoice';

// Base command interface
export interface BaseCommand {
  type: string;
  correlationId: string;
  timestamp: string;
}

// Team 2 → Team 1
export interface ProcessInvoiceCommand extends BaseCommand {
  type: 'PROCESS_INVOICE';
  payload: {
    source: 'email' | 'sftp' | 'api';
    sourceId: string;              // Email ID, file path, etc.
    content: string;                // Base64 encoded
    format: 'xml' | 'pdf' | 'json';
    metadata: Record<string, any>;
  };
}

// Team 1 → Team 3
export interface SubmitToFINACommand extends BaseCommand {
  type: 'SUBMIT_TO_FINA';
  payload: {
    invoice: UBLInvoice;
    signature?: string;             // If pre-signed
    priority: 'normal' | 'high';
    retryCount: number;
  };
}

// Team 1 → Team 2
export interface RequestOCRCommand extends BaseCommand {
  type: 'REQUEST_OCR';
  payload: {
    documentId: string;
    content: string;                // Base64 PDF
    options: {
      language?: string;
      enhanceImage?: boolean;
      extractTables?: boolean;
    };
  };
}

// Team 3 → Team 1
export interface SignDocumentCommand extends BaseCommand {
  type: 'SIGN_DOCUMENT';
  payload: {
    documentId: string;
    xml: string;
    certificateId: string;
    algorithm: 'RSA-SHA256' | 'RSA-SHA512';
  };
}
