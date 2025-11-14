/**
 * Format Detector
 * Detects invoice format from content
 */

import { injectable } from 'inversify';
import { XMLParser } from 'fast-xml-parser';
import pino from 'pino';

const logger = pino({ name: 'format-detector' });

export enum InvoiceFormat {
  UBL_21 = 'UBL_2.1',
  PDF = 'PDF',
  JSON = 'JSON',
  EDI = 'EDI',
  UNKNOWN = 'UNKNOWN',
}

@injectable()
export class FormatDetector {
  private xmlParser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
  });

  /**
   * Detect invoice format from content
   */
  detect(content: string | Buffer): InvoiceFormat {
    // Convert Buffer to string if needed
    const contentStr = Buffer.isBuffer(content) ? content.toString('utf-8') : content;

    // Check for PDF
    if (this.isPDF(contentStr)) {
      logger.debug('Detected PDF format');
      return InvoiceFormat.PDF;
    }

    // Check for JSON
    if (this.isJSON(contentStr)) {
      logger.debug('Detected JSON format');
      return InvoiceFormat.JSON;
    }

    // Check for XML (UBL)
    if (this.isUBL21(contentStr)) {
      logger.debug('Detected UBL 2.1 format');
      return InvoiceFormat.UBL_21;
    }

    // Check for EDI
    if (this.isEDI(contentStr)) {
      logger.debug('Detected EDI format');
      return InvoiceFormat.EDI;
    }

    logger.warn('Unknown format detected');
    return InvoiceFormat.UNKNOWN;
  }

  /**
   * Check if content is PDF
   */
  private isPDF(content: string): boolean {
    return content.startsWith('%PDF-');
  }

  /**
   * Check if content is JSON
   */
  private isJSON(content: string): boolean {
    try {
      const trimmed = content.trim();
      if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
        return false;
      }
      JSON.parse(content);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if content is UBL 2.1 XML
   */
  private isUBL21(content: string): boolean {
    try {
      const trimmed = content.trim();
      if (!trimmed.startsWith('<?xml') && !trimmed.startsWith('<Invoice')) {
        return false;
      }

      const parsed = this.xmlParser.parse(content);

      // Check for UBL namespace
      if (parsed.Invoice) {
        const invoice = parsed.Invoice;
        // Check for UBL 2.1 namespace
        if (invoice['@_xmlns']?.includes('ubl:schema:xsd:Invoice-2')) {
          return true;
        }
      }

      return false;
    } catch {
      return false;
    }
  }

  /**
   * Check if content is EDI format
   */
  private isEDI(content: string): boolean {
    // EDI typically starts with UNB (for EDIFACT) or ISA (for X12)
    const trimmed = content.trim();
    return trimmed.startsWith('UNB+') || trimmed.startsWith('ISA*');
  }
}
