/**
 * UBL Transformer
 * Transforms various formats to UBL 2.1 with Croatian CIUS extensions
 */

import { injectable, inject } from 'inversify';
import { UBLInvoice } from '@eracun/contracts';
import { XMLGenerator } from '@eracun/test-fixtures';
import { FormatDetector, InvoiceFormat } from './format-detector';
import pino from 'pino';

const logger = pino({ name: 'ubl-transformer' });

export interface TransformationResult {
  success: boolean;
  xml?: string;
  format: InvoiceFormat;
  error?: string;
  processingTime: number;
}

@injectable()
export class UBLTransformer {
  constructor(
    @inject(FormatDetector) private formatDetector: FormatDetector
  ) {}

  /**
   * Transform invoice to UBL 2.1 format
   */
  async transform(content: string | Buffer): Promise<TransformationResult> {
    const startTime = Date.now();

    try {
      // Detect format
      const format = this.formatDetector.detect(content);
      logger.info({ format }, 'Detected invoice format');

      // Transform based on format
      let xml: string;
      switch (format) {
        case InvoiceFormat.UBL_21:
          xml = await this.transformUBL21(content.toString());
          break;
        case InvoiceFormat.JSON:
          xml = await this.transformJSON(content.toString());
          break;
        case InvoiceFormat.PDF:
          xml = await this.transformPDF(content);
          break;
        case InvoiceFormat.EDI:
          xml = await this.transformEDI(content.toString());
          break;
        default:
          throw new Error(`Unsupported format: ${format}`);
      }

      // Validate transformation
      await this.validateTransformation(xml);

      const processingTime = Date.now() - startTime;
      logger.info({ format, processingTime }, 'Transformation completed');

      return {
        success: true,
        xml,
        format,
        processingTime,
      };
    } catch (error) {
      const processingTime = Date.now() - startTime;
      logger.error({ error }, 'Transformation failed');

      return {
        success: false,
        format: InvoiceFormat.UNKNOWN,
        error: (error as Error).message,
        processingTime,
      };
    }
  }

  /**
   * Transform UBL 2.1 XML (validate and add Croatian CIUS if needed)
   */
  private async transformUBL21(xml: string): Promise<string> {
    logger.debug('Processing UBL 2.1 XML');

    // Check if Croatian CIUS extensions are present
    if (!this.hasCroatianCIUS(xml)) {
      logger.debug('Adding Croatian CIUS extensions');
      return this.addCroatianCIUS(xml);
    }

    return xml;
  }

  /**
   * Transform JSON to UBL 2.1 XML
   */
  private async transformJSON(json: string): Promise<string> {
    logger.debug('Transforming JSON to UBL 2.1');

    try {
      const invoice: UBLInvoice = JSON.parse(json);

      // Use XMLGenerator to create UBL 2.1 XML
      const xml = XMLGenerator.generateUBL21XML(invoice);

      // Add Croatian CIUS extensions
      return this.addCroatianCIUS(xml);
    } catch (error) {
      throw new Error(`JSON transformation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Transform PDF to UBL 2.1 XML (requires OCR)
   */
  private async transformPDF(content: string | Buffer): Promise<string> {
    logger.debug('Transforming PDF to UBL 2.1');

    // TODO: Integrate with OCR service
    // For now, throw error as this requires Team 2's OCR service
    throw new Error('PDF transformation requires OCR service (Team 2 dependency)');
  }

  /**
   * Transform EDI to UBL 2.1 XML
   */
  private async transformEDI(edi: string): Promise<string> {
    logger.debug('Transforming EDI to UBL 2.1');

    // TODO: Implement EDI parser and transformer
    // This is complex and may require specialized library
    throw new Error('EDI transformation not yet implemented');
  }

  /**
   * Check if XML has Croatian CIUS extensions
   */
  private hasCroatianCIUS(xml: string): boolean {
    // Check for Croatian CIUS customization ID
    return xml.includes('urn:fina.hr:cius-hr');
  }

  /**
   * Add Croatian CIUS extensions to UBL 2.1 XML
   */
  private addCroatianCIUS(xml: string): string {
    // Add Croatian CIUS customization ID if not present
    if (!xml.includes('CustomizationID')) {
      const customizationId = '<cbc:CustomizationID>urn:cen.eu:en16931:2017#compliant#urn:fina.hr:cius-hr:2.0</cbc:CustomizationID>';

      // Insert after opening Invoice tag
      xml = xml.replace(
        /<Invoice[^>]*>/,
        (match) => `${match}\n  ${customizationId}`
      );
    }

    // Add Croatian profile ID if not present
    if (!xml.includes('ProfileID')) {
      const profileId = '<cbc:ProfileID>urn:fina.hr:profile:01</cbc:ProfileID>';

      // Insert after CustomizationID
      xml = xml.replace(
        /<cbc:CustomizationID>.*?<\/cbc:CustomizationID>/,
        (match) => `${match}\n  ${profileId}`
      );
    }

    return xml;
  }

  /**
   * Validate transformed XML
   */
  private async validateTransformation(xml: string): Promise<void> {
    // Basic validation: check if it's valid XML
    if (!xml || xml.trim().length === 0) {
      throw new Error('Transformation produced empty XML');
    }

    // Check for required UBL elements
    const requiredElements = ['Invoice', 'cbc:ID', 'cbc:IssueDate'];
    for (const element of requiredElements) {
      if (!xml.includes(element)) {
        throw new Error(`Missing required element: ${element}`);
      }
    }

    // Check for Croatian CIUS
    if (!this.hasCroatianCIUS(xml)) {
      throw new Error('Missing Croatian CIUS extensions');
    }
  }
}
