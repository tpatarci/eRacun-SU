/**
 * Invoice Parser Module
 *
 * Parses extracted PDF text to identify invoice-specific structured data.
 * - Invoice number and date extraction
 * - Vendor and customer information
 * - Line items (products/services)
 * - Amount calculations (subtotal, VAT, total)
 * - Croatian-specific patterns (OIB, IBAN, address formats)
 */

import { logger, invoicesExtractedTotal } from './observability';

/**
 * Parsed invoice data
 */
export interface ParsedInvoice {
  /** Invoice number */
  invoiceNumber?: string;
  /** Invoice date */
  invoiceDate?: Date;
  /** Due date */
  dueDate?: Date;
  /** Vendor information */
  vendor: {
    name?: string;
    address?: string;
    oib?: string; // Croatian tax ID
    iban?: string;
  };
  /** Customer information */
  customer: {
    name?: string;
    address?: string;
    oib?: string;
  };
  /** Line items */
  lineItems: InvoiceLineItem[];
  /** Amounts */
  amounts: {
    subtotal?: number;
    vatAmount?: number;
    total?: number;
    currency?: string;
  };
  /** Parsing confidence */
  confidence: 'high' | 'medium' | 'low';
  /** Fields that were successfully extracted */
  extractedFields: string[];
}

/**
 * Invoice line item
 */
export interface InvoiceLineItem {
  description: string;
  quantity?: number;
  unitPrice?: number;
  vatRate?: number;
  amount?: number;
}

/**
 * Invoice Parser
 */
export class InvoiceParser {
  /**
   * Parse invoice from extracted PDF text
   *
   * @param text - Extracted PDF text
   * @returns Parsed invoice data
   */
  parseInvoice(text: string): ParsedInvoice {
    logger.debug({ textLength: text.length }, 'Parsing invoice from text');

    const extractedFields: string[] = [];

    // Extract invoice number
    const invoiceNumber = this.extractInvoiceNumber(text);
    if (invoiceNumber) extractedFields.push('invoiceNumber');

    // Extract dates
    const invoiceDate = this.extractInvoiceDate(text);
    if (invoiceDate) extractedFields.push('invoiceDate');

    const dueDate = this.extractDueDate(text);
    if (dueDate) extractedFields.push('dueDate');

    // Extract vendor information
    const vendor = this.extractVendorInfo(text);
    if (vendor.name) extractedFields.push('vendor.name');
    if (vendor.oib) extractedFields.push('vendor.oib');

    // Extract customer information
    const customer = this.extractCustomerInfo(text);
    if (customer.name) extractedFields.push('customer.name');
    if (customer.oib) extractedFields.push('customer.oib');

    // Extract line items (simplified - full implementation would be more complex)
    const lineItems = this.extractLineItems(text);
    if (lineItems.length > 0) extractedFields.push('lineItems');

    // Extract amounts
    const amounts = this.extractAmounts(text);
    if (amounts.total) extractedFields.push('amounts.total');

    // Calculate confidence based on extracted fields
    const confidence = this.calculateConfidence(extractedFields);

    logger.info(
      {
        extractedFieldsCount: extractedFields.length,
        confidence,
        hasInvoiceNumber: !!invoiceNumber,
        hasTotal: !!amounts.total,
      },
      'Invoice parsing complete'
    );

    invoicesExtractedTotal.inc({ extraction_quality: confidence });

    return {
      invoiceNumber,
      invoiceDate,
      dueDate,
      vendor,
      customer,
      lineItems,
      amounts,
      confidence,
      extractedFields,
    };
  }

  /**
   * Extract invoice number
   *
   * Patterns:
   * - "Račun br." / "Invoice No." / "R-" followed by numbers
   * - Common formats: R-2024-123, INV-123456, 2024/123
   */
  private extractInvoiceNumber(text: string): string | undefined {
    const patterns = [
      /Račun\s*br\.?\s*[:.]?\s*([A-Z0-9\-\/]+)/i,
      /Invoice\s*No\.?\s*[:.]?\s*([A-Z0-9\-\/]+)/i,
      /Broj\s*računa\s*[:.]?\s*([A-Z0-9\-\/]+)/i,
      /(R[-]\d{4}[-\/]\d+)/,
      /(INV[-]\d+)/i,
    ];

    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match && match[1]) {
        logger.debug({ invoiceNumber: match[1] }, 'Extracted invoice number');
        return match[1].trim();
      }
    }

    return undefined;
  }

  /**
   * Extract invoice date
   *
   * Croatian formats: DD.MM.YYYY, DD/MM/YYYY, D. MMMM YYYY.
   * International: YYYY-MM-DD, MM/DD/YYYY
   */
  private extractInvoiceDate(text: string): Date | undefined {
    const patterns = [
      /Datum\s*računa\s*[:.]?\s*(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})/i,
      /Datum\s*[:.]?\s*(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})/i,
      /Invoice\s*Date\s*[:.]?\s*(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})/i,
      /(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})/,
    ];

    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) {
        const day = parseInt(match[1], 10);
        const month = parseInt(match[2], 10) - 1; // 0-indexed
        const year = parseInt(match[3], 10);

        // Validate date ranges
        if (day >= 1 && day <= 31 && month >= 0 && month <= 11 && year >= 2000 && year <= 2100) {
          const date = new Date(year, month, day);
          logger.debug({ invoiceDate: date.toISOString() }, 'Extracted invoice date');
          return date;
        }
      }
    }

    return undefined;
  }

  /**
   * Extract due date (rok plaćanja)
   */
  private extractDueDate(text: string): Date | undefined {
    const patterns = [
      /Rok\s*plaćanja\s*[:.]?\s*(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})/i,
      /Due\s*Date\s*[:.]?\s*(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})/i,
      /Dospijeva\s*[:.]?\s*(\d{1,2})[.\/](\d{1,2})[.\/](\d{4})/i,
    ];

    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) {
        const day = parseInt(match[1], 10);
        const month = parseInt(match[2], 10) - 1;
        const year = parseInt(match[3], 10);

        if (day >= 1 && day <= 31 && month >= 0 && month <= 11 && year >= 2000 && year <= 2100) {
          return new Date(year, month, day);
        }
      }
    }

    return undefined;
  }

  /**
   * Extract vendor information
   */
  private extractVendorInfo(text: string): ParsedInvoice['vendor'] {
    const vendor: ParsedInvoice['vendor'] = {};

    // Extract OIB (Croatian tax ID - 11 digits)
    const oibMatch = text.match(/OIB\s*[:.]?\s*(\d{11})/i);
    if (oibMatch) {
      vendor.oib = oibMatch[1];
      logger.debug({ vendorOib: vendor.oib }, 'Extracted vendor OIB');
    }

    // Extract IBAN (Croatian format: HR + 19 digits)
    const ibanMatch = text.match(/IBAN\s*[:.]?\s*(HR\d{19})/i);
    if (ibanMatch) {
      vendor.iban = ibanMatch[1];
    }

    // Extract vendor name (heuristic: first occurrence of company-like text)
    // This is simplified - real implementation would need more sophisticated NLP
    const nameMatch = text.match(/Izdavatelj\s*[:.]?\s*([A-ZČĆŠŽĐ][^\n]{10,60})/i);
    if (nameMatch) {
      vendor.name = nameMatch[1].trim();
    }

    return vendor;
  }

  /**
   * Extract customer information
   */
  private extractCustomerInfo(text: string): ParsedInvoice['customer'] {
    const customer: ParsedInvoice['customer'] = {};

    // Look for customer-specific OIB (after vendor OIB)
    const allOibs = [...text.matchAll(/OIB\s*[:.]?\s*(\d{11})/gi)];
    if (allOibs.length > 1) {
      customer.oib = allOibs[1][1]; // Second OIB is likely customer
    }

    // Extract customer name
    const nameMatch = text.match(/Kupac\s*[:.]?\s*([A-ZČĆŠŽĐ][^\n]{10,60})/i);
    if (nameMatch) {
      customer.name = nameMatch[1].trim();
    }

    return customer;
  }

  /**
   * Extract line items (simplified version)
   *
   * Full implementation would use table detection algorithms
   */
  private extractLineItems(text: string): InvoiceLineItem[] {
    const items: InvoiceLineItem[] = [];

    // Look for table-like structures with descriptions and amounts
    // This is a very basic implementation - production would need table parsing
    const lines = text.split('\n');

    for (const line of lines) {
      // Match lines with amounts (e.g., "Product Name 100,00 kn")
      const amountMatch = line.match(/([^\d]+)\s+([\d.,]+)\s*(?:kn|EUR|€)/i);
      if (amountMatch) {
        items.push({
          description: amountMatch[1].trim(),
          amount: this.parseAmount(amountMatch[2]),
        });
      }
    }

    return items.slice(0, 50); // Limit to 50 items to prevent memory issues
  }

  /**
   * Extract amounts (subtotal, VAT, total)
   */
  private extractAmounts(text: string): ParsedInvoice['amounts'] {
    const amounts: ParsedInvoice['amounts'] = {};

    // Extract total amount
    const totalPatterns = [
      /Ukupno\s*[:.]?\s*([\d.,]+)\s*(kn|EUR|€)/i,
      /Total\s*[:.]?\s*([\d.,]+)\s*(kn|EUR|€)/i,
      /Za\s*platiti\s*[:.]?\s*([\d.,]+)\s*(kn|EUR|€)/i,
    ];

    for (const pattern of totalPatterns) {
      const match = text.match(pattern);
      if (match) {
        amounts.total = this.parseAmount(match[1]);
        amounts.currency = match[2].toUpperCase() === 'KN' ? 'HRK' : 'EUR';
        break;
      }
    }

    // Extract VAT amount
    const vatMatch = text.match(/PDV\s*\(?\d+%?\)?\s*[:.]?\s*([\d.,]+)/i);
    if (vatMatch) {
      amounts.vatAmount = this.parseAmount(vatMatch[1]);
    }

    // Calculate subtotal if total and VAT are present
    if (amounts.total && amounts.vatAmount) {
      amounts.subtotal = amounts.total - amounts.vatAmount;
    }

    return amounts;
  }

  /**
   * Parse amount string to number
   *
   * Handles Croatian format: 1.234,56 → 1234.56
   * Handles international: 1,234.56 → 1234.56
   */
  private parseAmount(amountStr: string): number {
    // Remove spaces
    let cleaned = amountStr.replace(/\s/g, '');

    // If both comma and dot present, determine which is decimal separator
    if (cleaned.includes(',') && cleaned.includes('.')) {
      // Croatian format: 1.234,56 (dot is thousands, comma is decimal)
      if (cleaned.lastIndexOf(',') > cleaned.lastIndexOf('.')) {
        cleaned = cleaned.replace(/\./g, '').replace(',', '.');
      }
      // International format: 1,234.56 (comma is thousands, dot is decimal)
      else {
        cleaned = cleaned.replace(/,/g, '');
      }
    }
    // If only comma present, it's decimal separator (Croatian format)
    else if (cleaned.includes(',') && !cleaned.includes('.')) {
      cleaned = cleaned.replace(',', '.');
    }

    return parseFloat(cleaned);
  }

  /**
   * Calculate parsing confidence based on extracted fields
   */
  private calculateConfidence(extractedFields: string[]): 'high' | 'medium' | 'low' {
    const criticalFields = [
      'invoiceNumber',
      'invoiceDate',
      'vendor.oib',
      'amounts.total',
    ];

    const criticalCount = criticalFields.filter((field) =>
      extractedFields.includes(field)
    ).length;

    if (criticalCount >= 3 && extractedFields.length >= 6) {
      return 'high';
    } else if (criticalCount >= 2 || extractedFields.length >= 4) {
      return 'medium';
    } else {
      return 'low';
    }
  }
}
