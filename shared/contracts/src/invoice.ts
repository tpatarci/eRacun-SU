/**
 * Core Invoice Domain Models
 * UBL 2.1 compliant with Croatian CIUS extensions
 */

export interface UBLInvoice {
  // Document identification
  id: string;                     // UUID v4
  invoiceNumber: string;          // Supplier's invoice number
  issueDate: string;              // ISO 8601 date
  dueDate?: string;               // ISO 8601 date

  // Croatian specific
  oib: {
    supplier: string;             // 11-digit OIB
    buyer: string;                // 11-digit OIB
    operator?: string;            // 11-digit OIB (if different from supplier)
  };

  // Parties
  supplier: Party;
  buyer: Party;

  // Line items
  lineItems: LineItem[];

  // Amounts
  amounts: {
    net: number;                  // Without VAT
    vat: VATBreakdown[];          // VAT by rate
    gross: number;                // Total with VAT
    currency: 'EUR' | 'HRK';      // Until Euro adoption
  };

  // Metadata
  metadata: {
    source: 'email' | 'api' | 'sftp' | 'manual';
    receivedAt: string;           // ISO 8601 timestamp
    processingId: string;         // Idempotency key
  };
}

export interface Party {
  name: string;
  address: Address;
  vatNumber: string;              // Format: HR + OIB
  email?: string;
  phone?: string;
  registrationNumber?: string;    // Company registration
}

export interface Address {
  street: string;
  city: string;
  postalCode: string;
  country: string;                // ISO 3166-1 alpha-2
}

export interface LineItem {
  id: string;                     // Line item ID
  description: string;
  quantity: number;
  unit: string;                   // UN/ECE Rec 20
  unitPrice: number;
  kpdCode: string;                // 6-digit KLASUS code (REQUIRED!)
  vatRate: 0 | 5 | 13 | 25;       // Croatian VAT rates
  vatAmount: number;
  netAmount: number;
  grossAmount: number;
}

export interface VATBreakdown {
  rate: 0 | 5 | 13 | 25;
  base: number;                   // Amount subject to this rate
  amount: number;                 // VAT amount
  category: 'STANDARD' | 'REDUCED' | 'SUPER_REDUCED' | 'EXEMPT';
}
