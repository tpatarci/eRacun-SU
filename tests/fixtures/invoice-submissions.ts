/**
 * Invoice Submission Fixtures for E2E Testing
 *
 * Provides various invoice submission payloads for testing
 * different scenarios and edge cases.
 */

import { standardB2BInvoice, retailInvoice, proformaInvoice } from './ubi-invoices.js';

export interface InvoiceSubmissionPayload {
  oib: string;
  invoiceNumber: string;
  amount: string;
  paymentMethod: 'G' | 'T' | 'K' | 'C' | 'P' | 'N' | 'O';
  businessPremises?: string;
  cashRegister?: string;
  dateTime: string;
  originalXml: string;
  signedXml?: string;
}

/**
 * Standard invoice submission payload
 */
export const standardSubmission: InvoiceSubmissionPayload = {
  oib: '12345678903',
  invoiceNumber: 'INV-2024-001',
  amount: '1500.00',
  paymentMethod: 'T', // Transakcijski račun
  dateTime: '2024-02-11T10:30:00Z',
  originalXml: standardB2BInvoice.xml,
  signedXml: '', // To be filled by signing process
};

/**
 * Cash payment submission (requires business premises and cash register)
 */
export const cashPaymentSubmission: InvoiceSubmissionPayload = {
  oib: '12345678903',
  invoiceNumber: 'RAC-2024-001',
  amount: '312.00',
  paymentMethod: 'G', // Gotovina
  businessPremises: 'PP1',
  cashRegister: '1',
  dateTime: '2024-02-11T10:30:00Z',
  originalXml: retailInvoice.xml,
};

/**
 * Card payment submission
 */
export const cardPaymentSubmission: InvoiceSubmissionPayload = {
  oib: '12345678903',
  invoiceNumber: 'CARD-2024-001',
  amount: '500.00',
  paymentMethod: 'K', // Kartično plaćanje
  businessPremises: 'PP1',
  cashRegister: '1',
  dateTime: '2024-02-11T10:30:00Z',
  originalXml: retailInvoice.xml,
};

/**
 * Proforma invoice submission
 */
export const proformaSubmission: InvoiceSubmissionPayload = {
  oib: '12345678903',
  invoiceNumber: 'PROF-2024-001',
  amount: '1000.00',
  paymentMethod: 'T',
  dateTime: '2024-02-11T10:30:00Z',
  originalXml: proformaInvoice.xml,
};

/**
 * Invoice with maximum amount (stress testing)
 */
export const maxAmountSubmission: InvoiceSubmissionPayload = {
  oib: '12345678903',
  invoiceNumber: 'MAX-2024-001',
  amount: '999999999999.99',
  paymentMethod: 'T',
  dateTime: '2024-02-11T10:30:00Z',
  originalXml: standardB2BInvoice.xml,
};

/**
 * Invoice with minimum amount
 */
export const minAmountSubmission: InvoiceSubmissionPayload = {
  oib: '12345678903',
  invoiceNumber: 'MIN-2024-001',
  amount: '0.01',
  paymentMethod: 'T',
  dateTime: '2024-02-11T10:30:00Z',
  originalXml: standardB2BInvoice.xml,
};

/**
 * Invoice with special characters in number
 */
export const specialCharsSubmission: InvoiceSubmissionPayload = {
  oib: '12345678903',
  invoiceNumber: 'INV-2024/ŠĐŽĆČ-001',
  amount: '100.00',
  paymentMethod: 'T',
  dateTime: '2024-02-11T10:30:00Z',
  originalXml: standardB2BInvoice.xml,
};

/**
 * Bulk invoice submissions for concurrent testing
 */
export function generateBulkSubmissions(count: number, baseOib: string): InvoiceSubmissionPayload[] {
  const submissions: InvoiceSubmissionPayload[] = [];

  for (let i = 0; i < count; i++) {
    submissions.push({
      oib: baseOib,
      invoiceNumber: `BULK-${Date.now()}-${String(i).padStart(4, '0')}`,
      amount: (Math.random() * 10000 + 100).toFixed(2),
      paymentMethod: 'T',
      dateTime: new Date().toISOString(),
      originalXml: i % 2 === 0 ? standardB2BInvoice.xml : retailInvoice.xml,
    });
  }

  return submissions;
}

/**
 * Invalid submission fixtures for negative testing
 */

export const invalidSubmissions = {
  missingOib: {
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  invalidOibTooShort: {
    oib: '123',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  invalidOibNonNumeric: {
    oib: 'ABCDEFGHIJKL',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  missingInvoiceNumber: {
    oib: '12345678903',
    amount: '100.00',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  invalidAmount: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: 'not_a_number',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  negativeAmount: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '-100.00',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  invalidPaymentMethod: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'X' as any,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  cashPaymentMissingBusinessPremises: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'G' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  cashPaymentMissingCashRegister: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'G' as const,
    businessPremises: 'PP1',
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: standardB2BInvoice.xml,
  },

  invalidXml: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: 'not valid xml',
  },

  emptyXml: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'T' as const,
    dateTime: '2024-02-11T10:30:00Z',
    originalXml: '',
  },

  missingDateTime: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'T' as const,
    originalXml: standardB2BInvoice.xml,
  },

  invalidDateTime: {
    oib: '12345678903',
    invoiceNumber: 'INV-2024-001',
    amount: '100.00',
    paymentMethod: 'T' as const,
    dateTime: 'not-a-date',
    originalXml: standardB2BInvoice.xml,
  },
};

/**
 * Valid payment methods according to Croatian Fiskalizacija
 */
export const paymentMethods = {
  G: 'Gotovina', // Cash
  T: 'Transakcijski račun', // Bank transfer
  K: 'Kartično plaćanje', // Card payment
  C: 'Ček', // Check
  P: 'PayPal', // PayPal
  N: 'Ostalo', // Other
  O: 'Vrijednosni papiri', // Securities
} as const;

/**
 * Helper function to create submission with custom OIB
 */
export function createSubmissionWithOib(oib: string, base: InvoiceSubmissionPayload = standardSubmission): InvoiceSubmissionPayload {
  return {
    ...base,
    oib,
    invoiceNumber: `${base.invoiceNumber}-${oib.slice(-4)}`,
  };
}

/**
 * Helper function to create submission with custom amount
 */
export function createSubmissionWithAmount(amount: number, base: InvoiceSubmissionPayload = standardSubmission): InvoiceSubmissionPayload {
  return {
    ...base,
    amount: amount.toFixed(2),
    invoiceNumber: `${base.invoiceNumber}-${amount.toFixed(0)}`,
  };
}

/**
 * Export all fixtures
 */
export const invoiceSubmissionFixtures = {
  standard: standardSubmission,
  cashPayment: cashPaymentSubmission,
  cardPayment: cardPaymentSubmission,
  proforma: proformaSubmission,
  maxAmount: maxAmountSubmission,
  minAmount: minAmountSubmission,
  specialChars: specialCharsSubmission,
  invalid: invalidSubmissions,
  paymentMethods,
};
