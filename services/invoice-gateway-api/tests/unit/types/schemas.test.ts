/**
 * Zod Schema Tests
 */

import {
  AddressSchema,
  PartySchema,
  LineItemSchema,
  InvoiceSubmissionSchema,
} from '../../../src/types/schemas';

describe('Zod Schemas', () => {
  describe('AddressSchema', () => {
    it('should validate correct address', () => {
      const validAddress = {
        street: 'Ilica 1',
        city: 'Zagreb',
        postalCode: '10000',
        country: 'HR',
      };

      const result = AddressSchema.safeParse(validAddress);
      expect(result.success).toBe(true);
    });

    it('should reject invalid postal code', () => {
      const invalidAddress = {
        street: 'Ilica 1',
        city: 'Zagreb',
        postalCode: '1000', // Only 4 digits
        country: 'HR',
      };

      const result = AddressSchema.safeParse(invalidAddress);
      expect(result.success).toBe(false);
    });

    it('should reject invalid country code', () => {
      const invalidAddress = {
        street: 'Ilica 1',
        city: 'Zagreb',
        postalCode: '10000',
        country: 'Croatia', // Should be 2-letter code
      };

      const result = AddressSchema.safeParse(invalidAddress);
      expect(result.success).toBe(false);
    });
  });

  describe('PartySchema', () => {
    it('should validate correct party', () => {
      const validParty = {
        name: 'Test d.o.o.',
        address: {
          street: 'Ilica 1',
          city: 'Zagreb',
          postalCode: '10000',
          country: 'HR',
        },
        vatNumber: 'HR12345678901',
      };

      const result = PartySchema.safeParse(validParty);
      expect(result.success).toBe(true);
    });

    it('should reject invalid VAT number format', () => {
      const invalidParty = {
        name: 'Test d.o.o.',
        address: {
          street: 'Ilica 1',
          city: 'Zagreb',
          postalCode: '10000',
          country: 'HR',
        },
        vatNumber: '12345678901', // Missing HR prefix
      };

      const result = PartySchema.safeParse(invalidParty);
      expect(result.success).toBe(false);
    });
  });

  describe('LineItemSchema', () => {
    it('should validate correct line item', () => {
      const validLineItem = {
        id: 'line-1',
        description: 'Professional services',
        quantity: 1,
        unit: 'EA',
        unitPrice: 1000,
        kpdCode: '123456',
        vatRate: 25,
      };

      const result = LineItemSchema.safeParse(validLineItem);
      expect(result.success).toBe(true);
    });

    it('should reject invalid KPD code', () => {
      const invalidLineItem = {
        id: 'line-1',
        description: 'Professional services',
        quantity: 1,
        unit: 'EA',
        unitPrice: 1000,
        kpdCode: '12345', // Only 5 digits
        vatRate: 25,
      };

      const result = LineItemSchema.safeParse(invalidLineItem);
      expect(result.success).toBe(false);
    });

    it('should reject invalid VAT rate', () => {
      const invalidLineItem = {
        id: 'line-1',
        description: 'Professional services',
        quantity: 1,
        unit: 'EA',
        unitPrice: 1000,
        kpdCode: '123456',
        vatRate: 20, // Not a Croatian VAT rate
      };

      const result = LineItemSchema.safeParse(invalidLineItem);
      expect(result.success).toBe(false);
    });

    it('should reject negative quantity', () => {
      const invalidLineItem = {
        id: 'line-1',
        description: 'Professional services',
        quantity: -1,
        unit: 'EA',
        unitPrice: 1000,
        kpdCode: '123456',
        vatRate: 25,
      };

      const result = LineItemSchema.safeParse(invalidLineItem);
      expect(result.success).toBe(false);
    });
  });

  describe('InvoiceSubmissionSchema', () => {
    it('should validate complete invoice', () => {
      const validInvoice = {
        invoiceNumber: 'INV-2025-001',
        issueDate: '2025-11-14',
        supplier: {
          name: 'Supplier d.o.o.',
          address: {
            street: 'Ilica 1',
            city: 'Zagreb',
            postalCode: '10000',
            country: 'HR',
          },
          vatNumber: 'HR12345678901',
        },
        buyer: {
          name: 'Buyer d.o.o.',
          address: {
            street: 'Trg 2',
            city: 'Split',
            postalCode: '21000',
            country: 'HR',
          },
          vatNumber: 'HR98765432109',
        },
        lineItems: [
          {
            id: 'line-1',
            description: 'Services',
            quantity: 1,
            unit: 'EA',
            unitPrice: 1000,
            kpdCode: '123456',
            vatRate: 25,
          },
        ],
        amounts: {
          net: 1000,
          vat: [
            {
              rate: 25,
              base: 1000,
              amount: 250,
              category: 'STANDARD',
            },
          ],
          gross: 1250,
          currency: 'EUR',
        },
      };

      const result = InvoiceSubmissionSchema.safeParse(validInvoice);
      expect(result.success).toBe(true);
    });

    it('should require at least one line item', () => {
      const invalidInvoice = {
        invoiceNumber: 'INV-2025-001',
        issueDate: '2025-11-14',
        supplier: {
          name: 'Supplier d.o.o.',
          address: {
            street: 'Ilica 1',
            city: 'Zagreb',
            postalCode: '10000',
            country: 'HR',
          },
          vatNumber: 'HR12345678901',
        },
        buyer: {
          name: 'Buyer d.o.o.',
          address: {
            street: 'Trg 2',
            city: 'Split',
            postalCode: '21000',
            country: 'HR',
          },
          vatNumber: 'HR98765432109',
        },
        lineItems: [], // Empty array
        amounts: {
          net: 0,
          vat: [
            {
              rate: 25,
              base: 0,
              amount: 0,
              category: 'STANDARD',
            },
          ],
          gross: 0,
          currency: 'EUR',
        },
      };

      const result = InvoiceSubmissionSchema.safeParse(invalidInvoice);
      expect(result.success).toBe(false);
    });
  });
});
