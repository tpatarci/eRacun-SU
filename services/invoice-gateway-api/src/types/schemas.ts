/**
 * Zod Validation Schemas
 * Based on UBL 2.1 and Croatian CIUS requirements
 */

import { z } from 'zod';

// Address schema
export const AddressSchema = z.object({
  street: z.string().min(1, 'Street is required'),
  city: z.string().min(1, 'City is required'),
  postalCode: z.string().regex(/^\d{5}$/, 'Postal code must be 5 digits'),
  country: z.string().regex(/^[A-Z]{2}$/, 'Country must be ISO 3166-1 alpha-2 code'),
});

// Party schema
export const PartySchema = z.object({
  name: z.string().min(1, 'Name is required'),
  address: AddressSchema,
  vatNumber: z.string().regex(/^HR\d{11}$/, 'VAT number must be HR followed by 11 digits (OIB)'),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  registrationNumber: z.string().optional(),
});

// Line item schema
export const LineItemSchema = z.object({
  id: z.string().min(1, 'Line item ID is required'),
  description: z.string().min(1, 'Description is required'),
  quantity: z.number().positive('Quantity must be positive'),
  unit: z.string().min(1, 'Unit is required'),
  unitPrice: z.number().nonnegative('Unit price must be non-negative'),
  kpdCode: z.string().regex(/^\d{6}$/, 'KPD code must be exactly 6 digits'),
  vatRate: z.enum(['0', '5', '13', '25']).or(z.number().refine(val => [0, 5, 13, 25].includes(val), {
    message: 'VAT rate must be 0, 5, 13, or 25',
  })),
  vatAmount: z.number().nonnegative('VAT amount must be non-negative').optional(),
  netAmount: z.number().nonnegative('Net amount must be non-negative').optional(),
  grossAmount: z.number().nonnegative('Gross amount must be non-negative').optional(),
});

// VAT breakdown schema
export const VATBreakdownSchema = z.object({
  rate: z.enum(['0', '5', '13', '25']).or(z.number().refine(val => [0, 5, 13, 25].includes(val))),
  base: z.number().nonnegative('Base amount must be non-negative'),
  amount: z.number().nonnegative('VAT amount must be non-negative'),
  category: z.enum(['STANDARD', 'REDUCED', 'SUPER_REDUCED', 'EXEMPT']),
});

// Amounts schema
export const AmountsSchema = z.object({
  net: z.number().nonnegative('Net amount must be non-negative'),
  vat: z.array(VATBreakdownSchema).min(1, 'At least one VAT breakdown is required'),
  gross: z.number().nonnegative('Gross amount must be non-negative'),
  currency: z.enum(['EUR', 'HRK']),
});

// Invoice submission schema
export const InvoiceSubmissionSchema = z.object({
  invoiceNumber: z.string().min(1, 'Invoice number is required'),
  issueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Issue date must be in YYYY-MM-DD format'),
  dueDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Due date must be in YYYY-MM-DD format').optional(),
  supplier: PartySchema,
  buyer: PartySchema,
  lineItems: z.array(LineItemSchema).min(1, 'At least one line item is required'),
  amounts: AmountsSchema,
});

// Invoice ID param schema
export const InvoiceIdParamSchema = z.object({
  invoiceId: z.string().uuid('Invoice ID must be a valid UUID'),
});

// Export types
export type InvoiceSubmission = z.infer<typeof InvoiceSubmissionSchema>;
export type InvoiceIdParam = z.infer<typeof InvoiceIdParamSchema>;
