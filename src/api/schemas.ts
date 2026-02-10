import { z } from 'zod';

/**
 * OIB validation - 11 digits
 */
const oibSchema = z
  .string()
  .length(11)
  .regex(/^\d+$/, 'OIB must contain only digits');

/**
 * Payment method validation
 */
const paymentMethodSchema = z.enum(['G', 'K', 'C', 'T', 'O'], {
  errorMap: () => ({ message: 'Payment method must be one of: G, K, C, T, O' }),
});

/**
 * Invoice submission schema
 */
export const invoiceSubmissionSchema = z.object({
  oib: oibSchema,
  invoiceNumber: z.string().min(1, 'Invoice number is required'),
  amount: z
    .string()
    .regex(/^\d+(\.\d{1,2})?$/, 'Amount must be a positive number with up to 2 decimal places')
    .refine((val) => parseFloat(val) > 0, { message: 'Amount must be greater than 0' }),
  paymentMethod: paymentMethodSchema,
  businessPremises: z.string().min(1, 'Business premises identifier is required'),
  cashRegister: z.string().min(1, 'Cash register identifier is required'),
  dateTime: z.string().datetime({ message: 'Invalid ISO 8601 datetime format' }),
  vatBreakdown: z
    .array(
      z.object({
        base: z.string().regex(/^\d+(\.\d{1,2})?$/),
        rate: z.string().regex(/^\d+(\.\d{1,2})?$/),
        amount: z.string().regex(/^\d+(\.\d{1,2})?$/),
      })
    )
    .optional(),
  // Optional XML fields for direct submission
  originalXml: z.string().optional(),
  signedXml: z.string().optional(),
});

/**
 * Invoice ID parameter schema
 */
export const invoiceIdParamSchema = z
  .string()
  .uuid('Invalid invoice ID format');

/**
 * OIB query parameter schema
 */
export const oibQuerySchema = z.object({
  oib: oibSchema,
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/**
 * Email validation
 */
const emailSchema = z
  .string()
  .min(1, 'Email is required')
  .email('Invalid email format');

/**
 * Password validation
 */
const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long');

/**
 * Login request schema
 */
export const loginSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});
