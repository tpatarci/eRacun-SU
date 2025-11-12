/**
 * IBAN (International Bank Account Number) Validator
 *
 * Croatian IBAN validation using ISO 13616 MOD-97 checksum algorithm.
 *
 * Croatian IBAN Format:
 * - Country code: HR (Croatia)
 * - 2 check digits (MOD-97)
 * - 17 digits (bank code + account number)
 * - Total length: 21 characters
 * - Example: HR1210010051863000160
 */

/**
 * IBAN validation result
 */
export interface IBANValidationResult {
  /** IBAN being validated */
  iban: string;
  /** Whether IBAN is valid */
  valid: boolean;
  /** Array of validation errors (empty if valid) */
  errors: string[];
  /** Metadata about the IBAN */
  metadata: {
    /** Country code (e.g., "HR") */
    countryCode: string;
    /** Check digits */
    checkDigits: string;
    /** Bank code (first 7 digits) */
    bankCode: string;
    /** Account number (remaining 10 digits) */
    accountNumber: string;
    /** Whether checksum is valid */
    checksumValid: boolean;
  };
}

/**
 * Croatian bank codes (from Croatian National Bank registry)
 * This is a subset for validation purposes
 */
const CROATIAN_BANK_CODES: { [key: string]: string } = {
  '1001005': 'Hrvatska poštanska banka',
  '2340009': 'Privredna banka Zagreb',
  '2360000': 'Raiffeisenbank Austria',
  '2390001': 'Societe Generale-Splitska banka',
  '2400008': 'Erste&Steiermärkische Bank',
  '2402006': 'Erste&Steiermärkische Bank - Card Center',
  '2410001': 'Zagrebačka banka',
  '2420000': 'Zagrebačka banka - Card Center',
  '2430003': 'Zagrebačka banka - Leasing',
  '2440006': 'Zagrebačka banka - Stambena štedionica',
  '2460002': 'Slatinska banka',
  '2480004': 'Istarska kreditna banka Umag',
  '2500009': 'Croatia banka',
  '2484001': 'Banka Kovanica',
};

/**
 * Validate IBAN format (length, country code, structure)
 *
 * @param iban - IBAN string to validate
 * @returns Array of format errors (empty if valid)
 */
export function validateIBANFormat(iban: string): string[] {
  const errors: string[] = [];

  // Check if IBAN is provided and is a string
  if (!iban || typeof iban !== 'string') {
    errors.push('IBAN is required');
    return errors;
  }

  const trimmed = iban.trim();

  if (trimmed === '') {
    errors.push('IBAN is required');
    return errors;
  }

  // Remove spaces for validation
  const normalized = trimmed.replace(/\s/g, '').toUpperCase();

  // Check length (Croatian IBAN is 21 characters)
  if (normalized.length !== 21) {
    errors.push(`Croatian IBAN must be exactly 21 characters (got ${normalized.length})`);
  }

  // Check if alphanumeric
  if (!/^[A-Z0-9]+$/.test(normalized)) {
    errors.push('IBAN must contain only letters and numbers');
  }

  // Check country code
  if (!normalized.startsWith('HR')) {
    errors.push('IBAN must start with HR (Croatian country code)');
  }

  // Check check digits (positions 2-3)
  if (normalized.length >= 4) {
    const checkDigits = normalized.substring(2, 4);
    if (!/^\d{2}$/.test(checkDigits)) {
      errors.push('IBAN check digits (positions 3-4) must be numeric');
    }
  }

  // Check BBAN (Basic Bank Account Number) - must be 17 digits
  if (normalized.length === 21) {
    const bban = normalized.substring(4);
    if (!/^\d{17}$/.test(bban)) {
      errors.push('IBAN bank code and account number (positions 5-21) must be 17 digits');
    }
  }

  return errors;
}

/**
 * Calculate IBAN checksum using MOD-97 algorithm (ISO 13616)
 *
 * Algorithm:
 * 1. Move first 4 characters to end (HR + 2 check digits → end)
 * 2. Replace letters with numbers (A=10, B=11, ..., Z=35)
 * 3. Calculate remainder when dividing by 97
 * 4. Valid IBAN has remainder = 1
 *
 * @param iban - IBAN string (21 characters)
 * @returns True if checksum is valid
 */
export function validateIBANChecksum(iban: string): boolean {
  // Normalize: remove spaces, uppercase
  const normalized = iban.replace(/\s/g, '').toUpperCase();

  // Basic format check
  if (normalized.length !== 21 || !/^[A-Z0-9]+$/.test(normalized)) {
    return false;
  }

  // Step 1: Move first 4 characters to end
  const rearranged = normalized.substring(4) + normalized.substring(0, 4);

  // Step 2: Replace letters with numbers (A=10, B=11, ..., Z=35)
  let numericString = '';
  for (const char of rearranged) {
    if (char >= 'A' && char <= 'Z') {
      // A=10, B=11, ..., Z=35
      numericString += (char.charCodeAt(0) - 55).toString();
    } else {
      numericString += char;
    }
  }

  // Step 3: Calculate MOD 97 (handle large numbers by chunking)
  const mod = calculateMod97(numericString);

  // Step 4: Valid IBAN has remainder = 1
  return mod === 1;
}

/**
 * Calculate MOD 97 for large number strings
 * (IBAN numeric representation can be > 30 digits)
 *
 * @param numericString - String of digits
 * @returns Remainder when divided by 97
 */
function calculateMod97(numericString: string): number {
  let remainder = 0;

  for (const digit of numericString) {
    remainder = (remainder * 10 + parseInt(digit, 10)) % 97;
  }

  return remainder;
}

/**
 * Extract IBAN metadata (country, check digits, bank code, account)
 *
 * @param iban - IBAN string (normalized)
 * @returns IBAN metadata
 */
export function extractIBANMetadata(iban: string): {
  countryCode: string;
  checkDigits: string;
  bankCode: string;
  accountNumber: string;
} {
  const normalized = iban.replace(/\s/g, '').toUpperCase();

  if (normalized.length !== 21) {
    return {
      countryCode: '',
      checkDigits: '',
      bankCode: '',
      accountNumber: '',
    };
  }

  return {
    countryCode: normalized.substring(0, 2),
    checkDigits: normalized.substring(2, 4),
    bankCode: normalized.substring(4, 11), // 7 digits
    accountNumber: normalized.substring(11, 21), // 10 digits
  };
}

/**
 * Validate Croatian bank code against registry
 *
 * @param bankCode - 7-digit bank code
 * @returns Bank name if valid, null otherwise
 */
export function validateBankCode(bankCode: string): string | null {
  return CROATIAN_BANK_CODES[bankCode] || null;
}

/**
 * Validate IBAN (complete validation)
 *
 * @param iban - IBAN string to validate
 * @returns Validation result object
 */
export function validateIBAN(iban: string): IBANValidationResult {
  // Handle non-string inputs
  if (!iban || typeof iban !== 'string') {
    return {
      iban: String(iban),
      valid: false,
      errors: ['IBAN is required'],
      metadata: {
        countryCode: '',
        checkDigits: '',
        bankCode: '',
        accountNumber: '',
        checksumValid: false,
      },
    };
  }

  // Normalize
  const normalized = iban.replace(/\s/g, '').toUpperCase();

  // Validate format
  const formatErrors = validateIBANFormat(normalized);

  // If format is invalid, return early
  if (formatErrors.length > 0) {
    return {
      iban: normalized,
      valid: false,
      errors: formatErrors,
      metadata: {
        countryCode: '',
        checkDigits: '',
        bankCode: '',
        accountNumber: '',
        checksumValid: false,
      },
    };
  }

  // Validate checksum
  const checksumValid = validateIBANChecksum(normalized);

  if (!checksumValid) {
    const metadata = extractIBANMetadata(normalized);
    return {
      iban: normalized,
      valid: false,
      errors: ['Invalid IBAN checksum (ISO 13616, MOD-97)'],
      metadata: {
        ...metadata,
        checksumValid: false,
      },
    };
  }

  // Valid IBAN
  const metadata = extractIBANMetadata(normalized);
  return {
    iban: normalized,
    valid: true,
    errors: [],
    metadata: {
      ...metadata,
      checksumValid: true,
    },
  };
}

/**
 * Validate batch of IBANs
 *
 * @param ibans - Array of IBAN strings
 * @returns Array of validation results
 */
export function validateIBANBatch(ibans: string[]): IBANValidationResult[] {
  return ibans.map((iban) => validateIBAN(iban));
}

/**
 * Generate valid Croatian IBAN for testing
 *
 * @param bankCode - 7-digit bank code (if not provided, uses default)
 * @param accountNumber - 10-digit account number (if not provided, random)
 * @returns Valid Croatian IBAN
 */
export function generateValidIBAN(bankCode?: string, accountNumber?: string): string {
  // Use default bank code if not provided
  const bank = bankCode || '1001005'; // Hrvatska poštanska banka

  if (bank.length !== 7 || !/^\d{7}$/.test(bank)) {
    throw new Error('Bank code must be exactly 7 digits');
  }

  // Generate random account number if not provided
  let account = accountNumber;
  if (!account) {
    account = Array.from({ length: 10 }, () => Math.floor(Math.random() * 10)).join('');
  }

  if (account.length !== 10 || !/^\d{10}$/.test(account)) {
    throw new Error('Account number must be exactly 10 digits');
  }

  // Calculate check digits
  const bban = bank + account;
  const checkDigits = calculateIBANCheckDigits('HR', bban);

  return `HR${checkDigits}${bban}`;
}

/**
 * Calculate IBAN check digits for given country and BBAN
 *
 * @param countryCode - 2-letter country code
 * @param bban - Basic Bank Account Number
 * @returns 2-digit check digits
 */
function calculateIBANCheckDigits(countryCode: string, bban: string): string {
  // Create IBAN with check digits 00
  const ibanWithZeros = countryCode + '00' + bban;

  // Rearrange: move first 4 to end
  const rearranged = ibanWithZeros.substring(4) + ibanWithZeros.substring(0, 4);

  // Convert to numeric string
  let numericString = '';
  for (const char of rearranged) {
    if (char >= 'A' && char <= 'Z') {
      numericString += (char.charCodeAt(0) - 55).toString();
    } else {
      numericString += char;
    }
  }

  // Calculate MOD 97
  const mod = calculateMod97(numericString);

  // Check digits = 98 - mod
  const checkDigits = 98 - mod;

  // Pad with leading zero if needed
  return checkDigits.toString().padStart(2, '0');
}
