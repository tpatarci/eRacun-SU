/**
 * OIB (Osobni Identifikacijski Broj) Validator
 *
 * Croatian personal and business identification number validation
 * using ISO 7064, MOD 11-10 checksum algorithm.
 *
 * Specification:
 * - 11 digits exactly
 * - First digit cannot be 0
 * - MOD-11, ISO 7064 checksum on 11th digit
 */

/**
 * OIB validation result
 */
export interface OIBValidationResult {
  /** OIB number being validated */
  oib: string;
  /** Whether OIB is valid */
  valid: boolean;
  /** Array of validation errors (empty if valid) */
  errors: string[];
  /** Metadata about the OIB */
  metadata: {
    /** OIB type: business or personal */
    type: 'business' | 'personal' | 'unknown';
    /** Whether checksum is valid */
    checksumValid: boolean;
  };
}

/**
 * Validate OIB format (11 digits, first digit not 0)
 *
 * @param oib - OIB string to validate
 * @returns Array of format errors (empty if valid)
 */
export function validateOIBFormat(oib: string): string[] {
  const errors: string[] = [];

  // Check if OIB is provided and is a string
  if (!oib || typeof oib !== 'string') {
    errors.push('OIB is required');
    return errors;
  }

  if (oib.trim() === '') {
    errors.push('OIB is required');
    return errors;
  }

  // Check length
  if (oib.length !== 11) {
    errors.push(`OIB must be exactly 11 digits (got ${oib.length})`);
  }

  // Check if numeric
  if (!/^\d+$/.test(oib)) {
    errors.push('OIB must contain only digits');
  }

  // Check first digit not 0
  if (oib[0] === '0') {
    errors.push('OIB first digit cannot be 0');
  }

  return errors;
}

/**
 * Calculate OIB checksum using ISO 7064, MOD 11-10 algorithm
 *
 * Algorithm:
 * 1. Start with remainder = 10
 * 2. For each of first 10 digits (left to right):
 *    a. Add digit to remainder
 *    b. Remainder = (remainder mod 10) or 10 if zero
 *    c. Remainder = (remainder * 2) mod 11
 * 3. Final check: (11 - remainder) mod 10 should equal 11th digit
 *
 * @param oib - OIB string (11 digits)
 * @returns True if checksum is valid
 */
export function validateOIBChecksum(oib: string): boolean {
  // Ensure OIB is 11 digits before checksum calculation
  if (oib.length !== 11 || !/^\d+$/.test(oib)) {
    return false;
  }

  let remainder = 10;

  // Process first 10 digits
  for (let i = 0; i < 10; i++) {
    const digit = parseInt(oib[i], 10);

    // Step 2a: Add digit to remainder
    remainder += digit;

    // Step 2b: Remainder = (remainder mod 10) or 10 if zero
    remainder = remainder % 10;
    if (remainder === 0) {
      remainder = 10;
    }

    // Step 2c: Remainder = (remainder * 2) mod 11
    remainder = (remainder * 2) % 11;
  }

  // Step 3: Calculate expected check digit
  const calculatedCheckDigit = (11 - remainder) % 10;
  const actualCheckDigit = parseInt(oib[10], 10);

  return calculatedCheckDigit === actualCheckDigit;
}

/**
 * Determine OIB type (business vs personal)
 *
 * Note: There's no official way to distinguish business from personal OIBs
 * by format alone. This is a heuristic based on common patterns.
 *
 * In practice, you would need to query Tax Authority database to know for certain,
 * but that API does not exist for public use.
 *
 * @param _oib - OIB string (unused - kept for API compatibility)
 * @returns OIB type
 */
export function determineOIBType(_oib: string): 'business' | 'personal' | 'unknown' {
  // This is a placeholder heuristic
  // In reality, OIB format doesn't distinguish between business and personal
  // You would need to query Tax Authority database to know for certain

  // For now, return 'unknown' as we can't determine from format alone
  return 'unknown';
}

/**
 * Validate OIB (complete validation)
 *
 * @param oib - OIB string to validate
 * @returns Validation result object
 */
export function validateOIB(oib: string): OIBValidationResult {
  // Handle non-string inputs
  if (!oib || typeof oib !== 'string') {
    return {
      oib: String(oib),
      valid: false,
      errors: ['OIB is required'],
      metadata: {
        type: 'unknown',
        checksumValid: false,
      },
    };
  }

  // Trim whitespace
  const trimmedOIB = oib.trim();

  // Validate format
  const formatErrors = validateOIBFormat(trimmedOIB);

  // If format is invalid, return early
  if (formatErrors.length > 0) {
    return {
      oib: trimmedOIB,
      valid: false,
      errors: formatErrors,
      metadata: {
        type: 'unknown',
        checksumValid: false,
      },
    };
  }

  // Validate checksum
  const checksumValid = validateOIBChecksum(trimmedOIB);

  if (!checksumValid) {
    return {
      oib: trimmedOIB,
      valid: false,
      errors: ['Invalid OIB checksum (ISO 7064, MOD 11-10)'],
      metadata: {
        type: determineOIBType(trimmedOIB),
        checksumValid: false,
      },
    };
  }

  // Valid OIB
  return {
    oib: trimmedOIB,
    valid: true,
    errors: [],
    metadata: {
      type: determineOIBType(trimmedOIB),
      checksumValid: true,
    },
  };
}

/**
 * Validate batch of OIBs
 *
 * @param oibs - Array of OIB strings
 * @returns Array of validation results
 */
export function validateOIBBatch(oibs: string[]): OIBValidationResult[] {
  return oibs.map((oib) => validateOIB(oib));
}

/**
 * Generate valid OIB for testing
 * (Used for property-based testing)
 *
 * @param prefix - Optional 10-digit prefix (if not provided, random)
 * @returns Valid OIB string
 */
export function generateValidOIB(prefix?: string): string {
  let oibPrefix: string;

  if (prefix) {
    // Use provided prefix (must be 10 digits)
    if (prefix.length !== 10 || !/^\d+$/.test(prefix)) {
      throw new Error('Prefix must be exactly 10 digits');
    }
    if (prefix[0] === '0') {
      throw new Error('First digit cannot be 0');
    }
    oibPrefix = prefix;
  } else {
    // Generate random 10-digit prefix (first digit 1-9)
    const firstDigit = Math.floor(Math.random() * 9) + 1;
    const remainingDigits = Array.from({ length: 9 }, () =>
      Math.floor(Math.random() * 10)
    ).join('');
    oibPrefix = firstDigit.toString() + remainingDigits;
  }

  // Calculate checksum
  let remainder = 10;
  for (let i = 0; i < 10; i++) {
    const digit = parseInt(oibPrefix[i], 10);
    remainder += digit;
    remainder = remainder % 10;
    if (remainder === 0) {
      remainder = 10;
    }
    remainder = (remainder * 2) % 11;
  }

  const checkDigit = (11 - remainder) % 10;

  return oibPrefix + checkDigit.toString();
}
