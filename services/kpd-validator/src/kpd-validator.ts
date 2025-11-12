/**
 * KPD (Klasifikacija Proizvoda po Djelatnostima) Validator
 *
 * Croatian product classification system (KLASUS 2025) validator.
 *
 * KPD Code Format:
 * - 6 digits (e.g., 123456)
 * - Hierarchical structure:
 *   - Level 1: First 2 digits (division)
 *   - Level 2: First 3 digits (group)
 *   - Level 3: First 4 digits (class)
 *   - Level 4: First 5 digits (subclass)
 *   - Level 5: All 6 digits (product)
 */

/**
 * KPD code entry from database
 */
export interface KPDEntry {
  /** 6-digit KPD code */
  code: string;
  /** Product/category name (Croatian) */
  name: string;
  /** Product/category description */
  description?: string;
  /** Hierarchical level (1-5) */
  level: number;
  /** Parent code (for hierarchical navigation) */
  parentCode?: string;
  /** Whether this code is active/valid */
  active: boolean;
}

/**
 * KPD validation result
 */
export interface KPDValidationResult {
  /** KPD code being validated */
  code: string;
  /** Whether code is valid */
  valid: boolean;
  /** Array of validation errors (empty if valid) */
  errors: string[];
  /** KPD entry data (if found) */
  entry?: KPDEntry;
}

/**
 * KPD search result
 */
export interface KPDSearchResult {
  /** Total number of results */
  total: number;
  /** Array of matching KPD entries */
  entries: KPDEntry[];
}

/**
 * Database interface for KPD lookups
 * (Abstracted for dependency injection and testing)
 */
export interface KPDDatabase {
  /**
   * Find KPD entry by exact code
   */
  findByCode(code: string): Promise<KPDEntry | null>;

  /**
   * Search KPD entries by name (case-insensitive)
   */
  searchByName(query: string, limit?: number): Promise<KPDEntry[]>;

  /**
   * Get children of a KPD code (next level in hierarchy)
   */
  getChildren(code: string): Promise<KPDEntry[]>;
}

/**
 * Validate KPD code format (6 digits)
 *
 * @param code - KPD code string to validate
 * @returns Array of format errors (empty if valid)
 */
export function validateKPDFormat(code: string): string[] {
  const errors: string[] = [];

  // Check if code is provided and is a string
  if (!code || typeof code !== 'string') {
    errors.push('KPD code is required');
    return errors;
  }

  const trimmed = code.trim();

  if (trimmed === '') {
    errors.push('KPD code is required');
    return errors;
  }

  // Check length (must be exactly 6 digits)
  if (trimmed.length !== 6) {
    errors.push(`KPD code must be exactly 6 digits (got ${trimmed.length})`);
  }

  // Check if numeric
  if (!/^\d{6}$/.test(trimmed)) {
    errors.push('KPD code must contain only digits');
  }

  return errors;
}

/**
 * Determine KPD code level from code structure
 *
 * @param code - 6-digit KPD code
 * @returns Hierarchical level (1-5)
 */
export function determineKPDLevel(code: string): number {
  // This is a simplified heuristic
  // In reality, level is stored in database

  // If code ends with 0000, it's level 1 (division)
  if (code.endsWith('0000')) return 1;

  // If code ends with 000, it's level 2 (group)
  if (code.endsWith('000')) return 2;

  // If code ends with 00, it's level 3 (class)
  if (code.endsWith('00')) return 3;

  // If code ends with 0, it's level 4 (subclass)
  if (code.endsWith('0')) return 4;

  // Otherwise, it's level 5 (product)
  return 5;
}

/**
 * Get parent code from KPD code
 *
 * @param code - 6-digit KPD code
 * @returns Parent code (or null if level 1)
 */
export function getParentCode(code: string): string | null {
  const level = determineKPDLevel(code);

  if (level === 1) return null; // No parent for level 1

  // For other levels, parent is the code with trailing zeros
  // Level 2 → Level 1: 123000 → 120000
  // Level 3 → Level 2: 123400 → 123000
  // Level 4 → Level 3: 123450 → 123400
  // Level 5 → Level 4: 123456 → 123450

  const digits = code.split('').map(Number);

  // Find the rightmost non-zero digit and set it to 0
  for (let i = digits.length - 1; i >= 0; i--) {
    if (digits[i] !== 0) {
      digits[i] = 0;
      break;
    }
  }

  return digits.join('');
}

/**
 * Validate KPD code (complete validation with database lookup)
 *
 * @param code - KPD code string to validate
 * @param database - KPD database interface
 * @returns Validation result object
 */
export async function validateKPD(
  code: string,
  database: KPDDatabase
): Promise<KPDValidationResult> {
  // Handle non-string inputs
  if (!code || typeof code !== 'string') {
    return {
      code: String(code),
      valid: false,
      errors: ['KPD code is required'],
    };
  }

  // Trim and normalize
  const trimmedCode = code.trim();

  // Validate format
  const formatErrors = validateKPDFormat(trimmedCode);

  // If format is invalid, return early
  if (formatErrors.length > 0) {
    return {
      code: trimmedCode,
      valid: false,
      errors: formatErrors,
    };
  }

  // Lookup in database
  try {
    const entry = await database.findByCode(trimmedCode);

    if (!entry) {
      return {
        code: trimmedCode,
        valid: false,
        errors: ['KPD code not found in registry'],
      };
    }

    if (!entry.active) {
      return {
        code: trimmedCode,
        valid: false,
        errors: ['KPD code is inactive/deprecated'],
        entry,
      };
    }

    // Valid KPD code
    return {
      code: trimmedCode,
      valid: true,
      errors: [],
      entry,
    };
  } catch (error) {
    return {
      code: trimmedCode,
      valid: false,
      errors: [`Database error: ${error instanceof Error ? error.message : 'Unknown error'}`],
    };
  }
}

/**
 * Validate batch of KPD codes
 *
 * @param codes - Array of KPD code strings
 * @param database - KPD database interface
 * @returns Array of validation results
 */
export async function validateKPDBatch(
  codes: string[],
  database: KPDDatabase
): Promise<KPDValidationResult[]> {
  return Promise.all(codes.map((code) => validateKPD(code, database)));
}

/**
 * Search KPD entries by name
 *
 * @param query - Search query (product/category name)
 * @param database - KPD database interface
 * @param limit - Maximum number of results (default: 50)
 * @returns Search results
 */
export async function searchKPD(
  query: string,
  database: KPDDatabase,
  limit: number = 50
): Promise<KPDSearchResult> {
  if (!query || typeof query !== 'string' || query.trim() === '') {
    return {
      total: 0,
      entries: [],
    };
  }

  try {
    const entries = await database.searchByName(query.trim(), limit);
    return {
      total: entries.length,
      entries,
    };
  } catch (error) {
    // Return empty results on error
    return {
      total: 0,
      entries: [],
    };
  }
}

/**
 * Get KPD hierarchy (parent and children)
 *
 * @param code - KPD code
 * @param database - KPD database interface
 * @returns Hierarchy information
 */
export async function getKPDHierarchy(
  code: string,
  database: KPDDatabase
): Promise<{
  code: string;
  entry: KPDEntry | null;
  parent: KPDEntry | null;
  children: KPDEntry[];
}> {
  // Validate format first
  const formatErrors = validateKPDFormat(code);
  if (formatErrors.length > 0) {
    return {
      code,
      entry: null,
      parent: null,
      children: [],
    };
  }

  try {
    // Get current entry
    const entry = await database.findByCode(code);

    // Get parent
    const parentCode = getParentCode(code);
    const parent = parentCode ? await database.findByCode(parentCode) : null;

    // Get children
    const children = await database.getChildren(code);

    return {
      code,
      entry,
      parent,
      children,
    };
  } catch (error) {
    return {
      code,
      entry: null,
      parent: null,
      children: [],
    };
  }
}
