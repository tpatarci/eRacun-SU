import { describe, it, expect, beforeEach } from '@jest/globals';
import fc from 'fast-check';
import {
  validateKPD,
  validateKPDFormat,
  validateKPDBatch,
  searchKPD,
  getKPDHierarchy,
  determineKPDLevel,
  getParentCode,
  type KPDDatabase,
  type KPDEntry,
} from '../../src/kpd-validator';

/**
 * Mock KPD database for testing
 */
class MockKPDDatabase implements KPDDatabase {
  private entries: Map<string, KPDEntry>;

  constructor() {
    this.entries = new Map();
    this.seedTestData();
  }

  private seedTestData(): void {
    // Level 1: Division
    this.entries.set('010000', {
      code: '010000',
      name: 'Proizvodi poljoprivrede',
      description: 'Agricultural products',
      level: 1,
      active: true,
    });

    // Level 2: Group
    this.entries.set('011000', {
      code: '011000',
      name: 'Žitarice',
      description: 'Cereals',
      level: 2,
      parentCode: '010000',
      active: true,
    });

    // Level 3: Class
    this.entries.set('011100', {
      code: '011100',
      name: 'Pšenica',
      description: 'Wheat',
      level: 3,
      parentCode: '011000',
      active: true,
    });

    // Level 4: Subclass
    this.entries.set('011110', {
      code: '011110',
      name: 'Pšenica obična',
      description: 'Common wheat',
      level: 4,
      parentCode: '011100',
      active: true,
    });

    // Level 5: Product
    this.entries.set('011111', {
      code: '011111',
      name: 'Pšenica obična - ozima',
      description: 'Common wheat - winter',
      level: 5,
      parentCode: '011110',
      active: true,
    });

    // Inactive code
    this.entries.set('999999', {
      code: '999999',
      name: 'Deprecated product',
      description: 'This code is no longer active',
      level: 5,
      active: false,
    });

    // Additional test data
    this.entries.set('020000', {
      code: '020000',
      name: 'Proizvodi šumarstva',
      description: 'Forestry products',
      level: 1,
      active: true,
    });
  }

  async findByCode(code: string): Promise<KPDEntry | null> {
    return this.entries.get(code) || null;
  }

  async searchByName(query: string, limit: number = 50): Promise<KPDEntry[]> {
    const lowerQuery = query.toLowerCase();
    const results: KPDEntry[] = [];

    for (const entry of this.entries.values()) {
      if (entry.name.toLowerCase().includes(lowerQuery)) {
        results.push(entry);
        if (results.length >= limit) break;
      }
    }

    return results;
  }

  async getChildren(code: string): Promise<KPDEntry[]> {
    const children: KPDEntry[] = [];

    for (const entry of this.entries.values()) {
      if (entry.parentCode === code) {
        children.push(entry);
      }
    }

    return children;
  }
}

/**
 * Database that throws errors (for error handling tests)
 */
class ErrorKPDDatabase implements KPDDatabase {
  async findByCode(_code: string): Promise<KPDEntry | null> {
    throw new Error('Database connection failed');
  }

  async searchByName(_query: string, _limit?: number): Promise<KPDEntry[]> {
    throw new Error('Database connection failed');
  }

  async getChildren(_code: string): Promise<KPDEntry[]> {
    throw new Error('Database connection failed');
  }
}

/**
 * Database that throws non-Error objects
 */
class NonErrorKPDDatabase implements KPDDatabase {
  async findByCode(_code: string): Promise<KPDEntry | null> {
    throw 'String error'; // eslint-disable-line @typescript-eslint/no-throw-literal
  }

  async searchByName(_query: string, _limit?: number): Promise<KPDEntry[]> {
    throw 'String error'; // eslint-disable-line @typescript-eslint/no-throw-literal
  }

  async getChildren(_code: string): Promise<KPDEntry[]> {
    throw 'String error'; // eslint-disable-line @typescript-eslint/no-throw-literal
  }
}

describe('KPD Validator', () => {
  let database: MockKPDDatabase;

  beforeEach(() => {
    database = new MockKPDDatabase();
  });

  describe('validateKPDFormat', () => {
    it('should accept valid 6-digit KPD code', () => {
      const errors = validateKPDFormat('123456');
      expect(errors).toEqual([]);
    });

    it('should reject empty KPD code', () => {
      const errors = validateKPDFormat('');
      expect(errors).toContain('KPD code is required');
    });

    it('should reject whitespace-only KPD code', () => {
      const errors = validateKPDFormat('   ');
      expect(errors).toContain('KPD code is required');
    });

    it('should reject KPD code shorter than 6 digits', () => {
      const errors = validateKPDFormat('12345');
      expect(errors).toContain('KPD code must be exactly 6 digits (got 5)');
    });

    it('should reject KPD code longer than 6 digits', () => {
      const errors = validateKPDFormat('1234567');
      expect(errors).toContain('KPD code must be exactly 6 digits (got 7)');
    });

    it('should reject KPD code with letters', () => {
      const errors = validateKPDFormat('12345A');
      expect(errors).toContain('KPD code must contain only digits');
    });

    it('should reject KPD code with special characters', () => {
      const errors = validateKPDFormat('123-456');
      expect(errors).toContain('KPD code must contain only digits');
    });

    it('should reject non-string input', () => {
      const errors = validateKPDFormat(123456 as any);
      expect(errors).toContain('KPD code is required');
    });

    it('should reject null input', () => {
      const errors = validateKPDFormat(null as any);
      expect(errors).toContain('KPD code is required');
    });

    it('should reject undefined input', () => {
      const errors = validateKPDFormat(undefined as any);
      expect(errors).toContain('KPD code is required');
    });
  });

  describe('determineKPDLevel', () => {
    it('should determine level 1 (division)', () => {
      const level = determineKPDLevel('010000');
      expect(level).toBe(1);
    });

    it('should determine level 2 (group)', () => {
      const level = determineKPDLevel('011000');
      expect(level).toBe(2);
    });

    it('should determine level 3 (class)', () => {
      const level = determineKPDLevel('011100');
      expect(level).toBe(3);
    });

    it('should determine level 4 (subclass)', () => {
      const level = determineKPDLevel('011110');
      expect(level).toBe(4);
    });

    it('should determine level 5 (product)', () => {
      const level = determineKPDLevel('011111');
      expect(level).toBe(5);
    });

    it('should determine level 5 for non-zero ending', () => {
      const level = determineKPDLevel('123456');
      expect(level).toBe(5);
    });
  });

  describe('getParentCode', () => {
    it('should return null for level 1', () => {
      const parent = getParentCode('010000');
      expect(parent).toBeNull();
    });

    it('should return parent for level 2', () => {
      const parent = getParentCode('011000');
      expect(parent).toBe('010000');
    });

    it('should return parent for level 3', () => {
      const parent = getParentCode('011100');
      expect(parent).toBe('011000');
    });

    it('should return parent for level 4', () => {
      const parent = getParentCode('011110');
      expect(parent).toBe('011100');
    });

    it('should return parent for level 5', () => {
      const parent = getParentCode('011111');
      expect(parent).toBe('011110');
    });
  });

  describe('validateKPD', () => {
    it('should validate existing KPD code', async () => {
      const result = await validateKPD('011111', database);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.entry).toBeDefined();
      expect(result.entry?.code).toBe('011111');
      expect(result.entry?.name).toBe('Pšenica obična - ozima');
    });

    it('should reject non-existent KPD code', async () => {
      const result = await validateKPD('888888', database);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('KPD code not found in registry');
    });

    it('should reject inactive KPD code', async () => {
      const result = await validateKPD('999999', database);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('KPD code is inactive/deprecated');
      expect(result.entry).toBeDefined();
    });

    it('should reject KPD code with format errors', async () => {
      const result = await validateKPD('12345', database);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle database errors gracefully', async () => {
      const errorDb = new ErrorKPDDatabase();
      const result = await validateKPD('123456', errorDb);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Database error');
    });

    it('should handle non-Error exceptions gracefully', async () => {
      const nonErrorDb = new NonErrorKPDDatabase();
      const result = await validateKPD('123456', nonErrorDb);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('Unknown error');
    });

    it('should reject empty KPD code', async () => {
      const result = await validateKPD('', database);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('KPD code is required');
    });

    it('should reject undefined as KPD code', async () => {
      const result = await validateKPD(undefined as any, database);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('KPD code is required');
    });

    it('should reject null as KPD code', async () => {
      const result = await validateKPD(null as any, database);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('KPD code is required');
    });

    it('should reject object as KPD code', async () => {
      const result = await validateKPD({} as any, database);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('KPD code is required');
    });

    it('should trim whitespace before validation', async () => {
      const result = await validateKPD('  011111  ', database);
      expect(result.valid).toBe(true);
      expect(result.code).toBe('011111');
    });
  });

  describe('validateKPDBatch', () => {
    it('should validate multiple KPD codes', async () => {
      const codes = ['011111', '020000', '888888'];
      const results = await validateKPDBatch(codes, database);

      expect(results).toHaveLength(3);
      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(true);
      expect(results[2].valid).toBe(false);
    });

    it('should handle empty array', async () => {
      const results = await validateKPDBatch([], database);
      expect(results).toEqual([]);
    });

    it('should validate each code independently', async () => {
      const codes = ['011111', 'invalid', '020000'];
      const results = await validateKPDBatch(codes, database);

      expect(results[0].valid).toBe(true);
      expect(results[1].valid).toBe(false);
      expect(results[2].valid).toBe(true);
    });
  });

  describe('searchKPD', () => {
    it('should search by name', async () => {
      const result = await searchKPD('pšenica', database);
      expect(result.total).toBeGreaterThan(0);
      expect(result.entries.length).toBeGreaterThan(0);
      expect(result.entries[0].name.toLowerCase()).toContain('pšenica');
    });

    it('should search case-insensitively', async () => {
      const result = await searchKPD('PŠENICA', database);
      expect(result.total).toBeGreaterThan(0);
    });

    it('should return empty results for no matches', async () => {
      const result = await searchKPD('nonexistent', database);
      expect(result.total).toBe(0);
      expect(result.entries).toEqual([]);
    });

    it('should return empty results for empty query', async () => {
      const result = await searchKPD('', database);
      expect(result.total).toBe(0);
      expect(result.entries).toEqual([]);
    });

    it('should return empty results for whitespace query', async () => {
      const result = await searchKPD('   ', database);
      expect(result.total).toBe(0);
      expect(result.entries).toEqual([]);
    });

    it('should handle database errors gracefully', async () => {
      const errorDb = new ErrorKPDDatabase();
      const result = await searchKPD('test', errorDb);
      expect(result.total).toBe(0);
      expect(result.entries).toEqual([]);
    });

    it('should respect limit parameter', async () => {
      const result = await searchKPD('proizvodi', database, 1);
      expect(result.entries.length).toBeLessThanOrEqual(1);
    });

    it('should handle non-string query', async () => {
      const result = await searchKPD(123 as any, database);
      expect(result.total).toBe(0);
    });
  });

  describe('getKPDHierarchy', () => {
    it('should get hierarchy for level 5 code', async () => {
      const hierarchy = await getKPDHierarchy('011111', database);
      expect(hierarchy.code).toBe('011111');
      expect(hierarchy.entry).toBeDefined();
      expect(hierarchy.parent).toBeDefined();
      expect(hierarchy.parent?.code).toBe('011110');
      expect(hierarchy.children).toEqual([]);
    });

    it('should get hierarchy for level 1 code', async () => {
      const hierarchy = await getKPDHierarchy('010000', database);
      expect(hierarchy.code).toBe('010000');
      expect(hierarchy.entry).toBeDefined();
      expect(hierarchy.parent).toBeNull();
      expect(hierarchy.children.length).toBeGreaterThan(0);
    });

    it('should get hierarchy for level 2 code', async () => {
      const hierarchy = await getKPDHierarchy('011000', database);
      expect(hierarchy.code).toBe('011000');
      expect(hierarchy.entry).toBeDefined();
      expect(hierarchy.parent).toBeDefined();
      expect(hierarchy.parent?.code).toBe('010000');
      expect(hierarchy.children.length).toBeGreaterThan(0);
    });

    it('should handle non-existent code', async () => {
      const hierarchy = await getKPDHierarchy('888888', database);
      expect(hierarchy.code).toBe('888888');
      expect(hierarchy.entry).toBeNull();
      expect(hierarchy.parent).toBeNull();
      expect(hierarchy.children).toEqual([]);
    });

    it('should handle invalid format', async () => {
      const hierarchy = await getKPDHierarchy('12345', database);
      expect(hierarchy.code).toBe('12345');
      expect(hierarchy.entry).toBeNull();
      expect(hierarchy.parent).toBeNull();
      expect(hierarchy.children).toEqual([]);
    });

    it('should handle database errors gracefully', async () => {
      const errorDb = new ErrorKPDDatabase();
      const hierarchy = await getKPDHierarchy('123456', errorDb);
      expect(hierarchy.entry).toBeNull();
      expect(hierarchy.parent).toBeNull();
      expect(hierarchy.children).toEqual([]);
    });
  });

  // Property-based tests
  describe('Property-Based Tests', () => {
    it('should consistently validate the same code', async () => {
      await fc.assert(
        fc.asyncProperty(fc.constantFrom('011111', '020000', '999999'), async (code) => {
          const result1 = await validateKPD(code, database);
          const result2 = await validateKPD(code, database);
          return result1.valid === result2.valid;
        }),
        { numRuns: 20 }
      );
    });

    it('should reject all non-6-digit codes', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 0, maxLength: 10 }).filter((s) => s.length !== 6 || !/^\d{6}$/.test(s)),
          (code) => {
            const errors = validateKPDFormat(code);
            return errors.length > 0;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should accept all 6-digit codes in format validation', () => {
      fc.assert(
        fc.property(fc.integer({ min: 0, max: 999999 }), (num) => {
          const code = num.toString().padStart(6, '0');
          const errors = validateKPDFormat(code);
          return errors.length === 0;
        }),
        { numRuns: 100 }
      );
    });
  });

  // Edge cases
  describe('Edge Cases', () => {
    it('should handle code with leading zeros', async () => {
      const result = await validateKPD('000001', database);
      // Should validate format correctly even if not in database
      expect(result.errors).not.toContain('KPD code must be exactly 6 digits');
    });

    it('should handle all-zero code', async () => {
      const result = await validateKPD('000000', database);
      expect(result.errors).not.toContain('KPD code must be exactly 6 digits');
    });

    it('should handle maximum code value', async () => {
      const result = await validateKPD('999999', database);
      // This code exists but is inactive
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('KPD code is inactive/deprecated');
    });
  });
});
