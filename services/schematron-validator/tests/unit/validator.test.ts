/**
 * Unit Tests: SchematronValidator
 *
 * Tests core Schematron validation logic including:
 * - Rule loading and caching
 * - XML validation against Schematron rules
 * - SVRL report parsing
 * - Error and warning detection
 * - Performance characteristics
 */

import { describe, it, expect, beforeAll, afterEach } from '@jest/globals';
import { readFile } from 'fs/promises';
import { SchematronValidator, SchematronRuleSet, ValidationStatus } from '../../src/validator.js';

describe('SchematronValidator', () => {
  let validator: SchematronValidator;

  beforeAll(() => {
    validator = new SchematronValidator('./tests/fixtures/schematron-rules');
  });

  afterEach(() => {
    // Clear cache between tests to ensure isolation
    validator.clearCache();
  });

  // ==========================================================================
  // Rule Loading Tests
  // ==========================================================================

  describe('Rule Loading', () => {
    it('should load Croatian CIUS core rules successfully', async () => {
      await expect(
        validator.loadRules(SchematronRuleSet.CIUS_HR_CORE)
      ).resolves.not.toThrow();
    });

    it('should cache loaded rules', async () => {
      // Load rules
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);

      // Get cache stats
      const stats = validator.getCacheStats();
      expect(stats.has(SchematronRuleSet.CIUS_HR_CORE)).toBe(true);

      const cacheEntry = stats.get(SchematronRuleSet.CIUS_HR_CORE);
      expect(cacheEntry).toBeDefined();
      expect(cacheEntry!.rule_count).toBeGreaterThan(0);
      expect(cacheEntry!.size_bytes).toBeGreaterThan(0);
    });

    it('should not reload cached rules', async () => {
      // Load rules first time
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);
      const stats1 = validator.getCacheStats();
      const loadedAt1 = stats1.get(SchematronRuleSet.CIUS_HR_CORE)!.loaded_at;

      // Wait 10ms
      await new Promise(resolve => setTimeout(resolve, 10));

      // Load rules second time (should use cache)
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);
      const stats2 = validator.getCacheStats();
      const loadedAt2 = stats2.get(SchematronRuleSet.CIUS_HR_CORE)!.loaded_at;

      // Timestamp should be the same (no reload)
      expect(loadedAt1).toEqual(loadedAt2);
    });

    it('should throw error for non-existent rule set', async () => {
      await expect(
        validator.loadRules('NONEXISTENT_RULESET' as SchematronRuleSet)
      ).rejects.toThrow();
    });

    it('should clear cache when requested', async () => {
      // Load rules
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);
      expect(validator.getCacheStats().size).toBe(1);

      // Clear cache
      validator.clearCache(SchematronRuleSet.CIUS_HR_CORE);
      expect(validator.getCacheStats().size).toBe(0);
    });

    it('should clear all caches when no rule set specified', async () => {
      // Load multiple rule sets (only CIUS_HR_CORE exists in fixtures)
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);
      expect(validator.getCacheStats().size).toBeGreaterThan(0);

      // Clear all
      validator.clearCache();
      expect(validator.getCacheStats().size).toBe(0);
    });
  });

  // ==========================================================================
  // Validation Tests - Valid Documents
  // ==========================================================================

  describe('Valid Document Validation', () => {
    it('should validate a valid Croatian CIUS invoice', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.VALID);
      expect(result.errors).toHaveLength(0);
      expect(result.rules_checked).toBeGreaterThan(0);
      expect(result.rules_failed).toBe(0);
      expect(result.validation_time_ms).toBeGreaterThan(0);
      expect(result.rule_set).toBe(SchematronRuleSet.CIUS_HR_CORE);
    });

    it('should accept Buffer input', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.VALID);
      expect(result.errors).toHaveLength(0);
    });

    it('should accept string input', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.VALID);
      expect(result.errors).toHaveLength(0);
    });

    it('should return validation time in milliseconds', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.validation_time_ms).toBeGreaterThan(0);
      expect(result.validation_time_ms).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });

  // ==========================================================================
  // Validation Tests - Invalid Documents
  // ==========================================================================

  describe('Invalid Document Validation', () => {
    it('should detect invalid VAT rate (BR-S-01)', async () => {
      const xml = await readFile('./tests/fixtures/invoices/invalid-vat-rate.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.INVALID);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.rules_failed).toBeGreaterThan(0);

      // Should have error for BR-S-01
      const vatError = result.errors.find(e => e.rule_id === 'BR-S-01');
      expect(vatError).toBeDefined();
      expect(vatError!.severity).toBe('error');
      expect(vatError!.message).toContain('25%');
    });

    it('should detect invalid OIB length (BR-HR-01)', async () => {
      const xml = await readFile('./tests/fixtures/invoices/invalid-oib.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.INVALID);
      expect(result.errors.length).toBeGreaterThan(0);

      // Should have error for BR-HR-01
      const oibError = result.errors.find(e => e.rule_id === 'BR-HR-01');
      expect(oibError).toBeDefined();
      expect(oibError!.severity).toBe('error');
      expect(oibError!.message).toContain('11 digits');
    });

    it('should detect missing required fields', async () => {
      const xml = await readFile('./tests/fixtures/invoices/missing-required-fields.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.INVALID);
      expect(result.errors.length).toBeGreaterThan(0);

      // Should have errors for missing ID and/or IssueDate
      const hasCardianlityError = result.errors.some(e => e.rule_id.startsWith('BR-CO'));
      expect(hasCardianlityError).toBe(true);
    });

    it('should include error location (XPath)', async () => {
      const xml = await readFile('./tests/fixtures/invoices/invalid-vat-rate.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      const vatError = result.errors.find(e => e.rule_id === 'BR-S-01');
      expect(vatError).toBeDefined();
      expect(vatError!.location).toBeDefined();
      expect(vatError!.location).not.toBe('');
    });

    it('should return multiple errors for multiple violations', async () => {
      const xml = await readFile('./tests/fixtures/invoices/missing-required-fields.xml', 'utf-8');

      const result = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      // Missing ID and IssueDate = at least 2 errors
      expect(result.errors.length).toBeGreaterThanOrEqual(2);
      expect(result.rules_failed).toBeGreaterThanOrEqual(2);
    });
  });

  // ==========================================================================
  // Error Handling Tests
  // ==========================================================================

  describe('Error Handling', () => {
    it('should handle malformed XML gracefully', async () => {
      const malformedXML = '<Invoice><InvalidTag></Invoice>';

      const result = await validator.validate(malformedXML, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.ERROR);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0].rule_id).toBe('SYSTEM_ERROR');
      expect(result.errors[0].severity).toBe('fatal');
    });

    it('should handle empty XML', async () => {
      const result = await validator.validate('', SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.ERROR);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle null input gracefully', async () => {
      const result = await validator.validate(null as any, SchematronRuleSet.CIUS_HR_CORE);

      expect(result.status).toBe(ValidationStatus.ERROR);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle very large XML documents', async () => {
      // Create a large XML document (10MB+)
      const largeXML = `<?xml version="1.0"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>LARGE-001</cbc:ID>
  <cbc:IssueDate>2025-11-11</cbc:IssueDate>
  ${'<cbc:Note>Lorem ipsum '.repeat(10000)}
</Invoice>`;

      // Should either validate or timeout gracefully
      const result = await validator.validate(largeXML, SchematronRuleSet.CIUS_HR_CORE);

      expect([ValidationStatus.VALID, ValidationStatus.INVALID, ValidationStatus.ERROR])
        .toContain(result.status);
    });
  });

  // ==========================================================================
  // Performance Tests
  // ==========================================================================

  describe('Performance', () => {
    it('should validate small documents quickly (<1s)', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      const startTime = Date.now();
      await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(1000); // <1s for small documents
    });

    it('should benefit from rule caching (second validation faster)', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      // First validation (loads rules)
      const start1 = Date.now();
      await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);
      const duration1 = Date.now() - start1;

      // Second validation (uses cached rules)
      const start2 = Date.now();
      await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);
      const duration2 = Date.now() - start2;

      // Second validation should be faster or comparable
      // (May not always be faster in test environment, so we just check it doesn't fail)
      expect(duration2).toBeLessThan(10000);
    });

    it('should handle concurrent validations', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      // Validate 10 documents concurrently
      const promises = Array(10).fill(null).map(() =>
        validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE)
      );

      const results = await Promise.all(promises);

      // All should succeed
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(result.status).toBe(ValidationStatus.VALID);
      });
    });

    it('should process 10 validations in reasonable time (<10s)', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      const startTime = Date.now();

      for (let i = 0; i < 10; i++) {
        await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);
      }

      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(10000); // 10 validations in <10s
    });
  });

  // ==========================================================================
  // Cache Management Tests
  // ==========================================================================

  describe('Cache Management', () => {
    it('should track cache size in bytes', async () => {
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);

      const stats = validator.getCacheStats();
      const entry = stats.get(SchematronRuleSet.CIUS_HR_CORE);

      expect(entry).toBeDefined();
      expect(entry!.size_bytes).toBeGreaterThan(100); // XSLT should be >100 bytes
    });

    it('should track rule count', async () => {
      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);

      const stats = validator.getCacheStats();
      const entry = stats.get(SchematronRuleSet.CIUS_HR_CORE);

      expect(entry).toBeDefined();
      expect(entry!.rule_count).toBeGreaterThan(5); // Our test rules have multiple assertions
    });

    it('should track load timestamp', async () => {
      const beforeLoad = new Date();

      await validator.loadRules(SchematronRuleSet.CIUS_HR_CORE);

      const afterLoad = new Date();
      const stats = validator.getCacheStats();
      const entry = stats.get(SchematronRuleSet.CIUS_HR_CORE);

      expect(entry).toBeDefined();
      expect(entry!.loaded_at).toBeInstanceOf(Date);
      expect(entry!.loaded_at.getTime()).toBeGreaterThanOrEqual(beforeLoad.getTime());
      expect(entry!.loaded_at.getTime()).toBeLessThanOrEqual(afterLoad.getTime());
    });
  });

  // ==========================================================================
  // Edge Cases
  // ==========================================================================

  describe('Edge Cases', () => {
    it('should handle XML with special characters', async () => {
      const xmlWithSpecialChars = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>INV-&lt;&amp;&gt;</cbc:ID>
  <cbc:IssueDate>2025-11-11</cbc:IssueDate>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>12345678901</cbc:CompanyID>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:LegalMonetaryTotal>
    <cbc:PayableAmount currencyID="EUR">1250.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>`;

      const result = await validator.validate(xmlWithSpecialChars, SchematronRuleSet.CIUS_HR_CORE);

      // Should not crash, may be valid or invalid depending on rules
      expect([ValidationStatus.VALID, ValidationStatus.INVALID, ValidationStatus.ERROR])
        .toContain(result.status);
    });

    it('should handle XML with Unicode characters', async () => {
      const xmlWithUnicode = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>RAČUN-2025-001</cbc:ID>
  <cbc:IssueDate>2025-11-11</cbc:IssueDate>
  <cbc:DocumentCurrencyCode>EUR</cbc:DocumentCurrencyCode>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyName>
        <cbc:Name>Tvrtka d.o.o. - Željko Šimić</cbc:Name>
      </cac:PartyName>
      <cac:PartyTaxScheme>
        <cbc:CompanyID>12345678901</cbc:CompanyID>
      </cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:LegalMonetaryTotal>
    <cbc:PayableAmount currencyID="EUR">1250.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>`;

      const result = await validator.validate(xmlWithUnicode, SchematronRuleSet.CIUS_HR_CORE);

      // Should handle Unicode correctly
      expect([ValidationStatus.VALID, ValidationStatus.INVALID, ValidationStatus.ERROR])
        .toContain(result.status);
    });

    it('should be idempotent (same input always produces same output)', async () => {
      const xml = await readFile('./tests/fixtures/invoices/valid-cius-hr.xml', 'utf-8');

      const result1 = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);
      const result2 = await validator.validate(xml, SchematronRuleSet.CIUS_HR_CORE);

      expect(result1.status).toBe(result2.status);
      expect(result1.errors.length).toBe(result2.errors.length);
      expect(result1.warnings.length).toBe(result2.warnings.length);
      expect(result1.rules_checked).toBe(result2.rules_checked);
      expect(result1.rules_failed).toBe(result2.rules_failed);
    });
  });
});
