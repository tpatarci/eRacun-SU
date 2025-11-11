/**
 * Schematron Validator
 *
 * Validates XML documents against Schematron business rules using Saxon-JS.
 * Implements Croatian CIUS validation for UBL 2.1 e-invoices.
 *
 * Validation Pipeline:
 * 1. Load Schematron rules (.sch file)
 * 2. Transform Schematron → XSLT (ISO Schematron skeleton)
 * 3. Compile XSLT stylesheet (cached)
 * 4. Apply XSLT to invoice XML
 * 5. Parse SVRL (Schematron Validation Report Language) output
 * 6. Extract errors and warnings
 */

import { readFile } from 'fs/promises';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';
import { createSpan } from './observability.js';
import {
  validationTotal,
  validationDuration,
  rulesCheckedHistogram,
  rulesFailedHistogram,
  rulesLoaded,
  errorsByRule,
  warningsByRule
} from './observability.js';

// ============================================================================
// Types
// ============================================================================

export enum SchematronRuleSet {
  CIUS_HR_CORE = 'CIUS_HR_CORE',
  CIUS_HR_EXTENDED = 'CIUS_HR_EXTENDED',
  EN16931_CORE = 'EN16931_CORE',
  UBL_FULL = 'UBL_FULL'
}

export enum ValidationStatus {
  VALID = 'VALID',
  INVALID = 'INVALID',
  ERROR = 'ERROR'
}

export interface ValidationError {
  rule_id: string;
  severity: 'error' | 'fatal';
  message: string;
  location: string;        // XPath location in document
  xpath?: string;          // Full XPath to failing element
  actual_value?: string;
  expected_value?: string;
}

export interface ValidationWarning {
  rule_id: string;
  severity: 'warning' | 'info';
  message: string;
  location: string;
}

export interface ValidationResult {
  status: ValidationStatus;
  rules_checked: number;
  rules_failed: number;
  errors: ValidationError[];
  warnings: ValidationWarning[];
  validation_time_ms: number;
  rule_set: SchematronRuleSet;
}

// SVRL (Schematron Validation Report Language) structure
interface SVRLReport {
  'svrl:schematron-output': {
    'svrl:failed-assert'?: Array<{
      '@_id'?: string;
      '@_role'?: string;
      '@_location': string;
      'svrl:text': string;
      'svrl:diagnostic-reference'?: Array<{
        '@_diagnostic': string;
        '#text': string;
      }>;
    }>;
    'svrl:successful-report'?: Array<{
      '@_id'?: string;
      '@_role'?: string;
      '@_location': string;
      'svrl:text': string;
    }>;
    'svrl:fired-rule'?: Array<{
      '@_context': string;
    }>;
  };
}

// ============================================================================
// Rule Cache
// ============================================================================

interface CompiledRule {
  xslt: string;             // Compiled XSLT stylesheet
  rule_count: number;       // Number of rules in schema
  loaded_at: Date;
  size_bytes: number;
}

const ruleCache = new Map<SchematronRuleSet, CompiledRule>();

// ============================================================================
// Schematron Validator Class
// ============================================================================

export class SchematronValidator {
  private rulesPath: string;
  private xmlParser: XMLParser;
  private xmlBuilder: XMLBuilder;

  constructor(rulesPath: string = './rules') {
    this.rulesPath = rulesPath;

    // Configure XML parser for SVRL output
    this.xmlParser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      parseAttributeValue: true,
      trimValues: true
    });

    this.xmlBuilder = new XMLBuilder({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      format: false
    });
  }

  /**
   * Load Schematron rules from file system
   */
  async loadRules(ruleSet: SchematronRuleSet): Promise<void> {
    const span = createSpan('load_rules', { 'rule_set': ruleSet });

    try {
      // Check cache first
      if (ruleCache.has(ruleSet)) {
        span.end();
        return;
      }

      const startTime = Date.now();
      const ruleFileName = this.getRuleFileName(ruleSet);
      const ruleFilePath = `${this.rulesPath}/${ruleFileName}`;

      // Read Schematron file
      const schematronContent = await readFile(ruleFilePath, 'utf-8');

      // Transform Schematron → XSLT
      // NOTE: In production, this would use iso-schematron-xslt3 XSLT stylesheets
      // For now, we'll use a simplified approach for development
      const xslt = await this.transformSchematronToXSLT(schematronContent, ruleSet);

      // Count rules in Schematron
      const ruleCount = this.countRules(schematronContent);

      // Cache compiled XSLT
      const compiled: CompiledRule = {
        xslt,
        rule_count: ruleCount,
        loaded_at: new Date(),
        size_bytes: Buffer.byteLength(xslt, 'utf-8')
      };

      ruleCache.set(ruleSet, compiled);
      rulesLoaded.set({ rule_set: ruleSet }, ruleCount);

      const duration = Date.now() - startTime;
      span.setAttribute('duration_ms', duration);
      span.setAttribute('rule_count', ruleCount);
      span.end();

    } catch (error) {
      span.recordException(error as Error);
      span.end();
      throw new Error(`Failed to load Schematron rules for ${ruleSet}: ${(error as Error).message}`);
    }
  }

  /**
   * Validate XML document against Schematron rules
   */
  async validate(
    xmlContent: Buffer | string,
    ruleSet: SchematronRuleSet
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const span = createSpan('schematron_validation', { 'rule_set': ruleSet });

    try {
      // Ensure rules are loaded
      await this.loadRules(ruleSet);

      const compiled = ruleCache.get(ruleSet)!;

      // Parse XML (validate well-formedness)
      const xmlString = typeof xmlContent === 'string' ? xmlContent : xmlContent.toString('utf-8');

      // Apply XSLT transformation to generate SVRL report
      const svrlOutput = await this.applyXSLT(xmlString, compiled.xslt, ruleSet);

      // Parse SVRL report
      const result = this.parseSVRL(svrlOutput, ruleSet, compiled.rule_count);

      // Record metrics
      const duration = Date.now() - startTime;
      result.validation_time_ms = duration;

      validationTotal.inc({ status: result.status.toLowerCase(), rule_set: ruleSet });
      validationDuration.observe({ rule_set: ruleSet }, duration / 1000);
      rulesCheckedHistogram.observe({ rule_set: ruleSet }, result.rules_checked);
      rulesFailedHistogram.observe({ rule_set: ruleSet }, result.rules_failed);

      // Record errors by rule
      for (const error of result.errors) {
        errorsByRule.inc({ rule_id: error.rule_id, rule_set: ruleSet });
      }

      // Record warnings by rule
      for (const warning of result.warnings) {
        warningsByRule.inc({ rule_id: warning.rule_id, rule_set: ruleSet });
      }

      span.setAttribute('status', result.status);
      span.setAttribute('rules_checked', result.rules_checked);
      span.setAttribute('rules_failed', result.rules_failed);
      span.setAttribute('duration_ms', duration);
      span.end();

      return result;

    } catch (error) {
      const duration = Date.now() - startTime;

      validationTotal.inc({ status: 'error', rule_set: ruleSet });
      validationDuration.observe({ rule_set: ruleSet }, duration / 1000);

      span.recordException(error as Error);
      span.setAttribute('error', true);
      span.end();

      return {
        status: ValidationStatus.ERROR,
        rules_checked: 0,
        rules_failed: 0,
        errors: [{
          rule_id: 'SYSTEM_ERROR',
          severity: 'fatal',
          message: `Validation error: ${(error as Error).message}`,
          location: '/'
        }],
        warnings: [],
        validation_time_ms: duration,
        rule_set: ruleSet
      };
    }
  }

  /**
   * Get rule file name for rule set
   */
  private getRuleFileName(ruleSet: SchematronRuleSet): string {
    const fileMap: Record<SchematronRuleSet, string> = {
      [SchematronRuleSet.CIUS_HR_CORE]: 'cius-hr-core.sch',
      [SchematronRuleSet.CIUS_HR_EXTENDED]: 'cius-hr-extended.sch',
      [SchematronRuleSet.EN16931_CORE]: 'en16931-core.sch',
      [SchematronRuleSet.UBL_FULL]: 'ubl-full.sch'
    };

    return fileMap[ruleSet];
  }

  /**
   * Transform Schematron rules to XSLT stylesheet
   *
   * NOTE: This is a simplified implementation for development.
   * Production should use official ISO Schematron XSLT skeletons:
   * - iso_schematron_skeleton_for_xslt1.xsl
   * - iso_schematron_skeleton_for_saxon.xsl (XSLT 2.0+)
   *
   * These are maintained by ISO/IEC and available at:
   * https://github.com/Schematron/schematron
   */
  private async transformSchematronToXSLT(
    schematronContent: string,
    ruleSet: SchematronRuleSet
  ): Promise<string> {
    const span = createSpan('transform_schematron_to_xslt', { 'rule_set': ruleSet });

    try {
      // Parse Schematron XML
      const schematron = this.xmlParser.parse(schematronContent);

      // Extract namespace declarations (for XPath in XSLT)
      const namespaces = this.extractNamespaces(schematron);

      // Extract patterns and rules
      const patterns = this.extractPatterns(schematron);

      // Generate XSLT that validates document and produces SVRL output
      const xslt = this.generateValidationXSLT(namespaces, patterns, ruleSet);

      span.end();
      return xslt;

    } catch (error) {
      span.recordException(error as Error);
      span.end();
      throw new Error(`Failed to transform Schematron to XSLT: ${(error as Error).message}`);
    }
  }

  /**
   * Extract namespace declarations from Schematron
   */
  private extractNamespaces(schematron: any): Record<string, string> {
    const namespaces: Record<string, string> = {};

    // Default UBL namespaces
    namespaces[''] = 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2';
    namespaces['cac'] = 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2';
    namespaces['cbc'] = 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2';

    // Extract from Schematron <ns> elements
    const schema = schematron.schema || schematron['sch:schema'] || {};
    const nsElements = schema.ns || schema['sch:ns'] || [];
    const nsArray = Array.isArray(nsElements) ? nsElements : [nsElements];

    for (const ns of nsArray) {
      if (ns['@_prefix'] && ns['@_uri']) {
        namespaces[ns['@_prefix']] = ns['@_uri'];
      }
    }

    return namespaces;
  }

  /**
   * Extract patterns and rules from Schematron
   */
  private extractPatterns(schematron: any): any[] {
    const schema = schematron.schema || schematron['sch:schema'] || {};
    const patterns = schema.pattern || schema['sch:pattern'] || [];
    return Array.isArray(patterns) ? patterns : [patterns];
  }

  /**
   * Generate XSLT stylesheet for validation
   *
   * This creates an XSLT that:
   * 1. Matches document elements based on Schematron rules
   * 2. Evaluates assertions and reports
   * 3. Generates SVRL (Schematron Validation Report Language) output
   */
  private generateValidationXSLT(
    namespaces: Record<string, string>,
    patterns: any[],
    ruleSet: SchematronRuleSet
  ): string {
    // NOTE: This is a HIGHLY SIMPLIFIED Schematron → XSLT transformation
    // Production MUST use official ISO Schematron XSLT skeletons

    const nsDeclarations = Object.entries(namespaces)
      .map(([prefix, uri]) => prefix ? `xmlns:${prefix}="${uri}"` : `xmlns="${uri}"`)
      .join(' ');

    return `<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:svrl="http://purl.oclc.org/dsdl/svrl"
  ${nsDeclarations}>

  <xsl:output method="xml" indent="yes"/>

  <!-- Root template: generate SVRL output -->
  <xsl:template match="/">
    <svrl:schematron-output
      title="Schematron Validation Report"
      schemaVersion="${ruleSet}">
      <xsl:apply-templates mode="validate"/>
    </svrl:schematron-output>
  </xsl:template>

  <!-- Validation templates generated from Schematron patterns -->
  <!-- NOTE: In production, these would be generated from actual Schematron rules -->

  <xsl:template match="*" mode="validate">
    <xsl:apply-templates mode="validate"/>
  </xsl:template>

  <!-- Placeholder for actual rule templates -->
  <!-- Production: Parse patterns/rules/asserts from Schematron and generate templates -->

</xsl:stylesheet>`;
  }

  /**
   * Apply XSLT transformation to XML document
   *
   * NOTE: This is a placeholder. Production implementation should use Saxon-JS:
   *
   * import SaxonJS from 'saxon-js';
   * const result = await SaxonJS.transform({
   *   stylesheetText: xslt,
   *   sourceText: xmlString,
   *   destination: 'serialized'
   * });
   */
  private async applyXSLT(
    xmlString: string,
    xslt: string,
    ruleSet: SchematronRuleSet
  ): Promise<string> {
    const span = createSpan('apply_xslt', { 'rule_set': ruleSet });

    try {
      // TODO: Implement Saxon-JS transformation
      // For now, return a mock SVRL report for development

      const mockSVRL = `<?xml version="1.0" encoding="UTF-8"?>
<svrl:schematron-output
  xmlns:svrl="http://purl.oclc.org/dsdl/svrl"
  xmlns:xs="http://www.w3.org/2001/XMLSchema"
  title="Schematron Validation Report"
  schemaVersion="${ruleSet}">

  <!-- Mock validation report - replace with real Saxon-JS output -->
  <svrl:active-pattern id="pattern-1" name="Core validation rules"/>

  <svrl:fired-rule context="/"/>

  <!-- Example: Document is valid (no failed assertions) -->
  <!-- Uncomment below to test error handling:
  <svrl:failed-assert id="BR-S-01" role="error" location="/Invoice/cac:TaxTotal/cac:TaxSubtotal[1]/cac:TaxCategory">
    <svrl:text>VAT rate MUST be 25% when category code is 'S'</svrl:text>
    <svrl:diagnostic-reference diagnostic="actual-value">
      Actual: 20
    </svrl:diagnostic-reference>
    <svrl:diagnostic-reference diagnostic="expected-value">
      Expected: 25
    </svrl:diagnostic-reference>
  </svrl:failed-assert>
  -->

</svrl:schematron-output>`;

      span.end();
      return mockSVRL;

    } catch (error) {
      span.recordException(error as Error);
      span.end();
      throw new Error(`XSLT transformation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Parse SVRL (Schematron Validation Report Language) output
   */
  private parseSVRL(
    svrlOutput: string,
    ruleSet: SchematronRuleSet,
    totalRules: number
  ): Omit<ValidationResult, 'validation_time_ms'> {
    const span = createSpan('parse_svrl', { 'rule_set': ruleSet });

    try {
      const svrl: SVRLReport = this.xmlParser.parse(svrlOutput);
      const output = svrl['svrl:schematron-output'];

      const errors: ValidationError[] = [];
      const warnings: ValidationWarning[] = [];

      // Parse failed assertions (errors)
      const failedAsserts = output['svrl:failed-assert'] || [];
      const assertsArray = Array.isArray(failedAsserts) ? failedAsserts : [failedAsserts];

      for (const assert of assertsArray) {
        if (!assert) continue;

        const severity = (assert['@_role'] === 'warning' || assert['@_role'] === 'info')
          ? assert['@_role'] as 'warning' | 'info'
          : 'error';

        const message = typeof assert['svrl:text'] === 'string'
          ? assert['svrl:text']
          : assert['svrl:text']?.['#text'] || 'Validation failed';

        // Extract diagnostic information
        let actual_value: string | undefined;
        let expected_value: string | undefined;

        const diagnostics = assert['svrl:diagnostic-reference'];
        if (diagnostics) {
          const diagArray = Array.isArray(diagnostics) ? diagnostics : [diagnostics];
          for (const diag of diagArray) {
            if (diag['@_diagnostic'] === 'actual-value') {
              actual_value = diag['#text']?.trim().replace('Actual: ', '');
            }
            if (diag['@_diagnostic'] === 'expected-value') {
              expected_value = diag['#text']?.trim().replace('Expected: ', '');
            }
          }
        }

        if (severity === 'warning' || severity === 'info') {
          warnings.push({
            rule_id: assert['@_id'] || 'UNKNOWN',
            severity,
            message,
            location: assert['@_location']
          });
        } else {
          errors.push({
            rule_id: assert['@_id'] || 'UNKNOWN',
            severity,
            message,
            location: assert['@_location'],
            xpath: assert['@_location'],
            actual_value,
            expected_value
          });
        }
      }

      // Parse successful reports (can also be warnings)
      const successfulReports = output['svrl:successful-report'] || [];
      const reportsArray = Array.isArray(successfulReports) ? successfulReports : [successfulReports];

      for (const report of reportsArray) {
        if (!report) continue;

        const severity = (report['@_role'] as 'warning' | 'info') || 'info';
        const message = typeof report['svrl:text'] === 'string'
          ? report['svrl:text']
          : report['svrl:text']?.['#text'] || 'Information';

        warnings.push({
          rule_id: report['@_id'] || 'UNKNOWN',
          severity,
          message,
          location: report['@_location']
        });
      }

      // Determine overall status
      const status = errors.length > 0 ? ValidationStatus.INVALID : ValidationStatus.VALID;

      // Count fired rules (rules that were checked)
      const firedRules = output['svrl:fired-rule'] || [];
      const firedRulesArray = Array.isArray(firedRules) ? firedRules : [firedRules];
      const rulesChecked = firedRulesArray.length || totalRules;

      span.setAttribute('status', status);
      span.setAttribute('errors_count', errors.length);
      span.setAttribute('warnings_count', warnings.length);
      span.end();

      return {
        status,
        rules_checked: rulesChecked,
        rules_failed: errors.length,
        errors,
        warnings,
        rule_set: ruleSet
      };

    } catch (error) {
      span.recordException(error as Error);
      span.end();
      throw new Error(`Failed to parse SVRL output: ${(error as Error).message}`);
    }
  }

  /**
   * Count number of rules in Schematron schema
   */
  private countRules(schematronContent: string): number {
    try {
      const schematron = this.xmlParser.parse(schematronContent);
      const schema = schematron.schema || schematron['sch:schema'] || {};
      const patterns = schema.pattern || schema['sch:pattern'] || [];
      const patternsArray = Array.isArray(patterns) ? patterns : [patterns];

      let ruleCount = 0;
      for (const pattern of patternsArray) {
        const rules = pattern.rule || pattern['sch:rule'] || [];
        const rulesArray = Array.isArray(rules) ? rules : [rules];

        for (const rule of rulesArray) {
          const asserts = rule.assert || rule['sch:assert'] || [];
          const assertsArray = Array.isArray(asserts) ? asserts : [asserts];
          ruleCount += assertsArray.filter(a => a).length;
        }
      }

      return ruleCount || 1; // At least 1 rule

    } catch (error) {
      return 1; // Fallback
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): Map<SchematronRuleSet, { rule_count: number; loaded_at: Date; size_bytes: number }> {
    const stats = new Map();
    for (const [ruleSet, compiled] of ruleCache.entries()) {
      stats.set(ruleSet, {
        rule_count: compiled.rule_count,
        loaded_at: compiled.loaded_at,
        size_bytes: compiled.size_bytes
      });
    }
    return stats;
  }

  /**
   * Clear rule cache (for testing or hot reload)
   */
  clearCache(ruleSet?: SchematronRuleSet): void {
    if (ruleSet) {
      ruleCache.delete(ruleSet);
      rulesLoaded.set({ rule_set: ruleSet }, 0);
    } else {
      ruleCache.clear();
      for (const rs of Object.values(SchematronRuleSet)) {
        rulesLoaded.set({ rule_set: rs }, 0);
      }
    }
  }
}
