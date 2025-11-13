import { parseXml } from 'libxmljs2';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export enum SchemaType {
  UBL_INVOICE_2_1 = 'UBL-Invoice-2.1',
  UBL_CREDIT_NOTE_2_1 = 'UBL-CreditNote-2.1',
}

export enum ValidationStatus {
  VALID = 'VALID',
  INVALID = 'INVALID',
  ERROR = 'ERROR',
}

export interface ValidationError {
  code: string;
  message: string;
  line?: number;
  column?: number;
  field?: string;
}

export interface ValidationResult {
  status: ValidationStatus;
  errors: ValidationError[];
  validationTimeMs: number;
}

/**
 * IMPROVEMENT-011: Cached parsed XML document
 * Stores recently parsed XML to avoid re-parsing on subsequent validations
 */
interface CachedParsedXML {
  /** MD5 hash of XML content for cache key */
  hash: string;
  /** Parsed XML document object */
  document: any;
  /** Timestamp when cached */
  cachedAt: number;
  /** TTL in milliseconds (default: 5 minutes) */
  ttl: number;
}

/**
 * XSD Validator for UBL 2.1 documents
 *
 * Validates XML documents against official UBL 2.1 XSD schemas.
 *
 * Security:
 * - XXE protection: External entity resolution disabled
 * - Billion laughs protection: Entity expansion limited
 * - Size limits: Enforced by caller (max 10MB)
 *
 * Performance Optimizations (IMPROVEMENT-011):
 * - Cached parsed XML (avoid re-parsing on subsequent validations)
 * - Separated XML parsing from XSD validation
 * - Direct validation on pre-parsed documents where possible
 */
export class XSDValidator {
  private schemaCache: Map<SchemaType, any> = new Map();
  private schemaPath: string;
  /** IMPROVEMENT-011: Cache for parsed XML documents */
  private parsedXmlCache: Map<string, CachedParsedXML> = new Map();
  /** IMPROVEMENT-011: Maximum size of parsed XML cache (number of entries) */
  private maxParsedXmlCacheSize: number = 1000;

  constructor(schemaPath?: string, maxCacheSize?: number) {
    this.schemaPath = schemaPath || path.join(__dirname, '../schemas/ubl-2.1');
    if (maxCacheSize) {
      this.maxParsedXmlCacheSize = maxCacheSize;
    }
  }

  /**
   * IMPROVEMENT-011: Generate cache key from XML content
   * Uses a simple hash to identify XML documents
   *
   * @param xmlContent - XML as string or buffer
   * @returns Cache key
   */
  private getCacheKey(xmlContent: Buffer | string): string {
    const content = typeof xmlContent === 'string' ? xmlContent : xmlContent.toString('utf-8');
    // Simple hash: use first 50 chars + last 50 chars + length
    // This is fast and works well for caching recently seen documents
    const prefix = content.substring(0, 50);
    const suffix = content.length > 100 ? content.substring(content.length - 50) : '';
    return `${prefix}|${content.length}|${suffix}`;
  }

  /**
   * IMPROVEMENT-011: Check if parsed XML is cached and still valid
   *
   * @param cacheKey - Cache key for XML document
   * @returns Cached parsed document, or null if not cached/expired
   */
  private getCachedParsedXml(cacheKey: string): any | null {
    const cached = this.parsedXmlCache.get(cacheKey);
    if (!cached) return null;

    // Check if cache entry has expired
    const age = Date.now() - cached.cachedAt;
    if (age > cached.ttl) {
      this.parsedXmlCache.delete(cacheKey);
      return null;
    }

    return cached.document;
  }

  /**
   * IMPROVEMENT-011: Cache parsed XML document
   *
   * @param cacheKey - Cache key for XML document
   * @param document - Parsed XML document
   * @param ttl - Time to live in milliseconds (default: 5 minutes)
   */
  private cacheParsedXml(cacheKey: string, document: any, ttl: number = 5 * 60 * 1000): void {
    // Evict oldest entry if cache is full
    if (this.parsedXmlCache.size >= this.maxParsedXmlCacheSize) {
      const firstKey = this.parsedXmlCache.keys().next().value;
      if (firstKey) {
        this.parsedXmlCache.delete(firstKey);
      }
    }

    this.parsedXmlCache.set(cacheKey, {
      hash: cacheKey,
      document,
      cachedAt: Date.now(),
      ttl,
    });
  }

  /**
   * IMPROVEMENT-011: Parse XML with caching to avoid redundant parsing
   * Returns cached parsed document if available, otherwise parses and caches
   *
   * @param xmlContent - XML document as buffer or string
   * @returns Parsed XML document
   * @throws Error if parsing fails
   */
  private parseXmlWithCache(xmlContent: Buffer | string): any {
    const cacheKey = this.getCacheKey(xmlContent);

    // Check cache first
    const cached = this.getCachedParsedXml(cacheKey);
    if (cached) {
      return cached;
    }

    // Parse XML with security protections
    const xmlString = typeof xmlContent === 'string' ? xmlContent : xmlContent.toString('utf-8');
    const document = parseXml(xmlString, {
      nonet: true, // Disable network access (XXE protection)
      noent: false, // Disable entity substitution (billion laughs protection)
      nocdata: false, // Allow CDATA sections
      recover: false, // Strict parsing (don't try to recover from errors)
    });

    // Cache the parsed document
    this.cacheParsedXml(cacheKey, document);

    return document;
  }

  /**
   * Load UBL 2.1 schemas into memory at startup
   * Schemas are cached for the lifetime of the service
   */
  async loadSchemas(): Promise<void> {
    const schemaFiles: Record<SchemaType, string> = {
      [SchemaType.UBL_INVOICE_2_1]: 'maindoc/UBL-Invoice-2.1.xsd',
      [SchemaType.UBL_CREDIT_NOTE_2_1]: 'maindoc/UBL-CreditNote-2.1.xsd',
    };

    for (const [schemaType, schemaFile] of Object.entries(schemaFiles)) {
      const schemaFullPath = path.join(this.schemaPath, schemaFile);

      try {
        const schemaContent = await fs.readFile(schemaFullPath, 'utf-8');
        const schemaDoc = parseXml(schemaContent, {
          nonet: true, // Disable network access (XXE protection)
          noent: false, // Disable entity substitution (billion laughs protection)
        });

        this.schemaCache.set(schemaType as SchemaType, schemaDoc);
      } catch (error) {
        throw new Error(
          `Failed to load schema ${schemaType}: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    }
  }

  /**
   * Validate XML document against UBL 2.1 XSD schema
   *
   * IMPROVEMENT-011: Optimized to use cached parsed XML
   *
   * @param xmlContent - XML document as bytes/string
   * @param schemaType - UBL document type (Invoice, CreditNote, etc.)
   * @returns ValidationResult with status and errors
   */
  async validate(
    xmlContent: Buffer | string,
    schemaType: SchemaType
  ): Promise<ValidationResult> {
    const startTime = Date.now();
    const errors: ValidationError[] = [];

    try {
      // IMPROVEMENT-011: Use parseXmlWithCache to avoid redundant parsing
      const xmlDoc = this.parseXmlWithCache(xmlContent);

      // Get cached schema
      const schema = this.schemaCache.get(schemaType);
      if (!schema) {
        return {
          status: ValidationStatus.ERROR,
          errors: [
            {
              code: 'SCHEMA_NOT_LOADED',
              message: `Schema ${schemaType} not loaded. Call loadSchemas() first.`,
            },
          ],
          validationTimeMs: Date.now() - startTime,
        };
      }

      // Validate against XSD schema
      const isValid = xmlDoc.validate(schema);

      if (!isValid) {
        // Extract validation errors from libxmljs2
        const validationErrors = xmlDoc.validationErrors || [];

        for (const error of validationErrors) {
          errors.push({
            code: 'XSD_VALIDATION_ERROR',
            message: error.message || 'Validation error',
            line: error.line,
            column: error.column,
          });
        }
      }

      return {
        status: errors.length > 0 ? ValidationStatus.INVALID : ValidationStatus.VALID,
        errors,
        validationTimeMs: Date.now() - startTime,
      };
    } catch (error) {
      // Parse errors or other exceptions
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      // Try to extract line/column from libxml2 error message
      const lineMatch = errorMessage.match(/line (\d+)/i);
      const columnMatch = errorMessage.match(/column (\d+)/i);

      return {
        status: ValidationStatus.ERROR,
        errors: [
          {
            code: 'XML_PARSE_ERROR',
            message: errorMessage,
            line: lineMatch ? parseInt(lineMatch[1], 10) : undefined,
            column: columnMatch ? parseInt(columnMatch[1], 10) : undefined,
          },
        ],
        validationTimeMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Validate pre-parsed XML document (for scenarios where XML is already parsed elsewhere)
   *
   * IMPROVEMENT-011: Direct validation without re-parsing
   *
   * @param xmlDoc - Already-parsed XML document object
   * @param schemaType - UBL document type (Invoice, CreditNote, etc.)
   * @returns ValidationResult with status and errors
   */
  async validateParsedXml(xmlDoc: any, schemaType: SchemaType): Promise<ValidationResult> {
    const startTime = Date.now();
    const errors: ValidationError[] = [];

    try {
      // Get cached schema
      const schema = this.schemaCache.get(schemaType);
      if (!schema) {
        return {
          status: ValidationStatus.ERROR,
          errors: [
            {
              code: 'SCHEMA_NOT_LOADED',
              message: `Schema ${schemaType} not loaded. Call loadSchemas() first.`,
            },
          ],
          validationTimeMs: Date.now() - startTime,
        };
      }

      // Validate against XSD schema
      const isValid = xmlDoc.validate(schema);

      if (!isValid) {
        // Extract validation errors from libxmljs2
        const validationErrors = xmlDoc.validationErrors || [];

        for (const error of validationErrors) {
          errors.push({
            code: 'XSD_VALIDATION_ERROR',
            message: error.message || 'Validation error',
            line: error.line,
            column: error.column,
          });
        }
      }

      return {
        status: errors.length > 0 ? ValidationStatus.INVALID : ValidationStatus.VALID,
        errors,
        validationTimeMs: Date.now() - startTime,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      const lineMatch = errorMessage.match(/line (\d+)/i);
      const columnMatch = errorMessage.match(/column (\d+)/i);

      return {
        status: ValidationStatus.ERROR,
        errors: [
          {
            code: 'VALIDATION_ERROR',
            message: errorMessage,
            line: lineMatch ? parseInt(lineMatch[1], 10) : undefined,
            column: columnMatch ? parseInt(columnMatch[1], 10) : undefined,
          },
        ],
        validationTimeMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Check if schemas are loaded and ready
   */
  isReady(): boolean {
    return this.schemaCache.size > 0;
  }

  /**
   * Get loaded schema types (for diagnostics)
   */
  getLoadedSchemas(): SchemaType[] {
    return Array.from(this.schemaCache.keys());
  }

  /**
   * IMPROVEMENT-011: Get parsed XML cache statistics (for monitoring)
   * @returns Cache statistics
   */
  getCacheStats(): {
    entries: number;
    maxSize: number;
    utilizationPercent: number;
  } {
    return {
      entries: this.parsedXmlCache.size,
      maxSize: this.maxParsedXmlCacheSize,
      utilizationPercent: Math.round((this.parsedXmlCache.size / this.maxParsedXmlCacheSize) * 100),
    };
  }

  /**
   * IMPROVEMENT-011: Clear parsed XML cache (for testing or maintenance)
   */
  clearCache(): void {
    this.parsedXmlCache.clear();
  }
}
