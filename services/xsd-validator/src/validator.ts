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
 * IMPROVEMENT-012: Cached XSD schema with metadata
 * Stores loaded XSD schemas with expiration and freshness tracking
 */
interface CachedSchema {
  /** Loaded schema document */
  document: any;
  /** Timestamp when loaded */
  loadedAt: number;
  /** TTL in milliseconds (default: 24 hours) */
  ttl: number;
  /** Schema version (extracted from WSDL or file) */
  version?: string;
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
  /** IMPROVEMENT-012: Updated schema cache to use CachedSchema interface with TTL */
  private schemaCache: Map<SchemaType, CachedSchema> = new Map();
  private schemaPath: string;
  /** IMPROVEMENT-011: Cache for parsed XML documents */
  private parsedXmlCache: Map<string, CachedParsedXML> = new Map();
  /** IMPROVEMENT-011: Maximum size of parsed XML cache (number of entries) */
  private maxParsedXmlCacheSize: number = 1000;
  /** IMPROVEMENT-012: Schema cache configuration */
  private schemaCacheTtl: number = 24 * 60 * 60 * 1000; // 24 hours default
  /** IMPROVEMENT-013: Maximum validation errors to collect (DoS prevention) */
  private maxValidationErrors: number = 100;

  constructor(schemaPath?: string, maxCacheSize?: number, schemaCacheTtlHours?: number) {
    this.schemaPath = schemaPath || path.join(__dirname, '../schemas/ubl-2.1');
    if (maxCacheSize) {
      this.maxParsedXmlCacheSize = maxCacheSize;
    }
    if (schemaCacheTtlHours) {
      this.schemaCacheTtl = schemaCacheTtlHours * 60 * 60 * 1000;
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
   * IMPROVEMENT-014: Validate message structure before schema validation
   * Ensures message format is correct and contains required fields
   *
   * @param xmlContent - XML content to validate
   * @returns Array of ValidationError if message validation fails
   */
  private validateMessageSchema(xmlContent: Buffer | string): ValidationError[] {
    const errors: ValidationError[] = [];
    const content = typeof xmlContent === 'string' ? xmlContent : xmlContent.toString('utf-8');

    // Check for empty content
    if (!content || content.trim().length === 0) {
      errors.push({
        code: 'INVALID_MESSAGE',
        message: 'Message content is empty',
      });
    }

    // Check for valid XML declaration
    const trimmed = content.trim();
    if (!trimmed.startsWith('<')) {
      errors.push({
        code: 'INVALID_MESSAGE',
        message: 'Message does not start with XML element',
      });
    }

    // Check for root element
    const rootMatch = trimmed.match(/<(\w+)[>\s]/);
    if (!rootMatch) {
      errors.push({
        code: 'INVALID_MESSAGE',
        message: 'Message has no valid root element',
      });
    }

    return errors;
  }

  /**
   * IMPROVEMENT-013: Extract validation errors with bounds checking
   * Prevents DoS by limiting error collection to reasonable maximum
   *
   * @param validationErrors - Array of errors from libxmljs2
   * @returns Bounded array of ValidationError objects
   */
  private extractValidationErrors(validationErrors: any[]): ValidationError[] {
    const errors: ValidationError[] = [];

    if (!validationErrors || !Array.isArray(validationErrors)) {
      return errors;
    }

    // IMPROVEMENT-013: Limit error collection to prevent DoS
    const maxErrors = Math.min(this.maxValidationErrors, validationErrors.length);

    for (let i = 0; i < maxErrors; i++) {
      const error = validationErrors[i];
      errors.push({
        code: 'XSD_VALIDATION_ERROR',
        message: error.message || 'Validation error',
        line: error.line,
        column: error.column,
      });
    }

    // Add summary if errors were truncated
    if (validationErrors.length > maxErrors) {
      errors.push({
        code: 'VALIDATION_ERRORS_TRUNCATED',
        message: `Validation had ${validationErrors.length} errors, showing first ${maxErrors}`,
      });
    }

    return errors;
  }

  /**
   * IMPROVEMENT-020: Validate XXE protection in XML parsing
   * Ensures no external entities are present in parsed XML
   *
   * @param xmlContent - XML content to check
   * @returns Array of XXE-related errors, or empty array if safe
   */
  private validateXXEProtection(xmlContent: Buffer | string): ValidationError[] {
    const errors: ValidationError[] = [];
    const content = typeof xmlContent === 'string' ? xmlContent : xmlContent.toString('utf-8');

    // IMPROVEMENT-020: Check for XXE attack patterns
    // Pattern 1: DOCTYPE declarations with external entities
    if (content.includes('<!DOCTYPE') || content.includes('<!ENTITY')) {
      errors.push({
        code: 'XXE_VULNERABILITY',
        message: 'XML contains potentially dangerous DOCTYPE or ENTITY declarations (XXE protection)',
      });
    }

    // Pattern 2: SYSTEM identifiers (external resource access)
    if (content.includes('SYSTEM') && (content.includes('<!ENTITY') || content.includes('<!DOCTYPE'))) {
      errors.push({
        code: 'XXE_VULNERABILITY',
        message: 'XML contains SYSTEM identifiers that could access external resources',
      });
    }

    // Pattern 3: Parameter entities (billion laughs variation)
    if (content.includes('<!ENTITY %')) {
      errors.push({
        code: 'XXE_VULNERABILITY',
        message: 'XML contains parameter entities (billion laughs variant)',
      });
    }

    return errors;
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
   * IMPROVEMENT-012: Check if cached schema is still valid (not expired)
   *
   * @param schemaType - Schema type to check
   * @returns true if schema is cached and valid, false otherwise
   */
  private isSchemaCacheValid(schemaType: SchemaType): boolean {
    const cached = this.schemaCache.get(schemaType);
    if (!cached) return false;

    // Check if cache entry has expired
    const age = Date.now() - cached.loadedAt;
    if (age > cached.ttl) {
      this.schemaCache.delete(schemaType);
      return false;
    }

    return true;
  }

  /**
   * IMPROVEMENT-012: Store schema in cache with TTL
   *
   * @param schemaType - Schema type
   * @param document - Parsed schema document
   * @param version - Optional schema version
   */
  private cacheSchema(schemaType: SchemaType, document: any, version?: string): void {
    this.schemaCache.set(schemaType, {
      document,
      loadedAt: Date.now(),
      ttl: this.schemaCacheTtl,
      version,
    });
  }

  /**
   * IMPROVEMENT-012: Get cached schema if valid (not expired)
   *
   * @param schemaType - Schema type to retrieve
   * @returns Schema document, or null if not cached or expired
   */
  private getCachedSchema(schemaType: SchemaType): any | null {
    if (!this.isSchemaCacheValid(schemaType)) {
      return null;
    }

    const cached = this.schemaCache.get(schemaType);
    return cached ? cached.document : null;
  }

  /**
   * Load UBL 2.1 schemas into memory at startup
   * Schemas are cached for the lifetime of the service
   *
   * IMPROVEMENT-012: Updated to use CachedSchema interface with TTL
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

        // IMPROVEMENT-012: Use cacheSchema with TTL instead of direct set
        this.cacheSchema(schemaType as SchemaType, schemaDoc);
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
    let errors: ValidationError[] = [];

    try {
      // IMPROVEMENT-014: Validate message structure first (early failure)
      const messageErrors = this.validateMessageSchema(xmlContent);
      if (messageErrors.length > 0) {
        errors.push(...messageErrors);
        return {
          status: ValidationStatus.ERROR,
          errors,
          validationTimeMs: Date.now() - startTime,
        };
      }

      // IMPROVEMENT-020: Validate XXE protection before parsing
      const xxeErrors = this.validateXXEProtection(xmlContent);
      if (xxeErrors.length > 0) {
        errors.push(...xxeErrors);
        return {
          status: ValidationStatus.ERROR,
          errors,
          validationTimeMs: Date.now() - startTime,
        };
      }

      // IMPROVEMENT-011: Use parseXmlWithCache to avoid redundant parsing
      const xmlDoc = this.parseXmlWithCache(xmlContent);

      // IMPROVEMENT-012: Use getCachedSchema with TTL checking
      const schema = this.getCachedSchema(schemaType);
      if (!schema) {
        return {
          status: ValidationStatus.ERROR,
          errors: [
            {
              code: 'SCHEMA_NOT_LOADED',
              message: `Schema ${schemaType} not loaded or expired. Call loadSchemas() to refresh.`,
            },
          ],
          validationTimeMs: Date.now() - startTime,
        };
      }

      // Validate against XSD schema
      const isValid = xmlDoc.validate(schema);

      if (!isValid) {
        // IMPROVEMENT-013: Extract errors with bounds checking (prevent DoS)
        const validationErrors = xmlDoc.validationErrors || [];
        errors = this.extractValidationErrors(validationErrors);
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
      // IMPROVEMENT-012: Use getCachedSchema with TTL checking
      const schema = this.getCachedSchema(schemaType);
      if (!schema) {
        return {
          status: ValidationStatus.ERROR,
          errors: [
            {
              code: 'SCHEMA_NOT_LOADED',
              message: `Schema ${schemaType} not loaded or expired. Call loadSchemas() to refresh.`,
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
   *
   * IMPROVEMENT-012: Updated to check schema validity (not just presence)
   */
  isReady(): boolean {
    if (this.schemaCache.size === 0) return false;

    // Check if at least one schema is valid (not expired)
    for (const schemaType of Object.values(SchemaType)) {
      if (this.isSchemaCacheValid(schemaType)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Get loaded schema types (for diagnostics)
   *
   * IMPROVEMENT-012: Updated to only return valid (not expired) schemas
   */
  getLoadedSchemas(): SchemaType[] {
    return Array.from(this.schemaCache.keys()).filter((schemaType) =>
      this.isSchemaCacheValid(schemaType)
    );
  }

  /**
   * IMPROVEMENT-012: Refresh schemas from disk
   * Reloads all schemas to ensure they are up-to-date
   */
  async refreshSchemas(): Promise<void> {
    this.schemaCache.clear();
    await this.loadSchemas();
  }

  /**
   * IMPROVEMENT-012: Get schema cache health information
   * @returns Schema cache health status
   */
  getSchemaCacheHealth(): {
    totalSchemas: number;
    validSchemas: number;
    expiredSchemas: number;
    schemas: Array<{
      type: SchemaType;
      loaded: string;
      expires: string;
      version?: string;
    }>;
  } {
    const schemas: Array<{
      type: SchemaType;
      loaded: string;
      expires: string;
      version?: string;
    }> = [];

    for (const [schemaType, cached] of this.schemaCache.entries()) {
      const expiresAt = new Date(cached.loadedAt + cached.ttl);

      schemas.push({
        type: schemaType,
        loaded: new Date(cached.loadedAt).toISOString(),
        expires: expiresAt.toISOString(),
        version: cached.version,
      });
    }

    const expiredSchemas = schemas.filter(
      (s) => new Date(s.expires).getTime() <= Date.now()
    ).length;
    const validSchemas = schemas.length - expiredSchemas;

    return {
      totalSchemas: schemas.length,
      validSchemas,
      expiredSchemas,
      schemas,
    };
  }

  /**
   * IMPROVEMENT-012: Clear schema cache (for testing or maintenance)
   */
  clearSchemaCache(): void {
    this.schemaCache.clear();
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
